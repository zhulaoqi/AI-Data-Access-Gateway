"""The extended ``execute_query`` flow (PA-1/3/4/5).

``GatewayRuntimeService.execute_query`` delegates here when the extension is enabled and the
caller's roles were synced by the management service (``run`` returns ``None`` otherwise, and the
upstream flow continues untouched). The flow keeps the upstream stages and adds, in order: the
dialect-aware guard, closed column scope, masked-column position rules, row-filter injection with a
second verification pass, admission control, a *committed* audit row before execution, a watchdog
with server-side ``KILL QUERY``, and a completion record.
"""

import json
import logging
import re
import threading
import time
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from sqlalchemy import exc as sa_exc
from sqlalchemy import select

from adg.app.settings import get_settings
from adg.connectors.base import QueryResult
from adg.connectors.errors import ConnectorDependencyError, ConnectorOperationError
from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.resource import Resource, ResourceField
from adg.policy.runtime import IdentityContext
from adg_ext import clientip, guard
from adg_ext import context as ctxmod
from adg_ext.admission import Admission, AdmissionRejected, Ticket
from adg_ext.analyze import FilterDef, TableView, rewrite
from adg_ext.config import get_ext_settings
from adg_ext.fingerprint import sql_fingerprint
from adg_ext.killer import kill_query
from adg_ext.metrics import get_query_metrics, reset_query_metrics
from adg_ext.redis_share import get_share

if TYPE_CHECKING:
    from adg.gateway_runtime.tools import GatewayRuntimeService

logger = logging.getLogger(__name__)

_TIME_TYPE = re.compile(r"date|time", re.IGNORECASE)
_INFRA_CODES = {1040, 2002, 2003, 2006, 2013, 2055}
_INFRA_CLASSES = {
    "NewConnectionError",
    "MaxRetryError",
    "ConnectTimeoutError",
    "ReadTimeoutError",
    "ProtocolError",
}
_admission: Admission | None = None
_admission_lock = threading.Lock()


def effective_datasource_limit() -> int:
    """The datasource-wide concurrency cap: never above what the runtime pool can serve.

    The connector draws from a pool of ``ADG_RUNTIME_DATASOURCE_POOL_SIZE`` (+ overflow)
    connections; admitting more statements than that parks them inside the pool, outside the
    queue and its timeout, so they would neither queue nor be refused in a controlled way.
    """

    base = get_ext_settings().datasource_max_concurrency
    runtime = get_settings()
    capacity = runtime.runtime_datasource_pool_size + runtime.runtime_datasource_pool_max_overflow
    return max(1, min(base, capacity))


def release_connection(session: Any) -> None:
    """Return the session's pooled connection (ends the read transaction).

    Loaded objects stay usable (the session factory sets ``expire_on_commit=False``); the next
    statement checks a connection out again. Nothing is pending here, so this writes nothing.
    """

    session.commit()


def get_admission() -> Admission:
    global _admission
    with _admission_lock:
        if _admission is None:
            s = get_ext_settings()
            _admission = Admission(
                datasource_limit=effective_datasource_limit(),
                breaker_threshold=s.breaker_failure_threshold,
                breaker_open_seconds=s.breaker_open_seconds,
            )
        return _admission


def reset_admission() -> None:
    """Drop controller state (tests)."""

    global _admission
    with _admission_lock:
        _admission = None
    reset_query_metrics()


def is_infra_failure(error: BaseException) -> bool:
    """Whether a connector failure says the datasource is unhealthy (vs. a bad query)."""

    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, OSError | TimeoutError) or type(current).__name__ in _INFRA_CLASSES:
            return True
        orig = getattr(current, "orig", current)
        args = getattr(orig, "args", ())
        if args and isinstance(args[0], int) and args[0] in _INFRA_CODES:
            return True
        current = current.__cause__ or current.__context__
    return False


def build_views(
    svc: "GatewayRuntimeService",
    ctx: ctxmod.ExtContext,
    resources: list[Resource],
) -> tuple[list[TableView], set[str]]:
    """Describe the touched resources; also returns the date/time column names (time-range rule)."""

    session = svc._session
    ids = [r.id for r in resources]
    columns: dict[str, set[str]] = {i: set() for i in ids}
    time_columns: set[str] = set()
    if ids:
        for rid, name, dtype in session.execute(
            select(ResourceField.resource_id, ResourceField.name, ResourceField.data_type).where(
                ResourceField.resource_id.in_(ids), ResourceField.status == "active"
            )
        ):
            columns[rid].add(name.lower())
            if _TIME_TYPE.search(dtype or ""):
                time_columns.add(name.lower())
    views: list[TableView] = []
    for resource in resources:
        scopes = ctx.scopes.get(resource.id, [])
        view = TableView(
            path=resource.path,
            resource_id=resource.id,
            restricted=bool(scopes),
            columns=frozenset(columns[resource.id]),
        )
        if scopes:
            view.allow = frozenset(c for s in scopes for c in s.allow)
            view.deny = frozenset(c for s in scopes for c in s.deny)
            for s in scopes:
                view.mask.update(s.mask)
            filters = {f.role_id: f for f in ctx.row_filters.get(resource.id, [])}
            view.filters = [
                FilterDef(f.where, f.params) if (f := filters.get(s.role_id)) else None
                for s in scopes
            ]
        views.append(view)
    return views, time_columns


def _audit_meta(request_id: str | None, audit_extra: dict[str, Any] | None) -> dict[str, Any]:
    """Metadata every audit row of one query carries: ``channel`` and (if known) ``request_id``.

    ``channel`` defaults to ``mcp`` (the MCP/HTTP runtime path never passes one); the delegated
    entry passes ``jdbc`` etc. through ``audit_extra``.
    """

    meta: dict[str, Any] = {"channel": "mcp"}
    meta.update(audit_extra or {})
    if not meta.get("client_ip"):
        # PA-8: the MCP/HTTP path has no caller-supplied address; use the resolved request address
        resolved = clientip.current()
        if resolved:
            meta["client_ip"] = resolved
        else:
            meta.pop("client_ip", None)
    if request_id:
        meta["request_id"] = request_id
    return meta


def _record_rejection(
    svc: "GatewayRuntimeService",
    identity: IdentityContext,
    api_key_id: str,
    kind: str,
    datasource_id: str | None,
    resource_ids: list[str],
    sql_text: str | None,
    reason: str,
    meta: dict[str, Any],
) -> None:
    """Like the upstream ``_record_rejection`` but the row carries ``channel``/``request_id``."""

    svc._audit.record_event(
        user_id=identity.user_id,
        api_key_id=api_key_id,
        event_type=kind,
        decision="denied",
        datasource_id=datasource_id,
        resource_ids=resource_ids,
        query_id=None,
        sql_text=sql_text,
        reason=reason,
        metadata=dict(meta),
    )
    svc._session.flush()


class _Run:
    """Executes one statement on a worker thread, bounded by a timeout and cancellable."""

    def __init__(self, fn: Any) -> None:
        self.result: QueryResult | None = None
        self.error: BaseException | None = None
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._go, args=(fn,), daemon=True)

    def _go(self, fn: Any) -> None:
        try:
            self.result = fn()
        except BaseException as error:
            self.error = error
        finally:
            self._done.set()

    def start(self) -> None:
        self._thread.start()

    def wait(self, timeout: float) -> bool:
        return self._done.wait(timeout)


def run(
    svc: "GatewayRuntimeService",
    *,
    identity: IdentityContext,
    api_key_id: str,
    datasource_id: str,
    resource_ids: list[str],
    query: str,
    limit: int,
    event_type: str,
    request_id: str | None = None,
    audit_extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Run the extended flow; ``None`` means "not managed by the extension, use upstream"."""

    session = svc._session
    ctx = ctxmod.load(session, user_id=identity.user_id, role_ids=identity.roles)
    if not ctx.managed:
        return None
    settings = get_settings()
    audit_meta = _audit_meta(request_id, audit_extra)

    def reject(kind: str, reason: str, hint: dict[str, object] | None = None) -> dict[str, Any]:
        get_query_metrics().rejected(reason)
        _record_rejection(
            svc, identity, api_key_id, kind, datasource_id, resource_ids, query, reason, audit_meta
        )
        out: dict[str, Any] = {"status": "rejected", "reason": reason}
        if hint:
            out["hint"] = hint
        return out

    if limit < 1:
        return reject("sql_rejected", "runtime_limit_invalid")
    if limit > settings.runtime_query_max_limit:
        return reject("sql_rejected", "runtime_limit_exceeded")
    effective_limit = min(limit, ctx.limits["maxRows"])

    datasource = svc._get_datasource(datasource_id)
    if datasource.status != "active":
        return reject("permission_rejected", "datasource_disabled")
    dialect = guard.dialect_for(datasource.type)
    # PA-8: a literal-free structural hash of the statement; the only SQL-derived value that leaves
    # the executor for risk inspection (see ``adg_ext.fingerprint``).
    fingerprint = sql_fingerprint(query, dialect)
    if fingerprint:
        audit_meta["sql_fingerprint"] = fingerprint

    declared = [svc._get_resource(rid) for rid in resource_ids]
    for resource in declared:
        disabled = svc._disabled_resource_reason(resource)
        if disabled is not None:
            return reject("permission_rejected", disabled)
        decision = svc._policy.check_resource_access(
            identity=identity, resource=resource, action="read"
        )
        if not decision.allowed:
            return reject("permission_rejected", decision.reason)

    _, time_columns = build_views(svc, ctx, declared)
    verdict = guard.check(
        query,
        dialect=dialect,
        default_limit=effective_limit,
        max_limit=effective_limit,
        operations=ctx.operations,
        time_columns=time_columns,
    )
    if not verdict.allowed:
        # The wildcard hint lists the columns the caller may use, never anything else.
        probe_views, _ = build_views(svc, ctx, declared)
        out = rewrite(verdict, probe_views, dialect=dialect, user_params={})
        return reject("sql_rejected", ",".join(out.reasons), out.hint)

    actual = svc._resolve_guard_resources(
        identity=identity,
        datasource_id=datasource_id,
        resource_paths=verdict.result.accessed_resources,
    )
    declared_ids = set(resource_ids)
    # Unknown, undeclared and unauthorised tables answer identically: no existence oracle.
    if len(actual) != len(verdict.result.accessed_resources) or not {r.id for r in actual}.issubset(
        declared_ids
    ):
        return reject("permission_rejected", "table_not_accessible")

    disabled_field = svc._first_disabled_field(actual, verdict.result.accessed_fields)
    if disabled_field is not None:
        return reject("permission_rejected", f"field_disabled:{disabled_field}")

    views, _ = build_views(svc, ctx, actual)
    outcome = rewrite(verdict, views, dialect=dialect, user_params=ctx.user_params)
    if not outcome.allowed or outcome.sql is None:
        kind = (
            "permission_rejected"
            if any(
                r.startswith(("column_", "masked_", "row_filter_", "table_"))
                for r in outcome.reasons
            )
            else "sql_rejected"
        )
        return reject(kind, ",".join(outcome.reasons), outcome.hint)

    projection_rejection = svc._masking.projection_rejection(
        identity=identity, resources=actual, projections=verdict.result.projections
    )
    if projection_rejection is not None:
        return reject("permission_rejected", projection_rejection)

    return _execute(
        svc,
        ctx=ctx,
        identity=identity,
        api_key_id=api_key_id,
        datasource=datasource,
        actual=actual,
        verdict=verdict,
        final_sql=outcome.sql,
        statement_limit=outcome.limit,
        effective_limit=effective_limit,
        event_type=event_type,
        original_query=query,
        request_id=request_id,
        audit_extra=audit_meta,
    )


def _execute(
    svc: "GatewayRuntimeService",
    *,
    ctx: ctxmod.ExtContext,
    identity: IdentityContext,
    api_key_id: str,
    datasource: Datasource,
    actual: list[Resource],
    verdict: guard.GuardVerdict,
    final_sql: str,
    statement_limit: int | None,
    effective_limit: int,
    event_type: str,
    original_query: str,
    request_id: str | None,
    audit_extra: dict[str, Any],
) -> dict[str, Any]:
    session = svc._session
    datasource_id = datasource.id
    actual_ids = sorted(r.id for r in actual)
    query_id = f"qry_{uuid4()}"
    user_key = identity.user_id or api_key_id
    admission = get_admission()
    limits = ctx.limits

    def rejected(kind: str, reason: str) -> dict[str, Any]:
        get_query_metrics().rejected(reason)
        _record_rejection(
            svc,
            identity,
            api_key_id,
            kind,
            datasource_id,
            actual_ids,
            original_query,
            reason,
            audit_extra,
        )
        return {"status": "rejected", "reason": reason}

    # Never wait in the admission queue while holding a control-plane connection: every queued
    # request would pin a pooled connection (opened by authentication and the reads above) while the
    # running ones need one to write their audit rows, and the pool deadlocks until its timeout.
    release_connection(session)
    try:
        ticket = admission.acquire(
            user_key=user_key,
            datasource_key=datasource_id,
            max_concurrency=limits["maxConcurrency"],
            queue_size=limits["queueSize"],
            queue_timeout=float(limits["queueTimeoutSeconds"]),
            tags=frozenset(
                t
                for t in (
                    identity.user_id,
                    api_key_id,
                    f"req:{request_id}" if request_id else None,
                )
                if t
            ),
        )
    except AdmissionRejected as error:
        return rejected("permission_rejected", f"admission_{error.reason}")

    get_share().register_run(request_id or "")
    final = "failed"  # the outcome label unless a branch below says otherwise
    try:
        tagged = f"/* grant={identity.user_id},req={query_id} */ {final_sql}"
        started_wall = time.monotonic()
        event = svc._audit.record_event(
            user_id=identity.user_id,
            api_key_id=api_key_id,
            event_type=event_type,
            decision="allowed",
            datasource_id=datasource_id,
            resource_ids=actual_ids,
            query_id=query_id,
            sql_text=verdict.result.normalized_sql,
            reason=None,
            metadata={
                "phase": "started",
                "rewritten_sql": final_sql,
                "grant": identity.user_id,
                "queue_wait_ms": int(ticket.waited_seconds * 1000),
                "max_rows": effective_limit,
                "accessed_fields": verdict.result.accessed_fields,
                **audit_extra,
            },
        )
        try:
            session.flush()
            if get_ext_settings().audit_fail_closed:
                session.commit()
        except sa_exc.TimeoutError:
            final = ""  # no connection within the pool timeout: a 503 for the caller, see router
            session.rollback()
            raise
        except Exception:
            logger.error("audit write failed; refusing to execute query %s", query_id)
            session.rollback()
            get_query_metrics().audit_unavailable()
            get_query_metrics().rejected("audit_unavailable")
            final = ""
            return {"status": "rejected", "reason": "audit_unavailable"}

        outcome = _run_connector(svc, datasource, tagged, effective_limit, query_id, limits, ticket)
        duration_ms = int((time.monotonic() - started_wall) * 1000)
        metadata: dict[str, Any] = dict(json_loads(event.metadata_json))
        metadata.update(phase="completed", duration_ms=duration_ms)

        if isinstance(outcome, str):  # an error type
            final = _OUTCOME_OF_ERROR.get(outcome, "failed")
            event.decision = "error"
            event.reason = outcome
            metadata["error_type"] = outcome
            event.metadata_json = _dumps(metadata)
            _persist(session)
            return {
                "query_id": query_id,
                "status": "error",
                "warnings": verdict.result.warnings,
                "error": {
                    "type": outcome,
                    "message": _ERROR_MESSAGES.get(outcome, "Query failed."),
                },
            }

        result = svc._enrich_result_column_types(result=outcome, resources=actual)
        result, masked_columns = svc._masking.apply_to_result(
            identity=identity,
            datasource_id=datasource_id,
            query_id=query_id,
            resources=actual,
            result=result,
            projections=verdict.result.projections,
        )
        rows = list(result.rows)
        truncated = (
            statement_limit is not None
            and statement_limit >= effective_limit
            and len(rows) >= effective_limit
        )
        metadata.update(rows=len(rows), truncated=truncated, masked_columns=masked_columns)
        event.metadata_json = _dumps(metadata)
        _persist(session)
        final = "completed"
        return {
            "query_id": query_id,
            "status": "success",
            "columns": list(result.columns),
            "rows": rows,
            "masking": {"masked_columns": masked_columns},
            "warnings": verdict.result.warnings,
            "truncated": truncated,
            "max_rows": effective_limit,
        }
    finally:
        ticket.release()
        if request_id:
            get_share().clear_run(request_id)
        if final:
            get_query_metrics().outcome(final)


_OUTCOME_OF_ERROR = {"query_timeout": "timeout", "query_cancelled": "cancelled"}

_ERROR_MESSAGES = {
    "query_timeout": "The query exceeded its time limit and was cancelled.",
    "query_cancelled": "The query was cancelled because access was revoked.",
    "datasource_unavailable": "The datasource is unavailable right now. Try again later.",
    "connector_operation_error": "Query execution failed. Reference query_id for details.",
    "connector_dependency_error": "Connector dependency is unavailable. Contact an administrator.",
    "circuit_open": "The datasource is temporarily paused after repeated failures.",
}


def json_loads(text: str | None) -> dict[str, Any]:
    try:
        value = json.loads(text or "{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _dumps(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)


def _persist(session: Any) -> None:
    try:
        session.flush()
        session.commit()
    except Exception:
        logger.error("completion audit write failed", exc_info=False)
        session.rollback()


def _run_connector(
    svc: "GatewayRuntimeService",
    datasource: Datasource,
    sql: str,
    limit: int,
    query_id: str,
    limits: dict[str, int],
    ticket: Ticket,
) -> QueryResult | str:
    """Execute on a worker thread; returns the result or an error-type string."""

    timeout = float(limits["queryTimeoutSeconds"])
    config = dict(datasource.config())
    config["_ext_timeout_seconds"] = int(timeout)
    config["_ext_query_id"] = query_id
    breaker = get_admission().breaker(datasource.id)
    connector = svc._connector_registry.create(datasource.type)

    def kill() -> None:
        kill_query(datasource.type, dict(datasource.config()), query_id)

    ticket.on_cancel(kill)
    runner = _Run(lambda: connector.execute_query(config, sql, limit))
    runner.start()
    if not runner.wait(timeout):
        kill()
        runner.wait(5.0)
        breaker.release_probe()
        return "query_timeout"
    if ticket.cancelled:
        breaker.release_probe()
        return "query_cancelled"
    error = runner.error
    if error is None and runner.result is not None:
        breaker.success()
        get_share().note_success(datasource.id)
        return runner.result
    if isinstance(error, ConnectorDependencyError):
        breaker.release_probe()
        return "connector_dependency_error"
    if isinstance(error, ConnectorOperationError):
        if is_infra_failure(error):
            breaker.failure()
            get_share().note_failure(datasource.id, breaker.threshold, breaker.open_seconds)
            return "datasource_unavailable"
        breaker.success()  # the datasource answered; the query itself was at fault
        get_share().note_success(datasource.id)
        return "connector_operation_error"
    breaker.release_probe()
    logger.error("unexpected connector failure: %s", type(error).__name__)
    return "connector_operation_error"
