"""Read side of the audit trail for the management service (PA-7, ``admin`` scope).

Three queries over ``audit_events``: a filtered, paginated list (never carrying SQL), the detail of
one event (original and rewritten SQL; reading it writes an ``audit_sql_view`` event) and window
statistics. Every filter is translated to SQL; nothing is filtered in memory. ``LIKE`` patterns are
built from escaped user input only.

Contract: ``sql-gateway/api/executor-admin.md`` §9.
"""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, and_, case, func, or_, select
from sqlalchemy.orm import Session

from adg.audit.models import AuditEvent
from adg.audit.service import AuditService
from adg.control_plane.models.directory import User
from adg.control_plane.models.resource import Resource
from adg_ext.sync import PREFIX

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_OFFSET = 10_000
MAX_GRANT_IDS = 500
MAX_WINDOW = timedelta(days=93)
DEFAULT_WINDOW = timedelta(hours=24)
REASON_TOP = 10
_MAX_TEXT = 200
_ESCAPE = "!"

# decision values as exposed (``rejected`` is stored as ``denied``)
DECISIONS = {"allowed": "allowed", "rejected": "denied", "denied": "denied", "error": "error"}
STATUSES = ("started", "completed", "failed", "cancelled", "timeout")
# events that represent one submitted query (executed or refused)
QUERY_EVENT_TYPES = ("query_execution", "resource_preview", "sql_rejected", "permission_rejected")
_TIMEOUT = "query_timeout"
_CANCELLED = "query_cancelled"


class AuditQueryError(Exception):
    """A request that cannot be served; ``status`` is the HTTP status, ``reason`` a stable code."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class Filters:
    start: datetime
    end: datetime
    grant_ids: list[str] = field(default_factory=list)
    datasource_id: str | None = None
    decision: str | None = None
    status: str | None = None
    table: str | None = None
    reason: str | None = None
    query_id: str | None = None
    event_type: str | None = None
    request_id: str | None = None
    channel: str | None = None


# ---- input handling ---------------------------------------------------------------------------


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is not None:
        value = value.astimezone(UTC)
    return value.replace(tzinfo=None)


def parse_instant(text: str) -> datetime:
    """ISO-8601 (``Z``/offset/naive = UTC) or epoch milliseconds, as a naive UTC datetime."""

    raw = text.strip()
    try:
        if raw.isdigit():
            return datetime.fromtimestamp(int(raw) / 1000, tz=UTC).replace(tzinfo=None)
        try:
            return _naive_utc(datetime.fromisoformat(raw))
        except ValueError:
            # a "+" offset in a query string arrives as a space
            return _naive_utc(datetime.fromisoformat(raw.replace(" ", "+")))
    except (ValueError, OverflowError, OSError) as error:
        raise AuditQueryError(422, "invalid_time") from error


def resolve_window(
    start: str | None, end: str | None, *, now: datetime | None = None
) -> tuple[datetime, datetime]:
    """Both ends optional: ``to`` defaults to now, ``from`` to 24 hours before ``to``; capped."""

    current = _naive_utc(now) if now else _naive_utc(datetime.now(UTC))
    end_at = parse_instant(end) if end and end.strip() else current
    start_at = parse_instant(start) if start and start.strip() else end_at - DEFAULT_WINDOW
    if start_at >= end_at:
        raise AuditQueryError(422, "invalid_time_range")
    if end_at - start_at > MAX_WINDOW:
        raise AuditQueryError(422, "time_window_too_large")
    return start_at, end_at


def build_filters(
    *,
    start: str | None,
    end: str | None,
    grant_ids: list[str] | None = None,
    datasource_id: str | None = None,
    decision: str | None = None,
    status: str | None = None,
    table: str | None = None,
    reason: str | None = None,
    query_id: str | None = None,
    event_type: str | None = None,
    request_id: str | None = None,
    channel: str | None = None,
) -> Filters:
    window = resolve_window(start, end)
    ids = _split(grant_ids)
    if len(ids) > MAX_GRANT_IDS:
        raise AuditQueryError(422, "too_many_grant_ids")
    stored_decision = None
    if decision:
        stored_decision = DECISIONS.get(decision.strip().lower())
        if stored_decision is None:
            raise AuditQueryError(422, "invalid_decision")
    stored_status = None
    if status:
        stored_status = status.strip().lower()
        if stored_status not in STATUSES:
            raise AuditQueryError(422, "invalid_status")
    return Filters(
        start=window[0],
        end=window[1],
        grant_ids=ids,
        datasource_id=_text(datasource_id),
        decision=stored_decision,
        status=stored_status,
        table=_text(table),
        reason=_text(reason),
        query_id=_text(query_id),
        event_type=_text(event_type),
        request_id=_text(request_id),
        channel=_text(channel),
    )


def _split(values: list[str] | None) -> list[str]:
    out: dict[str, None] = {}
    for value in values or []:
        for part in value.split(","):
            if part.strip():
                out[part.strip()] = None
    return list(out)


def _text(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    cleaned = value.strip()
    if len(cleaned) > _MAX_TEXT:
        raise AuditQueryError(422, "filter_too_long")
    return cleaned


def check_page(limit: int | None, offset: int) -> tuple[int, int]:
    page_limit = DEFAULT_LIMIT if limit is None else limit
    if page_limit < 1 or page_limit > MAX_LIMIT:
        raise AuditQueryError(422, "limit_out_of_range")
    if offset < 0:
        raise AuditQueryError(422, "offset_negative")
    if offset > MAX_OFFSET:
        raise AuditQueryError(422, "offset_too_large")
    return page_limit, offset


# ---- SQL construction -------------------------------------------------------------------------


def like_escape(text: str) -> str:
    """Neutralise ``LIKE`` wildcards (and the escape character itself) in user input."""

    return (
        text.replace(_ESCAPE, _ESCAPE * 2).replace("%", _ESCAPE + "%").replace("_", _ESCAPE + "_")
    )


def _like(column: Any, pattern: str) -> ColumnElement[bool]:
    result: ColumnElement[bool] = column.like(pattern, escape=_ESCAPE)
    return result


def _reason_condition(reason: str) -> ColumnElement[bool]:
    """Exact code, a code with a ``:detail`` suffix, or one entry of a comma separated list."""

    r = like_escape(reason)
    return or_(
        AuditEvent.reason == reason,
        _like(AuditEvent.reason, f"{r}:%"),
        _like(AuditEvent.reason, f"{r},%"),
        _like(AuditEvent.reason, f"%,{r}"),
        _like(AuditEvent.reason, f"%,{r},%"),
        _like(AuditEvent.reason, f"%,{r}:%"),
    )


def _table_condition(session: Session, table: str) -> ColumnElement[bool]:
    """Match events that touched ``table``.

    ``resource_ids_json`` holds resource ids, so the name is first resolved to resources in SQL
    (``path`` equal to it or ending in ``.<table>``); the same text is also looked up verbatim
    (a caller passing a resource id) and among the accessed fields of the event metadata.
    """

    wanted = like_escape(table)
    resource_ids = list(
        session.execute(
            select(Resource.id)
            .where(
                or_(
                    Resource.path == table,
                    _like(Resource.path, f"%.{wanted}"),
                    Resource.id == table,
                )
            )
            .limit(MAX_LIMIT)
        ).scalars()
    )
    needles = [json.dumps(table)] + [json.dumps(rid) for rid in resource_ids]
    conditions: list[ColumnElement[bool]] = [
        _like(AuditEvent.resource_ids_json, f"%{like_escape(n)}%") for n in needles
    ]
    conditions.append(
        _like(AuditEvent.metadata_json, f'%"accessed_fields":%{like_escape(json.dumps(table))}%')
    )
    return or_(*conditions)


def _meta_equals(key: str, value: str) -> ColumnElement[bool]:
    """Event whose metadata has ``"<key>":"<value>"`` (compact JSON; the value is quoted whole).

    ``json.dumps`` escapes quotes inside strings, so a value carrying ``"`` cannot forge a match
    through another field (e.g. SQL text), and the closing quote makes the match exact, not a
    prefix.
    """

    needle = f"{json.dumps(key)}:{json.dumps(value)}"
    return _like(AuditEvent.metadata_json, f"%{like_escape(needle)}%")


def _status_condition(status: str) -> ColumnElement[bool]:
    if status == "timeout":
        return and_(AuditEvent.decision == "error", AuditEvent.reason == _TIMEOUT)
    if status == "cancelled":
        return and_(AuditEvent.decision == "error", AuditEvent.reason == _CANCELLED)
    if status == "failed":
        return and_(
            AuditEvent.decision == "error",
            or_(AuditEvent.reason.is_(None), AuditEvent.reason.not_in([_TIMEOUT, _CANCELLED])),
        )
    return and_(
        AuditEvent.decision == "allowed",
        _like(AuditEvent.metadata_json, f'%"phase":"{status}"%'),
    )


def _grant_user_ids(session: Session, grant_ids: list[str]) -> list[str]:
    """Audit ``user_id`` is the executor user of a grant (``gw:user:<grantId>``).

    Grant ids are mapped through the synced users; a value that is already a user id is kept.
    """

    names = [f"{PREFIX}user:{g}" for g in grant_ids]
    mapped = list(session.execute(select(User.id).where(User.external_ref.in_(names))).scalars())
    return sorted(set(mapped) | set(grant_ids))


def conditions(session: Session, f: Filters) -> list[ColumnElement[bool]]:
    out: list[ColumnElement[bool]] = [
        AuditEvent.created_at >= f.start,
        AuditEvent.created_at < f.end,
    ]
    if f.grant_ids:
        out.append(AuditEvent.user_id.in_(_grant_user_ids(session, f.grant_ids)))
    if f.datasource_id:
        out.append(AuditEvent.datasource_id == f.datasource_id)
    if f.decision:
        out.append(AuditEvent.decision == f.decision)
    if f.status:
        out.append(_status_condition(f.status))
    if f.table:
        out.append(_table_condition(session, f.table))
    if f.reason:
        out.append(_reason_condition(f.reason))
    if f.query_id:
        out.append(AuditEvent.query_id == f.query_id)
    if f.event_type:
        out.append(AuditEvent.event_type == f.event_type)
    if f.request_id:
        out.append(_meta_equals("request_id", f.request_id))
    if f.channel:
        out.append(_meta_equals("channel", f.channel))
    return out


# ---- serialisation ----------------------------------------------------------------------------


def _iso(value: datetime) -> str:
    if value.tzinfo is not None:
        value = value.astimezone(UTC)
    return value.replace(tzinfo=None).isoformat(timespec="milliseconds") + "Z"


def _metadata(event: AuditEvent) -> dict[str, Any]:
    try:
        decoded = json.loads(event.metadata_json or "{}")
    except ValueError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _resource_ids(event: AuditEvent) -> list[str]:
    try:
        decoded = json.loads(event.resource_ids_json or "[]")
    except ValueError:
        return []
    return [i for i in decoded if isinstance(i, str)] if isinstance(decoded, list) else []


def derive_status(event: AuditEvent, meta: dict[str, Any]) -> str | None:
    """Execution phase of an event; ``None`` for events that never started (rejections etc.)."""

    if event.decision == "error":
        if event.reason == _TIMEOUT:
            return "timeout"
        if event.reason == _CANCELLED:
            return "cancelled"
        return "failed"
    if event.decision == "allowed":
        phase = meta.get("phase")
        return phase if phase in ("started", "completed") else None
    return None


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _grant_id(external_ref: str | None, meta: dict[str, Any], user_id: str | None) -> str | None:
    if external_ref and external_ref.startswith(f"{PREFIX}user:"):
        return external_ref[len(f"{PREFIX}user:") :]
    delegated = meta.get("grant_id")
    if isinstance(delegated, str) and delegated:
        return delegated
    return user_id


def _meta_text(meta: dict[str, Any], key: str) -> str | None:
    value = meta.get(key)
    return value if isinstance(value, str) and value else None


def serialize(event: AuditEvent, external_ref: str | None) -> dict[str, Any]:
    """List item: never contains SQL text."""

    meta = _metadata(event)
    return {
        "id": event.id,
        "createdAt": _iso(event.created_at),
        "eventType": event.event_type,
        "decision": "rejected" if event.decision == "denied" else event.decision,
        "reason": event.reason,
        "grantId": _grant_id(external_ref, meta, event.user_id),
        "datasourceId": event.datasource_id,
        "resourceIds": _resource_ids(event),
        "queryId": event.query_id,
        "requestId": _meta_text(meta, "request_id"),
        "channel": _meta_text(meta, "channel"),
        "status": derive_status(event, meta),
        "queueWaitMs": _int_or_none(meta.get("queue_wait_ms")),
        "rowCount": _int_or_none(meta.get("rows")),
        "durationMs": _int_or_none(meta.get("duration_ms")),
    }


def _external_refs(session: Session, user_ids: set[str]) -> dict[str, str | None]:
    if not user_ids:
        return {}
    rows = session.execute(select(User.id, User.external_ref).where(User.id.in_(sorted(user_ids))))
    return {uid: ref for uid, ref in rows}


# ---- operations -------------------------------------------------------------------------------


def list_events(session: Session, f: Filters, limit: int, offset: int) -> dict[str, Any]:
    where = conditions(session, f)
    total = int(
        session.execute(select(func.count()).select_from(AuditEvent).where(*where)).scalar_one()
    )
    stmt = (
        select(AuditEvent)
        .where(*where)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(limit)
        .offset(offset)
    )
    events = list(session.execute(stmt).scalars())
    refs = _external_refs(session, {e.user_id for e in events if e.user_id})
    return {
        "items": [serialize(e, refs.get(e.user_id or "")) for e in events],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def event_detail(
    session: Session, event_id: str, *, api_key_id: str | None, user_id: str | None
) -> dict[str, Any]:
    """One event with SQL; the read itself is recorded as ``audit_sql_view`` (committed)."""

    event = session.get(AuditEvent, event_id)
    if event is None:
        raise AuditQueryError(404, "audit_event_not_found")
    meta = _metadata(event)
    refs = _external_refs(session, {event.user_id} if event.user_id else set())
    out = serialize(event, refs.get(event.user_id or ""))
    accessed = meta.get("accessed_fields")
    out["sqlText"] = event.sql_text
    out["rewrittenSql"] = (
        meta.get("rewritten_sql") if isinstance(meta.get("rewritten_sql"), str) else None
    )
    out["accessedFields"] = (
        [a for a in accessed if isinstance(a, str)] if isinstance(accessed, list) else []
    )
    AuditService(session).record_sql_view(
        api_key_id=api_key_id, user_id=user_id, target_event=event
    )
    session.commit()
    return out


def stats(session: Session, start: str | None, end: str | None) -> dict[str, Any]:
    window_start, window_end = resolve_window(start, end)
    base = [
        AuditEvent.created_at >= window_start,
        AuditEvent.created_at < window_end,
        AuditEvent.event_type.in_(QUERY_EVENT_TYPES),
    ]

    def count_if(condition: ColumnElement[bool]) -> Any:
        return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)

    row = session.execute(
        select(
            func.count(),
            count_if(AuditEvent.decision.in_(["allowed", "error"])),
            count_if(AuditEvent.decision == "denied"),
            count_if(AuditEvent.decision == "error"),
            count_if(
                and_(
                    AuditEvent.decision == "denied",
                    AuditEvent.reason.startswith("admission_", autoescape=True),
                )
            ),
            count_if(and_(AuditEvent.decision == "error", AuditEvent.reason == _TIMEOUT)),
        ).where(*base)
    ).one()
    top = session.execute(
        select(AuditEvent.reason, func.count().label("n"))
        .where(*base, AuditEvent.decision == "denied", AuditEvent.reason.is_not(None))
        .group_by(AuditEvent.reason)
        .order_by(func.count().desc(), AuditEvent.reason)
        .limit(REASON_TOP)
    ).all()
    return {
        "from": _iso(window_start),
        "to": _iso(window_end),
        "total": int(row[0]),
        "allowed": int(row[1]),
        "rejected": int(row[2]),
        "failed": int(row[3]),
        "admissionRejected": int(row[4]),
        "timeouts": int(row[5]),
        "reasonTop": [{"reason": str(reason), "count": int(n)} for reason, n in top],
    }
