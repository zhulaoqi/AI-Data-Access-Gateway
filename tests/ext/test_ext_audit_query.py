"""PA-7 audit queries on SQLite: filters, limits, detail (+ ``audit_sql_view``), stats, scopes."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from adg.app.auth_rate_limit import reset_auth_rate_limiter
from adg.app.main import create_app
from adg.app.settings import get_settings
from adg.audit.models import AuditEvent
from adg.connectors.registry import get_connector_registry
from adg.control_plane.db import create_engine_from_url, create_session_factory
from adg.control_plane.models import Base
from adg.control_plane.models.directory import User
from adg.control_plane.models.resource import Resource
from adg.control_plane.services.api_key_service import create_api_key
from adg_ext import audit_query, pipeline, revocation
from adg_ext.config import get_ext_settings

ADMIN = {"X-ADG-API-Key": "adg_admin_audit_key"}
RUNTIME = {"X-ADG-API-Key": "adg_runtime_audit_key"}
ENTRY = {"X-ADG-API-Key": "adg_entry_audit_key"}
SECRET_SQL = "SELECT id, phone FROM shop.orders WHERE tenant_id = 7"
REWRITTEN = "SELECT id, phone FROM shop.orders WHERE tenant_id = 7 AND (tenant_id = 7) LIMIT 100"


def naive_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Env:
    def __init__(self, client: TestClient, factory: sessionmaker[Session]) -> None:
        self.client = client
        self.factory = factory
        self.ids: dict[str, str] = {}

    def get(self, path: str, headers: dict[str, str] | None = None, **params: Any) -> Any:
        return self.client.get(path, params=params, headers=headers or ADMIN)

    def events(self, **params: Any) -> list[dict[str, Any]]:
        r = self.get("/ext/audit/events", **params)
        assert r.status_code == 200, r.text
        return list(r.json()["items"])

    def ids_of(self, **params: Any) -> set[str]:
        return {i["id"] for i in self.events(**params)}


def add(
    session: Session,
    key: str,
    env: Env,
    *,
    ago: timedelta = timedelta(minutes=5),
    user_id: str | None = "u1",
    event_type: str = "query_execution",
    decision: str = "allowed",
    reason: str | None = None,
    metadata: dict[str, Any] | None = None,
    sql: str | None = SECRET_SQL,
    resources: list[str] | None = None,
    datasource: str | None = "ds1",
    query_id: str | None = None,
) -> None:
    event = AuditEvent(
        user_id=user_id,
        api_key_id="k1",
        event_type=event_type,
        datasource_id=datasource,
        resource_ids_json=json.dumps(resources or [], separators=(",", ":")),
        query_id=query_id,
        sql_text=sql,
        decision=decision,
        reason=reason,
        metadata_json=json.dumps(metadata or {}, separators=(",", ":")),
        created_at=naive_now() - ago,
    )
    session.add(event)
    session.flush()
    env.ids[key] = event.id


def run_env(url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    """The seeded app on any control-plane database (SQLite here, MySQL in the integration tests)."""

    monkeypatch.setenv("ADG_EXT_ENABLED", "true")
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()
    reset_auth_rate_limiter()
    engine = create_engine_from_url(url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    registry = get_connector_registry()
    saved = dict(registry._connectors)
    holder = Env(TestClient(create_app(session_factory=factory)), factory)
    with factory() as session:
        create_api_key(session, name="admin", scopes=["admin"], plaintext="adg_admin_audit_key")
        create_api_key(session, name="rt", scopes=["runtime"], plaintext="adg_runtime_audit_key")
        create_api_key(session, name="entry", scopes=["entry"], plaintext="adg_entry_audit_key")
        session.add(User(id="u1", name="Alice", external_ref="gw:user:g1"))
        session.add(User(id="u2", name="Bob", external_ref="gw:user:g2"))
        session.add(
            Resource(
                id="res-orders",
                datasource_id="ds1",
                kind="relational_table",
                name="orders",
                path="shop.orders",
                display_name="orders",
            )
        )
        session.add(
            Resource(
                id="res-dim",
                datasource_id="ds1",
                kind="relational_table",
                name="dim",
                path="shop.dim",
                display_name="dim",
            )
        )
        session.flush()
        add(
            session,
            "started",
            holder,
            ago=timedelta(minutes=1),
            query_id="qry_started",
            resources=["res-orders"],
            metadata={"phase": "started", "queue_wait_ms": 4, "accessed_fields": ["id"]},
        )
        add(
            session,
            "done",
            holder,
            ago=timedelta(minutes=2),
            query_id="qry_done",
            resources=["res-orders"],
            metadata={
                "phase": "completed",
                "rewritten_sql": REWRITTEN,
                "queue_wait_ms": 12,
                "duration_ms": 35,
                "rows": 2,
                "accessed_fields": ["id", "phone"],
            },
        )
        add(
            session,
            "denied",
            holder,
            ago=timedelta(minutes=3),
            user_id="u2",
            event_type="permission_rejected",
            decision="denied",
            reason="table_not_accessible",
            resources=["res-dim"],
        )
        add(
            session,
            "column",
            holder,
            ago=timedelta(minutes=4),
            user_id="u2",
            event_type="sql_rejected",
            decision="denied",
            reason="column_not_allowed:ssn",
            resources=["res-orders"],
        )
        add(
            session,
            "admission",
            holder,
            ago=timedelta(minutes=6),
            event_type="permission_rejected",
            decision="denied",
            reason="admission_queue_full",
        )
        add(
            session,
            "timeout",
            holder,
            ago=timedelta(minutes=7),
            decision="error",
            reason="query_timeout",
            query_id="qry_timeout",
            metadata={"phase": "completed", "error_type": "query_timeout", "duration_ms": 5000},
        )
        add(
            session,
            "failed",
            holder,
            ago=timedelta(minutes=8),
            decision="error",
            reason="connector_operation_error",
            metadata={"phase": "completed", "error_type": "connector_operation_error"},
        )
        add(
            session,
            "cancelled",
            holder,
            ago=timedelta(minutes=9),
            decision="error",
            reason="query_cancelled",
            metadata={"phase": "completed"},
        )
        add(
            session,
            "view",
            holder,
            ago=timedelta(minutes=10),
            event_type="audit_sql_view",
            sql=None,
            metadata={"target_event_id": "x"},
        )
        add(
            session,
            "old",
            holder,
            ago=timedelta(days=2),
            decision="denied",
            event_type="permission_rejected",
            reason="table_not_accessible",
        )
        session.commit()
    yield holder
    registry._connectors.clear()
    registry._connectors.update(saved)
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()
    reset_auth_rate_limiter()  # the refused-key tests must not lock out later tests' client


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    yield from run_env(f"sqlite:///{tmp_path / 'cp.db'}", monkeypatch)


# ---- pure helpers ------------------------------------------------------------------------------


def test_like_escape_neutralises_wildcards_and_the_escape_character() -> None:
    assert audit_query.like_escape("a%b_c!d") == "a!%b!_c!!d"


def test_parse_instant_accepts_iso_offsets_and_epoch_millis() -> None:
    expected = datetime(2026, 10, 14, 10, 0, 0)
    assert audit_query.parse_instant("2026-10-14T10:00:00Z") == expected
    assert audit_query.parse_instant("2026-10-14T18:00:00+08:00") == expected
    assert audit_query.parse_instant("2026-10-14T18:00:00 08:00") == expected  # '+' decoded
    assert audit_query.parse_instant("2026-10-14T10:00:00") == expected
    assert audit_query.parse_instant("1791972000000") == expected
    with pytest.raises(audit_query.AuditQueryError):
        audit_query.parse_instant("yesterday")


def test_window_defaults_to_the_last_24_hours_and_is_validated() -> None:
    now = datetime(2026, 10, 14, 12, 0, 0, tzinfo=UTC)
    start, end = audit_query.resolve_window(None, None, now=now)
    assert end - start == timedelta(hours=24) and end == datetime(2026, 10, 14, 12)
    start, end = audit_query.resolve_window(None, "2026-10-10T00:00:00Z", now=now)
    assert end - start == timedelta(hours=24)
    for bad in (
        ("2026-10-02T00:00:00Z", "2026-10-01T00:00:00Z"),
        ("2026-01-01T00:00:00Z", "2026-10-01T00:00:00Z"),
    ):
        with pytest.raises(audit_query.AuditQueryError):
            audit_query.resolve_window(*bad, now=now)


# ---- list --------------------------------------------------------------------------------------


def test_list_defaults_to_24_hours_newest_first_and_never_carries_sql(env: Env) -> None:
    r = env.get("/ext/audit/events")
    assert r.status_code == 200
    body = r.json()
    items = body["items"]
    assert body["total"] == 9 and body["limit"] == 50 and body["offset"] == 0
    assert env.ids["old"] not in {i["id"] for i in items}
    stamps = [i["createdAt"] for i in items]
    assert stamps == sorted(stamps, reverse=True)
    assert items[0]["id"] == env.ids["started"]
    text = r.text
    assert "SELECT" not in text and "sqlText" not in text and "rewrittenSql" not in text
    done = next(i for i in items if i["id"] == env.ids["done"])
    assert done == {
        "id": env.ids["done"],
        "createdAt": done["createdAt"],
        "eventType": "query_execution",
        "decision": "allowed",
        "reason": None,
        "grantId": "g1",
        "datasourceId": "ds1",
        "resourceIds": ["res-orders"],
        "queryId": "qry_done",
        "requestId": None,  # rows written before the field existed
        "channel": None,
        "status": "completed",
        "queueWaitMs": 12,
        "rowCount": 2,
        "durationMs": 35,
    }
    assert done["createdAt"].endswith("Z")
    denied = next(i for i in items if i["id"] == env.ids["denied"])
    assert denied["decision"] == "rejected" and denied["status"] is None


def test_filter_by_grant_ids_maps_grants_to_executor_users(env: Env) -> None:
    assert env.ids_of(grantIds="g2") == {env.ids["denied"], env.ids["column"]}
    both = env.client.get(
        "/ext/audit/events", params=[("grantIds", "g2"), ("grantIds", "g1")], headers=ADMIN
    )
    assert len(both.json()["items"]) == 9
    assert env.ids_of(grantIds="g2,nobody") == {env.ids["denied"], env.ids["column"]}
    assert env.ids_of(grantIds="nobody") == set()
    assert env.ids_of(grantIds="u2") == {env.ids["denied"], env.ids["column"]}  # raw user id


def test_filter_by_decision_and_status(env: Env) -> None:
    denied = {env.ids[k] for k in ("denied", "column", "admission")}
    assert env.ids_of(decision="rejected") == denied
    assert env.ids_of(decision="denied") == denied
    assert env.ids_of(decision="error") == {env.ids[k] for k in ("timeout", "failed", "cancelled")}
    assert env.ids_of(decision="allowed") == {env.ids[k] for k in ("started", "done", "view")}
    assert env.ids_of(status="started") == {env.ids["started"]}
    assert env.ids_of(status="completed") == {env.ids["done"]}
    assert env.ids_of(status="timeout") == {env.ids["timeout"]}
    assert env.ids_of(status="cancelled") == {env.ids["cancelled"]}
    assert env.ids_of(status="failed") == {env.ids["failed"]}
    assert env.get("/ext/audit/events", status="bogus").status_code == 422
    assert env.get("/ext/audit/events", decision="bogus").status_code == 422


def test_filter_by_reason_handles_details_and_exact_codes(env: Env) -> None:
    assert env.ids_of(reason="table_not_accessible") == {env.ids["denied"]}
    assert env.ids_of(reason="column_not_allowed") == {env.ids["column"]}
    assert env.ids_of(reason="column_not_allowed:ssn") == {env.ids["column"]}
    assert env.ids_of(reason="admission_queue_full") == {env.ids["admission"]}
    assert env.ids_of(reason="table") == set()  # no prefix matching on a bare word
    assert env.ids_of(reason="%") == set()


def test_filter_by_table_uses_resources_and_is_injection_safe(env: Env) -> None:
    assert env.ids_of(table="orders") == {env.ids[k] for k in ("started", "done", "column")}
    assert env.ids_of(table="shop.dim") == {env.ids["denied"]}
    assert env.ids_of(table="res-dim") == {env.ids["denied"]}
    # accessed fields of the event metadata
    assert env.ids_of(table="phone") == {env.ids["done"]}
    for hostile in (
        "%",
        "_",
        "ord_rs",
        "o%",
        "x' OR '1'='1",
        '"%',
        "\\",
        "!",
        "'; DROP TABLE audit_events;--",
    ):
        assert env.ids_of(table=hostile) == set(), hostile
    assert len(env.events()) == 9  # table still there


def test_filter_by_query_id_event_type_datasource_and_window(env: Env) -> None:
    assert env.ids_of(queryId="qry_done") == {env.ids["done"]}
    assert env.ids_of(eventType="sql_rejected") == {env.ids["column"]}
    assert env.ids_of(eventType="audit_sql_view") == {env.ids["view"]}
    assert env.ids_of(datasourceId="ds1") == env.ids_of()
    assert env.ids_of(datasourceId="other") == set()
    wide = env.ids_of(**{"from": (naive_now() - timedelta(days=3)).isoformat() + "Z"})
    assert env.ids["old"] in wide and len(wide) == 10
    narrow = env.ids_of(
        **{
            "from": (naive_now() - timedelta(minutes=4, seconds=30)).isoformat() + "Z",
            "to": (naive_now() - timedelta(minutes=1, seconds=30)).isoformat() + "Z",
        }
    )
    assert narrow == {env.ids[k] for k in ("done", "denied", "column")}
    assert env.get("/ext/audit/events", **{"from": "nonsense"}).status_code == 422
    assert (
        env.get(
            "/ext/audit/events", **{"from": "2026-01-01T00:00:00Z", "to": "2026-10-01T00:00:00Z"}
        ).json()["detail"]
        == "time_window_too_large"
    )


def _add_channel_rows(env: Env) -> None:
    with env.factory() as session:
        add(
            session,
            "jdbc_done",
            env,
            ago=timedelta(minutes=20),
            query_id="qry_j1",
            metadata={"phase": "completed", "channel": "jdbc", "request_id": "req-100"},
        )
        add(
            session,
            "jdbc_rejected",
            env,
            ago=timedelta(minutes=21),
            event_type="permission_rejected",
            decision="denied",
            reason="column_not_allowed:ssn",
            metadata={"channel": "jdbc", "request_id": "req-101"},
        )
        add(
            session,
            "mcp_done",
            env,
            ago=timedelta(minutes=22),
            query_id="qry_m1",
            metadata={"phase": "completed", "channel": "mcp"},
        )
        add(
            session,
            "pct",
            env,
            ago=timedelta(minutes=23),
            metadata={"channel": "jdbc", "request_id": "a%b_c"},
        )
        # a SQL text that *looks* like the metadata key must not forge a match
        add(
            session,
            "forged",
            env,
            ago=timedelta(minutes=24),
            metadata={"rewritten_sql": 'x "request_id":"req-100" y', "channel": "mcp"},
        )
        session.commit()


def test_events_expose_request_id_and_channel(env: Env) -> None:
    _add_channel_rows(env)
    items = {i["id"]: i for i in env.events(limit=200)}
    done = items[env.ids["jdbc_done"]]
    assert done["requestId"] == "req-100" and done["channel"] == "jdbc"
    rejected = items[env.ids["jdbc_rejected"]]
    assert rejected["requestId"] == "req-101" and rejected["channel"] == "jdbc"
    assert rejected["queryId"] is None and rejected["decision"] == "rejected"
    assert items[env.ids["mcp_done"]]["channel"] == "mcp"
    assert items[env.ids["mcp_done"]]["requestId"] is None
    old = items[env.ids["done"]]
    assert old["requestId"] is None and old["channel"] is None
    detail = env.get(f"/ext/audit/events/{env.ids['jdbc_done']}").json()
    assert detail["requestId"] == "req-100" and detail["channel"] == "jdbc"
    assert env.get(f"/ext/audit/events/{env.ids['jdbc_rejected']}").json()["requestId"] == "req-101"


def test_filter_by_request_id_and_channel(env: Env) -> None:
    _add_channel_rows(env)
    assert env.ids_of(requestId="req-100") == {env.ids["jdbc_done"]}
    assert env.ids_of(requestId="req-101") == {env.ids["jdbc_rejected"]}
    assert env.ids_of(requestId="req-10") == set()  # exact, not a prefix
    assert env.ids_of(requestId="req-1000") == set()
    assert env.ids_of(requestId="nope") == set()
    assert env.ids_of(channel="jdbc") == {
        env.ids["jdbc_done"],
        env.ids["jdbc_rejected"],
        env.ids["pct"],
    }
    assert env.ids_of(channel="mcp") == {env.ids["mcp_done"], env.ids["forged"]}
    assert env.ids_of(channel="jdbc", requestId="req-101") == {env.ids["jdbc_rejected"]}
    assert env.ids_of(channel="mcp", requestId="req-101") == set()
    assert env.ids_of(channel="jdbc", decision="rejected") == {env.ids["jdbc_rejected"]}
    assert env.ids_of(requestId="  ") == env.ids_of()  # blank = no filter


def test_request_id_filter_is_wildcard_and_injection_safe(env: Env) -> None:
    _add_channel_rows(env)
    assert env.ids_of(requestId="a%b_c") == {env.ids["pct"]}
    assert env.ids_of(requestId="%") == set()
    assert env.ids_of(requestId="_") == set()
    assert env.ids_of(requestId="a_b_c") == set()
    assert env.ids_of(requestId="req-100' OR '1'='1") == set()
    assert env.ids_of(requestId="req-100\\") == set()
    assert env.ids_of(requestId='req-100" y') == set()
    assert env.get("/ext/audit/events", requestId="x" * 201).json()["detail"] == "filter_too_long"
    assert env.get("/ext/audit/events", channel="x" * 201).status_code == 422


def test_pagination_defaults_and_caps(env: Env) -> None:
    with env.factory() as session:
        for _ in range(60):
            add(session, "bulk", env, ago=timedelta(minutes=30), metadata={"phase": "completed"})
        session.commit()
    first = env.get("/ext/audit/events").json()
    assert len(first["items"]) == 50 and first["total"] == 69 and first["limit"] == 50
    page = env.get("/ext/audit/events", limit=10, offset=65).json()
    assert len(page["items"]) == 4 and page["offset"] == 65
    assert len(env.get("/ext/audit/events", limit=200).json()["items"]) == 69
    assert env.get("/ext/audit/events", limit=201).json()["detail"] == "limit_out_of_range"
    assert env.get("/ext/audit/events", limit=0).status_code == 422
    assert env.get("/ext/audit/events", offset=10_001).json()["detail"] == "offset_too_large"
    assert env.get("/ext/audit/events", offset=10_000).json()["items"] == []
    assert env.get("/ext/audit/events", offset=-1).status_code == 422


# ---- detail ------------------------------------------------------------------------------------


def test_detail_returns_sql_and_records_a_sql_view(env: Env) -> None:
    r = env.get(f"/ext/audit/events/{env.ids['done']}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sqlText"] == SECRET_SQL
    assert body["rewrittenSql"] == REWRITTEN
    assert body["accessedFields"] == ["id", "phone"]
    assert body["grantId"] == "g1" and body["status"] == "completed" and body["rowCount"] == 2
    with env.factory() as session:
        views = list(
            session.execute(
                select(AuditEvent).where(
                    AuditEvent.event_type == "audit_sql_view", AuditEvent.id != env.ids["view"]
                )
            ).scalars()
        )
    assert len(views) == 1
    assert json.loads(views[0].metadata_json) == {"target_event_id": env.ids["done"]}
    assert views[0].sql_text is None and views[0].query_id == "qry_done"
    # a second read is audited again
    env.get(f"/ext/audit/events/{env.ids['done']}")
    with env.factory() as session:
        count = session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "audit_sql_view")
        ).scalars()
        assert len(list(count)) == 3


def test_detail_of_rejection_and_unknown_event(env: Env) -> None:
    body = env.get(f"/ext/audit/events/{env.ids['denied']}").json()
    assert body["sqlText"] == SECRET_SQL and body["rewrittenSql"] is None
    assert body["accessedFields"] == [] and body["decision"] == "rejected"
    missing = env.get("/ext/audit/events/does-not-exist")
    assert missing.status_code == 404
    with env.factory() as session:
        views = session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "audit_sql_view")
        ).scalars()
        assert len(list(views)) == 2  # the seeded one and the successful read; none for the 404


# ---- stats -------------------------------------------------------------------------------------


def test_stats_aggregate_the_window(env: Env) -> None:
    body = env.get("/ext/audit/stats").json()
    assert body["total"] == 8  # audit_sql_view and the 2 day old event are not queries
    assert body["rejected"] == 3
    assert body["allowed"] == 5  # allowed + errored (they passed the gate)
    assert body["failed"] == 3
    assert body["admissionRejected"] == 1
    assert body["timeouts"] == 1
    assert body["reasonTop"] == [
        {"reason": "admission_queue_full", "count": 1},
        {"reason": "column_not_allowed:ssn", "count": 1},
        {"reason": "table_not_accessible", "count": 1},
    ]
    assert body["from"].endswith("Z") and body["to"].endswith("Z")
    wide = env.get(
        "/ext/audit/stats", **{"from": (naive_now() - timedelta(days=3)).isoformat() + "Z"}
    ).json()
    assert wide["total"] == 9 and wide["rejected"] == 4
    assert wide["reasonTop"][0] == {"reason": "table_not_accessible", "count": 2}


def test_stats_reason_top_is_capped_at_ten(env: Env) -> None:
    with env.factory() as session:
        for n in range(14):
            add(
                session,
                f"r{n}",
                env,
                event_type="sql_rejected",
                decision="denied",
                reason=f"reason_{n:02d}",
            )
        session.commit()
    body = env.get("/ext/audit/stats").json()
    assert len(body["reasonTop"]) == 10
    assert env.get("/ext/audit/stats", **{"from": "x"}).status_code == 422


# ---- scopes ------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/ext/audit/events", "/ext/audit/events/x", "/ext/audit/stats"])
def test_only_admin_scope_keys_may_read_audit(env: Env, path: str) -> None:
    assert env.client.get(path).status_code == 401
    assert env.client.get(path, headers={"X-ADG-API-Key": "nope"}).status_code == 401
    assert env.client.get(path, headers=RUNTIME).status_code == 403
    assert env.client.get(path, headers=ENTRY).status_code == 403
    assert env.client.get(path, headers=ADMIN).status_code in {200, 404}
    with env.factory() as session:
        views = session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "audit_sql_view")
        ).scalars()
        assert len(list(views)) == 1  # refused callers leave no trace of a view
