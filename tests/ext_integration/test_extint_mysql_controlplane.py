"""End-to-end queries with a **MySQL control plane** (schema from ``alembic upgrade head``).

Regression for the kind deployment defect: ``audit_events.query_id`` was ``String(36)`` while a
query id is ``qry_<uuid4>`` (40 characters). SQLite ignores the length, MySQL (strict mode) answers
``Data too long``, the pre-execution audit write failed and the fail-closed pipeline refused every
query as ``audit_unavailable``. The other ``test_extint_*`` modules run on SQLite and could not see
it; these run the full runtime and delegated paths against MySQL.
"""

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from tests.ext_integration.conftest import Gateway
from tests.ext_integration.test_extint_delegated import body, entry
from tests.ext_integration.test_extint_mysql import provision, query

from adg.audit.models import AuditEvent

QUERY_ID = re.compile(r"qry_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _events(gw: Gateway, **params: Any) -> list[dict[str, Any]]:
    """List audit events; ``to`` is explicit because MySQL rounds ``created_at`` to the second.

    A row written in the second half of a second is stored as the *next* second, i.e. after the
    default window end (``now``), so an immediate default-window listing can miss it.
    """

    params["to"] = (datetime.now(UTC) + timedelta(minutes=1)).isoformat()
    r = gw.client.get("/ext/audit/events", params=params, headers={"X-ADG-API-Key": gw.admin})
    assert r.status_code == 200, r.text
    items: list[dict[str, Any]] = r.json()["items"]
    return items


def _rows_of(gw: Gateway, query_id: str) -> list[AuditEvent]:
    with gw.factory() as session:
        return list(
            session.execute(select(AuditEvent).where(AuditEvent.query_id == query_id)).scalars()
        )


def test_runtime_query_is_audited_on_a_mysql_control_plane(
    gateway_mysql: Gateway, mysql_seed: dict[str, str]
) -> None:
    gw = gateway_mysql
    key = provision(gw, mysql_seed)
    out = query(gw, key, "SELECT id, phone AS phone FROM shop.orders ORDER BY id")
    assert out["status"] == "success", out  # was: rejected / audit_unavailable
    assert QUERY_ID.fullmatch(out["query_id"]) and len(out["query_id"]) == 40
    rows = _rows_of(gw, out["query_id"])
    assert len(rows) == 1
    meta = json.loads(rows[0].metadata_json)
    assert rows[0].decision == "allowed" and rows[0].event_type == "query_execution"
    assert meta["phase"] == "completed" and meta["rows"] == 2 and meta["channel"] == "mcp"
    # the audit query reads the same row back through the MySQL-backed filters
    assert [i["queryId"] for i in _events(gw, queryId=out["query_id"])] == [out["query_id"]]
    detail = gw.admin_get(f"/ext/audit/events/{rows[0].id}")
    assert detail.status_code == 200 and detail.json()["queryId"] == out["query_id"]


def test_delegated_query_is_audited_on_a_mysql_control_plane(
    gateway_mysql: Gateway, mysql_seed: dict[str, str]
) -> None:
    gw = gateway_mysql
    provision(gw, mysql_seed)
    request_id = "r" * 200  # the longest legal requestId travels in the audit metadata
    r = gw.client.post(
        "/ext/delegated/query",
        json=body("SELECT id FROM shop.orders ORDER BY id", requestId=request_id),
        headers=entry(gw),
    )
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()
    assert out["status"] == "success", out
    rows = _rows_of(gw, out["query_id"])
    assert len(rows) == 1
    meta = json.loads(rows[0].metadata_json)
    assert meta["channel"] == "jdbc" and meta["request_id"] == request_id
    assert [i["queryId"] for i in _events(gw, requestId=request_id)] == [out["query_id"]]


def test_rejections_and_errors_are_audited_on_a_mysql_control_plane(
    gateway_mysql: Gateway, mysql_seed: dict[str, str]
) -> None:
    gw = gateway_mysql
    key = provision(gw, mysql_seed)
    column = query(gw, key, "SELECT ssn FROM shop.orders")
    assert column["status"] == "rejected" and column["reason"].startswith("column_not_allowed")
    erroring = query(gw, key, "SELECT id FROM shop.orders WHERE no_such_column = 1")
    assert erroring["status"] in {"error", "rejected"}
    with gw.factory() as session:
        decisions = {
            e.decision
            for e in session.execute(
                select(AuditEvent).where(AuditEvent.event_type != "audit_sql_view")
            ).scalars()
        }
    assert "denied" in decisions  # the rejection row was written
