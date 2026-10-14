"""PA-7 audit queries against real engines.

* ``test_audit_trail_of_real_queries``: real queries on MySQL 8.4 (success, rejections, admission,
  timeout) produce audit rows that the three endpoints list, filter, detail and aggregate.
* the ``test_*`` functions of the unit module re-run with the control-plane database on MySQL, so
  the ``LIKE ... ESCAPE``, conditional aggregation and ordering are checked on that dialect.
"""

import json
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import select
from tests.ext import test_ext_audit_query as unit
from tests.ext_integration.conftest import Gateway, mysql_conn
from tests.ext_integration.test_extint_mysql import provision, query, target
from tests.ext_integration.test_extint_runtime import _user_id, running_sleeps

from adg.audit.models import AuditEvent
from adg_ext.pipeline import get_admission

for _name, _fn in vars(unit).items():
    if _name.startswith("test_") and _name not in {
        "test_like_escape_neutralises_wildcards_and_the_escape_character",
        "test_parse_instant_accepts_iso_offsets_and_epoch_millis",
        "test_window_defaults_to_the_last_24_hours_and_is_validated",
    }:
        globals()[_name] = _fn


@pytest.fixture
def env(engines: None, monkeypatch: pytest.MonkeyPatch) -> Iterator[unit.Env]:
    conn = mysql_conn()
    with conn.cursor() as c:
        c.execute("CREATE DATABASE IF NOT EXISTS adg_audit_cp CHARACTER SET utf8mb4")
    conn.close()
    yield from unit.run_env(
        "mysql+pymysql://root:rootpw@127.0.0.1:33306/adg_audit_cp?charset=utf8mb4", monkeypatch
    )


def audit(gw: Gateway, path: str, **params: Any) -> Any:
    return gw.client.get(path, params=params, headers={"X-ADG-API-Key": gw.admin})


def test_audit_trail_of_real_queries(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    key = provision(
        gateway,
        mysql_seed,
        with_big=True,
        limits={
            "maxConcurrency": 1,
            "queueSize": 1,
            "queueTimeoutSeconds": 2,
            "queryTimeoutSeconds": 1,
            "maxRows": 100,
        },
    )
    ok = query(gateway, key, "SELECT id, phone AS phone FROM shop.orders ORDER BY id")
    assert ok["status"] == "success"
    column = query(gateway, key, "SELECT ssn FROM shop.orders")
    assert column["reason"].startswith("column_not_allowed")
    other = query(gateway, key, "SELECT id FROM shop.dim")
    assert other["reason"] == "table_not_accessible"

    # admission: hold the slot, queue one request, overflow the next
    ds, ids = target(gateway, key)
    admission = get_admission()
    holder = admission.acquire(
        user_key=_user_id(gateway),
        datasource_key=ds,
        max_concurrency=1,
        queue_size=1,
        queue_timeout=1,
    )
    queued = threading.Thread(
        target=lambda: gateway.tool(
            key,
            "execute_query",
            datasource_id=ds,
            resource_ids=ids,
            query="SELECT id FROM shop.orders",
        )
    )
    queued.start()
    time.sleep(0.5)
    overflow = gateway.tool(
        key, "execute_query", datasource_id=ds, resource_ids=ids, query="SELECT id FROM shop.orders"
    ).json()
    assert overflow["reason"] == "admission_queue_full"
    holder.release()
    queued.join(timeout=5)

    slow = query(
        gateway,
        key,
        "SELECT sum(a.id + b.id + c.id + d.id) AS n FROM shop.big a, shop.big b, shop.big c, shop.big d",  # noqa: E501
        names=("big",),
    )
    assert slow["error"]["type"] == "query_timeout"
    for _ in range(10):
        if running_sleeps() == 0:
            break
        time.sleep(0.5)

    # ---- list: filters, no SQL
    listing = audit(gateway, "/ext/audit/events", eventType="query_execution")
    assert listing.status_code == 200, listing.text
    assert "SELECT" not in listing.text and "sqlText" not in listing.text
    by_status = {i["status"]: i for i in listing.json()["items"]}
    assert set(by_status) >= {"completed", "timeout"}
    done = by_status["completed"]
    assert done["grantId"] == "g1" and done["rowCount"] == 2
    assert done["durationMs"] is not None and done["queueWaitMs"] is not None
    assert done["queryId"] == ok["query_id"] and done["decision"] == "allowed"
    assert by_status["timeout"]["decision"] == "error"
    assert by_status["timeout"]["reason"] == "query_timeout"

    def reasons(**params: Any) -> list[str | None]:
        return [i["reason"] for i in audit(gateway, "/ext/audit/events", **params).json()["items"]]

    assert reasons(reason="table_not_accessible") == ["table_not_accessible"]
    assert reasons(reason="column_not_allowed", decision="rejected") == [column["reason"]]
    assert reasons(reason="admission_queue_full") == ["admission_queue_full"]
    assert reasons(status="timeout") == ["query_timeout"]
    assert len(reasons(grantIds="g1")) == len(reasons())
    assert reasons(grantIds="someone-else") == []
    orders = audit(gateway, "/ext/audit/events", table="orders").json()
    assert orders["total"] >= 2  # real resource ids resolved from the scanned table path
    # rejections record the *declared* resources, so a table that was never declared has no events
    assert audit(gateway, "/ext/audit/events", table="shop.dim").json()["total"] == 0
    assert audit(gateway, "/ext/audit/events", table="%").json()["total"] == 0

    # ---- stats
    stats = audit(gateway, "/ext/audit/stats").json()
    assert stats["total"] == stats["allowed"] + stats["rejected"]
    assert stats["rejected"] >= 3 and stats["admissionRejected"] == 1 and stats["timeouts"] == 1
    top = {t["reason"]: t["count"] for t in stats["reasonTop"]}
    assert top["table_not_accessible"] == 1 and top["admission_queue_full"] == 1
    assert len(stats["reasonTop"]) <= 10

    # ---- detail: SQL, rewritten SQL, and the read is audited
    detail = audit(gateway, f"/ext/audit/events/{done['id']}").json()
    assert detail["sqlText"].lower().startswith("select")
    assert "tenant_id" in detail["rewrittenSql"]  # the row filter was injected
    assert set(detail["accessedFields"]) >= {"id", "phone"}
    with gateway.factory() as session:
        views = list(
            session.execute(
                select(AuditEvent).where(AuditEvent.event_type == "audit_sql_view")
            ).scalars()
        )
    assert len(views) == 1
    assert json.loads(views[0].metadata_json)["target_event_id"] == done["id"]
    assert views[0].sql_text is None

    # ---- scopes: a runtime key (and an unknown one) are refused
    runtime = gateway.client.get("/ext/audit/stats", headers={"X-ADG-API-Key": key})
    assert runtime.status_code == 403
    assert gateway.client.get("/ext/audit/stats").status_code == 401
