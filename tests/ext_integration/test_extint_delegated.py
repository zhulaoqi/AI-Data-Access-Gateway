import json
import threading
import time
from typing import Any

import httpx
from sqlalchemy import select
from tests.ext_integration.conftest import Gateway
from tests.ext_integration.test_extint_mysql import provision, query, sha, target
from tests.ext_integration.test_extint_runtime import _user_id, running_sleeps

from adg.audit.models import AuditEvent
from adg.control_plane.services.api_key_service import create_api_key
from adg_ext import revocation
from adg_ext.pipeline import get_admission


def entry(gw: Gateway) -> dict[str, str]:
    with gw.factory() as session:
        create_api_key(session, name="entry", scopes=["entry"], plaintext="adg_entry_key")
        session.commit()
    return {"X-ADG-API-Key": "adg_entry_key"}


def body(sql: str, **over: Any) -> dict[str, Any]:
    return {
        "grantId": "g1",
        "sql": sql,
        "database": "shop",
        "channel": "jdbc",
        "requestId": "req-1",
        "clientIp": "10.1.2.3",
        **over,
    }


def test_delegated_query_matches_runtime_and_is_audited(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed)
    h = entry(gateway)
    r = gateway.client.post(
        "/ext/delegated/query",
        json=body("SELECT id, phone AS phone FROM shop.orders ORDER BY id"),
        headers=h,
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "success"
    assert [row["id"] for row in out["rows"]] == [1, 2]
    assert out["rows"][0]["phone"] == "13*******01"
    assert {c["name"] for c in out["columns"]} == {"id", "phone"}
    # same rejections as the runtime path
    bad = gateway.client.post(
        "/ext/delegated/query", json=body("SELECT * FROM shop.orders"), headers=h
    )
    assert bad.json()["status"] == "rejected"
    with gateway.factory() as session:
        events = session.execute(
            select(AuditEvent).where(AuditEvent.query_id == out["query_id"])
        ).scalars()
        meta = json.loads(next(iter(events)).metadata_json)
    assert meta["channel"] == "jdbc" and meta["request_id"] == "req-1"
    assert meta["client_ip"] == "10.1.2.3"
    assert key


def test_selected_database_qualifies_tables_the_client_left_unqualified(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    provision(gateway, mysql_seed)
    response = gateway.client.post(
        "/ext/delegated/query",
        json=body("SELECT id FROM orders ORDER BY id"),
        headers=entry(gateway),
    )
    assert response.status_code == 200, response.text
    out = response.json()
    assert out["status"] == "success", out
    assert [row["id"] for row in out["rows"]] == [1, 2]
    with gateway.factory() as session:
        events = session.execute(
            select(AuditEvent).where(AuditEvent.query_id == out["query_id"])
        ).scalars()
        rewritten = [json.loads(event.metadata_json).get("rewritten_sql", "") for event in events]
    assert any("shop.orders" in sql.lower() for sql in rewritten)


def _events(gw: Gateway, **params: Any) -> list[dict[str, Any]]:
    r = gw.client.get("/ext/audit/events", params=params, headers={"X-ADG-API-Key": gw.admin})
    assert r.status_code == 200, r.text
    return list(r.json()["items"])


def test_audit_carries_request_id_and_channel_for_every_outcome(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(
        gateway,
        mysql_seed,
        limits={
            "maxConcurrency": 1,
            "queueSize": 0,
            "queueTimeoutSeconds": 1,
            "queryTimeoutSeconds": 5,
            "maxRows": 100,
        },
    )
    h = entry(gateway)

    def post(sql: str, request_id: str, **over: Any) -> Any:
        return gateway.client.post(
            "/ext/delegated/query", json=body(sql, requestId=request_id, **over), headers=h
        )

    ok = post("SELECT id FROM shop.orders ORDER BY id", "req-ok").json()
    assert ok["status"] == "success"
    wild = post("SELECT * FROM shop.orders", "req-wild").json()
    assert wild["status"] == "rejected"
    column = post("SELECT ssn FROM shop.orders", "req-ssn").json()
    assert column["reason"].startswith("column_not_allowed")
    other = post("SELECT id FROM shop.dim", "req-dim", channel="JDBC").json()
    assert other["reason"] == "table_not_accessible"
    insert = post("DELETE FROM shop.orders", "req-del").json()
    assert insert["status"] == "rejected"

    # admission rejection happens after the guard: hold the only slot
    ds, _ = target(gateway, key)
    holder = get_admission().acquire(
        user_key=_user_id(gateway),
        datasource_key=ds,
        max_concurrency=1,
        queue_size=0,
        queue_timeout=1,
    )
    try:
        busy = post("SELECT id FROM shop.orders", "req-busy").json()
    finally:
        holder.release()
    assert busy["reason"] == "admission_queue_full"

    done = _events(gateway, requestId="req-ok")
    assert [(e["requestId"], e["channel"], e["decision"]) for e in done] == [
        ("req-ok", "jdbc", "allowed")
    ]
    assert done[0]["queryId"] == ok["query_id"] and done[0]["status"] == "completed"
    for request_id, reason in [
        ("req-wild", "wildcard_projection_not_allowed"),
        ("req-ssn", "column_not_allowed:ssn"),
        ("req-dim", "table_not_accessible"),
        ("req-del", None),
        ("req-busy", "admission_queue_full"),
    ]:
        rows = _events(gateway, requestId=request_id)
        assert len(rows) == 1, (request_id, rows)
        row = rows[0]
        assert row["decision"] == "rejected" and row["queryId"] is None
        assert row["requestId"] == request_id and row["channel"] == "jdbc"
        assert row["grantId"] == "g1"
        if reason:
            assert row["reason"] == reason
    detail = gateway.client.get(
        f"/ext/audit/events/{_events(gateway, requestId='req-ssn')[0]['id']}",
        headers={"X-ADG-API-Key": gateway.admin},
    ).json()
    assert detail["requestId"] == "req-ssn" and detail["channel"] == "jdbc"
    assert detail["sqlText"].lower().startswith("select ssn")

    # the channel is normalised; the MCP/HTTP runtime path is ``mcp`` and has no request id
    assert _events(gateway, requestId="req-dim")[0]["channel"] == "jdbc"
    assert query(gateway, key, "SELECT id FROM shop.orders ORDER BY id")["status"] == "success"
    assert query(gateway, key, "SELECT ssn FROM shop.orders")["reason"].startswith("column_not")
    mcp = _events(gateway, channel="mcp")
    assert len(mcp) == 2 and all(e["requestId"] is None for e in mcp)
    assert {e["decision"] for e in mcp} == {"allowed", "rejected"}
    jdbc = _events(gateway, channel="jdbc")
    assert {e["requestId"] for e in jdbc} == {
        "req-ok",
        "req-wild",
        "req-ssn",
        "req-dim",
        "req-del",
        "req-busy",
    }
    assert len(jdbc) == 6
    assert _events(gateway, channel="jdbc", requestId="req-ssn")[0]["reason"].startswith("column")
    assert _events(gateway, channel="mcp", requestId="req-ssn") == []


def test_delegated_validates_request_id_and_channel(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    provision(gateway, mysql_seed)
    h = entry(gateway)
    for over, detail in [
        ({"channel": "x y"}, "invalid_channel"),
        ({"channel": 'jdbc"'}, "invalid_channel"),
        ({"channel": "a" * 33}, "invalid_channel"),
        ({"requestId": "r" * 201}, "requestId_too_long"),
    ]:
        r = gateway.client.post(
            "/ext/delegated/query", json=body("SELECT id FROM shop.orders", **over), headers=h
        )
        assert r.status_code == 400 and r.json()["detail"] == detail, (over, r.text)
    assert _events(gateway) == []  # nothing was executed or audited


def test_delegated_refuses_unknown_revoked_and_expired_grants(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    provision(gateway, mysql_seed)
    h = entry(gateway)
    unknown = gateway.client.post(
        "/ext/delegated/query", json=body("SELECT id FROM shop.orders", grantId="nope"), headers=h
    )
    assert unknown.status_code == 403
    expired = gateway.sync(
        "user",
        "gw:user:g1",
        {
            "grantId": "g1",
            "principalName": "Alice",
            "role": "gw:role:p1:v1",
            "params": {"tenant_id": 7},
            "expiresAt": 1_000,
        },
    )
    assert expired.status_code == 200
    r = gateway.client.post(
        "/ext/delegated/query", json=body("SELECT id FROM shop.orders"), headers=h
    )
    assert r.status_code == 403 and r.json()["detail"] == "grant_expired"
    assert gateway.delete("user", "gw:user:g1").status_code == 204
    r = gateway.client.post(
        "/ext/delegated/query", json=body("SELECT id FROM shop.orders"), headers=h
    )
    assert r.status_code == 403 and r.json()["detail"] == "grant_not_active"


def test_delegated_query_can_be_cancelled_by_request_id(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    provision(
        gateway,
        mysql_seed,
        with_big=True,
        limits={
            "maxConcurrency": 1,
            "queueSize": 1,
            "queueTimeoutSeconds": 1,
            "queryTimeoutSeconds": 30,
            "maxRows": 100,
        },
    )
    h = entry(gateway)
    out: list[Any] = []

    def slow() -> None:
        out.append(
            gateway.client.post(
                "/ext/delegated/query",
                json=body(
                    "SELECT sum(a.id + b.id + c.id + d.id) AS n "
                    "FROM shop.big a, shop.big b, shop.big c, shop.big d",
                    requestId="slow-1",
                ),
                headers=h,
            ).json()
        )

    th = threading.Thread(target=slow)
    th.start()
    for _ in range(20):
        if running_sleeps() > 0:
            break
        time.sleep(0.25)
    assert running_sleeps() > 0
    cancelled = gateway.client.delete("/ext/delegated/query/slow-1", headers=h).json()
    assert cancelled["cancelled"] == 1
    th.join(timeout=15)
    assert out[0]["error"]["type"] == "query_cancelled"
    for _ in range(10):
        if running_sleeps() == 0:
            break
        time.sleep(0.5)
    assert running_sleeps() == 0


def test_revocation_list_blocks_a_key_and_kills_its_running_query(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed, with_big=True)
    state = {"entries": [], "version": 1, "full": True}
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "version": state["version"],
                    "full": state["full"],
                    "hasMore": False,
                    "entries": state["entries"],
                },
            },
        )

    now = [0.0]
    cache = revocation.RevocationCache(
        "http://mgmt/revocations",
        "gwr_token",
        ttl=5,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: now[0],
    )
    from sqlalchemy import select as sel

    from adg.control_plane.models.api_key import ApiKey
    from adg_ext.app import get_admission

    def on_new(hashes: set[str]) -> None:
        with gateway.factory() as session:
            for kid in session.execute(sel(ApiKey.id).where(ApiKey.key_hash.in_(hashes))).scalars():
                get_admission().revoke(kid)

    cache.on_new = on_new
    revocation.reset_cache(cache)
    assert gateway.tool(key, "list_datasources").status_code == 200
    assert seen == ["Bearer gwr_token"]
    # within the ttl nothing is fetched again
    assert gateway.tool(key, "list_datasources").status_code == 200
    assert len(seen) == 1
    now[0] = 6
    state.update(
        entries=[{"hash": sha(key), "reason": "revoked", "at": "x", "version": 2}],
        version=2,
        full=False,
    )
    assert gateway.tool(key, "list_datasources").status_code == 401
    # an unreachable management service keeps the last list
    now[0] = 20

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    cache._client = httpx.Client(transport=httpx.MockTransport(down))
    assert gateway.tool(key, "list_datasources").status_code == 401
