"""Admission control, timeouts with KILL QUERY, revocation, sync lifecycle and scope isolation."""

import threading
import time
from typing import Any

import pymysql
from tests.ext_integration.conftest import MYSQL, Gateway, mysql_conn
from tests.ext_integration.test_extint_mysql import provision, query, sha, target

from adg.control_plane.services.api_key_service import create_api_key
from adg_ext.pipeline import get_admission


def running_sleeps() -> int:
    conn = mysql_conn()
    try:
        with conn.cursor() as c:
            c.execute(
                "SELECT COUNT(*) FROM information_schema.processlist "
                "WHERE info LIKE '%shop.big%' AND info NOT LIKE '%processlist%'"
            )
            return int(c.fetchone()[0])
    finally:
        conn.close()


def test_tenants_see_only_their_own_rows(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    k7 = provision(gateway, mysql_seed, tenant=7, suffix="1")
    k8 = provision(gateway, mysql_seed, tenant=8, suffix="2")
    sql = "SELECT id FROM shop.orders ORDER BY id"
    assert [r["id"] for r in query(gateway, k7, sql)["rows"]] == [1, 2]
    assert [r["id"] for r in query(gateway, k8, sql)["rows"]] == [3]


def test_a_slow_query_is_cancelled_on_the_database(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(
        gateway,
        mysql_seed,
        with_big=True,
        limits={
            "maxConcurrency": 1,
            "queueSize": 1,
            "queueTimeoutSeconds": 1,
            "queryTimeoutSeconds": 1,
            "maxRows": 100,
        },
    )
    started = time.monotonic()
    out = query(
        gateway,
        key,
        "SELECT sum(a.id + b.id + c.id + d.id) AS n FROM shop.big a, shop.big b, shop.big c, shop.big d",  # noqa: E501
        names=("big",),
    )
    elapsed = time.monotonic() - started
    assert out["status"] == "error" and out["error"]["type"] == "query_timeout", out
    assert elapsed < 8
    for _ in range(10):
        if running_sleeps() == 0:
            break
        time.sleep(0.5)
    assert running_sleeps() == 0  # KILL QUERY reached the server


def test_revoking_a_credential_kills_a_running_query(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(
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
    out: list[Any] = []

    def slow() -> None:
        out.append(
            query(
                gateway,
                key,
                "SELECT sum(a.id + b.id + c.id + d.id) AS n FROM shop.big a, shop.big b, shop.big c, shop.big d",  # noqa: E501
                names=("big",),
            )
        )

    th = threading.Thread(target=slow)
    th.start()
    for _ in range(20):
        if running_sleeps() > 0:
            break
        time.sleep(0.25)
    assert running_sleeps() > 0
    assert gateway.delete("credential", "gw:cred:c1").status_code == 204
    th.join(timeout=15)
    assert out and out[0]["status"] == "error" and out[0]["error"]["type"] == "query_cancelled"
    for _ in range(10):
        if running_sleeps() == 0:
            break
        time.sleep(0.5)
    assert running_sleeps() == 0


def test_queue_then_reject_when_full(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    key = provision(
        gateway,
        mysql_seed,
        limits={
            "maxConcurrency": 1,
            "queueSize": 1,
            "queueTimeoutSeconds": 2,
            "queryTimeoutSeconds": 5,
            "maxRows": 100,
        },
    )
    ds, ids = target(gateway, key)
    admission = get_admission()
    user_id = _user_id(gateway)
    # occupy the single slot so that the next request must queue
    holder = admission.acquire(
        user_key=user_id,
        datasource_key=ds,
        max_concurrency=1,
        queue_size=1,
        queue_timeout=1,
    )
    results: list[Any] = []

    def call() -> None:
        r = gateway.tool(
            key,
            "execute_query",
            datasource_id=ds,
            resource_ids=ids,
            query="SELECT id FROM shop.orders",
        )
        results.append(r.json())

    queued = threading.Thread(target=call)
    queued.start()
    time.sleep(0.5)
    snapshot = admission.snapshot()
    assert snapshot["queued"] == 1
    overflow = gateway.tool(
        key, "execute_query", datasource_id=ds, resource_ids=ids, query="SELECT id FROM shop.orders"
    ).json()
    assert overflow["status"] == "rejected" and overflow["reason"] == "admission_queue_full"
    holder.release()
    queued.join(timeout=5)
    assert results and results[0]["status"] == "success"
    assert results[0]["rows"]


def _user_id(gw: Gateway) -> str:
    from sqlalchemy import select

    from adg.control_plane.models.directory import User

    with gw.factory() as session:
        return session.execute(
            select(User.id).where(User.external_ref == "gw:user:g1")
        ).scalar_one()


def test_deleting_a_credential_revokes_it_immediately(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed)
    assert query(gateway, key, "SELECT id FROM shop.orders")["status"] == "success"
    assert gateway.delete("credential", "gw:cred:c1").status_code == 204
    r = gateway.tool(key, "list_datasources")
    assert r.status_code == 401
    assert gateway.delete("credential", "gw:cred:c1").status_code == 204  # idempotent


def test_deleting_a_user_blocks_the_key_too(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    key = provision(gateway, mysql_seed)
    assert gateway.delete("user", "gw:user:g1").status_code == 204
    assert gateway.tool(key, "list_datasources").status_code in {401, 403}


def test_sync_is_idempotent_and_listable_by_prefix(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    provision(gateway, mysql_seed)
    listing = gateway.admin_get("/admin/ext/sync/role?prefix=gw:role:").json()["items"]
    assert [i["name"] for i in listing] == ["gw:role:p1:v1"]
    assert gateway.admin_get("/admin/ext/sync/role?prefix=gw:rf:").json()["items"] == []
    first = listing[0]
    again = gateway.sync("role", first["name"], {"tables": []}, hash_=first["hash"])
    assert again.status_code == 200 and again.json()["externalId"] == first["externalId"]
    # unchanged hash: the stored object was not rewritten (the tables survive)
    key = gateway.keys["1"]
    assert query(gateway, key, "SELECT id FROM shop.orders")["status"] == "success"


def test_objects_without_the_gw_prefix_are_refused(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    assert gateway.sync("role", "plain-role", {"tables": []}).status_code == 400
    assert gateway.delete("role", "plain-role").status_code == 400
    assert gateway.admin_get("/admin/ext/sync/role?prefix=x").status_code == 400
    assert gateway.sync("nonsense", "gw:x", {}).status_code == 404


def test_dependencies_must_exist(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    r = gateway.sync(
        "user",
        "gw:user:gx",
        {"grantId": "gx", "role": "gw:role:missing:v1", "params": {}, "principalName": "x"},
    )
    assert r.status_code == 409


def test_scope_isolation(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    runtime_key = provision(gateway, mysql_seed)
    with gateway.factory() as session:
        create_api_key(session, name="entry", scopes=["entry"], plaintext="adg_entry_key")
        session.commit()
    h = {"X-ADG-API-Key": "adg_entry_key"}
    assert gateway.client.get("/admin/ext/sync/role?prefix=gw:", headers=h).status_code == 403
    assert gateway.client.get("/admin/api-keys", headers=h).status_code == 403
    assert gateway.client.post("/api/tools/list_datasources", json={}, headers=h).status_code == 403
    hr = {"X-ADG-API-Key": runtime_key}
    assert gateway.client.get("/admin/ext/metrics", headers=hr).status_code == 403
    body = {"grantId": "g1", "sql": "SELECT 1", "requestId": "r1"}
    assert gateway.client.post("/ext/delegated/query", json=body, headers=hr).status_code == 403
    admin = {"X-ADG-API-Key": gateway.admin}
    assert gateway.client.post("/ext/delegated/query", json=body, headers=admin).status_code == 403


def test_external_key_hash_on_the_admin_api(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    digest = sha("gateway-made-secret")
    r = gateway.client.post(
        "/admin/api-keys",
        json={"name": "k", "scopes": ["admin"], "key_hash": digest},
        headers={"X-ADG-API-Key": gateway.admin},
    )
    assert r.status_code == 201 and r.json()["api_key"] == ""
    ok = gateway.client.get("/admin/api-keys", headers={"X-ADG-API-Key": "gateway-made-secret"})
    assert ok.status_code == 200
    bad = gateway.client.post(
        "/admin/api-keys",
        json={"name": "k2", "scopes": ["admin"], "key_hash": "nothex"},
        headers={"X-ADG-API-Key": gateway.admin},
    )
    assert bad.status_code == 400


def test_datasource_password_is_not_exposed(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    provision(gateway, mysql_seed)
    body = gateway.admin_get("/admin/datasources").text
    assert mysql_seed["password"] not in body
    assert (
        mysql_seed["password"] not in gateway.admin_get("/admin/ext/sync/datasource_account").text
    )


def test_preview_resource_obeys_the_same_restrictions(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed)
    ds, ids = target(gateway, key)
    r = gateway.tool(key, "preview_resource", resource_id=ids[0], limit=10).json()
    assert r["status"] == "success", r
    assert {row["id"] for row in r["rows"]} == {1, 2}
    assert "ssn" not in r["rows"][0]
    desc = gateway.tool(key, "describe_resource", resource_id=ids[0]).json()
    assert "ssn" not in {c["name"] for c in desc["columns"]}


def test_dry_run_matches_the_live_decision(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    spec = {
        "scope": {
            "tables": [
                {
                    "datasource": "d",
                    "database": "shop",
                    "name": "orders",
                    "columns": {"allow": ["id", "tenant_id"], "deny": [], "mask": {}},
                }
            ]
        },
        "params": [{"name": "tenant_id", "type": "long", "required": True}],
        "row_filter": [
            {
                "datasource": "d",
                "database": "shop",
                "table": "orders",
                "where": "tenant_id = {{tenant_id}}",
            }
        ],
        "operations": {"mode": "read_only"},
        "limits": {"max_rows": 50},
    }
    base = {"dialect": "mysql", "datasource": "d", "spec": spec, "params": {"tenant_id": 7}}
    h = {"X-ADG-API-Key": gateway.admin}
    ok = gateway.client.post(
        "/admin/ext/dry-run", json={**base, "sql": "SELECT id FROM shop.orders"}, headers=h
    ).json()
    assert ok["allowed"] and "tenant_id = 7" in ok["rewrittenSql"] and "50" in ok["rewrittenSql"]
    bad = gateway.client.post(
        "/admin/ext/dry-run", json={**base, "sql": "SELECT * FROM shop.orders"}, headers=h
    ).json()
    assert not bad["allowed"] and bad["hint"]["allowed_columns"]
    other = gateway.client.post(
        "/admin/ext/dry-run", json={**base, "sql": "SELECT id FROM shop.other"}, headers=h
    ).json()
    assert other["rejectReasons"] == ["table_not_accessible"]
    noparam = gateway.client.post(
        "/admin/ext/dry-run",
        json={**base, "params": {}, "sql": "SELECT id FROM shop.orders"},
        headers=h,
    ).json()
    assert noparam["rejectReasons"][0].startswith("row_filter_param_missing")


def test_metrics_are_exposed(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    key = provision(gateway, mysql_seed)
    query(gateway, key, "SELECT id FROM shop.orders")
    m = gateway.admin_get("/admin/ext/metrics").json()
    assert m["counters"]["admitted"] >= 1 and "queued" in m


_ = (pymysql, MYSQL)


def test_audit_failure_refuses_execution(
    gateway: Gateway, mysql_seed: dict[str, str], monkeypatch: Any
) -> None:
    from adg.audit.service import AuditService
    from adg_ext.mysql_scoped import ScopedMySqlConnector

    key = provision(gateway, mysql_seed)
    calls: list[str] = []
    real_execute = ScopedMySqlConnector.execute_query

    def counting(self: Any, *args: Any, **kwargs: Any) -> Any:
        calls.append("executed")
        return real_execute(self, *args, **kwargs)

    monkeypatch.setattr(ScopedMySqlConnector, "execute_query", counting)
    real_record = AuditService.record_event

    def broken(self: Any, **kwargs: Any) -> Any:
        if (kwargs.get("metadata") or {}).get("phase") == "started":
            kwargs["event_type"] = None  # NOT NULL: the pre-execution audit write fails
        return real_record(self, **kwargs)

    monkeypatch.setattr(AuditService, "record_event", broken)
    out = query(gateway, key, "SELECT id FROM shop.orders")
    assert out == {"status": "rejected", "reason": "audit_unavailable"}
    assert calls == []


def test_circuit_breaker_opens_after_repeated_datasource_failures(
    gateway: Gateway, mysql_seed: dict[str, str], monkeypatch: Any
) -> None:
    from adg.connectors.errors import ConnectorOperationError
    from adg_ext.mysql_scoped import ScopedMySqlConnector

    key = provision(gateway, mysql_seed)
    calls: list[int] = []

    def down(self: Any, *args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        raise ConnectorOperationError("server gone") from ConnectionRefusedError("refused")

    monkeypatch.setattr(ScopedMySqlConnector, "execute_query", down)
    for _ in range(5):
        out = query(gateway, key, "SELECT id FROM shop.orders")
        assert out["error"]["type"] == "datasource_unavailable"
    fast = query(gateway, key, "SELECT id FROM shop.orders")
    assert fast == {"status": "rejected", "reason": "admission_circuit_open"}
    assert len(calls) == 5  # the sixth request never reached the datasource
    assert gateway.admin_get("/admin/ext/metrics").json()["breakers"]


def test_a_bad_query_does_not_trip_the_breaker(
    gateway: Gateway, mysql_seed: dict[str, str], monkeypatch: Any
) -> None:
    from adg.connectors.errors import ConnectorOperationError
    from adg_ext.mysql_scoped import ScopedMySqlConnector

    key = provision(gateway, mysql_seed)

    def syntax(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise ConnectorOperationError("(1064) You have an error in your SQL syntax")

    monkeypatch.setattr(ScopedMySqlConnector, "execute_query", syntax)
    for _ in range(8):
        out = query(gateway, key, "SELECT id FROM shop.orders")
        assert out["error"]["type"] == "connector_operation_error"
