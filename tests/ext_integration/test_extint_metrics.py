"""Prometheus counters move when the state changes, against real MySQL 8.4 and the live pipeline."""

import threading
import time
from typing import Any

import httpx
from tests.ext.test_ext_metrics import Clock, parse, value
from tests.ext_integration.conftest import Gateway
from tests.ext_integration.test_extint_mysql import provision, query, target
from tests.ext_integration.test_extint_runtime import _user_id, running_sleeps

from adg_ext import revocation
from adg_ext.config import get_ext_settings
from adg_ext.pipeline import get_admission, reset_admission

SLOW = (
    "SELECT sum(a.id + b.id + c.id + d.id) AS n FROM shop.big a, shop.big b, shop.big c, shop.big d"  # noqa: E501
)


def prom(gw: Gateway) -> dict[Any, float]:
    r = gw.admin_get("/admin/ext/metrics/prometheus")
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
    return parse(r.text)


def total(s: dict[Any, float], outcome: str) -> float:
    return value(s, "adg_ext_query_total", outcome=outcome)


def test_completed_and_rejected_counters_follow_real_queries(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed)
    before = prom(gateway)
    assert total(before, "completed") == 0 and total(before, "rejected") == 0

    assert query(gateway, key, "SELECT id FROM shop.orders")["status"] == "success"
    assert query(gateway, key, "SELECT id FROM shop.orders")["status"] == "success"
    assert query(gateway, key, "SELECT ssn FROM shop.orders")["status"] == "rejected"
    assert query(gateway, key, "SELECT id FROM shop.dim", names=("orders",))["status"] == "rejected"

    after = prom(gateway)
    assert total(after, "completed") == 2
    assert total(after, "rejected") == 2
    assert total(after, "failed") == total(after, "timeout") == total(after, "cancelled") == 0
    # reason codes are cut at the colon: the denied column name is not a label value
    assert value(after, "adg_ext_query_rejected_total", reason="column_not_allowed") == 1
    assert value(after, "adg_ext_query_rejected_total", reason="table_not_accessible") == 1
    assert value(after, "adg_ext_admission_admitted_total") == 2
    assert value(after, "adg_ext_admission_wait_seconds_count") == 2
    text = gateway.admin_get("/admin/ext/metrics/prometheus").text
    assert "ssn" not in text and "adg_key_1_secret" not in text and "SELECT" not in text
    # the JSON snapshot is still served, unchanged in shape
    assert gateway.admin_get("/admin/ext/metrics").json()["counters"]["admitted"] == 2


def test_timeout_counter_and_wait_histogram(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
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
    out = query(gateway, key, SLOW, names=("big",))
    assert out["status"] == "error" and out["error"]["type"] == "query_timeout"
    s = prom(gateway)
    assert total(s, "timeout") == 1 and total(s, "completed") == 0
    assert value(s, "adg_ext_admission_wait_seconds_bucket", le="+Inf") == 1
    for _ in range(10):  # leave no query running on the shared server
        if running_sleeps() == 0:
            break
        time.sleep(0.5)


def test_cancelled_counter_after_revocation(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
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
    th = threading.Thread(target=lambda: out.append(query(gateway, key, SLOW, names=("big",))))
    th.start()
    for _ in range(20):
        if running_sleeps() > 0:
            break
        time.sleep(0.25)
    assert running_sleeps() > 0
    assert prom(gateway)["adg_ext_admission_running", ()] == 1
    assert gateway.delete("credential", "gw:cred:c1").status_code == 204
    th.join(timeout=15)
    assert out and out[0]["error"]["type"] == "query_cancelled"
    s = prom(gateway)
    assert total(s, "cancelled") == 1 and total(s, "timeout") == 0
    assert s["adg_ext_admission_running", ()] == 0
    for _ in range(10):
        if running_sleeps() == 0:
            break
        time.sleep(0.5)


def test_failed_counter_when_the_datasource_errors(
    gateway: Gateway, mysql_seed: dict[str, str], monkeypatch: Any
) -> None:
    from adg.connectors.errors import ConnectorOperationError
    from adg_ext.mysql_scoped import ScopedMySqlConnector

    key = provision(gateway, mysql_seed)

    def broken(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise ConnectorOperationError("(1064) You have an error in your SQL syntax")

    monkeypatch.setattr(ScopedMySqlConnector, "execute_query", broken)
    assert query(gateway, key, "SELECT id FROM shop.orders")["status"] == "error"
    s = prom(gateway)
    assert total(s, "failed") == 1 and total(s, "completed") == 0


def test_audit_unavailable_counter(
    gateway: Gateway, mysql_seed: dict[str, str], monkeypatch: Any
) -> None:
    from adg.audit.service import AuditService

    key = provision(gateway, mysql_seed)
    real_record = AuditService.record_event

    def broken(self: Any, **kwargs: Any) -> Any:
        if (kwargs.get("metadata") or {}).get("phase") == "started":
            kwargs["event_type"] = None  # NOT NULL: the pre-execution audit write fails
        return real_record(self, **kwargs)

    monkeypatch.setattr(AuditService, "record_event", broken)
    assert prom(gateway)["adg_ext_audit_unavailable_total", ()] == 0
    out = query(gateway, key, "SELECT id FROM shop.orders")
    assert out == {"status": "rejected", "reason": "audit_unavailable"}
    s = prom(gateway)
    assert s["adg_ext_audit_unavailable_total", ()] == 1
    assert total(s, "rejected") == 1 and total(s, "completed") == 0
    assert value(s, "adg_ext_query_rejected_total", reason="audit_unavailable") == 1
    query(gateway, key, "SELECT id FROM shop.orders")
    assert prom(gateway)["adg_ext_audit_unavailable_total", ()] == 2


def test_queue_rejections_and_wait_histogram(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    key = provision(
        gateway,
        mysql_seed,
        limits={
            "maxConcurrency": 1,
            "queueSize": 1,
            "queueTimeoutSeconds": 1,
            "queryTimeoutSeconds": 5,
            "maxRows": 100,
        },
    )
    ds, ids = target(gateway, key)
    holder = get_admission().acquire(
        user_key=_user_id(gateway),
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
    time.sleep(0.3)  # the first request is waiting in the single queue place
    overflow = gateway.tool(
        key, "execute_query", datasource_id=ds, resource_ids=ids, query="SELECT id FROM shop.orders"
    ).json()
    assert overflow["reason"] == "admission_queue_full"
    queued.join(timeout=5)
    assert results[0]["reason"] == "admission_queue_timeout"
    holder.release()

    s = prom(gateway)
    assert total(s, "rejected") == 2
    assert value(s, "adg_ext_query_rejected_total", reason="admission_queue_full") == 1
    assert value(s, "adg_ext_query_rejected_total", reason="admission_queue_timeout") == 1
    assert value(s, "adg_ext_admission_rejected_total", reason="queue_timeout") == 1
    assert value(s, "adg_ext_admission_rejected_total", reason="queue_full") == 1
    # the holder (instant) and the timed-out waiter (about 1 s); queue_full waited for nothing
    assert value(s, "adg_ext_admission_wait_seconds_count") == 2
    assert value(s, "adg_ext_admission_wait_seconds_sum") >= 0.9
    assert value(s, "adg_ext_admission_wait_seconds_bucket", le="0.5") == 1
    assert value(s, "adg_ext_admission_wait_seconds_bucket", le="2.5") == 2


def test_datasource_limit_matches_the_setting(
    gateway: Gateway, mysql_seed: dict[str, str], monkeypatch: Any
) -> None:
    monkeypatch.setenv("ADG_EXT_DATASOURCE_MAX_CONCURRENCY", "5")
    get_ext_settings.cache_clear()
    reset_admission()
    key = provision(gateway, mysql_seed)
    assert query(gateway, key, "SELECT id FROM shop.orders")["status"] == "success"
    ds, _ = target(gateway, key)
    s = prom(gateway)
    assert value(s, "adg_ext_admission_datasource_limit", datasource=ds) == 5
    assert value(s, "adg_ext_admission_datasource_running", datasource=ds) == 0
    assert value(s, "adg_ext_admission_breaker_state", datasource=ds) == 0


def test_revocation_poll_age_grows_when_the_management_service_is_down(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    provision(gateway, mysql_seed)
    up = {"ok": True}

    def handler(request: httpx.Request) -> httpx.Response:
        if not up["ok"]:
            raise httpx.ConnectError("down")
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {"version": 1, "full": True, "hasMore": False, "entries": []},
            },
        )

    clock = Clock()
    cache = revocation.RevocationCache(
        "http://mgmt/revocations",
        "gwr_token",
        ttl=5,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=clock,
    )
    revocation.reset_cache(cache)
    cache.refresh()
    assert prom(gateway)["adg_ext_revocation_poll_age_seconds", ()] == 0
    up["ok"] = False
    clock.now += 90
    cache.refresh()  # fails: the list is kept, the age keeps growing
    assert prom(gateway)["adg_ext_revocation_poll_age_seconds", ()] == 90
    up["ok"] = True
    clock.now += 10
    cache.refresh()
    assert prom(gateway)["adg_ext_revocation_poll_age_seconds", ()] == 0


def test_prometheus_endpoint_is_admin_only(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    runtime_key = provision(gateway, mysql_seed)
    url = "/admin/ext/metrics/prometheus"
    assert gateway.client.get(url, headers={"X-ADG-API-Key": runtime_key}).status_code == 403
    assert gateway.client.get(url).status_code == 401
    assert gateway.admin_get(url).status_code == 200
