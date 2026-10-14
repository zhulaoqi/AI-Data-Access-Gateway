"""Control-plane pool exhaustion: bounded wait, 503 ``admission_pool_exhausted``, no leaked slots.

Reproduces the loadtest finding (several grants queueing at once: every request stalled for the
pool timeout and then failed with a 500). Real MySQL 8.4 is the queried datasource; the control
plane is a file SQLite database behind a deliberately tiny SQLAlchemy ``QueuePool``.
"""

import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from tests.ext_integration.conftest import Gateway
from tests.ext_integration.test_extint_delegated import body, entry
from tests.ext_integration.test_extint_mysql import provision, target

from adg.app.auth_rate_limit import reset_auth_rate_limiter
from adg.app.main import create_app
from adg.app.settings import get_settings
from adg.connectors.registry import get_connector_registry
from adg.control_plane.db import create_engine_from_url, create_session_factory
from adg.control_plane.models import Base
from adg.control_plane.services.api_key_service import create_api_key
from adg_ext import kdf_cache, pipeline, revocation
from adg_ext.config import get_ext_settings
from adg_ext.pipeline import get_admission

SLOW = (
    "SELECT sum(a.id + b.id + c.id + d.id) AS n FROM shop.big a, shop.big b, shop.big c, shop.big d"  # noqa: E501
)
LIMITS = {
    "maxConcurrency": 1,
    "queueSize": 8,
    "queueTimeoutSeconds": 30,
    "queryTimeoutSeconds": 1,
    "maxRows": 100,
}

MakeGateway = Callable[..., tuple[Gateway, Any]]


@pytest.fixture
def make_gateway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engines: None
) -> Iterator[MakeGateway]:
    registry = get_connector_registry()
    saved = dict(registry._connectors)

    def build(pool_size: int, overflow: int, timeout: float, **env: str) -> tuple[Gateway, Any]:
        monkeypatch.setenv("ADG_EXT_ENABLED", "true")
        monkeypatch.setenv("ADG_DATASOURCE_NETWORK_ALLOWLIST", "127.0.0.1")
        monkeypatch.setenv("ADG_RUNTIME_QUERY_MAX_LIMIT", "1000")
        monkeypatch.setenv("ADG_EXT_CONTROL_PLANE_POOL_SIZE", str(pool_size))
        monkeypatch.setenv("ADG_EXT_CONTROL_PLANE_POOL_MAX_OVERFLOW", str(overflow))
        monkeypatch.setenv("ADG_EXT_CONTROL_PLANE_POOL_TIMEOUT_SECONDS", str(timeout))
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        get_settings.cache_clear()
        get_ext_settings.cache_clear()
        pipeline.reset_admission()
        revocation.reset_cache()
        kdf_cache.reset_kdf_cache()
        engine = create_engine_from_url(f"sqlite:///{tmp_path / 'cp-pool.db'}")
        Base.metadata.create_all(engine)
        factory = create_session_factory(engine)
        with factory() as session:
            create_api_key(session, name="admin", scopes=["admin"], plaintext="adg_admin_test_key")
            session.commit()
        client = TestClient(create_app(session_factory=factory), raise_server_exceptions=False)
        return Gateway(client, factory, "adg_admin_test_key"), engine

    yield build
    registry._connectors.clear()
    registry._connectors.update(saved)
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()
    kdf_cache.reset_kdf_cache()
    reset_auth_rate_limiter()


def test_pool_settings_reach_the_engine(make_gateway: MakeGateway) -> None:
    _, engine = make_gateway(3, 2, 1.5)
    assert engine.pool.size() == 3
    assert engine.pool._max_overflow == 2
    assert engine.pool.timeout() == 1.5


@pytest.mark.parametrize("path", ["runtime", "delegated"])
def test_queued_requests_do_not_pin_connections_and_nothing_leaks(
    make_gateway: MakeGateway, mysql_seed: dict[str, str], path: str
) -> None:
    """More in-flight requests than pooled connections, most of them waiting in the admission queue.

    Before the fix every queued request kept the connection its authentication opened, the running
    one could not write its audit row, and everything stalled for the pool timeout and then failed.
    """

    gw, engine = make_gateway(2, 1, 4)
    keys = [
        provision(gw, mysql_seed, suffix=str(i), limits=LIMITS, with_big=True) for i in range(1, 3)
    ]
    ds, ids = target(gw, keys[0], ("big",))
    headers = entry(gw)
    results: list[tuple[float, int, str]] = []

    def one(i: int) -> None:
        started = time.perf_counter()
        if path == "runtime":
            r = gw.tool(
                keys[i % 2],
                "execute_query",
                datasource_id=ds,
                resource_ids=ids,
                query=SLOW,
                limit=10,
            )
        else:
            r = gw.client.post(
                "/ext/delegated/query",
                json=body(SLOW, grantId=f"g{i % 2 + 1}", requestId=f"r{i}", database="shop"),
                headers=headers,
            )
        out = r.json()
        label = out.get("reason") or (out.get("error") or {}).get("type") or str(out.get("status"))
        results.append((time.perf_counter() - started, r.status_code, label))

    threads = [threading.Thread(target=one, args=(i,)) for i in range(8)]
    began = time.perf_counter()
    [t.start() for t in threads]
    [t.join(timeout=60) for t in threads]
    elapsed = time.perf_counter() - began

    assert len(results) == 8
    codes = Counter(code for _, code, _ in results)
    labels = Counter(label for _, _, label in results)
    # each grant runs its statements one after another (limit 1, 1 s query timeout) while the
    # others wait in the queue: all eight get their turn; none is refused for lack of a connection
    # (the pool has 3, the pool timeout is 4 s, eight requests are in flight)
    assert codes == {200: 8}, (codes, labels)
    assert labels == {"query_timeout": 8}, labels
    assert elapsed < 15, (elapsed, labels)
    # every slot and connection is back
    snapshot = get_admission().snapshot()
    assert snapshot["running"] == 0 and snapshot["queued"] == 0
    assert snapshot["datasource_running"] == {ds: 0}
    assert engine.pool.checkedout() == 0


def test_a_request_without_a_connection_gets_503_not_a_hang_or_500(
    make_gateway: MakeGateway, mysql_seed: dict[str, str]
) -> None:
    gw, engine = make_gateway(1, 0, 1)
    key = provision(gw, mysql_seed)
    ds, ids = target(gw, key)
    headers = entry(gw)

    holder = engine.connect()  # the only pooled connection
    try:
        started = time.perf_counter()
        runtime = gw.tool(
            key,
            "execute_query",
            datasource_id=ds,
            resource_ids=ids,
            query="SELECT id FROM shop.orders",
        )
        delegated = gw.client.post(
            "/ext/delegated/query",
            json=body("SELECT id FROM shop.orders", requestId="r-pool"),
            headers=headers,
        )
        elapsed = time.perf_counter() - started
    finally:
        holder.close()

    for r in (runtime, delegated):
        assert r.status_code == 503, r.text
        assert r.headers["retry-after"] == "1"
        out = r.json()
        assert out["status"] == "rejected"
        assert out["reason"] == out["detail"] == "admission_pool_exhausted"
        assert out["retry_after_seconds"] == 1
        # no credentials or SQL in the refusal
        assert key not in r.text and "SELECT" not in r.text
    assert elapsed < 6, elapsed  # two requests, ~1 s pool timeout each; the default was 30 s
    # the process recovers as soon as a connection is free
    ok = gw.tool(
        key, "execute_query", datasource_id=ds, resource_ids=ids, query="SELECT id FROM shop.orders"
    )
    assert ok.status_code == 200 and ok.json()["status"] == "success"
    # the refusal is visible in the metrics under the same vocabulary as the other admission_* codes
    metrics = gw.admin_get("/admin/ext/metrics/prometheus").text
    assert 'adg_ext_query_rejected_total{reason="admission_pool_exhausted"} 2' in metrics
    assert 'adg_ext_admission_rejected_total{reason="pool_exhausted"} 2' in metrics


def test_losing_the_pool_after_admission_releases_the_slot(
    make_gateway: MakeGateway, mysql_seed: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The audit row cannot be written for lack of a connection: 503, slot and breaker released."""

    from sqlalchemy import exc as sa_exc

    from adg.audit.service import AuditService

    gw, engine = make_gateway(2, 0, 1)
    key = provision(gw, mysql_seed)
    ds, ids = target(gw, key)

    def starved(*args: Any, **kwargs: Any) -> None:
        raise sa_exc.TimeoutError("QueuePool limit of size 2 overflow 0 reached")

    monkeypatch.setattr(AuditService, "record_event", starved)
    r = gw.tool(
        key, "execute_query", datasource_id=ds, resource_ids=ids, query="SELECT id FROM shop.orders"
    )
    assert r.status_code == 503 and r.json()["reason"] == "admission_pool_exhausted"
    snapshot = get_admission().snapshot()
    assert snapshot["running"] == 0 and snapshot["datasource_running"][ds] == 0
    assert snapshot["breakers"].get(ds, "closed") == "closed"
    assert engine.pool.checkedout() == 0


def test_datasource_admission_never_exceeds_the_runtime_pool(
    make_gateway: MakeGateway, mysql_seed: dict[str, str]
) -> None:
    """Admitting more statements than the connector pool has connections would park the rest in
    the pool (outside the queue and its timeout); the effective limit is capped at the pool."""

    gw, _ = make_gateway(
        2,
        1,
        2,
        ADG_RUNTIME_DATASOURCE_POOL_SIZE="2",
        ADG_RUNTIME_DATASOURCE_POOL_MAX_OVERFLOW="1",
        ADG_EXT_DATASOURCE_MAX_CONCURRENCY="20",
    )
    key = provision(gw, mysql_seed)
    ds, ids = target(gw, key)
    assert pipeline.effective_datasource_limit() == 3
    assert get_admission().datasource_limit == 3
    assert (
        gw.tool(
            key,
            "execute_query",
            datasource_id=ds,
            resource_ids=ids,
            query="SELECT id FROM shop.orders",
        ).json()["status"]
        == "success"
    )
    metrics = gw.admin_get("/admin/ext/metrics/prometheus").text
    assert f'adg_ext_admission_datasource_limit{{datasource="{ds}"}} 3' in metrics
