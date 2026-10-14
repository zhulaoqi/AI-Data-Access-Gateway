"""Opt-in measurements for PER-1 (extra latency) and the in-flight stall (``ADG_EXT_BENCH=1``).

Not part of the regular suite. The executor runs in a real uvicorn server thread on loopback and
the client is httpx with keep-alive, so the numbers include HTTP and are comparable with
``sql-gateway/scripts/loadtest`` S3 / ``repro_inflight_stall.py`` (same method: alternate a
gateway request and a direct statement on a long-lived connection; 5 grants x 6 concurrent
requests).

    ADG_EXT_BENCH=1 .venv/bin/pytest -q -p no:cacheprovider \
        tests/ext_integration/test_extint_bench.py -s

Knobs: ``BENCH_PAIRS`` (default 300), ``BENCH_ROUNDS`` (default 3), ``ADG_EXT_KDF_CACHE_SIZE=0``
turns the PBKDF2 cache off, ``ADG_SECRET_KDF_ITERATIONS`` sets the iterations used when the
datasource password is stored (read when the datasource is synced).
"""

import os
import socket
import statistics
import threading
import time
from collections import Counter
from collections.abc import Iterator

import httpx
import pymysql
import pytest
import uvicorn
from tests.ext_integration.conftest import MYSQL, Gateway
from tests.ext_integration.test_extint_mysql import provision, target
from tests.ext_integration.test_extint_pool import LIMITS, SLOW, MakeGateway, make_gateway  # noqa: F401

pytestmark = pytest.mark.skipif(os.environ.get("ADG_EXT_BENCH") != "1", reason="opt-in benchmark")


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


@pytest.fixture
def server(make_gateway: MakeGateway) -> Iterator[tuple[Gateway, str]]:  # noqa: F811
    gw, _ = make_gateway(
        int(os.environ.get("ADG_EXT_CONTROL_PLANE_POOL_SIZE", "10")),
        int(os.environ.get("ADG_EXT_CONTROL_PLANE_POOL_MAX_OVERFLOW", "30")),
        float(os.environ.get("ADG_EXT_CONTROL_PLANE_POOL_TIMEOUT_SECONDS", "5")),
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = uvicorn.Config(
        gw.client.app, host="127.0.0.1", port=port, log_level="warning", lifespan="off"
    )
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield gw, f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(timeout=10)


def test_per1_extra_latency(server: tuple[Gateway, str], mysql_seed: dict[str, str]) -> None:
    gw, url = server
    key = provision(gw, mysql_seed)
    ds, ids = target(gw, key)
    pairs = int(os.environ.get("BENCH_PAIRS", "300"))
    payload = {
        "datasource_id": ds,
        "resource_ids": ids,
        "query": "SELECT id, amount FROM shop.orders ORDER BY id",
        "limit": 100,
    }
    conn = pymysql.connect(
        host=MYSQL[0],
        port=MYSQL[1],
        user="gw_ro",
        password="ropw",
        database="shop",
        autocommit=True,
    )
    extra: list[float] = []
    via: list[float] = []
    direct: list[float] = []
    with httpx.Client(base_url=url, headers={"X-ADG-API-Key": key}, timeout=60) as http:
        for _ in range(5):
            assert http.post("/api/tools/execute_query", json=payload).json()["status"] == "success"
        for _ in range(pairs):
            t0 = time.perf_counter()
            with conn.cursor() as c:
                c.execute("SELECT id, amount FROM shop.orders WHERE tenant_id = 7 ORDER BY id")
                c.fetchall()
            d = (time.perf_counter() - t0) * 1000
            t0 = time.perf_counter()
            r = http.post("/api/tools/execute_query", json=payload)
            g = (time.perf_counter() - t0) * 1000
            assert r.json()["status"] == "success", r.text
            direct.append(d)
            via.append(g)
            extra.append(g - d)
    print(
        f"\nPER1 pairs={pairs} cache={os.environ.get('ADG_EXT_KDF_CACHE_SIZE', 'default')} "
        f"kdf={os.environ.get('ADG_SECRET_KDF_ITERATIONS', '390000')}: "
        f"via p50/p95/p99={pct(via, 0.5):.1f}/{pct(via, 0.95):.1f}/{pct(via, 0.99):.1f} "
        f"direct p50/p95={pct(direct, 0.5):.1f}/{pct(direct, 0.95):.1f} "
        f"EXTRA p50/p95/p99={pct(extra, 0.5):.1f}/{pct(extra, 0.95):.1f}/{pct(extra, 0.99):.1f} "
        f"mean={statistics.mean(extra):.1f}",
        flush=True,
    )


def test_inflight_stall(server: tuple[Gateway, str], mysql_seed: dict[str, str]) -> None:
    """5 grants x 6 concurrent requests per round (limit 3 / queue 10 each), the repro's shape."""

    gw, url = server
    limits = {
        "maxConcurrency": 3,
        "queueSize": 10,
        "queueTimeoutSeconds": 30,
        "queryTimeoutSeconds": 2,
        "maxRows": 100,
    }
    keys = [
        provision(gw, mysql_seed, suffix=str(i), limits=limits, with_big=True) for i in range(1, 6)
    ]
    ds, ids = target(gw, keys[0], ("big",))
    rounds = int(os.environ.get("BENCH_ROUNDS", "3"))
    for n in range(rounds):
        results: list[tuple[float, str]] = []

        def one(i: int, results: list[tuple[float, str]] = results) -> None:
            started = time.perf_counter()
            try:
                r = httpx.post(
                    f"{url}/api/tools/execute_query",
                    json={
                        "datasource_id": ds,
                        "resource_ids": ids,
                        "query": SLOW,
                        "limit": 10,
                    },
                    headers={"X-ADG-API-Key": keys[i % 5]},
                    timeout=120,
                )
                out = (
                    r.json()
                    if r.headers.get("content-type", "").startswith("application/json")
                    else {}
                )
                label = (
                    out.get("reason")
                    or (out.get("error") or {}).get("type")
                    or str(out.get("status"))
                )
                results.append((time.perf_counter() - started, f"{r.status_code} {label}"))
            except Exception as error:  # noqa: BLE001
                results.append((time.perf_counter() - started, type(error).__name__))

        threads = [threading.Thread(target=one, args=(i,)) for i in range(30)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        print(
            f"\nSTALL round {n + 1}: fastest {min(r[0] for r in results):.2f}s "
            f"slowest {max(r[0] for r in results):.2f}s {dict(Counter(r[1] for r in results))}",
            flush=True,
        )
