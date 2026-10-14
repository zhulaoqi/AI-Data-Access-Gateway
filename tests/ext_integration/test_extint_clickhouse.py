import time
from typing import Any

from tests.ext_integration.conftest import Gateway
from tests.ext_integration.test_extint_mysql import provision, query


def ch(gw: Gateway, creds: dict[str, str], **kw: Any) -> str:
    return provision(gw, creds, engine="clickhouse", **kw)


def test_clickhouse_filter_mask_and_scope(
    gateway: Gateway, clickhouse_seed: dict[str, str]
) -> None:
    key = ch(gateway, clickhouse_seed)
    out = query(gateway, key, "SELECT id, phone AS phone FROM shop.orders ORDER BY id")
    assert out["status"] == "success", out
    assert [r["id"] for r in out["rows"]] == [1, 2]
    assert out["rows"][0]["phone"] == "13*******01"
    assert query(gateway, key, "SELECT * FROM shop.orders")["status"] == "rejected"
    assert query(gateway, key, "SELECT ssn FROM shop.orders")["reason"].startswith("column_not")
    system = query(gateway, key, "SELECT name FROM system.tables")
    assert system["status"] == "rejected"


def test_clickhouse_rejects_settings_and_table_functions(
    gateway: Gateway, clickhouse_seed: dict[str, str]
) -> None:
    key = ch(gateway, clickhouse_seed)
    for sql in [
        "SELECT id FROM shop.orders SETTINGS readonly = 0",
        "SELECT id FROM shop.orders FORMAT JSON",
        "SELECT id FROM url('http://x', CSV, 'a Int')",
        "SELECT id FROM shop.orders INTO OUTFILE '/tmp/x'",
    ]:
        out = query(gateway, key, sql)
        assert out["status"] == "rejected", sql


def test_clickhouse_timeout_is_enforced(gateway: Gateway, clickhouse_seed: dict[str, str]) -> None:
    key = ch(
        gateway,
        clickhouse_seed,
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
        "SELECT sum(a.id + b.id + c.id + d.id) AS n FROM shop.big a, shop.big b, shop.big c, shop.big d",
        names=("big",),
    )
    assert out["status"] == "error", out
    assert out["error"]["type"] in {"query_timeout", "connector_operation_error"}
    assert time.monotonic() - started < 10


def test_clickhouse_row_cap(gateway: Gateway, clickhouse_seed: dict[str, str]) -> None:
    key = ch(
        gateway,
        clickhouse_seed,
        limits={
            "maxConcurrency": 1,
            "queueSize": 1,
            "queueTimeoutSeconds": 1,
            "queryTimeoutSeconds": 5,
            "maxRows": 1,
        },
    )
    out = query(gateway, key, "SELECT id FROM shop.orders ORDER BY id")
    assert out["status"] == "success" and len(out["rows"]) == 1 and out["truncated"] is True
