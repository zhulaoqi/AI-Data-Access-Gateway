import time
from typing import Any

import pytest
from tests.ext_integration.conftest import CLICKHOUSE, Gateway
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
        "SELECT sum(a.id + b.id + c.id + d.id) AS n FROM shop.big a, shop.big b, shop.big c, shop.big d",  # noqa: E501
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


@pytest.fixture
def clickhouse_column_grants(clickhouse_seed: dict[str, str]) -> dict[str, str]:
    """An account with column-level grants only: ClickHouse then hides ``ssn`` from the catalog."""

    import clickhouse_connect

    admin = clickhouse_connect.get_client(
        host=CLICKHOUSE[0], port=CLICKHOUSE[1], username="root", password="rootpw"
    )
    try:
        admin.command("DROP USER IF EXISTS gw_cols")
        admin.command("CREATE USER gw_cols IDENTIFIED BY 'colspw'")
        admin.command(
            "GRANT SELECT(id, tenant_id, phone, amount, created_at) ON shop.orders TO gw_cols"
        )
        admin.command("GRANT SELECT ON system.* TO gw_cols")
    finally:
        admin.close()
    return {"user": "gw_cols", "password": "colspw"}


def test_clickhouse_unlisted_column_is_a_guard_rejection_not_a_database_error(
    gateway: Gateway, clickhouse_column_grants: dict[str, str]
) -> None:
    import clickhouse_connect

    # premise: the database itself refuses the column, and the account's catalog does not list it
    direct = clickhouse_connect.get_client(
        host=CLICKHOUSE[0], port=CLICKHOUSE[1], username="gw_cols", password="colspw"
    )
    try:
        with pytest.raises(Exception, match="ACCESS_DENIED|Not enough privileges"):
            direct.query("SELECT ssn FROM shop.orders")
        listed = {
            r[0]
            for r in direct.query(
                "SELECT name FROM system.columns WHERE database = 'shop' AND table = 'orders'"
            ).result_rows
        }
    finally:
        direct.close()
    assert "ssn" not in listed and "id" in listed

    key = ch(gateway, clickhouse_column_grants)
    for sql in [
        "SELECT ssn FROM shop.orders",
        "SELECT id FROM shop.orders WHERE ssn = '111'",
        "SELECT id FROM shop.orders ORDER BY ssn",
        "SELECT id FROM (SELECT id, ssn FROM shop.orders) t",
        "SELECT id FROM shop.orders WHERE no_such_column = 1",
    ]:
        out = query(gateway, key, sql)
        assert out["status"] == "rejected", (sql, out)  # same shape as MySQL, not "error"
        assert out["reason"].startswith("column_not_allowed:"), (sql, out)
    ok = query(gateway, key, "SELECT id, amount AS a FROM shop.orders WHERE a > 1 ORDER BY id")
    assert ok["status"] == "success" and [r["id"] for r in ok["rows"]] == [1, 2]
