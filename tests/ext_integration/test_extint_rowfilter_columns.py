"""N-2: a row filter must work for an account that only has *column-level* ``SELECT``.

The management service provisions the database account with column-level grants (least privilege).
The executor used to rewrite a filtered table into ``(SELECT * FROM t WHERE ...) AS t``; MySQL
refuses ``SELECT *`` unless every column is granted (error 1142/1143), so every query failed.
These tests run against the real engines with exactly that kind of account.
"""

from typing import Any

import pymysql
import pytest
from tests.ext_integration.conftest import CLICKHOUSE, MYSQL, Gateway, mysql_conn
from tests.ext_integration.test_extint_mysql import provision, query

ALLOWED = "id, tenant_id, phone, amount, created_at"


@pytest.fixture
def mysql_column_grants(mysql_seed: dict[str, str]) -> dict[str, str]:
    """Column-level ``SELECT`` on the allowed columns (never ``ssn``) plus table ``REFERENCES``.

    This mirrors what the management service's MySQL provisioner grants.
    """

    conn = mysql_conn()
    try:
        with conn.cursor() as c:
            c.execute("DROP USER IF EXISTS 'gw_cols'@'%'")
            c.execute("CREATE USER 'gw_cols'@'%' IDENTIFIED BY 'colspw'")
            c.execute(f"GRANT SELECT ({ALLOWED}) ON shop.orders TO 'gw_cols'@'%'")
            c.execute("GRANT REFERENCES ON shop.orders TO 'gw_cols'@'%'")
    finally:
        conn.close()
    return {"user": "gw_cols", "password": "colspw"}


@pytest.fixture
def clickhouse_column_grants(clickhouse_seed: dict[str, str]) -> dict[str, str]:
    import clickhouse_connect

    admin = clickhouse_connect.get_client(
        host=CLICKHOUSE[0], port=CLICKHOUSE[1], username="root", password="rootpw"
    )
    try:
        admin.command("DROP USER IF EXISTS gw_rfcols")
        admin.command("CREATE USER gw_rfcols IDENTIFIED BY 'colspw'")
        admin.command(f"GRANT SELECT({ALLOWED}) ON shop.orders TO gw_rfcols")
        admin.command("GRANT SELECT ON system.* TO gw_rfcols")
    finally:
        admin.close()
    return {"user": "gw_rfcols", "password": "colspw"}


def test_premise_mysql_refuses_select_star_but_accepts_listed_columns(
    mysql_column_grants: dict[str, str],
) -> None:
    conn = pymysql.connect(
        host=MYSQL[0],
        port=MYSQL[1],
        user="gw_cols",
        password="colspw",
        database="shop",
        autocommit=True,
    )
    try:
        with conn.cursor() as c:
            with pytest.raises(pymysql.err.OperationalError) as error:
                c.execute("SELECT id FROM (SELECT * FROM orders WHERE tenant_id = 7) AS orders")
            assert error.value.args[0] in (1142, 1143)
            c.execute(
                f"SELECT id FROM (SELECT {ALLOWED} FROM orders WHERE tenant_id = 7) AS orders"
            )
            assert len(c.fetchall()) == 2
    finally:
        conn.close()


def ids(out: dict[str, Any]) -> list[int]:
    return sorted(row["id"] for row in out["rows"])


def test_mysql_row_filter_with_column_level_grants(
    gateway: Gateway, mysql_column_grants: dict[str, str]
) -> None:
    key = provision(gateway, mysql_column_grants)
    out = query(gateway, key, "SELECT id, phone AS phone, amount FROM shop.orders ORDER BY id")
    assert out["status"] == "success", out
    assert ids(out) == [1, 2]  # tenant 7 only
    assert out["rows"][0]["phone"] == "13*******01"  # masking still applies


def test_mysql_row_filter_alias_join_subquery_and_cte(
    gateway: Gateway, mysql_column_grants: dict[str, str]
) -> None:
    # no masking here: masked tables do not support nested projections (separate, existing rule)
    key = provision(gateway, mysql_column_grants, mask={})
    cases = {
        "SELECT o.id FROM shop.orders o ORDER BY o.id": [1, 2],
        "SELECT a.id FROM shop.orders a JOIN shop.orders b ON a.id = b.id ORDER BY a.id": [1, 2],
        "SELECT id FROM (SELECT id, tenant_id FROM shop.orders) t ORDER BY id": [1, 2],
        "SELECT id FROM shop.orders WHERE id IN (SELECT id FROM shop.orders) ORDER BY id": [1, 2],
        "WITH x AS (SELECT id FROM shop.orders) SELECT id FROM x ORDER BY id": [1, 2],
        "SELECT id FROM shop.orders WHERE tenant_id = 8 ORDER BY id": [],  # filter is ANDed
        "SELECT id FROM shop.orders WHERE 1=1 OR tenant_id = 8 ORDER BY id": [1, 2],
        "SELECT sum(amount) AS s FROM shop.orders GROUP BY tenant_id": None,
    }
    for sql, expected in cases.items():
        out = query(gateway, key, sql)
        assert out["status"] == "success", (sql, out)
        if expected is not None:
            assert ids(out) == expected, sql
    total = query(gateway, key, "SELECT sum(amount) AS s FROM shop.orders")
    assert total["status"] == "success" and float(total["rows"][0]["s"]) == 30.5


def test_mysql_wildcard_is_still_refused_and_never_reaches_the_database(
    gateway: Gateway, mysql_column_grants: dict[str, str]
) -> None:
    key = provision(gateway, mysql_column_grants)
    for sql in ("SELECT * FROM shop.orders", "SELECT o.* FROM shop.orders o"):
        out = query(gateway, key, sql)
        assert out["status"] == "rejected", (sql, out)
        assert "ssn" not in str(out["hint"])


def test_mysql_unauthorised_columns_are_refused_with_a_filter_present(
    gateway: Gateway, mysql_column_grants: dict[str, str]
) -> None:
    key = provision(gateway, mysql_column_grants)
    for sql in (
        "SELECT ssn FROM shop.orders",
        "SELECT id FROM shop.orders WHERE ssn = '111'",
        "SELECT id FROM (SELECT id, ssn FROM shop.orders) t",
    ):
        out = query(gateway, key, sql)
        assert out["status"] == "rejected", (sql, out)
        assert out["reason"].startswith("column_not_allowed:ssn"), (sql, out)


def test_mysql_filter_on_a_column_the_role_cannot_read_is_rejected_clearly(
    gateway: Gateway, mysql_column_grants: dict[str, str]
) -> None:
    # `ssn` is denied by the role (and the account has no privilege on it): the filter cannot be
    # evaluated, so the query is refused with a precise reason instead of failing in the database
    # or - worse - running without the filter.
    key = provision(
        gateway, mysql_column_grants, filter_where="tenant_id = {{tenant_id}} AND ssn <> '000'"
    )
    out = query(gateway, key, "SELECT id FROM shop.orders")
    assert out["status"] == "rejected", out
    assert out["reason"] == "row_filter_column_not_permitted:ssn", out


def test_clickhouse_row_filter_with_column_level_grants(
    gateway: Gateway, clickhouse_column_grants: dict[str, str]
) -> None:
    key = provision(gateway, clickhouse_column_grants, engine="clickhouse")
    out = query(gateway, key, "SELECT id, phone AS phone, amount FROM shop.orders ORDER BY id")
    assert out["status"] == "success", out
    assert ids(out) == [1, 2]
    assert out["rows"][0]["phone"] == "13*******01"
    key = provision(gateway, clickhouse_column_grants, engine="clickhouse", suffix="3", mask={})
    for sql, expected in {
        "SELECT o.id FROM shop.orders o ORDER BY o.id": [1, 2],
        "SELECT a.id FROM shop.orders a JOIN shop.orders b ON a.id = b.id ORDER BY a.id": [1, 2],
        "SELECT id FROM (SELECT id FROM shop.orders) t ORDER BY id": [1, 2],
        "SELECT id FROM shop.orders WHERE id IN (SELECT id FROM shop.orders) ORDER BY id": [1, 2],
    }.items():
        res = query(gateway, key, sql)
        assert res["status"] == "success", (sql, res)
        assert ids(res) == expected, sql


def test_clickhouse_unauthorised_columns_and_filter_columns(
    gateway: Gateway, clickhouse_column_grants: dict[str, str]
) -> None:
    key = provision(gateway, clickhouse_column_grants, engine="clickhouse")
    for sql in (
        "SELECT ssn FROM shop.orders",
        "SELECT id FROM shop.orders WHERE ssn = '111'",
        "SELECT * FROM shop.orders",
    ):
        assert query(gateway, key, sql)["status"] == "rejected", sql
    key2 = provision(
        gateway,
        clickhouse_column_grants,
        engine="clickhouse",
        suffix="2",
        filter_where="tenant_id = {{tenant_id}} AND ssn <> '000'",
    )
    out = query(gateway, key2, "SELECT id FROM shop.orders")
    assert out["status"] == "rejected" and out["reason"] == "row_filter_column_not_permitted:ssn"


def test_alias_shadowing_a_denied_column_never_returns_its_data(
    gateway: Gateway, mysql_column_grants: dict[str, str]
) -> None:
    key = provision(gateway, mysql_column_grants, mask={})
    # `id AS ssn` is only an alias; the physical column is not even visible inside the statement
    out = query(gateway, key, "SELECT id AS ssn FROM shop.orders ORDER BY ssn")
    if out["status"] == "success":
        assert [row["ssn"] for row in out["rows"]] == [1, 2]  # ids, not the `111`/`222` values
    else:
        assert out["status"] == "rejected", out
