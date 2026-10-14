"""B-series regression: bypass attempts that must stay rejected, per engine (CI gate).

Every ALLOW sample must come out with the row filter on every reference to the table and with
no trace of a forbidden column; every DENY sample must be rejected. A sample moving from DENY
to ALLOW is a security regression and fails the build.
"""

import re

import pytest

from adg_ext.dryrun import dry_run

SPEC = {
    "scope": {
        "tables": [
            {
                "datasource": "d",
                "database": "shop",
                "name": "orders",
                "columns": {
                    "allow": ["id", "tenant_id", "phone", "amount", "created_at"],
                    "deny": ["ssn"],
                    "mask": {"phone": "partial"},
                },
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
    "operations": {"mode": "read_only", "deny_functions": ["load_file"]},
    "limits": {"max_rows": 100},
}
COLUMNS = {"shop.orders": ["id", "tenant_id", "phone", "amount", "ssn", "created_at"]}

MYSQL_DENY = [
    "SELECT id FROM shop.orders; DROP TABLE shop.orders",
    "SELECT id FROM shop.orders /* x */ UNION SELECT id FROM shop.dim",
    "SELECT id FROM shop.orders UNION SELECT id FROM shop.orders",
    "SELECT id FROM shop.orders WHERE EXISTS (SELECT 1 FROM shop.orders)",
    "SELECT (SELECT ssn FROM shop.orders LIMIT 1) AS s FROM shop.orders",
    "SELECT id FROM shop.orders WHERE ssn LIKE '1%'",
    "SELECT id FROM shop.orders ORDER BY ssn",
    "SELECT id FROM shop.orders GROUP BY ssn",
    "SELECT CASE WHEN ssn = '111' THEN 1 ELSE 0 END AS c FROM shop.orders",
    "SELECT id, o.ssn FROM shop.orders o",
    "SELECT * FROM shop.orders",
    "SELECT o.* FROM shop.orders o",
    "SELECT id FROM shop.orders INTO OUTFILE '/tmp/x'",
    "SELECT id FROM shop.orders INTO DUMPFILE '/tmp/x'",
    "SELECT load_file('/etc/passwd') AS f FROM shop.orders",
    "SELECT id FROM shop.orders FOR UPDATE",
    "SELECT id FROM shop.orders LOCK IN SHARE MODE",
    "SELECT @@version AS v FROM shop.orders",
    "SELECT @x := id AS v FROM shop.orders",
    "SET @a = 1",
    "USE shop",
    "SHOW TABLES",
    "SHOW DATABASES",
    "DESCRIBE shop.orders",
    "EXPLAIN SELECT id FROM shop.orders",
    "CALL p()",
    "HANDLER shop.orders OPEN",
    "INSERT INTO shop.orders VALUES (1)",
    "UPDATE shop.orders SET id = 1",
    "DELETE FROM shop.orders",
    "SELECT id FROM information_schema.tables",
    "SELECT user FROM mysql.user",
    "SELECT id FROM performance_schema.threads",
    "SELECT id FROM sys.session",
    "SELECT id FROM shop.dim",
    "SELECT id FROM other.orders",
    "SELECT id FROM shop.orders PARTITION (p0)",
    "SELECT /*+ MAX_EXECUTION_TIME(1) */ id FROM shop.orders",
    "SELECT id FROM shop.orders USE INDEX (idx)",
    "SELECT sleep(10) AS s FROM shop.orders",
    "SELECT benchmark(1000000, 1) AS s FROM shop.orders",
    "SELECT id FROM shop.orders JOIN shop.dim USING (id)",
    "SELECT id FROM shop.orders INTERSECT SELECT id FROM shop.orders",
    "SELECT id FROM shop.orders EXCEPT SELECT id FROM shop.orders",
    "SELECT JSON_EXTRACT(phone, '$') AS j FROM shop.orders",
    "SELECT concat(phone, 'x') AS p FROM shop.orders",
    "SELECT id FROM shop.orders WHERE phone IS NOT NULL",
    "SELECT count(phone) AS n FROM shop.orders",
    "SELECT id FROM shop.orders LIMIT (SELECT 1)",
    "SELECT id FROM shop.orders WHERE id IN (SELECT id FROM shop.dim)",
]

# N-2 row-filter samples: the filtered table is a derived table over the permitted columns only, so
# none of these may get the unauthorised column through the filter wrapper (or around it).
ROWFILTER_DENY = [
    "SELECT id FROM shop.orders WHERE tenant_id = 7 OR ssn = '111'",
    "SELECT id FROM shop.orders WHERE id IN (SELECT ssn FROM shop.orders)",
    "SELECT id FROM shop.orders WHERE (SELECT ssn FROM shop.orders LIMIT 1) = '111'",
    "SELECT id FROM (SELECT ssn FROM shop.orders) t",
    "SELECT t.id FROM (SELECT id, ssn FROM shop.orders) t WHERE t.ssn = '111'",
    "WITH s AS (SELECT ssn FROM shop.orders) SELECT 1 AS x FROM s",
    "SELECT a.id FROM shop.orders a JOIN shop.orders b ON a.ssn = b.ssn",
    "SELECT o.id FROM shop.orders o WHERE o.ssn > 0",
    "SELECT shop.orders.ssn FROM shop.orders",
    "SELECT orders.id FROM shop.orders WHERE orders.ssn = '111'",
    # alias shadowing: the alias reuses a forbidden name, or the forbidden column hides behind one
    "SELECT ssn AS id FROM shop.orders",
    "SELECT id AS ssn FROM shop.orders WHERE ssn = '111'",
    "SELECT id AS ssn, ssn AS id FROM shop.orders",
    "SELECT o.* FROM shop.orders o JOIN shop.orders p ON o.id = p.id",
    "SELECT orders.* FROM shop.orders",
    "SELECT id FROM shop.orders UNION ALL SELECT ssn FROM shop.orders",
    "SELECT id FROM shop.orders WHERE EXISTS (SELECT 1 FROM shop.orders o WHERE o.ssn = '1')",
]

MYSQL_ALLOW = [
    "SELECT id FROM shop.orders",
    "SELECT id FROM `shop`.`orders`",
    "SELECT id FROM SHOP.ORDERS",
    "SELECT ID FROM shop.orders",
    "SELECT id FROM shop.orders WHERE 1=1 OR tenant_id = 8",
    "SELECT id FROM shop.orders WHERE tenant_id = 8",
    "SELECT id FROM shop.orders o WHERE o.tenant_id IN (8, 9)",
    "SELECT id FROM (SELECT id, tenant_id FROM shop.orders) t WHERE tenant_id = 8",
    "WITH x AS (SELECT id FROM shop.orders) SELECT id FROM x",
    "SELECT id FROM shop.orders a JOIN shop.orders b ON a.id = b.id",
    "SELECT id FROM shop.orders a LEFT JOIN shop.orders b ON a.id = b.id AND b.tenant_id <> 7",
    "SELECT id FROM shop.orders WHERE id = 1 -- comment",
    "SELECT id FROM shop.orders WHERE id = '1' OR '1'='1'",
    "SELECT id FROM shop.orders NATURAL JOIN shop.orders o2",
    "SELECT phone FROM shop.orders",
    "SELECT phone AS p FROM shop.orders",
    "SELECT phone AS p, phone AS q FROM shop.orders",
    "SELECT id FROM shop.orders LIMIT 100000",
    "SELECT id FROM shop.orders LIMIT 5 OFFSET 2",
    "SELECT id FROM shop.orders t1, shop.orders t2",
    "SELECT 1",
    "SELECT id FROM shop.orders WHERE tenant_id = 7",
    "SELECT sum(amount) AS s FROM shop.orders GROUP BY tenant_id",
    "SELECT id FROM shop.orders WHERE amount > 1 AND created_at > '2026-01-01'",
]

CLICKHOUSE_DENY = [
    "SELECT id FROM shop.orders SETTINGS max_threads = 1",
    "SELECT id FROM shop.orders FORMAT JSON",
    "SELECT id FROM shop.orders ARRAY JOIN [1,2] AS x",
    "SELECT id FROM shop.orders LEFT ARRAY JOIN [1] AS x",
    "SELECT id FROM url('http://x', CSV, 'a Int')",
    "SELECT id FROM file('x', CSV, 'a Int')",
    "SELECT id FROM remote('h', shop.orders)",
    "SELECT id FROM s3('http://x', CSV, 'a Int')",
    "SELECT number FROM numbers(10)",
    "SELECT id FROM system.tables",
    "SELECT id FROM information_schema.tables",
    "SELECT * EXCEPT (ssn) FROM shop.orders",
    "SELECT * REPLACE (1 AS id) FROM shop.orders",
    "SELECT COLUMNS('ssn') FROM shop.orders",
    "SELECT COLUMNS('.*') FROM shop.orders",
    "SELECT dictGet('d', 'a', toUInt64(1)) AS x FROM shop.orders",
    "SELECT currentUser() AS u FROM shop.orders",
    "SELECT id FROM shop.orders t WHERE t.ssn = '1'",
    "SELECT id FROM shop.orders WHERE ssn = '1'",
    "SELECT id FROM shop.orders WITH TOTALS",
    "SELECT id, sum(amount) AS s FROM shop.orders GROUP BY id WITH ROLLUP",
    "SELECT id FROM shop.orders INTO OUTFILE '/tmp/x'",
    "SET max_threads = 1",
    "SHOW TABLES",
    "DESCRIBE TABLE shop.orders",
    "EXPLAIN SELECT id FROM shop.orders",
    "SYSTEM RELOAD DICTIONARIES",
    "KILL QUERY WHERE 1",
    "INSERT INTO shop.orders VALUES (1)",
    "ALTER TABLE shop.orders DELETE WHERE 1",
    "OPTIMIZE TABLE shop.orders",
    "SELECT id FROM shop.orders; SELECT 1",
    "SELECT id FROM shop.orders UNION ALL SELECT id FROM shop.orders",
    "WITH (SELECT max(id) FROM shop.orders) AS m SELECT m AS x FROM shop.orders",
    "SELECT id FROM shop.orders ORDER BY id LIMIT 1 BY id",
    "SELECT arrayJoin([1,2]) AS x FROM shop.orders",
    "SELECT toString(phone) AS p FROM shop.orders",
    "SELECT id FROM shop.orders WHERE has([1], id)",
]

CLICKHOUSE_ALLOW = [
    "SELECT id FROM shop.orders",
    "SELECT id FROM shop.orders WHERE tenant_id = 8",
    "SELECT id FROM shop.orders PREWHERE tenant_id = 8",
    "SELECT id FROM shop.orders FINAL",
    "SELECT id FROM shop.orders SAMPLE 0.5",
    "SELECT id FROM shop.orders WHERE id IN (SELECT id FROM shop.orders)",
    "SELECT id FROM shop.orders ANY LEFT JOIN shop.orders b USING id",
    "SELECT id FROM shop.orders GLOBAL JOIN shop.orders b ON 1",
    "SELECT phone AS p FROM shop.orders",
    "SELECT id FROM shop.orders WHERE tenant_id = 7",
]

# N-2: aliases, joins, subqueries and CTEs over the derived (permitted-columns-only) wrapper
ROWFILTER_ALLOW = [
    "SELECT o.id FROM shop.orders o WHERE o.tenant_id = 8",
    "SELECT orders.id FROM shop.orders",
    "SELECT id AS tenant_id FROM shop.orders",
    "SELECT id AS tenant FROM shop.orders",
    "SELECT a.id, b.amount FROM shop.orders a JOIN shop.orders b ON a.id = b.id",
    "SELECT id FROM shop.orders WHERE id IN (SELECT id FROM shop.orders WHERE amount > 1)",
    "WITH c AS (SELECT id, tenant_id FROM shop.orders) SELECT c.id FROM c",
    "SELECT x.id FROM (SELECT id FROM shop.orders) x JOIN shop.orders y ON x.id = y.id",
    "SELECT count(*) AS n FROM shop.orders",
    "SELECT tenant_id, count(*) AS n FROM shop.orders GROUP BY tenant_id",
]


def run(dialect: str, sql: str) -> dict:
    return dry_run(
        {
            "dialect": dialect,
            "datasource": "d",
            "spec": SPEC,
            "params": {"tenant_id": 7},
            "sql": sql,
            "columns": COLUMNS,
        }
    )


@pytest.mark.parametrize("sql", MYSQL_DENY)
def test_mysql_bypass_is_rejected(sql: str) -> None:
    assert run("mysql", sql)["allowed"] is False, sql


@pytest.mark.parametrize("sql", ROWFILTER_DENY)
@pytest.mark.parametrize("dialect", ["mysql", "clickhouse"])
def test_row_filter_bypass_is_rejected(dialect: str, sql: str) -> None:
    result = run(dialect, sql)
    assert result["allowed"] is False, sql
    assert result.get("rewrittenSql") in (None, ""), sql


@pytest.mark.parametrize("sql", CLICKHOUSE_DENY)
def test_clickhouse_bypass_is_rejected(sql: str) -> None:
    assert run("clickhouse", sql)["allowed"] is False, sql


@pytest.mark.parametrize(
    "dialect,sql",
    [("mysql", s) for s in MYSQL_ALLOW + ROWFILTER_ALLOW]
    + [("clickhouse", s) for s in CLICKHOUSE_ALLOW + ROWFILTER_ALLOW],
)
def test_allowed_statements_are_always_confined(dialect: str, sql: str) -> None:
    result = run(dialect, sql)
    assert result["allowed"] is True, sql
    rewritten = result["rewrittenSql"].lower()
    assert "ssn" not in rewritten
    assert "information_schema" not in rewritten and "system." not in rewritten
    # every physical reference to the table sits inside its row-filter wrapper
    references = len(re.findall(r"`?shop`?\.`?orders`?", rewritten))
    wrapped = len(
        re.findall(
            r"\(select [^()*]+ from `?shop`?\.`?orders`?(?: final| sample [0-9.]+)? "
            r"where tenant_id = 7",
            rewritten,
        )
    )
    assert references == wrapped, rewritten
