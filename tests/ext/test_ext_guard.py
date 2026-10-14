from datetime import UTC, datetime

import pytest

from adg_ext.guard import Operations, check, dialect_for

NOW = datetime(2026, 10, 14, tzinfo=UTC)


def verdict(sql: str, dialect: str, **kw):
    return check(sql, dialect=dialect, default_limit=100, max_limit=1000, now=NOW, **kw)


COMMON_REJECTS = {
    "multi": "select id from t; select id from u",
    "write": "insert into t(id) values (1)",
    "update": "update t set id = 1",
    "delete": "delete from t",
    "ddl": "drop table t",
    "show": "show tables",
    "set": "set @a = 1",
    "use": "use db1",
    "describe": "describe t",
    "explain": "explain select id from t",
    "explain_analyze": "explain analyze select id from t",
    "wildcard": "select * from t",
    "qualified_wildcard": "select t.* from t",
    "variable": "select @a from t",
    "session_variable": "select @@version from t",
    "sleep": "select sleep(5) from t",
    "union": "select id from t union select id from u",
    "limit_subquery": "select id from t limit (select 1)",
    "system_db": "select table_name from information_schema.tables",
    "system_db_upper": "select table_name from INFORMATION_SCHEMA.TABLES",
    "mysql_db": "select user from mysql.user",
    "cross_catalog": "select id from other_cat.db1.t",
    "derived_no_alias": "select id + 1 from t",
    "lock": "select id from t for update",
}

ENGINE_REJECTS = {
    "mysql": {
        "into_outfile": "select id from t into outfile '/tmp/x'",
        "into_dumpfile": "select id from t into dumpfile '/tmp/x'",
        "hint": "select /*+ MAX_EXECUTION_TIME(1) */ id from t",
        "index_hint": "select id from t use index (i)",
        "partition": "select id from t partition (p0)",
        "json_table": "select jt.a from json_table('[]', '$[*]' columns (a int path '$')) jt",
        "load_file": "select load_file('/etc/passwd') from t",
        "performance_schema": "select * from performance_schema.threads",
    },
    "starrocks": {
        "files": "select id from files('path'='s3://x')",
        "pivot": "select id from t pivot (sum(a) for b in (1))",
        "hint": "select /*+ SET_VAR(query_timeout=1) */ id from t",
        "statistics": "select id from _statistics_.t",
        "into": "select id from t into outfile 's3://x'",
    },
    "clickhouse": {
        "settings": "select id from t settings max_threads = 1",
        "format": "select id from t format JSON",
        "url": "select id from url('http://x', 'CSV')",
        "file": "select id from file('x', 'CSV')",
        "remote": "select id from remote('h', 'db', 't')",
        "s3": "select id from s3('x', 'y')",
        "system": "select name from system.tables",
        "param": "select id from t where id = {p:Int32}",
        "array_join": "select id from t array join arr as a",
        "pivot": "select id from t pivot (sum(a) for b in (1))",
        "kill": "kill query where query_id = 'x'",
        "optimize": "optimize table t",
    },
}


@pytest.mark.parametrize("dialect", ["mysql", "starrocks", "clickhouse"])
@pytest.mark.parametrize("name", sorted(COMMON_REJECTS))
def test_common_rejections(dialect: str, name: str) -> None:
    v = verdict(COMMON_REJECTS[name], dialect)
    assert not v.allowed, (name, v.reasons)
    assert v.reasons


@pytest.mark.parametrize(
    ("dialect", "name"),
    [(d, n) for d, cases in ENGINE_REJECTS.items() for n in cases],
)
def test_engine_specific_rejections(dialect: str, name: str) -> None:
    v = verdict(ENGINE_REJECTS[dialect][name], dialect)
    assert not v.allowed, (name, v.reasons)


@pytest.mark.parametrize("dialect", ["mysql", "starrocks", "clickhouse"])
def test_legitimate_queries_pass_and_are_regenerated_with_a_limit(dialect: str) -> None:
    v = verdict(
        "select a.id, sum(b.amount) as total from db1.orders a join db1.items b on a.id = b.oid where a.day >= '2026-10-01' group by a.id",
        dialect,
    )
    assert v.allowed, v.reasons
    assert v.result.normalized_sql is not None and "LIMIT 100" in v.result.normalized_sql
    assert sorted(v.result.accessed_resources) == ["db1.items", "db1.orders"]
    v = verdict(
        "with x as (select id from t where id > 1 limit 10) select id from x limit 5", dialect
    )
    assert v.allowed, v.reasons


def test_backticks_parse_in_mysql_and_starrocks_but_not_the_default_dialect() -> None:
    assert verdict("select `id` from `db1`.`t` limit 5", "mysql").allowed
    assert verdict("select `id` from `db1`.`t` limit 5", "starrocks").allowed


def test_wildcard_reason_is_specific() -> None:
    assert "wildcard_projection_not_allowed" in verdict("select * from t", "mysql").reasons
    assert (
        "wildcard_projection_not_allowed" in verdict("select count(*), * from t", "mysql").reasons
    )


def test_deny_functions_from_the_role_spec() -> None:
    ops = Operations(deny_functions=frozenset({"count"}))
    v = verdict("select count(id) as c from t", "mysql", operations=ops)
    assert "function_not_allowed:count" in v.reasons


def test_executed_sql_is_regenerated_so_trailing_text_cannot_ride_along() -> None:
    v = verdict("select id from t limit 5 settings max_threads = 1", "clickhouse")
    assert not v.allowed
    v = verdict("select id from t -- ; drop table t\n limit 5", "mysql")
    assert v.allowed and "drop" not in (v.result.normalized_sql or "").lower()


class TestTimeRange:
    ops = Operations(require_time_range_days=7)
    cols = {"day", "created_at"}

    def ok(self, sql: str) -> bool:
        return verdict(sql, "mysql", operations=self.ops, time_columns=self.cols).allowed

    def test_closed_window_within_limit(self) -> None:
        assert self.ok("select id from t where day >= '2026-10-08' and day <= '2026-10-14'")
        assert self.ok("select id from t where day between '2026-10-01' and '2026-10-07'")
        assert self.ok("select id from t where day = '2026-10-10'")
        assert self.ok("select id from t where '2026-10-08' <= day and '2026-10-14' >= day")

    def test_open_window_must_start_within_limit_of_today(self) -> None:
        assert self.ok("select id from t where created_at >= '2026-10-10 00:00:00'")
        assert not self.ok("select id from t where created_at >= '2026-01-01'")

    def test_window_too_wide_missing_or_unusable(self) -> None:
        assert not self.ok("select id from t where day >= '2026-09-01' and day <= '2026-10-14'")
        assert not self.ok("select id from t")
        assert not self.ok("select id from t where id > 5")
        assert not self.ok("select id from t where day > id")
        assert not self.ok("select id from t where day >= '2026-10-10' or id = 1")
        assert not self.ok("select id from t where day <= '2026-10-14'")

    def test_not_required_without_the_setting(self) -> None:
        assert verdict("select id from t", "mysql").allowed


def test_dialect_mapping() -> None:
    assert dialect_for("mysql") == "mysql"
    assert dialect_for("doris") == "starrocks"
    assert dialect_for("clickhouse") == "clickhouse"
    assert dialect_for("unknown") is None


def test_deny_syntax_tokens_forbid_the_matching_constructs() -> None:
    from adg_ext.guard import Operations

    ops = Operations(deny_syntax=frozenset({"union", "join", "subquery", "cte"}))
    cases = {
        "union": "SELECT a FROM t UNION SELECT a FROM u",
        "join": "SELECT t.a FROM t JOIN u ON t.a = u.a",
        "subquery": "SELECT a FROM (SELECT a FROM t) x",
        "cte": "WITH c AS (SELECT a FROM t) SELECT a FROM c",
    }
    for token, sql in cases.items():
        v = check(sql, dialect="mysql", default_limit=10, max_limit=10, operations=ops)
        assert f"syntax_not_allowed:{token}" in v.reasons, sql
    ok = check("SELECT a FROM t", dialect="mysql", default_limit=10, max_limit=10, operations=ops)
    assert ok.allowed
