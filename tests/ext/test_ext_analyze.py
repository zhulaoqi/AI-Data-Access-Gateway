import pytest

from adg_ext import guard
from adg_ext.analyze import (
    FilterDef,
    TableView,
    qualify_session_database,
    referenced_databases,
    rewrite,
)
from adg_ext.params import ParamSpec

ORDERS = TableView(
    path="shop.shop.orders",
    restricted=True,
    columns=frozenset({"id", "tenant_id", "phone", "amount", "ssn", "created_at"}),
    allow=frozenset({"id", "tenant_id", "phone", "amount", "created_at"}),
    deny=frozenset({"ssn"}),
    mask={"phone": "partial"},
    filters=[FilterDef("tenant_id = {{tenant_id}}", (ParamSpec("tenant_id", "long"),))],
)
PLAIN = TableView(path="shop.shop.dim", restricted=False)


def run(sql, dialect="mysql", views=None, params=None):
    verdict = guard.check(sql, dialect=dialect, default_limit=100, max_limit=100)
    return rewrite(
        verdict,
        views or [ORDERS],
        dialect=dialect,
        user_params={"tenant_id": 7} if params is None else params,
    )


def _bare(sql: str) -> str:
    return sql.lower().replace("`", "")


def test_session_database_qualifies_unqualified_tables() -> None:
    sql = qualify_session_database(
        "SELECT * FROM bi_view_panel a JOIN bi_view_panel_label b ON a.id = b.panel_id",
        "dataeye",
        "mysql",
    )
    bare = _bare(sql)
    assert "dataeye.bi_view_panel" in bare
    assert "dataeye.bi_view_panel_label" in bare


def test_explicit_database_cte_subquery_and_dual_are_not_requalified() -> None:
    explicit = "SELECT id FROM other.bi_view_panel"
    assert qualify_session_database(explicit, "dataeye", "mysql") == explicit
    dual = "SELECT 1 FROM DUAL"
    assert qualify_session_database(dual, "dataeye", "mysql") == dual
    assert qualify_session_database(explicit, "", "mysql") == explicit
    assert qualify_session_database(explicit, "information_schema", "mysql") == explicit

    cte = qualify_session_database(
        "WITH t AS (SELECT id FROM bi_view_panel) SELECT id FROM t",
        "dataeye",
        "mysql",
    )
    assert "dataeye.bi_view_panel" in _bare(cte)
    assert "dataeye.t" not in _bare(cte)

    nested = qualify_session_database(
        "SELECT id FROM (SELECT id FROM bi_view_panel) x",
        "dataeye",
        "mysql",
    )
    assert "dataeye.bi_view_panel" in _bare(nested)
    assert "dataeye.x" not in _bare(nested)


def test_referenced_databases_keep_explicit_names_only() -> None:
    assert referenced_databases("SELECT id FROM dataeye.bi_view_panel", "mysql") == ["dataeye"]
    assert referenced_databases(
        "SELECT a.id FROM bi_view_panel a JOIN other.labels b ON a.id = b.id",
        "mysql",
    ) == ["other"]
    assert referenced_databases(
        "WITH t AS (SELECT id FROM dataeye.bi_view_panel) SELECT id FROM t",
        "mysql",
    ) == ["dataeye"]


def test_qualified_name_still_receives_the_row_filter() -> None:
    sql = qualify_session_database("SELECT id FROM orders", "shop", "mysql")
    result = run(sql)
    assert result.allowed, result.reasons
    assert "shop.orders" in _bare(result.sql or "")
    assert "tenant_id = 7" in (result.sql or "")


def test_allowed_query_gets_the_row_filter_and_keeps_limit() -> None:
    r = run("SELECT id, amount FROM shop.orders WHERE amount > 10")
    assert r.allowed, r.reasons
    assert "tenant_id = 7" in r.sql
    assert r.sql.count("tenant_id = 7") == 1
    assert r.limit == 100


def test_wildcard_expands_to_permitted_columns_when_rejection_is_off() -> None:
    verdict = guard.check(
        "SELECT * FROM shop.orders",
        dialect="mysql",
        default_limit=100,
        max_limit=100,
        reject_wildcards=False,
    )
    result = rewrite(
        verdict,
        [ORDERS],
        dialect="mysql",
        user_params={"tenant_id": 7},
        reject_wildcards=False,
    )
    assert result.allowed, result.reasons
    sql = result.sql.lower()
    for name in ("id", "amount", "phone", "tenant_id", "created_at"):
        assert name in sql
    assert "ssn" not in sql
    assert "select *" not in sql


def test_wildcard_is_rejected_with_the_allowed_columns_as_hint() -> None:
    r = run("SELECT * FROM shop.orders")
    assert r.reasons[0].startswith("wildcard")
    assert r.hint["allowed_columns"] == {
        "shop.shop.orders": ["amount", "created_at", "id", "phone", "tenant_id"]
    }


def test_count_star_is_not_a_wildcard_projection() -> None:
    r = run("SELECT count(*) AS n FROM shop.orders")
    assert r.allowed, r.reasons


@pytest.mark.parametrize("column", ["ssn"])
def test_denied_and_unlisted_columns_are_rejected(column: str) -> None:
    r = run(f"SELECT {column} FROM shop.orders")
    assert r.reasons == [f"column_not_allowed:{column}"]


def test_unlisted_column_hidden_in_where_is_rejected() -> None:
    r = run("SELECT id FROM shop.orders WHERE ssn = '1'")
    assert r.reasons == ["column_not_allowed:ssn"]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id FROM shop.orders WHERE phone = '13800000000'",
        "SELECT id FROM shop.orders ORDER BY phone",
        "SELECT phone, count(*) FROM shop.orders GROUP BY phone",
        "SELECT id FROM (SELECT phone, id FROM shop.orders) t",
        "WITH c AS (SELECT phone FROM shop.orders) SELECT phone FROM c",
    ],
)
def test_masked_columns_cannot_be_probed(sql: str) -> None:
    r = run(sql)
    assert r.reasons and r.reasons[0].startswith("masked_column_position_not_allowed"), sql


def test_masked_column_may_be_projected_directly() -> None:
    assert run("SELECT phone AS p, id FROM shop.orders").allowed


def test_missing_row_filter_parameter_rejects() -> None:
    r = run("SELECT id FROM shop.orders", params={})
    assert r.reasons == ["row_filter_param_missing:tenant_id"]


def test_filter_wraps_every_reference_including_subqueries_and_joins() -> None:
    r = run(
        "SELECT a.id FROM shop.orders a JOIN shop.orders b ON a.id = b.id "
        "WHERE a.id IN (SELECT id FROM shop.orders)"
    )
    assert r.allowed, r.reasons
    assert r.sql.count("tenant_id = 7") == 3


def test_unrestricted_tables_pass_untouched() -> None:
    r = run("SELECT id FROM shop.dim", views=[PLAIN, ORDERS])
    assert r.allowed and "WHERE" not in r.sql.upper().replace("LIMIT", "")


def test_several_roles_or_their_filters_and_open_role_wins() -> None:
    two = TableView(
        path="shop.shop.orders",
        restricted=True,
        allow=ORDERS.allow,
        filters=[
            FilterDef("tenant_id = 1", ()),
            FilterDef("tenant_id = 2", ()),
        ],
    )
    r = run("SELECT id FROM shop.orders", views=[two])
    assert "tenant_id = 1) OR (tenant_id = 2" in r.sql
    open_role = TableView(
        path="shop.shop.orders",
        restricted=True,
        allow=ORDERS.allow,
        filters=[FilterDef("id = 1", ()), None],
    )
    assert "WHERE id = 1" not in run("SELECT id FROM shop.orders", views=[open_role]).sql


def test_clickhouse_dialect_roundtrip() -> None:
    r = run("SELECT id FROM shop.orders", dialect="clickhouse")
    assert r.allowed, r.reasons
    assert "tenant_id = 7" in r.sql


# ---- closed column scope for columns the synced catalog does not list ---------------------------

# ClickHouse lists only columns the datasource account holds a column-level grant on, so ``ssn`` is
# absent from the catalog even though it exists in the table.
ORDERS_GRANTED_ONLY = TableView(
    path="shop.shop.orders",
    restricted=True,
    columns=frozenset({"id", "tenant_id", "phone", "amount", "created_at"}),
    allow=frozenset({"id", "tenant_id", "phone", "amount", "created_at"}),
    deny=frozenset({"ssn"}),
    mask={"phone": "partial"},
    filters=[FilterDef("tenant_id = {{tenant_id}}", (ParamSpec("tenant_id", "long"),))],
)


@pytest.mark.parametrize("dialect", ["mysql", "clickhouse"])
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT ssn FROM shop.orders",
        "SELECT id FROM shop.orders WHERE ssn = '1'",
        "SELECT id FROM shop.orders ORDER BY ssn",
        "SELECT id FROM (SELECT id, ssn FROM shop.orders) t",
        "SELECT id FROM shop.orders WHERE nonexistent > 1",  # never reaches the database
    ],
)
def test_column_missing_from_the_catalog_is_rejected_by_the_guard(dialect: str, sql: str) -> None:
    r = run(sql, dialect=dialect, views=[ORDERS_GRANTED_ONLY])
    assert not r.allowed
    assert r.reasons[0].startswith("column_not_allowed:")
    assert "ssn" not in str(r.hint)


@pytest.mark.parametrize("dialect", ["mysql", "clickhouse"])
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id, amount * 2 AS double_amount FROM shop.orders ORDER BY double_amount",
        "SELECT id, amount AS a FROM shop.orders WHERE a > 1",  # alias reference (ClickHouse)
        "SELECT count(*) AS n, max(amount) AS m FROM shop.orders HAVING m > 1",
        "SELECT id FROM (SELECT id, amount AS a FROM shop.orders) t WHERE a > 1",
    ],
)
def test_aliases_and_allowed_columns_still_pass(dialect: str, sql: str) -> None:
    r = run(sql, dialect=dialect, views=[ORDERS_GRANTED_ONLY])
    assert r.allowed, (sql, r.reasons)


def test_column_of_an_unrestricted_table_is_not_mistaken_for_an_unlisted_one() -> None:
    plain = TableView(path="shop.shop.dim", restricted=False, columns=frozenset({"id", "name"}))
    ok = run(
        "SELECT o.id, d.name FROM shop.orders o JOIN shop.dim d ON o.id = d.id",
        views=[ORDERS_GRANTED_ONLY, plain],
    )
    assert ok.allowed, ok.reasons
    bad = run(
        "SELECT o.id FROM shop.orders o JOIN shop.dim d ON o.id = d.id WHERE d.secret = 1",
        views=[ORDERS_GRANTED_ONLY, plain],
    )
    assert bad.reasons == ["column_not_allowed:secret"]


# ---- N-2: the derived table lists permitted columns, never ``*`` --------------------------------


def test_derived_table_projects_exactly_the_permitted_columns_in_every_dialect() -> None:
    for dialect in ("mysql", "clickhouse"):
        r = run("SELECT id FROM shop.orders", dialect=dialect)
        assert r.allowed, r.reasons
        inner = r.sql[r.sql.index("(SELECT") : r.sql.index(") AS orders")].lower()
        assert "*" not in inner
        assert "ssn" not in r.sql.lower()
        for column in ("amount", "created_at", "id", "phone", "tenant_id"):
            assert column in inner, (dialect, column)


def test_derived_table_skips_permitted_columns_missing_from_the_catalog() -> None:
    view = TableView(
        path="shop.shop.orders",
        restricted=True,
        columns=frozenset({"id", "tenant_id"}),  # `phone`... were dropped / not visible
        allow=frozenset({"id", "tenant_id", "phone", "amount"}),
        filters=ORDERS.filters,
    )
    r = run("SELECT id FROM shop.orders", views=[view])
    assert r.allowed, r.reasons
    inner = r.sql[r.sql.index("(SELECT") : r.sql.index(") AS orders")].lower()
    assert "phone" not in inner and "amount" not in inner and "tenant_id" in inner


def test_unknown_catalog_uses_every_permitted_column() -> None:
    view = TableView(
        path="shop.shop.orders",
        restricted=True,
        allow=frozenset({"id", "tenant_id"}),
        filters=ORDERS.filters,
    )
    r = run("SELECT id FROM shop.orders", views=[view])
    assert r.allowed and "SELECT `id`, `tenant_id` FROM" in r.sql


@pytest.mark.parametrize("dialect", ["mysql", "clickhouse"])
def test_filter_reading_a_denied_column_is_rejected_with_a_clear_reason(dialect: str) -> None:
    view = TableView(
        path="shop.shop.orders",
        restricted=True,
        columns=ORDERS.columns,
        allow=ORDERS.allow,
        deny=frozenset({"ssn"}),
        filters=[FilterDef("tenant_id = {{tenant_id}} AND ssn <> '0'", ORDERS.filters[0].params)],  # type: ignore[union-attr]
    )
    r = run("SELECT id FROM shop.orders", dialect=dialect, views=[view])
    assert not r.allowed and r.sql is None
    assert r.reasons == ["row_filter_column_not_permitted:ssn"]


def test_filter_reading_a_column_outside_allow_is_rejected_not_dropped() -> None:
    view = TableView(
        path="shop.shop.orders",
        restricted=True,
        columns=ORDERS.columns,
        allow=frozenset({"id", "amount"}),  # tenant_id is not allowed, yet the filter needs it
        filters=ORDERS.filters,
    )
    r = run("SELECT id FROM shop.orders", views=[view])
    assert r.reasons == ["row_filter_column_not_permitted:tenant_id"]


def test_filter_column_check_is_case_insensitive_and_covers_every_role() -> None:
    ok = TableView(
        path="shop.shop.orders",
        restricted=True,
        allow=frozenset({"id", "Tenant_ID"}),
        filters=[FilterDef("TENANT_ID = 7", ())],
    )
    assert run("SELECT id FROM shop.orders", views=[ok]).allowed
    bad = TableView(
        path="shop.shop.orders",
        restricted=True,
        allow=frozenset({"id", "tenant_id"}),
        filters=[FilterDef("tenant_id = 7", ()), FilterDef("region = 'x'", ())],
    )
    assert run("SELECT id FROM shop.orders", views=[bad]).reasons == [
        "row_filter_column_not_permitted:region"
    ]


def test_filter_with_no_permitted_column_at_all_is_rejected() -> None:
    view = TableView(
        path="shop.shop.orders",
        restricted=True,
        columns=ORDERS.columns,
        allow=frozenset({"ssn"}),
        deny=frozenset({"ssn"}),
        filters=[FilterDef("1 = 1", ())],
    )
    r = run("SELECT 1 AS one FROM shop.orders", views=[view])
    assert r.reasons == ["row_filter_no_permitted_columns"]


def test_alias_shadowing_a_denied_column_cannot_reach_the_physical_column() -> None:
    # `id AS ssn` is a legal alias; the derived table still never exposes the physical `ssn`
    for dialect in ("mysql", "clickhouse"):
        r = run("SELECT id AS ssn FROM shop.orders", dialect=dialect)
        if r.allowed:
            inner = r.sql[r.sql.index("(SELECT") : r.sql.index(") AS orders")].lower()
            assert "ssn" not in inner
