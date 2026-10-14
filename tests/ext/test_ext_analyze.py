import pytest

from adg_ext import guard
from adg_ext.analyze import FilterDef, TableView, rewrite
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


def test_allowed_query_gets_the_row_filter_and_keeps_limit() -> None:
    r = run("SELECT id, amount FROM shop.orders WHERE amount > 10")
    assert r.allowed, r.reasons
    assert "tenant_id = 7" in r.sql
    assert r.sql.count("tenant_id") == 1
    assert r.limit == 100


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
