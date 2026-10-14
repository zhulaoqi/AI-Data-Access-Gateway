import pytest
import sqlglot

from adg_ext.errors import ExtRejection
from adg_ext.params import ParamSpec
from adg_ext.rowfilter import Binding, compile_template, inject, render, verify

P = [
    ParamSpec("tenant_id", "long"),
    ParamSpec("regions", "string_list"),
    ParamSpec("name", "string"),
    ParamSpec("day", "date"),
    ParamSpec("ids", "long_list"),
]


def binding(where: str, supplied: dict[str, object], dialect: str = "mysql") -> Binding:
    return Binding((render(compile_template(where, P, dialect=dialect), supplied),))


def lookup_for(table: str, b: Binding):
    def lookup(db: str | None, name: str) -> Binding | None:
        return b if name == table else None

    return lookup


def run(sql: str, table: str, b: Binding, dialect: str = "mysql") -> str:
    lookup = lookup_for(table, b)
    out = inject(sqlglot.parse_one(sql, dialect=dialect), lookup, dialect=dialect).sql(
        dialect=dialect
    )
    verify(out, lookup, dialect=dialect)
    return out


def test_renders_typed_literals() -> None:
    b = binding(
        "tenant_id = {{tenant_id}} AND region IN ({{regions}})",
        {"tenant_id": 7, "regions": ["cn", "us"]},
    )
    assert b.predicates[0].sql(dialect="mysql") == "tenant_id = 7 AND region IN ('cn', 'us')"


def test_wraps_the_table_keeping_the_alias() -> None:
    b = binding("tenant_id = {{tenant_id}}", {"tenant_id": 7})
    assert run("select o.id from orders o", "orders", b) == (
        "SELECT o.id FROM (SELECT * FROM orders WHERE tenant_id = 7) AS o"
    )
    assert run("select id from db1.orders", "orders", b) == (
        "SELECT id FROM (SELECT * FROM db1.orders WHERE tenant_id = 7) AS orders"
    )


def test_every_reference_is_wrapped_in_joins_self_joins_and_subqueries() -> None:
    b = binding("tenant_id = {{tenant_id}}", {"tenant_id": 7})
    out = run(
        "select a.id from orders a join orders b on a.pid = b.id "
        "where a.id in (select id from orders where amount > 1)",
        "orders",
        b,
    )
    assert out.count("tenant_id = 7") == 3
    out = run("select a.id from users a left join orders b on a.id = b.uid", "orders", b)
    assert out.count("tenant_id = 7") == 1
    ch = binding("tenant_id = {{tenant_id}}", {"tenant_id": 7}, "clickhouse")
    out = run(
        "select a.id from orders a full join users b on a.id = b.uid", "orders", ch, "clickhouse"
    )
    assert out.count("tenant_id = 7") == 1
    # MySQL has no FULL JOIN; sqlglot expands it into a union, and every branch stays filtered
    out = run("select a.id from orders a full join users b on a.id = b.uid", "orders", b)
    assert out.count("tenant_id = 7") >= 2


def test_cte_name_shadowing_a_filtered_table_still_filters_the_physical_table() -> None:
    b = binding("tenant_id = {{tenant_id}}", {"tenant_id": 7})
    out = run("with orders as (select id from orders) select id from orders", "orders", b)
    assert out.count("tenant_id = 7") == 1
    # the CTE reference itself must not be wrapped, only the physical table inside it
    assert (
        "WITH orders AS (SELECT id FROM (SELECT * FROM orders WHERE tenant_id = 7) AS orders)"
        in out
    )


def test_alias_that_hides_another_tables_name() -> None:
    b = binding("tenant_id = {{tenant_id}}", {"tenant_id": 7})
    out = run("select orders.id from users orders", "orders", b)
    assert "tenant_id" not in out  # `orders` here is an alias of users, not the filtered table
    out = run("select users.id from orders users", "orders", b)
    assert out == "SELECT users.id FROM (SELECT * FROM orders WHERE tenant_id = 7) AS users"


def test_union_branches_are_each_wrapped() -> None:
    b = binding("tenant_id = {{tenant_id}}", {"tenant_id": 7})
    out = run("select id from orders union all select id from orders", "orders", b)
    assert out.count("tenant_id = 7") == 2


def test_unfiltered_tables_are_untouched() -> None:
    b = binding("tenant_id = {{tenant_id}}", {"tenant_id": 7})
    sql = "select id from users"
    assert run(sql, "orders", b) == "SELECT id FROM users"


def test_multiple_predicates_are_anded_in_parentheses() -> None:
    p1 = render(compile_template("tenant_id = {{tenant_id}}", P, dialect="mysql"), {"tenant_id": 7})
    p2 = render(compile_template("a = 1 OR b = 2", P, dialect="mysql"), {})
    out = run("select id from orders", "orders", Binding((p1, p2)))
    assert "(tenant_id = 7) AND (a = 1 OR b = 2)" in out


@pytest.mark.parametrize(
    "value",
    ["x'; drop table t; --", "a\\'", "x' OR '1'='1", "ünï", "a%b", '"q"'],
)
def test_string_values_cannot_break_out_of_the_literal(value: str) -> None:
    for dialect in ("mysql", "clickhouse"):
        b = binding("name = {{name}}", {"name": value}, dialect)
        out = run("select id from orders", "orders", b, dialect)
        reparsed = sqlglot.parse_one(out, dialect=dialect)
        literals = [lit.this for lit in reparsed.find_all(sqlglot.exp.Literal) if lit.is_string]
        assert literals == [value]  # exactly one string literal, equal to the raw value


@pytest.mark.parametrize(
    "supplied",
    [
        {"tenant_id": "1 OR 1=1"},
        {"tenant_id": True},
        {"tenant_id": 1.5},
        {"tenant_id": None},
        {},
        {"tenant_id": [1]},
    ],
)
def test_bad_long_values_are_rejected(supplied: dict[str, object]) -> None:
    with pytest.raises(ExtRejection):
        binding("tenant_id = {{tenant_id}}", supplied)


def test_param_value_checks() -> None:
    for bad in ({"name": "a\nb"}, {"name": "a\x00b"}, {"name": 5}, {"name": "x" * 300}):
        with pytest.raises(ExtRejection):
            binding("name = {{name}}", bad)
    with pytest.raises(ExtRejection):
        binding("day = {{day}}", {"day": "2024-13-45"})
    with pytest.raises(ExtRejection):
        binding("day = {{day}}", {"day": "2024-01-01 or 1=1"})
    assert "'2024-02-29'" in binding("day = {{day}}", {"day": "2024-02-29"}).predicates[0].sql()
    with pytest.raises(ExtRejection):
        binding("id IN ({{ids}})", {"ids": []})
    with pytest.raises(ExtRejection):
        binding("id IN ({{ids}})", {"ids": list(range(1001))})
    with pytest.raises(ExtRejection):
        binding("id IN ({{ids}})", {"ids": [1, "x"]})
    assert binding("id IN ({{ids}})", {"ids": [1, 2]}).predicates[0].sql() == "id IN (1, 2)"


@pytest.mark.parametrize(
    "template",
    [
        "tenant_id = (select 1)",
        "tenant_id = {{tenant_id}}; drop table x",
        "tenant_id = {{tenant_id}} -- c",
        "lower(name) = {{name}}",
        "sleep(1) = 0",
        "t.tenant_id = {{tenant_id}}",
        "tenant_id = {{unknown}}",
        "{{tenant_id}} = {{tenant_id}} AND x = {{tenant_id}} OR (select 1)",
        "exists (select 1)",
        "",
        "   ",
        "a = 1 and",
    ],
)
def test_templates_outside_the_predicate_grammar_are_rejected(template: str) -> None:
    with pytest.raises(ExtRejection):
        compile_template(template, P, dialect="mysql")


def test_missing_required_param_rejects_at_render_time() -> None:
    t = compile_template("tenant_id = {{tenant_id}}", P, dialect="mysql")
    with pytest.raises(ExtRejection) as error:
        render(t, {})
    assert error.value.reason == "row_filter_param_missing"


def test_qualified_columns_on_a_filtered_table_are_refused() -> None:
    b = binding("tenant_id = {{tenant_id}}", {"tenant_id": 7})
    with pytest.raises(ExtRejection):
        run("select db1.orders.id from db1.orders", "orders", b)


def test_verification_catches_an_unwrapped_reference() -> None:
    b = binding("tenant_id = {{tenant_id}}", {"tenant_id": 7})
    lookup = lookup_for("orders", b)
    with pytest.raises(ExtRejection):
        verify("select id from orders", lookup, dialect="mysql")
    with pytest.raises(ExtRejection):  # wrapper with the wrong predicate
        verify(
            "select id from (select * from orders where tenant_id = 8) as orders",
            lookup,
            dialect="mysql",
        )
    with pytest.raises(ExtRejection):  # wrapper projecting fewer columns is not our wrapper
        verify(
            "select id from (select id from orders where tenant_id = 7) as orders",
            lookup,
            dialect="mysql",
        )
    verify(
        "select id from (select * from orders where tenant_id = 7) as orders",
        lookup,
        dialect="mysql",
    )
