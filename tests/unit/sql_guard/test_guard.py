import pytest

from adg.sql_guard.guard import SqlGuard


def test_guard_allows_select_and_injects_default_limit() -> None:
    result = SqlGuard(default_limit=100, max_limit=500).check(
        "select id, name from public.customers"
    )

    assert result.allowed is True
    assert result.statement_type == "SELECT"
    assert result.normalized_sql is not None
    assert "LIMIT 100" in result.normalized_sql
    assert result.accessed_resources == ["public.customers"]
    assert result.accessed_fields == ["id", "name"]
    assert result.risk_level == "low"


def test_guard_allows_read_only_cte_and_excludes_cte_alias_from_resources() -> None:
    result = SqlGuard(default_limit=100, max_limit=500).check(
        "with recent_customers as ("
        "select id, name from public.customers"
        ") select id, name from recent_customers"
    )

    assert result.allowed is True
    assert result.normalized_sql is not None
    assert "LIMIT 100" in result.normalized_sql
    assert result.accessed_resources == ["public.customers"]
    assert result.accessed_fields == ["id", "name"]


def test_guard_rejects_data_modifying_cte_even_in_admin_mode() -> None:
    result = SqlGuard(execution_mode="admin").check(
        "with customers as ("
        "update public.customers set name = 'Alice' where id = 1 returning id"
        ") select id from customers"
    )

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["cte_non_select_not_allowed"]


def test_guard_rejects_data_modifying_cte_nested_in_subquery() -> None:
    result = SqlGuard().check(
        "select id from ("
        "with changed as ("
        "update public.customers set name = 'Alice' where id = 1 returning id"
        ") select id from changed"
        ") nested_customers"
    )

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["cte_non_select_not_allowed"]


def test_guard_rejects_non_select_final_statement_for_cte_even_in_admin_mode() -> None:
    result = SqlGuard(execution_mode="admin").check(
        "with selected_customers as ("
        "select id from public.customers"
        ") update public.customers set name = 'Alice' "
        "where id in (select id from selected_customers)"
    )

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["cte_final_statement_not_allowed"]


def test_guard_rejects_recursive_cte() -> None:
    result = SqlGuard().check(
        "with recursive series(n) as ("
        "select 1 union all select n + 1 from series where n < 3"
        ") select n from series"
    )

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["recursive_cte_not_allowed"]


def test_guard_tracks_cte_source_fields_without_cte_output_aliases() -> None:
    result = SqlGuard().check(
        "with customer_email as ("
        "select email as leaked from public.customers"
        ") select leaked from customer_email"
    )

    assert result.allowed is True
    assert result.accessed_fields == ["email"]


def test_guard_rejects_locking_read_inside_cte() -> None:
    result = SqlGuard().check(
        "with locked_customers as ("
        "select id from public.customers for update"
        ") select id from locked_customers"
    )

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["cte_locking_read_not_allowed"]


def test_guard_rejects_locking_read_nested_inside_cte() -> None:
    result = SqlGuard().check(
        "with customer_ids as ("
        "select id from (select id from public.customers for update) locked_customers"
        ") select id from customer_ids"
    )

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["cte_locking_read_not_allowed"]


def test_guard_rejects_non_literal_limit_inside_cte() -> None:
    result = SqlGuard().check(
        "with limited_customers as ("
        "select id from public.customers limit ?"
        ") select id from limited_customers"
    )

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["non_literal_limit_not_allowed"]


def test_guard_rejects_cte_limit_above_maximum() -> None:
    result = SqlGuard(default_limit=100, max_limit=500).check(
        "with limited_customers as ("
        "select id from public.customers limit 501"
        ") select id from limited_customers"
    )

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["cte_limit_exceeded"]


def test_guard_rejects_cte_wildcard_even_with_relaxed_validation() -> None:
    result = SqlGuard(strict_validation=False).check(
        "with customer_data as ("
        "select * from public.customers"
        ") select email from customer_data"
    )

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["cte_wildcard_projection_not_allowed"]


def test_guard_tracks_projection_output_lineage() -> None:
    result = SqlGuard(strict_validation=False).check(
        "select email as leaked, lower(phone) as normalized_phone from public.customers"
    )

    assert result.allowed is True
    assert [
        (projection.output_name, projection.source_fields)
        for projection in result.projections
    ] == [
        ("leaked", ("email",)),
        ("normalized_phone", ("phone",)),
    ]


def test_guard_allows_unaliased_expression() -> None:
    result = SqlGuard().check("select lower(email), id + 1 from public.customers")

    assert result.allowed is True
    assert result.normalized_sql is not None


def test_guard_reduces_limit_to_maximum() -> None:
    result = SqlGuard(default_limit=100, max_limit=500).check(
        "select id from public.customers limit 900"
    )

    assert result.allowed is True
    assert result.normalized_sql is not None
    assert "LIMIT 500" in result.normalized_sql


def test_guard_rejects_mutation_statement() -> None:
    result = SqlGuard().check("delete from public.customers where id = 1")

    assert result.allowed is False
    assert "statement_not_allowed" in result.rejection_reasons


@pytest.mark.parametrize(
    "query",
    [
        "explain analyze delete from public.customers where id = 1",
        "explain update public.customers set name = 'Alice' where id = 1",
    ],
)
def test_guard_rejects_explain_commands_that_can_execute_mutations(query: str) -> None:
    result = SqlGuard().check(query)

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["statement_not_allowed"]


@pytest.mark.parametrize(
    "query,rejection",
    [
        (
            "select id into archived_customers from public.customers",
            "select_into_not_allowed",
        ),
        ("select id from public.customers for update", "locking_read_not_allowed"),
        ("select id from public.customers for share", "locking_read_not_allowed"),
    ],
)
def test_guard_rejects_select_side_effects_even_with_relaxed_validation(
    query: str,
    rejection: str,
) -> None:
    result = SqlGuard(strict_validation=False).check(query)

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == [rejection]


def test_guard_only_allows_select_into_in_schema_mode() -> None:
    result = SqlGuard(execution_mode="schema").check(
        "select id into archived_customers from public.customers"
    )

    assert result.allowed is True
    assert result.normalized_sql is not None
    assert result.normalized_sql.startswith("CREATE TABLE archived_customers AS SELECT")


@pytest.mark.parametrize(
    "sql",
    [
        "create table public.customers_archive (id int)",
        "update public.customers set name = 'Alice' where id = 1",
        "insert into public.customers (id, name) values (1, 'Alice')",
        "delete from public.customers where id = 1",
        "drop table public.customers",
        "truncate table public.customers",
        "alter table public.customers add column name text",
    ],
)
def test_guard_rejects_write_statements_in_read_only_mode(sql: str) -> None:
    result = SqlGuard().check(sql)

    assert result.allowed is False
    assert "statement_not_allowed" in result.rejection_reasons


@pytest.mark.parametrize(
    "sql",
    [
        "update public.customers set name = 'Alice' where id = 1",
        "insert into public.customers (id, name) values (1, 'Alice')",
        "delete from public.customers where id = 1",
        "merge into public.customers using public.customer_updates "
        "on customers.id = customer_updates.id "
        "when matched then update set name = customer_updates.name",
    ],
)
def test_guard_dml_mode_allows_dml_statements(sql: str) -> None:
    result = SqlGuard(execution_mode="dml").check(sql)

    assert result.allowed is True
    assert result.normalized_sql is not None


@pytest.mark.parametrize(
    "sql",
    [
        "create table public.customers_archive (id int)",
        "drop table public.customers_archive",
        "alter table public.customers add column name text",
        "truncate table public.customers",
    ],
)
def test_guard_dml_mode_rejects_schema_statements(sql: str) -> None:
    result = SqlGuard(execution_mode="dml").check(sql)

    assert result.allowed is False
    assert "statement_not_allowed" in result.rejection_reasons


@pytest.mark.parametrize(
    "sql",
    [
        "create table public.customers_archive (id int)",
        "drop table public.customers_archive",
        "alter table public.customers add column name text",
        "truncate table public.customers",
    ],
)
def test_guard_schema_mode_allows_schema_statements(sql: str) -> None:
    result = SqlGuard(execution_mode="schema").check(sql)

    assert result.allowed is True
    assert result.normalized_sql is not None


@pytest.mark.parametrize(
    "sql",
    [
        "grant select on public.customers to analyst",
        "revoke select on public.customers from analyst",
        "set role all",
        "call refresh_customer_cache()",
        "copy public.customers from stdin",
    ],
)
def test_guard_admin_mode_allows_admin_statements(sql: str) -> None:
    result = SqlGuard(execution_mode="admin").check(sql)

    assert result.allowed is True
    assert result.normalized_sql is not None


def test_guard_schema_mode_rejects_admin_statements() -> None:
    result = SqlGuard(execution_mode="schema").check("grant select on public.customers to analyst")

    assert result.allowed is False
    assert "statement_not_allowed" in result.rejection_reasons


def test_guard_rejects_multiple_statements() -> None:
    result = SqlGuard().check("select id from public.customers; select id from public.orders")

    assert result.allowed is False
    assert "multiple_statements" in result.rejection_reasons


def test_guard_rejects_select_star() -> None:
    result = SqlGuard().check("select * from public.customers")

    assert result.allowed is False
    assert result.normalized_sql is None
    assert "wildcard_projection_not_allowed" in result.rejection_reasons


def test_guard_allows_star_over_a_derived_table() -> None:
    wrapped = SqlGuard().check(
        "select * from (select id, name from public.customers order by updated_at desc limit 3) "
        "as miao_sql_result limit 3"
    )
    cte = SqlGuard().check(
        "with c as (select id, name from public.customers) select * from c"
    )

    assert wrapped.allowed is True
    assert cte.allowed is True
    assert "wildcard_projection_not_allowed" not in wrapped.rejection_reasons


def test_guard_rejects_qualified_wildcard() -> None:
    result = SqlGuard().check("select c.*, c.id from public.customers c")

    assert result.allowed is False
    assert result.normalized_sql is None
    assert "wildcard_projection_not_allowed" in result.rejection_reasons


def test_guard_rejects_side_effect_functions() -> None:
    result = SqlGuard().check("select sleep(5) from public.customers")

    assert result.allowed is False
    assert "function_not_allowed:sleep" in result.rejection_reasons


def test_guard_relaxed_validation_allows_non_allowlisted_select_features() -> None:
    result = SqlGuard(strict_validation=False).check(
        "select *, md5(email) as email_hash from public.customers"
    )

    assert result.allowed is True
    assert result.normalized_sql is not None
    assert result.used_functions == ["md5"]
    assert "LIMIT 100" in result.normalized_sql


def test_guard_marks_relaxed_wildcard_and_nested_projection_boundaries() -> None:
    wildcard = SqlGuard(strict_validation=False).check(
        "select *, email as leaked from public.customers"
    )
    nested = SqlGuard().check(
        "select t.leaked from (select email as leaked from public.customers) t"
    )

    assert wildcard.allowed is True
    assert any(projection.is_wildcard for projection in wildcard.projections)
    assert nested.allowed is True
    assert all(projection.has_nested_select for projection in nested.projections)


def test_guard_rejects_case_insensitive_duplicate_projection_names() -> None:
    result = SqlGuard().check('select email as x, email as "X" from public.customers')

    assert result.allowed is False
    assert result.normalized_sql is None
    assert result.rejection_reasons == ["duplicate_projection_output_name"]


def test_guard_allows_boolean_predicates() -> None:
    result = SqlGuard().check(
        "select id, total from public.orders "
        "where (status = 'paid' and total > 100) or status = 'refunded'"
    )

    assert result.allowed is True
    assert result.normalized_sql is not None
    assert result.used_functions == []
    assert "AND" in result.normalized_sql
    assert "OR" in result.normalized_sql


def test_guard_allows_common_date_predicates() -> None:
    result = SqlGuard().check(
        "select id from public.orders where created_at >= current_date - interval '30 days'"
    )

    assert result.allowed is True
    assert result.normalized_sql is not None
    assert result.used_functions == []


def test_guard_allows_date_literal_casts() -> None:
    result = SqlGuard().check("select id from public.orders where created_at >= date '2026-05-15'")

    assert result.allowed is True
    assert result.normalized_sql is not None
    assert result.used_functions == []


def test_guard_allows_cast_of_a_granted_column() -> None:
    result = SqlGuard().check("select cast(email as char) as email_text from public.customers")

    assert result.allowed is True
    assert result.normalized_sql is not None


@pytest.mark.parametrize(
    "query",
    [
        "select order_detail_id, create_time "
        "from prod_welfare.ods_t_after_sale_handle_record "
        "where date(create_time) > '2024-09-30'",
        "select id from public.orders where cast(created_at as date) >= '2026-05-15'",
        "select id from public.orders where date_trunc('day', created_at) >= '2026-05-15'",
        "select id from public.orders where year(created_at) = 2026 "
        "and month(created_at) = 5 and day(created_at) = 15",
        "select id from public.orders where date_format(created_at, '%Y-%m-%d') >= '2026-05-15'",
        "select id from public.orders where to_date(created_at) >= '2026-05-15'",
        "select id from public.orders where created_at >= date_sub(current_date, interval 30 day)",
        "select id from public.orders where datediff(current_date, created_at) <= 30",
        "select id from public.orders "
        "where timestampdiff(day, created_at, current_timestamp) <= 30",
        "select id from public.orders where from_unixtime(created_at_epoch) >= '2026-05-15'",
        "select id from public.orders where unix_timestamp(created_at) >= 1778803200",
    ],
)
def test_guard_allows_common_temporal_predicate_functions(query: str) -> None:
    result = SqlGuard().check(query)

    assert result.allowed is True
    assert result.normalized_sql is not None


@pytest.mark.parametrize(
    "query",
    [
        "select date(created_at) as created_day from public.orders",
        "select date_format(created_at, '%Y-%m-%d') as created_day from public.orders",
        "select cast(created_at as date) as created_day from public.orders",
        "select id from public.orders union all select id from public.orders",
        "select id from public.orders except select id from public.orders",
        "select row_number() over (order by id) as n from public.orders",
        "select concat(id, '-'), coalesce(id, 0), case when id > 0 then id end from public.orders",
    ],
)
def test_guard_allows_read_structures_inside_the_grant(query: str) -> None:
    result = SqlGuard(default_limit=100, max_limit=100).check(query)

    assert result.allowed is True, result.rejection_reasons
    assert result.normalized_sql is not None
    assert "LIMIT 100" in result.normalized_sql


def test_guard_allows_common_aggregate_functions() -> None:
    result = SqlGuard().check("select count(*), sum(total) from public.orders")

    assert result.allowed is True
    assert result.used_functions == ["count", "sum"]


@pytest.mark.parametrize(
    "query",
    [
        "select id from public.customers limit ?",
        "select id from public.customers limit :limit",
        "select id from public.customers limit 10 + 5",
    ],
)
def test_guard_rejects_non_literal_limit(query: str) -> None:
    result = SqlGuard(default_limit=100, max_limit=500).check(query)

    assert result.allowed is False
    assert result.normalized_sql is None
    assert "non_literal_limit_not_allowed" in result.rejection_reasons
