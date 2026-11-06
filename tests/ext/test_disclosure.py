from adg_ext.analyze import TableView
from adg_ext.disclosure import bind, parse_external, resolve_values, trace
from adg_ext.rowfilter import compile_template, render


def _view() -> TableView:
    return TableView(
        path="shop.orders",
        restricted=True,
        allow=frozenset({"creator_id", "id"}),
        filters=[None],
    )


def test_external_header_accepts_version_one() -> None:
    values, reason = parse_external(
        {"person": "agent-1", "scope": '{"v":1,"dimensionId":"dim_1","values":["10086","10086"]}'},
        "dim_1",
    )
    assert reason is None
    assert values == ["10086"]


def test_external_header_rejects_a_missing_or_foreign_dimension() -> None:
    assert parse_external({"person": "agent-1"}, "dim_1")[1] == "external_scope_required"
    assert (
        parse_external(
            {"person": "agent-1", "scope": '{"v":2,"dimensionId":"dim_1","values":["1"]}'},
            "dim_1",
        )[1]
        == "external_scope_unsupported"
    )
    assert (
        parse_external(
            {"person": "agent-1", "scope": '{"v":1,"dimensionId":"other","values":["1"]}'},
            "dim_1",
        )[1]
        == "external_scope_mismatch"
    )


def test_memory_hit_does_not_read_redis() -> None:
    calls = {"n": 0}

    def redis_get(_key: str) -> str:
        calls["n"] += 1
        return '{"v":1,"values":["9"]}'

    resolve_values("dim_mem", "ou_1", redis_get=redis_get, local_get=lambda: ["8"])
    assert calls["n"] == 1
    again = resolve_values("dim_mem", "ou_1", redis_get=redis_get, local_get=lambda: ["8"])
    assert again == ["9"]
    assert calls["n"] == 1


def test_bind_replaces_an_empty_row_filter_and_keeps_jdbc_closed() -> None:
    view = _view()
    params: dict[str, object] = {}
    reason = bind(
        {"dimensionId": "dim_1", "source": "manual", "columns": [{"database": "shop", "table": "orders", "column": "creator_id"}]},
        [view],
        params,
        channel="mcp",
        headers={"person": "ou_1"},
        lookup=lambda _d, _p: ["10086"],
    )
    assert reason is None
    assert params["gw_disclosure_values"] == ["10086"]
    assert view.filters[0] is not None
    assert view.filters[0].where == "`creator_id` IN ({{gw_disclosure_values}})"

    jdbc = bind(
        {"dimensionId": "dim_1", "source": "manual", "columns": [{"database": "shop", "table": "orders", "column": "creator_id"}]},
        [_view()],
        {},
        channel="jdbc",
        headers=None,
        lookup=lambda _d, _p: ["10086"],
    )
    assert jdbc == "disclosure_not_supported_on_jdbc"


def test_bind_quotes_spaces_and_non_ascii_and_rejects_breakout() -> None:
    name = "event 的列"
    view = TableView(path="shop.orders", restricted=True, allow=frozenset({name}), filters=[None])
    reason = bind(
        {"dimensionId": "dim_1", "source": "manual", "columns": [{"database": "shop", "table": "orders", "column": name}]},
        [view],
        {},
        channel="mcp",
        headers={"person": "ou_1"},
        lookup=lambda _d, _p: ["10086"],
    )
    assert reason is None
    assert view.filters[0] is not None
    assert view.filters[0].where == "`event 的列` IN ({{gw_disclosure_values}})"
    compile_template(view.filters[0].where, view.filters[0].params, dialect="mysql")

    quoted = TableView(path="shop.orders", restricted=True, allow=frozenset({"a`b"}), filters=[None])
    bind(
        {"dimensionId": "dim_1", "source": "manual", "columns": [{"database": "shop", "table": "orders", "column": "a`b"}]},
        [quoted],
        {},
        channel="mcp",
        headers={"person": "ou_1"},
        lookup=lambda _d, _p: ["1"],
    )
    assert quoted.filters[0] is not None
    assert quoted.filters[0].where.startswith("`a``b` IN")

    rejected = bind(
        {"dimensionId": "dim_1", "source": "manual", "columns": [{"database": "shop", "table": "orders", "column": "a;b"}]},
        [TableView(path="shop.orders", restricted=True, allow=frozenset({"a;b"}), filters=[None])],
        {},
        channel="mcp",
        headers={"person": "ou_1"},
        lookup=lambda _d, _p: ["1"],
    )
    assert rejected is not None
    assert rejected.startswith("row_filter_column_not_permitted:")


def test_comma_separated_values_become_separate_sql_literals() -> None:
    view = _view()
    params: dict[str, object] = {}
    reason = bind(
        {"dimensionId": "dim_1", "source": "manual", "columns": [{"database": "shop", "table": "orders", "column": "creator_id"}]},
        [view],
        params,
        channel="mcp",
        headers={"person": "ou_1"},
        lookup=lambda _d, _p: ["10086, 10087", "O'Brien"],
    )
    assert reason is None
    assert params["gw_disclosure_values"] == ["10086", "10087", "O'Brien"]
    assert view.filters[0] is not None
    template = compile_template(view.filters[0].where, view.filters[0].params, dialect="mysql")
    assert render(template, params).sql(dialect="mysql") == "`creator_id` IN ('10086', '10087', 'O''Brien')"

    rejected = bind(
        {"dimensionId": "dim_1", "source": "manual", "columns": [{"database": "shop", "table": "orders", "column": "creator_id"}]},
        [_view()],
        {},
        channel="mcp",
        headers={"person": "ou_1"},
        lookup=lambda _d, _p: ["10086，10087"],
    )
    assert rejected == "disclosure_value_invalid"

    external, external_reason = parse_external(
        {"person": "agent-1", "scope": '{"v":1,"dimensionId":"dim_1","values":["10086,10087"]}'},
        "dim_1",
    )
    assert external_reason is None
    assert external == ["10086", "10087"]


def test_pending_marker_does_not_fall_back_to_a_stale_local_copy() -> None:
    def redis_get(_key: str) -> str:
        return '{"v":1,"pending":true}'

    assert resolve_values("dim_pending", "ou_9", redis_get=redis_get, local_get=lambda: ["10086"]) is None


def test_missing_values_do_not_open_the_table() -> None:
    reason = bind(
        {"dimensionId": "dim_1", "source": "manual", "ownerNames": ["张三"], "columns": [{"database": "shop", "table": "orders", "column": "creator_id"}]},
        [_view()],
        {},
        channel="mcp",
        headers={"person": "ou_2"},
        lookup=lambda _d, _p: None,
    )
    assert reason is not None
    assert "张三" in reason
    assert "10086" not in reason


def test_trace_shows_a_missing_person_and_a_spliced_sample() -> None:
    missing = trace(
        {"dimensionId": "dim_1", "source": "manual"},
        {},
        channel="mcp",
        reason="person_required",
        values=None,
    )
    assert missing["person"] == "-"
    assert missing["attached"] == "no"
    assert missing["reason"] == "person_required"
    spliced = trace(
        {"dimensionId": "dim_1", "source": "manual"},
        {"person": "ou_2"},
        channel="mcp",
        reason=None,
        values=["10086", "10087", "10088", "10089", "10090", "10091"],
    )
    assert spliced["person"] == "ou_2"
    assert spliced["attached"] == "yes"
    assert spliced["values"] == 6
    assert spliced["sample"] == "10086,10087,10088,10089,10090,+1"
