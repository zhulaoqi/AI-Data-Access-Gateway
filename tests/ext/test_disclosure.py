from adg_ext.analyze import TableView
from adg_ext.disclosure import bind, parse_external, resolve_values


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
    assert "creator_id IN" in view.filters[0].where

    jdbc = bind(
        {"dimensionId": "dim_1", "source": "manual", "columns": [{"database": "shop", "table": "orders", "column": "creator_id"}]},
        [_view()],
        {},
        channel="jdbc",
        headers=None,
        lookup=lambda _d, _p: ["10086"],
    )
    assert jdbc == "disclosure_not_supported_on_jdbc"


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
