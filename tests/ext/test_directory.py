from unittest.mock import MagicMock

from adg.mcp_api.runtime_tools import dispatch_runtime_tool_call
from adg.policy.runtime import IdentityContext
from adg_ext.directory import lookup, resolve_caller


def test_lookup_returns_the_header_value_without_changing_the_connection() -> None:
    found = lookup(
        " Kinch@Example.com ",
        lambda key: '{"v":1,"status":"active","openId":"ou_a","name":"Kinch"}'
        if key == "gw:directory:email:kinch@example.com"
        else None,
    )

    assert found["status"] == "ok"
    assert found["open_id"] == "ou_a"
    assert found["header_name"] == "X-GW-Person"
    assert found["header_value"] == "ou_a"
    assert found["reload_required"] is False
    assert "email" in found["message"] and "不要把 open_id" in found["message"]


def test_lookup_rejects_missing_ambiguous_and_invalid_email() -> None:
    store = {
        "gw:directory:email:gone@example.com": '{"status":"disabled"}',
        "gw:directory:email:two@example.com": '{"status":"ambiguous"}',
    }

    assert lookup("gone@example.com", store.get)["reason"] == "person_not_found"
    assert lookup("two@example.com", store.get)["reason"] == "email_ambiguous"
    assert lookup("not-an-email", store.get)["reason"] == "email_invalid"


def test_lookup_reports_cache_outage_separately() -> None:
    def broken(_key: str) -> str | None:
        raise RuntimeError("down")

    assert lookup("a@example.com", broken)["reason"] == "directory_unavailable"


def _active(open_id: str) -> str:
    return f'{{"v":1,"status":"active","openId":"{open_id}","name":"Kinch"}}'


def test_email_resolves_only_when_the_header_is_absent() -> None:
    store = {"gw:directory:email:kinch@example.com": _active("ou_mail")}

    assert resolve_caller(" ou_header ", None, store.get)["open_id"] == "ou_header"
    assert resolve_caller(None, "", store.get)["open_id"] is None
    assert resolve_caller(None, " Kinch@Example.com ", store.get)["open_id"] == "ou_mail"
    matched = resolve_caller("ou_mail", "kinch@example.com", store.get)
    assert matched == {"status": "ok", "open_id": "ou_mail"}


def test_email_and_header_must_name_one_person() -> None:
    store = {
        "gw:directory:email:kinch@example.com": _active("ou_mail"),
        "gw:directory:email:two@example.com": '{"status":"ambiguous"}',
    }

    conflict = resolve_caller("ou_header", "kinch@example.com", store.get)
    assert conflict["reason"] == "person_conflict"
    assert resolve_caller(None, "not-a-person", store.get)["reason"] == "email_invalid"
    assert resolve_caller("ou_header", "two@example.com", store.get)["reason"] == "email_ambiguous"
    assert resolve_caller(None, "missing@example.com", store.get)["reason"] == "person_not_found"


def test_resolve_person_does_not_require_the_person_header() -> None:
    runtime = MagicMock()
    runtime.resolve_person.return_value = {"status": "ok"}
    runtime.audience_block.return_value = "person_required"

    result = dispatch_runtime_tool_call(
        runtime,
        "resolve_person",
        {"email": "a@example.com"},
        IdentityContext(user_id="grant-user"),
        "key-1",
        {"person": None, "scope": None},
    )

    assert result == {"status": "ok"}
    runtime.audience_block.assert_not_called()
    runtime.resolve_person.assert_called_once_with(
        identity=IdentityContext(user_id="grant-user"),
        api_key_id="key-1",
        email="a@example.com",
    )


def _query_runtime() -> MagicMock:
    runtime = MagicMock()
    runtime.audience_block.return_value = None
    runtime.preview_resource.return_value = {"status": "ok"}
    runtime.execute_query.return_value = {"status": "ok"}
    runtime.list_datasources.return_value = {"datasources": []}
    return runtime


def test_query_uses_the_resolved_open_id_and_keeps_scope(monkeypatch) -> None:
    monkeypatch.setattr(
        "adg_ext.directory.lookup",
        lambda email, redis_get=None: {"status": "ok", "open_id": "ou_mail", "message": "x"},
    )
    runtime = _query_runtime()

    result = dispatch_runtime_tool_call(
        runtime,
        "execute_query",
        {
            "datasource_id": "ds",
            "resource_ids": ["res"],
            "query": "select id from dataeye.product",
            "email": " kinch@example.com ",
        },
        IdentityContext(user_id="grant-user"),
        "key-1",
        {"person": None, "scope": '{"v":1}'},
    )

    assert result == {"status": "ok"}
    headers = runtime.execute_query.call_args.kwargs["disclosure_headers"]
    assert headers == {"person": "ou_mail", "scope": '{"v":1}'}
    runtime.audience_block.assert_called_once_with(
        IdentityContext(user_id="grant-user"),
        "ou_mail",
    )


def test_bad_email_rejects_before_query_and_audience() -> None:
    runtime = _query_runtime()

    result = dispatch_runtime_tool_call(
        runtime,
        "preview_resource",
        {"resource_id": "res", "email": "ou_not_an_email"},
        IdentityContext(user_id="grant-user"),
        "key-1",
        {"person": "ou_header", "scope": None},
    )

    assert result["status"] == "rejected"
    assert result["reason"] == "email_invalid"
    runtime.preview_resource.assert_not_called()
    runtime.audience_block.assert_not_called()


def test_absent_identity_still_reaches_the_existing_query_path() -> None:
    runtime = _query_runtime()

    dispatch_runtime_tool_call(
        runtime,
        "preview_resource",
        {"resource_id": "res"},
        IdentityContext(user_id="grant-user"),
        "key-1",
        {"person": None, "scope": None},
    )

    headers = runtime.preview_resource.call_args.kwargs["disclosure_headers"]
    assert headers["person"] is None


def test_row_tool_without_a_person_explains_the_email_fallback() -> None:
    runtime = _query_runtime()
    runtime.audience_block.return_value = "person_required"

    result = dispatch_runtime_tool_call(
        runtime,
        "execute_query",
        {"datasource_id": "ds", "resource_ids": [], "query": "select 1"},
        IdentityContext(user_id="grant-user"),
        "key-1",
        None,
    )

    assert result["reason"] == "person_required"
    assert "email" in result["message"] and "X-GW-Person" in result["message"]
    runtime.execute_query.assert_not_called()


def test_catalog_without_a_person_still_asks_for_the_header() -> None:
    runtime = _query_runtime()
    runtime.audience_block.return_value = "person_required"

    result = dispatch_runtime_tool_call(
        runtime,
        "list_datasources",
        {},
        IdentityContext(user_id="grant-user"),
        "key-1",
        None,
    )

    assert result["reason"] == "person_required"
    assert "请求头" in result["message"]
    assert "email" not in result["message"]
    runtime.list_datasources.assert_not_called()
