from adg.policy.runtime import IdentityContext
from adg_ext.directory import lookup


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
    assert found["reload_required"] is True


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


def test_resolve_person_does_not_require_the_person_header() -> None:
    from unittest.mock import MagicMock

    from adg.mcp_api.runtime_tools import dispatch_runtime_tool_call

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
