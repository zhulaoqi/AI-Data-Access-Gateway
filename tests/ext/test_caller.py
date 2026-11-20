"""X-GW-Caller is stored on MCP audit rows and ignored for JDBC."""

from adg_ext.caller import HEADER, bound, normalize, stamp
from adg_ext.pipeline import _audit_meta


def test_header_name() -> None:
    assert HEADER == "X-GW-Caller"


def test_normalize_strips_controls_and_caps_length() -> None:
    assert normalize(None) is None
    assert normalize("   ") is None
    assert normalize(" \n alice@example.com \t") == "alice@example.com"
    assert normalize("a\x00b") == "ab"
    assert normalize("x" * 200) == "x" * 128


def test_stamp_is_a_noop_outside_an_mcp_call() -> None:
    assert stamp({"channel": "mcp", "tool": "list_datasources"}) == {
        "channel": "mcp",
        "tool": "list_datasources",
    }


def test_stamp_records_caller_only_for_mcp() -> None:
    with bound("  zhangsan@example.com  "):
        assert stamp({"tool": "list_datasources"}) == {
            "tool": "list_datasources",
            "channel": "mcp",
            "caller": "zhangsan@example.com",
        }
        assert stamp({"channel": "jdbc", "request_id": "req-1"}) == {
            "channel": "jdbc",
            "request_id": "req-1",
        }
        assert stamp({"channel": "mcp"})["caller"] == "zhangsan@example.com"
    assert stamp({"tool": "list_datasources"}) == {"tool": "list_datasources"}


def test_stamp_records_the_request_address_for_mcp_only() -> None:
    from adg_ext.clientip import reset_current, set_current

    token = set_current("203.0.113.9")
    try:
        with bound("alice@example.com"):
            row = stamp({"tool": "list_datasources"})
        assert row["client_ip"] == "203.0.113.9"
        assert row["caller"] == "alice@example.com"
        with bound(None):
            assert stamp({"channel": "jdbc", "request_id": "req-1"}) == {
                "channel": "jdbc",
                "request_id": "req-1",
            }
    finally:
        reset_current(token)


def test_audit_meta_keeps_mcp_caller_and_drops_it_for_jdbc() -> None:
    with bound("alice@example.com"):
        mcp = _audit_meta(None, None)
        jdbc = _audit_meta("req-1", {"channel": "jdbc", "request_id": "req-1"})
    assert mcp["channel"] == "mcp"
    assert mcp["caller"] == "alice@example.com"
    assert jdbc["channel"] == "jdbc"
    assert "caller" not in jdbc
    assert _audit_meta(None, None).get("caller") is None
