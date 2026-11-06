from adg.mcp_api.agent_message import attach_agent_message, explain_reason


def test_success_payloads_stay_unchanged() -> None:
    body = {"datasources": [], "resources": []}
    assert attach_agent_message(body) is body


def test_existing_message_is_kept() -> None:
    body = {"status": "rejected", "reason": "person_required", "message": "已有说明"}
    assert attach_agent_message(body)["message"] == "已有说明"


def test_codes_explain_the_next_step() -> None:
    missing = explain_reason("person_required")
    hidden = explain_reason("column_not_allowed:salary")
    several = explain_reason("statement_not_allowed,wildcard_projection_not_allowed")
    prose = explain_reason("你还没有这项数据的查询权限。请联系数据负责人。")
    assert "X-GW-Person" in missing and "email" in missing
    assert "同一个人" in explain_reason("person_conflict")
    assert "salary" in hidden and "没有开放的列" in hidden
    assert "；" in several and "SELECT *" in several
    assert prose.startswith("你还没有")
    assert "不要把它理解成库或表不存在" in explain_reason("some_new_code")
    assert "WITH" in explain_reason("cte_non_select_not_allowed")
    assert "行过滤" in explain_reason("row_filter_param_missing:tenant")


def test_connector_error_message_is_lifted() -> None:
    body = attach_agent_message(
        {
            "query_id": "qry_1",
            "status": "error",
            "error": {"type": "query_timeout", "message": "The query exceeded its time limit."},
        }
    )
    assert "超过时限" in body["message"]
    assert "qry_1" in body["message"]
    assert body["error"]["message"].startswith("The query")


def test_allowed_columns_stay_in_the_hint() -> None:
    body = attach_agent_message(
        {
            "status": "rejected",
            "reason": "column_not_allowed:salary",
            "hint": {"allowed_columns": {"dataeye.product": ["id"]}},
        }
    )
    assert "salary" in body["message"]
    assert "hint.allowed_columns" in body["message"]
    assert body["hint"]["allowed_columns"]["dataeye.product"] == ["id"]
