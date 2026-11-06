"""Explain a rejected or failed MCP tool result so a calling agent can act on it.

``reason`` stays the stable code used by audit and metrics. ``message`` is the
sentence the agent should show. A result that already has ``message`` is left
alone.
"""

from __future__ import annotations

from typing import Any

from adg_ext.audience import audience_message

_TEXT = {
    "person_required": (
        "这份数据权限开了动态权限。请求头 X-GW-Person 和本次调用的 email 都没有，"
        "网关不知道现在是谁，已拒绝查询，没有改成查整张表。"
        "接入服务请在请求头写通讯录 open_id。"
        "模型请在本次调用传入当前这个人的企业邮箱，不要猜测。"
    ),
    "person_conflict": (
        "请求头 X-GW-Person 和本次 email 查到的不是同一个人，已拒绝查询，没有改成查整张表。"
    ),
    "person_not_entitled": audience_message("person_not_entitled"),
    "disclosure_conflict": "这条授权同时开了多份动态权限，网关无法决定按哪一份过滤，已拒绝查询。",
    "disclosure_column_missing": (
        "这次查询碰到的表里有还没绑定披露列的表。按当前策略整次拒绝，不会改成查整张表。"
    ),
    "disclosure_param_conflict": "查询参数占用了网关的动态权限参数名，请去掉后重试。",
    "disclosure_value_invalid": "这个人的取值不是合法的编号列表，查询已拒绝，没有改成查整张表。",
    "external_scope_required": (
        "这份动态权限由调用方提供取值。请求头 X-GW-Scope 缺失、不是约定的 JSON，"
        "或 values 为空，查询已拒绝。"
    ),
    "external_scope_too_large": "请求头 X-GW-Scope 里的取值过长，查询已拒绝。",
    "external_scope_unsupported": "请求头 X-GW-Scope 的版本不是 1，查询已拒绝。",
    "external_scope_mismatch": "请求头 X-GW-Scope 里的动态权限编号和这条授权不一致，查询已拒绝。",
    "person_scope_too_large": "这个人的取值太多，网关拒绝查询，没有改成查整张表。",
    "runtime_limit_invalid": "limit 必须是正整数。",
    "runtime_limit_exceeded": "limit 超过这条授权允许的单次最大行数。",
    "datasource_disabled": "数据源已停用，不能查询。",
    "resource_disabled": "这张表已停用，不能查询。",
    "table_not_accessible": (
        "SQL 里的表不在这把密钥能读的范围内，或没有在 resource_ids 里声明。"
        "网关不会说明这张表是否存在。"
    ),
    "unknown_sql_resource": (
        "SQL 里的表无法对应到已授权的对象。"
        "请先用 list_resources 拿到 resource_id，再放进 resource_ids。"
    ),
    "actual_resource_outside_declared_scope": (
        "SQL 用到的表超出了本次传入的 resource_ids。把用到的表都放进 resource_ids。"
    ),
    "no_readable_fields": "这张表在这份数据权限里没有可读列，不能预览。",
    "no_policy_default_deny": "没有匹配到允许策略，默认拒绝。",
    "no_matching_allow": "没有匹配到允许这条访问的策略。",
    "denied_by_policy": "策略明确拒绝了这次访问。",
    "field_not_in_scope": "查询用到的列不在已声明的列范围内。",
    "field_disabled": "查询用到的列已停用。",
    "field_access_denied": "查询用到的列不在这份数据权限的可读列里。",
    "column_not_allowed": "查询用到了这份数据权限没有开放的列。",
    "masked_column_position_not_allowed": "脱敏列不能出现在这个位置。",
    "row_filter_column_not_permitted": "行过滤用到的列不在可读列里。",
    "wildcard_projection_not_allowed": "不能使用 SELECT *。请列出 list 或 describe 里看到的列名。",
    "statement_not_allowed": "只允许一条只读查询，不能执行写入、DDL 或多条语句。",
    "time_range_required": "这份数据权限要求查询带上时间范围。",
    "function_not_allowed": "查询使用了这份数据权限禁止的函数。",
    "syntax_not_allowed": "查询使用了这份数据权限禁止的语法。",
    "rewrite_parse_failed": "网关无法安全改写这条 SQL，已拒绝执行。",
    "audit_unavailable": "审计暂时写不进去，查询被拒绝。请稍后再试。",
    "admission_pool_exhausted": "网关控制库连接已满，请稍后再试。",
    "admission_queue_full": "这条授权的查询排队已满，请稍后再试。",
    "admission_queue_timeout": "排队等待超时，查询没有开始执行。请稍后再试。",
    "admission_datasource_busy": "这个数据源当前查询过多，请稍后再试。",
    "admission_circuit_open": "这个数据源连续失败，网关暂时停止向它发查询。请稍后再试。",
    "admission_revoked": "这次查询在排队时被取消。",
    "hint_not_allowed": "SQL 里不能带优化器 hint。",
    "query_settings_not_allowed": "SQL 里不能带 SETTINGS。",
    "output_format_not_allowed": "SQL 里不能指定输出格式。",
    "into_outfile_not_allowed": "不能把结果写到文件。",
    "locking_read_not_allowed": "不能使用锁读。",
    "system_database_not_allowed": "不能查询系统库。",
    "catalog_not_allowed": "不能切换或查询其他 catalog。",
    "variable_not_allowed": "不能读取或设置数据库变量。",
    "table_function_not_allowed": "不能使用表函数。",
    "email_invalid": "需要完整的企业邮箱。",
    "email_ambiguous": "这个邮箱对应多名在职人员，不能确定 open_id。",
    "person_not_found": "通讯录里没有这个在职邮箱。",
    "directory_unavailable": "通讯录缓存暂时不可用，请稍后再试。",
}


_ERROR = {
    "query_timeout": "查询超过时限，已被取消。",
    "query_cancelled": "访问被收回，查询已取消。",
    "datasource_unavailable": "数据源暂时不可用，请稍后再试。",
    "connector_operation_error": "查询执行失败。请把 query_id 交给网关管理员，不要重试同一条语句。",
    "connector_dependency_error": "数据源连接组件不可用，请联系管理员。",
    "circuit_open": "这个数据源连续失败，网关暂时停止向它发查询。请稍后再试。",
    "timeout": "数据源查询超时。",
}


def attach_agent_message(body: dict[str, Any]) -> dict[str, Any]:
    """Add ``message`` when a tool result is rejected or failed and does not explain itself."""

    if body.get("message"):
        return body
    status = body.get("status")
    if status not in {"rejected", "error"}:
        return body
    reason = body.get("reason")
    if isinstance(reason, str) and reason:
        explained = dict(body)
        explained["message"] = _with_hint(explain_reason(reason), body.get("hint"))
        return explained
    error = body.get("error")
    if isinstance(error, dict):
        kind = error.get("type")
        text = _ERROR.get(kind) if isinstance(kind, str) else None
        if text is None:
            raw = error.get("message")
            text = raw if isinstance(raw, str) and raw else None
        if text:
            query_id = body.get("query_id")
            if isinstance(query_id, str) and query_id and "query_id" not in text:
                text = f"{text} query_id：{query_id}。"
            explained = dict(body)
            explained["message"] = text
            return explained
    return body


def _with_hint(message: str, hint: object) -> str:
    if isinstance(hint, dict) and hint.get("allowed_columns"):
        return message + " 允许使用的列在 hint.allowed_columns。"
    return message


def explain_reason(reason: str) -> str:
    parts = [part.strip() for part in reason.split(",") if part.strip()]
    if len(parts) > 1:
        return "；".join(explain_reason(part) for part in parts)
    code, separator, detail = reason.partition(":")
    if separator and _cjk(detail) and code in _TEXT:
        return _TEXT[code] + detail
    if not separator and _cjk(reason):
        return reason
    text = _TEXT.get(code) or _prefix_text(code)
    if text is None:
        return (
            f"请求被拒绝，原因码是 {reason}。请把 reason 原样交给网关管理员，"
            "不要把它理解成库或表不存在。"
        )
    if detail and not _cjk(detail):
        return f"{text} 具体对象：{detail}。"
    return text


_PREFIX = (
    ("row_filter_", "行过滤条件无法套用，查询已拒绝。"),
    ("masked_", "脱敏列不能这样使用。"),
    ("cte_", "WITH 子句不符合只读查询限制。"),
    ("admission_", "查询没有排到执行名额，请稍后再试。"),
)


def _prefix_text(code: str) -> str | None:
    for prefix, text in _PREFIX:
        if code.startswith(prefix):
            return text
    return None


def _cjk(value: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in value)
