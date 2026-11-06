"""Grant audience. JDBC never calls this. An empty listed set rejects everyone."""

from __future__ import annotations

import json
from typing import Any


_MESSAGES = {
    "person_required": (
        "这条授权限定了可以提问的人。请求没有带 X-GW-Person，网关不知道现在是谁，"
        "所以没有返回库表。请在 MCP 连接的请求头里写上通讯录 open_id。"
    ),
    "person_not_entitled": (
        "这次请求标明的这个人不在这条授权的可见名单里，所以没有返回库表。"
        "请让签发人把该 open_id 加入授权可见性，或换成名单上的人。"
    ),
}

_QUERY_PERSON_REQUIRED = (
    "这条授权限定了可以提问的人。请求头 X-GW-Person 和本次调用的 email 都没有，"
    "网关不知道现在是谁，所以没有返回库表。"
    "接入服务请在请求头写通讯录 open_id。"
    "模型请在本次 preview_resource 或 execute_query 传入当前这个人的企业邮箱，不要猜测。"
)


def audience_message(reason: str) -> str:
    """Caller-facing explanation. The reason code stays stable for audit and metrics."""

    return _MESSAGES.get(reason, "这条授权的可见性不允许当前请求查看库表。原因：" + reason)


def query_identity_message(reason: str) -> str:
    """Row tools can name the person with this call's email when the header is absent."""

    if reason == "person_required":
        return _QUERY_PERSON_REQUIRED
    return audience_message(reason)


def audience_reason(raw: str | None, person: str | None) -> str | None:
    """None means this grant does not restrict who may call MCP."""

    if raw is None or raw == "":
        return None
    try:
        body: Any = json.loads(raw)
    except json.JSONDecodeError:
        return "person_not_entitled"
    if not isinstance(body, dict) or body.get("mode") != "listed":
        return "person_not_entitled"
    values = body.get("openIds")
    allowed = (
        {item for item in values if isinstance(item, str)} if isinstance(values, list) else set()
    )
    who = (person or "").strip()
    if not who:
        return "person_required"
    if who not in allowed:
        return "person_not_entitled"
    return None
