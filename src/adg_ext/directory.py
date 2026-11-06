"""Directory email index. The query path reads Redis only, never the management database."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

EMAIL_PREFIX = "gw:directory:email:"


def normalize(email: str | None) -> str | None:
    if email is None:
        return None
    value = email.strip().lower()
    if not value or len(value) > 128 or "@" not in value or _control(value):
        return None
    return value


def lookup(email: str, redis_get: Callable[[str], str | None] | None = None) -> dict[str, Any]:
    """Exact enterprise email to the directory open_id. Ambiguous and disabled emails miss."""

    key = normalize(email)
    if key is None:
        return _rejected("email_invalid", "需要完整的企业邮箱。")
    getter = redis_get or _redis_get
    try:
        raw = getter(EMAIL_PREFIX + key)
    except Exception:
        return _rejected("directory_unavailable", "通讯录缓存暂时不可用，请稍后再试。")
    body = _object(raw)
    if body.get("status") == "ambiguous":
        return _rejected("email_ambiguous", "这个邮箱对应多名在职人员，不能确定 open_id。")
    open_id = body.get("openId")
    if body.get("status") != "active" or not isinstance(open_id, str) or not open_id:
        return _rejected("person_not_found", "通讯录里没有这个在职邮箱。")
    name = body.get("name") if isinstance(body.get("name"), str) else ""
    return {
        "status": "ok",
        "open_id": open_id,
        "name": name,
        "header_name": "X-GW-Person",
        "header_value": open_id,
        "reload_required": True,
        "message": (
            "把 header_value 写入 MCP 客户端配置的请求头 X-GW-Person，然后重新连接。"
            "当前连接的请求头不会随这次结果改变，重连之前不要继续查数据。"
        ),
    }


def _rejected(reason: str, message: str) -> dict[str, str]:
    return {"status": "rejected", "reason": reason, "message": message}


def _object(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return body if isinstance(body, dict) else {}


def _control(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _redis_get(key: str) -> str | None:
    from adg_ext.disclosure import _redis

    client = _redis()
    if client is None:
        raise RuntimeError("redis unavailable")
    value = client.get(key)
    if isinstance(value, bytes):
        return value.decode()
    if value is None or isinstance(value, str):
        return value
    raise RuntimeError("redis unavailable")
