"""Directory cache. The query path reads Redis only, never the management database."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

EMAIL_PREFIX = "gw:directory:email:"
OPEN_ID_PREFIX = "gw:directory:openid:"
_OPEN_ID = re.compile(r"[A-Za-z0-9_.:@-]{1,128}")


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
        "reload_required": False,
        "message": (
            "这是通讯录 open_id。查数据时把同一个企业邮箱作为本次 preview_resource 或 "
            "execute_query 的 email 参数。接入服务也可以把这个 open_id 放进请求头 X-GW-Person。"
            "头里已有时，不要再传另一个人的 email。不要把 open_id 写进密钥或 MCP 配置。"
        ),
    }


def resolve_caller(
    header: object,
    email: object,
    redis_get: Callable[[str], str | None] | None = None,
) -> dict[str, Any]:
    """Use the header open_id. An email on this call must resolve to that same person."""

    who = header.strip() if isinstance(header, str) else ""
    if email is None:
        supplied = ""
    elif not isinstance(email, str):
        return _rejected("email_invalid", "需要完整的企业邮箱。")
    else:
        supplied = email.strip()
    if not supplied:
        return {"status": "ok", "open_id": who or None}
    found = lookup(supplied, redis_get)
    if found.get("status") != "ok":
        return {"status": "rejected", "reason": found["reason"], "message": found["message"]}
    open_id = found["open_id"]
    if who and who != open_id:
        return {
            "status": "rejected",
            "reason": "person_conflict",
            "message": (
                "请求头 X-GW-Person 和本次 email 查到的不是同一个人，"
                "已拒绝查询，没有改成查整张表。"
            ),
        }
    return {"status": "ok", "open_id": open_id}


def membership(
    open_id: str | None,
    redis_get: Callable[[str], str | None] | None = None,
) -> str:
    """``active``, ``missing``, or ``unavailable`` when the cache cannot be read."""

    who = (open_id or "").strip()
    if not _OPEN_ID.fullmatch(who):
        return "missing"
    getter = redis_get or _redis_get
    try:
        raw = getter(OPEN_ID_PREFIX + who)
    except Exception:
        return "unavailable"
    if _object(raw).get("status") == "active":
        return "active"
    return "missing"


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
