"""Grant audience. JDBC never calls this. An empty listed set rejects everyone."""

from __future__ import annotations

import json
from typing import Any


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
