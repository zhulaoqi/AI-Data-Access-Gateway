"""Caller label supplied by the integrating service on an MCP request.

``X-GW-Caller`` is free text for the audit trail (who asked). It does not grant
access, and it is not a tool argument. JDBC never carries it.
"""

from __future__ import annotations

import contextvars
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from adg_ext import clientip

HEADER = "X-GW-Caller"
MAX_LEN = 128
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_current: contextvars.ContextVar[str | None] = contextvars.ContextVar("gw_caller", default=None)
_active: contextvars.ContextVar[bool] = contextvars.ContextVar("gw_caller_active", default=False)


def normalize(value: str | None) -> str | None:
    """Strip, drop control characters, and keep at most ``MAX_LEN`` characters."""

    if value is None:
        return None
    cleaned = _CONTROL.sub("", value).strip()
    if not cleaned:
        return None
    return cleaned[:MAX_LEN]


@contextmanager
def bound(value: str | None) -> Iterator[str | None]:
    """Remember the caller for audit rows written during this MCP call."""

    caller = normalize(value)
    token_caller = _current.set(caller)
    token_active = _active.set(True)
    try:
        yield caller
    finally:
        _current.reset(token_caller)
        _active.reset(token_active)


def stamp(metadata: dict[str, Any]) -> dict[str, Any]:
    """Attach the MCP caller. JDBC and any other named channel stay unchanged."""

    if not _active.get():
        return metadata
    channel = metadata.get("channel")
    if channel not in (None, "", "mcp"):
        return metadata
    out = dict(metadata)
    if not channel:
        out["channel"] = "mcp"
    caller = _current.get()
    if caller:
        out["caller"] = caller
    # Query rows already carry the address from the pipeline. Catalog calls do not.
    if not out.get("client_ip"):
        ip = clientip.current()
        if ip:
            out["client_ip"] = ip
    return out
