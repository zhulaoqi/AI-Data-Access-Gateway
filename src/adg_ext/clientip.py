"""Real client address of a request (PA-8).

``ADG_EXT_TRUSTED_PROXY_HOPS`` says how many reverse proxies in front of the executor append to
``X-Forwarded-For``. With 0 hops the TCP peer is the client and the header is ignored; with N hops
the address is the N-th entry from the right (entries further left are client supplied and can be
forged). A missing, malformed or too short header falls back to the peer. A pure ASGI middleware
stores the result in a context variable so every layer below (authentication, audit, the query
pipeline) can read it without a ``Request`` object; it survives ``anyio.to_thread`` calls.
"""

import ipaddress
from contextvars import ContextVar
from typing import Any

from adg_ext.config import get_ext_settings

_current: ContextVar[str | None] = ContextVar("adg_ext_client_ip", default=None)


def normalize(value: str | None) -> str | None:
    """Canonical text of an IP address (IPv4-mapped IPv6 becomes IPv4); None when not an IP."""

    if not value:
        return None
    text = value.strip().strip("[]")
    if text.count(":") == 1 and "." in text:  # ``1.2.3.4:5678``
        text = text.rsplit(":", 1)[0]
    if "%" in text:  # IPv6 zone id
        text = text.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def resolve(peer: str | None, forwarded_for: str | None, hops: int) -> str | None:
    """The client address given the TCP peer, the ``X-Forwarded-For`` value and the hop count."""

    fallback = normalize(peer)
    if hops <= 0 or not forwarded_for:
        return fallback
    parts = [p.strip() for p in forwarded_for.split(",") if p.strip()]
    if len(parts) < hops:
        return fallback
    picked = normalize(parts[-hops])
    return picked or fallback


def current() -> str | None:
    """The client address of the request being served (None outside a request)."""

    return _current.get()


def set_current(value: str | None) -> Any:
    return _current.set(value)


def reset_current(token: Any) -> None:
    _current.reset(token)


class ClientIpMiddleware:
    """Pure ASGI middleware: resolves the client address once per HTTP or WebSocket request."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        peer = (scope.get("client") or (None, None))[0]
        forwarded = None
        for name, value in scope.get("headers") or []:
            if name == b"x-forwarded-for":
                forwarded = value.decode("latin-1")
                break
        token = _current.set(resolve(peer, forwarded, get_ext_settings().trusted_proxy_hops))
        try:
            await self.app(scope, receive, send)
        finally:
            _current.reset(token)
