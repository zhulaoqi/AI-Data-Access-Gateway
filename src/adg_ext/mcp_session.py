"""Serve a Streamable HTTP MCP session from any executor replica.

The SDK keeps the live transport in the process that handled ``initialize``.
Behind a load balancer the next request often lands elsewhere and the SDK
answers ``Session not found``. Redis stores only the session id (same client
and key prefix as the other shared limits). A replica that does not own the
transport still handles the JSON-RPC call: the server runs in the SDK's
stateless mode, which starts the protocol as already initialized, and the
response keeps the original session id.

Without ``redis.host`` nothing is stored and the SDK behavior is unchanged.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

import anyio
from mcp.server.streamable_http import StreamableHTTPServerTransport
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from adg_ext.redis_share import (
    MCP_HIT,
    MCP_UNAVAILABLE,
    get_share,
)

logger = logging.getLogger(__name__)

_SESSION_HEADER = b"mcp-session-id"
HandleRequest = Callable[[Scope, Receive, Send], Awaitable[None]]


class PublishingSessions(dict[str, Any]):
    """Publish a session id to Redis at the moment the SDK records it locally.

    That happens before the initialize response is written, so another replica
    can already see the id when the client sends the next call.
    Removal from this process (idle timeout, crash cleanup) does not delete the
    shared id; an explicit DELETE does.
    """

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, value)
        get_share().save_mcp_session(key)


def install_shared_sessions(manager: Any) -> None:
    """Route MCP requests that belong to a session created on another replica."""

    if getattr(manager, "_sqlgw_shared_sessions", False):
        return
    current = manager._server_instances
    if not isinstance(current, PublishingSessions):
        manager._server_instances = PublishingSessions(current)
    original = manager.handle_request

    async def handle_request(scope: Scope, receive: Receive, send: Send) -> None:
        await dispatch(manager, original, scope, receive, send)

    manager.handle_request = handle_request
    manager._sqlgw_shared_sessions = True


async def dispatch(
    manager: Any,
    local: HandleRequest,
    scope: Scope,
    receive: Receive,
    send: Send,
) -> None:
    session_id = _session_id(scope)
    method = scope.get("method", "GET")
    local_owner = bool(session_id) and session_id in manager._server_instances
    if session_id and not local_owner:
        state = get_share().read_mcp_session(session_id)
        if state == MCP_HIT:
            await serve_shared_session(manager, scope, receive, send, session_id)
            if method == "DELETE":
                get_share().clear_mcp_session(session_id)
            else:
                get_share().save_mcp_session(session_id)
            return
        if state == MCP_UNAVAILABLE:
            response = JSONResponse(
                status_code=503,
                content={"detail": "session store unavailable"},
                headers={"Retry-After": "1"},
            )
            await response(scope, receive, send)
            return
    await local(scope, receive, send)
    if method == "DELETE" and session_id:
        get_share().clear_mcp_session(session_id)
    elif session_id and session_id in manager._server_instances:
        get_share().save_mcp_session(session_id)


async def serve_shared_session(
    manager: Any,
    scope: Scope,
    receive: Receive,
    send: Send,
    session_id: str,
) -> None:
    """Handle one request for a session this process did not create.

    A fresh transport carries the shared session id, so the client keeps using
    it. ``stateless=True`` marks the protocol initialized: the client already
    completed ``initialize`` on whichever replica received it.
    """

    task_group = manager._task_group
    if task_group is None:
        raise RuntimeError("MCP session manager is not running")
    transport = StreamableHTTPServerTransport(
        mcp_session_id=session_id,
        is_json_response_enabled=bool(manager.json_response),
        event_store=None,
        security_settings=manager.security_settings,
    )

    async def run_server(
        *,
        task_status: anyio.abc.TaskStatus[None] = anyio.TASK_STATUS_IGNORED,
    ) -> None:
        async with transport.connect() as streams:
            read_stream, write_stream = streams
            task_status.started()
            try:
                await manager.app.run(
                    read_stream,
                    write_stream,
                    manager.app.create_initialization_options(),
                    stateless=True,
                )
            except Exception:
                logger.exception("shared mcp session crashed")

    await task_group.start(run_server)
    try:
        await transport.handle_request(scope, receive, send)
    finally:
        await transport.terminate()


def _session_id(scope: Scope) -> str | None:
    headers: Any = scope.get("headers") or []
    for name, value in headers:
        if name.lower() == _SESSION_HEADER:
            text = value.decode("latin-1").strip()
            return text or None
    return None
