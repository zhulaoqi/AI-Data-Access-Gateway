from collections.abc import Callable
from typing import Any, cast

from anyio import to_thread
from fastapi import HTTPException
from mcp.server.fastmcp import Context, FastMCP
from sqlalchemy.orm import Session, sessionmaker
from starlette.applications import Starlette
from starlette.datastructures import Headers, QueryParams
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from adg.app.dependencies import AuthenticatedRuntimeKey, authenticate_runtime_api_key_value
from adg.app.settings import get_settings
from adg.control_plane.db import SessionLocal
from adg.gateway_runtime.tools import GatewayRuntimeService
from adg.mcp_api.runtime_tools import RUNTIME_TOOL_DEFINITIONS, dispatch_runtime_tool_call

_TOOL_DESCRIPTION = {item.name: item.description for item in RUNTIME_TOOL_DEFINITIONS}

runtime_mcp_server = FastMCP("AI Data Access Gateway", host="0.0.0.0")
McpContext = Context[Any, Any, Any]


async def _run_in_threadpool[ThreadResult](
    function: Callable[..., ThreadResult],
    *args: object,
) -> ThreadResult:
    """Run synchronous MCP work in AnyIO's worker threadpool."""

    return await to_thread.run_sync(function, *args)


class RuntimeApiKeyMiddleware:
    """Require one runtime-scoped API key on every Streamable HTTP request."""

    def __init__(self, app: ASGIApp, session_factory: sessionmaker[Session]):
        self.app = app
        self._session_factory = session_factory

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client_identifier = _client_identifier_from_scope(scope)
        try:
            raw_api_key = _extract_api_key_from_scope(scope)
            authenticated = await to_thread.run_sync(
                self._authenticate,
                raw_api_key,
                client_identifier,
            )
        except HTTPException as exc:
            await JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})(
                scope,
                receive,
                send,
            )
            return

        scope.setdefault("state", {})
        cast(dict[str, Any], scope["state"])["authenticated_api_key"] = authenticated
        await self.app(scope, receive, send)

    def _authenticate(
        self,
        raw_api_key: str | None,
        client_identifier: str | None,
    ) -> AuthenticatedRuntimeKey:
        """Authenticate inside the worker thread that owns the SQLAlchemy session."""

        with self._session_factory() as session:
            return authenticate_runtime_api_key_value(
                session,
                raw_api_key,
                client_identifier=client_identifier,
            )


def _extract_bearer_api_key(authorization: str | None) -> str | None:
    """Return the API key from one Bearer authorization value, if present."""

    if authorization is None:
        return None
    parts = authorization.split(maxsplit=1)
    if len(parts) != 2 or parts[0].casefold() != "bearer":
        return None
    return parts[1].strip() or None


def _extract_api_key_from_scope(scope: Scope) -> str | None:
    """Resolve one matching MCP API key credential or reject conflicting values."""

    headers = Headers(raw=scope["headers"])
    settings = get_settings()
    configured_header = settings.api_key_header
    configured_values = headers.getlist(configured_header)
    authorization_values = headers.getlist("authorization")
    if any("," in value for value in [*configured_values, *authorization_values]):
        raise HTTPException(status_code=400, detail="Conflicting API key credentials")
    header_candidates: list[str | None]
    if configured_header.casefold() == "authorization":
        header_candidates = [
            _extract_bearer_api_key(value) or value for value in authorization_values
        ]
    else:
        header_candidates = [
            *configured_values,
            *(_extract_bearer_api_key(value) for value in authorization_values),
        ]
    candidates = [
        *header_candidates,
        *(
            QueryParams(scope["query_string"]).getlist("apikey")
            if settings.mcp_query_api_key_enabled
            else []
        ),
    ]
    supplied_keys = {candidate for candidate in candidates if candidate}
    if len(supplied_keys) > 1:
        raise HTTPException(status_code=400, detail="Conflicting API key credentials")
    return next(iter(supplied_keys), None)


def _client_identifier_from_scope(scope: Scope) -> str | None:
    client = scope.get("client")
    if not isinstance(client, tuple) or not client:
        return None
    return str(client[0])


class MountedMcpServerApp:
    """Rewrite the mounted root path to FastMCP's internal /mcp endpoint."""

    def __init__(self, app: Starlette):
        self.app = app
        self.state = app.state

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in {"", "/", "/mcp/"}:
            rewritten_scope = dict(scope)
            rewritten_scope["path"] = "/mcp"
            rewritten_scope["raw_path"] = b"/mcp"
            rewritten_scope["root_path"] = ""
            await self.app(rewritten_scope, receive, send)
            return

        await self.app(scope, receive, send)


def build_mcp_server_app(
    session_factory: sessionmaker[Session] | None = None,
) -> MountedMcpServerApp:
    """Build the mounted Streamable HTTP MCP server app."""

    factory = session_factory or SessionLocal
    inner_app = runtime_mcp_server.streamable_http_app()
    inner_app.state.session_factory = factory
    inner_app.add_middleware(RuntimeApiKeyMiddleware, session_factory=factory)
    return MountedMcpServerApp(inner_app)


def _request_from_context(ctx: McpContext) -> Request:
    """Return the active Starlette request from one MCP tool invocation."""

    request = ctx.request_context.request
    if request is None:  # pragma: no cover
        raise RuntimeError("MCP request context is unavailable")
    return cast(Request, request)


def _run_runtime_tool(ctx: McpContext, tool_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Execute one runtime tool call with authenticated context and commit the audit event."""

    request = _request_from_context(ctx)
    session_factory = cast(
        sessionmaker[Session],
        getattr(request.app.state, "session_factory", SessionLocal),
    )
    authenticated = cast(AuthenticatedRuntimeKey, request.state.authenticated_api_key)

    with session_factory() as session:
        runtime = GatewayRuntimeService(session)
        response = dispatch_runtime_tool_call(
            runtime,
            tool_name,
            payload,
            authenticated.runtime_identity,
            authenticated.id,
            {
                "person": request.headers.get("x-gw-person"),
                "scope": request.headers.get("x-gw-scope"),
            },
        )
        session.commit()
        return response


@runtime_mcp_server.tool(
    name="list_datasources",
    description=_TOOL_DESCRIPTION["list_datasources"],
)
async def list_datasources(
    ctx: McpContext,
) -> dict[str, Any]:
    """List datasources visible to the calling runtime identity."""

    return await _run_in_threadpool(_run_runtime_tool, ctx, "list_datasources", {})


@runtime_mcp_server.tool(
    name="list_resources",
    description=_TOOL_DESCRIPTION["list_resources"],
)
async def list_resources(
    ctx: McpContext,
    datasource_id: str,
) -> dict[str, Any]:
    """List readable resources under one datasource."""

    return await _run_in_threadpool(
        _run_runtime_tool,
        ctx,
        "list_resources",
        {
            "datasource_id": datasource_id,
        },
    )


@runtime_mcp_server.tool(
    name="describe_resource",
    description=_TOOL_DESCRIPTION["describe_resource"],
)
async def describe_resource(
    ctx: McpContext,
    resource_id: str,
) -> dict[str, Any]:
    """Describe one resource and its visible columns."""

    return await _run_in_threadpool(
        _run_runtime_tool,
        ctx,
        "describe_resource",
        {
            "resource_id": resource_id,
        },
    )


@runtime_mcp_server.tool(
    name="preview_resource",
    description=_TOOL_DESCRIPTION["preview_resource"],
)
async def preview_resource(
    ctx: McpContext,
    resource_id: str,
    limit: int = 20,
) -> dict[str, Any]:
    """Preview rows from one resource with policy enforcement."""

    return await _run_in_threadpool(
        _run_runtime_tool,
        ctx,
        "preview_resource",
        {
            "resource_id": resource_id,
            "limit": limit,
        },
    )


@runtime_mcp_server.tool(
    name="execute_query",
    description=_TOOL_DESCRIPTION["execute_query"],
)
async def execute_query(
    ctx: McpContext,
    datasource_id: str,
    resource_ids: list[str],
    query: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Run one guarded read-only SQL query."""

    return await _run_in_threadpool(
        _run_runtime_tool,
        ctx,
        "execute_query",
        {
            "datasource_id": datasource_id,
            "resource_ids": resource_ids,
            "query": query,
            "limit": limit,
        },
    )
