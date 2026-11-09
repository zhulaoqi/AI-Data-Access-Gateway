from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from adg.app.dependencies import AuthenticatedRuntimeKey, require_runtime_api_key
from adg.control_plane.db import get_session
from adg.gateway_runtime.tools import GatewayRuntimeService
from adg.mcp_api.agent_message import attach_agent_message
from adg.mcp_api.runtime_tools import dispatch_runtime_tool_call

router = APIRouter(prefix="/api/tools", tags=["mcp"])


@router.post("/{tool_name}")
def call_tool(
    tool_name: str,
    payload: dict[str, Any],
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[AuthenticatedRuntimeKey, Depends(require_runtime_api_key)],
    x_gw_person: Annotated[str | None, Header(alias="X-GW-Person")] = None,
    x_gw_scope: Annotated[str | None, Header(alias="X-GW-Scope")] = None,
) -> dict[str, Any]:
    """Dispatch one MCP-style HTTP tool call to the shared runtime service."""

    runtime = GatewayRuntimeService(session)

    # Keep transport routing thin so future MCP transports can reuse GatewayRuntimeService.
    try:
        response = dispatch_runtime_tool_call(
            runtime,
            tool_name,
            payload,
            api_key.runtime_identity,
            api_key.id,
            {"person": x_gw_person, "scope": x_gw_scope},
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown MCP tool",
        ) from None

    session.commit()
    return attach_agent_message(response)
