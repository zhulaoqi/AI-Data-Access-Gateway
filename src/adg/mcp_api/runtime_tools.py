from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, status

from adg.gateway_runtime.tools import GatewayRuntimeService
from adg.policy.runtime import IdentityContext


@dataclass(frozen=True)
class RuntimeToolDefinition:
    """Operator-facing metadata for one runtime tool exposed over MCP transports."""

    name: str
    description: str


RUNTIME_TOOL_DEFINITIONS = [
    RuntimeToolDefinition(
        name="list_datasources",
        description="List the datasources visible to the current runtime identity.",
    ),
    RuntimeToolDefinition(
        name="list_tags",
        description="List the governance tags visible to the current runtime identity.",
    ),
    RuntimeToolDefinition(
        name="list_resources",
        description=(
            "List readable tables under one datasource. description is the business meaning of "
            "the table when one was written, otherwise the database comment. database_description "
            "is the business meaning of the database."
        ),
    ),
    RuntimeToolDefinition(
        name="list_resources_by_tag",
        description="Find readable resources by one or more governance tag names.",
    ),
    RuntimeToolDefinition(
        name="describe_resource",
        description=(
            "Describe one table and its readable columns. description and database_description "
            "are business meanings. Each column description is the business meaning of that "
            "field when one was written, otherwise the database comment."
        ),
    ),
    RuntimeToolDefinition(
        name="preview_resource",
        description="Preview rows from one resource with policy and masking enforcement.",
    ),
    RuntimeToolDefinition(
        name="execute_query",
        description="Run one read-only SQL query scoped to declared resources.",
    ),
]

FORBIDDEN_RUNTIME_IDENTITY_FIELDS = frozenset({"user_id", "roles", "groups"})


def serialize_runtime_tool_definitions() -> list[dict[str, str]]:
    """Return JSON-ready runtime tool metadata for operator-facing setup guides."""

    return [
        {"name": tool.name, "description": tool.description}
        for tool in RUNTIME_TOOL_DEFINITIONS
    ]


def dispatch_runtime_tool_call(
    runtime: GatewayRuntimeService,
    tool_name: str,
    payload: dict[str, Any],
    runtime_identity: IdentityContext,
    api_key_id: str,
    disclosure_headers: dict[str, str | None] | None = None,
) -> dict[str, Any]:
    """Dispatch one runtime tool call to the shared service implementation."""

    forbidden_fields = FORBIDDEN_RUNTIME_IDENTITY_FIELDS & payload.keys()
    if forbidden_fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Runtime identity fields are not accepted",
        )

    person = (disclosure_headers or {}).get("person") if disclosure_headers else None
    blocked = runtime.audience_block(runtime_identity, person)
    if blocked:
        return {"status": "rejected", "reason": blocked}

    if tool_name == "list_datasources":
        return runtime.list_datasources(identity=runtime_identity, api_key_id=api_key_id)
    if tool_name == "list_tags":
        return runtime.list_tags(identity=runtime_identity, api_key_id=api_key_id)
    if tool_name == "list_resources":
        return runtime.list_resources(
            identity=runtime_identity,
            api_key_id=api_key_id,
            datasource_id=str(payload["datasource_id"]),
        )
    if tool_name == "list_resources_by_tag":
        return runtime.list_resources_by_tag(
            identity=runtime_identity,
            api_key_id=api_key_id,
            tag_names=[str(item) for item in payload.get("tag_names", [])],
        )
    if tool_name == "describe_resource":
        return runtime.describe_resource(
            identity=runtime_identity,
            api_key_id=api_key_id,
            resource_id=str(payload["resource_id"]),
        )
    if tool_name == "preview_resource":
        return runtime.preview_resource(
            identity=runtime_identity,
            api_key_id=api_key_id,
            resource_id=str(payload["resource_id"]),
            limit=int(payload.get("limit", 20)),
            disclosure_headers=disclosure_headers,
        )
    if tool_name == "execute_query":
        return runtime.execute_query(
            identity=runtime_identity,
            api_key_id=api_key_id,
            datasource_id=str(payload["datasource_id"]),
            resource_ids=[str(item) for item in payload.get("resource_ids", [])],
            query=str(payload["query"]),
            limit=int(payload.get("limit", 100)),
            disclosure_headers=disclosure_headers,
        )
    raise KeyError(tool_name)
