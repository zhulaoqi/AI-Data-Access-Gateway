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
        description=(
            "List datasources this grant can read. A datasource is included only when the "
            "grant allows at least one of its tables."
        ),
    ),
    RuntimeToolDefinition(
        name="list_resources",
        description=(
            "List tables this grant can read under one datasource. description is the business "
            "meaning of the table when one was written, otherwise the database comment. "
            "database_description is the business meaning of the database."
        ),
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
    RuntimeToolDefinition(
        name="resolve_person",
        description=(
            "用调用者自己的企业邮箱，查出他在本网关通讯录里的 open_id。"
            "这个值只能由用户写进 MCP 客户端配置的请求头 X-GW-Person，然后重新连接。"
            "本工具的返回值不会改变当前连接已经带上的请求头，也不能当作其他工具的参数。"
            "只接受用户明确给出的完整企业邮箱，不要猜测、补全或改查别人的邮箱。"
            "查到之后，把 open_id 原样告诉用户，请他写入 headers.X-GW-Person 并重连；"
            "在他重连之前，不要继续查数据。"
            "不同飞书应用的 open_id 不同。这里返回的是本网关通讯录里的那个。"
        ),
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

    if tool_name == "resolve_person":
        return runtime.resolve_person(
            identity=runtime_identity,
            api_key_id=api_key_id,
            email=str(payload.get("email") or ""),
        )

    person = (disclosure_headers or {}).get("person") if disclosure_headers else None
    blocked = runtime.audience_block(runtime_identity, person)
    if blocked:
        from adg_ext.audience import audience_message

        return {"status": "rejected", "reason": blocked, "message": audience_message(blocked)}

    if tool_name == "list_datasources":
        return runtime.list_datasources(identity=runtime_identity, api_key_id=api_key_id)
    if tool_name == "list_resources":
        return runtime.list_resources(
            identity=runtime_identity,
            api_key_id=api_key_id,
            datasource_id=str(payload["datasource_id"]),
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
