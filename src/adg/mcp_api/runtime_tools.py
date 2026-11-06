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
        description=(
            "预览一张表的行，并按数据权限和脱敏执行。"
            "一把密钥给很多人用，网关不记得上次是谁。"
            "请求头已有 X-GW-Person 时不要传 email。"
            "没有这个头时，把当前这个人自己给出的企业邮箱作为本次 email 传入。"
            "网关把它换成通讯录 open_id 后再套行权限。"
            "不要猜测邮箱，不要把 open_id 写进密钥或 MCP 配置。"
        ),
    ),
    RuntimeToolDefinition(
        name="execute_query",
        description=(
            "对已声明的表执行一条只读 SQL。"
            "一把密钥给很多人用，网关不记得上次是谁。"
            "请求头已有 X-GW-Person 时不要传 email。"
            "没有这个头时，把当前这个人自己给出的企业邮箱作为本次 email 传入。"
            "网关把它换成通讯录 open_id 后再套行权限。"
            "不要猜测邮箱，不要把 open_id 写进密钥或 MCP 配置。"
        ),
    ),
    RuntimeToolDefinition(
        name="resolve_person",
        description=(
            "用企业邮箱查出通讯录 open_id。查行不必先调这个工具，"
            "preview_resource 和 execute_query 可以直接传 email。"
            "本工具只返回 open_id，不改变当前连接，也不把人记在密钥上。"
            "接入服务要把 open_id 放进请求头 X-GW-Person 时，用这里返回的值。"
            "只接受用户明确给出的完整企业邮箱，不要猜测、补全或改查别人的邮箱。"
            "不同飞书应用的 open_id 不同。这里返回的是本网关通讯录里的那个。"
        ),
    ),
]

_QUERY_TOOLS = frozenset({"preview_resource", "execute_query"})

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

    headers = dict(disclosure_headers or {})
    if tool_name in _QUERY_TOOLS:
        from adg_ext.directory import resolve_caller

        resolved = resolve_caller(headers.get("person"), payload.get("email"))
        if resolved.get("status") != "ok":
            return {
                "status": "rejected",
                "reason": resolved["reason"],
                "message": resolved["message"],
            }
        headers["person"] = resolved.get("open_id")

    person = headers.get("person")
    blocked = runtime.audience_block(runtime_identity, person if isinstance(person, str) else None)
    if blocked:
        from adg_ext.audience import audience_message, query_identity_message

        message = (
            query_identity_message(blocked)
            if tool_name in _QUERY_TOOLS and blocked == "person_required"
            else audience_message(blocked)
        )
        return {"status": "rejected", "reason": blocked, "message": message}

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
            disclosure_headers=headers,
        )
    if tool_name == "execute_query":
        return runtime.execute_query(
            identity=runtime_identity,
            api_key_id=api_key_id,
            datasource_id=str(payload["datasource_id"]),
            resource_ids=[str(item) for item in payload.get("resource_ids", [])],
            query=str(payload["query"]),
            limit=int(payload.get("limit", 100)),
            disclosure_headers=headers,
        )
    raise KeyError(tool_name)
