import inspect
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
import pytest
from fastapi import FastAPI
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from sqlalchemy.orm import Session, sessionmaker

from adg.app.main import create_app
from adg.app.settings import get_settings
from adg.control_plane.db import create_engine_from_url, create_session_factory
from adg.control_plane.models import Base
from adg.control_plane.models.api_key import ApiKey
from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.directory import Role, User, UserRole
from adg.control_plane.models.governance import ResourcePolicy
from adg.control_plane.models.resource import Resource
from adg.mcp_server import server as mcp_server_module
from adg.mcp_server.server import runtime_mcp_server
from adg.shared.security import hash_api_key


def build_streamable_mcp_app() -> tuple[FastAPI, sessionmaker[Session]]:
    engine = create_engine_from_url("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)

    with session_factory() as session:
        session.add(
            User(
                id="user_1",
                name="Alice",
                external_ref="u001",
                org_node_id=None,
                status="active",
            )
        )
        session.add(Role(id="role_finance", name="Finance"))
        session.add(UserRole(user_id="user_1", role_id="role_finance"))
        session.add(
            ApiKey(
                id="key_runtime",
                name="runtime",
                key_hash=hash_api_key("adg_runtime"),
                user_id="user_1",
                status="active",
                scopes='["runtime"]',
            )
        )
        session.add(
            ApiKey(
                id="key_expired_runtime",
                name="expired-runtime",
                key_hash=hash_api_key("adg_expired_runtime"),
                user_id="user_1",
                status="active",
                scopes='["runtime"]',
                expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )
        )
        session.add(
            ApiKey(
                id="key_admin_only",
                name="admin-only",
                key_hash=hash_api_key("adg_admin_only"),
                user_id="user_1",
                status="active",
                scopes='["admin"]',
            )
        )
        session.add(
            Datasource(
                id="ds_1",
                name="Warehouse",
                type="postgres",
                datasource_kind="relational",
                config_json="{}",
                status="active",
            )
        )
        session.add(
            Resource(
                id="res_customers",
                datasource_id="ds_1",
                parent_id=None,
                kind="relational_table",
                name="customers",
                path="warehouse.public.customers",
                display_name="customers",
                query_language="sql",
                status="active",
                metadata_json="{}",
            )
        )
        session.add(
            ResourcePolicy(
                subject_type="user",
                subject_id="user_1",
                effect="allow",
                action="read",
                resource_id="res_customers",
                status="active",
            )
        )
        session.commit()

    return create_app(session_factory=session_factory), session_factory


@pytest.fixture(autouse=True)
def reset_streamable_mcp_session_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    """Create a new one-shot FastMCP session manager for every integration test."""

    monkeypatch.setattr(runtime_mcp_server, "_session_manager", None)


@pytest.fixture
def enabled_mcp_query_api_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ADG_MCP_QUERY_API_KEY_ENABLED", "true")
    get_settings.cache_clear()
    try:
        yield
    finally:
        get_settings.cache_clear()


async def assert_mcp_list_datasources(
    app: FastAPI,
    *,
    headers: dict[str, str] | list[tuple[str, str]],
    query: str = "",
    base_url: str = "http://127.0.0.1:8000",
) -> None:
    async with runtime_mcp_server.session_manager.run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=base_url,
            headers=headers,
        ) as http_client:
            async with streamable_http_client(
                f"{base_url}/mcp{query}",
                http_client=http_client,
            ) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()

                    tools = await session.list_tools()
                    list_datasources_tool = next(
                        tool for tool in tools.tools if tool.name == "list_datasources"
                    )
                    properties = list_datasources_tool.inputSchema.get("properties", {})
                    assert "user_id" not in properties
                    assert "roles" not in properties
                    assert "groups" not in properties

                    result = await session.call_tool("list_datasources", {})
                    assert result.structuredContent is not None
                    assert result.structuredContent["datasources"][0]["id"] == "ds_1"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("headers", "query"),
    [
        ({"X-ADG-API-Key": "adg_runtime"}, ""),
        ({"Authorization": "bEaReR adg_runtime"}, ""),
    ],
)
async def test_streamable_mcp_server_accepts_runtime_api_key_sources(
    headers: dict[str, str],
    query: str,
) -> None:
    app, _ = build_streamable_mcp_app()

    await assert_mcp_list_datasources(app, headers=headers, query=query)


@pytest.mark.anyio
async def test_streamable_mcp_server_accepts_query_api_key_when_enabled(
    enabled_mcp_query_api_key: None,
) -> None:
    app, _ = build_streamable_mcp_app()

    await assert_mcp_list_datasources(
        app,
        headers={},
        query="?apikey=adg_runtime",
    )


@pytest.mark.anyio
async def test_streamable_mcp_server_accepts_public_host_header() -> None:
    app, _ = build_streamable_mcp_app()

    await assert_mcp_list_datasources(
        app,
        headers={"X-ADG-API-Key": "adg_runtime"},
        base_url="http://101.200.0.241:8001",
    )


@pytest.mark.anyio
async def test_streamable_mcp_server_accepts_configured_api_key_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADG_API_KEY_HEADER", "X-Custom-ADG-Key")
    get_settings.cache_clear()
    try:
        app, _ = build_streamable_mcp_app()

        await assert_mcp_list_datasources(
            app,
            headers={"X-Custom-ADG-Key": "adg_runtime"},
        )
    finally:
        monkeypatch.delenv("ADG_API_KEY_HEADER", raising=False)
        get_settings.cache_clear()


@pytest.mark.anyio
async def test_streamable_mcp_server_accepts_bearer_when_configured_header_is_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADG_API_KEY_HEADER", "Authorization")
    get_settings.cache_clear()
    try:
        app, _ = build_streamable_mcp_app()

        await assert_mcp_list_datasources(
            app,
            headers={"Authorization": "Bearer adg_runtime"},
        )
    finally:
        monkeypatch.delenv("ADG_API_KEY_HEADER", raising=False)
        get_settings.cache_clear()


@pytest.mark.anyio
async def test_streamable_mcp_server_accepts_matching_api_key_credentials(
    enabled_mcp_query_api_key: None,
) -> None:
    app, _ = build_streamable_mcp_app()

    await assert_mcp_list_datasources(
        app,
        headers={
            "X-ADG-API-Key": "adg_runtime",
            "Authorization": "Bearer adg_runtime",
        },
        query="?apikey=adg_runtime",
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        [
            ("X-ADG-API-Key", "adg_runtime"),
            ("X-ADG-API-Key", "adg_runtime"),
        ],
        [
            ("Authorization", "Bearer adg_runtime"),
            ("Authorization", "bEaReR adg_runtime"),
        ],
    ],
)
async def test_streamable_mcp_server_accepts_matching_duplicate_api_key_headers(
    headers: list[tuple[str, str]],
) -> None:
    app, _ = build_streamable_mcp_app()

    await assert_mcp_list_datasources(app, headers=headers)


@pytest.mark.anyio
async def test_streamable_mcp_server_accepts_matching_duplicate_query_credentials(
    enabled_mcp_query_api_key: None,
) -> None:
    app, _ = build_streamable_mcp_app()

    await assert_mcp_list_datasources(
        app,
        headers={},
        query="?apikey=adg_runtime&apikey=adg_runtime",
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        [
            ("X-ADG-API-Key", "adg_runtime"),
            ("X-ADG-API-Key", "adg_other"),
        ],
        [
            ("Authorization", "Bearer adg_runtime"),
            ("Authorization", "Bearer adg_other"),
        ],
    ],
)
async def test_streamable_mcp_server_rejects_conflicting_duplicate_api_key_headers(
    headers: list[tuple[str, str]],
) -> None:
    app, _ = build_streamable_mcp_app()

    async with runtime_mcp_server.session_manager.run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8000",
        ) as http_client:
            response = await http_client.post(
                "/mcp",
                content="{}",
                headers=[("Content-Type", "application/json"), *headers],
            )

    assert response.status_code == 400
    assert response.json() == {"detail": "Conflicting API key credentials"}


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        {"X-ADG-API-Key": "adg_runtime, adg_other"},
        {"Authorization": "Bearer adg_runtime, Bearer adg_other"},
    ],
)
async def test_streamable_mcp_server_rejects_comma_joined_api_key_headers(
    headers: dict[str, str],
) -> None:
    app, _ = build_streamable_mcp_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as http_client:
        response = await http_client.post("/mcp", headers=headers)

    assert response.status_code == 400
    assert response.json() == {"detail": "Conflicting API key credentials"}


@pytest.mark.anyio
async def test_streamable_mcp_server_rejects_conflicting_duplicate_query_credentials(
    enabled_mcp_query_api_key: None,
) -> None:
    app, _ = build_streamable_mcp_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as http_client:
        response = await http_client.post(
            "/mcp?apikey=adg_runtime&apikey=adg_other"
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Conflicting API key credentials"}


@pytest.mark.anyio
async def test_streamable_mcp_server_rejects_conflicting_api_key_credentials(
    enabled_mcp_query_api_key: None,
) -> None:
    app, _ = build_streamable_mcp_app()

    async with runtime_mcp_server.session_manager.run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8000",
        ) as http_client:
            response = await http_client.post(
                "/mcp?apikey=adg_other",
                content="{}",
                headers={
                    "Content-Type": "application/json",
                    "X-ADG-API-Key": "adg_runtime",
                },
            )

    assert response.status_code == 400
    assert response.json() == {"detail": "Conflicting API key credentials"}


@pytest.mark.anyio
async def test_streamable_mcp_server_rejects_missing_api_key() -> None:
    app, _ = build_streamable_mcp_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as http_client:
        response = await http_client.post("/mcp")

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing API key"}


@pytest.mark.anyio
async def test_grant_alias_path_uses_the_same_mcp_endpoint() -> None:
    """`/mcp/c/<grant>` is only a client discriminator; the key still comes from the header."""

    app, _ = build_streamable_mcp_app()
    await assert_mcp_list_datasources(
        app,
        headers={"X-ADG-API-Key": "adg_runtime"},
        query="/c/01JGHI",
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as http_client:
        response = await http_client.post("/mcp/c/01JGHI")

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing API key"}


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("raw_api_key", "expected_status", "expected_detail"),
    [
        ("adg_invalid", 401, "Invalid API key"),
        ("adg_expired_runtime", 401, "Expired API key"),
        ("adg_admin_only", 403, "Runtime scope required"),
    ],
)
async def test_streamable_mcp_server_preserves_runtime_authentication_errors(
    raw_api_key: str,
    expected_status: int,
    expected_detail: str,
) -> None:
    app, _ = build_streamable_mcp_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as http_client:
        response = await http_client.post(
            "/mcp",
            headers={"X-ADG-API-Key": raw_api_key},
        )

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}


@pytest.mark.anyio
async def test_streamable_mcp_server_does_not_read_default_header_when_customized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADG_API_KEY_HEADER", "X-Custom-ADG-Key")
    get_settings.cache_clear()
    try:
        app, _ = build_streamable_mcp_app()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8000",
        ) as http_client:
            response = await http_client.post(
                "/mcp",
                headers={"X-ADG-API-Key": "adg_runtime"},
            )

        assert response.status_code == 401
        assert response.json() == {"detail": "Missing API key"}
    finally:
        get_settings.cache_clear()


@pytest.mark.anyio
async def test_streamable_mcp_server_rejects_query_api_key_by_default() -> None:
    app, _ = build_streamable_mcp_app()

    async with runtime_mcp_server.session_manager.run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8000",
        ) as http_client:
            response = await http_client.post("/mcp?apikey=adg_runtime")

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing API key"}


@pytest.mark.anyio
async def test_streamable_mcp_server_ignores_query_conflict_when_query_auth_is_disabled() -> None:
    app, _ = build_streamable_mcp_app()

    await assert_mcp_list_datasources(
        app,
        headers={"X-ADG-API-Key": "adg_runtime"},
        query="?apikey=adg_other",
    )


@pytest.mark.anyio
async def test_mcp_tool_handlers_are_async_and_run_runtime_work_in_threadpool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, tuple[Any, ...]]] = []

    def fake_run_runtime_tool(
        ctx: object,
        tool_name: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return {"tool_name": tool_name, "payload": payload, "ctx": ctx is fake_ctx}

    async def fake_run_sync(
        function: Callable[..., object],
        *args: object,
    ) -> dict[str, Any]:
        calls.append((function.__name__, args))
        return cast(dict[str, Any], function(*args))

    fake_ctx = object()
    monkeypatch.setattr(mcp_server_module, "_run_runtime_tool", fake_run_runtime_tool)
    monkeypatch.setattr(mcp_server_module, "_run_in_threadpool", fake_run_sync)

    assert inspect.iscoroutinefunction(mcp_server_module.list_datasources)

    result = await mcp_server_module.list_datasources(fake_ctx)

    assert result == {"tool_name": "list_datasources", "payload": {}, "ctx": True}
    assert calls == [("fake_run_runtime_tool", (fake_ctx, "list_datasources", {}))]
