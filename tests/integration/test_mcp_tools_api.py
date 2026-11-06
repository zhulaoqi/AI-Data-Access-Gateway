from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from adg.app.main import create_app
from adg.audit.models import AuditEvent
from adg.connectors.base import MetadataSnapshot, QueryResult
from adg.connectors.errors import ConnectorOperationError
from adg.connectors.registry import DEFAULT_CONNECTOR_REGISTRY
from adg.control_plane.db import create_engine_from_url, create_session_factory, get_session
from adg.control_plane.models import Base
from adg.control_plane.models.api_key import ApiKey
from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.directory import Role, User, UserRole
from adg.control_plane.models.governance import ResourcePolicy
from adg.control_plane.models.resource import Resource
from adg.shared.security import hash_api_key


class FailingPostgresConnector:
    connector_type = "postgres"

    def test_connection(self, config: dict[str, object]) -> None:
        return None

    def scan_metadata(self, config: dict[str, object]) -> MetadataSnapshot:
        return {"databases": []}

    def execute_query(self, config: dict[str, object], sql: str, limit: int) -> QueryResult:
        raise ConnectorOperationError("Lost connection to MySQL server during query")


def build_mcp_app(
    *,
    raise_server_exceptions: bool = True,
) -> tuple[TestClient, sessionmaker[Session]]:
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
                id="key_admin_only",
                name="admin-only",
                key_hash=hash_api_key("adg_admin_only"),
                status="active",
                scopes='["admin"]',
            )
        )
        session.add(
            ApiKey(
                id="key_runtime_unbound",
                name="runtime-unbound",
                key_hash=hash_api_key("adg_runtime_unbound"),
                status="active",
                scopes='["runtime"]',
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

    app = create_app()

    def override_session() -> Iterator[Session]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    return TestClient(
        app,
        raise_server_exceptions=raise_server_exceptions,
    ), session_factory


def test_mcp_tool_route_accepts_non_admin_api_key() -> None:
    client, _ = build_mcp_app()

    response = client.post(
        "/api/tools/list_datasources",
        json={},
        headers={"X-ADG-API-Key": "adg_runtime"},
    )

    assert response.status_code == 200
    assert response.json()["datasources"][0]["id"] == "ds_1"


@pytest.mark.parametrize(
    ("params", "headers"),
    [
        ({"apikey": "adg_runtime"}, {}),
        ({}, {"Authorization": "Bearer adg_runtime"}),
    ],
)
def test_mcp_tool_route_does_not_accept_query_or_bearer_api_key(
    params: dict[str, str],
    headers: dict[str, str],
) -> None:
    client, _ = build_mcp_app()

    response = client.post(
        "/api/tools/list_datasources",
        json={},
        params=params,
        headers=headers,
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing API key"}


def test_mcp_tool_route_inherits_database_policy_to_child_tables() -> None:
    client, session_factory = build_mcp_app()

    with session_factory() as session:
        session.add(
            Datasource(
                id="ds_2",
                name="Inherited Warehouse",
                type="postgres",
                datasource_kind="relational",
                config_json="{}",
                status="active",
            )
        )
        session.add_all(
            [
                Resource(
                    id="res_database",
                    datasource_id="ds_2",
                    parent_id=None,
                    kind="database",
                    name="warehouse",
                    path="warehouse",
                    display_name="warehouse",
                    query_language="sql",
                    status="active",
                    metadata_json="{}",
                ),
                Resource(
                    id="res_schema",
                    datasource_id="ds_2",
                    parent_id="res_database",
                    kind="schema",
                    name="public",
                    path="warehouse.public",
                    display_name="public",
                    query_language="sql",
                    status="active",
                    metadata_json="{}",
                ),
                Resource(
                    id="res_orders",
                    datasource_id="ds_2",
                    parent_id="res_schema",
                    kind="relational_table",
                    name="orders",
                    path="warehouse.public.orders",
                    display_name="orders",
                    query_language="sql",
                    status="active",
                    metadata_json="{}",
                ),
            ]
        )
        session.add(
            ResourcePolicy(
                subject_type="user",
                subject_id="user_1",
                effect="allow",
                action="read",
                resource_id="res_database",
                status="active",
            )
        )
        session.commit()

    datasources = client.post(
        "/api/tools/list_datasources",
        json={},
        headers={"X-ADG-API-Key": "adg_runtime"},
    )
    resources = client.post(
        "/api/tools/list_resources",
        json={"datasource_id": "ds_2"},
        headers={"X-ADG-API-Key": "adg_runtime"},
    )

    assert datasources.status_code == 200
    assert "ds_2" in [item["id"] for item in datasources.json()["datasources"]]
    assert resources.status_code == 200
    assert resources.json() == {
        "resources": [
            {
                "id": "res_orders",
                "datasource_id": "ds_2",
                "kind": "relational_table",
                "name": "orders",
                "path": "warehouse.public.orders",
                "display_name": "orders",
                "description": None,
                "database": "warehouse.public",
                "database_description": None,
                "query_language": "sql",
            }
        ]
    }


def test_mcp_tool_route_rejects_unknown_tool_name() -> None:
    client, _ = build_mcp_app()

    response = client.post(
        "/api/tools/not_a_tool",
        json={},
        headers={"X-ADG-API-Key": "adg_runtime"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Unknown MCP tool"


def test_mcp_tool_route_rejects_request_identity_fields() -> None:
    client, _ = build_mcp_app()

    response = client.post(
        "/api/tools/list_datasources",
        json={"user_id": "spoofed", "roles": ["admin"], "groups": ["finance"]},
        headers={"X-ADG-API-Key": "adg_runtime"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Runtime identity fields are not accepted"


def test_mcp_tool_route_commits_runtime_audit_events() -> None:
    client, session_factory = build_mcp_app()

    response = client.post(
        "/api/tools/list_datasources",
        json={},
        headers={"X-ADG-API-Key": "adg_runtime"},
    )

    assert response.status_code == 200
    with session_factory() as session:
        event = session.execute(select(AuditEvent)).scalar_one()
    assert event.event_type == "metadata_discovery"
    assert event.user_id == "user_1"


def test_mcp_tool_route_returns_structured_error_for_connector_failure() -> None:
    original_connector = DEFAULT_CONNECTOR_REGISTRY.get("postgres")
    DEFAULT_CONNECTOR_REGISTRY.register("postgres", FailingPostgresConnector)
    try:
        client, session_factory = build_mcp_app(raise_server_exceptions=False)

        response = client.post(
            "/api/tools/execute_query",
            json={
                "datasource_id": "ds_1",
                "resource_ids": ["res_customers"],
                "query": "select id from public.customers",
                "limit": 1,
            },
            headers={"X-ADG-API-Key": "adg_runtime"},
        )
    finally:
        DEFAULT_CONNECTOR_REGISTRY.register("postgres", original_connector)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "error"
    assert "columns" not in body
    assert "rows" not in body
    assert "masking" not in body
    assert body["error"] == {
        "type": "connector_operation_error",
        "message": "Datasource query execution failed. Reference query_id for details.",
    }
    assert "Lost connection to MySQL server" not in str(body)
    with session_factory() as session:
        event = session.execute(select(AuditEvent)).scalar_one()
    assert event.event_type == "query_execution"
    assert event.decision == "error"
    assert event.reason == "connector_operation_error"
    assert event.query_id == body["query_id"]
    assert event.audit_metadata["error_type"] == "connector_operation_error"
    assert event.audit_metadata["query_id"] == body["query_id"]
    assert "error_message" not in event.audit_metadata
    assert "Lost connection to MySQL server" not in str(event.audit_metadata)


def test_mcp_tool_route_rejects_api_key_without_runtime_scope() -> None:
    client, _ = build_mcp_app()

    response = client.post(
        "/api/tools/list_datasources",
        json={},
        headers={"X-ADG-API-Key": "adg_admin_only"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Runtime scope required"


def test_mcp_tool_route_rejects_runtime_key_without_user_binding() -> None:
    client, _ = build_mcp_app()

    response = client.post(
        "/api/tools/list_datasources",
        json={},
        headers={"X-ADG-API-Key": "adg_runtime_unbound"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Runtime key must be bound to a user"
