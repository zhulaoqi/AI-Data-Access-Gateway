from typing import cast

import pytest
from pytest import MonkeyPatch
from sqlalchemy import event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from adg.audit.models import AuditEvent
from adg.connectors.base import MetadataConnector, MetadataSnapshot, QueryResult
from adg.connectors.errors import ConnectorDependencyError, ConnectorOperationError
from adg.connectors.registry import ConnectorRegistry
from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.governance import FieldPolicy, ResourcePolicy, ResourceTag, Tag
from adg.control_plane.models.masking import DecryptContext, MaskingPolicy
from adg.control_plane.models.resource import Resource, ResourceField
from adg.gateway_runtime.tools import GatewayRuntimeService
from adg.policy.runtime import IdentityContext


class FakeConnector:
    connector_type = "fake"
    last_sql: str | None = None
    override_columns: list[dict[str, str]] | None = None

    def test_connection(self, config: dict[str, object]) -> None:
        return None

    def scan_metadata(self, config: dict[str, object]) -> MetadataSnapshot:
        return {"databases": []}

    def execute_query(self, config: dict[str, object], sql: str, limit: int) -> QueryResult:
        type(self).last_sql = sql
        if type(self).override_columns is not None:
            override_columns = type(self).override_columns
            assert override_columns is not None
            return QueryResult(
                columns=override_columns,
                rows=[{"ID": 1, "EMAIL": "alice@example.com"}],
            )
        if "email" in sql.lower():
            return QueryResult(
                columns=[
                    {"name": "id", "data_type": "integer"},
                    {"name": "email", "data_type": "varchar"},
                ],
                rows=[{"id": 1, "email": "alice@example.com"}],
            )
        return QueryResult(
            columns=[{"name": "id", "data_type": "integer"}],
            rows=[{"id": 1}, {"id": 2}][:limit],
        )


class FailingOperationConnector(FakeConnector):
    def execute_query(self, config: dict[str, object], sql: str, limit: int) -> QueryResult:
        raise ConnectorOperationError(
            "OperationalError: could not connect to "
            "postgresql+psycopg://alice@10.0.0.9/private; "
            "Lost connection to MySQL server during query"
        )


class FailingDependencyConnector(FakeConnector):
    def execute_query(self, config: dict[str, object], sql: str, limit: int) -> QueryResult:
        raise ConnectorDependencyError("Connector 'postgres' requires optional extra 'postgres'")


class AliasedResultConnector(FakeConnector):
    def execute_query(self, config: dict[str, object], sql: str, limit: int) -> QueryResult:
        type(self).last_sql = sql
        return QueryResult(
            columns=[{"name": "LEAKED", "data_type": "varchar"}],
            rows=[{"LEAKED": "alice@example.com"}],
        )


class RuntimeSettingsStub:
    secret_key = "unit-test-secret-key"
    masking_encryption_key = "unit-test-masking-key"
    secret_kdf_iterations = 1
    sql_execution_mode = "read_only"
    sql_strict_validation = False
    sql_reject_wildcard = True
    runtime_query_max_limit = 1000


def identity() -> IdentityContext:
    return IdentityContext(user_id="user-1", roles=["analyst"])


def add_datasource(
    db_session: Session,
    *,
    datasource_id: str = "ds_1",
    status: str = "active",
    description: str | None = None,
) -> Datasource:
    datasource = Datasource(
        id=datasource_id,
        name=f"Datasource {datasource_id}",
        type="fake",
        datasource_kind="relational",
        description=description,
        config_json="{}",
        status=status,
    )
    db_session.add(datasource)
    return datasource


def add_resource(
    db_session: Session,
    *,
    resource_id: str,
    datasource_id: str = "ds_1",
    path: str = "warehouse.public.customers",
    status: str = "active",
    parent_id: str | None = None,
    kind: str = "relational_table",
) -> Resource:
    resource = Resource(
        id=resource_id,
        datasource_id=datasource_id,
        parent_id=parent_id,
        kind=kind,
        name=path.rsplit(".", 1)[-1],
        path=path,
        display_name=path.rsplit(".", 1)[-1],
        query_language="sql",
        status=status,
        metadata_json="{}",
    )
    db_session.add(resource)
    db_session.flush()
    for index, field_name in enumerate(("id", "email"), start=1):
        db_session.add(
            ResourceField(
                datasource_id=datasource_id,
                resource_id=resource.id,
                name=field_name,
                data_type="integer" if field_name == "id" else "varchar",
                nullable=False,
                ordinal_position=index,
                status="active",
                metadata_json="{}",
            )
        )
    return resource


def runtime(db_session: Session) -> GatewayRuntimeService:
    return GatewayRuntimeService(
        db_session,
        connector_registry=ConnectorRegistry(
            {"fake": cast(type[MetadataConnector], FakeConnector)}
        ),
    )


def runtime_with_connector(
    db_session: Session,
    connector: type[MetadataConnector],
) -> GatewayRuntimeService:
    return GatewayRuntimeService(
        db_session,
        connector_registry=ConnectorRegistry({"fake": connector}),
    )


def allow_resource_read(
    db_session: Session,
    resource_id: str | None = None,
    *,
    subject_type: str = "role",
    subject_id: str = "analyst",
    allow_decrypt: bool = False,
) -> None:
    db_session.add(
        ResourcePolicy(
            subject_type=subject_type,
            subject_id=subject_id,
            effect="allow",
            action="read",
            resource_id=resource_id,
            allow_decrypt=allow_decrypt,
            status="active",
        )
    )


def test_list_datasources_only_returns_datasources_with_visible_resources(
    db_session: Session,
) -> None:
    add_datasource(db_session, datasource_id="ds_visible")
    add_datasource(db_session, datasource_id="ds_hidden")
    add_datasource(db_session, datasource_id="ds_disabled", status="disabled")
    visible = add_resource(
        db_session,
        resource_id="res_visible",
        datasource_id="ds_visible",
        path="warehouse.public.visible_customers",
    )
    hidden = add_resource(
        db_session,
        resource_id="res_hidden",
        datasource_id="ds_hidden",
        path="warehouse.public.hidden_customers",
    )
    allow_resource_read(db_session, visible.id)
    db_session.add(
        ResourcePolicy(
            subject_type="all",
            subject_id="*",
            effect="deny",
            action="read",
            resource_id=hidden.id,
            status="active",
        )
    )

    response = runtime(db_session).list_datasources(identity=identity(), api_key_id="key_1")

    assert response["datasources"] == [
        {
            "id": "ds_visible",
            "name": "Datasource ds_visible",
            "type": "fake",
            "datasource_kind": "relational",
            "description": None,
        }
    ]


def test_list_datasources_includes_operator_description_for_agents(db_session: Session) -> None:
    add_datasource(
        db_session,
        description="Contains curated customer service datasets for support analysis.",
    )
    resource = add_resource(db_session, resource_id="res_orders")
    allow_resource_read(db_session, resource.id)

    response = runtime(db_session).list_datasources(
        identity=identity(),
        api_key_id="key_1",
    )

    assert response["datasources"] == [
        {
            "id": "ds_1",
            "name": "Datasource ds_1",
            "type": "fake",
            "datasource_kind": "relational",
            "description": "Contains curated customer service datasets for support analysis.",
        }
    ]


def test_tags_only_include_accessible_resources(db_session: Session) -> None:
    add_datasource(db_session)
    allowed = add_resource(db_session, resource_id="res_allowed")
    denied = add_resource(db_session, resource_id="res_denied", path="warehouse.public.secret")
    public_tag = Tag(id="tag_public", name="public")
    secret_tag = Tag(id="tag_secret", name="secret")
    db_session.add_all([public_tag, secret_tag])
    db_session.add_all(
        [
            ResourceTag(tag_id=public_tag.id, resource_id=allowed.id),
            ResourceTag(tag_id=secret_tag.id, resource_id=denied.id),
            ResourcePolicy(
                subject_type="all",
                subject_id="*",
                effect="allow",
                action="read",
                status="active",
            ),
            ResourcePolicy(
                subject_type="all",
                subject_id="*",
                effect="deny",
                action="read",
                resource_id=denied.id,
                status="active",
            ),
        ]
    )

    response = runtime(db_session).list_tags(identity=identity(), api_key_id="key_1")

    assert response["tags"] == [{"id": "tag_public", "name": "public", "category": None}]


def test_runtime_discovery_hides_disabled_resources_and_fields(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    active = add_resource(db_session, resource_id="res_active")
    disabled = add_resource(
        db_session,
        resource_id="res_disabled",
        path="warehouse.public.secret_customers",
        status="disabled",
    )
    email = db_session.execute(
        select(ResourceField).where(
            ResourceField.resource_id == active.id,
            ResourceField.name == "email",
        )
    ).scalar_one()
    email.status = "disabled"
    db_session.add(
        ResourcePolicy(
            subject_type="all",
            subject_id="*",
            effect="allow",
            action="read",
            status="active",
        )
    )

    listed = runtime(db_session).list_resources(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
    )
    described = runtime(db_session).describe_resource(
        identity=identity(),
        api_key_id="key_1",
        resource_id=active.id,
    )
    disabled_description = runtime(db_session).describe_resource(
        identity=identity(),
        api_key_id="key_1",
        resource_id=disabled.id,
    )

    assert [resource["id"] for resource in listed["resources"]] == [active.id]
    assert [column["name"] for column in described["columns"]] == ["id"]
    assert disabled_description == {"status": "rejected", "reason": "resource_disabled"}


def test_runtime_rejects_resources_from_disabled_datasource(db_session: Session) -> None:
    add_datasource(db_session, status="disabled")
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    service = runtime(db_session)

    listed = service.list_resources(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
    )
    described = service.describe_resource(
        identity=identity(),
        api_key_id="key_1",
        resource_id=resource.id,
    )
    FakeConnector.last_sql = None
    previewed = service.preview_resource(
        identity=identity(),
        api_key_id="key_1",
        resource_id=resource.id,
        limit=1,
    )
    assert FakeConnector.last_sql is None
    executed = service.execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id from warehouse.public.customers",
        limit=1,
    )

    assert listed == {"resources": []}
    assert described == {"status": "rejected", "reason": "datasource_disabled"}
    assert previewed == {"status": "rejected", "reason": "datasource_disabled"}
    assert executed == {"status": "rejected", "reason": "datasource_disabled"}
    assert FakeConnector.last_sql is None


def test_runtime_discovery_hides_resources_under_disabled_parent(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    database = add_resource(
        db_session,
        resource_id="res_database",
        path="warehouse",
        kind="database",
        status="disabled",
    )
    table = add_resource(
        db_session,
        resource_id="res_customers",
        path="warehouse.public.customers",
        parent_id=database.id,
    )
    allow_resource_read(db_session, table.id)

    listed = runtime(db_session).list_resources(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
    )

    assert listed["resources"] == []

def test_database_policy_makes_child_tables_discoverable(db_session: Session) -> None:
    add_datasource(db_session)
    database = add_resource(
        db_session,
        resource_id="res_database",
        path="warehouse",
        kind="database",
    )
    schema = add_resource(
        db_session,
        resource_id="res_schema",
        path="warehouse.public",
        parent_id=database.id,
        kind="schema",
    )
    table = add_resource(
        db_session,
        resource_id="res_customers",
        path="warehouse.public.customers",
        parent_id=schema.id,
    )
    allow_resource_read(db_session, database.id)

    listed = runtime(db_session).list_resources(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
    )

    assert [resource["id"] for resource in listed["resources"]] == [table.id]


def test_describe_resource_hides_denied_fields(db_session: Session) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.add(
        FieldPolicy(
            subject_type="all",
            subject_id="*",
            effect="deny",
            resource_id=resource.id,
            field_name="email",
            action="read",
            status="active",
        )
    )

    response = runtime(db_session).describe_resource(
        identity=identity(),
        api_key_id="key_1",
        resource_id=resource.id,
    )

    assert response["columns"] == [
        {
            "name": "id",
            "data_type": "integer",
            "nullable": False,
            "description": None,
            "access": "allowed",
            "masking_strategy": None,
        }
    ]


def test_execute_query_rejects_actual_resources_outside_declared_scope(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    add_resource(db_session, resource_id="res_orders", path="warehouse.public.orders")
    allow_resource_read(db_session, resource.id)

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=["res_customers"],
        query="select id from public.orders",
        limit=100,
    )

    assert response["status"] == "rejected"
    assert response["reason"] == "actual_resource_outside_declared_scope"
    event = db_session.execute(select(AuditEvent)).scalar_one()
    assert event.event_type == "permission_rejected"


def test_execute_query_rejects_unknown_sql_resources(db_session: Session) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id from public.unknown_table",
        limit=100,
    )

    assert response["status"] == "rejected"
    assert response["reason"] == "unknown_sql_resource"
    event = db_session.execute(select(AuditEvent)).scalar_one()
    assert event.event_type == "permission_rejected"


def test_execute_query_runs_allowed_sql_and_audits_success(db_session: Session) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id from public.customers",
        limit=1,
    )

    assert response["status"] == "success"
    assert response["columns"] == [{"name": "id", "data_type": "integer"}]
    assert response["rows"] == [{"id": 1}]
    assert response["query_id"].startswith("qry_")
    assert FakeConnector.last_sql is not None
    assert "LIMIT 1" in FakeConnector.last_sql
    event = db_session.execute(select(AuditEvent)).scalar_one()
    assert event.event_type == "query_execution"
    assert event.decision == "allowed"


def test_execute_query_runs_allowed_read_only_cte(db_session: Session) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    FakeConnector.last_sql = None

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query=(
            "with customer_ids as (select id from public.customers) "
            "select id from customer_ids"
        ),
        limit=1,
    )

    assert response["status"] == "success"
    assert response["rows"] == [{"id": 1}]
    assert FakeConnector.last_sql is not None
    assert "WITH customer_ids AS" in FakeConnector.last_sql


def test_execute_query_rejects_data_modifying_cte_before_connector(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    FakeConnector.last_sql = None

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query=(
            "with customers as ("
            "update public.customers set email = 'alice@example.com' "
            "where id = 1 returning id"
            ") select id from customers"
        ),
        limit=1,
    )

    assert response == {"status": "rejected", "reason": "cte_non_select_not_allowed"}
    assert FakeConnector.last_sql is None


def test_execute_query_rejects_invalid_or_excessive_runtime_limits(
    db_session: Session,
    monkeypatch: MonkeyPatch,
) -> None:
    class LimitSettingsStub(RuntimeSettingsStub):
        runtime_query_max_limit = 2

    monkeypatch.setattr("adg.gateway_runtime.tools.get_settings", lambda: LimitSettingsStub())
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    service = runtime(db_session)
    FakeConnector.last_sql = None

    invalid = service.execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id from warehouse.public.customers",
        limit=0,
    )
    excessive = service.execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id from warehouse.public.customers",
        limit=3,
    )

    assert invalid == {"status": "rejected", "reason": "runtime_limit_invalid"}
    assert excessive == {"status": "rejected", "reason": "runtime_limit_exceeded"}
    assert FakeConnector.last_sql is None


def test_execute_query_returns_structured_error_when_connector_fails(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)

    response = runtime_with_connector(
        db_session,
        FailingOperationConnector,
    ).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id from public.customers",
        limit=1,
    )

    assert response["status"] == "error"
    assert response["query_id"].startswith("qry_")
    assert "columns" not in response
    assert "rows" not in response
    assert "masking" not in response
    assert response["error"] == {
        "type": "connector_operation_error",
        "message": "Datasource query execution failed. Reference query_id for details.",
    }
    assert "10.0.0.9" not in str(response)
    assert "postgresql+psycopg" not in str(response)
    assert "OperationalError" not in str(response)
    event = db_session.execute(select(AuditEvent)).scalar_one()
    assert event.event_type == "query_execution"
    assert event.decision == "error"
    assert event.reason == "connector_operation_error"
    assert event.query_id == response["query_id"]
    assert event.audit_metadata["error_type"] == "connector_operation_error"
    assert event.audit_metadata["query_id"] == response["query_id"]
    assert "error_message" not in event.audit_metadata
    assert "10.0.0.9" not in str(event.audit_metadata)
    assert "postgresql+psycopg" not in str(event.audit_metadata)
    assert "OperationalError" not in str(event.audit_metadata)


def test_execute_query_returns_structured_error_when_connector_dependency_is_missing(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)

    response = runtime_with_connector(
        db_session,
        FailingDependencyConnector,
    ).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id from public.customers",
        limit=1,
    )

    assert response["status"] == "error"
    assert "columns" not in response
    assert "rows" not in response
    assert response["error"] == {
        "type": "connector_dependency_error",
        "message": "Datasource connector dependency is unavailable. Contact an administrator.",
    }
    assert "optional extra" not in str(response)
    event = db_session.execute(select(AuditEvent)).scalar_one()
    assert event.decision == "error"
    assert event.reason == "connector_dependency_error"


def test_execute_query_uses_relaxed_sql_validation_from_settings(
    db_session: Session,
    monkeypatch: MonkeyPatch,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    monkeypatch.setattr(
        "adg.gateway_runtime.tools.get_settings",
        lambda: RuntimeSettingsStub(),
    )

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select *, md5(email) as email_hash from public.customers",
        limit=1,
    )

    assert response["status"] == "success"
    assert FakeConnector.last_sql is not None
    assert "MD5(email)" in FakeConnector.last_sql


def test_execute_query_rejects_denied_field_and_skips_connector(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.add(
        FieldPolicy(
            subject_type="all",
            subject_id="*",
            effect="deny",
            resource_id=resource.id,
            field_name="email",
            action="read",
            status="active",
        )
    )
    FakeConnector.last_sql = None

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id, email from public.customers",
        limit=10,
    )

    assert response["status"] == "rejected"
    assert response["reason"] == "field_access_denied:email"
    assert FakeConnector.last_sql is None


def test_execute_query_rejects_denied_field_referenced_inside_cte(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.add(
        FieldPolicy(
            subject_type="all",
            subject_id="*",
            effect="deny",
            resource_id=resource.id,
            field_name="email",
            action="read",
            status="active",
        )
    )
    FakeConnector.last_sql = None

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query=(
            "with customer_email as ("
            "select email as leaked from public.customers"
            ") select leaked from customer_email"
        ),
        limit=10,
    )

    assert response == {"status": "rejected", "reason": "field_access_denied:email"}
    assert FakeConnector.last_sql is None


def test_execute_query_rejects_disabled_field_and_skips_connector(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.flush()
    email = db_session.execute(
        select(ResourceField).where(
            ResourceField.resource_id == resource.id,
            ResourceField.name == "email",
        )
    ).scalar_one()
    email.status = "disabled"
    FakeConnector.last_sql = None

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id, email from public.customers",
        limit=10,
    )

    assert response["status"] == "rejected"
    assert response["reason"] == "field_disabled:email"
    assert FakeConnector.last_sql is None


def test_list_resources_checks_resource_policy_and_tags_in_one_batch(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    public_tag = Tag(id="tag_public", name="public")
    db_session.add(public_tag)
    resources = [
        add_resource(
            db_session,
            resource_id=f"res_customers_{index}",
            path=f"warehouse.public.customers_{index}",
        )
        for index in range(3)
    ]
    db_session.add_all(
        [ResourceTag(tag_id=public_tag.id, resource_id=resource.id) for resource in resources]
    )
    db_session.add(
        ResourcePolicy(
            subject_type="role",
            subject_id="analyst",
            effect="allow",
            action="read",
            tag_id=public_tag.id,
            status="active",
        )
    )
    engine = cast(Engine, db_session.get_bind())
    resource_policy_select_count = 0
    resource_tag_select_count = 0

    def count_resource_access_selects(
        conn: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        nonlocal resource_policy_select_count, resource_tag_select_count
        lowered = statement.lower()
        if "from resource_policies" in lowered:
            resource_policy_select_count += 1
        if "from resource_tags" in lowered:
            resource_tag_select_count += 1

    event.listen(engine, "before_cursor_execute", count_resource_access_selects)
    try:
        response = runtime(db_session).list_resources(
            identity=identity(),
            api_key_id="key_1",
            datasource_id="ds_1",
        )
    finally:
        event.remove(engine, "before_cursor_execute", count_resource_access_selects)

    assert [resource["id"] for resource in response["resources"]] == [
        resource.id for resource in resources
    ]
    assert resource_policy_select_count == 1
    assert resource_tag_select_count == 1

def test_execute_query_checks_field_policies_in_one_batch(db_session: Session) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    engine = cast(Engine, db_session.get_bind())
    field_policy_select_count = 0

    def count_field_policy_selects(
        conn: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        nonlocal field_policy_select_count
        if "field_policies" in statement.lower():
            field_policy_select_count += 1

    event.listen(engine, "before_cursor_execute", count_field_policy_selects)
    try:
        response = runtime(db_session).execute_query(
            identity=identity(),
            api_key_id="key_1",
            datasource_id="ds_1",
            resource_ids=[resource.id],
            query="select id, email from public.customers",
            limit=1,
        )
    finally:
        event.remove(engine, "before_cursor_execute", count_field_policy_selects)

    assert response["status"] == "success"
    assert field_policy_select_count == 1


def test_execute_query_applies_fixed_masking_policy(db_session: Session) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.add(
        MaskingPolicy(
            resource_id=resource.id,
            field_name="email",
            strategy="fixed",
            config_json='{"replacement":"REDACTED"}',
            status="active",
        )
    )

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id, email from public.customers",
        limit=1,
    )

    assert response["rows"] == [{"id": 1, "email": "REDACTED"}]
    assert response["masking"]["masked_columns"] == [
        {"name": "email", "strategy": "fixed"}
    ]


def test_execute_query_masks_aliased_columns_case_insensitively(
    db_session: Session,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr("adg.gateway_runtime.tools.get_settings", lambda: RuntimeSettingsStub())
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.add(
        MaskingPolicy(
            resource_id=resource.id,
            field_name="email",
            strategy="fixed",
            config_json='{"replacement":"REDACTED"}',
            status="active",
        )
    )

    service = runtime_with_connector(db_session, AliasedResultConnector)
    for query in (
        "select email as leaked from public.customers",
        "select lower(email) as leaked from public.customers",
    ):
        response = service.execute_query(
            identity=identity(),
            api_key_id="key_1",
            datasource_id="ds_1",
            resource_ids=[resource.id],
            query=query,
            limit=1,
        )

        assert response["status"] == "success"
        assert response["rows"] == [{"LEAKED": "REDACTED"}]
        assert response["masking"]["masked_columns"] == [
            {"name": "LEAKED", "strategy": "fixed"}
        ]


def test_execute_query_rejects_cte_when_resource_has_masking_policy(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.add(
        MaskingPolicy(
            resource_id=resource.id,
            field_name="email",
            strategy="fixed",
            config_json='{"replacement":"REDACTED"}',
            status="active",
        )
    )
    FakeConnector.last_sql = None

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query=(
            "with customer_email as ("
            "select email as leaked from public.customers"
            ") select leaked from customer_email"
        ),
        limit=1,
    )

    assert response == {
        "status": "rejected",
        "reason": "masked_nested_projection_not_supported",
    }
    assert FakeConnector.last_sql is None


@pytest.mark.parametrize(
    "query,reason,use_relaxed_validation",
    [
        (
            "select *, email as leaked from public.customers",
            "masked_wildcard_projection_not_allowed",
            True,
        ),
        (
            "select t.leaked from (select email as leaked from public.customers) t",
            "masked_nested_projection_not_supported",
            False,
        ),
        (
            'select email as x, email as "X" from public.customers',
            "duplicate_projection_output_name",
            False,
        ),
    ],
)
def test_execute_query_rejects_masking_projection_bypasses_before_connector(
    db_session: Session,
    monkeypatch: MonkeyPatch,
    query: str,
    reason: str,
    use_relaxed_validation: bool,
) -> None:
    if use_relaxed_validation:
        monkeypatch.setattr(
            "adg.gateway_runtime.tools.get_settings",
            lambda: RuntimeSettingsStub(),
        )
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.add(
        MaskingPolicy(
            resource_id=resource.id,
            field_name="email",
            strategy="fixed",
            config_json='{"replacement":"REDACTED"}',
            status="active",
        )
    )
    AliasedResultConnector.last_sql = None

    response = runtime_with_connector(db_session, AliasedResultConnector).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query=query,
        limit=1,
    )

    assert response == {"status": "rejected", "reason": reason}
    assert AliasedResultConnector.last_sql is None


def test_execute_query_rejects_projection_with_multiple_masking_policies(
    db_session: Session,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr("adg.gateway_runtime.tools.get_settings", lambda: RuntimeSettingsStub())
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.add(
        ResourceField(
            datasource_id="ds_1",
            resource_id=resource.id,
            name="phone",
            data_type="varchar",
            nullable=True,
            ordinal_position=3,
            status="active",
            metadata_json="{}",
        )
    )
    db_session.add_all(
        [
            MaskingPolicy(
                resource_id=resource.id,
                field_name=field_name,
                strategy="fixed",
                config_json='{"replacement":"REDACTED"}',
                status="active",
            )
            for field_name in ("email", "phone")
        ]
    )
    AliasedResultConnector.last_sql = None

    response = runtime_with_connector(db_session, AliasedResultConnector).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select concat(email, phone) as leaked from public.customers",
        limit=1,
    )

    assert response == {"status": "rejected", "reason": "ambiguous_masking_projection"}
    assert AliasedResultConnector.last_sql is None


def test_execute_query_applies_reversible_masking_policy(db_session: Session) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id, allow_decrypt=True)
    db_session.add(
        MaskingPolicy(
            resource_id=resource.id,
            field_name="email",
            strategy="reversible",
            config_json="{}",
            status="active",
        )
    )

    response = runtime(db_session).execute_query(
        identity=identity(),
        api_key_id="key_1",
        datasource_id="ds_1",
        resource_ids=[resource.id],
        query="select id, email from public.customers",
        limit=1,
    )

    assert response["rows"][0]["email"].startswith("$adg_rev$")
    assert response["masking"]["masked_columns"] == [
        {"name": "email", "strategy": "reversible"}
    ]
    assert db_session.query(DecryptContext).count() == 1


def test_preview_resource_runs_bounded_preview(db_session: Session) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.add(
        FieldPolicy(
            subject_type="all",
            subject_id="*",
            effect="deny",
            resource_id=resource.id,
            field_name="email",
            action="read",
            status="active",
        )
    )
    FakeConnector.last_sql = None

    response = runtime(db_session).preview_resource(
        identity=identity(),
        api_key_id="key_1",
        resource_id=resource.id,
        limit=1,
    )

    assert response["status"] == "success"
    assert response["rows"] == [{"id": 1}]
    assert FakeConnector.last_sql == "SELECT id FROM warehouse.public.customers LIMIT 1"


def test_preview_resource_rejects_when_no_fields_are_readable(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    db_session.add_all(
        [
            FieldPolicy(
                subject_type="all",
                subject_id="*",
                effect="deny",
                resource_id=resource.id,
                field_name="id",
                action="read",
                status="active",
            ),
            FieldPolicy(
                subject_type="all",
                subject_id="*",
                effect="deny",
                resource_id=resource.id,
                field_name="email",
                action="read",
                status="active",
            ),
        ]
    )
    FakeConnector.last_sql = None

    response = runtime(db_session).preview_resource(
        identity=identity(),
        api_key_id="key_1",
        resource_id=resource.id,
        limit=1,
    )

    assert response == {"status": "rejected", "reason": "no_readable_fields"}
    assert FakeConnector.last_sql is None


def test_preview_resource_uses_schema_less_doris_style_paths(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(
        db_session,
        resource_id="res_customers",
        path="warehouse.customers",
    )
    allow_resource_read(db_session, resource.id)
    FakeConnector.last_sql = None

    response = runtime(db_session).preview_resource(
        identity=identity(),
        api_key_id="key_1",
        resource_id=resource.id,
        limit=1,
    )

    assert response["status"] == "success"
    assert FakeConnector.last_sql == "SELECT id, email FROM warehouse.customers LIMIT 1"


def test_execute_query_enriches_unknown_column_types_from_scanned_metadata(
    db_session: Session,
) -> None:
    add_datasource(db_session)
    resource = add_resource(db_session, resource_id="res_customers")
    allow_resource_read(db_session, resource.id)
    FakeConnector.override_columns = [
        {"name": "ID", "data_type": "unknown"},
        {"name": "EMAIL", "data_type": "unknown"},
    ]

    try:
        response = runtime(db_session).execute_query(
            identity=identity(),
            api_key_id="key_1",
            datasource_id="ds_1",
            resource_ids=[resource.id],
            query="select id, email from public.customers",
            limit=1,
        )
    finally:
        FakeConnector.override_columns = None

    assert response["status"] == "success"
    assert response["columns"] == [
        {"name": "ID", "data_type": "integer"},
        {"name": "EMAIL", "data_type": "varchar"},
    ]
