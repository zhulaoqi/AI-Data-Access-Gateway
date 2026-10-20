from typing import Any
from uuid import uuid4

from sqlalchemy import ColumnElement, select
from sqlalchemy.orm import Session

from adg.app.settings import get_settings
from adg.audit.service import AuditService
from adg.connectors.base import QueryResult
from adg.connectors.errors import ConnectorDependencyError, ConnectorOperationError
from adg.connectors.registry import ConnectorRegistry, get_connector_registry
from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.governance import ResourceTag, Tag
from adg.control_plane.models.resource import Resource, ResourceField
from adg.masking.service import MaskingService
from adg.policy.runtime import IdentityContext, RuntimePolicyService
from adg.shared.errors import NotFoundError
from adg.sql_guard.guard import SqlGuard
from adg_ext import pipeline as ext_pipeline
from adg_ext.config import ext_enabled


class GatewayRuntimeService:
    """Coordinates runtime discovery, SQL validation, policy checks, masking, and audit."""

    def __init__(
        self,
        session: Session,
        *,
        connector_registry: ConnectorRegistry | None = None,
    ) -> None:
        """Build the runtime service around one unit-of-work database session."""

        self._session = session
        self._connector_registry = connector_registry or get_connector_registry()
        self._policy = RuntimePolicyService(session)
        self._audit = AuditService(session)
        settings = get_settings()
        self._masking = MaskingService(
            session,
            secret_key=settings.secret_key,
            masking_encryption_key=getattr(settings, "masking_encryption_key", settings.secret_key),
            kdf_iterations=getattr(settings, "secret_kdf_iterations", 390_000),
        )

    def list_datasources(
        self,
        *,
        identity: IdentityContext,
        api_key_id: str,
    ) -> dict[str, Any]:
        """Return active datasources visible to runtime callers."""

        self._session.flush()
        visible_datasource_ids = {
            resource.datasource_id for resource in self._visible_resources(identity=identity)
        }
        datasources = self._session.execute(
            select(Datasource)
            .where(
                Datasource.status == "active",
                Datasource.id.in_(visible_datasource_ids),
            )
            .order_by(Datasource.name)
        ).scalars()
        response = {
            "datasources": [
                {
                    "id": datasource.id,
                    "name": datasource.name,
                    "type": datasource.type,
                    "datasource_kind": datasource.datasource_kind,
                    "description": datasource.description,
                }
                for datasource in datasources
            ]
        }
        self._record_discovery(identity, api_key_id, "list_datasources", None, [])
        return response

    def list_tags(self, *, identity: IdentityContext, api_key_id: str) -> dict[str, Any]:
        """Return tags attached to resources the identity may discover."""

        self._session.flush()
        visible_resource_ids = {
            resource.id for resource in self._visible_resources(identity=identity)
        }
        tags = self._session.execute(
            select(Tag)
            .join(ResourceTag, ResourceTag.tag_id == Tag.id)
            .where(
                ResourceTag.resource_id.in_(visible_resource_ids),
            )
            .order_by(Tag.name)
        ).scalars()
        response = {
            "tags": [
                {"id": tag.id, "name": tag.name, "category": tag.category}
                for tag in self._unique_tags(tags)
            ]
        }
        self._record_discovery(identity, api_key_id, "list_tags", None, [])
        return response

    def list_resources(
        self,
        *,
        identity: IdentityContext,
        api_key_id: str,
        datasource_id: str,
    ) -> dict[str, Any]:
        """Return policy-visible relational resources for a datasource."""

        self._session.flush()
        resources = [
            resource
            for resource in self._visible_resources(identity=identity, datasource_id=datasource_id)
        ]
        self._record_discovery(identity, api_key_id, "list_resources", datasource_id, [])
        return {"resources": [self._serialize_resource(resource) for resource in resources]}

    def list_resources_by_tag(
        self,
        *,
        identity: IdentityContext,
        api_key_id: str,
        tag_names: list[str],
    ) -> dict[str, Any]:
        """Return policy-visible resources that have at least one requested tag."""

        self._session.flush()
        tag_rows = self._session.execute(
            select(Tag).where(Tag.name.in_(tag_names))
        ).scalars()
        tag_ids = [tag.id for tag in tag_rows]
        resources = [
            resource
            for resource in self._visible_resources(identity=identity)
            if self._resource_has_any_tag(resource, tag_ids)
        ]
        self._record_discovery(identity, api_key_id, "list_resources_by_tag", None, [])
        return {"resources": [self._serialize_resource(resource) for resource in resources]}

    def describe_resource(
        self,
        *,
        identity: IdentityContext,
        api_key_id: str,
        resource_id: str,
    ) -> dict[str, Any]:
        """Describe a resource and annotate each field with field-policy access."""

        self._session.flush()
        resource = self._get_resource(resource_id)
        disabled_reason = self._disabled_resource_reason(resource)
        if disabled_reason is not None:
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                resource.datasource_id,
                [resource.id],
                None,
                disabled_reason,
            )
            return {"status": "rejected", "reason": disabled_reason}
        access = self._policy.check_resource_access(
            identity=identity,
            resource=resource,
            action="read",
        )
        if not access.allowed:
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                resource.datasource_id,
                [resource.id],
                None,
                access.reason,
            )
            return {"status": "rejected", "reason": access.reason}

        fields = self._session.execute(
            select(ResourceField)
            .where(
                ResourceField.resource_id == resource.id,
                ResourceField.status == "active",
            )
            .order_by(ResourceField.ordinal_position)
        ).scalars()
        columns = []
        for field in fields:
            field_access = self._policy.check_field_access(
                identity=identity,
                resource=resource,
                field_name=field.name,
                action="read",
            )
            if field_access.allowed:
                columns.append(
                    {
                        "name": field.name,
                        "data_type": field.data_type,
                        "nullable": field.nullable,
                        "description": field.description,
                        "access": "allowed",
                        "masking_strategy": None,
                    }
                )
        self._record_discovery(
            identity, api_key_id, "describe_resource", resource.datasource_id, [resource.id]
        )
        return {
            "id": resource.id,
            "name": resource.name,
            "path": resource.path,
            "kind": resource.kind,
            "columns": columns,
        }

    def preview_resource(
        self,
        *,
        identity: IdentityContext,
        api_key_id: str,
        resource_id: str,
        limit: int,
    ) -> dict[str, Any]:
        """Run a bounded SELECT * preview through the same guarded query pipeline."""

        self._session.flush()
        resource = self._get_resource(resource_id)
        disabled_reason = self._disabled_resource_reason(resource)
        if disabled_reason is not None:
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                resource.datasource_id,
                [resource.id],
                None,
                disabled_reason,
            )
            return {"status": "rejected", "reason": disabled_reason}
        decision = self._policy.check_resource_access(
            identity=identity,
            resource=resource,
            action="read",
        )
        if not decision.allowed:
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                resource.datasource_id,
                [resource.id],
                None,
                decision.reason,
            )
            return {"status": "rejected", "reason": decision.reason}
        preview_columns = self._preview_select_columns(identity=identity, resource=resource)
        if preview_columns is None:
            reason = "no_readable_fields"
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                resource.datasource_id,
                [resource.id],
                None,
                reason,
            )
            return {"status": "rejected", "reason": reason}
        return self.execute_query(
            identity=identity,
            api_key_id=api_key_id,
            datasource_id=resource.datasource_id,
            resource_ids=[resource.id],
            query=f"select {preview_columns} from {resource.path}",
            limit=limit,
            event_type="resource_preview",
        )

    def execute_query(
        self,
        *,
        identity: IdentityContext,
        api_key_id: str,
        datasource_id: str,
        resource_ids: list[str],
        query: str,
        limit: int,
        event_type: str = "query_execution",
    ) -> dict[str, Any]:
        """Validate, authorize, execute, mask, and audit a read-only runtime query."""

        self._session.flush()
        if ext_enabled():
            managed = ext_pipeline.run(
                self,
                identity=identity,
                api_key_id=api_key_id,
                datasource_id=datasource_id,
                resource_ids=resource_ids,
                query=query,
                limit=limit,
                event_type=event_type,
            )
            if managed is not None:
                return managed
        settings = get_settings()
        limit_reason = None
        if limit < 1:
            limit_reason = "runtime_limit_invalid"
        elif limit > settings.runtime_query_max_limit:
            limit_reason = "runtime_limit_exceeded"
        if limit_reason is not None:
            self._record_rejection(
                identity,
                api_key_id,
                "sql_rejected",
                datasource_id,
                resource_ids,
                query,
                limit_reason,
            )
            return {"status": "rejected", "reason": limit_reason}
        datasource = self._get_datasource(datasource_id)
        if datasource.status != "active":
            reason = "datasource_disabled"
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                datasource_id,
                resource_ids,
                query,
                reason,
            )
            return {"status": "rejected", "reason": reason}
        declared_resources = [self._get_resource(resource_id) for resource_id in resource_ids]
        # Declared resources are the caller's intended scope; every declared resource is checked.
        for resource in declared_resources:
            disabled_reason = self._disabled_resource_reason(resource)
            if disabled_reason is not None:
                self._record_rejection(
                    identity,
                    api_key_id,
                    "permission_rejected",
                    datasource_id,
                    resource_ids,
                    query,
                    disabled_reason,
                )
                return {"status": "rejected", "reason": disabled_reason}
            decision = self._policy.check_resource_access(
                identity=identity,
                resource=resource,
                action="read",
            )
            if not decision.allowed:
                self._record_rejection(
                    identity,
                    api_key_id,
                    "permission_rejected",
                    datasource_id,
                    resource_ids,
                    query,
                    decision.reason,
                )
                return {"status": "rejected", "reason": decision.reason}

        guard_result = SqlGuard(
            default_limit=limit,
            max_limit=limit,
            execution_mode=settings.sql_execution_mode,
            strict_validation=settings.sql_strict_validation,
            reject_wildcards=settings.sql_reject_wildcard,
        ).check(query)
        if not guard_result.allowed or guard_result.normalized_sql is None:
            reason = ",".join(guard_result.rejection_reasons)
            self._record_rejection(
                identity,
                api_key_id,
                "sql_rejected",
                datasource_id,
                resource_ids,
                query,
                reason,
            )
            return {"status": "rejected", "reason": reason}

        actual_resources = self._resolve_guard_resources(
            identity=identity,
            datasource_id=datasource_id,
            resource_paths=guard_result.accessed_resources,
        )
        if len(actual_resources) != len(guard_result.accessed_resources):
            reason = "unknown_sql_resource"
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                datasource_id,
                resource_ids,
                query,
                reason,
            )
            return {"status": "rejected", "reason": reason}

        disabled_field = self._first_disabled_field(actual_resources, guard_result.accessed_fields)
        if disabled_field is not None:
            reason = f"field_disabled:{disabled_field}"
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                datasource_id,
                resource_ids,
                query,
                reason,
            )
            return {"status": "rejected", "reason": reason}
        inaccessible_field = self._first_inaccessible_field(
            identity=identity,
            resources=actual_resources,
            accessed_fields=guard_result.accessed_fields,
        )
        if inaccessible_field is not None:
            reason = f"field_access_denied:{inaccessible_field}"
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                datasource_id,
                resource_ids,
                query,
                reason,
            )
            return {"status": "rejected", "reason": reason}

        projection_rejection = self._masking.projection_rejection(
            identity=identity,
            resources=actual_resources,
            projections=guard_result.projections,
        )
        if projection_rejection is not None:
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                datasource_id,
                resource_ids,
                query,
                projection_rejection,
            )
            return {"status": "rejected", "reason": projection_rejection}

        declared_ids = set(resource_ids)
        actual_ids = {resource.id for resource in actual_resources}
        # SQL-derived resources are authoritative and must stay inside the declared scope.
        if not actual_ids.issubset(declared_ids):
            reason = "actual_resource_outside_declared_scope"
            self._record_rejection(
                identity,
                api_key_id,
                "permission_rejected",
                datasource_id,
                resource_ids,
                query,
                reason,
            )
            return {"status": "rejected", "reason": reason}

        query_id = f"qry_{uuid4()}"
        try:
            connector = self._connector_registry.create(datasource.type)
            result = connector.execute_query(
                datasource.config(),
                guard_result.normalized_sql,
                limit,
            )
        except (ConnectorDependencyError, ConnectorOperationError) as error:
            error_type = self._connector_error_type(error)
            self._record_connector_error(
                identity=identity,
                api_key_id=api_key_id,
                event_type=event_type,
                datasource_id=datasource_id,
                resource_ids=sorted(actual_ids),
                query_id=query_id,
                sql_text=guard_result.normalized_sql,
                error_type=error_type,
                warnings=guard_result.warnings,
                accessed_fields=guard_result.accessed_fields,
            )
            return {
                "query_id": query_id,
                "status": "error",
                "warnings": guard_result.warnings,
                "error": {
                    "type": error_type,
                    "message": self._connector_error_message(error),
                },
            }
        result = self._enrich_result_column_types(result=result, resources=actual_resources)
        result, masked_columns = self._masking.apply_to_result(
            identity=identity,
            datasource_id=datasource_id,
            query_id=query_id,
            resources=actual_resources,
            result=result,
            projections=guard_result.projections,
        )
        self._audit.record_event(
            user_id=identity.user_id,
            api_key_id=api_key_id,
            event_type=event_type,
            decision="allowed",
            datasource_id=datasource_id,
            resource_ids=sorted(actual_ids),
            query_id=query_id,
            sql_text=guard_result.normalized_sql,
            reason=None,
            metadata={
                "warnings": guard_result.warnings,
                "accessed_fields": guard_result.accessed_fields,
                "masked_columns": masked_columns,
            },
        )
        self._session.flush()
        return {
            "query_id": query_id,
            "status": "success",
            "columns": list(result.columns),
            "rows": list(result.rows),
            "masking": {"masked_columns": masked_columns},
            "warnings": guard_result.warnings,
        }

    def _connector_error_type(
        self,
        error: ConnectorDependencyError | ConnectorOperationError,
    ) -> str:
        """Return a stable client-facing runtime connector error code."""

        if isinstance(error, ConnectorDependencyError):
            return "connector_dependency_error"
        return "connector_operation_error"

    def _connector_error_message(
        self,
        error: ConnectorDependencyError | ConnectorOperationError,
    ) -> str:
        """Return a safe client-facing connector error message."""

        if isinstance(error, ConnectorDependencyError):
            return "Datasource connector dependency is unavailable. Contact an administrator."
        return "Datasource query execution failed. Reference query_id for details."

    def _visible_resources(
        self,
        *,
        identity: IdentityContext,
        datasource_id: str | None = None,
    ) -> list[Resource]:
        """Load relational table/view resources and filter them through resource policies."""

        conditions: list[ColumnElement[bool]] = [
            Resource.kind.in_(["relational_table", "relational_view"]),
            Resource.status == "active",
        ]
        if datasource_id is not None:
            conditions.append(Resource.datasource_id == datasource_id)
        resources = list(
            self._session.execute(
                select(Resource)
                .join(Datasource, Datasource.id == Resource.datasource_id)
                .where(Datasource.status == "active", *conditions)
            ).scalars()
        )
        disabled_reasons = self._disabled_resource_reasons(resources)
        candidates = [
            resource for resource in resources if disabled_reasons.get(resource.id) is None
        ]
        decisions = self._policy.check_resource_access_batch(
            identity=identity,
            resources=candidates,
            action="read",
        )
        return [
            resource
            for resource in candidates
            if decisions.get(resource.id, None) is not None and decisions[resource.id].allowed
        ]

    def _resolve_guard_resources(
        self,
        *,
        identity: IdentityContext,
        datasource_id: str,
        resource_paths: list[str],
    ) -> list[Resource]:
        """Map SQL Guard table references back to exactly one known resource each."""

        resources = list(
            self._session.execute(
                select(Resource).where(
                    Resource.datasource_id == datasource_id,
                    Resource.kind.in_(["relational_table", "relational_view"]),
                    Resource.status == "active",
                )
            ).scalars()
        )
        matched: list[Resource] = []
        for resource_path in resource_paths:
            # SQL may reference a full path or a suffix such as schema.table.
            matches = [
                resource
                for resource in resources
                if resource.path == resource_path or resource.path.endswith(f".{resource_path}")
                if self._disabled_resource_reason(resource) is None
            ]
            if len(matches) == 1:
                matched.append(matches[0])
        return matched

    def _get_datasource(self, datasource_id: str) -> Datasource:
        """Load a datasource for runtime execution."""

        datasource = self._session.get(Datasource, datasource_id)
        if datasource is None:
            raise NotFoundError("Datasource not found")
        return datasource

    def _get_resource(self, resource_id: str) -> Resource:
        """Load a resource or raise a domain not-found error."""

        resource = self._session.get(Resource, resource_id)
        if resource is None:
            raise NotFoundError("Resource not found")
        return resource

    def _resource_has_any_tag(self, resource: Resource, tag_ids: list[str]) -> bool:
        """Check whether a resource has any of the requested tag ids."""

        if not tag_ids:
            return False
        return (
            self._session.execute(
                select(ResourceTag).where(
                    ResourceTag.resource_id == resource.id,
                    ResourceTag.tag_id.in_(tag_ids),
                )
            ).scalar_one_or_none()
            is not None
        )

    def _unique_tags(self, tags: Any) -> list[Tag]:
        """Preserve tag order while removing duplicates introduced by joins."""

        seen: set[str] = set()
        unique: list[Tag] = []
        for tag in tags:
            if tag.id not in seen:
                seen.add(tag.id)
                unique.append(tag)
        return unique

    def _serialize_resource(self, resource: Resource) -> dict[str, Any]:
        """Shape a resource for MCP-style runtime responses."""

        return {
            "id": resource.id,
            "datasource_id": resource.datasource_id,
            "kind": resource.kind,
            "name": resource.name,
            "path": resource.path,
            "display_name": resource.display_name,
            "description": resource.description,
            "query_language": resource.query_language,
        }

    def _disabled_resource_reasons(self, resources: list[Resource]) -> dict[str, str | None]:
        """Return disabled reasons for many resources after batched ancestor loading."""

        resources_by_id = {resource.id: resource for resource in resources}
        pending_parent_ids = {
            resource.parent_id
            for resource in resources
            if resource.parent_id is not None and resource.parent_id not in resources_by_id
        }
        while pending_parent_ids:
            parents = list(
                self._session.execute(
                    select(Resource).where(Resource.id.in_(sorted(pending_parent_ids)))
                ).scalars()
            )
            if not parents:
                break
            pending_parent_ids = set()
            for parent in parents:
                resources_by_id[parent.id] = parent
                if parent.parent_id is not None and parent.parent_id not in resources_by_id:
                    pending_parent_ids.add(parent.parent_id)

        reasons: dict[str, str | None] = {}
        for resource in resources:
            current: Resource | None = resource
            seen_ids: set[str] = set()
            reason = None
            while current is not None and current.id not in seen_ids:
                seen_ids.add(current.id)
                if current.status != "active":
                    reason = "resource_disabled"
                    break
                current = resources_by_id.get(current.parent_id) if current.parent_id else None
            reasons[resource.id] = reason
        return reasons
    def _disabled_resource_reason(self, resource: Resource) -> str | None:
        """Return a stable rejection reason when a resource or ancestor is disabled."""

        datasource = self._session.get(Datasource, resource.datasource_id)
        if datasource is None or datasource.status != "active":
            return "datasource_disabled"
        current: Resource | None = resource
        while current is not None:
            if current.status != "active":
                return "resource_disabled"
            current = self._session.get(Resource, current.parent_id) if current.parent_id else None
        return None

    def _first_disabled_field(
        self,
        resources: list[Resource],
        accessed_fields: list[str],
    ) -> str | None:
        """Find the first explicitly referenced field disabled in any actual resource."""

        if not accessed_fields:
            return None
        disabled_fields = self._session.execute(
            select(ResourceField).where(
                ResourceField.resource_id.in_([resource.id for resource in resources]),
                ResourceField.name.in_(accessed_fields),
                ResourceField.status != "active",
            )
        ).scalars()
        field = next(disabled_fields, None)
        return None if field is None else field.name

    def _first_inaccessible_field(
        self,
        *,
        identity: IdentityContext,
        resources: list[Resource],
        accessed_fields: list[str],
    ) -> str | None:
        """Find the first referenced field denied by active runtime field policy."""

        return self._policy.first_inaccessible_field(
            identity=identity,
            resources=resources,
            field_names=accessed_fields,
            action="read",
        )

    def _preview_select_columns(
        self,
        *,
        identity: IdentityContext,
        resource: Resource,
    ) -> str | None:
        """Build an explicit preview projection from active, readable fields."""

        fields = self._session.execute(
            select(ResourceField)
            .where(
                ResourceField.resource_id == resource.id,
                ResourceField.status == "active",
            )
            .order_by(ResourceField.ordinal_position)
        ).scalars()
        readable_fields = [
            field.name
            for field in fields
            if self._policy.check_field_access(
                identity=identity,
                resource=resource,
                field_name=field.name,
                action="read",
            ).allowed
        ]
        if not readable_fields:
            return None
        return ", ".join(readable_fields)

    def _enrich_result_column_types(
        self,
        *,
        result: QueryResult,
        resources: list[Resource],
    ) -> QueryResult:
        """Fill connector-unknown column types from scanned field metadata when available."""

        if not result.columns:
            return result

        field_rows = self._session.execute(
            select(ResourceField.name, ResourceField.data_type)
            .where(ResourceField.resource_id.in_([resource.id for resource in resources]))
            .order_by(ResourceField.resource_id, ResourceField.ordinal_position)
        ).all()
        data_type_by_name: dict[str, str] = {}
        for field_name, data_type in field_rows:
            data_type_by_name.setdefault(str(field_name).lower(), str(data_type))

        enriched_columns: list[dict[str, Any]] = []
        for column in result.columns:
            column_name = str(column.get("name", ""))
            data_type = str(column.get("data_type", "unknown"))
            if data_type == "unknown":
                data_type = data_type_by_name.get(column_name.lower(), data_type)
            enriched_columns.append({"name": column_name, "data_type": data_type})

        return QueryResult(columns=enriched_columns, rows=result.rows)

    def _record_discovery(
        self,
        identity: IdentityContext,
        api_key_id: str,
        tool_name: str,
        datasource_id: str | None,
        resource_ids: list[str],
    ) -> None:
        """Audit successful metadata-discovery style tool calls."""

        self._audit.record_event(
            user_id=identity.user_id,
            api_key_id=api_key_id,
            event_type="metadata_discovery",
            decision="allowed",
            datasource_id=datasource_id,
            resource_ids=resource_ids,
            query_id=None,
            sql_text=None,
            reason=None,
            metadata={"tool": tool_name},
        )
        self._session.flush()

    def _record_rejection(
        self,
        identity: IdentityContext,
        api_key_id: str,
        event_type: str,
        datasource_id: str | None,
        resource_ids: list[str],
        sql_text: str | None,
        reason: str,
    ) -> None:
        """Audit SQL and permission rejections with their stable reason codes."""

        self._audit.record_event(
            user_id=identity.user_id,
            api_key_id=api_key_id,
            event_type=event_type,
            decision="denied",
            datasource_id=datasource_id,
            resource_ids=resource_ids,
            query_id=None,
            sql_text=sql_text,
            reason=reason,
            metadata={},
        )
        self._session.flush()

    def _record_connector_error(
        self,
        *,
        identity: IdentityContext,
        api_key_id: str,
        event_type: str,
        datasource_id: str,
        resource_ids: list[str],
        query_id: str,
        sql_text: str,
        error_type: str,
        warnings: list[str],
        accessed_fields: list[str],
    ) -> None:
        """Audit connector failures after SQL and policy checks have allowed execution."""

        self._audit.record_event(
            user_id=identity.user_id,
            api_key_id=api_key_id,
            event_type=event_type,
            decision="error",
            datasource_id=datasource_id,
            resource_ids=resource_ids,
            query_id=query_id,
            sql_text=sql_text,
            reason=error_type,
            metadata={
                "warnings": warnings,
                "accessed_fields": accessed_fields,
                "error_type": error_type,
                "query_id": query_id,
            },
        )
        self._session.flush()
