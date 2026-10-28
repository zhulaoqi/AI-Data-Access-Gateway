import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.resource import Resource, ResourceField
from adg.shared.ids import uuidv7


class MetadataScanService:
    """Persists connector metadata snapshots into normalized resource tables."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def replace_snapshot(
        self,
        *,
        datasource: Datasource,
        snapshot: Mapping[str, Sequence[Mapping[str, object]]],
    ) -> dict[str, int]:
        """Replace all scanned resources for a datasource in one deterministic pass."""

        existing_resources = {
            resource.path: resource
            for resource in self._session.execute(
                select(Resource).where(Resource.datasource_id == datasource.id)
            ).scalars()
        }
        self._existing_fields = {
            (field.resource_id, field.name): field
            for field in self._session.execute(
                select(ResourceField).where(ResourceField.datasource_id == datasource.id)
            ).scalars()
        }
        seen_resource_ids: set[str] = set()
        seen_field_ids: set[str] = set()
        resource_count = 0
        field_count = 0
        scanned_at = datetime.now(UTC)

        # Connectors always emit databases, and may either nest relations under schemas
        # or attach tables/views directly to the database when schemas are not meaningful.
        for database_payload in snapshot.get("databases", []):
            database = self._upsert_resource(
                datasource=datasource,
                existing_resources=existing_resources,
                kind="database",
                name=str(database_payload["name"]),
                path=str(database_payload["name"]),
                parent_id=None,
                query_language="sql",
                description=self._payload_description(database_payload),
                metadata={},
                scanned_at=scanned_at,
            )
            seen_resource_ids.add(database.id)
            resource_count += 1

            relation_resources, relation_fields = self._upsert_relations(
                datasource=datasource,
                existing_resources=existing_resources,
                parent_resource=database,
                relation_container=database_payload,
                scanned_at=scanned_at,
            )
            seen_resource_ids.update(relation_resources)
            seen_field_ids.update(relation_fields)
            resource_count += len(relation_resources)
            field_count += len(relation_fields)

            schema_items = database_payload.get("schemas", [])
            if not isinstance(schema_items, Sequence):
                continue

            for schema_payload in schema_items:
                schema_path = f"{database.path}.{schema_payload['name']}"
                schema = self._upsert_resource(
                    datasource=datasource,
                    existing_resources=existing_resources,
                    kind="schema",
                    name=str(schema_payload["name"]),
                    path=schema_path,
                    parent_id=database.id,
                    query_language="sql",
                    description=self._payload_description(schema_payload),
                    metadata={},
                    scanned_at=scanned_at,
                )
                seen_resource_ids.add(schema.id)
                resource_count += 1

                relation_resources, relation_fields = self._upsert_relations(
                    datasource=datasource,
                    existing_resources=existing_resources,
                    parent_resource=schema,
                    relation_container=schema_payload,
                    scanned_at=scanned_at,
                )
                seen_resource_ids.update(relation_resources)
                seen_field_ids.update(relation_fields)
                resource_count += len(relation_resources)
                field_count += len(relation_fields)

        self._session.flush()
        self._delete_stale_snapshot_rows(datasource.id, seen_resource_ids, seen_field_ids)
        return {"resources": resource_count, "fields": field_count}

    def _upsert_resource(
        self,
        *,
        datasource: Datasource,
        existing_resources: dict[str, Resource],
        kind: str,
        name: str,
        path: str,
        parent_id: str | None,
        query_language: str | None,
        description: str | None,
        metadata: dict[str, object],
        scanned_at: datetime,
    ) -> Resource:
        """Create or update one resource while preserving operator annotations."""

        resource = existing_resources.get(path)
        if resource is None:
            resource = Resource(
                id=uuidv7(),
                datasource_id=datasource.id,
                path=path,
                display_name=name,
                description=description,
                status="active",
            )
            self._session.add(resource)
            existing_resources[path] = resource
        elif resource.description is None and description is not None:
            resource.description = description

        resource.parent_id = parent_id
        resource.kind = kind
        resource.name = name
        resource.query_language = query_language
        resource.metadata_json = json.dumps(metadata, separators=(",", ":"))
        resource.scanned_at = scanned_at
        return resource

    def _payload_description(self, payload: Mapping[str, object]) -> str | None:
        """Return a non-empty description from connector metadata payloads."""

        description = payload.get("description")
        if description is None:
            return None
        text = str(description).strip()
        return text or None

    def _upsert_field(
        self,
        *,
        datasource: Datasource,
        relation: Resource,
        name: str,
        data_type: str,
        nullable: bool,
        ordinal_position: int,
        description: str | None,
    ) -> ResourceField:
        """Create or update one field while keeping manual descriptions and status."""

        field = self._existing_fields.get((relation.id, name))
        if field is None:
            field = ResourceField(
                id=uuidv7(),
                datasource_id=datasource.id,
                resource_id=relation.id,
                name=name,
                description=description,
                status="active",
                metadata_json=json.dumps({}, separators=(",", ":")),
            )
            self._session.add(field)
            self._existing_fields[(relation.id, name)] = field
        elif field.description is None and description is not None:
            field.description = description

        field.data_type = data_type
        field.nullable = nullable
        field.ordinal_position = ordinal_position
        field.metadata_json = json.dumps({}, separators=(",", ":"))
        return field

    def _delete_stale_snapshot_rows(
        self,
        datasource_id: str,
        seen_resource_ids: set[str],
        seen_field_ids: set[str],
    ) -> None:
        """Remove assets that disappeared from the latest connector snapshot."""

        field_conditions = [ResourceField.datasource_id == datasource_id]
        if seen_field_ids:
            field_conditions.append(ResourceField.id.not_in(seen_field_ids))
        self._session.execute(delete(ResourceField).where(*field_conditions))

        resource_conditions = [Resource.datasource_id == datasource_id]
        if seen_resource_ids:
            resource_conditions.append(Resource.id.not_in(seen_resource_ids))
        self._session.execute(delete(Resource).where(*resource_conditions))

    def _upsert_relations(
        self,
        *,
        datasource: Datasource,
        existing_resources: dict[str, Resource],
        parent_resource: Resource,
        relation_container: Mapping[str, object],
        scanned_at: datetime,
    ) -> tuple[set[str], set[str]]:
        """Persist tables and views nested directly under one parent resource."""

        seen_resource_ids: set[str] = set()
        seen_field_ids: set[str] = set()
        for relation_key, relation_kind in (
            ("tables", "relational_table"),
            ("views", "relational_view"),
        ):
            relation_items = relation_container.get(relation_key, [])
            if not isinstance(relation_items, Sequence):
                continue
            for relation_payload in relation_items:
                relation_path = f"{parent_resource.path}.{relation_payload['name']}"
                relation = self._upsert_resource(
                    datasource=datasource,
                    existing_resources=existing_resources,
                    kind=relation_kind,
                    name=str(relation_payload["name"]),
                    path=relation_path,
                    parent_id=parent_resource.id,
                    query_language="sql",
                    description=self._payload_description(relation_payload),
                    metadata={},
                    scanned_at=scanned_at,
                )
                seen_resource_ids.add(relation.id)

                column_items = relation_payload.get("columns", [])
                if not isinstance(column_items, Sequence):
                    continue
                for index, column_payload in enumerate(column_items, start=1):
                    field = self._upsert_field(
                        datasource=datasource,
                        relation=relation,
                        name=str(column_payload["name"]),
                        data_type=str(column_payload["data_type"]),
                        nullable=bool(column_payload.get("nullable", True)),
                        ordinal_position=int(column_payload.get("ordinal_position", index)),
                        description=(
                            None
                            if column_payload.get("description") is None
                            else str(column_payload["description"])
                        ),
                    )
                    seen_field_ids.add(field.id)
        return seen_resource_ids, seen_field_ids
