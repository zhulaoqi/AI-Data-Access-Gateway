from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, insert, or_, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.resource import Resource, ResourceField
from adg.shared.ids import uuidv7

# 大库一次扫描会有几万列。整段 NOT IN 会超过数据库的包大小，写入和删除都按这个批量切开。
_WRITE_BATCH = 400
_ATTEMPTS = 3

Progress = Callable[[int, int, str], None]


@dataclass
class _ResourceRow:
    id: str
    kind: str
    name: str
    parent_id: str | None
    query_language: str | None
    description: str | None


@dataclass
class _FieldRow:
    id: str
    data_type: str
    nullable: bool
    ordinal_position: int
    description: str | None


@dataclass
class Applied:
    resources: int
    fields: int
    resource_ids: set[str]
    field_ids: set[str]


class CatalogGone(Exception):
    """The datasource row disappeared while a scan was writing."""


def persist_snapshot(
    session_factory: sessionmaker[Session],
    datasource_id: str,
    snapshot: Mapping[str, Sequence[Mapping[str, object]]],
    progress: Progress | None = None,
) -> dict[str, int]:
    """Write one database per transaction. A dropped connection retries that database only.

    Rows that disappeared are removed after every database has committed. A failure leaves
    the previous catalog in place for the databases that did not finish.
    """

    databases = list(snapshot.get("databases") or [])
    seen_resources: set[str] = set()
    seen_fields: set[str] = set()
    totals = {"resources": 0, "fields": 0}
    scanned_at = datetime.now(UTC)
    total = len(databases)
    for index, payload in enumerate(databases):
        if not isinstance(payload, Mapping):
            continue
        name = str(payload.get("name") or "")
        if progress is not None:
            progress(index, total, name)
        applied = _apply_with_retry(session_factory, datasource_id, payload, scanned_at)
        totals["resources"] += applied.resources
        totals["fields"] += applied.fields
        seen_resources.update(applied.resource_ids)
        seen_fields.update(applied.field_ids)
    _delete_with_retry(session_factory, datasource_id, seen_resources, seen_fields)
    return totals


def _apply_with_retry(
    session_factory: sessionmaker[Session],
    datasource_id: str,
    payload: Mapping[str, object],
    scanned_at: datetime,
) -> Applied:
    last: OperationalError | None = None
    for _ in range(_ATTEMPTS):
        try:
            with session_factory() as session:
                datasource = session.get(Datasource, datasource_id)
                if datasource is None:
                    raise CatalogGone(datasource_id)
                applied = MetadataScanService(session).apply_database(
                    datasource=datasource,
                    database_payload=payload,
                    scanned_at=scanned_at,
                )
                session.commit()
                return applied
        except CatalogGone:
            raise
        except OperationalError as error:
            last = error
    assert last is not None
    raise last


def _delete_with_retry(
    session_factory: sessionmaker[Session],
    datasource_id: str,
    seen_resources: set[str],
    seen_fields: set[str],
) -> None:
    last: OperationalError | None = None
    for _ in range(_ATTEMPTS):
        try:
            with session_factory() as session:
                if session.get(Datasource, datasource_id) is None:
                    return
                MetadataScanService(session).delete_stale(
                    datasource_id, seen_resources, seen_fields
                )
                session.commit()
                return
        except OperationalError as error:
            last = error
    assert last is not None
    raise last


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
        """Replace all scanned resources for a datasource in the caller's transaction."""

        seen_resources: set[str] = set()
        seen_fields: set[str] = set()
        resource_count = 0
        field_count = 0
        scanned_at = datetime.now(UTC)
        for database_payload in snapshot.get("databases", []):
            if not isinstance(database_payload, Mapping):
                continue
            applied = self.apply_database(
                datasource=datasource,
                database_payload=database_payload,
                scanned_at=scanned_at,
            )
            seen_resources.update(applied.resource_ids)
            seen_fields.update(applied.field_ids)
            resource_count += applied.resources
            field_count += applied.fields
        self.delete_stale(datasource.id, seen_resources, seen_fields)
        return {"resources": resource_count, "fields": field_count}

    def apply_database(
        self,
        *,
        datasource: Datasource,
        database_payload: Mapping[str, object],
        scanned_at: datetime,
    ) -> Applied:
        """Insert or update one database. Unchanged columns are not written."""

        database_name = str(database_payload["name"])
        existing = self._load_resources(datasource.id, database_name)
        fields = self._load_fields(datasource.id, [row.id for row in existing.values()])
        new_resources: list[dict[str, object]] = []
        new_fields: list[dict[str, object]] = []
        seen_resources: set[str] = set()
        seen_fields: set[str] = set()
        resource_count = 0
        field_count = 0

        def upsert_resource(
            *,
            kind: str,
            name: str,
            path: str,
            parent_id: str | None,
            description: str | None,
        ) -> str:
            row = existing.get(path)
            if row is None:
                resource_id = uuidv7()
                new_resources.append(
                    {
                        "id": resource_id,
                        "datasource_id": datasource.id,
                        "parent_id": parent_id,
                        "kind": kind,
                        "name": name,
                        "path": path,
                        "display_name": name,
                        "description": description,
                        "query_language": "sql",
                        "status": "active",
                        "metadata_json": "{}",
                        "scanned_at": scanned_at,
                    }
                )
                existing[path] = _ResourceRow(
                    id=resource_id,
                    kind=kind,
                    name=name,
                    parent_id=parent_id,
                    query_language="sql",
                    description=description,
                )
                seen_resources.add(resource_id)
                return resource_id
            seen_resources.add(row.id)
            changes: dict[str, object] = {}
            if row.kind != kind:
                changes["kind"] = kind
            if row.name != name:
                changes["name"] = name
            if row.parent_id != parent_id:
                changes["parent_id"] = parent_id
            if row.query_language != "sql":
                changes["query_language"] = "sql"
            if row.description is None and description is not None:
                changes["description"] = description
            if changes:
                changes["scanned_at"] = scanned_at
                self._session.execute(
                    update(Resource).where(Resource.id == row.id).values(**changes)
                )
                existing[path] = _ResourceRow(
                    id=row.id,
                    kind=kind,
                    name=name,
                    parent_id=parent_id,
                    query_language="sql",
                    description=row.description if row.description is not None else description,
                )
            return row.id

        def upsert_field(
            *,
            resource_id: str,
            name: str,
            data_type: str,
            nullable: bool,
            ordinal_position: int,
            description: str | None,
        ) -> None:
            row = fields.get((resource_id, name))
            if row is None:
                field_id = uuidv7()
                new_fields.append(
                    {
                        "id": field_id,
                        "datasource_id": datasource.id,
                        "resource_id": resource_id,
                        "name": name,
                        "data_type": data_type,
                        "nullable": nullable,
                        "ordinal_position": ordinal_position,
                        "description": description,
                        "status": "active",
                        "metadata_json": "{}",
                    }
                )
                fields[(resource_id, name)] = _FieldRow(
                    id=field_id,
                    data_type=data_type,
                    nullable=nullable,
                    ordinal_position=ordinal_position,
                    description=description,
                )
                seen_fields.add(field_id)
                return
            seen_fields.add(row.id)
            changes: dict[str, object] = {}
            if row.data_type != data_type:
                changes["data_type"] = data_type
            if bool(row.nullable) != nullable:
                changes["nullable"] = nullable
            if row.ordinal_position != ordinal_position:
                changes["ordinal_position"] = ordinal_position
            if row.description is None and description is not None:
                changes["description"] = description
            if changes:
                self._session.execute(
                    update(ResourceField).where(ResourceField.id == row.id).values(**changes)
                )

        upsert_resource(
            kind="database",
            name=database_name,
            path=database_name,
            parent_id=None,
            description=_description(database_payload),
        )
        resource_count += 1
        resource_count, field_count = self._apply_relations(
            container=database_payload,
            parent_id=existing[database_name].id,
            parent_path=database_name,
            upsert_resource=upsert_resource,
            upsert_field=upsert_field,
            resource_count=resource_count,
            field_count=field_count,
        )
        for schema_payload in _sequence(database_payload.get("schemas")):
            schema_name = str(schema_payload["name"])
            schema_path = f"{database_name}.{schema_name}"
            schema_id = upsert_resource(
                kind="schema",
                name=schema_name,
                path=schema_path,
                parent_id=existing[database_name].id,
                description=_description(schema_payload),
            )
            resource_count += 1
            resource_count, field_count = self._apply_relations(
                container=schema_payload,
                parent_id=schema_id,
                parent_path=schema_path,
                upsert_resource=upsert_resource,
                upsert_field=upsert_field,
                resource_count=resource_count,
                field_count=field_count,
            )
        self._insert(Resource, new_resources)
        self._insert(ResourceField, new_fields)
        return Applied(resource_count, field_count, seen_resources, seen_fields)

    def delete_stale(
        self,
        datasource_id: str,
        seen_resource_ids: set[str],
        seen_field_ids: set[str],
    ) -> None:
        """Remove assets that disappeared from the latest connector snapshot."""

        self._delete_absent(ResourceField, datasource_id, seen_field_ids)
        self._delete_absent(Resource, datasource_id, seen_resource_ids)

    def _apply_relations(
        self,
        *,
        container: Mapping[str, object],
        parent_id: str,
        parent_path: str,
        upsert_resource: Callable[..., str],
        upsert_field: Callable[..., None],
        resource_count: int,
        field_count: int,
    ) -> tuple[int, int]:
        for relation_key, relation_kind in (
            ("tables", "relational_table"),
            ("views", "relational_view"),
        ):
            for relation_payload in _sequence(container.get(relation_key)):
                relation_name = str(relation_payload["name"])
                relation_id = upsert_resource(
                    kind=relation_kind,
                    name=relation_name,
                    path=f"{parent_path}.{relation_name}",
                    parent_id=parent_id,
                    description=_description(relation_payload),
                )
                resource_count += 1
                for index, column_payload in enumerate(
                    _sequence(relation_payload.get("columns")), start=1
                ):
                    upsert_field(
                        resource_id=relation_id,
                        name=str(column_payload["name"]),
                        data_type=str(column_payload["data_type"]),
                        nullable=bool(column_payload.get("nullable", True)),
                        ordinal_position=_ordinal(column_payload.get("ordinal_position"), index),
                        description=_description(column_payload),
                    )
                    field_count += 1
        return resource_count, field_count

    def _load_resources(self, datasource_id: str, database: str) -> dict[str, _ResourceRow]:
        prefix = _like_prefix(database)
        rows = self._session.execute(
            select(
                Resource.id,
                Resource.path,
                Resource.kind,
                Resource.name,
                Resource.parent_id,
                Resource.query_language,
                Resource.description,
            ).where(
                Resource.datasource_id == datasource_id,
                or_(Resource.path == database, Resource.path.like(prefix, escape="\\")),
            )
        )
        return {
            path: _ResourceRow(
                id=resource_id,
                kind=kind,
                name=name,
                parent_id=parent_id,
                query_language=query_language,
                description=description,
            )
            for resource_id, path, kind, name, parent_id, query_language, description in rows
        }

    def _load_fields(
        self, datasource_id: str, resource_ids: list[str]
    ) -> dict[tuple[str, str], _FieldRow]:
        found: dict[tuple[str, str], _FieldRow] = {}
        for start in range(0, len(resource_ids), _WRITE_BATCH):
            chunk = resource_ids[start : start + _WRITE_BATCH]
            rows = self._session.execute(
                select(
                    ResourceField.id,
                    ResourceField.resource_id,
                    ResourceField.name,
                    ResourceField.data_type,
                    ResourceField.nullable,
                    ResourceField.ordinal_position,
                    ResourceField.description,
                ).where(
                    ResourceField.datasource_id == datasource_id,
                    ResourceField.resource_id.in_(chunk),
                )
            )
            for (
                field_id,
                resource_id,
                name,
                data_type,
                nullable,
                ordinal_position,
                description,
            ) in rows:
                found[(resource_id, name)] = _FieldRow(
                    id=field_id,
                    data_type=data_type,
                    nullable=bool(nullable),
                    ordinal_position=ordinal_position,
                    description=description,
                )
        return found

    def _insert(
        self, model: type[Resource] | type[ResourceField], rows: list[dict[str, object]]
    ) -> None:
        for start in range(0, len(rows), _WRITE_BATCH):
            self._session.execute(insert(model), rows[start : start + _WRITE_BATCH])

    def _delete_absent(
        self,
        model: type[Resource] | type[ResourceField],
        datasource_id: str,
        seen_ids: set[str],
    ) -> None:
        """Delete rows this scan did not touch, in small id lists."""

        existing = self._session.execute(
            select(model.id).where(model.datasource_id == datasource_id)
        ).scalars()
        stale = [item for item in existing if item not in seen_ids]
        for start in range(0, len(stale), _WRITE_BATCH):
            chunk = stale[start : start + _WRITE_BATCH]
            self._session.execute(delete(model).where(model.id.in_(chunk)))


def _ordinal(value: object, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value


def _description(payload: Mapping[str, object]) -> str | None:
    description = payload.get("description")
    if description is None:
        return None
    text = str(description).strip()
    return text or None


def _sequence(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _like_prefix(database: str) -> str:
    escaped = database.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped + ".%"
