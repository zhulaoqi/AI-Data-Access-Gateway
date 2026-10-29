"""Materializes the management service's objects (``/admin/ext/sync``) into ADG's native model.

Contract: ``sql-gateway/api/executor-admin.md``. Every object is addressed by a ``gw:``-prefixed
name; PUT/DELETE are idempotent and the hash it was synced at is kept so the management service
can reconcile. Object types map to ADG as: datasource_account -> Datasource (+ metadata scan),
role -> Role + resource policies + masking policies + ``ext_role_*`` rows, row_filter ->
``ext_row_filter_policies``, user -> User + user role + ``ext_user_attributes``, credential ->
ApiKey (``runtime`` scope, externally supplied SHA-256 hash).
"""

import json
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from adg.app.log_config import kv
from adg.connectors.errors import ConnectorDependencyError, ConnectorOperationError
from adg.connectors.registry import ConnectorRegistry, get_connector_registry
from adg.control_plane.models.api_key import ApiKey
from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.directory import Role, User, UserRole
from adg.control_plane.models.governance import ResourcePolicy
from adg.control_plane.models.masking import MaskingPolicy
from adg.control_plane.models.resource import Resource, ResourceField
from adg.control_plane.services.api_key_service import create_api_key
from adg.control_plane.services.datasource_service import DatasourceService
from adg.control_plane.services.metadata_scan_service import MetadataScanService
from adg_ext.guard import dialect_for
from adg_ext.models import (
    ExtDatasourceCapacity,
    ExtRoleSpec,
    ExtRoleTable,
    ExtRowFilterPolicy,
    ExtSyncObject,
    ExtUserAttribute,
)
from adg_ext.params import ParamSpec
from adg_ext.rowfilter import compile_template

logger = logging.getLogger(__name__)

PREFIX = "gw:"
TYPES = ("datasource_account", "role", "row_filter", "user", "credential")
_ENGINE_TO_CONNECTOR = {
    "mysql": "mysql",
    "starrocks": "doris",
    "doris": "doris",
    "clickhouse": "clickhouse",
}
_MASK_STRATEGIES = {
    "hash": ("hash", {}),
    "partial": ("partial", {"prefix": 2, "suffix": 2, "fill": "*"}),
    "null": ("null", {}),
}
# Object names land in the native columns ``datasources.name``, ``roles.name``,
# ``users.external_ref`` and ``api_keys.name`` (all ``String(200)``); a longer name used to fail
# deep in the database ("Data too long" on MySQL), now it is refused up front with a 400.
MAX_NAME = 200
MAX_IDENT = 200  # resources.name / display_name, resource_fields.name / data_type
MAX_PATH = 512  # resources.path
MAX_DESCRIPTION = 4000  # free text kept as a display label (TEXT is 64 KB on MySQL)


def _fit_description(payload: dict[str, Any]) -> dict[str, Any]:
    description = payload.get("description")
    if isinstance(description, str) and len(description) > MAX_DESCRIPTION:
        return {**payload, "description": description[:MAX_DESCRIPTION]}
    return dict(payload)


def fit_snapshot(snapshot: Any, datasource: str) -> dict[str, Any]:
    """Make a scanned catalog fit the control-plane columns instead of failing the whole sync.

    A column ``data_type`` (a ClickHouse ``Enum``/``Tuple`` can be very long) is only displayed, so
    it is truncated. A database, schema, table or column whose name (or table path) is longer than
    its column cannot be stored; it is left out of the catalog, which makes it unqueryable (fail
    closed), and the omission is logged. MySQL/Doris identifiers are at most 64 characters, so
    this only ever concerns ClickHouse.
    """

    dropped: list[str] = []

    def fits(name: str, path: str) -> bool:
        return len(name) <= MAX_IDENT and len(path) <= MAX_PATH

    def relations(container: dict[str, Any], parent_path: str) -> dict[str, Any]:
        out = _fit_description(container)
        for key in ("tables", "views"):
            kept: list[dict[str, Any]] = []
            for relation in container.get(key) or []:
                name = str(relation["name"])
                path = f"{parent_path}.{name}"
                if not fits(name, path):
                    dropped.append(path[:80])
                    continue
                columns: list[dict[str, Any]] = []
                for column in relation.get("columns") or []:
                    if len(str(column["name"])) > MAX_IDENT:
                        dropped.append(f"{path}.{str(column['name'])[:40]}")
                        continue
                    data_type = str(column.get("data_type", ""))[:MAX_IDENT]
                    columns.append({**_fit_description(column), "data_type": data_type})
                kept.append({**_fit_description(relation), "columns": columns})
            if key in container:
                out[key] = kept
        return out

    databases: list[dict[str, Any]] = []
    for database in snapshot.get("databases") or []:
        db_name = str(database["name"])
        if not fits(db_name, db_name):
            dropped.append(db_name[:80])
            continue
        fitted = relations(database, db_name)
        if "schemas" in database:
            schemas: list[dict[str, Any]] = []
            for schema in database.get("schemas") or []:
                schema_path = f"{db_name}.{schema['name']}"
                if not fits(str(schema["name"]), schema_path):
                    dropped.append(schema_path[:80])
                    continue
                schemas.append(relations(schema, schema_path))
            fitted["schemas"] = schemas
        databases.append(fitted)
    if dropped:
        logger.warning(
            kv(
                event="catalog_entries_dropped",
                datasource=datasource,
                count=len(dropped),
                first=dropped[0],
                reason="exceeds_control_plane_column_width",
            )
        )
    return {**snapshot, "databases": databases}


class ExtSyncError(Exception):
    """A sync request that cannot be applied; ``status`` is the HTTP status to answer with."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class Remote:
    name: str
    external_id: str | None
    hash: str


def _ms(value: Any) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(int(value) / 1000, tz=UTC)


class SyncService:
    """Applies one sync request inside the caller's session (the caller commits)."""

    def __init__(self, session: Session, registry: ConnectorRegistry | None = None) -> None:
        self._s = session
        self._registry = registry or get_connector_registry()

    # ---- public API -----------------------------------------------------------------------

    def put(self, object_type: str, name: str, hash_: str, spec: dict[str, Any]) -> str:
        self._check(object_type, name)
        if len(hash_) != 64:
            raise ExtSyncError(400, "hash must be a 64 character digest")
        existing = self._find(object_type, name)
        if existing is not None and existing.hash == hash_ and existing.external_id:
            logger.debug(kv(event="sync_put", type=object_type, name=name, changed=False))
            return existing.external_id
        handler = getattr(self, f"_put_{object_type}")
        external_id: str = handler(name, spec, existing)
        record = existing or ExtSyncObject(object_type=object_type, name=name)
        record.hash = hash_
        record.spec_json = json.dumps(spec, separators=(",", ":"), sort_keys=True)
        record.external_id = external_id
        record.updated_at = datetime.now(UTC)
        self._s.add(record)
        self._s.flush()
        logger.info(
            kv(
                event="sync_put",
                type=object_type,
                name=name,
                changed=True,
                created=existing is None,
                external_id=external_id,
            )
        )
        return external_id

    def delete(self, object_type: str, name: str) -> None:
        self._check(object_type, name)
        existing = self._find(object_type, name)
        if existing is None:
            return
        getattr(self, f"_delete_{object_type}")(name, existing)
        self._s.delete(existing)
        self._s.flush()
        logger.info(
            kv(event="sync_delete", type=object_type, name=name, external_id=existing.external_id)
        )

    def reinstate(self, object_type: str, name: str) -> bool:
        """Lift the revocation tombstone of a user or credential (explicit, admin only).

        A revoked credential or a deleted (disabled) user is a tombstone: replaying the same
        object through ``put`` is refused (``credential_revoked`` / ``user_revoked``). Reinstating
        only makes a *new* PUT possible; it does not restore any authorization by itself: the
        user comes back active but without a role, a retired key hash can never authenticate.
        """

        if object_type not in ("user", "credential"):
            raise ExtSyncError(422, "only user and credential tombstones can be lifted")
        self._check(object_type, name)
        if self._find(object_type, name) is not None:
            return False  # not revoked: it is a live synced object
        if object_type == "user":
            user = self._s.execute(
                select(User).where(User.external_ref == name, User.status == "disabled")
            ).scalar_one_or_none()
            if user is None:
                return False
            user.status = "active"  # no role, no attributes: nothing is granted
        else:
            keys = list(
                self._s.execute(
                    select(ApiKey).where(ApiKey.name == name, ApiKey.status == "revoked")
                ).scalars()
            )
            if not keys:
                return False
            for key in keys:
                key.key_hash = f"retired:{key.id}"  # frees the unique hash, can never match
        self._s.flush()
        logger.info(kv(event="sync_reinstated", type=object_type, name=name))
        return True

    def external_id_of(self, object_type: str, name: str) -> str | None:
        existing = self._find(object_type, name) if object_type in TYPES else None
        return existing.external_id if existing else None

    def list(self, object_type: str, prefix: str) -> list[Remote]:
        if object_type not in TYPES:
            raise ExtSyncError(404, "unknown object type")
        if not prefix.startswith(PREFIX):
            raise ExtSyncError(400, "prefix must start with gw:")
        rows = self._s.execute(
            select(ExtSyncObject)
            .where(ExtSyncObject.object_type == object_type, ExtSyncObject.name.like(prefix + "%"))
            .order_by(ExtSyncObject.name)
        ).scalars()
        return [Remote(r.name, r.external_id, r.hash) for r in rows]

    # ---- helpers --------------------------------------------------------------------------

    @staticmethod
    def _check(object_type: str, name: str) -> None:
        if object_type not in TYPES:
            raise ExtSyncError(404, "unknown object type")
        if not name.startswith(PREFIX) or len(name) > MAX_NAME:
            raise ExtSyncError(
                400, f"object names must start with gw: and be at most {MAX_NAME} characters"
            )

    def _find(self, object_type: str, name: str) -> ExtSyncObject | None:
        return self._s.execute(
            select(ExtSyncObject).where(
                ExtSyncObject.object_type == object_type, ExtSyncObject.name == name
            )
        ).scalar_one_or_none()

    def _external_id(self, object_type: str, name: str, what: str) -> str:
        obj = self._find(object_type, name)
        if obj is None or not obj.external_id:
            raise ExtSyncError(409, f"{what} {name} has not been synced")
        return obj.external_id

    # ---- datasource_account ---------------------------------------------------------------

    def _put_datasource_account(
        self, name: str, spec: dict[str, Any], existing: ExtSyncObject | None
    ) -> str:
        engine = str(spec.get("engine", "")).lower()
        connector_type = _ENGINE_TO_CONNECTOR.get(engine)
        if connector_type is None:
            raise ExtSyncError(422, f"unsupported engine: {engine or 'missing'}")
        config: dict[str, object] = {
            "host": spec.get("host"),
            "port": spec.get("port"),
            "username": spec.get("username"),
            "password": spec.get("password"),
        }
        if spec.get("database"):
            config["database"] = spec["database"]
        if "databases" in spec:
            raw_databases = spec.get("databases")
            if isinstance(raw_databases, list):
                config["databases"] = [
                    str(item).strip() for item in raw_databases if str(item).strip()
                ]
            else:
                config["databases"] = []
        if not config["host"] or not config["username"]:
            raise ExtSyncError(422, "host and username are required")
        service = DatasourceService(self._s)
        datasource = self._datasource_for(existing)
        if datasource is None:
            datasource = service.create_datasource(
                name=name,
                connector_type=connector_type,
                config=config,
                description=str(spec.get("label") or "")[:MAX_DESCRIPTION],
            )
        else:
            service.update_datasource(
                datasource_id=datasource.id,
                name=name,
                description=str(spec.get("label") or "")[:MAX_DESCRIPTION],
                description_provided=True,
                status="active",
                config=config,
            )
            datasource.type = connector_type
        self._s.flush()
        self._sync_datasource_capacity(datasource.id, spec.get("capacity"))
        self._scan(datasource, name)
        return datasource.id

    def _sync_datasource_capacity(self, datasource_id: str, raw: Any) -> None:
        existing = self._s.get(ExtDatasourceCapacity, datasource_id)
        if raw is None:
            if existing is not None:
                self._s.delete(existing)
            return
        if not isinstance(raw, dict):
            raise ExtSyncError(422, "capacity must be an object")
        try:
            connection_budget = int(raw["connectionBudget"])
            max_query_concurrency = int(raw["maxQueryConcurrency"])
        except (KeyError, TypeError, ValueError) as error:
            raise ExtSyncError(
                422, "capacity requires integer connectionBudget and maxQueryConcurrency"
            ) from error
        if connection_budget < 1 or max_query_concurrency < 1:
            raise ExtSyncError(422, "datasource capacity values must be positive")
        tier = str(raw.get("tier") or "")[:64]
        if existing is None:
            self._s.add(
                ExtDatasourceCapacity(
                    datasource_id=datasource_id,
                    tier=tier,
                    connection_budget=connection_budget,
                    max_query_concurrency=max_query_concurrency,
                )
            )
        else:
            existing.tier = tier
            existing.connection_budget = connection_budget
            existing.max_query_concurrency = max_query_concurrency
        self._s.flush()

    def rescan(self, name: str) -> dict[str, int]:
        """Re-read the live catalog of a synced datasource; the spec and hash stay unchanged."""

        self._check("datasource_account", name)
        datasource = self._datasource_for(self._find("datasource_account", name))
        if datasource is None:
            raise ExtSyncError(404, f"datasource_account {name} has not been synced")
        return self._scan(datasource, name)

    def _scan(self, datasource: Datasource, name: str) -> dict[str, int]:
        started = time.perf_counter()
        try:
            connector = self._registry.create(datasource.type)
            snapshot = connector.scan_metadata(datasource.config())
            counts = MetadataScanService(self._s).replace_snapshot(
                datasource=datasource, snapshot=fit_snapshot(snapshot, name)
            )
        except (ConnectorDependencyError, ConnectorOperationError) as error:
            logger.warning(
                kv(
                    event="catalog_scan_failed",
                    datasource=name,
                    engine=datasource.type,
                    ms=int((time.perf_counter() - started) * 1000),
                    error=type(error).__name__,
                )
            )
            raise ExtSyncError(409, f"cannot scan datasource {name}: {error}") from error
        logger.info(
            kv(
                event="catalog_scanned",
                datasource=name,
                engine=datasource.type,
                ms=int((time.perf_counter() - started) * 1000),
                **{k: v for k, v in counts.items() if isinstance(v, int)},
            )
        )
        return counts

    def _datasource_for(self, existing: ExtSyncObject | None) -> Datasource | None:
        if existing is None or not existing.external_id:
            return None
        return self._s.get(Datasource, existing.external_id)

    def _delete_datasource_account(self, name: str, existing: ExtSyncObject) -> None:
        datasource = self._datasource_for(existing)
        if datasource is None:
            return
        resource_ids = list(
            self._s.execute(
                select(Resource.id).where(Resource.datasource_id == datasource.id)
            ).scalars()
        )
        if resource_ids:
            self._s.execute(delete(ExtRoleTable).where(ExtRoleTable.resource_id.in_(resource_ids)))
            self._s.execute(
                delete(ExtRowFilterPolicy).where(ExtRowFilterPolicy.resource_id.in_(resource_ids))
            )
        self._s.execute(
            delete(ExtDatasourceCapacity).where(
                ExtDatasourceCapacity.datasource_id == datasource.id
            )
        )
        DatasourceService(self._s).delete_datasource(datasource.id)

    # ---- role -----------------------------------------------------------------------------

    def _resource_for(self, datasource_name: str, database: str, table: str) -> Resource:
        datasource_id = self._external_id("datasource_account", datasource_name, "datasource")
        key = f"{database}.{table}"
        matches = [
            r
            for r in self._s.execute(
                select(Resource).where(
                    Resource.datasource_id == datasource_id,
                    Resource.kind.in_(["relational_table", "relational_view"]),
                    Resource.status == "active",
                )
            ).scalars()
            if r.path == key or r.path.endswith(f".{key}")
        ]
        if len(matches) != 1:
            raise ExtSyncError(409, f"table {key} not found in {datasource_name}")
        return matches[0]

    def _put_role(self, name: str, spec: dict[str, Any], existing: ExtSyncObject | None) -> str:
        role = self._s.execute(select(Role).where(Role.name == name)).scalar_one_or_none()
        if role is None:
            description = str(spec.get("profileName") or "")[:MAX_DESCRIPTION]
            role = Role(name=name, description=description, status="active")
            self._s.add(role)
            self._s.flush()
        role.status = "active"
        self._clear_role(role.id)
        spec_row = ExtRoleSpec(
            role_id=role.id,
            operations_json=json.dumps(spec.get("operations") or {}, separators=(",", ":")),
            limits_json=json.dumps(spec.get("limits") or {}, separators=(",", ":")),
        )
        self._s.add(spec_row)
        for table in spec.get("tables") or []:
            resource = self._resource_for(
                str(table["datasource"]), str(table["database"]), str(table["table"])
            )
            allow = sorted({str(c) for c in table.get("allow") or []})
            deny = sorted({str(c) for c in table.get("deny") or []})
            mask: dict[str, str] = {str(k): str(v) for k, v in (table.get("mask") or {}).items()}
            self._s.add(
                ExtRoleTable(
                    role_id=role.id,
                    resource_id=resource.id,
                    allow_json=json.dumps(allow),
                    deny_json=json.dumps(deny),
                    mask_json=json.dumps(mask, sort_keys=True),
                )
            )
            self._s.add(
                ResourcePolicy(
                    subject_type="role",
                    subject_id=role.id,
                    effect="allow",
                    action="read",
                    resource_id=resource.id,
                )
            )
            known = set(
                self._s.execute(
                    select(ResourceField.name).where(ResourceField.resource_id == resource.id)
                ).scalars()
            )
            for column, method in mask.items():
                if method not in _MASK_STRATEGIES:
                    raise ExtSyncError(422, f"unsupported mask method {method}")
                if column not in known:
                    raise ExtSyncError(409, f"column {column} not found in {resource.path}")
                strategy, config = _MASK_STRATEGIES[method]
                self._s.add(
                    MaskingPolicy(
                        resource_id=resource.id,
                        field_name=column,
                        subject_type="role",
                        subject_id=role.id,
                        strategy=strategy,
                        config_json=json.dumps(config, separators=(",", ":")),
                    )
                )
        self._s.flush()
        return role.id

    def _clear_role(self, role_id: str) -> None:
        self._s.execute(delete(ExtRoleSpec).where(ExtRoleSpec.role_id == role_id))
        self._s.execute(delete(ExtRoleTable).where(ExtRoleTable.role_id == role_id))
        self._s.execute(
            delete(ResourcePolicy).where(
                ResourcePolicy.subject_type == "role", ResourcePolicy.subject_id == role_id
            )
        )
        self._s.execute(
            delete(MaskingPolicy).where(
                MaskingPolicy.subject_type == "role", MaskingPolicy.subject_id == role_id
            )
        )

    def _delete_role(self, name: str, existing: ExtSyncObject) -> None:
        role = self._s.execute(select(Role).where(Role.name == name)).scalar_one_or_none()
        if role is None:
            return
        self._clear_role(role.id)
        self._s.execute(delete(ExtRowFilterPolicy).where(ExtRowFilterPolicy.role_id == role.id))
        self._s.execute(delete(UserRole).where(UserRole.role_id == role.id))
        self._s.delete(role)

    # ---- row_filter -----------------------------------------------------------------------

    def _put_row_filter(
        self, name: str, spec: dict[str, Any], existing: ExtSyncObject | None
    ) -> str:
        role_name = str(spec.get("role", ""))
        role_id = self._external_id("role", role_name, "role")
        params = [
            ParamSpec(
                str(p["name"]),
                str(p["type"]),
                bool(p.get("required", True)),
                p.get("maxSize"),
            )
            for p in spec.get("params") or []
        ]
        self._s.execute(delete(ExtRowFilterPolicy).where(ExtRowFilterPolicy.role_id == role_id))
        for f in spec.get("filters") or []:
            resource = self._resource_for(str(f["datasource"]), str(f["database"]), str(f["table"]))
            datasource = self._s.get(Datasource, resource.datasource_id)
            dialect = dialect_for(datasource.type if datasource else "")
            try:
                compile_template(str(f["where"]), params, dialect=dialect)
            except Exception as error:
                reason = getattr(error, "reason", "row_filter_template_invalid")
                raise ExtSyncError(
                    422, f"row filter on {resource.path} rejected: {reason}"
                ) from error
            self._s.add(
                ExtRowFilterPolicy(
                    role_id=role_id,
                    resource_id=resource.id,
                    where_text=str(f["where"]),
                    params_json=json.dumps(
                        [
                            {
                                "name": p.name,
                                "type": p.type,
                                "required": p.required,
                                "maxSize": p.max_size,
                            }
                            for p in params
                        ]
                    ),
                )
            )
        self._s.flush()
        return existing.external_id if existing and existing.external_id else name

    def _delete_row_filter(self, name: str, existing: ExtSyncObject) -> None:
        try:
            spec = json.loads(existing.spec_json)
            role = self._find("role", str(spec.get("role", "")))
        except ValueError:
            return
        if role is not None and role.external_id:
            self._s.execute(
                delete(ExtRowFilterPolicy).where(ExtRowFilterPolicy.role_id == role.external_id)
            )

    # ---- user -----------------------------------------------------------------------------

    def _put_user(self, name: str, spec: dict[str, Any], existing: ExtSyncObject | None) -> str:
        role_id = self._external_id("role", str(spec.get("role", "")), "role")
        user = self._s.execute(select(User).where(User.external_ref == name)).scalar_one_or_none()
        if user is None:
            display = str(spec.get("principalName") or name)[:MAX_IDENT]  # cosmetic: users.name
            user = User(name=display, external_ref=name)
            self._s.add(user)
        elif user.status != "active":
            # a deleted (disabled) grant stays dead until the tombstone is lifted explicitly
            raise ExtSyncError(409, "user_revoked")
        user.status = "active"
        self._s.flush()
        self._s.execute(delete(UserRole).where(UserRole.user_id == user.id))
        self._s.add(UserRole(user_id=user.id, role_id=role_id))
        attribute = self._s.get(ExtUserAttribute, user.id)
        params = json.dumps(spec.get("params") or {}, separators=(",", ":"), sort_keys=True)
        limits = json.dumps(spec.get("limits") or {}, separators=(",", ":"), sort_keys=True)
        if attribute is None:
            self._s.add(ExtUserAttribute(user_id=user.id, params_json=params, limits_json=limits))
        else:
            attribute.params_json = params
            attribute.limits_json = limits
        self._s.flush()
        return user.id

    def _delete_user(self, name: str, existing: ExtSyncObject) -> None:
        user = self._s.execute(select(User).where(User.external_ref == name)).scalar_one_or_none()
        if user is None:
            return
        self._s.execute(delete(UserRole).where(UserRole.user_id == user.id))
        self._s.execute(delete(ExtUserAttribute).where(ExtUserAttribute.user_id == user.id))
        user.status = "disabled"
        for key in self._s.execute(select(ApiKey).where(ApiKey.user_id == user.id)).scalars():
            key.status = "revoked"

    # ---- credential -----------------------------------------------------------------------

    def _put_credential(
        self, name: str, spec: dict[str, Any], existing: ExtSyncObject | None
    ) -> str:
        user_name = str(spec.get("user", ""))
        user_id = self._external_id("user", user_name, "user")
        key_hash = str(spec.get("keyHash", ""))
        expires_at = _ms(spec.get("expiresAt"))
        record = (
            self._s.get(ApiKey, existing.external_id) if existing and existing.external_id else None
        )
        if record is not None and record.status != "active":
            # revoked (credential or user deleted, or revoked on the executor): never revive it
            raise ExtSyncError(409, "credential_revoked")
        clash = self._s.execute(
            select(ApiKey).where(ApiKey.key_hash == key_hash)
        ).scalar_one_or_none()
        if clash is not None and (record is None or clash.id != record.id):
            # the hash belongs to another key; a revoked one is the replay of a revoked credential
            raise ExtSyncError(
                409, "credential_revoked" if clash.status != "active" else "key_hash_conflict"
            )
        try:
            if record is None:
                record, _ = create_api_key(
                    self._s,
                    name=name,
                    scopes=["runtime"],
                    expires_at=expires_at,
                    user_id=user_id,
                    key_hash=key_hash,
                )
            else:
                if len(key_hash) != 64:
                    raise ValueError("key_hash must be a SHA-256 hex digest")
                record.key_hash = key_hash
                record.user_id = user_id
                record.status = "active"
                record.expires_at = expires_at
        except ValueError as error:
            raise ExtSyncError(422, str(error)) from error
        except IntegrityError as error:  # lost a race on the unique key hash
            raise ExtSyncError(409, "key_hash_conflict") from error
        self._s.flush()
        return record.id

    def _delete_credential(self, name: str, existing: ExtSyncObject) -> None:
        record = self._s.get(ApiKey, existing.external_id) if existing.external_id else None
        if record is not None:
            record.status = "revoked"
