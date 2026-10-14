"""Materializes the management service's objects (``/admin/ext/sync``) into ADG's native model.

Contract: ``sql-gateway/api/executor-admin.md``. Every object is addressed by a ``gw:``-prefixed
name; PUT/DELETE are idempotent and the hash it was synced at is kept so the management service
can reconcile. Object types map to ADG as: datasource_account -> Datasource (+ metadata scan),
role -> Role + resource policies + masking policies + ``ext_role_*`` rows, row_filter ->
``ext_row_filter_policies``, user -> User + user role + ``ext_user_attributes``, credential ->
ApiKey (``runtime`` scope, externally supplied SHA-256 hash).
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

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
    ExtRoleSpec,
    ExtRoleTable,
    ExtRowFilterPolicy,
    ExtSyncObject,
    ExtUserAttribute,
)
from adg_ext.params import ParamSpec
from adg_ext.rowfilter import compile_template

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
MAX_NAME = 256


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
        return external_id

    def delete(self, object_type: str, name: str) -> None:
        self._check(object_type, name)
        existing = self._find(object_type, name)
        if existing is None:
            return
        getattr(self, f"_delete_{object_type}")(name, existing)
        self._s.delete(existing)
        self._s.flush()

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
            raise ExtSyncError(400, "object names must start with gw:")

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
        if not config["host"] or not config["username"]:
            raise ExtSyncError(422, "host and username are required")
        service = DatasourceService(self._s)
        datasource = self._datasource_for(existing)
        if datasource is None:
            datasource = service.create_datasource(
                name=name,
                connector_type=connector_type,
                config=config,
                description=str(spec.get("label") or ""),
            )
        else:
            service.update_datasource(
                datasource_id=datasource.id,
                name=name,
                description=str(spec.get("label") or ""),
                description_provided=True,
                status="active",
                config=config,
            )
            datasource.type = connector_type
        self._s.flush()
        try:
            connector = self._registry.create(connector_type)
            snapshot = connector.scan_metadata(datasource.config())
            MetadataScanService(self._s).replace_snapshot(datasource=datasource, snapshot=snapshot)
        except (ConnectorDependencyError, ConnectorOperationError) as error:
            raise ExtSyncError(409, f"cannot scan datasource {name}: {error}") from error
        return datasource.id

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
            role = Role(name=name, description=str(spec.get("profileName") or ""), status="active")
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
            user = User(name=str(spec.get("principalName") or name), external_ref=name)
            self._s.add(user)
        user.status = "active"
        self._s.flush()
        self._s.execute(delete(UserRole).where(UserRole.user_id == user.id))
        self._s.add(UserRole(user_id=user.id, role_id=role_id))
        attribute = self._s.get(ExtUserAttribute, user.id)
        params = json.dumps(spec.get("params") or {}, separators=(",", ":"), sort_keys=True)
        if attribute is None:
            self._s.add(ExtUserAttribute(user_id=user.id, params_json=params))
        else:
            attribute.params_json = params
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
        self._s.flush()
        return record.id

    def _delete_credential(self, name: str, existing: ExtSyncObject) -> None:
        record = self._s.get(ApiKey, existing.external_id) if existing.external_id else None
        if record is not None:
            record.status = "revoked"
