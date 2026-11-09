"""Redis copies of hot authorization and catalog reads.

Callers read through :func:`remember`. A committed change calls :func:`refresh`, which
loads the new rows and replaces the key in place before the write returns. The key
has no expiry: a timer would make the next query miss, and a miss that finishes late
could write older rows over the snapshot just published by a sync.

Each key has a monotonic version. A refresh publishes only when its version is not
older than the one already stored, so a slow read cannot put stale rows back. A
failed reload drops the key only when nothing newer has been published, and the next
read fills it from the database. Redis errors never fail the request.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.governance import FieldPolicy, ResourcePolicy, ResourceTag, Tag
from adg.control_plane.models.resource import Resource, ResourceField
from adg_ext.redis_share import get_client

logger = logging.getLogger(__name__)

PREFIX = "{sqlgw}:hot:"
_VERSION_PREFIX = "{sqlgw}:hotver:"
_SEQUENCE_PREFIX = "{sqlgw}:hotseq:"
_TABLE_KINDS = frozenset({"relational_table", "relational_view"})
_TIME_MARKERS = ("date", "time")

# Publish when this version is at least the stored one. Never expires.
_PUBLISH = """-- hot-publish
local incoming = tonumber(ARGV[1])
local current = redis.call('GET', KEYS[2])
if current and tonumber(current) > incoming then
  return 0
end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], ARGV[1])
return 1
"""

# A miss may fill only while nobody has published. It must not cover a sync snapshot.
_FILL = """-- hot-fill
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 0
end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], ARGV[1])
return 1
"""

# Drop a snapshot only when a newer publish has not already replaced it.
_DROP = """-- hot-drop
local current = redis.call('GET', KEYS[2])
if current and tonumber(current) > tonumber(ARGV[1]) then
  return 0
end
redis.call('DEL', KEYS[1], KEYS[2])
return 1
"""

# A payload that cannot be read is not a snapshot. Remove it so the next fill can store one.
_DROP_BROKEN = """-- hot-drop-broken
redis.call('DEL', KEYS[1], KEYS[2])
return 1
"""


def read_cached(key: str) -> Any | None:
    """Return the stored copy, or ``None`` when there is nothing to patch.

    Unlike :func:`remember`, a miss does not load from the database.
    """

    found = _read(key)
    if found is _MISS:
        return None
    return found


def remember(key: str, load: Callable[[], Any]) -> Any:
    """Return the cached JSON value, or load it and store the copy if still absent."""

    found = _read(key)
    if found is not _MISS:
        return found
    value = load()
    _fill(key, value)
    return value


def refresh(key: str, load: Callable[[], Any]) -> None:
    """Replace the cached copy with a fresh load. Never raises and never expires the key."""

    version = _next_version(key)
    loaded = _try_load(load)
    if loaded is _MISS:
        logger.warning("event=hot_cache_refresh_load_failed key=%s", key)
        _drop(key, version)
        return
    if _publish(key, version, loaded) == "error":
        _drop(key, version)


def _data_key(key: str) -> str:
    return PREFIX + key


def _version_key(key: str) -> str:
    return _VERSION_PREFIX + key


def _sequence_key(key: str) -> str:
    return _SEQUENCE_PREFIX + key


def _next_version(key: str) -> int:
    client = get_client()
    if client is None:
        return 0
    try:
        return int(client.incr(_sequence_key(key)))
    except Exception:
        logger.warning("event=hot_cache_version_failed key=%s", key, exc_info=True)
        return 0


def _try_load(load: Callable[[], Any]) -> Any:
    try:
        return load()
    except Exception:
        logger.warning("event=hot_cache_load_failed", exc_info=True)
        return _MISS


def _read(key: str) -> Any:
    client = get_client()
    if client is None:
        return _MISS
    try:
        raw = client.get(_data_key(key))
    except Exception:
        logger.warning("event=hot_cache_read_failed key=%s", key, exc_info=True)
        return _MISS
    if raw is None:
        return _MISS
    try:
        payload = json.loads(raw)
    except ValueError:
        logger.warning("event=hot_cache_payload_invalid key=%s", key)
        _eval(_DROP_BROKEN, key, 0, None)
        return _MISS
    if not isinstance(payload, dict) or "d" not in payload:
        logger.warning("event=hot_cache_payload_invalid key=%s", key)
        _eval(_DROP_BROKEN, key, 0, None)
        return _MISS
    return payload["d"]


def _fill(key: str, value: Any) -> None:
    """Store a miss fill only while no published version exists."""

    _eval(_FILL, key, 0, value)


def _publish(key: str, version: int, value: Any) -> str:
    """Store this version, or leave a newer one in place. ``error`` when Redis did not answer."""

    if version <= 0:
        return "error"
    result = _eval(_PUBLISH, key, version, value)
    if result is None:
        return "error"
    return "stored" if result == 1 else "older"


def _drop(key: str, version: int) -> None:
    _eval(_DROP, key, version, None)


def _eval(script: str, key: str, version: int, value: Any) -> int | None:
    client = get_client()
    if client is None:
        return 0
    args = [str(version)]
    if value is not None:
        args.append(json.dumps({"v": version, "d": value}, separators=(",", ":")))
    elif script is _DROP:
        args.append("")
    try:
        result = client.eval(script, 2, _data_key(key), _version_key(key), *args)
    except Exception:
        logger.warning("event=hot_cache_write_failed key=%s", key, exc_info=True)
        return None
    return int(result)


class _Miss:
    pass


_MISS = _Miss()


def _policy_row(policy: ResourcePolicy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "subject_type": policy.subject_type,
        "subject_id": policy.subject_id,
        "effect": policy.effect,
        "action": policy.action,
        "datasource_id": policy.datasource_id,
        "resource_id": policy.resource_id,
        "tag_id": policy.tag_id,
        "allow_decrypt": bool(policy.allow_decrypt),
        "status": policy.status,
    }


def _policy_model(row: dict[str, Any]) -> ResourcePolicy:
    return ResourcePolicy(
        id=row["id"],
        subject_type=row["subject_type"],
        subject_id=row["subject_id"],
        effect=row["effect"],
        action=row["action"],
        datasource_id=row.get("datasource_id"),
        resource_id=row.get("resource_id"),
        tag_id=row.get("tag_id"),
        allow_decrypt=bool(row.get("allow_decrypt")),
        status=row.get("status") or "active",
    )


def load_policies(session: Session) -> dict[str, list[ResourcePolicy]]:
    """Active resource policies grouped by action. One read per process lifetime of the caller."""

    def load() -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        rows = session.execute(
            select(ResourcePolicy).where(ResourcePolicy.status == "active")
        ).scalars()
        for policy in rows:
            grouped.setdefault(policy.action, []).append(_policy_row(policy))
        return grouped

    raw = remember("policies", load)
    if not isinstance(raw, dict):
        return {}
    return {
        str(action): [_policy_model(row) for row in rows if isinstance(row, dict)]
        for action, rows in raw.items()
        if isinstance(rows, list)
    }


def bump_visible_epoch() -> None:
    """Drop the generation of cached visible-table lists. The next list rebuilds them."""

    _next_version("visible_epoch")


def visible_epoch() -> int | None:
    """Current visible-list generation. None when Redis cannot be read."""

    client = get_client()
    if client is None:
        return None
    try:
        raw = client.get(_sequence_key("visible_epoch"))
    except Exception:
        logger.warning("event=hot_cache_read_failed key=visible_epoch", exc_info=True)
        return None
    if raw is None:
        return 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def load_visible(
    identity_key: str,
    epoch: int | None,
    load: Callable[[], dict[str, list[dict[str, Any]]]],
) -> dict[str, Any]:
    """Return this identity's visible datasources and tables.

    A Redis miss or a generation change loads from the executor database.
    An older generation cannot replace the list just published for a newer one.
    Redis errors return the freshly loaded rows and do not fail the list.
    """

    key = f"visible:{identity_key}"
    if epoch is not None:
        found = _read(key)
        if (
            isinstance(found, dict)
            and found.get("e") == epoch
            and isinstance(found.get("datasources"), list)
            and isinstance(found.get("resources"), list)
        ):
            return found
    loaded = load()
    stored = {
        "e": 0 if epoch is None else epoch,
        "datasources": loaded["datasources"],
        "resources": loaded["resources"],
    }
    if epoch is None:
        return stored
    if epoch <= 0:
        _fill(key, stored)
    else:
        _publish(key, epoch, stored)
    return stored


def refresh_policies(session: Session, *, visibility: bool = True) -> None:
    """Reload active resource policies after a committed policy change.

    ``visibility=False`` leaves discovery snapshots alone. Sync passes that and then
    refreshes only the datasource it just wrote, instead of every user's full catalog.
    """

    def load() -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        rows = session.execute(
            select(ResourcePolicy).where(ResourcePolicy.status == "active")
        ).scalars()
        for policy in rows:
            grouped.setdefault(policy.action, []).append(_policy_row(policy))
        return grouped

    refresh("policies", load)
    if visibility:
        _refresh_visibility(session)


def _query_datasources(session: Session) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            Datasource.id,
            Datasource.name,
            Datasource.type,
            Datasource.datasource_kind,
            Datasource.description,
            Datasource.status,
        ).order_by(Datasource.name)
    )
    return [
        {
            "id": item.id,
            "name": item.name,
            "type": item.type,
            "datasource_kind": item.datasource_kind,
            "description": item.description,
            "status": item.status,
        }
        for item in rows
    ]


def load_datasource_directory(session: Session) -> list[dict[str, Any]]:
    """Every datasource the discovery tools may name. Refreshed when one is saved."""

    raw = remember("datasources", lambda: _query_datasources(session))
    if not isinstance(raw, list):
        return []
    return [row for row in raw if isinstance(row, dict)]


def refresh_datasources(session: Session, *, visibility: bool = True) -> None:
    """Reload the datasource directory after a committed datasource change.

    Sync has already patched the one datasource's discovery snapshot, so it passes
    ``visibility=False`` and does not walk every other database.
    """

    refresh("datasources", lambda: _query_datasources(session))
    if visibility:
        _refresh_visibility(session)


def _query_tag_catalog(session: Session) -> dict[str, Any]:
    tags = session.execute(select(Tag.id, Tag.name, Tag.category).order_by(Tag.name))
    bindings = session.execute(select(ResourceTag.resource_id, ResourceTag.tag_id))
    by_resource: dict[str, list[str]] = {}
    for resource_id, tag_id in bindings:
        by_resource.setdefault(str(resource_id), []).append(str(tag_id))
    return {
        "tags": [{"id": item.id, "name": item.name, "category": item.category} for item in tags],
        "by_resource": by_resource,
    }


def load_tag_catalog(session: Session) -> dict[str, Any]:
    """Tags and the resources they label. Discovery and tag policies read this copy."""

    raw = remember("tags", lambda: _query_tag_catalog(session))
    if not isinstance(raw, dict):
        return {"tags": [], "by_resource": {}}
    tags = raw.get("tags")
    by_resource = raw.get("by_resource")
    return {
        "tags": [row for row in tags if isinstance(row, dict)] if isinstance(tags, list) else [],
        "by_resource": by_resource if isinstance(by_resource, dict) else {},
    }


def load_tag_bindings(session: Session) -> dict[str, list[str]]:
    """Resource id to tag ids, from the same copy as :func:`load_tag_catalog`."""

    bindings = load_tag_catalog(session)["by_resource"]
    return bindings if isinstance(bindings, dict) else {}


def refresh_tags(session: Session) -> None:
    """Reload tags and their resource bindings after a committed label change."""

    refresh("tags", lambda: _query_tag_catalog(session))
    _refresh_visibility(session)


def _query_table_index(session: Session, datasource_id: str) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            Resource.id,
            Resource.datasource_id,
            Resource.parent_id,
            Resource.kind,
            Resource.name,
            Resource.path,
            Resource.display_name,
            Resource.description,
            Resource.query_language,
            Resource.status,
        ).where(Resource.datasource_id == datasource_id)
    )
    return [
        {
            "id": item.id,
            "datasource_id": item.datasource_id,
            "parent_id": item.parent_id,
            "kind": item.kind,
            "name": item.name,
            "path": item.path,
            "display_name": item.display_name,
            "description": item.description,
            "query_language": item.query_language,
            "status": item.status,
        }
        for item in rows
    ]


def access_rows(
    session: Session, datasource_id: str | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Active tables and views, plus ancestors, both taken from the hot copies.

    The second list is only there so a policy on a schema resolves without reading
    ``resources`` again. Callers return the first list after the policy check.
    """

    active = [
        str(row["id"])
        for row in load_datasource_directory(session)
        if row.get("status") == "active" and row.get("id")
    ]
    if datasource_id is not None:
        active = [datasource_id] if datasource_id in active else []
    tables: list[dict[str, Any]] = []
    extra: dict[str, dict[str, Any]] = {}
    for current_id in active:
        index = load_table_index(session, current_id)
        by_id = {str(row["id"]): row for row in index if row.get("id")}
        local = [
            row
            for row in index
            if row.get("kind") in _TABLE_KINDS and not ancestor_disabled(row, by_id)
        ]
        tables.extend(local)
        seen = {str(row["id"]) for row in local}
        for row in local:
            parent_id = row.get("parent_id")
            while isinstance(parent_id, str) and parent_id not in seen:
                parent = by_id.get(parent_id)
                if parent is None:
                    break
                seen.add(parent_id)
                extra[parent_id] = parent
                parent_id = parent.get("parent_id")
    return tables, list(extra.values())


def load_table_index(session: Session, datasource_id: str) -> list[dict[str, Any]]:
    """Slim rows for every resource of one datasource, used to resolve SQL table names."""

    raw = remember(f"tables:{datasource_id}", lambda: _query_table_index(session, datasource_id))
    if not isinstance(raw, list):
        return []
    return [row for row in raw if isinstance(row, dict)]


def refresh_tables(session: Session, datasource_id: str) -> None:
    """Reload one datasource's resource index after a committed catalog change."""

    refresh(f"tables:{datasource_id}", lambda: _query_table_index(session, datasource_id))


def ancestor_disabled(row: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> bool:
    """True when the row or one of its cached ancestors is not active."""

    current: dict[str, Any] | None = row
    seen: set[str] = set()
    while current is not None and current["id"] not in seen:
        seen.add(str(current["id"]))
        if current.get("status") != "active":
            return True
        parent_id = current.get("parent_id")
        current = by_id.get(parent_id) if isinstance(parent_id, str) else None
    return False


def match_table_paths(
    index: list[dict[str, Any]], resource_paths: list[str]
) -> list[dict[str, Any]]:
    """Resolve each SQL path to the single active table or view it names."""

    by_id = {str(row["id"]): row for row in index if row.get("id")}
    matched: list[dict[str, Any]] = []
    for resource_path in resource_paths:
        if not resource_path:
            continue
        suffix = f".{resource_path}"
        hits = [
            row
            for row in index
            if row.get("kind") in _TABLE_KINDS
            and (row.get("path") == resource_path or str(row.get("path") or "").endswith(suffix))
            and not ancestor_disabled(row, by_id)
        ]
        if len(hits) == 1:
            matched.append(hits[0])
    return matched


def resource_from_index(row: dict[str, Any]) -> Resource:
    """Build a detached resource. Callers only read identity fields and must not flush it."""

    name = str(row.get("name") or "")
    display_name = row.get("display_name")
    description = row.get("description")
    query_language = row.get("query_language")
    return Resource(
        id=str(row["id"]),
        datasource_id=str(row.get("datasource_id") or ""),
        parent_id=row.get("parent_id"),
        kind=str(row.get("kind") or ""),
        name=name,
        path=str(row.get("path") or ""),
        display_name=str(display_name) if isinstance(display_name, str) and display_name else name,
        description=description if isinstance(description, str) else None,
        query_language=query_language if isinstance(query_language, str) else None,
        status=str(row.get("status") or "active"),
        metadata_json="{}",
        scanned_at=datetime.now(UTC),
    )


def time_column_names(session: Session, datasource_id: str, resource_ids: list[str]) -> set[str]:
    """Date and time column names of the given resources. The datasource copy is cached."""

    def load() -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        rows = session.execute(
            select(ResourceField.resource_id, ResourceField.name, ResourceField.data_type).where(
                ResourceField.datasource_id == datasource_id,
                ResourceField.status == "active",
            )
        )
        for resource_id, name, data_type in rows:
            lowered = str(data_type or "").lower()
            if any(marker in lowered for marker in _TIME_MARKERS):
                grouped.setdefault(str(resource_id), []).append(str(name).lower())
        return grouped

    raw = remember(f"timecols:{datasource_id}", load)
    if not isinstance(raw, dict):
        return set()
    names: set[str] = set()
    for resource_id in resource_ids:
        values = raw.get(resource_id)
        if isinstance(values, list):
            names.update(str(name).lower() for name in values)
    return names


def refresh_time_columns(session: Session, datasource_id: str) -> None:
    """Reload cached time-column names after a committed field change."""

    def load() -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        rows = session.execute(
            select(ResourceField.resource_id, ResourceField.name, ResourceField.data_type).where(
                ResourceField.datasource_id == datasource_id,
                ResourceField.status == "active",
            )
        )
        for resource_id, name, data_type in rows:
            lowered = str(data_type or "").lower()
            if any(marker in lowered for marker in _TIME_MARKERS):
                grouped.setdefault(str(resource_id), []).append(str(name).lower())
        return grouped

    refresh(f"timecols:{datasource_id}", load)


def _field_row(policy: FieldPolicy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "subject_type": policy.subject_type,
        "subject_id": policy.subject_id,
        "effect": policy.effect,
        "resource_id": policy.resource_id,
        "field_name": policy.field_name,
        "action": policy.action,
        "status": policy.status,
    }


def _field_model(row: dict[str, Any]) -> FieldPolicy:
    return FieldPolicy(
        id=row["id"],
        subject_type=row["subject_type"],
        subject_id=row["subject_id"],
        effect=row["effect"],
        resource_id=row["resource_id"],
        field_name=row["field_name"],
        action=row.get("action") or "read",
        status=row.get("status") or "active",
    )


def load_field_policies(session: Session, resource_id: str) -> list[FieldPolicy]:
    """Active field policies of one resource."""

    def load() -> list[dict[str, Any]]:
        rows = session.execute(
            select(FieldPolicy).where(
                FieldPolicy.resource_id == resource_id,
                FieldPolicy.status == "active",
            )
        ).scalars()
        return [_field_row(policy) for policy in rows]

    raw = remember(f"fields:{resource_id}", load)
    if not isinstance(raw, list):
        return []
    return [_field_model(row) for row in raw if isinstance(row, dict)]


def refresh_field_policies(session: Session, resource_id: str) -> None:
    """Reload one resource's field policies after a committed change."""

    def load() -> list[dict[str, Any]]:
        rows = session.execute(
            select(FieldPolicy).where(
                FieldPolicy.resource_id == resource_id,
                FieldPolicy.status == "active",
            )
        ).scalars()
        return [_field_row(policy) for policy in rows]

    refresh(f"fields:{resource_id}", load)


def refresh_catalog(session: Session, datasource_id: str) -> None:
    """Reload one datasource's index, then patch discovery snapshots for that datasource only."""

    refresh_tables(session, datasource_id)
    refresh_time_columns(session, datasource_id)
    from adg.visibility_cache import refresh_visibility

    refresh_visibility(session, datasource_id=datasource_id)


def _refresh_visibility(session: Session) -> None:
    """Rebuild the per-user discovery snapshots after a committed catalog or policy change."""

    from adg.visibility_cache import refresh_visibility

    refresh_visibility(session)
