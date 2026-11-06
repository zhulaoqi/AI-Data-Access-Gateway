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

from adg.control_plane.models.governance import FieldPolicy, ResourcePolicy
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


def refresh_policies(session: Session) -> None:
    """Reload active resource policies after a committed policy change."""

    def load() -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        rows = session.execute(
            select(ResourcePolicy).where(ResourcePolicy.status == "active")
        ).scalars()
        for policy in rows:
            grouped.setdefault(policy.action, []).append(_policy_row(policy))
        return grouped

    refresh("policies", load)


def _query_table_index(session: Session, datasource_id: str) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            Resource.id,
            Resource.datasource_id,
            Resource.parent_id,
            Resource.kind,
            Resource.name,
            Resource.path,
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
            "status": item.status,
        }
        for item in rows
    ]


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
    return Resource(
        id=str(row["id"]),
        datasource_id=str(row.get("datasource_id") or ""),
        parent_id=row.get("parent_id"),
        kind=str(row.get("kind") or ""),
        name=name,
        path=str(row.get("path") or ""),
        display_name=name,
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
    """Reload the table index and time-column names of one datasource."""

    refresh_tables(session, datasource_id)
    refresh_time_columns(session, datasource_id)
