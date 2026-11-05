"""Short-lived Redis copies of hot authorization and catalog reads.

A query used to repeat the same control-plane reads once per granted table. Callers
read through :func:`remember`. After a commit that changes the underlying rows, the
writer calls :func:`refresh`, which drops the key and loads the new value back in
before returning, so the next query does not pay for a cold read.

Redis is optional. A miss, a broken payload, or any Redis error loads from the
database and the request still succeeds. A failed refresh deletes the key again so
a later read cannot keep serving the previous copy; the backstop TTL does the same
when a delete itself fails.
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
# Safety net when a writer forgets to refresh. Writers still reload immediately.
TTL_SECONDS = 120
_TABLE_KINDS = frozenset({"relational_table", "relational_view"})
_TIME_MARKERS = ("date", "time")


def remember(key: str, load: Callable[[], Any]) -> Any:
    """Return the cached JSON value, or load it and store the copy."""

    found = _read(key)
    if found is not _MISS:
        return found
    value = load()
    _write(key, value)
    return value


def refresh(key: str, load: Callable[[], Any]) -> None:
    """Drop the cached copy and store a fresh one. Never raises."""

    _delete(key)
    try:
        value = load()
    except Exception:
        logger.warning("event=hot_cache_refresh_load_failed key=%s", key, exc_info=True)
        _delete(key)
        return
    if not _write(key, value):
        _delete(key)


def _read(key: str) -> Any:
    client = get_client()
    if client is None:
        return _MISS
    try:
        raw = client.get(PREFIX + key)
    except Exception:
        logger.warning("event=hot_cache_read_failed key=%s", key, exc_info=True)
        return _MISS
    if raw is None:
        return _MISS
    try:
        return json.loads(raw)
    except ValueError:
        logger.warning("event=hot_cache_payload_invalid key=%s", key)
        _delete(key)
        return _MISS


def _write(key: str, value: Any) -> bool:
    client = get_client()
    if client is None:
        return False
    try:
        client.set(PREFIX + key, json.dumps(value, separators=(",", ":")), ex=TTL_SECONDS)
        return True
    except Exception:
        logger.warning("event=hot_cache_write_failed key=%s", key, exc_info=True)
        return False


def _delete(key: str) -> None:
    client = get_client()
    if client is None:
        return
    try:
        client.delete(PREFIX + key)
    except Exception:
        logger.warning("event=hot_cache_delete_failed key=%s", key, exc_info=True)


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
