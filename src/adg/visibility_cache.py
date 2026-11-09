"""Per-user discovery snapshots.

List tools read this document. It is rebuilt with the same policy batch the live path
uses, after a committed change to the catalog, policies, tags, or directory. A request
never walks every table to decide what the caller may see. Query execution still checks
the touched tables on the spot.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Collection
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.control_plane.models.directory import Role, User, UserRole
from adg.control_plane.models.resource import Resource
from adg.policy.runtime import IdentityContext, RuntimePolicyService
from adg.runtime_cache import (
    access_rows,
    load_datasource_directory,
    load_tag_catalog,
    read_cached,
    refresh,
    remember,
    resource_from_index,
)
from adg_ext.catalog_notes import NoteIndex
from adg_ext.models import ExtRoleTable

logger = logging.getLogger(__name__)

_GUARD = threading.local()


def refresh_visibility(
    session: Session,
    *,
    user_id: str | None = None,
    role_id: str | None = None,
    datasource_id: str | None = None,
) -> None:
    """Refresh discovery snapshots.

    No scope rebuilds every user from the whole catalog. That is only for an admin
    edit that can change anyone's view. A sync names one user, one role, or one
    datasource and only those tables are checked again.
    """

    if not _redis_ready() or getattr(_GUARD, "on", False):
        return
    if user_id is None and role_id is None and datasource_id is None:
        _refresh_all(session)
        return
    _GUARD.on = True
    try:
        if datasource_id is not None and user_id is None and role_id is None:
            _patch_datasource(session, datasource_id)
            return
        user_ids: set[str] = set()
        if user_id is not None:
            user_ids.add(user_id)
        if role_id is not None:
            user_ids.update(_users_of_role(session, role_id))
        _patch_users(session, user_ids)
    finally:
        _GUARD.on = False


def _refresh_all(session: Session) -> None:
    identities = _identities(session)
    if not identities:
        return
    _GUARD.on = True
    try:
        catalog = _load_catalog(session, None)
        for identity in identities:
            stored = _project(catalog, identity)
            refresh(f"visible:{identity.user_id}", lambda stored=stored: stored)
        logger.info("event=visibility_refreshed users=%s scope=all", len(identities))
    finally:
        _GUARD.on = False


def _patch_datasource(session: Session, datasource_id: str) -> None:
    """Recompute one datasource inside the snapshots of users who already have a table there."""

    user_ids = _users_of_datasources(session, {datasource_id})
    identities = _identities(session, user_ids)
    if not identities:
        logger.info("event=visibility_refreshed users=0 datasource=%s", datasource_id)
        return
    catalog = _load_catalog(session, {datasource_id})
    patched = 0
    for identity in identities:
        if _patch_one(identity, catalog, {datasource_id}, replace=False):
            patched += 1
    logger.info(
        "event=visibility_refreshed users=%s datasource=%s patched=%s",
        len(identities),
        datasource_id,
        patched,
    )


def _patch_users(session: Session, user_ids: set[str]) -> None:
    """Rebuild only the datasources each user's current roles still grant."""

    identities = _identities(session, user_ids)
    patched = 0
    for identity in identities:
        if identity.user_id is None:
            continue
        datasource_ids = _datasources_of_user(session, identity.user_id)
        catalog = _load_catalog(session, datasource_ids)
        if _patch_one(identity, catalog, datasource_ids, replace=True):
            patched += 1
        logger.info(
            "event=visibility_refreshed users=%s patched=%s scope=granted",
            len(identities),
            patched,
        )


def _patch_one(
    identity: IdentityContext,
    catalog: dict[str, Any],
    datasource_ids: set[str],
    *,
    replace: bool,
) -> bool:
    """Merge one datasource slice into an existing snapshot. A missing snapshot is left alone."""

    user_id = identity.user_id
    if user_id is None:
        return False
    previous = read_cached(f"visible:{user_id}")
    if not isinstance(previous, dict) or not isinstance(previous.get("by_datasource"), dict):
        return False
    fresh = _project(catalog, identity)
    merged = merge_visible(previous, fresh, datasource_ids, identity, replace=replace)
    refresh(f"visible:{user_id}", lambda merged=merged: merged)
    return True


def merge_visible(
    previous: dict[str, Any],
    fresh: dict[str, Any],
    datasource_ids: set[str],
    identity: IdentityContext,
    *,
    replace: bool,
) -> dict[str, Any]:
    """Keep every other datasource. Replace only the ones this sync touched."""

    by_datasource = {
        str(key): value
        for key, value in previous.get("by_datasource", {}).items()
        if isinstance(value, list)
    }
    replaced_ids = _resource_ids(by_datasource, datasource_ids)
    if replace:
        by_datasource = {key: rows for key, rows in by_datasource.items() if key in datasource_ids}
    for one_id in datasource_ids:
        rows = fresh.get("by_datasource", {}).get(one_id)
        if isinstance(rows, list) and rows:
            by_datasource[one_id] = rows
        else:
            by_datasource.pop(one_id, None)
    visible_ids = _resource_ids(by_datasource, set())
    tag_names = {
        str(key): value
        for key, value in (previous.get("tag_names") or {}).items()
        if isinstance(value, list) and str(key) in visible_ids and str(key) not in replaced_ids
    }
    for key, value in (fresh.get("tag_names") or {}).items():
        if isinstance(value, list) and str(key) in visible_ids:
            tag_names[str(key)] = value
    used_names = {name for names in tag_names.values() for name in names if isinstance(name, str)}
    seen_tags: set[str] = set()
    tags: list[dict[str, Any]] = []
    for tag in [*(previous.get("tags") or []), *(fresh.get("tags") or [])]:
        if not isinstance(tag, dict) or tag.get("name") not in used_names:
            continue
        tag_id = str(tag.get("id") or "")
        if not tag_id or tag_id in seen_tags:
            continue
        seen_tags.add(tag_id)
        tags.append(tag)
    directory = {
        str(row.get("id")): row
        for row in [*(previous.get("datasources") or []), *(fresh.get("datasources") or [])]
        if isinstance(row, dict) and row.get("id")
    }
    return {
        "roles": sorted(identity.roles),
        "datasources": [directory[key] for key in by_datasource if key in directory],
        "by_datasource": by_datasource,
        "tags": tags,
        "tag_names": tag_names,
    }


def load_visible(session: Session, identity: IdentityContext) -> dict[str, Any] | None:
    """Return the caller's snapshot. ``None`` means the caller should compute it."""

    user_id = identity.user_id
    if user_id is None or not _redis_ready():
        return None
    key = f"visible:{user_id}"
    raw = remember(key, lambda: _project(_load_catalog(session), identity))
    if _matches(raw, identity):
        return raw
    rebuilt = _project(_load_catalog(session), identity)
    refresh(key, lambda: rebuilt)
    return rebuilt


def _redis_ready() -> bool:
    from adg.runtime_cache import get_client

    return get_client() is not None


def _identities(
    session: Session, user_ids: Collection[str] | None = None
) -> list[IdentityContext]:
    """Active users and their active roles. A given id set never loads the other users."""

    if user_ids is not None and not user_ids:
        return []
    stmt = select(User).where(User.status == "active")
    if user_ids is not None:
        stmt = stmt.where(User.id.in_(list(user_ids)))
    users = list(session.execute(stmt).scalars())
    if not users:
        return []
    role_rows = session.execute(
        select(UserRole.user_id, Role.id)
        .join(Role, Role.id == UserRole.role_id)
        .where(
            UserRole.user_id.in_([user.id for user in users]),
            Role.status == "active",
        )
        .order_by(Role.id)
    )
    by_user: dict[str, list[str]] = {user.id: [] for user in users}
    for owner_id, role_id in role_rows:
        by_user[str(owner_id)].append(str(role_id))
    return [
        IdentityContext(user_id=user.id, roles=by_user[user.id], org_node_id=user.org_node_id)
        for user in users
    ]


def _users_of_role(session: Session, role_id: str) -> set[str]:
    rows = session.execute(select(UserRole.user_id).where(UserRole.role_id == role_id)).scalars()
    return {str(row) for row in rows}


def _users_of_datasources(session: Session, datasource_ids: set[str]) -> set[str]:
    if not datasource_ids:
        return set()
    rows = session.execute(
        select(UserRole.user_id)
        .join(ExtRoleTable, ExtRoleTable.role_id == UserRole.role_id)
        .join(Resource, Resource.id == ExtRoleTable.resource_id)
        .where(Resource.datasource_id.in_(datasource_ids))
    ).scalars()
    return {str(row) for row in rows}


def _datasources_of_user(session: Session, user_id: str) -> set[str]:
    rows = session.execute(
        select(Resource.datasource_id)
        .join(ExtRoleTable, ExtRoleTable.resource_id == Resource.id)
        .join(UserRole, UserRole.role_id == ExtRoleTable.role_id)
        .where(UserRole.user_id == user_id)
    ).scalars()
    return {str(row) for row in rows if row}


def _resource_ids(by_datasource: dict[str, list[Any]], only: set[str]) -> set[str]:
    found: set[str] = set()
    for datasource_id, rows in by_datasource.items():
        if only and datasource_id not in only:
            continue
        for row in rows:
            if isinstance(row, dict) and row.get("id"):
                found.add(str(row["id"]))
    return found


def _load_catalog(session: Session, datasource_ids: set[str] | None = None) -> dict[str, Any]:
    """Shared inputs for one snapshot. ``datasource_ids`` limits the tables that are checked."""

    from adg.gateway_runtime.tools import GatewayRuntimeService

    if datasource_ids is None:
        tables, ancestors = access_rows(session)
    else:
        tables = []
        ancestors = []
        for one_id in datasource_ids:
            part_tables, part_ancestors = access_rows(session, one_id)
            tables.extend(part_tables)
            ancestors.extend(part_ancestors)
    catalog = load_tag_catalog(session)
    names_by_id = {
        str(tag["id"]): str(tag["name"])
        for tag in catalog["tags"]
        if tag.get("id") and tag.get("name")
    }
    names_by_resource: dict[str, list[str]] = {}
    for resource_id, tag_ids in catalog["by_resource"].items():
        if not isinstance(tag_ids, list):
            continue
        names_by_resource[str(resource_id)] = [
            names_by_id[str(tag_id)] for tag_id in tag_ids if str(tag_id) in names_by_id
        ]
    return {
        "service": GatewayRuntimeService(session),
        "policy": RuntimePolicyService(session),
        "candidates": [resource_from_index(row) for row in tables],
        "context": [resource_from_index(row) for row in ancestors],
        "notes": NoteIndex.load(
            session,
            {str(row.get("datasource_id")) for row in tables if row.get("datasource_id")},
        ),
        "directory": [
            row
            for row in load_datasource_directory(session)
            if row.get("status") == "active"
            and row.get("id")
            and (datasource_ids is None or str(row.get("id")) in datasource_ids)
        ],
        "tags": catalog["tags"],
        "bindings": catalog["by_resource"],
        "names_by_resource": names_by_resource,
    }


def _project(catalog: dict[str, Any], identity: IdentityContext) -> dict[str, Any]:
    """One user's lists, using the same allow and deny rules as a live check."""

    candidates = catalog["candidates"]
    decisions = catalog["policy"].check_resource_access_batch(
        identity=identity,
        resources=[*candidates, *catalog["context"]],
        action="read",
    )
    visible = [
        resource
        for resource in candidates
        if decisions.get(resource.id) is not None and decisions[resource.id].allowed
    ]
    by_datasource: dict[str, list[dict[str, Any]]] = {}
    visible_ids: set[str] = set()
    for resource in visible:
        visible_ids.add(resource.id)
        by_datasource.setdefault(resource.datasource_id, []).append(
            catalog["service"]._serialize_resource(resource, catalog["notes"])
        )
    visible_tag_ids: set[str] = set()
    for resource_id in visible_ids:
        bound = catalog["bindings"].get(resource_id, [])
        if isinstance(bound, list):
            visible_tag_ids.update(str(tag_id) for tag_id in bound)
    return {
        "roles": sorted(identity.roles),
        "datasources": [
            {
                "id": row["id"],
                "name": row["name"],
                "type": row["type"],
                "datasource_kind": row["datasource_kind"],
                "description": row.get("description"),
            }
            for row in catalog["directory"]
            if row["id"] in by_datasource
        ],
        "by_datasource": by_datasource,
        "tags": [
            {"id": tag["id"], "name": tag["name"], "category": tag.get("category")}
            for tag in catalog["tags"]
            if tag.get("id") in visible_tag_ids
        ],
        "tag_names": {
            resource_id: names
            for resource_id, names in catalog["names_by_resource"].items()
            if resource_id in visible_ids
        },
    }


def _matches(raw: object, identity: IdentityContext) -> bool:
    if not isinstance(raw, dict):
        return False
    return (
        raw.get("roles") == sorted(identity.roles)
        and isinstance(raw.get("datasources"), list)
        and isinstance(raw.get("by_datasource"), dict)
        and isinstance(raw.get("tags"), list)
        and isinstance(raw.get("tag_names"), dict)
    )
