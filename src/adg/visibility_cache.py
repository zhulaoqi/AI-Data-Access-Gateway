"""Per-user discovery snapshots.

List tools read this document. It is rebuilt with the same policy batch the live path
uses, after a committed change to the catalog, policies, tags, or directory. A request
never walks every table to decide what the caller may see. Query execution still checks
the touched tables on the spot.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.control_plane.models.directory import Role, User, UserRole
from adg.policy.runtime import IdentityContext, RuntimePolicyService
from adg.runtime_cache import (
    access_rows,
    load_datasource_directory,
    load_tag_catalog,
    refresh,
    remember,
    resource_from_index,
)
from adg_ext.catalog_notes import NoteIndex

logger = logging.getLogger(__name__)

_GUARD = threading.local()


def refresh_visibility(session: Session) -> None:
    """Replace every active user's discovery snapshot. No-op without Redis."""

    if not _redis_ready() or getattr(_GUARD, "on", False):
        return
    identities = _identities(session)
    if not identities:
        return
    _GUARD.on = True
    try:
        catalog = _load_catalog(session)
        for identity in identities:
            user_id = identity.user_id
            refresh(
                f"visible:{user_id}",
                lambda identity=identity, catalog=catalog: _project(catalog, identity),
            )
        logger.info("event=visibility_refreshed users=%s", len(identities))
    finally:
        _GUARD.on = False


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


def _identities(session: Session) -> list[IdentityContext]:
    """Active users and their active roles, in the same order as request authentication."""

    users = session.execute(select(User).where(User.status == "active")).scalars()
    identities: list[IdentityContext] = []
    for user in users:
        role_ids = list(
            session.execute(
                select(Role.id)
                .join(UserRole, UserRole.role_id == Role.id)
                .where(UserRole.user_id == user.id, Role.status == "active")
                .order_by(Role.id)
            ).scalars()
        )
        identities.append(
            IdentityContext(user_id=user.id, roles=role_ids, org_node_id=user.org_node_id)
        )
    return identities


def _load_catalog(session: Session) -> dict[str, Any]:
    """Shared inputs for every user's snapshot. Policy decisions still differ per user."""

    from adg.gateway_runtime.tools import GatewayRuntimeService

    tables, ancestors = access_rows(session)
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
            if row.get("status") == "active" and row.get("id")
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
