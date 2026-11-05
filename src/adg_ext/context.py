"""Per-request view of the synced configuration that applies to one identity."""

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.runtime_cache import refresh, remember
from adg_ext.guard import Operations
from adg_ext.models import ExtRoleSpec, ExtRoleTable, ExtRowFilterPolicy, ExtUserAttribute
from adg_ext.params import ParamSpec

DEFAULT_LIMITS = {
    "maxConcurrency": 2,
    "queueSize": 10,
    "queueTimeoutSeconds": 30,
    "queryTimeoutSeconds": 60,
    "maxRows": 10000,
}


@dataclass(frozen=True)
class TableScope:
    role_id: str
    resource_id: str
    allow: frozenset[str]
    deny: frozenset[str]
    mask: dict[str, str]

    def permits(self, column: str) -> bool:
        c = column.lower()
        return c in {a.lower() for a in self.allow} and c not in {d.lower() for d in self.deny}


@dataclass(frozen=True)
class RowFilterSpec:
    role_id: str
    resource_id: str
    where: str
    params: tuple[ParamSpec, ...]


@dataclass
class ExtContext:
    """Everything the extension pipeline needs to know about one identity."""

    role_ids: list[str]
    scopes: dict[str, list[TableScope]] = field(default_factory=dict)
    row_filters: dict[str, list[RowFilterSpec]] = field(default_factory=dict)
    operations: Operations = field(default_factory=Operations)
    limits: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_LIMITS))
    user_params: dict[str, Any] = field(default_factory=dict)

    @property
    def managed(self) -> bool:
        """True when any of the identity's roles was synced from the management service."""

        return bool(self.scopes) or self.has_role_spec

    has_role_spec: bool = False

    def permitted_columns(self, resource_id: str) -> list[str]:
        out: set[str] = set()
        for scope in self.scopes.get(resource_id, []):
            out |= {c for c in scope.allow if scope.permits(c)}
        return sorted(out)

    def column_allowed(self, resource_id: str, column: str) -> bool | None:
        """None when no synced role covers the resource; otherwise whether the column is open."""

        scopes = self.scopes.get(resource_id)
        if not scopes:
            return None
        return any(scope.permits(column) for scope in scopes)


def _loads(text: str, default: Any) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return default


def _role_bundle(session: Session, role_id: str) -> dict[str, Any]:
    """Tables, row filters and the spec of one role. Cached; refreshed when the role is synced."""

    raw = remember(f"role:{role_id}", lambda: _role_rows(session, role_id))
    if not isinstance(raw, dict):
        return {"tables": [], "filters": [], "specs": []}
    return raw


def refresh_role(session: Session, role_id: str) -> None:
    """Reload one role's scope after its sync commit."""

    refresh(f"role:{role_id}", lambda: _role_rows(session, role_id))


def _role_rows(session: Session, role_id: str) -> dict[str, Any]:
    tables = session.execute(select(ExtRoleTable).where(ExtRoleTable.role_id == role_id)).scalars()
    filters = session.execute(
        select(ExtRowFilterPolicy).where(ExtRowFilterPolicy.role_id == role_id)
    ).scalars()
    specs = session.execute(select(ExtRoleSpec).where(ExtRoleSpec.role_id == role_id)).scalars()
    return {
        "tables": [
            {
                "resource_id": row.resource_id,
                "allow_json": row.allow_json,
                "deny_json": row.deny_json,
                "mask_json": row.mask_json,
            }
            for row in tables
        ],
        "filters": [
            {
                "resource_id": row.resource_id,
                "where_text": row.where_text,
                "params_json": row.params_json,
            }
            for row in filters
        ],
        "specs": [
            {"operations_json": row.operations_json, "limits_json": row.limits_json}
            for row in specs
        ],
    }


def load(session: Session, *, user_id: str | None, role_ids: Iterable[str]) -> ExtContext:
    roles = list(role_ids)
    ctx = ExtContext(role_ids=roles)
    if not roles:
        return ctx
    table_rows: list[tuple[str, dict[str, Any]]] = []
    filter_rows: list[tuple[str, dict[str, Any]]] = []
    spec_rows: list[dict[str, Any]] = []
    for role_id in roles:
        bundle = _role_bundle(session, role_id)
        for row in bundle.get("tables") or []:
            if isinstance(row, dict):
                table_rows.append((role_id, row))
        for row in bundle.get("filters") or []:
            if isinstance(row, dict):
                filter_rows.append((role_id, row))
        for row in bundle.get("specs") or []:
            if isinstance(row, dict):
                spec_rows.append(row)
    for role_id, row in table_rows:
        ctx.scopes.setdefault(str(row.get("resource_id")), []).append(
            TableScope(
                role_id=role_id,
                resource_id=str(row.get("resource_id")),
                allow=frozenset(_loads(str(row.get("allow_json") or "[]"), [])),
                deny=frozenset(_loads(str(row.get("deny_json") or "[]"), [])),
                mask=dict(_loads(str(row.get("mask_json") or "{}"), {})),
            )
        )
    for role_id, row in filter_rows:
        params = tuple(
            ParamSpec(p["name"], p["type"], bool(p.get("required", True)), p.get("maxSize"))
            for p in _loads(str(row.get("params_json") or "[]"), [])
        )
        resource_id = str(row.get("resource_id"))
        ctx.row_filters.setdefault(resource_id, []).append(
            RowFilterSpec(role_id, resource_id, str(row.get("where_text") or ""), params)
        )
    specs = spec_rows
    if specs:
        ctx.has_role_spec = True
        deny_functions: set[str] = set()
        deny_syntax: set[str] = set()
        days: list[int] = []
        # With several roles the strictest numeric limit wins; deny lists are unioned.
        limits = dict(DEFAULT_LIMITS)
        first = True
        for spec in specs:
            ops = _loads(str(spec.get("operations_json") or "{}"), {})
            deny_functions |= {str(f).lower() for f in ops.get("denyFunctions") or []}
            deny_syntax |= {str(f).lower() for f in ops.get("denySyntax") or []}
            if ops.get("requireTimeRangeDays"):
                days.append(int(ops["requireTimeRangeDays"]))
            lim = _loads(str(spec.get("limits_json") or "{}"), {})
            for key in DEFAULT_LIMITS:
                if lim.get(key) is not None:
                    value = int(lim[key])
                    limits[key] = value if first else min(limits[key], value)
            first = False
        ctx.operations = Operations(
            deny_functions=frozenset(deny_functions),
            deny_syntax=frozenset(deny_syntax),
            require_time_range_days=min(days) if days else None,
        )
        ctx.limits = limits
    if user_id:
        attr = session.get(ExtUserAttribute, user_id)
        if attr is not None:
            ctx.user_params = dict(_loads(attr.params_json, {}))
            user_limits = _loads(attr.limits_json, {})
            if isinstance(user_limits, dict):
                for key in DEFAULT_LIMITS:
                    if user_limits.get(key) is not None:
                        ctx.limits[key] = min(ctx.limits[key], int(user_limits[key]))
    return ctx
