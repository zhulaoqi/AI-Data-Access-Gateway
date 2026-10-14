"""Per-request view of the synced configuration that applies to one identity."""

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

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


def load(session: Session, *, user_id: str | None, role_ids: Iterable[str]) -> ExtContext:
    roles = list(role_ids)
    ctx = ExtContext(role_ids=roles)
    if not roles:
        return ctx
    for row in session.execute(
        select(ExtRoleTable).where(ExtRoleTable.role_id.in_(roles))
    ).scalars():
        ctx.scopes.setdefault(row.resource_id, []).append(
            TableScope(
                role_id=row.role_id,
                resource_id=row.resource_id,
                allow=frozenset(_loads(row.allow_json, [])),
                deny=frozenset(_loads(row.deny_json, [])),
                mask=dict(_loads(row.mask_json, {})),
            )
        )
    for rf in session.execute(
        select(ExtRowFilterPolicy).where(ExtRowFilterPolicy.role_id.in_(roles))
    ).scalars():
        params = tuple(
            ParamSpec(p["name"], p["type"], bool(p.get("required", True)), p.get("maxSize"))
            for p in _loads(rf.params_json, [])
        )
        ctx.row_filters.setdefault(rf.resource_id, []).append(
            RowFilterSpec(rf.role_id, rf.resource_id, rf.where_text, params)
        )
    specs = list(
        session.execute(select(ExtRoleSpec).where(ExtRoleSpec.role_id.in_(roles))).scalars()
    )
    if specs:
        ctx.has_role_spec = True
        deny_functions: set[str] = set()
        deny_syntax: set[str] = set()
        days: list[int] = []
        # With several roles the strictest numeric limit wins; deny lists are unioned.
        limits = dict(DEFAULT_LIMITS)
        first = True
        for spec in specs:
            ops = _loads(spec.operations_json, {})
            deny_functions |= {str(f).lower() for f in ops.get("denyFunctions") or []}
            deny_syntax |= {str(f).lower() for f in ops.get("denySyntax") or []}
            if ops.get("requireTimeRangeDays"):
                days.append(int(ops["requireTimeRangeDays"]))
            lim = _loads(spec.limits_json, {})
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
    return ctx
