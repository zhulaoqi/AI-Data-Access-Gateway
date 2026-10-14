"""The pure decision core shared by the live pipeline and the dry-run API.

Given the guard verdict and a description of the tables a request touches (their column scope,
masks and row filter), it decides whether the statement may run and produces the SQL that
may be sent. It never touches a database, which is what makes it testable from a role spec alone.
"""

from dataclasses import dataclass, field
from typing import cast

import sqlglot
from sqlglot import exp

from adg_ext.errors import ExtRejection
from adg_ext.guard import GuardVerdict
from adg_ext.params import ParamSpec
from adg_ext.rowfilter import Binding, FilterTemplate, compile_template, inject, render, verify


@dataclass
class FilterDef:
    where: str
    params: tuple[ParamSpec, ...]


@dataclass
class TableView:
    """One table a statement may reference, with the synced restrictions that apply to it."""

    path: str
    resource_id: str | None = None
    # None = no synced role restricts this table (only upstream policies apply)
    restricted: bool = False
    columns: frozenset[str] | None = None  # every column that exists (lowercase); None = unknown
    allow: frozenset[str] = frozenset()
    deny: frozenset[str] = frozenset()
    mask: dict[str, str] = field(default_factory=dict)
    # one entry per role covering the table; None inside = that role has no row filter
    filters: list[FilterDef | None] = field(default_factory=list)

    def matches(self, db: str | None, name: str) -> bool:
        path = self.path.lower()
        name = name.lower()
        if db:
            key = f"{db.lower()}.{name}"
            return path == key or path.endswith("." + key)
        return path == name or path.endswith("." + name)

    def permits(self, column: str) -> bool:
        c = column.lower()
        return c in {a.lower() for a in self.allow} and c not in {d.lower() for d in self.deny}

    def has_column(self, column: str) -> bool:
        return self.columns is None or column.lower() in self.columns

    def permitted_columns(self) -> list[str]:
        return sorted(c for c in self.allow if self.permits(c))


@dataclass
class Rewrite:
    sql: str | None = None
    reasons: list[str] = field(default_factory=list)
    hint: dict[str, object] = field(default_factory=dict)
    limit: int | None = None

    @property
    def allowed(self) -> bool:
        return not self.reasons and self.sql is not None


def _wildcards(tree: exp.Expression) -> bool:
    for select in tree.find_all(exp.Select):
        for projection in select.expressions:
            if isinstance(projection, exp.Star):
                return True
            if isinstance(projection, exp.Column) and isinstance(projection.this, exp.Star):
                return True
            if isinstance(projection, exp.Alias) and isinstance(projection.this, exp.Star):
                return True
    return any(True for _ in tree.find_all(exp.Columns))


def _top_selects(tree: exp.Expression) -> list[exp.Select]:
    """The selects whose projections become the visible result (the root and UNION branches)."""

    if isinstance(tree, exp.Select):
        return [tree]
    if isinstance(tree, exp.SetOperation):
        out: list[exp.Select] = []
        for side in (tree.this, tree.args.get("expression")):
            if isinstance(side, exp.Expression):
                out.extend(_top_selects(side))
        return out
    return []


def _masked_misuse(tree: exp.Expression, masked: set[str]) -> str | None:
    """Masked columns may only be plain top-level projections (elsewhere they can be probed)."""

    if not masked:
        return None
    allowed: set[int] = set()
    for select in _top_selects(tree):
        for projection in select.expressions:
            node = projection.this if isinstance(projection, exp.Alias) else projection
            if isinstance(node, exp.Column):
                allowed.add(id(node))
    for column in tree.find_all(exp.Column):
        if column.name.lower() in masked and id(column) not in allowed:
            return column.name
    return None


def _predicate(view: TableView, params: dict[str, object], dialect: str | None) -> Binding | None:
    """The row predicate for a table, or None when it is unrestricted."""

    if not view.restricted or not view.filters or any(f is None for f in view.filters):
        return None
    predicates: list[exp.Expression] = []
    for definition in view.filters:
        assert definition is not None
        template: FilterTemplate = compile_template(
            definition.where, definition.params, dialect=dialect
        )
        predicates.append(render(template, params))
    combined = predicates[0]
    for extra in predicates[1:]:
        combined = exp.Or(this=exp.Paren(this=combined), expression=exp.Paren(this=extra))
    return Binding((combined,))


def rewrite(
    verdict: GuardVerdict,
    views: list[TableView],
    *,
    dialect: str | None,
    user_params: dict[str, object],
) -> Rewrite:
    """Apply column scope, masking-position and row-filter rules to an allowed guard verdict."""

    out = Rewrite()
    normalized = verdict.result.normalized_sql
    restricted = [v for v in views if v.restricted]
    if not verdict.allowed or normalized is None:
        out.reasons = list(verdict.reasons) or ["sql_rejected"]
        if restricted and any(r.startswith("wildcard") for r in out.reasons):
            out.hint["allowed_columns"] = {v.path: v.permitted_columns() for v in restricted}
        return out
    tree = cast(exp.Expression, sqlglot.parse_one(normalized, read=dialect))

    if restricted and _wildcards(tree):
        out.reasons.append("wildcard_projection_not_allowed")
        out.hint["allowed_columns"] = {v.path: v.permitted_columns() for v in restricted}
        return out

    for name in dict.fromkeys(verdict.result.accessed_fields):
        for view in restricted:
            if view.has_column(name) and not view.permits(name):
                out.reasons.append(f"column_not_allowed:{name}")
                out.hint["allowed_columns"] = {v.path: v.permitted_columns() for v in restricted}
                return out

    masked = {c.lower() for v in restricted for c in v.mask}
    misuse = _masked_misuse(tree, masked)
    if misuse is not None:
        out.reasons.append(f"masked_column_position_not_allowed:{misuse}")
        out.hint["masked_columns"] = sorted(masked)
        return out

    def lookup(db: str | None, name: str) -> Binding | None:
        found = [v for v in views if v.matches(db, name)]
        if len(found) != 1:
            raise ExtRejection("table_not_accessible")
        return _predicate(found[0], user_params, dialect)

    try:
        rewritten = inject(tree, lookup, dialect=dialect)
        final = rewritten.sql(dialect=dialect)
        verify(final, lookup, dialect=dialect)
    except ExtRejection as error:
        out.reasons.append(error.reason + (f":{error.detail}" if error.detail else ""))
        return out
    out.sql = final
    limit = rewritten.args.get("limit")
    if isinstance(limit, exp.Limit) and isinstance(limit.expression, exp.Literal):
        try:
            out.limit = int(limit.expression.this)
        except ValueError:
            out.limit = None
    return out
