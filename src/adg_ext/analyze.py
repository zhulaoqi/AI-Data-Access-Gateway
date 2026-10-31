"""The pure decision core shared by the live pipeline and the dry-run API.

Given the guard verdict and a description of the tables a request touches (their column scope,
masks and row filter), it decides whether the statement may run and produces the SQL that
may be sent. It never touches a database, which is what makes it testable from a role spec alone.
"""

from dataclasses import dataclass, field
from typing import cast

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import Scope, traverse_scope

from adg_ext.errors import ExtRejection
from adg_ext.guard import SYSTEM_DATABASES, GuardVerdict
from adg_ext.params import ParamSpec
from adg_ext.rowfilter import (
    Binding,
    FilterTemplate,
    compile_template,
    inject,
    predicate_columns,
    render,
    verify,
)


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

    def projection_columns(self) -> list[str]:
        """What a row-filter derived table may project: permitted columns that exist.

        The datasource account only holds column-level ``SELECT`` on the permitted columns, so the
        derived table must name them (``SELECT *`` needs every column). When the catalog is known
        it also drops permitted names that do not exist (a column dropped since the grant was
        written) because naming a missing column would fail every query on the table.
        """

        names = self.permitted_columns()
        if self.columns:
            names = [c for c in names if c.lower() in self.columns]
        return list(dict.fromkeys(names))


@dataclass
class Rewrite:
    sql: str | None = None
    reasons: list[str] = field(default_factory=list)
    hint: dict[str, object] = field(default_factory=dict)
    limit: int | None = None

    @property
    def allowed(self) -> bool:
        return not self.reasons and self.sql is not None


def qualify_session_database(sql: str, database: str, dialect: str | None) -> str:
    """Prefix unqualified physical tables with the client session database.

    The connector connection uses the datasource default database, which is not the database the
    client selected. Already-qualified names, CTE references and ``DUAL`` stay as written. A system
    database name is never used as a prefix. Parse failures leave the text untouched so the guard
    reports them.
    """

    database = database.strip()
    if not database or database.lower() in SYSTEM_DATABASES:
        return sql
    try:
        tree = cast(exp.Expression, sqlglot.parse_one(sql, read=dialect))
    except sqlglot.errors.SqlglotError:
        return sql
    changed = False
    for scope in traverse_scope(tree):
        for table in scope.tables:
            source = scope.sources.get(table.alias_or_name)
            if not isinstance(source, exp.Table) or source.db:
                continue
            if source.name.lower() == "dual":
                continue
            source.set("db", exp.to_identifier(database))
            changed = True
    if not changed:
        return sql
    return tree.sql(dialect=dialect)


def referenced_databases(sql: str, dialect: str | None) -> list[str]:
    """Databases named on physical tables, in first-seen order.

    Unqualified names contribute nothing.
    """

    if not sql or not sql.strip():
        return []
    try:
        tree = cast(exp.Expression, sqlglot.parse_one(sql, read=dialect))
    except sqlglot.errors.SqlglotError:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for scope in traverse_scope(tree):
        for table in scope.tables:
            source = scope.sources.get(table.alias_or_name)
            if not isinstance(source, exp.Table) or not source.db:
                continue
            if source.name.lower() == "dual":
                continue
            name = str(source.db)
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            found.append(name)
    return found


def _projection_star(projection: exp.Expression) -> str | None:
    """``None`` when this is not a star. ``""`` for ``*``. The table name for ``t.*``."""

    node = projection.this if isinstance(projection, exp.Alias) else projection
    if isinstance(node, exp.Star):
        return ""
    if isinstance(node, exp.Column) and isinstance(node.this, exp.Star):
        return node.table or ""
    # 有的 sqlglot 版本把 * 收成 Columns，而不是 Star。
    if isinstance(node, exp.Columns):
        return ""
    text = node.sql().replace("`", "").strip()
    if text == "*":
        return ""
    if text.endswith(".*") and " " not in text:
        return text[:-2].split(".")[-1]
    return None


def _from_tables(select: exp.Select) -> list[tuple[str, str | None, str]]:
    """Base tables of this select only: ``(alias, database, name)``. Subqueries are skipped."""

    nodes: list[exp.Expression] = []
    # sqlglot 的 FROM 参数名有过 from / from_ 两种。
    source = select.args.get("from_") or select.args.get("from")
    if source is not None and isinstance(getattr(source, "this", None), exp.Expression):
        nodes.append(source.this)
    for join in select.args.get("joins") or []:
        this = getattr(join, "this", None)
        if isinstance(this, exp.Expression):
            nodes.append(this)
    out: list[tuple[str, str | None, str]] = []
    for node in nodes:
        if isinstance(node, exp.Table):
            out.append((node.alias or node.name, node.db or None, node.name))
    if out:
        return out
    for table in select.find_all(exp.Table):
        parent = table.parent
        while parent is not None and not isinstance(parent, exp.Select):
            parent = parent.parent
        if parent is select:
            out.append((table.alias or table.name, table.db or None, table.name))
    return out


def _plain_ident(name: str) -> bool:
    return bool(name) and name.replace("_", "a").isalnum() and not name[0].isdigit()


def _output_names(expr: exp.Expression) -> list[str] | None:
    """Result column names of a select or union, after inner stars have been expanded.

    Names must be unique plain identifiers. An expression without an alias has no stable name,
    so a star over it is refused instead of guessed.
    """

    if isinstance(expr, exp.SetOperation):
        left = _output_names(expr.this)
        other = expr.expression
        right = _output_names(other) if isinstance(other, exp.Expression) else None
        if left is None or right is None or [n.lower() for n in left] != [n.lower() for n in right]:
            return None
        return left
    if not isinstance(expr, exp.Select):
        return None
    names: list[str] = []
    for projection in expr.expressions:
        if _projection_star(projection) is not None:
            return None
        if isinstance(projection, exp.Alias):
            if not _plain_ident(projection.alias):
                return None
            names.append(projection.alias)
            continue
        if isinstance(projection, exp.Column) and _plain_ident(projection.name):
            names.append(projection.name)
            continue
        return None
    if not names or len({name.lower() for name in names}) != len(names):
        return None
    return names


def _columns_of_source(
    source: object, views: list[TableView], *, allow_physical: bool
) -> list[str] | None:
    """Columns a star over this FROM source may become. ``None`` means it cannot be expanded."""

    if isinstance(source, exp.Table):
        if not allow_physical:
            return None
        found = [v for v in views if v.restricted and v.matches(source.db or None, source.name)]
        if len(found) != 1:
            return None
        columns = found[0].projection_columns()
        return columns or None
    if isinstance(source, Scope) and isinstance(source.expression, exp.Expression):
        return _output_names(source.expression)
    if isinstance(source, exp.Expression):
        return _output_names(source)
    return None


def _expand_wildcards(
    tree: exp.Expression, views: list[TableView], *, allow_physical: bool = True
) -> str | None:
    """Replace ``*`` / ``t.*`` with known columns.

    A star over a real table becomes that table's permitted columns, and only when physical
    stars are allowed. A star over a subquery or CTE becomes the names that source already
    projects, so ``SELECT * FROM (SELECT id, name FROM t) s`` does not ask the database for
    every column. A star that cannot be named exactly is refused.
    """

    # traverse_scope visits inner selects before the statements that read them.
    for scope in traverse_scope(tree):
        select = scope.expression
        if not isinstance(select, exp.Select):
            continue
        if not any(_projection_star(p) is not None for p in select.expressions):
            continue
        sources = list(scope.sources.items())
        expanded: list[exp.Expression] = []
        for projection in select.expressions:
            star = _projection_star(projection)
            if star is None:
                expanded.append(projection)
                continue
            targets = (
                sources
                if star == ""
                else [
                    item
                    for item in sources
                    if item[0].lower() == star.lower()
                    or (
                        isinstance(item[1], exp.Table) and item[1].name.lower() == star.lower()
                    )
                ]
            )
            if not targets:
                return "wildcard_projection_not_allowed"
            qualify = len(sources) > 1
            for alias, source in targets:
                columns = _columns_of_source(source, views, allow_physical=allow_physical)
                if not columns:
                    return "wildcard_projection_not_allowed"
                table = alias if qualify and alias else None
                expanded.extend(exp.column(column, table=table) for column in columns)
        select.set("expressions", expanded)
    for select in tree.find_all(exp.Select):
        if any(_projection_star(projection) is not None for projection in select.expressions):
            return "wildcard_projection_not_allowed"
    return None


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
    # The derived table projects the permitted columns only, and the database account holds
    # column-level grants for exactly those: a predicate that reads any other column could not be
    # evaluated (a database error at best). Refuse it with a precise reason instead of dropping or
    # loosening the filter, and never widen the grant to make it work.
    columns = view.projection_columns()
    if not columns:
        raise ExtRejection("row_filter_no_permitted_columns")
    readable = {c.lower() for c in view.permitted_columns()}
    for predicate in predicates:
        for name in predicate_columns(predicate):
            if name.lower() not in readable:
                raise ExtRejection("row_filter_column_not_permitted", detail=name)
    combined = predicates[0]
    for extra in predicates[1:]:
        combined = exp.Or(this=exp.Paren(this=combined), expression=exp.Paren(this=extra))
    return Binding((combined,), tuple(columns))


def rewrite(
    verdict: GuardVerdict,
    views: list[TableView],
    *,
    dialect: str | None,
    user_params: dict[str, object],
    reject_wildcards: bool = True,
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
    try:
        tree = cast(exp.Expression, sqlglot.parse_one(normalized, read=dialect))
    except sqlglot.errors.SqlglotError:
        # e.g. LIMIT appended after WITH ROLLUP: it cannot be inspected, so it is refused
        out.reasons.append("rewrite_parse_failed")
        return out

    if restricted and _wildcards(tree):
        # 子查询和 CTE 上的 * 总是按已写出的结果列展开。物理表上的 * 仍由 reject_wildcards 决定。
        failure = _expand_wildcards(tree, views, allow_physical=not reject_wildcards)
        if failure is not None or _wildcards(tree):
            out.reasons.append("wildcard_projection_not_allowed")
            out.hint["allowed_columns"] = {v.path: v.permitted_columns() for v in restricted}
            return out

    # Names the statement defines itself (``expr AS name``); they are not physical columns.
    aliases = {a.alias.lower() for a in tree.find_all(exp.Alias) if a.alias}
    unrestricted = [v for v in views if not v.restricted]
    for name in dict.fromkeys(verdict.result.accessed_fields):
        for view in restricted:
            if view.has_column(name) and not view.permits(name):
                out.reasons.append(f"column_not_allowed:{name}")
                out.hint["allowed_columns"] = {v.path: v.permitted_columns() for v in restricted}
                return out
        # Closed column scope: a name no restricted table permits is refused even when the synced
        # catalog does not list it. The catalog is what the datasource account may *see* (ClickHouse
        # only lists columns with a column-level grant) or what existed at the last scan, so a
        # column missing from it must not slip through to the database (and fail there with an
        # engine error instead of a guard rejection, or - for a column added later - be returned).
        if (
            not any(v.permits(name) for v in restricted)
            and name.lower() not in aliases
            and not any(v.has_column(name) for v in unrestricted)
        ):
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
