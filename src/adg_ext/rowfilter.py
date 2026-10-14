"""Row-level filter templates, rendering and per-table injection (PA-1).

A template is a predicate over the table's own columns with ``{{param}}`` placeholders, for example
``tenant_id = {{tenant_id}} AND region IN ({{regions}})``. It is parsed (never string-substituted),
checked against a small predicate grammar, rendered with typed literals, and injected by replacing
every physical reference to the table with
``(SELECT <permitted columns> FROM <table> WHERE <predicate>) AS <alias>``.

The derived table lists the grant's *permitted columns* explicitly instead of ``*`` (N-2): the
datasource account only holds column-level ``SELECT``, MySQL refuses ``SELECT *`` for such an
account, and a ``*`` would also be the one place where a column the grant does not cover could
leak into the statement. The columns the predicate itself reads must be permitted columns too
(``Binding.columns`` is checked against them by the caller). The result is verified again before
it may reach a connector; anything uncertain is rejected.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import cast

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope

from adg_ext.errors import ExtRejection
from adg_ext.params import PLACEHOLDER_RE, ParamSpec, placeholders, resolve_values

_PARAM_PREFIX = "__gwp_"
_ALLOWED_NODES: tuple[type[exp.Expression], ...] = (
    exp.And,
    exp.Or,
    exp.Not,
    exp.Paren,
    exp.EQ,
    exp.NEQ,
    exp.GT,
    exp.GTE,
    exp.LT,
    exp.LTE,
    exp.In,
    exp.Between,
    exp.Is,
    exp.Null,
    exp.Boolean,
    exp.Like,
    exp.ILike,
    exp.Column,
    exp.Identifier,
    exp.Literal,
    exp.Tuple,
    exp.Neg,
)


@dataclass(frozen=True)
class FilterTemplate:
    """A validated row-filter predicate with its declared parameters."""

    where: str
    params: dict[str, ParamSpec]
    dialect: str | None

    def parsed(self) -> exp.Expression:
        """The predicate AST with placeholders as ``__gwp_<name>`` columns."""

        text = PLACEHOLDER_RE.sub(lambda m: _PARAM_PREFIX + m.group(1), self.where)
        return cast(exp.Expression, sqlglot.condition(text, dialect=self.dialect))


def compile_template(
    where: str, params: Iterable[ParamSpec], *, dialect: str | None
) -> FilterTemplate:
    """Validate a template against the predicate grammar; raises ``ExtRejection`` if unusable."""

    specs = {p.name: p for p in params}
    template = FilterTemplate(where=where, params=specs, dialect=dialect)
    if not where or not where.strip():
        raise ExtRejection("row_filter_empty")
    if any(token in where for token in (";", "--", "/*", "*/", "\\")):
        raise ExtRejection("row_filter_template_invalid", detail="forbidden token")
    try:
        tree = template.parsed()
    except sqlglot.errors.SqlglotError as error:
        raise ExtRejection(
            "row_filter_template_invalid", detail=error.__class__.__name__
        ) from error
    for node in tree.walk():
        if not isinstance(node, _ALLOWED_NODES):
            raise ExtRejection("row_filter_template_invalid", detail=type(node).__name__)
        if isinstance(node, exp.Column):
            if node.args.get("table") or node.args.get("db") or node.args.get("catalog"):
                raise ExtRejection("row_filter_template_invalid", detail="qualified column")
            if isinstance(node.this, exp.Star):
                raise ExtRejection("row_filter_template_invalid", detail="star")
    needed = placeholders(where)
    for name in needed:
        if name not in specs:
            raise ExtRejection("row_filter_param_undeclared", detail=name)
    # Every parameter has to sit in a value position, not be compared as a column against itself.
    for node in tree.find_all(exp.Column):
        if node.name.startswith(_PARAM_PREFIX):
            parent = node.parent
            if not isinstance(
                parent,
                (
                    exp.EQ,
                    exp.NEQ,
                    exp.GT,
                    exp.GTE,
                    exp.LT,
                    exp.LTE,
                    exp.In,
                    exp.Between,
                    exp.Like,
                    exp.ILike,
                    exp.Paren,
                    exp.Tuple,
                ),
            ):
                raise ExtRejection("row_filter_template_invalid", detail="param position")
    return template


def render(template: FilterTemplate, supplied: dict[str, object]) -> exp.Expression:
    """Substitute typed literals for the placeholders and return the predicate AST."""

    values = resolve_values(template.params, supplied, placeholders(template.where))
    tree = template.parsed()

    def substitute(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.Column) and node.name.startswith(_PARAM_PREFIX):
            return values[node.name.removeprefix(_PARAM_PREFIX)].copy()
        return node

    rendered = cast(exp.Expression, tree.transform(substitute))
    # `col IN ({{list}})` becomes `col IN (1, 2, 3)`: unwrap the tuple a list parameter produced.
    for in_node in list(rendered.find_all(exp.In)):
        items = in_node.expressions
        if len(items) == 1 and isinstance(items[0], exp.Tuple):
            in_node.set("expressions", list(items[0].expressions))
    return rendered


@dataclass(frozen=True)
class Binding:
    """Rendered predicates that apply to one physical table (conjunction).

    ``columns`` are the permitted columns the derived table projects (in this order). ``None``
    keeps the legacy ``SELECT *`` projection (only unit tests that do not model column scope).
    """

    predicates: tuple[exp.Expression, ...]
    columns: tuple[str, ...] | None = None

    def combined(self) -> exp.Expression:
        out = self.predicates[0].copy()
        for extra in self.predicates[1:]:
            out = exp.And(this=exp.Paren(this=out), expression=exp.Paren(this=extra.copy()))
        return out


Lookup = Callable[[str | None, str], Binding | None]


def _physical_tables(statement: exp.Expression) -> list[exp.Table]:
    """Physical table references, resolved through scopes so CTE names and aliases are exact."""

    found: list[exp.Table] = []
    seen: set[int] = set()
    for scope in traverse_scope(statement):
        for table in scope.tables:
            source = scope.sources.get(table.alias_or_name)
            if isinstance(source, exp.Table) and id(table) not in seen:
                seen.add(id(table))
                found.append(table)
    return found


def inject(statement: exp.Expression, lookup: Lookup, *, dialect: str | None) -> exp.Expression:
    """Wrap every filtered physical table in ``statement``; returns a new tree."""

    tree = statement.copy()
    targets: list[tuple[exp.Table, Binding]] = []
    for table in _physical_tables(tree):
        binding = lookup(table.db or None, table.name)
        if binding is not None:
            targets.append((table, binding))
    if not targets:
        return tree
    for column in tree.find_all(exp.Column):
        if column.args.get("db"):
            raise ExtRejection("row_filter_qualified_column_unsupported")
    for table, binding in targets:
        alias = table.alias or table.name
        # ClickHouse's `FINAL` modifies the table reference and must stay on the inner table
        final = table.parent if isinstance(table.parent, exp.Final) else None
        inner_table = table.copy()
        inner_table.set("alias", None)
        inner: exp.Expression = exp.Final(this=inner_table) if final is not None else inner_table
        projection: list[exp.Expression] = (
            [exp.Star()]
            if binding.columns is None
            else [exp.column(exp.to_identifier(c, quoted=True)) for c in binding.columns]
        )
        wrapper = exp.Subquery(
            this=exp.select(*projection).from_(inner).where(binding.combined()),
            alias=exp.TableAlias(this=exp.to_identifier(alias)),
        )
        (final if final is not None else table).replace(wrapper)
    return tree


def _from_of(select: exp.Select) -> exp.Expression | None:
    source = select.args.get("from_") or select.args.get("from")
    return source.this if source is not None else None


def _projection_matches(select: exp.Select, binding: Binding) -> bool:
    """The wrapper projects exactly the permitted columns (or ``*`` for a column-less binding)."""

    if binding.columns is None:
        return len(select.expressions) == 1 and isinstance(select.expressions[0], exp.Star)
    if len(select.expressions) != len(binding.columns):
        return False
    for projection, name in zip(select.expressions, binding.columns, strict=True):
        if not isinstance(projection, exp.Column) or isinstance(projection.this, exp.Star):
            return False
        if projection.args.get("table") or projection.args.get("db"):
            return False
        if projection.name != name:
            return False
    return True


def predicate_columns(predicate: exp.Expression) -> list[str]:
    """Column names a rendered predicate reads (placeholders are already literals), in order."""

    names: list[str] = []
    for column in predicate.find_all(exp.Column):
        if column.name not in names:
            names.append(column.name)
    return names


def verify(sql: str, lookup: Lookup, *, dialect: str | None) -> None:
    """Re-parse the final SQL and prove every filtered table sits inside its filtering wrapper."""

    try:
        tree = sqlglot.parse_one(sql, dialect=dialect)
    except sqlglot.errors.SqlglotError as error:
        raise ExtRejection("row_filter_verification_failed") from error
    for table in _physical_tables(cast(exp.Expression, tree)):
        binding = lookup(table.db or None, table.name)
        if binding is None:
            continue
        node: exp.Expression = table
        if isinstance(table.parent, exp.Final):
            node = table.parent
        holder = node.parent  # From or Join
        select = holder.parent if holder is not None else None
        if not isinstance(select, exp.Select) or _from_of(select) is not node:
            raise ExtRejection("row_filter_verification_failed")
        if not isinstance(select.parent, exp.Subquery):
            raise ExtRejection("row_filter_verification_failed")
        where = select.args.get("where")
        if where is None or where.this.sql(dialect=dialect) != binding.combined().sql(
            dialect=dialect
        ):
            raise ExtRejection("row_filter_verification_failed")
        if not _projection_matches(select, binding):
            raise ExtRejection("row_filter_verification_failed")
        if select.args.get("joins"):
            raise ExtRejection("row_filter_verification_failed")
