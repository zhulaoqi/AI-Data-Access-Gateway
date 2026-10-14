"""Dialect-aware SQL guard wrapper (PA-3).

Parses with the datasource's dialect, applies the extra rejections the upstream guard lacks
(``PIVOT``, table functions, ``SETTINGS``/``FORMAT``, ``INTO OUTFILE``, hints, variables, system
databases, ``SHOW``/``SET``/``USE``/``EXPLAIN``/``DESCRIBE``, and the optional time-range
requirement), then defers to the upstream ``SqlGuard`` for the rest. The SQL handed on is always
regenerated from the parsed tree, never the caller's text.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import cast

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope

from adg.sql_guard.guard import SqlGuard, SqlGuardResult

DIALECTS = {
    "mysql": "mysql",
    "doris": "starrocks",
    "starrocks": "starrocks",
    "clickhouse": "clickhouse",
    "postgres": "postgres",
}

SYSTEM_DATABASES = {
    "information_schema",
    "mysql",
    "performance_schema",
    "sys",
    "system",
    "_statistics_",
    "__internal_schema",
    "pg_catalog",
    "pg_toast",
    "information_schema_",
}

_TABLE_FUNCTION_NODES: tuple[type[exp.Expression], ...] = (
    exp.Lateral,
    exp.Unnest,
    exp.Explode,
    exp.JSONTable,
    exp.ReadCSV,
    exp.TableFromRows,
)
_COMMAND_REASONS: dict[type[exp.Expression], str] = {
    exp.Show: "show_not_allowed",
    exp.Set: "set_not_allowed",
    exp.Use: "use_not_allowed",
    exp.Describe: "describe_not_allowed",
    exp.Command: "command_not_allowed",
}


def dialect_for(datasource_type: str) -> str | None:
    """The sqlglot dialect used to parse queries for a datasource connector type."""

    return DIALECTS.get(datasource_type.lower())


@dataclass(frozen=True)
class Operations:
    """The operation limits carried by a role spec."""

    mode: str = "read_only"
    deny_functions: frozenset[str] = frozenset()
    deny_syntax: frozenset[str] = frozenset()
    require_time_range_days: int | None = None


# ``operations.deny_syntax`` tokens a profile may use, and the AST nodes they forbid.
SYNTAX_NODES: dict[str, tuple[type[exp.Expression], ...]] = {
    "union": (exp.SetOperation,),
    "join": (exp.Join,),
    "subquery": (exp.Subquery,),
    "cte": (exp.CTE,),
    "window": (exp.Window,),
    "distinct": (exp.Distinct,),
    "group_by": (exp.Group,),
    "order_by": (exp.Order,),
}


@dataclass(frozen=True)
class GuardVerdict:
    """Result of the extended guard: the upstream result plus extension-level rejections."""

    result: SqlGuardResult
    statement: exp.Expression | None
    reasons: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return not self.reasons and self.result.allowed and self.result.normalized_sql is not None


def _structural_reasons(statement: exp.Expression) -> list[str]:
    reasons: list[str] = []

    def add(reason: str) -> None:
        if reason not in reasons:
            reasons.append(reason)

    for kind, reason in _COMMAND_REASONS.items():
        if isinstance(statement, kind):
            add(reason)
    if not isinstance(statement, exp.Select):
        if not reasons:
            add("statement_not_allowed")
        return reasons
    for node in statement.walk():
        if isinstance(node, exp.Select):
            if node.args.get("settings"):
                add("query_settings_not_allowed")
            if node.args.get("format"):
                add("output_format_not_allowed")
            if node.args.get("into") is not None:
                add("into_outfile_not_allowed")
            if node.args.get("locks"):
                add("locking_read_not_allowed")
        elif isinstance(node, (exp.Pivot,)):
            add("pivot_not_allowed")
        elif isinstance(node, exp.Hint):
            add("hint_not_allowed")
        elif isinstance(node, exp.Limit) and node.args.get("expressions"):
            # ClickHouse `LIMIT n BY col`: the upstream limit rewrite would silently drop `BY`
            add("limit_by_not_allowed")
        elif isinstance(node, (exp.Parameter, exp.SessionParameter, exp.Placeholder)):
            add("variable_not_allowed")
        elif isinstance(node, _TABLE_FUNCTION_NODES):
            add("table_function_not_allowed")
        elif isinstance(node, (exp.IndexTableHint, exp.Partition)):
            add("table_option_not_allowed")
        elif isinstance(node, exp.Table):
            if not isinstance(node.this, exp.Identifier):
                add("table_function_not_allowed")
            if node.args.get("catalog"):
                add("catalog_not_allowed")
            db = node.args.get("db")
            if db is not None and db.name.lower() in SYSTEM_DATABASES:
                add("system_database_not_allowed")
            if node.args.get("pivots"):
                add("pivot_not_allowed")
            alias = node.args.get("alias")
            if alias is not None and alias.args.get("columns"):
                # `file('x', 'CSV')` style table functions parse as a table with a column list
                add("table_function_not_allowed")
        elif isinstance(node, exp.Join) and (node.args.get("kind") or "").upper() == "ARRAY":
            add("array_join_not_allowed")
    return reasons


_FLIPPED = {"GT": "LT", "GTE": "LTE", "LT": "GT", "LTE": "GTE", "EQ": "EQ"}

# ---- time range requirement ---------------------------------------------------------------


def _literal_date(node: exp.Expression) -> date | None:
    if isinstance(node, exp.Cast):
        node = node.this
    if isinstance(node, exp.Literal) and node.is_string:
        text = node.this.strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(text[:19], fmt).replace(tzinfo=UTC).date()
            except ValueError:
                continue
    return None


def _conjuncts(where: exp.Expression | None) -> list[exp.Expression]:
    if where is None:
        return []
    out: list[exp.Expression] = []
    stack = [where.this if isinstance(where, exp.Where) else where]
    while stack:
        node = stack.pop()
        if isinstance(node, exp.And):
            stack.extend([node.this, node.expression])
        elif isinstance(node, exp.Paren):
            stack.append(node.this)
        else:
            out.append(node)
    return out


def _time_range_satisfied(
    statement: exp.Expression, time_columns: set[str], days: int, today: date
) -> bool:
    """True if some scope bounds a date/time column to a window of at most ``days`` days."""

    for scope in traverse_scope(statement):
        select = scope.expression
        if not isinstance(select, exp.Select):
            continue
        lowers: dict[str, date] = {}
        uppers: dict[str, date] = {}
        for node in _conjuncts(select.args.get("where")):
            if isinstance(node, (exp.GT, exp.GTE, exp.LT, exp.LTE, exp.EQ)):
                left, right = node.this, node.expression
                op = type(node).__name__
                if isinstance(left, (exp.Literal, exp.Cast)) and isinstance(right, exp.Column):
                    left, right = right, left
                    op = _FLIPPED[op]
                if isinstance(left, exp.Column) and left.name.lower() in time_columns:
                    value = _literal_date(right)
                    if value is not None:
                        name = left.name.lower()
                        if op in ("GT", "GTE", "EQ"):
                            lowers[name] = max(lowers.get(name, value), value)
                        if op in ("LT", "LTE", "EQ"):
                            uppers[name] = min(uppers.get(name, value), value)
            elif isinstance(node, exp.Between) and isinstance(node.this, exp.Column):
                name = node.this.name.lower()
                low, high = node.args.get("low"), node.args.get("high")
                if name in time_columns and low is not None and high is not None:
                    lo, hi = _literal_date(low), _literal_date(high)
                    if lo is not None and hi is not None:
                        lowers[name], uppers[name] = lo, hi
        for name, lo in lowers.items():
            hi = uppers.get(name)
            if hi is not None:
                if timedelta(0) <= hi - lo <= timedelta(days=days):
                    return True
            elif today - lo <= timedelta(days=days) and lo <= today:
                return True
    return False


# ---- entry point --------------------------------------------------------------------------


def check(
    sql: str,
    *,
    dialect: str | None,
    default_limit: int,
    max_limit: int,
    operations: Operations | None = None,
    time_columns: set[str] | None = None,
    now: datetime | None = None,
) -> GuardVerdict:
    """Validate ``sql`` for ``dialect``; the verdict carries every rejection reason found."""

    guard = SqlGuard(
        default_limit=default_limit,
        max_limit=max_limit,
        execution_mode="read_only",
        strict_validation=True,
        dialect=dialect,
    )
    try:
        statements = [
            cast(exp.Expression, s) for s in sqlglot.parse(sql, read=dialect) if s is not None
        ]
    except sqlglot.errors.SqlglotError:
        raw = guard.check(sql)
        return GuardVerdict(raw, None, list(raw.rejection_reasons) or ["parse_error"])
    if len(statements) != 1:
        raw = guard.check(sql)
        return GuardVerdict(raw, None, list(raw.rejection_reasons) or ["multiple_statements"])
    statement = statements[0]
    # Comments never reach the database (MySQL executes `/*! ... */`); only regenerated SQL does.
    for node in statement.walk():
        node.comments = None
    upstream = guard.check(statement.sql(dialect=dialect))
    reasons = _structural_reasons(statement)
    reasons += [r for r in upstream.rejection_reasons if r not in reasons]
    ops = operations or Operations()
    if ops.deny_functions:
        for func in statement.find_all(exp.Func):
            name = (func.name if isinstance(func, exp.Anonymous) else func.sql_name()).lower()
            if name in ops.deny_functions:
                reasons.append(f"function_not_allowed:{name}")
    for token in sorted(ops.deny_syntax):
        nodes = SYNTAX_NODES.get(token)
        if nodes and any(True for _ in statement.find_all(*nodes)):
            reasons.append(f"syntax_not_allowed:{token}")
    if ops.require_time_range_days and not reasons:
        today = (now or datetime.now(UTC)).date()
        if not _time_range_satisfied(
            statement,
            {c.lower() for c in (time_columns or set())},
            ops.require_time_range_days,
            today,
        ):
            reasons.append("time_range_required")
    return GuardVerdict(upstream, statement, reasons)


_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def is_plain_identifier(name: str) -> bool:
    """Whether ``name`` can be used as an unquoted identifier (used for names we generate)."""

    return bool(_IDENT.fullmatch(name))
