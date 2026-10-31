from dataclasses import dataclass, field
from typing import Literal, cast

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope

type SqlExecutionMode = Literal["read_only", "dml", "schema", "admin"]


def is_read_query(statement: exp.Expression) -> bool:
    """A SELECT, or UNION/EXCEPT/INTERSECT made only of SELECTs.

    INTO and row locks are still rejected by the statement checks. They stay selects so a
    CTE can report the specific lock or INTO reason instead of "not a select".
    """

    if isinstance(statement, exp.Select):
        return True
    if isinstance(statement, exp.SetOperation):
        left, right = statement.this, statement.expression
        return (
            isinstance(left, exp.Expression)
            and isinstance(right, exp.Expression)
            and is_read_query(left)
            and is_read_query(right)
        )
    return False


@dataclass(frozen=True)
class ProjectionLineage:
    """Map one result projection to the source fields that feed it."""

    output_name: str | None
    source_fields: tuple[str, ...]
    is_wildcard: bool = False
    has_nested_select: bool = False


@dataclass(frozen=True)
class SqlGuardResult:
    """Structured verdict produced after parsing and normalizing a SQL statement."""

    allowed: bool
    normalized_sql: str | None
    statement_type: str | None
    accessed_resources: list[str] = field(default_factory=list)
    accessed_fields: list[str] = field(default_factory=list)
    projections: list[ProjectionLineage] = field(default_factory=list)
    used_functions: list[str] = field(default_factory=list)
    risk_level: str = "high"
    rejection_reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def projection_lineage(sql: str, dialect: str | None) -> list[ProjectionLineage] | None:
    """Output-to-source mapping of SQL that has already been rewritten.

    Returns None when the SQL cannot be parsed. Callers use this after wildcard expansion and
    row-filter injection so masking follows the columns that will actually be returned.
    """

    try:
        statement = cast(exp.Expression, sqlglot.parse_one(sql, read=dialect))
    except sqlglot.errors.SqlglotError:
        return None
    return SqlGuard(dialect=dialect)._projection_lineage(statement)


class SqlGuard:
    """Configurable SQL allowlist for runtime query execution."""

    _mode_allowed_statement_categories: dict[SqlExecutionMode, set[str]] = {
        "read_only": {"read"},
        "dml": {"read", "dml"},
        "schema": {"read", "dml", "schema"},
        "admin": {"read", "dml", "schema", "admin"},
    }
    _read_only_command_names = {"show"}
    _dml_statement_keys = {"delete", "insert", "merge", "update"}
    _schema_statement_keys = {"alter", "create", "drop", "truncate", "truncatetable"}
    _schema_command_names = {"rename"}
    _admin_statement_keys = {"copy", "grant", "revoke"}
    _admin_command_names = {"call", "set"}
    # Side effects, file access, lock waits, error-based extraction, and account identity.
    # Ordinary scalar, aggregate, and window functions stay available inside the grant.
    _denied_functions = {
        "benchmark",
        "connection_id",
        "current_user",
        "extractvalue",
        "get_lock",
        "is_free_lock",
        "is_used_lock",
        "load_file",
        "master_pos_wait",
        "release_all_locks",
        "release_lock",
        "currentuser",
        "session_user",
        "sleep",
        "source_pos_wait",
        "system_user",
        "updatexml",
        "user",
    }
    _safe_temporal_function_types = (
        exp.CurrentDate,
        exp.CurrentTime,
        exp.CurrentTimestamp,
        exp.Date,
        exp.DateAdd,
        exp.DateDiff,
        exp.DateSub,
        exp.DateTrunc,
        exp.DatetimeAdd,
        exp.DatetimeDiff,
        exp.DatetimeSub,
        exp.DatetimeTrunc,
        exp.Day,
        exp.Hour,
        exp.Minute,
        exp.Month,
        exp.Quarter,
        exp.Second,
        exp.TimeAdd,
        exp.TimeDiff,
        exp.TimeSub,
        exp.TimeTrunc,
        exp.TimestampAdd,
        exp.TimestampDiff,
        exp.TimestampSub,
        exp.TimestampTrunc,
        exp.Week,
        exp.Year,
    )
    _safe_temporal_anonymous_functions = {
        "date_format",
        "from_unixtime",
        "to_date",
        "unix_timestamp",
    }
    _safe_temporal_cast_types = (
        exp.DataType.Type.DATE,
        exp.DataType.Type.DATE32,
        exp.DataType.Type.DATETIME,
        exp.DataType.Type.DATETIME2,
        exp.DataType.Type.DATETIME64,
        exp.DataType.Type.SMALLDATETIME,
        exp.DataType.Type.TIME,
        exp.DataType.Type.TIMETZ,
        exp.DataType.Type.TIME_NS,
        exp.DataType.Type.TIMESTAMP,
        exp.DataType.Type.TIMESTAMPNTZ,
        exp.DataType.Type.TIMESTAMPLTZ,
        exp.DataType.Type.TIMESTAMPTZ,
        exp.DataType.Type.TIMESTAMP_S,
        exp.DataType.Type.TIMESTAMP_MS,
        exp.DataType.Type.TIMESTAMP_NS,
    )

    def __init__(
        self,
        *,
        default_limit: int = 100,
        max_limit: int = 1000,
        execution_mode: SqlExecutionMode = "read_only",
        strict_validation: bool = True,
        reject_wildcards: bool = True,
        dialect: str | None = None,
    ) -> None:
        """Configure statement permissions and strict validation for accepted queries."""

        self._dialect = dialect
        self._default_limit = default_limit
        self._max_limit = max_limit
        self._execution_mode = execution_mode
        self._strict_validation = strict_validation
        self._reject_wildcards = reject_wildcards

    def check(self, sql: str) -> SqlGuardResult:
        """Parse, validate, and normalize a single SQL statement."""

        try:
            statements = [
                cast(exp.Expression, statement)
                for statement in sqlglot.parse(sql, read=self._dialect)
                if statement is not None
            ]
        except sqlglot.errors.SqlglotError as error:
            return SqlGuardResult(
                allowed=False,
                normalized_sql=None,
                statement_type=None,
                rejection_reasons=[f"parse_error:{error.__class__.__name__}"],
            )

        if len(statements) != 1:
            return SqlGuardResult(
                allowed=False,
                normalized_sql=None,
                statement_type=None,
                rejection_reasons=["multiple_statements"],
            )

        statement = statements[0]
        statement_type = statement.key.upper()
        cte_rejection = self._cte_rejection(statement)
        if cte_rejection is not None:
            return SqlGuardResult(
                allowed=False,
                normalized_sql=None,
                statement_type=statement_type,
                accessed_resources=self._accessed_resources(statement),
                accessed_fields=self._accessed_fields(statement),
                projections=self._projection_lineage(statement),
                rejection_reasons=[cte_rejection],
            )
        statement_rejection = self._statement_rejection(statement)
        if statement_rejection is not None:
            return SqlGuardResult(
                allowed=False,
                normalized_sql=None,
                statement_type=statement_type,
                accessed_resources=self._accessed_resources(statement),
                accessed_fields=self._accessed_fields(statement),
                projections=self._projection_lineage(statement),
                rejection_reasons=[statement_rejection],
            )

        if not isinstance(statement, exp.Select) and not is_read_query(statement):
            normalized_sql = statement.sql(dialect=self._dialect)
            return SqlGuardResult(
                allowed=True,
                normalized_sql=normalized_sql,
                statement_type=statement_type,
                accessed_resources=self._accessed_resources(statement),
                accessed_fields=self._accessed_fields(statement),
                risk_level="medium",
            )

        reported_type = "SELECT" if isinstance(statement, exp.Select) else statement.key.upper()
        limit_rejection = self._query_limit_rejection(statement)
        if limit_rejection is not None:
            return SqlGuardResult(
                allowed=False,
                normalized_sql=None,
                statement_type=reported_type,
                accessed_resources=self._accessed_resources(statement),
                accessed_fields=self._accessed_fields(statement),
                projections=self._projection_lineage(statement),
                rejection_reasons=[limit_rejection],
            )

        selects = (
            [statement]
            if isinstance(statement, exp.Select)
            else self._set_leaves(statement)
        )
        used_functions = self._used_functions(statement)
        rejection_reasons: list[str] = []
        for select in selects:
            rejection_reasons.extend(self._projection_rejections(select))
        if self._strict_validation:
            # Deny functions that sleep, read files, take locks, or reveal the database account.
            # Scalar, aggregate, and window functions on granted columns stay available.
            rejection_reasons.extend(
                f"function_not_allowed:{function_name}"
                for function_name in used_functions
                if self._is_denied_function(function_name)
            )
            if self._reject_wildcards and any(
                self._has_wildcard_projection(select) for select in selects
            ):
                rejection_reasons.append("wildcard_projection_not_allowed")
        normalized_sql, warnings = self._with_effective_limit(statement)

        return SqlGuardResult(
            allowed=not rejection_reasons,
            normalized_sql=normalized_sql if not rejection_reasons else None,
            statement_type=reported_type,
            accessed_resources=self._accessed_resources(statement),
            accessed_fields=self._accessed_fields(statement),
            projections=self._projection_lineage(statement),
            used_functions=used_functions,
            risk_level="low" if not rejection_reasons else "high",
            rejection_reasons=rejection_reasons,
            warnings=warnings,
        )

    def _cte_rejection(self, statement: exp.Expression) -> str | None:
        """Reject unsupported CTEs across the complete SQL expression tree."""

        with_clauses = list(statement.find_all(exp.With))
        if not with_clauses:
            return None
        if not is_read_query(statement):
            return "cte_final_statement_not_allowed"
        for with_clause in with_clauses:
            if with_clause.args.get("recursive"):
                return "recursive_cte_not_allowed"
            for cte in with_clause.expressions:
                if not isinstance(cte.this, exp.Expression) or not is_read_query(cte.this):
                    return "cte_non_select_not_allowed"
                bodies = [cte.this] if isinstance(cte.this, exp.SetOperation) else []
                for cte_select in cte.this.find_all(exp.Select):
                    bodies.append(cte_select)
                for cte_select in bodies:
                    limit_rejection = self._limit_rejection(cte_select)
                    if limit_rejection is not None:
                        return limit_rejection
                    cte_limit = self._limit_value(cte_select)
                    if cte_limit is not None and cte_limit > self._max_limit:
                        return "cte_limit_exceeded"
                    if not isinstance(cte_select, exp.Select):
                        continue
                    if cte_select.args.get("locks"):
                        return "cte_locking_read_not_allowed"
                    if cte_select.args.get("into") is not None:
                        return "cte_select_into_not_allowed"
                    if self._reject_wildcards and self._has_wildcard_projection(cte_select):
                        return "cte_wildcard_projection_not_allowed"
        return None

    def _statement_rejection(self, statement: exp.Expression) -> str | None:
        """Return a first-layer statement-type rejection reason, if any."""

        allowed_categories = self._mode_allowed_statement_categories[self._execution_mode]
        selects = (
            list(statement.find_all(exp.Select))
            if isinstance(statement, exp.SetOperation)
            else [statement] if isinstance(statement, exp.Select) else []
        )
        for select in selects:
            if select.args.get("locks"):
                return "locking_read_not_allowed"
            if select.args.get("into") is not None and "schema" not in allowed_categories:
                return "select_into_not_allowed"
        statement_category = self._statement_category(statement)
        if statement_category in allowed_categories:
            return None
        return "statement_not_allowed"

    def _statement_category(self, statement: exp.Expression) -> str:
        """Classify a parsed statement into a coarse execution-mode category."""

        statement_type = statement.key.lower()
        if isinstance(statement, exp.Select) and statement.args.get("into") is not None:
            return "schema"
        if is_read_query(statement) or statement_type == "describe":
            return "read"
        if isinstance(statement, exp.Command):
            command_name = self._command_name(statement)
            if command_name in self._read_only_command_names:
                return "read"
            if command_name in self._schema_command_names:
                return "schema"
            if command_name in self._admin_command_names:
                return "admin"
            return "unknown"
        if statement_type in self._dml_statement_keys:
            return "dml"
        if statement_type in self._schema_statement_keys:
            return "schema"
        if statement_type in self._admin_statement_keys:
            return "admin"
        return "unknown"

    def _command_name(self, statement: exp.Command) -> str:
        """Return the normalized leading command name for sqlglot Command nodes."""

        return str(statement.this).lower()

    def _query_limit_rejection(self, statement: exp.Expression) -> str | None:
        """Reject a non-literal LIMIT on the statement, and on every branch of a set operation."""

        nodes: list[exp.Expression] = [statement]
        if isinstance(statement, exp.SetOperation):
            nodes.extend(self._set_leaves(statement))
        for node in nodes:
            reason = self._limit_rejection(node)
            if reason is not None:
                return reason
        return None

    def _is_denied_function(self, name: str) -> bool:
        """Side-effect functions, account identity, and dictionary reads outside the grant."""

        if name in self._denied_functions:
            return True
        # ClickHouse dictGet* reads a dictionary the profile never granted.
        return name.startswith("dictget") or name in {"dicthas", "dictisin"}

    def _limit_rejection(self, statement: exp.Expression) -> str | None:
        """Reject dynamic LIMIT clauses before the query can reach a connector."""

        limit = statement.args.get("limit")
        if not isinstance(limit, exp.Limit):
            return None
        expression = limit.expression
        if isinstance(expression, exp.Literal) and expression.is_int:
            return None
        return "non_literal_limit_not_allowed"

    def _with_effective_limit(self, statement: exp.Expression) -> tuple[str, list[str]]:
        """Return SQL with a bounded LIMIT and warnings describing limit changes."""

        warnings: list[str] = []
        current_limit = self._limit_value(statement)
        effective_limit = self._default_limit if current_limit is None else current_limit
        if effective_limit > self._max_limit:
            effective_limit = self._max_limit
            warnings.append("limit_reduced_to_max")
        elif current_limit is None:
            warnings.append("default_limit_applied")

        limited = statement.copy()
        limited.set("limit", exp.Limit(expression=exp.Literal.number(effective_limit)))
        return limited.sql(dialect=self._dialect), warnings

    def _limit_value(self, statement: exp.Expression) -> int | None:
        """Extract a literal LIMIT value, or None when no LIMIT is present."""

        limit = statement.args.get("limit")
        if not isinstance(limit, exp.Limit):
            return None
        expression = limit.expression
        if isinstance(expression, exp.Literal) and expression.is_int:
            return int(expression.this)
        return None

    def _accessed_resources(self, statement: exp.Expression) -> list[str]:
        """Collect referenced table names for later resource-policy resolution."""

        resources: set[str] = set()
        for scope in traverse_scope(statement):
            for table in scope.tables:
                source = scope.sources.get(table.alias_or_name)
                if not isinstance(source, exp.Table):
                    continue
                resources.add(".".join(part for part in (table.db, table.name) if part))
        return sorted(resources)

    def _accessed_fields(self, statement: exp.Expression) -> list[str]:
        """Collect physical-source column names for policy checks and audit metadata."""

        fields: set[str] = set()
        for scope in traverse_scope(statement):
            physical_source_names = {
                name for name, source in scope.sources.items() if isinstance(source, exp.Table)
            }
            if not physical_source_names:
                continue
            for column in scope.columns:
                if column.name == "*":
                    continue
                if column.table and column.table not in physical_source_names:
                    continue
                fields.add(column.name)
        return sorted(fields)

    def _set_leaves(self, statement: exp.Expression) -> list[exp.Select]:
        """SELECT branches of a UNION, EXCEPT, or INTERSECT, in left-to-right order."""

        if isinstance(statement, exp.Select):
            return [statement]
        if isinstance(statement, exp.SetOperation):
            leaves: list[exp.Select] = []
            for side in (statement.this, statement.expression):
                if isinstance(side, exp.Expression):
                    leaves.extend(self._set_leaves(side))
            return leaves
        return []

    def _projection_lineage(self, statement: exp.Expression) -> list[ProjectionLineage]:
        """Return stable output-to-source mappings for SELECT result masking."""

        if isinstance(statement, exp.SetOperation):
            return self._set_projection_lineage(statement)
        if not isinstance(statement, exp.Select):
            return []
        return self._select_projection_lineage(statement)

    def _select_projection_lineage(self, statement: exp.Select) -> list[ProjectionLineage]:
        has_nested_select = any(
            isinstance(expression, exp.Select) and expression is not statement
            for expression in statement.walk()
        )
        return [
            self._one_projection(projection, has_nested_select)
            for projection in statement.expressions
        ]

    def _set_projection_lineage(self, statement: exp.SetOperation) -> list[ProjectionLineage]:
        """Name each output from the first branch and union the source fields at that position."""

        leaves = self._set_leaves(statement)
        if not leaves:
            return []
        has_nested_select = any(
            isinstance(expression, exp.Select) and expression not in leaves
            for expression in statement.find_all(exp.Select)
        )
        lineages: list[ProjectionLineage] = []
        for index, projection in enumerate(leaves[0].expressions):
            fields: set[str] = set()
            wildcard = False
            for leaf in leaves:
                if index >= len(leaf.expressions):
                    continue
                item = leaf.expressions[index]
                wildcard = wildcard or self._is_wildcard_projection(item)
                fields.update(
                    column.name for column in item.find_all(exp.Column) if column.name != "*"
                )
            lineages.append(
                ProjectionLineage(
                    output_name=projection.alias_or_name or None,
                    source_fields=tuple(sorted(fields)),
                    is_wildcard=wildcard,
                    has_nested_select=has_nested_select,
                )
            )
        return lineages

    def _one_projection(
        self, projection: exp.Expression, has_nested_select: bool
    ) -> ProjectionLineage:
        source_fields = tuple(
            sorted(
                {column.name for column in projection.find_all(exp.Column) if column.name != "*"}
            )
        )
        return ProjectionLineage(
            output_name=projection.alias_or_name or None,
            source_fields=source_fields,
            is_wildcard=self._is_wildcard_projection(projection),
            has_nested_select=has_nested_select,
        )

    def _projection_rejections(self, statement: exp.Select) -> list[str]:
        """Reject two outputs that collapse to the same result name. That hides a mask."""

        output_names = [
            projection.alias_or_name.casefold()
            for projection in statement.expressions
            if projection.alias_or_name
        ]
        if len(output_names) != len(set(output_names)):
            return ["duplicate_projection_output_name"]
        return []

    def _is_wildcard_projection(self, projection: exp.Expression) -> bool:
        """Return whether one top-level projection expands an unknown result shape."""

        return isinstance(projection, exp.Star) or (
            isinstance(projection, exp.Column) and isinstance(projection.this, exp.Star)
        )

    def _used_functions(self, statement: exp.Expression) -> list[str]:
        """Collect SQL function names used by the statement."""

        names: set[str] = set()
        for function in statement.find_all(exp.Func):
            if self._is_safe_builtin_expression(function):
                continue
            sql_name = self._function_name(function)
            if sql_name:
                names.add(sql_name)
        return sorted(names)

    def _is_safe_builtin_expression(self, function: exp.Func) -> bool:
        """Skip sqlglot function-shaped nodes that are safe SQL operators or literals."""

        if isinstance(
            function,
            (
                exp.And,
                exp.Or,
            ),
        ):
            return True
        if self._is_safe_temporal_function(function):
            return True
        if isinstance(function, exp.Cast):
            return self._is_safe_temporal_cast(function)
        return False

    def _is_safe_temporal_function(self, function: exp.Func) -> bool:
        """Allow common temporal helpers without opening arbitrary SQL functions."""

        if isinstance(function, self._safe_temporal_function_types):
            return True
        return (
            isinstance(function, exp.Anonymous)
            and self._function_name(function) in self._safe_temporal_anonymous_functions
        )

    def _is_safe_temporal_cast(self, function: exp.Cast) -> bool:
        """Allow DATE/TIME/TIMESTAMP casts while keeping projection safeguards separate."""

        target = function.to
        return isinstance(target, exp.DataType) and target.is_type(*self._safe_temporal_cast_types)

    def _function_name(self, function: exp.Func) -> str:
        """Return a stable lowercase function name, including sqlglot anonymous functions."""

        if isinstance(function, exp.Anonymous):
            return function.name.lower()
        return function.sql_name().lower()

    def _has_wildcard_projection(self, statement: exp.Select) -> bool:
        """Reject a star that reads a physical table.

        A star over a subquery or CTE does not choose new columns; rewrite names the columns
        that source already projects. Those stars are not rejected here.
        """

        stars = [
            projection
            for projection in statement.expressions
            if self._is_wildcard_projection(projection)
        ]
        if not stars:
            return False
        sources = self._from_source_kinds(statement)
        if not sources:
            return True
        for projection in stars:
            qualifier = self._star_qualifier(projection)
            targets = (
                sources
                if qualifier == ""
                else [item for item in sources if item[0].lower() == qualifier.lower()]
            )
            if not targets or any(kind == "table" for _, kind in targets):
                return True
        return False

    def _star_qualifier(self, projection: exp.Expression) -> str:
        node = projection.this if isinstance(projection, exp.Alias) else projection
        if isinstance(node, exp.Column) and isinstance(node.this, exp.Star):
            return node.table or ""
        return ""

    def _cte_names(self, select: exp.Select) -> set[str]:
        names: set[str] = set()
        node: exp.Expression | None = select
        while node is not None:
            with_clause = None
            if isinstance(node, exp.Expression):
                with_clause = node.args.get("with_") or node.args.get("with")
            if isinstance(with_clause, exp.With):
                for cte in with_clause.expressions:
                    if cte.alias:
                        names.add(cte.alias.lower())
            node = node.parent
        return names

    def _from_source_kinds(self, select: exp.Select) -> list[tuple[str, str]]:
        """``(alias, "table"|"derived")`` for this select's FROM and JOIN sources only."""

        ctes = self._cte_names(select)
        nodes: list[exp.Expression] = []
        source = select.args.get("from_") or select.args.get("from")
        if source is not None and isinstance(getattr(source, "this", None), exp.Expression):
            nodes.append(source.this)
        for join in select.args.get("joins") or []:
            this = getattr(join, "this", None)
            if isinstance(this, exp.Expression):
                nodes.append(this)
        kinds: list[tuple[str, str]] = []
        for node in nodes:
            if isinstance(node, exp.Table):
                alias = node.alias or node.name
                kind = "derived" if node.name.lower() in ctes else "table"
                kinds.append((alias, kind))
            elif isinstance(node, exp.Subquery):
                kinds.append((node.alias or "", "derived"))
            else:
                kinds.append(("", "table"))
        return kinds
