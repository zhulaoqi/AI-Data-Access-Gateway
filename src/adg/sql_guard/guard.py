from dataclasses import dataclass, field
from typing import Literal, cast

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope

type SqlExecutionMode = Literal["read_only", "dml", "schema", "admin"]


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
    allowed_functions = {"count", "sum", "avg", "min", "max"}
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

        if not isinstance(statement, exp.Select):
            normalized_sql = statement.sql(dialect=self._dialect)
            return SqlGuardResult(
                allowed=True,
                normalized_sql=normalized_sql,
                statement_type=statement_type,
                accessed_resources=self._accessed_resources(statement),
                accessed_fields=self._accessed_fields(statement),
                risk_level="medium",
            )

        limit_rejection = self._limit_rejection(statement)
        if limit_rejection is not None:
            return SqlGuardResult(
                allowed=False,
                normalized_sql=None,
                statement_type="SELECT",
                accessed_resources=self._accessed_resources(statement),
                accessed_fields=self._accessed_fields(statement),
                projections=self._projection_lineage(statement),
                rejection_reasons=[limit_rejection],
            )

        used_functions = self._used_functions(statement)
        rejection_reasons = self._projection_rejections(statement)
        if self._strict_validation:
            # Function allowlisting keeps expensive or unsafe database functions out of runtime SQL.
            rejection_reasons.extend(
                f"function_not_allowed:{function_name}"
                for function_name in used_functions
                if function_name not in self.allowed_functions
            )
            if self._reject_wildcards and self._has_wildcard_projection(statement):
                rejection_reasons.append("wildcard_projection_not_allowed")
            rejection_reasons.extend(self._temporal_projection_rejections(statement))
        normalized_sql, warnings = self._with_effective_limit(statement)

        return SqlGuardResult(
            allowed=not rejection_reasons,
            normalized_sql=normalized_sql if not rejection_reasons else None,
            statement_type="SELECT",
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
        if not isinstance(statement, exp.Select):
            return "cte_final_statement_not_allowed"
        for with_clause in with_clauses:
            if with_clause.args.get("recursive"):
                return "recursive_cte_not_allowed"
            for cte in with_clause.expressions:
                if not isinstance(cte.this, exp.Select):
                    return "cte_non_select_not_allowed"
                for cte_select in cte.this.find_all(exp.Select):
                    if cte_select.args.get("locks"):
                        return "cte_locking_read_not_allowed"
                    if cte_select.args.get("into") is not None:
                        return "cte_select_into_not_allowed"
                    if self._reject_wildcards and self._has_wildcard_projection(cte_select):
                        return "cte_wildcard_projection_not_allowed"
                    limit_rejection = self._limit_rejection(cte_select)
                    if limit_rejection is not None:
                        return limit_rejection
                    cte_limit = self._limit_value(cte_select)
                    if cte_limit is not None and cte_limit > self._max_limit:
                        return "cte_limit_exceeded"
        return None

    def _statement_rejection(self, statement: exp.Expression) -> str | None:
        """Return a first-layer statement-type rejection reason, if any."""

        allowed_categories = self._mode_allowed_statement_categories[self._execution_mode]
        if isinstance(statement, exp.Select):
            if statement.args.get("locks"):
                return "locking_read_not_allowed"
            if statement.args.get("into") is not None and "schema" not in allowed_categories:
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
        if isinstance(statement, exp.Select) or statement_type == "describe":
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

    def _limit_rejection(self, statement: exp.Select) -> str | None:
        """Reject dynamic LIMIT clauses before the query can reach a connector."""

        limit = statement.args.get("limit")
        if not isinstance(limit, exp.Limit):
            return None
        expression = limit.expression
        if isinstance(expression, exp.Literal) and expression.is_int:
            return None
        return "non_literal_limit_not_allowed"

    def _with_effective_limit(self, statement: exp.Select) -> tuple[str, list[str]]:
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

    def _limit_value(self, statement: exp.Select) -> int | None:
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

    def _projection_lineage(self, statement: exp.Expression) -> list[ProjectionLineage]:
        """Return stable output-to-source mappings for SELECT result masking."""

        if not isinstance(statement, exp.Select):
            return []
        has_nested_select = any(
            isinstance(expression, exp.Select) and expression is not statement
            for expression in statement.walk()
        )
        projections: list[ProjectionLineage] = []
        for projection in statement.expressions:
            output_name = projection.alias_or_name or None
            source_fields = tuple(
                sorted(
                    {
                        column.name
                        for column in projection.find_all(exp.Column)
                        if column.name != "*"
                    }
                )
            )
            projections.append(
                ProjectionLineage(
                    output_name=output_name,
                    source_fields=source_fields,
                    is_wildcard=self._is_wildcard_projection(projection),
                    has_nested_select=has_nested_select,
                )
            )
        return projections

    def _projection_rejections(self, statement: exp.Select) -> list[str]:
        """Reject derived outputs whose database result name cannot be mapped reliably."""

        output_names = [
            projection.alias_or_name.casefold()
            for projection in statement.expressions
            if projection.alias_or_name
        ]
        if len(output_names) != len(set(output_names)):
            return ["duplicate_projection_output_name"]
        for projection in statement.expressions:
            references_field = any(projection.find_all(exp.Column))
            if (
                references_field
                and not isinstance(projection, (exp.Column, exp.AggFunc))
                and not projection.alias
            ):
                return ["derived_projection_requires_alias"]
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

    def _temporal_projection_rejections(self, statement: exp.Select) -> list[str]:
        """Reject temporal column transforms in projections to preserve masking boundaries."""

        rejections: set[str] = set()
        for projection in statement.expressions:
            for function in projection.find_all(exp.Func):
                if self._is_safe_temporal_projection_transform(
                    function
                ) and self._references_column(function):
                    rejections.add(
                        f"temporal_projection_not_allowed:{self._function_name(function)}"
                    )
        return sorted(rejections)

    def _is_safe_temporal_projection_transform(self, function: exp.Func) -> bool:
        """Return whether a function is a temporal transform guarded in SELECT output."""

        return (
            self._is_safe_temporal_function(function)
            or isinstance(
                function,
                exp.Cast,
            )
            and self._is_safe_temporal_cast(function)
        )

    def _references_column(self, expression: exp.Expression) -> bool:
        """Check whether an expression derives from at least one source column."""

        return any(expression.find_all(exp.Column))

    def _has_wildcard_projection(self, statement: exp.Select) -> bool:
        """Reject wildcard projections so runtime callers must name fields explicitly."""

        return any(self._is_wildcard_projection(projection) for projection in statement.expressions)
