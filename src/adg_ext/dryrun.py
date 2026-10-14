"""Dry-run (``POST /admin/ext/dry-run``): the same decision core, fed from a profile spec.

Nothing is read from or sent to any database; the answer is the verdict and the SQL that would
be sent. The profile spec uses the management service's snake_case form
(``scope.tables[].columns``, ``row_filter``, ``params``, ``operations``, ``limits``).
"""

from typing import Any

from adg_ext import guard
from adg_ext.analyze import FilterDef, TableView, rewrite
from adg_ext.params import ParamSpec

MAX_SQL = 20_000


def _params(spec: dict[str, Any]) -> tuple[ParamSpec, ...]:
    return tuple(
        ParamSpec(
            str(p["name"]),
            str(p["type"]),
            bool(p.get("required", True)),
            p.get("max_size", p.get("maxSize")),
        )
        for p in spec.get("params") or []
    )


def dry_run(body: dict[str, Any]) -> dict[str, Any]:
    sql = str(body.get("sql") or "")
    spec: dict[str, Any] = body.get("spec") or {}
    datasource = body.get("datasource")
    dialect = guard.dialect_for(str(body.get("dialect") or ""))
    warnings: list[str] = []
    if not sql.strip() or len(sql) > MAX_SQL:
        return {"allowed": False, "rejectReasons": ["sql_invalid"], "warnings": warnings}

    ops_spec = spec.get("operations") or {}
    limits = spec.get("limits") or {}
    limit = int(limits.get("max_rows") or 1000)
    time_columns = {str(c).lower() for c in body.get("timeColumns") or []}
    days = ops_spec.get("require_time_range_days")
    if days and not time_columns:
        warnings.append("time_range_not_verified")
        days = None
    operations = guard.Operations(
        deny_functions=frozenset(str(f).lower() for f in ops_spec.get("deny_functions") or []),
        deny_syntax=frozenset(str(f).lower() for f in ops_spec.get("deny_syntax") or []),
        require_time_range_days=int(days) if days else None,
    )
    known_columns: dict[str, list[str]] = body.get("columns") or {}
    params = _params(spec)
    filters: dict[str, list[FilterDef | None]] = {}
    for f in spec.get("row_filter") or []:
        if datasource and f.get("datasource") != datasource:
            continue
        key = f"{f['database']}.{f['table']}".lower()
        filters.setdefault(key, []).append(FilterDef(str(f["where"]), params))

    views: list[TableView] = []
    for t in (spec.get("scope") or {}).get("tables") or []:
        if datasource and t.get("datasource") != datasource:
            continue
        cols = t.get("columns") or {}
        key = f"{t['database']}.{t['name']}"
        views.append(
            TableView(
                path=key,
                restricted=True,
                columns=(
                    frozenset(c.lower() for c in known_columns[key])
                    if key in known_columns
                    else None
                ),
                allow=frozenset(cols.get("allow") or []),
                deny=frozenset(cols.get("deny") or []),
                mask=dict(cols.get("mask") or {}),
                filters=list(filters.get(key.lower(), [None])),
            )
        )

    verdict = guard.check(
        sql,
        dialect=dialect,
        default_limit=limit,
        max_limit=limit,
        operations=operations,
        time_columns=time_columns,
    )
    if verdict.allowed:
        for path in verdict.result.accessed_resources:
            db, _, name = path.rpartition(".")
            if sum(1 for v in views if v.matches(db or None, name)) != 1:
                return {
                    "allowed": False,
                    "rejectReasons": ["table_not_accessible"],
                    "warnings": warnings,
                }
    user_params = {str(k): v for k, v in (body.get("params") or {}).items()}
    outcome = rewrite(verdict, views, dialect=dialect, user_params=user_params)
    out: dict[str, Any] = {
        "allowed": outcome.allowed,
        "rewrittenSql": outcome.sql,
        "rejectReasons": outcome.reasons,
        "warnings": warnings + list(verdict.result.warnings),
    }
    if outcome.hint:
        out["hint"] = outcome.hint
    return out
