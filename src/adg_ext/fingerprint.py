"""Structural fingerprint of a SQL statement (PA-8).

Literals are replaced by ``?`` (and ``IN (...)`` lists collapse to one placeholder) before the
statement is hashed, so two statements that differ only in literal values share a fingerprint while
a structural change (another column, table or predicate shape) produces a different one. The
fingerprint is the only thing about the statement that leaves the executor for risk inspection;
it carries no data and cannot be reversed to the SQL text.
"""

import hashlib

import sqlglot
from sqlglot import exp


def _literals(node: exp.Expression) -> exp.Expression | None:
    if isinstance(node, (exp.Literal, exp.Boolean, exp.Null)):
        return exp.Placeholder()
    return node


def _collapse_lists(node: exp.Expression) -> exp.Expression | None:
    if isinstance(node, exp.In):
        values = node.args.get("expressions")
        if values and all(isinstance(e, exp.Placeholder) for e in values):
            node.set("expressions", [exp.Placeholder()])
    return node


def sql_fingerprint(sql: str, dialect: str | None = None) -> str | None:
    """16 hex characters, or None when the statement cannot be parsed."""

    try:
        tree = sqlglot.parse_one(sql, read=dialect)
        normalized = tree.transform(_literals).transform(_collapse_lists)
        text = normalized.sql(dialect=dialect, normalize=True)
    except Exception:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
