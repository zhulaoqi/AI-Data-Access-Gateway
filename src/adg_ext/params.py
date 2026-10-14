"""Typed grant parameters and safe literal rendering for row-filter predicates (PA-1)."""

import re
from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlglot import exp

from adg_ext.errors import ExtRejection

PARAM_TYPES = {"long", "long_list", "string", "string_list", "date"}
MAX_LIST_ITEMS = 1000
MAX_STRING_LENGTH = 512
PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True)
class ParamSpec:
    """Declaration of one grant parameter used by a row-filter template."""

    name: str
    type: str
    required: bool = True
    max_size: int | None = None

    def __post_init__(self) -> None:
        if self.type not in PARAM_TYPES:
            raise ExtRejection("row_filter_param_type_invalid", detail=self.name)


def placeholders(template: str) -> list[str]:
    """Names referenced by ``{{name}}`` placeholders in a template, in order of appearance."""

    return PLACEHOLDER_RE.findall(template)


def _check_string(value: object, name: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ExtRejection("row_filter_param_invalid", detail=name)
    if len(value) > min(limit, MAX_STRING_LENGTH):
        raise ExtRejection("row_filter_param_too_long", detail=name)
    # Control characters (including NUL and newlines) never belong in a filter value.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ExtRejection("row_filter_param_invalid", detail=name)
    return value


def _check_long(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ExtRejection("row_filter_param_invalid", detail=name)
    if isinstance(value, str) and not re.fullmatch(r"-?\d{1,18}", value.strip()):
        raise ExtRejection("row_filter_param_invalid", detail=name)
    number = int(value)
    if abs(number) > 9_223_372_036_854_775_807:
        raise ExtRejection("row_filter_param_invalid", detail=name)
    return number


def render_value(spec: ParamSpec, value: Any) -> exp.Expression:
    """Turn one validated parameter value into a SQL literal expression (never raw text)."""

    limit = spec.max_size or MAX_LIST_ITEMS
    match spec.type:
        case "long":
            return exp.Literal.number(_check_long(value, spec.name))
        case "string":
            return exp.Literal.string(_check_string(value, spec.name, spec.max_size or 256))
        case "date":
            text = _check_string(value, spec.name, 10)
            if not _DATE.fullmatch(text):
                raise ExtRejection("row_filter_param_invalid", detail=spec.name)
            try:
                date.fromisoformat(text)
            except ValueError as error:
                raise ExtRejection("row_filter_param_invalid", detail=spec.name) from error
            return exp.Literal.string(text)
        case "long_list" | "string_list":
            if not isinstance(value, list) or not value:
                raise ExtRejection("row_filter_param_invalid", detail=spec.name)
            if len(value) > min(limit, MAX_LIST_ITEMS):
                raise ExtRejection("row_filter_param_list_too_long", detail=spec.name)
            if spec.type == "long_list":
                return exp.Tuple(
                    expressions=[exp.Literal.number(_check_long(v, spec.name)) for v in value]
                )
            return exp.Tuple(
                expressions=[exp.Literal.string(_check_string(v, spec.name, 256)) for v in value]
            )
    raise ExtRejection("row_filter_param_type_invalid", detail=spec.name)  # pragma: no cover


def resolve_values(
    specs: dict[str, ParamSpec], supplied: dict[str, Any], needed: list[str]
) -> dict[str, exp.Expression]:
    """Validate and render every parameter a template needs; missing required ones reject."""

    out: dict[str, exp.Expression] = {}
    for name in dict.fromkeys(needed):
        spec = specs.get(name)
        if spec is None:
            raise ExtRejection("row_filter_param_undeclared", detail=name)
        if name not in supplied or supplied[name] is None:
            raise ExtRejection("row_filter_param_missing", detail=name)
        out[name] = render_value(spec, supplied[name])
    return out
