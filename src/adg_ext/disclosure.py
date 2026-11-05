"""Per-person disclosure. Values are applied before SQL runs. A memory hit does not touch Redis."""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable

from adg_ext.analyze import FilterDef, TableView
from adg_ext.params import ParamSpec

_UNSAFE = (";", "--", "/*", "*/", "\\", "{", "}")
PARAM = "gw_disclosure_values"
REDIS_PREFIX = "gw:person_scope:"
MEMORY_TTL = 15.0
MAX_VALUES = 1000
MAX_VALUE_LEN = 256
MAX_HEADER = 7168
MAX_PERSON = 128

_lock = threading.Lock()
_memory: dict[tuple[str, str], tuple[float, list[str]]] = {}

_NOT_ENTITLED = (
    "你还没有这项数据的查询权限。请联系数据负责人{names}，为你开通网关数据权限，"
    "并在数据可视化中开通相应权限。开通后无需登录管理端，可以直接再问。"
)


def redis_key(dimension_id: str, open_id: str) -> str:
    return f"{REDIS_PREFIX}{dimension_id}:{open_id}"


def sync_name(dimension_id: str, open_id: str) -> str:
    return f"gw:ps:{dimension_id}:{open_id}"


def remember(dimension_id: str, open_id: str, values: list[str]) -> None:
    """Called when a scope is synced. Warms memory and Redis off the query path."""

    _store(dimension_id, open_id, values)
    client = _redis()
    if client is None:
        return
    try:
        client.set(redis_key(dimension_id, open_id), json.dumps({"v": 1, "values": values}, ensure_ascii=False))
    except Exception:
        return


def forget(dimension_id: str, open_id: str) -> None:
    with _lock:
        _memory.pop((dimension_id, open_id), None)
    client = _redis()
    if client is None:
        return
    try:
        client.delete(redis_key(dimension_id, open_id))
    except Exception:
        return


def bind(
    disclosure: dict[str, Any] | None,
    views: list[TableView],
    user_params: dict[str, Any],
    *,
    channel: str,
    headers: dict[str, str | None] | None,
    lookup,
) -> str | None:
    """Return a rejection reason, or None after the person predicate is attached to every view."""

    if not disclosure or not disclosure.get("dimensionId"):
        return None
    if disclosure.get("conflict"):
        return "disclosure_conflict"
    if channel == "jdbc":
        return "disclosure_not_supported_on_jdbc"
    source = str(disclosure.get("source") or "manual")
    columns = disclosure.get("columns") or []
    if not isinstance(columns, list) or not columns:
        return "disclosure_column_missing"
    if source == "external":
        values, reason = parse_external(headers or {}, str(disclosure["dimensionId"]))
        if reason:
            return reason
    else:
        person = ((headers or {}).get("person") or "").strip()
        if not person or len(person) > MAX_PERSON or _control(person):
            return "person_required"
        values = lookup(str(disclosure["dimensionId"]), person)
        if not values:
            return _friendly(disclosure)
    values, problem = _comma_values(values)
    if problem == "too_large":
        return "person_scope_too_large:" + _friendly(disclosure) if source != "external" else "external_scope_too_large"
    if values is None:
        return "external_scope_required" if source == "external" else "disclosure_value_invalid"
    if PARAM in user_params:
        return "disclosure_param_conflict"
    spec = ParamSpec(PARAM, "string_list", True, MAX_VALUES)
    clause = None
    bound = _bindings(columns)
    for view in views:
        if not view.restricted:
            continue
        column = _column_for(view, bound)
        if column is None:
            return "disclosure_column_missing"
        quoted = _quote(column)
        if quoted is None or not view.permits(column):
            return f"row_filter_column_not_permitted:{column}"
        piece = f"{quoted} IN ({{{{{PARAM}}}}})"
        clause = piece
        if not view.filters:
            view.filters = [FilterDef(piece, (spec,))]
        else:
            view.filters = [_and(item, piece, spec) for item in view.filters]
    if clause is None:
        return "disclosure_column_missing"
    user_params[PARAM] = list(values)
    return None


def resolve_values(
    dimension_id: str,
    open_id: str,
    *,
    redis_get: Callable[[str], str | None] | None = None,
    local_get: Callable[[], list[str] | None] | None = None,
    now: float | None = None,
) -> list[str] | None:
    """Memory, then one Redis GET, then the synced snapshot. Missing means not entitled."""

    clock = time.monotonic() if now is None else now
    cached = _read(dimension_id, open_id, clock)
    if cached is not None:
        return cached
    raw = None
    failed = False
    if redis_get is not None:
        try:
            raw = redis_get(redis_key(dimension_id, open_id))
        except Exception:
            failed = True
    if not failed and raw:
        parsed = _payload(raw)
        if parsed is not None:
            _store(dimension_id, open_id, parsed, clock)
            return parsed
        return None
    if local_get is None:
        return None
    local = local_get()
    if local:
        _store(dimension_id, open_id, local, clock)
        return local
    return None


def parse_external(headers: dict[str, str | None], dimension_id: str) -> tuple[list[str] | None, str | None]:
    person = headers.get("person") or ""
    if not person or len(person) > MAX_PERSON or _control(person):
        return None, "external_scope_required"
    raw = headers.get("scope")
    if raw is None or raw == "":
        return None, "external_scope_required"
    if len(raw.encode("utf-8")) > MAX_HEADER or "\n" in raw or "\r" in raw:
        return None, "external_scope_too_large"
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return None, "external_scope_required"
    if not isinstance(body, dict):
        return None, "external_scope_required"
    version = body.get("v")
    if version != 1:
        return None, "external_scope_unsupported"
    if body.get("dimensionId") != dimension_id:
        return None, "external_scope_mismatch"
    values = body.get("values")
    if not isinstance(values, list) or not values:
        return None, "external_scope_required"
    clean, problem = _comma_values(values)
    if problem == "too_large":
        return None, "external_scope_too_large"
    if clean is None:
        return None, "external_scope_required"
    return clean, None


def _bindings(columns: list[Any]) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for item in columns:
        if not isinstance(item, dict):
            continue
        database = str(item.get("database") or "")
        table = str(item.get("table") or "")
        column = str(item.get("column") or "")
        if database and table and column:
            out.append((database, table, column))
    return out


def _column_for(view: TableView, columns: list[tuple[str, str, str]]) -> str | None:
    for database, table, column in columns:
        if view.matches(database, table):
            return column
    return None


def _and(existing: FilterDef | None, clause: str, spec: ParamSpec) -> FilterDef:
    if existing is None:
        return FilterDef(clause, (spec,))
    return FilterDef(f"({existing.where}) AND ({clause})", existing.params + (spec,))


def _friendly(disclosure: dict[str, Any]) -> str:
    names = disclosure.get("ownerNames") or []
    label = ""
    if isinstance(names, list):
        clean = [str(n) for n in names if isinstance(n, str) and n.strip()][:3]
        if clean:
            label = "（" + "、".join(clean) + "）"
    return _NOT_ENTITLED.format(names=label)


def _payload(raw: str) -> list[str] | None:
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(body, dict) or body.get("pending") is True:
        return None
    values = body.get("values")
    clean, problem = _comma_values(values) if isinstance(values, list) else (None, "invalid")
    if problem or clean is None:
        return None
    return clean


def _read(dimension_id: str, open_id: str, now: float) -> list[str] | None:
    with _lock:
        hit = _memory.get((dimension_id, open_id))
        if hit is None or hit[0] <= now:
            if hit is not None:
                _memory.pop((dimension_id, open_id), None)
            return None
        return list(hit[1])


def _store(dimension_id: str, open_id: str, values: list[str], now: float | None = None) -> None:
    clock = time.monotonic() if now is None else now
    with _lock:
        _memory[(dimension_id, open_id)] = (clock + MEMORY_TTL, list(values))


_BAD_VALUE = ("，", "、", ";", "；")


def _comma_values(values: list[Any]) -> tuple[list[str] | None, str]:
    """Split each item on English commas. A value is one token, never a second separator."""

    if not isinstance(values, list) or not values:
        return None, "invalid"
    out: list[str] = []
    for item in values:
        if not isinstance(item, str) or _control(item) or any(mark in item for mark in _BAD_VALUE):
            return None, "invalid"
        for part in item.split(","):
            text = part.strip()
            if not text:
                continue
            if len(text) > MAX_VALUE_LEN:
                return None, "too_large"
            if text not in out:
                out.append(text)
            if len(out) > MAX_VALUES:
                return None, "too_large"
    if not out:
        return None, "invalid"
    return out, ""


def _control(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _quote(name: str) -> str | None:
    """Quote a catalog column. Spaces and non-ASCII stay; breakout characters do not."""

    if not name or len(name) > 200 or _control(name) or any(token in name for token in _UNSAFE):
        return None
    return "`" + name.replace("`", "``") + "`"


def _redis() -> Any:
    try:
        from adg_ext.redis_share import get_client
    except Exception:
        return None
    return get_client()
