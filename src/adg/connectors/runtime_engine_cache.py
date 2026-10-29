from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import RLock
from typing import Protocol

from sqlalchemy import URL, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import TimeoutError as SqlAlchemyTimeoutError

from adg.app.settings import get_settings


class RuntimePoolSettings(Protocol):
    runtime_datasource_pool_cache_size: int
    runtime_datasource_pool_idle_ttl_seconds: int
    runtime_datasource_pool_size: int
    runtime_datasource_pool_max_overflow: int
    runtime_datasource_pool_global_max_connections: int


EngineFactory = Callable[..., Engine]
SettingsProvider = Callable[[], RuntimePoolSettings]
Clock = Callable[[], float]


class _GlobalConnectionBudget:
    """Process-wide physical connection guard shared by every datasource pool."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._used = 0
        self._connections: set[int] = set()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    def reserve(self, limit: int) -> bool:
        """Reserve one slot before the driver starts opening a physical connection."""

        with self._lock:
            if self._used >= limit:
                return False
            self._used += 1
            return True

    def bind(self, connection: object) -> None:
        """Bind a successful reservation to its DBAPI connection identity."""

        with self._lock:
            key = id(connection)
            if key in self._connections:
                raise RuntimeError("DBAPI connection already counted")
            self._connections.add(key)

    def cancel_reservation(self) -> None:
        with self._lock:
            if self._used <= len(self._connections):
                raise RuntimeError("no pending connection reservation")
            self._used -= 1

    def release(self, connection: object) -> bool:
        """Release a physical connection once; duplicate close events are harmless."""

        with self._lock:
            key = id(connection)
            if key not in self._connections:
                return False
            self._connections.remove(key)
            self._used -= 1
            return True


_global_connection_budget = _GlobalConnectionBudget()


@dataclass
class CacheEntry:
    engine: Engine
    last_used_at: float
    generation: str


ConnectArgs = Mapping[str, object]


def build_cache_key(
    connector_type: str,
    url: URL,
    *,
    connect_args: ConnectArgs | None = None,
) -> str:
    """Build a stable cache key without exposing datasource credentials."""

    payload = {
        "url": url.render_as_string(hide_password=False),
        "connect_args": {
            str(key): repr(value)
            for key, value in sorted((connect_args or {}).items(), key=lambda item: str(item[0]))
        },
    }
    fingerprint = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"{connector_type}:{fingerprint}"


class RuntimeEngineCache:
    """Thread-safe LRU cache for runtime datasource SQLAlchemy engines."""

    def __init__(
        self,
        *,
        settings_provider: SettingsProvider | None = None,
        engine_factory: EngineFactory | None = None,
        clock: Clock | None = None,
        connection_budget_guard: _GlobalConnectionBudget | None = None,
    ) -> None:
        self._settings_provider = settings_provider or get_settings
        self._engine_factory = engine_factory
        self._clock = clock or time.monotonic
        self._connection_budget_guard = connection_budget_guard or _global_connection_budget
        self._lock = RLock()
        self._entries: OrderedDict[str, CacheEntry] = OrderedDict()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def get_engine(
        self,
        connector_type: str,
        url: URL,
        *,
        connect_args: ConnectArgs | None = None,
        datasource_key: str | None = None,
        connection_budget: int | None = None,
    ) -> Engine:
        settings = self._settings_provider()
        now = self._clock()
        fingerprint = build_cache_key(connector_type, url, connect_args=connect_args)
        pool_size = connection_budget or settings.runtime_datasource_pool_size
        max_overflow = (
            0 if connection_budget is not None else settings.runtime_datasource_pool_max_overflow
        )
        generation = f"{fingerprint}:pool={pool_size}:overflow={max_overflow}"
        key = f"datasource:{datasource_key}" if datasource_key else generation

        with self._lock:
            self._dispose_expired_locked(now, settings.runtime_datasource_pool_idle_ttl_seconds)

            entry = self._entries.get(key)
            if entry is not None and entry.generation == generation:
                entry.last_used_at = now
                self._entries.move_to_end(key)
                return entry.engine

            engine = self._create_engine(
                url,
                pool_size=pool_size,
                max_overflow=max_overflow,
                global_connection_limit=settings.runtime_datasource_pool_global_max_connections,
                connect_args=connect_args,
            )
            previous = self._entries.pop(key, None)
            self._entries[key] = CacheEntry(engine=engine, last_used_at=now, generation=generation)
            self._entries.move_to_end(key)
            self._enforce_cache_size_locked(settings.runtime_datasource_pool_cache_size)
            if previous is not None:
                # SQLAlchemy closes idle connections now; checked-out connections continue and
                # are closed when returned, so a capacity/credential rotation never kills work.
                previous.engine.dispose()
            return engine

    def dispose_all(self) -> None:
        with self._lock:
            entries = list(self._entries.values())
            self._entries.clear()

        for entry in entries:
            entry.engine.dispose()

    def _create_engine(
        self,
        url: URL,
        *,
        pool_size: int,
        max_overflow: int,
        global_connection_limit: int,
        connect_args: ConnectArgs | None,
    ) -> Engine:
        factory = self._engine_factory or create_engine
        engine = factory(
            url,
            pool_pre_ping=True,
            pool_size=pool_size,
            max_overflow=max_overflow,
            connect_args=dict(connect_args or {}),
        )
        if self._engine_factory is None:
            self._install_global_budget(engine, global_connection_limit)
        return engine

    def _install_global_budget(self, engine: Engine, limit: int) -> None:
        budget = self._connection_budget_guard

        def connect(
            dialect: object,
            _record: object,
            cargs: list[object],
            cparams: dict[str, object],
        ) -> object:
            if not budget.reserve(limit):
                raise SqlAlchemyTimeoutError(
                    "runtime datasource global connection budget exhausted"
                )
            try:
                connection = dialect.connect(*cargs, **cparams)  # type: ignore[attr-defined]
            except BaseException:
                budget.cancel_reservation()
                raise
            try:
                budget.bind(connection)
            except BaseException:
                connection.close()  # type: ignore[attr-defined]
                budget.cancel_reservation()
                raise
            return connection

        def close(dbapi_connection: object, _record: object) -> None:
            budget.release(dbapi_connection)

        def close_detached(dbapi_connection: object) -> None:
            budget.release(dbapi_connection)

        event.listen(engine, "do_connect", connect, retval=True)
        event.listen(engine.pool, "close", close)
        event.listen(engine.pool, "close_detached", close_detached)

    def _dispose_expired_locked(self, now: float, idle_ttl_seconds: int) -> None:
        expired_keys = [
            key
            for key, entry in self._entries.items()
            if now - entry.last_used_at > idle_ttl_seconds
        ]
        for key in expired_keys:
            entry = self._entries.pop(key)
            entry.engine.dispose()

    def _enforce_cache_size_locked(self, cache_size: int) -> None:
        while len(self._entries) > cache_size:
            _, entry = self._entries.popitem(last=False)
            entry.engine.dispose()


_runtime_engine_cache = RuntimeEngineCache()


def get_engine(
    connector_type: str,
    url: URL,
    *,
    connect_args: ConnectArgs | None = None,
    datasource_key: str | None = None,
    connection_budget: int | None = None,
) -> Engine:
    return _runtime_engine_cache.get_engine(
        connector_type,
        url,
        connect_args=connect_args,
        datasource_key=datasource_key,
        connection_budget=connection_budget,
    )


def dispose_all() -> None:
    _runtime_engine_cache.dispose_all()
