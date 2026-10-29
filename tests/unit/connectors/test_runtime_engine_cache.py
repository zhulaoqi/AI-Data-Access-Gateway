from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import URL

from adg.connectors.runtime_engine_cache import (
    EngineFactory,
    RuntimeEngineCache,
    build_cache_key,
)


@dataclass
class CacheSettings:
    runtime_datasource_pool_cache_size: int = 32
    runtime_datasource_pool_idle_ttl_seconds: int = 300
    runtime_datasource_pool_size: int = 5
    runtime_datasource_pool_max_overflow: int = 0
    runtime_datasource_pool_global_max_connections: int = 1024


class FakeEngine:
    def __init__(self, name: str) -> None:
        self.name = name
        self.disposed = False

    def dispose(self) -> None:
        self.disposed = True


class MonotonicClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def make_url(
    *,
    password: str = "secret-password",
    database: str = "warehouse",
) -> URL:
    return URL.create(
        drivername="postgresql+psycopg",
        username="alice",
        password=password,
        host="db.internal",
        database=database,
    )


def test_cache_reuses_same_engine_for_same_connector_and_url() -> None:
    created: list[URL] = []

    def engine_factory(url: URL, **kwargs: Any) -> FakeEngine:
        created.append(url)
        return FakeEngine(f"engine-{len(created)}")

    cache = RuntimeEngineCache(
        settings_provider=lambda: CacheSettings(),
        engine_factory=cast(EngineFactory, engine_factory),
    )

    engine_one = cast(FakeEngine, cache.get_engine("postgres", make_url()))
    engine_two = cast(FakeEngine, cache.get_engine("postgres", make_url()))

    assert engine_one is engine_two
    assert len(created) == 1


def test_cache_key_uses_safe_fingerprint_without_plaintext_password() -> None:
    key = build_cache_key(
        "postgres",
        make_url(password="very-secret-password"),
        connect_args={"connect_timeout": 10},
    )

    assert key.startswith("postgres:")
    assert "very-secret-password" not in key
    assert "alice" not in key
    assert "db.internal" not in key


def test_cache_key_changes_when_connect_args_change() -> None:
    url = make_url()

    key_one = build_cache_key("postgres", url, connect_args={"connect_timeout": 10})
    key_two = build_cache_key("postgres", url, connect_args={"connect_timeout": 20})

    assert key_one != key_two


def test_cache_evicts_least_recently_used_engine_when_size_is_exceeded() -> None:
    created: list[FakeEngine] = []

    def engine_factory(url: URL, **kwargs: Any) -> FakeEngine:
        engine = FakeEngine(str(url.database))
        created.append(engine)
        return engine

    cache = RuntimeEngineCache(
        settings_provider=lambda: CacheSettings(runtime_datasource_pool_cache_size=2),
        engine_factory=cast(EngineFactory, engine_factory),
    )

    first = cast(FakeEngine, cache.get_engine("postgres", make_url(database="one")))
    second = cast(FakeEngine, cache.get_engine("postgres", make_url(database="two")))
    assert cast(FakeEngine, cache.get_engine("postgres", make_url(database="one"))) is first

    third = cast(FakeEngine, cache.get_engine("postgres", make_url(database="three")))

    assert third is created[2]
    assert first.disposed is False
    assert second.disposed is True
    assert len(cache) == 2


def test_cache_lazily_disposes_idle_engine_on_next_access_after_ttl() -> None:
    clock = MonotonicClock()
    created: list[FakeEngine] = []

    def engine_factory(url: URL, **kwargs: Any) -> FakeEngine:
        engine = FakeEngine(f"engine-{len(created)}")
        created.append(engine)
        return engine

    cache = RuntimeEngineCache(
        settings_provider=lambda: CacheSettings(runtime_datasource_pool_idle_ttl_seconds=10),
        engine_factory=cast(EngineFactory, engine_factory),
        clock=clock,
    )

    first = cast(FakeEngine, cache.get_engine("postgres", make_url()))
    clock.advance(11)
    second = cast(FakeEngine, cache.get_engine("postgres", make_url()))

    assert first is not second
    assert first.disposed is True
    assert second.disposed is False
    assert len(cache) == 1


def test_cache_does_not_reuse_engine_when_url_fingerprint_changes() -> None:
    created: list[FakeEngine] = []

    def engine_factory(url: URL, **kwargs: Any) -> FakeEngine:
        engine = FakeEngine(str(url))
        created.append(engine)
        return engine

    cache = RuntimeEngineCache(
        settings_provider=lambda: CacheSettings(),
        engine_factory=cast(EngineFactory, engine_factory),
    )

    engine_one = cast(FakeEngine, cache.get_engine("postgres", make_url(password="old-secret")))
    engine_two = cast(FakeEngine, cache.get_engine("postgres", make_url(password="new-secret")))

    assert engine_one is not engine_two
    assert len(created) == 2


def test_dispose_all_clears_cache_and_disposes_all_engines() -> None:
    created: list[FakeEngine] = []

    def engine_factory(url: URL, **kwargs: Any) -> FakeEngine:
        engine = FakeEngine(str(url.database))
        created.append(engine)
        return engine

    cache = RuntimeEngineCache(
        settings_provider=lambda: CacheSettings(),
        engine_factory=cast(EngineFactory, engine_factory),
    )
    cache.get_engine("postgres", make_url(database="one"))
    cache.get_engine("postgres", make_url(database="two"))

    cache.dispose_all()

    assert [engine.disposed for engine in created] == [True, True]
    assert len(cache) == 0


def test_runtime_create_engine_uses_pre_ping_and_pool_limits() -> None:
    captured_kwargs: dict[str, Any] = {}

    def engine_factory(url: URL, **kwargs: Any) -> FakeEngine:
        captured_kwargs.update(kwargs)
        return FakeEngine("engine")

    cache = RuntimeEngineCache(
        settings_provider=lambda: CacheSettings(),
        engine_factory=cast(EngineFactory, engine_factory),
    )

    cache.get_engine("postgres", make_url(), connect_args={"connect_timeout": 10})

    assert captured_kwargs == {
        "pool_pre_ping": True,
        "pool_size": 5,
        "max_overflow": 0,
        "connect_args": {"connect_timeout": 10},
    }


def test_datasource_connection_budget_overrides_default_pool_size() -> None:
    captured_kwargs: dict[str, Any] = {}

    def engine_factory(url: URL, **kwargs: Any) -> FakeEngine:
        captured_kwargs.update(kwargs)
        return FakeEngine("engine")

    cache = RuntimeEngineCache(
        settings_provider=lambda: CacheSettings(),
        engine_factory=cast(EngineFactory, engine_factory),
    )
    cache.get_engine(
        "postgres",
        make_url(),
        connect_args={"connect_timeout": 10},
        datasource_key="ds-orders",
        connection_budget=3,
    )

    assert captured_kwargs["pool_size"] == 3
    assert captured_kwargs["max_overflow"] == 0


def test_capacity_change_replaces_pool_and_disposes_only_old_idle_generation() -> None:
    created: list[FakeEngine] = []

    def engine_factory(url: URL, **kwargs: Any) -> FakeEngine:
        engine = FakeEngine(f"pool-{kwargs['pool_size']}")
        created.append(engine)
        return engine

    cache = RuntimeEngineCache(
        settings_provider=lambda: CacheSettings(),
        engine_factory=cast(EngineFactory, engine_factory),
    )
    first = cast(
        FakeEngine,
        cache.get_engine(
            "postgres",
            make_url(),
            datasource_key="ds-orders",
            connection_budget=5,
        ),
    )
    same = cache.get_engine(
        "postgres",
        make_url(),
        datasource_key="ds-orders",
        connection_budget=5,
    )
    replacement = cast(
        FakeEngine,
        cache.get_engine(
            "postgres",
            make_url(),
            datasource_key="ds-orders",
            connection_budget=2,
        ),
    )

    assert same is first
    assert replacement is not first
    assert first.disposed is True
    assert replacement.disposed is False
    assert len(cache) == 1
