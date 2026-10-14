from collections.abc import Generator
from pathlib import Path

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from adg.app.settings import get_settings
from adg_ext.config import ext_enabled, get_ext_settings


def create_engine_from_url(database_url: str) -> Engine:
    """Create a SQLAlchemy engine and prepare SQLite-specific filesystem settings."""

    connect_args: dict[str, object] = {}
    poolclass: type[StaticPool] | None = None
    pool_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        if database_url == "sqlite:///:memory:":
            # StaticPool keeps one in-memory SQLite database visible across sessions.
            poolclass = StaticPool
        else:
            url = make_url(database_url)
            if url.database:
                # Local self-hosted defaults should work before the data directory exists.
                Path(url.database).expanduser().parent.mkdir(parents=True, exist_ok=True)
    in_memory = database_url.startswith("sqlite") and make_url(database_url).database in (
        None,
        "",
        ":memory:",
    )
    if poolclass is None and not in_memory and ext_enabled():
        # adg_ext: bounded wait for a pooled connection (503 ``admission_pool_exhausted`` upstream of here
        # instead of the 30 s default followed by a 500) and a pool sized for the worker threads.
        ext = get_ext_settings()
        pool_args = {
            "pool_size": ext.control_plane_pool_size,
            "max_overflow": ext.control_plane_pool_max_overflow,
            "pool_timeout": ext.control_plane_pool_timeout_seconds,
        }

    return create_engine(
        database_url,
        connect_args=connect_args,
        future=True,
        poolclass=poolclass,
        **pool_args,
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create the session factory used by FastAPI dependencies and tests."""

    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


engine = create_engine_from_url(get_settings().control_plane_database_url)
SessionLocal = create_session_factory(engine)


def get_session() -> Generator[Session, None, None]:
    """Yield one request-scoped database session."""

    with SessionLocal() as session:
        yield session
