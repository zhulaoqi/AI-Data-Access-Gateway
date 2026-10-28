import logging
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request, Response
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from adg.admin_api.console import router as admin_console_router
from adg.admin_api.datasources import router as admin_datasource_router
from adg.admin_api.system import router as admin_system_router
from adg.app.apollo import enable_for_ide_launch
from adg.app.banner import print_banner
from adg.app.log_config import RequestContextMiddleware, configure_logging, kv
from adg.app.settings import Settings, get_settings
from adg.connectors import runtime_engine_cache
from adg.control_plane.db import SessionLocal
from adg.control_plane.db import get_session as get_db_session
from adg.internal_api.decrypt import router as internal_decrypt_router
from adg.mcp_api.tools import router as mcp_tools_router
from adg.mcp_server.server import build_mcp_server_app, runtime_mcp_server
from adg_ext.app import app_kwargs as ext_app_kwargs
from adg_ext.app import install as ext_install
from adg_ext.clientip import current as ext_client_ip
from adg_ext.config import ext_enabled, get_ext_settings

logger = logging.getLogger(__name__)


def create_app(session_factory: sessionmaker[Session] | None = None) -> FastAPI:
    """Build the FastAPI application and attach all V1 routers."""

    enable_for_ide_launch()
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_file)
    factory = session_factory or SessionLocal
    mcp_server_app = build_mcp_server_app(factory)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        print_banner()
        _log_startup(settings)
        async with runtime_mcp_server.session_manager.run():
            try:
                yield
            finally:
                logger.info(kv(event="shutdown"))
                runtime_engine_cache.dispose_all()

    app = FastAPI(title=settings.service_name, lifespan=lifespan, **ext_app_kwargs())
    app.state.session_factory = factory

    @app.middleware("http")
    async def normalize_mcp_mount_path(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Serve /mcp and /mcp/c/<grant> as the same endpoint, without a redirect hop.

        The extra path segment lets one agent load several grants that share this gateway.
        It is not a credential; authentication still reads the API key header.
        """

        path = request.scope["path"]
        if path == "/mcp" or path == "/mcp/c" or path.startswith("/mcp/c/"):
            request.scope["path"] = "/mcp/"
            request.scope["raw_path"] = b"/mcp/"
        return await call_next(request)

    if session_factory is not None:
        def override_session() -> Generator[Session, None, None]:
            with factory() as session:
                yield session

        app.dependency_overrides[get_db_session] = override_session
    app.include_router(admin_console_router)
    app.include_router(admin_datasource_router)
    app.include_router(admin_system_router)
    app.include_router(internal_decrypt_router)
    app.include_router(mcp_tools_router)
    app.mount("/mcp", mcp_server_app)
    # Added before the extension so its ClientIpMiddleware wraps this one and the access line can
    # use the resolved client address.
    app.add_middleware(
        RequestContextMiddleware, client_ip=ext_client_ip if ext_enabled() else None
    )
    if ext_enabled():
        ext_install(app, factory)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        """Return a lightweight liveness response."""

        return {"status": "ok", "service": settings.service_name}

    @app.get("/ready", tags=["system"])
    def ready() -> dict[str, str]:
        """Return readiness for the current single-process service."""

        return {"status": "ready"}

    return app


def _database_endpoint(url: str) -> str:
    """``driver://host:port/db`` only: never the user or password."""

    try:
        parsed = make_url(url)
    except Exception:
        return "invalid"
    host = parsed.host or ""
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.drivername}://{host}{port}/{parsed.database or ''}"


def _log_startup(settings: Settings) -> None:
    ext = get_ext_settings()
    logger.info(
        kv(
            event="startup",
            env=settings.env,
            log_level=settings.log_level,
            control_plane_db=_database_endpoint(settings.control_plane_database_url),
            sql_execution_mode=settings.sql_execution_mode,
            sql_reject_wildcard=settings.sql_reject_wildcard,
            runtime_pool_size=settings.runtime_datasource_pool_size,
            query_max_limit=settings.runtime_query_max_limit,
            ext_enabled=ext.enabled,
            revocation_configured=bool(ext.revocation_url),
            blocklist_configured=bool(ext.blocklist_url),
            trusted_proxy_hops=ext.trusted_proxy_hops,
            audit_fail_closed=ext.audit_fail_closed,
            datasource_max_concurrency=ext.datasource_max_concurrency,
        )
    )


def run() -> None:
    """Run the local development server entry point."""

    uvicorn.run("adg.app.main:create_app", factory=True, host="127.0.0.1", port=8000)
