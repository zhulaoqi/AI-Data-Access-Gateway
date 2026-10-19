from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request, Response
from sqlalchemy.orm import Session, sessionmaker

from adg.admin_api.console import router as admin_console_router
from adg.admin_api.datasources import router as admin_datasource_router
from adg.admin_api.system import router as admin_system_router
from adg.app.apollo import enable_for_ide_launch
from adg.app.settings import get_settings
from adg.connectors import runtime_engine_cache
from adg.control_plane.db import SessionLocal
from adg.control_plane.db import get_session as get_db_session
from adg.internal_api.decrypt import router as internal_decrypt_router
from adg.mcp_api.tools import router as mcp_tools_router
from adg.mcp_server.server import build_mcp_server_app, runtime_mcp_server
from adg_ext.app import app_kwargs as ext_app_kwargs
from adg_ext.app import install as ext_install
from adg_ext.config import ext_enabled


def create_app(session_factory: sessionmaker[Session] | None = None) -> FastAPI:
    """Build the FastAPI application and attach all V1 routers."""

    enable_for_ide_launch()
    settings = get_settings()
    factory = session_factory or SessionLocal
    mcp_server_app = build_mcp_server_app(factory)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        async with runtime_mcp_server.session_manager.run():
            try:
                yield
            finally:
                runtime_engine_cache.dispose_all()

    app = FastAPI(title=settings.service_name, lifespan=lifespan, **ext_app_kwargs())
    app.state.session_factory = factory

    @app.middleware("http")
    async def normalize_mcp_mount_path(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Serve the mounted MCP endpoint at /mcp without a redirect hop."""

        if request.scope["path"] == "/mcp":
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


def run() -> None:
    """Run the local development server entry point."""

    uvicorn.run("adg.app.main:create_app", factory=True, host="127.0.0.1", port=8000)
