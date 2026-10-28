"""Wires the extension into the FastAPI app (called from ``create_app`` when enabled)."""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import exc as sa_exc
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from adg.app.log_config import kv
from adg.connectors.registry import get_connector_registry
from adg.control_plane.models.api_key import ApiKey
from adg.mcp_server.server import runtime_mcp_server
from adg_ext import blocklist, revocation
from adg_ext.clickhouse import ClickHouseConnector
from adg_ext.clientip import ClientIpMiddleware
from adg_ext.config import get_ext_settings
from adg_ext.mcp_session import install_shared_sessions
from adg_ext.metrics import get_query_metrics
from adg_ext.mysql_scoped import ScopedMySqlConnector
from adg_ext.pipeline import get_admission
from adg_ext.router import admin_router, audit_router, delegated_router

logger = logging.getLogger(__name__)

POOL_EXHAUSTED = "admission_pool_exhausted"


def app_kwargs() -> dict[str, Any]:
    """Extra ``FastAPI(...)`` arguments: docs and schema pages are off unless enabled (N05)."""

    if not get_ext_settings().enabled or get_ext_settings().enable_docs:
        return {}
    return {"docs_url": None, "redoc_url": None, "openapi_url": None}


def _pool_exhausted(_: Request, error: Exception) -> JSONResponse:
    """No control-plane connection within the pool timeout: a clear, retryable 503 (never a 500)."""

    retry_after = get_ext_settings().pool_exhausted_retry_after_seconds
    logger.warning(
        kv(
            event="control_plane_pool_exhausted",
            error=type(error).__name__,
            retry_after=retry_after,
        )
    )
    get_query_metrics().rejected(POOL_EXHAUSTED)
    get_admission().count_rejection("pool_exhausted")
    return JSONResponse(
        status_code=503,
        content={
            "status": "rejected",
            "reason": POOL_EXHAUSTED,
            "detail": POOL_EXHAUSTED,
            "retry_after_seconds": retry_after,
        },
        headers={"Retry-After": str(retry_after)},
    )


def install(app: FastAPI, session_factory: sessionmaker[Session]) -> None:
    registry = get_connector_registry()
    registry.register("clickhouse", ClickHouseConnector)
    registry.register("mysql", ScopedMySqlConnector)
    app.include_router(admin_router)
    app.include_router(audit_router)
    app.include_router(delegated_router)
    app.add_exception_handler(sa_exc.TimeoutError, _pool_exhausted)
    # PA-8: the real client address (trusted proxy hops) for audit rows and blocklist decisions
    app.add_middleware(ClientIpMiddleware)
    # MCP sessions are created before this install (create_app builds the server first).
    manager = getattr(runtime_mcp_server, "_session_manager", None)
    if manager is not None:
        install_shared_sessions(manager)

    cache = revocation.get_cache()

    def on_new(hashes: set[str]) -> None:
        with session_factory() as session:
            ids = session.execute(select(ApiKey.id).where(ApiKey.key_hash.in_(hashes))).scalars()
            for api_key_id in ids:
                get_admission().revoke(api_key_id)

    cache.on_new = on_new
    revocation.start_poller(cache, get_ext_settings().revocation_ttl_seconds)
    blocklist.start_poller(blocklist.get_cache(), get_ext_settings().blocklist_poll_seconds)
