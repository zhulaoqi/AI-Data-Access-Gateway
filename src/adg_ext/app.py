"""Wires the extension into the FastAPI app (called from ``create_app`` when enabled)."""

import logging

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from adg.connectors.registry import get_connector_registry
from adg.control_plane.models.api_key import ApiKey
from adg_ext import revocation
from adg_ext.clickhouse import ClickHouseConnector
from adg_ext.config import get_ext_settings
from adg_ext.pipeline import get_admission
from adg_ext.router import admin_router, delegated_router

logger = logging.getLogger(__name__)


def install(app: FastAPI, session_factory: sessionmaker[Session]) -> None:
    get_connector_registry().register("clickhouse", ClickHouseConnector)
    app.include_router(admin_router)
    app.include_router(delegated_router)

    cache = revocation.get_cache()

    def on_new(hashes: set[str]) -> None:
        with session_factory() as session:
            ids = session.execute(select(ApiKey.id).where(ApiKey.key_hash.in_(hashes))).scalars()
            for api_key_id in ids:
                get_admission().revoke(api_key_id)

    cache.on_new = on_new
    revocation.start_poller(cache, get_ext_settings().revocation_ttl_seconds)
