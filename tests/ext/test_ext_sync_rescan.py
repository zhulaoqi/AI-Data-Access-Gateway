"""Rescan of a synced datasource: the catalog follows the live source although the spec is unchanged."""

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from adg.app.auth_rate_limit import reset_auth_rate_limiter
from adg.app.main import create_app
from adg.app.settings import get_settings
from adg.connectors.registry import get_connector_registry
from adg.control_plane.db import create_engine_from_url, create_session_factory
from adg.control_plane.models import Base
from adg.control_plane.models.resource import Resource
from adg.control_plane.services.api_key_service import create_api_key
from adg_ext import pipeline, revocation
from adg_ext.config import get_ext_settings

ADMIN = {"X-ADG-API-Key": "adg_admin_rescan_key"}
DS = "gw:ds:a1"
SPEC = {
    "engine": "mysql",
    "host": "db.example",
    "port": 3306,
    "username": "u",
    "password": "p",
    "databases": ["app"],
}
HASH = hashlib.sha256(b"spec-v1").hexdigest()
TABLES: list[str] = []


class FakeMySql:
    def scan_metadata(self, config: dict[str, object]) -> dict[str, Any]:
        return {
            "databases": [
                {
                    "name": "app",
                    "tables": [
                        {
                            "name": t,
                            "kind": "table",
                            "schema": "app",
                            "columns": [
                                {
                                    "name": "id",
                                    "data_type": "BIGINT",
                                    "nullable": False,
                                    "ordinal_position": 1,
                                    "description": None,
                                }
                            ],
                        }
                        for t in TABLES
                    ],
                }
            ]
        }


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, Any]]:
    monkeypatch.setenv("ADG_EXT_ENABLED", "true")
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()
    reset_auth_rate_limiter()
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 't.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    registry = get_connector_registry()
    saved = dict(registry._connectors)
    with factory() as session:
        create_api_key(session, name="admin", scopes=["admin"], plaintext="adg_admin_rescan_key")
        session.commit()
    app = create_app(session_factory=factory)
    registry.register("mysql", FakeMySql)  # type: ignore[arg-type]
    TABLES.clear()
    yield TestClient(app), factory
    registry._connectors.clear()
    registry._connectors.update(saved)
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()
    reset_auth_rate_limiter()


def _paths(factory: Any) -> set[str]:
    with factory() as s:
        return {r.path for r in s.execute(select(Resource)).scalars() if r.kind != "database"}


def test_rescan_picks_up_tables_the_first_scan_did_not_see(client: tuple[TestClient, Any]) -> None:
    http, factory = client
    put = http.put(
        f"/admin/ext/sync/datasource_account/{DS}", json={"hash": HASH, "spec": SPEC}, headers=ADMIN
    )
    assert put.status_code == 200, put.text
    assert _paths(factory) == set()

    TABLES.append("admin_logs")
    # replaying the same hash is a no-op: it never rescans
    http.put(
        f"/admin/ext/sync/datasource_account/{DS}", json={"hash": HASH, "spec": SPEC}, headers=ADMIN
    )
    assert _paths(factory) == set()

    r = http.post(f"/admin/ext/sync/datasource_account/{DS}/rescan", headers=ADMIN)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ok"
    assert any(p.endswith("admin_logs") for p in _paths(factory))


def test_rescan_of_an_unknown_datasource_is_404_and_admin_only(
    client: tuple[TestClient, Any],
) -> None:
    http, _ = client
    assert http.post(f"/admin/ext/sync/datasource_account/{DS}/rescan").status_code == 401
    r = http.post(f"/admin/ext/sync/datasource_account/{DS}/rescan", headers=ADMIN)
    assert r.status_code == 404
