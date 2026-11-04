"""Only GET /mcp/metrics is public. Admin, sync, audit and MCP calls still require a key."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from adg.app.auth_rate_limit import reset_auth_rate_limiter
from adg.app.main import create_app
from adg.app.settings import get_settings
from adg.control_plane.db import create_engine_from_url, create_session_factory
from adg.control_plane.models import Base
from adg.control_plane.services.api_key_service import create_api_key
from adg_ext.config import get_ext_settings
from adg_ext.pipeline import reset_admission
from adg_ext import revocation


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("ADG_EXT_ENABLED", "true")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("ADG_CONTROL_PLANE_DATABASE_URL", f"sqlite:///{tmp_path / 'cp.db'}")
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    reset_auth_rate_limiter()
    reset_admission()
    revocation.reset_cache()
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'cp.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        create_api_key(session, name="admin", scopes=["admin"], plaintext="adg_admin_test_key")
        session.commit()
    app = create_app(session_factory=factory)
    try:
        yield TestClient(app)
    finally:
        get_settings.cache_clear()
        get_ext_settings.cache_clear()
        reset_auth_rate_limiter()
        reset_admission()
        revocation.reset_cache()


def test_only_the_metrics_path_is_public(client: TestClient) -> None:
    metrics = client.get("/mcp/metrics")
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")
    assert "adg_ext_query_total" in metrics.text
    assert "password" not in metrics.text.lower()

    denied = [
        ("GET", "/mcp/metrics/extra"),
        ("POST", "/mcp/metrics"),
        ("GET", "/mcp"),
        ("POST", "/mcp"),
        ("GET", "/admin/ext/metrics"),
        ("GET", "/admin/ext/metrics/prometheus"),
        ("GET", "/admin/ext/sync/user"),
        ("PUT", "/admin/ext/sync/user/gw:user:1"),
        ("GET", "/ext/audit/events"),
        ("GET", "/admin/datasources"),
        ("POST", "/api/tools/execute_query"),
    ]
    for method, path in denied:
        response = client.request(method, path)
        assert response.status_code == 401, (method, path, response.status_code, response.text)

    opened = client.get(
        "/admin/ext/metrics/prometheus",
        headers={"X-ADG-API-Key": "adg_admin_test_key"},
    )
    assert opened.status_code == 200
    assert "adg_ext_query_total" in opened.text
