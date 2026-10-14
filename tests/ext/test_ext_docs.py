"""N05: ``/docs``, ``/redoc`` and ``/openapi.json`` are unauthenticated; off unless explicitly enabled."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from adg.app.main import create_app
from adg.connectors.registry import get_connector_registry
from adg_ext.config import get_ext_settings

PAGES = ("/docs", "/redoc", "/openapi.json")


@pytest.fixture(autouse=True)
def fresh_settings() -> Iterator[None]:
    # enabling the extension registers its connectors in the process-wide registry: restore it
    registry = get_connector_registry()
    saved = dict(registry._connectors)
    get_ext_settings.cache_clear()
    yield
    registry._connectors.clear()
    registry._connectors.update(saved)
    get_ext_settings.cache_clear()


def client_for(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, **env: str
) -> TestClient:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    get_ext_settings.cache_clear()
    return TestClient(create_app(session_factory=session_factory))


def test_docs_are_closed_by_default_when_the_extension_is_on(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ADG_EXT_ENABLE_DOCS", raising=False)
    client = client_for(session_factory, monkeypatch, ADG_EXT_ENABLED="true")
    for page in PAGES:
        r = client.get(page)
        assert r.status_code == 404, page
        # nothing of the schema leaks into the 404
        assert "openapi" not in r.text.lower() and "swagger" not in r.text.lower()
    assert client.get("/health").status_code == 200
    # the API itself is unaffected: it still answers (and still refuses unauthenticated calls)
    assert client.get("/admin/ext/sync/role").status_code == 401


def test_docs_can_be_enabled_explicitly(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    client = client_for(
        session_factory, monkeypatch, ADG_EXT_ENABLED="true", ADG_EXT_ENABLE_DOCS="true"
    )
    for page in PAGES:
        assert client.get(page).status_code == 200, page
    assert "/admin/ext/dry-run" in client.get("/openapi.json").text


@pytest.mark.parametrize("value", ["false", "0", "no"])
def test_explicit_off_values_keep_docs_closed(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    client = client_for(
        session_factory, monkeypatch, ADG_EXT_ENABLED="true", ADG_EXT_ENABLE_DOCS=value
    )
    for page in PAGES:
        assert client.get(page).status_code == 404, page


def test_an_invalid_switch_value_refuses_to_start_instead_of_opening_the_docs(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ADG_EXT_ENABLED", "true")
    monkeypatch.setenv("ADG_EXT_ENABLE_DOCS", "maybe")
    get_ext_settings.cache_clear()
    with pytest.raises(ValueError):
        create_app(session_factory=session_factory)


def test_upstream_behaviour_is_unchanged_when_the_extension_is_off(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ADG_EXT_ENABLED", raising=False)
    monkeypatch.delenv("ADG_EXT_ENABLE_DOCS", raising=False)
    client = client_for(session_factory, monkeypatch)
    for page in PAGES:
        assert client.get(page).status_code == 200, page
