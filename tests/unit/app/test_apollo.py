import json
import os
from urllib.error import URLError

import pytest

from adg.app import apollo


class _Response:
    def __init__(self, payload: object) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_ide_launch_uses_dev_and_production_does_not(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADG_APOLLO_ENV", raising=False)
    monkeypatch.delenv("ADG_ENV", raising=False)
    monkeypatch.setattr(apollo.sys, "modules", {})
    apollo.enable_for_ide_launch()
    assert os.environ["ADG_APOLLO_ENV"] == "dev"

    monkeypatch.delenv("ADG_APOLLO_ENV")
    monkeypatch.setenv("ADG_ENV", "production")
    apollo.enable_for_ide_launch()
    assert "ADG_APOLLO_ENV" not in os.environ


def test_unset_profile_does_not_call_apollo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADG_APOLLO_ENV", raising=False)
    called = False

    def boom(url: str, timeout: int) -> object:
        nonlocal called
        called = True
        raise AssertionError(url)

    monkeypatch.setattr(apollo, "urlopen", boom)
    apollo.reset_for_tests()
    apollo.load_apollo()
    assert called is False


def test_dev_profile_fills_missing_env_and_keeps_existing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADG_APOLLO_ENV", "dev")
    monkeypatch.setenv("ADG_SECRET_KEY", "already-set-value")

    def fake_open(url: str, timeout: int) -> _Response:
        assert timeout == apollo._TIMEOUT_SECONDS
        if url.endswith("/services/config"):
            assert url.startswith("http://172.30.10.48:8080/")
            return _Response([{"homepageUrl": "http://config.internal:8080/"}])
        assert url == "http://config.internal:8080/configs/sql-gw/default/application"
        return _Response(
            {
                "configurations": {
                    "ADG_SECRET_KEY": "from-apollo",
                    "ADG_CONTROL_PLANE_DATABASE_URL": "mysql+pymysql://db/adg_cp",
                    "SQLGW_ADMIN_KEY_SHA256": "a" * 64,
                    "ignored": 1,
                }
            }
        )

    monkeypatch.setattr(apollo, "urlopen", fake_open)
    apollo.reset_for_tests()
    apollo.load_apollo()
    assert os_get("ADG_SECRET_KEY") == "already-set-value"
    assert os_get("ADG_CONTROL_PLANE_DATABASE_URL") == "mysql+pymysql://db/adg_cp"
    assert os_get("SQLGW_ADMIN_KEY_SHA256") == "a" * 64
    apollo.load_apollo()


def test_unreachable_apollo_fails_without_leaking_the_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADG_APOLLO_ENV", "pro")

    def fake_open(url: str, timeout: int) -> object:
        raise URLError("secret-body-should-not-surface")

    monkeypatch.setattr(apollo, "urlopen", fake_open)
    apollo.reset_for_tests()
    with pytest.raises(RuntimeError, match="sql-gw/application") as raised:
        apollo.load_apollo()
    assert "secret-body" not in str(raised.value)


def os_get(name: str) -> str | None:
    return os.environ.get(name)
