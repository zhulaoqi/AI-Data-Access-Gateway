"""Load the company Apollo namespace into this process.

The app is ``sql-gw``, namespace ``application``. An IDE or ``python -m`` launch
reads DEV. Production and kind set ``ADG_ENV=production`` and do not. Pytest does
not. ``ADG_APOLLO_ENV=pro`` selects PRO. A variable already present in the
environment is left as-is.
"""

from __future__ import annotations

import json
import os
import sys
from urllib.error import URLError
from urllib.request import urlopen

APP_ID = "sql-gw"
NAMESPACE = "application"
CLUSTER = "default"
METAS = {
    "dev": "http://172.30.10.48:8080",
    "pro": "http://confcenter.spellso.com",
}
_TIMEOUT_SECONDS = 5
_loaded = False


def enable_for_ide_launch() -> None:
    """Point an IDE or module launch at DEV. Pytest and production processes stay off."""

    if os.environ.get("ADG_APOLLO_ENV", "").strip():
        return
    if os.environ.get("ADG_ENV", "").strip().lower() == "production":
        return
    if "pytest" in sys.modules:
        return
    os.environ["ADG_APOLLO_ENV"] = "dev"


def load_apollo() -> None:
    """Fetch Apollo once when ``ADG_APOLLO_ENV`` selects DEV or PRO."""

    global _loaded
    if _loaded:
        return
    selected = _selection()
    if selected is None:
        return
    meta = METAS[selected]
    try:
        configurations = _configurations(meta)
    except (URLError, TimeoutError, OSError, ValueError) as error:
        raise RuntimeError(f"无法从 Apollo 读取 {APP_ID}/{NAMESPACE}（{selected}）") from error
    for key, value in configurations.items():
        if not key or key in os.environ or not isinstance(value, str):
            continue
        os.environ[key] = value
    _loaded = True


def reset_for_tests() -> None:
    """Allow another load in the same process. Tests only."""

    global _loaded
    _loaded = False


def _selection() -> str | None:
    raw = os.environ.get("ADG_APOLLO_ENV", "").strip().lower()
    if raw in ("", "off", "local"):
        return None
    if raw in ("test", "fat"):
        raw = "dev"
    if raw in ("prod", "production"):
        raw = "pro"
    if raw not in METAS:
        raise RuntimeError("ADG_APOLLO_ENV 只能是 dev 或 pro")
    return raw


def _configurations(meta: str) -> dict[str, str]:
    services = _get_json(_meta_url(meta) + "/services/config")
    if not isinstance(services, list) or not services:
        raise ValueError("config service list is empty")
    homepage = ""
    for item in services:
        if isinstance(item, dict) and isinstance(item.get("homepageUrl"), str):
            homepage = item["homepageUrl"]
            break
    if not homepage:
        raise ValueError("config service homepage missing")
    payload = _get_json(
        homepage.rstrip("/") + f"/configs/{APP_ID}/{CLUSTER}/{NAMESPACE}"
    )
    configurations = payload.get("configurations") if isinstance(payload, dict) else None
    if not isinstance(configurations, dict):
        raise ValueError("configurations missing")
    return {str(key): value for key, value in configurations.items() if isinstance(value, str)}


def _meta_url(meta: str) -> str:
    if meta.startswith("http://") or meta.startswith("https://"):
        return meta.rstrip("/")
    return "http://" + meta.rstrip("/")


def _get_json(url: str) -> object:
    with urlopen(url, timeout=_TIMEOUT_SECONDS) as response:
        body = response.read().decode("utf-8")
    return json.loads(body)
