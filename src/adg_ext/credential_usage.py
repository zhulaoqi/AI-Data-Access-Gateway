"""Tell the management service that a gateway MCP credential just ran a query.

One POST per credential per minute, off the query thread. JDBC usage is reported by the entry:
a delegated query authenticates with the entry key, whose name is not ``gw:cred:``.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.control_plane.models.api_key import ApiKey
from adg_ext.config import get_ext_settings

PREFIX = "gw:cred:"
_INTERVAL = timedelta(minutes=1)
_lock = threading.Lock()
_names: dict[str, str] = {}
_recent: dict[str, datetime] = {}
_poster: Callable[[str], None] | None = None
_LOG = logging.getLogger(__name__)


def reset() -> None:
    global _poster
    with _lock:
        _names.clear()
        _recent.clear()
        _poster = None


def set_poster(poster: Callable[[str], None] | None) -> None:
    global _poster
    with _lock:
        _poster = poster


def usage_url(revocation_url: str) -> str:
    """The usage endpoint sits next to the revocation list the executor already calls."""

    base = revocation_url.split("?", 1)[0].rstrip("/")
    if base.endswith("/revocations"):
        return base + "/usage"
    return ""


def note_api_key(session: Session, api_key_id: str | None) -> None:
    """Look up the key name once and report a ``gw:cred:`` id. Never raises into the query path."""
    if not api_key_id:
        return
    try:
        name = _cached_name(session, api_key_id)
        if name:
            note_named(name, datetime.now(UTC))
    except Exception:
        _LOG.info("credential usage note skipped")


def note_named(name: str, now: datetime) -> None:
    if not name.startswith(PREFIX):
        return
    cred = name[len(PREFIX) :]
    if not cred or len(cred) > 32:
        return
    with _lock:
        prev = _recent.get(cred)
        if prev is not None and now - prev < _INTERVAL:
            return
        _recent[cred] = now
        poster = _poster
    if poster is not None:
        poster(cred)
        return
    _post_async(cred)


def _post_async(credential_id: str) -> None:
    settings = get_ext_settings()
    url = usage_url(settings.revocation_url)
    token = settings.revocation_token
    if not url or not token:
        return

    def send() -> None:
        try:
            httpx.post(
                url,
                json={"ids": [credential_id]},
                headers={"Authorization": "Bearer " + token},
                timeout=settings.revocation_timeout_seconds,
            )
        except Exception:
            _LOG.info("credential usage report skipped")

    threading.Thread(target=send, name="credential-usage", daemon=True).start()


def _cached_name(session: Session, api_key_id: str) -> str:
    with _lock:
        cached = _names.get(api_key_id)
    if cached is not None:
        return cached
    row = session.scalar(select(ApiKey).where(ApiKey.id == api_key_id))
    name = "" if row is None or not row.name else row.name
    with _lock:
        _names[api_key_id] = name
    return name
