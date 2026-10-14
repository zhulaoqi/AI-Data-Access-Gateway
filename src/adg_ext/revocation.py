"""Revocation list reader (PA-6, ADR-0008).

The management service publishes the SHA-256 of every revoked, expired or disabled credential.
Authentication consults a locally cached copy refreshed at most every ``ttl`` seconds; a failed
refresh keeps the last list (the synced credential state remains the final authority). Newly
learned revocations kill that credential's queued and running requests.
"""

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx

from adg_ext.config import get_ext_settings

logger = logging.getLogger(__name__)
_MAX_PAGES = 50


class RevocationCache:
    def __init__(
        self,
        url: str,
        token: str,
        *,
        ttl: float = 5.0,
        timeout: float = 2.0,
        client: httpx.Client | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url
        self._token = token
        self._ttl = ttl
        self._timeout = timeout
        self._client = client
        self._clock = clock
        self._hashes: set[str] = set()
        self._version: int | None = None
        self._next_due = 0.0
        self._started = clock()
        self._last_success: float | None = None
        self._lock = threading.Lock()
        self._refreshing = threading.Lock()
        self.on_new: Callable[[set[str]], None] | None = None

    @property
    def enabled(self) -> bool:
        return bool(self._url)

    def poll_age_seconds(self) -> float:
        """Seconds since the last successful pull (since creation when there was none yet)."""

        with self._lock:
            reference = self._last_success if self._last_success is not None else self._started
        return max(0.0, self._clock() - reference)

    def is_revoked(self, key_hash: str) -> bool:
        if not self.enabled:
            return False
        if self._clock() >= self._next_due:
            self.refresh()
        with self._lock:
            return key_hash in self._hashes

    def refresh(self) -> set[str]:
        """Pull the list; returns hashes that were not known before. Never raises."""

        if not self.enabled or not self._refreshing.acquire(blocking=False):
            return set()
        try:
            return self._pull()
        finally:
            self._refreshing.release()

    def _pull(self) -> set[str]:
        client = self._client or httpx.Client(timeout=self._timeout)
        added: set[str] = set()
        try:
            for _ in range(_MAX_PAGES):
                with self._lock:
                    since = self._version
                params = {"since": since} if since is not None else None
                response = client.get(
                    self._url,
                    params=params,
                    headers={"Authorization": f"Bearer {self._token}"},
                )
                response.raise_for_status()
                data: dict[str, Any] = response.json().get("data") or {}
                entries = {str(e["hash"]) for e in data.get("entries") or [] if e.get("hash")}
                with self._lock:
                    previous = set(self._hashes)
                    if data.get("full"):
                        self._hashes = set(entries)
                    else:
                        self._hashes |= entries
                    added |= self._hashes - previous
                    self._version = int(data["version"]) if "version" in data else self._version
                if not data.get("hasMore"):
                    break
            with self._lock:
                self._last_success = self._clock()
            self._next_due = self._clock() + self._ttl
        except Exception as error:
            logger.warning("revocation refresh failed: %s", type(error).__name__)
            # retry soon, but not on every request
            self._next_due = self._clock() + min(self._ttl, 1.0)
        finally:
            if self._client is None:
                client.close()
        if added and self.on_new is not None:
            try:
                self.on_new(added)
            except Exception:
                logger.warning("revocation callback failed", exc_info=False)
        return added


_cache: RevocationCache | None = None
_cache_lock = threading.Lock()


def get_cache() -> RevocationCache:
    global _cache
    with _cache_lock:
        if _cache is None:
            s = get_ext_settings()
            _cache = RevocationCache(
                s.revocation_url,
                s.revocation_token,
                ttl=s.revocation_ttl_seconds,
                timeout=s.revocation_timeout_seconds,
            )
        return _cache


def reset_cache(cache: RevocationCache | None = None) -> None:
    """Replace the process cache (tests, app start)."""

    global _cache
    with _cache_lock:
        _cache = cache


def start_poller(cache: RevocationCache, interval: float) -> threading.Thread | None:
    """Poll in the background so revocations also stop requests of otherwise idle clients."""

    if not cache.enabled:
        return None

    def loop() -> None:
        while True:
            cache.refresh()
            time.sleep(interval)

    thread = threading.Thread(target=loop, name="adg-ext-revocation", daemon=True)
    thread.start()
    return thread
