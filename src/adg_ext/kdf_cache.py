"""Process-local cache of PBKDF2 outputs used to open datasource secret envelopes (PER-1).

Every query reads the datasource config, which decrypts the stored datasource password. The v2
envelope derives its Fernet key with PBKDF2-HMAC-SHA256 (``ADG_SECRET_KDF_ITERATIONS``, 390 000 by
default), roughly 45-130 ms of CPU per query on a laptop, and nothing in the request path caches it
(profiling: exactly one PBKDF2 per query, none for API-key or delegated authentication, which are a
plain SHA-256 lookup).

The derivation is a pure function of ``(master secret, salt, iterations)``, so memoising it changes
no authorisation outcome: the Fernet token itself (HMAC, timestamp, padding) is still verified on
every decrypt, the iteration count is still range-checked before the cache is consulted, and the
count is never lowered. What it does hold is key material, so:

* the cache key is an HMAC (per-process random key) of the inputs, never the secret or the salt;
* values are the derived keys only; nothing is ever logged or exposed through an API;
* the cache is bounded (LRU, ``ADG_EXT_KDF_CACHE_SIZE``) and entries expire
  (``ADG_EXT_KDF_CACHE_TTL_SECONDS``); size 0 disables it;
* concurrent misses for one key are collapsed into a single derivation;
* nothing here depends on credential or grant state: revoking a key, deleting a user, an expiry or a
  tombstone are decided before and independently of this cache, so none of them can be delayed by
  it. Rotating the datasource password produces a new envelope (new random salt) and so a new
  cache key; rotating the master secret changes the key too.

Each worker process has its own cache (nothing is shared or persisted); the first query per
datasource in a fresh process pays one derivation.
"""

import hashlib
import hmac
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from adg_ext.config import get_ext_settings


@dataclass
class _Entry:
    derived: bytes
    expires_at: float


class _Flight:
    """One derivation in progress; waiters block on ``done`` and then re-read the cache."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.derived: bytes | None = None


class KdfCache:
    def __init__(
        self,
        *,
        max_entries: int,
        ttl_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max = max(0, max_entries)
        self._ttl = max(0.0, ttl_seconds)
        self._clock = clock
        self._mac_key = os.urandom(32)  # makes cache keys unguessable and not a hash of the secret
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._flights: dict[str, _Flight] = {}
        self.hits = 0
        self.misses = 0

    @property
    def enabled(self) -> bool:
        return self._max > 0 and self._ttl > 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def _key(self, secret: str, salt: bytes, iterations: int) -> str:
        mac = hmac.new(self._mac_key, digestmod=hashlib.sha256)
        for part in (secret.encode(), salt, str(iterations).encode()):
            mac.update(len(part).to_bytes(4, "big"))  # unambiguous framing
            mac.update(part)
        return mac.hexdigest()

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def derive(
        self,
        *,
        secret: str,
        salt: bytes,
        iterations: int,
        compute: Callable[..., bytes],
    ) -> bytes:
        """The derived key, from the cache when still valid; ``compute`` is the real PBKDF2."""

        if not self.enabled:
            return compute(secret=secret, salt=salt, iterations=iterations)
        key = self._key(secret, salt, iterations)
        while True:
            with self._lock:
                entry = self._entries.get(key)
                now = self._clock()
                if entry is not None and entry.expires_at > now:
                    self._entries.move_to_end(key)
                    self.hits += 1
                    return entry.derived
                if entry is not None:
                    del self._entries[key]
                flight = self._flights.get(key)
                leader = flight is None
                if flight is None:
                    flight = _Flight()
                    self._flights[key] = flight
                    self.misses += 1
            if not leader:
                flight.done.wait()
                if flight.derived is not None:
                    return flight.derived
                continue  # the leader failed: try again (and derive here)
            try:
                derived = compute(secret=secret, salt=salt, iterations=iterations)
                flight.derived = derived
                with self._lock:
                    self._entries[key] = _Entry(derived, self._clock() + self._ttl)
                    self._entries.move_to_end(key)
                    while len(self._entries) > self._max:
                        self._entries.popitem(last=False)
                return derived
            finally:
                with self._lock:
                    self._flights.pop(key, None)
                flight.done.set()


_cache: KdfCache | None = None
_cache_lock = threading.Lock()


def get_kdf_cache() -> KdfCache:
    global _cache
    with _cache_lock:
        if _cache is None:
            s = get_ext_settings()
            _cache = KdfCache(max_entries=s.kdf_cache_size, ttl_seconds=s.kdf_cache_ttl_seconds)
        return _cache


def reset_kdf_cache(cache: KdfCache | None = None) -> None:
    """Replace the process cache (tests, settings changes)."""

    global _cache
    with _cache_lock:
        _cache = cache


def derive_key(
    *,
    secret: str,
    salt: bytes,
    iterations: int,
    compute: Callable[..., bytes],
) -> bytes:
    """Hook for ``adg.shared.crypto``: cached when the extension is on, plain PBKDF2 otherwise."""

    settings = get_ext_settings()
    if not settings.enabled:
        return compute(secret=secret, salt=salt, iterations=iterations)
    return get_kdf_cache().derive(secret=secret, salt=salt, iterations=iterations, compute=compute)
