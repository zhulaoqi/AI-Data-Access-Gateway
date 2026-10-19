from __future__ import annotations

import hashlib
import importlib
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Protocol, cast

from adg.app.settings import Settings, get_settings

RATE_LIMIT_DETAIL = "Too many authentication failures"
_MISSING_KEY_SENTINEL = "<missing>"
_REDIS_RECORD_FAILURE_SCRIPT = """
if redis.call('EXISTS', KEYS[2]) == 1 then
    return 1
end
local failures = redis.call('INCR', KEYS[1])
if failures == 1 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
if failures >= tonumber(ARGV[2]) then
    redis.call('SETEX', KEYS[2], tonumber(ARGV[3]), 1)
    redis.call('DEL', KEYS[1])
    return 1
end
return 0
"""


class RedisClient(Protocol):
    """Minimal synchronous Redis API used by the auth failure limiter."""

    def eval(self, script: str, numkeys: int, *keys_and_args: object) -> object: ...

    def exists(self, key: str) -> int: ...

    def delete(self, *keys: str) -> object: ...


@dataclass
class MemoryFailureBucket:
    failures: int
    window_expires_at: float
    blocked_until: float | None = None


class AuthRateLimiter:
    """Track API-key authentication failures without exposing key existence."""

    def __init__(self, settings: Settings, redis_client: RedisClient | None = None) -> None:
        self._settings = settings
        self._redis_client = redis_client
        self._memory_buckets: OrderedDict[str, MemoryFailureBucket] = OrderedDict()
        self._lock = threading.Lock()

    def check_auth_rate_limited(
        self,
        raw_api_key: str | None,
        client_identifier: str | None = None,
    ) -> bool:
        """Return whether the credential or client failure bucket is blocked."""

        if not self._settings.auth_rate_limit_enabled:
            return False
        fingerprints = self._bucket_fingerprints(raw_api_key, client_identifier)
        if self._redis_client is not None:
            return any(self._redis_is_blocked(fingerprint) for fingerprint in fingerprints)
        return any(self._memory_is_blocked(fingerprint) for fingerprint in fingerprints)

    def record_auth_failure(
        self,
        raw_api_key: str | None,
        client_identifier: str | None = None,
    ) -> bool:
        """Record one failure and return whether the caller should now be blocked."""

        if not self._settings.auth_rate_limit_enabled:
            return False
        blocked = False
        for fingerprint in self._bucket_fingerprints(raw_api_key, client_identifier):
            if self._redis_client is not None:
                blocked = self._redis_record_failure(fingerprint) or blocked
            else:
                blocked = self._memory_record_failure(fingerprint) or blocked
        return blocked

    def record_auth_success(
        self,
        raw_api_key: str | None,
        client_identifier: str | None = None,
    ) -> None:
        """Clear only the credential bucket after successful authentication."""

        if not self._settings.auth_rate_limit_enabled:
            return
        fingerprint = self._fingerprint("key", raw_api_key)
        if self._redis_client is not None:
            client = self._require_redis_client()
            client.delete(self._failure_key(fingerprint), self._block_key(fingerprint))
            return
        with self._lock:
            self._memory_buckets.pop(fingerprint, None)

    def _memory_is_blocked(self, fingerprint: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._memory_buckets.get(fingerprint)
            if bucket is None:
                return False
            if bucket.blocked_until is not None:
                if bucket.blocked_until > now:
                    self._memory_buckets.move_to_end(fingerprint)
                    return True
                self._memory_buckets.pop(fingerprint, None)
                return False
            if bucket.window_expires_at <= now:
                self._memory_buckets.pop(fingerprint, None)
                return False
            self._memory_buckets.move_to_end(fingerprint)
            return False

    def _memory_record_failure(self, fingerprint: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._memory_buckets.get(fingerprint)
            if bucket is not None and bucket.blocked_until is not None:
                if bucket.blocked_until > now:
                    self._memory_buckets.move_to_end(fingerprint)
                    return True
                self._memory_buckets.pop(fingerprint, None)
                bucket = None
            if bucket is None or bucket.window_expires_at <= now:
                if bucket is not None:
                    self._memory_buckets.pop(fingerprint, None)
                self._prune_memory_buckets(now)
                while (
                    len(self._memory_buckets)
                    >= self._settings.auth_rate_limit_memory_max_buckets
                ):
                    self._memory_buckets.popitem(last=False)
                bucket = MemoryFailureBucket(
                    failures=0,
                    window_expires_at=now + self._settings.auth_rate_limit_window_seconds,
                )
                self._memory_buckets[fingerprint] = bucket
            else:
                self._memory_buckets.move_to_end(fingerprint)
            bucket.failures += 1
            if bucket.failures >= self._settings.auth_rate_limit_max_failures:
                bucket.blocked_until = now + self._settings.auth_rate_limit_block_seconds
                return True
            return False

    def _prune_memory_buckets(self, now: float) -> None:
        """Discard expired buckets before enforcing the configured memory bound."""

        expired = [
            fingerprint
            for fingerprint, bucket in self._memory_buckets.items()
            if (
                bucket.blocked_until is not None
                and bucket.blocked_until <= now
                or bucket.blocked_until is None
                and bucket.window_expires_at <= now
            )
        ]
        for fingerprint in expired:
            self._memory_buckets.pop(fingerprint, None)

    def _redis_is_blocked(self, fingerprint: str) -> bool:
        client = self._require_redis_client()
        return bool(client.exists(self._block_key(fingerprint)))

    def _redis_record_failure(self, fingerprint: str) -> bool:
        client = self._require_redis_client()
        return bool(
            client.eval(
                _REDIS_RECORD_FAILURE_SCRIPT,
                2,
                self._failure_key(fingerprint),
                self._block_key(fingerprint),
                self._settings.auth_rate_limit_window_seconds,
                self._settings.auth_rate_limit_max_failures,
                self._settings.auth_rate_limit_block_seconds,
            )
        )

    def _require_redis_client(self) -> RedisClient:
        if self._redis_client is None:
            if self._settings.auth_rate_limit_redis_url is None:
                raise RuntimeError("ADG_AUTH_RATE_LIMIT_REDIS_URL is required for redis storage")
            self._redis_client = create_redis_client(self._settings.auth_rate_limit_redis_url)
        return self._redis_client

    def _bucket_fingerprints(
        self,
        raw_api_key: str | None,
        client_identifier: str | None,
    ) -> list[str]:
        fingerprints = [self._fingerprint("key", raw_api_key)]
        if client_identifier not in {None, ""}:
            fingerprints.append(self._fingerprint("client", client_identifier))
        return fingerprints

    def _fingerprint(self, namespace: str, value: str | None) -> str:
        safe_value = value if value not in {None, ""} else _MISSING_KEY_SENTINEL
        return hashlib.sha256(f"{namespace}:{safe_value}".encode()).hexdigest()

    def _failure_key(self, fingerprint: str) -> str:
        return f"adg:auth-rate-limit:{{{fingerprint}}}:failure"

    def _block_key(self, fingerprint: str) -> str:
        return f"adg:auth-rate-limit:{{{fingerprint}}}:block"


def create_redis_client(redis_url: str) -> RedisClient:
    """Create a Redis client lazily so memory-only deployments need no Redis package."""

    try:
        redis_module = importlib.import_module("redis")
    except ImportError as exc:  # pragma: no cover - depends on optional deployment package
        raise RuntimeError("Install redis to use ADG_AUTH_RATE_LIMIT_STORAGE=redis") from exc
    client = redis_module.Redis.from_url(redis_url, decode_responses=True)
    return cast(RedisClient, client)


_auth_rate_limiter: AuthRateLimiter | None = None
_auth_rate_limiter_lock = threading.Lock()


def get_auth_rate_limiter() -> AuthRateLimiter:
    """Return the shared limiter configured from current settings."""

    global _auth_rate_limiter
    with _auth_rate_limiter_lock:
        if _auth_rate_limiter is None:
            settings = get_settings()
            redis_client = None
            if settings.auth_rate_limit_storage == "redis" and settings.auth_rate_limit_redis_url:
                redis_client = create_redis_client(settings.auth_rate_limit_redis_url)
            else:
                from adg_ext.redis_share import get_client

                redis_client = get_client()
            _auth_rate_limiter = AuthRateLimiter(settings, redis_client)
        return _auth_rate_limiter


def reset_auth_rate_limiter() -> None:
    """Reset cached limiter state for tests and settings reloads."""

    global _auth_rate_limiter
    with _auth_rate_limiter_lock:
        _auth_rate_limiter = None


def check_auth_rate_limited(
    raw_api_key: str | None,
    client_identifier: str | None = None,
) -> bool:
    return get_auth_rate_limiter().check_auth_rate_limited(raw_api_key, client_identifier)


def record_auth_failure(
    raw_api_key: str | None,
    client_identifier: str | None = None,
) -> bool:
    return get_auth_rate_limiter().record_auth_failure(raw_api_key, client_identifier)


def record_auth_success(
    raw_api_key: str | None,
    client_identifier: str | None = None,
) -> None:
    get_auth_rate_limiter().record_auth_success(raw_api_key, client_identifier)
