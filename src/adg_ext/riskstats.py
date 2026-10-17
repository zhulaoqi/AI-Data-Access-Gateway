"""Per process counters behind ``GET /ext/audit/aggregates`` for non-audit events (PA-8).

Authentication failures and blocked attempts can arrive at attack rates; writing a database row for
each would turn an attack into a database load. They are counted here instead, in minute buckets
keyed by (client address, grant, reason), and only the key and counts are kept: **never** the API
key, its hash or any request content. Retention is bounded (default 26 hours) and so is the number
of distinct keys per bucket. With several executor replicas each one reports its own counters.
"""

import threading
import time
from collections import defaultdict
from collections.abc import Callable

_MAX_KEYS_PER_BUCKET = 5000
OVERFLOW_IP = "overflow"

AUTH_REASONS = ("invalid", "revoked", "expired", "disabled")
BLOCK_REASONS = ("source_blocked", "grant_frozen")


class RiskCounters:
    def __init__(self, retention_seconds: int, clock: Callable[[], float] = time.time) -> None:
        self._retention = retention_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._auth: dict[int, dict[tuple[str, str, str], int]] = defaultdict(dict)
        self._blocked: dict[int, dict[tuple[str, str, str], int]] = defaultdict(dict)

    def _add(
        self,
        store: dict[int, dict[tuple[str, str, str], int]],
        ip: str | None,
        grant_id: str | None,
        reason: str,
    ) -> None:
        now = self._clock()
        minute = int(now // 60)
        key = (ip or "unknown", grant_id or "", reason)
        with self._lock:
            bucket = store[minute]
            if key not in bucket and len(bucket) >= _MAX_KEYS_PER_BUCKET:
                key = (OVERFLOW_IP, "", reason)
            bucket[key] = bucket.get(key, 0) + 1
            horizon = minute - self._retention // 60
            for old in [m for m in store if m < horizon]:
                del store[old]

    def auth_failed(self, ip: str | None, grant_id: str | None, reason: str) -> None:
        self._add(self._auth, ip, grant_id, reason)

    def blocked(self, ip: str | None, grant_id: str | None, reason: str) -> None:
        self._add(self._blocked, ip, grant_id, reason)

    def _sum(
        self,
        store: dict[int, dict[tuple[str, str, str], int]],
        start_epoch: float,
        end_epoch: float,
    ) -> list[dict[str, object]]:
        first, last = int(start_epoch // 60), int(end_epoch // 60)
        totals: dict[tuple[str, str, str], int] = {}
        with self._lock:
            for minute, bucket in store.items():
                if first <= minute <= last:
                    for key, count in bucket.items():
                        totals[key] = totals.get(key, 0) + count
        return [
            {"clientIp": ip, "grantId": grant or None, "reason": reason, "count": count}
            for (ip, grant, reason), count in sorted(totals.items(), key=lambda kv: -kv[1])
        ]

    def auth_failures(self, start_epoch: float, end_epoch: float) -> list[dict[str, object]]:
        return self._sum(self._auth, start_epoch, end_epoch)

    def blocked_attempts(self, start_epoch: float, end_epoch: float) -> list[dict[str, object]]:
        return self._sum(self._blocked, start_epoch, end_epoch)


_counters: RiskCounters | None = None
_lock = threading.Lock()


def get_counters() -> RiskCounters:
    global _counters
    with _lock:
        if _counters is None:
            from adg_ext.config import get_ext_settings

            _counters = RiskCounters(get_ext_settings().risk_counter_retention_seconds)
        return _counters


def reset_counters(counters: RiskCounters | None = None) -> None:
    global _counters
    with _lock:
        _counters = counters
