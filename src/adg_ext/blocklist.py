"""Source blocklist reader and enforcement (PA-8, ADR-0027).

The management service publishes a versioned, pull-only feed of entries: IP/CIDR ``deny`` and
``allow`` entries (an ``allow`` match always wins over ``deny``) and frozen grants. This keeps
a local copy refreshed every few seconds and answers two questions on the hot path, without any
network call: *is this source address blocked?* and *is this grant frozen?*

Safety properties (each covered by tests):

* The last good snapshot is kept when the management service is unreachable or answers garbage; an
  error never empties the list.
* A **full** snapshot that would drop more than the configured share of current entries is refused
  (``refused``), unless an operator forces it (``refresh(force=True)``).
* The snapshot is persisted (atomic write, mode 0600) and loaded at start, so a restart works while
  the management service is down. A persisted file that cannot be read is ignored.
* Expired entries are ignored locally by their own ``expiresAt``; no round trip is needed.
* A request without a resolvable client address is **not** blocked (MCP behind a proxy that does not
  forward the source); frozen grants still apply.
"""

import ipaddress
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from adg_ext.config import get_ext_settings

logger = logging.getLogger(__name__)
_MAX_PAGES = 200

ALLOW = "allow"
DENY = "deny"
SOURCE_BLOCKED = "source_blocked"
GRANT_FROZEN = "grant_frozen"


@dataclass(frozen=True)
class Entry:
    id: str
    kind: str  # "ip" | "grant"
    direction: str  # "deny" | "allow" (ip entries)
    cidr: str | None
    grant_id: str | None
    expires_at: float | None  # epoch seconds, None = permanent

    def expired(self, now: float) -> bool:
        return self.expires_at is not None and self.expires_at <= now

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "direction": self.direction,
            "cidr": self.cidr,
            "grantId": self.grant_id,
            "expiresAt": self.expires_at,
        }


def _parse_expires(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        return number / 1000.0 if number > 1e11 else number  # epoch ms or seconds
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def parse_entry(raw: dict[str, Any]) -> Entry | None:
    """One feed or snapshot entry; ``None`` for anything malformed (never raises)."""

    try:
        entry_id = str(raw["id"])
        kind = str(raw.get("kind") or "")
        expires = _parse_expires(raw.get("expiresAt"))
        if kind == "grant":
            grant = str(raw.get("grantId") or "")
            if not grant:
                return None
            return Entry(entry_id, kind, DENY, None, grant, expires)
        if kind == "ip":
            direction = str(raw.get("direction") or "")
            if direction not in (ALLOW, DENY):
                return None
            network = ipaddress.ip_network(str(raw["cidr"]), strict=False)
            if isinstance(network, ipaddress.IPv6Network) and network.network_address.ipv4_mapped:
                return None  # entries are published canonically; a mapped network is ambiguous
            return Entry(entry_id, kind, direction, str(network), None, expires)
    except (KeyError, ValueError, TypeError):
        return None
    return None


class BlocklistCache:
    def __init__(
        self,
        url: str,
        token: str,
        *,
        poll: float = 5.0,
        timeout: float = 2.0,
        snapshot_path: str = "",
        consumer: str = "executor",
        shrink_ratio: float = 0.5,
        client: httpx.Client | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self._url = url
        self._token = token
        self._poll = poll
        self._timeout = timeout
        self._path = snapshot_path
        self._consumer = consumer
        self._shrink_ratio = shrink_ratio
        self._client = client
        self._clock = clock
        self._wall = wall
        self._lock = threading.Lock()
        self._refreshing = threading.Lock()
        self._entries: dict[str, Entry] = {}
        self._version: int = 0
        self._ips: dict[tuple[int, int], dict[int, list[Entry]]] = {}
        self._frozen: dict[str, Entry] = {}
        self._started = clock()
        self._last_success: float | None = None
        self.refused = 0
        self.last_error: str | None = None
        self.blocked_total = 0
        self.frozen_total = 0
        self._load()

    # ---- state -------------------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        # 令牌是可选的 Secret 键：缺失时整个功能关闭（不拉取、不拦截），而不是带着空令牌反复 401
        return bool(self._url and self._token)

    @property
    def version(self) -> int:
        return self._version

    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def poll_age_seconds(self) -> float:
        with self._lock:
            reference = self._last_success if self._last_success is not None else self._started
        return max(0.0, self._clock() - reference)

    def has_frozen(self) -> bool:
        return bool(self._frozen)

    def _index(self, entries: dict[str, Entry]) -> None:
        ips: dict[tuple[int, int], dict[int, list[Entry]]] = {}
        frozen: dict[str, Entry] = {}
        for entry in entries.values():
            if entry.kind == "grant" and entry.grant_id:
                frozen[entry.grant_id] = entry
            elif entry.cidr:
                network = ipaddress.ip_network(entry.cidr)
                key = (network.version, network.prefixlen)
                ips.setdefault(key, {}).setdefault(int(network.network_address), []).append(entry)
        self._ips = ips
        self._frozen = frozen

    # ---- decisions (hot path, no I/O) --------------------------------------------------------

    def decide(self, ip: str | None) -> str | None:
        """``allow`` (an allow entry matches), ``deny`` or ``None``. Allow beats deny."""

        if not ip or not self._ips:
            return None
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        now = self._wall()
        bits = 32 if address.version == 4 else 128
        value = int(address)
        denied = False
        for (version, prefix), table in self._ips.items():
            if version != address.version:
                continue
            masked = value & (((1 << bits) - 1) ^ ((1 << (bits - prefix)) - 1))
            for entry in table.get(masked, ()):
                if entry.expired(now):
                    continue
                if entry.direction == ALLOW:
                    return ALLOW
                denied = True
        return DENY if denied else None

    def grant_frozen(self, grant_id: str | None) -> bool:
        if not grant_id or not self._frozen:
            return False
        entry = self._frozen.get(grant_id)
        return entry is not None and not entry.expired(self._wall())

    def blocked_source(self, ip: str | None) -> bool:
        return self.decide(ip) == DENY

    # ---- pulling -----------------------------------------------------------------------------

    def refresh(self, *, force: bool = False) -> bool:
        """Pull the feed. Returns True when the local list was updated. Never raises."""

        if not self.enabled or not self._refreshing.acquire(blocking=False):
            return False
        try:
            return self._pull(force)
        finally:
            self._refreshing.release()

    def _pull(self, force: bool) -> bool:
        client = self._client or httpx.Client(timeout=self._timeout)
        changed = False
        try:
            staged: dict[str, Entry] | None = None
            version = self._version
            full_seen = False
            for _ in range(_MAX_PAGES):
                params: dict[str, Any] = {"consumer": self._consumer}
                if version > 0 or staged is not None:
                    params["since"] = version
                response = client.get(
                    self._url,
                    params=params,
                    headers={"Authorization": f"Bearer {self._token}"},
                )
                response.raise_for_status()
                data = response.json().get("data")
                if not isinstance(data, dict) or "version" not in data:
                    raise ValueError("malformed_feed")
                items = data.get("items") or []
                if not isinstance(items, list):
                    raise ValueError("malformed_feed")
                if staged is None:
                    staged = dict(self._entries)
                if data.get("full") and not full_seen:
                    staged = {}
                    full_seen = True
                for item in items:
                    entry = parse_entry(item.get("entry") or {}) if isinstance(item, dict) else None
                    if entry is None:
                        continue
                    if item.get("op") == "remove":
                        staged.pop(entry.id, None)
                    else:
                        staged[entry.id] = entry
                version = int(data["version"])
                if not data.get("hasMore"):
                    break
            if staged is None:
                raise ValueError("empty_response")
            current = len(self._entries)
            if (
                full_seen
                and not force
                and current > 0
                and len(staged) < current * (1.0 - self._shrink_ratio)
            ):
                self.refused += 1
                self.last_error = "snapshot_shrink_refused"
                logger.warning(
                    "blocklist full snapshot refused: %d -> %d entries", current, len(staged)
                )
                return False
            self.last_error = None
            if staged == self._entries and version == self._version:
                self.mark_polled()
                return False
            with self._lock:
                self._entries = staged
                self._version = version
                self._index(staged)
                self._last_success = self._clock()
            self._persist()
            changed = True
        except Exception as error:
            self.last_error = type(error).__name__
            logger.warning("blocklist refresh failed: %s", type(error).__name__)
        finally:
            if self._client is None:
                client.close()
        return changed

    def mark_polled(self) -> None:
        """A successful pull that changed nothing still counts as fresh."""

        with self._lock:
            self._last_success = self._clock()

    # ---- persistence -------------------------------------------------------------------------

    def _persist(self) -> None:
        if not self._path:
            return
        body = json.dumps(
            {"version": self._version, "entries": [e.as_json() for e in self._entries.values()]},
            separators=(",", ":"),
        )
        directory = os.path.dirname(os.path.abspath(self._path)) or "."
        try:
            fd, tmp = tempfile.mkstemp(prefix=".blocklist-", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(body)
                os.chmod(tmp, 0o600)
                os.replace(tmp, self._path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        except OSError as error:
            logger.warning("blocklist snapshot not persisted: %s", type(error).__name__)

    def _load(self) -> None:
        if not self._path or not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as handle:
                data = json.load(handle)
            entries: dict[str, Entry] = {}
            for raw in data.get("entries") or []:
                entry = parse_entry(raw) if isinstance(raw, dict) else None
                if entry is not None:
                    entries[entry.id] = entry
            self._entries = entries
            self._version = int(data.get("version") or 0)
            self._index(entries)
        except (OSError, ValueError, TypeError, AttributeError) as error:
            logger.warning("blocklist snapshot ignored: %s", type(error).__name__)


_cache: BlocklistCache | None = None
_cache_lock = threading.Lock()


def get_cache() -> BlocklistCache:
    global _cache
    with _cache_lock:
        if _cache is None:
            s = get_ext_settings()
            _cache = BlocklistCache(
                s.blocklist_url,
                s.blocklist_token,
                poll=s.blocklist_poll_seconds,
                timeout=s.blocklist_timeout_seconds,
                snapshot_path=s.blocklist_snapshot_path,
                consumer=s.blocklist_consumer,
                shrink_ratio=s.blocklist_shrink_guard_ratio,
            )
        return _cache


def reset_cache(cache: BlocklistCache | None = None) -> None:
    global _cache
    with _cache_lock:
        _cache = cache


def start_poller(cache: BlocklistCache, interval: float) -> threading.Thread | None:
    if not cache.enabled:
        return None

    def loop() -> None:
        while True:
            cache.refresh()
            time.sleep(interval)

    thread = threading.Thread(target=loop, name="adg-ext-blocklist", daemon=True)
    thread.start()
    return thread
