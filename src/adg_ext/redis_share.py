"""Cross-process state for executor replicas.

Redis is optional. Without ``redis.host`` every call keeps the in-process behavior.
A Redis error on a limit does the same: one replica keeps enforcing its own limit
instead of refusing every query. MCP sessions are the exception: a read failure is
reported to the caller so it can retry, and is never treated as "no such session".
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

PREFIX = "{sqlgw}"
_LEASE_MS = 300_000
# Refreshed on every request that uses the session. Long enough that an open Cursor
# connection still resolves after a quiet stretch; short enough that a deleted
# process does not leave a permanent key.
_MCP_SESSION_TTL_SECONDS = 24 * 60 * 60
_MCP_SESSION_ID = re.compile(r"^[\x21-\x7E]{1,128}$")
# read_mcp_session results. "unavailable" is a Redis failure, not a missing key.
MCP_DISABLED = "disabled"
MCP_HIT = "hit"
MCP_MISS = "miss"
MCP_UNAVAILABLE = "unavailable"

_ACQUIRE = """
local now = tonumber(ARGV[1])
local lease = tonumber(ARGV[2])
local maxn = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) >= maxn then return 0 end
redis.call('ZADD', KEYS[1], now + lease, ARGV[4])
redis.call('PEXPIRE', KEYS[1], lease + 30000)
return 1
"""

_FAIL = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1])) end
if n >= tonumber(ARGV[2]) then
  redis.call('SET', KEYS[2], '1', 'EX', tonumber(ARGV[3]))
  redis.call('DEL', KEYS[1])
end
return n
"""

_client: Any = None
_client_lock = threading.Lock()
_client_ready = False


def get_client() -> Any:
    """Shared client for db selected by ``redis.db`` (default 1). None when unconfigured."""

    global _client, _client_ready
    with _client_lock:
        if _client_ready:
            return _client
        _client_ready = True
        host = os.environ.get("redis.host") or os.environ.get("REDIS_HOST") or ""
        if not host:
            return None
        try:
            import redis
            from redis.backoff import ExponentialBackoff
            from redis.retry import Retry
        except ImportError:
            logger.warning("redis.host is set but the redis package is not installed")
            return None
        port = int(os.environ.get("redis.port") or os.environ.get("REDIS_PORT") or 6379)
        db = int(os.environ.get("redis.db") or os.environ.get("REDIS_DB") or 1)
        password = os.environ.get("redis.password") or os.environ.get("REDIS_PASSWORD") or None
        # One retry covers a dead pooled connection. The pool checks idle
        # connections before use so a replica does not keep writing to a socket
        # Redis already closed. Timeouts stay short: a down Redis must not stall
        # the query path.
        _client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password or None,
            decode_responses=True,
            socket_timeout=0.4,
            socket_connect_timeout=0.4,
            socket_keepalive=True,
            health_check_interval=30,
            retry=Retry(ExponentialBackoff(cap=0.2, base=0.05), retries=1),
        )
        return _client


def reset_client() -> None:
    global _client, _client_ready
    with _client_lock:
        _client = None
        _client_ready = False


def self_owner() -> str:
    host = os.environ.get("HOSTIP") or os.environ.get("POD_IP") or "127.0.0.1"
    port = os.environ.get("ADG_BACKEND_PORT") or "8000"
    return f"{host}|{port}"


class Share:
    def try_slot(self, name: str, limit: int, member: str) -> bool:
        client = get_client()
        if client is None:
            return True
        try:
            ok = client.eval(
                _ACQUIRE,
                1,
                f"{PREFIX}:slot:{name}",
                int(time.time() * 1000),
                _LEASE_MS,
                max(1, limit),
                member,
            )
        except Exception:
            logger.warning("redis slot acquire failed; using the local limit")
            return True
        return bool(ok)

    def release_slot(self, name: str, member: str) -> None:
        client = get_client()
        if client is None:
            return
        try:
            client.zrem(f"{PREFIX}:slot:{name}", member)
        except Exception:
            logger.warning("redis slot release failed; the lease expires on its own")

    def circuit_open(self, datasource_id: str) -> bool:
        client = get_client()
        if client is None:
            return False
        try:
            return bool(client.exists(f"{PREFIX}:circuit:open:{datasource_id}"))
        except Exception:
            return False

    def note_failure(self, datasource_id: str, threshold: int, open_seconds: float) -> None:
        client = get_client()
        if client is None:
            return
        try:
            client.eval(
                _FAIL,
                2,
                f"{PREFIX}:circuit:fail:{datasource_id}",
                f"{PREFIX}:circuit:open:{datasource_id}",
                60,
                max(1, threshold),
                max(1, int(open_seconds)),
            )
        except Exception:
            logger.warning("redis circuit update failed")

    def note_success(self, datasource_id: str) -> None:
        client = get_client()
        if client is None:
            return
        try:
            client.delete(
                f"{PREFIX}:circuit:fail:{datasource_id}",
                f"{PREFIX}:circuit:open:{datasource_id}",
            )
        except Exception:
            logger.warning("redis circuit reset failed")

    def register_run(self, request_id: str, lease_seconds: int = 300) -> None:
        if not request_id:
            return
        client = get_client()
        if client is None:
            return
        try:
            client.set(f"{PREFIX}:run:{request_id}", self_owner(), ex=lease_seconds)
        except Exception:
            logger.warning("redis run register failed")

    def clear_run(self, request_id: str) -> None:
        client = get_client()
        if client is None or not request_id:
            return
        try:
            client.delete(f"{PREFIX}:run:{request_id}")
        except Exception:
            return

    def save_mcp_session(self, session_id: str) -> None:
        """Remember a Streamable HTTP session so any replica can serve it.

        The value is only a marker. The protocol state is recreated per request;
        what has to be shared is that this session id was established.
        """

        if not _mcp_session_id_ok(session_id):
            return
        client = get_client()
        if client is None:
            return
        try:
            client.set(self._mcp_key(session_id), "1", ex=_MCP_SESSION_TTL_SECONDS)
        except Exception:
            logger.warning("redis mcp session save failed")

    def read_mcp_session(self, session_id: str) -> str:
        """Return hit, miss, disabled (no Redis), or unavailable (Redis error)."""

        if not _mcp_session_id_ok(session_id):
            return MCP_MISS
        client = get_client()
        if client is None:
            return MCP_DISABLED
        try:
            found = client.get(self._mcp_key(session_id))
        except Exception:
            logger.warning("redis mcp session read failed")
            return MCP_UNAVAILABLE
        return MCP_HIT if found else MCP_MISS

    def clear_mcp_session(self, session_id: str) -> None:
        if not _mcp_session_id_ok(session_id):
            return
        client = get_client()
        if client is None:
            return
        try:
            client.delete(self._mcp_key(session_id))
        except Exception:
            logger.warning("redis mcp session delete failed")

    @staticmethod
    def _mcp_key(session_id: str) -> str:
        return f"{PREFIX}:mcp:{session_id}"

    def forward_cancel(
        self,
        request_id: str,
        authorization: str | None,
        hop: str | None,
    ) -> int | None:
        """Return the remote cancel count, or None to cancel locally."""

        if hop == "1":
            return None
        client = get_client()
        if client is None:
            return None
        try:
            owner = client.get(f"{PREFIX}:run:{request_id}")
        except Exception:
            return None
        if not owner or owner == self_owner() or "|" not in owner:
            return None
        host, port = owner.rsplit("|", 1)
        url = f"http://{host}:{port}/ext/delegated/query/{request_id}"
        headers = {"X-Sqlgw-Cancel-Hop": "1"}
        if authorization:
            headers["Authorization"] = authorization
        request = urllib.request.Request(url, method="DELETE", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            logger.warning("forwarded cancel to %s failed", owner)
            return None
        cancelled = body.get("cancelled", 0)
        return int(cancelled) if isinstance(cancelled, int) else 0


_share = Share()


def get_share() -> Share:
    return _share


def _mcp_session_id_ok(session_id: str) -> bool:
    return bool(session_id) and _MCP_SESSION_ID.fullmatch(session_id) is not None
