import pytest

from adg_ext.redis_share import (
    MCP_DISABLED,
    MCP_HIT,
    MCP_MISS,
    MCP_UNAVAILABLE,
    Share,
    get_client,
    reset_client,
)


def test_share_is_a_noop_without_redis(monkeypatch):
    monkeypatch.delenv("redis.host", raising=False)
    monkeypatch.delenv("REDIS_HOST", raising=False)
    reset_client()
    assert get_client() is None
    share = Share()
    assert share.try_slot("user:a", 1, "m") is True
    assert share.circuit_open("ds") is False
    assert share.forward_cancel("req", None, None) is None
    share.release_slot("user:a", "m")
    share.note_failure("ds", 5, 30)
    share.note_success("ds")
    share.register_run("req")
    share.clear_run("req")
    session_id = "a" * 32
    share.save_mcp_session(session_id)
    assert share.read_mcp_session(session_id) == MCP_DISABLED
    share.clear_mcp_session(session_id)


class _Redis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.ttl: int | None = None
        self.fail = False

    def get(self, key: str) -> str | None:
        if self.fail:
            raise ConnectionError("down")
        return self.store.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> bool:
        if self.fail:
            raise ConnectionError("down")
        self.store[key] = value
        self.ttl = ex
        return True

    def delete(self, key: str) -> int:
        if self.fail:
            raise ConnectionError("down")
        return 1 if self.store.pop(key, None) is not None else 0


def test_mcp_session_is_shared_across_callers(monkeypatch):
    redis = _Redis()
    monkeypatch.setattr("adg_ext.redis_share.get_client", lambda: redis)
    share = Share()
    session_id = "b" * 32
    assert share.read_mcp_session(session_id) == MCP_MISS
    share.save_mcp_session(session_id)
    assert redis.ttl == 24 * 60 * 60
    assert share.read_mcp_session(session_id) == MCP_HIT
    share.clear_mcp_session(session_id)
    assert share.read_mcp_session(session_id) == MCP_MISS
    share.save_mcp_session("bad id")
    assert redis.store == {}


def test_mcp_session_read_failure_is_not_a_miss(monkeypatch):
    redis = _Redis()
    redis.fail = True
    monkeypatch.setattr("adg_ext.redis_share.get_client", lambda: redis)
    share = Share()
    assert share.read_mcp_session("c" * 32) == MCP_UNAVAILABLE
    share.save_mcp_session("c" * 32)
    share.clear_mcp_session("c" * 32)


def test_redis_client_checks_idle_connections(monkeypatch):
    pytest.importorskip("redis")
    monkeypatch.setenv("redis.host", "127.0.0.1")
    monkeypatch.setenv("redis.port", "6399")
    monkeypatch.delenv("REDIS_HOST", raising=False)
    reset_client()
    try:
        client = get_client()
        assert client is not None
        kwargs = client.connection_pool.connection_kwargs
        assert kwargs["socket_keepalive"] is True
        assert kwargs["health_check_interval"] == 30
        retry = client.get_retry()
        assert retry is not None
        assert retry.get_retries() == 1
    finally:
        reset_client()
