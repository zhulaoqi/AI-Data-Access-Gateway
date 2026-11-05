"""Hot-cache contract: a miss loads once, a refresh replaces the copy, Redis errors fall back."""

from typing import Any

from adg.runtime_cache import match_table_paths, refresh, remember


class _MemoryRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.fail_set = False
        self.fail_get = False

    def get(self, key: str) -> str | None:
        if self.fail_get:
            raise ConnectionError("down")
        return self.store.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        del ex
        if self.fail_set:
            raise ConnectionError("down")
        self.store[key] = value

    def delete(self, key: str) -> None:
        self.store.pop(key, None)


def test_remember_loads_once_then_serves_the_copy(monkeypatch: Any) -> None:
    client = _MemoryRedis()
    monkeypatch.setattr("adg.runtime_cache.get_client", lambda: client)
    calls = {"n": 0}

    def load() -> list[str]:
        calls["n"] += 1
        return ["a"]

    assert remember("policies", load) == ["a"]
    assert remember("policies", load) == ["a"]
    assert calls["n"] == 1
    assert "{sqlgw}:hot:policies" in client.store


def test_empty_list_is_a_hit(monkeypatch: Any) -> None:
    client = _MemoryRedis()
    monkeypatch.setattr("adg.runtime_cache.get_client", lambda: client)
    calls = {"n": 0}

    def load() -> list[str]:
        calls["n"] += 1
        return []

    assert remember("tables:ds", load) == []
    assert remember("tables:ds", load) == []
    assert calls["n"] == 1


def test_refresh_replaces_before_returning(monkeypatch: Any) -> None:
    client = _MemoryRedis()
    monkeypatch.setattr("adg.runtime_cache.get_client", lambda: client)
    remember("policies", lambda: ["old"])
    refresh("policies", lambda: ["new"])
    assert remember("policies", lambda: ["unused"]) == ["new"]


def test_failed_refresh_drops_the_stale_copy(monkeypatch: Any) -> None:
    client = _MemoryRedis()
    monkeypatch.setattr("adg.runtime_cache.get_client", lambda: client)
    remember("policies", lambda: ["old"])

    def explode() -> list[str]:
        raise RuntimeError("db")

    refresh("policies", explode)
    assert "{sqlgw}:hot:policies" not in client.store
    assert remember("policies", lambda: ["fresh"]) == ["fresh"]


def test_broken_payload_is_deleted_and_reloaded(monkeypatch: Any) -> None:
    client = _MemoryRedis()
    client.store["{sqlgw}:hot:policies"] = "not-json"
    monkeypatch.setattr("adg.runtime_cache.get_client", lambda: client)
    assert remember("policies", lambda: ["fresh"]) == ["fresh"]
    assert client.store["{sqlgw}:hot:policies"] != "not-json"


def test_redis_read_error_falls_back_to_the_loader(monkeypatch: Any) -> None:
    client = _MemoryRedis()
    client.fail_get = True
    monkeypatch.setattr("adg.runtime_cache.get_client", lambda: client)
    assert remember("policies", lambda: ["db"]) == ["db"]


def test_match_keeps_the_single_active_table() -> None:
    index = [
        {
            "id": "db",
            "parent_id": None,
            "kind": "relational_database",
            "path": "sales",
            "status": "active",
        },
        {
            "id": "live",
            "parent_id": "db",
            "kind": "relational_table",
            "path": "sales.orders",
            "status": "active",
        },
        {
            "id": "gone",
            "parent_id": "db",
            "kind": "relational_table",
            "path": "sales.orders_old",
            "status": "disabled",
        },
    ]
    matched = match_table_paths(index, ["orders", "orders_old", ""])
    assert [row["id"] for row in matched] == ["live"]


def test_match_drops_a_table_under_a_disabled_parent() -> None:
    index = [
        {
            "id": "db",
            "parent_id": None,
            "kind": "relational_database",
            "path": "sales",
            "status": "disabled",
        },
        {
            "id": "t",
            "parent_id": "db",
            "kind": "relational_table",
            "path": "sales.orders",
            "status": "active",
        },
    ]
    assert match_table_paths(index, ["orders"]) == []


def test_match_skips_ambiguous_paths() -> None:
    index = [
        {"id": "a", "kind": "relational_table", "path": "one.orders", "status": "active"},
        {"id": "b", "kind": "relational_view", "path": "two.orders", "status": "active"},
    ]
    assert match_table_paths(index, ["orders"]) == []
