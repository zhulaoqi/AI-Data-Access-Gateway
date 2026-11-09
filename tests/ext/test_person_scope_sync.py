"""person_scope sync keeps the per-table shape and the shared-list shape apart."""

import json

from sqlalchemy import select

from adg_ext.disclosure import redis_key, resolve_scope
from adg_ext.models import ExtSyncObject
from adg_ext.sync import SyncService


class _CasRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.store.get(key)

    def eval(self, _script: str, _numkeys: int, key: str, payload: str, at: str) -> int:
        current = self.store.get(key)
        new_at = int(at)
        if current:
            seen = json.loads(current).get("at")
            if seen is not None and int(seen) > new_at:
                return 0
        self.store[key] = payload
        return 1


def _tables(open_id: str, at: int = 20) -> dict:
    return {
        "dimensionId": "dim_sync",
        "openId": open_id,
        "values": [],
        "tables": [
            {"database": "dataeye", "table": "product", "values": ["1", "3"]},
            {"database": "dataeye", "table": "bi_event", "values": ["9"]},
        ],
        "updatedAt": at,
    }


def _shared(open_id: str, at: int = 10, values: list[str] | None = None) -> dict:
    return {
        "dimensionId": "dim_sync",
        "openId": open_id,
        "values": ["1", "3", "5", "8"] if values is None else values,
        "updatedAt": at,
    }


def _name(open_id: str) -> str:
    return f"gw:ps:dim_sync:{open_id}"


def _spec(db_session, open_id: str) -> dict:
    row = db_session.execute(
        select(ExtSyncObject).where(ExtSyncObject.name == _name(open_id))
    ).scalar_one()
    return json.loads(row.spec_json)


def test_per_table_sync_writes_tables_and_keeps_an_older_shared_list_out(db_session, monkeypatch) -> None:
    redis = _CasRedis()
    monkeypatch.setattr("adg_ext.redis_share.get_client", lambda: redis)
    service = SyncService(db_session)
    service.put("person_scope", _name("ou_a"), "a" * 64, _tables("ou_a"))

    body = json.loads(redis.get(redis_key("dim_sync", "ou_a")) or "")
    assert body == {"v": 1, "at": 20, "tables": _tables("ou_a")["tables"]}
    stored = _spec(db_session, "ou_a")
    assert stored["values"] == []
    assert stored["tables"] == _tables("ou_a")["tables"]
    assert stored["updatedAt"] == 20

    service.put("person_scope", _name("ou_a"), "b" * 64, _shared("ou_a"))
    assert _spec(db_session, "ou_a")["updatedAt"] == 20
    assert "values" not in json.loads(redis.get(redis_key("dim_sync", "ou_a")) or "")
    scope = resolve_scope(
        "dim_sync",
        "ou_a",
        redis_get=redis.get,
        local_get=lambda: ["1", "3", "5", "8"],
        now=0,
    )
    assert scope is not None
    assert scope["tables"][("dataeye", "bi_event")] == ["9"]


def test_a_newer_shared_list_replaces_per_table_scope(db_session, monkeypatch) -> None:
    redis = _CasRedis()
    monkeypatch.setattr("adg_ext.redis_share.get_client", lambda: redis)
    service = SyncService(db_session)
    service.put("person_scope", _name("ou_b"), "c" * 64, _tables("ou_b"))
    service.put("person_scope", _name("ou_b"), "d" * 64, _shared("ou_b", 30, ["7"]))

    body = json.loads(redis.get(redis_key("dim_sync", "ou_b")) or "")
    assert body["values"] == ["7"]
    assert "tables" not in body
    assert _spec(db_session, "ou_b")["values"] == ["7"]
    assert "tables" not in _spec(db_session, "ou_b")
    scope = resolve_scope("dim_sync", "ou_b", redis_get=redis.get, local_get=lambda: None, now=0)
    assert scope == {"values": ["7"]}


def test_a_shared_list_sync_still_has_no_tables(db_session, monkeypatch) -> None:
    redis = _CasRedis()
    monkeypatch.setattr("adg_ext.redis_share.get_client", lambda: redis)
    SyncService(db_session).put("person_scope", _name("ou_c"), "e" * 64, _shared("ou_c", 11))
    body = json.loads(redis.get(redis_key("dim_sync", "ou_c")) or "")
    assert body["values"] == ["1", "3", "5", "8"]
    assert "tables" not in body
    assert "tables" not in _spec(db_session, "ou_c")
