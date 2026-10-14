"""The PBKDF2 cache (PER-1) against the live pipeline: it saves the derivation, and it can never
delay a revocation, a deletion, an expiry or a tombstone (those are decided before and independently
of it), even while the cache is warm.
"""

from typing import Any

import httpx
import pytest
from tests.ext_integration.conftest import Gateway
from tests.ext_integration.test_extint_delegated import body, entry
from tests.ext_integration.test_extint_mysql import provision, query, sha

from adg.control_plane.models.api_key import ApiKey
from adg.shared import crypto
from adg_ext import kdf_cache, revocation
from adg_ext.app import get_admission

SQL = "SELECT id FROM shop.orders ORDER BY id"


@pytest.fixture
def pbkdf2_calls(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    kdf_cache.reset_kdf_cache()
    calls: list[int] = []
    real = crypto.derive_pbkdf2_fernet_key

    def counting(**kwargs: Any) -> bytes:
        calls.append(int(kwargs["iterations"]))
        return real(**kwargs)

    monkeypatch.setattr(crypto, "derive_pbkdf2_fernet_key", counting)
    return calls


def test_one_derivation_serves_many_queries_without_lowering_the_iterations(
    gateway: Gateway, mysql_seed: dict[str, str], pbkdf2_calls: list[int]
) -> None:
    key = provision(gateway, mysql_seed)
    pbkdf2_calls.clear()
    kdf_cache.reset_kdf_cache()
    for _ in range(8):
        assert query(gateway, key, SQL)["status"] == "success"
    assert len(pbkdf2_calls) == 1
    # the stored envelope's own iteration count is used, never a reduced one
    assert pbkdf2_calls[0] == 390_000
    assert kdf_cache.get_kdf_cache().hits >= 7


def test_the_delegated_path_shares_the_same_derivation(
    gateway: Gateway, mysql_seed: dict[str, str], pbkdf2_calls: list[int]
) -> None:
    provision(gateway, mysql_seed)
    h = entry(gateway)
    pbkdf2_calls.clear()
    kdf_cache.reset_kdf_cache()
    for i in range(4):
        r = gateway.client.post(
            "/ext/delegated/query", json=body(SQL, requestId=f"r{i}"), headers=h
        )
        assert r.json()["status"] == "success", r.text
    assert len(pbkdf2_calls) == 1


def test_a_disabled_cache_derives_every_time_and_still_works(
    gateway: Gateway,
    mysql_seed: dict[str, str],
    pbkdf2_calls: list[int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = provision(gateway, mysql_seed)
    monkeypatch.setenv("ADG_EXT_KDF_CACHE_SIZE", "0")
    from adg_ext.config import get_ext_settings

    get_ext_settings.cache_clear()
    kdf_cache.reset_kdf_cache()
    pbkdf2_calls.clear()
    for _ in range(3):
        assert query(gateway, key, SQL)["status"] == "success"
    assert len(pbkdf2_calls) == 3
    assert len(kdf_cache.get_kdf_cache()) == 0


def warm(gateway: Gateway, key: str) -> None:
    assert query(gateway, key, SQL)["status"] == "success"
    assert len(kdf_cache.get_kdf_cache()) == 1  # the cache is hot for what follows


def test_deleting_a_credential_is_immediate_while_the_cache_is_warm(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed)
    warm(gateway, key)
    assert gateway.delete("credential", "gw:cred:c1").status_code == 204
    assert gateway.tool(key, "list_datasources").status_code == 401
    assert (
        gateway.tool(
            key, "execute_query", datasource_id="x", resource_ids=[], query=SQL
        ).status_code
        == 401
    )
    # replaying the synced credential is a tombstone conflict and does not bring the key back
    replay = gateway.sync(
        "credential",
        "gw:cred:c1",
        {
            "user": "gw:user:g1",
            "channel": "mcp",
            "keyHash": sha(key),
            "keyPrefix": key[:8],
            "expiresAt": 4_102_444_800_000,
        },
    )
    assert replay.status_code == 409 and replay.json()["detail"] == "credential_revoked"
    assert gateway.tool(key, "list_datasources").status_code == 401


def test_deleting_a_user_is_immediate_while_the_cache_is_warm(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed)
    h = entry(gateway)
    warm(gateway, key)
    assert gateway.delete("user", "gw:user:g1").status_code == 204
    assert gateway.tool(key, "list_datasources").status_code in {401, 403}
    r = gateway.client.post("/ext/delegated/query", json=body(SQL), headers=h)
    assert r.status_code == 403 and r.json()["detail"] == "grant_not_active"
    # a replayed user is a tombstone too
    replay = gateway.sync(
        "user",
        "gw:user:g1",
        {
            "grantId": "g1",
            "principalName": "Alice",
            "role": "gw:role:p1:v1",
            "params": {"tenant_id": 7},
            "expiresAt": 4_102_444_800_000,
        },
    )
    assert replay.status_code == 409 and replay.json()["detail"] == "user_revoked"


def test_an_expired_grant_is_refused_immediately_while_the_cache_is_warm(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed)
    h = entry(gateway)
    warm(gateway, key)
    r = gateway.client.post("/ext/delegated/query", json=body(SQL), headers=h)
    assert r.json()["status"] == "success"
    expired = gateway.sync(
        "user",
        "gw:user:g1",
        {
            "grantId": "g1",
            "principalName": "Alice",
            "role": "gw:role:p1:v1",
            "params": {"tenant_id": 7},
            "expiresAt": 1_000,
        },
    )
    assert expired.status_code == 200
    r = gateway.client.post("/ext/delegated/query", json=body(SQL), headers=h)
    assert r.status_code == 403 and r.json()["detail"] == "grant_expired"


def test_an_expired_credential_is_refused_immediately_while_the_cache_is_warm(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import update

    key = provision(gateway, mysql_seed)
    warm(gateway, key)
    with gateway.factory() as session:
        session.execute(
            update(ApiKey)
            .where(ApiKey.key_hash == sha(key))
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()
    assert gateway.tool(key, "list_datasources").status_code == 401


def test_a_revocation_entry_takes_effect_at_the_next_poll_while_the_cache_is_warm(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    """The cache adds no delay on top of the revocation list's own 5 s refresh interval."""

    from sqlalchemy import select

    key = provision(gateway, mysql_seed)
    warm(gateway, key)
    state: dict[str, Any] = {"entries": [], "version": 1, "full": True}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "version": state["version"],
                    "full": state["full"],
                    "hasMore": False,
                    "entries": state["entries"],
                },
            },
        )

    now = [0.0]
    cache = revocation.RevocationCache(
        "http://mgmt/revocations",
        "gwr_token",
        ttl=5,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: now[0],
    )

    def on_new(hashes: set[str]) -> None:
        with gateway.factory() as session:
            for kid in session.execute(
                select(ApiKey.id).where(ApiKey.key_hash.in_(hashes))
            ).scalars():
                get_admission().revoke(kid)

    cache.on_new = on_new
    revocation.reset_cache(cache)
    assert gateway.tool(key, "list_datasources").status_code == 200
    now[0] = 5.0  # exactly the refresh interval
    state.update(
        entries=[{"hash": sha(key), "reason": "revoked", "at": "x", "version": 2}],
        version=2,
        full=False,
    )
    assert gateway.tool(key, "list_datasources").status_code == 401
    assert len(kdf_cache.get_kdf_cache()) == 1  # the cache was hot the whole time
    # and other credentials of the same datasource keep working off the same cached derivation
    other = provision(gateway, mysql_seed, suffix="2")
    assert query(gateway, other, SQL)["status"] == "success"


def test_rotating_the_datasource_account_uses_the_new_envelope(
    gateway: Gateway, mysql_seed: dict[str, str], pbkdf2_calls: list[int]
) -> None:
    """A re-synced datasource account is stored in a new envelope (new random salt): it gets its own
    derivation instead of reusing the cached key of the old one."""

    from tests.ext_integration.conftest import mysql_conn

    conn = mysql_conn()
    with conn.cursor() as c:
        c.execute("DROP USER IF EXISTS 'gw_ro2'@'%'")
        c.execute("CREATE USER 'gw_ro2'@'%' IDENTIFIED BY 'ropw2'")
        c.execute("GRANT SELECT ON shop.* TO 'gw_ro2'@'%'")
    conn.close()
    key = provision(gateway, mysql_seed)
    pbkdf2_calls.clear()
    kdf_cache.reset_kdf_cache()
    warm(gateway, key)
    assert len(pbkdf2_calls) == 1
    rotated = gateway.sync(
        "datasource_account",
        "gw:ds:1",
        {
            "label": "shop",
            "engine": "mysql",
            "dialect": "mysql",
            "host": "127.0.0.1",
            "port": 33306,
            "database": "shop",
            "username": "gw_ro2",
            "password": "ropw2",
        },
    )
    assert rotated.status_code == 200, rotated.text
    pbkdf2_calls.clear()
    for _ in range(3):
        assert query(gateway, key, SQL)["status"] == "success"
    assert (
        len(pbkdf2_calls) <= 1
    )  # one derivation for the new salt (a scan on sync may have cached it)
    conn = mysql_conn()
    with conn.cursor() as c:
        c.execute("DROP USER IF EXISTS 'gw_ro2'@'%'")
    conn.close()
