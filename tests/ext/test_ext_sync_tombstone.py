"""K-3 and the replay risk: revoked credentials and deleted users are tombstones for the sync API."""

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from adg.app.auth_rate_limit import reset_auth_rate_limiter
from adg.app.main import create_app
from adg.app.settings import get_settings
from adg.connectors.registry import get_connector_registry
from adg.control_plane.db import create_engine_from_url, create_session_factory
from adg.control_plane.models import Base
from adg.control_plane.models.api_key import ApiKey
from adg.control_plane.models.directory import User, UserRole
from adg.control_plane.services.api_key_service import create_api_key
from adg_ext import pipeline, revocation
from adg_ext.config import get_ext_settings

ADMIN = {"X-ADG-API-Key": "adg_admin_tomb_key"}
SECRET = "plaintext-of-the-synced-credential"
KEY_HASH = hashlib.sha256(SECRET.encode()).hexdigest()
USER = "gw:user:g1"
CRED = "gw:cred:c1"
ROLE = "gw:role:p1:v1"


class Env:
    def __init__(self, client: TestClient, factory: Any) -> None:
        self.client = client
        self.factory = factory

    def put(self, kind: str, name: str, spec: dict[str, Any], hash_: str | None = None) -> Any:
        digest = hash_ or hashlib.sha256(repr(sorted(spec.items())).encode()).hexdigest()
        return self.client.put(
            f"/admin/ext/sync/{kind}/{name}", json={"hash": digest, "spec": spec}, headers=ADMIN
        )

    def delete(self, kind: str, name: str) -> Any:
        return self.client.delete(f"/admin/ext/sync/{kind}/{name}", headers=ADMIN)

    def reinstate(self, kind: str, name: str) -> Any:
        return self.client.post(f"/admin/ext/sync/{kind}/{name}/reinstate", headers=ADMIN)

    def user_spec(self, **extra: Any) -> dict[str, Any]:
        return {"grantId": "g1", "role": ROLE, "params": {}, "principalName": "p", **extra}

    def cred_spec(self, key_hash: str = KEY_HASH, **extra: Any) -> dict[str, Any]:
        return {"user": USER, "keyHash": key_hash, "channel": "api", **extra}

    def provision(self) -> None:
        assert self.put("role", ROLE, {"tables": []}).status_code == 200
        assert self.put("user", USER, self.user_spec()).status_code == 200
        assert self.put("credential", CRED, self.cred_spec()).status_code == 200

    def keys(self) -> list[ApiKey]:
        with self.factory() as s:
            return list(s.execute(select(ApiKey).where(ApiKey.name == CRED)).scalars())

    def key_authenticates(self) -> bool:
        r = self.client.get("/admin/api-keys", headers={"X-ADG-API-Key": SECRET})
        return r.status_code != 401  # 403 = authenticated with the wrong scope

    def user_row(self) -> User | None:
        with self.factory() as s:
            return s.execute(select(User).where(User.external_ref == USER)).scalar_one_or_none()

    def roles_of_user(self) -> int:
        with self.factory() as s:
            user = s.execute(select(User).where(User.external_ref == USER)).scalar_one()
            return len(list(s.execute(select(UserRole).where(UserRole.user_id == user.id))))


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    monkeypatch.setenv("ADG_EXT_ENABLED", "true")
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()
    reset_auth_rate_limiter()
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 't.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    registry = get_connector_registry()
    saved = dict(registry._connectors)
    with factory() as session:
        create_api_key(session, name="admin", scopes=["admin"], plaintext="adg_admin_tomb_key")
        session.commit()
    yield Env(TestClient(create_app(session_factory=factory)), factory)
    registry._connectors.clear()
    registry._connectors.update(saved)
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()
    reset_auth_rate_limiter()


def test_a_synced_credential_authenticates_until_it_is_deleted(env: Env) -> None:
    env.provision()
    assert env.key_authenticates()
    assert env.delete("credential", CRED).status_code == 204
    assert not env.key_authenticates()


def test_replaying_a_revoked_credential_answers_409_and_does_not_restore_it(env: Env) -> None:
    """K-3: used to be an HTTP 500 (unique key hash), now a stable 409 ``credential_revoked``."""

    env.provision()
    assert env.delete("credential", CRED).status_code == 204
    for _ in range(2):  # stable, not a one-off
        r = env.put("credential", CRED, env.cred_spec())
        assert r.status_code == 409, r.text
        assert r.json() == {"detail": "credential_revoked"}
    assert not env.key_authenticates()
    keys = env.keys()
    assert len(keys) == 1 and keys[0].status == "revoked"


def test_replaying_the_revoked_hash_under_another_name_is_refused_too(env: Env) -> None:
    env.provision()
    assert env.delete("credential", CRED).status_code == 204
    r = env.put("credential", "gw:cred:c2", env.cred_spec())
    assert r.status_code == 409 and r.json() == {"detail": "credential_revoked"}
    assert not env.key_authenticates()


def test_a_live_hash_cannot_be_claimed_by_another_credential(env: Env) -> None:
    env.provision()
    r = env.put("credential", "gw:cred:c2", env.cred_spec())
    assert r.status_code == 409 and r.json() == {"detail": "key_hash_conflict"}
    assert env.key_authenticates()


def test_updating_a_credential_to_a_taken_hash_is_a_409_not_a_500(env: Env) -> None:
    env.provision()
    other = hashlib.sha256(b"another-secret").hexdigest()
    assert env.put("credential", "gw:cred:c2", env.cred_spec(other)).status_code == 200
    r = env.put("credential", "gw:cred:c2", env.cred_spec(KEY_HASH, expiresAt=1))
    assert r.status_code == 409 and r.json() == {"detail": "key_hash_conflict"}


def test_an_update_never_revives_a_key_revoked_on_the_executor(env: Env) -> None:
    """A key revoked outside the sync (e.g. the executor's own admin API) stays revoked."""

    env.provision()
    with env.factory() as s:
        for key in s.execute(select(ApiKey).where(ApiKey.name == CRED)).scalars():
            key.status = "revoked"
        s.commit()
    assert not env.key_authenticates()
    r = env.put("credential", CRED, env.cred_spec(expiresAt=4102444800000))  # changed spec
    assert r.status_code == 409 and r.json() == {"detail": "credential_revoked"}
    assert not env.key_authenticates()
    assert [k.status for k in env.keys()] == ["revoked"]


def test_replaying_user_and_credential_after_a_user_delete_restores_nothing(env: Env) -> None:
    """Whole-grant revocation (credential, then user) followed by a replay of both."""

    env.provision()
    assert env.delete("credential", CRED).status_code == 204
    assert env.delete("user", USER).status_code == 204
    user = env.put("user", USER, env.user_spec())
    assert user.status_code == 409 and user.json() == {"detail": "user_revoked"}
    cred = env.put("credential", CRED, env.cred_spec())
    assert cred.status_code == 409  # the user object does not exist, so nothing can be attached
    assert not env.key_authenticates()
    row = env.user_row()
    assert row is not None and row.status == "disabled" and env.roles_of_user() == 0


def test_a_disabled_user_does_not_come_back_through_a_changed_replay(env: Env) -> None:
    env.provision()
    assert env.delete("user", USER).status_code == 204
    r = env.put("user", USER, env.user_spec(params={"tenant_id": 7}))
    assert r.status_code == 409 and r.json() == {"detail": "user_revoked"}
    row = env.user_row()
    assert row is not None and row.status == "disabled"
    assert env.roles_of_user() == 0


def test_reinstating_lifts_the_tombstone_explicitly(env: Env) -> None:
    env.provision()
    assert env.delete("credential", CRED).status_code == 204
    assert env.delete("user", USER).status_code == 204
    assert env.put("user", USER, env.user_spec()).status_code == 409

    # reinstating alone grants nothing: the user is active again but has no role
    assert env.reinstate("user", USER).json() == {"reinstated": True}
    assert env.roles_of_user() == 0
    assert not env.key_authenticates()
    assert env.reinstate("user", USER).json() == {"reinstated": False}  # idempotent

    assert env.put("user", USER, env.user_spec()).status_code == 200
    assert env.put("credential", CRED, env.cred_spec()).status_code == 409  # hash tombstone
    assert env.reinstate("credential", CRED).json() == {"reinstated": True}
    assert env.put("credential", CRED, env.cred_spec()).status_code == 200
    assert env.key_authenticates()


def test_reinstate_is_admin_only_and_validates_its_arguments(env: Env) -> None:
    env.provision()
    assert env.client.post(f"/admin/ext/sync/user/{USER}/reinstate").status_code == 401
    assert env.reinstate("role", ROLE).status_code == 422
    assert env.reinstate("user", "plain-name").status_code == 400
    assert env.reinstate("user", USER).json() == {"reinstated": False}  # live, not revoked
    assert env.reinstate("credential", "gw:cred:never-existed").json() == {"reinstated": False}
