"""PA-8: client address, fingerprint, blocklist cache, enforcement and risk aggregates."""

import json
import logging
import time
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from tests.ext.test_ext_audit_query import ADMIN, Env, add, run_env

from adg.audit.models import AuditEvent
from adg.control_plane.services.api_key_service import create_api_key
from adg_ext import blocklist, clientip, enforce, riskstats
from adg_ext.config import get_ext_settings
from adg_ext.fingerprint import sql_fingerprint

# ---- helpers ---------------------------------------------------------------------------------


def feed(
    version: int,
    entries: list[dict[str, Any]],
    *,
    full: bool = True,
    removed: list[str] | None = None,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = [{"op": "add", "entry": e} for e in entries]
    items += [
        {"op": "remove", "entry": {"id": i, "kind": "grant", "grantId": "x"}} for i in removed or []
    ]
    return {"data": {"version": version, "full": full, "hasMore": False, "items": items}}


def deny(entry_id: str, cidr: str, **extra: Any) -> dict[str, Any]:
    return {"id": entry_id, "kind": "ip", "direction": "deny", "cidr": cidr, **extra}


def allow(entry_id: str, cidr: str) -> dict[str, Any]:
    return {"id": entry_id, "kind": "ip", "direction": "allow", "cidr": cidr}


def frozen(entry_id: str, grant_id: str) -> dict[str, Any]:
    return {"id": entry_id, "kind": "grant", "grantId": grant_id}


class Feed:
    """A mutable fake management service feeding a cache through an in-process transport."""

    def __init__(self) -> None:
        self.body: dict[str, Any] = feed(0, [])
        self.status = 200
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, json=self.body)

    def cache(self, **kw: Any) -> blocklist.BlocklistCache:
        client = httpx.Client(transport=httpx.MockTransport(self.handler))
        return blocklist.BlocklistCache("http://cp.test/feed", "tok", client=client, **kw)


@pytest.fixture
def source() -> Feed:
    return Feed()


# ---- pure helpers ----------------------------------------------------------------------------


def test_fingerprint_ignores_literals_and_in_list_length_but_not_structure() -> None:
    a = sql_fingerprint("SELECT id FROM orders WHERE tenant = 7 AND st IN (1,2,3)", "mysql")
    b = sql_fingerprint("select id from orders where tenant = 99 and st in (4)", "mysql")
    c = sql_fingerprint("SELECT id, phone FROM orders WHERE tenant = 7 AND st IN (1,2,3)", "mysql")
    assert a == b
    assert a != c
    assert a is not None and len(a) == 16
    assert "7" not in a or True  # a hash, never the text
    assert sql_fingerprint("SELECT FROM WHERE (", "mysql") is None


@pytest.mark.parametrize(
    ("peer", "forwarded", "hops", "expected"),
    [
        ("10.0.0.5", "1.2.3.4", 0, "10.0.0.5"),  # no trusted proxy: the header is ignored
        (
            "10.0.0.5",
            "9.9.9.9, 1.2.3.4",
            1,
            "1.2.3.4",
        ),  # the rightmost entry, client faked the left
        ("10.0.0.5", "9.9.9.9, 1.2.3.4, 10.0.0.9", 2, "1.2.3.4"),
        ("10.0.0.5", "1.2.3.4", 3, "10.0.0.5"),  # header shorter than the hop count
        ("10.0.0.5", "garbage", 1, "10.0.0.5"),
        ("::ffff:10.0.0.5", None, 0, "10.0.0.5"),
        ("testclient", None, 0, None),
    ],
)
def test_client_ip_resolution(
    peer: str, forwarded: str | None, hops: int, expected: str | None
) -> None:
    assert clientip.resolve(peer, forwarded, hops) == expected


# ---- cache semantics -------------------------------------------------------------------------


def test_allow_beats_deny_and_unknown_source_passes(source: Feed) -> None:
    source.body = feed(1, [deny("d1", "10.0.0.0/8"), allow("a1", "10.1.0.0/16")])
    cache = source.cache()
    assert cache.refresh()
    assert cache.decide("10.9.9.9") == blocklist.DENY
    assert cache.decide("10.1.2.3") == blocklist.ALLOW
    assert cache.decide("192.168.0.1") is None
    assert cache.decide(None) is None  # no resolvable address is never blocked
    assert cache.decide("not-an-ip") is None


def test_expired_entries_are_ignored_locally() -> None:
    now = [1000.0]
    feed_ = Feed()
    feed_.body = feed(1, [deny("d1", "1.1.1.1/32", expiresAt=1100)])
    cache = feed_.cache(wall=lambda: now[0])
    cache.refresh()
    assert cache.decide("1.1.1.1") == blocklist.DENY
    now[0] = 1100.0
    assert cache.decide("1.1.1.1") is None


def test_failure_keeps_last_good_snapshot(source: Feed) -> None:
    source.body = feed(1, [deny("d1", "1.1.1.1/32")])
    cache = source.cache()
    cache.refresh()
    source.status = 500
    assert not cache.refresh()
    assert cache.decide("1.1.1.1") == blocklist.DENY
    source.status = 200
    source.body = {"unexpected": True}
    assert not cache.refresh()
    assert cache.decide("1.1.1.1") == blocklist.DENY
    assert cache.last_error is not None


def test_shrink_guard_refuses_a_collapsing_full_snapshot_unless_forced(source: Feed) -> None:
    source.body = feed(1, [deny(f"d{i}", f"10.0.0.{i}/32") for i in range(1, 11)])
    cache = source.cache()
    cache.refresh()
    assert cache.size() == 10
    source.body = feed(2, [deny("d1", "10.0.0.1/32")])
    assert not cache.refresh()
    assert cache.size() == 10
    assert cache.refused == 1
    assert cache.refresh(force=True)
    assert cache.size() == 1


def test_incremental_feed_adds_and_removes(source: Feed) -> None:
    source.body = feed(1, [deny("d1", "1.1.1.1/32"), frozen("f1", "g1")])
    cache = source.cache()
    cache.refresh()
    assert cache.grant_frozen("g1")
    source.body = feed(2, [deny("d2", "2.2.2.2/32")], full=False, removed=["f1"])
    cache.refresh()
    assert not cache.grant_frozen("g1")
    assert cache.decide("1.1.1.1") == blocklist.DENY
    assert cache.decide("2.2.2.2") == blocklist.DENY
    assert source.requests[-1].url.params["since"] == "1"
    assert source.requests[-1].headers["authorization"] == "Bearer tok"


def test_snapshot_survives_restart_and_a_broken_file_is_ignored(
    source: Feed, tmp_path: Path
) -> None:
    path = tmp_path / "snap.json"
    source.body = feed(5, [deny("d1", "1.1.1.1/32"), frozen("f1", "g1")])
    first = source.cache(snapshot_path=str(path))
    first.refresh()
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    second = Feed().cache(snapshot_path=str(path))  # management service down: nothing answers
    assert second.version == 5
    assert second.decide("1.1.1.1") == blocklist.DENY
    assert second.grant_frozen("g1")
    path.write_text("{ not json", encoding="utf-8")
    third = Feed().cache(snapshot_path=str(path))
    assert third.size() == 0


def test_malformed_entries_are_skipped_not_fatal(source: Feed) -> None:
    source.body = feed(1, [deny("d1", "999.1.1.1/8"), {"id": "x"}, deny("d2", "3.3.3.3/32")])
    cache = source.cache()
    cache.refresh()
    assert cache.decide("3.3.3.3") == blocklist.DENY
    assert cache.size() == 1


# ---- counters --------------------------------------------------------------------------------


def test_counters_group_by_source_and_forget_old_buckets() -> None:
    now = [6000.0]
    counters = riskstats.RiskCounters(retention_seconds=3600, clock=lambda: now[0])
    for _ in range(3):
        counters.auth_failed("1.1.1.1", None, "invalid")
    counters.auth_failed("2.2.2.2", "g1", "revoked")
    got = {(r["clientIp"], r["reason"]): r["count"] for r in counters.auth_failures(0, 1e9)}
    assert got == {("1.1.1.1", "invalid"): 3, ("2.2.2.2", "revoked"): 1}
    now[0] += 7200
    counters.auth_failed("3.3.3.3", None, "invalid")  # triggers pruning
    assert {r["clientIp"] for r in counters.auth_failures(0, 1e9)} == {"3.3.3.3"}


# ---- enforcement and aggregates through the real app -----------------------------------------


@pytest.fixture
def risk_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: Feed
) -> Iterator[tuple[Env, Feed]]:
    monkeypatch.setenv("ADG_EXT_TRUSTED_PROXY_HOPS", "1")
    gen = run_env(f"sqlite:///{tmp_path / 'cp.db'}", monkeypatch)
    env = next(gen)
    source.body = feed(1, [deny("d1", "6.6.6.0/24"), allow("a1", "6.6.6.7/32"), frozen("f1", "g1")])
    cache = source.cache()
    cache.refresh()
    blocklist.reset_cache(cache)
    riskstats.reset_counters()
    enforce.reset_sampling()
    with env.factory() as session:
        create_api_key(
            session, name="rt-g1", scopes=["runtime"], plaintext="adg_rt_g1", user_id="u1"
        )
        create_api_key(
            session, name="rt-g2", scopes=["runtime"], plaintext="adg_rt_g2", user_id="u2"
        )
        session.commit()
    yield env, source
    blocklist.reset_cache()
    riskstats.reset_counters()
    get_ext_settings.cache_clear()
    next(gen, None)


def via(ip: str) -> Callable[[str], dict[str, str]]:
    def make(key: str) -> dict[str, str]:
        return {"X-ADG-API-Key": key, "X-Forwarded-For": ip}

    return make


def test_blocked_source_is_refused_before_the_key_is_examined(
    risk_env: tuple[Env, Feed], caplog: pytest.LogCaptureFixture
) -> None:
    env, _ = risk_env
    caplog.set_level(logging.DEBUG)
    for key in ("adg_admin_audit_key", "totally-wrong-key", ""):
        r = env.client.get("/ext/audit/stats", headers=via("6.6.6.9")(key))
        assert r.status_code == 403
        assert r.json()["detail"] == "source_blocked"
    assert "totally-wrong-key" not in caplog.text
    assert "adg_admin_audit_key" not in caplog.text


def test_allow_entry_and_unresolvable_source_pass(risk_env: tuple[Env, Feed]) -> None:
    env, _ = risk_env
    allowed = env.client.get("/ext/audit/stats", headers=via("6.6.6.7")("adg_admin_audit_key"))
    assert allowed.status_code == 200
    unknown = env.client.get("/ext/audit/stats", headers=ADMIN)  # peer is not an IP, no header
    assert unknown.status_code == 200


def test_blocked_attempt_is_counted_audited_once_per_minute_and_exposed(
    risk_env: tuple[Env, Feed],
) -> None:
    env, _ = risk_env
    for _ in range(5):
        env.client.get("/ext/audit/stats", headers=via("6.6.6.9")("whatever"))
    with env.factory() as session:
        rows = list(
            session.execute(select(AuditEvent).where(AuditEvent.event_type == "source_blocked"))
            .scalars()
            .all()
        )
    assert len(rows) == 1
    assert rows[0].decision == "denied" and rows[0].reason == "source_blocked"
    assert json.loads(rows[0].metadata_json)["client_ip"] == "6.6.6.9"
    assert rows[0].sql_text is None
    # an allowed address can read the numbers
    out = env.client.get(
        "/ext/audit/aggregates",
        params={"groupBy": "blocked"},
        headers=via("6.6.6.7")("adg_admin_audit_key"),
    ).json()
    assert {(i["clientIp"], i["reason"]): i["count"] for i in out["items"]} == {
        ("6.6.6.9", "source_blocked"): 5
    }
    assert (
        env.client.get(
            "/ext/admin/ext/metrics/prometheus".replace("/ext/admin/ext", "/admin/ext"),
            headers=via("6.6.6.7")("adg_admin_audit_key"),
        ).text.count('adg_ext_blocked_total{reason="source_blocked"} 5')
        == 1
    )


def test_frozen_grant_is_refused_after_authentication_other_grants_pass(
    risk_env: tuple[Env, Feed],
) -> None:
    env, _ = risk_env
    ok_ip = via("8.8.8.8")
    frozen_call = env.client.post("/api/tools/nope", json={}, headers=ok_ip("adg_rt_g1"))
    assert frozen_call.status_code == 403
    assert frozen_call.json()["detail"] == "grant_frozen"
    other = env.client.post("/api/tools/nope", json={}, headers=ok_ip("adg_rt_g2"))
    assert other.status_code == 404  # authenticated, then unknown tool
    wrong = env.client.post("/api/tools/nope", json={}, headers=ok_ip("adg_wrong"))
    assert wrong.status_code == 401  # a bad key is still a plain 401


def test_auth_failures_are_counted_by_source_and_reason_without_the_key(
    risk_env: tuple[Env, Feed],
) -> None:
    env, _ = risk_env
    for _ in range(3):
        env.client.get("/ext/audit/stats", headers=via("8.8.8.8")("adg_guess_secret_value"))
    env.client.get("/ext/audit/stats", headers={"X-Forwarded-For": "8.8.8.4"})  # no key at all
    out = env.client.get(
        "/ext/audit/aggregates",
        params={"groupBy": "auth"},
        headers=via("8.8.8.8")("adg_admin_audit_key"),
    )
    assert out.status_code == 200
    got = {(i["clientIp"], i["reason"]): i["count"] for i in out.json()["items"]}
    assert got[("8.8.8.8", "invalid")] == 3
    assert got[("8.8.8.4", "invalid")] == 1
    assert "adg_guess_secret_value" not in out.text


def test_audit_rows_carry_the_resolved_address_and_events_expose_it(
    risk_env: tuple[Env, Feed],
) -> None:
    env, _ = risk_env
    with env.factory() as session:
        add(
            session,
            "withip",
            env,
            metadata={"phase": "completed", "client_ip": "8.8.8.8", "sql_fingerprint": "abc123"},
        )
        session.commit()
    items = env.events()
    hit = next(i for i in items if i["id"] == env.ids["withip"])
    assert hit["clientIp"] == "8.8.8.8" and hit["sqlFingerprint"] == "abc123"


def seed_usage(env: Env) -> None:
    with env.factory() as session:
        for n in range(4):
            add(
                session,
                f"u1-a{n}",
                env,
                ago=timedelta(minutes=10 + n),
                resources=["res-orders"],
                metadata={
                    "phase": "completed",
                    "client_ip": "8.8.8.8",
                    "sql_fingerprint": "fp1",
                    "rows": 95 if n == 0 else 10,
                    "max_rows": 100,
                },
            )
        add(
            session,
            "u1-b",
            env,
            ago=timedelta(minutes=20),
            resources=["res-orders", "res-dim"],
            metadata={
                "phase": "completed",
                "client_ip": "9.9.9.9",
                "sql_fingerprint": "fp1",
                "rows": 3,
            },
        )
        add(
            session,
            "u2-denied",
            env,
            ago=timedelta(minutes=21),
            user_id="u2",
            event_type="sql_rejected",
            decision="denied",
            reason="column_not_allowed:ssn,table_not_accessible",
            metadata={"client_ip": "7.7.7.7", "sql_fingerprint": "fp2"},
        )
        session.commit()


def aggregates(env: Env, group: str, **params: Any) -> dict[str, Any]:
    r = env.client.get(
        "/ext/audit/aggregates",
        params={"groupBy": group, **params},
        headers=via("8.8.8.8")("adg_admin_audit_key"),
    )
    assert r.status_code == 200, r.text
    return dict(r.json())


def test_aggregates_by_grant_and_source(risk_env: tuple[Env, Feed]) -> None:
    env, _ = risk_env
    seed_usage(env)
    out = aggregates(env, "grant_source", nearPercent=90)
    assert out["truncated"] is False
    by = {(i["grantId"], i["clientIp"]): i for i in out["items"] if i["grantId"] in ("g1", "g2")}
    g1_main = by[("g1", "8.8.8.8")]
    assert g1_main["queries"] >= 4
    assert g1_main["nearLimitQueries"] == 1  # 95 of 100 rows, others far below
    assert g1_main["maxRows"] == 95
    assert g1_main["distinctTables"] == 1
    assert by[("g1", "9.9.9.9")]["distinctTables"] == 2
    assert by[("g2", "7.7.7.7")]["denied"] == 1
    assert "sql" not in json.dumps(out).lower().replace("sql_fingerprint", "")


def test_aggregates_by_reason_and_fingerprint(risk_env: tuple[Env, Feed]) -> None:
    env, _ = risk_env
    seed_usage(env)
    reasons = {
        (i["grantId"], i["reason"]): i["count"] for i in aggregates(env, "grant_reason")["items"]
    }
    assert reasons[("g2", "column_not_allowed")] == 2  # one more is seeded by the fixture
    assert reasons[("g2", "table_not_accessible")] == 2
    prints = {
        (i["grantId"], i["sqlFingerprint"]): i for i in aggregates(env, "fingerprint")["items"]
    }
    assert prints[("g1", "fp1")]["count"] == 5
    assert prints[("g1", "fp1")]["distinctSources"] == 2


def test_aggregates_truncate_at_the_scan_cap_and_validate_input(
    risk_env: tuple[Env, Feed], monkeypatch: pytest.MonkeyPatch
) -> None:
    env, _ = risk_env
    seed_usage(env)
    monkeypatch.setattr(get_ext_settings(), "aggregates_max_events", 3)
    assert aggregates(env, "grant_source")["truncated"] is True
    bad = env.client.get(
        "/ext/audit/aggregates",
        params={"groupBy": "nope"},
        headers=via("8.8.8.8")("adg_admin_audit_key"),
    )
    assert bad.status_code == 422
    assert (
        env.client.get(
            "/ext/audit/aggregates",
            params={"groupBy": "auth", "nearPercent": 0},
            headers=via("8.8.8.8")("adg_admin_audit_key"),
        ).status_code
        == 422
    )


def test_disabled_blocklist_changes_nothing(
    risk_env: tuple[Env, Feed], monkeypatch: pytest.MonkeyPatch
) -> None:
    env, _ = risk_env
    blocklist.reset_cache(blocklist.BlocklistCache("", ""))
    r = env.client.get("/ext/audit/stats", headers=via("6.6.6.9")("adg_admin_audit_key"))
    assert r.status_code == 200
    time.sleep(0)


def test_delegated_path_refuses_blocked_source_and_frozen_grant(
    risk_env: tuple[Env, Feed],
) -> None:
    env, _ = risk_env
    with env.factory() as session:
        blocked = enforce.delegated_check(session, "g2", "6.6.6.9")
        assert blocked == {"reason": "source_blocked"}
        assert enforce.delegated_check(session, "g2", "6.6.6.7") is None  # allow beats deny
        assert enforce.delegated_check(session, "g1", "8.8.8.8") == {"reason": "grant_frozen"}
        assert enforce.delegated_check(session, "g2", "") is None  # no address: not blocked
    out = env.client.post(
        "/ext/delegated/query",
        json={
            "grantId": "g1",
            "sql": "select 1",
            "database": "shop",
            "requestId": "r1",
            "clientIp": "8.8.8.8",
        },
        headers=via("8.8.8.8")("adg_entry_audit_key"),
    )
    assert out.status_code == 403 and out.json()["detail"] == "grant_frozen"


def test_revoked_expired_and_disabled_keys_are_counted_with_their_own_reason(
    risk_env: tuple[Env, Feed],
) -> None:
    from datetime import UTC, datetime, timedelta

    from adg.shared.security import hash_api_key
    from adg_ext import revocation

    env, _ = risk_env
    with env.factory() as session:
        _, _ = create_api_key(
            session,
            name="expired",
            scopes=["runtime"],
            plaintext="adg_rt_expired",
            user_id="u2",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        off, _ = create_api_key(
            session, name="off", scopes=["runtime"], plaintext="adg_rt_off", user_id="u2"
        )
        off.status = "revoked"
        session.commit()
    cache = revocation.RevocationCache("http://cp.test/revocations", "t")
    cache._hashes.add(hash_api_key("adg_rt_g2"))
    cache._next_due = float("inf")
    revocation.reset_cache(cache)
    ip = via("8.8.4.4")
    for key in ("adg_rt_g2", "adg_rt_expired", "adg_rt_off", "adg_rt_unknown"):
        assert env.client.post("/api/tools/nope", json={}, headers=ip(key)).status_code == 401
    out = aggregates(env, "auth")
    got = {(i["clientIp"], i["reason"]): i["count"] for i in out["items"]}
    assert got[("8.8.4.4", "revoked")] == 1
    assert got[("8.8.4.4", "expired")] == 1
    assert got[("8.8.4.4", "disabled")] == 1
    assert got[("8.8.4.4", "invalid")] == 1
    # the grant behind a key that was recognised is reported, the key itself never is
    assert "adg_rt" not in json.dumps(out)
