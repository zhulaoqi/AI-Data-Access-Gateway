"""PER-1: the PBKDF2 output cache. Bounded, expiring, never keyed by plaintext, never logged, and it
cannot make a decrypt succeed that would otherwise fail."""

import logging
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.fernet import InvalidToken

from adg.shared import crypto
from adg_ext import kdf_cache
from adg_ext.config import get_ext_settings
from adg_ext.kdf_cache import KdfCache

SECRET = "master-secret-for-the-kdf-cache-tests"
SALT = bytes(range(16))


class Counter:
    """A stand-in for PBKDF2 that records every real derivation."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes, int]] = []

    def __call__(self, *, secret: str, salt: bytes, iterations: int) -> bytes:
        self.calls.append((secret, salt, iterations))
        return crypto.derive_pbkdf2_fernet_key(secret=secret, salt=salt, iterations=iterations)


def cache(**kw: Any) -> KdfCache:
    return KdfCache(
        max_entries=kw.pop("max_entries", 8), ttl_seconds=kw.pop("ttl_seconds", 60), **kw
    )


def derive(
    c: KdfCache, compute: Counter, *, secret: str = SECRET, salt: bytes = SALT, it: int = 1000
) -> bytes:
    return c.derive(secret=secret, salt=salt, iterations=it, compute=compute)


def test_the_second_derivation_is_served_from_the_cache_and_equals_the_real_one() -> None:
    c, compute = cache(), Counter()
    first = derive(c, compute)
    second = derive(c, compute)
    assert (
        first
        == second
        == crypto.derive_pbkdf2_fernet_key(secret=SECRET, salt=SALT, iterations=1000)
    )
    assert len(compute.calls) == 1 and (c.hits, c.misses) == (1, 1)
    # the exact iteration count requested is the one derived with (never lowered)
    assert compute.calls[0][2] == 1000


def test_every_input_is_part_of_the_key() -> None:
    c, compute = cache(), Counter()
    a = derive(c, compute)
    b = derive(c, compute, secret=SECRET + "x")
    d = derive(c, compute, salt=bytes(16))
    e = derive(c, compute, it=1001)
    assert len({a, b, d, e}) == 4
    assert len(compute.calls) == 4 and len(c) == 4


def test_keys_do_not_contain_the_secret_the_salt_or_the_derived_key() -> None:
    c, compute = cache(), Counter()
    derived = derive(c, compute)
    keys = list(c._entries)
    assert len(keys) == 1 and len(keys[0]) == 64 and int(keys[0], 16) >= 0  # a hex HMAC digest
    blob = repr(c.__dict__.keys()) + keys[0]
    assert SECRET not in blob and SALT.hex() not in blob and derived.decode() not in blob
    # another process (another random MAC key) derives a different key for the same input
    other = cache()
    derive(other, compute)
    assert list(other._entries) != keys


def test_entries_expire() -> None:
    now = [0.0]
    c, compute = cache(ttl_seconds=5, clock=lambda: now[0]), Counter()
    derive(c, compute)
    now[0] = 4.9
    derive(c, compute)
    assert len(compute.calls) == 1
    now[0] = 5.0
    derive(c, compute)
    assert len(compute.calls) == 2


def test_the_cache_is_bounded_and_evicts_the_least_recently_used() -> None:
    c, compute = cache(max_entries=2), Counter()
    derive(c, compute, it=1000)
    derive(c, compute, it=1001)
    derive(c, compute, it=1000)  # touch: 1001 is now the oldest
    derive(c, compute, it=1002)  # evicts 1001
    assert len(c) == 2
    n = len(compute.calls)
    derive(c, compute, it=1000)
    assert len(compute.calls) == n  # still cached
    derive(c, compute, it=1001)
    assert len(compute.calls) == n + 1  # was evicted


@pytest.mark.parametrize("size,ttl", [(0, 60), (8, 0)])
def test_size_or_ttl_zero_disables_the_cache(size: int, ttl: float) -> None:
    c, compute = KdfCache(max_entries=size, ttl_seconds=ttl), Counter()
    derive(c, compute)
    derive(c, compute)
    assert len(compute.calls) == 2 and len(c) == 0 and not c.enabled


def test_concurrent_misses_derive_once() -> None:
    c = cache()
    started = threading.Event()
    calls: list[int] = []

    def slow(*, secret: str, salt: bytes, iterations: int) -> bytes:
        calls.append(1)
        started.set()
        time.sleep(0.2)
        return b"k" * 44

    results: list[bytes] = []
    threads = [
        threading.Thread(
            target=lambda: results.append(
                c.derive(secret=SECRET, salt=SALT, iterations=1000, compute=slow)
            )
        )
        for _ in range(12)
    ]
    [t.start() for t in threads]
    [t.join(timeout=10) for t in threads]
    assert len(calls) == 1 and results == [b"k" * 44] * 12


def test_a_failed_derivation_is_not_cached_and_does_not_wedge_waiters() -> None:
    c = cache()
    attempts: list[int] = []

    def flaky(*, secret: str, salt: bytes, iterations: int) -> bytes:
        attempts.append(1)
        if len(attempts) == 1:
            time.sleep(0.1)
            raise RuntimeError("boom")
        return b"ok"

    outcomes: list[Any] = []

    def run() -> None:
        try:
            outcomes.append(c.derive(secret=SECRET, salt=SALT, iterations=1000, compute=flaky))
        except RuntimeError as error:
            outcomes.append(error)

    threads = [threading.Thread(target=run) for _ in range(4)]
    [t.start() for t in threads]
    [t.join(timeout=10) for t in threads]
    assert len(outcomes) == 4  # nobody hangs
    assert any(isinstance(o, RuntimeError) for o in outcomes)
    assert c.derive(secret=SECRET, salt=SALT, iterations=1000, compute=flaky) == b"ok"


def test_nothing_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    c, compute = cache(), Counter()
    with caplog.at_level(logging.DEBUG):
        derived = derive(c, compute)
        derive(c, compute)
        c.clear()
    text = caplog.text
    assert SECRET not in text and SALT.hex() not in text and derived.decode() not in text


# ---- through the real envelope code -----------------------------------------------------------


@pytest.fixture
def ext_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[KdfCache]:
    monkeypatch.setenv("ADG_EXT_ENABLED", "true")
    get_ext_settings.cache_clear()
    fresh = cache()
    kdf_cache.reset_kdf_cache(fresh)
    yield fresh
    kdf_cache.reset_kdf_cache()
    get_ext_settings.cache_clear()


def envelope(
    secret: str = SECRET, iterations: int = 1000, text: bytes = b"db-password"
) -> dict[str, object]:
    return crypto.encrypt_fernet_envelope(text, secret=secret, iterations=iterations)


def test_decrypt_goes_through_the_cache_when_the_extension_is_on(ext_on: KdfCache) -> None:
    env = envelope()
    assert crypto.decrypt_fernet_envelope(env, secret=SECRET) == b"db-password"
    assert crypto.decrypt_fernet_envelope(env, secret=SECRET) == b"db-password"
    assert (ext_on.hits, ext_on.misses) == (1, 1)


def test_the_cache_is_not_used_when_the_extension_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADG_EXT_ENABLED", raising=False)
    get_ext_settings.cache_clear()
    fresh = cache()
    kdf_cache.reset_kdf_cache(fresh)
    try:
        env = envelope()
        assert crypto.decrypt_fernet_envelope(env, secret=SECRET) == b"db-password"
        assert len(fresh) == 0 and fresh.misses == 0
    finally:
        kdf_cache.reset_kdf_cache()
        get_ext_settings.cache_clear()


def test_a_warm_cache_does_not_let_a_wrong_secret_decrypt(ext_on: KdfCache) -> None:
    env = envelope()
    crypto.decrypt_fernet_envelope(env, secret=SECRET)
    with pytest.raises(InvalidToken):
        crypto.decrypt_fernet_envelope(env, secret=SECRET + "-rotated")


def test_a_warm_cache_does_not_let_a_tampered_envelope_decrypt(ext_on: KdfCache) -> None:
    env = envelope()
    crypto.decrypt_fernet_envelope(env, secret=SECRET)
    flipped = dict(env)
    token = str(env["ciphertext"])
    flipped["ciphertext"] = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")
    with pytest.raises(InvalidToken):
        crypto.decrypt_fernet_envelope(flipped, secret=SECRET)
    # a different (valid-looking) salt: new key, so the original ciphertext no longer opens
    other_salt = dict(env)
    other_salt["salt"] = str(envelope()["salt"])
    with pytest.raises(InvalidToken):
        crypto.decrypt_fernet_envelope(other_salt, secret=SECRET)


@pytest.mark.parametrize("iterations", [999, 2_000_001, True, "1000", None])
def test_iteration_bounds_are_still_enforced_before_the_cache(
    ext_on: KdfCache, iterations: Any
) -> None:
    env = envelope()
    crypto.decrypt_fernet_envelope(env, secret=SECRET)
    forged = dict(env)
    forged["iterations"] = iterations
    with pytest.raises(InvalidToken):
        crypto.decrypt_fernet_envelope(forged, secret=SECRET)
    assert ext_on.misses == 1  # the forged request never reached the cache


def test_a_changed_iteration_count_is_a_different_key(ext_on: KdfCache) -> None:
    env = envelope()
    crypto.decrypt_fernet_envelope(env, secret=SECRET)
    changed = dict(env)
    changed["iterations"] = 1001
    with pytest.raises(InvalidToken):
        crypto.decrypt_fernet_envelope(changed, secret=SECRET)


def test_defaults_are_bounded() -> None:
    get_ext_settings.cache_clear()
    s = get_ext_settings()
    assert 0 < s.kdf_cache_size <= 4096 and 0 < s.kdf_cache_ttl_seconds <= 3600
    get_ext_settings.cache_clear()
