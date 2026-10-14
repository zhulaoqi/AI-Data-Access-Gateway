import threading
import time

import pytest

from adg_ext.admission import Admission, AdmissionRejected


def make(**kw):
    return Admission(**kw)


def acquire(a, user="u", ds="d", conc=1, queue=2, timeout=0.5, tags=frozenset()):
    return a.acquire(
        tags=tags,
        user_key=user,
        datasource_key=ds,
        max_concurrency=conc,
        queue_size=queue,
        queue_timeout=timeout,
    )


def test_user_limit_queues_then_runs_in_fifo_order() -> None:
    a = make()
    first = acquire(a, timeout=2)
    order: list[int] = []

    def worker(i: int) -> None:
        t = acquire(a, queue=5, timeout=3)
        order.append(i)
        time.sleep(0.05)
        t.release()

    threads = []
    for i in range(3):
        th = threading.Thread(target=worker, args=(i,))
        th.start()
        threads.append(th)
        time.sleep(0.05)  # fix the arrival order
    assert a.snapshot()["queued"] == 3
    first.release()
    for th in threads:
        th.join()
    assert order == [0, 1, 2]


def test_queue_full_is_rejected_immediately() -> None:
    a = make()
    held = acquire(a)
    waiters = [threading.Thread(target=lambda: _try(a)) for _ in range(2)]
    for w in waiters:
        w.start()
    time.sleep(0.1)
    with pytest.raises(AdmissionRejected) as e:
        acquire(a, queue=2)
    assert e.value.reason == "queue_full"
    held.release()
    for w in waiters:
        w.join()


def _try(a):
    try:
        acquire(a, timeout=1).release()
    except AdmissionRejected:
        pass


def test_queue_timeout() -> None:
    a = make()
    held = acquire(a)
    start = time.monotonic()
    with pytest.raises(AdmissionRejected) as e:
        acquire(a, timeout=0.2)
    assert e.value.reason == "queue_timeout"
    assert 0.15 <= time.monotonic() - start < 1.0
    held.release()
    acquire(a).release()  # the timed-out waiter left nothing behind
    assert a.snapshot()["queued"] == 0


def test_users_do_not_block_each_other() -> None:
    a = make()
    t1 = acquire(a, user="a")
    t2 = acquire(a, user="b")
    t1.release()
    t2.release()


def test_datasource_limit_applies_across_users() -> None:
    a = make(datasource_limit=1)
    t1 = acquire(a, user="a", ds="x")
    with pytest.raises(AdmissionRejected) as e:
        acquire(a, user="b", ds="x", timeout=0.1)
    assert e.value.reason == "datasource_busy"
    other = acquire(a, user="b", ds="y")  # another datasource is unaffected
    other.release()
    t1.release()
    acquire(a, user="b", ds="x").release()
    # the user slot of the refused request was given back
    assert a.snapshot()["running"] == 0


def test_breaker_opens_then_half_open_probe_closes() -> None:
    now = [0.0]
    a = make(breaker_threshold=2, breaker_open_seconds=10, clock=lambda: now[0])
    b = a.breaker("d")
    b.failure()
    b.failure()
    with pytest.raises(AdmissionRejected) as e:
        acquire(a)
    assert e.value.reason == "circuit_open"
    now[0] = 11
    probe = acquire(a)
    with pytest.raises(AdmissionRejected):  # only one probe at a time
        acquire(a, user="other")
    probe.release()
    b.success()
    assert b.state == "closed"
    acquire(a).release()


def test_failed_probe_reopens() -> None:
    now = [0.0]
    a = make(breaker_threshold=1, breaker_open_seconds=5, clock=lambda: now[0])
    b = a.breaker("d")
    b.failure()
    now[0] = 6
    acquire(a).release()
    b.failure()
    assert b.state == "open"


def test_revoke_rejects_queued_and_cancels_running() -> None:
    a = make()
    running = acquire(a, timeout=5, tags=frozenset({"u"}))
    killed: list[bool] = []
    running.on_cancel(lambda: killed.append(True))
    outcome: list[str] = []

    def queued() -> None:
        try:
            acquire(a, timeout=5, tags=frozenset({"u"}))
        except AdmissionRejected as e:
            outcome.append(e.reason)

    th = threading.Thread(target=queued)
    th.start()
    time.sleep(0.1)
    assert a.revoke_user("u") == 2
    th.join(timeout=2)
    assert outcome == ["revoked"]
    assert killed == [True]
    assert running.cancelled
    running.release()
    assert a.snapshot()["running"] == 0 and a.snapshot()["queued"] == 0


def test_release_is_idempotent() -> None:
    a = make()
    t = acquire(a)
    t.release()
    t.release()
    assert a.snapshot()["running"] == 0
    assert a.snapshot()["datasource_running"] == {"d": 0}


def test_revoke_by_key_tag_leaves_other_keys_of_the_same_user_running() -> None:
    a = make()
    old = acquire(a, conc=2, tags=frozenset({"u", "key-old"}))
    new = acquire(a, conc=2, tags=frozenset({"u", "key-new"}))
    killed: list[str] = []
    old.on_cancel(lambda: killed.append("old"))
    new.on_cancel(lambda: killed.append("new"))
    assert a.revoke("key-old") == 1
    assert killed == ["old"] and not new.cancelled
    assert a.revoke("u") == 2
    old.release()
    new.release()
