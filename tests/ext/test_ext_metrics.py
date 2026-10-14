"""Prometheus exposition of the extension: format, labels, counters, endpoint access control."""

import re
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from adg.app.auth_rate_limit import reset_auth_rate_limiter
from adg.app.main import create_app
from adg.app.settings import get_settings
from adg.connectors.registry import get_connector_registry
from adg.control_plane.db import create_engine_from_url, create_session_factory
from adg.control_plane.models import Base
from adg.control_plane.services.api_key_service import create_api_key
from adg_ext import metrics, pipeline, revocation
from adg_ext.admission import Admission, AdmissionRejected
from adg_ext.config import get_ext_settings
from adg_ext.metrics import Histogram, QueryMetrics, reason_label

ADMIN = {"X-ADG-API-Key": "adg_admin_metrics_key"}
RUNTIME = {"X-ADG-API-Key": "adg_runtime_metrics_key"}
ENTRY = {"X-ADG-API-Key": "adg_entry_metrics_key"}

SAMPLE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})? (-?[0-9.]+(?:e[+-]?[0-9]+)?|\+Inf)$")
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse(text: str) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    """A strict reader of the 0.0.4 text format: every line must be HELP, TYPE or a sample."""

    assert text.endswith("\n")
    out: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
    typed: set[str] = set()
    for line in text.splitlines():
        if line.startswith("# HELP "):
            continue
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ")
            assert kind in {"counter", "gauge", "histogram"}
            typed.add(name)
            continue
        m = SAMPLE.match(line)
        assert m, f"not a valid sample line: {line!r}"
        name, raw_labels, value = m.groups()
        base = re.sub(r"_(bucket|sum|count)$", "", name)
        assert name in typed or base in typed, f"{name} has no TYPE"
        labels = tuple(sorted(LABEL.findall(raw_labels or "")))
        key = (name, labels)
        assert key not in out, f"duplicate series {key}"
        out[key] = float("inf") if value == "+Inf" else float(value)
    return out


def value(
    samples: dict[tuple[str, tuple[tuple[str, str], ...]], float], name: str, **labels: str
) -> float:
    return samples[(name, tuple(sorted(labels.items())))]


def new_admission(**kw: object) -> Admission:
    return Admission(**kw)  # type: ignore[arg-type]


# ---- units ------------------------------------------------------------------------------------


def test_reason_label_keeps_only_the_code_before_the_colon() -> None:
    assert reason_label("column_not_allowed:ssn") == "column_not_allowed"
    assert reason_label("field_disabled:secret_col") == "field_disabled"
    assert reason_label("table_not_accessible") == "table_not_accessible"
    # anything that is not a plain code never becomes a label (no SQL, no free text)
    assert reason_label("SELECT * FROM t") == "other"
    assert reason_label("") == "other"
    assert reason_label('bad"quote') == "other"
    assert reason_label("x" * 200) == "other"


def test_rejected_counts_each_reason_once_and_the_outcome_once() -> None:
    q = QueryMetrics()
    q.rejected("column_not_allowed:ssn,limit_by_not_allowed,column_not_allowed:phone")
    outcomes, reasons, audit = q.snapshot()
    assert outcomes["rejected"] == 1
    assert reasons == {"column_not_allowed": 1, "limit_by_not_allowed": 1}
    assert audit == 0


def test_reason_cardinality_is_capped() -> None:
    q = QueryMetrics()
    for i in range(metrics.MAX_REASONS + 20):
        q.rejected(f"code_{i}")
    _, reasons, _ = q.snapshot()
    assert len(reasons) == metrics.MAX_REASONS + 1  # the cap plus the collapsed "other"
    assert reasons["other"] == 20


def test_histogram_is_cumulative_and_counts_the_overflow() -> None:
    h = Histogram((0.1, 1.0))
    for v in (0.05, 0.1, 0.5, 5.0):
        h.observe(v)
    buckets, total, count = h.snapshot()
    assert buckets == [(0.1, 2), (1.0, 3)]
    assert count == 4 and total == pytest.approx(5.65)


def test_render_is_valid_text_with_all_gap_metrics() -> None:
    a = new_admission(datasource_limit=7)
    t = a.acquire(
        user_key="u", datasource_key="ds-1", max_concurrency=1, queue_size=1, queue_timeout=1
    )
    q = QueryMetrics()
    q.outcome("completed")
    q.outcome("timeout")
    q.rejected("column_not_allowed:ssn")
    q.audit_unavailable()
    text = metrics.render(a, q, None)
    s = parse(text)
    assert value(s, "adg_ext_query_total", outcome="completed") == 1
    assert value(s, "adg_ext_query_total", outcome="timeout") == 1
    assert value(s, "adg_ext_query_total", outcome="rejected") == 1
    assert value(s, "adg_ext_query_total", outcome="failed") == 0
    assert value(s, "adg_ext_query_total", outcome="cancelled") == 0
    assert value(s, "adg_ext_query_rejected_total", reason="column_not_allowed") == 1
    assert value(s, "adg_ext_audit_unavailable_total") == 1
    assert value(s, "adg_ext_admission_datasource_limit", datasource="ds-1") == 7
    assert value(s, "adg_ext_admission_datasource_running", datasource="ds-1") == 1
    assert value(s, "adg_ext_admission_breaker_state", datasource="ds-1") == 0
    assert value(s, "adg_ext_admission_running") == 1
    assert value(s, "adg_ext_admission_admitted_total") == 1
    assert value(s, "adg_ext_admission_wait_seconds_count") == 1
    assert value(s, "adg_ext_admission_wait_seconds_bucket", le="+Inf") == 1
    # no revocation cache given: the poll age is not claimed
    assert "adg_ext_revocation_poll_age_seconds" not in text
    t.release()


def test_wait_histogram_buckets_are_monotonic_and_end_in_count() -> None:
    a = new_admission()
    for _ in range(3):
        a.acquire(
            user_key="u", datasource_key="d", max_concurrency=3, queue_size=1, queue_timeout=1
        ).release()
    s = parse(metrics.render(a, QueryMetrics(), None))
    buckets = sorted(
        (float(dict(k[1])["le"]), v) for k, v in s.items() if k[0].endswith("wait_seconds_bucket")
    )
    counts = [v for _, v in buckets]
    assert counts == sorted(counts) and buckets[-1][0] == float("inf")
    assert counts[-1] == value(s, "adg_ext_admission_wait_seconds_count") == 3
    assert value(s, "adg_ext_admission_wait_seconds_sum") >= 0


def test_queue_timeout_shows_up_in_the_wait_histogram_and_the_reject_counter() -> None:
    a = new_admission()
    held = a.acquire(
        user_key="u", datasource_key="d", max_concurrency=1, queue_size=2, queue_timeout=1
    )
    with pytest.raises(AdmissionRejected):
        a.acquire(
            user_key="u", datasource_key="d", max_concurrency=1, queue_size=2, queue_timeout=0.2
        )
    with pytest.raises(AdmissionRejected):  # a full queue refuses instantly: no wait sample
        a.acquire(
            user_key="u", datasource_key="d", max_concurrency=1, queue_size=0, queue_timeout=0.2
        )
    s = parse(metrics.render(a, QueryMetrics(), None))
    assert value(s, "adg_ext_admission_rejected_total", reason="queue_timeout") == 1
    assert value(s, "adg_ext_admission_rejected_total", reason="queue_full") == 1
    # the admitted holder plus the timed-out waiter (about 0.2 s)
    assert value(s, "adg_ext_admission_wait_seconds_count") == 2
    assert value(s, "adg_ext_admission_wait_seconds_sum") >= 0.15
    held.release()


def test_datasource_limit_follows_the_setting_and_covers_breaker_only_datasources() -> None:
    a = new_admission(datasource_limit=3, breaker_threshold=1)
    a.breaker("only-breaker").failure()
    s = parse(metrics.render(a, QueryMetrics(), None))
    assert value(s, "adg_ext_admission_datasource_limit", datasource="only-breaker") == 3
    assert value(s, "adg_ext_admission_breaker_state", datasource="only-breaker") == 2


def test_labels_never_carry_users_sql_or_keys() -> None:
    a = new_admission()
    a.acquire(
        user_key="alice@example.com",
        datasource_key="ds-9",
        max_concurrency=1,
        queue_size=1,
        queue_timeout=1,
    ).release()
    q = QueryMetrics()
    q.rejected("sql_rejected:SELECT secret FROM t WHERE k='adg_key'")
    q.rejected("column_not_allowed:ssn")
    text = metrics.render(a, q, None)
    for secret in ("alice", "example.com", "SELECT", "secret", "adg_key", "ssn"):
        assert secret not in text
    label_names = {n for _, labels in parse(text) for n, _ in labels}
    assert label_names <= {"outcome", "reason", "datasource", "le"}


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class FakeResponse:
    def __init__(self, ok: bool) -> None:
        self.ok = ok

    def raise_for_status(self) -> None:
        if not self.ok:
            raise RuntimeError("boom")

    def json(self) -> dict[str, object]:
        return {"data": {"version": 1, "full": True, "hasMore": False, "entries": []}}


class FakeClient:
    def __init__(self) -> None:
        self.ok = True

    def get(self, *args: object, **kwargs: object) -> FakeResponse:
        return FakeResponse(self.ok)


def test_revocation_poll_age_tracks_the_last_successful_pull() -> None:
    clock = Clock()
    client = FakeClient()
    cache = revocation.RevocationCache(
        "http://mgmt/revocations",
        "token",
        ttl=5,
        client=client,
        clock=clock,  # type: ignore[arg-type]
    )
    clock.now += 12
    assert cache.poll_age_seconds() == pytest.approx(12)  # never pulled: age since creation
    cache.refresh()
    assert cache.poll_age_seconds() == 0
    clock.now += 40
    assert cache.poll_age_seconds() == pytest.approx(40)
    client.ok = False
    cache.refresh()  # a failed pull does not reset the age
    assert cache.poll_age_seconds() == pytest.approx(40)
    client.ok = True
    clock.now += 100
    cache.refresh()
    assert cache.poll_age_seconds() == 0

    s = parse(metrics.render(new_admission(), QueryMetrics(), cache))
    assert value(s, "adg_ext_revocation_poll_age_seconds") == 0
    clock.now += 61
    s = parse(metrics.render(new_admission(), QueryMetrics(), cache))
    assert value(s, "adg_ext_revocation_poll_age_seconds") == pytest.approx(61)


def test_disabled_revocation_cache_exports_no_poll_age() -> None:
    cache = revocation.RevocationCache("", "")
    assert "adg_ext_revocation_poll_age_seconds" not in metrics.render(
        new_admission(), QueryMetrics(), cache
    )


def test_query_metrics_are_thread_safe() -> None:
    q = QueryMetrics()

    def work() -> None:
        for _ in range(500):
            q.outcome("completed")
            q.rejected("x_code:detail")

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    outcomes, reasons, _ = q.snapshot()
    assert outcomes["completed"] == 2000 and outcomes["rejected"] == 2000
    assert reasons == {"x_code": 2000}
    time.sleep(0)


# ---- HTTP endpoint ----------------------------------------------------------------------------


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("ADG_EXT_ENABLED", "true")
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()
    reset_auth_rate_limiter()
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'm.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    registry = get_connector_registry()
    saved = dict(registry._connectors)
    with factory() as session:
        create_api_key(session, name="admin", scopes=["admin"], plaintext="adg_admin_metrics_key")
        create_api_key(session, name="rt", scopes=["runtime"], plaintext="adg_runtime_metrics_key")
        create_api_key(session, name="entry", scopes=["entry"], plaintext="adg_entry_metrics_key")
        session.commit()
    yield TestClient(create_app(session_factory=factory), client=("10.1.2.3", 5000))
    registry._connectors.clear()
    registry._connectors.update(saved)
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()
    reset_auth_rate_limiter()


def test_prometheus_endpoint_serves_text_0_0_4_for_admin(app_env: TestClient) -> None:
    r = app_env.get("/admin/ext/metrics/prometheus", headers=ADMIN)
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
    s = parse(r.text)
    assert value(s, "adg_ext_query_total", outcome="completed") == 0
    assert value(s, "adg_ext_audit_unavailable_total") == 0
    assert ("adg_ext_admission_wait_seconds_count", ()) in s


def test_prometheus_endpoint_reflects_state_changes(app_env: TestClient) -> None:
    pipeline.get_admission().acquire(
        user_key="u", datasource_key="ds-x", max_concurrency=1, queue_size=1, queue_timeout=1
    )
    q = metrics.get_query_metrics()
    q.outcome("timeout")
    q.rejected("admission_queue_full")
    q.audit_unavailable()
    s = parse(app_env.get("/admin/ext/metrics/prometheus", headers=ADMIN).text)
    assert value(s, "adg_ext_admission_running") == 1
    assert value(s, "adg_ext_admission_datasource_running", datasource="ds-x") == 1
    assert value(s, "adg_ext_query_total", outcome="timeout") == 1
    assert value(s, "adg_ext_query_rejected_total", reason="admission_queue_full") == 1
    assert value(s, "adg_ext_audit_unavailable_total") == 1
    q.outcome("timeout")
    again = parse(app_env.get("/admin/ext/metrics/prometheus", headers=ADMIN).text)
    assert value(again, "adg_ext_query_total", outcome="timeout") == 2


def test_prometheus_endpoint_requires_the_admin_scope(app_env: TestClient) -> None:
    url = "/admin/ext/metrics/prometheus"
    assert app_env.get(url).status_code == 401
    assert app_env.get(url, headers={"X-ADG-API-Key": "wrong"}).status_code == 401
    assert app_env.get(url, headers=RUNTIME).status_code == 403
    assert app_env.get(url, headers=ENTRY).status_code == 403


def test_prometheus_endpoint_obeys_the_admin_cidr_allowlist(
    app_env: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "/admin/ext/metrics/prometheus"
    monkeypatch.setenv("ADG_EXT_ADMIN_ALLOWED_CIDRS", "192.168.0.0/16")
    get_ext_settings.cache_clear()
    assert app_env.get(url, headers=ADMIN).status_code == 403  # 10.1.2.3 is outside
    monkeypatch.setenv("ADG_EXT_ADMIN_ALLOWED_CIDRS", "10.0.0.0/8")
    get_ext_settings.cache_clear()
    assert app_env.get(url, headers=ADMIN).status_code == 200


def test_the_json_metrics_endpoint_is_unchanged(app_env: TestClient) -> None:
    r = app_env.get("/admin/ext/metrics", headers=ADMIN)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert set(r.json()) == {
        "queued",
        "running",
        "datasource_running",
        "breakers",
        "counters",
        "wait_seconds_avg",
    }
    assert app_env.get("/admin/ext/metrics", headers=RUNTIME).status_code == 403
