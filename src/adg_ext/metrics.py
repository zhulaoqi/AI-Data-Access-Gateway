"""Prometheus metrics of the extension (text exposition format 0.0.4, standard library only).

``GET /admin/ext/metrics/prometheus`` renders:

* the admission gauges/counters the JSON snapshot already carries (same ``adg_ext_`` names as the
  sidecar exporter in ``sql-gateway/deploy/observability/exporter``, so the exporter can retire);
* the six gaps of the NFR-O1 coverage report: ``adg_ext_query_total{outcome}``,
  ``adg_ext_query_rejected_total{reason}``, ``adg_ext_admission_wait_seconds`` (histogram),
  ``adg_ext_admission_datasource_limit{datasource}``, ``adg_ext_audit_unavailable_total`` and
  ``adg_ext_revocation_poll_age_seconds``.

Label policy: only closed or bounded vocabularies. ``outcome`` is one of five fixed values,
``reason`` is the part of a rejection code before the first ``:`` (so ``column_not_allowed:ssn``
never leaks a column name), validated against ``[a-z][a-z0-9_]*`` and capped at
``MAX_REASONS`` distinct values (the overflow collapses into ``other``), ``datasource`` is the
executor's datasource id. Users, SQL text, key material and error messages never become labels.
"""

import asyncio
import gc
import os
import re
import resource
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from adg_ext.admission import Admission
    from adg_ext.blocklist import BlocklistCache
    from adg_ext.revocation import RevocationCache

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

OUTCOMES = ("completed", "failed", "timeout", "cancelled", "rejected")
# 排队之后、数据库返回之前的耗时。上限对齐查询超时 600 秒。
DURATION_BUCKETS: tuple[float, ...] = (
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
    120.0,
    300.0,
    600.0,
)
WAIT_BUCKETS: tuple[float, ...] = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
)
BREAKER_STATES = {"closed": 0, "half_open": 1, "open": 2}
MAX_REASONS = 64
OTHER = "other"
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ADMISSION_REJECT_PREFIX = "rejected_"
# 这些原因在第一次发生前也输出 0，否则拒绝序列要等事故之后才出现。
ADMISSION_REJECT_REASONS = (
    "circuit_open",
    "queue_full",
    "revoked",
    "queue_timeout",
    "datasource_busy",
)
_MAX_DATASOURCE_HISTOGRAMS = 128
_PROCESS_START = time.time()
_loop_lag = 0.0
_loop_lag_lock = threading.Lock()


def reason_label(code: str) -> str:
    """The metric label of a rejection code: the part before ``:``, validated."""

    head = code.split(":", 1)[0].strip()
    return head if _REASON.match(head) else OTHER


class Histogram:
    """A thread-safe cumulative histogram with fixed upper bounds."""

    def __init__(self, buckets: Sequence[float] = WAIT_BUCKETS) -> None:
        self._bounds = tuple(sorted(buckets))
        self._counts = [0] * len(self._bounds)
        self._sum = 0.0
        self._count = 0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        value = max(0.0, value)
        with self._lock:
            self._sum += value
            self._count += 1
            for i, bound in enumerate(self._bounds):
                if value <= bound:
                    self._counts[i] += 1
                    break

    def snapshot(self) -> tuple[list[tuple[float, int]], float, int]:
        """Cumulative ``(upper bound, count)`` pairs (without ``+Inf``), the sum and the count."""

        with self._lock:
            running = 0
            cumulative: list[tuple[float, int]] = []
            for bound, n in zip(self._bounds, self._counts, strict=True):
                running += n
                cumulative.append((bound, running))
            return cumulative, self._sum, self._count


class QueryMetrics:
    """Query outcome counters; every method is cheap and never raises."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._outcomes: dict[str, int] = dict.fromkeys(OUTCOMES, 0)
        self._rejected: dict[str, int] = {}
        self._audit_unavailable = 0
        self._duration = Histogram(DURATION_BUCKETS)
        self._duration_by_datasource: dict[str, Histogram] = {}

    def outcome(self, name: str) -> None:
        if name not in self._outcomes:
            return
        with self._lock:
            self._outcomes[name] += 1

    def rejected(self, reason: str) -> None:
        """One rejected request; ``reason`` may be a comma separated list of codes."""

        labels = {reason_label(part) for part in reason.split(",") if part.strip()} or {OTHER}
        with self._lock:
            self._outcomes["rejected"] += 1
            for label in sorted(labels):
                if label not in self._rejected and len(self._rejected) >= MAX_REASONS:
                    label = OTHER
                self._rejected[label] = self._rejected.get(label, 0) + 1

    def audit_unavailable(self) -> None:
        with self._lock:
            self._audit_unavailable += 1

    def observe_duration(self, seconds: float, datasource: str | None = None) -> None:
        """Record execution time after a slot was granted. Queue wait is a separate histogram.

        A datasource id also feeds the per-datasource histogram. The global histogram stays
        unlabeled so existing queries keep working.
        """

        self._duration.observe(seconds)
        if not datasource or len(datasource) > 128 or "\n" in datasource:
            return
        with self._lock:
            histogram = self._duration_by_datasource.get(datasource)
            if histogram is None:
                if len(self._duration_by_datasource) >= _MAX_DATASOURCE_HISTOGRAMS:
                    return
                histogram = Histogram(DURATION_BUCKETS)
                self._duration_by_datasource[datasource] = histogram
            # observe() takes its own lock; do not call it while holding ours
            pending = histogram
        pending.observe(seconds)

    def duration_histogram(self) -> Histogram:
        return self._duration

    def datasource_durations(self) -> dict[str, Histogram]:
        with self._lock:
            return dict(self._duration_by_datasource)

    def snapshot(self) -> tuple[dict[str, int], dict[str, int], int]:
        with self._lock:
            return dict(self._outcomes), dict(self._rejected), self._audit_unavailable


_query_metrics = QueryMetrics()
_query_metrics_lock = threading.Lock()


def get_query_metrics() -> QueryMetrics:
    with _query_metrics_lock:
        return _query_metrics


def reset_query_metrics() -> None:
    """Drop all counters (tests)."""

    global _query_metrics
    with _query_metrics_lock:
        _query_metrics = QueryMetrics()


# ---- text rendering ---------------------------------------------------------------------------


def _escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _number(value: float) -> str:
    if isinstance(value, int):
        return str(value)
    return repr(float(value))


def _bound(value: float) -> str:
    return repr(float(value))


class _Writer:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def family(self, name: str, kind: str, help_: str) -> None:
        self.lines.append(f"# HELP {name} {help_}")
        self.lines.append(f"# TYPE {name} {kind}")

    def sample(self, metric: str, value: float, **labels: object) -> None:
        if labels:
            rendered = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
            self.lines.append(f"{metric}{{{rendered}}} {_number(value)}")
        else:
            self.lines.append(f"{metric} {_number(value)}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def render_current() -> str:
    """Prometheus text for the process, without the admin API key.

    Served at ``GET /mcp/metrics`` because that prefix is already routed to the executor.
    """

    from adg_ext import blocklist, revocation
    from adg_ext.pipeline import get_admission

    return render(
        get_admission(),
        get_query_metrics(),
        revocation.get_cache(),
        blocklist.get_cache(),
        names=datasource_display_names(),
    )


def datasource_display_names() -> dict[str, str]:
    """Datasource id to the name shown in the console. Empty when the table cannot be read."""

    try:
        from sqlalchemy import select

        from adg.control_plane.db import SessionLocal
        from adg.control_plane.models.datasource import Datasource

        with SessionLocal() as session:
            rows = session.execute(select(Datasource.id, Datasource.name)).all()
    except Exception:
        return {}
    names: dict[str, str] = {}
    for datasource_id, name in rows:
        cleaned = " ".join(str(name or "").split())[:200]
        if datasource_id and cleaned:
            names[str(datasource_id)] = cleaned
    return names


def _datasource_labels(datasource_id: str, names: Mapping[str, str]) -> dict[str, str]:
    labels = {"datasource": datasource_id}
    name = names.get(datasource_id)
    if name:
        labels["name"] = name
    return labels


def render(
    admission: "Admission",
    queries: QueryMetrics,
    revocation: "RevocationCache | None" = None,
    blocklist: "BlocklistCache | None" = None,
    names: Mapping[str, str] | None = None,
) -> str:
    """The full exposition text; deterministic ordering (sorted label values)."""

    w = _Writer()
    view = admission.metrics_view()
    known_names = names or {}

    w.family("adg_ext_admission_queued", "gauge", "Requests currently waiting for a slot.")
    w.sample("adg_ext_admission_queued", view.queued)
    w.family("adg_ext_admission_running", "gauge", "Requests currently executing.")
    w.sample("adg_ext_admission_running", view.running)

    running = view.datasource_running
    limits = view.datasource_limits
    breakers = view.breakers
    datasources = sorted(set(running) | set(limits) | set(breakers))
    w.family("adg_ext_admission_datasource_running", "gauge", "Requests executing per datasource.")
    for ds in datasources:
        w.sample(
            "adg_ext_admission_datasource_running",
            running.get(ds, 0),
            **_datasource_labels(ds, known_names),
        )
    w.family(
        "adg_ext_admission_datasource_limit",
        "gauge",
        "Effective datasource concurrency limit after capacity and deployment caps.",
    )
    for ds in datasources:
        w.sample(
            "adg_ext_admission_datasource_limit",
            limits.get(ds, admission.datasource_limit),
            **_datasource_labels(ds, known_names),
        )
    w.family(
        "adg_ext_admission_breaker_state",
        "gauge",
        "Datasource circuit breaker: 0 closed, 1 half_open, 2 open.",
    )
    for ds in sorted(breakers):
        w.sample(
            "adg_ext_admission_breaker_state",
            BREAKER_STATES.get(breakers[ds], 0),
            **_datasource_labels(ds, known_names),
        )

    counters = view.counters
    w.family("adg_ext_admission_admitted_total", "counter", "Requests admitted to execution.")
    w.sample("adg_ext_admission_admitted_total", counters.get("admitted", 0))
    w.family(
        "adg_ext_admission_rejected_total",
        "counter",
        "Requests refused by admission control, by reason.",
    )
    reasons = {
        key[len(_ADMISSION_REJECT_PREFIX) :]: counters[key]
        for key in counters
        if key.startswith(_ADMISSION_REJECT_PREFIX)
    }
    for reason in ADMISSION_REJECT_REASONS:
        reasons.setdefault(reason, 0)
    for reason in sorted(reasons):
        w.sample("adg_ext_admission_rejected_total", reasons[reason], reason=reason)

    w.family(
        "adg_ext_admission_wait_seconds_avg",
        "gauge",
        "Mean admission wait since process start (use the histogram for percentiles).",
    )
    w.sample("adg_ext_admission_wait_seconds_avg", view.wait_seconds_avg)
    _histogram(
        w,
        "adg_ext_admission_wait_seconds",
        "Time spent waiting for an execution slot (admitted and queue_timeout/datasource_busy).",
        admission.wait_histogram,
    )

    outcomes, rejected, audit_unavailable = queries.snapshot()
    w.family(
        "adg_ext_query_total",
        "counter",
        "Managed queries by outcome (completed, failed, timeout, cancelled, rejected).",
    )
    for outcome in OUTCOMES:
        w.sample("adg_ext_query_total", outcomes.get(outcome, 0), outcome=outcome)
    _histogram(
        w,
        "adg_ext_query_duration_seconds",
        "Seconds from gaining an execution slot until the database call returns.",
        queries.duration_histogram(),
    )
    for datasource, histogram in sorted(queries.datasource_durations().items()):
        _histogram(
            w,
            "adg_ext_datasource_query_duration_seconds",
            "Per-datasource seconds from a granted slot until the database returns.",
            histogram,
            **_datasource_labels(datasource, known_names),
        )
    w.family(
        "adg_ext_query_rejected_total",
        "counter",
        "Rejected queries by reason code (the part before the first colon).",
    )
    for reason in sorted(rejected):
        w.sample("adg_ext_query_rejected_total", rejected[reason], reason=reason)
    w.family(
        "adg_ext_audit_unavailable_total",
        "counter",
        "Queries refused because the pre-execution audit record could not be written.",
    )
    w.sample("adg_ext_audit_unavailable_total", audit_unavailable)

    revocation_on = revocation is not None and revocation.enabled
    w.family(
        "adg_ext_revocation_enabled",
        "gauge",
        "1 when the revocation list is being pulled, otherwise 0.",
    )
    w.sample("adg_ext_revocation_enabled", 1 if revocation_on else 0)
    blocklist_on = blocklist is not None and blocklist.enabled
    w.family(
        "adg_ext_blocklist_enabled",
        "gauge",
        "1 when the source blocklist is being enforced, otherwise 0.",
    )
    w.sample("adg_ext_blocklist_enabled", 1 if blocklist_on else 0)

    if revocation_on and revocation is not None:
        w.family(
            "adg_ext_revocation_poll_age_seconds",
            "gauge",
            "Seconds since the revocation list was last pulled successfully "
            "(since start-up when it never was).",
        )
        w.sample("adg_ext_revocation_poll_age_seconds", revocation.poll_age_seconds())
    if blocklist_on and blocklist is not None:
        w.family(
            "adg_ext_blocklist_version",
            "gauge",
            "Version of the source blocklist currently enforced.",
        )
        w.sample("adg_ext_blocklist_version", blocklist.version)
        w.family("adg_ext_blocklist_entries", "gauge", "Entries in the enforced blocklist.")
        w.sample("adg_ext_blocklist_entries", blocklist.size())
        w.family(
            "adg_ext_blocklist_poll_age_seconds",
            "gauge",
            "Seconds since the blocklist was last pulled successfully "
            "(since start-up when it never was).",
        )
        w.sample("adg_ext_blocklist_poll_age_seconds", blocklist.poll_age_seconds())
        w.family(
            "adg_ext_blocklist_refused_total",
            "counter",
            "Blocklist snapshots refused by the shrink guard.",
        )
        w.sample("adg_ext_blocklist_refused_total", blocklist.refused)
        w.family(
            "adg_ext_blocked_total",
            "counter",
            "Requests refused by the blocklist, by reason (source_blocked / grant_frozen).",
        )
        w.sample("adg_ext_blocked_total", blocklist.blocked_total, reason="source_blocked")
        w.sample("adg_ext_blocked_total", blocklist.frozen_total, reason="grant_frozen")
    _render_runtime(w)
    return w.text()


def _histogram(
    w: _Writer, metric: str, help_: str, histogram: Histogram, **labels: object
) -> None:
    buckets, total, count = histogram.snapshot()
    # One family header per metric name. Callers with the same name must share one header.
    if not any(line.startswith(f"# TYPE {metric} ") for line in w.lines):
        w.family(metric, "histogram", help_)
    for bound, n in buckets:
        _histogram_sample(w, f"{metric}_bucket", n, le=_bound(bound), **labels)
    _histogram_sample(w, f"{metric}_bucket", count, le="+Inf", **labels)
    _histogram_sample(w, f"{metric}_sum", total, **labels)
    _histogram_sample(w, f"{metric}_count", count, **labels)


def _histogram_sample(w: _Writer, metric: str, value: float, **labels: object) -> None:
    ordered = {k: v for k, v in labels.items() if k != "le"}
    if "le" in labels:
        ordered["le"] = labels["le"]
    w.sample(name, value, **ordered)


def _rss_bytes() -> int:
    try:
        with open("/proc/self/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return int(rss)
    return int(rss) * 1024


def _open_fds() -> int | None:
    for path in ("/proc/self/fd", "/dev/fd"):
        try:
            return max(0, len(os.listdir(path)) - 1)
        except OSError:
            continue
    return None


def loop_lag_seconds() -> float:
    with _loop_lag_lock:
        return _loop_lag


async def watch_event_loop(interval: float = 1.0) -> None:
    """Record how late the event loop wakes up. A stuck loop still serves a stale gauge."""

    global _loop_lag
    try:
        while True:
            started = time.perf_counter()
            await asyncio.sleep(interval)
            lag = max(0.0, time.perf_counter() - started - interval)
            with _loop_lag_lock:
                _loop_lag = lag
    except asyncio.CancelledError:
        raise


def _render_runtime(w: _Writer) -> None:
    """Process and interpreter metrics. Names match prometheus_client's default collectors."""

    usage = resource.getrusage(resource.RUSAGE_SELF)
    w.family(
        "process_cpu_seconds_total",
        "counter",
        "Total user and system CPU time spent in seconds.",
    )
    w.sample("process_cpu_seconds_total", usage.ru_utime + usage.ru_stime)
    w.family("process_resident_memory_bytes", "gauge", "Resident memory size in bytes.")
    w.sample("process_resident_memory_bytes", _rss_bytes())
    w.family(
        "process_start_time_seconds",
        "gauge",
        "Start time of the process since unix epoch in seconds.",
    )
    w.sample("process_start_time_seconds", _PROCESS_START)
    w.family("process_max_fds", "gauge", "Maximum number of open file descriptors.")
    w.sample("process_max_fds", resource.getrlimit(resource.RLIMIT_NOFILE)[0])
    open_fds = _open_fds()
    if open_fds is not None:
        w.family("process_open_fds", "gauge", "Number of open file descriptors.")
        w.sample("process_open_fds", open_fds)
    w.family(
        "adg_asyncio_loop_lag_seconds",
        "gauge",
        "Seconds the event loop was late for its last one-second wake. 0 until the watcher starts.",
    )
    w.sample("adg_asyncio_loop_lag_seconds", loop_lag_seconds())

    w.family(
        "python_gc_collections_total",
        "counter",
        "Number of garbage collections, by generation.",
    )
    w.family(
        "python_gc_objects_collected_total",
        "counter",
        "Objects collected during garbage collection, by generation.",
    )
    for generation, stat in enumerate(gc.get_stats()):
        label = str(generation)
        w.sample("python_gc_collections_total", stat.get("collections", 0), generation=label)
        w.sample(
            "python_gc_objects_collected_total",
            stat.get("collected", 0),
            generation=label,
        )
