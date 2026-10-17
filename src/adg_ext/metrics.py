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

import re
import threading
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from adg_ext.admission import Admission
    from adg_ext.blocklist import BlocklistCache
    from adg_ext.revocation import RevocationCache

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

OUTCOMES = ("completed", "failed", "timeout", "cancelled", "rejected")
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

    def sample(self, name: str, value: float, **labels: object) -> None:
        if labels:
            rendered = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
            self.lines.append(f"{name}{{{rendered}}} {_number(value)}")
        else:
            self.lines.append(f"{name} {_number(value)}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def render(
    admission: "Admission",
    queries: QueryMetrics,
    revocation: "RevocationCache | None" = None,
    blocklist: "BlocklistCache | None" = None,
) -> str:
    """The full exposition text; deterministic ordering (sorted label values)."""

    w = _Writer()
    view = admission.metrics_view()

    w.family("adg_ext_admission_queued", "gauge", "Requests currently waiting for a slot.")
    w.sample("adg_ext_admission_queued", view.queued)
    w.family("adg_ext_admission_running", "gauge", "Requests currently executing.")
    w.sample("adg_ext_admission_running", view.running)

    running = view.datasource_running
    breakers = view.breakers
    datasources = sorted(set(running) | set(breakers))
    w.family("adg_ext_admission_datasource_running", "gauge", "Requests executing per datasource.")
    for ds in datasources:
        w.sample("adg_ext_admission_datasource_running", running.get(ds, 0), datasource=ds)
    w.family(
        "adg_ext_admission_datasource_limit",
        "gauge",
        "Datasource-wide concurrency limit (ADG_EXT_DATASOURCE_MAX_CONCURRENCY).",
    )
    for ds in datasources:
        w.sample("adg_ext_admission_datasource_limit", admission.datasource_limit, datasource=ds)
    w.family(
        "adg_ext_admission_breaker_state",
        "gauge",
        "Datasource circuit breaker: 0 closed, 1 half_open, 2 open.",
    )
    for ds in sorted(breakers):
        w.sample(
            "adg_ext_admission_breaker_state", BREAKER_STATES.get(breakers[ds], 0), datasource=ds
        )

    counters = view.counters
    w.family("adg_ext_admission_admitted_total", "counter", "Requests admitted to execution.")
    w.sample("adg_ext_admission_admitted_total", counters.get("admitted", 0))
    w.family(
        "adg_ext_admission_rejected_total",
        "counter",
        "Requests refused by admission control, by reason.",
    )
    for key in sorted(k for k in counters if k.startswith(_ADMISSION_REJECT_PREFIX)):
        w.sample(
            "adg_ext_admission_rejected_total",
            counters[key],
            reason=key[len(_ADMISSION_REJECT_PREFIX) :],
        )

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

    if revocation is not None and revocation.enabled:
        w.family(
            "adg_ext_revocation_poll_age_seconds",
            "gauge",
            "Seconds since the revocation list was last pulled successfully "
            "(since start-up when it never was).",
        )
        w.sample("adg_ext_revocation_poll_age_seconds", revocation.poll_age_seconds())
    if blocklist is not None and blocklist.enabled:
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
    return w.text()


def _histogram(w: _Writer, name: str, help_: str, histogram: Histogram) -> None:
    buckets, total, count = histogram.snapshot()
    w.family(name, "histogram", help_)
    for bound, n in buckets:
        w.lines.append(f'{name}_bucket{{le="{_bound(bound)}"}} {n}')
    w.lines.append(f'{name}_bucket{{le="+Inf"}} {count}')
    w.lines.append(f"{name}_sum {_number(total)}")
    w.lines.append(f"{name}_count {count}")
