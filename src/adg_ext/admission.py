"""Admission control (PA-4): per-user concurrency, a bounded FIFO queue, a datasource-wide
limit and a per-datasource circuit breaker.

The runtime is synchronous and runs in worker threads, so the controller is thread based. A query
first takes one of the user's concurrency slots (waiting in a bounded FIFO queue when they are all
busy), then a slot of the datasource-wide limit. Every refusal is a stable reason code:
``queue_full``, ``queue_timeout``, ``datasource_busy``, ``circuit_open`` or ``revoked``.
"""

import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from adg_ext.metrics import Histogram
from adg_ext.redis_share import get_share

# Rejections that happened after (some) waiting; they feed the wait histogram so that a long tail
# of queue timeouts is visible, whereas ``queue_full``/``circuit_open`` refuse instantly.
_WAITED_REJECTIONS = frozenset({"queue_timeout", "datasource_busy", "revoked"})


@dataclass(frozen=True)
class MetricsView:
    """A consistent copy of the controller state for the Prometheus exposition."""

    queued: int
    running: int
    datasource_running: dict[str, int]
    breakers: dict[str, str]
    counters: dict[str, int]
    wait_seconds_avg: float


class AdmissionRejected(Exception):
    """The request was not admitted; ``reason`` is a stable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class _Waiter:
    tags: frozenset[str] = frozenset()
    cancelled: bool = False


@dataclass
class _Lane:
    running: int = 0
    queue: deque[_Waiter] = field(default_factory=deque)
    tickets: set["Ticket"] = field(default_factory=set)


class Ticket:
    """A granted execution slot. Release exactly once; ``cancel`` kills the running query."""

    def __init__(
        self,
        controller: "Admission",
        user_key: str,
        datasource_key: str,
        waited: float,
        tags: frozenset[str] = frozenset(),
    ):
        self._controller = controller
        self.tags = tags
        self.user_key = user_key
        self.datasource_key = datasource_key
        self.waited_seconds = waited
        self.cancelled = False
        self._released = False
        self._on_cancel: Callable[[], None] | None = None
        self._lock = threading.Lock()
        self.redis_member: str | None = None

    def on_cancel(self, callback: Callable[[], None]) -> None:
        with self._lock:
            self._on_cancel = callback
            already = self.cancelled
        if already:
            callback()

    def cancel(self) -> None:
        with self._lock:
            self.cancelled = True
            callback = self._on_cancel
        if callback is not None:
            callback()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._controller._release(self)


class CircuitBreaker:
    """Opens after consecutive failures, lets one probe through after the cool-down."""

    def __init__(self, threshold: int, open_seconds: float, clock: Callable[[], float]) -> None:
        self._threshold = threshold
        self._open_seconds = open_seconds
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._probing = False
        self._lock = threading.Lock()

    @property
    def threshold(self) -> int:
        return self._threshold

    @property
    def open_seconds(self) -> float:
        return self._open_seconds

    @property
    def state(self) -> str:
        with self._lock:
            if self._opened_at is None:
                return "closed"
            return "half_open" if self._probing else "open"

    def allow(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return True
            if self._probing:
                return False
            if self._clock() - self._opened_at >= self._open_seconds:
                self._probing = True
                return True
            return False

    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._probing = False

    def failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._probing or self._failures >= self._threshold:
                self._opened_at = self._clock()
                self._probing = False

    def release_probe(self) -> None:
        """A probe that ended without a verdict (e.g. cancelled) must not wedge the breaker."""

        with self._lock:
            self._probing = False


class Admission:
    def __init__(
        self,
        *,
        datasource_limit: int = 20,
        breaker_threshold: int = 5,
        breaker_open_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._datasource_limit = datasource_limit
        self._breaker_threshold = breaker_threshold
        self._breaker_open_seconds = breaker_open_seconds
        self._clock = clock
        self._cond = threading.Condition()
        self._lanes: dict[str, _Lane] = {}
        self._datasource_running: dict[str, int] = {}
        self._breakers: dict[str, CircuitBreaker] = {}
        self._counters: dict[str, int] = {}
        self._wait_total = 0.0
        self._wait_count = 0
        self.wait_histogram = Histogram()

    # ---- metrics ----------------------------------------------------------------------------

    @property
    def datasource_limit(self) -> int:
        return self._datasource_limit

    def _count(self, name: str) -> None:
        self._counters[name] = self._counters.get(name, 0) + 1

    def count_rejection(self, reason: str) -> None:
        """Count a refusal decided outside the controller (e.g. ``pool_exhausted``)."""

        with self._cond:
            self._count(f"rejected_{reason}")

    def metrics_view(self) -> MetricsView:
        with self._cond:
            return MetricsView(
                queued=sum(len(lane.queue) for lane in self._lanes.values()),
                running=sum(lane.running for lane in self._lanes.values()),
                datasource_running=dict(self._datasource_running),
                breakers={k: b.state for k, b in self._breakers.items()},
                counters=dict(self._counters),
                wait_seconds_avg=(self._wait_total / self._wait_count) if self._wait_count else 0.0,
            )

    def snapshot(self) -> dict[str, object]:
        with self._cond:
            return {
                "queued": sum(len(lane.queue) for lane in self._lanes.values()),
                "running": sum(lane.running for lane in self._lanes.values()),
                "datasource_running": dict(self._datasource_running),
                "breakers": {k: b.state for k, b in self._breakers.items()},
                "counters": dict(self._counters),
                "wait_seconds_avg": (self._wait_total / self._wait_count)
                if self._wait_count
                else 0.0,
            }

    # ---- breaker ----------------------------------------------------------------------------

    def breaker(self, datasource_key: str) -> CircuitBreaker:
        with self._cond:
            breaker = self._breakers.get(datasource_key)
            if breaker is None:
                breaker = CircuitBreaker(
                    self._breaker_threshold, self._breaker_open_seconds, self._clock
                )
                self._breakers[datasource_key] = breaker
            return breaker

    # ---- admission --------------------------------------------------------------------------

    def acquire(
        self,
        *,
        user_key: str,
        datasource_key: str,
        max_concurrency: int,
        queue_size: int,
        queue_timeout: float,
        tags: frozenset[str] = frozenset(),
    ) -> Ticket:
        max_concurrency = max(1, max_concurrency)
        if get_share().circuit_open(datasource_key) or not self.breaker(datasource_key).allow():
            with self._cond:
                self._count("rejected_circuit_open")
            raise AdmissionRejected("circuit_open")
        started = self._clock()
        deadline = started + max(0.0, queue_timeout)
        try:
            self._take_user_slot(user_key, max_concurrency, queue_size, deadline, tags)
        except AdmissionRejected as error:
            self.breaker(datasource_key).release_probe()
            self._observe_rejected_wait(error, started)
            raise
        try:
            self._take_datasource_slot(datasource_key, deadline)
        except AdmissionRejected as error:
            with self._cond:
                self._lanes[user_key].running -= 1
                self._cond.notify_all()
            self.breaker(datasource_key).release_probe()
            self._observe_rejected_wait(error, started)
            raise
        waited = self._clock() - started
        self.wait_histogram.observe(waited)
        ticket = Ticket(self, user_key, datasource_key, waited, tags)
        with self._cond:
            self._lanes[user_key].tickets.add(ticket)
            self._wait_total += waited
            self._wait_count += 1
            self._count("admitted")
        member = uuid.uuid4().hex
        share = get_share()
        if not share.try_slot(f"user:{user_key}", max_concurrency, member):
            self._release(ticket)
            raise AdmissionRejected("queue_full")
        if not share.try_slot(f"ds:{datasource_key}", self._datasource_limit, member):
            share.release_slot(f"user:{user_key}", member)
            self._release(ticket)
            raise AdmissionRejected("datasource_busy")
        ticket.redis_member = member
        return ticket

    def _observe_rejected_wait(self, error: AdmissionRejected, started: float) -> None:
        if error.reason in _WAITED_REJECTIONS:
            self.wait_histogram.observe(self._clock() - started)

    def _take_user_slot(
        self,
        user_key: str,
        max_concurrency: int,
        queue_size: int,
        deadline: float,
        tags: frozenset[str],
    ) -> None:
        with self._cond:
            lane = self._lanes.setdefault(user_key, _Lane())
            if lane.running < max_concurrency and not lane.queue:
                lane.running += 1
                return
            if len(lane.queue) >= queue_size:
                self._count("rejected_queue_full")
                raise AdmissionRejected("queue_full")
            waiter = _Waiter(tags)
            lane.queue.append(waiter)
            try:
                while True:
                    if waiter.cancelled:
                        self._count("rejected_revoked")
                        raise AdmissionRejected("revoked")
                    if lane.queue[0] is waiter and lane.running < max_concurrency:
                        lane.queue.popleft()
                        lane.running += 1
                        # the next waiter may also fit (the limit can have been raised)
                        self._cond.notify_all()
                        return
                    remaining = deadline - self._clock()
                    if remaining <= 0:
                        self._count("rejected_queue_timeout")
                        raise AdmissionRejected("queue_timeout")
                    self._cond.wait(remaining)
            except AdmissionRejected:
                if waiter in lane.queue:
                    lane.queue.remove(waiter)
                self._cond.notify_all()
                raise

    def _take_datasource_slot(self, datasource_key: str, deadline: float) -> None:
        with self._cond:
            while self._datasource_running.get(datasource_key, 0) >= self._datasource_limit:
                remaining = deadline - self._clock()
                if remaining <= 0:
                    self._count("rejected_datasource_busy")
                    raise AdmissionRejected("datasource_busy")
                self._cond.wait(remaining)
            self._datasource_running[datasource_key] = (
                self._datasource_running.get(datasource_key, 0) + 1
            )

    def _release(self, ticket: Ticket) -> None:
        with self._cond:
            lane = self._lanes.get(ticket.user_key)
            if lane is not None:
                lane.running = max(0, lane.running - 1)
                lane.tickets.discard(ticket)
            current = self._datasource_running.get(ticket.datasource_key, 0)
            self._datasource_running[ticket.datasource_key] = max(0, current - 1)
            self._cond.notify_all()
        member = getattr(ticket, "redis_member", None)
        if member:
            share = get_share()
            share.release_slot(f"user:{ticket.user_key}", member)
            share.release_slot(f"ds:{ticket.datasource_key}", member)

    # ---- revocation -------------------------------------------------------------------------

    def revoke(self, tag: str) -> int:
        """Reject every queued request and kill every running one carrying ``tag``.

        Pipelines tag requests with the user id and the API key id, so a revoked key (or a
        disabled user) takes effect on its own requests only.
        """

        tickets: list[Ticket] = []
        affected = 0
        with self._cond:
            for lane in self._lanes.values():
                for waiter in lane.queue:
                    if tag in waiter.tags:
                        waiter.cancelled = True
                        affected += 1
                for ticket in lane.tickets:
                    if tag in ticket.tags:
                        tickets.append(ticket)
            self._cond.notify_all()
        for ticket in tickets:
            ticket.cancel()
        return affected + len(tickets)

    revoke_user = revoke
