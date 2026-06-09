"""``SlidingWindowCounter`` — a deque-of-timestamps event-rate counter.

Reusable primitive (PR-S4-8, Task 32). The comms dispatcher uses it as the
error-rate breaker trigger: three handler failures inside a five-minute
window trips the adapter's circuit breaker. Kept dependency-free so any
subsystem can adopt it.

Semantics:

* :meth:`increment` records one event at the current clock time.
* :meth:`count_in_window` returns the number of events strictly newer than
  ``now - window``. An event exactly on the cutoff is *excluded* so a window
  is a half-open ``(now - window, now]`` interval — a counter never
  double-counts an event that has aged exactly to the boundary.
* :meth:`exceeds` is the breaker predicate: ``count_in_window >= threshold``.

Aging is lazy — stale entries are pruned on each query, never on a timer, so
the counter holds no background task and is cheap to construct per adapter.

The ``clock`` is injectable (defaulting to ``datetime.now(UTC)``) so tests
drive time deterministically. The counter stores aware ``datetime`` values
for human-readable window math; the token-bucket refill math elsewhere uses
``time.monotonic()`` (comms-003) because it does arithmetic on elapsed
deltas where an NTP step would corrupt state — this counter only compares
timestamps to a cutoff, so a clock step at worst prunes a little early or
late, never corrupts a running total.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SlidingWindowCounter:
    """Counts events within a trailing time window. Not thread-safe by design.

    Callers that share a counter across tasks serialise their own access (the
    comms dispatcher holds it under the per-adapter dispatch path, which is
    already single-flighted by the dispatch semaphore).
    """

    def __init__(self, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._clock = clock
        self._events: deque[datetime] = deque()

    def increment(self) -> None:
        """Record one event at the current clock time."""
        self._events.append(self._clock())

    def count_in_window(self, window: timedelta) -> int:
        """Number of events strictly newer than ``now - window``.

        Prunes events at or before the cutoff as a side effect so the deque
        never grows unbounded for a long-lived counter.
        """
        cutoff = self._clock() - window
        while self._events and self._events[0] <= cutoff:
            self._events.popleft()
        return len(self._events)

    def exceeds(self, *, threshold: int, window: timedelta) -> bool:
        """True when at least ``threshold`` events fall inside ``window``."""
        return self.count_in_window(window) >= threshold


__all__ = ["SlidingWindowCounter"]
