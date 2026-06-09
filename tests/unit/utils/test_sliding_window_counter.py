"""``SlidingWindowCounter`` reusable primitive (Task 32).

A deque-of-timestamps counter: ``increment()`` records an event,
``count_in_window(window)`` counts events newer than ``now - window``, and
``exceeds(threshold, window)`` is the breaker trigger the comms dispatcher
uses (3 handler failures inside 5 minutes trips the adapter breaker).
Entries age out lazily on each query.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from alfred.utils.sliding_window_counter import SlidingWindowCounter


def test_counter_aggregates() -> None:
    now = datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)
    c = SlidingWindowCounter(clock=lambda: now)
    c.increment()
    c.increment()
    assert c.count_in_window(timedelta(minutes=5)) == 2
    assert not c.exceeds(threshold=3, window=timedelta(minutes=5))
    c.increment()
    assert c.exceeds(threshold=3, window=timedelta(minutes=5))


def test_entries_age_out() -> None:
    clock_value = [datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)]
    c = SlidingWindowCounter(clock=lambda: clock_value[0])
    c.increment()
    clock_value[0] += timedelta(minutes=6)
    assert c.count_in_window(timedelta(minutes=5)) == 0


def test_exceeds_is_inclusive_threshold() -> None:
    now = datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)
    c = SlidingWindowCounter(clock=lambda: now)
    c.increment()
    c.increment()
    # exactly at threshold -> exceeds is True (>=).
    assert c.exceeds(threshold=2, window=timedelta(minutes=5))
    assert not c.exceeds(threshold=3, window=timedelta(minutes=5))


def test_default_clock_is_utc_now() -> None:
    # Constructing without a clock must work and count a fresh increment.
    c = SlidingWindowCounter()
    c.increment()
    assert c.count_in_window(timedelta(minutes=5)) == 1


def test_boundary_entry_at_window_edge_excluded() -> None:
    clock_value = [datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)]
    c = SlidingWindowCounter(clock=lambda: clock_value[0])
    c.increment()
    # Advance exactly to the window edge: the entry is now == cutoff, excluded.
    clock_value[0] += timedelta(minutes=5)
    assert c.count_in_window(timedelta(minutes=5)) == 0
