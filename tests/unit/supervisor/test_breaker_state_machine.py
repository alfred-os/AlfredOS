"""CircuitBreaker state-machine tests (spec §10.2).

Pins the three-state machine on a pure in-memory CircuitBreaker — DB
persistence is exercised separately in
``tests/unit/supervisor/test_persisted_state_restore.py``.

Test discipline:

* Pure unit tests — no DB, no clock. All transitions take an injected
  ``now=`` so we never sleep.
* Frozen-time pattern: a fixed ``base`` datetime and ``timedelta`` offsets
  describe every event. Wall-clock flake is impossible by construction.
* ``_make_cb`` injects an ``AsyncMock`` session_scope so save_to_db calls
  later (Task 8) do not need real DB plumbing in this file.
"""

from __future__ import annotations

import datetime as dt
from unittest.mock import AsyncMock

import pytest

from alfred.supervisor.breaker import (
    _BACKOFF_INITIAL_SECONDS,
    _BACKOFF_MAX_SECONDS,
    _BACKOFF_MULTIPLIER,
    BreakerState,
    CircuitBreaker,
)
from alfred.supervisor.errors import BreakStateError, QuarantinedUnavailable


def _make_cb(**kwargs: object) -> CircuitBreaker:
    """Construct a CircuitBreaker with a mocked session_scope.

    Why an ``AsyncMock`` and not ``None``: later tests (Task 8) call
    ``save_to_db`` via the real lock path; passing ``None`` would make
    those tests harder to extend. For the pure state-machine tests in this
    file the session is never touched.
    """
    return CircuitBreaker(component_id="test-plugin", session_scope=AsyncMock(), **kwargs)  # type: ignore[arg-type]


def test_initial_state_is_closed() -> None:
    """A fresh breaker starts CLOSED with zero trip count (spec §10.2)."""
    cb = CircuitBreaker(component_id="test-plugin", session_scope=None)
    assert cb.state == BreakerState.CLOSED
    assert cb.trip_count == 0
    assert cb.last_trip_at is None


def test_breaker_state_enum_values() -> None:
    """Exactly three states — closed domain pinned by DB CHECK constraint."""
    assert {s.value for s in BreakerState} == {"CLOSED", "OPEN", "HALF_OPEN"}


# ---------------------------------------------------------------------------
# record_failure / assert_available (Task 5)
# ---------------------------------------------------------------------------


def test_single_failure_stays_closed() -> None:
    """One failure does NOT trip the breaker — threshold is 3."""
    cb = _make_cb()
    cb.record_failure(
        "SubprocessExitedError",
        now=dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC),
    )
    assert cb.state == BreakerState.CLOSED
    assert cb.trip_count == 0


def test_three_failures_in_window_opens_breaker() -> None:
    """Threshold failures inside the 5min window trip CLOSED→OPEN."""
    cb = _make_cb()
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    for i in range(3):
        cb.record_failure(
            "SubprocessExitedError",
            now=base + dt.timedelta(seconds=i * 60),
        )
    assert cb.state == BreakerState.OPEN
    assert cb.trip_count == 1
    assert cb.last_trip_at == base + dt.timedelta(seconds=120)


def test_failures_outside_window_do_not_trip() -> None:
    """Failures separated by >5min do not accumulate toward threshold."""
    cb = _make_cb()
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    cb.record_failure("SubprocessExitedError", now=base)
    cb.record_failure(
        "SubprocessExitedError", now=base + dt.timedelta(seconds=400)
    )  # outside 5min — drops the first
    cb.record_failure(
        "SubprocessExitedError", now=base + dt.timedelta(seconds=800)
    )  # outside 5min — drops the second
    assert cb.state == BreakerState.CLOSED


def test_record_failure_in_open_state_is_noop() -> None:
    """Once OPEN, additional failures are ignored — trip_count stays at 1."""
    cb = _make_cb()
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    for i in range(3):
        cb.record_failure("SubprocessExitedError", now=base + dt.timedelta(seconds=i))
    assert cb.state == BreakerState.OPEN
    cb.record_failure("SubprocessExitedError", now=base + dt.timedelta(seconds=10))
    assert cb.trip_count == 1  # not incremented again


def test_record_failure_default_now_uses_wall_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Omitting ``now`` falls back to ``datetime.now(UTC)``.

    Pins the production-path default — every callsite from
    ``PluginLifecycle.on_crash`` (Task 10) relies on it.
    """
    cb = _make_cb()
    fixed = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)

    class _FrozenDateTime(dt.datetime):
        @classmethod
        def now(cls, tz: dt.tzinfo | None = None) -> dt.datetime:  # type: ignore[override]
            return fixed if tz is None else fixed.astimezone(tz)

    monkeypatch.setattr("alfred.supervisor.breaker.dt", _patched_dt_module(_FrozenDateTime))
    cb.record_failure("SubprocessExitedError")
    assert cb._recent_failures == [fixed]


def _patched_dt_module(replacement: type[dt.datetime]) -> object:
    """Return an object that proxies the ``datetime`` module with ``datetime`` swapped.

    Lighter-weight than monkeypatching the real ``datetime`` class: replaces
    just the attribute the production code reads (``dt.datetime``,
    ``dt.timedelta``, ``dt.UTC``). Keeps the rest of the ``datetime`` API
    untouched and isolated to this test.
    """

    class _ProxyModule:
        datetime = replacement
        timedelta = dt.timedelta
        UTC = dt.UTC

    return _ProxyModule()


def test_assert_available_open_raises() -> None:
    """OPEN breaker raises QuarantinedUnavailable on assert_available()."""
    cb = _make_cb()
    cb.state = BreakerState.OPEN
    with pytest.raises(QuarantinedUnavailable):
        cb.assert_available()


def test_assert_available_closed_is_silent() -> None:
    """CLOSED breaker passes assert_available() without raising."""
    cb = _make_cb()
    cb.assert_available()  # no raise


def test_assert_available_half_open_is_silent() -> None:
    """HALF_OPEN breaker allows the probe — assert_available() does not raise.

    Only OPEN is fully closed to traffic. HALF_OPEN lets the probe through
    so the lifecycle can attempt re-entry to CLOSED.
    """
    cb = _make_cb()
    cb.state = BreakerState.HALF_OPEN
    cb.assert_available()  # no raise


# ---------------------------------------------------------------------------
# maybe_rearm / probe handlers (Task 6)
# ---------------------------------------------------------------------------


def test_open_rearms_after_1h() -> None:
    """OPEN→HALF_OPEN after the re-arm window elapses (spec §10.2)."""
    cb = _make_cb()
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    cb.state = BreakerState.OPEN
    cb.last_trip_at = base - dt.timedelta(seconds=3601)  # > 1h ago
    cb.maybe_rearm(now=base)
    assert cb.state == BreakerState.HALF_OPEN


def test_open_does_not_rearm_before_1h() -> None:
    """OPEN stays OPEN until the re-arm window elapses."""
    cb = _make_cb()
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    cb.state = BreakerState.OPEN
    cb.last_trip_at = base - dt.timedelta(seconds=1800)  # 30min ago
    cb.maybe_rearm(now=base)
    assert cb.state == BreakerState.OPEN


def test_maybe_rearm_noop_for_closed() -> None:
    """maybe_rearm is a no-op for non-OPEN states (defensive guard)."""
    cb = _make_cb()
    assert cb.state == BreakerState.CLOSED
    cb.maybe_rearm(now=dt.datetime(2030, 1, 1, tzinfo=dt.UTC))
    assert cb.state == BreakerState.CLOSED


def test_maybe_rearm_noop_for_half_open() -> None:
    """maybe_rearm is a no-op for HALF_OPEN — re-arm runs only from OPEN."""
    cb = _make_cb()
    cb.state = BreakerState.HALF_OPEN
    cb.maybe_rearm(now=dt.datetime(2030, 1, 1, tzinfo=dt.UTC))
    assert cb.state == BreakerState.HALF_OPEN


def test_maybe_rearm_noop_when_last_trip_at_is_none() -> None:
    """OPEN without a known trip time stays OPEN — refuse to re-arm blind.

    Defensive: every legitimate trip records last_trip_at via _trip(). A
    None here implies bad state and we leave the operator's reset path as
    the only way out.
    """
    cb = _make_cb()
    cb.state = BreakerState.OPEN
    cb.last_trip_at = None
    cb.maybe_rearm(now=dt.datetime(2030, 1, 1, tzinfo=dt.UTC))
    assert cb.state == BreakerState.OPEN


def test_maybe_rearm_default_now_uses_wall_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Omitting ``now=`` falls back to wall-clock now(UTC).

    Pins the supervisor-scheduler default — the periodic re-arm sweep
    calls ``maybe_rearm()`` with no arguments.
    """
    cb = _make_cb()
    cb.state = BreakerState.OPEN
    fixed = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    cb.last_trip_at = fixed - dt.timedelta(hours=2)

    class _FrozenDateTime(dt.datetime):
        @classmethod
        def now(cls, tz: dt.tzinfo | None = None) -> dt.datetime:  # type: ignore[override]
            return fixed if tz is None else fixed.astimezone(tz)

    monkeypatch.setattr("alfred.supervisor.breaker.dt", _patched_dt_module(_FrozenDateTime))
    cb.maybe_rearm()
    assert cb.state == BreakerState.HALF_OPEN


def test_half_open_probe_success_closes_and_resets_backoff() -> None:
    """A successful HALF_OPEN probe closes the breaker; backoff resets."""
    cb = _make_cb()
    cb.state = BreakerState.HALF_OPEN
    cb._backoff_seconds = 80.0  # simulate post-failure backoff
    cb.record_probe_success()
    assert cb.state == BreakerState.CLOSED
    assert cb._backoff_seconds == _BACKOFF_INITIAL_SECONDS


def test_half_open_probe_failure_reopens_and_doubles_backoff() -> None:
    """A failed HALF_OPEN probe reopens the breaker; backoff doubles."""
    cb = _make_cb()
    cb.state = BreakerState.HALF_OPEN
    cb.record_probe_failure("SubprocessExitedError")
    assert cb.state == BreakerState.OPEN
    assert cb._backoff_seconds == _BACKOFF_INITIAL_SECONDS * _BACKOFF_MULTIPLIER


def test_record_probe_failure_caps_backoff_at_max() -> None:
    """Backoff caps at _BACKOFF_MAX_SECONDS — never grows unbounded."""
    cb = _make_cb()
    cb.state = BreakerState.HALF_OPEN
    cb._backoff_seconds = _BACKOFF_MAX_SECONDS  # already at cap
    cb.record_probe_failure("SubprocessExitedError")
    assert cb._backoff_seconds == _BACKOFF_MAX_SECONDS


def test_record_probe_success_outside_half_open_raises() -> None:
    """Calling record_probe_success() outside HALF_OPEN is a protocol error."""
    cb = _make_cb()
    assert cb.state == BreakerState.CLOSED
    with pytest.raises(BreakStateError):
        cb.record_probe_success()


def test_record_probe_failure_outside_half_open_raises() -> None:
    """Calling record_probe_failure() outside HALF_OPEN is a protocol error."""
    cb = _make_cb()
    cb.state = BreakerState.OPEN
    with pytest.raises(BreakStateError):
        cb.record_probe_failure("SubprocessExitedError")
