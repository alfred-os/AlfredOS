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


# ---------------------------------------------------------------------------
# reset() operator-triggered (Task 7)
# ---------------------------------------------------------------------------


def test_operator_reset_from_open_closes_and_preserves_trip_count() -> None:
    """reset() transitions OPEN→CLOSED. trip_count is an audit counter — preserved."""
    cb = _make_cb()
    cb.state = BreakerState.OPEN
    cb.trip_count = 5
    cb.last_trip_at = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)
    cb.reset()
    assert cb.state == BreakerState.CLOSED
    assert cb.trip_count == 5  # NOT cleared — audit trail must survive reset


def test_reset_from_closed_is_silent_noop() -> None:
    """reset() from CLOSED is a no-op — no raise, no audit churn."""
    cb = _make_cb()
    assert cb.state == BreakerState.CLOSED
    cb.reset()
    assert cb.state == BreakerState.CLOSED


def test_reset_from_half_open_closes() -> None:
    """reset() from HALF_OPEN forces CLOSED — operator overrides the probe."""
    cb = _make_cb()
    cb.state = BreakerState.HALF_OPEN
    cb.reset()
    assert cb.state == BreakerState.CLOSED


def test_reset_clears_recent_failures_and_backoff() -> None:
    """reset() restores the failure window and backoff to a fresh state.

    Without this, the next failure after operator reset would immediately
    re-trip from stale window entries — defeating the operator override.
    """
    cb = _make_cb()
    cb.state = BreakerState.OPEN
    cb._recent_failures = [dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)] * 2
    cb._backoff_seconds = 80.0
    cb.reset()
    assert cb._recent_failures == []
    assert cb._backoff_seconds == _BACKOFF_INITIAL_SECONDS


def test_reset_then_failures_can_trip_fresh() -> None:
    """After reset, three failures inside the window cleanly re-trip.

    End-to-end check that reset() leaves the breaker in a state
    indistinguishable from a freshly-constructed CLOSED breaker (modulo
    trip_count, which the operator wants preserved for audit).
    """
    cb = _make_cb()
    cb.state = BreakerState.OPEN
    cb.trip_count = 1
    cb.last_trip_at = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)
    cb.reset()
    base = dt.datetime(2026, 1, 1, 13, 0, tzinfo=dt.UTC)
    for i in range(3):
        cb.record_failure("SubprocessExitedError", now=base + dt.timedelta(seconds=i))
    assert cb.state == BreakerState.OPEN
    assert cb.trip_count == 2  # incremented past the prior 1


# ---------------------------------------------------------------------------
# Hookpoint invocation helpers (Task 9) — err-001 / core-004
# ---------------------------------------------------------------------------
#
# The helpers are standalone async functions in :mod:`alfred.supervisor.breaker`
# that callers (``PluginLifecycle.on_crash`` Task 10; ``Supervisor.reset_breaker``
# Task 20) await INSIDE their own TaskGroup. ``_trip()`` does NOT spawn
# fire-and-forget hookpoint tasks (err-001 / core-004). These tests pin the
# contract: helper signatures match the documented input shapes; helpers route
# through :func:`alfred.hooks.invoke.invoke` with ``name`` as the positional
# arg (core-004); ``_trip()`` does not call ``create_task`` on the running
# loop (err-001 fire-and-forget regression guard).


def test_trip_does_not_fire_and_forget_hookpoint() -> None:
    """``_trip()`` must NOT spawn a fire-and-forget task (err-001 / core-004).

    Hookpoint invocation is the caller's responsibility (``PluginLifecycle``
    Task 10; ``Supervisor.reset_breaker`` Task 20). If a future refactor
    re-introduces ``asyncio.get_running_loop().create_task(...)`` inside
    ``_trip``, this test catches it. ``record_failure`` calls ``_trip`` on the
    threshold-crossing call; we patch the loop accessor and assert
    ``create_task`` is never reached.
    """
    from unittest.mock import patch

    cb = _make_cb()
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    with patch("asyncio.get_running_loop") as mock_loop:
        for i in range(3):
            cb.record_failure(
                "SubprocessExitedError",
                now=base + dt.timedelta(seconds=i),
            )
    assert cb.state == BreakerState.OPEN
    mock_loop.return_value.create_task.assert_not_called()


@pytest.mark.asyncio
async def test_invoke_breaker_tripped_hookpoint_routes_through_invoke() -> None:
    """``invoke_breaker_tripped_hookpoint`` awaits ``invoke`` with ``name`` positional.

    Pins three invariants for the helper:

    * It is ``async`` and awaitable — so callers stay inside the
      ``TaskGroup`` that owns the breaker transition (no fire-and-forget).
    * The first positional argument it passes to ``invoke`` is ``"supervisor.breaker.tripped"``
      (core-004 — verbatim positional ``name``, never ``hookpoint=`` keyword).
    * The ``HookContext.input`` carries the four breaker-tripped subject
      fields callers must thread to the dispatcher: ``component_id``,
      ``trip_count``, ``last_failure_type``, ``breaker_state="OPEN"``.
    """
    from unittest.mock import AsyncMock, patch

    from alfred.supervisor.breaker import invoke_breaker_tripped_hookpoint

    with patch("alfred.hooks.invoke.invoke", new=AsyncMock()) as mock_invoke:
        await invoke_breaker_tripped_hookpoint(
            component_id="comp-A",
            trip_count=3,
            last_failure_type="SubprocessExitedError",
        )
    assert mock_invoke.await_count == 1
    args, kwargs = mock_invoke.call_args
    # core-004 — name passed as the first positional, not a keyword
    assert args[0] == "supervisor.breaker.tripped"
    ctx = args[1]
    assert ctx.input["component_id"] == "comp-A"
    assert ctx.input["trip_count"] == 3
    assert ctx.input["last_failure_type"] == "SubprocessExitedError"
    assert ctx.input["breaker_state"] == "OPEN"
    assert ctx.kind == "post"
    assert kwargs["kind"] == "post"
    assert kwargs["fail_closed"] is False


@pytest.mark.asyncio
async def test_invoke_breaker_reset_hookpoint_routes_through_invoke() -> None:
    """``invoke_breaker_reset_hookpoint`` awaits ``invoke`` with the reset subject.

    Mirrors the tripped-hookpoint helper but for the operator-initiated reset
    path. ``old_state`` survives reset so the audit graph can tell apart a
    no-op CLOSED reset from a true OPEN→CLOSED rescue.
    """
    from unittest.mock import AsyncMock, patch

    from alfred.supervisor.breaker import invoke_breaker_reset_hookpoint

    with patch("alfred.hooks.invoke.invoke", new=AsyncMock()) as mock_invoke:
        await invoke_breaker_reset_hookpoint(
            component_id="comp-B",
            old_state="OPEN",
            new_state="CLOSED",
            trip_count=4,
            operator_user_id="alice",
        )
    assert mock_invoke.await_count == 1
    args, kwargs = mock_invoke.call_args
    assert args[0] == "supervisor.breaker.reset"
    ctx = args[1]
    assert ctx.input["component_id"] == "comp-B"
    assert ctx.input["old_state"] == "OPEN"
    assert ctx.input["new_state"] == "CLOSED"
    assert ctx.input["trip_count"] == 4
    assert ctx.input["operator_user_id"] == "alice"
    assert ctx.kind == "post"
    assert kwargs["kind"] == "post"
    assert kwargs["fail_closed"] is False


@pytest.mark.asyncio
async def test_hookpoint_helpers_generate_distinct_correlation_ids() -> None:
    """Each helper call mints a fresh correlation id so distinct trip rows are joinable.

    A single shared module-level id would let two concurrent crash handlers
    collapse onto the same audit row in downstream readers that index by
    ``correlation_id``.
    """
    from unittest.mock import AsyncMock, patch

    from alfred.supervisor.breaker import invoke_breaker_tripped_hookpoint

    with patch("alfred.hooks.invoke.invoke", new=AsyncMock()) as mock_invoke:
        await invoke_breaker_tripped_hookpoint(
            component_id="c", trip_count=1, last_failure_type="E"
        )
        await invoke_breaker_tripped_hookpoint(
            component_id="c", trip_count=2, last_failure_type="E"
        )
    first_ctx = mock_invoke.call_args_list[0].args[1]
    second_ctx = mock_invoke.call_args_list[1].args[1]
    assert first_ctx.correlation_id != second_ctx.correlation_id


# ---------------------------------------------------------------------------
# Shared ``_invoke_supervisor_hookpoint`` helper (S3-3b-R2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invoke_supervisor_hookpoint_helper_routes_through_invoke() -> None:
    """The shared helper awaits ``invoke`` with ``name`` positional + ctx (S3-3b-R2).

    Pins the single-point-of-truth invariant: every supervisor hookpoint
    invocation flows through the same helper, so the err-001 / core-004
    no-fire-and-forget contract is enforced in ONE place. The thin
    per-hookpoint helpers (tripped/reset/action_timeout/plugin.lifecycle.*)
    delegate here.
    """
    from unittest.mock import AsyncMock, patch

    from alfred.supervisor.breaker import _invoke_supervisor_hookpoint

    with patch("alfred.hooks.invoke.invoke", new=AsyncMock()) as mock_invoke:
        await _invoke_supervisor_hookpoint(
            "supervisor.test_helper",
            {"foo": "bar", "baz": 7},
        )
    assert mock_invoke.await_count == 1
    args, kwargs = mock_invoke.call_args
    assert args[0] == "supervisor.test_helper"
    ctx = args[1]
    assert ctx.action_id == "supervisor.test_helper"
    assert ctx.hookpoint == "supervisor.test_helper"
    assert ctx.input["foo"] == "bar"
    assert ctx.input["baz"] == 7
    # The helper injects correlation_id and threads it through both ctx
    # and the payload — concurrent invocations never collapse on shared
    # state (core-005).
    assert ctx.input["correlation_id"] == ctx.correlation_id
    assert ctx.kind == "post"
    assert kwargs["kind"] == "post"
    # Default fail_closed is False — supervisor hookpoints are observability shape.
    assert kwargs["fail_closed"] is False


@pytest.mark.asyncio
async def test_invoke_supervisor_hookpoint_helper_honours_fail_closed_override() -> None:
    """``fail_closed=True`` propagates to the dispatcher.

    Pins the override path so a future security-blocking hookpoint
    (where subscriber refusal should halt the action) can opt in
    without forking the helper.
    """
    from unittest.mock import AsyncMock, patch

    from alfred.supervisor.breaker import _invoke_supervisor_hookpoint

    with patch("alfred.hooks.invoke.invoke", new=AsyncMock()) as mock_invoke:
        await _invoke_supervisor_hookpoint("supervisor.test_secure", {"k": "v"}, fail_closed=True)
    _args, kwargs = mock_invoke.call_args
    assert kwargs["fail_closed"] is True


# ---------------------------------------------------------------------------
# F2 — newly-wired hookpoint helpers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invoke_supervisor_action_timeout_hookpoint_payload() -> None:
    """``invoke_supervisor_action_timeout_hookpoint`` threads the deadline-arm payload.

    Pins the orchestrator's contract: the row's subject (user_id,
    deadline_seconds, phase_at_timeout) round-trips through the hookpoint
    ctx so a subscriber sees the same data the audit row does.
    """
    from unittest.mock import AsyncMock, patch

    from alfred.supervisor.breaker import invoke_supervisor_action_timeout_hookpoint

    with patch("alfred.hooks.invoke.invoke", new=AsyncMock()) as mock_invoke:
        await invoke_supervisor_action_timeout_hookpoint(
            user_id="bruce",
            deadline_seconds=30.0,
            phase_at_timeout="unknown",
        )
    args, kwargs = mock_invoke.call_args
    assert args[0] == "supervisor.action_timeout"
    ctx = args[1]
    assert ctx.input["user_id"] == "bruce"
    assert ctx.input["deadline_seconds"] == 30.0
    assert ctx.input["phase_at_timeout"] == "unknown"
    assert ctx.input["correlation_id"] != ""
    assert kwargs["fail_closed"] is False


@pytest.mark.asyncio
async def test_invoke_plugin_lifecycle_loaded_hookpoint_payload() -> None:
    """``invoke_plugin_lifecycle_loaded_hookpoint`` threads the start-plugin payload."""
    from unittest.mock import AsyncMock, patch

    from alfred.supervisor.breaker import invoke_plugin_lifecycle_loaded_hookpoint

    with patch("alfred.hooks.invoke.invoke", new=AsyncMock()) as mock_invoke:
        await invoke_plugin_lifecycle_loaded_hookpoint(
            plugin_id="quarantined-llm",
            manifest_subscriber_tier="system",
            breaker_state="CLOSED",
        )
    args, _kwargs = mock_invoke.call_args
    assert args[0] == "plugin.lifecycle.loaded"
    ctx = args[1]
    assert ctx.input["plugin_id"] == "quarantined-llm"
    assert ctx.input["manifest_subscriber_tier"] == "system"
    assert ctx.input["breaker_state"] == "CLOSED"


@pytest.mark.asyncio
async def test_invoke_plugin_lifecycle_crashed_hookpoint_payload() -> None:
    """``invoke_plugin_lifecycle_crashed_hookpoint`` threads on_crash payload (CLOSED path).

    ``exception_type`` is the Python type name only (spec §5.6 — never
    ``str(exc)`` / ``exc.args``).
    """
    from unittest.mock import AsyncMock, patch

    from alfred.supervisor.breaker import invoke_plugin_lifecycle_crashed_hookpoint

    with patch("alfred.hooks.invoke.invoke", new=AsyncMock()) as mock_invoke:
        await invoke_plugin_lifecycle_crashed_hookpoint(
            plugin_id="quarantined-llm",
            exception_type="SubprocessExitedError",
            breaker_state="CLOSED",
            restart_count=2,
        )
    args, _kwargs = mock_invoke.call_args
    assert args[0] == "plugin.lifecycle.crashed"
    ctx = args[1]
    assert ctx.input["plugin_id"] == "quarantined-llm"
    assert ctx.input["exception_type"] == "SubprocessExitedError"
    assert ctx.input["breaker_state"] == "CLOSED"
    assert ctx.input["restart_count"] == 2


@pytest.mark.asyncio
async def test_invoke_plugin_lifecycle_quarantined_hookpoint_payload() -> None:
    """``invoke_plugin_lifecycle_quarantined_hookpoint`` threads on_crash payload (OPEN path).

    ``kill_succeeded`` reflects the actual SIGKILL outcome the supervisor
    threaded through (CR-S3-3a F2/F3); ``trip_count`` is the cumulative
    counter.
    """
    from unittest.mock import AsyncMock, patch

    from alfred.supervisor.breaker import invoke_plugin_lifecycle_quarantined_hookpoint

    with patch("alfred.hooks.invoke.invoke", new=AsyncMock()) as mock_invoke:
        await invoke_plugin_lifecycle_quarantined_hookpoint(
            plugin_id="quarantined-llm",
            trip_count=3,
            kill_succeeded=True,
        )
    args, _kwargs = mock_invoke.call_args
    assert args[0] == "plugin.lifecycle.quarantined"
    ctx = args[1]
    assert ctx.input["plugin_id"] == "quarantined-llm"
    assert ctx.input["trip_count"] == 3
    assert ctx.input["kill_succeeded"] is True
