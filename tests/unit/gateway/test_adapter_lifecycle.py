"""Tests for the pure per-adapter lifecycle kernel (G6-2b-1, Spec B §3/§6 / #288).

Mirrors ``tests/unit/gateway/test_link_state.py``: the
:class:`~alfred.gateway.adapter_lifecycle.AdapterLifecycleMachine` is a pure
``feed(event) -> AdapterControl | None`` table with NO I/O and NO clock — the
``GatewayAdapterSupervisor`` shell (Task 4+) drives the clock/backoff and turns
each emitted :class:`AdapterControl` into a ``gateway.adapter.*`` frame on its
sink. Keeping the kernel pure is what makes the §6 "every transition is loud /
non-skippable" invariant hypothesis-testable in isolation.

Per-incarnation contract (the spawn -> up -> crash -> restart cycle):

* ``EMIT_UP`` fires AT MOST ONCE per spawn incarnation and ONLY out of
  ``HANDSHAKING`` (the false-liveness defence the observer mirrors).
* ``EMIT_BREAKER_OPEN`` and ``EMIT_DOWN`` lead to absorbing terminals, exactly like
  ``link_state``'s ``UNAVAILABLE`` — once tripped, every event self-loops and emits
  nothing (no crash-loop can re-emit; recovery is a fresh machine).
* An undefined ``(state, event)`` pair raises ``AdapterLifecycleStateError``
  (fail-loud, CLAUDE.md hard rule #7) — never a silent no-op.
"""

from __future__ import annotations

import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st

from alfred.gateway.adapter_lifecycle import (
    _TRANSITIONS,
    AdapterControl,
    AdapterLifecycleEvent,
    AdapterLifecycleMachine,
    AdapterLifecycleState,
    AdapterLifecycleStateError,
)

_SPAWNING = AdapterLifecycleState.SPAWNING
_HANDSHAKING = AdapterLifecycleState.HANDSHAKING
_UP = AdapterLifecycleState.UP
_CRASHED = AdapterLifecycleState.CRASHED
_RESTARTING = AdapterLifecycleState.RESTARTING
_AWAITING_CORE = AdapterLifecycleState.AWAITING_CORE
_BREAKER_OPEN = AdapterLifecycleState.BREAKER_OPEN
_DOWN = AdapterLifecycleState.DOWN

_SPAWN_STARTED = AdapterLifecycleEvent.SPAWN_STARTED
_HANDSHAKE_OK = AdapterLifecycleEvent.HANDSHAKE_OK
_HANDSHAKE_FAILED = AdapterLifecycleEvent.HANDSHAKE_FAILED
_CHILD_EXITED = AdapterLifecycleEvent.CHILD_EXITED
_BACKOFF_ELAPSED = AdapterLifecycleEvent.BACKOFF_ELAPSED
_BREAKER_TRIPPED = AdapterLifecycleEvent.BREAKER_TRIPPED
_CRED_UNAVAILABLE = AdapterLifecycleEvent.CRED_UNAVAILABLE
_CRED_AVAILABLE = AdapterLifecycleEvent.CRED_AVAILABLE
_STOP_REQUESTED = AdapterLifecycleEvent.STOP_REQUESTED


# ---------------------------------------------------------------------------
# StrEnum value pins (the wire/audit vocabulary the supervisor + emitter key on)
# ---------------------------------------------------------------------------


def test_machine_starts_spawning() -> None:
    """A fresh machine is one spawn incarnation beginning — it starts SPAWNING."""
    assert AdapterLifecycleMachine().state is AdapterLifecycleState.SPAWNING


def test_state_and_event_values() -> None:
    assert AdapterLifecycleState.UP == "up"
    assert AdapterLifecycleState.BREAKER_OPEN == "breaker_open"
    assert AdapterLifecycleState.AWAITING_CORE == "awaiting_core"
    assert AdapterLifecycleEvent.CHILD_EXITED == "child_exited"
    assert AdapterLifecycleEvent.STOP_REQUESTED == "stop_requested"


def test_control_values() -> None:
    assert (
        AdapterControl.EMIT_UP,
        AdapterControl.EMIT_DOWN,
        AdapterControl.EMIT_CRASHED,
        AdapterControl.EMIT_BREAKER_OPEN,
    ) == ("emit_up", "emit_down", "emit_crashed", "emit_breaker_open")


# ---------------------------------------------------------------------------
# The explicit transition table (the plan's failing-test list 1..9)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("start", "event", "expected_state", "expected_control"),
    [
        # 1. spawn -> handshake (no emit).
        (_SPAWNING, _SPAWN_STARTED, _HANDSHAKING, None),
        # 2. handshake ok -> up, EMIT_UP (the only liveness-asserting frame).
        (_HANDSHAKING, _HANDSHAKE_OK, _UP, AdapterControl.EMIT_UP),
        # 3. the child exits while up -> crashed, EMIT_CRASHED.
        (_UP, _CHILD_EXITED, _CRASHED, AdapterControl.EMIT_CRASHED),
        # 4a. crashed -> backoff elapsed -> restarting (no emit).
        (_CRASHED, _BACKOFF_ELAPSED, _RESTARTING, None),
        # 4b. restarting -> spawn started -> handshaking (the next incarnation).
        (_RESTARTING, _SPAWN_STARTED, _HANDSHAKING, None),
        # 5. crashed -> breaker tripped -> breaker_open, EMIT_BREAKER_OPEN.
        (_CRASHED, _BREAKER_TRIPPED, _BREAKER_OPEN, AdapterControl.EMIT_BREAKER_OPEN),
        # 6. restarting -> cred unavailable -> awaiting_core (no emit).
        (_RESTARTING, _CRED_UNAVAILABLE, _AWAITING_CORE, None),
        # 7. awaiting_core -> cred available -> restarting (no emit).
        (_AWAITING_CORE, _CRED_AVAILABLE, _RESTARTING, None),
        # A handshake that fails -> crashed (a failed handshake is a crash of the
        # incarnation; it routes through the same backoff/breaker arms), EMIT_CRASHED.
        (_HANDSHAKING, _HANDSHAKE_FAILED, _CRASHED, AdapterControl.EMIT_CRASHED),
        # The child can exit DURING spawn/handshake too (never reached UP) -> crashed.
        (_SPAWNING, _CHILD_EXITED, _CRASHED, AdapterControl.EMIT_CRASHED),
        (_HANDSHAKING, _CHILD_EXITED, _CRASHED, AdapterControl.EMIT_CRASHED),
    ],
)
def test_transition_table(
    start: AdapterLifecycleState,
    event: AdapterLifecycleEvent,
    expected_state: AdapterLifecycleState,
    expected_control: AdapterControl | None,
) -> None:
    machine = AdapterLifecycleMachine()
    machine.state = start
    emitted = machine.feed(event)
    assert machine.state is expected_state
    assert emitted is expected_control


def test_full_happy_then_crash_then_restart_path() -> None:
    """The plan's path 4: spawn -> up -> crash -> backoff -> restart -> handshake."""
    m = AdapterLifecycleMachine()
    assert m.feed(_SPAWN_STARTED) is None  # -> HANDSHAKING
    assert m.feed(_HANDSHAKE_OK) is AdapterControl.EMIT_UP  # -> UP
    assert m.feed(_CHILD_EXITED) is AdapterControl.EMIT_CRASHED  # -> CRASHED
    assert m.feed(_BACKOFF_ELAPSED) is None  # -> RESTARTING
    assert m.feed(_SPAWN_STARTED) is None  # -> HANDSHAKING (next incarnation)
    assert m.state is _HANDSHAKING


# ---------------------------------------------------------------------------
# STOP_REQUESTED -> DOWN-terminal from every LIVE state, exactly once
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "live_state",
    [_SPAWNING, _HANDSHAKING, _UP, _CRASHED, _RESTARTING, _AWAITING_CORE],
)
def test_stop_requested_from_every_live_state_emits_down_once(
    live_state: AdapterLifecycleState,
) -> None:
    """An operator/planned stop from any live state -> DOWN, EMIT_DOWN exactly once."""
    m = AdapterLifecycleMachine()
    m.state = live_state
    assert m.feed(_STOP_REQUESTED) is AdapterControl.EMIT_DOWN
    assert m.state is _DOWN
    # Absorbing: a second STOP (or any event) emits nothing.
    assert m.feed(_STOP_REQUESTED) is None
    assert m.state is _DOWN


# ---------------------------------------------------------------------------
# Absorbing terminals: BREAKER_OPEN and DOWN swallow every event
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("event", list(AdapterLifecycleEvent))
def test_breaker_open_absorbs_every_event_emitting_nothing(
    event: AdapterLifecycleEvent,
) -> None:
    m = AdapterLifecycleMachine()
    m.state = _CRASHED
    assert m.feed(_BREAKER_TRIPPED) is AdapterControl.EMIT_BREAKER_OPEN  # -> BREAKER_OPEN
    assert m.feed(event) is None
    assert m.state is _BREAKER_OPEN


@pytest.mark.parametrize("event", list(AdapterLifecycleEvent))
def test_down_absorbs_every_event_emitting_nothing(event: AdapterLifecycleEvent) -> None:
    m = AdapterLifecycleMachine()
    assert m.feed(_STOP_REQUESTED) is AdapterControl.EMIT_DOWN  # SPAWNING -> DOWN
    assert m.feed(event) is None
    assert m.state is _DOWN


# ---------------------------------------------------------------------------
# Fail-loud on an undefined pair
# ---------------------------------------------------------------------------


def test_undefined_transition_fails_loud_and_does_not_corrupt_state() -> None:
    """``UP + BACKOFF_ELAPSED`` is undefined (no backoff while serving) -> fail loud.

    The machine must not mutate on a fail-loud raise (the hypothesis property below
    leans on no-corruption-on-fail).
    """
    m = AdapterLifecycleMachine()
    m.state = _UP
    with pytest.raises(AdapterLifecycleStateError):
        m.feed(_BACKOFF_ELAPSED)
    assert m.state is _UP
    # Still usable: a real UP event still works after the fail-loud.
    assert m.feed(_CHILD_EXITED) is AdapterControl.EMIT_CRASHED


# ---------------------------------------------------------------------------
# Table totality pins (both directions)
# ---------------------------------------------------------------------------

# The deliberately-undefined pairs: events that cannot occur in a given state.
# Pinned so the fail-loud guard stays meaningful AND a hand-edit that drops a
# legitimate row fails loudly.
_SANCTIONED_UNDEFINED: frozenset[tuple[AdapterLifecycleState, AdapterLifecycleEvent]] = frozenset(
    {
        # No spawn/handshake/backoff/cred event makes sense while serving (UP).
        (_UP, _SPAWN_STARTED),
        (_UP, _HANDSHAKE_OK),
        (_UP, _HANDSHAKE_FAILED),
        (_UP, _BACKOFF_ELAPSED),
        (_UP, _BREAKER_TRIPPED),
        (_UP, _CRED_UNAVAILABLE),
        (_UP, _CRED_AVAILABLE),
        # SPAWNING: cannot hand-shake-ok before the handshake begins; no backoff/
        # breaker/cred mid-spawn.
        (_SPAWNING, _HANDSHAKE_OK),
        (_SPAWNING, _HANDSHAKE_FAILED),
        (_SPAWNING, _BACKOFF_ELAPSED),
        (_SPAWNING, _BREAKER_TRIPPED),
        (_SPAWNING, _CRED_UNAVAILABLE),
        (_SPAWNING, _CRED_AVAILABLE),
        # HANDSHAKING: not yet spawning-restart; no backoff/breaker/cred here.
        (_HANDSHAKING, _SPAWN_STARTED),
        (_HANDSHAKING, _BACKOFF_ELAPSED),
        (_HANDSHAKING, _BREAKER_TRIPPED),
        (_HANDSHAKING, _CRED_UNAVAILABLE),
        (_HANDSHAKING, _CRED_AVAILABLE),
        # CRASHED: awaiting the backoff/breaker decision; no spawn/handshake/cred
        # until backoff elapses. A second CHILD_EXITED while already crashed is also
        # undefined (the child already exited).
        (_CRASHED, _SPAWN_STARTED),
        (_CRASHED, _HANDSHAKE_OK),
        (_CRASHED, _HANDSHAKE_FAILED),
        (_CRASHED, _CHILD_EXITED),
        (_CRASHED, _CRED_UNAVAILABLE),
        (_CRASHED, _CRED_AVAILABLE),
        # RESTARTING: about to spawn or defer on cred; no handshake/backoff/breaker/
        # child-exit yet (the child is not spawned).
        (_RESTARTING, _HANDSHAKE_OK),
        (_RESTARTING, _HANDSHAKE_FAILED),
        (_RESTARTING, _CHILD_EXITED),
        (_RESTARTING, _BACKOFF_ELAPSED),
        (_RESTARTING, _BREAKER_TRIPPED),
        (_RESTARTING, _CRED_AVAILABLE),
        # AWAITING_CORE: only a cred-available (or a stop) moves it; nothing is
        # spawned.
        (_AWAITING_CORE, _SPAWN_STARTED),
        (_AWAITING_CORE, _HANDSHAKE_OK),
        (_AWAITING_CORE, _HANDSHAKE_FAILED),
        (_AWAITING_CORE, _CHILD_EXITED),
        (_AWAITING_CORE, _BACKOFF_ELAPSED),
        (_AWAITING_CORE, _BREAKER_TRIPPED),
        (_AWAITING_CORE, _CRED_UNAVAILABLE),
    }
)


def test_transition_table_is_total_except_sanctioned_holes() -> None:
    """Every (state, event) has a row EXCEPT the sanctioned undefined pairs.

    The two terminals (BREAKER_OPEN, DOWN) are total (they self-loop on everything);
    the live states are total minus the impossible-pair holes above.
    """
    for state, event in itertools.product(AdapterLifecycleState, AdapterLifecycleEvent):
        present = (state, event) in _TRANSITIONS
        if (state, event) in _SANCTIONED_UNDEFINED:
            assert not present, f"sanctioned hole must stay absent: {state} x {event}"
        else:
            assert present, f"missing transition: {state} x {event}"


# ---------------------------------------------------------------------------
# Hypothesis properties (mirror test_link_state.py)
# ---------------------------------------------------------------------------


@given(events=st.lists(st.sampled_from(list(AdapterLifecycleEvent)), max_size=40))
def test_emit_up_at_most_once_per_incarnation_and_only_from_handshaking(
    events: list[AdapterLifecycleEvent],
) -> None:
    """EMIT_UP fires only out of HANDSHAKING, and at most once per spawn incarnation.

    A spawn incarnation begins at SPAWNING (the initial state) and at each
    RESTARTING->SPAWNING-equivalent re-entry into HANDSHAKING; EMIT_UP may fire once
    per such incarnation. We assert the weaker, sufficient property: every EMIT_UP is
    immediately preceded by the machine being in HANDSHAKING, and a second EMIT_UP
    cannot fire without a fresh HANDSHAKING entry in between.
    """
    m = AdapterLifecycleMachine()
    up_outstanding = False  # True once UP and not yet left.
    for event in events:
        before = m.state
        try:
            emitted = m.feed(event)
        except AdapterLifecycleStateError:
            # Only a sanctioned-undefined pair may fail loud; anything else is a
            # real regression (re-raise rather than swallow — CR #271 lesson).
            assert (before, event) in _SANCTIONED_UNDEFINED
            continue
        if emitted is AdapterControl.EMIT_UP:
            assert before is _HANDSHAKING, "EMIT_UP only out of HANDSHAKING"
            assert not up_outstanding, "EMIT_UP twice without leaving UP"
            up_outstanding = True
        elif emitted in (AdapterControl.EMIT_CRASHED, AdapterControl.EMIT_DOWN):
            # Left UP (crash) or terminal-stop — the incarnation's up-ness is cleared.
            up_outstanding = False
        # State cross-check: up_outstanding IFF the machine is UP.
        assert up_outstanding == (m.state is _UP)


@given(events=st.lists(st.sampled_from(list(AdapterLifecycleEvent)), min_size=1, max_size=40))
def test_terminals_are_absorbing(events: list[AdapterLifecycleEvent]) -> None:
    """Once BREAKER_OPEN or DOWN is emitted, no further control is ever emitted and
    feed never raises (mirrors link_state UNAVAILABLE)."""
    m = AdapterLifecycleMachine()
    terminal_reached = False
    for event in events:
        before = m.state
        try:
            control = m.feed(event)
        except AdapterLifecycleStateError:
            assert (before, event) in _SANCTIONED_UNDEFINED
            continue
        if terminal_reached:
            assert control is None, "no control after a terminal"
            assert m.state in (_BREAKER_OPEN, _DOWN)
        if control in (AdapterControl.EMIT_BREAKER_OPEN, AdapterControl.EMIT_DOWN):
            terminal_reached = True
