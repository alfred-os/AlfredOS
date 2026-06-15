"""Tests for the gateway link-state kernel (Spec A G3-3a / ADR-0032).

Covers two things (the machine->wire round-trip, Task 2b, lives in
``test_client_listener.py`` where the listener fixtures already are):

* the gateway->client ``link.*`` control-frame wire models (Task 1) — pure,
  fieldless state signals that ``extra="forbid"`` rejects any smuggled text;
* the pure :class:`~alfred.gateway.link_state.LinkStateMachine` transition
  table + the spec §9 invariant under hypothesis (Task 2).
"""

from __future__ import annotations

import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    LINK_RECONNECTING,
    LINK_RESTORED,
    LINK_UNAVAILABLE,
    LinkReconnectingNotification,
    LinkRestoredNotification,
    LinkUnavailableNotification,
)
from alfred.gateway import control_notification
from alfred.gateway.link_state import (
    _TRANSITIONS,
    GatewayLinkEvent,
    GatewayLinkState,
    GatewayLinkStateError,
    LinkControl,
    LinkStateMachine,
)

# ---------------------------------------------------------------------------
# Task 1 — control-frame wire models
# ---------------------------------------------------------------------------


def test_link_control_frames_are_empty_state_signals() -> None:
    assert (LINK_RECONNECTING, LINK_RESTORED, LINK_UNAVAILABLE) == (
        "link.reconnecting",
        "link.restored",
        "link.unavailable",
    )
    # Pure state signals: no fields, and extra="forbid" rejects any smuggled text
    # (banner/reason/T3) — the client renders its own localized banner from the method.
    assert LinkReconnectingNotification().model_dump() == {}
    assert LinkRestoredNotification().model_dump() == {}
    assert LinkUnavailableNotification().model_dump() == {}
    for model in (
        LinkReconnectingNotification,
        LinkRestoredNotification,
        LinkUnavailableNotification,
    ):
        with pytest.raises(ValidationError):
            model(banner="x")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Task 4b — the LinkControl -> LinkControlNotification helper (the shared map)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("control", "model"),
    [
        (LinkControl.RECONNECTING, LinkReconnectingNotification),
        (LinkControl.RESTORED, LinkRestoredNotification),
        (LinkControl.UNAVAILABLE, LinkUnavailableNotification),
    ],
)
def test_control_notification_maps_each_member(
    control: LinkControl, model: type[LinkReconnectingNotification]
) -> None:
    assert isinstance(control_notification(control), model)


def test_control_notification_maps_every_member_exhaustively() -> None:
    # Every LinkControl member MUST map — a future member with no mapping is a loud
    # failure (assert_never), never a silent KeyError default. This iterates the full
    # enum so adding a member without extending the map fails this test.
    for control in LinkControl:
        assert control_notification(control) is not None


_UP = GatewayLinkState.UP
_DOWN_SIGNALLED = GatewayLinkState.DOWN_SIGNALLED
_DOWN_CRASH = GatewayLinkState.DOWN_CRASH
_REDIALING = GatewayLinkState.REDIALING

_GOING_DOWN = GatewayLinkEvent.CORE_GOING_DOWN
_CRASH_EOF = GatewayLinkEvent.CORE_CRASH_EOF
_REDIAL_STARTED = GatewayLinkEvent.REDIAL_STARTED
_READY = GatewayLinkEvent.CORE_READY


@pytest.mark.parametrize(
    ("start", "event", "expected_state", "expected_control"),
    [
        # UP transitions.
        (_UP, _GOING_DOWN, _DOWN_SIGNALLED, LinkControl.RECONNECTING),
        (_UP, _CRASH_EOF, _DOWN_CRASH, LinkControl.RECONNECTING),
        # Duplicate/late ready while already up: idempotent, no spurious restored.
        (_UP, _READY, _UP, None),
        # A second down-signal within one gap: idempotent, gap already announced.
        (_DOWN_SIGNALLED, _GOING_DOWN, _DOWN_SIGNALLED, None),
        (_DOWN_SIGNALLED, _CRASH_EOF, _DOWN_SIGNALLED, None),
        (_DOWN_CRASH, _GOING_DOWN, _DOWN_CRASH, None),
        (_DOWN_CRASH, _CRASH_EOF, _DOWN_CRASH, None),
        # Redial begins.
        (_DOWN_SIGNALLED, _REDIAL_STARTED, _REDIALING, None),
        (_DOWN_CRASH, _REDIAL_STARTED, _REDIALING, None),
        # H2: a ready can race AHEAD of redial_started; the gap still closes.
        (_DOWN_SIGNALLED, _READY, _UP, LinkControl.RESTORED),
        (_DOWN_CRASH, _READY, _UP, LinkControl.RESTORED),
        # REDIALING transitions.
        (_REDIALING, _READY, _UP, LinkControl.RESTORED),
        # Repeated redial attempts within one gap: idempotent.
        (_REDIALING, _REDIAL_STARTED, _REDIALING, None),
        # The core bounced again mid-redial; gap still open.
        (_REDIALING, _GOING_DOWN, _REDIALING, None),
        (_REDIALING, _CRASH_EOF, _REDIALING, None),
    ],
)
def test_transition_table(
    start: GatewayLinkState,
    event: GatewayLinkEvent,
    expected_state: GatewayLinkState,
    expected_control: LinkControl | None,
) -> None:
    machine = LinkStateMachine()
    machine.state = start
    emitted = machine.feed(event)
    assert machine.state is expected_state
    assert emitted is expected_control


def test_machine_starts_up() -> None:
    assert LinkStateMachine().state is GatewayLinkState.UP


def test_unavailable_state_and_breaker_event_exist() -> None:
    # Pin the on-the-wire StrEnum values (the control-frame vocabulary the TUI banner
    # and audit rows key on) — names use the module-level imports already in scope.
    assert GatewayLinkState.UNAVAILABLE == "unavailable"
    assert GatewayLinkEvent.BREAKER_TRIPPED == "breaker_tripped"


@pytest.mark.parametrize(
    "to_gap",
    [
        [],  # UP -> breaker (wedged-but-connected core; no prior reconnecting)
        [GatewayLinkEvent.CORE_GOING_DOWN],  # DOWN_SIGNALLED -> breaker
        [GatewayLinkEvent.CORE_CRASH_EOF],  # DOWN_CRASH -> breaker
        [
            GatewayLinkEvent.CORE_GOING_DOWN,
            GatewayLinkEvent.REDIAL_STARTED,
        ],  # REDIALING -> breaker
    ],
)
def test_breaker_escalates_each_live_state_to_unavailable_once(
    to_gap: list[GatewayLinkEvent],
) -> None:
    m = LinkStateMachine()
    for ev in to_gap:
        m.feed(ev)
    assert m.feed(GatewayLinkEvent.BREAKER_TRIPPED) is LinkControl.UNAVAILABLE
    assert m.state is GatewayLinkState.UNAVAILABLE


def test_up_breaker_emits_unavailable_without_a_preceding_reconnecting() -> None:
    """The wedged-but-connected-core case: link never dropped, so no RECONNECTING first."""
    m = LinkStateMachine()
    assert m.feed(GatewayLinkEvent.BREAKER_TRIPPED) is LinkControl.UNAVAILABLE


@pytest.mark.parametrize(
    "event",
    [
        GatewayLinkEvent.BREAKER_TRIPPED,  # repeated trip while latched -> idempotent
        GatewayLinkEvent.CORE_READY,  # core revived but buffer still wedged -> NO restored
        GatewayLinkEvent.CORE_GOING_DOWN,
        GatewayLinkEvent.CORE_CRASH_EOF,
        GatewayLinkEvent.REDIAL_STARTED,
    ],
)
def test_unavailable_absorbs_every_event_emitting_nothing(event: GatewayLinkEvent) -> None:
    m = LinkStateMachine()
    m.feed(GatewayLinkEvent.BREAKER_TRIPPED)  # -> UNAVAILABLE
    assert m.feed(event) is None
    assert m.state is GatewayLinkState.UNAVAILABLE


def test_core_ready_after_unavailable_never_emits_restored() -> None:
    """A wedged buffer is not un-wedged by a core returning — recovery is a fresh session."""
    m = LinkStateMachine()
    m.feed(GatewayLinkEvent.CORE_GOING_DOWN)  # -> DOWN_SIGNALLED, RECONNECTING
    m.feed(GatewayLinkEvent.BREAKER_TRIPPED)  # -> UNAVAILABLE, UNAVAILABLE
    assert m.feed(GatewayLinkEvent.CORE_READY) is None  # NOT RESTORED


def test_undefined_transition_fails_loud() -> None:
    # ``UP + redial_started`` is genuinely undefined: a redial cannot begin while
    # the link is up (no gap is open). With the H2 fix, ``DOWN_* + core_ready`` IS
    # defined, so the fail-loud only fires for a genuinely-undefined pair.
    machine = LinkStateMachine()
    assert machine.state is GatewayLinkState.UP
    with pytest.raises(GatewayLinkStateError):
        machine.feed(GatewayLinkEvent.REDIAL_STARTED)
    # No state corruption on a fail-loud raise: the machine stays in ``UP`` and is
    # still usable afterwards (the §9 hypothesis property quietly leans on this
    # no-corruption-on-fail invariant — test-g33a-001).
    assert machine.state is GatewayLinkState.UP
    assert machine.feed(GatewayLinkEvent.CORE_GOING_DOWN) is LinkControl.RECONNECTING


# ---------------------------------------------------------------------------
# Task 2 — the spec §9 invariant under hypothesis
# ---------------------------------------------------------------------------

# Only the events that are DEFINED from ``UP`` open the machine; a random walk
# that begins from ``UP`` must avoid feeding ``redial_started`` while up (that is
# the genuinely-undefined pair). So the property drives the machine but skips a
# step that would fail-loud, focusing the property on the §9 ordering invariant.
# NB: kept to the four pre-breaker events ON PURPOSE — the gap-open cross-check in
# `test_restored_always_preceded_by_reconnecting` (`gap_open == (state is not UP)`)
# is only valid while UNAVAILABLE is unreachable (UNAVAILABLE is not-UP yet not
# gap-open). BREAKER_TRIPPED coverage lives in the new property
# `test_invariant_no_control_after_unavailable_...`.
_ALL_EVENTS = (
    GatewayLinkEvent.CORE_GOING_DOWN,
    GatewayLinkEvent.CORE_CRASH_EOF,
    GatewayLinkEvent.REDIAL_STARTED,
    GatewayLinkEvent.CORE_READY,
)


@given(events=st.lists(st.sampled_from(_ALL_EVENTS), max_size=40))
def test_restored_always_preceded_by_reconnecting(
    events: list[GatewayLinkEvent],
) -> None:
    """Spec §9: every ``restored`` is preceded by a ``reconnecting``, exactly one
    per gap; ``restored`` never fires from ``UP`` with no open gap, and a second
    ``restored`` never fires within the same gap.
    """
    machine = LinkStateMachine()
    gap_open = False  # True once a reconnecting has fired and not yet closed.
    for event in events:
        before = machine.state  # feed() raises before mutating, so this is the pair's state
        try:
            emitted = machine.feed(event)
        except GatewayLinkStateError:
            # Skip ONLY the single genuinely-undefined pair (`UP + redial_started`)
            # so the property focuses on the §9 emit ordering. ANY other fail-loud
            # pair is a real regression — assert (re-raise) so the test surfaces it
            # rather than silently swallowing every GatewayLinkStateError (CR #271).
            assert before is GatewayLinkState.UP and event is GatewayLinkEvent.REDIAL_STARTED
            continue
        if emitted is LinkControl.RECONNECTING:
            # A gap opens. We must NOT already be inside an open gap when one opens
            # (the down-signal self-loops emit nothing, so no double-open).
            assert not gap_open
            gap_open = True
        elif emitted is LinkControl.RESTORED:
            # A restored may ONLY fire to close an open gap.
            assert gap_open
            gap_open = False
        elif emitted is LinkControl.UNAVAILABLE:  # pragma: no cover - never emitted in 3a
            pytest.fail("G3-3a never emits unavailable")
        # Cross-check the emit-derived gap against the machine's ACTUAL state: a gap
        # is open IFF the machine is not ``UP``. A bug that emitted the right frames
        # but landed in a wrong state would otherwise slip past the §9 property
        # (test-g33a-002).
        assert gap_open == (machine.state is not GatewayLinkState.UP)


# ---------------------------------------------------------------------------
# G4b-1 — the §9 invariant refined for the breaker escalation + absorbing sink
# ---------------------------------------------------------------------------


@given(st.lists(st.sampled_from(list(GatewayLinkEvent)), min_size=0, max_size=40))
def test_invariant_no_control_after_unavailable_and_no_unprefixed_restored(
    events: list[GatewayLinkEvent],
) -> None:
    """§9 (refined for G4b-1): RESTORED only after a RECONNECTING since the last UP;
    no control of ANY kind once UNAVAILABLE has been emitted; feed never raises.
    """
    m = LinkStateMachine()
    reconnecting_open = False
    unavailable_emitted = False
    for ev in events:
        # feed is total EXCEPT (UP, REDIAL_STARTED) — the H2 fail-loud hole. Skip it
        # exactly as the existing §9 property does, so a real undefined pair still
        # surfaces as a raise rather than being swallowed here.
        if m.state is GatewayLinkState.UP and ev is GatewayLinkEvent.REDIAL_STARTED:
            with pytest.raises(GatewayLinkStateError):
                m.feed(ev)
            continue
        control = m.feed(ev)  # raises only on the H2 hole, skipped above
        if unavailable_emitted:
            assert control is None  # absorbing terminal: nothing after UNAVAILABLE
        if control is LinkControl.RECONNECTING:
            reconnecting_open = True
        elif control is LinkControl.RESTORED:
            assert reconnecting_open, "RESTORED without a preceding RECONNECTING"
            reconnecting_open = False
        elif control is LinkControl.UNAVAILABLE:
            unavailable_emitted = True
        # State cross-check (the terminal-sink analogue of the gap-open cross-check
        # in `test_restored_always_preceded_by_reconnecting`): once UNAVAILABLE has
        # been emitted the machine state is forever the terminal sink. This catches a
        # "right control frame, wrong next_state" table typo the control-only
        # bookkeeping above would otherwise miss.
        if unavailable_emitted:
            assert m.state is GatewayLinkState.UNAVAILABLE


# The one deliberately-undefined pair (H2 fix): a redial cannot begin while the
# link is UP — no gap is open, so feed(UP, REDIAL_STARTED) must fail loud. The
# table is total over state x event EXCEPT here; see GatewayLinkStateError.
_SANCTIONED_UNDEFINED: frozenset[tuple[GatewayLinkState, GatewayLinkEvent]] = frozenset(
    {(GatewayLinkState.UP, GatewayLinkEvent.REDIAL_STARTED)}
)


def test_transition_table_is_total_except_the_sanctioned_hole() -> None:
    """Every (state, event) has a row except the one fail-loud H2 hole.

    Pins both directions: (a) all 24 modelled pairs present, so a future hand-edit
    that drops a row fails here; (b) (UP, REDIAL_STARTED) stays ABSENT, so the
    fail-loud guard + its test remain meaningful. Complements (does not replace)
    test_undefined_transition_fails_loud.
    """
    for state, event in itertools.product(GatewayLinkState, GatewayLinkEvent):
        present = (state, event) in _TRANSITIONS
        if (state, event) in _SANCTIONED_UNDEFINED:
            assert not present, f"sanctioned hole must stay absent: {state} x {event}"
        else:
            assert present, f"missing transition: {state} x {event}"
