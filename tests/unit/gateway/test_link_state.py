"""Tests for the gateway link-state kernel (Spec A G3-3a / ADR-0032).

Covers two things (the machine->wire round-trip, Task 2b, lives in
``test_client_listener.py`` where the listener fixtures already are):

* the gateway->client ``link.*`` control-frame wire models (Task 1) — pure,
  fieldless state signals that ``extra="forbid"`` rejects any smuggled text;
* the pure :class:`~alfred.gateway.link_state.LinkStateMachine` transition
  table + the spec §9 invariant under hypothesis (Task 2).
"""

from __future__ import annotations

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
from alfred.gateway.link_state import (
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
# Task 2 — the LinkStateMachine transition table
# ---------------------------------------------------------------------------

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
