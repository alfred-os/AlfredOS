"""The gateway's pure link-state machine (Spec A G3-3a / ADR-0032).

The ``alfred-gateway`` process holds the client connection ACROSS core restarts.
When the core link gaps (a planned ``going_down`` or a crash EOF) and later
recovers, the gateway must signal the client EXACTLY once per gap so the TUI can
paint — and clear — a reconnect banner. This module is the kernel that decides
*which* control frame (if any) a given transition emits, and nothing else.

**Pure — no I/O, no clock.** :meth:`LinkStateMachine.feed` is a total function of
``(state, event)``: it mutates ``state`` and returns the :class:`LinkControl` to
emit (or ``None``). The wire send, the socket, the reconnect/backoff loop, and the
lifecycle-frame validation all live ABOVE this kernel (the G3-3b core-link). That
split is what makes the §9 invariant hypothesis-testable in isolation.

**Typed events only — no wire-trust decision (security M4).** :meth:`feed` accepts
a :class:`GatewayLinkEvent`, never a raw wire frame. Deriving ``core_ready`` from a
lifecycle frame is a G3-3b obligation: the frame must be ``ReadyNotification``-parsed
and epoch-checked BEFORE ``feed(core_ready)`` is called. The pure machine is
structurally incapable of being driven by raw bytes, so a forged ``ready`` cannot
reach it.

**Spec §9 invariant.** No ``restored`` without a preceding ``reconnecting``; exactly
one control frame per gap. The transition table below encodes it; the hypothesis
property in ``tests/unit/gateway/test_link_state.py`` proves it over random event
sequences.
"""

from __future__ import annotations

from enum import StrEnum

from alfred.errors import AlfredError


class GatewayLinkStateError(AlfredError):
    """An undefined ``(state, event)`` was fed to the link-state machine.

    Fail-loud (CLAUDE.md hard rule #7): an unmodelled transition is a programming
    error or a sequence the spec did not anticipate, never a silent no-op. The only
    genuinely-undefined pair after the H2 fix is ``UP + redial_started`` (a redial
    cannot begin while the link is up — no gap is open).
    """


class GatewayLinkState(StrEnum):
    """The four link states the gateway tracks for the core connection."""

    UP = "up"
    """The core link is healthy; frames relay end-to-end."""

    DOWN_SIGNALLED = "down_signalled"
    """The core announced a planned drain (``going_down``); the gap is announced."""

    DOWN_CRASH = "down_crash"
    """The core link dropped unexpectedly (crash EOF); the gap is announced."""

    REDIALING = "redialing"
    """A reconnect attempt is in flight; the gap is still open."""

    UNAVAILABLE = "unavailable"
    """The buffer's back-pressure breaker tripped (spec §5): a terminal, absorbing
    state. The gap is escalated to ``link.unavailable``; recovery is a fresh session
    (a new machine), never an in-place exit — the buffer's breaker latch clears only
    on ``discard``."""


class GatewayLinkEvent(StrEnum):
    """The events that drive the G3-3a link-state machine."""

    CORE_GOING_DOWN = "core_going_down"
    """The core sent a planned ``daemon.lifecycle.going_down``."""

    CORE_CRASH_EOF = "core_crash_eof"
    """The core link hit an unexpected EOF (the core crashed / the socket dropped)."""

    REDIAL_STARTED = "redial_started"
    """The core-link began a reconnect attempt."""

    CORE_READY = "core_ready"
    """The core sent a (validated, epoch-checked) ``daemon.lifecycle.ready``."""

    BREAKER_TRIPPED = "breaker_tripped"
    """The ReplayBuffer's back-pressure breaker tripped (soft-cap breach, spec §5).
    Fed by the G4b relay when ``buffer.breaker_tripped`` is observed after an append;
    escalates the link to the absorbing ``UNAVAILABLE`` state."""


class LinkControl(StrEnum):
    """The control frame a transition emits.

    ``UNAVAILABLE`` is defined for the wire vocabulary even though G3-3a never emits
    it — its transition (the G4 breaker, spec §5) lands later; defining it here keeps
    the vocab whole without a half-specified G4 edge.
    """

    RECONNECTING = "reconnecting"
    RESTORED = "restored"
    UNAVAILABLE = "unavailable"


# The explicit transition table: ``(state, event) -> (next_state, emitted)``. An
# undefined pair is ABSENT (not mapped to ``None``) so ``feed`` can fail loud on it.
# See the design notes in the G3-3 plan (the spec §9 invariant) — every comment
# below names why the emit is what it is.
_TRANSITIONS: dict[
    tuple[GatewayLinkState, GatewayLinkEvent],
    tuple[GatewayLinkState, LinkControl | None],
] = {
    # --- UP ---------------------------------------------------------------
    # A gap OPENS — announce the reconnect exactly once.
    (GatewayLinkState.UP, GatewayLinkEvent.CORE_GOING_DOWN): (
        GatewayLinkState.DOWN_SIGNALLED,
        LinkControl.RECONNECTING,
    ),
    (GatewayLinkState.UP, GatewayLinkEvent.CORE_CRASH_EOF): (
        GatewayLinkState.DOWN_CRASH,
        LinkControl.RECONNECTING,
    ),
    # A duplicate/late ready while already up: idempotent, NEVER a spurious second
    # restored (the gap is already closed).
    (GatewayLinkState.UP, GatewayLinkEvent.CORE_READY): (GatewayLinkState.UP, None),
    # --- DOWN_SIGNALLED ---------------------------------------------------
    # A second down-signal within one gap: idempotent — the gap was already announced.
    (GatewayLinkState.DOWN_SIGNALLED, GatewayLinkEvent.CORE_GOING_DOWN): (
        GatewayLinkState.DOWN_SIGNALLED,
        None,
    ),
    (GatewayLinkState.DOWN_SIGNALLED, GatewayLinkEvent.CORE_CRASH_EOF): (
        GatewayLinkState.DOWN_SIGNALLED,
        None,
    ),
    (GatewayLinkState.DOWN_SIGNALLED, GatewayLinkEvent.REDIAL_STARTED): (
        GatewayLinkState.REDIALING,
        None,
    ),
    # H2: a ready can legitimately race AHEAD of redial_started; the gap closes
    # regardless, so this must NOT fail-loud-crash a real sequence.
    (GatewayLinkState.DOWN_SIGNALLED, GatewayLinkEvent.CORE_READY): (
        GatewayLinkState.UP,
        LinkControl.RESTORED,
    ),
    # --- DOWN_CRASH -------------------------------------------------------
    (GatewayLinkState.DOWN_CRASH, GatewayLinkEvent.CORE_GOING_DOWN): (
        GatewayLinkState.DOWN_CRASH,
        None,
    ),
    (GatewayLinkState.DOWN_CRASH, GatewayLinkEvent.CORE_CRASH_EOF): (
        GatewayLinkState.DOWN_CRASH,
        None,
    ),
    (GatewayLinkState.DOWN_CRASH, GatewayLinkEvent.REDIAL_STARTED): (
        GatewayLinkState.REDIALING,
        None,
    ),
    (GatewayLinkState.DOWN_CRASH, GatewayLinkEvent.CORE_READY): (
        GatewayLinkState.UP,
        LinkControl.RESTORED,
    ),
    # --- REDIALING --------------------------------------------------------
    # The gap closes — announce the restore exactly once.
    (GatewayLinkState.REDIALING, GatewayLinkEvent.CORE_READY): (
        GatewayLinkState.UP,
        LinkControl.RESTORED,
    ),
    # Repeated redial attempts within one gap: idempotent.
    (GatewayLinkState.REDIALING, GatewayLinkEvent.REDIAL_STARTED): (
        GatewayLinkState.REDIALING,
        None,
    ),
    # The core bounced again mid-redial; the gap is still open.
    (GatewayLinkState.REDIALING, GatewayLinkEvent.CORE_GOING_DOWN): (
        GatewayLinkState.REDIALING,
        None,
    ),
    (GatewayLinkState.REDIALING, GatewayLinkEvent.CORE_CRASH_EOF): (
        GatewayLinkState.REDIALING,
        None,
    ),
}


class LinkStateMachine:
    """A pure ``(state, event) -> LinkControl | None`` link-state machine.

    Starts ``UP``. :meth:`feed` mutates ``state`` and returns the control frame to
    emit (or ``None``). No I/O, no clock — the wire send is the caller's job. An
    undefined ``(state, event)`` raises :class:`GatewayLinkStateError` (fail-loud).
    """

    def __init__(self) -> None:
        self.state: GatewayLinkState = GatewayLinkState.UP

    def feed(self, event: GatewayLinkEvent) -> LinkControl | None:
        """Apply ``event`` to the current state; return the control frame to emit.

        Raises :class:`GatewayLinkStateError` on an undefined ``(state, event)`` pair
        — never a silent no-op (CLAUDE.md hard rule #7).
        """
        try:
            next_state, emitted = _TRANSITIONS[(self.state, event)]
        except KeyError as exc:
            raise GatewayLinkStateError(
                f"undefined link transition: state={self.state.value!r} event={event.value!r}"
            ) from exc
        self.state = next_state
        return emitted


__all__ = [
    "GatewayLinkEvent",
    "GatewayLinkState",
    "GatewayLinkStateError",
    "LinkControl",
    "LinkStateMachine",
]
