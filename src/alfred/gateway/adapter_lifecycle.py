"""The gateway's pure per-adapter lifecycle state machine (Spec B §3/§6 / G6-2b-1).

The always-up ``alfred-gateway`` process SUPERVISES each sandbox-spawned comms
adapter child (ADR-0036 inversion): it spawns the child through the launcher, runs
the handshake, watches for a crash, restarts with bounded backoff, and trips a
per-adapter breaker on a crash-loop. This module is the KERNEL that decides which
``gateway.adapter.*`` status frame (if any) a given lifecycle transition emits, and
nothing else.

**Pure — no I/O, no clock.** :meth:`AdapterLifecycleMachine.feed` is a total
function of ``(state, event)``: it mutates ``state`` and returns the
:class:`AdapterControl` to emit (or ``None``). The launcher spawn, the handshake
read, the backoff sleep, the breaker window, and the status-frame send all live
ABOVE this kernel in :mod:`alfred.gateway.adapter_supervisor` (the imperative
shell). That split is what makes the §6 "every lifecycle transition is loud /
non-skippable" invariant hypothesis-testable in isolation — mirrors
:mod:`alfred.gateway.link_state`.

**One machine per spawn lifetime.** A fresh machine starts ``SPAWNING`` (one
incarnation beginning). ``EMIT_UP`` — the only liveness-asserting frame — fires at
most once per incarnation and only out of ``HANDSHAKING`` (the false-liveness
defence the core-side observer mirrors). A crash-loop ends in ``BREAKER_OPEN`` and a
planned stop in ``DOWN``; both are ABSORBING terminals (every later event self-loops
and emits nothing), exactly like ``link_state``'s ``UNAVAILABLE`` — a crash-loop can
never re-emit, recovery is a fresh machine. An undefined ``(state, event)`` raises
:class:`AdapterLifecycleStateError` (fail-loud, CLAUDE.md hard rule #7).
"""

from __future__ import annotations

from enum import StrEnum

from alfred.errors import AlfredError


class AdapterLifecycleStateError(AlfredError):
    """An undefined ``(state, event)`` was fed to the adapter-lifecycle machine.

    Fail-loud (CLAUDE.md hard rule #7): an unmodelled transition is a programming
    error or a sequence the spec did not anticipate, never a silent no-op. Examples
    of genuinely-undefined pairs: ``UP + BACKOFF_ELAPSED`` (no backoff runs while the
    adapter is serving), ``CRASHED + CHILD_EXITED`` (the child already exited).
    """


class AdapterLifecycleState(StrEnum):
    """The lifecycle states the gateway tracks for one supervised adapter child."""

    SPAWNING = "spawning"
    """The launcher spawn is in flight (or the incarnation is just beginning)."""

    HANDSHAKING = "handshaking"
    """The child spawned; the ``lifecycle.start`` handshake is in flight."""

    UP = "up"
    """The handshake succeeded; the adapter is serving. The ONLY state ``EMIT_UP``
    is reachable from — and ``up`` is the only liveness-asserting status frame."""

    CRASHED = "crashed"
    """The child exited (or the handshake failed). Awaiting the backoff/breaker
    decision: a ``BACKOFF_ELAPSED`` restarts, a ``BREAKER_TRIPPED`` quarantines."""

    RESTARTING = "restarting"
    """The backoff elapsed; a restart is about to spawn — UNLESS the (fake, in 2b-1)
    credential is unavailable, which defers to ``AWAITING_CORE``."""

    AWAITING_CORE = "awaiting_core"
    """The credential for the next spawn is unavailable; the adapter waits for the
    core to make it available (``CRED_AVAILABLE``). Observable but emits no NEW wire
    transition — the last emitted frame (``crashed``) already told the core the
    adapter is not serving."""

    BREAKER_OPEN = "breaker_open"
    """The per-adapter circuit breaker tripped on a crash-loop. ABSORBING terminal
    (spec §6(c): never silently dark — the breaker_open frame is the loud signal):
    every later event self-loops and emits nothing. Recovery is a fresh machine."""

    DOWN = "down"
    """A planned/operator stop reached this adapter. ABSORBING terminal: every later
    event self-loops and emits nothing."""


class AdapterLifecycleEvent(StrEnum):
    """The events that drive the per-adapter lifecycle machine."""

    SPAWN_STARTED = "spawn_started"
    """The launcher spawn began (the supervisor called ``transport.spawn``)."""

    HANDSHAKE_OK = "handshake_ok"
    """The ``lifecycle.start`` handshake completed and the gate allowed the load."""

    HANDSHAKE_FAILED = "handshake_failed"
    """The handshake failed (gate denial / not-ok ack / EOF before ack). Treated as a
    crash of the incarnation — it routes through the same backoff/breaker arms."""

    CHILD_EXITED = "child_exited"
    """The supervisor observed the child process exit (the gateway's PROCESS-level
    crash signal, Spec B §3) — from any pre-terminal state where a child is alive."""

    BACKOFF_ELAPSED = "backoff_elapsed"
    """The crash backoff window elapsed; it is time to attempt a restart."""

    BREAKER_TRIPPED = "breaker_tripped"
    """The per-adapter circuit breaker tripped (too many crashes in the window)."""

    CRED_UNAVAILABLE = "cred_unavailable"
    """The (fake, in 2b-1) credential for the next spawn is unavailable -> defer to
    AWAITING_CORE rather than spawn credential-less."""

    CRED_AVAILABLE = "cred_available"
    """The credential became available again -> resume the restart from AWAITING_CORE."""

    STOP_REQUESTED = "stop_requested"
    """A planned/operator stop -> the absorbing DOWN terminal, EMIT_DOWN once."""


class AdapterControl(StrEnum):
    """The status-frame control a transition emits (maps 1:1 to a G6-2a frame).

    The supervisor's emitter turns each member into the matching
    ``gateway.adapter.*`` notification (Task 8): ``EMIT_UP`` ->
    :class:`AdapterUpNotification`, etc.
    """

    EMIT_UP = "emit_up"
    EMIT_DOWN = "emit_down"
    EMIT_CRASHED = "emit_crashed"
    EMIT_BREAKER_OPEN = "emit_breaker_open"


# A child is "alive" (can still exit) in these states; STOP_REQUESTED and
# CHILD_EXITED rows are generated for them below so the table stays total without
# hand-repeating the same edge.
_CHILD_ALIVE_STATES: tuple[AdapterLifecycleState, ...] = (
    AdapterLifecycleState.SPAWNING,
    AdapterLifecycleState.HANDSHAKING,
)

# Every live (non-terminal) state from which an operator/planned stop is honoured.
_STOPPABLE_STATES: tuple[AdapterLifecycleState, ...] = (
    AdapterLifecycleState.SPAWNING,
    AdapterLifecycleState.HANDSHAKING,
    AdapterLifecycleState.UP,
    AdapterLifecycleState.CRASHED,
    AdapterLifecycleState.RESTARTING,
    AdapterLifecycleState.AWAITING_CORE,
)


def _build_transitions() -> dict[
    tuple[AdapterLifecycleState, AdapterLifecycleEvent],
    tuple[AdapterLifecycleState, AdapterControl | None],
]:
    """Build the explicit ``(state, event) -> (next_state, emitted)`` table.

    Constructed once at import. An undefined pair is ABSENT (not mapped to ``None``)
    so :meth:`AdapterLifecycleMachine.feed` can fail loud on it.
    """
    s = AdapterLifecycleState
    e = AdapterLifecycleEvent
    c = AdapterControl
    table: dict[
        tuple[AdapterLifecycleState, AdapterLifecycleEvent],
        tuple[AdapterLifecycleState, AdapterControl | None],
    ] = {
        # --- SPAWNING ----------------------------------------------------
        (s.SPAWNING, e.SPAWN_STARTED): (s.HANDSHAKING, None),
        # --- HANDSHAKING -------------------------------------------------
        (s.HANDSHAKING, e.HANDSHAKE_OK): (s.UP, c.EMIT_UP),
        # A failed handshake is a crash of this incarnation -> same backoff/breaker arm.
        (s.HANDSHAKING, e.HANDSHAKE_FAILED): (s.CRASHED, c.EMIT_CRASHED),
        # --- UP ----------------------------------------------------------
        (s.UP, e.CHILD_EXITED): (s.CRASHED, c.EMIT_CRASHED),
        # --- CRASHED -----------------------------------------------------
        (s.CRASHED, e.BACKOFF_ELAPSED): (s.RESTARTING, None),
        (s.CRASHED, e.BREAKER_TRIPPED): (s.BREAKER_OPEN, c.EMIT_BREAKER_OPEN),
        # --- RESTARTING --------------------------------------------------
        (s.RESTARTING, e.SPAWN_STARTED): (s.HANDSHAKING, None),
        (s.RESTARTING, e.CRED_UNAVAILABLE): (s.AWAITING_CORE, None),
        # --- AWAITING_CORE -----------------------------------------------
        (s.AWAITING_CORE, e.CRED_AVAILABLE): (s.RESTARTING, None),
    }

    # CHILD_EXITED can fire while the child is alive but pre-UP (spawn/handshake
    # exit) -> the same CRASHED + EMIT_CRASHED edge as UP.
    for state in _CHILD_ALIVE_STATES:
        table[(state, e.CHILD_EXITED)] = (s.CRASHED, c.EMIT_CRASHED)

    # STOP_REQUESTED from every live state -> the absorbing DOWN terminal, EMIT_DOWN
    # exactly once.
    for state in _STOPPABLE_STATES:
        table[(state, e.STOP_REQUESTED)] = (s.DOWN, c.EMIT_DOWN)

    # The two ABSORBING terminals swallow EVERY event: self-loop, emit nothing.
    for terminal in (s.BREAKER_OPEN, s.DOWN):
        for event in AdapterLifecycleEvent:
            table[(terminal, event)] = (terminal, None)

    return table


_TRANSITIONS = _build_transitions()


class AdapterLifecycleMachine:
    """A pure ``(state, event) -> AdapterControl | None`` lifecycle machine.

    Starts ``SPAWNING`` (one spawn incarnation beginning). :meth:`feed` mutates
    ``state`` and returns the control frame to emit (or ``None``). No I/O, no clock —
    the spawn/handshake/backoff/breaker/send all live in the supervisor shell. An
    undefined ``(state, event)`` raises :class:`AdapterLifecycleStateError`
    (fail-loud). Once a terminal (``BREAKER_OPEN`` / ``DOWN``) is reached every event
    absorbs and emits ``None``.
    """

    def __init__(self) -> None:
        self.state: AdapterLifecycleState = AdapterLifecycleState.SPAWNING

    def feed(self, event: AdapterLifecycleEvent) -> AdapterControl | None:
        """Apply ``event`` to the current state; return the control frame to emit.

        Raises :class:`AdapterLifecycleStateError` on a genuinely-undefined pair
        (never a silent no-op — CLAUDE.md hard rule #7). The machine is NOT mutated
        on a fail-loud raise, so it stays usable afterwards.
        """
        try:
            next_state, emitted = _TRANSITIONS[(self.state, event)]
        except KeyError as exc:
            raise AdapterLifecycleStateError(
                f"undefined adapter-lifecycle transition: "
                f"state={self.state.value!r} event={event.value!r}"
            ) from exc
        self.state = next_state
        return emitted


__all__ = [
    "AdapterControl",
    "AdapterLifecycleEvent",
    "AdapterLifecycleMachine",
    "AdapterLifecycleState",
    "AdapterLifecycleStateError",
]
