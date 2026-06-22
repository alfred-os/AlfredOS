"""``GatewayLegScheduler`` — fair egress across N legs over one core writer (Spec B G6-4).

Keystone K3. The always-up gateway multiplexes N adapter legs (+ the TUI dial-in leg)
over the SINGLE physical ``core_link`` writer. Left unmanaged, a chatty or large-payload
leg would serialize ahead of a live ``alfred chat`` frame or starve another adapter
(``[fleet perf-001]``). This scheduler fans the legs' egress fairly onto that one writer:

* **bounded per-leg send queue (in BYTES, perf-M3).** :meth:`enqueue` accepts a payload
  iff the leg's queued bytes stay ``<= max_per_leg_queue_bytes``; an over-budget enqueue
  raises :class:`LegQueueFullError` so the caller back-pressures THAT leg only (never an
  unbounded queue, never a silent drop — the frame is rejected with a typed signal). The
  queue is pre-append working memory the :class:`GlobalReplayCap` does not yet see, so it
  is bounded independently.
* **round-robin-by-frame fairness (K3 v1).** :meth:`run` drains ONE frame per non-empty
  leg per round. The single physical writer means at most one in-flight frame, so RR-by-
  frame is the honest unit: a large frame still delays others *by its own serialization*
  (bounded by the leg ingress gate's ``max_frame_bytes``), but no leg is drained twice
  before another is drained once.
* **TUI reserved minimum credit (K3 / sec L).** The TUI (interactive) leg is drained
  FIRST in each round, so its frame is at most one adapter frame behind a saturated
  adapter — its latency has a floor in N, not just an equal share.
* **per-leg isolation (perf-M4).** Each leg's drain is wrapped so a leg whose
  :meth:`GatewayLeg.record_for_send` raises (a global-cap-full / hard-ceiling fail-closed)
  is torn down (its buffer discarded → pre-DLP bytes zeroed, its global-cap budget
  released) and deregistered — the pump survives and keeps draining every other leg.

**At drain time the LEG mints the seq + appends to its buffer (K1).** The scheduler calls
:meth:`GatewayLeg.record_for_send`, which returns the minted seq, then hands the unit to
the leg-agnostic :meth:`GatewayCoreLink.write_leg_unit` for the physical write. The
scheduler never reaches into the transport — the single-writer / snapshot atomicity lives
in ``core_link``.

**Payload-blind (CLAUDE.md hard rule #5).** Queues hold opaque bytes keyed only on
``adapter_id``; nothing here parses or logs a body.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Iterable
from typing import Final, Protocol

import structlog

from alfred.errors import AlfredError
from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.replay_buffer import ReplayBufferError

log = structlog.get_logger(__name__)

# The TUI leg's adapter id — drained first each round for its reserved interactive credit.
_TUI_ADAPTER_ID: Final[str] = "tui"


class LegQueueFullError(AlfredError):
    """A leg's bounded send queue is full — back-pressure THAT leg (CLAUDE.md hard rule #7).

    Raised by :meth:`GatewayLegScheduler.enqueue` when accepting the payload would push the
    leg's queued bytes over ``max_per_leg_queue_bytes``. A typed back-pressure signal, never
    a silent drop: the caller (the relay's read pump) stops draining the upstream socket so
    the OS buffer back-pressures the peer.
    """


class _CoreWriterLike(Protocol):
    """The minimal core-link surface the scheduler drains onto (the single writer).

    Includes the :meth:`replay_pending_gate` seam (Spec B G6-4 Task 7 / Option A): the
    drain pump awaits this :class:`asyncio.Event` before each round so a CLEARED gate (a
    reconnect-replay in flight) PARKS the scheduler while
    :meth:`alfred.gateway.core_link.GatewayCoreLink._flush_pending_replay` re-sends the
    captured remainder directly (the sanctioned reconnect-internal writer). The flush sets
    the gate on completion, so fresh frames drain BEHIND the replayed ones — preserving the
    resume oracle (replay-precedes-fresh, per-leg seq monotonicity). On a link with no
    buffer the gate is permanently set, so the await is a zero-cost immediate return.
    """

    def core_cumulative_ack(self) -> int: ...

    @property
    def replay_pending_gate(self) -> asyncio.Event: ...

    async def escalate_if_breaker_tripped(self, leg: GatewayLeg) -> None: ...

    async def write_leg_unit(
        self, adapter_id: str, payload: bytes, *, seq: int, ack: int
    ) -> None: ...


# The MINIMUM queue cost charged per frame (CR / Spec B G6-4 #288). A zero-length payload
# would otherwise add 0 bytes to the accounting while still appending to the deque, so an
# empty-frame flood could grow the deque UNBOUNDED past ``max_bytes`` (the "bounded queue"
# guarantee silently broken — CLAUDE.md hard rule #7). Charging at least one unit per frame
# makes the byte budget ALSO a frame-count cap: at most ``max_bytes`` queued frames.
_MIN_FRAME_COST_BYTES: Final[int] = 1


class _LegQueue:
    """One leg's bounded FIFO send queue + its byte accounting.

    The accounting charges ``max(len(payload), _MIN_FRAME_COST_BYTES)`` per frame so a flood
    of zero-length frames cannot bypass the byte bound and grow the deque without limit.
    """

    def __init__(self, leg: GatewayLeg, *, max_bytes: int) -> None:
        self.leg = leg
        self._max_bytes = max_bytes
        # Each entry is ``(payload, charged_cost)`` so ``pop`` credits back the SAME cost the
        # ``offer`` charged (never ``len(payload)``, which would under-credit an empty frame
        # and slowly leak the budget).
        self._frames: deque[tuple[bytes, int]] = deque()
        self._bytes = 0

    @property
    def empty(self) -> bool:
        return not self._frames

    def offer(self, payload: bytes) -> None:
        """Append iff within the byte budget; else raise :class:`LegQueueFullError`.

        Charges ``max(len(payload), _MIN_FRAME_COST_BYTES)`` — a minimum of one unit per
        frame — so an empty-frame flood cannot append unbounded (CR / Spec B G6-4 #288).
        """
        cost = max(len(payload), _MIN_FRAME_COST_BYTES)
        if self._bytes + cost > self._max_bytes:
            raise LegQueueFullError(
                f"leg {self.leg.adapter_id!r} send queue full "
                f"({self._bytes} + {cost} > {self._max_bytes} bytes)"
            )
        self._frames.append((payload, cost))
        self._bytes += cost

    def pop(self) -> bytes:
        payload, cost = self._frames.popleft()
        self._bytes -= cost
        return payload


class GatewayLegScheduler:
    """Fair round-robin egress of registered legs onto the single core writer (K3)."""

    def __init__(self, core_link: _CoreWriterLike, *, max_per_leg_queue_bytes: int) -> None:
        if max_per_leg_queue_bytes <= 0:
            raise ValueError(f"max_per_leg_queue_bytes must be positive: {max_per_leg_queue_bytes}")
        self._core_link = core_link
        self._max_per_leg_queue_bytes = max_per_leg_queue_bytes
        # Insertion-ordered so RR is deterministic; the TUI leg is drained first regardless.
        self._queues: dict[str, _LegQueue] = {}
        # Signalled whenever a frame is enqueued so an idle pump wakes promptly.
        self._wakeup = asyncio.Event()
        # Spec B G6-7-3 (#309) — FORK-C: optional per-adapter back-pressure gates. The
        # gateway forward path CLEARS an adapter's gate when its leg is full (pausing the
        # child-stdio reader so the child back-pressures the platform); this scheduler
        # SETS that adapter's gate after it drains a frame off that leg (resume). A leg
        # with NO registered gate (the TUI / daemon-default legs) drains byte-for-byte
        # unchanged — the gate is a forward-runner collaborator, not a scheduler invariant.
        self._back_pressure_gates: dict[str, asyncio.Event] = {}

    @property
    def registered_adapters(self) -> frozenset[str]:
        """The adapter ids currently registered (observability / teardown checks)."""
        return frozenset(self._queues)

    def register_leg(self, leg: GatewayLeg) -> None:
        """Register ``leg`` with a fresh bounded send queue; duplicate is a loud misuse."""
        if leg.adapter_id in self._queues:
            raise ValueError(f"leg already registered: {leg.adapter_id!r}")
        self._queues[leg.adapter_id] = _LegQueue(leg, max_bytes=self._max_per_leg_queue_bytes)

    def set_back_pressure_gate(self, adapter_id: str, gate: asyncio.Event) -> None:
        """Register ``adapter_id``'s forward back-pressure gate (Spec B G6-7-3 / FORK-C).

        The gateway forward path clears this gate when the leg is full; this scheduler
        SETS it after draining a frame off the leg (resume). ``KeyError`` for an
        unregistered adapter — registering a gate for a leg the scheduler does not own
        is a loud routing misuse (CLAUDE.md hard rule #7), never a silent no-op.
        """
        if adapter_id not in self._queues:
            raise KeyError(f"back-pressure gate for an unregistered leg: {adapter_id!r}")
        self._back_pressure_gates[adapter_id] = gate

    def deregister_leg(self, adapter_id: str) -> None:
        """Drop + tear down a leg (discard buffer + release budget); no-op if absent.

        Spec B G6-7-3 (#309): also drops the leg's back-pressure gate so a deregistered
        leg's gate cannot linger and a later re-registration starts clean.
        """
        self._back_pressure_gates.pop(adapter_id, None)
        entry = self._queues.pop(adapter_id, None)
        if entry is not None:
            entry.leg.teardown()

    def enqueue(self, adapter_id: str, payload: bytes) -> None:
        """Queue one opaque payload for ``adapter_id``; raise on an unknown / full leg.

        ``KeyError`` for an unregistered adapter (a routing bug — never default-route);
        :class:`LegQueueFullError` when the per-leg byte budget is exceeded (back-pressure that
        leg only). On success the pump is woken.
        """
        queue = self._queues.get(adapter_id)
        if queue is None:
            raise KeyError(f"enqueue for an unregistered leg: {adapter_id!r}")
        queue.offer(payload)
        self._wakeup.set()

    async def run(self) -> None:
        """Drain registered legs fairly onto the single core writer until cancelled.

        Each round: drain ONE frame from the TUI leg first (reserved credit), then one
        frame from every other non-empty leg in registration order (RR-by-frame). When
        every queue is empty the pump parks on the wakeup event (cleared each idle pass) so
        it does not busy-spin; an :meth:`enqueue` sets it. Cancellation-safe: the park and
        the writes are interruptible, so a shutdown cancel ends the pump cleanly.

        **Replay gate (Spec B G6-4 Task 7 / Option A).** Each round AWAITS the core-link's
        replay-pending gate FIRST: while it is CLEAR (a reconnect-replay in flight), the
        scheduler parks so :meth:`GatewayCoreLink._flush_pending_replay` is the sole writer
        of the captured remainder (seqs 0..N-1, in FIFO at the lowest seqs). The flush sets
        the gate on completion, so the scheduler then drains fresh frames behind the
        replayed ones — the resume oracle (replay-precedes-fresh, per-leg monotonicity) is
        preserved. On a no-buffer link the gate is permanently set (zero-cost return).
        """
        while True:
            await self._core_link.replay_pending_gate.wait()
            drained = await self._drain_one_round()
            if not drained:
                # ``not drained`` means every leg's queue was empty this round (a round
                # drains one frame off EVERY non-empty leg). There is no await between that
                # and ``clear()``, and ``enqueue`` always ``set()``s, so a frame queued
                # after this point re-sets the event and the ``wait()`` returns promptly —
                # no lost wakeup, no busy-spin.
                self._wakeup.clear()
                await self._wakeup.wait()

    async def _drain_one_round(self) -> bool:
        """Drain at most one frame per leg (TUI first); return whether anything was drained.

        **Per-frame replay-gate re-check (CR / Spec B G6-4 #288).** A round drains one frame
        off EVERY non-empty leg, and each drain ``await``s a physical write. ``run`` gates the
        START of the round on :attr:`replay_pending_gate`, but a reconnect can CLEAR that gate
        AFTER an early leg's write — and then
        :meth:`GatewayCoreLink._flush_pending_replay` becomes the sanctioned reconnect-internal
        writer of the captured remainder. So BEFORE each per-leg drain we re-check the gate: if
        it has been CLEARED mid-round (a reconnect-replay started), the round STOPS draining and
        returns, yielding the writer to the flush. ``run`` re-awaits the gate at the top of the
        NEXT round, so the remaining queued frames drain BEHIND the replayed ones — preserving
        the single-writer invariant + replay-precedes-fresh ACROSS legs (the per-leg
        generation-guard in :meth:`_drain_one_frame` only catches a leg that was itself RESET;
        it does NOT stop an un-reset OTHER leg from writing during a peer leg's replay).

        The check is a non-blocking ``is_set()`` (NOT an ``await``) and is skipped for the FIRST
        leg of the round: ``run`` already awaited the gate at round start, so the first frame
        always drains (a DIRECT caller driving a deliberate single post-handshake / pre-flush
        drain — the unit-suite seam — must complete the frame it just enqueued, never deadlock).
        The bail only skips the REMAINING legs once a replay has actually started mid-round. On
        a no-buffer link the gate is permanently set (never bails).
        """
        drained = False
        for index, adapter_id in enumerate(self._round_order()):
            if index > 0 and not self._core_link.replay_pending_gate.is_set():
                # A reconnect-replay started mid-round (after >=1 leg drained): stop and yield
                # the single writer to the flush. ``run`` re-awaits the gate before the next
                # round, so the remaining queued frames drain BEHIND the replayed ones.
                break
            queue = self._queues.get(adapter_id)
            if queue is None or queue.empty:
                continue
            await self._drain_one_frame(adapter_id, queue)
            drained = True
        return drained

    def _round_order(self) -> list[str]:
        """The drain order for one round: the TUI leg first (reserved credit), then the rest.

        A snapshot list so a leg deregistered mid-round (the isolation path) does not mutate
        the iterable under us.
        """
        order = [a for a in self._queues if a != _TUI_ADAPTER_ID]
        if _TUI_ADAPTER_ID in self._queues:
            order.insert(0, _TUI_ADAPTER_ID)
        return order

    async def _drain_one_frame(self, adapter_id: str, queue: _LegQueue) -> None:
        """Record + write ONE frame off ``queue``; isolate a faulting leg (perf-M4).

        The leg's :meth:`GatewayLeg.record_for_send` mints the seq + appends to the buffer
        (under the global cap). A :class:`ReplayBufferError` (global-cap-full / hard-ceiling
        fail-closed) is isolated: the faulting leg is torn down (buffer discarded, budget
        released) + deregistered, the frame dropped LOUD — the pump survives for every other
        leg. The physical write itself is the leg-agnostic ``write_leg_unit`` (loud-drops a
        gapped leg internally; never raises here).

        **Breaker escalation (Spec B G6-4 Task 7).** AFTER a successful ``record_for_send``
        (the append is what can breach the soft cap) and BEFORE the physical write, the
        scheduler calls the leg-agnostic core-link seam
        :meth:`GatewayCoreLink.escalate_if_breaker_tripped` — the breaker feed moved out of
        the retired inline ``submit_tui_unit`` path into this drain context. The
        ``LinkStateMachine`` the core-link owns absorbs a repeat feed, so the once-only
        ``link.unavailable`` escalation + its audit row fire EXACTLY once across every
        caller. Skipped on the isolation path (a torn-down leg never escalates).

        **Stale-write guard (H3, Spec B G6-4 / #288).** The seq is minted synchronously, but
        the escalate + write ``await``. A concurrent reconnect that resets the leg during that
        window (capturing + re-flushing this frame at the fresh seq) bumps the leg generation;
        the drain snapshots the generation at mint and SKIPS the physical write if it changed —
        the frame is already re-sent at the fresh seq, so skipping the stale write preserves
        wire-seq contiguity + exactly-once delivery (the frame is NOT lost).
        """
        payload = queue.pop()
        # Spec B G6-7-3 (#309) — FORK-C: the queue slot just freed; SET this adapter's
        # back-pressure gate (if the forward path registered one) so a paused child-stdio
        # reader RESUMES. Set on the POP (capacity-freed edge), before the record/write
        # awaits, so resume is prompt and the isolation/stale-write arms below still
        # release the reader (the frame left the queue regardless of the wire outcome).
        # A leg with no registered gate (TUI / daemon-default) is unaffected.
        resume_gate = self._back_pressure_gates.get(adapter_id)
        if resume_gate is not None:
            resume_gate.set()
        ack = self._core_link.core_cumulative_ack()
        try:
            seq = queue.leg.record_for_send(payload)
        except ReplayBufferError as exc:
            log.warning(
                "gateway.scheduler.leg_isolated",
                adapter_id=adapter_id,
                reason="record_failed",
                error=repr(exc),
            )
            self.deregister_leg(adapter_id)
            return
        # H3 (Spec B G6-4, #288): snapshot the leg GENERATION right after the seq mint. The
        # mint is synchronous, but the escalate + write below ``await`` — a concurrent reconnect
        # can, during those awaits, capture this leg's un-acked frames, ``reset_for_new_epoch``
        # it (generation bump, seq->0), and re-flush THIS frame at the fresh seq. If that
        # happened, the in-flight ``write_leg_unit`` below would write the SAME frame a SECOND
        # time at the now-STALE seq on the fresh transport — a forward-seq-jump that corrupts
        # the wire-seq contiguity the ack/resume keys on. The generation snapshot lets us detect
        # it before the physical write (re-awaiting the gate alone is a TOCTOU — the
        # generation-compare-before-write is the robust fix).
        generation = queue.leg.generation
        await self._core_link.escalate_if_breaker_tripped(queue.leg)
        if queue.leg.generation != generation:
            # A reconnect reset the leg DURING the mint->write await: this physical write is
            # STALE. SKIP it — the frame was captured into ``_pending_replay`` and re-flushed at
            # the fresh seq, so it is NOT lost (exactly-once preserved). Loud (CLAUDE.md hard
            # rule #7), payload-blind (``adapter_id`` + the stale seq only).
            log.warning(
                "gateway.scheduler.stale_write_skipped",
                adapter_id=adapter_id,
                seq=seq,
                reason="leg_reset_mid_drain",
            )
            return
        await self._core_link.write_leg_unit(adapter_id, payload, seq=seq, ack=ack)

    def aclose(self) -> None:
        """Tear down EVERY registered leg (reap on process exit). Idempotent."""
        for adapter_id in list(self._queues):
            self.deregister_leg(adapter_id)

    def adapter_ids(self) -> Iterable[str]:
        """The registered adapter ids (for the periodic sweeper to iterate, Task 7)."""
        return tuple(self._queues)

    def leg(self, adapter_id: str) -> GatewayLeg:
        """The registered leg for ``adapter_id`` (the sweeper / wiring reaches it)."""
        return self._queues[adapter_id].leg


__all__ = ["GatewayLegScheduler", "LegQueueFullError"]
