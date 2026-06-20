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
    """The minimal core-link surface the scheduler drains onto (the single writer)."""

    def core_cumulative_ack(self) -> int: ...

    async def write_leg_unit(
        self, adapter_id: str, payload: bytes, *, seq: int, ack: int
    ) -> None: ...


class _LegQueue:
    """One leg's bounded FIFO send queue + its byte accounting."""

    def __init__(self, leg: GatewayLeg, *, max_bytes: int) -> None:
        self.leg = leg
        self._max_bytes = max_bytes
        self._frames: deque[bytes] = deque()
        self._bytes = 0

    @property
    def empty(self) -> bool:
        return not self._frames

    def offer(self, payload: bytes) -> None:
        """Append iff within the byte budget; else raise :class:`LegQueueFullError`."""
        if self._bytes + len(payload) > self._max_bytes:
            raise LegQueueFullError(
                f"leg {self.leg.adapter_id!r} send queue full "
                f"({self._bytes} + {len(payload)} > {self._max_bytes} bytes)"
            )
        self._frames.append(payload)
        self._bytes += len(payload)

    def pop(self) -> bytes:
        payload = self._frames.popleft()
        self._bytes -= len(payload)
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

    @property
    def registered_adapters(self) -> frozenset[str]:
        """The adapter ids currently registered (observability / teardown checks)."""
        return frozenset(self._queues)

    def register_leg(self, leg: GatewayLeg) -> None:
        """Register ``leg`` with a fresh bounded send queue; duplicate is a loud misuse."""
        if leg.adapter_id in self._queues:
            raise ValueError(f"leg already registered: {leg.adapter_id!r}")
        self._queues[leg.adapter_id] = _LegQueue(leg, max_bytes=self._max_per_leg_queue_bytes)

    def deregister_leg(self, adapter_id: str) -> None:
        """Drop + tear down a leg (discard buffer + release budget); no-op if absent."""
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
        """
        while True:
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
        """Drain at most one frame per leg (TUI first); return whether anything was drained."""
        drained = False
        for adapter_id in self._round_order():
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
        """
        payload = queue.pop()
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
