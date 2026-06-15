"""``BoundedSeqAckTracker`` — a bounded contiguous-ack tracker for the relay.

Spec A G3-3b-2 / ADR-0032 (#237). The gateway's core-leg pump RECEIVES seq-framed
units from the core and must send back its REAL cumulative ack (the top of the
unbroken ``0..k`` run). This is the receive-side tracker the relay reads
:meth:`cumulative_ack` from when it writes a unit back to the core.

**Why a NEW class — not :class:`alfred.plugins.comms_seq_codec.SeqDedupWindow`.**
The merged window's seen-set grows UNBOUNDED on an always-up process; that is
correct for G2 (a pure unit under test) but a memory-DoS on the long-lived
gateway. Pruning the merged window cannot be retrofitted without breaking its
documented idempotent-``accept`` contract that other call sites rely on (architect
M2). And pruning the seen-set BELOW the high-water would not even bound the real
adversary: an every-other-seq stream (``0, 2, 4, …``) never fills the gap at 1, so
the holes are all ABOVE the high-water and pruning-below-high-water frees nothing
(security H2). This tracker instead REJECTS any seq more than :data:`_MAX_OOO_GAP`
beyond the contiguous high-water, so the out-of-order retention is hard-bounded.

**Trust posture.** A seq outside the window is rejected LOUD (a structlog warning)
and NOT admitted (CLAUDE.md hard rule #7 — no silent drop). A negative seq is a
programming error, raised loudly. The tracker is pure state + no I/O beyond the
one warning log.
"""

from __future__ import annotations

from typing import Final

import structlog

log = structlog.get_logger(__name__)

# The maximum distance a newly-observed ``seq`` may sit beyond the contiguous
# high-water before it is rejected. This bounds the out-of-order set: on an
# every-other-seq adversary (``0, 2, 4, …``) the high-water stalls at the first
# gap, so once the stream reaches ``high + _MAX_OOO_GAP`` every further seq is
# refused and the admitted out-of-order retention can never exceed ~``_MAX_OOO_GAP``
# entries. 1024 is generous for legitimate in-flight reordering on a single boot's
# wire yet small enough that the worst-case retention is trivially bounded.
_MAX_OOO_GAP: Final[int] = 1024


class BoundedSeqAckTracker:
    """Receive-side contiguous-ack tracker with a bounded out-of-order window.

    :meth:`observe` records a received ``seq`` and advances ``_contiguous_high``
    over the unbroken run (like :class:`SeqDedupWindow`'s advance loop). A ``seq``
    more than :data:`_MAX_OOO_GAP` beyond the current high-water is REJECTED loud
    and NOT admitted — so the seen-set cannot grow without bound on an always-up
    process. :meth:`cumulative_ack` returns the high-water (``-1`` until any
    contiguous run exists).

    Not a dedup oracle: it does not report whether a ``seq`` was new (that is the
    G2 window's job on the core side). It exists solely so the relay can answer the
    core with a memory-safe cumulative ack.
    """

    def __init__(self) -> None:
        self._seen: set[int] = set()
        self._contiguous_high: int = -1

    def observe(self, seq: int) -> None:
        """Record ``seq`` and advance the high-water; reject + log if out of window.

        A negative ``seq`` is a programming error (raised loudly). A ``seq`` strictly
        beyond ``_contiguous_high + _MAX_OOO_GAP`` is rejected loud and not admitted
        (the out-of-order bound). Otherwise the seq is recorded and the contiguous
        high-water advances over the unbroken ``0.. run`` it now reaches.
        """
        if seq < 0:
            raise ValueError(f"seq must be non-negative: {seq}")
        if seq > self._contiguous_high + _MAX_OOO_GAP:
            # Beyond the out-of-order window: refuse it (do NOT admit), loud so an
            # operator sees an adversarial / badly-reordered stream (hard rule #7).
            log.warning(
                "gateway.relay.seq_out_of_window",
                seq=seq,
                high=self._contiguous_high,
            )
            return
        self._seen.add(seq)
        # Advance the contiguous high-water as far as the unbroken run now reaches.
        while (self._contiguous_high + 1) in self._seen:
            self._contiguous_high += 1

    def cumulative_ack(self) -> int:
        """Highest CONTIGUOUS seq seen (top of the unbroken 0.. run); ``-1`` if none."""
        return self._contiguous_high


__all__ = ["BoundedSeqAckTracker"]
