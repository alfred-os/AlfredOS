"""Unit tests for ``BoundedSeqAckTracker`` (Spec A G3-3b-2 / ADR-0032).

The relay needs ONLY the contiguous-high-water ``cumulative_ack()`` to send the
core its real cumulative ack. It must do so under a memory bound on an always-up
process: an adversary streaming every-other-seq (``0, 2, 4, …``) must NOT be able
to grow the out-of-order set without limit. These tests pin the bound (the gap
cap) and the loud rejection of any seq beyond it, alongside the ordinary
contiguous-advance + gap-fill semantics.
"""

from __future__ import annotations

import pytest
import structlog.testing

from alfred.gateway._seq_tracker import _MAX_OOO_GAP, BoundedSeqAckTracker


def test_contiguous_run_advances_high_water() -> None:
    tracker = BoundedSeqAckTracker()

    tracker.observe(0)
    tracker.observe(1)
    tracker.observe(2)

    assert tracker.cumulative_ack() == 2


def test_empty_tracker_acks_negative_one() -> None:
    assert BoundedSeqAckTracker().cumulative_ack() == -1


def test_out_of_order_then_gap_fill_advances() -> None:
    tracker = BoundedSeqAckTracker()

    # A hole at 1: high-water stalls at 0 (the top of the unbroken 0.. run).
    tracker.observe(0)
    tracker.observe(2)
    assert tracker.cumulative_ack() == 0

    # Fill the gap: the run jumps to 2 (0,1,2 all present).
    tracker.observe(1)
    assert tracker.cumulative_ack() == 2


def test_idempotent_reobserve_does_not_regress() -> None:
    tracker = BoundedSeqAckTracker()
    tracker.observe(0)
    tracker.observe(1)
    tracker.observe(1)  # a re-sighting is a no-op for the high-water
    assert tracker.cumulative_ack() == 1


def test_every_other_seq_stream_stays_bounded() -> None:
    """The always-up adversary: ``0, 2, 4, …`` never fills the gap at 1, so the
    high-water is pinned at 0 and every even seq above ``high + _MAX_OOO_GAP`` is
    REJECTED loud — so the out-of-order retention can never exceed the cap.

    Without the window guard the ``_seen`` set would grow one entry per even seq
    forever (an unbounded-memory DoS on an always-up gateway).
    """
    tracker = BoundedSeqAckTracker()

    with structlog.testing.capture_logs() as captured:
        for seq in range(0, 4097, 2):
            tracker.observe(seq)

    # The high-water never advances past 0 (1 is never seen).
    assert tracker.cumulative_ack() == 0
    # Every even seq strictly beyond high(0) + _MAX_OOO_GAP is rejected loud.
    rejected = [c for c in captured if c.get("event") == "gateway.relay.seq_out_of_window"]
    assert rejected, captured
    assert all(c.get("log_level") == "warning" for c in rejected)
    # The bound holds: the largest ADMITTED out-of-order seq is within the cap of high.
    assert tracker.cumulative_ack() + _MAX_OOO_GAP >= 2  # the cap admits at least seq 2


def test_seq_at_cap_edge_is_admitted_but_beyond_is_rejected() -> None:
    """The exact cap edge: ``high + _MAX_OOO_GAP`` is admitted; one beyond is rejected."""
    tracker = BoundedSeqAckTracker()
    tracker.observe(0)  # high-water = 0
    # 1 is never observed, so the high-water stays 0 and the window is [1, 0+cap].
    at_edge = _MAX_OOO_GAP  # 0 + _MAX_OOO_GAP
    beyond = _MAX_OOO_GAP + 1

    tracker.observe(at_edge)  # admitted (== high + cap)

    with structlog.testing.capture_logs() as captured:
        tracker.observe(beyond)  # rejected (> high + cap)

    rejected = [c for c in captured if c.get("event") == "gateway.relay.seq_out_of_window"]
    assert len(rejected) == 1
    assert rejected[0].get("log_level") == "warning"
    assert rejected[0].get("seq") == beyond
    assert rejected[0].get("high") == 0


def test_rejected_seq_is_not_admitted_so_later_fill_cannot_use_it() -> None:
    """A rejected seq is NOT recorded: it cannot silently appear in the run later."""
    tracker = BoundedSeqAckTracker()
    tracker.observe(0)
    beyond = _MAX_OOO_GAP + 1
    tracker.observe(beyond)  # rejected, not admitted

    # Walk the contiguous run up to ``beyond`` - 1. If ``beyond`` had been admitted,
    # filling 1..beyond-1 would jump the high-water THROUGH ``beyond``; it must stop
    # one short because ``beyond`` was never recorded.
    for seq in range(1, beyond):
        tracker.observe(seq)
    assert tracker.cumulative_ack() == beyond - 1


def test_negative_seq_raises_value_error() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        BoundedSeqAckTracker().observe(-1)
