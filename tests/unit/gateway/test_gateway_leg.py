"""Unit tests for the ``GatewayLeg`` owning object (Spec B G6-4 / #288, K1 + K2 + Task 4).

K1: each leg owns {adapter_id, ReplayBuffer, per-leg seq counter, breaker latch,
read-halt gate, PerAdapterIngressGate, bounded send queue}. Seq is minted + the buffer
appended at DRAIN time, strict per-leg FIFO. K2: the leg wraps every byte-reclaim path
with a GlobalReplayCap reserve/release so the budget never leaks. Task 4: the per-adapter
buffer-depth gauges track this leg's buffer and only this leg's.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from alfred.gateway.adapter_metrics import (
    ADAPTER_BUFFER_DEPTH_BYTES,
    ADAPTER_BUFFER_DEPTH_FRAMES,
)
from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.global_replay_cap import GlobalReplayCap
from alfred.gateway.ingress_gate import IngressDecision, PerAdapterIngressGate
from alfred.gateway.replay_buffer import ReplayBuffer, ReplayBufferError


class _FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def _leg(
    *,
    adapter_id: str = "tui",
    cap: GlobalReplayCap | None = None,
    max_frames: int = 8,
    max_bytes: int = 1024,
    burst: int = 99,
    max_inflight: int = 99,
    max_frame_bytes: int = 1024,
    clock: _FakeClock | None = None,
) -> tuple[GatewayLeg, GlobalReplayCap, _FakeClock]:
    c = clock or _FakeClock()
    cap = cap or GlobalReplayCap(max_total_bytes=10_000)
    gate = PerAdapterIngressGate(
        adapter_id,
        sustained_rate_per_s=100.0,
        burst=burst,
        max_inflight=max_inflight,
        ttl_seconds=30.0,
        max_frame_bytes=max_frame_bytes,
        now=c,
    )
    buffer = ReplayBuffer(max_frames=max_frames, max_bytes=max_bytes, ttl_seconds=30.0)
    leg = GatewayLeg(
        adapter_id=adapter_id,
        buffer=buffer,
        ingress_gate=gate,
        global_cap=cap,
        now=c,
    )
    return leg, cap, c


def _depth_frames_gauge(adapter: str) -> float:
    return float(ADAPTER_BUFFER_DEPTH_FRAMES.labels(adapter=adapter)._value.get())  # type: ignore[attr-defined]


def _depth_bytes_gauge(adapter: str) -> float:
    return float(ADAPTER_BUFFER_DEPTH_BYTES.labels(adapter=adapter)._value.get())  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Identity + admission delegation                                             #
# --------------------------------------------------------------------------- #


def test_leg_exposes_adapter_id() -> None:
    leg, _, _ = _leg(adapter_id="discord")
    assert leg.adapter_id == "discord"


def test_try_admit_delegates_to_gate() -> None:
    leg, _, _ = _leg(burst=1, max_inflight=99)
    assert leg.try_admit(frame_bytes=1).decision is IngressDecision.ADMITTED
    assert leg.try_admit(frame_bytes=1).decision is IngressDecision.THROTTLED_RATE


def test_observability_accessors() -> None:
    leg, _, _ = _leg()
    assert leg.depth_frames == 0
    assert leg.cap_ratio == 0.0
    assert leg.inflight_count == 0
    assert leg.last_seq == -1
    leg.record_for_send(b"aaaa")
    assert leg.depth_frames == 1
    assert leg.cap_ratio > 0.0
    assert leg.last_seq == 0


def test_admit_release_and_evict_stalled_delegate() -> None:
    clock = _FakeClock()
    leg, _, _ = _leg(max_inflight=1, clock=clock)
    admit = leg.try_admit(frame_bytes=1)
    assert admit.token is not None
    assert leg.inflight_count == 1
    leg.release_admit(admit.token)
    assert leg.inflight_count == 0
    # evict_stalled path: hold a slot past TTL.
    held = leg.try_admit(frame_bytes=1)
    clock.advance(31.0)
    assert held.token in leg.evict_stalled_admits()


def test_unacked_frames_returns_seq_payload_pairs() -> None:
    leg, _, _ = _leg()
    leg.record_for_send(b"aa")
    leg.record_for_send(b"bbb")
    assert leg.unacked_frames() == ((0, b"aa"), (1, b"bbb"))


# --------------------------------------------------------------------------- #
# Seq mint + buffer append at DRAIN time (K1)                                  #
# --------------------------------------------------------------------------- #


def test_record_for_send_mints_monotonic_seq_and_appends() -> None:
    leg, _, _ = _leg()
    s0 = leg.record_for_send(b"aaa")
    s1 = leg.record_for_send(b"bb")
    assert (s0, s1) == (0, 1)  # strict per-leg FIFO seq
    assert leg.depth_frames == 2
    assert leg.depth_bytes == len(b"aaa") + len(b"bb")


def test_seq_resets_on_new_epoch() -> None:
    leg, _, _ = _leg()
    leg.record_for_send(b"a")
    leg.reset_for_new_epoch()
    assert leg.record_for_send(b"b") == 0  # fresh per-connection seq space


# --------------------------------------------------------------------------- #
# K2 — global cap reserve before append, release on ALL reclaim paths          #
# --------------------------------------------------------------------------- #


def test_record_reserves_global_cap() -> None:
    leg, cap, _ = _leg(adapter_id="a")
    leg.record_for_send(b"xxxxx")
    assert cap.leg_bytes("a") == 5
    assert cap.total_bytes == 5


def test_global_cap_refusal_back_pressures_without_appending() -> None:
    cap = GlobalReplayCap(max_total_bytes=4)
    leg, cap, _ = _leg(adapter_id="a", cap=cap)
    with pytest.raises(ReplayBufferError):
        # 5 bytes > 4-byte global cap: the leg refuses via a loud fail-closed raise.
        leg.record_for_send(b"xxxxx")
    # Nothing accrued — no leak.
    assert cap.total_bytes == 0
    assert leg.depth_bytes == 0


def test_trim_releases_global_cap() -> None:
    leg, cap, _ = _leg(adapter_id="a")
    leg.record_for_send(b"aaaa")  # seq 0
    leg.record_for_send(b"bb")  # seq 1
    assert cap.total_bytes == 6
    leg.trim_to_ack(0)  # acks seq 0 (the 4-byte frame)
    assert cap.leg_bytes("a") == 2
    assert cap.total_bytes == 2
    assert leg.depth_bytes == 2


def test_evict_releases_global_cap() -> None:
    clock = _FakeClock()
    leg, cap, _ = _leg(adapter_id="a", clock=clock)
    leg.record_for_send(b"aaaa")
    clock.advance(31.0)
    evicted = leg.evict_expired()
    assert evicted == (0,)
    assert cap.total_bytes == 0
    assert leg.depth_bytes == 0


def test_discard_releases_global_cap() -> None:
    leg, cap, _ = _leg(adapter_id="a")
    leg.record_for_send(b"aaaa")
    leg.discard()
    assert cap.total_bytes == 0
    assert leg.depth_bytes == 0


def test_reset_for_new_epoch_releases_global_cap() -> None:
    leg, cap, _ = _leg(adapter_id="a")
    leg.record_for_send(b"aaaa")
    leg.reset_for_new_epoch()
    assert cap.total_bytes == 0
    assert leg.depth_bytes == 0


def test_discard_zeros_bodies_but_preserves_seq_floor() -> None:
    """PR9: ``discard`` empties + releases bytes but PRESERVES the seq floor; reset does not.

    The discard != reset distinction is load-bearing for resume after a terminal scrub:
    ``discard`` zeros + empties the buffer and releases the global cap, but the per-leg seq
    counter MUST keep advancing (the next mint continues the sequence) — only the
    per-connection ``reset_for_new_epoch`` rebinds the floor to 0. A regression folding
    ``discard`` into ``reset`` would silently restart the wire seq at 0 after a scrub and
    corrupt the core's G0-dedup keying, yet pass every other test. Pin BOTH halves so the
    distinction cannot regress.
    """
    leg, cap, _ = _leg(adapter_id="a")
    leg.record_for_send(b"aaaa")  # seq 0
    leg.record_for_send(b"bb")  # seq 1
    assert leg.last_seq == 1
    assert cap.total_bytes == 6

    # discard: bodies + bytes gone, global cap released — but the seq floor is UNCHANGED.
    leg.discard()
    assert leg.depth_frames == 0
    assert leg.depth_bytes == 0
    assert cap.total_bytes == 0
    assert cap.leg_bytes("a") == 0
    assert leg.last_seq == 1  # seq floor preserved across the scrub
    assert leg.record_for_send(b"c") == 2  # the next mint CONTINUES the sequence, not 0

    # reset_for_new_epoch: the per-connection path DOES rebind the floor to 0.
    leg.reset_for_new_epoch()
    assert leg.last_seq == -1  # floor reset (nothing minted on the fresh connection)
    assert leg.record_for_send(b"d") == 0  # the next mint RESTARTS the sequence


def test_hard_ceiling_raise_rolls_back_global_reserve() -> None:
    # K2 (a): a ReplayBufferError between reserve and a completed append must release the
    # reservation. Drive the buffer to its hard ceiling so append raises AFTER the leg
    # reserved global budget.
    leg, cap, _ = _leg(adapter_id="a", max_frames=2, max_bytes=1024)
    # soft cap is 2 frames; hard ceiling is 2x = 4 frames. Fill to the hard ceiling.
    for _ in range(4):
        leg.record_for_send(b"x")
    reserved_before = cap.total_bytes
    with pytest.raises(ReplayBufferError):
        leg.record_for_send(b"x")  # 5th frame breaches the hard ceiling
    # The failed append released its reservation — no leak.
    assert cap.total_bytes == reserved_before


# --------------------------------------------------------------------------- #
# Task 4 — per-adapter buffer metrics, only the mutated leg                    #
# --------------------------------------------------------------------------- #


def test_record_refreshes_this_legs_depth_gauges() -> None:
    leg, _, _ = _leg(adapter_id="metric-leg-1")
    leg.record_for_send(b"abc")
    assert _depth_frames_gauge("metric-leg-1") == 1.0
    assert _depth_bytes_gauge("metric-leg-1") == 3.0


def test_series_exist_at_construction() -> None:
    _leg(adapter_id="metric-leg-2")
    assert _depth_frames_gauge("metric-leg-2") == 0.0
    assert _depth_bytes_gauge("metric-leg-2") == 0.0


def test_cross_leg_gauge_non_interference() -> None:
    leg_a, cap, _ = _leg(adapter_id="m-A")
    leg_b = GatewayLeg(
        adapter_id="m-B",
        buffer=ReplayBuffer(max_frames=8, max_bytes=1024, ttl_seconds=30.0),
        ingress_gate=PerAdapterIngressGate(
            "m-B",
            sustained_rate_per_s=100.0,
            burst=99,
            max_inflight=99,
            ttl_seconds=30.0,
            max_frame_bytes=1024,
            now=_FakeClock(),
        ),
        global_cap=cap,
        now=_FakeClock(),
    )
    leg_a.record_for_send(b"aaaa")
    # B's gauge is untouched by A's churn (B exists, at 0).
    assert leg_b.depth_bytes == 0
    assert _depth_bytes_gauge("m-B") == 0.0
    assert _depth_bytes_gauge("m-A") == 4.0


# --------------------------------------------------------------------------- #
# read-halt gate (back-pressure)                                              #
# --------------------------------------------------------------------------- #


def test_breaker_tripped_reflects_buffer() -> None:
    leg, _, _ = _leg(max_frames=2, max_bytes=1024)
    assert leg.breaker_tripped is False
    for _ in range(3):  # 3 > soft cap of 2 -> breaker latches
        leg.record_for_send(b"x")
    assert leg.breaker_tripped is True


# --------------------------------------------------------------------------- #
# teardown (perf-L1)                                                          #
# --------------------------------------------------------------------------- #


def test_teardown_discards_buffer_and_removes_cap_entry() -> None:
    leg, cap, _ = _leg(adapter_id="td")
    leg.record_for_send(b"aaaa")
    leg.teardown()
    assert cap.leg_bytes("td") == 0
    assert cap.total_bytes == 0
    assert leg.depth_bytes == 0


# --------------------------------------------------------------------------- #
# K2 invariant — cap.total == Σ leg.depth_bytes across any op sequence         #
# --------------------------------------------------------------------------- #


@given(
    ops=st.lists(
        st.sampled_from(["record", "trim", "evict", "discard", "reset", "teardown"]),
        max_size=30,
    ),
    sizes=st.lists(st.integers(min_value=1, max_value=20), min_size=30, max_size=30),
)
def test_cap_total_equals_leg_depth_invariant(ops: list[str], sizes: list[int]) -> None:
    clock = _FakeClock()
    cap = GlobalReplayCap(max_total_bytes=100_000)
    leg, cap, _ = _leg(adapter_id="inv", cap=cap, max_frames=1000, max_bytes=100_000, clock=clock)
    size_it = iter(sizes)
    for op in ops:
        try:
            if op == "record":
                leg.record_for_send(b"x" * next(size_it))
            elif op == "trim":
                leg.trim_to_ack(leg.last_seq)
            elif op == "evict":
                clock.advance(31.0)
                leg.evict_expired()
            elif op == "discard":
                leg.discard()
            elif op == "reset":
                leg.reset_for_new_epoch()
            else:
                leg.teardown()
        except (ReplayBufferError, StopIteration):
            pass
        # The cap's accounting for THIS leg always equals the leg's resident bytes —
        # teardown drops both to 0 together; a later record re-establishes both. This is
        # the K2 budget-leak guard: no op can desynchronise the cap from the buffer.
        assert cap.leg_bytes("inv") == leg.depth_bytes
        assert cap.total_bytes == cap.leg_bytes("inv")
