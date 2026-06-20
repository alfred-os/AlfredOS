"""Unit tests for the pure ``PerAdapterIngressGate`` (Spec B G6-4 / #288).

The gate is a payload-blind, per-adapter admission controller: a sustained-rate
token bucket (lazy refill, ``min``-clamped — no timer) + an in-flight concurrency
cap (with a TTL-evict so a stalled leg cannot wedge) + a ``max_frame_bytes``
size guard (size != content, so payload-blindness holds). A fake monotonic clock
drives every time-dependent branch deterministically.
"""

from __future__ import annotations

import pytest

from alfred.gateway.ingress_gate import (
    AdmitResult,
    IngressDecision,
    PerAdapterIngressGate,
)


class _FakeClock:
    """A monotonic fake clock: ``advance`` moves it forward, never backward."""

    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def _gate(
    *,
    adapter_id: str = "tui",
    sustained_rate_per_s: float = 5.0,
    burst: int = 3,
    max_inflight: int = 2,
    ttl_seconds: float = 30.0,
    max_frame_bytes: int = 1024,
    clock: _FakeClock | None = None,
) -> tuple[PerAdapterIngressGate, _FakeClock]:
    c = clock or _FakeClock()
    gate = PerAdapterIngressGate(
        adapter_id,
        sustained_rate_per_s=sustained_rate_per_s,
        burst=burst,
        max_inflight=max_inflight,
        ttl_seconds=ttl_seconds,
        max_frame_bytes=max_frame_bytes,
        now=c,
    )
    return gate, c


# --------------------------------------------------------------------------- #
# Construction validation                                                      #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("rate", "burst", "max_inflight", "ttl", "max_frame_bytes"),
    [
        (0.0, 3, 2, 30.0, 1024),
        (-1.0, 3, 2, 30.0, 1024),
        (5.0, 0, 2, 30.0, 1024),
        (5.0, -1, 2, 30.0, 1024),
        (5.0, 3, 0, 30.0, 1024),
        (5.0, 3, -1, 30.0, 1024),
        (5.0, 3, 2, 0.0, 1024),
        (5.0, 3, 2, -1.0, 1024),
        (5.0, 3, 2, 30.0, 0),
        (5.0, 3, 2, 30.0, -1),
    ],
)
def test_non_positive_params_raise(
    rate: float, burst: int, max_inflight: int, ttl: float, max_frame_bytes: int
) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        PerAdapterIngressGate(
            "tui",
            sustained_rate_per_s=rate,
            burst=burst,
            max_inflight=max_inflight,
            ttl_seconds=ttl,
            max_frame_bytes=max_frame_bytes,
            now=_FakeClock(),
        )


def test_adapter_id_exposed() -> None:
    gate, _ = _gate(adapter_id="discord")
    assert gate.adapter_id == "discord"


def test_inflight_count_tracks_admits_and_releases() -> None:
    gate, _ = _gate(burst=99, max_inflight=99)
    assert gate.inflight_count == 0
    a = gate.try_admit(frame_bytes=1)
    b = gate.try_admit(frame_bytes=1)
    assert gate.inflight_count == 2
    assert a.token is not None and b.token is not None
    gate.release(a.token)
    assert gate.inflight_count == 1


# --------------------------------------------------------------------------- #
# Token bucket (rate tier)                                                     #
# --------------------------------------------------------------------------- #


def test_admits_within_burst() -> None:
    gate, _ = _gate(burst=3, max_inflight=99)
    for _ in range(3):
        result = gate.try_admit(frame_bytes=10)
        assert result.decision is IngressDecision.ADMITTED
        assert result.token is not None


def test_throttles_on_rate_exhaustion_then_recovers_after_refill() -> None:
    gate, clock = _gate(sustained_rate_per_s=5.0, burst=3, max_inflight=99)
    # Drain the burst.
    tokens = [gate.try_admit(frame_bytes=1) for _ in range(3)]
    assert all(t.decision is IngressDecision.ADMITTED for t in tokens)
    # 4th within the same instant: no tokens left -> rate throttle.
    blocked = gate.try_admit(frame_bytes=1)
    assert blocked.decision is IngressDecision.THROTTLED_RATE
    assert blocked.token is None
    # Refill: at 5/s, after 0.2s exactly one token is back.
    clock.advance(0.2)
    again = gate.try_admit(frame_bytes=1)
    assert again.decision is IngressDecision.ADMITTED


def test_refill_is_clamped_to_burst_no_over_accrual() -> None:
    # K5: lazy refill is min(burst, tokens + elapsed*rate); a long idle does not
    # accrue more than ``burst`` tokens.
    gate, clock = _gate(sustained_rate_per_s=5.0, burst=3, max_inflight=99)
    clock.advance(1_000.0)  # huge idle
    admitted = 0
    while gate.try_admit(frame_bytes=1).decision is IngressDecision.ADMITTED:
        admitted += 1
        if admitted > 10:  # guard against an unclamped infinite refill
            break
    assert admitted == 3  # clamped to burst, not 1000*5


def test_refill_sub_token_does_not_admit() -> None:
    # F7: a sub-token elapsed refill (< 1 token) must NOT admit.
    gate, clock = _gate(sustained_rate_per_s=5.0, burst=1, max_inflight=99)
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.ADMITTED
    clock.advance(0.1)  # 0.5 tokens — not a whole token
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.THROTTLED_RATE


def test_zero_elapsed_refill_is_noop() -> None:
    # F7: zero elapsed (two admits at the same instant) refills nothing.
    gate, _ = _gate(sustained_rate_per_s=5.0, burst=1, max_inflight=99)
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.ADMITTED
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.THROTTLED_RATE


# --------------------------------------------------------------------------- #
# In-flight cap (concurrency tier)                                             #
# --------------------------------------------------------------------------- #


def test_throttles_on_inflight_cap() -> None:
    gate, _ = _gate(burst=99, max_inflight=2)
    a = gate.try_admit(frame_bytes=1)
    b = gate.try_admit(frame_bytes=1)
    assert a.decision is IngressDecision.ADMITTED
    assert b.decision is IngressDecision.ADMITTED
    c = gate.try_admit(frame_bytes=1)
    assert c.decision is IngressDecision.THROTTLED_INFLIGHT
    assert c.token is None


def test_release_decrements_inflight_and_re_admits() -> None:
    gate, _ = _gate(burst=99, max_inflight=1)
    first = gate.try_admit(frame_bytes=1)
    assert first.decision is IngressDecision.ADMITTED
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.THROTTLED_INFLIGHT
    assert first.token is not None
    gate.release(first.token)
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.ADMITTED


def test_release_unknown_token_is_loud() -> None:
    gate, _ = _gate()
    other_gate, _ = _gate()
    tok = other_gate.try_admit(frame_bytes=1).token
    assert tok is not None
    with pytest.raises(ValueError, match="unknown"):
        gate.release(tok)


# --------------------------------------------------------------------------- #
# TTL eviction (the wedge guard)                                              #
# --------------------------------------------------------------------------- #


def test_stalled_slot_past_ttl_is_evicted_and_re_admits() -> None:
    gate, clock = _gate(burst=99, max_inflight=1, ttl_seconds=30.0)
    held = gate.try_admit(frame_bytes=1)
    assert held.decision is IngressDecision.ADMITTED
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.THROTTLED_INFLIGHT
    # Past the TTL: the stalled slot is reclaimed.
    clock.advance(31.0)
    evicted = gate.evict_stalled()
    assert held.token in evicted
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.ADMITTED


def test_evict_at_ttl_boundary_retains() -> None:
    # F7: a slot exactly at TTL (not strictly past) is retained.
    gate, clock = _gate(burst=99, max_inflight=2, ttl_seconds=30.0)
    gate.try_admit(frame_bytes=1)
    clock.advance(30.0)  # exactly at TTL
    assert gate.evict_stalled() == ()


def test_evict_empty_inflight_is_noop() -> None:
    # F7: evicting with no in-flight slots returns the empty tuple.
    gate, clock = _gate()
    clock.advance(100.0)
    assert gate.evict_stalled() == ()


def test_evicted_slot_release_is_safe_noop() -> None:
    # A token evicted by TTL, then released by a late completion, is a quiet no-op
    # (not a double-decrement, not a raise) — the slot is already reclaimed.
    gate, clock = _gate(burst=99, max_inflight=1, ttl_seconds=30.0)
    held = gate.try_admit(frame_bytes=1)
    clock.advance(31.0)
    gate.evict_stalled()
    assert held.token is not None
    gate.release(held.token)  # idempotent: no raise, no double free
    # Cap is back to 1 free slot, not 2.
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.ADMITTED
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.THROTTLED_INFLIGHT


# --------------------------------------------------------------------------- #
# max_frame_bytes (K3 — size, not content)                                     #
# --------------------------------------------------------------------------- #


def test_oversized_frame_refused() -> None:
    gate, _ = _gate(max_frame_bytes=16)
    result = gate.try_admit(frame_bytes=17)
    assert result.decision is IngressDecision.OVERSIZED
    assert result.token is None


def test_exact_max_frame_bytes_admitted() -> None:
    gate, _ = _gate(max_frame_bytes=16, burst=99)
    assert gate.try_admit(frame_bytes=16).decision is IngressDecision.ADMITTED


def test_oversize_check_precedes_rate_and_inflight() -> None:
    # An oversized frame must NOT consume a token or an in-flight slot.
    gate, _ = _gate(max_frame_bytes=4, burst=1, max_inflight=1)
    assert gate.try_admit(frame_bytes=99).decision is IngressDecision.OVERSIZED
    # The single token + slot are still free.
    assert gate.try_admit(frame_bytes=1).decision is IngressDecision.ADMITTED


# --------------------------------------------------------------------------- #
# Payload-blindness + volumetric (not identity) bound                          #
# --------------------------------------------------------------------------- #


def test_admit_takes_only_a_size_never_a_body() -> None:
    # The gate's admission surface is (frame_bytes) — there is no body / platform
    # id parameter, so it CANNOT key on identity. A distributed-id flood is bounded
    # by volume alone: N admits then throttle, regardless of "who".
    gate, _ = _gate(burst=4, max_inflight=99)
    admitted = sum(
        1 for _ in range(10) if gate.try_admit(frame_bytes=1).decision is IngressDecision.ADMITTED
    )
    assert admitted == 4  # the burst, irrespective of any per-id distribution


def test_admit_result_is_frozen() -> None:
    import dataclasses

    gate, _ = _gate()
    result = gate.try_admit(frame_bytes=1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.decision = IngressDecision.OVERSIZED  # type: ignore[misc]
    assert isinstance(result, AdmitResult)
