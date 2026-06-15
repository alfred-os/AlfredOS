"""Unit tests for the pure ``ReplayBuffer`` (Spec A G4a / ADR-0032, #237)."""

from __future__ import annotations

import pytest

from alfred.gateway.replay_buffer import ReplayBuffer, ReplayBufferError, ReplayFrame


def _buffer(*, max_frames: int = 8, max_bytes: int = 1024, ttl_seconds: float = 30.0) -> ReplayBuffer:
    return ReplayBuffer(max_frames=max_frames, max_bytes=max_bytes, ttl_seconds=ttl_seconds)


def test_fresh_buffer_is_empty_and_not_tripped() -> None:
    buf = _buffer()
    assert buf.depth_frames == 0
    assert buf.depth_bytes == 0
    assert buf.breaker_tripped is False


def test_replay_frame_is_frozen() -> None:
    frame = ReplayFrame(seq=3, payload=b"x")
    with pytest.raises(Exception):  # frozen dataclass -> FrozenInstanceError
        frame.seq = 4  # type: ignore[misc]


@pytest.mark.parametrize(
    ("max_frames", "max_bytes", "ttl_seconds"),
    [(0, 1024, 30.0), (-1, 1024, 30.0), (8, 0, 30.0), (8, -1, 30.0), (8, 1024, 0.0), (8, 1024, -1.0)],
)
def test_non_positive_caps_raise(max_frames: int, max_bytes: int, ttl_seconds: float) -> None:
    with pytest.raises(ReplayBufferError):
        ReplayBuffer(max_frames=max_frames, max_bytes=max_bytes, ttl_seconds=ttl_seconds)


def test_append_increments_depths() -> None:
    buf = _buffer()
    buf.append(0, b"hello", now=1.0)
    buf.append(1, b"world!", now=2.0)
    assert buf.depth_frames == 2
    assert buf.depth_bytes == len(b"hello") + len(b"world!")


def test_append_requires_strictly_increasing_seq() -> None:
    buf = _buffer()
    buf.append(5, b"a", now=1.0)
    with pytest.raises(ReplayBufferError):
        buf.append(5, b"b", now=2.0)  # equal — not strictly increasing
    with pytest.raises(ReplayBufferError):
        buf.append(4, b"c", now=3.0)  # decreasing


def test_append_rejects_negative_seq() -> None:
    buf = _buffer()
    with pytest.raises(ReplayBufferError):
        buf.append(-1, b"a", now=1.0)


def test_append_requires_non_decreasing_now() -> None:
    buf = _buffer()
    buf.append(0, b"a", now=5.0)
    with pytest.raises(ReplayBufferError):
        buf.append(1, b"b", now=4.0)  # clock went backwards
    buf.append(1, b"b", now=5.0)  # equal now is allowed


@pytest.mark.skip(reason="unacked_frames lands in Task 6")
def test_append_stores_independent_mutable_copy() -> None:
    buf = _buffer()
    source = bytearray(b"mutable")
    buf.append(0, bytes(source), now=1.0)
    source[:] = b"XXXXXXX"  # mutating the source must not change what we retained
    assert buf.unacked_frames() == (ReplayFrame(seq=0, payload=b"mutable"),)


def test_trim_removes_acked_prefix() -> None:
    buf = _buffer()
    for seq in range(5):
        buf.append(seq, bytes([seq]) * 4, now=float(seq))
    buf.trim_to_ack(2)  # acks seqs 0,1,2
    assert buf.depth_frames == 2  # 3,4 remain
    assert buf.depth_bytes == 4 + 4


def test_trim_zeroes_removed_bodies() -> None:
    buf = _buffer()
    buf.append(0, b"secret", now=1.0)
    body = buf._retained[0].body  # noqa: SLF001 - white-box assertion of zeroing
    buf.trim_to_ack(0)
    assert bytes(body) == b"\x00" * len(b"secret")


def test_trim_below_first_seq_is_noop() -> None:
    buf = _buffer()
    buf.append(3, b"x", now=1.0)
    buf.trim_to_ack(-1)
    buf.trim_to_ack(2)
    assert buf.depth_frames == 1


def test_trim_at_or_past_last_seq_empties() -> None:
    buf = _buffer()
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"bb", now=2.0)
    buf.trim_to_ack(9)
    assert buf.depth_frames == 0
    assert buf.depth_bytes == 0


def test_soft_frame_cap_breach_trips_breaker_and_keeps_frame() -> None:
    buf = _buffer(max_frames=2, max_bytes=10_000)
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"b", now=2.0)
    assert buf.breaker_tripped is False
    buf.append(2, b"c", now=3.0)  # 3rd frame, over soft max_frames=2 (hard=4)
    assert buf.breaker_tripped is True
    assert buf.depth_frames == 3  # NEVER dropped


def test_soft_byte_cap_breach_trips_breaker_and_keeps_frame() -> None:
    buf = _buffer(max_frames=100, max_bytes=8)
    buf.append(0, b"aaaa", now=1.0)
    buf.append(1, b"bbbb", now=2.0)  # depth_bytes == 8 == cap, not over
    assert buf.breaker_tripped is False
    buf.append(2, b"c", now=3.0)  # depth_bytes == 9 > 8 (hard=16)
    assert buf.breaker_tripped is True
    assert buf.depth_frames == 3


def test_hard_frame_ceiling_refuses_loud() -> None:
    buf = _buffer(max_frames=2, max_bytes=10_000)  # hard=4 frames
    for seq in range(4):
        buf.append(seq, b"x", now=float(seq))  # fills to the hard ceiling
    assert buf.depth_frames == 4
    with pytest.raises(ReplayBufferError, match="hard ceiling"):
        buf.append(4, b"y", now=5.0)
    assert buf.depth_frames == 4  # the refused frame was NOT stored


def test_hard_byte_ceiling_refuses_loud() -> None:
    buf = _buffer(max_frames=100, max_bytes=4)  # hard=8 bytes
    buf.append(0, b"aaaa", now=1.0)
    buf.append(1, b"bbbb", now=2.0)  # depth_bytes == 8 == hard ceiling
    with pytest.raises(ReplayBufferError, match="hard ceiling"):
        buf.append(2, b"c", now=3.0)  # would be 9 > 8
    assert buf.depth_bytes == 8


def test_breaker_is_a_latch_trim_does_not_clear() -> None:
    buf = _buffer(max_frames=1, max_bytes=10_000)
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"b", now=2.0)  # trips
    assert buf.breaker_tripped is True
    buf.trim_to_ack(1)  # back to empty, under cap
    assert buf.depth_frames == 0
    assert buf.breaker_tripped is True  # still latched


def test_evict_removes_only_expired_frames() -> None:
    buf = _buffer(ttl_seconds=10.0)
    buf.append(0, b"old", now=0.0)
    buf.append(1, b"mid", now=5.0)
    buf.append(2, b"new", now=9.0)
    evicted = buf.evict_expired(now=11.0)  # frame@0 age 11 > 10; @5 age 6; @9 age 2
    assert evicted == (0,)
    assert buf.depth_frames == 2


def test_evict_boundary_age_equal_ttl_is_retained() -> None:
    buf = _buffer(ttl_seconds=10.0)
    buf.append(0, b"x", now=0.0)
    assert buf.evict_expired(now=10.0) == ()  # age exactly 10, not > 10
    assert buf.depth_frames == 1


def test_evict_zeroes_removed_bodies() -> None:
    buf = _buffer(ttl_seconds=1.0)
    buf.append(0, b"secret", now=0.0)
    body = buf._retained[0].body  # noqa: SLF001 - white-box assertion of zeroing
    buf.evict_expired(now=100.0)
    assert bytes(body) == b"\x00" * len(b"secret")


def test_evict_returns_empty_when_nothing_expired() -> None:
    buf = _buffer(ttl_seconds=10.0)
    buf.append(0, b"x", now=0.0)
    assert buf.evict_expired(now=1.0) == ()
