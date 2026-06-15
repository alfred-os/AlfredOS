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
