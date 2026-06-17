"""Unit tests for the pure ``ReplayBuffer`` (Spec A G4a / ADR-0032, #237)."""

from __future__ import annotations

import dataclasses

import pytest
from hypothesis import given
from hypothesis import strategies as st

from alfred.gateway.replay_buffer import ReplayBuffer, ReplayBufferError, ReplayFrame


def _buffer(
    *, max_frames: int = 8, max_bytes: int = 1024, ttl_seconds: float = 30.0
) -> ReplayBuffer:
    return ReplayBuffer(max_frames=max_frames, max_bytes=max_bytes, ttl_seconds=ttl_seconds)


def test_fresh_buffer_is_empty_and_not_tripped() -> None:
    buf = _buffer()
    assert buf.depth_frames == 0
    assert buf.depth_bytes == 0
    assert buf.breaker_tripped is False


def test_replay_frame_is_frozen() -> None:
    frame = ReplayFrame(seq=3, payload=b"x")
    with pytest.raises(dataclasses.FrozenInstanceError):  # frozen dataclass
        frame.seq = 4  # type: ignore[misc]


@pytest.mark.parametrize(
    ("max_frames", "max_bytes", "ttl_seconds"),
    [
        (0, 1024, 30.0),
        (-1, 1024, 30.0),
        (8, 0, 30.0),
        (8, -1, 30.0),
        (8, 1024, 0.0),
        (8, 1024, -1.0),
    ],
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
    body = buf._retained[0].body  # white-box assertion of zeroing
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


def test_hard_byte_ceiling_refuses_a_single_oversized_first_payload() -> None:
    """One giant frame on an empty buffer blows past the byte ceiling on the first append.

    The byte cap exists precisely for this adversarial "one huge payload" shape:
    frames=1 is fine but the payload alone exceeds ``hard_max_bytes``, so the very
    first append must fail-closed loud rather than store-then-OOM.
    """
    buf = _buffer(max_frames=100, max_bytes=4)  # hard=8 bytes
    with pytest.raises(ReplayBufferError, match="hard ceiling"):
        buf.append(0, b"xxxxxxxxx", now=1.0)  # 9 bytes > hard ceiling of 8
    assert buf.depth_frames == 0
    assert buf.depth_bytes == 0


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
    # depth_bytes must drop by exactly the evicted frame's length — the byte-cap
    # accounting line (depth_bytes -= len(body)) executes on a partial evict but is
    # only pinned here, so a regression can't hide behind 100% line coverage.
    assert buf.depth_bytes == len(b"mid") + len(b"new")


def test_evict_boundary_age_equal_ttl_is_retained() -> None:
    buf = _buffer(ttl_seconds=10.0)
    buf.append(0, b"x", now=0.0)
    assert buf.evict_expired(now=10.0) == ()  # age exactly 10, not > 10
    assert buf.depth_frames == 1


def test_evict_zeroes_removed_bodies() -> None:
    buf = _buffer(ttl_seconds=1.0)
    buf.append(0, b"secret", now=0.0)
    body = buf._retained[0].body  # white-box assertion of zeroing
    buf.evict_expired(now=100.0)
    assert bytes(body) == b"\x00" * len(b"secret")


def test_evict_returns_empty_when_nothing_expired() -> None:
    buf = _buffer(ttl_seconds=10.0)
    buf.append(0, b"x", now=0.0)
    assert buf.evict_expired(now=1.0) == ()


def test_evict_rejects_regressed_now() -> None:
    """A backwards clock into evict_expired raises (would silently under-evict)."""
    buf = _buffer(ttl_seconds=10.0)
    buf.append(0, b"x", now=5.0)
    buf.evict_expired(now=8.0)  # advances the shared monotonic floor to 8.0
    with pytest.raises(ReplayBufferError, match="monotonic"):
        buf.evict_expired(now=7.0)  # clock went backwards
    with pytest.raises(ReplayBufferError, match="monotonic"):
        buf.append(1, b"y", now=7.5)  # append floor also advanced by the evict


def test_unacked_frames_returns_fifo_replayframes_carrying_seq() -> None:
    buf = _buffer()
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"bb", now=2.0)
    buf.append(2, b"ccc", now=3.0)
    frames = buf.unacked_frames()
    assert frames == (
        ReplayFrame(seq=0, payload=b"a"),
        ReplayFrame(seq=1, payload=b"bb"),
        ReplayFrame(seq=2, payload=b"ccc"),
    )
    assert all(isinstance(f.payload, bytes) for f in frames)  # immutable for the wire


def test_unacked_frames_does_not_remove() -> None:
    buf = _buffer()
    buf.append(0, b"a", now=1.0)
    buf.unacked_frames()
    buf.unacked_frames()
    assert buf.depth_frames == 1  # still retained until the NEW core acks


def test_unacked_frames_reflects_post_trim_remainder_with_original_seqs() -> None:
    buf = _buffer()
    for seq in range(4):
        buf.append(seq, bytes([65 + seq]), now=float(seq))  # b"A".."D"
    buf.trim_to_ack(1)
    # The remainder carries its ORIGINAL seqs 2,3 (the core dedups on (leg, seq)).
    assert buf.unacked_frames() == (
        ReplayFrame(seq=2, payload=b"C"),
        ReplayFrame(seq=3, payload=b"D"),
    )


def test_retained_seqs_returns_fifo_seqs_body_free() -> None:
    """``retained_seqs`` yields the retained seqs in FIFO order without copying a body.

    Unlike :meth:`unacked_frames` (which mints a fresh immutable ``bytes`` per body —
    an extra un-zeroable pre-DLP copy), this returns ONLY the seqs, so the reconnect
    loss-audit path can name each dropped seq without minting plaintext copies.
    """
    buf = _buffer()
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"bb", now=2.0)
    buf.append(2, b"ccc", now=3.0)
    assert buf.retained_seqs() == (0, 1, 2)
    # White-box: no retained body was copied out — the returned tuple is int-only.
    assert all(isinstance(s, int) for s in buf.retained_seqs())


def test_retained_seqs_empty_buffer_is_empty_tuple() -> None:
    """A fresh (or fully-drained) buffer reports no retained seqs."""
    assert _buffer().retained_seqs() == ()


def test_retained_seqs_reflects_post_trim_remainder() -> None:
    """After a trim the retained seqs are the un-acked remainder, original seqs intact."""
    buf = _buffer()
    for seq in range(4):
        buf.append(seq, bytes([65 + seq]), now=float(seq))
    buf.trim_to_ack(1)
    assert buf.retained_seqs() == (2, 3)


def test_normal_restart_replay_then_continue_never_trips_monotonic_guard() -> None:
    """Spec §4: inbound seq is gateway-owned + monotonic across a core restart."""
    buf = _buffer()
    for seq in range(4):
        buf.append(seq, bytes([seq]), now=float(seq))
    buf.trim_to_ack(1)  # core durably acked 0,1
    # ...core crashes; gateway keeps buffering inbound (no discard)...
    buf.append(4, b"x", now=4.0)
    buf.append(5, b"y", now=5.0)
    # ...new core handshakes, advertises high-water 1 -> trim no-op -> replay remainder.
    replayed = buf.unacked_frames()
    assert [f.seq for f in replayed] == [2, 3, 4, 5]
    # operator types again; gateway mints the next seq -> accepted, no reset needed.
    buf.append(6, b"z", now=6.0)
    assert [f.seq for f in buf.unacked_frames()] == [2, 3, 4, 5, 6]


def test_discard_empties_and_clears_breaker() -> None:
    buf = _buffer(max_frames=1, max_bytes=10_000)
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"b", now=2.0)  # trips breaker
    assert buf.breaker_tripped is True
    buf.discard()
    assert buf.depth_frames == 0
    assert buf.depth_bytes == 0
    assert buf.breaker_tripped is False


def test_discard_zeroes_all_bodies() -> None:
    buf = _buffer()
    buf.append(0, b"alpha", now=1.0)
    buf.append(1, b"bravo", now=2.0)
    bodies = [entry.body for entry in buf._retained]  # white-box zeroing assertion
    buf.discard()
    assert all(bytes(b) == b"\x00" * len(b) for b in bodies)


def test_discard_does_not_reset_seq_floor() -> None:
    """Security F1 / Architect CRITICAL: the gateway-owned seq stays monotonic.

    discard is the give-up/shutdown path; it must NOT re-admit a lower seq, so a
    late stale-stream frame after discard cannot be silently accepted. A genuine
    seq-space restart is G4b's epoch-handshake concern, not a discard side-effect.
    """
    buf = _buffer()
    buf.append(7, b"x", now=1.0)
    buf.discard()
    with pytest.raises(ReplayBufferError):
        buf.append(5, b"stale", now=2.0)  # below the retained floor -> loud reject
    buf.append(8, b"ok", now=3.0)  # still-monotonic continuation is accepted
    assert buf.unacked_frames() == (ReplayFrame(seq=8, payload=b"ok"),)


def test_discard_does_not_reset_now_floor() -> None:
    buf = _buffer()
    buf.append(0, b"x", now=10.0)
    buf.discard()
    with pytest.raises(ReplayBufferError):
        buf.append(1, b"y", now=9.0)  # clock can't go backwards across a discard either


def test_reset_for_new_epoch_zeroes_clears_and_rebinds_floor() -> None:
    """G4b-2a reconnect reset: a fresh core epoch is a fresh seq space restarting at 0.

    Unlike :meth:`discard` (which preserves the monotonic floor so a stale
    post-discard frame is rejected loud), this rebinds the floor so the new epoch's
    seq-0 frame is admitted — while still zeroing every retained pre-DLP body.
    """
    buf = _buffer(max_frames=1, max_bytes=10_000)
    buf.append(0, b"alpha", now=1.0)
    buf.append(1, b"bravo", now=2.0)  # trips the breaker on max_frames=1
    assert buf.breaker_tripped is True
    bodies = [entry.body for entry in buf._retained]  # white-box: capture before reset

    buf.reset_for_new_epoch()

    assert buf.depth_frames == 0
    assert buf.depth_bytes == 0
    assert buf.breaker_tripped is False
    assert all(bytes(b) == b"\x00" * len(b) for b in bodies)  # bodies zeroed in place

    # The floor is rebound: a fresh seq space restarting at 0 is admitted (discard
    # would raise "seq must strictly increase" here), with now also reset to -inf.
    buf.append(0, b"fresh", now=0.0)
    assert buf.unacked_frames() == (ReplayFrame(seq=0, payload=b"fresh"),)


# (payload, monotonic dt) appends with strictly-increasing seq 0..n-1 and non-decreasing now.
_payloads = st.lists(
    st.tuples(st.binary(min_size=0, max_size=16), st.floats(min_value=0.0, max_value=5.0)),
    min_size=0,
    max_size=40,
)


def _fill(payloads: list[tuple[bytes, float]]) -> tuple[ReplayBuffer, list[bytes]]:
    # Generous caps so the hard ceiling never fires in these structural properties.
    buf = ReplayBuffer(max_frames=10_000, max_bytes=10_000_000, ttl_seconds=10_000.0)
    bodies: list[bytes] = []
    clock = 0.0
    for seq, (payload, dt) in enumerate(payloads):
        clock += dt  # dt >= 0 -> now is non-decreasing
        buf.append(seq, payload, now=clock)
        bodies.append(payload)
    return buf, bodies


@given(_payloads)
def test_depth_bytes_equals_sum_of_retained_lengths(payloads: list[tuple[bytes, float]]) -> None:
    buf, bodies = _fill(payloads)
    assert buf.depth_bytes == sum(len(b) for b in bodies)
    assert buf.depth_frames == len(bodies)


@given(_payloads, st.integers(min_value=-1, max_value=60))
def test_trim_is_a_fifo_prefix_and_never_grows_depth(
    payloads: list[tuple[bytes, float]], ack: int
) -> None:
    buf, bodies = _fill(payloads)
    before = buf.depth_frames
    buf.trim_to_ack(ack)
    assert buf.depth_frames <= before
    expected = [(seq, b) for seq, b in enumerate(bodies) if seq > ack]
    assert [(f.seq, f.payload) for f in buf.unacked_frames()] == expected


@given(_payloads)
def test_replay_order_and_seqs_match_append(payloads: list[tuple[bytes, float]]) -> None:
    buf, bodies = _fill(payloads)
    assert [(f.seq, f.payload) for f in buf.unacked_frames()] == list(enumerate(bodies))


@given(_payloads, st.floats(min_value=0.0, max_value=10_000.0))
def test_evict_is_a_fifo_prefix(payloads: list[tuple[bytes, float]], extra: float) -> None:
    buf, bodies = _fill(payloads)
    depth_before = buf.depth_frames
    # evict_expired enforces a monotonic ``now`` (>= the last appended time), so the
    # horizon must sit at or after the fill's final clock — ``max(_last_now, 0.0)``
    # handles the empty-fill ``-inf`` floor without a backwards-clock raise.
    horizon = max(buf._last_now, 0.0) + extra
    evicted = buf.evict_expired(now=horizon)
    assert len(evicted) + buf.depth_frames == depth_before
    assert list(evicted) == sorted(evicted)  # leading ascending run
    # Byte accounting survives a partial evict: depth_bytes equals the sum of the
    # surviving (un-evicted suffix) payload lengths.
    survivors = bodies[len(evicted) :]
    assert buf.depth_bytes == sum(len(b) for b in survivors)
