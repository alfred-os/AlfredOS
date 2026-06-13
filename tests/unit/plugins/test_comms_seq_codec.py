"""Pure CommsSeqCodec encode/decode + dedup-window (Spec A G2 / ADR-0032) (#237)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from alfred.plugins.comms_seq_codec import (
    _MAX_DECIMAL_WIDTH,
    _MAX_HEADER_BYTES,
    SEQ_MAGIC,
    SeqDedupWindow,
    SeqFrame,
    decode_seq_frame,
    encode_seq_frame,
)
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsProtocolError

_PLAIN = b'{"jsonrpc":"2.0","id":7,"method":"inbound.message","params":{}}'


def test_encode_prepends_magic_header() -> None:
    raw = encode_seq_frame(_PLAIN, seq=3, ack=1)
    assert raw.startswith(SEQ_MAGIC)
    assert raw.endswith(b"\n")


def test_round_trip_preserves_payload_verbatim() -> None:
    raw = encode_seq_frame(_PLAIN, seq=3, ack=1)
    frame = decode_seq_frame(raw)
    assert frame.payload == _PLAIN  # byte-for-byte, never re-serialized
    assert frame.seq == 3
    assert frame.ack == 1


def test_plain_line_without_magic_is_fallback() -> None:
    """A non-negotiated peer's plain ADR-0025 line decodes as un-sequenced."""
    frame = decode_seq_frame(_PLAIN + b"\n")
    assert frame.seq is None
    assert frame.ack is None
    assert frame.payload == _PLAIN


def test_plain_line_without_trailing_newline_is_fallback() -> None:
    """A plain line with no trailing newline still decodes (decode strips one)."""
    frame = decode_seq_frame(_PLAIN)
    assert frame.seq is None
    assert frame.payload == _PLAIN


def test_id_inside_payload_is_untouched() -> None:
    """The codec never decodes the payload, so the JSON-RPC id survives."""
    raw = encode_seq_frame(_PLAIN, seq=99, ack=0)
    assert b'"id":7' in decode_seq_frame(raw).payload


def test_lying_length_raises() -> None:
    raw = encode_seq_frame(_PLAIN, seq=1, ack=0)
    # Corrupt the declared n= so it no longer matches the payload run.
    tampered = raw.replace(b"n=%d" % len(_PLAIN), b"n=%d" % (len(_PLAIN) + 5))
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(tampered)


def test_non_integer_seq_raises() -> None:
    bad = SEQ_MAGIC + b" s=NOPE a=0 n=2 |{}\n"
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(bad)


def test_wrong_field_prefix_raises() -> None:
    """A header token without its expected key prefix is malformed."""
    bad = SEQ_MAGIC + b" x=0 a=0 n=2 |{}\n"
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(bad)


def test_negative_counter_on_wire_raises() -> None:
    """A header with a negative counter (``s=-5``) is malformed on decode."""
    bad = SEQ_MAGIC + b" s=-5 a=0 n=2 |{}\n"
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(bad)


@pytest.mark.parametrize(
    "bad",
    [
        SEQ_MAGIC + b" s=+5 a=0 n=2 |{}\n",  # explicit-sign token
        SEQ_MAGIC + b" s=1_0 a=0 n=2 |{}\n",  # PEP-515 underscore grouping
    ],
)
def test_non_canonical_counter_token_raises(bad: bytes) -> None:
    """A counter token that is not pure base-10 digits is malformed.

    ``int()`` accepts ``+5`` and ``1_0`` (Python literal syntax), but this is a
    cross-implementation WIRE format: a counter is canonical base-10 digits only.
    ``bytes.isdigit()`` rejects the sign, the grouping underscore, leading/trailing
    spaces, and the empty body before ``int()`` is reached, so a non-conformant
    peer's token fails loudly rather than being silently normalised.
    """
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(bad)


def test_header_wrong_token_count_raises() -> None:
    """A magic-prefixed header with too few space-separated tokens is malformed."""
    bad = SEQ_MAGIC + b" s=0 a=0 |{}\n"  # missing the n= token
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(bad)


def test_over_bound_unit_raises_on_encode() -> None:
    huge = b"x" * 16
    with pytest.raises(CommsProtocolError):
        encode_seq_frame(huge, seq=0, ack=0, max_unit_bytes=8)


def test_over_bound_raw_raises_on_decode() -> None:
    """The decode path enforces the bound too (drive the decode over-bound branch)."""
    raw = encode_seq_frame(b"x" * 32, seq=0, ack=0)
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(raw, max_unit_bytes=8)


def test_payload_ceiling_is_guaranteed_for_worst_case_counters() -> None:
    """On a negotiated wire the payload ceiling is max_unit_bytes - _MAX_HEADER_BYTES.

    Option A (architect F1): the header costs budget, so the usable payload
    shrinks. ``_MAX_HEADER_BYTES`` is a worst-case RESERVATION — a payload at
    exactly the ceiling is guaranteed to encode regardless of how wide the
    seq/ack counters are (so the G3 relay can size payloads against the
    reservation without knowing the counters). Prove it with the WIDEST counters
    the codec will emit: a payload at the ceiling still fits under the bound.
    """
    cap = _MAX_COMMS_LINE_BYTES
    ceiling = cap - _MAX_HEADER_BYTES
    wide = _MAX_COMMS_LINE_BYTES  # widest decimal counter
    raw = encode_seq_frame(b"x" * ceiling, seq=wide, ack=wide, max_unit_bytes=cap)
    assert raw.endswith(b"\n")
    assert len(raw) <= cap


def test_payload_just_over_outer_bound_raises_on_send() -> None:
    """A payload whose real unit exceeds max_unit_bytes raises on SEND."""
    cap = 256
    # A payload that, with even the SMALLEST header (seq/ack=0), exceeds cap.
    with pytest.raises(CommsProtocolError):
        encode_seq_frame(b"x" * cap, seq=0, ack=0, max_unit_bytes=cap)


def test_max_header_bytes_reserves_real_worst_case() -> None:
    """_MAX_HEADER_BYTES bounds the actual header width for a max-len payload."""
    # The widest header is produced by the widest counters. The payload-len field
    # is bounded by _MAX_COMMS_LINE_BYTES, so a header sized for that bounds all.
    big_seq = _MAX_COMMS_LINE_BYTES
    payload = b"z"
    raw = encode_seq_frame(payload, seq=big_seq, ack=big_seq)
    header = raw[: raw.index(b"|") + 1]  # through the delimiter
    assert len(header) <= _MAX_HEADER_BYTES


def test_no_delimiter_arm_raises() -> None:
    """A magic-prefixed line with no `` |`` delimiter is malformed (branch cover)."""
    bad = SEQ_MAGIC + b" s=0 a=0 n=0"  # header, no delimiter, no payload
    with pytest.raises(CommsProtocolError):
        decode_seq_frame(bad + b"\n")


def test_empty_payload_round_trips() -> None:
    raw = encode_seq_frame(b"", seq=0, ack=0)
    frame = decode_seq_frame(raw)
    assert frame.payload == b""
    assert frame.seq == 0


def test_negative_seq_rejected_on_encode() -> None:
    with pytest.raises(ValueError):
        encode_seq_frame(_PLAIN, seq=-1, ack=0)


def test_negative_ack_rejected_on_encode() -> None:
    with pytest.raises(ValueError):
        encode_seq_frame(_PLAIN, seq=0, ack=-1)


def test_too_wide_counter_raises() -> None:
    """A counter wider than ``_MAX_DECIMAL_WIDTH`` digits violates the
    ``_MAX_HEADER_BYTES`` reservation invariant, so encode rejects it loudly.

    The reservation guarantees ``cap - _MAX_HEADER_BYTES`` always fits ONLY while
    seq/ack stay within the reserved decimal width. A counter just over
    ``10**_MAX_DECIMAL_WIDTH`` is one digit too wide; encode must refuse rather
    than silently overrun the documented reservation.
    """
    too_wide = 10**_MAX_DECIMAL_WIDTH  # one digit wider than the reserved width
    with pytest.raises(ValueError):
        encode_seq_frame(_PLAIN, seq=too_wide, ack=0)
    with pytest.raises(ValueError):
        encode_seq_frame(_PLAIN, seq=0, ack=too_wide)


# --- hypothesis property tests -------------------------------------------------

# Building blocks that LOOK like header structure inside the payload, so the
# round-trip proves the `` |`` delimiter + `n=` length-prefix split is unambiguous
# regardless of payload content (test F1). The codec must split on the FIRST `` |``
# and trust `n=`, never re-scan the payload.
_ADVERSARIAL_CHUNK = st.sampled_from([b"x", b" |", b"n=5", b"a=0", b"A1 ", b"\t", b"{}"])
_ADVERSARIAL_PAYLOAD = (
    st.lists(_ADVERSARIAL_CHUNK, max_size=64).map(b"".join).filter(lambda b: b"\n" not in b)
)


# Counters are bounded to the reserved decimal width (the invariant
# ``encode_seq_frame`` now enforces): a counter wider than ``_MAX_DECIMAL_WIDTH``
# digits would violate the ``_MAX_HEADER_BYTES`` reservation and is rejected, so
# the round-trip identity property is stated over the VALID counter domain.
_MAX_WIRE_COUNTER: int = 10**_MAX_DECIMAL_WIDTH - 1


@given(
    payload=_ADVERSARIAL_PAYLOAD,
    seq=st.integers(min_value=0, max_value=_MAX_WIRE_COUNTER),
    ack=st.integers(min_value=0, max_value=_MAX_WIRE_COUNTER),
)
def test_property_round_trip_is_identity_on_payload(payload: bytes, seq: int, ack: int) -> None:
    frame = decode_seq_frame(encode_seq_frame(payload, seq=seq, ack=ack))
    assert frame.payload == payload  # delimiter/length split is unambiguous
    assert frame.seq == seq
    assert frame.ack == ack


@given(payloads=st.lists(_ADVERSARIAL_PAYLOAD, min_size=1, max_size=16))
def test_property_fifo_ordering_preserved(payloads: list[bytes]) -> None:
    """Encode a list with seq=i, decode all: seqs == range(n) AND payloads in order."""
    units = [encode_seq_frame(p, seq=i, ack=0) for i, p in enumerate(payloads)]
    frames = [decode_seq_frame(u) for u in units]
    assert [f.seq for f in frames] == list(range(len(payloads)))
    assert [f.payload for f in frames] == payloads


def test_seqframe_is_frozen() -> None:
    frame = SeqFrame(seq=1, ack=0, payload=b"x")
    with pytest.raises(FrozenInstanceError):
        frame.seq = 2  # type: ignore[misc]


# --- SeqDedupWindow: per-leg accept-once + cumulative-ack state machine --------


def test_window_accepts_in_order_and_advances_ack() -> None:
    w = SeqDedupWindow(leg="inbound")
    assert w.accept(0) is True
    assert w.accept(1) is True
    assert w.accept(2) is True
    assert w.cumulative_ack() == 2


def test_window_leg_is_exposed() -> None:
    assert SeqDedupWindow(leg="outbound").leg == "outbound"


def test_window_empty_ack_is_negative_one() -> None:
    assert SeqDedupWindow(leg="inbound").cumulative_ack() == -1


def test_window_drops_reseen_seq_idempotently() -> None:
    w = SeqDedupWindow(leg="inbound")
    assert w.accept(0) is True
    assert w.accept(0) is False  # re-seen (leg, seq) dropped
    assert w.accept(0) is False  # third sighting behaves like the second
    assert w.cumulative_ack() == 0


def test_window_gap_does_not_advance_ack() -> None:
    w = SeqDedupWindow(leg="inbound")
    assert w.accept(0) is True
    assert w.accept(2) is True  # accepted (new) but NON-contiguous
    assert w.cumulative_ack() == 0  # ack stalls at the top of the 0.. run
    assert w.accept(1) is True  # fills the gap
    assert w.cumulative_ack() == 2  # now the run is 0,1,2


def test_window_first_seq_not_zero_stalls_ack() -> None:
    """A leg that has never seen seq 0 has no contiguous run from 0 (ack == -1)."""
    w = SeqDedupWindow(leg="inbound")
    assert w.accept(5) is True
    assert w.cumulative_ack() == -1


def test_ack_is_monotonic_non_decreasing() -> None:
    w = SeqDedupWindow(leg="inbound")
    for s in (0, 1, 2):
        w.accept(s)
    high = w.cumulative_ack()
    w.accept(2)  # re-seen — must not lower the ack
    assert w.cumulative_ack() == high


def test_window_rejects_negative_seq() -> None:
    w = SeqDedupWindow(leg="inbound")
    with pytest.raises(ValueError):
        w.accept(-1)


@settings(max_examples=200)
@given(seqs=st.lists(st.integers(min_value=0, max_value=64), max_size=128))
def test_property_ack_never_exceeds_contiguous_run(seqs: list[int]) -> None:
    """ack == top of the unbroken 0..k run, regardless of arrival order."""
    w = SeqDedupWindow(leg="inbound")
    seen: set[int] = set()
    for s in seqs:
        accepted = w.accept(s)
        assert accepted is (s not in seen)  # dedup idempotency
        seen.add(s)
    # Independent recomputation of the contiguous high-water.
    expected = -1
    while (expected + 1) in seen:
        expected += 1
    assert w.cumulative_ack() == expected


@given(seqs=st.lists(st.integers(min_value=0, max_value=64), max_size=128))
def test_property_replay_is_idempotent(seqs: list[int]) -> None:
    """Replaying the whole sequence a second time accepts nothing new + same ack."""
    w = SeqDedupWindow(leg="inbound")
    for s in seqs:
        w.accept(s)
    ack_after_first = w.cumulative_ack()
    for s in seqs:
        assert w.accept(s) is False  # every replayed (leg, seq) is a dup
    assert w.cumulative_ack() == ack_after_first
