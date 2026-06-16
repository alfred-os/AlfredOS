r"""``CommsSeqCodec`` — out-of-band seq/ack/dedup framing for the comms wire.

Spec A G2 / ADR-0032 (#237). A PURE codec that wraps the opaque ADR-0025
line-delimited comms payload (``json.dumps(frame) + "\n"``) with a small
out-of-band ASCII header carrying a per-direction monotonic ``seq``, a
cumulative ``ack``, and a payload byte-length. The header is CARRIER metadata:
``seq``/``ack``/``n`` are computed from the transport's own counters and the
payload's BYTE LENGTH — never from the payload's CONTENT (spec §6). The codec
NEVER ``json.loads`` the payload, so the relay (G3) forwards the body verbatim,
the wire stays payload-blind (T1 carrier), and the JSON-RPC ``id`` the runner
correlates on survives end-to-end (it lives inside the opaque payload, which the
codec treats as an untouchable byte run).

**Wire shape** (one newline-terminated unit when seq/ack is negotiated)::

    A1 s=<seq> a=<ack> n=<payload_len> |<opaque-payload-bytes>\n

``A1`` is the magic (``A`` = AlfredSeqAck) + wire version (``1``). A line WITHOUT
the magic is a PLAIN ADR-0025 frame — :func:`decode_seq_frame` recognises it and
returns an un-sequenced :class:`SeqFrame` (the version-gate default-OFF fallback),
so a mixed / one-direction-only wire still reads.

**Version-gated, default-OFF.** The negotiation lives in the ``lifecycle.start``
handshake (``alfred.plugins.comms_runner``); this module only knows how to encode
a frame WITH the header and decode either form. The header is emitted only when
BOTH peers advertised support.

**Trust posture.** Fail-loud on a malformed header (over-bound unit, non-integer
``seq``/``ack``, a ``n=`` that does not match the payload run) via
:class:`alfred.plugins.comms_wire.CommsProtocolError`, carrying NO raw payload
bytes on the exception (spec §5.6). ``_MAX_COMMS_LINE_BYTES`` still bounds the
WHOLE unit (header + payload + ``\n``) so the out-of-band header cannot smuggle
past the per-frame DoS bound. On a NEGOTIATED wire the header costs budget, so the
effective payload ceiling is ``max_unit_bytes - _MAX_HEADER_BYTES`` (Option A).

**Pure.** No I/O, no clock, no global state, no async — encode/decode are
functions and :class:`SeqDedupWindow` is an explicit per-leg state machine. This
is what makes the codec a hypothesis-property-testable unit (spec §7/§9).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from alfred.plugins.comms_wire import (
    _MAX_COMMS_LINE_BYTES,
    CommsProtocolError,
)

#: Magic + wire version. ``A`` = AlfredSeqAck; ``1`` = wire version 1. A unit that
#: does not start with this is a plain ADR-0025 frame (default-OFF fallback).
SEQ_VERSION: Final[str] = "1"
SEQ_MAGIC: Final[bytes] = b"A" + SEQ_VERSION.encode()

#: Reserved TOP-LEVEL frame key under which the seq-enabled socket carrier folds
#: the decoded wire seq onto the JSON-RPC frame ``read_frame`` returns (Spec A
#: G4b-2a-pre / ADR-0032). The runner's pump lifts it and threads it as an
#: explicit per-frame ``wire_seq`` argument into ``model_validate`` so the seq
#: TRAVELS WITH ITS OWN FRAME (never a shared per-transport slot — F1, racy). It
#: is a FRAME key (alongside ``method``/``params``), NOT a ``params`` key, so it
#: never collides with a wire-model field and ``extra="forbid"`` never sees it.
#: The leading ``_`` keeps it visually distinct from JSON-RPC's own keys; a plain
#: / stdio frame (no seq) never carries it.
WIRE_SEQ_FRAME_KEY: Final[str] = "_wire_seq"

# The single header/payload delimiter. It cannot occur in the fixed
# ``A1 s= a= n=`` header grammar, so the FIRST ``|`` unambiguously ends the
# header and begins the opaque payload run.
_DELIM: Final[bytes] = b" |"

# Worst-case NON-PAYLOAD width (Option A — architect F1) — i.e. the full
# reservation a payload must leave room for. The fixed grammar is
# ``A1 s=<seq> a=<ack> n=<len> |<payload>\n`` — the literal skeleton (incl. the
# ``|`` delimiter), three base-10 counters, and the trailing newline. Each counter
# is at most as wide as the decimal expansion of ``_MAX_COMMS_LINE_BYTES`` (the
# payload-len field is itself bounded by it, and ``seq``/``ack`` are operationally
# never wider in a single boot's lifetime). On a NEGOTIATED wire this overhead
# costs budget, so the EFFECTIVE payload ceiling is ``max_unit_bytes -
# _MAX_HEADER_BYTES`` — a payload at or under that is GUARANTEED to encode for any
# counter widths. The runtime bound is still enforced on the OUTER unit in
# :func:`encode_seq_frame`; ``_MAX_HEADER_BYTES`` is the DOCUMENTED reservation a
# caller (and the G3 relay) sizes payloads against. The trailing ``\n`` is folded
# in so the reservation accounts for EVERYTHING that is not payload.
_MAX_DECIMAL_WIDTH: Final[int] = len(str(_MAX_COMMS_LINE_BYTES))
_HEADER_SKELETON: Final[bytes] = b"A1 s= a= n= |"  # literal chars + the delimiter
_MAX_HEADER_BYTES: Final[int] = len(_HEADER_SKELETON) + 3 * _MAX_DECIMAL_WIDTH + 1


@dataclass(frozen=True, slots=True)
class SeqFrame:
    """A decoded wire unit: header seq/ack (or ``None`` for a plain frame) + payload.

    ``payload`` is the opaque ADR-0025 frame bytes, byte-for-byte — the codec
    never decodes it. ``seq``/``ack`` are ``None`` when the unit was a plain
    (non-negotiated) ADR-0025 line.
    """

    seq: int | None
    ack: int | None
    payload: bytes


def encode_seq_frame(
    payload: bytes,
    *,
    seq: int,
    ack: int,
    max_unit_bytes: int = _MAX_COMMS_LINE_BYTES,
) -> bytes:
    """Wrap ``payload`` (an ADR-0025 frame line, no trailing newline) with the header.

    Returns the newline-terminated wire unit. ``seq``/``ack`` must be
    non-negative (a negative counter is a programming error, raised loudly). The
    whole unit (header + payload + newline) is bounded by ``max_unit_bytes`` so
    the out-of-band header cannot exceed the per-frame DoS bound.
    """
    if seq < 0 or ack < 0:
        raise ValueError(f"seq/ack must be non-negative: seq={seq} ack={ack}")
    if len(str(seq)) > _MAX_DECIMAL_WIDTH or len(str(ack)) > _MAX_DECIMAL_WIDTH:
        # ``_MAX_HEADER_BYTES`` reserves room for counters up to
        # ``_MAX_DECIMAL_WIDTH`` digits; a wider counter would silently overrun
        # that reservation, breaking the ``cap - _MAX_HEADER_BYTES`` guarantee.
        raise ValueError(
            "seq/ack exceed supported wire counter width; "
            "would violate _MAX_HEADER_BYTES reservation"
        )
    header = b"%s s=%d a=%d n=%d" % (SEQ_MAGIC, seq, ack, len(payload))
    unit = header + _DELIM + payload + b"\n"
    if len(unit) > max_unit_bytes:
        raise CommsProtocolError("comms seq frame exceeds the per-frame byte bound")
    return unit


def decode_seq_frame(
    raw: bytes,
    *,
    max_unit_bytes: int = _MAX_COMMS_LINE_BYTES,
) -> SeqFrame:
    """Decode one wire unit; magic-gated, with a plain-ADR-0025 fallback.

    A unit beginning with :data:`SEQ_MAGIC` is parsed for ``seq``/``ack``/``n``
    and its payload run validated against ``n``. A unit WITHOUT the magic is a
    plain ADR-0025 frame (default-OFF fallback): its line (sans trailing newline)
    is returned as ``SeqFrame(seq=None, ack=None, payload=...)``. Raises
    :class:`CommsProtocolError` on an over-bound unit or a malformed header,
    carrying NO raw payload bytes.

    Decode is direction-AGNOSTIC: it inspects the magic on the bytes in front of
    it, so a seq-enabled reader still reads a plain line from an un-upgraded peer
    (and a plain reader reads either form). The negotiation gate flag is
    per-transport and lives in the transport, not here.
    """
    if len(raw) > max_unit_bytes:
        raise CommsProtocolError("comms seq frame exceeds the per-frame byte bound")
    line = raw[:-1] if raw.endswith(b"\n") else raw
    if not line.startswith(SEQ_MAGIC):
        # Plain ADR-0025 frame — the negotiation default-OFF fallback.
        return SeqFrame(seq=None, ack=None, payload=line)
    delim_at = line.find(_DELIM)
    if delim_at == -1:
        raise CommsProtocolError("comms seq frame header has no payload delimiter")
    header = line[:delim_at]
    payload = line[delim_at + len(_DELIM) :]
    try:
        # ``line`` already passed ``startswith(SEQ_MAGIC)`` above, so the first
        # space-split token IS the magic — no second magic check is needed (it
        # would be unreachable defensive code). A wrong token COUNT (too few / too
        # many spaces) is caught by the tuple-unpack raising ``ValueError``.
        _magic, s_tok, a_tok, n_tok = header.split(b" ")
        seq = _parse_kv(s_tok, b"s=")
        ack = _parse_kv(a_tok, b"a=")
        declared_len = _parse_kv(n_tok, b"n=")
    except ValueError as exc:
        raise CommsProtocolError("comms seq frame header is malformed") from exc
    if declared_len != len(payload):
        raise CommsProtocolError("comms seq frame declared length mismatch")
    return SeqFrame(seq=seq, ack=ack, payload=payload)


def _parse_kv(token: bytes, prefix: bytes) -> int:
    """Parse ``<prefix><canonical-base-10-digits>``; raise ``ValueError`` otherwise.

    ``int(b"...")`` accepts non-canonical forms — an explicit ``+`` sign, PEP-515
    grouping underscores (``1_0``), surrounding whitespace, and (for ``-``) negative
    values. This is a CROSS-IMPLEMENTATION wire format, so a counter must be PURE
    base-10 digits: reject any non-digit body via ``bytes.isdigit()`` (which is
    ``False`` for an empty body, a sign, an underscore, or spaces) before ``int()``.
    The redundant ``< 0`` re-check below is now unreachable for a digit-only body
    but kept as a defensive belt-and-braces invariant.
    """
    if not token.startswith(prefix):
        raise ValueError(f"expected {prefix!r} prefix")
    body = token[len(prefix) :]
    if not body.isdigit():
        raise ValueError(f"non-canonical counter token: {body!r}")
    value = int(body)
    if value < 0:  # pragma: no cover - unreachable for a digit-only body; defensive
        raise ValueError("negative counter")
    return value


class SeqDedupWindow:
    """Per-leg accept-once + cumulative-ack state machine (Spec A §4).

    Constructed PER DIRECTION (``leg`` = ``"inbound"`` / ``"outbound"``), so the
    dedup key is effectively ``seq`` within this leg — matching the spec's
    "key = ``(leg, seq)`` ONLY — never payload-derived". :meth:`accept` returns
    ``True`` the FIRST time a ``seq`` is seen and ``False`` on every re-sighting
    (idempotent). :meth:`cumulative_ack` returns the highest CONTIGUOUS seq seen
    (the top of the unbroken ``0..k`` run) — NOT merely the max — so a gap stalls
    the ack until it is filled.

    **No ack emission here.** This computes the ack VALUE; the choice of ack
    SOURCE and COALESCING (piggyback + bounded timer) are sender/relay behaviours
    owned by G3. G2 proves the value semantics; it does not fire acks, and the
    transport carries an ``a=0`` placeholder rather than reading this. The G3
    relay wires :meth:`cumulative_ack` as the ack source.

    Pure: explicit state, no I/O, no clock. The seen-set grows unbounded — that is
    correct for G2 (a pure unit under test); the bounded retention the seen-set
    needs in production is a G4 (ReplayBuffer) concern, stated in ADR-0032's scope
    note, not built here.
    """

    def __init__(self, *, leg: str) -> None:
        self._leg = leg
        self._seen: set[int] = set()
        self._contiguous_high: int = -1

    @property
    def leg(self) -> str:
        return self._leg

    def accept(self, seq: int) -> bool:
        """Record ``seq``; return ``True`` if NEW, ``False`` if a re-seen dup."""
        if seq < 0:
            raise ValueError(f"seq must be non-negative: {seq}")
        if seq in self._seen:
            return False
        self._seen.add(seq)
        # Advance the contiguous high-water as far as the unbroken run reaches.
        while (self._contiguous_high + 1) in self._seen:
            self._contiguous_high += 1
        return True

    def cumulative_ack(self) -> int:
        """Highest CONTIGUOUS seq seen (top of the unbroken 0.. run); -1 if none."""
        return self._contiguous_high


__all__ = [
    "SEQ_MAGIC",
    "SEQ_VERSION",
    "WIRE_SEQ_FRAME_KEY",
    "_MAX_HEADER_BYTES",
    "SeqDedupWindow",
    "SeqFrame",
    "decode_seq_frame",
    "encode_seq_frame",
]
