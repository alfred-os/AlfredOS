"""Deterministic, collision-resistant egress-id + body-hash for the ledger (Spec C §5).

A side-effecting tool egress (web POST, email) crosses a money/side-effect
boundary, so a re-run of a turn — a core restart mid-turn, a Spec A replay — must
not double-fire it. The dedup key is the ``egress-id``: a deterministic function of
the committed per-turn anchor ``(adapter_id, inbound_id, session_id)`` and the
logical call position (``call_index``) — NEVER completion-order, which mis-keys a
concurrent fan-out.

The distinctness rides an **unambiguous length-prefixed encoding** (injective over
the field tuple): each field is emitted as its UTF-8 byte length (8-byte big-endian)
followed by its bytes, so no separator can be forged across a field boundary —
``(inbound=1, session=23)`` and ``(inbound=12, session=3)`` encode distinctly. The id
is the sha256 hexdigest of that encoding (64 lowercase hex chars — the ledger PK
width); sha256 is collision-resistant, so distinct field tuples yield distinct ids
except under a sha256 collision (not a threat we model).
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict

from alfred.errors import AlfredError
from alfred.i18n import t


class TurnEgressContext(BaseModel):
    """The committed per-turn anchor for egress-id stamping.

    ``(adapter_id, inbound_id)`` is the G0 committed inbound identity; ``session_id``
    scopes the turn. Constructed turn-side (the synthetic driver in G7-2, the
    tool-loop in #339) — never synthesized from a correlation id.
    """

    adapter_id: str
    inbound_id: str
    session_id: str
    model_config = ConfigDict(frozen=True, extra="forbid")


def _length_prefixed(*fields: str) -> bytes:
    """Encode ``fields`` so the field boundaries are unforgeable.

    Each field becomes ``len(utf8_bytes)`` (8-byte big-endian) + the bytes. Because
    every field self-describes its length, no concatenation of one field's tail with
    the next's head can reproduce a different field tuple — **the encoding is injective**
    over the field sequence. sha256 of that encoding is then *collision-resistant* (not
    itself injective — by pigeonhole, 256-bit digests cannot be), so distinct field
    tuples yield distinct ids except under a sha256 collision (not a threat we model).
    """
    out = bytearray()
    for field in fields:
        raw = field.encode("utf-8")
        out += len(raw).to_bytes(8, "big") + raw
    return bytes(out)


def compute_egress_id(ctx: TurnEgressContext, *, call_index: int) -> str:
    """The deterministic dedup key for one logical egress call (collision-resistant)."""
    # ``format(call_index, "d")`` canonicalizes the index as a decimal int: a bool
    # (``True``) renders as ``"1"`` so it cannot smuggle a divergent encoding for the
    # same logical slot, and a non-int (float/str) raises here rather than silently
    # producing a distinct id. ``str()`` would render ``True`` as ``"True"`` — a footgun.
    encoded = _length_prefixed(
        ctx.adapter_id, ctx.inbound_id, ctx.session_id, format(call_index, "d")
    )
    return hashlib.sha256(encoded).hexdigest()


def compute_body_hash(redacted_body: str) -> str:
    """sha256 hexdigest of the UTF-8 redacted body (the ledger integrity check)."""
    return hashlib.sha256(redacted_body.encode("utf-8")).hexdigest()


def compute_request_descriptor(*, method: str, url: str, schema_id: str) -> str:
    """sha256 hex over the length-prefixed (method, url, schema_id) — the per-call
    request identity folded into the ledger integrity hash so a divergent URL/schema
    replayed at the same egress-id fires EgressIdIntegrityError (Spec C §5 / G7-2.5 C6).

    Reuses ``_length_prefixed`` for injective field boundaries — the same
    collision-resistance guarantee as ``compute_egress_id``.  The result is a
    fixed-width 64-char hex digest so prepending it to ``redacted_text`` before
    ``compute_body_hash`` cannot introduce a separator-collision (fixed-width prefix).
    """
    return hashlib.sha256(_length_prefixed(method, url, schema_id)).hexdigest()


class EgressIdIntegrityError(AlfredError):
    """A duplicate egress-id arrived with a different redacted-body hash.

    Same logical-call position, different body → a non-deterministic re-run. Fails
    loud (HARD rule #7). The message carries only the (already-public) egress-id —
    NO body or hash value, so the mismatch surface is not a body-content oracle.
    """

    reason = "egress_id_integrity_mismatch"

    def __init__(self, *, egress_id: str) -> None:
        self.egress_id = egress_id
        super().__init__(t("egress.id_integrity_mismatch", egress_id=egress_id))


__all__ = [
    "EgressIdIntegrityError",
    "TurnEgressContext",
    "compute_body_hash",
    "compute_egress_id",
    "compute_request_descriptor",
]
