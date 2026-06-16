"""InboundMessageNotification.wire_seq — optional, default None, non-negative.

Spec A G4b-2a-pre / ADR-0032 (#237). ``wire_seq`` is the carrier out-of-band
wire seq (the gateway's per-connection client->core send-seq) the host reads off
its own socket leg to advance the durable-intake ack tracker. It is OPTIONAL and
defaults ``None`` so the stdio adapters (Discord, reference plugin — plain
ADR-0025, no seq) and every existing producer are byte-for-byte unchanged. A
NEGATIVE seq is REJECTED at the model so a forged negative never reaches
``BoundedSeqAckTracker.observe`` (which would raise ValueError mid-pipeline).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import InboundMessageNotification


def _kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "adapter_id": "tui",
        "inbound_id": "frame-1",
        "platform_user_id": "u1",
        "body": {"content": "hi"},
        "sub_payload_refs": (),
        "received_at": datetime.now(UTC),
        "addressing_signal": "dm",
    }
    base.update(overrides)
    return base


def test_wire_seq_defaults_none_when_absent() -> None:
    # Back-compat: a notification WITHOUT wire_seq still parses (stdio/Discord
    # producers never carry it) and reads ``None``.
    note = InboundMessageNotification(**_kwargs())
    assert note.wire_seq is None


def test_wire_seq_accepts_a_non_negative_int() -> None:
    note = InboundMessageNotification(**_kwargs(wire_seq=5))
    assert note.wire_seq == 5


def test_wire_seq_accepts_zero() -> None:
    # Zero is the first valid seq on a fresh connection — it MUST advance the ack.
    note = InboundMessageNotification(**_kwargs(wire_seq=0))
    assert note.wire_seq == 0


def test_wire_seq_negative_is_rejected() -> None:
    # A forged negative seq is refused at the wire so it never reaches
    # ``observe`` (which would ValueError mid-pipeline — F2.2).
    with pytest.raises(ValidationError):
        InboundMessageNotification(**_kwargs(wire_seq=-1))


def test_wire_seq_round_trips_json() -> None:
    note = InboundMessageNotification(**_kwargs(wire_seq=7))
    dumped = note.model_dump(mode="json")
    assert dumped["wire_seq"] == 7
    reparsed = InboundMessageNotification.model_validate(dumped)
    assert reparsed.wire_seq == 7
