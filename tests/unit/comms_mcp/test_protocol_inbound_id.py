"""InboundMessageNotification requires a bounded, non-empty wire inbound_id."""

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


def test_accepts_a_valid_inbound_id() -> None:
    note = InboundMessageNotification(**_kwargs())
    assert note.inbound_id == "frame-1"


def test_missing_inbound_id_is_rejected() -> None:
    kwargs = _kwargs()
    del kwargs["inbound_id"]
    with pytest.raises(ValidationError):
        InboundMessageNotification(**kwargs)


def test_empty_inbound_id_is_rejected() -> None:
    with pytest.raises(ValidationError):
        InboundMessageNotification(**_kwargs(inbound_id=""))


def test_max_length_inbound_id_is_accepted() -> None:
    # The boundary is inclusive: a 255-char id matches the
    # ``inbound_idempotency.inbound_id`` VARCHAR(255) column exactly.
    note = InboundMessageNotification(**_kwargs(inbound_id="x" * 255))
    assert len(note.inbound_id) == 255


def test_overlong_inbound_id_is_rejected() -> None:
    # A 256-char id overflows the VARCHAR(255) column; the shape gate refuses it
    # at the wire so it can never reach the ledger key (DB column width + a
    # ledger-key DoS vector via unbounded keys).
    with pytest.raises(ValidationError):
        InboundMessageNotification(**_kwargs(inbound_id="x" * 256))
