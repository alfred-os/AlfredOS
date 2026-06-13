"""Host -> outward lifecycle notification frames (Spec A G1 / ADR-0033) (#237)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import GoingDownNotification, ReadyNotification


def test_ready_carries_epoch() -> None:
    note = ReadyNotification(epoch="a" * 32)
    assert note.epoch == "a" * 32


def test_ready_is_frozen_and_extra_forbidden() -> None:
    note = ReadyNotification(epoch="a" * 32)
    with pytest.raises(ValidationError):
        note.epoch = "b" * 32  # frozen
    with pytest.raises(ValidationError):
        ReadyNotification(epoch="a" * 32, surprise=1)  # extra forbidden


def test_ready_rejects_empty_epoch() -> None:
    with pytest.raises(ValidationError):
        ReadyNotification(epoch="")


def test_going_down_accepts_shutdown_reason() -> None:
    assert GoingDownNotification(reason="shutdown").reason == "shutdown"


def test_going_down_rejects_unknown_reason() -> None:
    with pytest.raises(ValidationError):
        GoingDownNotification(reason="kaboom")
    # "restart" is reserved for G3 (no producer yet) — closed out of G1's vocab.
    with pytest.raises(ValidationError):
        GoingDownNotification(reason="restart")


def test_frames_round_trip_to_wire_dicts() -> None:
    """G1 DEFINES the frames for G3 to send; assert their wire shape now."""
    assert ReadyNotification(epoch="a" * 32).model_dump() == {"epoch": "a" * 32}
    assert GoingDownNotification(reason="shutdown").model_dump() == {"reason": "shutdown"}
