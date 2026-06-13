"""Seq/ack handshake capability field (Spec A G2 / ADR-0032) (#237)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    LifecycleStartRequest,
    LifecycleStartResult,
    SeqAckCapability,
)


def test_capability_pins_version_one() -> None:
    assert SeqAckCapability(version="1").version == "1"
    with pytest.raises(ValidationError):
        SeqAckCapability(version="2")  # type: ignore[arg-type]  # closed vocab — only "1"


def test_capability_is_frozen() -> None:
    cap = SeqAckCapability(version="1")
    with pytest.raises(ValidationError):
        cap.version = "1"  # frozen model raises on assignment


def test_capability_forbids_extra() -> None:
    with pytest.raises(ValidationError):
        SeqAckCapability(version="1", extra="x")  # type: ignore[call-arg]


def test_start_request_seq_ack_defaults_none() -> None:
    """Absent capability == default-OFF; the field is optional."""
    req = LifecycleStartRequest(
        adapter_id="alfred_comms_test",
        credentials_ref="ref",
        policies_snapshot_hash="h",
    )
    assert req.seq_ack is None


def test_start_request_can_advertise_capability() -> None:
    req = LifecycleStartRequest(
        adapter_id="alfred_comms_test",
        credentials_ref="ref",
        policies_snapshot_hash="h",
        seq_ack=SeqAckCapability(version="1"),
    )
    assert req.seq_ack is not None and req.seq_ack.version == "1"


def test_start_result_can_echo_capability() -> None:
    res = LifecycleStartResult(
        ok=True, plugin_version="0.1.0", seq_ack=SeqAckCapability(version="1")
    )
    assert res.seq_ack is not None and res.seq_ack.version == "1"


def test_start_result_seq_ack_defaults_none() -> None:
    """A conformant pre-G2 plugin result (no seq_ack) still validates as default-OFF."""
    res = LifecycleStartResult(ok=True, plugin_version="0.1.0")
    assert res.seq_ack is None
