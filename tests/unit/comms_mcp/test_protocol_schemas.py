"""Wire-format schema round-trip + frozen-model contract (Tasks 1, 3-6, 9).

Covers the ADR-0024 eight-method request/result schemas in
``alfred.comms_mcp.protocol``. Every model is frozen + ``extra="forbid"``;
Literal-typed fields are ``Literal[...]`` not ``str``; ``idempotency_key``
is a ``UUID`` not a string.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import BaseModel, ValidationError

from alfred.comms_mcp import protocol
from alfred.security.dlp import OutboundDlp


def _scanned(text: str) -> object:
    class _StubBroker:
        def redact(self, t: str) -> str:
            return t

    def _audit(*, event: str, subject: object) -> None: ...

    return OutboundDlp(broker=_StubBroker(), audit=_audit).scan_for_outbound(text)


def test_module_imports() -> None:
    assert hasattr(protocol, "LifecycleStartRequest")
    assert hasattr(protocol, "OutboundMessageResult")
    assert hasattr(protocol, "InboundMessageNotification")
    assert hasattr(protocol, "adapter_kind")
    assert hasattr(protocol, "BODY_FIELD_BY_KIND")


def test_persona_addressing_mode_is_literal() -> None:
    # Members are exactly the four addressing modes.
    from typing import get_args

    assert set(get_args(protocol.PersonaAddressingMode)) == {
        "dm",
        "mention",
        "channel",
        "thread",
    }


# ----- Lifecycle -----------------------------------------------------------


def test_lifecycle_start_request_fields() -> None:
    req = protocol.LifecycleStartRequest(
        adapter_id="alfred_comms_test",
        credentials_ref="secret-id-123",
        policies_snapshot_hash="abc123",
    )
    assert req.adapter_id == "alfred_comms_test"


def test_lifecycle_start_request_rejects_unknown_adapter_kind() -> None:
    with pytest.raises(ValidationError):
        protocol.LifecycleStartRequest(
            adapter_id="not_a_real_kind",
            credentials_ref="x",
            policies_snapshot_hash="y",
        )


def test_lifecycle_start_request_frozen_and_extra_forbid() -> None:
    req = protocol.LifecycleStartRequest(
        adapter_id="alfred_comms_test",
        credentials_ref="x",
        policies_snapshot_hash="y",
    )
    with pytest.raises(ValidationError):
        req.adapter_id = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        protocol.LifecycleStartRequest(
            adapter_id="alfred_comms_test",
            credentials_ref="x",
            policies_snapshot_hash="y",
            extra_field="boom",  # type: ignore[call-arg]
        )


def test_lifecycle_stop_request_reason_literal() -> None:
    protocol.LifecycleStopRequest(adapter_id="alfred_comms_test", reason="operator")
    with pytest.raises(ValidationError):
        protocol.LifecycleStopRequest(adapter_id="alfred_comms_test", reason="bogus")


def test_lifecycle_stop_result_fields() -> None:
    res = protocol.LifecycleStopResult(ok=True, flushed_messages=3)
    assert res.flushed_messages == 3
    with pytest.raises(ValidationError):
        protocol.LifecycleStopResult(ok=True, flushed_messages=-1)


# ----- Health --------------------------------------------------------------


def test_adapter_health_request_minimal() -> None:
    protocol.AdapterHealthRequest(adapter_id="alfred_comms_test")


def test_health_report_accepts_none_last_inbound() -> None:
    rep = protocol.HealthReport(ok=True, last_inbound_at=None, queue_depth=0, error_count=0)
    assert rep.last_inbound_at is None


def test_health_report_rejects_naive_last_inbound() -> None:
    with pytest.raises(ValidationError):
        protocol.HealthReport(
            ok=True,
            last_inbound_at=datetime(2026, 6, 7, 12, 0, 0),  # naive  # noqa: DTZ001
            queue_depth=0,
            error_count=0,
        )


def test_health_report_negative_counts_rejected() -> None:
    with pytest.raises(ValidationError):
        protocol.HealthReport(ok=True, last_inbound_at=None, queue_depth=-1, error_count=0)
    with pytest.raises(ValidationError):
        protocol.HealthReport(ok=True, last_inbound_at=None, queue_depth=0, error_count=-1)


# ----- Outbound request ----------------------------------------------------


def test_outbound_request_idempotency_key_is_uuid() -> None:
    with pytest.raises(ValidationError):
        protocol.OutboundMessageRequest(
            adapter_id="alfred_comms_test",
            idempotency_key="not-a-uuid",  # type: ignore[arg-type]
            target_platform_id="chan:1",
            body=_scanned("hi"),  # type: ignore[arg-type]
            attachments_refs=(),
            addressing_mode="dm",
        )


def test_outbound_request_valid() -> None:
    req = protocol.OutboundMessageRequest(
        adapter_id="alfred_comms_test",
        idempotency_key=uuid4(),
        target_platform_id="chan:1",
        body=_scanned("hi"),  # type: ignore[arg-type]
        attachments_refs=(),
        addressing_mode="dm",
    )
    assert req.addressing_mode == "dm"
    assert req.body[0] == "hi"


def test_outbound_request_empty_target_rejected() -> None:
    with pytest.raises(ValidationError):
        protocol.OutboundMessageRequest(
            adapter_id="alfred_comms_test",
            idempotency_key=uuid4(),
            target_platform_id="",
            body=_scanned("hi"),  # type: ignore[arg-type]
            attachments_refs=(),
            addressing_mode="dm",
        )


def test_outbound_request_attachments_is_tuple() -> None:
    ref = protocol.ContentRef(handle_id=uuid4(), kind="attachment")
    req = protocol.OutboundMessageRequest(
        adapter_id="alfred_comms_test",
        idempotency_key=uuid4(),
        target_platform_id="chan:1",
        body=_scanned("hi"),  # type: ignore[arg-type]
        attachments_refs=(ref,),
        addressing_mode="channel",
    )
    assert isinstance(req.attachments_refs, tuple)


def test_content_ref_kind_literal() -> None:
    with pytest.raises(ValidationError):
        protocol.ContentRef(handle_id=uuid4(), kind="bogus")  # type: ignore[arg-type]


# ----- JSON round trip -----------------------------------------------------


@pytest.mark.parametrize(
    "model",
    [
        protocol.LifecycleStartRequest(
            adapter_id="alfred_comms_test",
            credentials_ref="x",
            policies_snapshot_hash="y",
        ),
        protocol.LifecycleStartResult(ok=True),
        protocol.LifecycleStopRequest(adapter_id="alfred_comms_test", reason="operator"),
        protocol.LifecycleStopResult(ok=True, flushed_messages=0),
        protocol.AdapterHealthRequest(adapter_id="alfred_comms_test"),
        protocol.HealthReport(
            ok=True, last_inbound_at=datetime.now(UTC), queue_depth=0, error_count=0
        ),
        protocol.InboundMessageNotification(
            adapter_id="alfred_comms_test",
            platform_user_id="discord:1",
            body={"content": "hi"},
            sub_payload_refs=(),
            received_at=datetime.now(UTC),
            addressing_signal="dm",
        ),
        protocol.BindingRequestNotification(
            adapter_id="alfred_comms_test",
            platform_user_id="discord:1",
            verification_phrase="banana phone 7",
            platform_metadata={"username": "alice"},
        ),
        protocol.RateLimitSignal(
            adapter_id="alfred_comms_test",
            retry_after_seconds=0,
            platform_endpoint="gateway",
        ),
        protocol.CrashedNotification(
            adapter_id="alfred_comms_test",
            error_class="ConnectionResetError",
            detail="redacted",
        ),
    ],
)
def test_model_json_roundtrip(model: BaseModel) -> None:
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model
