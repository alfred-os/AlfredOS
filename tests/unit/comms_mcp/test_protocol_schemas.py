"""Wire-format schema round-trip + frozen-model contract (Tasks 1, 3-6, 9).

Covers the ADR-0024 eight-method request/result schemas in
``alfred.comms_mcp.protocol``. Every model is frozen + ``extra="forbid"``;
Literal-typed fields are ``Literal[...]`` not ``str``; ``idempotency_key``
is a ``UUID`` not a string.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import get_args
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


def test_inbound_notification_rejects_extra_fields() -> None:
    """H3 / sec-001: ``extra="forbid"`` IS the forged-canonical-id defence.

    The real defence against an adversary planting a forged
    ``platform_metadata.canonical_user_id`` on the wire is that
    ``InboundMessageNotification`` forbids unknown fields — the model never
    admits ``platform_metadata`` at all. The integration harness used to strip
    the forged field with ``params.pop`` BEFORE ``model_validate``, so the
    rejection was never exercised. This test drives the rejection directly: an
    otherwise-valid payload carrying the forged field raises ``ValidationError``.
    """
    valid = {
        "adapter_id": "alfred_comms_test",
        "inbound_id": "frame-1",
        "platform_user_id": "discord:victim",
        "body": {"content": "attack"},
        "sub_payload_refs": (),
        "received_at": datetime.now(UTC),
        "addressing_signal": "dm",
    }
    # Sanity: the valid payload alone constructs.
    protocol.InboundMessageNotification.model_validate(valid)
    # The forged field is refused — it never reaches the host as a model field.
    with pytest.raises(ValidationError):
        protocol.InboundMessageNotification.model_validate(
            {**valid, "platform_metadata": {"canonical_user_id": "forged"}}
        )


def test_inbound_notification_rejects_oversized_platform_user_id() -> None:
    """L1: a pre-resolution platform identifier is bounded (max_length=512)."""
    valid = {
        "adapter_id": "alfred_comms_test",
        "inbound_id": "frame-1",
        "platform_user_id": "x" * 513,
        "body": {"content": "hi"},
        "sub_payload_refs": (),
        "received_at": datetime.now(UTC),
        "addressing_signal": "dm",
    }
    with pytest.raises(ValidationError):
        protocol.InboundMessageNotification.model_validate(valid)
    # The boundary value (exactly 512) is accepted.
    protocol.InboundMessageNotification.model_validate({**valid, "platform_user_id": "x" * 512})


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


def test_lifecycle_start_request_credentials_optional() -> None:
    """ADR-0035: ``credentials_ref``/``policies_snapshot_hash`` are optional.

    No producer sends them (the host runner handshake emits only
    ``{adapter_id, seq_ack, epoch?}``), and the sole strict consumer — the TUI
    co-host — reads only ``adapter_id`` and discards the rest. This is the
    exact shape the runner + gateway actually put on the wire.
    """
    req = protocol.LifecycleStartRequest.model_validate(
        {"adapter_id": "tui", "seq_ack": {"version": "1"}}
    )
    assert req.adapter_id == "tui"
    assert req.credentials_ref is None
    assert req.policies_snapshot_hash is None
    assert req.seq_ack is not None and req.seq_ack.version == "1"


def test_lifecycle_start_request_credentials_back_compat() -> None:
    """A request carrying both fields still validates and round-trips them."""
    req = protocol.LifecycleStartRequest.model_validate(
        {
            "adapter_id": "alfred_comms_test",
            "credentials_ref": "secret-id-123",
            "policies_snapshot_hash": "abc123",
        }
    )
    assert req.credentials_ref == "secret-id-123"
    assert req.policies_snapshot_hash == "abc123"


def test_lifecycle_start_request_still_forbids_extra_field() -> None:
    """Relaxing the credential fields does not relax ``extra="forbid"``."""
    with pytest.raises(ValidationError):
        protocol.LifecycleStartRequest.model_validate({"adapter_id": "tui", "bogus": 1})


def test_lifecycle_start_request_credentials_optional_still_validates_adapter() -> None:
    """``adapter_id`` stays required + validated against the ``adapter_kind`` set."""
    with pytest.raises(ValidationError):
        protocol.LifecycleStartRequest.model_validate({"adapter_id": "not_a_real_kind"})
    with pytest.raises(ValidationError):
        protocol.LifecycleStartRequest.model_validate({"seq_ack": {"version": "1"}})


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
        protocol.LifecycleStartResult(ok=True, plugin_version="0.1.0"),
        protocol.LifecycleStopRequest(adapter_id="alfred_comms_test", reason="operator"),
        protocol.LifecycleStopResult(ok=True, flushed_messages=0),
        protocol.AdapterHealthRequest(adapter_id="alfred_comms_test"),
        protocol.HealthReport(
            ok=True, last_inbound_at=datetime.now(UTC), queue_depth=0, error_count=0
        ),
        protocol.InboundMessageNotification(
            adapter_id="alfred_comms_test",
            inbound_id="frame-1",
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
        protocol.TurnFailedNotification(stage="refused"),
        protocol.TurnFailedNotification(stage="budget_exhausted"),
        protocol.TurnFailedNotification(stage="internal_error"),
    ],
)
def test_model_json_roundtrip(model: BaseModel) -> None:
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model


# ----- Turn-state control frames (#593, Task 9) -----------------------------


def test_turn_failed_notification_rejects_extra_fields() -> None:
    """Anti-smuggling guard: an unknown ``detail`` field is refused, not silently kept.

    This is the executable form of the standing objection recorded on
    :class:`protocol.TurnFailedNotification`'s docstring — the frame has NO
    channel for a core-supplied / T3-derived string, and ``extra="forbid"`` is
    what makes an attempt to smuggle one a loud failure instead of a silent pass.
    """
    protocol.TurnFailedNotification.model_validate({"stage": "refused"})
    with pytest.raises(ValidationError):
        protocol.TurnFailedNotification.model_validate({"stage": "refused", "detail": "boom"})


def test_turn_failure_stage_is_a_closed_literal() -> None:
    assert set(get_args(protocol.TurnFailureStage)) == {
        "refused",
        "budget_exhausted",
        "internal_error",
    }


def test_turn_failed_notification_frozen() -> None:
    """``frozen=True`` (inherited from ``_WireModel``) — the other half of the guard."""
    notification = protocol.TurnFailedNotification(stage="refused")
    with pytest.raises(ValidationError):
        notification.stage = "internal_error"


def test_turn_failed_notification_has_no_str_fields() -> None:
    """No field on the frame is a bare ``str`` — the "no free text on the wire" rule.

    Walks ``model_fields`` rather than special-casing ``stage`` by name, so the
    guard still means something if the model ever grows a second field: a future
    ``str`` addition trips this test instead of silently reintroducing a
    smuggling channel.
    """
    fields = protocol.TurnFailedNotification.model_fields
    assert fields, "expected at least one field to make this a real check"
    for name, field in fields.items():
        assert field.annotation is not str, f"{name} is a bare str field"


def test_turn_state_client_kinds_subset_of_adapter_kind() -> None:
    """Drift guard: every listed client kind must be a real, known adapter kind."""
    assert protocol.adapter_kind >= protocol.TURN_STATE_CLIENT_KINDS


def test_turn_failed_method_is_not_gateway_consumed() -> None:
    """``turn.failed`` must stay OUTSIDE the gateway's four consumed method names.

    ``GatewayCoreLink._route_unit`` consumes exactly these four constants
    (payload-blind for everything else); if ``TURN_FAILED`` ever collided with
    one, the gateway would silently swallow the client's failure frame instead
    of relaying it — the opposite of what #593 needs. ``CORE_ADAPTER_SPAWN_GRANT``
    lives in ``adapter_credential_protocol``, not this module, but is still one
    of the four names the router special-cases.
    """
    from alfred.comms_mcp.adapter_credential_protocol import CORE_ADAPTER_SPAWN_GRANT

    gateway_consumed = {
        protocol.DAEMON_COMMS_ACK,
        protocol.DAEMON_LIFECYCLE_READY,
        protocol.DAEMON_LIFECYCLE_GOING_DOWN,
        CORE_ADAPTER_SPAWN_GRANT,
    }
    assert protocol.TURN_FAILED not in gateway_consumed
    assert not protocol.TURN_FAILED.startswith(protocol.GATEWAY_ADAPTER_STATUS_PREFIX)
