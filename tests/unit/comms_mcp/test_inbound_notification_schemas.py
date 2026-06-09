"""Plugin -> host notification schemas (Task 8).

The four notification models: ``InboundMessageNotification``,
``BindingRequestNotification``, ``RateLimitSignal``, ``CrashedNotification``.
Frozen, ``extra="forbid"``, aware-datetime validators where applicable.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    BindingRequestNotification,
    CrashedNotification,
    InboundMessageNotification,
    RateLimitSignal,
)


def test_inbound_message_required_fields() -> None:
    n = InboundMessageNotification(
        adapter_id="alfred_comms_test",
        platform_user_id="discord:123",
        body={"content": "hello"},
        sub_payload_refs=(),
        received_at=datetime.now(UTC),
        addressing_signal="dm",
    )
    assert n.addressing_signal == "dm"


def test_inbound_message_rejects_naive_received_at() -> None:
    with pytest.raises(ValidationError):
        InboundMessageNotification(
            adapter_id="alfred_comms_test",
            platform_user_id="discord:123",
            body={"content": "hello"},
            sub_payload_refs=(),
            received_at=datetime(2026, 6, 7, 12, 0, 0),  # naive  # noqa: DTZ001
            addressing_signal="dm",
        )


def test_inbound_message_addressing_signal_literal() -> None:
    with pytest.raises(ValidationError):
        InboundMessageNotification(
            adapter_id="alfred_comms_test",
            platform_user_id="discord:123",
            body={"content": "hello"},
            sub_payload_refs=(),
            received_at=datetime.now(UTC),
            addressing_signal="bogus",  # type: ignore[arg-type]
        )


def test_inbound_message_unknown_adapter_kind_rejected() -> None:
    with pytest.raises(ValidationError):
        InboundMessageNotification(
            adapter_id="not_a_kind",
            platform_user_id="discord:123",
            body={"content": "hello"},
            sub_payload_refs=(),
            received_at=datetime.now(UTC),
            addressing_signal="dm",
        )


def test_inbound_message_frozen_extra_forbid() -> None:
    n = InboundMessageNotification(
        adapter_id="alfred_comms_test",
        platform_user_id="discord:123",
        body={"content": "hello"},
        sub_payload_refs=(),
        received_at=datetime.now(UTC),
        addressing_signal="dm",
    )
    with pytest.raises(ValidationError):
        n.platform_user_id = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        InboundMessageNotification(
            adapter_id="alfred_comms_test",
            platform_user_id="discord:123",
            body={"content": "hello"},
            sub_payload_refs=(),
            received_at=datetime.now(UTC),
            addressing_signal="dm",
            sneaky="x",  # type: ignore[call-arg]
        )


def test_binding_request_required_fields() -> None:
    n = BindingRequestNotification(
        adapter_id="alfred_comms_test",
        platform_user_id="discord:123",
        verification_phrase="banana phone 7",
        platform_metadata={"username": "alice"},
    )
    assert n.verification_phrase == "banana phone 7"


def test_rate_limit_signal_retry_after_ge_0() -> None:
    RateLimitSignal(
        adapter_id="alfred_comms_test",
        retry_after_seconds=0,
        platform_endpoint="gateway",
    )
    with pytest.raises(ValidationError):
        RateLimitSignal(
            adapter_id="alfred_comms_test",
            retry_after_seconds=-1,
            platform_endpoint="gateway",
        )


def test_crashed_notification_required_fields() -> None:
    c = CrashedNotification(
        adapter_id="alfred_comms_test",
        error_class="ConnectionResetError",
        detail="redacted by plugin",
    )
    assert c.error_class == "ConnectionResetError"
