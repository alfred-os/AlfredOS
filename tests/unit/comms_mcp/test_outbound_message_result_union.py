"""``OutboundMessageResult`` discriminated union (Task 7, comms-008).

The union forbids field coupling: ``_OutboundDelivered`` has no
``retry_after_seconds``; ``_OutboundRetryable`` requires it;
``_OutboundTerminal`` requires ``detail_redacted`` <= 256 chars. The
discriminator routes by ``outcome``.
"""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from alfred.comms_mcp.protocol import (
    OutboundMessageResult,
    _OutboundDelivered,
    _OutboundRetryable,
    _OutboundTerminal,
)


def test_delivered_has_no_retry_after() -> None:
    delivered = _OutboundDelivered(outcome="delivered", platform_message_id="m1")
    with pytest.raises(AttributeError):
        delivered.retry_after_seconds  # type: ignore[attr-defined]  # noqa: B018


def test_retryable_requires_retry_after() -> None:
    with pytest.raises(ValidationError):
        _OutboundRetryable(outcome="retryable_failure", error_class="rate_limited")
    ok = _OutboundRetryable(
        outcome="retryable_failure", retry_after_seconds=30, error_class="rate_limited"
    )
    assert ok.retry_after_seconds == 30


def test_terminal_requires_detail_redacted_le_256() -> None:
    _OutboundTerminal(
        outcome="terminal_failure", error_class="forbidden", detail_redacted="x" * 256
    )
    with pytest.raises(ValidationError):
        _OutboundTerminal(
            outcome="terminal_failure",
            error_class="forbidden",
            detail_redacted="x" * 257,
        )


def test_discriminator_routes_by_outcome() -> None:
    adapter: TypeAdapter[object] = TypeAdapter(OutboundMessageResult)
    result = adapter.validate_python({"outcome": "delivered", "platform_message_id": "m1"})
    assert isinstance(result, _OutboundDelivered)
    result = adapter.validate_python(
        {"outcome": "retryable_failure", "retry_after_seconds": 5, "error_class": "rl"}
    )
    assert isinstance(result, _OutboundRetryable)
    result = adapter.validate_python(
        {"outcome": "terminal_failure", "error_class": "forbidden", "detail_redacted": "x"}
    )
    assert isinstance(result, _OutboundTerminal)


def test_discriminator_rejects_unknown_outcome() -> None:
    adapter: TypeAdapter[object] = TypeAdapter(OutboundMessageResult)
    with pytest.raises(ValidationError):
        adapter.validate_python({"outcome": "weird", "platform_message_id": "m1"})


def test_all_variants_frozen() -> None:
    d = _OutboundDelivered(outcome="delivered", platform_message_id="m1")
    with pytest.raises(ValidationError):
        d.platform_message_id = "m2"  # type: ignore[misc]
