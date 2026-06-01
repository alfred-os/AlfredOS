"""Spec §9 (Fork 8) — CommsAdapterMCP Protocol structural tests.

Validates the four-method MCP wire contract: lifecycle.start,
lifecycle.stop, inbound.message, adapter.health.

The Protocol is structural (typing.Protocol), so any class implementing
all four methods satisfies it — no inheritance required.

Depends on: PR-S3-3a (StdioTransport, AlfredPluginSession) for wiring;
this unit test validates the Protocol shape only.
"""

from __future__ import annotations

import pytest
from alfred.comms.mcp_protocol import (
    AdapterHealthResponse,
    CommsAdapterMCP,
    InboundMessage,
)
from pydantic import ValidationError


class _EchoAdapter:
    """Minimal concrete implementation of CommsAdapterMCP for testing."""

    async def lifecycle_start(self) -> None:
        pass

    async def lifecycle_stop(self) -> None:
        pass

    async def inbound_message(self, msg: InboundMessage) -> None:
        pass

    async def adapter_health(self) -> AdapterHealthResponse:
        return AdapterHealthResponse(status="ok", detail="")


def test_echo_adapter_satisfies_protocol() -> None:
    adapter = _EchoAdapter()
    assert isinstance(adapter, CommsAdapterMCP)


def test_inbound_message_valid_payload() -> None:
    # comms-001: platform field is now required
    msg = InboundMessage(
        platform="discord",
        platform_user_id="12345",
        content="hello",
        language="en-US",
    )
    assert msg.platform == "discord"
    assert msg.content == "hello"
    assert msg.language == "en-US"


def test_inbound_message_rejects_missing_content() -> None:
    with pytest.raises(ValidationError):
        InboundMessage(platform="discord", platform_user_id="12345", language="en")  # type: ignore[call-arg]


def test_inbound_message_rejects_missing_platform() -> None:
    """comms-001: platform is required; omitting it must raise ValidationError."""
    with pytest.raises(ValidationError):
        InboundMessage(platform_user_id="12345", content="hi", language="en")  # type: ignore[call-arg]


def test_adapter_health_response_status_values() -> None:
    ok = AdapterHealthResponse(status="ok", detail="all good")
    assert ok.status == "ok"
    degraded = AdapterHealthResponse(status="degraded", detail="reconnecting")
    assert degraded.status == "degraded"


def test_adapter_health_rejects_invalid_status() -> None:
    with pytest.raises(ValidationError):
        AdapterHealthResponse(status="unknown", detail="")  # type: ignore[arg-type]


def test_protocol_is_runtime_checkable() -> None:
    """CommsAdapterMCP must be @runtime_checkable for isinstance checks."""

    # The class-level check: a non-adapter should NOT satisfy it
    class _NotAnAdapter:
        pass

    assert not isinstance(_NotAnAdapter(), CommsAdapterMCP)
