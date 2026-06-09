"""Dispatch arms route each notification to its handler (Tasks 36-37).

``_on_post_handshake_method`` validates the params against the matching wire
schema and awaits the corresponding handler exactly once.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from alfred.comms_mcp.protocol import (
    BindingRequestNotification,
    CrashedNotification,
    InboundMessageNotification,
    RateLimitSignal,
)

from ._session_builders import INBOUND_PARAMS, build_session


@pytest.mark.asyncio
async def test_inbound_message_routed_to_inbound_handler() -> None:
    handler = AsyncMock()
    session = build_session(inbound_handler=handler)
    await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    handler.process.assert_awaited_once()
    call_arg = handler.process.await_args.args[0]
    assert isinstance(call_arg, InboundMessageNotification)
    assert call_arg.platform_user_id == "discord:123"


@pytest.mark.asyncio
async def test_binding_request_routed_to_binding_handler() -> None:
    handler = AsyncMock()
    session = build_session(binding_handler=handler)
    params: dict[str, Any] = {
        "adapter_id": "alfred_comms_test",
        "platform_user_id": "discord:123",
        "verification_phrase": "blue-otter-42",
        "platform_metadata": {},
    }
    await session._on_post_handshake_method(method="adapter.binding_request", params=params)
    handler.process.assert_awaited_once()
    assert isinstance(handler.process.await_args.args[0], BindingRequestNotification)


@pytest.mark.asyncio
async def test_rate_limit_signal_routed_to_rate_limit_handler() -> None:
    handler = AsyncMock()
    session = build_session(rate_limit_handler=handler)
    params: dict[str, Any] = {
        "adapter_id": "alfred_comms_test",
        "retry_after_seconds": 5,
        "platform_endpoint": "POST /channels/1/messages",
    }
    await session._on_post_handshake_method(method="adapter.rate_limit_signal", params=params)
    handler.process.assert_awaited_once()
    assert isinstance(handler.process.await_args.args[0], RateLimitSignal)


@pytest.mark.asyncio
async def test_crashed_routed_to_crash_handler() -> None:
    handler = AsyncMock()
    session = build_session(crash_handler=handler)
    params: dict[str, Any] = {
        "adapter_id": "alfred_comms_test",
        "error_class": "ConnectionResetError",
        "detail": "socket dropped",
    }
    await session._on_post_handshake_method(method="adapter.crashed", params=params)
    handler.process.assert_awaited_once()
    assert isinstance(handler.process.await_args.args[0], CrashedNotification)
