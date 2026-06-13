"""Shared builders for the ``_on_post_handshake_method`` dispatch tests (Tasks 36-42).

Constructs an :class:`AlfredPluginSession` already past the handshake with the
four comms handlers wired, so a test can drive a notification straight into the
dispatch arm without re-running the manifest/gate machinery each time.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from alfred.plugins.manifest import parse_manifest
from alfred.plugins.session import AlfredPluginSession
from alfred.utils.sliding_window_counter import SlidingWindowCounter

_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred_comms_test"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"

[sandbox]
kind = "none"
"""

# A well-formed inbound.message params dict the InboundMessageNotification
# schema validates without error.
INBOUND_PARAMS: dict[str, Any] = {
    "adapter_id": "alfred_comms_test",
    "inbound_id": "frame-1",
    "platform_user_id": "discord:123",
    "body": {"content": "hi"},
    "sub_payload_refs": [],
    "received_at": "2026-06-07T12:00:00Z",
    "addressing_signal": "dm",
}


def build_session(
    *,
    inbound_handler: Any = None,
    binding_handler: Any = None,
    rate_limit_handler: Any = None,
    crash_handler: Any = None,
    supervisor: Any = None,
    audit_writer: Any = None,
    dispatch_semaphore: asyncio.BoundedSemaphore | None = None,
    error_counter: SlidingWindowCounter | None = None,
    adapter_id: str = "alfred_comms_test",
) -> AlfredPluginSession:
    """Build a post-handshake comms session with sensible AsyncMock defaults."""
    manifest = parse_manifest(_MANIFEST)
    audit = audit_writer if audit_writer is not None else _default_audit()
    gate = MagicMock()
    gate.check_plugin_load = MagicMock(return_value=True)
    session = AlfredPluginSession(
        manifest=manifest,
        audit_writer=audit,
        gate=gate,
        adapter_id=adapter_id,
        inbound_handler=inbound_handler if inbound_handler is not None else AsyncMock(),
        binding_handler=binding_handler if binding_handler is not None else AsyncMock(),
        rate_limit_handler=(rate_limit_handler if rate_limit_handler is not None else AsyncMock()),
        crash_handler=crash_handler if crash_handler is not None else AsyncMock(),
        supervisor=supervisor if supervisor is not None else AsyncMock(),
        dispatch_semaphore=(
            dispatch_semaphore
            if dispatch_semaphore is not None
            else asyncio.BoundedSemaphore(value=32)
        ),
        error_counter=error_counter if error_counter is not None else SlidingWindowCounter(),
    )
    session._handshake_complete = True
    return session


def _default_audit() -> MagicMock:
    writer = MagicMock()
    writer.append_schema = AsyncMock()
    return writer
