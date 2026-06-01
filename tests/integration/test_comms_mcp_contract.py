"""Spec §9.1 — CommsAdapterMCP reference plugin contract test.

comms-007: Filename matches spec §9.1 line 746 so ADR-0016 cross-references hold.

Validates:

1. Handshake: ``manifest_version=1`` accepted, plugin loaded.
2. Lifecycle: ``lifecycle.start`` → host receives ``inbound.message``
   notification (comms-003: plugin → host direction verified, not
   host → plugin).
3. ``lifecycle.stop`` completes cleanly.
4. ``adapter.health`` returns a ``ControlResult`` with ``{"status": "ok"}``.

The test plugin is an MCP stdio server. This test uses
:class:`AlfredPluginSession` (PR-S3-3a) to load it, verifying the
transport contract works for a second consumer beyond the
quarantined-LLM and web-fetch plugins.

Depends on: PR-S3-3a (``StdioTransport``, ``AlfredPluginSession`` with
notification-handler support), PR-S3-2 (``RealGate`` or ``DevGate`` in
test config), PR-S3-0b (``manifest_version=1`` schema).

Marked: ``pytest.mark.integration`` — requires subprocess launch of
the test plugin.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

try:
    # Plan-line 1975 imports ``AlfredPluginSession`` from
    # ``alfred.plugins.stdio_transport``. The real package layout (PR-S3-3a)
    # puts it in ``alfred.plugins.session``. The plan's intent is
    # "skip when the plugin host is not yet wired up the way the test
    # expects" — the constructor the test uses
    # (``AlfredPluginSession(plugin_dir=..., gate=..., notification_handlers=...)``)
    # also does not exist on the real factory-style API. Both gaps live behind
    # ``HAS_PLUGIN_HOST`` so the suite collects on every developer's box.
    from alfred.hooks.capability import DevGate
    from alfred.plugins.session import AlfredPluginSession

    # ``AlfredPluginSession.create()`` is async / manifest-string-based.
    # The plan test calls ``AlfredPluginSession(plugin_dir=..., gate=...,
    # notification_handlers=...)`` as an async context manager. That
    # surface is part of PR-S3-3a's notification-handler extension and is
    # not yet shipped. Detect it dynamically and skip when absent.
    _accepts_plugin_dir = hasattr(AlfredPluginSession, "__aenter__") and (
        # ``plugin_dir`` parameter only present on the planned async-CM API.
        "plugin_dir" in AlfredPluginSession.__init__.__code__.co_varnames
    )
    HAS_PLUGIN_HOST = _accepts_plugin_dir
except ImportError:
    HAS_PLUGIN_HOST = False
    AlfredPluginSession = None  # type: ignore[assignment,misc]
    DevGate = None  # type: ignore[assignment,misc]

PLUGIN_DIR = Path(__file__).parent.parent.parent / "plugins" / "alfred_comms_test"


@pytest.mark.integration
@pytest.mark.skipif(
    not HAS_PLUGIN_HOST,
    reason="PR-S3-3a (AlfredPluginSession plugin_dir CM) not merged",
)
@pytest.mark.skipif(
    not PLUGIN_DIR.exists(),
    reason="reference plugin not yet created",
)
async def test_comms_test_plugin_handshake() -> None:
    """Plugin loads without error: ``manifest_version=1`` accepted."""
    assert DevGate is not None and AlfredPluginSession is not None
    gate = DevGate(allow_system=True)
    async with AlfredPluginSession(plugin_dir=PLUGIN_DIR, gate=gate) as session:  # type: ignore[call-arg,attr-defined]
        assert session.is_loaded


@pytest.mark.integration
@pytest.mark.skipif(
    not HAS_PLUGIN_HOST,
    reason="PR-S3-3a (AlfredPluginSession plugin_dir CM) not merged",
)
@pytest.mark.skipif(
    not PLUGIN_DIR.exists(),
    reason="reference plugin not yet created",
)
async def test_comms_test_plugin_lifecycle_start_emits_inbound_message() -> None:
    """comms-003: ``lifecycle.start`` triggers plugin → host ``inbound.message``.

    The host must have a notification handler registered for
    ``inbound.message``. The notification payload must match
    :class:`InboundMessage` shape (``platform``, ``platform_user_id``,
    ``content``, ``language``) per comms-001 + spec §9.1.
    """
    assert DevGate is not None and AlfredPluginSession is not None
    gate = DevGate(allow_system=True)
    received_notifications: list[dict[str, Any]] = []

    async def on_inbound_message(params: dict[str, Any]) -> None:
        received_notifications.append(params)

    async with AlfredPluginSession(  # type: ignore[call-arg,attr-defined]
        plugin_dir=PLUGIN_DIR,
        gate=gate,
        notification_handlers={"inbound.message": on_inbound_message},
    ) as session:
        result_start = await session.dispatch("lifecycle.start", {})
        assert result_start is not None
        # Give the notification a tick to arrive.
        await asyncio.sleep(0.05)

    assert len(received_notifications) >= 1, "Expected at least one inbound.message notification"
    notif = received_notifications[0]
    assert "platform" in notif
    assert "platform_user_id" in notif
    assert "content" in notif
    assert "language" in notif


@pytest.mark.integration
@pytest.mark.skipif(
    not HAS_PLUGIN_HOST,
    reason="PR-S3-3a (AlfredPluginSession plugin_dir CM) not merged",
)
@pytest.mark.skipif(
    not PLUGIN_DIR.exists(),
    reason="reference plugin not yet created",
)
async def test_comms_test_plugin_adapter_health_ok() -> None:
    """``adapter.health`` returns a control result with ``status=ok``."""
    assert DevGate is not None and AlfredPluginSession is not None
    gate = DevGate(allow_system=True)
    async with AlfredPluginSession(plugin_dir=PLUGIN_DIR, gate=gate) as session:  # type: ignore[call-arg,attr-defined]
        await session.dispatch("lifecycle.start", {})
        result = await session.dispatch("adapter.health", {})
        assert result is not None
        payload = getattr(result, "payload", {})
        assert payload.get("status") == "ok"
