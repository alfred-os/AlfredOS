"""Unit tests for the comms-MCP host bootstrap bridges (#338 PR1)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from alfred.comms_mcp.bootstrap import SyncIdentityResolverBridge


@pytest.mark.asyncio
async def test_resolver_bridge_carries_display_name() -> None:
    """The bridge copies the resolved User's display_name onto ResolvedInbound."""
    user = MagicMock()
    user.slug = "alice-slug"
    user.display_name = "Alice"
    user.language = "en"
    resolver = MagicMock()
    resolver.resolve.return_value = user
    bridge = SyncIdentityResolverBridge(resolver=resolver)

    resolved = await bridge.resolve(adapter_id="tui", platform_user_id="u-1")

    assert resolved is not None
    assert resolved.display_name == "Alice"
    assert resolved.canonical_user_id == "alice-slug"
