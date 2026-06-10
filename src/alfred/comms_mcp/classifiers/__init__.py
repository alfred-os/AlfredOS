"""Host-side comms-MCP inbound classifiers (PR-S4-9, #206).

Each classifier registers itself at import time via
:func:`alfred.comms_mcp.classifier_registry.register_classifier`. Importing this
package imports every classifier module so the registry is populated for the
:class:`alfred.comms_mcp.inbound_scanner.InboundContentScanner` to dispatch.
"""

from __future__ import annotations

from alfred.comms_mcp.classifiers.discord import (
    DiscordSubPayload,
    DiscordSubPayloadClassifier,
)

__all__ = ["DiscordSubPayload", "DiscordSubPayloadClassifier"]
