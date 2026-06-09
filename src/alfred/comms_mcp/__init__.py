"""Comms-MCP host-side foundations (PR-S4-8, #152).

Wave 1 ships the wire-format module (:mod:`alfred.comms_mcp.protocol`) and
the host-owned classifier registry (:mod:`alfred.comms_mcp.classifier_registry`).
Later waves add ``inbound`` (the ``process_inbound_message`` entrypoint),
``inbound_scanner``, ``handlers``, and ``errors``.

Path note: deliberately ``comms_mcp``, not ``comms`` — the legacy
``alfred.comms`` package is dormant through this PR (spec §8.8).
"""

from alfred.comms_mcp import protocol

__all__ = ["protocol"]
