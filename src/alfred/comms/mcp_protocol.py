"""CommsAdapterMCP Protocol — MCP wire-shape for comms adapters.

Defines the Slice-3 MCP comms adapter Protocol stub per spec §9 (Fork 8).
This Protocol is DISTINCT from the in-process CommsAdapter Protocol at
src/alfred/comms/adapter.py. Both coexist through Slice 3.

The four methods pin the minimum wire shape the reference test plugin
(plugins/alfred-comms-test/) validates against:

| Direction              | Method            | Payload                                            |
|------------------------|-------------------|----------------------------------------------------|
| Orchestrator → adapter | lifecycle_start   | none                                               |
| Orchestrator → adapter | lifecycle_stop    | none                                               |
| Adapter → orchestrator | inbound_message   | platform, platform_user_id, content, language      |
| Orchestrator → adapter | adapter_health    | → {status: ok|degraded, detail: str}               |

comms-001 fix: ``platform`` field added — spec §9.1 line 744 says adapters
send raw (platform, platform_user_id) so the orchestrator can disambiguate
discord:12345 from telegram:12345 from tui:12345. Without platform, identity
resolution collides across platforms.

The full message-contract definition (error shapes, rate-limit signalling)
is co-defined in ADR-0016 when Slice 4 implements the Discord rewrite; it
is NOT finalised here. This stub validates transport + handshake only.

Per spec §9.1: identity resolution stays in-process to the orchestrator
in Slice 3. comms-MCP plugins send raw (platform, platform_user_id) over
the wire; the orchestrator resolves identity before invoking ``_ingest_tier``.

ADR-0009 status: "Superseded by ADR-0016 for new adapters; in-process
adapters live through Slice 3 unchanged." (spec §9.4)

comms-011: Authorised by ADR-0017 (Slice-3 trust-tier completion + MCP
plugin transport). Why this stub lands in Slice 3: spec §9 Fork-8 commits
to validating the MCP transport contract against a second consumer before
Slice 4 rewrites Discord and TUI as MCP plugins.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

# comms-002 fix: architect cross-check confirmed method names are literal
# JSON-RPC method names (NOT MCP tools/call subjects). AlfredPluginSession.dispatch
# in PR-S3-3a MUST route these as JSON-RPC method=<name>, not as tools/call.
# This constant is the single source of truth for the wire mapping;
# test_mcp_identity_boundary.py and the integration test verify it is honoured.
WIRE_METHOD_NAMES: Final[Mapping[str, str]] = {
    "lifecycle_start": "lifecycle.start",
    "lifecycle_stop": "lifecycle.stop",
    "inbound_message": "inbound.message",
    "adapter_health": "adapter.health",
}


class InboundMessage(BaseModel):
    """Message payload received from a comms-MCP adapter.

    Corresponds to the adapter → orchestrator ``inbound.message`` method.
    All fields are required — adapters MUST supply platform, platform_user_id,
    and language with every message (spec §9.1 identity-resolver placement).

    comms-001: ``platform`` is required so the orchestrator can disambiguate
    e.g. discord:12345 from telegram:12345 from tui:12345. Without it,
    IdentityResolver.resolve() cannot scope the lookup to the correct
    platform namespace and identity collisions occur across platforms.

    ``language`` is a BCP-47 tag per CLAUDE.md i18n rule #3.
    """

    model_config = ConfigDict(frozen=True)

    platform: str
    platform_user_id: str
    content: str
    language: str


class AdapterHealthResponse(BaseModel):
    """Health snapshot returned by ``adapter_health()``.

    ``status="ok"`` → adapter fully operational.
    ``status="degraded"`` → adapter running but with reduced capability
    (e.g. reconnecting to gateway). ``detail`` provides human-readable
    context for operators.
    """

    model_config = ConfigDict(frozen=True)

    # comms-009: Slice-3 narrow set per spec §9.1. ADR-0016 (Slice 4) will
    # widen this to include "unhealthy" / "starting" / "stopping" for full
    # lifecycle visibility. When ADR-0016 lands, widen the Literal AND
    # update test_adapter_health_rejects_invalid_status to accept the
    # new values.
    status: Literal["ok", "degraded"]
    detail: str


@runtime_checkable
class CommsAdapterMCP(Protocol):
    """MCP-shaped comms adapter Protocol.

    Slice 3 stub: pins four wire methods only. Full contract (error shapes,
    rate-limit signalling, rich-media handling) lands in ADR-0016 + Slice 4
    when TUI and Discord adapters rewrite as MCP plugins.

    The Protocol is ``@runtime_checkable`` so ``AlfredPluginSession`` and the
    integration test can use ``isinstance()`` checks.

    Note on method naming: JSON-RPC method names use dot-notation
    (``lifecycle.start``, ``inbound.message``) but Python method names cannot
    contain dots. The wire mapping (see ``WIRE_METHOD_NAMES``):

      * ``lifecycle_start``  → JSON-RPC method ``lifecycle.start``
      * ``lifecycle_stop``   → JSON-RPC method ``lifecycle.stop``
      * ``inbound_message``  → JSON-RPC method ``inbound.message`` (adapter → host)
      * ``adapter_health``   → JSON-RPC method ``adapter.health``
    """

    async def lifecycle_start(self) -> None:
        """Initiate the adapter's main loop. Spec §9.1: method ``lifecycle.start``."""
        ...

    async def lifecycle_stop(self) -> None:
        """Gracefully shut down the adapter. Spec §9.1: method ``lifecycle.stop``."""
        ...

    async def inbound_message(self, msg: InboundMessage) -> None:
        """Adapter→host notification: adapter sends inbound user message.

        Spec §9.1: JSON-RPC notification ``inbound.message``. The adapter
        sends this notification to the host when a user turn arrives.
        Identity resolution happens in-process in the host; raw
        ``platform_user_id`` is resolved before ``_ingest_tier`` is invoked.
        """
        ...

    async def adapter_health(self) -> AdapterHealthResponse:
        """Return adapter health snapshot. Called by ``alfred supervisor status``.

        Spec §9.1: method ``adapter.health``. Returns
        :class:`AdapterHealthResponse`.
        """
        ...
