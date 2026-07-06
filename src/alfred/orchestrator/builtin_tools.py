"""The two tools #339 PR2 wires: the internal ≤T2 ``clock.now`` demo tool and the
T3 ``web.fetch`` tool (Task 5). Kept together as the registry's builtin surface."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Final

from alfred.orchestrator.tool_registry import InternalToolSpec, ToolInvocation
from alfred.providers.base import ToolDefinition

_CLOCK_DEFINITION: Final[ToolDefinition] = ToolDefinition(
    name="clock.now",
    description="Return the current server time as an ISO-8601 UTC timestamp.",
    input_schema={"type": "object", "properties": {}, "additionalProperties": False},
)


def build_clock_tool(*, now: Callable[[], datetime]) -> InternalToolSpec:
    """First-party ≤T2 demo tool. Output is a server-generated timestamp — no
    external content — so its ≤T2 claim is true by construction (test-verified)."""

    async def _dispatch(_inv: ToolInvocation) -> str:
        return now().isoformat()

    return InternalToolSpec(name="clock.now", definition=_CLOCK_DEFINITION, dispatch=_dispatch)
