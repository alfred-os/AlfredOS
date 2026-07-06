"""Unit tests for the internal ``clock.now`` demo tool (#339 PR2 Task 4).

Covers the happy path (returns the injected time) and the ≤T2/allowlist
membership claim the ``ToolRegistry`` construction-time check relies on
(sec-001). The refusal/error paths for tool dispatch live at the
``dispatch_tool`` layer (Task 6) — this tool has no external input to refuse.
"""

from datetime import UTC, datetime

import pytest

from alfred.egress.egress_id import TurnEgressContext
from alfred.orchestrator.builtin_tools import build_clock_tool
from alfred.orchestrator.tool_registry import (
    FIRST_PARTY_LE_T2_TOOL_ALLOWLIST,
    InternalToolSpec,
    ToolInvocation,
)


def _inv(args: dict[str, object]) -> ToolInvocation:
    return ToolInvocation(
        arguments=args,
        ctx=TurnEgressContext(adapter_id="a", inbound_id="i", session_id="s"),
        call_index=0,
        user_id="u",
        correlation_id="c",
        language="en",
    )


@pytest.mark.asyncio
async def test_clock_tool_is_internal_and_allowlisted() -> None:
    spec = build_clock_tool(now=lambda: datetime(2026, 7, 6, tzinfo=UTC))
    assert isinstance(spec, InternalToolSpec)
    assert spec.name == "clock.now"
    assert spec.name in FIRST_PARTY_LE_T2_TOOL_ALLOWLIST


@pytest.mark.asyncio
async def test_clock_tool_returns_injected_time() -> None:
    spec = build_clock_tool(now=lambda: datetime(2026, 7, 6, 12, 0, tzinfo=UTC))
    out = await spec.dispatch(_inv({}))
    assert out == "2026-07-06T12:00:00+00:00"
