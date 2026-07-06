"""Unit tests for the #339 PR3 agentic act-phase loop (core.py _handle_turn)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from alfred.egress.egress_id import TurnEgressContext
from alfred.orchestrator import loop_constants
from alfred.orchestrator.core import Orchestrator


def _make_orchestrator(*, router: Any = None, budget: Any = None, **kw: Any) -> Orchestrator:
    @asynccontextmanager
    async def _scope() -> Any:
        yield MagicMock()

    resolver = MagicMock()
    resolver.get_operator = MagicMock(return_value=MagicMock())
    audit = MagicMock()
    audit.append = AsyncMock()
    audit.append_schema = AsyncMock()
    return Orchestrator(
        identity_resolver=resolver,
        session_scope=_scope,
        router=router if router is not None else MagicMock(),
        budget=budget if budget is not None else MagicMock(),
        audit_factory=lambda _f: audit,
        autocommit_audit_factory=lambda _f: audit,
        **kw,
    )


def test_constructor_defaults_tool_seams_to_none() -> None:
    orch = _make_orchestrator()
    assert orch._tool_registry is None
    assert orch._gate is None
    assert orch._outbound_dlp is None


def test_loop_constants_are_positive_ints() -> None:
    assert loop_constants.MAX_TOOL_ITERATIONS > 0
    assert loop_constants.MAX_TOOL_CALLS_PER_ITERATION > 0
    assert loop_constants.TOOL_RESULT_MAX_CHARS > 0


def test_synthesize_egress_context_is_deterministic_for_the_turn() -> None:
    orch = _make_orchestrator()
    user = MagicMock()
    user.slug = "alice"
    ctx_a = orch._synthesize_egress_context(trace_id="trace-1", user=user)
    ctx_b = orch._synthesize_egress_context(trace_id="trace-1", user=user)
    assert isinstance(ctx_a, TurnEgressContext)
    assert ctx_a == ctx_b  # replay-stable within the turn
    # committed inbound identity == trace_id (fixture path)
    assert ctx_a.inbound_id == "trace-1"
    other = orch._synthesize_egress_context(trace_id="trace-2", user=user)
    assert other != ctx_a  # distinct turns -> distinct anchors
