"""Unit tests for the #339 PR3 agentic act-phase loop (core.py _handle_turn)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.budget.guard import BudgetExceededError
from alfred.egress.egress_id import TurnEgressContext
from alfred.memory.working import Turn
from alfred.orchestrator import loop_constants
from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse
from alfred.security.tiers import T2, TaggedContent, tag


def _stub_user(
    *, slug: str = "bruce", display_name: str = "Bruce", language: str = "en-US"
) -> MagicMock:
    """A duck-typed ``UserLike`` stand-in with real str attributes.

    A bare ``MagicMock()`` (no attributes set) would hand ``render_persona_prompt``
    a MagicMock for ``display_name``/``language`` — those get f-string-interpolated
    into the system prompt, which "works" but produces garbage, defeating any
    assertion on the driven turn's content. Setting real strings keeps the
    driven turn representative of production.
    """
    user = MagicMock()
    user.slug = slug
    user.display_name = display_name
    user.language = language
    return user


def _tag_t2(content: str) -> TaggedContent[T2]:
    """T2-tagged content as the adapter would produce it (mirrors test_core.py)."""
    return tag(T2, content, source="test.adapter")


def _make_working_memory() -> MagicMock:
    """An in-memory ``WorkingMemory`` stand-in (mirrors test_core.py's ``_build``)."""
    buffer: list[Turn] = []

    async def _append(*, role: str, content: str) -> None:
        buffer.append(Turn(role=role, content=content))  # type: ignore[arg-type]

    async def _turns() -> list[Turn]:
        return list(buffer)

    return MagicMock(
        turns=AsyncMock(side_effect=_turns),
        append=AsyncMock(side_effect=_append),
        clear=AsyncMock(),
    )


def _make_episodic() -> MagicMock:
    """A mocked ``EpisodicMemory`` — the loop tests assert audit rows, not
    episodic persistence, so a real ``EpisodicMemory`` (which needs a real
    ``AsyncSession``) would be unnecessary machinery here."""
    episodic = MagicMock()
    episodic.record = AsyncMock()
    return episodic


def _text_response(content: str = "hello", cost: float = 0.01) -> CompletionResponse:
    """A terminal (no-tools) provider completion — the pre-#339 response shape."""
    return CompletionResponse(
        content=content,
        tokens_in=5,
        tokens_out=3,
        cost_usd=cost,
        model="fake",
        stop_reason="end_turn",
        tool_calls=(),
    )


def _make_orchestrator(*, router: Any = None, budget: Any = None, **kw: Any) -> Orchestrator:
    @asynccontextmanager
    async def _scope() -> Any:
        yield MagicMock()

    resolver = MagicMock()
    resolver.get_operator = MagicMock(return_value=_stub_user())
    audit = MagicMock()
    audit.append = AsyncMock()
    audit.append_schema = AsyncMock()
    return Orchestrator(
        identity_resolver=resolver,
        session_scope=_scope,
        router=router if router is not None else MagicMock(),
        budget=budget if budget is not None else MagicMock(),
        episodic_factory=lambda _s: _make_episodic(),
        audit_factory=lambda _f: audit,
        autocommit_audit_factory=lambda _f: audit,
        **kw,
    )


async def _drive_turn(orch: Orchestrator, *, text: str = "hello, alfred") -> str:
    """Drive one no-tools-registry turn end-to-end — adapter-shaped: tag T2,
    pass a fresh in-memory working buffer in. Mirrors test_core.py's ``_send``."""
    return await orch.handle_user_message(
        user=_stub_user(),
        content=_tag_t2(text),
        working_memory=_make_working_memory(),
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


def _make_no_op_budget() -> MagicMock:
    """A budget mock that never blocks and never overruns."""
    budget = MagicMock()
    budget.estimate_for = MagicMock(return_value=0.0)
    budget.would_exceed = MagicMock(return_value=False)
    budget.check_and_charge = MagicMock(return_value=None)
    return budget


class TestActLoopNoToolsPreservesSingleCompletionTurn:
    """With ``self._tool_registry is None`` (Task 1's default), ``tools=()`` on
    every ``CompletionRequest`` and the FIRST completion is terminal —
    ``stop_reason != "tool_use"`` — so the loop runs exactly one iteration and
    reduces to the pre-#339 single-completion turn (task-2-supplement.md)."""

    async def test_no_tools_runs_exactly_one_completion(self) -> None:
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("final answer"))
        orch = _make_orchestrator(router=router, budget=_make_no_op_budget())

        reply = await _drive_turn(orch)

        assert reply == "final answer"
        assert router.complete.await_count == 1  # one iteration, no tools

    async def test_no_tools_turn_emits_only_completed_row(self) -> None:
        """FIX-3: a terminal (non-tool-use) completion is audited SOLELY by
        the `completed` row — there is no per-iteration `provider_call:0` row
        on the no-tools happy path (that row exists only for a NON-terminal
        completion that continues the loop, tested in Task 3)."""
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("ok"))
        orch = _make_orchestrator(router=router, budget=_make_no_op_budget())

        await _drive_turn(orch)

        phases = [c.kwargs["subject"]["phase"] for c in orch._audit.append.await_args_list]
        assert phases == ["completed"]


class TestActLoopBudgetOverrunTerminal:
    """Mirrors test_core.py's ``test_charge_overrun_records_truthfully_and_does_not_raise``
    inside the new loop shape: the provider call succeeds, the actual cost busts
    the per-call cap, the work already happened so we record truthfully and do
    NOT raise (FIX-6 folds this into the terminal ``completed`` row)."""

    async def test_budget_overrun_terminal_records_budget_overrun(self) -> None:
        budget = _make_no_op_budget()
        budget.check_and_charge = MagicMock(
            side_effect=BudgetExceededError(spent_usd=0.50, cap_usd=0.10)
        )
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("expensive request", cost=0.50))
        orch = _make_orchestrator(router=router, budget=budget)

        reply = await _drive_turn(orch)
        assert reply == "expensive request"

        assert orch._audit.append.await_count == 1
        audit_kwargs = orch._audit.append.await_args.kwargs
        assert audit_kwargs["result"] == "budget_overrun"
        assert audit_kwargs["subject"]["phase"] == "completed"
        assert audit_kwargs["subject"]["charge_result"] == "budget_overrun"
        assert audit_kwargs["cost_actual_usd"] == pytest.approx(0.50)
