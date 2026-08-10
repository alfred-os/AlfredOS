"""Unit tests for the #339 PR3 agentic act-phase loop (core.py _handle_turn)."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from alfred.budget.guard import BudgetError, BudgetExceededError
from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.response_inspection import InboundCanaryTripped
from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.memory.replay_journal import JournalEntry
from alfred.memory.working import Turn
from alfred.orchestrator import loop_constants
from alfred.orchestrator.core import (
    Orchestrator,
    ReplayIterationCeilingError,
    _truncate_tool_result,
)
from alfred.orchestrator.tool_registry import ToolRegistry
from alfred.providers.base import CompletionResponse, ToolCall, ToolDefinition
from alfred.security.dlp import OutboundCanaryTripped
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
        # #410 PR1: handle_user_message no longer calls session.rollback()
        # itself (each phase's scope owns rollback), but the double keeps
        # commit/rollback as AsyncMocks so it stays shaped like a real
        # AsyncSession for any scope double that models the real session_scope.
        session = MagicMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        yield session

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


def _forwarded_egress_context(inbound_id: str = "ib-resume-1") -> TurnEgressContext:
    """A REAL forwarded adapter context — the only shape that can carry a prefix.

    #410 PR2 (final whole-branch review, finding 3): the Act loop only reads
    the replay journal when ``handle_user_message`` was handed a forwarded
    ``TurnEgressContext``. The synthesized fallback mints
    ``inbound_id = trace_id`` (a fresh uuid4 per turn), so a synthesized turn
    can never have journalled entries and the read is skipped for it —
    matching production, where only ADR-0039's forwarded dispatched-edge
    replay ever re-presents the same ``inbound_id``. Every fast-forward test
    therefore drives a FORWARDED turn.
    """
    return TurnEgressContext(adapter_id="discord", inbound_id=inbound_id, session_id="bruce")


async def _drive_turn(
    orch: Orchestrator,
    *,
    text: str = "hello, alfred",
    egress_context: TurnEgressContext | None = None,
) -> str:
    """Drive one turn end-to-end — adapter-shaped: tag T2, pass a fresh
    in-memory working buffer in. Mirrors test_core.py's ``_send``.

    ``egress_context`` defaults to ``None`` (the synthesized fixture/``alfred
    chat`` path, as before); fast-forward tests pass
    ``_forwarded_egress_context()`` because only a forwarded context can
    resume."""
    return await orch.handle_user_message(
        user=_stub_user(),
        content=_tag_t2(text),
        working_memory=_make_working_memory(),
        egress_context=egress_context,
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


# ---------------------------------------------------------------------------
# Task 3: ordered tool dispatch, ephemeral transcript, fan-out cap, escalation
# propagation (#339 PR3, task-3-supplement.md).
#
# FIX-16: every test below monkeypatches ``alfred.orchestrator.core.dispatch_tool``
# wholesale, so ``gate=MagicMock()`` / ``outbound_dlp=MagicMock()`` are safe
# stand-ins here — the real gate/dlp are never consulted (dispatch_tool itself
# is faked out). Task 5's integration test exercises the real gate + dlp.
# ---------------------------------------------------------------------------


def _tool_use_response(*calls: ToolCall, cost: float = 0.01) -> CompletionResponse:
    """A non-terminal provider completion requesting one or more tool calls."""
    return CompletionResponse(
        content="",
        tokens_in=5,
        tokens_out=3,
        cost_usd=cost,
        model="fake",
        stop_reason="tool_use",
        tool_calls=calls,
    )


def _fake_registry(*names: str) -> Any:
    """A ``ToolRegistry`` stand-in advertising ``names`` via ``.definitions()``.

    Tests that monkeypatch ``dispatch_tool`` wholesale never call
    ``registry.get`` — only ``.definitions()`` (consumed in Orient to build
    ``tools`` for the ``CompletionRequest``) needs to be real.
    """
    reg = MagicMock()
    reg.definitions = MagicMock(
        return_value=tuple(
            ToolDefinition(name=n, description=n, input_schema={"type": "object", "properties": {}})
            for n in names
        )
    )
    return reg


async def _drive_turn_capturing_episodic(
    *, router: Any, tool_registry: Any, gate: Any = None, outbound_dlp: Any = None
) -> list[dict[str, Any]]:
    """Drive one turn and capture every ``EpisodicMemory.record`` call's kwargs.

    Backs the negative-persistence test: proves a tool_result's raw content
    never reaches ``episodic.record`` — it only ever lands in the ephemeral
    ``local`` transcript that ``_handle_turn`` discards at the end of the turn.
    """
    records: list[dict[str, Any]] = []

    async def _record(**kwargs: Any) -> None:
        records.append(kwargs)

    episodic = MagicMock()
    episodic.record = AsyncMock(side_effect=_record)

    @asynccontextmanager
    async def _scope() -> Any:
        yield MagicMock()

    resolver = MagicMock()
    resolver.get_operator = MagicMock(return_value=_stub_user())
    audit = MagicMock()
    audit.append = AsyncMock()
    audit.append_schema = AsyncMock()

    orch = Orchestrator(
        identity_resolver=resolver,
        session_scope=_scope,
        router=router,
        budget=_make_no_op_budget(),
        episodic_factory=lambda _s: episodic,
        audit_factory=lambda _f: audit,
        autocommit_audit_factory=lambda _f: audit,
        tool_registry=tool_registry,
        gate=gate if gate is not None else MagicMock(),
        outbound_dlp=outbound_dlp if outbound_dlp is not None else MagicMock(),
    )
    await orch.handle_user_message(
        user=_stub_user(),
        content=_tag_t2("hello, alfred"),
        working_memory=_make_working_memory(),
    )
    return records


class TestTruncateToolResult:
    """``_truncate_tool_result`` bounds a tool_result fed back to the planner
    (spec §6, TOOL_RESULT_MAX_CHARS) — a pathological or verbose tool must not
    balloon the next completion's context.

    A2 (CR Minor, real bug): the marker itself must count against the cap —
    appending it AFTER slicing to the full limit let the result exceed
    ``TOOL_RESULT_MAX_CHARS`` by the marker's length."""

    def test_result_at_or_under_the_cap_passes_through_unchanged(self) -> None:
        text = "x" * loop_constants.TOOL_RESULT_MAX_CHARS
        assert _truncate_tool_result(text) == text
        assert _truncate_tool_result("short") == "short"

    def test_result_over_the_cap_truncates_with_ellipsis_marker(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(loop_constants, "TOOL_RESULT_MAX_CHARS", 20)
        marker = "…[truncated]"
        result = _truncate_tool_result("x" * 40)
        assert result == ("x" * (20 - len(marker))) + marker
        assert result.startswith("x")  # truncates on the character boundary
        assert len(result) <= loop_constants.TOOL_RESULT_MAX_CHARS  # A2: never exceeds the cap

    def test_result_over_the_cap_never_exceeds_the_cap_even_when_marker_alone_overflows_it(
        self, monkeypatch: Any
    ) -> None:
        """Pathological config: a cap smaller than the marker itself. The
        function must degrade gracefully (clip the marker) rather than
        exceed the cap."""
        monkeypatch.setattr(loop_constants, "TOOL_RESULT_MAX_CHARS", 5)
        result = _truncate_tool_result("x" * 20)
        assert result == "…[truncated]"[:5]
        assert len(result) <= 5


class TestActLoopOrderedDispatch:
    """Deterministic ordered dispatch — never ``asyncio.gather`` — with a
    monotonic ``call_index`` threaded across the whole turn."""

    async def test_two_tool_turn_dispatches_in_order_then_returns(self, monkeypatch: Any) -> None:
        # planner: iteration 0 asks for two tools; iteration 1 gives the final answer.
        r0 = _tool_use_response(
            ToolCall(id="c0", name="clock.now", arguments={}),
            ToolCall(id="c1", name="clock.now", arguments={}),
        )
        r1 = _text_response("done")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        seen_call_index: list[int] = []
        captured_kwargs: list[dict[str, Any]] = []

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            seen_call_index.append(call_index)
            captured_kwargs.append(kw)
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)

        registry = _fake_registry("clock.now")
        gate = MagicMock()
        dlp = MagicMock()
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=registry,
            gate=gate,
            outbound_dlp=dlp,
        )

        reply = await _drive_turn(orch)

        assert reply == "done"
        assert seen_call_index == [0, 1]  # monotonic, in tool_calls order, no gather
        assert router.complete.await_count == 2  # re-completed after feeding results back

        # FIX-10: assert the loop passed the EXACT seam objects through to
        # dispatch_tool — not just that it was called.
        assert len(captured_kwargs) == 2
        for kwargs in captured_kwargs:
            assert isinstance(kwargs["ctx"], TurnEgressContext)
            assert kwargs["registry"] is registry
            assert kwargs["gate"] is gate
            assert kwargs["dlp"] is dlp
            assert kwargs["user_id"] == "bruce"  # _stub_user() default slug
            assert kwargs["language"] == "en-US"  # _stub_user() default language
            # the committed per-turn egress anchor's inbound_id IS the trace_id
            # threaded as correlation_id — same identity, not merely equal by
            # coincidence (both derive from the same _handle_turn trace_id).
            assert kwargs["correlation_id"] == kwargs["ctx"].inbound_id


class TestActLoopFanoutCap:
    """FIX-6: the fan-out-over-cap arm folds into the terminal ``completed``
    row — there is no separate ``tool_fanout_exceeded`` audit row."""

    async def test_fanout_over_cap_refuses(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(loop_constants, "MAX_TOOL_CALLS_PER_ITERATION", 1)
        r0 = _tool_use_response(
            ToolCall(id="c0", name="clock.now", arguments={}),
            ToolCall(id="c1", name="clock.now", arguments={}),
        )
        router = MagicMock()
        router.complete = AsyncMock(return_value=r0)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
        )

        reply = await _drive_turn(orch)

        assert reply == t("orchestrator.tool.too_many_tool_calls")

        # The over-cap completion itself still gets the ordinary non-terminal
        # `provider_call:0` row (FIX-3 — every continuing completion is
        # audited that way regardless of what happens next). FIX-6 is about
        # what does NOT happen: there is no SEPARATE `tool_fanout_exceeded`
        # row — the refusal is folded into the terminal `completed` row.
        phases = [c.kwargs["subject"]["phase"] for c in orch._audit.append.await_args_list]
        assert phases == ["provider_call:0", "completed"]
        completed_kwargs = orch._audit.append.await_args.kwargs
        assert completed_kwargs["result"] == "refused"
        assert completed_kwargs["subject"]["exit_reason"] == "too_many_tool_calls"


class TestActLoopMaxIterations:
    """The monotonic ``call_index`` across iterations is REACHABLE now that
    dispatch actually runs (Task 3). The terminal iteration (``iteration ==
    MAX_TOOL_ITERATIONS - 1``) is guarded to stop BEFORE dispatch — a further
    tool request on that iteration can never be fed back to a re-completion,
    so dispatching would be wasted egress/spend/call_index (PR3 fix2 batch,
    #399). This replaced the old trailing ``for...else`` clause, which is now
    unreachable and has been removed."""

    async def test_max_iterations_reached(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(loop_constants, "MAX_TOOL_ITERATIONS", 2)
        forever = _tool_use_response(ToolCall(id="c", name="clock.now", arguments={}))
        router = MagicMock()
        router.complete = AsyncMock(return_value=forever)

        dispatch_calls: list[ToolCall] = []

        async def _d(call: ToolCall, call_index: int, **kw: Any) -> str:
            dispatch_calls.append(call)
            return "r"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _d)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
        )

        reply = await _drive_turn(orch)

        assert reply == t("orchestrator.tool.max_iterations_reached")
        # Both iterations still complete (0 and the terminal iteration 1) —
        # the guard stops dispatch, not the completion itself.
        assert router.complete.await_count == 2
        # Iteration 0 dispatches; iteration 1 (MAX_TOOL_ITERATIONS - 1, the
        # terminal iteration) does NOT — its results could never be fed back.
        assert len(dispatch_calls) == 1

    async def test_max_iterations_one_never_dispatches(self, monkeypatch: Any) -> None:
        """``MAX_TOOL_ITERATIONS=1``: iteration 0 IS the terminal iteration —
        the guard fires before ANY dispatch on the model's very first
        tool-use request, so ``dispatch_tool`` is never called at all."""
        monkeypatch.setattr(loop_constants, "MAX_TOOL_ITERATIONS", 1)
        forever = _tool_use_response(ToolCall(id="c", name="clock.now", arguments={}))
        router = MagicMock()
        router.complete = AsyncMock(return_value=forever)

        dispatch_calls: list[ToolCall] = []

        async def _d(call: ToolCall, call_index: int, **kw: Any) -> str:
            dispatch_calls.append(call)
            return "r"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _d)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
        )

        reply = await _drive_turn(orch)

        assert reply == t("orchestrator.tool.max_iterations_reached")
        assert router.complete.await_count == 1
        assert dispatch_calls == []


class TestActLoopSyntheticRefusalEpisodicCost:
    """A1 (CR Major, real bug): a synthetic refusal (``final_exit_reason`` set)
    is a local i18n string, not a provider completion. Its episodic row must
    carry ZERO provider tokens/cost — charging it ``final_response``'s
    tokens/cost (the PRIOR completion that triggered the refusal) would
    misattribute that completion's spend to the refusal string AND
    double-count cost already logged on a ``provider_call:*`` audit row."""

    async def test_max_iterations_refusal_episodic_row_carries_zero_cost(
        self, monkeypatch: Any
    ) -> None:
        monkeypatch.setattr(loop_constants, "MAX_TOOL_ITERATIONS", 1)
        # Nonzero tokens/cost on the ONLY completion — proves the fix actually
        # zeroes them out on the synthetic-refusal row rather than the values
        # coincidentally already being zero.
        forever = _tool_use_response(ToolCall(id="c", name="clock.now", arguments={}), cost=0.42)
        router = MagicMock()
        router.complete = AsyncMock(return_value=forever)

        async def _d(call: ToolCall, call_index: int, **kw: Any) -> str:
            return "r"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _d)

        episodic_rows = await _drive_turn_capturing_episodic(
            router=router,
            tool_registry=_fake_registry("clock.now"),
        )

        assistant_rows = [r for r in episodic_rows if r["role"] == "assistant"]
        assert len(assistant_rows) == 1
        refusal_row = assistant_rows[0]
        assert refusal_row["content"] == t("orchestrator.tool.max_iterations_reached")
        assert refusal_row["cost_usd"] == 0.0
        assert refusal_row["tokens_in"] == 0
        assert refusal_row["tokens_out"] == 0

    async def test_terminal_answer_from_provider_keeps_its_real_cost(self) -> None:
        """The discriminator's other side: when the answer DOES come straight
        from the provider (no synthetic refusal — ``final_exit_reason`` stays
        ``None``), the episodic row keeps the real tokens/cost unchanged."""
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("final answer", cost=0.07))

        episodic_rows = await _drive_turn_capturing_episodic(
            router=router,
            tool_registry=None,
        )

        assistant_rows = [r for r in episodic_rows if r["role"] == "assistant"]
        assert len(assistant_rows) == 1
        answer_row = assistant_rows[0]
        assert answer_row["content"] == "final answer"
        assert answer_row["cost_usd"] == pytest.approx(0.07)
        assert answer_row["tokens_in"] == 5
        assert answer_row["tokens_out"] == 3


class TestActLoopNegativePersistence:
    """A tool_result's raw content is EPHEMERAL — it must never reach the
    episodic store, only the ephemeral in-turn ``local`` transcript."""

    async def test_tool_results_never_persist_to_episodic(self, monkeypatch: Any) -> None:
        r0 = _tool_use_response(ToolCall(id="c0", name="clock.now", arguments={}))
        r1 = _text_response("final")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        async def _d(call: ToolCall, call_index: int, **kw: Any) -> str:
            return "SENSITIVE-TOOL-BODY"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _d)

        episodic_rows = await _drive_turn_capturing_episodic(
            router=router, tool_registry=_fake_registry("clock.now")
        )

        contents = [r["content"] for r in episodic_rows]
        assert "SENSITIVE-TOOL-BODY" not in contents  # ephemeral: never persists
        assert "final" in contents  # only user input + final assistant answer persist


class TestActLoopEscalationPropagation:
    """FIX-5: dispatch_tool's escalation exceptions MUST propagate UNCAUGHT
    out of the loop / ``_handle_turn`` / ``handle_user_message`` — a canary
    trip or a clearance denial halts the turn, it is never converted into a
    recoverable ``tool_result`` string (spec §9 / CLAUDE.md HARD rule #7)."""

    async def test_inbound_canary_tripped_propagates_uncaught(self, monkeypatch: Any) -> None:
        r0 = _tool_use_response(ToolCall(id="c0", name="web.fetch", arguments={}))
        router = MagicMock()
        router.complete = AsyncMock(return_value=r0)

        async def _d(call: ToolCall, call_index: int, **kw: Any) -> str:
            raise InboundCanaryTripped(destination="evil.example", egress_id="egress-1")

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _d)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("web.fetch"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
        )

        with pytest.raises(InboundCanaryTripped):
            await _drive_turn(orch)

    async def test_outbound_canary_tripped_propagates_uncaught(self, monkeypatch: Any) -> None:
        r0 = _tool_use_response(ToolCall(id="c0", name="web.fetch", arguments={}))
        router = MagicMock()
        router.complete = AsyncMock(return_value=r0)

        async def _d(call: ToolCall, call_index: int, **kw: Any) -> str:
            raise OutboundCanaryTripped(token="canary-token-1")  # noqa: S106

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _d)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("web.fetch"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
        )

        with pytest.raises(OutboundCanaryTripped):
            await _drive_turn(orch)

    async def test_downgrade_clearance_denial_propagates_uncaught(self, monkeypatch: Any) -> None:
        r0 = _tool_use_response(ToolCall(id="c0", name="web.fetch", arguments={}))
        router = MagicMock()
        router.complete = AsyncMock(return_value=r0)

        async def _d(call: ToolCall, call_index: int, **kw: Any) -> str:
            # the downgrade-clearance shape: a bare AlfredError (not a more
            # specific subclass) raised by downgrade_to_orchestrator on a
            # clearance denial (tool_dispatch.py's downgrade_denied arm).
            raise AlfredError("downgrade clearance denied")

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _d)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("web.fetch"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
        )

        with pytest.raises(AlfredError):
            await _drive_turn(orch)


# ---------------------------------------------------------------------------
# #338 PR1: optional egress_context on the privileged turn (behaviour-neutral
# core seam — no production caller yet; PR2's comms adapter wires the real
# TurnEgressContext through the daemon boot graph).
# ---------------------------------------------------------------------------


async def test_handle_user_message_uses_provided_egress_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provided egress_context short-circuits the per-turn synthesis."""
    router = MagicMock()
    router.complete = AsyncMock(return_value=_text_response("ok"))
    orch = _make_orchestrator(router=router, budget=_make_no_op_budget())
    spy = MagicMock(wraps=orch._synthesize_egress_context)
    monkeypatch.setattr(orch, "_synthesize_egress_context", spy)
    provided = TurnEgressContext(adapter_id="discord", inbound_id="ib-1", session_id="alice-slug")
    await orch.handle_user_message(
        user=_stub_user(),
        content=_tag_t2("hello"),
        working_memory=_make_working_memory(),
        egress_context=provided,
    )
    spy.assert_not_called()


async def test_handle_user_message_synthesizes_when_no_egress_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no egress_context (the default), the turn synthesizes as before."""
    router = MagicMock()
    router.complete = AsyncMock(return_value=_text_response("ok"))
    orch = _make_orchestrator(router=router, budget=_make_no_op_budget())
    spy = MagicMock(wraps=orch._synthesize_egress_context)
    monkeypatch.setattr(orch, "_synthesize_egress_context", spy)
    await orch.handle_user_message(
        user=_stub_user(),
        content=_tag_t2("hello"),
        working_memory=_make_working_memory(),
    )
    spy.assert_called_once()


# ---------------------------------------------------------------------------
# #410 PR2: fast-forward a journalled tool-call prefix instead of re-planning
# (task-4-brief.md, design spec §10).
# ---------------------------------------------------------------------------


class TestReplayJournalFastForward:
    """#410 PR2: a journalled prefix is replayed via dispatch_tool, not re-planned."""

    async def test_no_journal_behaves_exactly_as_today(self, monkeypatch: Any) -> None:
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        reply = await _drive_turn(orch, egress_context=_forwarded_egress_context())
        assert reply == "done"
        journal.read.assert_awaited_once()
        journal.append_batch.assert_not_called()  # no tool_use in this fixture's response

    async def test_missing_replay_journal_with_registry_wired_returns_cleanly(
        self, monkeypatch: Any
    ) -> None:
        """review-pr fleet, 2026-08-10.

        `_fast_forward_journalled_calls` has 4 ordered early-return guards;
        the other three each have an isolated pin elsewhere in this class —
        this is guard 3's (``self._replay_journal is None``). Constructs an
        orchestrator with ``tool_registry`` wired (guard 1 passes) and NO
        ``replay_journal`` at all — a real partial-wiring state, distinct
        from every other fast-forward test in this class, which always
        wires a ``MagicMock`` journal — driving a FORWARDED turn (guard 2
        passes) to pin that guard 3 returns ``([], 0, 0)`` cleanly rather
        than raising ``AttributeError`` on ``self._replay_journal.read(...)``.
        """
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("no journal, no crash"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            # replay_journal intentionally omitted -> defaults to None.
        )
        reply = await _drive_turn(orch, egress_context=_forwarded_egress_context())
        assert reply == "no journal, no crash"

    async def test_synthesized_context_never_reads_the_journal(self, monkeypatch: Any) -> None:
        """#410 PR2 final whole-branch review, finding 3.

        A turn with NO forwarded ``egress_context`` synthesizes one whose
        ``inbound_id`` is the per-turn ``trace_id`` — never journalled by
        construction. The Act loop must skip the read entirely rather than pay
        a guaranteed-empty Postgres round-trip on every direct/``alfred chat``
        turn once PR3 arms a live registry. The WRITE stays unconditional —
        ``test_fresh_tool_call_gets_journalled_before_dispatch`` below drives a
        synthesized turn and still asserts the batch write — and that
        asymmetry is deliberate: writing under a fresh-by-construction
        identity is inert, whereas READING under one is the direction that
        could splice a foreign turn's decided calls into this one.
        """
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        journal.append_batch = AsyncMock()
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        reply = await _drive_turn(orch)  # no egress_context -> synthesized
        assert reply == "done"
        journal.read.assert_not_called()

    async def test_fresh_tool_call_gets_journalled_before_dispatch(self, monkeypatch: Any) -> None:
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        journal.append_batch = AsyncMock()
        r0 = _tool_use_response(ToolCall(id="c0", name="clock.now", arguments={}))
        r1 = _text_response("done")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch)
        journal.append_batch.assert_awaited_once()
        batch_kwargs = journal.append_batch.await_args.kwargs
        assert batch_kwargs["adapter_id"]
        assert batch_kwargs["iteration"] == 0
        assert len(batch_kwargs["calls"]) == 1
        call_index, call = batch_kwargs["calls"][0]
        assert call_index == 0
        assert call.name == "clock.now"

    async def test_journalled_prefix_fast_forwards_via_dispatch_tool_not_replanning(
        self, monkeypatch: Any
    ) -> None:
        journalled_call = ToolCall(id="tc-1", name="clock.now", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(JournalEntry(call_index=0, iteration=0, tool_call=journalled_call),)
        )
        journal.append_batch = AsyncMock()
        dispatched: list[str] = []

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            dispatched.append(call.id)
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        # The router only ever sees ONE request: the resumed loop's, starting
        # past the fast-forwarded prefix — never asked to re-plan the
        # journalled call.
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("resumed answer"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        reply = await _drive_turn(orch, egress_context=_forwarded_egress_context())
        assert reply == "resumed answer"
        assert router.complete.await_count == 1
        assert dispatched == ["tc-1"]  # the journalled call WAS dispatched, via fast-forward
        # The fast-forwarded call was NOT re-journalled (it came FROM the journal).
        journal.append_batch.assert_not_called()

    async def test_journalled_prefix_still_allows_further_tool_calls_after_resume(
        self, monkeypatch: Any
    ) -> None:
        # The regression pin for the rejected forced-wrap-up design: resume
        # must NOT force a text-only answer — the planner is free to keep
        # calling tools after the fast-forwarded prefix.
        journalled_call = ToolCall(id="tc-1", name="clock.now", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(JournalEntry(call_index=0, iteration=0, tool_call=journalled_call),)
        )
        journal.append_batch = AsyncMock()
        r0 = _tool_use_response(ToolCall(id="tc-2", name="clock.now", arguments={}))
        r1 = _text_response("second call worked too")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        reply = await _drive_turn(
            orch,
            text="what time is it, then check again",
            egress_context=_forwarded_egress_context(),
        )
        assert reply == "second call worked too"
        # The SECOND (fresh, post-resume) call gets journalled at call_index=1,
        # continuing the sequence the fast-forward left off at.
        journal.append_batch.assert_awaited_once()
        batch_kwargs = journal.append_batch.await_args.kwargs
        assert len(batch_kwargs["calls"]) == 1
        assert batch_kwargs["calls"][0][0] == 1
        # ...and at ITERATION 1, not 0 (#410 PR2 final whole-branch review,
        # finding 4): the fast-forwarded prefix's highest journalled iteration
        # is 0, so `start_iteration = max_iteration + 1 = 1` and the resumed
        # loop's first fresh completion is iteration 1. Nothing else in this
        # class pinned the iteration side of that arithmetic — only call_index
        # — even though the whole resume story (and findings 1a/1b) depends
        # on it.
        assert batch_kwargs["iteration"] == 1

    async def test_multi_call_iteration_reconstructs_grouping_by_iteration(
        self, monkeypatch: Any
    ) -> None:
        # Two journalled calls from the SAME original iteration must land in
        # ONE reconstructed assistant tool_calls message, not two.
        call_a = ToolCall(id="tc-a", name="clock.now", arguments={})
        call_b = ToolCall(id="tc-b", name="clock.now", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(
                JournalEntry(call_index=0, iteration=0, tool_call=call_a),
                JournalEntry(call_index=1, iteration=0, tool_call=call_b),
            )
        )
        journal.append_batch = AsyncMock()

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(
            orch, text="two calls at once", egress_context=_forwarded_egress_context()
        )
        # Exactly one fresh completion (the resumed iteration) — its request
        # history must contain exactly one assistant tool_calls-bearing
        # message covering BOTH replayed calls, not two separate ones.
        sent_request = router.complete.await_args_list[0].args[0]
        assistant_tool_msgs = [
            msg for msg in sent_request.messages if msg.role == "assistant" and msg.tool_calls
        ]
        assert len(assistant_tool_msgs) == 1
        assert {c.id for c in assistant_tool_msgs[0].tool_calls} == {"tc-a", "tc-b"}

    async def test_fresh_multi_call_iteration_journalled_in_one_atomic_batch(
        self, monkeypatch: Any
    ) -> None:
        """The core-001 wiring-level regression pin (found during `/review-plan` pass 2,
        2026-08-07).

        A single completion that requests TWO fresh tool calls in the same
        iteration must produce exactly ONE `journal.append_batch` call
        covering both — never two separate calls, which would reopen the
        per-call crash window `append_batch` exists to close.
        """
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        journal.append_batch = AsyncMock()
        r0 = _tool_use_response(
            ToolCall(id="c0", name="clock.now", arguments={}),
            ToolCall(id="c1", name="clock.now", arguments={}),
        )
        r1 = _text_response("both done")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch)
        journal.append_batch.assert_awaited_once()  # ONE batch write, not two
        batch_kwargs = journal.append_batch.await_args.kwargs
        assert batch_kwargs["iteration"] == 0
        assert [call_index for call_index, _call in batch_kwargs["calls"]] == [0, 1]
        assert [call.id for _call_index, call in batch_kwargs["calls"]] == ["c0", "c1"]

    async def test_no_live_consumer_never_touches_the_journal_without_a_tool_registry(
        self, monkeypatch: Any
    ) -> None:
        # #410 design correction (found during /review-plan): the "no live
        # consumer" claim depends on checking self._tool_registry FIRST,
        # before ever consulting self._replay_journal. This is the
        # regression pin for that ordering.
        #
        # Drives a FORWARDED turn deliberately (#410 PR2 final whole-branch
        # review, finding 3): the new `forwarded_context` early return would
        # otherwise ALSO stop the read here, so a synthesized turn could no
        # longer isolate the tool_registry check and this pin would pass even
        # if that check were deleted. With a real forwarded context, the
        # registry check is the ONLY thing that can keep `read` uncalled.
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(
                JournalEntry(
                    call_index=0,
                    iteration=0,
                    tool_call=ToolCall(id="tc-1", name="clock.now", arguments={}),
                ),
            )
        )
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(
            router=router, budget=_make_no_op_budget(), replay_journal=journal
        )
        reply = await _drive_turn(orch, egress_context=_forwarded_egress_context())
        assert reply == "done"
        journal.read.assert_not_called()

    async def test_seams_unwired_raises_when_journal_has_entries_but_gate_missing(
        self, monkeypatch: Any
    ) -> None:
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(
                JournalEntry(
                    call_index=0,
                    iteration=0,
                    tool_call=ToolCall(id="tc-1", name="clock.now", arguments={}),
                ),
            )
        )
        orch = _make_orchestrator(
            router=MagicMock(),
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            # gate and outbound_dlp deliberately omitted.
            replay_journal=journal,
        )
        # t()'s resolved English string, not the i18n key itself — the key
        # (`orchestrator.tool.dispatch_seams_unwired`) never appears in the
        # raised message; matching on the translated prose is the only way
        # this regex can find the raise (verified against the SAME guard's
        # pre-existing shape at the main dispatch-loop's `dispatch_tool` call).
        with pytest.raises(RuntimeError, match="not fully wired"):
            await _drive_turn(orch, egress_context=_forwarded_egress_context())

    async def test_temperature_is_zero_when_tools_are_advertised(self, monkeypatch: Any) -> None:
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch)
        sent_request = router.complete.await_args.args[0]
        assert sent_request.temperature == 0.0

    async def test_temperature_stays_default_when_no_tools_advertised(
        self, monkeypatch: Any
    ) -> None:
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(router=router, budget=_make_no_op_budget())
        await _drive_turn(orch)
        sent_request = router.complete.await_args.args[0]
        assert sent_request.temperature == 0.7

    async def test_journal_never_receives_a_resolved_secret_value(self, monkeypatch: Any) -> None:
        # Pins Task 1's disputed-severity invariant: the journal write
        # happens BEFORE dispatch_tool runs, so it always sees the raw
        # planner-authored arguments — a {{secret:name}} placeholder stays
        # a placeholder, never the value dispatch_tool's own broker
        # substitution would have resolved it to.
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        journal.append_batch = AsyncMock()
        placeholder_call = ToolCall(
            id="c0", name="clock.now", arguments={"header": "{{secret:api-key}}"}
        )
        r0 = _tool_use_response(placeholder_call)
        r1 = _text_response("done")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            # Simulates what a real tool dispatcher does INTERNALLY: resolve
            # the secret for ITS OWN use, never writing it back to `call`.
            # `call` is the SAME frozen ToolCall object journal.append_batch
            # already received (journalled before this function runs) — a
            # real dispatcher resolving into a separate local variable, as
            # web.fetch's does, can never retroactively change what was
            # already journalled.
            del call, call_index, kw
            return "used-sk-real-secret-value-never-journalled"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch)
        _journalled_index, journalled_call = journal.append_batch.await_args.kwargs["calls"][0]
        assert journalled_call.arguments["header"] == "{{secret:api-key}}"

    async def test_dispatch_failure_mid_iteration_does_not_lose_the_journal_write(
        self, monkeypatch: Any
    ) -> None:
        """Found during a second `/review-plan` pass, 2026-08-09: every prior
        test in this class proved atomicity only via call-count/ordering on
        the HAPPY path — none actually drove a real `dispatch_tool` failure
        to prove the journal write already landed durably BEFORE the crash.
        This is the PR's central crash-safety claim; simulate the SECOND of
        two calls in one iteration raising.

        `events` (review-pr fleet, 2026-08-10): `journal.append_batch.
        assert_awaited_once()` and `dispatched == ["c0", "c1"]` alone do NOT
        prove ordering — both would still pass if the journal write landed
        BETWEEN c0 and c1's dispatch rather than before either (the mocks
        don't observe each other's timing). Recording both operations into
        one shared list and asserting its exact order closes that gap.

        Scope (CodeRabbit review, 2026-08-11): this test proves the
        ORCHESTRATOR half of the crash-safety claim — that `_orient_and_act`
        awaits `append_batch` to completion before entering the dispatch
        loop, with both `dispatch_tool` and `append_batch` MOCKED (this
        `monkeypatch.setattr` line replaces `dispatch_tool`; `journal` is a
        `MagicMock`, not a real `PostgresReplayJournal`). It does not, by
        itself, exercise a failure from the real `dispatch_tool` chokepoint
        or prove a durable PostgreSQL commit. The other half — that a real
        `PostgresReplayJournal.append_batch` durably persists a full
        multi-call iteration atomically — is proven separately, against a
        real database, by
        `test_append_batch_writes_every_call_of_one_iteration_in_one_call`
        in `tests/integration/test_replay_journal_postgres.py`. Composing
        the two is the actual "central crash-safety claim" proof; neither
        test alone claims to be it.
        """
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        events: list[str] = []
        journal.append_batch = AsyncMock(side_effect=lambda **_: events.append("journal"))
        r0 = _tool_use_response(
            ToolCall(id="c0", name="clock.now", arguments={}),
            ToolCall(id="c1", name="clock.now", arguments={}),
        )
        router = MagicMock()
        router.complete = AsyncMock(return_value=r0)
        dispatched: list[str] = []

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            events.append(f"dispatch:{call.id}")
            dispatched.append(call.id)
            if call.id == "c1":
                raise RuntimeError("simulated crash mid-dispatch")
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        with pytest.raises(RuntimeError, match="simulated crash mid-dispatch"):
            await _drive_turn(orch)
        # The WHOLE iteration's decision (both c0 and c1) was already
        # durably journalled before dispatch of EITHER call began — a
        # resume can fast-forward the full iteration even though the
        # process crashed between dispatching c0 and c1.
        journal.append_batch.assert_awaited_once()
        batch_kwargs = journal.append_batch.await_args.kwargs
        assert [call.id for _idx, call in batch_kwargs["calls"]] == ["c0", "c1"]
        assert events == ["journal", "dispatch:c0", "dispatch:c1"]
        assert dispatched == ["c0", "c1"]

    async def test_journal_write_failure_propagates_without_dispatching(
        self, monkeypatch: Any
    ) -> None:
        """review-pr fleet, 2026-08-11 (CodeRabbit).

        `_orient_and_act`'s post-loop invariant comment names "a journal
        write failure" as one of the raising exits that keep
        `final_response` assigned — and `PostgresReplayJournal` propagates
        `SQLAlchemyError` by design, reachable once PR3 arms a live
        registry. No prior test in this class drove a RAISING
        `append_batch`; every journal double here uses a succeeding one. A
        regression that swallowed the journal error would leave the turn
        dispatching tools whose decision was never durably recorded, and
        this suite would have stayed green.
        """
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        journal.append_batch = AsyncMock(
            side_effect=RuntimeError("simulated journal write failure")
        )
        r0 = _tool_use_response(ToolCall(id="c0", name="clock.now", arguments={}))
        router = MagicMock()
        router.complete = AsyncMock(return_value=r0)
        dispatched: list[str] = []

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            dispatched.append(call.id)
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        with pytest.raises(RuntimeError, match="simulated journal write failure"):
            await _drive_turn(orch)
        # The journal write failure propagates BEFORE any call in the
        # iteration is dispatched — a decision that was never durably
        # recorded must never be acted on.
        journal.append_batch.assert_awaited_once()
        assert dispatched == []

    async def test_fast_forward_propagates_an_escalation_exception_from_dispatch(
        self, monkeypatch: Any
    ) -> None:
        """Found during a second `/review-plan` pass, 2026-08-09: every
        fast-forward test before this one used an unconditionally-succeeding
        fake dispatch. `_fast_forward_journalled_calls` calls the real
        `dispatch_tool` chokepoint with no try/except around it, so an
        escalation exception (e.g. a canary trip) on a REPLAYED call must
        propagate exactly like it does on the live path — mirrors
        `TestActLoopEscalationPropagation` (this same file).
        """
        journalled_call = ToolCall(id="tc-1", name="clock.now", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(JournalEntry(call_index=0, iteration=0, tool_call=journalled_call),)
        )

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            raise InboundCanaryTripped(destination="evil.example", egress_id="egress-1")

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("unreachable"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        with pytest.raises(InboundCanaryTripped):
            await _drive_turn(orch, egress_context=_forwarded_egress_context())
        router.complete.assert_not_awaited()  # never reached the resumed planner call

    async def test_fast_forward_of_a_now_unknown_tool_returns_the_refusal_result(
        self, monkeypatch: Any
    ) -> None:
        """Found during a second `/review-plan` pass, 2026-08-09: a
        cross-restart registry-drift scenario the live path can never
        exercise by definition — a journalled tool that no longer exists in
        the registry by the time a resume fast-forwards it. `dispatch_tool`
        resolves this to its own `unknown_tool` refusal RESULT (not an
        exception, see `tool_dispatch.py`); the fast-forward path must
        surface that result exactly like the live path does, never crash or
        silently drop it.
        """
        journalled_call = ToolCall(id="tc-1", name="retired.tool", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(JournalEntry(call_index=0, iteration=0, tool_call=journalled_call),)
        )
        dispatched_results: list[str] = []

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            result = t("orchestrator.tool.unknown_tool", tool=call.name)
            dispatched_results.append(result)
            return result

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("handled the refusal"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            # The registry no longer advertises "retired.tool" — the
            # fast-forward path dispatches it anyway, from the journalled
            # ToolCall directly rather than a fresh PLANNER decision
            # (review-pr fleet, 2026-08-10: dispatch_tool still performs its
            # OWN real registry.get() lookup on every call, live or
            # replayed — nothing here skips that), matching dispatch_tool's
            # own unknown_tool resolution.
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        reply = await _drive_turn(orch, egress_context=_forwarded_egress_context())
        assert reply == "handled the refusal"
        assert dispatched_results == [t("orchestrator.tool.unknown_tool", tool="retired.tool")]

    async def test_fast_forward_of_a_registry_dropped_tool_uses_the_real_dispatch_path(
        self, monkeypatch: Any
    ) -> None:
        """CodeRabbit review, PR #579 (2026-08-10).

        The test above proves the fast-forward path surfaces whatever
        ``dispatch_tool`` returns without crashing or dropping it, but its
        ``_fake_dispatch`` ignores every kwarg — it does not prove the
        fast-forward call site actually threads the CURRENT
        ``self._tool_registry`` into the real ``dispatch_tool``, which is
        the thing that makes registry drift resolvable at all. This test
        does not monkeypatch ``dispatch_tool``: it drives the real
        chokepoint (already unit-tested in isolation by
        ``test_tool_dispatch.py::test_unknown_tool_recoverable_and_audited``)
        through the fast-forward wiring, with a registry that no longer
        advertises the journalled tool — ``spec is None`` resolves before
        ``gate``/``dlp`` are ever touched, so the fixture's plain
        ``MagicMock()`` gate/dlp are never exercised on this path.

        A real (not ``_fake_registry``) empty ``ToolRegistry`` is required
        here: ``_fake_registry`` is a bare ``MagicMock`` whose unconfigured
        ``.get()`` returns a truthy ``MagicMock`` for ANY name — it would
        make ``retired.tool`` resolve as a false "known" tool the instant
        the real ``dispatch_tool`` calls ``registry.get(call.name)``,
        defeating the whole point of this test.
        """
        journalled_call = ToolCall(id="tc-1", name="retired.tool", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(JournalEntry(call_index=0, iteration=0, tool_call=journalled_call),)
        )
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("handled the refusal"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            # A real, empty registry — "retired.tool" is genuinely absent,
            # so the real dispatch_tool resolves this to its unknown_tool
            # refusal.
            tool_registry=ToolRegistry([]),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        reply = await _drive_turn(orch, egress_context=_forwarded_egress_context())
        assert reply == "handled the refusal"
        sent_request = router.complete.await_args_list[0].args[0]
        tool_result_msgs = [msg for msg in sent_request.messages if msg.role == "tool"]
        assert len(tool_result_msgs) == 1
        assert tool_result_msgs[0].content == t(
            "orchestrator.tool.unknown_tool", tool="retired.tool"
        )

    async def test_fast_forward_dispatches_using_the_journalled_call_index_not_a_rederived_counter(
        self, monkeypatch: Any
    ) -> None:
        """Mutation-testing spot-check pin (2026-08-10): swapping the fast-forward
        dispatch's ``entry.call_index`` argument for a freshly re-derived running
        counter survives every OTHER test in this class, because every other
        fixture's journalled entries happen to be contiguous and 0-based — the
        running counter and ``entry.call_index`` coincide by construction there.

        ``_fast_forward_journalled_calls``'s own docstring/comments explain WHY
        it reads ``entry.call_index`` straight off the journal rather than
        re-deriving one: call_index is the sole (with ctx) input to
        ``compute_egress_id``, and the write side's contiguity is an
        UNENFORCED invariant, not a type-level guarantee. This test uses a
        deliberately non-contiguous journalled call_index sequence (0, then 3 —
        as if an earlier attempt's middle entries were never durably recorded)
        so a future refactor that "simplifies" this to a re-derived counter
        fails loud here even though every contiguous fixture elsewhere would
        stay green.
        """
        call_a = ToolCall(id="tc-a", name="clock.now", arguments={})
        call_b = ToolCall(id="tc-b", name="clock.now", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(
                JournalEntry(call_index=0, iteration=0, tool_call=call_a),
                JournalEntry(call_index=3, iteration=1, tool_call=call_b),
            )
        )
        seen_call_index: list[int] = []

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            seen_call_index.append(call_index)
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch, egress_context=_forwarded_egress_context())
        # The journalled call_index values (0, 3), NOT a re-derived (0, 1).
        assert seen_call_index == [0, 3]

    async def test_multi_iteration_prefix_rebuilds_one_assistant_message_per_iteration(
        self, monkeypatch: Any
    ) -> None:
        """#410 PR2 final whole-branch review, finding 5.

        `itertools.groupby` is what guarantees the reconstructed transcript
        has ONE assistant-tool_calls message per journalled ITERATION (not one
        per call, and not one in total). Every prior test in this class either
        covered a single iteration with multiple calls
        (`test_multi_call_iteration_reconstructs_grouping_by_iteration`) or
        multiple iterations with call-index-only assertions
        (`..._not_a_rederived_counter`) — none pinned the MESSAGE SHAPE across
        more than one iteration, so a regression collapsing every replayed
        call into a single assistant message would have stayed green.
        """
        entries = (
            JournalEntry(
                call_index=0,
                iteration=0,
                tool_call=ToolCall(id="tc-a", name="clock.now", arguments={}),
            ),
            JournalEntry(
                call_index=1,
                iteration=1,
                tool_call=ToolCall(id="tc-b", name="clock.now", arguments={}),
            ),
            JournalEntry(
                call_index=2,
                iteration=1,
                tool_call=ToolCall(id="tc-c", name="clock.now", arguments={}),
            ),
        )
        journal = MagicMock()
        journal.read = AsyncMock(return_value=entries)
        journal.append_batch = AsyncMock()

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("wrapped up"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch, egress_context=_forwarded_egress_context())

        sent_request = router.complete.await_args_list[0].args[0]
        assistant_tool_msgs = [
            msg for msg in sent_request.messages if msg.role == "assistant" and msg.tool_calls
        ]
        # TWO iterations journalled -> TWO assistant messages, split on the
        # iteration boundary (1 call, then 2), never one flattened message.
        assert len(assistant_tool_msgs) == 2
        assert [c.id for c in assistant_tool_msgs[0].tool_calls] == ["tc-a"]
        assert [c.id for c in assistant_tool_msgs[1].tool_calls] == ["tc-b", "tc-c"]
        # Every replayed call still contributes its own tool-result message,
        # in journalled order, so the assistant/tool pairing stays well-formed.
        assert [msg.tool_call_id for msg in sent_request.messages if msg.role == "tool"] == [
            "tc-a",
            "tc-b",
            "tc-c",
        ]

    async def test_fast_forward_groups_by_iteration_even_when_call_index_interleaves(
        self, monkeypatch: Any
    ) -> None:
        """CodeRabbit review, PR #579 (2026-08-10).

        `read()` orders rows by `call_index ASC` only; `itertools.groupby`
        groups CONSECUTIVE equal keys. Grouping the raw read order therefore
        only produces one group per iteration while call-index order happens
        to coincide with iteration order — the exact write-side invariant
        this method already refuses to trust for `entry.call_index`
        (commit 360e60a8) and for `max_iteration` (the test above). This
        fixture journals iteration 0 at call_index 0 AND 2, with iteration
        1's single call at call_index 1 in between, so grouping the raw read
        order would yield THREE groups — splitting iteration 0's two calls
        into two separate assistant messages — unless entries are sorted by
        `(iteration, call_index)` before grouping.
        """
        entries = (
            JournalEntry(
                call_index=0,
                iteration=0,
                tool_call=ToolCall(id="tc-a", name="clock.now", arguments={}),
            ),
            JournalEntry(
                call_index=1,
                iteration=1,
                tool_call=ToolCall(id="tc-b", name="clock.now", arguments={}),
            ),
            JournalEntry(
                call_index=2,
                iteration=0,
                tool_call=ToolCall(id="tc-c", name="clock.now", arguments={}),
            ),
        )
        journal = MagicMock()
        journal.read = AsyncMock(return_value=entries)
        journal.append_batch = AsyncMock()

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("wrapped up"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch, egress_context=_forwarded_egress_context())

        sent_request = router.complete.await_args_list[0].args[0]
        assistant_tool_msgs = [
            msg for msg in sent_request.messages if msg.role == "assistant" and msg.tool_calls
        ]
        # TWO journalled iterations -> TWO assistant messages, iteration 0's
        # two calls reunited into ONE message despite the call-index gap.
        assert len(assistant_tool_msgs) == 2
        assert [c.id for c in assistant_tool_msgs[0].tool_calls] == ["tc-a", "tc-c"]
        assert [c.id for c in assistant_tool_msgs[1].tool_calls] == ["tc-b"]

    async def test_resume_point_is_the_maximum_journalled_iteration_not_the_last(
        self, monkeypatch: Any
    ) -> None:
        """#410 PR2 final whole-branch review, finding 2.

        `max_iteration` used to be a plain assignment at the tail of each
        `groupby` group, i.e. "the LAST group's iteration wins". That is only
        the MAXIMUM while `read()`'s `call_index ASC` order happens to coincide
        with iteration-ascending order — an unenforced write-side invariant,
        exactly like the contiguity assumption commit 360e60a8 already refused
        to trust for `call_index`. This fixture deliberately journals a HIGHER
        iteration at a LOWER call_index so the last group is not the max: with
        the plain assignment the turn would resume at iteration 1 and re-use an
        already-spent iteration slot; with `max(...)` it resumes at 2.
        """
        entries = (
            JournalEntry(
                call_index=0,
                iteration=1,
                tool_call=ToolCall(id="tc-high", name="clock.now", arguments={}),
            ),
            JournalEntry(
                call_index=1,
                iteration=0,
                tool_call=ToolCall(id="tc-low", name="clock.now", arguments={}),
            ),
        )
        journal = MagicMock()
        journal.read = AsyncMock(return_value=entries)
        journal.append_batch = AsyncMock()
        # The resumed loop's first fresh completion asks for one more tool, so
        # the journal write records the iteration the loop actually resumed at.
        r0 = _tool_use_response(ToolCall(id="tc-fresh", name="clock.now", arguments={}))
        r1 = _text_response("done")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch, egress_context=_forwarded_egress_context())
        journal.append_batch.assert_awaited_once()
        assert journal.append_batch.await_args.kwargs["iteration"] == 2

    async def test_resumed_turn_refused_by_the_budget_pre_check_raises_not_asserts(
        self, monkeypatch: Any
    ) -> None:
        """#410 PR2 final whole-branch review, finding 1a (Critical).

        A resumed turn enters the Act loop at `start_iteration >= 1`, so the
        budget pre-check's old `iteration == 0` discriminator was FALSE on the
        turn's FIRST fresh completion attempt even though nothing had completed
        in this process. That fell through to the mid-turn graceful-break arm,
        which leaves `final_response is None` — and the post-loop
        `assert final_response is not None` then fired an AssertionError
        instead of the pre-check's contracted `BudgetError` + `budget_pre_check`
        audit row. Keying the arm on `final_response is None` states the real
        condition and is byte-for-byte equivalent on a non-resumed turn.

        No test in this class drove a resumed turn through a budget check at
        all before this one.
        """
        journalled_call = ToolCall(id="tc-1", name="clock.now", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(JournalEntry(call_index=0, iteration=0, tool_call=journalled_call),)
        )
        journal.append_batch = AsyncMock()
        budget = _make_no_op_budget()
        budget.estimate_for = MagicMock(return_value=0.42)
        budget.would_exceed = MagicMock(return_value=True)

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("never reached"))
        orch = _make_orchestrator(
            router=router,
            budget=budget,
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )

        with pytest.raises(BudgetError, match="pre-check refused"):
            await _drive_turn(orch, egress_context=_forwarded_egress_context())

        # Refused BEFORE any provider spend, and audited as a pre-check —
        # the same contract a non-resumed over-budget turn gets.
        router.complete.assert_not_awaited()
        rows = [
            c.kwargs
            for c in orch._audit.append.await_args_list
            if c.kwargs["subject"]["phase"] == "budget_pre_check"
        ]
        assert len(rows) == 1
        assert rows[0]["result"] == "budget_blocked"

    async def test_resume_point_at_or_past_the_iteration_ceiling_fails_loud(
        self, monkeypatch: Any
    ) -> None:
        """#410 PR2 final whole-branch review, finding 1b (Critical).

        `start_iteration >= MAX_TOOL_ITERATIONS` makes the Act loop's
        `range(start_iteration, MAX_TOOL_ITERATIONS)` EMPTY: the body never
        runs, no completion happens, and the turn used to fall straight through
        to `assert final_response is not None`. Unreachable through today's
        write side (the `iteration == MAX - 1` guard breaks above the journal
        write), but `tool_call_journal.iteration` carries no upper-bound CHECK,
        so lowering `MAX_TOOL_ITERATIONS` between a crash and a resume reaches
        it — and "unreachable today" is not a safety argument.

        Note the ACCEPTED ordering pinned below: the journalled prefix is
        fast-forwarded (and therefore dispatched) before the ceiling is
        checked. The guard deliberately sits where the coupling to
        `MAX_TOOL_ITERATIONS` lives — in front of the loop — so it catches ANY
        future producer of a bad `start_iteration`, not just this journal.
        """
        journalled_call = ToolCall(id="tc-1", name="clock.now", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(
                JournalEntry(
                    call_index=0,
                    # -> start_iteration == MAX_TOOL_ITERATIONS, an empty range
                    iteration=loop_constants.MAX_TOOL_ITERATIONS - 1,
                    tool_call=journalled_call,
                ),
            )
        )
        journal.append_batch = AsyncMock()
        dispatched: list[str] = []

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            dispatched.append(call.id)
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("never reached"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )

        with pytest.raises(ReplayIterationCeilingError):
            await _drive_turn(orch, egress_context=_forwarded_egress_context())

        router.complete.assert_not_awaited()  # the loop never ran
        assert dispatched == ["tc-1"]  # accepted: the prefix replayed first


@given(
    call_ids=st.lists(
        st.text(
            alphabet=st.characters(categories=("Lu", "Ll", "Nd")),
            min_size=1,
            max_size=8,
        ),
        min_size=1,
        max_size=6,
        unique=True,
    )
)
@settings(deadline=None)
def test_fast_forward_always_dispatches_in_journalled_call_index_order(
    call_ids: list[str],
) -> None:
    """For ANY journalled call list, fast-forward dispatches in exactly the
    journalled call_index order — never re-ordered, never skipped.

    Hypothesis drives a sync body that runs the async turn via ``asyncio.run``
    (the project's @given+async pattern — see test_core_link.py's
    ``test_minted_core_seqs_are_contiguous_within_a_leg`` — avoids the
    function-scoped-event-loop pitfall of combining @given directly with an
    async test function under pytest-asyncio's auto mode).
    """
    entries = tuple(
        JournalEntry(
            call_index=i,
            iteration=0,
            tool_call=ToolCall(id=cid, name="clock.now", arguments={}),
        )
        for i, cid in enumerate(call_ids)
    )
    journal = MagicMock()
    journal.read = AsyncMock(return_value=entries)
    dispatched: list[str] = []

    async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
        dispatched.append(call.id)
        return f"result-{call.id}"

    async def _drive() -> None:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
            router = MagicMock()
            router.complete = AsyncMock(return_value=_text_response("done"))
            orch = _make_orchestrator(
                router=router,
                budget=_make_no_op_budget(),
                tool_registry=_fake_registry("clock.now"),
                gate=MagicMock(),
                outbound_dlp=MagicMock(),
                replay_journal=journal,
            )
            await _drive_turn(orch, egress_context=_forwarded_egress_context())

    asyncio.run(_drive())
    assert dispatched == call_ids
