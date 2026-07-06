"""Unit tests for the #339 PR3 agentic act-phase loop (core.py _handle_turn)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.budget.guard import BudgetExceededError
from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.response_inspection import InboundCanaryTripped
from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.memory.working import Turn
from alfred.orchestrator import loop_constants
from alfred.orchestrator.core import Orchestrator, _truncate_tool_result
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
        # ``rollback`` must be an AsyncMock (mirrors test_core.py's ``_build``):
        # the top-level ``except BaseException`` arm in ``handle_user_message``
        # awaits ``session.rollback()`` on ANY propagating exception — including
        # the Task 3 escalation-propagation tests' faked ``dispatch_tool``
        # raises. A plain ``MagicMock`` attribute is a sync callable and would
        # raise ``TypeError: 'MagicMock' object can't be awaited`` there,
        # masking the escalation the test means to observe.
        session = MagicMock()
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
    """The for-else + monotonic ``call_index`` across iterations are now
    REACHABLE now that dispatch actually runs (Task 3)."""

    async def test_max_iterations_reached(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(loop_constants, "MAX_TOOL_ITERATIONS", 2)
        forever = _tool_use_response(ToolCall(id="c", name="clock.now", arguments={}))
        router = MagicMock()
        router.complete = AsyncMock(return_value=forever)

        async def _d(call: ToolCall, call_index: int, **kw: Any) -> str:
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
        assert router.complete.await_count == 2


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
