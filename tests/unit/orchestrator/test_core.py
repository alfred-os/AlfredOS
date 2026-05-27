"""Tests for the Slice-1 slim OODA orchestrator.

Spec: docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md (Task 13),
with the spec-bug fixes from the parent agent's task brief baked in
(WorkingMemory is async per ADR-0002; constructor kwargs are keyword-only;
``source=`` is passed at every ``tag()`` site; etc.).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.budget.guard import BudgetError, PerCallCapExceededError
from alfred.memory.working import Turn
from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse


def _make_budget(*, estimate: float = 0.01, would_exceed: bool = False) -> MagicMock:
    budget = MagicMock()
    budget.estimate_for = MagicMock(return_value=estimate)
    budget.would_exceed = MagicMock(return_value=would_exceed)
    budget.check_and_charge = MagicMock(return_value=None)
    return budget


def _make_session_scope() -> tuple[Any, MagicMock]:
    """Return (scope_callable, session_mock) — the scope is an async ctx manager
    that yields the session. The session has an async ``rollback``."""
    session = MagicMock()
    session.rollback = AsyncMock()

    @asynccontextmanager
    async def scope() -> AsyncIterator[MagicMock]:
        yield session

    return scope, session


def _make_episodic_audit() -> tuple[MagicMock, MagicMock]:
    episodic = MagicMock()
    episodic.record = AsyncMock()
    audit = MagicMock()
    audit.append = AsyncMock()
    return episodic, audit


def _build(
    *,
    working: MagicMock | None = None,
    router: MagicMock | None = None,
    budget: MagicMock | None = None,
    operator_name: str = "Sir",
    operator_language: str = "en-US",
    redactor: Any = None,
    # ``episodic_factory`` lets a test inject a custom EpisodicMemory stand-in —
    # used by the cancellation tests to make a specific record() call cancel
    # mid-await. Default = the shared mock created by `_make_episodic_audit`.
    episodic_factory: Any = None,
) -> tuple[Orchestrator, dict[str, Any]]:
    if working is None:
        # A simple in-memory stand-in: append accumulates Turns; turns() returns
        # the accumulated list. Lets the orchestrator's "append user, assemble
        # request from history" sequence work end-to-end through the mock.
        buffer: list[Turn] = []

        async def _append(*, role: str, content: str) -> None:
            buffer.append(Turn(role=role, content=content))  # type: ignore[arg-type]

        async def _turns() -> list[Turn]:
            return list(buffer)

        working = MagicMock(
            turns=AsyncMock(side_effect=_turns),
            append=AsyncMock(side_effect=_append),
            clear=AsyncMock(),
        )
    if router is None:
        router = MagicMock()
        router.complete = AsyncMock(
            return_value=CompletionResponse(
                content="Very good, Sir.",
                tokens_in=12,
                tokens_out=4,
                cost_usd=0.0005,
                model="deepseek-chat",
            )
        )
    if budget is None:
        budget = _make_budget()
    scope, session = _make_session_scope()
    episodic, audit = _make_episodic_audit()
    # If a test supplied a custom factory, route through it (and resolve the
    # episodic mock the test owns); otherwise wire the default shared mock so
    # assertions on m["episodic"] continue to work.
    if episodic_factory is not None:
        resolved_factory = episodic_factory
        episodic = episodic_factory(session)
    else:
        resolved_factory = lambda _s: episodic  # noqa: E731 — mock seam stays one-liner.
    # ``audit_factory`` now receives the session-scope factory (not a session).
    # The orchestrator wires the writer once at __init__ and the writer owns
    # its own per-call session. The test ignores the arg and returns the
    # shared mock so assertions can inspect calls.
    kwargs: dict[str, Any] = {
        "operator_name": operator_name,
        "operator_language": operator_language,
        "session_scope": scope,
        "working": working,
        "router": router,
        "budget": budget,
        "episodic_factory": resolved_factory,
        "audit_factory": lambda _f: audit,
    }
    if redactor is not None:
        kwargs["redactor"] = redactor
    orch = Orchestrator(**kwargs)
    return orch, {
        "working": working,
        "router": router,
        "budget": budget,
        "session": session,
        "episodic": episodic,
        "audit": audit,
    }


class TestOrchestratorHappyPath:
    async def test_records_episode_calls_provider_and_audits(self) -> None:
        orch, m = _build()
        reply = await orch.handle_user_message("Good morning, Alfred.")

        assert reply == "Very good, Sir."

        # Working memory: one append for the user turn, one for the assistant turn.
        assert m["working"].append.await_count == 2
        user_call = m["working"].append.await_args_list[0]
        assistant_call = m["working"].append.await_args_list[1]
        assert user_call.kwargs == {"role": "user", "content": "Good morning, Alfred."}
        assert assistant_call.kwargs == {"role": "assistant", "content": "Very good, Sir."}

        # Episodic: two records, both pinned to en-US.
        assert m["episodic"].record.await_count == 2
        for call in m["episodic"].record.await_args_list:
            assert call.kwargs["language"] == "en-US"
        ep_user = m["episodic"].record.await_args_list[0].kwargs
        ep_asst = m["episodic"].record.await_args_list[1].kwargs
        assert ep_user["role"] == "user"
        assert ep_user["trust_tier"] == "T2"
        assert ep_user["content"] == "Good morning, Alfred."
        assert ep_asst["role"] == "assistant"
        # ADR-0008: assistant output is T2 in Slice 1 (at-most-as-trusted as
        # the T2 input that triggered it). T0 is reserved for AlfredOS
        # internals/code/prompts/configs per PRD §7.1.
        assert ep_asst["trust_tier"] == "T2"
        assert ep_asst["tokens_in"] == 12
        assert ep_asst["tokens_out"] == 4
        assert ep_asst["cost_usd"] == pytest.approx(0.0005)

        # Provider request: first message is the system prompt; user message follows.
        req = m["router"].complete.await_args.args[0]
        assert req.messages[0].role == "system"
        assert "Sir" in req.messages[0].content
        assert "en-US" in req.messages[0].content
        # Working memory was empty, so the user message must come from this turn.
        # The orchestrator assembles via working.turns() AFTER appending the user
        # turn, so the request includes the user message.
        assert any(msg.role == "user" and "Good morning" in msg.content for msg in req.messages)

        # Budget pre-check happened; the charge succeeded.
        assert m["budget"].estimate_for.call_count == 1
        assert m["budget"].would_exceed.call_count == 1
        assert m["budget"].check_and_charge.call_count == 1
        # PR-B Phase 1: BudgetGuard.check_and_charge now keys on canonical
        # user_id; the orchestrator threads ``operator_name`` ("Sir" in
        # ``_build``'s default) as the first positional argument.
        m["budget"].check_and_charge.assert_called_with("Sir", pytest.approx(0.0005))

        # Audit: one row, success.
        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["event"] == "orchestrator.turn"
        assert audit_kwargs["result"] == "success"
        assert audit_kwargs["trust_tier_of_trigger"] == "T2"
        assert audit_kwargs["language"] == "en-US"
        assert audit_kwargs["cost_actual_usd"] == pytest.approx(0.0005)
        assert audit_kwargs["subject"]["model"] == "deepseek-chat"
        assert audit_kwargs["subject"]["charge_result"] == "success"

        # Session was not rolled back.
        m["session"].rollback.assert_not_awaited()


class TestOrchestratorBudgetBlocked:
    async def test_pre_check_refusal_audits_and_raises(self) -> None:
        budget = _make_budget(estimate=0.50, would_exceed=True)
        orch, m = _build(budget=budget)
        with pytest.raises(BudgetError):
            await orch.handle_user_message("a long request")

        # Provider must not be called.
        m["router"].complete.assert_not_awaited()
        # Charge must not be made (the call never happened).
        m["budget"].check_and_charge.assert_not_called()
        # Audit row was still written with the right result.
        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "budget_blocked"
        assert audit_kwargs["cost_estimate_usd"] == pytest.approx(0.50)
        assert audit_kwargs["cost_actual_usd"] == 0.0
        # The user-input episode was still written; the assistant one was not.
        # (We tag + record user input before the budget check so the operator's
        # words survive even if the call is refused.)
        roles = [c.kwargs["role"] for c in m["episodic"].record.await_args_list]
        assert roles == ["user"]
        # Session rolled back because we raised out of the scope.
        m["session"].rollback.assert_awaited()


class TestOrchestratorProviderFailure:
    async def test_provider_exception_is_audited_and_re_raised(self) -> None:
        router = MagicMock()
        router.complete = AsyncMock(side_effect=RuntimeError("upstream 503"))
        orch, m = _build(router=router)

        with pytest.raises(RuntimeError, match="upstream 503"):
            await orch.handle_user_message("ping?")

        # One audit row recording the failure.
        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "provider_failed"
        assert audit_kwargs["subject"]["error_type"] == "RuntimeError"
        assert "upstream 503" in audit_kwargs["subject"]["error"]
        assert audit_kwargs["cost_actual_usd"] == 0.0
        # No charge on a failed call.
        m["budget"].check_and_charge.assert_not_called()
        # Working memory got the user turn but not an assistant turn.
        assert m["working"].append.await_count == 1
        # Rollback fired on the way out.
        m["session"].rollback.assert_awaited()


class TestOrchestratorAuditFailureIsLoud:
    async def test_post_success_audit_failure_propagates(self) -> None:
        orch, m = _build()
        m["audit"].append = AsyncMock(side_effect=RuntimeError("audit table missing"))

        with pytest.raises(RuntimeError, match="audit table missing"):
            await orch.handle_user_message("hi")

        # The provider call still happened and the assistant turn was buffered.
        m["router"].complete.assert_awaited()
        assert m["working"].append.await_count == 2
        # Rollback fired because we propagated out of the session scope.
        m["session"].rollback.assert_awaited()


class TestOrchestratorBudgetOverrun:
    """Covers the post-success-but-over-cap branch: provider call succeeded,
    actual cost blew the per-call cap, so the work happened but the audit row
    records ``charge_result=budget_overrun`` and we don't re-raise."""

    async def test_charge_overrun_records_truthfully_and_does_not_raise(self) -> None:
        budget = _make_budget()
        budget.check_and_charge = MagicMock(
            side_effect=PerCallCapExceededError("cost $0.50 exceeds per-call cap $0.10")
        )
        orch, m = _build(budget=budget)

        reply = await orch.handle_user_message("expensive request")
        assert reply == "Very good, Sir."

        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "budget_overrun"
        assert audit_kwargs["subject"]["charge_result"] == "budget_overrun"
        assert audit_kwargs["cost_actual_usd"] == pytest.approx(0.0005)
        # The episode for the assistant turn still recorded the actual cost.
        assistant_call = m["episodic"].record.await_args_list[1].kwargs
        assert assistant_call["cost_usd"] == pytest.approx(0.0005)


class TestOrchestratorOperatorName:
    """The orchestrator must use the injected ``operator_name`` everywhere it
    records a user_id — not a hardcoded module-level constant. Multi-user
    landing in Slice 3 hinges on this seam.
    """

    async def test_operator_name_propagates_to_episodes_and_audit(self) -> None:
        orch, m = _build(operator_name="Bruce")
        await orch.handle_user_message("good morning")

        # Both episodes (user + assistant) carry the operator name.
        for call in m["episodic"].record.await_args_list:
            assert call.kwargs["user_id"] == "Bruce"

        # The success-path audit row carries the operator name.
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["actor_user_id"] == "Bruce"

    async def test_operator_name_propagates_on_budget_block(self) -> None:
        budget = _make_budget(estimate=0.50, would_exceed=True)
        orch, m = _build(operator_name="Bruce", budget=budget)
        with pytest.raises(BudgetError):
            await orch.handle_user_message("expensive")
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["actor_user_id"] == "Bruce"
        # User-input episode also carries the operator name.
        assert m["episodic"].record.await_args_list[0].kwargs["user_id"] == "Bruce"

    async def test_operator_name_propagates_on_provider_failure(self) -> None:
        router = MagicMock()
        router.complete = AsyncMock(side_effect=RuntimeError("upstream"))
        orch, m = _build(operator_name="Bruce", router=router)
        with pytest.raises(RuntimeError):
            await orch.handle_user_message("ping")
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["actor_user_id"] == "Bruce"


class TestOrchestratorCancellation:
    """``asyncio.CancelledError`` is a ``BaseException``, not ``Exception``.

    CLAUDE.md hard rule #7 forbids silent cancellation: every awaited step in
    the turn (working-memory append, episodic write, pre-/post-provider
    audit, provider call itself) must produce a `cancelled` audit row, not
    only cancellation that lands inside ``_router.complete``. The top-level
    ``handle_user_message`` arm is the backstop; these tests exercise three
    points of the turn (pre-provider, provider, post-provider) to prove the
    backstop fires regardless of WHERE the cancellation lands.
    """

    async def test_user_cancellation_inside_provider_call_is_audited(self) -> None:
        router = MagicMock()
        router.complete = AsyncMock(side_effect=asyncio.CancelledError())
        orch, m = _build(router=router)

        with pytest.raises(asyncio.CancelledError):
            await orch.handle_user_message("midway-cancel")

        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "cancelled"
        assert audit_kwargs["subject"]["phase"] == "turn_cancelled"
        assert audit_kwargs["cost_actual_usd"] == 0.0
        # Assistant turn never buffered (provider call was cancelled).
        assert m["working"].append.await_count == 1
        # User-content txn rolled back as part of the outer BaseException arm.
        m["session"].rollback.assert_awaited()

    async def test_cancellation_before_provider_call_is_still_audited(self) -> None:
        # Cancellation lands inside ``WorkingMemory.append`` — the FIRST
        # awaited step after T2-tagging. Pre-fix this would have skipped the
        # audit (the inner provider-call arm never executed). The top-level
        # backstop now writes the cancellation row regardless.
        working = MagicMock()
        working.append = AsyncMock(side_effect=asyncio.CancelledError())
        working.turns = AsyncMock(return_value=[])
        orch, m = _build(working=working)

        with pytest.raises(asyncio.CancelledError):
            await orch.handle_user_message("cancel-before-provider")

        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "cancelled"
        assert audit_kwargs["subject"]["phase"] == "turn_cancelled"
        # Provider was never called.
        assert m["router"].complete.await_count == 0
        m["session"].rollback.assert_awaited()

    async def test_cancellation_after_provider_call_is_still_audited(self) -> None:
        # Provider succeeded; cancellation lands during the post-provider
        # episodic write (operator hit Esc between turns). The completed
        # response is discarded — the user-content txn rolls back — but the
        # audit row still lands so the cancelled turn is visible in the trail.
        from alfred.providers.base import CompletionResponse

        response = CompletionResponse(
            content="reply", tokens_in=4, tokens_out=2, cost_usd=0.0001, model="m"
        )
        router = MagicMock()
        router.complete = AsyncMock(return_value=response)
        # First episodic.record() (user turn) succeeds; second (assistant)
        # cancels. This simulates a cancellation that arrives between the
        # successful provider call and the assistant-turn persistence.
        episodic = MagicMock()
        episodic.record = AsyncMock(side_effect=[None, asyncio.CancelledError()])

        def _episodic_factory(_session: object) -> MagicMock:
            return episodic

        orch, m = _build(router=router, episodic_factory=_episodic_factory)

        with pytest.raises(asyncio.CancelledError):
            await orch.handle_user_message("cancel-after-provider")

        # Only the cancellation-audit row should have landed; the post-provider
        # success-audit never executed because cancellation interrupted first.
        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "cancelled"
        assert audit_kwargs["subject"]["phase"] == "turn_cancelled"
        m["session"].rollback.assert_awaited()


class TestOrchestratorRedactsAuditSubject:
    """Provider SDK exceptions stringify with URLs / Authorization headers /
    API keys. The redactor must run over every str value in the audit subject
    so secrets never reach the audit log.
    """

    async def test_provider_failure_subject_is_redacted(self) -> None:
        router = MagicMock()
        router.complete = AsyncMock(
            side_effect=RuntimeError(
                "401 Unauthorized for https://api.example.com (Authorization: Bearer sk-LEAKED)"
            )
        )
        # Redactor that scrubs the canary string.
        orch, m = _build(
            router=router,
            redactor=lambda s: s.replace("sk-LEAKED", "[REDACTED]"),
        )

        with pytest.raises(RuntimeError):
            await orch.handle_user_message("hi")

        audit_kwargs = m["audit"].append.await_args.kwargs
        assert "sk-LEAKED" not in audit_kwargs["subject"]["error"]
        assert "[REDACTED]" in audit_kwargs["subject"]["error"]
