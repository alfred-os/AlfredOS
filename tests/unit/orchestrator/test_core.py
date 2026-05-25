"""Tests for the Slice-1 slim OODA orchestrator.

Spec: docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md (Task 13),
with the spec-bug fixes from the parent agent's task brief baked in
(WorkingMemory is async per ADR-0002; constructor kwargs are keyword-only;
``source=`` is passed at every ``tag()`` site; etc.).
"""

from __future__ import annotations

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
    orch = Orchestrator(
        operator_name=operator_name,
        operator_language=operator_language,
        session_scope=scope,
        working=working,
        router=router,
        budget=budget,
        episodic_factory=lambda _s: episodic,
        audit_factory=lambda _s: audit,
    )
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
        assert ep_asst["trust_tier"] == "T0"
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
        m["budget"].check_and_charge.assert_called_with(pytest.approx(0.0005))

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
