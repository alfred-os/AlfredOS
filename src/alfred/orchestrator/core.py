"""Slice-1 slim OODA orchestrator.

Glues the existing subsystems — security tagging, working memory, episodic
memory, provider router, budget guard, audit writer — into one turn-handling
function.

Flow per turn:
    Observe → tag user input T2, buffer in working memory, write user episode.
    Orient  → build Alfred's system prompt + the message list (system + history).
    Decide  → estimate cost, refuse loudly if it would breach budget.
    Act     → call the provider; on success charge budget, buffer assistant
              turn, write assistant episode, write audit. On failure, audit the
              failure and re-raise. On post-success cap overrun, record the
              truthful cost and the ``budget_overrun`` result but do NOT raise
              (the work happened).

Session lifecycle: a per-turn ``session_scope`` is opened around the whole
turn so episodic + audit writes share a transaction. The scope context
manager is responsible for commit on clean exit; we explicitly rollback on
any propagating exception. This keeps the orchestrator decoupled from the
session-factory's commit/rollback policy (real DB vs. testcontainers vs.
in-memory mock).

CLAUDE.md hard rules honoured here:
    #3  external input is ``tag()``-ed at the boundary (user_input → T2)
    #7  audit-write failures are LOUD — logged at error and re-raised
    i18n#3 every persisted user-content row carries ``language``
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetError, BudgetGuard
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working import WorkingMemory
from alfred.personas.alfred import alfred_system_prompt
from alfred.providers.base import CompletionRequest, Message
from alfred.providers.router import ProviderRouter
from alfred.security.tiers import T0, T2, tag

_log = structlog.get_logger(__name__)

_USER_ID = "operator"  # Slice 1 is single-user; multi-user lands in Slice 3.


class Orchestrator:
    """Single-turn OODA dispatch for the Slice-1 single-operator case."""

    def __init__(
        self,
        *,
        operator_name: str,
        operator_language: str,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
        working: WorkingMemory,
        router: ProviderRouter,
        budget: BudgetGuard,
        episodic_factory: Callable[[AsyncSession], EpisodicMemory] = lambda s: EpisodicMemory(
            session=s
        ),
        audit_factory: Callable[[AsyncSession], AuditWriter] = lambda s: AuditWriter(session=s),
    ) -> None:
        self._operator_name = operator_name
        self._operator_language = operator_language
        self._session_scope = session_scope
        self._working = working
        self._router = router
        self._budget = budget
        self._episodic_factory = episodic_factory
        self._audit_factory = audit_factory

    async def handle_user_message(self, content: str) -> str:
        """Process one user turn end-to-end and return the assistant reply.

        Raises ``BudgetError`` if the pre-check refuses the call; re-raises the
        provider's exception if both providers in the router fail; re-raises
        the audit writer's exception if persistence breaks after a successful
        provider call (CLAUDE.md hard rule #7).
        """
        async with self._session_scope() as session:
            try:
                return await self._handle_turn(session, content)
            except BaseException:
                await session.rollback()
                raise

    async def _handle_turn(self, session: AsyncSession, content: str) -> str:
        trace_id = str(uuid.uuid4())
        episodic = self._episodic_factory(session)
        audit = self._audit_factory(session)

        # ------------------------------------------------------------------
        # Observe
        # ------------------------------------------------------------------
        user_input = tag(T2, content, source="orchestrator.user_input")
        await self._working.append(role="user", content=user_input.content)
        await episodic.record(
            user_id=_USER_ID,
            role="user",
            content=user_input.content,
            trust_tier=user_input.tier.name,
            language=self._operator_language,
        )

        # ------------------------------------------------------------------
        # Orient
        # ------------------------------------------------------------------
        system_prompt = alfred_system_prompt(
            operator_name=self._operator_name,
            language=self._operator_language,
        )
        history = await self._working.turns()
        messages: list[Message] = [Message(role="system", content=system_prompt)]
        messages.extend(Message(role=turn.role, content=turn.content) for turn in history)
        request = CompletionRequest(messages=messages)

        # ------------------------------------------------------------------
        # Decide
        # ------------------------------------------------------------------
        estimate = self._budget.estimate_for(request)
        if self._budget.would_exceed(estimate):
            await audit.append(
                event="orchestrator.turn",
                actor_user_id=_USER_ID,
                subject={"phase": "budget_pre_check", "estimate_usd": estimate},
                trust_tier_of_trigger=user_input.tier.name,
                result="budget_blocked",
                cost_estimate_usd=estimate,
                cost_actual_usd=0.0,
                trace_id=trace_id,
                language=self._operator_language,
            )
            raise BudgetError(f"pre-check refused: estimate ${estimate:.4f} would breach budget")

        # ------------------------------------------------------------------
        # Act
        # ------------------------------------------------------------------
        try:
            response = await self._router.complete(request)
        except Exception as exc:
            _log.error(
                "orchestrator.provider_failed",
                trace_id=trace_id,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            await audit.append(
                event="orchestrator.turn",
                actor_user_id=_USER_ID,
                subject={
                    "phase": "provider_call",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
                trust_tier_of_trigger=user_input.tier.name,
                result="provider_failed",
                cost_estimate_usd=estimate,
                cost_actual_usd=0.0,
                trace_id=trace_id,
                language=self._operator_language,
            )
            raise

        # Charge the actual cost. If it busts the cap, the work has already
        # happened — record truthfully, log loudly, do not raise.
        charge_result = "success"
        try:
            self._budget.check_and_charge(response.cost_usd)
        except BudgetError as exc:
            charge_result = "budget_overrun"
            _log.warning(
                "orchestrator.budget_overrun",
                trace_id=trace_id,
                estimate_usd=estimate,
                actual_usd=response.cost_usd,
                error=str(exc),
            )

        assistant_output = tag(T0, response.content, source=f"provider.{response.model}")
        await self._working.append(role="assistant", content=assistant_output.content)
        await episodic.record(
            user_id=_USER_ID,
            role="assistant",
            content=assistant_output.content,
            trust_tier=assistant_output.tier.name,
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            cost_usd=response.cost_usd,
            language=self._operator_language,
        )

        try:
            await audit.append(
                event="orchestrator.turn",
                actor_user_id=_USER_ID,
                subject={
                    "phase": "completed",
                    "model": response.model,
                    "tokens_in": response.tokens_in,
                    "tokens_out": response.tokens_out,
                    "charge_result": charge_result,
                },
                trust_tier_of_trigger=user_input.tier.name,
                result=charge_result if charge_result == "budget_overrun" else "success",
                cost_estimate_usd=estimate,
                cost_actual_usd=response.cost_usd,
                trace_id=trace_id,
                language=self._operator_language,
            )
        except Exception as exc:
            # CLAUDE.md hard rule #7: audit-path failures are loud.
            _log.error(
                "orchestrator.audit_write_failed",
                trace_id=trace_id,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise

        _log.info(
            "orchestrator.turn",
            trace_id=trace_id,
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            cost_usd=response.cost_usd,
            charge_result=charge_result,
        )
        return response.content
