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
              (the work happened). On user cancellation, audit
              ``result="cancelled"`` and re-raise so the cancellation signal
              propagates.

Session lifecycle: a per-turn ``session_scope`` is opened around the whole
turn so episodic + user-content writes share a transaction. The scope context
manager is responsible for commit on clean exit; we explicitly rollback on
any propagating exception. This keeps the orchestrator decoupled from the
session-factory's commit/rollback policy (real DB vs. testcontainers vs.
in-memory mock).

**Audit writes live OUTSIDE that transaction.** ``AuditWriter`` takes its own
``session_factory`` and opens a fresh session per ``.append()``. Otherwise a
failing turn (provider error, budget block, cancellation) would rollback the
audit row alongside the user-content row, violating CLAUDE.md hard rule #7
(no silent failures in security paths).

CLAUDE.md hard rules honoured here:
    #1  exception strings are run through the redactor before they enter the
        audit subject — provider SDK exceptions stringify with URLs, headers
        and sometimes API keys.
    #3  external input is ``tag()``-ed at the boundary (user_input → T2)
    #7  audit-write failures are LOUD — logged at error and re-raised; audit
        rows survive caller-transaction rollback (own session_factory).
    i18n#3 every persisted user-content row carries ``language``

ADR-0008: assistant output is tagged T2 in Slice 1 (at-most-as-trusted-as
the T2 input that triggered it), not T0. Slice 2's dual-LLM split refines
provider output to T1 (operator-trust) and introduces T3 (untrusted).
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetError, BudgetGuard
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working import WorkingMemory
from alfred.personas.alfred import render_persona_prompt
from alfred.providers.base import CompletionRequest, Message
from alfred.providers.router import ProviderRouter
from alfred.security.tiers import T2, tag

_log = structlog.get_logger(__name__)

# Slice-2 per-row persona attribution (migration 0004 added the column on
# ``episodes`` + ``audit_log`` as nullable). Slice-1 is single-persona —
# every write is Alfred — so the orchestrator pins the literal here rather
# than threading another constructor kwarg through every test. Slice 5's
# persona registry replaces this with a per-turn lookup.
_ALFRED_PERSONA_ID = "alfred"


def _sanitize_subject(subject: dict[str, Any], redactor: Callable[[str], str]) -> dict[str, Any]:
    """Run every str value (recursively) through ``redactor``.

    Provider SDK exceptions stringify with URLs, Authorization headers, and
    occasionally API keys. The audit row's ``subject`` is JSONB so values can
    nest arbitrarily; walk the structure rather than relying on callers to
    redact field-by-field.

    Bounded recursion: only descends through ``dict`` and ``list``. Other
    types pass through untouched — we never reach into an object's
    ``__dict__`` and risk triggering ``__repr__`` side effects.
    """

    def _walk(value: Any) -> Any:
        if isinstance(value, str):
            return redactor(value)
        if isinstance(value, dict):
            return {k: _walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_walk(v) for v in value]
        return value

    return {k: _walk(v) for k, v in subject.items()}


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
        audit_factory: Callable[
            [Callable[[], AbstractAsyncContextManager[AsyncSession]]], AuditWriter
        ] = lambda f: AuditWriter(session_factory=f),
        redactor: Callable[[str], str] = lambda s: s,
    ) -> None:
        self._operator_name = operator_name
        self._operator_language = operator_language
        self._session_scope = session_scope
        self._working = working
        self._router = router
        self._budget = budget
        self._episodic_factory = episodic_factory
        self._audit_factory = audit_factory
        self._redactor = redactor
        # Audit writer is built once from the session_scope factory — it
        # opens its own session per `.append()` and is independent of the
        # per-turn user-content transaction below.
        self._audit = self._audit_factory(self._session_scope)

    async def handle_user_message(self, content: str) -> str:
        """Process one user turn end-to-end and return the assistant reply.

        Raises ``BudgetError`` if the pre-check refuses the call; re-raises the
        provider's exception if both providers in the router fail; re-raises
        ``asyncio.CancelledError`` after auditing on user cancellation;
        re-raises the audit writer's exception if persistence breaks after a
        successful provider call (CLAUDE.md hard rule #7).
        """
        trace_id = str(uuid.uuid4())
        async with self._session_scope() as session:
            try:
                return await self._handle_turn(session, content, trace_id=trace_id)
            except asyncio.CancelledError:
                # CLAUDE.md hard rule #7: cancellation at ANY awaited step in
                # the turn (working-memory append, episodic write, pre-/post-
                # provider audit) MUST write a `cancelled` audit row — not
                # only cancellation that lands inside `_router.complete`.
                # The inner provider-call branch (see `_handle_turn`) already
                # audits-and-re-raises for the common case; this top-level arm
                # is the backstop that catches any re-raised CancelledError
                # (and any cancellation that lands elsewhere). Tagged with a
                # distinct phase so the audit reader can tell the two apart.
                await self._audit_cancellation(trace_id=trace_id, phase="turn_cancelled")
                await session.rollback()
                raise
            except BaseException:
                # Catches KeyboardInterrupt, SystemExit (BaseException but not
                # asyncio.CancelledError, which is handled above) so the
                # user-content session is always rolled back on any abnormal
                # exit. Re-raises immediately to propagate the shutdown signal.
                await session.rollback()
                raise

    async def _audit_cancellation(self, *, trace_id: str, phase: str) -> None:
        """Best-effort audit write for a user-cancelled turn.

        Wrapped in its own try/except because the audit row matters more than
        the cancellation propagation: if the audit write itself raises, we
        log loudly (CLAUDE.md hard rule #7) but do NOT mask the original
        CancelledError that triggered us.
        """
        try:
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=self._operator_name,
                subject=_sanitize_subject({"phase": phase}, self._redactor),
                # Cancellation can land before the user-input tagging step has
                # executed, so we don't have a tier object to read from — the
                # input we never finished processing was always going to be
                # T2 (per the boundary at the top of `_handle_turn`), so pin
                # it explicitly.
                trust_tier_of_trigger="T2",
                result="cancelled",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=trace_id,
                language=self._operator_language,
                persona_id=_ALFRED_PERSONA_ID,
            )
        except Exception as audit_exc:
            _log.error(
                "orchestrator.cancellation_audit_failed",
                trace_id=trace_id,
                error=self._redactor(str(audit_exc)),
                error_type=type(audit_exc).__name__,
            )

    async def _handle_turn(self, session: AsyncSession, content: str, *, trace_id: str) -> str:
        # ``trace_id`` is supplied by ``handle_user_message`` so the top-level
        # cancellation-audit row and the per-phase audit rows share the same
        # trace identifier — without this they'd be different UUIDs and the
        # audit reader couldn't stitch the cancelled turn together.
        episodic = self._episodic_factory(session)

        # ------------------------------------------------------------------
        # Observe
        # ------------------------------------------------------------------
        user_input = tag(T2, content, source="orchestrator.user_input")
        await self._working.append(role="user", content=user_input.content)
        await episodic.record(
            user_id=self._operator_name,
            role="user",
            content=user_input.content,
            trust_tier=user_input.tier.name,
            language=self._operator_language,
            persona_id=_ALFRED_PERSONA_ID,
        )

        # ------------------------------------------------------------------
        # Orient
        # ------------------------------------------------------------------
        system_prompt = render_persona_prompt(
            operator_name=self._operator_name,
            requesting_user_name=self._operator_name,
            language=self._operator_language,
        )
        history = await self._working.turns()
        messages: list[Message] = [Message(role="system", content=system_prompt)]
        messages.extend(Message(role=turn.role, content=turn.content) for turn in history)
        request = CompletionRequest(messages=messages)

        # ------------------------------------------------------------------
        # Decide
        # ------------------------------------------------------------------
        # PR-B Phase 1: BudgetGuard now keys on canonical ``user_id``.
        # Slice-2 single-operator path threads ``self._operator_name`` (the
        # operator's slug) here; Phase 4 generalises to multi-user once the
        # orchestrator carries the per-turn requester identity.
        estimate = self._budget.estimate_for(self._operator_name, request)
        if self._budget.would_exceed(self._operator_name, estimate):
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=self._operator_name,
                subject=_sanitize_subject(
                    {"phase": "budget_pre_check", "estimate_usd": estimate},
                    self._redactor,
                ),
                trust_tier_of_trigger=user_input.tier.name,
                result="budget_blocked",
                cost_estimate_usd=estimate,
                cost_actual_usd=0.0,
                trace_id=trace_id,
                language=self._operator_language,
                persona_id=_ALFRED_PERSONA_ID,
            )
            raise BudgetError(f"pre-check refused: estimate ${estimate:.4f} would breach budget")

        # ------------------------------------------------------------------
        # Act
        # ------------------------------------------------------------------
        # Note: asyncio.CancelledError is NOT caught here — it propagates to
        # the top-level `handle_user_message` arm so a single backstop audits
        # cancellation at any awaited step in the turn (CLAUDE.md hard rule
        # #7). Auditing here would double-write when cancellation lands
        # inside the provider call.
        try:
            response = await self._router.complete(request)
        except Exception as exc:
            _log.error(
                "orchestrator.provider_failed",
                trace_id=trace_id,
                error=self._redactor(str(exc)),
                error_type=type(exc).__name__,
            )
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=self._operator_name,
                subject=_sanitize_subject(
                    {
                        "phase": "provider_call",
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                    self._redactor,
                ),
                trust_tier_of_trigger=user_input.tier.name,
                result="provider_failed",
                cost_estimate_usd=estimate,
                cost_actual_usd=0.0,
                trace_id=trace_id,
                language=self._operator_language,
                persona_id=_ALFRED_PERSONA_ID,
            )
            raise

        # Charge the actual cost. If it busts the cap, the work has already
        # happened — record truthfully, log loudly, do not raise.
        charge_result = "success"
        try:
            self._budget.check_and_charge(self._operator_name, response.cost_usd)
        except BudgetError as exc:
            charge_result = "budget_overrun"
            _log.warning(
                "orchestrator.budget_overrun",
                trace_id=trace_id,
                estimate_usd=estimate,
                actual_usd=response.cost_usd,
                error=self._redactor(str(exc)),
            )

        # ADR-0008: assistant output is T2 in Slice 1 (at-most-as-trusted as
        # the T2 input that triggered it). T0 is reserved for AlfredOS
        # internals/code/prompts/configs per PRD §7.1. Slice 2's dual-LLM
        # split refines provider output to T1 and introduces T3.
        assistant_output = tag(T2, response.content, source=f"provider.{response.model}")
        await self._working.append(role="assistant", content=assistant_output.content)
        await episodic.record(
            user_id=self._operator_name,
            role="assistant",
            content=assistant_output.content,
            trust_tier=assistant_output.tier.name,
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            cost_usd=response.cost_usd,
            language=self._operator_language,
            persona_id=_ALFRED_PERSONA_ID,
        )

        try:
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=self._operator_name,
                subject=_sanitize_subject(
                    {
                        "phase": "completed",
                        "model": response.model,
                        "tokens_in": response.tokens_in,
                        "tokens_out": response.tokens_out,
                        "charge_result": charge_result,
                    },
                    self._redactor,
                ),
                trust_tier_of_trigger=user_input.tier.name,
                result=charge_result if charge_result == "budget_overrun" else "success",
                cost_estimate_usd=estimate,
                cost_actual_usd=response.cost_usd,
                trace_id=trace_id,
                language=self._operator_language,
                persona_id=_ALFRED_PERSONA_ID,
            )
        except Exception as exc:
            # CLAUDE.md hard rule #7: audit-path failures are loud.
            _log.error(
                "orchestrator.audit_write_failed",
                trace_id=trace_id,
                error=self._redactor(str(exc)),
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
