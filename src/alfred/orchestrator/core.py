"""Slice-2 PR-B per-user OODA orchestrator.

Glues the existing subsystems — security tagging, working memory, episodic
memory, provider router, budget guard, audit writer — into one stateless-
per-turn function. PR-B reshapes the slice-1 single-operator orchestrator:

* The household operator is resolved ONCE at construction via
  ``IdentityResolverLike.get_operator()`` and cached for the orchestrator's
  lifetime. Re-resolving every turn would let a mid-flight operator demotion
  silently swap identity inside an open turn — and would also undo PR-A's
  single-DB-hit-per-start contract.
* ``handle_user_message`` takes a per-turn ``user`` value object (the
  requesting user — may or may not be the operator), a pre-tagged
  ``TaggedContent[T2]`` content (the adapter tagged it, not the orchestrator),
  and a pool-acquired ``WorkingMemory`` (the WorkingMemoryPool owns the
  buffer's lifecycle — the orchestrator is a borrower).
* Every per-row write threads ``user.slug`` (audit ``actor_user_id`` /
  episodic ``user_id`` / budget ``user_id``), ``user.language``, and the
  literal persona ``"alfred"`` so per-row attribution survives multi-user
  Slice-2 onwards.

Flow per turn:
    Observe → buffer the (already-T2) input in working memory, write user
              episode.
    Orient  → render the persona prompt with the operator's display_name,
              the requesting user's display_name, and the requester's
              language. Assemble the message list (system + history).
    Decide  → estimate cost FOR the requesting user, refuse loudly if it
              would breach their per-user budget.
    Act     → call the provider; on success charge the requester's budget,
              buffer assistant turn, write assistant episode, write audit.
              On failure, audit the failure and re-raise. On post-success
              cap overrun, record the truthful cost and the
              ``budget_overrun`` result but do NOT raise (the work
              happened). On user cancellation, audit ``result="cancelled"``
              and re-raise so the cancellation signal propagates.

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

7-branch audit enumeration (spec §5 line 792 — PR-B adds the 7th):
    1. ``result="success"`` (happy path)
    2. ``result="budget_blocked"`` (pre-check refusal)
    3. ``result="provider_failed"`` (router raises)
    4. ``result="budget_overrun"`` (post-success per-call cap exceeded)
    5. ``result="cancelled"`` (cancellation backstop — inner provider arm)
    6. ``result="cancelled"`` (cancellation backstop — outer arm, before provider)
    7. **NEW for PR B:** ``result="unknown_budget_user"`` —
       ``UnknownBudgetUserError`` from ``BudgetGuard``, defense-in-depth audit
       on a slug the resolver should have caught upstream. Subject carries
       ``phase="budget_pre_check"`` or ``"budget_post_charge"`` depending on
       which call raised. The error is re-raised so the adapter (TUI / Discord)
       can surface a generic error to the user.

CLAUDE.md hard rules honoured here:
    #1  exception strings are run through the redactor before they enter the
        audit subject — provider SDK exceptions stringify with URLs, headers
        and sometimes API keys.
    #3  external input arrives ALREADY T2-tagged (adapter is the boundary in
        PR-B; the orchestrator only reads the tier off the value).
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
from typing import TYPE_CHECKING, Any, Protocol

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetError, BudgetGuard, UnknownBudgetUserError
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working import WorkingMemory
from alfred.personas.alfred import ALFRED_PERSONA, render_persona_prompt
from alfred.providers.base import CompletionRequest, Message
from alfred.providers.router import ProviderRouter
from alfred.security.tiers import T2, TaggedContent

if TYPE_CHECKING:
    from alfred.identity.models import User

_log = structlog.get_logger(__name__)

# Slice-2 per-row persona attribution. Migration 0004 added the column on
# ``episodes`` + ``audit_log`` as nullable. Slice-1+2 is single-persona —
# every write is Alfred — so the orchestrator pins the literal here. Slice 5's
# persona registry replaces this with a per-turn lookup against the persona
# manifest in ``/var/lib/alfred/state.git/personas/``.
_ALFRED_PERSONA_ID = "alfred"


class UserLike(Protocol):
    """Structural type for the per-turn requester + the cached operator.

    The orchestrator reads exactly three fields off each user — ``slug``,
    ``display_name``, ``language`` — and never mutates them. A Protocol
    keeps the type signature decoupled from
    :class:`alfred.identity.models.User` (the SQLAlchemy ORM) so unit tests
    can pass frozen dataclasses and integration tests can pass real ORM
    instances without an adapter layer.

    All three fields are read-only properties on the ORM (mapped columns
    that the orchestrator never writes). Pinning them as plain attributes
    here is the structural minimum a Protocol can express.
    """

    # Protocol bodies need *some* body; ``raise NotImplementedError`` is
    # preferred over ``...`` so accidental instantiation fails loudly and
    # CodeQL's py/ineffectual-statement does not flag the ellipsis. Pattern
    # carried over from :class:`alfred.identity.rate_limit.RateLimiter`.
    @property
    def slug(self) -> str:
        raise NotImplementedError

    @property
    def display_name(self) -> str:
        raise NotImplementedError

    @property
    def language(self) -> str:
        raise NotImplementedError


class IdentityResolverLike(Protocol):
    """Structural type for the resolver dependency.

    The orchestrator only ever calls :meth:`get_operator` — exactly once,
    at construction. The Protocol exposes that single method so the
    constructor signature stays narrow and tests can pass a one-method
    stub. The full :class:`alfred.identity.resolver.IdentityResolver` ORM
    instance satisfies the Protocol structurally.
    """

    def get_operator(self) -> User:
        raise NotImplementedError


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
    """Stateless-per-turn OODA dispatch for Slice-2 PR-B multi-user.

    The constructor captures the household operator identity once (via
    :class:`IdentityResolverLike`) and caches it; per-turn requester
    identity arrives on :meth:`handle_user_message`. The orchestrator no
    longer holds a :class:`WorkingMemory` — the pool owns the buffer; the
    adapter (CLI / TUI / Discord) acquires + releases around each turn.
    """

    def __init__(
        self,
        *,
        identity_resolver: IdentityResolverLike,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
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
        # Resolve the operator exactly once, here. Caching for the
        # orchestrator's lifetime is load-bearing: re-resolving each turn
        # would let an in-flight operator demotion swap identity mid-turn
        # AND would undo PR-A's single-DB-hit-per-start contract. If the
        # operator role changes at runtime, the supervising process
        # rebuilds the orchestrator.
        self._operator: User = identity_resolver.get_operator()
        self._session_scope = session_scope
        self._router = router
        self._budget = budget
        self._episodic_factory = episodic_factory
        self._audit_factory = audit_factory
        self._redactor = redactor
        # Audit writer is built once from the session_scope factory — it
        # opens its own session per `.append()` and is independent of the
        # per-turn user-content transaction below.
        self._audit = self._audit_factory(self._session_scope)

    async def handle_user_message(
        self,
        *,
        user: UserLike,
        content: TaggedContent[T2],
        working_memory: WorkingMemory,
    ) -> str:
        """Process one user turn end-to-end and return the assistant reply.

        ``user`` is the per-turn requester (may be the operator or any other
        authorized household user). ``content`` is already T2-tagged by the
        adapter — the orchestrator reads ``content.content`` and
        ``content.tier.name`` but does not re-tag. ``working_memory`` is the
        pool-acquired buffer for this (persona, user.slug) pair; the adapter
        owns its lifecycle (acquire before, release in finally).

        Raises:
            BudgetError: pre-check refusal — or, for the 7th audit branch,
                ``UnknownBudgetUserError`` (defense-in-depth on a slug the
                resolver should have caught upstream).
            Exception: re-raises the provider's exception if both providers
                in the router fail.
            asyncio.CancelledError: re-raised after auditing on user cancel.
            Exception: re-raises the audit writer's exception if persistence
                breaks after a successful provider call (CLAUDE.md hard
                rule #7).
        """
        trace_id = str(uuid.uuid4())
        async with self._session_scope() as session:
            try:
                return await self._handle_turn(
                    session,
                    user=user,
                    content=content,
                    working_memory=working_memory,
                    trace_id=trace_id,
                )
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
                await self._audit_cancellation(user=user, trace_id=trace_id, phase="turn_cancelled")
                await session.rollback()
                raise
            except BaseException:
                # Catches KeyboardInterrupt, SystemExit (BaseException but not
                # asyncio.CancelledError, which is handled above) so the
                # user-content session is always rolled back on any abnormal
                # exit. Re-raises immediately to propagate the shutdown signal.
                await session.rollback()
                raise

    async def _audit_cancellation(self, *, user: UserLike, trace_id: str, phase: str) -> None:
        """Best-effort audit write for a user-cancelled turn.

        Wrapped in its own try/except because the audit row matters more than
        the cancellation propagation: if the audit write itself raises, we
        log loudly (CLAUDE.md hard rule #7) but do NOT mask the original
        CancelledError that triggered us.
        """
        try:
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject({"phase": phase}, self._redactor),
                # Cancellation can land before any tagging step has executed
                # on this orchestrator's input path, so we don't have a tier
                # object to read from — the input that triggered the turn
                # was always going to be T2 (the adapter tagged it before
                # calling us), so pin it explicitly.
                trust_tier_of_trigger="T2",
                result="cancelled",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=trace_id,
                language=user.language,
                persona_id=_ALFRED_PERSONA_ID,
            )
        except Exception as audit_exc:
            _log.error(
                "orchestrator.cancellation_audit_failed",
                trace_id=trace_id,
                error=self._redactor(str(audit_exc)),
                error_type=type(audit_exc).__name__,
            )

    async def _handle_turn(
        self,
        session: AsyncSession,
        *,
        user: UserLike,
        content: TaggedContent[T2],
        working_memory: WorkingMemory,
        trace_id: str,
    ) -> str:
        # ``trace_id`` is supplied by ``handle_user_message`` so the top-level
        # cancellation-audit row and the per-phase audit rows share the same
        # trace identifier — without this they'd be different UUIDs and the
        # audit reader couldn't stitch the cancelled turn together.
        episodic = self._episodic_factory(session)

        # ------------------------------------------------------------------
        # Observe — the adapter already T2-tagged ``content``; read off the
        # tier name for downstream rows but do not re-tag.
        # ------------------------------------------------------------------
        user_input_text = content.content
        user_input_tier = content.tier.name
        await working_memory.append(role="user", content=user_input_text)
        await episodic.record(
            user_id=user.slug,
            role="user",
            content=user_input_text,
            trust_tier=user_input_tier,
            language=user.language,
            persona=_ALFRED_PERSONA_ID,
            # Slice-2 per-row attribution: ``persona`` is the legacy text
            # column (kept for downstream analytics already reading it);
            # ``persona_id`` is the new migration-0004 column the audit
            # graph joins on. Both must be set on every write so a Slice 5+
            # multi-persona deployment doesn't end up with NULL persona_id
            # rows on its Slice-1+2 history.
            persona_id=_ALFRED_PERSONA_ID,
        )

        # ------------------------------------------------------------------
        # Orient — operator_name is the household OWNER (cached at
        # construction); addressed_user_name is the per-turn requester.
        # Mixing them up is the entire reason PR-B introduced two fields.
        # ------------------------------------------------------------------
        system_prompt = render_persona_prompt(
            persona=ALFRED_PERSONA,
            operator_name=self._operator.display_name,
            requesting_user_name=user.display_name,
            language=user.language,
        )
        history = await working_memory.turns()
        messages: list[Message] = [Message(role="system", content=system_prompt)]
        messages.extend(Message(role=turn.role, content=turn.content) for turn in history)
        request = CompletionRequest(messages=messages)

        # ------------------------------------------------------------------
        # Decide — budget calls are keyed on the REQUESTING user's slug.
        # The 7th audit branch (``unknown_budget_user``) surfaces if the
        # guard rejects a slug the resolver should have caught upstream:
        # the BudgetError except arm discriminates on isinstance and writes
        # a distinct audit row for that path.
        # ------------------------------------------------------------------
        try:
            estimate = self._budget.estimate_for(user.slug, request)
            would_exceed = self._budget.would_exceed(user.slug, estimate)
        except BudgetError as exc:
            # Defense-in-depth: the resolver is supposed to have rejected
            # an unknown slug long before it reaches the guard. If we land
            # here, surface it as the 7th audit branch and re-raise so the
            # adapter can show a generic error to the user.
            if isinstance(exc, UnknownBudgetUserError):
                await self._audit_unknown_budget_user(
                    user=user,
                    trace_id=trace_id,
                    phase="budget_pre_check",
                    trigger_tier=user_input_tier,
                )
                raise
            # Any other BudgetError on the pre-check path is structurally
            # impossible today (would_exceed/estimate_for don't raise the
            # other budget errors), but re-raise defensively rather than
            # silently swallowing.
            raise

        if would_exceed:
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject(
                    {"phase": "budget_pre_check", "estimate_usd": estimate},
                    self._redactor,
                ),
                trust_tier_of_trigger=user_input_tier,
                result="budget_blocked",
                cost_estimate_usd=estimate,
                cost_actual_usd=0.0,
                trace_id=trace_id,
                language=user.language,
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
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject(
                    {
                        "phase": "provider_call",
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                    self._redactor,
                ),
                trust_tier_of_trigger=user_input_tier,
                result="provider_failed",
                cost_estimate_usd=estimate,
                cost_actual_usd=0.0,
                trace_id=trace_id,
                language=user.language,
                persona_id=_ALFRED_PERSONA_ID,
            )
            raise

        # Charge the actual cost. If it busts the cap, the work has already
        # happened — record truthfully, log loudly, do not raise (except for
        # the 7th branch's UnknownBudgetUserError, which IS re-raised after
        # auditing because a phantom slug post-success indicates a partial-
        # state bug worth surfacing to the adapter).
        charge_result = "success"
        try:
            self._budget.check_and_charge(user.slug, response.cost_usd)
        except BudgetError as exc:
            if isinstance(exc, UnknownBudgetUserError):
                await self._audit_unknown_budget_user(
                    user=user,
                    trace_id=trace_id,
                    phase="budget_post_charge",
                    trigger_tier=user_input_tier,
                )
                raise
            charge_result = "budget_overrun"
            _log.warning(
                "orchestrator.budget_overrun",
                trace_id=trace_id,
                estimate_usd=estimate,
                actual_usd=response.cost_usd,
                error=self._redactor(str(exc)),
            )

        # ADR-0008: assistant output is T2 in Slice 1+2 (at-most-as-trusted as
        # the T2 input that triggered it). T0 is reserved for AlfredOS
        # internals/code/prompts/configs per PRD §7.1. Slice 2's dual-LLM
        # split refines provider output to T1 and introduces T3.
        await working_memory.append(role="assistant", content=response.content)
        await episodic.record(
            user_id=user.slug,
            role="assistant",
            content=response.content,
            trust_tier="T2",
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            cost_usd=response.cost_usd,
            language=user.language,
            persona=_ALFRED_PERSONA_ID,
            # See the user-turn ``episodic.record`` call above for the
            # ``persona`` vs ``persona_id`` split rationale.
            persona_id=_ALFRED_PERSONA_ID,
        )

        try:
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
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
                trust_tier_of_trigger=user_input_tier,
                result=charge_result if charge_result == "budget_overrun" else "success",
                cost_estimate_usd=estimate,
                cost_actual_usd=response.cost_usd,
                trace_id=trace_id,
                language=user.language,
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

    async def _audit_unknown_budget_user(
        self,
        *,
        user: UserLike,
        trace_id: str,
        phase: str,
        trigger_tier: str,
    ) -> None:
        """Write the 7th audit branch row for ``UnknownBudgetUserError``.

        ``phase`` is one of ``"budget_pre_check"`` / ``"budget_post_charge"``
        so the audit reader can tell whether the provider call had already
        executed (post-charge => provider succeeded; pre-check => no spend).
        """
        await self._audit.append(
            event="orchestrator.turn",
            actor_user_id=user.slug,
            actor_persona=_ALFRED_PERSONA_ID,
            subject=_sanitize_subject({"phase": phase}, self._redactor),
            trust_tier_of_trigger=trigger_tier,
            result="unknown_budget_user",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=trace_id,
            language=user.language,
            persona_id=_ALFRED_PERSONA_ID,
        )
