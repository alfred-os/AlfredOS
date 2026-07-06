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
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.audit.audit_row_schemas import SUPERVISOR_ACTION_TIMEOUT_FIELDS
from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetError, BudgetGuard, UnknownBudgetUserError
from alfred.comms_mcp import observability as comms_observability
from alfred.egress.egress_id import TurnEgressContext
from alfred.i18n import t
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working import WorkingMemory
from alfred.orchestrator import loop_constants
from alfred.personas.alfred import ALFRED_PERSONA, render_persona_prompt
from alfred.providers.base import CompletionRequest, CompletionResponse, Message
from alfred.providers.router import ProviderRouter
from alfred.security.tiers import T1, T2, TaggedContent
from alfred.supervisor.breaker import invoke_supervisor_action_timeout_hookpoint
from alfred.supervisor.deadline import DeadlineWrapper
from alfred.supervisor.observability import record_action_duration

if TYPE_CHECKING:
    from alfred.hooks.capability import CapabilityGate
    from alfred.identity.models import User
    from alfred.orchestrator.tool_registry import ToolRegistry
    from alfred.security.dlp import OutboundDlpProtocol
    from alfred.security.quarantine import ExtractionResult

_log = structlog.get_logger(__name__)


@runtime_checkable
class QuarantinedExtractorLike(Protocol):
    """Structural type for the orchestrator-side quarantined-extract funnel.

    The :meth:`Orchestrator.quarantined_extract` wrapper enforces the
    ``source_tier == "T3"`` invariant (sec-001 round-3 — comms inbound bodies
    cannot silently promote to T2) and delegates to this dependency. The
    delegate returns the real Slice-3 :data:`ExtractionResult` union
    (``Extracted | TypedRefusal``); there is no ``schema_version`` field.

    The Slice-3 :class:`alfred.security.quarantine.QuarantinedExtractor`'s
    public surface is ``extract(handle, schema)`` — it operates on opaque
    :class:`ContentHandle` references, not raw bodies. PR-S4-8 (Wave 2) ships
    this body-shaped seam so the inbound entrypoint can funnel through a single
    T3-enforcing chokepoint; the body→handle→``extract(handle, schema)`` bridge
    is wired by the comms host (the session/supervisor wiring PR, Wave 3) which
    constructs the concrete adapter satisfying this Protocol. Keeping the seam
    here means the trust-tier enforcement lives at the orchestrator edge
    regardless of how the bridge is implemented downstream.
    """

    async def extract(
        self,
        *,
        body: bytes | str | Mapping[str, object],
        canonical_user_id: str,
        source_tier: Literal["T3"],
    ) -> ExtractionResult: ...


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
        # PR-S3-3b Task 12: the autocommit writer flushes the
        # ``supervisor.action_timeout`` AND the timeout-derived
        # ``orchestrator.turn result=cancelled`` row OUTSIDE the rolled-back
        # session_scope (core-003 + CR-R3 #7). Production default re-uses
        # the same factory shape against session_scope; the writer instance
        # is still distinct from ``_audit`` so the test surface can
        # observe each independently. AuditWriter already opens its own
        # session per ``.append()`` so the row commits on a fresh
        # transaction — the rollback of the parent session_scope cannot
        # reach it.
        autocommit_audit_factory: Callable[
            [Callable[[], AbstractAsyncContextManager[AsyncSession]]], AuditWriter
        ] = lambda f: AuditWriter(session_factory=f),
        # Spec §10.5 per-action deadline default; tests inject sub-millisecond
        # values to fire the deadline deterministically. Hot-reload is out of
        # scope for PR-S3-3b — arch-002 owns reload semantics.
        deadline_seconds: float = 30.0,
        redactor: Callable[[str], str] = lambda s: s,
        # PR-S4-8 (#152): the orchestrator-side quarantined-extract funnel.
        # Additive + optional so every Slice-1..3 caller that omits it keeps
        # constructing; the comms inbound path (Wave 2) requires it wired and
        # ``quarantined_extract`` raises loudly when it is absent.
        quarantined_extractor: QuarantinedExtractorLike | None = None,
        # #339 PR3: the agentic act-phase loop seams. Additive + optional so
        # every Slice-1..4 caller that omits them keeps constructing and the
        # loop degrades to today's single completion (empty registry ->
        # tools=() -> stop_reason "end_turn" on iteration 0). The daemon
        # inbound assembly (#338) injects the live registry/gate/dlp.
        tool_registry: ToolRegistry | None = None,
        gate: CapabilityGate | None = None,
        outbound_dlp: OutboundDlpProtocol | None = None,
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
        self._autocommit_audit_factory = autocommit_audit_factory
        self._redactor = redactor
        # Audit writer is built once from the session_scope factory — it
        # opens its own session per `.append()` and is independent of the
        # per-turn user-content transaction below.
        self._audit = self._audit_factory(self._session_scope)
        # Second writer purpose-built for the deadline-fired path. Logically
        # distinct from ``self._audit`` even when both factories share the
        # same session_scope underneath — the duality makes the wiring
        # observable in tests and lets a future deployment swap an
        # independent autocommit-isolation factory in without changing the
        # call sites (core-003 + CR-R3 #7).
        self._autocommit_audit = self._autocommit_audit_factory(self._session_scope)
        # Per-action deadline wrapper — Task 11 ships a pure timing wrapper;
        # the orchestrator owns the audit-row emission so the row can land
        # outside the rolled-back session.
        self._deadline_wrapper = DeadlineWrapper(deadline_seconds=deadline_seconds)
        self._quarantined_extractor = quarantined_extractor
        self._tool_registry = tool_registry
        self._gate = gate
        self._outbound_dlp = outbound_dlp

    async def quarantined_extract(
        self,
        body: bytes | str | Mapping[str, object],
        *,
        canonical_user_id: str,
        source_tier: Literal["T3"],
    ) -> ExtractionResult:
        """Funnel a T3 comms inbound body into the quarantined extractor.

        This thin wrapper is the ONLY orchestrator-side path by which a comms
        inbound body becomes orchestrator-readable structured data. It enforces
        the trust-tier invariant and delegates to the injected
        :class:`QuarantinedExtractorLike`:

        * ``source_tier`` MUST be the literal ``"T3"``. Passing ``"T2"`` (the
          inter-persona-relay forgery shape) raises :class:`ValueError` BEFORE
          the extractor is consulted — there is no path by which a comms inbound
          body silently promotes to T2 (sec-001 round-3). The ``Literal["T3"]``
          annotation catches static violations; the runtime check is the
          defence-in-depth backstop that survives ``# type: ignore``.
        * A missing extractor (constructed without ``quarantined_extractor=``)
          raises :class:`RuntimeError` rather than silently no-op'ing the
          trust-boundary funnel (CLAUDE.md hard rule #7).

        Returns the real Slice-3 :data:`ExtractionResult` union
        (``Extracted | TypedRefusal``); the caller branches by ``isinstance``.
        """
        if source_tier != "T3":
            raise ValueError(t("orchestrator.quarantined_extract.source_tier_must_be_t3"))
        if self._quarantined_extractor is None:
            raise RuntimeError(t("orchestrator.quarantined_extract.no_extractor_wired"))
        # Task 62: observe the T3->orchestrator-readable crossing wall time on
        # every outcome (the finally fires on success AND on a raising extract).
        started = time.monotonic()
        try:
            return await self._quarantined_extractor.extract(
                body=body,
                canonical_user_id=canonical_user_id,
                source_tier="T3",
            )
        finally:
            comms_observability.record_quarantined_extract_seconds(time.monotonic() - started)

    async def handle_user_message(
        self,
        *,
        user: UserLike,
        content: TaggedContent[T1] | TaggedContent[T2],
        working_memory: WorkingMemory,
    ) -> str:
        """Process one user turn end-to-end and return the assistant reply.

        ``user`` is the per-turn requester (may be the operator or any other
        authorized household user). ``content`` arrives already tagged at the
        orchestrator boundary — the host-side comms-MCP ingress path owns the
        tagging post-PR-S4-10;
        :func:`alfred.identity._ingest._ingest_tier` encodes the
        role-x-adapter rule but is currently unwired (reserved; see issue
        #237). The orchestrator reads ``content.content`` and
        ``content.tier.name``
        but does not re-tag. The accepted tiers are T1 (operator via TUI)
        and T2 (all other authenticated ingress); T3 NEVER reaches this
        method directly — T3 bytes live behind opaque ContentHandle
        references in the plugin host's content store (spec §3.1, §7.3).
        ``working_memory`` is the pool-acquired buffer for this
        (persona, user.slug) pair; the adapter owns its lifecycle (acquire
        before, release in finally).

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
        # PR-S3-3b Task 14: stamp the start of the action for the per-turn
        # Prometheus histogram. ``time.monotonic`` is the right clock here —
        # immune to NTP step adjustments and never goes backwards across a
        # suspended laptop or a leap second. ``record_action_duration`` runs
        # on every exit branch (success / timeout / cancelled) so per-user p99
        # captures every action regardless of outcome (spec §7a.3).
        action_start = time.monotonic()
        async with self._session_scope() as session:
            try:
                # PR-S3-3b Task 12: wrap the turn body with the per-action
                # deadline. ``_user_id`` and ``_correlation_id`` are consumed
                # by ``DeadlineWrapper.run`` and NOT forwarded to
                # ``_handle_turn`` (core-005 — see DeadlineWrapper docstring).
                reply = await self._deadline_wrapper.run(
                    self._handle_turn,
                    session,
                    user=user,
                    content=content,
                    working_memory=working_memory,
                    trace_id=trace_id,
                    _user_id=user.slug,
                    _correlation_id=trace_id,
                )
                # PR-S3-3b Task 14: success-path histogram observation. Wired
                # post-return so a failed audit-write inside _handle_turn lands
                # in the except arm below instead of double-observing. The
                # ``breaker_state="UNKNOWN"`` literal is the Slice-3 default;
                # PR-S3-4+ threads real breaker state from
                # ``Supervisor.get_or_create_breaker`` once the supervisor is
                # constructed at process bootstrap.
                record_action_duration(
                    duration_seconds=time.monotonic() - action_start,
                    user_id=user.slug,
                    action_outcome="success",
                    breaker_state="UNKNOWN",
                )
                return reply
            except TimeoutError:
                # PR-S3-3b Task 12 — the deadline fired. Two audit rows land
                # on the AUTOCOMMIT writer so they survive the outer
                # rollback (core-003 + CR-R3 #7):
                #
                #   1. ``supervisor.action_timeout`` — operator-facing
                #      supervisor row carrying the deadline + phase label.
                #   2. ``orchestrator.turn`` ``result=cancelled`` — the
                #      turn's own cancellation row. Using the session-bound
                #      writer here would lose the row when ``session.rollback()``
                #      below runs; the autocommit writer flushes it in its
                #      own session that the parent rollback cannot reach.
                #
                # We then re-raise ``CancelledError`` so existing
                # cancellation-aware callers (TUI, adapter loops) keep their
                # single-shape handling. The orchestrator's higher-level
                # cancellation contract collapses "deadline expired" onto
                # the same shape as operator-initiated cancel (spec §10.5).
                await self._emit_supervisor_timeout_row(
                    user_id=user.slug,
                    correlation_id=trace_id,
                    action_duration_seconds=time.monotonic() - action_start,
                )
                await self._emit_orchestrator_turn_cancelled_row_autocommit(
                    user=user,
                    trace_id=trace_id,
                    phase="turn_timeout",
                )
                # PR-S3-3b Task 14: timeout-path histogram observation. Bound
                # to the same trace_id as the supervisor.action_timeout audit
                # row so dashboards can join the two by trace.
                record_action_duration(
                    duration_seconds=time.monotonic() - action_start,
                    user_id=user.slug,
                    action_outcome="timeout",
                    breaker_state="UNKNOWN",
                )
                await session.rollback()
                raise asyncio.CancelledError("deadline expired") from None
            except asyncio.CancelledError:
                # External cancellation (NOT timeout-derived). Session is
                # alive; the session-bound ``_audit_cancellation`` flushes
                # inside the active txn which we then roll back — the row
                # is intentionally tied to the rolled-back work and is
                # lost on rollback. That's the correct semantic for
                # "user cancelled mid-turn; nothing committed."
                #
                # CLAUDE.md hard rule #7: cancellation at ANY awaited step
                # in the turn (working-memory append, episodic write,
                # pre-/post-provider audit) MUST write a ``cancelled``
                # audit row — not only cancellation that lands inside
                # ``_router.complete``. The inner provider-call branch
                # (see ``_handle_turn``) already audits-and-re-raises for
                # the common case; this top-level arm is the backstop
                # that catches any re-raised CancelledError (and any
                # cancellation that lands elsewhere). Tagged with a
                # distinct phase so the audit reader can tell timeout
                # apart from operator-cancel.
                await self._audit_cancellation(user=user, trace_id=trace_id, phase="turn_cancelled")
                # PR-S3-3b Task 14: cancelled-path histogram observation.
                # Distinct outcome label from timeout — operator-initiated
                # cancellation contributes to per-user p99 the same way
                # successful turns do, just under a different label.
                record_action_duration(
                    duration_seconds=time.monotonic() - action_start,
                    user_id=user.slug,
                    action_outcome="cancelled",
                    breaker_state="UNKNOWN",
                )
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

    async def _emit_supervisor_timeout_row(
        self,
        *,
        user_id: str,
        correlation_id: str,
        action_duration_seconds: float,
    ) -> None:
        """Emit the ``supervisor.action_timeout`` row + invoke the matching hookpoint.

        Spec §10.5 + migration 0007: the row's ``result`` is ``"cancelled"``
        (the turn was cancelled by the deadline). The autocommit writer
        flushes the row OUTSIDE the rolled-back parent session_scope
        (core-003 + CR-R3 #7) — using ``self._audit`` here would risk losing
        the row when ``session.rollback()`` runs in the caller.

        Uses :meth:`AuditWriter.append_schema` against
        :data:`SUPERVISOR_ACTION_TIMEOUT_FIELDS` so PR-S3-0a's symmetric
        missing/extra-field guard catches drift between the schema constant
        and this emit site (S-S3-3b-1).

        After the row commits, invokes the
        ``supervisor.action_timeout`` hookpoint — registered by
        ``Supervisor.__init__`` but previously never fired (arch-s3-3b-001).
        Subscribers see the same transition the audit graph sees. Awaited
        inline (no fire-and-forget) — err-001 / core-004.

        ``phase_at_timeout="unknown"`` is the Slice-3 default;
        Slice-4+ resolves the in-flight phase from the OTel span hierarchy.

        ``action_duration_seconds`` is the actual wall-clock elapsed from
        ``action_start`` (``time.monotonic()`` delta) — NOT the configured
        deadline. The deadline value lands on ``deadline_seconds`` so
        operator dashboards can compare ``elapsed`` vs ``budget`` (the
        ratio is the deadline-hit signal); reporting the configured value
        on both fields would flatten the duration distribution to a single
        point per deadline configuration.

        err-006: no ``try/except`` here — an autocommit-write failure must
        propagate so the operator-facing error is loud (CLAUDE.md hard
        rule #7). The DeadlineWrapper itself takes no audit responsibility
        (core-002, core-003); that contract lives end-to-end in this method.
        """
        await self._autocommit_audit.append_schema(
            fields=SUPERVISOR_ACTION_TIMEOUT_FIELDS,
            schema_name="SUPERVISOR_ACTION_TIMEOUT_FIELDS",
            event="supervisor.action_timeout",
            actor_user_id=user_id,
            actor_persona="supervisor",
            subject={
                "user_id": user_id,
                "action_duration_seconds": action_duration_seconds,
                "deadline_seconds": self._deadline_wrapper.deadline_seconds,
                "phase_at_timeout": "unknown",
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="cancelled",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=correlation_id,
        )
        # arch-s3-3b-001: invoke the matching hookpoint AFTER the audit row
        # so subscribers see the same transition the audit graph sees.
        await invoke_supervisor_action_timeout_hookpoint(
            user_id=user_id,
            deadline_seconds=self._deadline_wrapper.deadline_seconds,
            phase_at_timeout="unknown",
        )

    async def _emit_orchestrator_turn_cancelled_row_autocommit(
        self,
        *,
        user: UserLike,
        trace_id: str,
        phase: str,
    ) -> None:
        """Emit ``orchestrator.turn`` ``result=cancelled`` via the autocommit writer.

        CR-R3 #7: the timeout-derived cancellation row MUST use the autocommit
        writer because the session-bound ``_audit_cancellation`` writes inside
        the active txn that the timeout arm is about to roll back. The row
        would be lost on rollback; the autocommit writer flushes the row in
        a fresh session that the parent rollback cannot reach.

        ``phase="turn_timeout"`` distinguishes this row from the
        operator-cancel ``"turn_cancelled"`` row in the audit graph.
        """
        await self._autocommit_audit.append(
            event="orchestrator.turn",
            actor_user_id=user.slug,
            actor_persona=_ALFRED_PERSONA_ID,
            subject=_sanitize_subject({"phase": phase}, self._redactor),
            trust_tier_of_trigger="T2",
            result="cancelled",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=trace_id,
            language=user.language,
            persona_id=_ALFRED_PERSONA_ID,
        )

    async def _handle_turn(
        self,
        session: AsyncSession,
        *,
        user: UserLike,
        content: TaggedContent[T1] | TaggedContent[T2],
        working_memory: WorkingMemory,
        trace_id: str,
    ) -> str:
        # ``trace_id`` is supplied by ``handle_user_message`` so the top-level
        # cancellation-audit row and the per-phase audit rows share the same
        # trace identifier — without this they'd be different UUIDs and the
        # audit reader couldn't stitch the cancelled turn together.
        episodic = self._episodic_factory(session)

        # ------------------------------------------------------------------
        # Observe — ``content`` arrives already tagged at this boundary
        # (host-side comms-MCP ingress owns tagging post-PR-S4-10;
        # ``alfred.identity._ingest._ingest_tier`` is reserved/unwired, see
        # issue #237); read off the tier name
        # for downstream rows but do not re-tag. Content is
        # ``TaggedContent[T1]`` (operator via TUI) or ``TaggedContent[T2]``
        # (all other ingress paths). T3 never reaches this method directly
        # — T3 bytes are held in ContentHandle references only (spec §3.1).
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
        # ------------------------------------------------------------------
        # Act — the agentic tool-calling loop (#339 PR3, spec §6/§7/§9).
        #
        # The per-action DEADLINE (DeadlineWrapper in handle_user_message)
        # bounds the WHOLE loop; loop_constants.MAX_TOOL_ITERATIONS is the
        # cost/round-trip backstop under it (core-004). asyncio.CancelledError
        # from the deadline is NOT caught here — it propagates to the top-level
        # timeout/cancel arm (hard rule #7). dispatch_tool escalations (Task 3)
        # likewise propagate to halt the turn. With no registry the loop runs
        # exactly one iteration and reduces to the pre-#339 single-completion
        # turn (empty tools -> stop_reason "end_turn" on iteration 0).
        # ------------------------------------------------------------------
        tools = self._tool_registry.definitions() if self._tool_registry is not None else ()
        base_messages = messages  # system + history (built in Orient)
        local: list[Message] = []  # in-turn tool transcript (EPHEMERAL — Task 3 appends)
        # Underscore-prefixed: unused until Task 3 starts incrementing it on
        # each dispatched tool call — kept here now so the loop preamble
        # shape doesn't churn again next task.
        _call_index = 0  # monotonic dispatch ordinal (Task 3 increments)
        per_turn_spent_usd = 0.0
        pending_completion_cost = 0.0  # this completion's cost until a provider_call row logs it
        final_content: str | None = None
        final_response: CompletionResponse | None = None
        # "token" here means a closed-vocabulary audit result label
        # (ck_audit_log_result), not a credential — bandit's S105 pattern-
        # matches the variable name, not the value; suppressed below.
        final_result_token = "success"  # noqa: S105
        final_exit_reason: str | None = None  # set only on a non-normal exit

        for iteration in range(loop_constants.MAX_TOOL_ITERATIONS):
            request = CompletionRequest(
                messages=base_messages + local,
                tools=tools,
                tool_choice="auto",
            )

            # --- per-iteration budget pre-check (spec §7) ---
            try:
                estimate = self._budget.estimate_for(user.slug, request)
                would_exceed = self._budget.would_exceed(user.slug, estimate)
            except BudgetError as exc:
                if isinstance(exc, UnknownBudgetUserError):
                    await self._audit_unknown_budget_user(
                        user=user,
                        trace_id=trace_id,
                        phase="budget_pre_check",
                        trigger_tier=user_input_tier,
                    )
                raise
            if would_exceed:
                if iteration == 0:
                    # No spend yet — preserve the pre-#339 pre-check contract
                    # (a budget_pre_check row + a raised BudgetError). Existing
                    # test_pre_check_refusal_audits_and_raises depends on this.
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
                    raise BudgetError(
                        f"pre-check refused: estimate ${estimate:.4f} would breach budget"
                    )
                # Mid-turn (iteration >= 1): end gracefully; the terminal
                # `completed` row records it (FIX-6 — no separate row).
                final_content = t("orchestrator.tool.budget_exhausted_mid_turn")
                final_result_token = "budget_blocked"  # noqa: S105
                final_exit_reason = "budget_exhausted_mid_turn"
                break

            # --- completion (NEVER gather) ---
            try:
                response = await self._router.complete(request)
            except Exception as exc:
                _log.error(
                    "orchestrator.provider_failed",
                    trace_id=trace_id,
                    iteration=iteration,
                    error=self._redactor(str(exc)),
                    error_type=type(exc).__name__,
                )
                await self._audit.append(
                    event="orchestrator.turn",
                    actor_user_id=user.slug,
                    actor_persona=_ALFRED_PERSONA_ID,
                    subject=_sanitize_subject(
                        {
                            "phase": f"provider_call:{iteration}",
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
            final_response = response

            # --- charge; force-record on overrun (spec §7, mem-002) ---
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
                    iteration=iteration,
                    estimate_usd=estimate,
                    actual_usd=response.cost_usd,
                    error=self._redactor(str(exc)),
                )
            per_turn_spent_usd += response.cost_usd
            pending_completion_cost = response.cost_usd  # not yet logged to any row

            # --- terminal? (no tool request -> final answer). FIX-3: the
            #     terminal completion is audited SOLELY by the `completed` row
            #     below — NO provider_call row here. This keeps the no-tools
            #     happy path at audit.append.await_count == 1 (byte-for-byte). ---
            if response.stop_reason != "tool_use" or not response.tool_calls:
                final_content = response.content
                final_result_token = charge_result  # "success" | "budget_overrun"
                break

            # --- non-terminal completion: audit it as provider_call:{iteration}
            #     (FIX-3 — only continuing completions get their own row). ---
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject(
                    {
                        "phase": f"provider_call:{iteration}",
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
            pending_completion_cost = 0.0  # logged to the provider_call row above

            if charge_result == "budget_overrun":
                # Over cap AND the model wants more tools — stop before more egress.
                final_content = t("orchestrator.tool.budget_overrun_mid_turn")
                final_result_token = "budget_overrun"  # noqa: S105
                final_exit_reason = "budget_overrun_mid_turn"
                break

            # --- TOOL DISPATCH HOOK (Task 3 replaces this line) ---
            raise NotImplementedError("tool dispatch lands in Task 3")
        else:
            # Loop exhausted MAX_TOOL_ITERATIONS without a terminal answer.
            final_content = t("orchestrator.tool.max_iterations_reached")
            final_result_token = "refused"  # noqa: S105 -- FIX-1: in-domain (NOT "max_iterations_reached")
            final_exit_reason = "max_iterations_reached"

        # final_response is None ONLY on the iteration-0 pre-check raise / provider
        # failure paths, which do not reach here (they raise). So it is populated
        # on every path that reaches persist.
        assert final_response is not None
        answer = final_content if final_content is not None else final_response.content

        # ADR-0008: assistant output is T2 in Slice 1+2 (at-most-as-trusted as
        # the T2 input that triggered it). T0 is reserved for AlfredOS
        # internals/code/prompts/configs per PRD §7.1. Slice 2's dual-LLM
        # split refines provider output to T1 and introduces T3.
        await working_memory.append(role="assistant", content=answer)
        # FIX-15: episodic.record logs the FINAL completion's cost/tokens (the
        # answer's attribution); the `completed` audit row logs the TURN total
        # (per_turn_spent_usd). For a multi-completion turn these differ BY
        # DESIGN — episodic = answer attribution, audit = turn spend.
        await episodic.record(
            user_id=user.slug,
            role="assistant",
            content=answer,
            trust_tier="T2",
            tokens_in=final_response.tokens_in,
            tokens_out=final_response.tokens_out,
            cost_usd=final_response.cost_usd,
            language=user.language,
            persona=_ALFRED_PERSONA_ID,
            # See the user-turn ``episodic.record`` call above for the
            # ``persona`` vs ``persona_id`` split rationale.
            persona_id=_ALFRED_PERSONA_ID,
        )

        completed_subject: dict[str, object] = {
            "phase": "completed",
            "model": final_response.model,
            "tokens_in": final_response.tokens_in,
            "tokens_out": final_response.tokens_out,
            "charge_result": final_result_token,
            "turn_cost_usd": per_turn_spent_usd,
        }
        if final_exit_reason is not None:
            completed_subject["exit_reason"] = final_exit_reason
        try:
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject(completed_subject, self._redactor),
                trust_tier_of_trigger=user_input_tier,
                result=final_result_token,
                cost_estimate_usd=0.0,
                cost_actual_usd=pending_completion_cost,  # FIX-3: terminal cost only
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
            tokens_in=final_response.tokens_in,
            tokens_out=final_response.tokens_out,
            cost_usd=per_turn_spent_usd,
            charge_result=final_result_token,
        )
        return answer

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

    def _synthesize_egress_context(self, *, trace_id: str, user: UserLike) -> TurnEgressContext:
        """Build the per-turn egress anchor for the fixture / ``alfred chat`` path.

        #339 is mechanism-proven-by-fixtures: there is no live comms resume, so
        the anchor is synthesized DETERMINISTICALLY from the turn identity (as
        G7-2's synthetic driver did). ``inbound_id`` is the turn ``trace_id``
        (the committed inbound identity on this path); ``session_id`` is the
        requesting user's slug. #338 REPLACES this synthesis with the real
        adapter/inbound/session identity carried by the live comms inbound.

        Replay note (spec §5): within a turn the same ``trace_id`` yields the
        same anchor, so ``compute_egress_id(ctx, call_index)`` is stable for a
        fixed dispatch sequence. Cross-turn at-most-once under re-planning is a
        hard #338 prerequisite (journal the dispatch sequence), NOT provided
        here — #339 has no live resume so it is not reachable.
        """
        return TurnEgressContext(
            adapter_id="orchestrator.synthetic",
            inbound_id=trace_id,
            session_id=user.slug,
        )
