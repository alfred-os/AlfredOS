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

Session lifecycle (#410 PR1 / ADR-0062 — the three-phase turn): NO database
connection is ever held across external I/O. Phase A (Observe) opens one
short-lived ``session_scope``, runs the ledger user-gate + the episodic user
write in ONE transaction, and commits; the working-memory append is deferred
until after that commit. Phase B (Orient + Act) — prompt construction, the
provider call, the whole tool loop, and every audit write — runs with ZERO
connections held. Phase C (Persist) opens a second short-lived scope for the
ledger assistant-gate + the episodic assistant write, commits, then performs
the deferred assistant append and the terminal audit row. Rollback of a
phase is the scope's own job — there are no manual ``session.rollback()``
calls in this module any more.

**Audit writes live OUTSIDE those transactions.** ``AuditWriter`` takes its
own ``session_factory`` (the SIDE_EFFECT-role scope in production) and opens
a fresh session per ``.append()`` — CLAUDE.md hard rule #7: audit rows
survive any caller rollback. That second-connection acquisition is exactly
why the SIDE_EFFECT pool is separate from the TURN pool: under the pre-#410
single-turn-transaction design, N in-flight turns each holding a TURN
connection while demanding a SIDE_EFFECT one deadlocked the unconfigured
shared pool (verified: 16 concurrent turns, 0 succeeded).

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
import itertools
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.audit.audit_row_schemas import SUPERVISOR_ACTION_TIMEOUT_FIELDS
from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetError, BudgetGuard, UnknownBudgetUserError
from alfred.comms_mcp import observability as comms_observability
from alfred.egress.egress_id import TurnEgressContext
from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.replay_journal import ReplayJournal
from alfred.memory.turn_side_effects import TurnSideEffectLedger
from alfred.memory.working import WorkingMemory
from alfred.orchestrator import loop_constants
from alfred.orchestrator.tool_dispatch import dispatch_tool
from alfred.personas.alfred import ALFRED_PERSONA, render_persona_prompt
from alfred.providers.base import CompletionRequest, CompletionResponse, Message
from alfred.providers.router import ProviderRouter
from alfred.security.tiers import T1, T2, TaggedContent
from alfred.supervisor.breaker import invoke_supervisor_action_timeout_hookpoint
from alfred.supervisor.deadline import DeadlineWrapper
from alfred.supervisor.observability import record_action_duration, record_orphaned_user_turn

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


def _truncate_tool_result(text: str) -> str:
    """Bound a tool_result fed back to the planner (spec §6, TOOL_RESULT_MAX_CHARS).

    A pathological or verbose tool must not balloon the next completion's
    context. Truncates on a character boundary and appends an ellipsis marker
    so the planner can tell the result was clipped. The marker itself counts
    against the cap — appending it AFTER slicing to the full limit would let
    the result exceed ``TOOL_RESULT_MAX_CHARS`` by the marker's length.
    """
    limit = loop_constants.TOOL_RESULT_MAX_CHARS
    marker = "…[truncated]"
    if len(text) <= limit:
        return text
    if limit <= len(marker):
        return marker[:limit]
    return text[: limit - len(marker)] + marker


class ReplayIterationCeilingError(AlfredError):
    """A journalled resume point sits at or past ``MAX_TOOL_ITERATIONS``.

    #410 PR2 final-review finding: ``_fast_forward_journalled_calls`` returns
    the iteration the Act loop should resume from, and the loop expresses that
    as ``range(start_iteration, MAX_TOOL_ITERATIONS)``. A ``start_iteration``
    at or past the ceiling makes that range EMPTY — the loop body never runs,
    no completion happens, and the turn would fall out the bottom with nothing
    to answer with. Silently producing an empty loop is exactly the shape
    CLAUDE.md hard rule #7 forbids, so the precondition is checked and raised
    on instead.

    Not reachable today: the Act loop's ``iteration == MAX_TOOL_ITERATIONS - 1``
    guard breaks BEFORE the journal write, so no row can carry an iteration at
    the ceiling. That ordering is an unenforced write-side invariant, not a
    schema constraint (``tool_call_journal.iteration`` has no upper-bound
    CHECK) — lowering ``MAX_TOOL_ITERATIONS`` between a crash and a resume
    reaches it, and so would any future writer that journals from somewhere
    else. "Unreachable today" is not a safety argument; guard the class.
    """


@dataclass(frozen=True, slots=True)
class _TurnOutcome:
    """Everything Phase B decides that Phases C + the terminal row consume.

    Frozen: Phase B's result is a fact by the time Phase C runs — nothing
    downstream may edit it.
    """

    answer: str
    final_response: CompletionResponse
    final_result_token: str
    final_exit_reason: str | None
    answer_from_provider: bool
    estimate: float
    per_turn_spent_usd: float
    pending_completion_cost: float


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
        # #410 PR1: the at-most-once guard for turn-start/turn-end (the
        # budget charge is deliberately NOT gated — see
        # alfred.memory.turn_side_effects's module docstring). Additive +
        # optional so every pre-#410 caller (tests, fixtures, alfred chat,
        # and every Slice-1..4 production path before this PR's Task 5)
        # keeps constructing unchanged and every guarded call site below
        # defaults to "always apply" (`side_effect_ledger is None`).
        side_effect_ledger: TurnSideEffectLedger | None = None,
        # #410 PR2: the deterministic tool-call replay journal. Additive +
        # optional; `None` (every caller before PR3 wires a live
        # tool_registry) preserves today's behaviour exactly — this seam has
        # NO live consumer until PR3.
        replay_journal: ReplayJournal | None = None,
        # #410 PR1: the scope the two AuditWriters draw their per-append
        # sessions from. In production this is the SIDE_EFFECT-role scope —
        # audit writes are the ONE acquisition permitted while a TURN-role
        # phase transaction is open (hard rule #7; ADR-0062 hierarchy).
        # ``None`` falls back to ``session_scope`` so every existing caller
        # and test constructs byte-for-byte unchanged.
        audit_session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]] | None = None,
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
        # Audit writer is built once from the audit_session_scope factory —
        # it opens its own session per `.append()` and is independent of the
        # per-phase turn transactions.
        if audit_session_scope is None:
            # #410 PR1 (fleet finding M-10, reworded post-Task-7 by the final
            # review's M-1): the fallback is legitimate for unit tests that
            # construct ``Orchestrator(...)`` directly (bypassing the
            # builder), but a PRODUCTION boot site omitting
            # audit_session_scope would silently point the AuditWriters at
            # the TURN pool — quietly re-coupling the two pools this plan
            # separates. Task 7 landed: ``Orchestrator(...)`` is constructed
            # in exactly ONE place in ``src/`` — ``cli/_bootstrap.py``'s
            # ``build_orchestrator`` — and that builder ALWAYS supplies
            # ``audit_session_scope`` explicitly, either injected (the
            # daemon's ``_comms_boot.py``, the one production caller with a
            # comms-enabled boot) or self-built as the SIDE_EFFECT-role
            # default (every other real caller, e.g. a comms-disabled boot).
            # ``alfred chat`` is NOT such a caller — ``_chat_main``
            # (``cli/main.py``) dials the running gateway over a socket and
            # constructs no orchestrator locally. So this warning firing
            # today means exactly one thing: a test (or some future code)
            # constructed ``Orchestrator(...)`` directly instead of going
            # through ``build_orchestrator`` — not a pending-wiring gap.
            _log.warning("orchestrator.audit_session_scope_fallback")
        self._audit_session_scope = (
            audit_session_scope if audit_session_scope is not None else session_scope
        )
        self._audit = self._audit_factory(self._audit_session_scope)
        # Second writer purpose-built for the deadline-fired path. Logically
        # distinct from ``self._audit`` even when both factories share the
        # same audit_session_scope underneath — the duality makes the wiring
        # observable in tests and lets a future deployment swap an
        # independent autocommit-isolation factory in without changing the
        # call sites (core-003 + CR-R3 #7).
        self._autocommit_audit = self._autocommit_audit_factory(self._audit_session_scope)
        # Per-action deadline wrapper — Task 11 ships a pure timing wrapper;
        # the orchestrator owns the audit-row emission so the row can land
        # outside the rolled-back session.
        self._deadline_wrapper = DeadlineWrapper(deadline_seconds=deadline_seconds)
        self._quarantined_extractor = quarantined_extractor
        self._tool_registry = tool_registry
        self._gate = gate
        self._outbound_dlp = outbound_dlp
        self._side_effect_ledger = side_effect_ledger
        self._replay_journal = replay_journal

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
        egress_context: TurnEgressContext | None = None,
    ) -> str:
        """Process one user turn end-to-end and return the assistant reply.

        ``user`` is the per-turn requester (may be the operator or any other
        authorized household user). ``content`` arrives already tagged at the
        orchestrator boundary — the host-side comms-MCP ingress path owns the
        tagging post-PR-S4-10;
        :func:`alfred.identity._ingest._ingest_tier` encodes the
        role-x-adapter rule but is currently unwired (reserved; see issue
        #237). The orchestrator reads ``content.content`` and
        ``content.tier.name`` but does not re-tag. The accepted tiers are T1
        (operator via TUI) and T2 (all other authenticated ingress); T3 NEVER
        reaches this method directly — T3 bytes live behind opaque
        ContentHandle references in the plugin host's content store (spec
        §3.1, §7.3). ``working_memory`` is the pool-acquired buffer for this
        (persona, user.slug) pair; the adapter owns its lifecycle (acquire
        before, release in finally). ``egress_context`` is the per-turn
        :class:`TurnEgressContext` the live comms inbound path passes so the
        egress ledger anchors to the real ``(adapter_id, inbound_id,
        session_id)`` identity; ``None`` (the default) synthesizes it from
        the ``trace_id`` for the ``alfred chat``/fixture path (#338).

        #410 PR1: the deadline wrapper now encloses the WHOLE three-phase
        sequence (Phase A observe-txn, Phase B provider/tools with no
        connection held, Phase C persist-txn + deferred appends + terminal
        row) instead of a single-session turn body. If the deadline or an
        external cancel fires during Phase B, no connection is held, so the
        autocommit audit writes below always acquire cleanly; if it fires
        during Phase A/C, that phase's own ``async with`` unwinds (rolling
        the transaction back) BEFORE either arm runs — the pre-#410
        recovery-ordering hazard (audit write needing a fresh connection
        BEFORE the held one was rolled back) is gone structurally, which is
        why the explicit ``session.rollback()`` calls that used to live in
        these arms no longer exist.

        Raises:
            BudgetError: pre-check refusal — or, for the 7th audit branch,
                ``UnknownBudgetUserError`` (defense-in-depth on a slug the
                resolver should have caught upstream). Phase A has committed
                by then: the orphan user episodic row is the ADR-0062
                accepted trade-off (replay re-denies the user gate and
                converges).
            Exception: re-raises the provider's exception if both providers
                in the router fail, and re-raises a phase-commit failure
                after recording ``action_outcome="commit_failed"``, writing
                the ``orchestrator.turn`` ``phase_commit:*`` audit row, and
                logging ``orchestrator.phase_commit_failed`` (see
                ``_run_committed_phase``).
            asyncio.CancelledError: re-raised after auditing on user cancel.
            Exception: re-raises the audit writer's exception if persistence
                breaks after a successful provider call (CLAUDE.md hard
                rule #7).
        """
        trace_id = str(uuid.uuid4())
        # PR-S3-3b Task 14: stamp the start of the action for the per-turn
        # Prometheus histogram. ``time.monotonic`` is the right clock here —
        # immune to NTP step adjustments and never goes backwards across a
        # suspended laptop or a leap second.
        action_start = time.monotonic()
        try:
            reply = await self._deadline_wrapper.run(
                self._run_turn_phases,
                user=user,
                content=content,
                working_memory=working_memory,
                trace_id=trace_id,
                egress_context=egress_context,
                action_start=action_start,
                _user_id=user.slug,
                _correlation_id=trace_id,
            )
        except TimeoutError:
            # PR-S3-3b Task 12 — the deadline fired. Two audit rows land on
            # the AUTOCOMMIT writer (its own SIDE_EFFECT-role sessions):
            #   1. ``supervisor.action_timeout`` — operator-facing row.
            #   2. ``orchestrator.turn`` ``result=cancelled`` — the turn's
            #      own cancellation row.
            # #410 PR1: no session is held here (see the method docstring),
            # so these writes always acquire a fresh connection cleanly.
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
            record_action_duration(
                duration_seconds=time.monotonic() - action_start,
                user_id=user.slug,
                action_outcome="timeout",
                breaker_state="UNKNOWN",
            )
            raise asyncio.CancelledError("deadline expired") from None
        except asyncio.CancelledError:
            # External cancellation (NOT timeout-derived). CLAUDE.md hard
            # rule #7: cancellation at ANY awaited step in the turn MUST
            # write a ``cancelled`` audit row. ``_audit_cancellation`` opens
            # its own session (audit_session_scope), so the row COMMITS and
            # survives — the pre-#410 comment claiming this row was
            # "intentionally lost on rollback" described a wiring that never
            # matched the writer's own fresh-session-per-append contract and
            # is gone with the held session itself.
            await self._audit_cancellation(user=user, trace_id=trace_id, phase="turn_cancelled")
            record_action_duration(
                duration_seconds=time.monotonic() - action_start,
                user_id=user.slug,
                action_outcome="cancelled",
                breaker_state="UNKNOWN",
            )
            raise
        # Success telemetry fires only after the whole sequence (both commits,
        # deferred appends, terminal audit row) returned — same post-return
        # position as pre-#410, so a terminal-audit failure still records
        # nothing rather than a spurious "success" (§3.4 requirement 1's
        # commit-ordering half is carried by _run_committed_phase).
        record_action_duration(
            duration_seconds=time.monotonic() - action_start,
            user_id=user.slug,
            action_outcome="success",
            breaker_state="UNKNOWN",
        )
        return reply

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

    async def _run_turn_phases(
        self,
        *,
        user: UserLike,
        content: TaggedContent[T1] | TaggedContent[T2],
        working_memory: WorkingMemory,
        trace_id: str,
        egress_context: TurnEgressContext | None,
        action_start: float,
    ) -> str:
        # ``trace_id`` is supplied by ``handle_user_message`` so the top-level
        # cancellation-audit row and the per-phase audit rows share the same
        # trace identifier. ctx is resolved once — both ledger gates and every
        # dispatch must key on the SAME (adapter_id, inbound_id).
        ctx = (
            egress_context
            if egress_context is not None
            else self._synthesize_egress_context(trace_id=trace_id, user=user)
        )
        # #410 PR2 (final whole-branch review, finding 3): only a FORWARDED
        # adapter context can ever have a journalled prefix to replay. The
        # synthesized fallback mints ``inbound_id = trace_id``, a fresh uuid4
        # per ``handle_user_message`` call, so its journal read is
        # guaranteed-empty by construction. Passing that fact down (rather
        # than paying a Postgres round-trip to rediscover it every direct /
        # `alfred chat` turn once PR3 arms a live tool_registry) both saves
        # the read AND makes the "a synthesized turn never resumes" property
        # structural instead of an unenforced consequence of how
        # ``_synthesize_egress_context`` happens to mint its inbound_id
        # today. Deliberately asymmetric with the journal WRITE, which stays
        # unconditional: writing rows under a fresh-by-construction identity
        # is inert (nothing can ever read them back), whereas READING under
        # an identity that later stopped being fresh would splice a foreign
        # turn's decided tool calls into this one — the hazardous direction
        # is the one guarded.
        forwarded_context = egress_context is not None
        user_input_text = content.content
        user_input_tier = content.tier.name

        # ── Phase A — Observe: ledger user-gate + episodic user row, ONE
        # short-lived transaction (ADR-0062). The gate travels with the write.
        user_turn_applied = await self._run_committed_phase(
            lambda session: self._observe_user_turn(
                session,
                user=user,
                user_input_text=user_input_text,
                user_input_tier=user_input_tier,
                ctx=ctx,
            ),
            user=user,
            trace_id=trace_id,
            trigger_tier=user_input_tier,
            phase="observe_user_turn",
            action_start=action_start,
        )
        # ONE orphan-counting arm spans everything BETWEEN Phase A's commit
        # and Phase C's commit (fleet finding M-14, widened by pass-2 finding
        # core-004): ANY failure in that span — the deferred user append,
        # a provider error, budget refusal, cancellation, deadline (both are
        # BaseExceptions), escalation, a Phase-C body exception, or Phase C's
        # own commit failure — leaves the IDENTICAL accepted
        # orphan-user-episodic-row state (ADR-0062). Count it on the way out
        # so the deliberate degradation has a production rate; the exception
        # itself propagates untouched to the existing arms. The post-commit
        # steps (deferred assistant append, terminal audit row) sit OUTSIDE
        # the arm: once Phase C committed, the assistant row exists and the
        # user row is no longer orphaned.
        try:
            if user_turn_applied:
                # Deferred until AFTER Phase A's commit: an append before
                # commit could survive a rollback the durable gate did not
                # (§3.3 of the 2026-08-08 design doc, carried into the phase
                # split).
                await working_memory.append(role="user", content=user_input_text)

            # ── Phase B — Orient + Act: NO database connection held. The
            # provider call, the tool loop, and every audit write happen
            # here; audit writers open their own SIDE_EFFECT-role sessions
            # per append.
            outcome = await self._orient_and_act(
                user=user,
                working_memory=working_memory,
                trace_id=trace_id,
                ctx=ctx,
                user_input_text=user_input_text,
                user_input_tier=user_input_tier,
                # §3.2, now CONDITIONAL under the phase split: on the happy path
                # Phase A already committed AND appended the user turn, so the
                # history read below ends on it — re-threading would duplicate
                # it. Only a denied user gate (a replay) needs the explicit
                # thread so the prompt never ends on an assistant turn (the
                # prefill-continuation bug). Keyed on the GATE RESULT — never on
                # content comparison.
                thread_current_user_message=not user_turn_applied,
                forwarded_context=forwarded_context,
            )

            # ── Phase C — Persist: ledger assistant-gate + episodic assistant
            # row, ONE short-lived transaction.
            assistant_turn_applied = await self._run_committed_phase(
                lambda session: self._persist_assistant_turn(
                    session, user=user, outcome=outcome, ctx=ctx
                ),
                user=user,
                trace_id=trace_id,
                trigger_tier=user_input_tier,
                phase="persist_assistant_turn",
                action_start=action_start,
            )
        except BaseException:
            if user_turn_applied:
                record_orphaned_user_turn(user_id=user.slug)
            raise

        if assistant_turn_applied:
            # Deferred post-commit append. Uncancelled-tail safety argument:
            # ``RealTurnOrchestratorAdapter._turn_locks``
            # (src/alfred/comms_mcp/real_turn_adapter.py:193-203) serialises
            # the whole turn per (persona, user_id), so this append's lock is
            # uncontended and returns without awaiting. Whoever removes or
            # bypasses that mutex inherits the obligation to re-derive this
            # safety argument (design doc §3.3; ADR-0062).
            await working_memory.append(role="assistant", content=outcome.answer)

        # Terminal ``completed`` audit row AFTER Phase C's scope has closed —
        # never nested inside it (its own fresh SIDE_EFFECT session must not
        # be an in-TURN acquisition when it doesn't have to be).
        await self._emit_turn_completed_row(
            user=user, trace_id=trace_id, outcome=outcome, user_input_tier=user_input_tier
        )
        _log.info(
            "orchestrator.turn",
            trace_id=trace_id,
            tokens_in=outcome.final_response.tokens_in,
            tokens_out=outcome.final_response.tokens_out,
            cost_usd=outcome.per_turn_spent_usd,
            charge_result=outcome.final_result_token,
        )
        return outcome.answer

    async def _run_committed_phase[R](
        self,
        body: Callable[[AsyncSession], Awaitable[R]],
        *,
        user: UserLike,
        trace_id: str,
        trigger_tier: str,
        phase: str,
        action_start: float,
    ) -> R:
        """Run ``body`` in ONE short-lived turn transaction; label commit failure.

        ``body_completed`` is the deterministic discriminator (§3.4): once the
        body returned, the only raiser left inside the ``async with`` is the
        scope's own ``session.commit()`` — so an ``Exception`` with
        ``body_completed=True`` IS a commit failure. Fleet finding H-2: every
        sibling failure arm in this turn (provider failure, budget refusal,
        terminal-row failure) writes an audit row, and a lost phase commit is
        at least as operator-significant — so a commit failure is recorded
        THREE ways before re-raising, never a spurious "success", never a
        metric-only whisper:

        * ``action_outcome="commit_failed"`` on the duration histogram;
        * a loud ``orchestrator.phase_commit_failed`` structlog error;
        * an ``orchestrator.turn`` audit row. ``result="failed"`` — an
          in-domain ``ck_audit_log_result`` value, reused across writers the
          same way the spawn-grant refusal row reuses ``'refused'``
          (models.py documents that precedent); the ``phase_commit:<phase>``
          ``subject.phase`` is the discriminator. The audit writer opens its
          OWN ``audit_session_scope`` session, so the row commits even though
          the phase's session is broken. If the audit write itself fails, it
          is logged loudly and the ORIGINAL commit exception still propagates
          — the same non-masking contract as ``_audit_cancellation`` —
          PROVIDED the audit write's own failure is an ``Exception``; the
          inner catch here is deliberately ``Exception``, not
          ``BaseException`` (mirroring the outer catch's own reasoning
          below), so a ``BaseException`` raised by the audit write itself
          (e.g. a cancellation landing mid-append) is NOT caught here and
          propagates in place of the original commit exception rather than
          alongside it.

        The catch is deliberately ``Exception``, not ``BaseException``: a
        ``CancelledError`` landing during the commit await is a CANCELLATION
        (the scope's own ``BaseException`` arm already rolled the phase back;
        the caller's timeout/cancel arms own its audit + telemetry) — not a
        commit failure to double-report. Body failures likewise record
        nothing here; the caller's arms handle them exactly as before.
        """
        body_completed = False
        try:
            async with self._session_scope() as session:
                result = await body(session)
                body_completed = True
        except Exception as exc:
            if body_completed:
                record_action_duration(
                    duration_seconds=time.monotonic() - action_start,
                    user_id=user.slug,
                    action_outcome="commit_failed",
                    breaker_state="UNKNOWN",
                )
                _log.error(
                    "orchestrator.phase_commit_failed",
                    trace_id=trace_id,
                    phase=phase,
                    error_type=type(exc).__name__,
                )
                try:
                    await self._audit.append(
                        event="orchestrator.turn",
                        actor_user_id=user.slug,
                        actor_persona=_ALFRED_PERSONA_ID,
                        subject=_sanitize_subject(
                            {
                                "phase": f"phase_commit:{phase}",
                                "error_type": type(exc).__name__,
                            },
                            self._redactor,
                        ),
                        trust_tier_of_trigger=trigger_tier,
                        result="failed",
                        cost_estimate_usd=0.0,
                        cost_actual_usd=0.0,
                        trace_id=trace_id,
                        language=user.language,
                        persona_id=_ALFRED_PERSONA_ID,
                    )
                except Exception as audit_exc:
                    _log.error(
                        "orchestrator.commit_failed_audit_write_failed",
                        trace_id=trace_id,
                        phase=phase,
                        error_type=type(audit_exc).__name__,
                    )
            raise
        return result

    async def _observe_user_turn(
        self,
        session: AsyncSession,
        *,
        user: UserLike,
        user_input_text: str,
        user_input_tier: str,
        ctx: TurnEgressContext,
    ) -> bool:
        """Phase A body: user-gate + episodic user row in the caller's txn.

        ``content`` arrives already tagged at this boundary (host-side
        comms-MCP ingress owns tagging post-PR-S4-10; ``alfred.identity.
        _ingest._ingest_tier`` is reserved/unwired, see issue #237); T3 never
        reaches this method — T3 bytes are held in ContentHandle references
        only (spec §3.1). ``None`` ledger (every pre-#410 caller) means
        "always apply" — behaviour unchanged.
        """
        applied = (
            True
            if self._side_effect_ledger is None
            else await self._side_effect_ledger.try_apply_user_turn(
                session, adapter_id=ctx.adapter_id, inbound_id=ctx.inbound_id
            )
        )
        if not applied:
            return False
        episodic = self._episodic_factory(session)
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
        return True

    async def _orient_and_act(
        self,
        *,
        user: UserLike,
        working_memory: WorkingMemory,
        trace_id: str,
        ctx: TurnEgressContext,
        user_input_text: str,
        user_input_tier: str,
        thread_current_user_message: bool,
        forwarded_context: bool,
    ) -> _TurnOutcome:
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
        if thread_current_user_message:
            # Replay path (user gate denied): the history already holds the
            # prior committed [user, assistant] pair and would otherwise END
            # on the assistant turn — which providers treat as a prefill to
            # continue, not a question to answer (§3.2). Redundant-but-
            # correct context; the prompt always ends on a fresh user turn.
            messages.append(Message(role="user", content=user_input_text))
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
        # #410 PR2: fast-forward any journalled tool-call prefix for this
        # inbound_id BEFORE entering the loop. Returns ([], 0, 0) — today's
        # exact behaviour — whenever no journal exists (always true until
        # PR3 wires a live tool_registry; even then, true for every
        # synthesized-context turn and for every FIRST attempt of any
        # forwarded inbound_id). See that method's docstring for the full
        # four-case early-return list.
        local, call_index, start_iteration = await self._fast_forward_journalled_calls(
            ctx=ctx, user=user, trace_id=trace_id, forwarded_context=forwarded_context
        )
        # #410 PR2 (final whole-branch review, finding 1b): the loop below is
        # `range(start_iteration, MAX_TOOL_ITERATIONS)`. A resume point at or
        # past the ceiling makes that range EMPTY — no completion runs and the
        # turn reaches the post-loop code with nothing to answer with. Check
        # the precondition where the coupling to MAX_TOOL_ITERATIONS actually
        # lives, so ANY future producer of a bad `start_iteration` (not just
        # the journal) fails loud here rather than silently no-op-ing a whole
        # turn. See ReplayIterationCeilingError for why this is guarded
        # despite being unreachable through today's write side.
        if start_iteration >= loop_constants.MAX_TOOL_ITERATIONS:
            _log.error(
                "orchestrator.replay_iteration_beyond_ceiling",
                trace_id=trace_id,
                start_iteration=start_iteration,
                max_tool_iterations=loop_constants.MAX_TOOL_ITERATIONS,
            )
            raise ReplayIterationCeilingError(
                t(
                    "orchestrator.tool.resume_iteration_beyond_ceiling",
                    start=start_iteration,
                    ceiling=loop_constants.MAX_TOOL_ITERATIONS,
                )
            )
        per_turn_spent_usd = 0.0
        pending_completion_cost = 0.0  # this completion's cost until a provider_call row logs it
        # Pyright can't prove the loop body below runs at least once (it only
        # sees MAX_TOOL_ITERATIONS as `Final[int]`, not a literal), so it
        # can't see that `estimate` is always assigned before the `completed`
        # audit row reads it. Runtime-safe either way — the constant is 8, so
        # the loop always executes — but the 0.0 here is never the value
        # actually persisted; it only satisfies the static analyzer.
        estimate: float = 0.0
        final_content: str | None = None
        final_response: CompletionResponse | None = None
        # "token" here means a closed-vocabulary audit result label
        # (ck_audit_log_result), not a credential — bandit's S105 pattern-
        # matches the variable name, not the value; suppressed below.
        final_result_token = "success"  # noqa: S105
        final_exit_reason: str | None = None  # set only on a non-normal exit

        # #410 PR2: resume from the fast-forwarded point (0 in every case
        # reachable before PR3). The upper bound and every per-iteration
        # check below (budget, fan-out cap, max-iterations) are UNCHANGED.
        for iteration in range(start_iteration, loop_constants.MAX_TOOL_ITERATIONS):
            request = CompletionRequest(
                messages=base_messages + local,
                tools=tools,
                tool_choice="auto",
                # #410 PR2: temperature=0 for tool-bearing turns as
                # defence-in-depth ON TOP OF the journal (not instead of
                # it) — a resumed turn should ideally re-derive the
                # identical plan even before the fast-forward above ever
                # runs. `tools` is empty until PR3 wires a live registry,
                # so this is inert (default 0.7) in production today.
                temperature=0.0 if tools else 0.7,
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
                if final_response is None:
                    # No completion has happened in THIS process yet, so there
                    # is no answer to fall back on — preserve the pre-#339
                    # pre-check contract (a budget_pre_check row + a raised
                    # BudgetError). Existing
                    # test_pre_check_refusal_audits_and_raises depends on this.
                    #
                    # #410 PR2 (final whole-branch review, finding 1a): this
                    # was `iteration == 0`. On a NON-resumed turn the two are
                    # exactly equivalent — the only way to reach iteration 1
                    # is to have completed iteration 0, which assigns
                    # `final_response` — so today's reachable behaviour is
                    # byte-for-byte unchanged. They diverge only once
                    # `_fast_forward_journalled_calls` can return a
                    # `start_iteration >= 1`: the resumed turn's FIRST fresh
                    # attempt is `iteration >= 1` but is still a pre-check
                    # with nothing completed, and the old test fell through to
                    # the mid-turn graceful break below, leaving
                    # `final_response is None` for the post-loop code to trip
                    # over. Keying on "has any completion landed in this
                    # process" states the ACTUAL condition the two arms
                    # discriminate on.
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
                # Mid-turn (a completion already landed this process): end
                # gracefully on the answer we already have; the terminal
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

            # --- fan-out cap (spec §7, mem-003). FIX-6: fold into the terminal
            #     `completed` row below — no separate audit row. A single
            #     completion requesting more tools than the cap allows is
            #     refused outright rather than partially honoured (a partial
            #     dispatch would silently drop the model's remaining
            #     requests without telling it). ---
            if len(response.tool_calls) > loop_constants.MAX_TOOL_CALLS_PER_ITERATION:
                final_content = t("orchestrator.tool.too_many_tool_calls")
                final_result_token = "refused"  # noqa: S105
                final_exit_reason = "too_many_tool_calls"
                break

            # --- FINAL iteration: a further tool request cannot be fed back
            #     (there is no next completion to consume the results), so
            #     dispatching here would incur real egress + spend + a
            #     consumed call_index for results we would then have to
            #     discard. Stop now instead (spec §9 max-iterations bound).
            #     This guard makes the trailing `for...else` unreachable —
            #     every path through the loop body now breaks — so that
            #     clause is REMOVED below rather than left as dead code. ---
            if iteration == loop_constants.MAX_TOOL_ITERATIONS - 1:
                final_content = t("orchestrator.tool.max_iterations_reached")
                final_result_token = "refused"  # noqa: S105 -- FIX-1: in-domain (NOT "max_iterations_reached")
                final_exit_reason = "max_iterations_reached"
                break

            # --- echo the assistant's tool-request turn into the EPHEMERAL
            #     local transcript (discarded after the turn; never persisted
            #     to working memory or episodic — only the final answer is). ---
            local.append(
                Message(role="assistant", content=response.content, tool_calls=response.tool_calls)
            )

            # --- deterministic ordered dispatch (NEVER gather; call_index
            #     monotonic across the whole turn, not per-iteration) ---
            # Not a behavioural guard, a construction-time invariant check:
            # reaching this branch means `response.tool_calls` is non-empty,
            # which is only possible when `tools` (built in Orient) was
            # non-empty, which is only possible when
            # `self._tool_registry is not None`. Production (#338) wires
            # registry/gate/dlp together as a trio, so a registry set without a
            # gate/dlp is a construction-time misconfiguration. An `assert`
            # here would be stripped under `python -O`, degrading this to an
            # opaque `AttributeError` inside `dispatch_tool` — an explicit
            # raise fails loud (hard rule #7) regardless of optimization flags,
            # and narrows all three for the `dispatch_tool` call below.
            if self._tool_registry is None or self._gate is None or self._outbound_dlp is None:
                # t()'d for consistency with the sibling quarantined_extract
                # wiring guards above (source_tier_must_be_t3 / no_extractor_wired).
                raise RuntimeError(t("orchestrator.tool.dispatch_seams_unwired"))
            if self._replay_journal is not None and response.tool_calls:
                # #410 PR2: journal the WHOLE iteration's decision as ONE
                # atomic write, BEFORE dispatching any call in it — so a
                # crash mid-dispatch still leaves a resume able to
                # fast-forward the entire iteration, rather than losing the
                # decision and re-asking a possibly-divergent planner.
                # Deliberately NOT one append per call inside the dispatch
                # loop below (a #410 design correction found during the
                # `/review-plan` fleet's second pass, 2026-08-07): a per-call
                # write would leave a crash window between journalling call
                # N and call N+1 of the SAME iteration — see
                # `ReplayJournal.append_batch`'s docstring (Task 1) for the
                # full failure mode this closes.
                await self._replay_journal.append_batch(
                    adapter_id=ctx.adapter_id,
                    inbound_id=ctx.inbound_id,
                    iteration=iteration,
                    calls=[
                        (call_index + offset, call)
                        for offset, call in enumerate(response.tool_calls)
                    ],
                )
            for call in response.tool_calls:
                result_t2 = await dispatch_tool(
                    call,
                    call_index,
                    ctx=ctx,
                    registry=self._tool_registry,
                    gate=self._gate,
                    dlp=self._outbound_dlp,
                    audit=self._audit,
                    user_id=user.slug,
                    correlation_id=trace_id,
                    language=user.language,
                )
                call_index += 1
                local.append(
                    Message(
                        role="tool",
                        tool_call_id=call.id,
                        content=_truncate_tool_result(result_t2),
                    )
                )

        # Invariant: every path that REACHES this point has assigned
        # final_response. Three things establish it, and all three are load-
        # bearing (#410 PR2 final whole-branch review, finding 1 — the
        # previous wording here claimed the sole no-completion exits were
        # "the iteration-0 pre-check raise / provider failure", which the
        # resume path falsified):
        #   1. Every raising exit (pre-check refusal, BudgetError from the
        #      estimate, provider failure, UnknownBudgetUserError on charge,
        #      the unwired-seams guard, a dispatch escalation, a journal
        #      write failure) leaves the function instead of arriving here.
        #   2. Every `break` OTHER than the budget pre-check's sits below
        #      `final_response = response`, so it cannot run before a
        #      completion landed; the budget pre-check's own break is now
        #      guarded by `if final_response is None:` taking the RAISE arm
        #      instead (finding 1a), which is what makes this hold on a
        #      RESUMED turn whose first fresh attempt is over budget.
        #   3. The loop body always breaks or raises on its final permitted
        #      iteration (the `iteration == MAX_TOOL_ITERATIONS - 1` guard),
        #      so the range is never merely exhausted — and the range is
        #      never EMPTY either, because `start_iteration >=
        #      MAX_TOOL_ITERATIONS` raises ReplayIterationCeilingError above
        #      the loop (finding 1b).
        assert final_response is not None
        answer = final_content if final_content is not None else final_response.content
        return _TurnOutcome(
            answer=answer,
            final_response=final_response,
            final_result_token=final_result_token,
            final_exit_reason=final_exit_reason,
            # A synthetic refusal (final_exit_reason set) is a local i18n
            # string, not a provider completion — its episodic row must carry
            # ZERO provider tokens/cost (the real cost already rode the
            # provider_call:* rows).
            answer_from_provider=final_exit_reason is None,
            estimate=estimate,
            per_turn_spent_usd=per_turn_spent_usd,
            pending_completion_cost=pending_completion_cost,
        )

    async def _persist_assistant_turn(
        self,
        session: AsyncSession,
        *,
        user: UserLike,
        outcome: _TurnOutcome,
        ctx: TurnEgressContext,
    ) -> bool:
        """Phase C body: assistant-gate + episodic assistant row in the caller's txn.

        ADR-0008: assistant output is T2 in Slice 1+2 (at-most-as-trusted as
        the T2 input that triggered it). ``outcome.answer`` is still returned
        by the caller regardless of this gate — a resumed turn always sends
        SOMETHING (a fresh completion's text, per ADR-0049's accepted
        "duplicate paid completion" residual) — this gate only stops that
        text from ALSO being re-persisted as a second assistant turn.
        """
        applied = (
            True
            if self._side_effect_ledger is None
            else await self._side_effect_ledger.try_apply_assistant_turn(
                session, adapter_id=ctx.adapter_id, inbound_id=ctx.inbound_id
            )
        )
        if not applied:
            return False
        episodic = self._episodic_factory(session)
        # FIX-15: episodic.record logs the FINAL completion's cost/tokens (the
        # answer's attribution); the `completed` audit row logs the TURN total
        # (per_turn_spent_usd). For a multi-completion turn these differ BY
        # DESIGN — episodic = answer attribution, audit = turn spend.
        await episodic.record(
            user_id=user.slug,
            role="assistant",
            content=outcome.answer,
            trust_tier="T2",
            tokens_in=outcome.final_response.tokens_in if outcome.answer_from_provider else 0,
            tokens_out=outcome.final_response.tokens_out if outcome.answer_from_provider else 0,
            cost_usd=outcome.final_response.cost_usd if outcome.answer_from_provider else 0.0,
            language=user.language,
            persona=_ALFRED_PERSONA_ID,
            # See _observe_user_turn for the persona vs persona_id rationale.
            persona_id=_ALFRED_PERSONA_ID,
        )
        return True

    async def _emit_turn_completed_row(
        self,
        *,
        user: UserLike,
        trace_id: str,
        outcome: _TurnOutcome,
        user_input_tier: str,
    ) -> None:
        completed_subject: dict[str, object] = {
            "phase": "completed",
            "model": outcome.final_response.model,
            "tokens_in": outcome.final_response.tokens_in,
            "tokens_out": outcome.final_response.tokens_out,
            "charge_result": outcome.final_result_token,
            "turn_cost_usd": outcome.per_turn_spent_usd,
        }
        if outcome.final_exit_reason is not None:
            completed_subject["exit_reason"] = outcome.final_exit_reason
        try:
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject(completed_subject, self._redactor),
                trust_tier_of_trigger=user_input_tier,
                result=outcome.final_result_token,
                cost_estimate_usd=outcome.estimate,  # MINOR-A: terminal estimate
                cost_actual_usd=outcome.pending_completion_cost,  # FIX-3: terminal cost only
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
        requesting user's slug. #338 ADDS an injected-context path (the live
        comms inbound passes a real ``TurnEgressContext`` to
        ``handle_user_message``); this synthesis is RETAINED as the
        ``alfred chat``/fixture default when no context is supplied.

        Replay note (spec §5): within a turn the same ``trace_id`` yields the
        same anchor, so ``compute_egress_id(ctx, call_index)`` is stable for a
        fixed dispatch sequence. Cross-turn at-most-once under re-planning (the
        deterministic-replay journal) is a tools-on follow-up concern, NOT
        #338's conversational scope — #339 has no live resume so it is not
        reachable.
        """
        return TurnEgressContext(
            adapter_id="orchestrator.synthetic",
            inbound_id=trace_id,
            session_id=user.slug,
        )

    async def _fast_forward_journalled_calls(
        self,
        *,
        ctx: TurnEgressContext,
        user: UserLike,
        trace_id: str,
        forwarded_context: bool,
    ) -> tuple[list[Message], int, int]:
        """Replay the journalled tool-call prefix for ``ctx.inbound_id``, if any.

        Returns ``(local, call_index, start_iteration)``: the reconstructed
        ephemeral tool transcript, the next ``call_index`` a fresh dispatch
        should use, and the iteration the main Act loop should resume from.
        Returns ``([], 0, 0)`` — behaviourally identical to today — in four
        cases, checked in this ORDER (each cheaper and more fundamental than
        the journal read it stands in front of):

        1. ``self._tool_registry is None``. Checked FIRST and
           unconditionally: this is what makes the whole seam provably
           dark/no-live-consumer until PR3 — a #410 design correction, found
           during the `/review-plan` fleet pass, to an earlier draft that
           only checked ``self._replay_journal is None`` and would have done
           a real Postgres round-trip on every live comms turn the moment
           Task 5's boot-graph wiring landed, well before PR3 exists.
        2. ``forwarded_context`` is ``False`` — ``_run_turn_phases``
           synthesized ``ctx`` instead of receiving one from a comms
           adapter, so ``ctx.inbound_id`` is a per-turn ``trace_id`` that BY
           CONSTRUCTION has never been journalled (the overwhelmingly common
           case even once tools are live: only a forwarded dispatched-edge
           replay, ADR-0039, can re-present the same ``inbound_id``). Added
           by the #410 PR2 final whole-branch review, finding 3; see the
           comment at the ``forwarded_context`` derivation in
           ``_run_turn_phases`` for why the READ is guarded on this and the
           WRITE deliberately is not.
        3. ``self._replay_journal is None``.
        4. No journal entries exist for this ``(adapter_id, inbound_id)`` —
           i.e. this forwarded frame's FIRST attempt, or an attempt that
           crashed before reaching the tool-dispatch stage.

        Each replayed call goes through the SAME ``dispatch_tool`` the
        normal path uses — the Spec C egress ledger's existing memoize-and-
        replay handles the actual dedup for ``ExternalToolSpec`` tools (e.g.
        web.fetch); this method adds no new dedup logic of its own.
        ``InternalToolSpec`` tools (e.g. `clock.now`) have NO such
        protection and re-dispatch for real on every fast-forward — an
        accepted, documented gap (Task 1's module docstring) since they are
        side-effect-free by construction. Entries are sorted by
        ``(iteration, call_index)`` and then grouped by their journalled
        ``iteration`` — ``read()`` only orders by ``call_index ASC``, and
        the two are not the same key, so grouping the raw read order would
        silently split one iteration across two groups the moment they
        diverge (CodeRabbit review, PR #579, 2026-08-10) — so the
        reconstructed transcript's assistant-tool_calls / tool-result
        message SHAPE
        matches the original run — the reconstructed assistant message's
        ``content`` is always the empty string, NOT the original model's
        accompanying text (the journal does not store it — only the tool
        calls). This is a deliberate, accepted simplification: `local` is
        purely EPHEMERAL scratch space for the remainder of THIS turn's
        completions, never persisted to working memory or episodic history,
        so the wrap-up completion sees a structurally faithful tool-call/
        tool-result exchange without needing the original prose.
        """
        if self._tool_registry is None:
            return [], 0, 0
        if not forwarded_context:
            return [], 0, 0
        if self._replay_journal is None:
            return [], 0, 0
        entries = await self._replay_journal.read(
            adapter_id=ctx.adapter_id, inbound_id=ctx.inbound_id
        )
        if not entries:
            return [], 0, 0
        if self._gate is None or self._outbound_dlp is None:
            # tool_registry is confirmed non-None above; gate/outbound_dlp
            # unwired alongside it is the SAME construction-time
            # misconfiguration the main Act loop's dispatch-loop guard
            # (below, ahead of its own `for call in response.tool_calls:`)
            # already names.
            raise RuntimeError(t("orchestrator.tool.dispatch_seams_unwired"))
        local: list[Message] = []
        max_iteration = -1
        # Sort by (iteration, call_index) before grouping: `read()` orders
        # by `call_index ASC` ONLY, and `groupby` groups CONSECUTIVE keys,
        # so grouping the raw read order would silently split one iteration
        # into two assistant messages the moment iterations interleave in
        # call-index order. Same defensive posture as `entry.call_index`
        # (commit 360e60a8) and `max(...)` below: read the journalled
        # values, don't trust a derived ordering (CodeRabbit review, PR
        # #579, 2026-08-10).
        ordered_entries = sorted(entries, key=lambda e: (e.iteration, e.call_index))
        for iteration, group in itertools.groupby(ordered_entries, key=lambda e: e.iteration):
            group_entries = list(group)
            calls = tuple(entry.tool_call for entry in group_entries)
            # content="" — see the docstring above: the journal stores tool
            # calls only, never the model's accompanying prose. `calls` is a
            # tuple (not a list) — Message.tool_calls is typed
            # tuple[ToolCall, ...] (a #410 design correction found during
            # the `/review-plan` fleet's second pass, 2026-08-07: an earlier
            # draft passed a list here, which mypy --strict rejects).
            local.append(Message(role="assistant", content="", tool_calls=calls))
            for entry in group_entries:
                # Dispatch using entry.call_index DIRECTLY, not a freshly
                # re-derived local counter (a #410 design correction found
                # during the `/review-plan` fleet's second pass, 2026-08-07):
                # call_index is the sole (with ctx) input to
                # compute_egress_id, so replay convergence must reproduce
                # the EXACT call_index the original dispatch used — reading
                # it straight from the journal makes that self-evidently
                # true rather than dependent on an unenforced contiguity
                # invariant on the write side.
                result_t2 = await dispatch_tool(
                    entry.tool_call,
                    entry.call_index,
                    ctx=ctx,
                    registry=self._tool_registry,
                    gate=self._gate,
                    dlp=self._outbound_dlp,
                    audit=self._audit,
                    user_id=user.slug,
                    correlation_id=trace_id,
                    language=user.language,
                )
                local.append(
                    Message(
                        role="tool",
                        tool_call_id=entry.tool_call.id,
                        content=_truncate_tool_result(result_t2),
                    )
                )
            # `max(...)`, not a plain assignment (#410 PR2 final whole-branch
            # review, finding 2): a plain assignment would make the LAST
            # group's iteration the resume point, which is only the MAXIMUM
            # while `read()`'s `call_index ASC` ordering happens to coincide
            # with iteration-ascending order — true today by write-side
            # construction, but an unenforced invariant rather than a
            # guarantee. Same defensive posture the fast-forward dispatch
            # above already takes for `entry.call_index` (commit 360e60a8):
            # read the journalled value, don't trust a derived ordering.
            max_iteration = max(max_iteration, iteration)
        # max(...) over ALL entries, not the last one processed: sorting
        # groups by iteration does not guarantee the highest call_index also
        # belongs to the highest iteration once they interleave — same
        # reasoning as `max_iteration` above.
        next_call_index = max(entry.call_index for entry in entries) + 1
        return local, next_call_index, max_iteration + 1
