"""Real privileged-turn inbound adapter (#338 PR2).

Replaces the deterministic-echo ``CommsInboundOrchestratorAdapter`` on the
production comms-inbound path. Satisfies the SAME ``_OrchestratorLike`` Protocol
(``quarantined_extract`` / ``ingest`` / ``dispatch``), so every Spec A/B
idempotency + replay invariant in ``process_inbound_message`` is untouched.

Turn placement (FOLD-3): ``ingest`` ONLY PREPARES the turn inputs (extract-result
branch -> gate-checked T3->T2 ``downgrade_to_orchestrator`` -> ``tag(T2)`` -> build
``UserLike`` + ``TurnEgressContext``). The real turn + the outbound send run inside
``dispatch`` (Task 2), which the forwarded path wraps in the audited
``dispatch_failed`` + bounded-replay envelope. Running the (paid) turn in ``ingest``
would put it OUTSIDE that envelope and replay it to the poison ceiling on any
failure (up to 5 duplicate paid completions).

The downgrade gate-DENY, BudgetError, and turn-error legs each write a LOUD,
content-free audit row owned by THIS adapter (``check_content_clearance`` writes no
audit on a policy deny — FOLD-5 / CLAUDE.md hard rule #7). Egress tools were
conversational-scope-only through #338/#410 PR2; since #410 PR3 the orchestrator
carries a live ``clock.now``-only tool registry, so the loop can genuinely iterate
(``dispatch`` may run more than one completion per turn). ``web.fetch`` remains
deferred (allowlist-projection gap, #582/#583).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, assert_never
from uuid import uuid4

import structlog

from alfred.audit import audit_row_schemas  # FOLD-R10
from alfred.budget.guard import BudgetError
from alfred.comms_mcp import audit_hash  # FOLD-R10: audit_hash lives in comms_mcp, NOT alfred.audit
from alfred.comms_mcp.protocol import (
    TURN_STATE_CLIENT_KINDS,
    OutboundMessageRequest,
    TurnFailedNotification,
    TurnFailureStage,
)
from alfred.errors import AlfredError
from alfred.i18n import set_language, t
from alfred.orchestrator.core import _ALFRED_PERSONA_ID as _PERSONA
from alfred.security.dlp import OutboundCanaryTripped
from alfred.security.quarantine import (
    DowngradeDeniedError,
    Extracted,
    TypedRefusal,
    downgrade_to_orchestrator,
)
from alfred.security.tiers import T2, tag

if TYPE_CHECKING:
    from collections.abc import Mapping

    from alfred.audit.log import AuditWriter
    from alfred.comms_mcp.bootstrap import CommsExtractorBridge
    from alfred.comms_mcp.daemon_runtime import OutboundSenderLike
    from alfred.egress.egress_id import TurnEgressContext
    from alfred.hooks.capability import CapabilityGate
    from alfred.memory.working_pool import WorkingMemoryPool  # FOLD-R10: memory.working_pool
    from alfred.orchestrator.core import Orchestrator
    from alfred.security.dlp import OutboundDlp
    from alfred.security.quarantine import ExtractionResult
    from alfred.security.tiers import TaggedContent

_log = structlog.get_logger(__name__)

# #338 is single-persona (DM/1:1). The pool is keyed (persona, canonical_user_id);
# "alfred" is the only enabled persona this slice. Group/multi-persona addressing
# is an explicit follow-up (FOLD-6). FOLD-R20: ``_PERSONA`` (imported above as
# ``_ALFRED_PERSONA_ID``) is the SAME shared persona-id constant the orchestrator
# writes episodic under and the pool rehydrates by (``working_pool.py:116``), so
# ``dispatch``'s pool-acquire key can never silently desync from rehydrate on a
# future persona rename — a fresh "alfred" literal here would risk exactly that.
# RE-VERIFIED (Task 2, #338): importing ``alfred.orchestrator.core`` at module
# level does not create an import cycle — it imports
# ``alfred.comms_mcp.observability`` (a sibling leaf module, not this one), and
# ``alfred.comms_mcp/__init__.py`` never imports ``real_turn_adapter``, so the
# dependency stays acyclic even though the two packages now reference each other
# overall (confirmed: this module's test suite collects and passes cleanly, which
# a real cycle would prevent).

# DM/1:1 reply (FOLD-6) — matches the echo adapter's dm-only reply leg.
_ADDRESSING_MODE: Literal["dm"] = "dm"

# Closed-vocab refusal stages for the adapter-owned loud audit row. FOLD-R24:
# `downgrade_malformed` (defensive text-type-guard) is DISTINCT from
# `downgrade_denied` (gate policy deny). FOLD-R11: `send_failed` for the outbound leg.
# #410 PR3 (I4 fix wave): `dlp_canary_tripped` for an `OutboundCanaryTripped` raised
# out of `dispatch_tool` — deterministic like `budget_denied`, so it halts rather
# than re-raising into the generic `turn_error` replay leg. #594 R1 (Fix C2):
# `dlp_scan_failed` for a NON-canary fault out of the outbound scan (e.g. a
# broker/vault blip in DLP stage 1) — DISTINCT from `send_failed` because the scan
# runs strictly BEFORE any wire write, so the wire is still healthy and a client
# notify is both deliverable and honest.
_RefusalStage = Literal[
    "downgrade_denied",
    "downgrade_malformed",
    "budget_denied",
    "dlp_canary_tripped",
    "dlp_scan_failed",
    "turn_error",
    "send_failed",
]

# A wedged-but-connected client must not hold the turn leg.
_NOTIFY_TIMEOUT_SECONDS: Final[float] = 2.0


def _client_turn_failure_stage(stage: _RefusalStage) -> TurnFailureStage | None:
    """Map the private AUDIT stage to the CLOSED client-facing wire stage (#593).

    ``None`` == deliberately not client-notifiable. Exhaustive over
    ``_RefusalStage`` via ``assert_never``: a future refusal stage added
    WITHOUT a client decision is a type-check failure here, never a silent
    drop — which is exactly the #593 regression shape.
    """
    match stage:
        case "downgrade_denied" | "dlp_canary_tripped":
            # COARSE on purpose: never name the control that fired.
            return "refused"
        case "budget_denied":
            return "budget_exhausted"
        case "downgrade_malformed" | "turn_error" | "dlp_scan_failed":
            # A scan-infrastructure fault (vault/broker blip) is genuinely an
            # internal error, not a refusal — and it is not attacker-triggerable
            # by content, so separating it from `refused` opens no oracle.
            return "internal_error"
        case "send_failed":
            # NOT notifiable — the client-side watchdog is the backstop.
            return None
    assert_never(stage)  # pragma: no cover


class _HasInboundIdentity(Protocol):
    """Structural shape ``_emit_refused`` reads off its ``notification`` arg.

    Both the wire ``notification`` object ``ingest`` receives and ``dispatch``'s
    ``_NotificationView`` (a ``_PreparedTurn`` adapter, below) satisfy this. A
    small Protocol instead of ``Any`` so a call site with a missing/misnamed
    field fails mypy at the call site rather than surfacing as an
    ``AttributeError`` inside the audit-emission path.
    """

    @property
    def adapter_id(self) -> str: ...

    @property
    def inbound_id(self) -> str: ...


@dataclass(frozen=True, slots=True)
class _InboundUser:
    """Concrete ``UserLike`` (core.py:158) built from the resolved inbound identity.

    A frozen value the orchestrator reads three fields off (``slug`` /
    ``display_name`` / ``language``). ``display_name`` is platform-influenced +
    UNTRUSTED once it enters the persona prompt — the corpus entry (Task 6) pins
    that it is treated as data, not instructions.
    """

    slug: str
    display_name: str
    language: str


@dataclass(frozen=True, slots=True)
class _PreparedTurn:
    """``ingest`` output when the turn will run: the cleared T2 inputs + identity."""

    content: TaggedContent[T2]
    user: _InboundUser
    egress: TurnEgressContext
    adapter_id: str
    target_platform_id: str


@dataclass(frozen=True, slots=True)
class _RefusalReply:
    """``ingest`` output for a quarantine ``TypedRefusal`` — send a benign reply.

    ``canonical_user_id`` (arc-001, PR #594 Task S1) is carried so ``dispatch``
    can key ``_await_turn_ordering_barrier`` at the SAME ``(persona, slug)``
    the ``_PreparedTurn`` leg locks on. Internal only, mirroring
    ``_HaltNoReply``'s existing note below — NOT a reply address and NOT on
    the wire; ``TurnFailedNotification`` and ``OutboundMessageRequest`` carry
    no such field.
    """

    reply: str
    adapter_id: str
    target_platform_id: str
    canonical_user_id: str


@dataclass(frozen=True, slots=True)
class _HaltNoReply:
    """``ingest`` output for a security/budget deny — audited, NO REPLY is sent.

    ``adapter_id`` (#593) is carried so ``dispatch`` can address the client-visible
    turn-failure NOTIFICATION at the right adapter kind. It is NOT a reply address
    (there is no reply) and NOT on the wire — the frame carries no ``adapter_id``.

    ``canonical_user_id`` (arc-001, PR #594 Task S1) is carried for the same
    reason as ``_RefusalReply`` above: it keys ``_await_turn_ordering_barrier``
    at the same ``(persona, slug)`` a ``_PreparedTurn`` for this user would
    lock on. Internal only, NOT on the wire.
    """

    stage: _RefusalStage
    adapter_id: str
    canonical_user_id: str


type _IngestOutcome = _PreparedTurn | _RefusalReply | _HaltNoReply


@dataclass(frozen=True, slots=True)
class _NotificationView:
    """Adapt a ``_PreparedTurn`` to the ``adapter_id``/``inbound_id`` shape ``_emit_refused`` reads.

    ``dispatch``'s BudgetError / turn-error legs have no wire ``notification``
    object on hand — only the already-prepared turn — so this view lets those
    legs reuse ``_emit_refused`` (Task 1) without threading a second parameter
    shape through the error-handling call sites.
    """

    _prepared: _PreparedTurn

    @property
    def adapter_id(self) -> str:
        return self._prepared.egress.adapter_id

    @property
    def inbound_id(self) -> str:
        return self._prepared.egress.inbound_id


@dataclass(frozen=True, slots=True)
class _TurnSucceeded:
    """``dispatch``'s pool-bracketed turn completed normally (perf-001, PR #594).

    Carries the orchestrator's answer OUT of the ``async with lock:`` block so
    the outbound send (already outside the mutex, FOLD-R11) can run once the
    per-user lock has released — unchanged from before this fix.
    """

    answer: str


@dataclass(frozen=True, slots=True)
class _TurnFailed:
    """``dispatch``'s pool-bracketed turn hit a refusal/error leg (perf-001, PR #594).

    Before this fix, each refusal leg's ``await self._notify_turn_failed(...)``
    (up to a 2.0s wire-send timeout) ran INSIDE ``async with lock:`` — holding
    the per-(persona, slug) turn mutex hostage to a wedged-but-connected
    client, unlike the successful-turn ``_send`` call which was already
    outside the lock. This type carries the notify stage + (optional)
    exception-to-reraise OUT of the lock so ``dispatch`` can notify (and, on
    the ``turn_error`` leg, re-raise) AFTER the mutex has released, while
    preserving each leg's original notify-then-{return,raise} ORDER.

    DOWNSTREAM CONTRACT (#594 follow-up finding, CLOSED by arc-001's ordering
    barrier — PR #594 Task S1, see ``_await_turn_ordering_barrier`` below):
    the TUI plugin's stale-turn debt counter
    (``AlfredTuiApp._resolve_pending_turn``,
    ``plugins/alfred_tui/src/alfred_tui/textual/app.py``) has no wire-level
    way to tell "this reply/turn.failed is for the turn I'm currently
    waiting on" apart from "this is a late signal for a turn my watchdog
    already gave up on" — the client's ONLY correctness lever is that this
    module sends one session's turn-completion signals to the sender in
    SUBMISSION order, even when two dispatches for the same ``(persona,
    slug)`` key are in flight "concurrently" from the caller's perspective.
    That guarantee now genuinely covers ALL THREE ``ingest`` outcomes —
    ``_PreparedTurn``, ``_RefusalReply``, and ``_HaltNoReply`` alike (before
    arc-001's fix it covered only the first: the two ingest-resolved outcomes
    never touched the per-key lock at all, so a later same-key turn's
    refusal could signal the client before an earlier same-key turn's own
    answer — reproduced by execution against the real adapter). It rests on
    TWO invariants living here, both load-bearing for a module the TUI never
    imports or type-checks against:

    1. the per-key ``asyncio.Lock`` (FOLD-R1) serializes same-key turns'
       PROCESSING — a later ``_PreparedTurn`` cannot even START running the
       orchestrator until every earlier same-key turn has released the lock.
       ``_RefusalReply``/``_HaltNoReply`` carry no turn work to serialize, so
       each instead AWAITS ``_await_turn_ordering_barrier`` — an
       acquire-then-immediately-release of the SAME per-key lock, purely as
       an ordering fence — before its own notify/send, giving it the
       identical acquire-then-signal SHAPE the ``_PreparedTurn`` leg already
       had;
    2. no ``await`` sits between a turn's lock release (the ``async with
       lock:`` block exiting for ``_PreparedTurn``, or the barrier's
       ``async with lock: pass`` returning for the other two outcomes) and
       that turn's notify/send call being INITIATED (see the ``perf-001``
       note on ``dispatch`` below) — so a later turn's own signal cannot
       reach the sender before an earlier turn's.

    One caveat inherent to the mechanism, not a bug: the lock gives
    ARRIVAL-AT-LOCK order, not SUBMISSION order — two same-key turns whose
    ``ingest()`` durations differ enough could in principle reach the lock
    out of the order they were submitted in. Immaterial in practice (the TUI
    can only have two turns outstanding at all once a 90s watchdog timeout
    has already separated them — see ``on_input_submitted`` in ``app.py``),
    but worth naming precisely rather than overselling "submission order" as
    a literal guarantee.

    Do not introduce an ``await`` between lock release and notify/send
    initiation on ANY of the three outcomes, and do not loosen the
    per-``(persona, slug)`` lock to allow same-key concurrency, without first
    re-reading ``AlfredTuiApp._resolve_pending_turn`` and the tests that pin
    this ordering in
    ``tests/unit/comms_mcp/test_real_turn_adapter_dispatch.py``:
    ``test_dispatch_notifies_same_key_turns_in_submission_order_even_when_concurrent``
    (the in-lock <-> in-lock case, unchanged since before arc-001),
    ``test_dispatch_halt_no_reply_waits_for_an_earlier_same_key_turn``, and
    ``test_dispatch_refusal_reply_waits_for_an_earlier_same_key_turn`` (the
    two ingest-resolved outcomes against an earlier in-lock turn) — all three
    fail loudly if this ordering ever regresses.
    """

    stage: _RefusalStage
    reraise: Exception | None


class RealTurnOrchestratorAdapter:
    """The ``_OrchestratorLike`` the live comms-inbound path drives (#338 PR2)."""

    def __init__(
        self,
        *,
        orchestrator: Orchestrator,
        working_memory_pool: WorkingMemoryPool,
        gate: CapabilityGate,
        audit_writer: AuditWriter,
        outbound_dlp: OutboundDlp,
        extractor_bridge: CommsExtractorBridge,
    ) -> None:
        self._orchestrator = orchestrator
        self._pool = working_memory_pool
        self._gate = gate
        self._audit = audit_writer
        self._outbound_dlp = outbound_dlp
        self._extractor_bridge = extractor_bridge
        self._sender: OutboundSenderLike | None = None
        # FOLD-R1 (MEM-1, Critical): the comms pump dispatches notifications
        # concurrently (comms_runner.py:663, semaphore 32/adapter), and the pool
        # hands the SAME shared WorkingMemory buffer to concurrent acquirers of one
        # (persona, slug) key (working_pool.py:135-146 — _in_use is a set, not a
        # refcount; its lock guards only rehydrate). So two same-user frames would
        # race the one deque. This per-key turn mutex serialises the WHOLE
        # acquire->handle_user_message->release span (Task 2's dispatch). `_locks_guard`
        # guards the lock-map itself (single event loop, but keep the create-or-get
        # atomic).
        self._turn_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()

    def bind_outbound_sender(self, sender: OutboundSenderLike) -> None:
        """Wire the late-bound outbound seam (bound per-adapter after the runner exists)."""
        self._sender = sender

    async def quarantined_extract(
        self,
        # FOLD-R8: Mapping, not dict (Protocol contravariance at _comms_boot.py:967).
        body: bytes | str | Mapping[str, object],
        *,
        canonical_user_id: str,
        source_tier: Literal["T3"],
    ) -> ExtractionResult:
        """Delegate to the bridge — identical to the echo adapter (the child is unchanged).

        FOLD-R18: this delegation + the outbound-send path duplicate the echo
        adapter; extract a shared helper (both adapters import it) OR justify the
        retained duplication (the echo class is the documented rollback fallback).
        """
        return await self._extractor_bridge.extract(
            body=body, canonical_user_id=canonical_user_id, source_tier=source_tier
        )

    async def ingest(self, **kwargs: Any) -> _IngestOutcome:
        """Prepare the turn inputs — the turn itself runs in ``dispatch`` (FOLD-3)."""
        notification = kwargs["notification"]
        extracted: ExtractionResult = kwargs["extracted"]
        canonical_user_id: str = kwargs["canonical_user_id"]
        language: str = kwargs["language"]
        display_name: str = kwargs["display_name"]
        # Render this adapter's own t() strings in the user's language (ContextVar;
        # propagates across awaits within this inbound coroutine — translator.py:161).
        set_language(language)

        if isinstance(extracted, TypedRefusal):
            return _RefusalReply(
                reply=t("comms.inbound.real_turn.extraction_refused"),
                adapter_id=notification.adapter_id,
                target_platform_id=notification.platform_user_id,
                canonical_user_id=canonical_user_id,
            )

        # FOLD-R23: explicit raise, not `assert` (stripped under python -O; matches
        # the core.py:973 wiring-guard pattern). The union is Extracted | TypedRefusal.
        if not isinstance(extracted, Extracted):  # pragma: no cover - exhaustive union
            raise RuntimeError(t("comms.inbound.real_turn.unexpected_extract_kind"))
        try:
            # FOLD-R16 (#338 PR2 review): `downgrade_to_orchestrator` raises the typed
            # `DowngradeDeniedError` (a narrow `AlfredError` subclass) on a gate policy
            # deny — narrowing the catch to it (rather than the broad `AlfredError`)
            # means a future, unrelated `AlfredError` raised inside that call (e.g. a
            # transient audit-write fault) propagates loudly instead of being silently
            # committed here as a no-reply turn.
            cleared = await downgrade_to_orchestrator(
                extracted.data, gate=self._gate, audit_writer=self._audit
            )
        except DowngradeDeniedError as exc:
            await self._emit_refused(
                notification, canonical_user_id=canonical_user_id, stage="downgrade_denied", exc=exc
            )
            return _HaltNoReply(
                stage="downgrade_denied",
                adapter_id=notification.adapter_id,
                canonical_user_id=canonical_user_id,
            )

        text = cleared.get("text")
        if not isinstance(text, str):  # defensive: the CommsBodyExtraction schema pins text:str
            # FOLD-R24: DISTINCT stage from the gate deny.
            await self._emit_refused(
                notification,
                canonical_user_id=canonical_user_id,
                stage="downgrade_malformed",
                exc=AlfredError("downgraded payload missing str 'text'"),
            )
            return _HaltNoReply(
                stage="downgrade_malformed",
                adapter_id=notification.adapter_id,
                canonical_user_id=canonical_user_id,
            )

        content = tag(T2, text, source="comms.inbound")
        user = _InboundUser(slug=canonical_user_id, display_name=display_name, language=language)
        # Import here to keep the module import graph light (egress is a heavy leaf).
        from alfred.egress.egress_id import TurnEgressContext

        egress = TurnEgressContext(
            adapter_id=notification.adapter_id,
            inbound_id=notification.inbound_id,
            session_id=canonical_user_id,
        )
        return _PreparedTurn(
            content=content,
            user=user,
            egress=egress,
            adapter_id=notification.adapter_id,
            target_platform_id=notification.platform_user_id,
        )

    async def _emit_refused(
        self,
        notification: _HasInboundIdentity,
        *,
        canonical_user_id: str,
        stage: _RefusalStage,
        exc: BaseException,
    ) -> None:
        """Write the LOUD, content-free adapter-owned refusal row (FOLD-5 / rule #7).

        FOLD-R2: keyed by the PEPPERED ``inbound_id_hash`` (mirrors
        ``_emit_dispatch_failed``); ``error_class`` is the CLASS name never
        ``str(exc)`` (could embed T3-derived text); ``actor_user_id`` carries the
        canonical slug RAW for attribution (an internal id, raw-eligible — matches
        ``orchestrator.turn``, core.py:1049). ``audit_hash.set_broker`` is live
        before this fires (inbound.py:707 runs at the top of every
        ``process_inbound_message``); unit tests MUST wire it (FOLD-R12).
        """
        inbound_id_hash = audit_hash.hash_inbound_id(notification.inbound_id)
        _log.warning(
            "comms.inbound.real_turn.refused",
            adapter_id=notification.adapter_id,
            refusal_stage=stage,
            error_class=type(exc).__name__,
        )
        await self._audit.append_schema(
            fields=audit_row_schemas.COMMS_INBOUND_TURN_REFUSED_FIELDS,
            schema_name="COMMS_INBOUND_TURN_REFUSED_FIELDS",
            event="comms.inbound.real_turn.refused",
            actor_user_id=canonical_user_id,  # RAW internal slug (FOLD-R2)
            subject={
                "adapter_id": notification.adapter_id,
                "inbound_id_hash": inbound_id_hash,
                "refusal_stage": stage,
                "error_class": type(exc).__name__,
                "observed_at": datetime.now(UTC).isoformat(),
            },
            trust_tier_of_trigger="T3",
            result="refused",
            cost_estimate_usd=0.0,
            trace_id=inbound_id_hash,
        )

    async def _notify_turn_failed(
        self,
        sender: OutboundSenderLike,
        *,
        adapter_id: str,
        stage: _RefusalStage,
    ) -> None:
        """Best-effort client-visible turn-failure signal (#593).

        NEVER raises — except ``CancelledError``, which propagates BY DESIGN
        (it derives from ``BaseException``, so the bare ``except Exception``
        below cannot catch it, and a caller-level cancellation must genuinely
        cancel an in-flight notify rather than be logged like a wire fault).

        The AUTHORITATIVE record is the audit row ``_emit_refused`` already wrote
        BEFORE this call; this frame is a UX affordance whose failure backstop is
        the client's own turn watchdog. A fault here is LOUD-but-contained:

        * On the ``_HaltNoReply`` legs, raising would convert a DETERMINISTIC halt
          into a re-raise -> the forwarded path's replay -> duplicate paid
          completions that re-fail identically. Exactly what `_HaltNoReply` exists
          to prevent.
        * On the ``turn_error`` leg, raising would REPLACE the re-raise of the
          real turn fault with a transport fault — losing the fault the replay
          path is supposed to act on.

        #594 R1 (err-001): the containment is over ``Exception``, not a fixed
        wire-fault tuple, because the docstring above is a contract other code
        relies on IN PROSE and a narrow tuple made it a lie — anything outside
        it (a ``ValidationError`` from constructing the notification, a bug in a
        sender implementation) escaped and did exactly the damage the two
        bullets describe. This is NOT a swallow-and-continue in a business
        path: the authoritative audit row is already written, the fail-loud
        posture is preserved by the ``_log.warning`` (``error_class`` only,
        never ``str(exc)``), and the alternative is strictly worse. Containment
        IS the fail-loud choice at this seam.
        """
        if adapter_id not in TURN_STATE_CLIENT_KINDS:
            _log.debug(
                "comms.inbound.real_turn.turn_state_unsupported_kind",
                adapter_id=adapter_id,
                refusal_stage=stage,
            )
            return
        client_stage = _client_turn_failure_stage(stage)
        if client_stage is None:
            # Symmetric with the `TURN_STATE_CLIENT_KINDS` skip above: no
            # production call site passes `send_failed` here today (`_send`'s
            # SEND-leg except block deliberately never notifies — see its
            # docstring; its SCAN leg does, but only ever with
            # `dlp_canary_tripped`/`dlp_scan_failed`), but the parameter type
            # stays the full `_RefusalStage` so a future call site is a
            # type-check pass, not a silent drop.
            # Log it so "why did nothing happen here" stays traceable if that
            # ever changes.
            _log.debug(
                "comms.inbound.real_turn.turn_state_not_notifiable",
                adapter_id=adapter_id,
                refusal_stage=stage,
            )
            return
        try:
            await asyncio.wait_for(
                sender.send_turn_state(TurnFailedNotification(stage=client_stage)),
                timeout=_NOTIFY_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            _log.warning(
                "comms.inbound.real_turn.turn_failed_notify_timeout",
                adapter_id=adapter_id,
                refusal_stage=stage,
                timeout_s=_NOTIFY_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            # Bare `Exception` (not a wire-fault tuple) — see the docstring:
            # this seam's whole job is to be a dead end for faults, and
            # `CancelledError` (BaseException) still propagates.
            _log.warning(
                "comms.inbound.real_turn.turn_failed_notify_failed",
                adapter_id=adapter_id,
                refusal_stage=stage,
                error_class=type(exc).__name__,  # CLASS NAME, never str(exc)
            )
        else:
            _log.info(
                "comms.inbound.real_turn.turn_failed_notified",
                adapter_id=adapter_id,
                turn_failure_stage=client_stage,
            )

    def _require_sender(self) -> OutboundSenderLike:
        """Return the bound sender or raise loudly (no silent failure, rule #7).

        Reuses the echo adapter's ``sender_unbound`` catalog msgid (grepped in
        ``daemon_runtime.py`` — same operator-facing meaning) rather than minting
        a duplicate ``sender_not_bound`` entry for an identical message.
        """
        if self._sender is None:
            _log.error("comms.daemon_runtime.sender_unbound")
            raise RuntimeError(t("comms.daemon_runtime.sender_unbound"))
        return self._sender

    async def dispatch(self, ingested: object) -> None:
        """Run the turn (FOLD-3) then send the DLP-scanned answer — or the benign reply.

        On the FORWARDED path this runs inside ``process_inbound_message``'s
        ``dispatch`` try/except (inbound.py:885): a re-raised turn error takes the
        audited ``dispatch_failed`` + bounded-replay path. BudgetError, an
        ``OutboundCanaryTripped`` DLP-canary trip (#410 PR3 — out of
        ``dispatch_tool``'s totality wrapper on either tool leg; since #594 R1
        Fix C2 also out of the FINAL answer's own outbound scan, classified
        identically in ``_send``), and the downgrade-deny (handled in
        ``ingest``) are DETERMINISTIC — the adapter
        audits them loudly and HALTS (no reply, no re-raise) so the frame commits
        rather than burning the replay ceiling on a completion that will re-fail
        identically (same content, same canary token, every retry). Genuinely
        transient turn errors (provider outage / deadline) DO re-raise so the
        forwarded leg can retry within the poison ceiling.

        FOLD-R25: on a forwarded replay both this adapter's ``turn_error`` row AND
        the inbound path's ``dispatch_failed`` row write — INTENTIONAL: they are
        distinct events (adapter-semantic turn fault vs inbound-transport dispatch
        fault) and both are content-free.

        #593 precondition: the ``turn_error`` leg's notify-then-raise ordering
        below is only correct because ``TURN_STATE_CLIENT_KINDS`` does not (yet)
        include any hosted/forwarded adapter kind. If one is ever added, a
        ``turn.failed`` sent on attempt 1 of a bounded-replay-eligible turn would
        be a LIE the moment a later attempt succeeds — this ordering must be
        revisited in the same commit that widens ``TURN_STATE_CLIENT_KINDS``.

        perf-001 (PR #594): the ``budget_denied`` / ``dlp_canary_tripped`` /
        ``turn_error`` legs' ``_notify_turn_failed`` call (up to a 2.0s wire-send
        timeout) runs AFTER the ``async with lock:`` block below has released —
        mirroring the successful-turn ``_send`` call's existing outside-the-mutex
        placement. Each leg's audit-write-then-notify-then-{return,raise} ORDER
        is unchanged; only the LOCK boundary moved. See ``_TurnFailed``.

        DO NOT add an ``await`` between a turn's lock release and the
        notify/``_send`` call that follows it — for ``_PreparedTurn`` that is
        the ``async with lock:`` block below releasing; for ``_HaltNoReply``
        and ``_RefusalReply`` it is ``_await_turn_ordering_barrier`` (below)
        returning (``_send``'s own scan-FAILURE legs are the one documented
        exception — see its docstring). Two same-``(persona, slug)``-key
        turns can no longer signal the client out of submission order —
        arc-001 (PR #594 Task S1) closed the gap where this held only
        for a ``_PreparedTurn``-vs-``_PreparedTurn`` pairing: the two
        ingest-resolved outcomes now take the SAME ordering barrier instead
        of running turn work under the lock, so EVERY pairing is covered
        (modulo the arrival-at-lock-vs-submission-order caveat on
        ``_TurnFailed`` above, which applies here too). A
        downstream client (the TUI's stale-turn debt counter) depends on
        this: it has NO wire-level correlation available to check it itself.
        See the longer note on ``_TurnFailed`` above and
        ``test_dispatch_notifies_same_key_turns_in_submission_order_even_when_concurrent``,
        ``test_dispatch_halt_no_reply_waits_for_an_earlier_same_key_turn``,
        and ``test_dispatch_refusal_reply_waits_for_an_earlier_same_key_turn``
        in ``tests/unit/comms_mcp/test_real_turn_adapter_dispatch.py``.
        """
        if isinstance(ingested, _HaltNoReply):
            # #593: the frame is committed and NOTHING is sent — but the operator
            # must not be left staring at a dead prompt. Signal the STATE (no text
            # on the wire) so the client can release its pending turn.
            #
            # arc-001 (PR #594 Task S1): the barrier runs UNCONDITIONALLY,
            # BEFORE the sender is even read — even with no sender bound there
            # is still an ordering contract to honour for whichever other
            # same-key turn eventually does have one. The sender itself is
            # read AFTER the barrier returns (not before): a synchronous
            # attribute read introduces no ``await`` and so doesn't touch the
            # no-await-between-release-and-notify invariant, and reading it
            # late is strictly FRESHER — a sender bound while this coroutine
            # was parked on the barrier must be seen, not missed via a stale
            # snapshot taken before the wait. Do not raise on ``None`` here —
            # a wiring precondition (unbound sender) must not turn this
            # DETERMINISTIC halt into a re-raise that the forwarded path's
            # bounded replay would amplify into up to 5 duplicate quarantined
            # extracts re-writing the identical audit row (the CodeRabbit
            # finding folded into this fix, root-cause report §2).
            await self._await_turn_ordering_barrier(ingested.canonical_user_id)
            sender = self._sender
            if sender is None:
                _log.error("comms.daemon_runtime.sender_unbound")
                return
            await self._notify_turn_failed(
                sender, adapter_id=ingested.adapter_id, stage=ingested.stage
            )
            return
        if isinstance(ingested, _RefusalReply):
            # This leg genuinely cannot proceed without a sender — there is a
            # reply to DELIVER, unlike the halt leg above, so fail-loud (raise)
            # via `_require_sender()` is the correct posture here. Deliberately
            # the mirror image of the halt leg's read: `_require_sender()` runs
            # EARLY, BEFORE the barrier, because this branch always needs a
            # sender to do its job — if none is bound, raise immediately rather
            # than parking on the barrier first only to fail after. The halt
            # leg above reads late (after the barrier) precisely because it can
            # legitimately complete with NO sender at all (one may bind mid-wait
            # or never bind), so there is no reason to fail-fast there.
            sender = self._require_sender()
            await self._await_turn_ordering_barrier(ingested.canonical_user_id)
            await self._send(
                sender,
                ingested.adapter_id,
                ingested.target_platform_id,
                ingested.reply,
                notification=None,
                canonical_user_id=None,
            )
            return
        if not isinstance(ingested, _PreparedTurn):  # defensive — the ingest union is closed
            raise RuntimeError(t("comms.daemon_runtime.dispatch_bad_ingested"))

        sender = self._require_sender()
        set_language(ingested.user.language)
        key = (_PERSONA, ingested.user.slug)
        note = _NotificationView(ingested)
        # FOLD-R1 (Critical): hold the per-key turn mutex across acquire -> turn ->
        # release so two same-user frames (the comms pump dispatches concurrently,
        # comms_runner.py:663) cannot race the ONE shared WorkingMemory buffer the
        # pool hands out for this key. Since #410 PR3, `handle_user_message` can
        # genuinely iterate the Act loop (a live, non-empty tool registry), so this
        # hold now spans a potentially multi-completion turn instead of exactly one
        # completion — the key is shared across whichever platform a
        # cross-platform-bound identity messages from, so a slow multi-iteration
        # turn on one adapter can delay that same user's next turn on another.
        # Small blast radius today (`clock.now` only); reassess once `web.fetch`
        # (network-latency-bound, #583) is live.
        lock = await self._turn_lock_for(key)
        outcome: _TurnSucceeded | _TurnFailed
        async with lock:
            wm = await self._pool.acquire(key)
            try:
                answer = await self._orchestrator.handle_user_message(
                    user=ingested.user,
                    content=ingested.content,
                    working_memory=wm,
                    egress_context=ingested.egress,
                )
                outcome = _TurnSucceeded(answer)
            except BudgetError as exc:
                # Deterministic: audit loudly + halt (no reply, no replay). FOLD-5.
                await self._emit_refused(
                    note, canonical_user_id=ingested.user.slug, stage="budget_denied", exc=exc
                )
                # perf-001 (PR #594): the notify (and the `return` it precedes) now
                # happens AFTER the lock releases below — see `_TurnFailed`.
                outcome = _TurnFailed(stage="budget_denied", reraise=None)
            except OutboundCanaryTripped as exc:
                # #410 PR3 (I4 fix wave): also deterministic, same reasoning as
                # BudgetError above — the SAME content trips the SAME canary on
                # every replay, so letting this fall into the generic
                # `except Exception` leg below would burn the poison ceiling (5
                # replays) reproducing an identical DLP-canary event for zero
                # benefit. Audit loudly + halt instead. Inert today (a `clock.now`
                # timestamp cannot embed a canary token); becomes load-bearing the
                # moment `web.fetch` goes live (#583), so the classification is
                # fixed now while it is cheap to review, not deferred.
                await self._emit_refused(
                    note,
                    canonical_user_id=ingested.user.slug,
                    stage="dlp_canary_tripped",
                    exc=exc,
                )
                # perf-001 (PR #594): notify deferred past lock release, as above.
                outcome = _TurnFailed(stage="dlp_canary_tripped", reraise=None)
            except Exception as exc:
                # Unknown/transient: audit loudly, then RE-RAISE so the forwarded
                # path's dispatch_failed handler + bounded replay take over (direct
                # path loses it, at-most-once, acceptable — FOLD-R22 confirms the
                # pump contains it). `Exception`, not `BaseException`, so
                # cancellation tears down cleanly.
                await self._emit_refused(
                    note, canonical_user_id=ingested.user.slug, stage="turn_error", exc=exc
                )
                # perf-001 (PR #594): `exc` is carried out via `_TurnFailed.reraise`
                # and re-raised AFTER the lock releases + the notify below runs —
                # the audit-write-then-notify-then-raise ORDER is unchanged, only
                # the lock boundary moved. `_notify_turn_failed` contains every
                # `Exception` (#594 R1 widened it from a narrow wire-fault tuple,
                # which had made this very claim false for anything outside that
                # tuple), so it cannot replace/mask `exc` — the forwarded replay
                # path still sees the original turn fault verbatim. A
                # `CancelledError` DOES propagate from the notify, by design:
                # a cancelled turn has no replay to protect.
                outcome = _TurnFailed(stage="turn_error", reraise=exc)
            finally:
                await self._pool.release(key, wm)

        # perf-001 (PR #594): notify (and, on `turn_error`, the re-raise) run
        # HERE — after the mutex above has released — instead of inside it. A
        # wedged-but-connected client's up-to-2s wire wait no longer holds the
        # per-(persona, slug) turn lock hostage, matching the successful-turn
        # `_send` call's existing outside-the-mutex placement below.
        if isinstance(outcome, _TurnFailed):
            await self._notify_turn_failed(
                sender, adapter_id=ingested.adapter_id, stage=outcome.stage
            )
            if outcome.reraise is not None:
                raise outcome.reraise
            return

        # Send OUTSIDE the mutex (the buffer work is done) but with its own
        # audited envelope (FOLD-R11): a scan/send failure gets a loud adapter
        # row, then re-raises (forwarded -> dispatch_failed + replay; direct ->
        # propagate) — EXCEPT a canary trip in the scan, which is deterministic
        # and halts there instead (#594 R1 Fix C2; see `_send`).
        await self._send(
            sender,
            ingested.adapter_id,
            ingested.target_platform_id,
            outcome.answer,
            notification=note,
            canonical_user_id=ingested.user.slug,
        )

    async def _await_turn_ordering_barrier(self, canonical_user_id: str) -> None:
        """Acquire-then-release the per-key turn mutex as a PURE ordering fence.

        arc-001 (PR #594 Task S1): ``ingest``'s two ingest-resolved outcomes
        (``_HaltNoReply`` / ``_RefusalReply``) carry no turn work and so never
        touched the per-``(persona, slug)`` lock at all — which meant a later
        same-key turn's refusal could reach the client before an earlier
        same-key turn's own answer, even though the earlier turn was still
        genuinely running (and provably still holding the lock) when the
        later one's ``ingest()`` finished. Reproduced by execution against the
        real adapter (root-cause report, root-cause-arc-001-turn-order-race.md
        §1.2/§1.3).

        This helper closes that gap WITHOUT running any turn work under the
        lock — ``ingest()`` staying lock-free is itself load-bearing (the
        authoritative ``_emit_refused`` audit row must be written promptly,
        not queued behind a possibly-long-running earlier turn) — and WITHOUT
        notifying from inside the lock either (that would re-break perf-001:
        a wedged-but-connected client holding the per-key mutex for up to
        ``_NOTIFY_TIMEOUT_SECONDS``). Three properties, all load-bearing:

        1. **No turn work runs under this lock.** The body is a bare
           ``async with lock: pass`` — its only job is to make an
           ingest-resolved outcome wait behind any earlier same-key turn
           still holding the lock, exactly as a ``_PreparedTurn`` for the
           same key would.
        2. **The lock releases BEFORE the notify/send that follows this
           call**, not after — so perf-001's "a wedged client never holds
           the per-key mutex" property survives unchanged. Only the ORDER of
           who reaches (and clears) the barrier first is what this buys.
        3. **Returning from this coroutine is NOT a suspension point.**
           ``asyncio.Lock.release()`` (invoked by the ``async with`` block's
           ``__aexit__``) is synchronous, and the function has no further
           ``await`` after that — so the caller's following
           ``await self._notify_turn_failed(...)`` / ``await self._send(...)``
           is still initiated in the same run-slice as the barrier's release.
           That is what the "no await between lock release and notify
           initiation" invariant (see ``_TurnFailed``) actually requires: the
           ONLY suspension point this helper introduces is the ``acquire()``
           wait for a contended lock, never anything after it clears.
        """
        lock = await self._turn_lock_for((_PERSONA, canonical_user_id))
        async with lock:
            pass

    async def _turn_lock_for(self, key: tuple[str, str]) -> asyncio.Lock:
        """Get-or-create the per-(persona, slug) turn mutex (FOLD-R1)."""
        async with self._locks_guard:
            lock = self._turn_locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._turn_locks[key] = lock
            return lock

    async def _send(
        self,
        sender: OutboundSenderLike,
        adapter_id: str,
        target_platform_id: str,
        body: str,
        *,
        notification: _NotificationView | None,
        canonical_user_id: str | None,
    ) -> None:
        """DLP-scan the body (rule #4) + send it as a DM (FOLD-6), audited (FOLD-R11).

        TWO legs with DELIBERATELY DIFFERENT postures (#594 R1 Fix C2 split the
        single ``try`` that used to cover both), because they differ in the one
        thing that matters — whether the wire is still healthy:

        * **SCAN leg** (``scan_for_outbound``) runs strictly BEFORE any wire
          write, so the wire IS healthy and a client notify is both deliverable
          and honest. An ``OutboundCanaryTripped`` here is audited
          ``dlp_canary_tripped`` and HALTS (no re-raise), matching the
          ``dispatch_tool`` arm in ``dispatch`` (#410 PR3's I4 fix wave); any
          other scan fault is audited ``dlp_scan_failed`` and re-raises for the
          forwarded path's replay. Both notify the client.
        * **SEND leg** (``sender.send_outbound``) keeps the original
          ``send_failed`` + NO-notify + re-raise posture — see its own comment.

        Before the split, an ``OutboundCanaryTripped`` on the persona's FINAL
        answer fell into the blanket handler and was audited under a TRANSPORT
        stage, then re-raised — so the single most security-relevant outbound
        event (a canary in the answer, i.e. a successful indirect prompt
        injection) landed in the forensic log misattributed AND burned the
        forwarded-replay ceiling re-tripping the identical canary on identical
        content. That is precisely what the I4 wave exists to prevent elsewhere.
        Inert today (``canary=None`` is the core default, ``dlp.py``); fixed now
        while it is cheap to review, same argument I4 itself made.

        Ordering invariant: ``scan_for_outbound`` is SYNCHRONOUS, so this split
        introduces no new ``await`` ahead of the send — the first suspension
        point on the happy path is still ``send_outbound`` itself. That is
        load-bearing for the TUI's stale-turn debt counter; see the contract
        note on ``_TurnFailed`` and
        ``test_dispatch_notifies_same_key_turns_in_submission_order_even_when_concurrent``.
        The scan-FAILURE legs are the one REMAINING documented exception to
        ``dispatch``'s otherwise-unconditional "zero awaits between lock
        release and notify/send initiation" claim (arc-001, PR #594 Task S1,
        closed the OTHER, larger exception — the two ingest-resolved outcomes
        that used to skip the lock entirely; see ``_await_turn_ordering_barrier``):
        ``_refuse_outbound_scan`` awaits ``_emit_refused`` (a real Postgres
        write) before its notify, and unlike the ``budget_denied``/
        ``turn_error`` legs — whose audit write happens INSIDE the lock —
        this one runs after release. Harmless in practice: an audit write
        completes long before a later turn finishes an LLM turn, so the
        ordering exposure here is negligible in magnitude even though it is
        real in kind — do not read this as an unconditional contract.

        Do NOT reach for the TUI's stale-turn debt bound
        (``plugins/alfred_tui/src/alfred_tui/textual/app.py``,
        ``_incur_stale_turn_debt``) as a reason this doesn't matter — that
        was arc-001's actual root cause. The debt counter is
        order-INSENSITIVE by construction: it is a FIFO of fungible handles,
        so whichever signal arrives first discharges a debt and whichever
        arrives second ends the turn, regardless of which turn either signal
        was really for (see the state-machine proof in the root-cause
        report, root-cause-arc-001-turn-order-race.md §3.1). That self-
        corrects STATE — the pending-turn flag and debt count converge to
        the same values either way — but it is INDIFFERENT to order, not a
        correction OF it: it neither detects nor repairs a transcript line
        printing in the wrong sequence. "The debt bound self-corrects a
        transcript-order swap anyway" was exactly the false reasoning that
        let arc-001 through review; ordering correctness lives ENTIRELY in
        this module (the per-key lock + the ordering barrier), never in the
        client's debt bookkeeping.

        The audit row needs turn context (``notification`` +
        ``canonical_user_id`` both present); the refusal-reply send
        (``ingest``'s ``_RefusalReply`` leg) has none, so it is audited by the
        inbound path on the forwarded edge instead — and on the scan leg the
        DLP's own ``dlp.outbound_canary_tripped`` / ``dlp.outbound_redacted``
        rows are the authoritative record either way.

        FOLD-R18: this DLP-scan -> ``OutboundMessageRequest`` -> send sequence
        duplicates ``CommsInboundOrchestratorAdapter.dispatch``
        (``daemon_runtime.py``). Retained rather than extracted into a shared
        helper: the echo adapter is the documented rollback fallback for this
        cutover (module docstring) and stays byte-for-byte independent of this
        one so a rollback cannot be broken by a shared-helper change made for the
        real-turn path.
        """
        try:
            scanned = self._outbound_dlp.scan_for_outbound(body)
        except OutboundCanaryTripped as exc:
            # DETERMINISTIC: the same answer trips the same token on every
            # replay, so HALT (audited, notified, no re-raise) exactly like the
            # `dispatch_tool` arm — re-raising would burn the poison ceiling
            # reproducing an identical trip for zero benefit.
            await self._refuse_outbound_scan(
                sender,
                adapter_id,
                stage="dlp_canary_tripped",
                exc=exc,
                notification=notification,
                canonical_user_id=canonical_user_id,
            )
            return
        except Exception as exc:
            # Non-canary scan fault (a broker/vault blip in DLP stage 1) —
            # plausibly transient, so re-raise for the forwarded path's replay,
            # but tell the client first: nothing has touched the wire yet.
            await self._refuse_outbound_scan(
                sender,
                adapter_id,
                stage="dlp_scan_failed",
                exc=exc,
                notification=notification,
                canonical_user_id=canonical_user_id,
            )
            raise

        try:
            request = OutboundMessageRequest(
                adapter_id=adapter_id,
                idempotency_key=uuid4(),
                target_platform_id=target_platform_id,
                body=scanned,
                attachments_refs=(),
                addressing_mode=_ADDRESSING_MODE,
            )
            await sender.send_outbound(request)
        except Exception as exc:
            if notification is not None and canonical_user_id is not None:
                await self._emit_refused(
                    notification, canonical_user_id=canonical_user_id, stage="send_failed", exc=exc
                )
            # #593: NO client turn-failure notify here, deliberately. The send
            # that just failed used THIS SAME WIRE, so a notify down the same
            # seam is near-certain to fail too; and this leg RE-RAISES, so on the
            # forwarded path a successful retry could deliver the real answer
            # AFTER we told the operator the turn failed — a false negative worse
            # than silence. The client-side turn watchdog is the correct backstop
            # for a dead-wire failure — and since #594 R1 that backstop is
            # bounded in time, so the client self-heals in one watchdog window
            # instead of depending on this notify to stay consistent.
            raise

    async def _refuse_outbound_scan(
        self,
        sender: OutboundSenderLike,
        adapter_id: str,
        *,
        stage: _RefusalStage,
        exc: Exception,
        notification: _NotificationView | None,
        canonical_user_id: str | None,
    ) -> None:
        """Audit (when there is turn context) + client-notify a PRE-WIRE scan fault.

        Split out of ``_send`` so both scan-leg arms share one
        audit-then-notify ordering — the authoritative record is written first,
        the best-effort UX frame second, exactly as every other refusal leg in
        ``dispatch`` does it. Never raises on its own behalf: ``_emit_refused``
        writes the row and ``_notify_turn_failed`` contains every ``Exception``,
        so the CALLER decides halt-vs-re-raise for the original fault.
        """
        if notification is not None and canonical_user_id is not None:
            await self._emit_refused(
                notification, canonical_user_id=canonical_user_id, stage=stage, exc=exc
            )
        await self._notify_turn_failed(sender, adapter_id=adapter_id, stage=stage)
