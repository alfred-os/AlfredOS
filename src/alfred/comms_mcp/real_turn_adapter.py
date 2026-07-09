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
audit on a policy deny — FOLD-5 / CLAUDE.md hard rule #7). Egress tools are deferred
(#338 conversational scope): the orchestrator runs with an empty tool registry, so
the loop reduces to exactly one completion.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol
from uuid import uuid4

import structlog

from alfred.audit import audit_row_schemas  # FOLD-R10
from alfred.budget.guard import BudgetError
from alfred.comms_mcp import audit_hash  # FOLD-R10: audit_hash lives in comms_mcp, NOT alfred.audit
from alfred.comms_mcp.protocol import OutboundMessageRequest
from alfred.errors import AlfredError
from alfred.i18n import set_language, t
from alfred.orchestrator.core import _ALFRED_PERSONA_ID as _PERSONA
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
_RefusalStage = Literal[
    "downgrade_denied", "downgrade_malformed", "budget_denied", "turn_error", "send_failed"
]


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
    """``ingest`` output for a quarantine ``TypedRefusal`` — send a benign reply."""

    reply: str
    adapter_id: str
    target_platform_id: str


@dataclass(frozen=True, slots=True)
class _HaltNoReply:
    """``ingest`` output for a security/budget deny — audited, NOTHING is sent."""

    stage: _RefusalStage


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
            return _HaltNoReply(stage="downgrade_denied")

        text = cleared.get("text")
        if not isinstance(text, str):  # defensive: the CommsBodyExtraction schema pins text:str
            # FOLD-R24: DISTINCT stage from the gate deny.
            await self._emit_refused(
                notification,
                canonical_user_id=canonical_user_id,
                stage="downgrade_malformed",
                exc=AlfredError("downgraded payload missing str 'text'"),
            )
            return _HaltNoReply(stage="downgrade_malformed")

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
        audited ``dispatch_failed`` + bounded-replay path. BudgetError + the
        downgrade-deny (handled in ``ingest``) are DETERMINISTIC — the adapter
        audits them loudly and HALTS (no reply, no re-raise) so the frame commits
        rather than burning the replay ceiling on a completion that will re-fail.
        Genuinely transient turn errors (provider outage / deadline) DO re-raise so
        the forwarded leg can retry within the poison ceiling.

        FOLD-R25: on a forwarded replay both this adapter's ``turn_error`` row AND
        the inbound path's ``dispatch_failed`` row write — INTENTIONAL: they are
        distinct events (adapter-semantic turn fault vs inbound-transport dispatch
        fault) and both are content-free.
        """
        sender = self._require_sender()
        if isinstance(ingested, _HaltNoReply):
            return
        if isinstance(ingested, _RefusalReply):
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

        set_language(ingested.user.language)
        key = (_PERSONA, ingested.user.slug)
        note = _NotificationView(ingested)
        # FOLD-R1 (Critical): hold the per-key turn mutex across acquire -> turn ->
        # release so two same-user frames (the comms pump dispatches concurrently,
        # comms_runner.py:663) cannot race the ONE shared WorkingMemory buffer the
        # pool hands out for this key.
        lock = await self._turn_lock_for(key)
        async with lock:
            wm = await self._pool.acquire(key)
            try:
                answer = await self._orchestrator.handle_user_message(
                    user=ingested.user,
                    content=ingested.content,
                    working_memory=wm,
                    egress_context=ingested.egress,
                )
            except BudgetError as exc:
                # Deterministic: audit loudly + halt (no reply, no replay). FOLD-5.
                await self._emit_refused(
                    note, canonical_user_id=ingested.user.slug, stage="budget_denied", exc=exc
                )
                return
            except Exception as exc:
                # Unknown/transient: audit loudly, then RE-RAISE so the forwarded
                # path's dispatch_failed handler + bounded replay take over (direct
                # path loses it, at-most-once, acceptable — FOLD-R22 confirms the
                # pump contains it). `Exception`, not `BaseException`, so
                # cancellation tears down cleanly.
                await self._emit_refused(
                    note, canonical_user_id=ingested.user.slug, stage="turn_error", exc=exc
                )
                raise
            finally:
                await self._pool.release(key, wm)

        # Send OUTSIDE the mutex (the buffer work is done) but with its own
        # audited envelope (FOLD-R11): a scan/send failure gets a loud adapter row
        # then re-raises (forwarded -> dispatch_failed + replay; direct ->
        # propagate).
        await self._send(
            sender,
            ingested.adapter_id,
            ingested.target_platform_id,
            answer,
            notification=note,
            canonical_user_id=ingested.user.slug,
        )

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

        On a scan/send failure with turn context (``notification`` +
        ``canonical_user_id`` both present) the adapter writes a loud
        ``send_failed`` row then re-raises; the refusal-reply send (no turn
        context — ``ingest``'s ``_RefusalReply`` leg) just re-raises (the inbound
        path audits it on the forwarded edge). A DLP CANARY trip is signalled in
        the scan RESULT, not an exception (unchanged from the echo path) — it does
        not raise here.

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
            raise
