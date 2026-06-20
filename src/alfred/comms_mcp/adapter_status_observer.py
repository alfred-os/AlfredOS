"""Core-side observer/auditor for gateway-reported adapter status (Spec B §4/§6).

The gateway is the adapter child's supervising parent (Spec B); it OBSERVES the
adapter lifecycle and reports each transition to the core as a
``gateway.adapter.*`` notification. The core never COMMANDS the lifecycle — it
consumes these here, Pydantic-validates, epoch-reconciles ``up`` (the G3
anti-forgery lesson: never trust a raw frame; a forged ``up`` while dark is a
false-liveness attack), writes one audit row per ACCEPTED transition, and
records the latest per-adapter status for ``alfred status``.

A malformed / forged-epoch / unknown-method frame is REFUSED LOUDLY — audited as
``gateway.adapter.status_rejected``, never silently dropped (Spec B §6,
CLAUDE.md hard rule #7). The rejection row carries NO raw frame field.

CARRIER-AUTH POSTURE (correction #5): only ``up`` is epoch-bound (spec-faithful
— it is the only liveness-asserting frame). The live gateway->core leg's ``0600``
+ ``SO_PEERCRED`` + per-boot-epoch envelope (Spec A) authenticates frame origin
and anti-replays cross-boot, so the non-``up`` frames rely on the carrier for
origin-auth + replay-defense; the ``up`` payload-epoch is the ADDITIONAL
application-level false-liveness-replay defense Spec B §6(f) mandates. A
forged-downgrade's blast radius is low: the core only OBSERVES (no lifecycle
directive), so a forged ``down``/``crashed`` mutates only the snapshot + an audit
row, never an actuation. This module's unit suite proves the application-level
validation only; the carrier-auth of the live leg is proven by G6-2b.

G6-2a ships this consumer in ISOLATION, exercised against synthetic frames. The
PRODUCER (GatewayAdapterSupervisor) + the live gateway->core status leg + the
daemon-boot registration land in G6-2b.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Final, Literal, Protocol

import structlog
from pydantic import BaseModel, ValidationError

from alfred.audit.audit_row_schemas import (
    GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS,
    GATEWAY_ADAPTER_CRASHED_FIELDS,
    GATEWAY_ADAPTER_DOWN_FIELDS,
    GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS,
    GATEWAY_ADAPTER_UP_FIELDS,
)
from alfred.comms_mcp.crash_incident_reconciler import CrashFoldResult, CrashIncidentReconciler
from alfred.comms_mcp.handlers import _MAX_CRASH_DETAIL_LEN
from alfred.comms_mcp.protocol import (
    GATEWAY_ADAPTER_BREAKER_OPEN,
    GATEWAY_ADAPTER_CRASHED,
    GATEWAY_ADAPTER_DOWN,
    GATEWAY_ADAPTER_UP,
    AdapterBreakerOpenNotification,
    AdapterCrashedNotification,
    AdapterDownNotification,
    AdapterUpNotification,
)
from alfred.errors import AlfredError
from alfred.security.dlp import redact_secret_shapes

log = structlog.get_logger(__name__)

# Core-owned control frames (gateway supervision metadata, NOT a T3 message body)
# audit at T0 — the SAME tier the daemon.lifecycle.* control rows use
# (correction #3). The gateway is payload-blind on this leg.
_STATUS_TRUST_TIER: Final[str] = "T0"

AdapterState = Literal["up", "down", "crashed", "breaker_open"]
_RejectionReason = Literal["malformed_frame", "epoch_mismatch", "unknown_method"]

# Re-exported so the bound is asserted against the SAME constant the in-child
# crash path uses (correction #1 — do NOT introduce a new bound).
__all__ = [
    "_MAX_CRASH_DETAIL_LEN",
    "AdapterState",
    "AdapterStatusAuditWriteError",
    "AdapterStatusObserver",
    "AdapterStatusSnapshot",
]


class AdapterStatusAuditWriteError(AlfredError):
    """A signed-audit-write failure while recording a ``gateway.adapter.*`` transition.

    SEC-1 (G6-2b-2a / #288): the DISTINCT typed marker the observer raises when an
    ``append_schema`` for an accepted transition OR a ``status_rejected`` refusal
    fails to persist. It exists so the live core leg's
    :meth:`alfred.plugins.comms_runner.CommsPluginRunner._route_notification` can
    DISTINGUISH a non-skippable signed-audit-write failure from an ordinary handler
    fault and ESCALATE it loudly — a ``log.error`` row + a restart request (trip
    restart/quarantine) — instead of letting its blanket ``except Exception: log +
    continue`` SWALLOW it (which would silently downgrade a failed signed-audit write
    to a structlog warning, defeating CLAUDE.md hard rules #5/#7). The escalation,
    NOT a re-raise, is what makes the fault non-skippable: ``_route_notification``
    only ever runs fire-and-forget, so a re-raise would reach no awaiter. The
    observer NEVER raises this on a bad/forged frame (that is a loud audited refusal,
    not an exception) — ONLY on a genuine write failure.
    """


class _AuditWriterLike(Protocol):
    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, object],
        trust_tier_of_trigger: str,
        result: str,
        cost_estimate_usd: float,
        trace_id: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class AdapterStatusSnapshot:
    """The latest observed status for one adapter (for ``alfred status``)."""

    adapter_id: str
    state: AdapterState
    occurred_at: datetime


# The transition family is fully described by (model, audit-fields, schema-name, state).
_TRANSITIONS: Final[Mapping[str, tuple[type[BaseModel], frozenset[str], str, AdapterState]]] = {
    GATEWAY_ADAPTER_UP: (
        AdapterUpNotification,
        GATEWAY_ADAPTER_UP_FIELDS,
        "GATEWAY_ADAPTER_UP_FIELDS",
        "up",
    ),
    GATEWAY_ADAPTER_DOWN: (
        AdapterDownNotification,
        GATEWAY_ADAPTER_DOWN_FIELDS,
        "GATEWAY_ADAPTER_DOWN_FIELDS",
        "down",
    ),
    GATEWAY_ADAPTER_CRASHED: (
        AdapterCrashedNotification,
        GATEWAY_ADAPTER_CRASHED_FIELDS,
        "GATEWAY_ADAPTER_CRASHED_FIELDS",
        "crashed",
    ),
    GATEWAY_ADAPTER_BREAKER_OPEN: (
        AdapterBreakerOpenNotification,
        GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS,
        "GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS",
        "breaker_open",
    ),
}


class AdapterStatusObserver:
    """Validate, epoch-reconcile, audit, and record gateway adapter-status frames."""

    def __init__(
        self,
        *,
        audit: _AuditWriterLike,
        expected_epoch: Callable[[], str],
        now: Callable[[], datetime],
        reconciler: CrashIncidentReconciler,
    ) -> None:
        self._audit = audit
        self._expected_epoch = expected_epoch
        self._now = now
        # The SHARED crash-dedup reconciler (G6-2b-2b / #288). The daemon injects the
        # SAME instance into the per-adapter in-child AdapterCrashHandler, so a gateway
        # crash (this arm) and an in-child crash for one physical crash fold into one
        # incident. Required (no None-default): a missing reconciler would be a silent
        # no-dedup path, which is a trust-boundary regression — fail loud at construction.
        self._reconciler = reconciler
        self._latest: dict[str, AdapterStatusSnapshot] = {}

    def latest(self, adapter_id: str) -> AdapterStatusSnapshot | None:
        """The most recent ACCEPTED status for ``adapter_id``, or None."""
        return self._latest.get(adapter_id)

    def all_latest(self) -> Mapping[str, AdapterStatusSnapshot]:
        """A read-only view of the latest accepted status for EVERY observed adapter.

        The in-process read surface for the daemon-status snapshot publisher
        (G6-2b-2c / #288). A ``MappingProxyType`` so a consumer cannot mutate the
        observer's internal map (the snapshot builder only ever reads it).
        """
        return MappingProxyType(self._latest)

    async def observe(self, method: object, params: object) -> None:
        """Consume one gateway adapter-status frame: validate -> reconcile -> audit.

        NEVER raises on a bad frame — a malformed / forged / unknown frame is a
        loud, audited refusal, not an exception that could unwind the gateway
        link pump. The ONLY raise path is a genuine audit-write failure (which
        MUST be loud — CLAUDE.md hard rule #7 — and is the caller's to handle).
        """
        transition = _TRANSITIONS.get(method) if isinstance(method, str) else None
        if transition is None:
            await self._reject(method, "", "unknown_method")
            return

        model_cls, fields, schema_name, state = transition
        raw_params = params if isinstance(params, Mapping) else {}
        try:
            parsed = model_cls.model_validate(raw_params)
        except ValidationError:
            # No exc detail logged/persisted — it could echo a malformed wire
            # field (CLAUDE.md hard rule #5/#7). The method name is the triage key.
            await self._reject(method, "", "malformed_frame")
            return

        if isinstance(parsed, AdapterUpNotification) and parsed.epoch != self._expected_epoch():
            # THE FORGERY DEFENSE (Spec B §3, the G3 lesson): an ``up`` against a
            # stale/foreign epoch is a false-liveness assertion. Refuse — no record.
            await self._reject(method, parsed.adapter_id, "epoch_mismatch")
            return

        await self._accept(parsed, fields, schema_name, str(method), state)

    async def _append_or_raise(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        subject: dict[str, object],
        result: str,
        trace_id: str,
    ) -> None:
        """Write one status audit row; translate a write failure to the typed marker.

        SEC-1 (#288): the observer's two ``append_schema`` sites funnel through here so
        a genuine signed-audit-write failure raises the DISTINCT
        :class:`AdapterStatusAuditWriteError` (CLAUDE.md hard rules #5/#7 — never a
        silent downgrade). The observer reaches this helper only on a frame it has
        ALREADY decided to record (an accepted transition or a loud refusal), so any
        exception from ``append_schema`` here is — by the audit writer's contract — a
        write failure, not a frame-validity decision; wrapping it gives the live core
        leg a typed handle to ESCALATE (loud ``log.error`` + restart request) instead
        of swallow.
        """
        try:
            await self._audit.append_schema(
                fields=fields,
                schema_name=schema_name,
                event=event,
                actor_user_id=None,
                subject=subject,
                trust_tier_of_trigger=_STATUS_TRUST_TIER,
                result=result,
                cost_estimate_usd=0.0,
                trace_id=trace_id,
            )
        except Exception as exc:
            # Loud + typed: a failed signed-audit write for a status transition is a
            # non-skippable event. Raising the DISTINCT marker (not the raw backend
            # error) is what lets the live runner's _route_notification recognise it
            # past its blanket catch-and-continue (SEC-1) and ESCALATE loudly
            # (log.error + restart request) instead of swallowing it — every other
            # caller still sees a loud AlfredError.
            raise AdapterStatusAuditWriteError(f"status audit write failed for {event!r}") from exc

    async def _accept(
        self,
        parsed: object,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        state: AdapterState,
    ) -> None:
        occurred_at = self._now()
        # Fold the crash-dedup signal BEFORE building the subject + writing the row, so
        # the row carries the incident handle/source and a replayed (duplicate) crash is
        # FLAGGED + still audited (never suppressed — hard rule #7). The fold is the
        # gateway arm; the in-child AdapterCrashHandler folds the child arm into the SAME
        # shared reconciler.
        fold = (
            self._reconciler.observe_gateway_crash(
                adapter_id=parsed.adapter_id, host_restart_seq=parsed.host_restart_seq
            )
            if isinstance(parsed, AdapterCrashedNotification)
            else None
        )
        subject = self._subject_for(parsed, occurred_at, fold)
        adapter_id = str(subject["adapter_id"])
        await self._append_or_raise(
            fields=fields,
            schema_name=schema_name,
            event=event,
            subject=subject,
            result="success",
            # Per-adapter correlation handle (correction #4), not the timestamp.
            trace_id=adapter_id,
        )
        self._latest[adapter_id] = AdapterStatusSnapshot(
            adapter_id=adapter_id, state=state, occurred_at=occurred_at
        )
        # SEC-01 (#288): advance the reconciler's current incarnation on an accepted up
        # (a fresh serving run) AFTER the audit write succeeds, so a later in-child crash
        # — which fires before the gateway observes process-exit — tags to the run that
        # was actually serving. ``up`` carries the incarnation being STARTED.
        if isinstance(parsed, AdapterUpNotification):
            self._reconciler.note_incarnation(
                adapter_id=parsed.adapter_id, host_restart_seq=parsed.host_restart_seq
            )

    @staticmethod
    def _subject_for(
        parsed: object, occurred_at: datetime, fold: CrashFoldResult | None
    ) -> dict[str, object]:
        ts = occurred_at.isoformat()
        if isinstance(parsed, AdapterUpNotification):
            return {
                "adapter_id": parsed.adapter_id,
                "epoch": parsed.epoch,
                "occurred_at": ts,
                # SEC-01 (#288): record the incarnation being STARTED.
                "host_restart_seq": parsed.host_restart_seq,
            }
        if isinstance(parsed, AdapterDownNotification):
            return {"adapter_id": parsed.adapter_id, "reason": parsed.reason, "occurred_at": ts}
        if isinstance(parsed, AdapterCrashedNotification):
            # The crashed accept ALWAYS folds first (see _accept), so a non-None fold is
            # a structural invariant here — assert it loud rather than silently emit a
            # row missing the dedup keys.
            assert fold is not None  # structural invariant: the crashed accept folds first
            # The wire ``detail`` is RE-SCRUBBED before it lands as detail_redacted;
            # the raw field is never persisted (mirrors the in-child CrashedNotification
            # handling at handlers.py:338). REDACT FIRST, then bound the length — NOT
            # bound-then-redact: truncating first could cut a secret straddling the
            # _MAX_CRASH_DETAIL_LEN boundary mid-token, leaving an unredacted prefix the
            # shape-regex no longer matches (a partial-secret leak). Redacting the full
            # string first replaces the whole secret with a short marker, so the
            # subsequent truncation can only cut already-safe text.
            return {
                "adapter_id": parsed.adapter_id,
                "error_class": parsed.error_class,
                "detail_redacted": redact_secret_shapes(parsed.detail)[:_MAX_CRASH_DETAIL_LEN],
                "occurred_at": ts,
                # G6-2b-2b (#288): the crash-dedup join key + incident handle/source +
                # the TE-2 duplicate marker (a replayed crash is FLAGGED, still audited).
                # Stamp the fold's seq (the reconciler is the single source of truth for
                # the incarnation the incident is keyed on; equal to parsed.host_restart_seq
                # on the gateway arm, but reading it from the fold keeps one authority).
                "host_restart_seq": fold.host_restart_seq,
                "crash_incident_id": fold.crash_incident_id,
                "crash_signal_source": fold.crash_signal_source,
                "duplicate": fold.duplicate,
            }
        if isinstance(parsed, AdapterBreakerOpenNotification):
            return {
                "adapter_id": parsed.adapter_id,
                "retry_after_seconds": parsed.retry_after_seconds,
                "occurred_at": ts,
            }
        # Defensive: ``_TRANSITIONS`` maps only the four handled models above, so this
        # is unreachable by construction. Kept as a loud RuntimeError (NOT ``assert`` —
        # so it survives ``python -O``) to fail fast if a fifth model is ever added
        # without a matching branch. Excluded from coverage as dead-by-construction.
        msg = f"unhandled status model {type(parsed).__name__}"  # pragma: no cover
        raise RuntimeError(msg)  # pragma: no cover

    async def _reject(self, method: object, adapter_id: str, reason: _RejectionReason) -> None:
        occurred_at = self._now()
        log.warning(
            "gateway.adapter.status_rejected",
            rejected_method=str(method),
            rejection_reason=reason,
            adapter_id=adapter_id,
        )
        await self._append_or_raise(
            fields=GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS,
            schema_name="GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS",
            event="gateway.adapter.status_rejected",
            subject={
                "adapter_id": adapter_id,
                "rejected_method": str(method),
                "rejection_reason": reason,
                "occurred_at": occurred_at.isoformat(),
            },
            result="refused",
            # Per-adapter correlation handle (correction #4); "" when the frame
            # was unparseable. The audit ``trace_id`` column is a plain
            # ``String(64)`` with no non-empty CHECK, so an empty correlation
            # handle is a valid value — an unparseable frame has no adapter to
            # correlate to, and a sentinel would invent a false handle. G6-2b's
            # live wiring (which may route through ``_emit_or_quarantine``) owns
            # any boot-time trace-id policy.
            trace_id=adapter_id,
        )
