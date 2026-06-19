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
    "AdapterStatusObserver",
    "AdapterStatusSnapshot",
]


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
    ) -> None:
        self._audit = audit
        self._expected_epoch = expected_epoch
        self._now = now
        self._latest: dict[str, AdapterStatusSnapshot] = {}

    def latest(self, adapter_id: str) -> AdapterStatusSnapshot | None:
        """The most recent ACCEPTED status for ``adapter_id``, or None."""
        return self._latest.get(adapter_id)

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

    async def _accept(
        self,
        parsed: object,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        state: AdapterState,
    ) -> None:
        occurred_at = self._now()
        subject = self._subject_for(parsed, occurred_at)
        adapter_id = str(subject["adapter_id"])
        await self._audit.append_schema(
            fields=fields,
            schema_name=schema_name,
            event=event,
            actor_user_id=None,
            subject=subject,
            trust_tier_of_trigger=_STATUS_TRUST_TIER,
            result="success",
            cost_estimate_usd=0.0,
            # Per-adapter correlation handle (correction #4), not the timestamp.
            trace_id=adapter_id,
        )
        self._latest[adapter_id] = AdapterStatusSnapshot(
            adapter_id=adapter_id, state=state, occurred_at=occurred_at
        )

    @staticmethod
    def _subject_for(parsed: object, occurred_at: datetime) -> dict[str, object]:
        ts = occurred_at.isoformat()
        if isinstance(parsed, AdapterUpNotification):
            return {"adapter_id": parsed.adapter_id, "epoch": parsed.epoch, "occurred_at": ts}
        if isinstance(parsed, AdapterDownNotification):
            return {"adapter_id": parsed.adapter_id, "reason": parsed.reason, "occurred_at": ts}
        if isinstance(parsed, AdapterCrashedNotification):
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
        await self._audit.append_schema(
            fields=GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS,
            schema_name="GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS",
            event="gateway.adapter.status_rejected",
            actor_user_id=None,
            subject={
                "adapter_id": adapter_id,
                "rejected_method": str(method),
                "rejection_reason": reason,
                "occurred_at": occurred_at.isoformat(),
            },
            trust_tier_of_trigger=_STATUS_TRUST_TIER,
            result="refused",
            cost_estimate_usd=0.0,
            # Per-adapter correlation handle (correction #4); "" when the frame
            # was unparseable. The audit ``trace_id`` column is a plain
            # ``String(64)`` with no non-empty CHECK, so an empty correlation
            # handle is a valid value — an unparseable frame has no adapter to
            # correlate to, and a sentinel would invent a false handle. G6-2b's
            # live wiring (which may route through ``_emit_or_quarantine``) owns
            # any boot-time trace-id policy.
            trace_id=adapter_id,
        )
