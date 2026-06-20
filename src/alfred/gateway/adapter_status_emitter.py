"""Gateway-side producer for ``gateway.adapter.*`` status frames (G6-2b-1 / #288).

The supervisor's lifecycle transitions are non-skippable status events (Spec B §6):
every transition the kernel emits a control for MUST put the matching
``gateway.adapter.*`` frame on the wire. This module is the PRODUCER that builds
each frame via the merged G6-2a Pydantic models (so a wrong field is a loud
:class:`pydantic.ValidationError` at the producer — symmetric with the core-side
:class:`alfred.comms_mcp.adapter_status_observer.AdapterStatusObserver`'s
consumer-side validation) and writes ``(method_constant, params_dict)`` to an
injected sink.

**Crash-detail redaction: REDACT-then-BOUND (correction #1 / SEC-1).** The
``crashed`` frame's ``detail`` is redacted BEFORE the wire:
``redact_secret_shapes(detail)[:_MAX_CRASH_DETAIL_LEN]`` — redact the FULL string,
THEN truncate. NOT bound-then-redact: truncating first could sever a secret
straddling the cap mid-token, leaving an unredacted prefix the shape-regex no longer
matches (a partial-secret leak). The bound is REUSED from
:mod:`alfred.comms_mcp.handlers` (no new value); the call is a pure CALLER of
:func:`alfred.security.dlp.redact_secret_shapes` — this module adds NO
``src/alfred/security/`` surface. Mirrors the observer's identical redact-then-bound
at ``adapter_status_observer.py``.

**Scope note (correction #2).** 2b-1's per-transition observability obligation is
met by this status-frame EMISSION (tested against the injected fake sink). The
gateway-LOCAL audit append + reconcile to the signed core log (Spec A's mechanism)
is DEFERRED to 2b-2 — it requires the live gateway->core reconcile leg that does
not exist on main until 2b-2. This producer does NOT touch the wire directly: it
writes to a sink the supervisor injects; 2b-1 injects a fake, 2b-2 injects the live
leg.
"""

from __future__ import annotations

from typing import Protocol

from alfred.comms_mcp.handlers import _MAX_CRASH_DETAIL_LEN
from alfred.comms_mcp.protocol import (
    GATEWAY_ADAPTER_BREAKER_OPEN,
    GATEWAY_ADAPTER_CRASHED,
    GATEWAY_ADAPTER_DOWN,
    GATEWAY_ADAPTER_UP,
    AdapterBreakerOpenNotification,
    AdapterCrashedNotification,
    AdapterDownNotification,
    AdapterDownReason,
    AdapterUpNotification,
)
from alfred.security.dlp import redact_secret_shapes


class _AdapterStatusSink(Protocol):
    """Where built+validated status frames go.

    2b-1 injects a fake (a recording list); 2b-2 injects the live gateway->core
    status leg. ``method`` is one of the four ``GATEWAY_ADAPTER_*`` method
    constants; ``params`` is the validated frame's ``model_dump()``.
    """

    async def emit(self, method: str, params: dict[str, object]) -> None: ...


class AdapterStatusEmitter:
    """Build + validate the four ``gateway.adapter.*`` frames; write them to a sink.

    Each ``emit_*`` builds the corresponding G6-2a model (validating on produce) and
    writes ``(method_constant, model.model_dump())`` to the injected sink. A
    malformed build (e.g. a non-32-hex epoch) raises :class:`pydantic.ValidationError`
    HERE, at the producer — before any frame reaches the sink.
    """

    def __init__(self, *, sink: _AdapterStatusSink) -> None:
        self._sink = sink

    async def emit_up(self, *, adapter_id: str, epoch: str, host_restart_seq: int) -> None:
        """``gateway.adapter.up`` — the only liveness-asserting frame (epoch-bound).

        ``host_restart_seq`` (SEC-01 / #288) is the supervisor's per-adapter
        ``restart_count`` for the incarnation being STARTED. The core's
        CrashIncidentReconciler advances its current incarnation to this on an
        accepted ``up`` so a later in-child crash tags to the run that was serving.
        """
        frame = AdapterUpNotification(
            adapter_id=adapter_id, epoch=epoch, host_restart_seq=host_restart_seq
        )
        await self._sink.emit(GATEWAY_ADAPTER_UP, frame.model_dump())

    async def emit_down(self, *, adapter_id: str, reason: AdapterDownReason) -> None:
        """``gateway.adapter.down`` — a planned/observed stop (closed-vocab reason)."""
        frame = AdapterDownNotification(adapter_id=adapter_id, reason=reason)
        await self._sink.emit(GATEWAY_ADAPTER_DOWN, frame.model_dump())

    async def emit_crashed(
        self, *, adapter_id: str, error_class: str, detail: str, host_restart_seq: int
    ) -> None:
        """``gateway.adapter.crashed`` — the process-level crash signal.

        ``host_restart_seq`` (G6-2b-2b / #288) is the supervisor's per-adapter
        ``restart_count`` — the INCARNATION that exited. The core's
        CrashIncidentReconciler keys the crash-dedup join on
        ``(adapter_id, host_restart_seq)``. ``detail`` is REDACTED then BOUND
        (correction #1) before it crosses to the sink:
        ``redact_secret_shapes(detail)[:_MAX_CRASH_DETAIL_LEN]``. Redacting the
        full string first guarantees the subsequent truncation can only cut
        already-safe text, so a secret straddling the cap cannot leak an unredacted
        prefix.
        """
        redacted_detail = redact_secret_shapes(detail)[:_MAX_CRASH_DETAIL_LEN]
        frame = AdapterCrashedNotification(
            adapter_id=adapter_id,
            error_class=error_class,
            detail=redacted_detail,
            host_restart_seq=host_restart_seq,
        )
        await self._sink.emit(GATEWAY_ADAPTER_CRASHED, frame.model_dump())

    async def emit_breaker_open(self, *, adapter_id: str, retry_after_seconds: int) -> None:
        """``gateway.adapter.breaker_open`` — the per-adapter breaker tripped."""
        frame = AdapterBreakerOpenNotification(
            adapter_id=adapter_id, retry_after_seconds=retry_after_seconds
        )
        await self._sink.emit(GATEWAY_ADAPTER_BREAKER_OPEN, frame.model_dump())


__all__ = [
    "_MAX_CRASH_DETAIL_LEN",
    "AdapterStatusEmitter",
]
