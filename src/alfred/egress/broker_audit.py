"""Durable, signed, core-side per-call egress-audit rows for the SCM_RIGHTS broker
(ADR-0050 Decision 7; golive spec §21; addresses ADR-0040 residual (vii)).

Egress-audit family (spec §21): a broker failure is an egress event, not a sandbox
refusal — the row carries ``destination`` (host:port), which ``SANDBOX_REFUSED_FIELDS``
cannot hold. Mirrors :class:`alfred.security.sandbox_refusal_audit.SandboxRefusalAuditor`'s
``append_schema`` + fail-closed T0 hookpoint pattern (#433, ADR-0051), but is a
distinct family: the sandbox-refusal auditor persists launcher-parsed sandbox
refusals; this one persists broker-side egress connect outcomes (both success and
refusal — a shape the sandbox-refusal family never needed).

Ships **dormant**: golive's ``broker_sockets`` wiring is the only caller (it flips
``control_fd=True``). Until then this module is exercised only by its own unit tests.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from typing import TYPE_CHECKING, Any

import structlog

from alfred.audit.audit_row_schemas import (
    EGRESS_BROKER_REFUSED_FIELDS,
    EGRESS_BROKER_SUCCESS_FIELDS,
)

if TYPE_CHECKING:
    # Annotation-only (``from __future__ import annotations`` stringizes it) — kept
    # off the runtime import graph, mirroring ``SandboxRefusalAuditor`` (#340 final review).
    from alfred.audit.log import AuditWriter

_log = structlog.get_logger(__name__)

_CONNECTED_EVENT = "egress.broker.connected"
_REFUSED_EVENT = "egress.broker.refused"

# Bound the per-extraction hot-path await (spec §21.4 / D3; distinct from #461's
# teardown-await case): a hung append_schema must fail loud, never stall the
# extraction. The golive caller invokes record_broker_success() N times before the
# extract frame, so an unbounded await here would wedge the hot path indefinitely.
_AUDIT_AWAIT_TIMEOUT_S: float = 5.0


def _egress_id(destination: str) -> str:
    """Deterministic, non-secret correlation id — sha256 of the bare destination.

    Never the proxy URL, never socket bytes (HARD #5 — the broker passes a bare
    fd; it never reads or writes application content). Deterministic so the same
    destination always yields the same id, letting an audit-graph consumer
    correlate rows without a lookup table.
    """
    return hashlib.sha256(destination.encode("utf-8")).hexdigest()


class EgressBrokerAuditor:
    """Writes ``egress.broker.*`` rows + dispatches the fail-closed hookpoint.

    Both ``record_broker_success`` and ``record_broker_failure`` write a signed
    T0 ``append_schema`` row and then dispatch a ``post``-stage, fail-closed,
    system-only-subscribable hookpoint — mirroring
    :meth:`SandboxRefusalAuditor.record`. The ``append_schema`` await is bounded
    by ``audit_await_timeout_s`` so a hung write fails loud (structlog error +
    re-raise) instead of silently stalling the caller (CLAUDE.md HARD rule #7).
    """

    def __init__(
        self,
        audit_writer: AuditWriter,
        *,
        audit_await_timeout_s: float = _AUDIT_AWAIT_TIMEOUT_S,
    ) -> None:
        self._audit = audit_writer
        self._timeout = audit_await_timeout_s

    async def record_broker_success(self, *, destination: str) -> None:
        """Persist the ``egress.broker.connected`` row for a brokered fd hand-off."""
        await self._write(
            fields=EGRESS_BROKER_SUCCESS_FIELDS,
            schema_name="EGRESS_BROKER_SUCCESS_FIELDS",
            event=_CONNECTED_EVENT,
            result="success",
            subject={"destination": destination, "egress_id": _egress_id(destination)},
        )

    async def record_broker_failure(self, *, destination: str, reason: str) -> None:
        """Persist the ``egress.broker.refused`` row for a ``ControlFdBrokerError`` refusal.

        ``reason`` is one of :data:`alfred.audit.audit_row_schemas.EGRESS_BROKER_REFUSED_REASONS`
        — the caller passes ``ControlFdBrokerError.reason`` verbatim.
        """
        await self._write(
            fields=EGRESS_BROKER_REFUSED_FIELDS,
            schema_name="EGRESS_BROKER_REFUSED_FIELDS",
            event=_REFUSED_EVENT,
            result="refused",
            subject={
                "destination": destination,
                "reason": reason,
                "egress_id": _egress_id(destination),
            },
        )

    async def _write(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        result: str,
        subject: dict[str, Any],
    ) -> None:
        from alfred.hooks import SYSTEM_ONLY_TIERS
        from alfred.hooks.context import HookContext
        from alfred.hooks.invoke import invoke

        correlation_id = str(uuid.uuid4())
        try:
            await asyncio.wait_for(
                self._audit.append_schema(
                    fields=fields,
                    schema_name=schema_name,
                    event=event,
                    actor_user_id=None,
                    actor_persona="supervisor",
                    subject=subject,
                    trust_tier_of_trigger="T0",
                    result=result,
                    cost_estimate_usd=0.0,
                    cost_actual_usd=0.0,
                    trace_id=correlation_id,
                ),
                timeout=self._timeout,
            )
        except TimeoutError:
            # Fail loud, never silent (HARD #7): a hung append_schema on the
            # extraction hot path must surface to the caller, which fails closed.
            # NOTE: the kwarg is "audit_event" (not "event") — structlog's bound
            # logger method signature is ``meth(event, *args, **kw)``, so a
            # kwarg literally named "event" collides with that positional
            # parameter and raises TypeError at the log call site itself.
            _log.error(
                "egress.broker.audit_write_timeout",
                audit_event=event,
                correlation_id=correlation_id,
                destination=subject["destination"],
                egress_id=subject["egress_id"],
            )
            raise

        ctx: HookContext[dict[str, object]] = HookContext(
            action_id=event,
            hookpoint=event,
            input={"result": result, "correlation_id": correlation_id},
            correlation_id=correlation_id,
            kind="post",
        )
        await invoke(
            event,
            ctx,
            kind="post",
            subscribable_tiers=SYSTEM_ONLY_TIERS,
            fail_closed=True,
        )


__all__ = ["EgressBrokerAuditor"]
