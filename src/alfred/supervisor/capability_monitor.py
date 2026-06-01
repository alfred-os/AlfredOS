"""Supervisor-side capability-gate health monitor (spec §10.4, §8.1).

:class:`CapabilityGateMonitor` is the supervisor-level outer poll loop
that wraps :class:`alfred.security.capability_gate.RealGate`. The gate
itself has an internal heartbeat that emits per-dispatch denial rows
during fail-closed (rate-limited at 1/sec/plugin_id; spec §8.1); this
monitor adds the **transition-only** audit rows the operator dashboard
joins on:

* ``entering_fail_closed`` — emitted the first heartbeat that sees the
  gate's backing store unavailable.
* ``exiting_fail_closed`` — emitted the heartbeat that observes the
  backing store has recovered. Carries a ``denied_dispatch_count``
  rollup of the denials counted during the outage window.

Both rows share a single per-outage ``correlation_id`` (err-014) so the
audit graph can answer "how long did this outage last" with a single
GROUP BY join — no window function, no streaming aggregation.

Why a supervisor-side monitor on top of RealGate's internal heartbeat?
RealGate's heartbeat is the gate's own self-healing loop — it owns the
fail-closed window enforcement (60s in-process grace; spec §8.1). The
supervisor monitor surfaces the **transition event** for the operator
dashboard's outage timeline. Two distinct concerns:

* RealGate.heartbeat → per-dispatch enforcement + gate's own emit path.
* CapabilityGateMonitor → supervisor-level "outage started" / "outage
  ended" surface for the audit graph.

Test boundary
-------------

PR-S3-2 ``tests/unit/security/capability_gate/test_fail_closed_outage.py``
pins the gate's internal heartbeat. This monitor's contract is pinned by
``tests/integration/supervisor/test_capability_gate_outage_fail_closed.py``
(supervisor-side coordination; structural mocks for the gate + audit
sink).

Cross-PR contracts
------------------

* :data:`SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS` (PR-S3-0a) — the
  typed field set every emit validates against. The monitor uses
  :meth:`AuditWriter.append_schema` so a typo on the emit side raises
  rather than silently writing a malformed row.
* ``actor_persona="supervisor"`` — pinned per the supervisor's audit
  attribution policy (matches PluginLifecycle's emit pattern).
* ``trust_tier_of_trigger="T0"`` — the row describes internal system
  state, never T-tiered user content (spec §3.6).
"""

from __future__ import annotations

import uuid
from typing import Protocol

import structlog

from alfred.audit.audit_row_schemas import SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS

_log = structlog.get_logger(__name__)

# Spec §8.1 — supervisor heartbeat interval default. 5 seconds is short
# enough that operators see an outage within a one-Grafana-refresh cycle
# yet long enough that the poll cost stays in the noise on a healthy
# gate. The interval is constructor-injectable so tests run without
# sleeping. Pinning here documents the production default.
_HEARTBEAT_INTERVAL_DEFAULT: float = 5.0


class _GateProbe(Protocol):
    """Structural type for the gate dependency.

    The monitor reads exactly one method off the gate:
    :meth:`is_backing_store_available`. A Protocol keeps the constructor
    decoupled from the concrete :class:`RealGate` so tests pass a
    one-method stub without an adapter layer (same pattern as
    :class:`alfred.supervisor.plugin_lifecycle._GateLike`).
    """

    def is_backing_store_available(self) -> bool:
        raise NotImplementedError


class _AuditSink(Protocol):
    """Structural type for the audit writer — only ``append_schema`` is used.

    Mirrors the Protocol shape in
    :mod:`alfred.supervisor.plugin_lifecycle`. The full
    :class:`alfred.audit.log.AuditWriter` satisfies the Protocol
    structurally; tests pass ``AsyncMock(spec=AuditWriter)`` or a bare
    AsyncMock with ``append_schema`` set.
    """

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
        actor_persona: str = "alfred",
        persona_id: str | None = None,
        cost_actual_usd: float | None = None,
        language: str = "en-US",
    ) -> None:
        raise NotImplementedError


class CapabilityGateMonitor:
    """Polls the capability gate and emits state-transition audit rows.

    One instance per supervised gate (Slice 3 ships one gate per process,
    so one monitor per Supervisor). Construction takes a structural
    gate probe and an audit sink; the supervisor calls
    :meth:`run_one_heartbeat` from its supervised task loop at
    ``heartbeat_interval`` cadence.

    Stateful: tracks the current fail-closed status and the per-outage
    ``correlation_id`` + ``denied_dispatch_count``. Reset on every
    entering transition so per-outage accumulation never bleeds across
    outages.

    Thread-safety: the monitor is single-task — only the supervised
    heartbeat task ever calls :meth:`run_one_heartbeat`. Plugin denial
    code paths call :meth:`record_denied_dispatch` from arbitrary tasks;
    that increment is a plain ``+= 1`` on a Python int which is
    atomic under the GIL. No lock needed for the counter; the
    state-transition logic only runs from the heartbeat task.
    """

    def __init__(
        self,
        *,
        gate: _GateProbe,
        audit: _AuditSink,
        heartbeat_interval: float = _HEARTBEAT_INTERVAL_DEFAULT,
    ) -> None:
        # ``heartbeat_interval`` is recorded but the monitor itself does
        # not sleep — the supervisor's TaskGroup-supervised loop owns the
        # cadence. Storing the value makes it observable to the
        # supervisor's status surface and lets future Slice-3+ patches
        # surface it on the audit row's subject without a constructor
        # signature change.
        self._gate = gate
        self._audit = audit
        self._heartbeat_interval = heartbeat_interval
        self._in_fail_closed: bool = False
        # ``_outage_correlation_id`` is set on each entering transition
        # and read on the matching exiting transition (err-014). Storing
        # ``None`` between outages makes a leaked read fail loudly rather
        # than reusing the previous outage's id.
        self._outage_correlation_id: str | None = None
        self._denied_dispatch_count: int = 0

    def record_denied_dispatch(self) -> None:
        """Increment the per-outage denial rollup.

        Called by dispatch code paths that observe the gate refusing a
        dispatch during fail-closed. The increment is a no-op outside
        fail-closed (err-015) so a denial racing the monitor's
        not-yet-observed transition doesn't bleed into a future
        outage's rollup.

        Spec §10.4: the exiting row carries the cumulative count; the
        per-dispatch denial rows live in the gate itself.
        """
        if self._in_fail_closed:
            self._denied_dispatch_count += 1

    async def run_one_heartbeat(self) -> None:
        """Probe the gate and emit a transition row if the state changed.

        Called once per heartbeat cycle by the supervisor's supervised
        task loop. Emits at most one audit row per call (entering OR
        exiting). On steady state — gate available, monitor not in
        fail-closed, or gate unavailable, monitor already in fail-closed
        — the method is a no-op (single read on the gate Protocol).

        Audit-before-commit invariant (CR PR-S3-3b R5 #3332700170):
        the in-memory state flip (``_in_fail_closed``,
        ``_outage_correlation_id``, ``_denied_dispatch_count``) ONLY lands
        if the matching audit emit succeeds. If ``append_schema`` raises,
        the previous state is restored and the exception propagates so the
        supervisor's TaskGroup surfaces the failure (err-001). Without
        this, a single transient sink failure during the entering branch
        would leave the monitor in the new state with no entering row in
        the audit graph — subsequent heartbeats would silently skip the
        transition forever because the "already in fail-closed" branch
        short-circuits before the emit (PRD §10.4 outage-transition
        contract).
        """
        available = self._gate.is_backing_store_available()
        if not available and not self._in_fail_closed:
            new_correlation_id = str(uuid.uuid4())
            await self._emit_transition(
                state_transition="entering_fail_closed",
                denied_dispatch_count=0,
                backing_store_error_type="unavailable",
                correlation_id_override=new_correlation_id,
            )
            # Audit emit succeeded — commit the in-memory transition.
            self._in_fail_closed = True
            self._outage_correlation_id = new_correlation_id
            self._denied_dispatch_count = 0
            return
        if available and self._in_fail_closed:
            denied = self._denied_dispatch_count
            correlation_id = self._outage_correlation_id
            await self._emit_transition(
                state_transition="exiting_fail_closed",
                denied_dispatch_count=denied,
                backing_store_error_type="",
                correlation_id_override=correlation_id,
            )
            # Audit emit succeeded — commit the in-memory transition.
            self._in_fail_closed = False
            self._denied_dispatch_count = 0
            self._outage_correlation_id = None

    async def _emit_transition(
        self,
        *,
        state_transition: str,
        denied_dispatch_count: int,
        backing_store_error_type: str,
        correlation_id_override: str | None = None,
    ) -> None:
        """Emit one ``supervisor.capability_gate_unavailable`` row.

        ``correlation_id`` defaults to the monitor's current outage id
        but the exiting path supplies it explicitly via
        ``correlation_id_override`` because the monitor clears the id
        BEFORE the emit await (so a crash between clear and emit doesn't
        leave the monitor stuck with a stale id for a future outage).

        Uses :meth:`AuditWriter.append_schema` against
        :data:`SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS` so the
        symmetric missing/extra-field guard catches drift between the
        schema constant and this emit site (PR-S3-0a contract).

        Attribution pins:
            * ``actor_persona="supervisor"`` — supervisor rows are never
              attributed to Alfred.
            * ``actor_user_id=None`` — no human actor for a self-healing
              probe (operator-cancel is the only supervisor row that
              carries an actor; that's breaker.reset).
            * ``trust_tier_of_trigger="T0"`` — describes internal system
              state, never T-tiered content (spec §3.6).
            * ``result="success"`` — the emit itself succeeded; the
              ``state_transition`` field carries the outage semantics.
        """
        # Defensive: the constructor leaves _outage_correlation_id at
        # None, and the entering branch sets it before this method is
        # called. The fallback uuid generation guards against a probe
        # firing on a monitor that was never entered (e.g. a test
        # invoking _emit_transition directly).
        correlation_id = (
            correlation_id_override
            if correlation_id_override is not None
            else (self._outage_correlation_id or str(uuid.uuid4()))
        )
        subject: dict[str, object] = {
            "state_transition": state_transition,
            "denied_dispatch_count": denied_dispatch_count,
            "backing_store_error_type": backing_store_error_type,
            "correlation_id": correlation_id,
        }
        await self._audit.append_schema(
            fields=SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS,
            schema_name="SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS",
            event="supervisor.capability_gate_unavailable",
            actor_user_id=None,
            actor_persona="supervisor",
            subject=subject,
            trust_tier_of_trigger="T0",
            result="success",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=correlation_id,
        )
        _log.warning(
            "supervisor.capability_gate_unavailable",
            state_transition=state_transition,
            denied_dispatch_count=denied_dispatch_count,
            correlation_id=correlation_id,
        )


__all__ = ["CapabilityGateMonitor"]
