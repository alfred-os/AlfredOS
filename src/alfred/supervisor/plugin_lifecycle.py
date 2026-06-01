"""Plugin lifecycle coordination for the supervisor (spec §10, §14).

Wires the breaker's pure state machine
(:mod:`alfred.supervisor.breaker`) into the audit log via the typed
``append_schema`` API. Two responsibilities:

* :meth:`PluginLifecycle.start_plugin` — gate-check the manifest at
  load time and emit ``plugin.lifecycle.loaded`` or
  ``plugin.lifecycle.load_refused`` depending on the
  :meth:`CapabilityGate.check_plugin_load` outcome. Does NOT spawn the
  subprocess — that's the Supervisor's :class:`asyncio.TaskGroup`
  responsibility (Task 19).
* :meth:`PluginLifecycle.on_crash` — record a subprocess crash in the
  breaker via :meth:`CircuitBreaker.record_failure` and emit either
  ``plugin.lifecycle.crashed`` (breaker still CLOSED — under threshold)
  or ``plugin.lifecycle.quarantined`` (breaker tripped to OPEN on this
  crash) with the appropriate typed schema constant.

Cross-PR contracts honoured here:

* **PR-S3-0a cceafbd** — every emit uses
  :meth:`AuditWriter.append_schema` with a ``fields=`` schema constant
  AND a ``schema_name=`` string so the symmetric missing/extra-field
  guard catches typos at runtime.
* **Spec §5.6** — ``exception_type`` is the Python *type name only*.
  Callers pre-funnel via ``type(exc).__name__``; this module never
  touches ``str(exc)`` or ``exc.args`` so T3 fragments cannot leak into
  the audit row.
* **CR-S3-3a F2/F3** — the ``kill_succeeded`` field on the quarantined
  row reflects the actual SIGKILL outcome. When the Supervisor pre-kills
  a quarantined subprocess before invoking ``on_crash``, it threads the
  bool through here so the row mirrors reality (not an assumption).
* **err-001 / core-004** — hookpoint invocation lives in
  :mod:`alfred.supervisor.breaker` as standalone async helpers. This
  module does NOT call ``asyncio.create_task`` and never spawns
  fire-and-forget tasks; the helpers are awaited inside the supervisor's
  TaskGroup so subscriber exceptions surface (see Task 9).
"""

from __future__ import annotations

import datetime as dt
from typing import Literal, Protocol

import structlog

from alfred.audit.audit_row_schemas import (
    PLUGIN_LIFECYCLE_CRASHED_FIELDS,
    PLUGIN_LIFECYCLE_FIELDS,
    PLUGIN_LIFECYCLE_QUARANTINED_FIELDS,
)
from alfred.supervisor.breaker import (
    BreakerState,
    CircuitBreaker,
    invoke_plugin_lifecycle_crashed_hookpoint,
    invoke_plugin_lifecycle_loaded_hookpoint,
    invoke_plugin_lifecycle_quarantined_hookpoint,
)

_log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Audit-row constants — pinned here so the trace_id callers thread does not
# leak into surfaces that need not see it (cost, language defaults). The
# audit writer's ``append_schema`` will validate every emit against the
# named schema constant; these are the *non-schema* attribution fields.
# ---------------------------------------------------------------------------

_SUPERVISOR_PERSONA: Literal["supervisor"] = "supervisor"
_SUPERVISOR_ACTOR_USER_ID: Literal["system"] = "system"
# Supervisor rows describe internal state, not T-tiered user content.
_AUDIT_TRUST_TIER: Literal["T0"] = "T0"
# PR-S3-3b ships single-version manifests.
_MANIFEST_VERSION_DEFAULT: int = 1
# Lifecycle has no manifest handle here — Supervisor (Task 19) threads the real
# sandbox_profile when it has one.
_SANDBOX_PROFILE_UNKNOWN: Literal["unknown"] = "unknown"


class _GateLike(Protocol):
    """Structural type for the gate dependency — only ``check_plugin_load`` is used.

    A Protocol keeps the constructor signature decoupled from the concrete
    :class:`alfred.security.capability_gate.CapabilityGate` so unit tests
    can pass a one-method mock without an adapter layer.
    """

    def check_plugin_load(self, *, plugin_id: str, manifest_tier: str) -> bool:
        raise NotImplementedError


class _AuditLike(Protocol):
    """Structural type for the audit writer — only ``append_schema`` is used."""

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


class PluginLifecycle:
    """Coordinates the gate check, audit-row emission, and breaker update.

    The class is intentionally a thin orchestrator — no subprocess
    spawning, no SIGKILL, no hookpoint invocation. Those concerns live in
    the Supervisor (Task 19+) and the breaker hookpoint helpers (Task 9).
    Keeping responsibilities split means the test surface for each piece
    stays small and the call-graph stays one-directional:

        Supervisor → PluginLifecycle → CircuitBreaker
                                  ↘ AuditWriter

    """

    def __init__(self, *, gate: _GateLike, audit: _AuditLike) -> None:
        self._gate = gate
        self._audit = audit

    # ------------------------------------------------------------------
    # start_plugin — gate check + load_refused / loaded
    # ------------------------------------------------------------------

    async def start_plugin(
        self,
        *,
        plugin_id: str,
        manifest_tier: str,
        breaker: CircuitBreaker,
        trace_id: str,
        correlation_id: str | None = None,
    ) -> Literal["loaded", "load_refused"]:
        """Gate-check a plugin at load time and emit the lifecycle audit row.

        The two outcomes are symmetric on shape — same schema constant
        (``PLUGIN_LIFECYCLE_FIELDS``), same subject keys, different
        ``event`` + ``result`` labels. ``manifest_subscriber_tier`` is
        the SUBSCRIBER tier (spec §4.3 two-axis naming) and threads to
        the row; the gate consumes ``manifest_tier`` under the
        ``manifest_tier=`` kwarg verbatim.

        Args:
            plugin_id: Stable plugin identifier (matches the manifest).
            manifest_tier: The subscriber-capability axis tier from the
                plugin manifest — one of ``"system"`` / ``"operator"`` /
                ``"user-plugin"``.
            breaker: The plugin's circuit breaker. Read for
                ``breaker_state`` on the row; NOT mutated by this method.
            trace_id: Cross-system trace identifier (orchestrator-issued
                conventionally; supervisor-side flows mint their own).
            correlation_id: Optional correlation id for downstream
                joining. ``None`` is permitted on the row per the
                audit_row_schemas conditional-field convention.

        Returns:
            ``"load_refused"`` if the gate denied the load, ``"loaded"``
            otherwise. Spawning the subprocess is the supervisor's
            responsibility — this method only mediates the gate +
            attribution.
        """
        breaker_state_label = breaker.state.value
        if not self._gate.check_plugin_load(plugin_id=plugin_id, manifest_tier=manifest_tier):
            await self._audit.append_schema(
                fields=PLUGIN_LIFECYCLE_FIELDS,
                schema_name="PLUGIN_LIFECYCLE_FIELDS",
                event="plugin.lifecycle.load_refused",
                actor_user_id=_SUPERVISOR_ACTOR_USER_ID,
                actor_persona=_SUPERVISOR_PERSONA,
                subject={
                    "plugin_id": plugin_id,
                    "manifest_subscriber_tier": manifest_tier,
                    "manifest_version": _MANIFEST_VERSION_DEFAULT,
                    "sandbox_profile": _SANDBOX_PROFILE_UNKNOWN,
                    "exit_code": None,
                    "signal": None,
                    "restart_count": 0,
                    "breaker_state": breaker_state_label,
                    "correlation_id": correlation_id,
                },
                trust_tier_of_trigger=_AUDIT_TRUST_TIER,
                result="load_refused",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=trace_id,
            )
            _log.info(
                "supervisor.plugin.load_refused",
                plugin_id=plugin_id,
                manifest_tier=manifest_tier,
                trace_id=trace_id,
            )
            return "load_refused"

        await self._audit.append_schema(
            fields=PLUGIN_LIFECYCLE_FIELDS,
            schema_name="PLUGIN_LIFECYCLE_FIELDS",
            event="plugin.lifecycle.loaded",
            actor_user_id=_SUPERVISOR_ACTOR_USER_ID,
            actor_persona=_SUPERVISOR_PERSONA,
            subject={
                "plugin_id": plugin_id,
                "manifest_subscriber_tier": manifest_tier,
                "manifest_version": _MANIFEST_VERSION_DEFAULT,
                "sandbox_profile": _SANDBOX_PROFILE_UNKNOWN,
                "exit_code": None,
                "signal": None,
                "restart_count": 0,
                "breaker_state": breaker_state_label,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger=_AUDIT_TRUST_TIER,
            result="success",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=trace_id,
        )
        _log.info(
            "supervisor.plugin.loaded",
            plugin_id=plugin_id,
            manifest_tier=manifest_tier,
            trace_id=trace_id,
        )
        # arch-s3-3b-001: invoke the loaded hookpoint AFTER the audit row
        # so subscribers see the same transition the audit graph sees.
        # Awaited inline (no fire-and-forget) — err-001 / core-004.
        await invoke_plugin_lifecycle_loaded_hookpoint(
            plugin_id=plugin_id,
            manifest_subscriber_tier=manifest_tier,
            breaker_state=breaker_state_label,
        )
        return "loaded"

    # ------------------------------------------------------------------
    # on_crash — breaker increment + crashed / quarantined row
    # ------------------------------------------------------------------

    async def on_crash(
        self,
        *,
        plugin_id: str,
        manifest_tier: str,
        exception_type: str,
        exit_code: int | None,
        signal: int | None,
        restart_count: int,
        breaker: CircuitBreaker,
        trace_id: str,
        kill_succeeded: bool = True,
        correlation_id: str | None = None,
        now: dt.datetime | None = None,
    ) -> None:
        """Record a plugin crash: update the breaker and emit the audit row.

        Two emit shapes:

        * Breaker still CLOSED after :meth:`record_failure` →
          ``plugin.lifecycle.crashed`` via
          :data:`PLUGIN_LIFECYCLE_CRASHED_FIELDS` (adds
          ``exception_type``). ``result="crashed"`` per migration 0007.
        * Breaker tripped to OPEN →
          ``plugin.lifecycle.quarantined`` via
          :data:`PLUGIN_LIFECYCLE_QUARANTINED_FIELDS` (adds
          ``kill_succeeded``, ``quarantine_reason``, ``trip_count``).
          ``result="quarantined"`` per migration 0007.

        Args:
            plugin_id: Stable plugin identifier.
            manifest_tier: The plugin's declared subscriber tier
                (``"system"`` / ``"user-plugin"`` / etc.) — lands on the
                audit row's ``manifest_subscriber_tier`` field so
                non-system plugin crashes are correctly attributed
                (CR PR-S3-3b R5 #3332700199). Threaded from the
                supervisor's crash handler, which has the manifest
                handle for the crashing plugin. Spec §4.3 + PR-S3-3a
                R1 — closed-domain validation lives in the gate at load
                time; on the crash path we faithfully echo whatever the
                manifest declared (the load gate already rejected
                out-of-domain tiers).
            exception_type: Python *type name only* of the failure —
                ``type(exc).__name__``. Spec §5.6 forbids ``str(exc)`` /
                ``exc.args`` here because a misbehaving subprocess may
                carry T3 fragments in its exception string.
            exit_code: Process exit code if known, else ``None``.
            signal: Posix signal number if exit was via signal, else
                ``None``.
            restart_count: Cumulative restart count for this plugin
                (caller threads from its restart-loop state).
            breaker: The plugin's circuit breaker. Mutated via
                :meth:`record_failure`. Singleton per plugin per
                :class:`Supervisor.get_or_create_breaker` (Task 19).
            trace_id: Cross-system trace identifier.
            kill_succeeded: Only consumed on the quarantined row. When
                the Supervisor pre-killed the subprocess before invoking
                ``on_crash`` (the OPEN-breaker preemptive kill flow), it
                passes the kill outcome here so the audit row reflects
                reality (spec §4.6 + CR-S3-3a F2/F3). Defaults to
                ``True`` because the typical case is "subprocess died
                on its own — no kill needed; nothing to fail."
            correlation_id: Optional correlation id.
            now: Frozen-clock injection for tests.

        Hookpoint invocation (``supervisor.breaker.tripped``) is the
        *caller's* responsibility on the OPEN-transition path so the
        await stays inside the supervisor's TaskGroup (err-001 /
        core-004). Task 9's :func:`invoke_breaker_tripped_hookpoint`
        helper is awaited by the Supervisor after this method returns
        when ``breaker.state == BreakerState.OPEN``.
        """
        breaker.record_failure(exception_type, now=now)
        breaker_state_label = breaker.state.value

        # Symmetric-shape subject — the field set differs across the two
        # emits, but the shared keys are computed once. ``manifest_tier``
        # threaded from the caller so non-system plugin crashes attribute
        # correctly (CR PR-S3-3b R5 #3332700199); previously hardcoded
        # ``"system"`` here, which misattributed user-plugin crashes.
        base_subject: dict[str, object] = {
            "plugin_id": plugin_id,
            "manifest_subscriber_tier": manifest_tier,
            "manifest_version": _MANIFEST_VERSION_DEFAULT,
            "sandbox_profile": _SANDBOX_PROFILE_UNKNOWN,
            "exit_code": exit_code,
            "signal": signal,
            "restart_count": restart_count,
            "breaker_state": breaker_state_label,
            "correlation_id": correlation_id,
        }

        if breaker.state == BreakerState.OPEN:
            await self._audit.append_schema(
                fields=PLUGIN_LIFECYCLE_QUARANTINED_FIELDS,
                schema_name="PLUGIN_LIFECYCLE_QUARANTINED_FIELDS",
                event="plugin.lifecycle.quarantined",
                actor_user_id=_SUPERVISOR_ACTOR_USER_ID,
                actor_persona=_SUPERVISOR_PERSONA,
                subject=base_subject
                | {
                    "kill_succeeded": kill_succeeded,
                    "quarantine_reason": "circuit_breaker_open",
                    "trip_count": breaker.trip_count,
                },
                trust_tier_of_trigger=_AUDIT_TRUST_TIER,
                result="quarantined",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=trace_id,
            )
            _log.warning(
                "supervisor.plugin.quarantined",
                plugin_id=plugin_id,
                trip_count=breaker.trip_count,
                kill_succeeded=kill_succeeded,
                trace_id=trace_id,
            )
            # arch-s3-3b-001: invoke the quarantined hookpoint AFTER the
            # audit row. The matching ``supervisor.breaker.tripped``
            # invocation (lower-level state transition) is the caller's
            # responsibility — both fire on the same OPEN transition and
            # downstream consumers join on ``plugin_id``. Awaited inline —
            # err-001 / core-004.
            await invoke_plugin_lifecycle_quarantined_hookpoint(
                plugin_id=plugin_id,
                trip_count=breaker.trip_count,
                kill_succeeded=kill_succeeded,
            )
            return

        await self._audit.append_schema(
            fields=PLUGIN_LIFECYCLE_CRASHED_FIELDS,
            schema_name="PLUGIN_LIFECYCLE_CRASHED_FIELDS",
            event="plugin.lifecycle.crashed",
            actor_user_id=_SUPERVISOR_ACTOR_USER_ID,
            actor_persona=_SUPERVISOR_PERSONA,
            subject=base_subject | {"exception_type": exception_type},
            trust_tier_of_trigger=_AUDIT_TRUST_TIER,
            result="crashed",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=trace_id,
        )
        _log.info(
            "supervisor.plugin.crashed",
            plugin_id=plugin_id,
            exception_type=exception_type,
            restart_count=restart_count,
            trace_id=trace_id,
        )
        # arch-s3-3b-001: invoke the crashed hookpoint AFTER the audit row
        # on the CLOSED-still path. Awaited inline — err-001 / core-004.
        await invoke_plugin_lifecycle_crashed_hookpoint(
            plugin_id=plugin_id,
            exception_type=exception_type,
            breaker_state=breaker_state_label,
            restart_count=restart_count,
        )


__all__ = ["PluginLifecycle"]
