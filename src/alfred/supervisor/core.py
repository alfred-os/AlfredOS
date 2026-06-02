"""Supervisor — top-level coordinator for plugin lifecycle and circuit breakers.

The Supervisor owns three things (spec §10.1, §10.5, §10.8):

1. An ``asyncio.TaskGroup`` under which every supervised plugin's
   stdio-reader task runs. Cancelling the group cascade-cancels all
   reader tasks; each reader's finally arm handles its own subprocess
   SIGTERM→SIGKILL escalation (the supervisor itself does not reach into
   subprocess plumbing; that's plugin-transport concern).
2. The per-component :class:`alfred.supervisor.breaker.CircuitBreaker`
   map. One breaker per ``component_id`` —
   :meth:`get_or_create_breaker` enforces the singleton invariant so
   ``record_failure`` calls from different supervisor paths converge on
   the same state machine.
3. The operator API :meth:`reset_breaker`. Emits the
   ``supervisor.breaker.reset`` audit row with operator attribution and
   persists the new CLOSED state to Postgres.

TaskGroup lifecycle (core-001 — Slice-3 plan-review landmine)
-------------------------------------------------------------

``asyncio.TaskGroup`` must be entered with ``async with`` before any
``create_task()`` calls; the group's lifetime cannot span a constructor.
The supervisor solves this with a long-lived internal ``_run()``
coroutine that holds the TaskGroup open until ``_shutdown_event`` is
set::

    async def _run(self) -> None:
        async with asyncio.TaskGroup() as tg:
            self._task_group = tg
            self._started_event.set()
            await self._shutdown_event.wait()

:meth:`start` spawns this runner; :meth:`stop` sets the shutdown event
and awaits the runner to drain. Plugin tasks added via
:meth:`register_plugin_task` join the group while it's active.

What this PR does NOT do
------------------------

PR-S3-3b Tasks 13-17 ship the Supervisor class and its public API;
Tasks 19-20 populate ``_register_hookpoints`` with the full spec §14
hookpoint table (``supervisor.breaker.tripped``,
``supervisor.breaker.reset``, ``supervisor.action_timeout``,
``plugin.lifecycle.*``). The CLI surface
(``alfred supervisor status``, ``alfred supervisor reset <component>
--confirm``) is owned exclusively by PR-S3-6 (devex-001 / rvw-002 —
shipping CLI here would race the Typer-based PR-S3-6 CLI on whichever
merges second).

Self-healing restart scheduling (HALF_OPEN re-arm cadence, exponential
backoff probe timing) is a Slice-4 concern — PR-S3-3b ships the
breaker primitives (``maybe_rearm``, ``record_probe_success``) but
not the scheduling loop that drives them.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Coroutine
from contextlib import AbstractAsyncContextManager, suppress
from typing import TYPE_CHECKING, Any, Protocol

import structlog
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.audit_row_schemas import SUPERVISOR_BREAKER_RESET_FIELDS
from alfred.i18n import t
from alfred.supervisor.breaker import BreakerState, CircuitBreaker
from alfred.supervisor.capability_monitor import CapabilityGateMonitor
from alfred.supervisor.errors import NoSuchComponentError
from alfred.supervisor.plugin_lifecycle import PluginLifecycle

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_log = structlog.get_logger(__name__)

# Spec §10.5 — graceful shutdown budget. After ``stop()`` sets the
# shutdown event the supervisor waits up to this many seconds for the
# TaskGroup to drain naturally. If any supervised task hangs past this
# window, the runner is cancelled outright and the shutdown row is
# emitted with the partial breaker count.
_STOP_DRAIN_TIMEOUT_SECONDS: float = 10.0


class _GateLike(Protocol):
    """Structural type for the gate dependency the supervisor wraps.

    The supervisor itself doesn't call methods on the gate — it holds the
    reference so it can pass it to :class:`PluginLifecycle` and
    :class:`CapabilityGateMonitor` at construction. The narrow Protocol
    here keeps the constructor signature decoupled from the concrete
    :class:`alfred.security.capability_gate.RealGate` for test purposes.

    Tests pass ``MagicMock()`` (no methods asserted on the gate itself);
    production passes a ``RealGate`` instance.
    """


class _AuditLike(Protocol):
    """Structural type for the audit writer — ``append`` + ``append_schema``."""

    async def append(
        self,
        *,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, Any],
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

    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, Any],
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


class Supervisor:
    """Top-level supervisor for plugin lifecycle and circuit breakers.

    Construction takes a ``session_scope`` factory (same pool as the
    orchestrator), a capability gate, and an audit writer. The
    supervisor immediately constructs a :class:`PluginLifecycle` and a
    :class:`CapabilityGateMonitor` bound to those dependencies — both are
    long-lived for the supervisor's lifetime.

    Lifecycle:

    * Construct: instance ready; ``_task_group`` is None.
    * :meth:`start`: opens the supervised TaskGroup via an internal
      ``_run()`` coroutine. Plugin tasks can be registered after
      ``_started_event`` resolves.
    * :meth:`register_plugin_task`: schedules a coroutine inside the
      active TaskGroup. Raises if called before start or after stop.
    * :meth:`stop`: sets the shutdown event; waits for the runner to
      drain; persists every breaker's state to Postgres; emits the
      ``supervisor.lifecycle.stopped`` audit row.

    Operator API:

    * :meth:`reset_breaker`: any state → CLOSED, emits
      ``supervisor.breaker.reset`` with operator attribution, persists.
    * :meth:`get_or_create_breaker`: singleton-per-component breaker.
    * :meth:`load_all_breakers`: bulk-load every breaker's state from
      Postgres (called once at process bootstrap before plugin spawns
      so a previously-tripped breaker stays OPEN across restarts).
    """

    def __init__(
        self,
        *,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
        gate: _GateLike,
        audit: _AuditLike,
    ) -> None:
        self._session_scope = session_scope
        self._gate = gate
        self._audit = audit
        self._breakers: dict[str, CircuitBreaker] = {}
        # PluginLifecycle and CapabilityGateMonitor share the gate and
        # audit references; both are bound at construction so the
        # supervisor surface stays narrow (start/stop/register/reset).
        # Type-ignored: the structural protocols here are intentionally
        # broader than the helper modules' Protocols (PluginLifecycle
        # expects ``check_plugin_load``, CapabilityGateMonitor expects
        # ``is_backing_store_available``) — the supervisor's _GateLike
        # is empty because the supervisor itself never calls methods on
        # the gate. Tests + production pass a RealGate that satisfies
        # every relevant Protocol structurally.
        self._lifecycle = PluginLifecycle(gate=gate, audit=audit)  # type: ignore[arg-type]
        self._capability_monitor = CapabilityGateMonitor(
            gate=gate,  # type: ignore[arg-type]
            audit=audit,
        )

        # start/stop state — see class docstring for the lifecycle.
        self._task_group: asyncio.TaskGroup | None = None
        self._run_task: asyncio.Task[None] | None = None
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._started_event: asyncio.Event = asyncio.Event()

        self._register_hookpoints()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Open the supervised TaskGroup and begin accepting plugin tasks.

        Spawns an internal ``_run()`` task that holds the TaskGroup open
        until :attr:`_shutdown_event` is set by :meth:`stop`. The await
        on ``_started_event`` here ensures :attr:`_task_group` is
        populated before this method returns, so callers can immediately
        call :meth:`register_plugin_task` without a race.

        Raises:
            RuntimeError: ``start()`` called twice without an intervening
                ``stop()``. Re-entrancy would orphan the first TaskGroup
                and double-supervise every subsequent register call.
        """
        if self._run_task is not None:
            raise RuntimeError(t("supervisor.start.already_started"))
        # Reset both events — the supervisor instance can in principle be
        # restarted (stop() then start()) and the events from the previous
        # cycle must not bleed into the new one.
        self._shutdown_event = asyncio.Event()
        self._started_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        self._run_task = loop.create_task(self._run())
        await self._started_event.wait()
        _log.info("supervisor.started")

    async def _run(self) -> None:
        """Hold the TaskGroup open until ``_shutdown_event`` resolves.

        This coroutine is the only place ``async with asyncio.TaskGroup()``
        appears. Spec §10.5: the TaskGroup's cancellation semantics are
        load-bearing — cancelling it cascades to every supervised plugin
        task, which is exactly the shutdown shape we want.

        devex-001 (F6): the :class:`CapabilityGateMonitor` heartbeat loop
        is scheduled here as a supervised TaskGroup task. Spec §8.1 /
        §10.4: the heartbeat polls the gate's backing store and emits
        transition rows when the gate enters/exits fail-closed. Wiring
        it as a TaskGroup task means a crashing heartbeat surfaces (via
        the TaskGroup's aggregated exception) rather than dying
        silently — the supervisor's observability surface stays loud.
        """
        async with asyncio.TaskGroup() as tg:
            self._task_group = tg
            tg.create_task(self._capability_heartbeat_loop())
            self._started_event.set()
            await self._shutdown_event.wait()

    async def _capability_heartbeat_loop(self) -> None:
        """Run the capability-gate heartbeat until shutdown.

        devex-001 (F6) — supervisor.heartbeat surface: polls the gate at
        ``CapabilityGateMonitor._heartbeat_interval`` cadence until the
        supervisor's :attr:`_shutdown_event` resolves. Each tick calls
        :meth:`CapabilityGateMonitor.run_one_heartbeat` which emits at
        most one transition row per cycle (entering or exiting
        fail-closed).

        The loop suspends on ``asyncio.wait_for(shutdown_event.wait(),
        timeout=interval)`` so a clean shutdown propagates immediately
        rather than waiting up to ``interval`` seconds. When the
        ``shutdown_event`` resolves the wait_for returns successfully
        and the loop exits.

        Subscriber exceptions inside ``run_one_heartbeat`` propagate out
        of this coroutine and into the TaskGroup, which cancels every
        sibling task (the supervised plugin reader loops) and re-raises
        the aggregated error from :meth:`_run`. The audit row inside
        ``run_one_heartbeat`` is the loud-failure signal; the
        TaskGroup-aggregated raise is the operator-facing escalation.
        """
        interval = self._capability_monitor._heartbeat_interval
        while not self._shutdown_event.is_set():
            await self._capability_monitor.run_one_heartbeat()
            try:
                # wait_for raises TimeoutError when the interval elapses
                # without shutdown; we treat that as "next tick due" and
                # loop back. Any other exception (e.g. external cancel)
                # propagates.
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
            except TimeoutError:
                continue

    async def stop(self) -> None:
        """Drain the supervised TaskGroup; persist breaker state; audit.

        Idempotent if not started (no-op). After the TaskGroup drains:

        1. Every breaker's current state is persisted to Postgres so a
           restart-then-load-from-db round-trip restores the correct
           state machine (spec §10.6).
        2. ``supervisor.lifecycle.stopped`` audit row is emitted with the
           component count so dashboards can show a clean-shutdown
           timeline.

        If the supervised TaskGroup does not drain within
        :data:`_STOP_DRAIN_TIMEOUT_SECONDS` the runner is force-cancelled
        and the row still emits — operators see "clean shutdown failed"
        as the audit-graph signal.
        """
        if self._run_task is None:
            return
        _log.info("supervisor.stopping")
        self._shutdown_event.set()
        force_cancel_exc: BaseException | None = None
        try:
            await asyncio.wait_for(self._run_task, timeout=_STOP_DRAIN_TIMEOUT_SECONDS)
        except TimeoutError:
            # Pure timeout — the task is still alive but exceeded the drain
            # budget. Cancel it and await it to completion so any
            # supervised plugin's finally-arm gets to run. The await may
            # raise CancelledError (the expected signal — swallow) or a
            # BaseExceptionGroup carrying real errors (capture for the
            # audit row below). err-001 (F5).
            self._run_task.cancel()
            _log.warning("supervisor.stop_timeout_force_cancel")
            with suppress(asyncio.CancelledError):
                try:
                    await self._run_task
                except BaseException as exc:
                    force_cancel_exc = exc
        except BaseException as exc:
            # Python 3.11+ wait_for(task, timeout) cancels the task on
            # timeout and awaits it — if the task raises a non-cancel
            # error during cancellation (e.g. a plugin's finally-arm
            # raised RuntimeError), wait_for re-raises that error
            # directly rather than TimeoutError. err-001 (F5): capture
            # it so the audit row reflects the unclean shutdown
            # instead of letting the exception silently propagate out
            # of stop() and skip the audit emit + state cleanup below.
            #
            # CR PR-S3-3b R5 #3332700176: ``SystemExit`` and
            # ``KeyboardInterrupt`` are operator-control signals — an
            # operator pressing Ctrl-C to force-abort a hung shutdown
            # MUST be honoured, not absorbed into the audit row. Re-raise
            # alongside ``CancelledError`` so the process exits promptly.
            if isinstance(exc, (asyncio.CancelledError, SystemExit, KeyboardInterrupt)):
                raise
            force_cancel_exc = exc
            _log.warning(
                "supervisor.stop_supervised_task_error",
                error_type=type(exc).__name__,
            )

        # Persist breaker states. The session_scope is a fresh transaction
        # — independent of any plugin-task transactions that may have
        # been rolled back by their cancellation.
        #
        # err-002 (F5): persistence failure on shutdown is loud — we
        # propagate the SQLAlchemyError so the operator-facing shutdown
        # error message surfaces — but we ALSO emit the lifecycle.stopped
        # row with ``result=persistence_failed`` BEFORE re-raising so the
        # audit graph records the failure. The audit writer opens its own
        # session per ``.append()`` call (it does not share our
        # session_scope), so the row commits even though our persistence
        # scope rolled back.
        try:
            async with self._session_scope() as session:
                for breaker in self._breakers.values():
                    await breaker.save_to_db(session)
                await session.commit()
        except SQLAlchemyError as persistence_exc:
            await self._audit.append(
                event="supervisor.lifecycle.stopped",
                actor_user_id=None,
                actor_persona="supervisor",
                subject={
                    "component_count": len(self._breakers),
                    "error_type": type(persistence_exc).__name__,
                },
                trust_tier_of_trigger="T0",
                result="persistence_failed",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=str(uuid.uuid4()),
            )
            _log.error(
                "supervisor.stop_persistence_failed",
                error_type=type(persistence_exc).__name__,
            )
            self._run_task = None
            self._task_group = None
            raise

        # err-001 (F5): if the force-cancel arm captured a BaseException
        # from the supervised TaskGroup, the row reflects that — operators
        # see "clean shutdown failed" as the audit-graph signal instead of
        # the misleading clean success row. The exception is NOT re-raised
        # (stop() is the shutdown path; we MUST drain before returning so
        # the supervising process can finish exiting), but it IS audited.
        result_label = "cancelled_with_errors" if force_cancel_exc is not None else "success"
        subject: dict[str, Any] = {"component_count": len(self._breakers)}
        if force_cancel_exc is not None:
            subject["error_type"] = type(force_cancel_exc).__name__

        await self._audit.append(
            event="supervisor.lifecycle.stopped",
            actor_user_id=None,
            actor_persona="supervisor",
            subject=subject,
            trust_tier_of_trigger="T0",
            result=result_label,
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=str(uuid.uuid4()),
        )
        self._run_task = None
        self._task_group = None

    def register_plugin_task(
        self,
        coro: Coroutine[Any, Any, None],
    ) -> asyncio.Task[None]:
        """Schedule a supervised plugin coroutine inside the active TaskGroup.

        Must be called between :meth:`start` and :meth:`stop`. The
        returned task's lifetime is owned by the TaskGroup — cancelling
        the supervisor cancels every task in the group, which is the
        shutdown contract.

        Raises:
            RuntimeError: ``register_plugin_task`` called before
                :meth:`start` or after :meth:`stop`. Without an active
                TaskGroup the task would either run unsupervised or be
                immediately orphaned.
        """
        if self._task_group is None:
            raise RuntimeError(t("supervisor.register_plugin_task.no_active_task_group"))
        return self._task_group.create_task(coro)

    # ------------------------------------------------------------------
    # Breaker map
    # ------------------------------------------------------------------

    def get_or_create_breaker(self, component_id: str) -> CircuitBreaker:
        """Return the breaker for ``component_id``, creating it if absent.

        Singleton-per-component: two ``record_failure`` calls from
        different supervisor paths against the same component_id must
        converge on the same state machine, else the failure window's
        sliding-window cutoff loses entries.
        """
        if component_id not in self._breakers:
            self._breakers[component_id] = CircuitBreaker(
                component_id=component_id,
                session_scope=self._session_scope,
            )
        return self._breakers[component_id]

    async def reset_breaker(
        self,
        component_id: str,
        *,
        operator_user_id: str,
    ) -> None:
        """Operator-triggered breaker reset (spec §10.8).

        Any state → CLOSED via :meth:`CircuitBreaker.reset`. Emits a
        ``supervisor.breaker.reset`` audit row with the operator's
        attribution and a correlation_id, then persists the new CLOSED
        state to Postgres so a restart preserves the reset.

        Trust tier on the audit row is ``T1`` — this is an
        operator-tier command (spec §3.6); distinct from the supervisor's
        own T0 rows that describe internal state.

        Raises:
            NoSuchComponentError: ``component_id`` is not registered. A
                typed :class:`SupervisorError` subclass so the CLI
                surface (PR-S3-6) can ``except NoSuchComponentError``
                separately from the generic ``SupervisorError`` arm.
                CR-149 round-7 replaced the previous English-substring
                dispatch in the CLI with a typed-exception narrow —
                non-English operator languages and catalog copy-edits
                no longer break the missing-component branch.
        """
        breaker = self._breakers.get(component_id)
        if breaker is None:
            # CR-149 round-7: raise the typed subclass. The catalog-
            # backed body still flows through ``str(exc)`` for the
            # forensic structlog stream + reviewer-side audit row, but
            # the CLI ``except`` arm now narrows on the class, not the
            # English substring.
            raise NoSuchComponentError(
                t("supervisor.no_such_component", component_id=component_id)
            )

        old_state = breaker.state.value
        breaker.reset()

        correlation_id = str(uuid.uuid4())

        # CR PR-S3-3b R5 #3332700182: persist BEFORE auditing ``success``.
        # Previously, the row was emitted with ``result="success"`` then
        # ``session.commit()`` ran; a commit failure left the audit graph
        # showing a clean reset while the on-disk state stayed pre-reset,
        # so a ``load_all_breakers`` on the next boot would silently re-open
        # the breaker the operator believed they cleared. Mirror the
        # err-002 pattern in ``stop()``: persist first, audit ``success``
        # on commit success, audit ``persistence_failed`` and re-raise on
        # ``SQLAlchemyError`` so the operator-facing reset error is loud.
        #
        # The in-memory ``breaker.reset()`` above is irreversible — it has
        # already mutated state by the time we get here. The audit row in
        # the failure arm captures the divergence: subscribers see the
        # operator-initiated transition AND the persistence failure, so
        # the next ``load_all_breakers`` (which restores OPEN) is
        # explainable from the graph.
        subject: dict[str, Any] = {
            "component_id": component_id,
            "old_state": old_state,
            # S3-3b-R1: pin the BreakerState enum's CLOSED value so a
            # future rename to the domain literal (CHECK constraint at
            # the DB layer is the source of truth) propagates here
            # without a manual sync. Mirrors line 370's old_state read.
            "new_state": BreakerState.CLOSED.value,
            "trip_count": breaker.trip_count,
            "operator_user_id": operator_user_id,
            "correlation_id": correlation_id,
        }

        try:
            async with self._session_scope() as session:
                await breaker.save_to_db(session)
                await session.commit()
        except SQLAlchemyError as persistence_exc:
            await self._audit.append_schema(
                fields=SUPERVISOR_BREAKER_RESET_FIELDS,
                schema_name="SUPERVISOR_BREAKER_RESET_FIELDS",
                event="supervisor.breaker.reset",
                actor_user_id=operator_user_id,
                actor_persona="supervisor",
                subject=subject,
                trust_tier_of_trigger="T1",
                result="persistence_failed",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=correlation_id,
            )
            _log.error(
                "supervisor.reset_breaker_persistence_failed",
                component_id=component_id,
                error_type=type(persistence_exc).__name__,
            )
            raise

        await self._audit.append_schema(
            fields=SUPERVISOR_BREAKER_RESET_FIELDS,
            schema_name="SUPERVISOR_BREAKER_RESET_FIELDS",
            event="supervisor.breaker.reset",
            actor_user_id=operator_user_id,
            actor_persona="supervisor",
            subject=subject,
            trust_tier_of_trigger="T1",
            result="success",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=correlation_id,
        )

    async def load_all_breakers(self) -> None:
        """Restore every registered breaker's state from Postgres.

        Called once at process bootstrap, AFTER every component's breaker
        has been registered via :meth:`get_or_create_breaker` but BEFORE
        plugin subprocess spawn. Spec §10.6: a previously-tripped breaker
        stays OPEN across restarts if ``last_trip_at`` is within the
        re-arm window — otherwise the operator's restart would silently
        re-arm every quarantined plugin.
        """
        async with self._session_scope() as session:
            for breaker in self._breakers.values():
                await breaker.load_from_db(session)

    # ------------------------------------------------------------------
    # Hookpoint registration (spec §14 — Tasks 19-20)
    # ------------------------------------------------------------------

    def _register_hookpoints(self) -> None:
        """Register every supervisor hookpoint with the global registry.

        Spec §14 enumerates the supervisor's six hookpoints. All of them
        — including ``supervisor.action_timeout`` — are declared HERE,
        from ``Supervisor.__init__``. Import-time registration in
        ``deadline.py`` / ``breaker.py`` was rejected at plan review
        (core-010): module-import side-effects break test isolation
        because pytest collects every test module's imports before any
        fixture runs, so a publisher's metadata would persist across
        tests that expect a clean registry.

        Idempotency contract (rvw-pre-flight): tests routinely construct
        multiple ``Supervisor`` instances per process (one per case);
        the underlying :meth:`HookRegistry.register_hookpoint` is
        already idempotent on equal metadata and strict on drift (see
        ``alfred/hooks/registry.py:660``). The shape here — pin the six
        entries to the public :data:`SYSTEM_ONLY_TIERS` /
        :data:`SYSTEM_OPERATOR_TIERS` constants so every Supervisor
        instance hands the registry the SAME frozenset objects — keeps
        the re-registration a no-op rather than a drift raise.

        Per-hookpoint trust-tier rationale:

        * ``supervisor.breaker.tripped`` — system-only emission of an
          internal state-machine transition; user-plugin subscribers
          would be a security smell (they'd see when the quarantine
          fires) and operator subscribers add nothing the audit-graph
          dashboards don't already surface. ``fail_closed=False``: a
          crashing subscriber on this event is observability noise,
          not a security regression — the breaker transition itself
          is persisted to Postgres irrespective of the hook chain.
        * ``supervisor.breaker.reset`` — operator-triggered command
          (spec §10.8). System + operator tiers may subscribe (operator
          for CLI confirmation flow, system for audit forwarding);
          user-plugin locked out. ``fail_closed=False`` for the same
          reason as ``.tripped``.
        * ``supervisor.action_timeout`` — system-only emission from the
          orchestrator's ``DeadlineWrapper`` arm (core-003). Same
          posture as ``.tripped``.
        * ``plugin.lifecycle.{loaded,crashed,quarantined}`` — three
          system-only emissions covering the spec §10.3 lifecycle.
          ``fail_closed=False`` consistent with the rest of the
          supervisor's observability-shaped hookpoints.
        """
        from alfred.hooks import SYSTEM_ONLY_TIERS, SYSTEM_OPERATOR_TIERS, get_registry

        registry = get_registry()
        hookpoints: tuple[tuple[str, frozenset[str], frozenset[str], bool], ...] = (
            ("supervisor.breaker.tripped", SYSTEM_ONLY_TIERS, frozenset(), False),
            ("supervisor.breaker.reset", SYSTEM_OPERATOR_TIERS, frozenset(), False),
            ("supervisor.action_timeout", SYSTEM_ONLY_TIERS, frozenset(), False),
            ("plugin.lifecycle.loaded", SYSTEM_ONLY_TIERS, frozenset(), False),
            ("plugin.lifecycle.crashed", SYSTEM_ONLY_TIERS, frozenset(), False),
            ("plugin.lifecycle.quarantined", SYSTEM_ONLY_TIERS, frozenset(), False),
        )
        for name, subscribable_tiers, refusable_tiers, fail_closed in hookpoints:
            registry.register_hookpoint(
                name=name,
                subscribable_tiers=subscribable_tiers,
                refusable_tiers=refusable_tiers,
                fail_closed=fail_closed,
            )


__all__ = ["Supervisor"]
