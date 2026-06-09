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
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, get_args

import structlog
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.audit_row_schemas import (
    STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS,
    SUPERVISOR_BREAKER_RESET_FIELDS,
    SUPERVISOR_BREAKER_TRIPPED_FIELDS,
    SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS,
)
from alfred.i18n import t
from alfred.supervisor.breaker import BreakerState, CircuitBreaker
from alfred.supervisor.capability_monitor import CapabilityGateMonitor
from alfred.supervisor.errors import NoSuchComponentError
from alfred.supervisor.plugin_lifecycle import PluginLifecycle

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from alfred.security.dlp import OutboundDlpProtocol
    from alfred.state.dispatch_registry import ProposalContext
    from alfred.supervisor.protocols import (
        OperatorResolverProtocol,
        PoliciesSnapshotRefProtocol,
    )

_log = structlog.get_logger(__name__)

# Spec §10.5 — graceful shutdown budget. After ``stop()`` sets the
# shutdown event the supervisor waits up to this many seconds for the
# TaskGroup to drain naturally. If any supervised task hangs past this
# window, the runner is cancelled outright and the shutdown row is
# emitted with the partial breaker count.
_STOP_DRAIN_TIMEOUT_SECONDS: float = 10.0

# ---------------------------------------------------------------------------
# Closed-vocab reasons for the failure-driven supervisor APIs (PR-S4-8).
# ---------------------------------------------------------------------------
#
# Both ``trip_breaker`` and ``request_plugin_restart`` are reason-checked
# façades — the Literal pins the accepted vocabulary at the type layer, and a
# runtime ``get_args`` membership check refuses an out-of-vocab string that
# slipped past a ``# type: ignore`` (defence-in-depth; a bare ``str`` reaching
# either method is a caller bug we surface loudly rather than silently audit).

# ``trip_breaker`` reasons: the new comms reason plus the Slice-3 failure-driven
# transitions. Kept exhaustive (no ``...`` placeholder) so a typo is a refusal.
TripBreakerReason = Literal[
    "comms_handler_repeated_failures",
    "plugin_lifecycle_crash",
]

# ``request_plugin_restart`` reasons — spec §8.4 / Task 43.
PluginRestartReason = Literal[
    "unknown_notification",
    "handler_repeated_failures",
    "manifest_handshake_failure",
]

_TRIP_BREAKER_REASONS: Final[frozenset[str]] = frozenset(get_args(TripBreakerReason))
_PLUGIN_RESTART_REASONS: Final[frozenset[str]] = frozenset(get_args(PluginRestartReason))

# The requester recorded on every ``SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS``
# row. The comms dispatcher is the only caller in this PR; pinned as a constant
# so the audit-graph correlator can filter restart requests by origin.
_PLUGIN_RESTART_REQUESTER: Final[str] = "AlfredPluginSession"


def _utcnow_iso() -> str:
    """Aware UTC wall-clock as an ISO-8601 string for audit-row timestamps."""
    return datetime.now(UTC).isoformat()


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
        state_git_path: Path | None = None,
        proposal_dispatch_interval_s: int = 30,
        # Slice-4 stub kwargs (#174). Both default to None so the legacy
        # 5-kwarg construction (unit tests, alfred chat bootstrap) keeps
        # passing unchanged. Real implementations:
        #   operator_session_resolver → PR-S4-5 (_resolve_operator)
        # PR-S4-4 (rev-003 closure): ``policies_ref`` is REQUIRED — no default.
        # Production refuses to run the privileged orchestrator with no policy
        # snapshot (CLAUDE.md hard rule 7). Tests pass a ``_StubPoliciesSnapshotRef``
        # (the ``tests.helpers.policies.stub_policies_ref`` fixture, or the class
        # directly in a test body). NOTE: the daemon still injects the stub ref in
        # production — the real PoliciesSnapshotRef + watcher scheduling are
        # pending #225 (PolicyWatcher ships here but is not yet scheduled).
        policies_ref: PoliciesSnapshotRefProtocol,
        operator_session_resolver: OperatorResolverProtocol | None = None,
        # arch-001 (#173 / PR-S4-2): the outbound DLP scanner threaded into
        # every ProposalContext so _record_failure can scan failure_detail
        # before it lands in the ledger. Optional default for legacy
        # callers (alfred chat bootstrap, supervisor unit tests) that never
        # schedule the dispatch loop; the daemon boot path constructs the
        # singleton and passes it. If the loop IS scheduled (state_git_path
        # set) but no scanner was supplied, _build_proposal_context raises
        # loudly rather than silently disarming the boundary.
        outbound_dlp: OutboundDlpProtocol | None = None,
    ) -> None:
        self._session_scope = session_scope
        self._gate = gate
        self._audit = audit
        self._breakers: dict[str, CircuitBreaker] = {}
        # Per-tick dedup for ``request_plugin_restart`` (Task 45). Cleared at
        # each tick boundary via :meth:`_reset_restart_dedup` so a handler-
        # failure storm within one tick emits exactly one restart-requested
        # row per ``(adapter_id, reason)``.
        self._restart_requested_this_tick: set[tuple[str, str]] = set()
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

        # ADR-0021 #171 — wiring for the side-effecting dispatch loop.
        # When ``state_git_path`` is None the loop is NOT scheduled (the
        # boot-time wiring opts in explicitly); legacy supervisor unit
        # tests that don't care about state.git continue to work
        # unchanged. Production wiring at ``alfred.cli.main`` always
        # supplies the path + reads the interval from Settings.
        self._state_git_path: Path | None = state_git_path
        self._proposal_dispatch_interval_s = proposal_dispatch_interval_s

        # Slice-4 stub deps (#174). Held but not yet dereferenced by the
        # dispatch loop in this PR — the CLI boot path passes the parse-once
        # snapshot stub + the no-op operator resolver so PR-S4-4 / PR-S4-5
        # can swap real implementations through the same kwargs without
        # re-touching __init__.
        self._policies_ref: PoliciesSnapshotRefProtocol = policies_ref
        # arch-LOW (#153): stored but intentionally NEVER read. Operator
        # attribution is resolved at the CLI boundary (the reviewer-gated
        # commands call ``resolve_operator_user_id_or_refuse`` /
        # ``_resolve_operator_session_or_refuse`` directly), so this field is
        # not live wiring — it is the PR-S4-1 stub kwarg kept so a future
        # in-supervisor consumer can dereference it without re-touching
        # ``__init__``. Do not mistake it for an active resolution path; a
        # cleanup PR may remove the kwarg. See docs/subsystems/supervisor.md.
        self._operator_session_resolver: OperatorResolverProtocol | None = operator_session_resolver
        self._outbound_dlp: OutboundDlpProtocol | None = outbound_dlp

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
            # ADR-0021 #171 — schedule the side-effecting dispatch loop
            # only when state.git is wired. Legacy supervisor unit tests
            # construct without a state.git path and skip the loop;
            # production wiring always supplies the path so the loop
            # always runs in real deployments.
            if self._state_git_path is not None:
                tg.create_task(self._proposal_dispatch_loop())
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

    def _build_proposal_context(self) -> ProposalContext:
        """Construct the per-cycle :class:`ProposalContext` with the DLP scanner.

        arch-001 (#173 / PR-S4-2): the outbound DLP scanner singleton lands
        on every ``ProposalContext`` so ``_record_failure`` can scan
        ``failure_detail`` before it reaches the ledger. The dispatch loop
        is only scheduled when ``state_git_path`` is set; reaching this
        method with no scanner wired is a boot-wiring bug, so we raise
        loudly rather than silently disarm the boundary (CLAUDE.md #4 — DLP
        cannot be disabled per-call).

        The Supervisor is captured as the ``effects`` adapter — it satisfies
        ``ProposalEffectsProtocol`` structurally (its ``reset_breaker``
        signature matches). The ``# type: ignore`` keeps the existing
        ``_AuditLike`` Protocol on the audit field — at runtime the
        production ``AuditWriter`` already satisfies the dispatcher's
        ``append_schema`` shape.
        """
        # Lazy import mirrors the dispatch-loop import discipline — the
        # legacy unit-tier Supervisor construct path never reaches here.
        from alfred.state.dispatch_registry import ProposalContext

        if self._outbound_dlp is None:
            raise RuntimeError(t("supervisor.dispatch.outbound_dlp_unwired"))
        return ProposalContext(
            audit_writer=self._audit,  # type: ignore[arg-type]
            effects=self,
            logger=_log,
            outbound_dlp=self._outbound_dlp,
        )

    async def _proposal_dispatch_loop(self) -> None:
        """Run the side-effecting state.git dispatch cycle until shutdown.

        ADR-0021 #171. Mirrors the shape of
        :meth:`_capability_heartbeat_loop` (sibling TaskGroup task; same
        shutdown discipline) but uses log+skip semantics on cycle
        failures rather than propagating-into-TaskGroup. The divergence
        is intentional and documented in ADR-0021 §Consequences (Negative):

        * The heartbeat is critical-path — a missed cycle could mean
          undetected gate config drift, so its exceptions surface
          loudly via the TaskGroup-aggregated raise.
        * The dispatch loop's work is non-critical-path — one skipped
          cycle delays a single operator action by ≤ ``interval``
          seconds. Crashing the supervisor on a transient Postgres
          outage would be worse than logging + retrying on the next
          tick. Every aborted cycle still emits an audit row
          (``state.proposal.dispatch_cycle_skipped``) — no silent skips.

        The cycle itself lives in :func:`alfred.state.dispatch_loop._proposal_dispatch_cycle`
        and handles every per-blob failure path internally; this loop
        wires the cycle to the supervisor's runtime context + scheduling
        cadence.
        """
        # Import lazily so the legacy unit-tier ``Supervisor`` construct
        # path (which does not wire ``state_git_path``) does not pull in
        # the dispatch_loop module just to skip the schedule.
        from alfred.state.dispatch_loop import _proposal_dispatch_cycle

        if self._state_git_path is None:  # pragma: no cover — schedule gates this
            return

        repo_path = self._state_git_path
        ctx = self._build_proposal_context()

        while not self._shutdown_event.is_set():
            # PR-S4-4 (core-003): deref the active policy snapshot at the TOP of
            # each iteration. A watcher swap mid-iteration is picked up on the
            # NEXT iteration (stale-snapshot-for-one-iteration invariant — see
            # alfred.policies.snapshot_ref). The interval read derives from the
            # per-iteration snapshot, NOT a cached local, so a future
            # hot-reloadable cadence knob takes effect without a restart. The
            # binding is intentionally re-read every loop and never cached
            # across the awaits below (the Component-D AST guard enforces this).
            snapshot = self._policies_ref.current()
            interval = self._dispatch_interval_for(snapshot)
            try:
                await _proposal_dispatch_cycle(
                    ctx=ctx,
                    repo_path=repo_path,
                    session_scope=self._session_scope,
                )
            except Exception as exc:
                # Cycle-level errors that escaped the dispatcher's
                # internal try/except chain — every known failure mode
                # is recorded as an audit row inside the cycle itself;
                # this arm is the belt-and-braces "the dispatcher's own
                # error discipline regressed" log. CR rework round-1
                # HIGH #6: ``exc_info=True`` preserves the traceback so
                # the operator can diagnose the dispatcher's regression
                # from the dev-log stream.
                #
                # CR-rework round-2 MAJOR T6: ALSO emit a
                # ``state.proposal.dispatch_cycle_skipped`` audit row
                # before the structlog warning so the audit graph
                # carries every aborted cycle. Without this emit, an
                # uncaught exception inside the cycle (a regression in
                # the dispatcher's exception arms) would silently drop
                # the audit signal — the ADR-0021 contract is "no
                # silent skips, every aborted cycle emits an audit row".
                # The emit is itself wrapped in a try/except so an
                # audit-writer-also-down case downgrades to the
                # structlog WARNING below (mirrors the discipline
                # inside :func:`_emit_cycle_skipped`).
                cycle_correlation_id = str(uuid.uuid4())
                # Audit-writer-also-down case downgrades to the structlog
                # WARNING below with ``exc_info=True`` — mirrors the
                # swallow-with-log discipline in
                # :func:`alfred.state.dispatch_loop._emit_cycle_skipped`.
                with suppress(Exception):
                    await self._audit.append_schema(
                        fields=STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS,
                        schema_name="STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS",
                        event="state.proposal.dispatch_cycle_skipped",
                        actor_user_id=None,
                        actor_persona="supervisor",
                        subject={
                            "skip_reason": "cycle_uncaught_exception",
                            "correlation_id": cycle_correlation_id,
                        },
                        trust_tier_of_trigger="T0",
                        result="refused",
                        cost_estimate_usd=0.0,
                        cost_actual_usd=0.0,
                        trace_id=cycle_correlation_id,
                    )
                _log.warning(
                    "supervisor.proposal_dispatch_cycle_uncaught",
                    error_type=type(exc).__name__,
                    exc_info=True,
                )
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
            except TimeoutError:
                continue

    def _dispatch_interval_for(self, snapshot: object) -> int:  # noqa: ARG002 — snapshot reserved for a future hot-reloadable cadence knob
        """Return the dispatch interval, derived from the per-iteration snapshot.

        The proposal-dispatch cadence is not yet an operator-tunable
        ``PoliciesV1`` field, so this returns the construction-time interval.
        The signature takes the per-iteration ``snapshot`` (core-003 deref) so
        a future hot-reloadable cadence knob lands as a one-line change here —
        the loop already re-derefs every iteration. ``snapshot`` is the active
        :class:`alfred.policies.snapshot_ref.PoliciesSnapshot`; typed as
        ``object`` because the supervisor holds the ref via the narrow
        ``PoliciesSnapshotRefProtocol`` whose ``current()`` returns ``object``.
        """
        return self._proposal_dispatch_interval_s

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

        **Idempotent** per ADR-0021 §Atomicity (CR rework round-1
        CRITICAL #1). The dispatcher's at-least-once guarantee depends
        on this contract: a re-invocation against a CLOSED breaker is
        a no-op for the state machine (``CircuitBreaker.reset`` resets
        the failure window + backoff counter; both are already in the
        cleared shape) and a no-op for the persisted row (the row is
        already CLOSED with the current ``trip_count``). The audit row
        still emits on the re-invocation, which is the desired
        forensic shape: the audit graph records every operator
        instruction. Side-effect emit semantics: handler runs N times
        across N dispatch-cycle replays produce N audit rows + 1
        ``circuit_breakers`` row in CLOSED.

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
            raise NoSuchComponentError(t("supervisor.no_such_component", component_id=component_id))

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

    @staticmethod
    def _drive_breaker_open(breaker: CircuitBreaker, *, reason: str) -> None:
        """Force a CLOSED/HALF_OPEN breaker to ``OPEN`` through its real API.

        The :class:`CircuitBreaker` has no public ``trip(reason)`` (arch-004):
        the only public failure-driven transition is ``record_failure``, which
        trips on the ``failure_threshold``-th call within the failure window.
        Calling it ``failure_threshold`` times in one shot satisfies the
        threshold deterministically — the breaker is ``OPEN`` afterwards.

        ``reason`` rides the breaker's ``exception_type`` slot, which is the
        T3-safe failure carrier (a closed-vocab Literal here, never
        ``str(exc)`` — spec §5.6). The caller guarantees the breaker is not
        already OPEN (``record_failure`` no-ops while OPEN).
        """
        for _ in range(breaker._failure_threshold):
            breaker.record_failure(reason)

    async def trip_breaker(
        self,
        *,
        component_id: str,
        reason: TripBreakerReason,
    ) -> None:
        """Failure-driven breaker trip — the symmetric counterpart to ``reset_breaker``.

        ``trip_breaker`` is the public, reason-checked façade the comms
        dispatcher (``AlfredPluginSession._on_post_handshake_method``) calls
        on the third handler failure inside a five-minute window. The
        :class:`CircuitBreaker` exposes ``record_failure`` (+ internal
        ``_trip``) but NO public ``trip(reason)`` (arch-004) — so this method
        drives the breaker to ``OPEN`` through the breaker's *real* API: it
        calls ``record_failure`` ``failure_threshold`` times in one shot,
        passing ``reason`` as the T3-safe ``exception_type`` carrier (a
        closed-vocab Literal, never ``str(exc)``).

        Idempotent against an already-``OPEN`` breaker: ``record_failure``
        no-ops while OPEN, so no second trip / no duplicate ``tripped`` row.
        The audit row is emitted only on a genuine CLOSED/HALF_OPEN → OPEN
        transition.

        Raises:
            ValueError: ``reason`` is not a known :data:`TripBreakerReason`.
                Defence-in-depth — a bare ``str`` reaching here past a
                ``# type: ignore`` is a caller bug surfaced loudly (CLAUDE.md
                hard rule 7), not silently audited.
        """
        if reason not in _TRIP_BREAKER_REASONS:
            raise ValueError(t("supervisor.trip_breaker.unknown_reason", reason=reason))

        breaker = self.get_or_create_breaker(component_id)
        if breaker.state == BreakerState.OPEN:
            # Already tripped — a second request is a no-op transition; no
            # duplicate audit row (the breaker did not change state).
            return

        self._drive_breaker_open(breaker, reason=reason)

        correlation_id = str(uuid.uuid4())
        await self._audit.append_schema(
            fields=SUPERVISOR_BREAKER_TRIPPED_FIELDS,
            schema_name="SUPERVISOR_BREAKER_TRIPPED_FIELDS",
            event="supervisor.breaker.tripped",
            actor_user_id=None,
            actor_persona="supervisor",
            subject={
                "component_id": component_id,
                "trip_count": breaker.trip_count,
                "last_failure_type": reason,
                "breaker_state": breaker.state.value,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="tripped",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=correlation_id,
        )

    async def request_plugin_restart(
        self,
        *,
        adapter_id: str,
        reason: PluginRestartReason,
    ) -> None:
        """Request a supervised-plugin restart — writes the audit row + marks unhealthy.

        Called by the comms dispatcher when a plugin sends an unknown
        notification method (``reason="unknown_notification"``) or repeatedly
        fails its handler. This method only *requests* the restart: it writes
        the ``SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS`` row and trips the
        adapter's breaker to ``OPEN`` (marking it unhealthy). The supervisor's
        existing restart scheduler spawns a fresh adapter on its next tick.

        Idempotent per tick (Task 45): repeat requests for the same
        ``(adapter_id, reason)`` within a single tick emit exactly one row —
        defence against a handler-failure storm spamming the audit graph. The
        per-tick dedup set is cleared at the tick boundary
        (:meth:`_reset_restart_dedup`).

        Raises:
            ValueError: ``reason`` is not a known :data:`PluginRestartReason`.
        """
        if reason not in _PLUGIN_RESTART_REASONS:
            raise ValueError(t("supervisor.request_plugin_restart.unknown_reason", reason=reason))

        dedup_key = (adapter_id, reason)
        if dedup_key in self._restart_requested_this_tick:
            # Already requested this exact restart this tick — no duplicate
            # row, no duplicate breaker churn.
            return
        self._restart_requested_this_tick.add(dedup_key)

        # Mark the adapter unhealthy so the breaker reflects the restart
        # request (a previously-CLOSED adapter trips OPEN; an already-OPEN one
        # stays OPEN). The breaker is the supervisor's "is this component
        # serving?" source of truth, so the restart scheduler sees it.
        breaker = self.get_or_create_breaker(adapter_id)
        if breaker.state != BreakerState.OPEN:
            self._drive_breaker_open(breaker, reason=reason)

        correlation_id = str(uuid.uuid4())
        await self._audit.append_schema(
            fields=SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS,
            schema_name="SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS",
            event="supervisor.plugin.restart_requested",
            actor_user_id=None,
            actor_persona="supervisor",
            subject={
                "plugin_id": adapter_id,
                "reason": reason,
                "requested_at": _utcnow_iso(),
                "requester": _PLUGIN_RESTART_REQUESTER,
            },
            trust_tier_of_trigger="T0",
            result="restart_requested",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=correlation_id,
        )

    def _reset_restart_dedup(self) -> None:
        """Clear the per-tick restart-request dedup set (Task 45).

        Called at each supervisor tick boundary so a restart request that was
        deduplicated within one tick can re-request (and re-audit) on the next
        tick — the dedup is a within-tick storm guard, not a permanent
        suppression.
        """
        self._restart_requested_this_tick.clear()

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
        from alfred.security.tiers import T0, TrustTier

        registry = get_registry()
        # PR-S4-3: every supervisor hookpoint is system-internal
        # observability (breaker state transitions, action-timeout
        # signals, plugin-lifecycle events). T0 (system-only) is the
        # correct carrier tier upper bound — none of these paths
        # carries operator or untrusted content.
        hookpoints: tuple[
            tuple[str, frozenset[str], frozenset[str], bool, type[TrustTier]], ...
        ] = (
            ("supervisor.breaker.tripped", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
            ("supervisor.breaker.reset", SYSTEM_OPERATOR_TIERS, frozenset(), False, T0),
            ("supervisor.action_timeout", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
            ("plugin.lifecycle.loaded", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
            ("plugin.lifecycle.crashed", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
            ("plugin.lifecycle.quarantined", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
            # PR-S4-6 (ADR-0015) sandbox-launcher hookpoints. All T0 —
            # system-internal posture/refusal signals carrying only
            # plugin_id + closed-vocabulary reason (no operator/untrusted
            # content). sandbox_refused is fail_closed (a subscriber-timeout
            # there must not let a refused spawn slip through); the two boot
            # posture rows are informational (fail_closed=False — boot
            # proceeds even when mlockall is unavailable or a subscriber is
            # slow).
            ("supervisor.plugin.sandbox_refused", SYSTEM_ONLY_TIERS, frozenset(), True, T0),
            # PR-S4-7: the dev/test-only stub-used row. The launcher emits this
            # (and execs unsandboxed) ONLY in development/test when no real OS
            # sandbox is available (Windows kind:full, runuser-missing dev path).
            # Registered here so a subscriber can observe — and an audit
            # consumer can never miss — that a plugin ran without OS-level
            # isolation. carrier_tier=T0 (carries only plugin_id/policy_ref/
            # host_os/environment — no operator/untrusted content; spec index
            # §3). fail_closed=True, mirroring its sandbox_refused sibling
            # verbatim (#167 per-kind override deferred — all Slice-4 supervisor
            # refusal/posture hookpoints are uniformly fail-closed).
            ("supervisor.plugin.sandbox_stub_used", SYSTEM_ONLY_TIERS, frozenset(), True, T0),
            ("supervisor.boot.mlock_unavailable", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
            ("supervisor.boot.core_dumps_disabled", SYSTEM_ONLY_TIERS, frozenset(), False, T0),
        )
        for name, subscribable_tiers, refusable_tiers, fail_closed, carrier_tier in hookpoints:
            registry.register_hookpoint(
                name=name,
                subscribable_tiers=subscribable_tiers,
                refusable_tiers=refusable_tiers,
                fail_closed=fail_closed,
                carrier_tier=carrier_tier,
            )


__all__ = ["Supervisor"]
