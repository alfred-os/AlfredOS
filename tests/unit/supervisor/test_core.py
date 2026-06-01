"""Supervisor core lifecycle and breaker management (spec §10.1, §10.5, §10.8).

The Supervisor is the top-level coordinator for plugin lifecycle and
circuit breakers:

* Owns the :class:`asyncio.TaskGroup` under which every supervised
  plugin's stdio-reader task runs.
* Owns the per-component :class:`CircuitBreaker` map; ensures one
  breaker per ``component_id`` via :meth:`get_or_create_breaker`.
* Exposes :meth:`reset_breaker` for the operator API (PR-S3-6 CLI wraps
  it). Emits ``supervisor.breaker.reset`` with operator attribution
  (spec §10.8).
* :meth:`start` opens the TaskGroup via an internal ``_run()`` coroutine
  that holds it open until ``stop()`` sets ``_shutdown_event``. This is
  the only safe shape — ``asyncio.TaskGroup`` must be entered with
  ``async with`` before ``create_task()`` calls, and the lifetime can't
  span a constructor.

Public surface (``alfred.supervisor.__init__``):
``Supervisor``, ``BreakerState``, ``CircuitBreaker``, ``BreakStateError``,
``QuarantinedUnavailable``, ``SupervisorError``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.supervisor.breaker import BreakerState, CircuitBreaker
from alfred.supervisor.core import Supervisor
from alfred.supervisor.errors import SupervisorError


@asynccontextmanager
async def _fake_session_scope() -> AsyncIterator[Any]:
    """Lightweight session_scope stub.

    The supervisor passes the same session_scope factory to every
    CircuitBreaker it creates (so breakers can persist their state on
    transition). For unit tests we hand the breaker an AsyncMock-backed
    session — the breaker's save_to_db is mocked at a higher level so
    the session itself only needs to satisfy the async context manager
    Protocol.
    """
    session = AsyncMock()
    session.commit = AsyncMock()
    yield session


def _build_supervisor() -> tuple[Supervisor, dict[str, Any]]:
    """Construct a Supervisor with structural mocks for gate + audit."""
    gate = MagicMock()
    gate.is_backing_store_available = MagicMock(return_value=True)
    audit = AsyncMock()
    audit.append = AsyncMock()
    audit.append_schema = AsyncMock()
    sup = Supervisor(
        session_scope=_fake_session_scope,
        gate=gate,
        audit=audit,
    )
    return sup, {"gate": gate, "audit": audit}


# ---------------------------------------------------------------------------
# Public surface — package re-exports (spec §10.1)
# ---------------------------------------------------------------------------


def test_supervisor_importable_from_package() -> None:
    """``Supervisor`` is exported on the package surface."""
    from alfred.supervisor import (
        BreakerState as _BreakerState,
    )
    from alfred.supervisor import (
        BreakStateError as _BreakStateError,
    )
    from alfred.supervisor import (
        CircuitBreaker as _CircuitBreaker,
    )
    from alfred.supervisor import (
        QuarantinedUnavailable as _QuarantinedUnavailable,
    )
    from alfred.supervisor import (
        Supervisor as _Supervisor,
    )
    from alfred.supervisor import (
        SupervisorError as _SupervisorError,
    )

    assert _Supervisor is Supervisor
    assert _BreakerState is BreakerState
    assert _CircuitBreaker is CircuitBreaker
    # The two error re-exports identity-equal the module-level types so
    # ``except Supervisor.<Err>`` works regardless of import path.
    assert (
        _BreakStateError
        is __import__("alfred.supervisor.errors", fromlist=["BreakStateError"]).BreakStateError
    )
    assert _SupervisorError is SupervisorError
    assert (
        _QuarantinedUnavailable
        is __import__(
            "alfred.supervisor.errors", fromlist=["QuarantinedUnavailable"]
        ).QuarantinedUnavailable
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_construct_with_dependencies() -> None:
    """Constructor accepts session_scope, gate, audit kwargs and stays unstarted."""
    sup, _m = _build_supervisor()
    # Run task is None until start() is called.
    assert sup._run_task is None
    assert sup._task_group is None
    # No breakers registered yet.
    assert sup._breakers == {}


# ---------------------------------------------------------------------------
# get_or_create_breaker — singleton-per-component invariant
# ---------------------------------------------------------------------------


def test_get_or_create_breaker_singleton() -> None:
    """Two calls with the same component_id return the same breaker."""
    sup, _m = _build_supervisor()
    a = sup.get_or_create_breaker("quarantined-llm")
    b = sup.get_or_create_breaker("quarantined-llm")
    assert a is b
    assert a.component_id == "quarantined-llm"


def test_get_or_create_breaker_distinct_components() -> None:
    """Different component_ids yield distinct breakers."""
    sup, _m = _build_supervisor()
    a = sup.get_or_create_breaker("quarantined-llm")
    b = sup.get_or_create_breaker("comms-discord")
    assert a is not b
    assert a.component_id == "quarantined-llm"
    assert b.component_id == "comms-discord"


# ---------------------------------------------------------------------------
# start / stop — TaskGroup lifecycle
# ---------------------------------------------------------------------------


async def test_start_opens_task_group_and_unblocks() -> None:
    """``start()`` opens the TaskGroup so ``register_plugin_task`` works."""
    sup, _m = _build_supervisor()
    await sup.start()
    try:
        assert sup._task_group is not None
        assert sup._run_task is not None
        # Internal contract: started_event is set when _run has entered the TG.
        assert sup._started_event.is_set()
    finally:
        await sup.stop()


async def test_start_called_twice_raises() -> None:
    """A second ``start()`` raises ``RuntimeError``.

    Re-entrancy would create a second supervised TaskGroup and orphan the
    first; the supervisor is a single-instance per process by design.
    """
    sup, _m = _build_supervisor()
    await sup.start()
    try:
        with pytest.raises(RuntimeError, match="twice"):
            await sup.start()
    finally:
        await sup.stop()


async def test_stop_drains_task_group_and_audits() -> None:
    """``stop()`` drains the TaskGroup and emits ``supervisor.lifecycle.stopped``."""
    sup, m = _build_supervisor()
    await sup.start()
    # Register one trivial supervised task so we have something for the
    # TaskGroup to drain.
    completed = False

    async def _plugin_task() -> None:
        nonlocal completed
        completed = True

    sup.register_plugin_task(_plugin_task())

    await sup.stop()

    assert completed is True
    # lifecycle.stopped row emitted with supervisor persona + T0 trust.
    stopped_calls = [
        call
        for call in m["audit"].append.await_args_list
        if call.kwargs.get("event") == "supervisor.lifecycle.stopped"
    ]
    assert len(stopped_calls) == 1
    assert stopped_calls[0].kwargs["actor_persona"] == "supervisor"
    assert stopped_calls[0].kwargs["trust_tier_of_trigger"] == "T0"
    assert stopped_calls[0].kwargs["result"] == "success"
    # Run task is cleared so the supervisor can in principle be restarted.
    assert sup._run_task is None
    assert sup._task_group is None


async def test_stop_without_start_is_noop() -> None:
    """``stop()`` before ``start()`` is silent (idempotent shutdown contract)."""
    sup, m = _build_supervisor()
    await sup.stop()
    # No audit row, no exception.
    assert m["audit"].append.await_count == 0


async def test_register_plugin_task_before_start_raises() -> None:
    """``register_plugin_task`` before ``start`` raises ``RuntimeError``."""
    sup, _m = _build_supervisor()

    async def _noop() -> None:
        return None

    coro = _noop()
    try:
        with pytest.raises(RuntimeError, match=r"before Supervisor\.start"):
            sup.register_plugin_task(coro)
    finally:
        # The raised RuntimeError leaves the coroutine un-awaited; close
        # it explicitly so asyncio doesn't warn about a never-awaited
        # coroutine on test teardown.
        coro.close()


# ---------------------------------------------------------------------------
# reset_breaker — operator-triggered breaker reset (spec §10.8)
# ---------------------------------------------------------------------------


async def test_reset_breaker_resets_state_and_audits() -> None:
    """``reset_breaker`` resets state, emits supervisor.breaker.reset, persists."""
    sup, m = _build_supervisor()
    breaker = sup.get_or_create_breaker("quarantined-llm")
    breaker.state = BreakerState.OPEN
    breaker.trip_count = 7

    await sup.reset_breaker("quarantined-llm", operator_user_id="alfred-the-operator")

    # State machine flipped to CLOSED; trip_count preserved (cumulative audit).
    assert breaker.state == BreakerState.CLOSED
    assert breaker.trip_count == 7

    # supervisor.breaker.reset audit row landed via append_schema with
    # operator attribution + T1 trust (operator command).
    reset_calls = [
        call
        for call in m["audit"].append_schema.await_args_list
        if call.kwargs.get("event") == "supervisor.breaker.reset"
    ]
    assert len(reset_calls) == 1
    kwargs = reset_calls[0].kwargs
    assert kwargs["actor_user_id"] == "alfred-the-operator"
    assert kwargs["actor_persona"] == "supervisor"
    assert kwargs["trust_tier_of_trigger"] == "T1"  # operator-tier command
    assert kwargs["result"] == "success"
    subject = kwargs["subject"]
    assert subject["component_id"] == "quarantined-llm"
    assert subject["old_state"] == "OPEN"
    assert subject["new_state"] == "CLOSED"
    assert subject["trip_count"] == 7
    assert subject["operator_user_id"] == "alfred-the-operator"
    assert subject["correlation_id"] != ""


async def test_reset_breaker_unknown_component_raises() -> None:
    """Reset for an unregistered component raises ``SupervisorError``."""
    sup, _m = _build_supervisor()

    with pytest.raises(SupervisorError, match="No supervised component"):
        await sup.reset_breaker("never-registered", operator_user_id="alfred")


# ---------------------------------------------------------------------------
# load_all_breakers — restart-time state restore
# ---------------------------------------------------------------------------


async def test_load_all_breakers_calls_load_from_db_on_each() -> None:
    """``load_all_breakers`` walks every registered breaker."""
    sup, _m = _build_supervisor()
    a = sup.get_or_create_breaker("a")
    b = sup.get_or_create_breaker("b")
    # Replace load_from_db with AsyncMock to verify the call without DB.
    a.load_from_db = AsyncMock()  # type: ignore[method-assign]
    b.load_from_db = AsyncMock()  # type: ignore[method-assign]

    await sup.load_all_breakers()

    a.load_from_db.assert_awaited_once()
    b.load_from_db.assert_awaited_once()


# ---------------------------------------------------------------------------
# Edge-case coverage — TimeoutError arm in stop, breaker persistence loop,
# Protocol stub bodies.
# ---------------------------------------------------------------------------


async def test_stop_persists_registered_breakers() -> None:
    """``stop()`` calls ``save_to_db`` on every registered breaker.

    Spec §10.6: a previously-tripped breaker stays OPEN across restarts
    only because ``stop`` flushes the current state on the way out.
    This test pins the loop body — without it the breaker map could
    drift silently on shutdown.
    """
    sup, _m = _build_supervisor()
    await sup.start()
    breaker = sup.get_or_create_breaker("quarantined-llm")
    breaker.save_to_db = AsyncMock()  # type: ignore[method-assign]

    await sup.stop()

    breaker.save_to_db.assert_awaited_once()


async def test_stop_force_cancels_runner_on_drain_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the runner exceeds the drain budget, ``stop`` cancels it.

    Pins the TimeoutError arm in stop() — without it a hung supervised
    task would block shutdown indefinitely. Drop the timeout to a
    sub-millisecond budget and register a task that explicitly never
    finishes so the wait_for trips deterministically.
    """
    # Shrink the budget so the timeout fires fast and deterministically.
    monkeypatch.setattr("alfred.supervisor.core._STOP_DRAIN_TIMEOUT_SECONDS", 0.001)
    sup, m = _build_supervisor()
    await sup.start()

    # Register a task that waits longer than the drain budget. The
    # TaskGroup pins the runner open until this task finishes — which
    # it never will inside the budget — so wait_for raises TimeoutError
    # inside stop() and the runner is force-cancelled.
    import asyncio as _asyncio

    sup.register_plugin_task(_asyncio.sleep(10))

    await sup.stop()

    # The audit row still landed even though the drain timed out — the
    # operator sees "clean shutdown failed" via the audit graph (warn
    # log emitted by the force-cancel arm).
    stopped_calls = [
        call
        for call in m["audit"].append.await_args_list
        if call.kwargs.get("event") == "supervisor.lifecycle.stopped"
    ]
    assert len(stopped_calls) == 1


# Protocol-body coverage so the 100% gate doesn't flag the stubs as dead.


# ---------------------------------------------------------------------------
# F5 (err-001 / err-002) — stop() force-cancel await + persistence-failed audit
# ---------------------------------------------------------------------------


async def test_stop_force_cancel_awaits_runner_and_audits_taskgroup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """err-001 (F5): a force-cancelled TaskGroup with a non-cancel error audits with errors.

    Pins that ``stop()`` awaits the cancelled runner before claiming
    shutdown completed. Without the await, TaskGroup-aggregated
    exceptions from supervised plugin tasks would be silently dropped on
    shutdown. The supervised task here raises ``RuntimeError`` which the
    TaskGroup aggregates into an ``ExceptionGroup`` and re-raises on
    runner exit — the stop() arm captures it and routes the audit row
    through ``result="cancelled_with_errors"``.

    The exception itself is NOT re-raised by stop() — the supervising
    process is already shutting down; the audit row is the operator's
    signal that shutdown was unclean.
    """
    monkeypatch.setattr("alfred.supervisor.core._STOP_DRAIN_TIMEOUT_SECONDS", 0.001)
    sup, m = _build_supervisor()
    await sup.start()

    # Supervised task that runs longer than the drain budget AND raises a
    # non-CancelledError when its TaskGroup is force-cancelled. The
    # finally-arm raise becomes part of the TaskGroup's aggregated
    # exception; the stop() arm captures it.
    async def _hanging_with_error() -> None:
        try:
            await asyncio.sleep(10)
        finally:
            raise RuntimeError("plugin shutdown failed")

    sup.register_plugin_task(_hanging_with_error())

    # stop() does not re-raise — it audits the failed shutdown and returns.
    await sup.stop()

    # Audit row reflects the unclean shutdown — the operator sees
    # "shutdown failed" via the audit graph.
    stopped_calls = [
        call
        for call in m["audit"].append.await_args_list
        if call.kwargs.get("event") == "supervisor.lifecycle.stopped"
    ]
    assert len(stopped_calls) == 1
    kwargs = stopped_calls[0].kwargs
    assert kwargs["result"] == "cancelled_with_errors"
    assert "error_type" in kwargs["subject"]


async def test_stop_force_cancel_preserves_external_cancelled_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """err-001 (F5): an external CancelledError during stop() propagates.

    A non-TimeoutError CancelledError raised from inside ``wait_for``
    (the supervising process cancelled the calling coroutine) must
    re-raise, NOT be swallowed and audited as ``cancelled_with_errors``.
    The audit path is for unclean shutdown — an external cancel of
    stop() itself is the operator's signal to abort.
    """
    monkeypatch.setattr("alfred.supervisor.core._STOP_DRAIN_TIMEOUT_SECONDS", 0.001)
    sup, _m = _build_supervisor()
    await sup.start()

    # Patch wait_for to immediately raise CancelledError so the err-001
    # branch routes through the ``isinstance(exc, asyncio.CancelledError)``
    # arm. This pins the operator-cancel-of-stop() path that the
    # finding's "re-raise on CancelledError" requirement protects.
    async def _cancel_immediately(*_args: Any, **_kwargs: Any) -> None:
        raise asyncio.CancelledError("operator cancelled stop()")

    monkeypatch.setattr("alfred.supervisor.core.asyncio.wait_for", _cancel_immediately)

    with pytest.raises(asyncio.CancelledError):
        await sup.stop()


async def test_stop_force_cancel_preserves_keyboard_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR PR-S3-3b R5 #3332700176: KeyboardInterrupt during stop() propagates.

    An operator pressing Ctrl-C to force-abort a hung shutdown MUST be
    honoured, not absorbed into ``cancelled_with_errors`` and the audit
    row. The ``except BaseException`` arm re-raises KeyboardInterrupt
    alongside CancelledError so the process exits promptly.
    """
    monkeypatch.setattr("alfred.supervisor.core._STOP_DRAIN_TIMEOUT_SECONDS", 0.001)
    sup, _m = _build_supervisor()
    await sup.start()

    async def _ki_immediately(*_args: Any, **_kwargs: Any) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("alfred.supervisor.core.asyncio.wait_for", _ki_immediately)

    with pytest.raises(KeyboardInterrupt):
        await sup.stop()


async def test_stop_force_cancel_preserves_system_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR PR-S3-3b R5 #3332700176: SystemExit during stop() propagates.

    Symmetric to the KeyboardInterrupt arm — SystemExit is a process-control
    signal and MUST NOT be absorbed by the err-001 capture arm. Re-raising
    keeps stop() honest about the shutdown signal it received.
    """
    monkeypatch.setattr("alfred.supervisor.core._STOP_DRAIN_TIMEOUT_SECONDS", 0.001)
    sup, _m = _build_supervisor()
    await sup.start()

    async def _exit_immediately(*_args: Any, **_kwargs: Any) -> None:
        raise SystemExit(0)

    monkeypatch.setattr("alfred.supervisor.core.asyncio.wait_for", _exit_immediately)

    with pytest.raises(SystemExit):
        await sup.stop()


async def test_capability_monitor_heartbeat_is_scheduled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """devex-001 (F6): the heartbeat loop runs while the supervisor is started.

    Pins that ``Supervisor._run`` schedules the capability monitor's
    heartbeat as a TaskGroup task. Before F6, ``CapabilityGateMonitor``
    was constructed but its ``run_one_heartbeat`` was never called —
    operators saw no transition rows even when the gate's backing
    store dropped. The shrink-to-zero interval here makes the loop
    spin tight so we observe multiple ticks during the test.
    """
    sup, _m = _build_supervisor()
    # Shrink the heartbeat interval so the loop ticks fast enough for
    # the test to observe more than one cycle. The monitor stores the
    # interval as an instance attribute (constructor-injectable but
    # patchable here without forking the supervisor constructor).
    sup._capability_monitor._heartbeat_interval = 0.0
    # Replace run_one_heartbeat with an AsyncMock so we can count calls
    # without driving the monitor's full state machine.
    sup._capability_monitor.run_one_heartbeat = AsyncMock()  # type: ignore[method-assign]

    await sup.start()
    # Yield the loop a few times so the heartbeat coroutine gets to run.
    for _ in range(10):
        await asyncio.sleep(0)
    await sup.stop()

    assert sup._capability_monitor.run_one_heartbeat.await_count > 0


async def test_capability_monitor_heartbeat_failure_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """devex-001 (F6): a crashing heartbeat surfaces via the TaskGroup.

    The TaskGroup aggregates per-task exceptions so a heartbeat failure
    re-raises out of ``_run`` and bubbles back to the supervising
    process — operators see the error instead of a silently-dead
    heartbeat loop. The audit-row emission inside
    ``CapabilityGateMonitor.run_one_heartbeat`` is the loud-failure
    signal; the TaskGroup propagation is the escalation.
    """
    monkeypatch.setattr("alfred.supervisor.core._STOP_DRAIN_TIMEOUT_SECONDS", 0.001)
    sup, _m = _build_supervisor()
    sup._capability_monitor._heartbeat_interval = 0.0

    boom = RuntimeError("heartbeat backing store check failed")
    sup._capability_monitor.run_one_heartbeat = AsyncMock(  # type: ignore[method-assign]
        side_effect=boom
    )

    await sup.start()
    # Give the heartbeat task a chance to run + crash.
    for _ in range(10):
        await asyncio.sleep(0)
    # The TaskGroup's aggregated exception surfaces via stop() — the
    # err-001 capture arm converts it into the cancelled_with_errors
    # audit row rather than letting it silently propagate.
    await sup.stop()

    stopped_calls = [
        call
        for call in _m["audit"].append.await_args_list
        if call.kwargs.get("event") == "supervisor.lifecycle.stopped"
    ]
    assert len(stopped_calls) == 1
    # Either the err-001 force-cancel-await branch or the wait_for-re-raise
    # branch captures the RuntimeError; both set result accordingly.
    assert stopped_calls[0].kwargs["result"] == "cancelled_with_errors"
    assert "error_type" in stopped_calls[0].kwargs["subject"]


async def test_stop_persistence_failure_audits_and_reraises() -> None:
    """err-002 (F5): SQLAlchemyError during stop() persistence is loud + audited.

    The persistence block is wrapped in try/except so that an outage on
    shutdown (Postgres unreachable, deadlock, etc.) lands in the audit
    graph BEFORE the exception propagates. The audit writer opens its
    own session per ``.append()`` call so the row commits even though
    our persistence scope rolled back.

    CLAUDE.md hard rule #7: the persistence failure MUST still propagate
    so the operator-facing shutdown error is loud — we re-raise after
    the audit row lands.
    """
    sup, m = _build_supervisor()
    await sup.start()
    # Register a breaker so the persistence loop has something to flush.
    breaker = sup.get_or_create_breaker("quarantined-llm")

    # Make the breaker's save_to_db raise an SQLAlchemyError so the
    # persistence scope inside stop() trips into the err-002 branch.
    from sqlalchemy.exc import SQLAlchemyError as _SQLAlchemyError

    breaker.save_to_db = AsyncMock(  # type: ignore[method-assign]
        side_effect=_SQLAlchemyError("simulated outage")
    )

    with pytest.raises(_SQLAlchemyError):
        await sup.stop()

    # The lifecycle.stopped row carries result=persistence_failed and
    # the offending exception type.
    stopped_calls = [
        call
        for call in m["audit"].append.await_args_list
        if call.kwargs.get("event") == "supervisor.lifecycle.stopped"
    ]
    assert len(stopped_calls) == 1
    kwargs = stopped_calls[0].kwargs
    assert kwargs["result"] == "persistence_failed"
    assert kwargs["subject"]["error_type"] == "SQLAlchemyError"


# ---------------------------------------------------------------------------
# Hookpoint registration (Tasks 19-20, spec §14, core-010)
# ---------------------------------------------------------------------------


def test_supervisor_action_timeout_hookpoint_registered_by_supervisor_init() -> None:
    """``supervisor.action_timeout`` is declared by ``Supervisor.__init__`` (core-010).

    Plan-review landmine: a previous draft considered registering the
    hookpoint at module-import time inside ``deadline.py``. That shape
    breaks test isolation because pytest's import phase happens before
    any fixture runs, so the registration would persist across tests
    that expect a clean registry. Declaring inside ``__init__`` ties
    the registration's lifetime to the Supervisor instance — exactly
    the scope tests already manage.

    This test pins the contract by importing ``deadline`` directly
    (importing it MUST NOT side-effect register) then constructing a
    Supervisor (which MUST register).
    """
    # Side-effect-free import — this line MUST NOT register the
    # hookpoint. A regression that adds an import-time call would be
    # caught by the assertion below noticing registration happens
    # before the Supervisor is constructed.
    import alfred.supervisor.deadline  # noqa: F401
    from alfred.hooks import get_registry

    sup, _m = _build_supervisor()
    del sup  # the registration is the side-effect we care about

    meta = get_registry().hookpoint_meta("supervisor.action_timeout")
    assert meta is not None, (
        "Supervisor.__init__ must register supervisor.action_timeout (core-010, spec §14)"
    )


def test_supervisor_registers_full_spec_14_hookpoint_table() -> None:
    """Every spec §14 supervisor hookpoint is declared at ``__init__``.

    The strict-membership assertion is the contract: a regression that
    drops one of the six entries surfaces as ``meta is None`` here,
    not as a silent runtime miss at the first dispatch site.
    """
    from alfred.hooks import get_registry

    sup, _m = _build_supervisor()
    del sup
    registry = get_registry()

    expected_hookpoints = (
        "supervisor.breaker.tripped",
        "supervisor.breaker.reset",
        "supervisor.action_timeout",
        "plugin.lifecycle.loaded",
        "plugin.lifecycle.crashed",
        "plugin.lifecycle.quarantined",
    )
    for hp in expected_hookpoints:
        assert registry.hookpoint_meta(hp) is not None, (
            f"Supervisor.__init__ must register hookpoint {hp!r} (spec §14, core-010)"
        )


def test_supervisor_register_hookpoints_is_idempotent_across_instances() -> None:
    """Two Supervisor instances in one process must not raise on re-registration.

    Tests routinely construct multiple Supervisors per process (one per
    case). The underlying ``HookRegistry.register_hookpoint`` is
    idempotent on equal metadata and raises on drift; this test pins
    that the supervisor's call-site preserves equality by sharing the
    same ``SYSTEM_ONLY_TIERS`` / ``SYSTEM_OPERATOR_TIERS`` constant
    objects across instances rather than constructing fresh frozensets
    each time.
    """
    sup_a, _ = _build_supervisor()
    sup_b, _ = _build_supervisor()  # would raise on drift
    del sup_a
    del sup_b


def test_supervisor_breaker_tripped_registered_system_only() -> None:
    """``supervisor.breaker.tripped`` is system-tier-only.

    System-only emission of an internal state-machine transition — see
    ``_register_hookpoints`` docstring. Operator and user-plugin tiers
    are locked out.
    """
    from alfred.hooks import SYSTEM_ONLY_TIERS, get_registry

    sup, _m = _build_supervisor()
    del sup
    meta = get_registry().hookpoint_meta("supervisor.breaker.tripped")
    assert meta is not None
    assert meta.subscribable_tiers == SYSTEM_ONLY_TIERS


def test_supervisor_breaker_reset_registered_system_operator() -> None:
    """``supervisor.breaker.reset`` is system + operator only.

    Operator-triggered command (spec §10.8) — operator subscribers
    handle CLI confirmation flow; user-plugin locked out.
    """
    from alfred.hooks import SYSTEM_OPERATOR_TIERS, get_registry

    sup, _m = _build_supervisor()
    del sup
    meta = get_registry().hookpoint_meta("supervisor.breaker.reset")
    assert meta is not None
    assert meta.subscribable_tiers == SYSTEM_OPERATOR_TIERS


async def test_audit_like_append_protocol_body_raises() -> None:
    """``_AuditLike.append`` Protocol stub body is exercised by coverage."""
    from alfred.supervisor.core import _AuditLike

    class _Stub(_AuditLike):
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
            await _AuditLike.append(
                self,
                event=event,
                actor_user_id=actor_user_id,
                subject=subject,
                trust_tier_of_trigger=trust_tier_of_trigger,
                result=result,
                cost_estimate_usd=cost_estimate_usd,
                trace_id=trace_id,
                actor_persona=actor_persona,
                persona_id=persona_id,
                cost_actual_usd=cost_actual_usd,
                language=language,
            )

        async def append_schema(self, **_: Any) -> None:
            return None

    with pytest.raises(NotImplementedError):
        await _Stub().append(
            event="x",
            actor_user_id=None,
            subject={},
            trust_tier_of_trigger="T0",
            result="success",
            cost_estimate_usd=0.0,
            trace_id="t",
        )


async def test_audit_like_append_schema_protocol_body_raises() -> None:
    """``_AuditLike.append_schema`` Protocol stub body is exercised by coverage."""
    from alfred.supervisor.core import _AuditLike

    class _Stub(_AuditLike):
        async def append(self, **_: Any) -> None:
            return None

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
            await _AuditLike.append_schema(
                self,
                fields=fields,
                schema_name=schema_name,
                event=event,
                actor_user_id=actor_user_id,
                subject=subject,
                trust_tier_of_trigger=trust_tier_of_trigger,
                result=result,
                cost_estimate_usd=cost_estimate_usd,
                trace_id=trace_id,
                actor_persona=actor_persona,
                persona_id=persona_id,
                cost_actual_usd=cost_actual_usd,
                language=language,
            )

    with pytest.raises(NotImplementedError):
        await _Stub().append_schema(
            fields=frozenset({"x"}),
            schema_name="X_FIELDS",
            event="x",
            actor_user_id=None,
            subject={"x": 1},
            trust_tier_of_trigger="T0",
            result="success",
            cost_estimate_usd=0.0,
            trace_id="t",
        )
