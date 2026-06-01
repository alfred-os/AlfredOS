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
