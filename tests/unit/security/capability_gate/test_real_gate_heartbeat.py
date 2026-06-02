"""Unit-tier coverage for :class:`RealGate` heartbeat / fail-closed paths.

CR-149 test-engineer-002 finding (PR-S3-7): the integration suite at
:mod:`tests.integration.security.capability_gate.test_fail_closed_outage`
already exercises this surface end-to-end, and the CI per-file gate
combines unit + integration data to enforce 100% line+branch coverage on
``src/alfred/security/capability_gate/_gate.py`` (CLAUDE.md hard rule
"every security boundary at 100% line+branch coverage"). Unit-only
coverage was 75% — the heartbeat loop body, ``_emit_gate_unavailable_audit``,
``stop_heartbeat``'s task-cancel branch, and the ``start_heartbeat=True``
construction lived exclusively in the integration tier.

This module closes the unit-tier gap so an unstable testcontainer
environment cannot silently drop coverage below the trust-boundary bar
without the unit run also catching it. The integration suite remains
the operator-facing narrative (outage + roundtrip stories together — see
the placement note in :mod:`test_fail_closed_outage`); the tests here
are the minimal-isolation pins covering the same code paths.

What's pinned here:

* ``RealGate.create(start_heartbeat=True)`` actually schedules an
  :class:`asyncio.Task` (line 161 — previously an unmocked unit gap).
* The heartbeat loop body's three arms — ping failure increments the
  counter; reaching ``_MAX_MISSED_HEARTBEATS`` flips ``_fail_closed``
  and emits ``entering_fail_closed``; a successful ping after fail-closed
  emits ``exiting_fail_closed`` and resets the counter / denied-count.
* ``_emit_gate_unavailable_audit`` produces a schema-shaped audit row
  with a UUID4 correlation_id (spec §5.6 / CR-139 finding #6 — no v1
  drift that would leak MAC + timestamp).
* ``stop_heartbeat`` cancels a running task and is a no-op when no task
  was started (the not-yet-started branch).

These tests use ``unittest.mock`` only — no testcontainer dependency —
so they live in the unit tier per spec §7a.2 (test placement: unit tests
must not require an out-of-process service).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


def _make_failing_backend() -> Any:
    """Stub backend whose ``ping`` raises :class:`ConnectionError`.

    Mirrors :mod:`tests.integration.security.capability_gate.test_fail_closed_outage`
    so the unit pins exercise the same wire shape the integration suite
    drives. The legacy per-op AsyncMocks stay on the stub for tests that
    bypass the gate's ``apply_atomic`` primitive.
    """
    backend = MagicMock()
    backend.ping = AsyncMock(side_effect=ConnectionError("db down"))
    backend.load_grants = AsyncMock(return_value=frozenset())
    backend.get_sync_hash = AsyncMock(return_value=None)
    backend.set_sync_hash = AsyncMock(return_value=None)
    backend.upsert_grant = AsyncMock(return_value=None)
    backend.revoke_grant = AsyncMock(return_value=None)
    backend.apply_atomic = AsyncMock(return_value=None)
    return backend


def _make_spy_sink() -> tuple[Any, list[dict[str, Any]]]:
    """Return a ``(sink, emitted_rows)`` tuple capturing every ``append_schema`` call.

    The spy validates the gate constructed the ``subject`` dict against
    the declared field set — mirrors :meth:`AuditWriter.append_schema`'s
    symmetric-strict check so a regression in the gate (typo'd key,
    missing key) surfaces at the test boundary before the production
    audit writer ever sees the row.
    """
    emitted: list[dict[str, Any]] = []

    async def _append_schema(
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        subject: dict[str, Any],
        **_unused: Any,
    ) -> None:
        if set(subject.keys()) != fields:
            msg = (
                f"capability_gate emit-site bug: subject keys "
                f"{sorted(subject.keys())!r} != declared fields "
                f"{sorted(fields)!r} for {schema_name}"
            )
            raise AssertionError(msg)
        emitted.append({"event": event, "schema_name": schema_name, **subject})

    sink = MagicMock()
    sink.append_schema = _append_schema
    return sink, emitted


def _no_op_sink() -> Any:
    """No-op audit sink for tests that don't assert on audit rows."""
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


# ---------------------------------------------------------------------------
# start_heartbeat=True construction (line 161 — previously unit-uncovered).
# ---------------------------------------------------------------------------


async def test_create_with_start_heartbeat_true_schedules_task() -> None:
    """``RealGate.create(start_heartbeat=True)`` actually starts the loop.

    Production bootstrap (see :mod:`alfred.bootstrap.gate_factory`) opts
    in to ``start_heartbeat=True`` after the gate is wired into the
    supervisor. Without a unit pin on this branch, a regression that
    drops the ``asyncio.create_task`` call would only surface in the
    integration suite — which the CI per-file gate combines with unit
    data, so an integration-environment flake could let the regression
    slip through.

    The test backend's ``ping`` succeeds so the loop body runs without
    incident; we cancel the task immediately to keep the test cheap.
    """
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_failing_backend()
    backend.ping = AsyncMock(return_value=None)
    gate = await RealGate.create(
        backend=backend,
        audit_sink=_no_op_sink(),
        start_heartbeat=True,
    )
    try:
        assert gate._heartbeat_task is not None
        assert isinstance(gate._heartbeat_task, asyncio.Task)
        assert not gate._heartbeat_task.done()
    finally:
        gate.stop_heartbeat()
        # Await cancellation to suppress the "task was destroyed but is
        # pending" warning asyncio emits at gc.
        with pytest.raises(asyncio.CancelledError):
            await gate._heartbeat_task


# ---------------------------------------------------------------------------
# Heartbeat loop body — counter increment, fail-closed transition,
# recovery, no-op success arm.
# ---------------------------------------------------------------------------


async def _drive_one_failing_iteration(gate: Any, backend: Any) -> None:
    """Drive ``gate._heartbeat_loop`` through exactly one failing ping, then cancel.

    CR-156 round-5 (3342278556): the old pattern rewired
    ``gate_module.asyncio.sleep`` process-wide so any concurrent task
    that hit ``asyncio.sleep()`` during these tests would see the fake
    and could fail nondeterministically. We instead wrap the failing
    ``backend.ping`` so it signals an :class:`asyncio.Event` after
    raising, run the heartbeat loop as its own task, await the Event
    (one ping observed), then cancel. The loop's natural cancellation
    point is the ``await asyncio.sleep`` at the bottom of the body —
    no stdlib mutation required.

    Ordering: ``backend.ping`` raises BEFORE the loop body's exception
    handler runs, but the handler's increment + (sometimes) emit are
    synchronous to the next ``await asyncio.sleep`` — cancellation
    cannot land between ``ping`` returning and ``sleep`` being awaited,
    so the assertions in the calling test see fully-applied state.
    """
    ping_seen = asyncio.Event()
    failing_ping = backend.ping

    async def _ping_then_signal() -> None:
        try:
            await failing_ping()
        finally:
            ping_seen.set()

    backend.ping = _ping_then_signal
    task = asyncio.create_task(gate._heartbeat_loop())
    try:
        await ping_seen.wait()
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


async def test_heartbeat_loop_increments_counter_on_ping_failure() -> None:
    """One failed ping bumps ``_missed_heartbeats`` from 0 to 1.

    Drives a single failing-ping iteration via
    :func:`_drive_one_failing_iteration` and cancels the loop task.
    The counter increment is the only side effect we assert on; the
    boundary-crossing entering-row emit is covered by the next test.
    """
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_failing_backend()
    gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=False)

    await _drive_one_failing_iteration(gate, backend)

    assert gate._missed_heartbeats == 1
    assert gate._fail_closed is False


async def test_heartbeat_loop_transitions_to_fail_closed() -> None:
    """Crossing ``_MAX_MISSED_HEARTBEATS`` flips fail-closed + emits the entering row.

    Seeds the gate at ``_MAX_MISSED_HEARTBEATS - 1`` so the next failed
    ping crosses the boundary; the loop emits the entering audit row,
    trips ``_fail_closed``, and we cancel.

    CR-139 finding #3 invariant: the flag flips BEFORE awaiting the audit
    emit, so an audit-sink wedge cannot leave the gate fully open. That
    ordering is pinned by ``test_heartbeat_loop_fail_closed_survives_audit_sink_failure``
    in the integration suite; this test only asserts the happy-path flip
    + audit-row emit.
    """
    from alfred.security.capability_gate._gate import _MAX_MISSED_HEARTBEATS, RealGate

    sink, emitted = _make_spy_sink()
    backend = _make_failing_backend()
    gate = await RealGate.create(backend=backend, audit_sink=sink, start_heartbeat=False)
    gate._missed_heartbeats = _MAX_MISSED_HEARTBEATS - 1

    await _drive_one_failing_iteration(gate, backend)

    assert gate._fail_closed is True
    assert gate._missed_heartbeats == _MAX_MISSED_HEARTBEATS
    assert len(emitted) == 1
    assert emitted[0]["state_transition"] == "entering_fail_closed"
    assert emitted[0]["backing_store_error_type"] == "ConnectionError"
    # spec §5.6: never persist ``str(exc)`` / ``exc.args`` — only the
    # type name. The spy schema check above already verifies the field
    # set is correct; this assertion locks the value shape.
    assert emitted[0]["denied_dispatch_count"] is None


async def _drive_one_succeeding_iteration(gate: Any, backend: Any) -> None:
    """Drive ``gate._heartbeat_loop`` through exactly one successful ping, then cancel.

    Twin of :func:`_drive_one_failing_iteration` for tests that need the
    success arm of the loop body (counter reset + optional exit-row
    emit) without the failure arm. Wraps ``backend.ping`` so it signals
    an :class:`asyncio.Event` after returning normally — the loop body's
    success arm runs to completion (synchronous through to the next
    ``await asyncio.sleep``) before cancellation can land, so the
    calling test sees fully-applied state.
    """
    ping_seen = asyncio.Event()
    succeeding_ping = backend.ping

    async def _ping_then_signal() -> None:
        try:
            await succeeding_ping()
        finally:
            ping_seen.set()

    backend.ping = _ping_then_signal
    task = asyncio.create_task(gate._heartbeat_loop())
    try:
        await ping_seen.wait()
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


async def test_heartbeat_loop_recovery_emits_exiting_row() -> None:
    """A successful ping after fail-closed emits ``exiting_fail_closed`` + resets state.

    Seeds the gate in fail-closed with a non-zero denied count, then
    runs the loop with a ping that succeeds; the loop emits the exiting
    row with the cumulative count and clears both the flag and the
    counters.
    """
    from alfred.security.capability_gate._gate import RealGate

    sink, emitted = _make_spy_sink()
    backend = _make_failing_backend()
    backend.ping = AsyncMock(return_value=None)
    gate = await RealGate.create(backend=backend, audit_sink=sink, start_heartbeat=False)
    gate._fail_closed = True
    gate._denied_dispatch_count = 7
    gate._missed_heartbeats = 6

    await _drive_one_succeeding_iteration(gate, backend)

    assert gate._fail_closed is False
    assert gate._missed_heartbeats == 0
    assert gate._denied_dispatch_count == 0
    assert len(emitted) == 1
    assert emitted[0]["state_transition"] == "exiting_fail_closed"
    assert emitted[0]["denied_dispatch_count"] == 7
    assert emitted[0]["backing_store_error_type"] is None


async def test_heartbeat_loop_success_when_already_open_is_no_op() -> None:
    """Successful ping when not fail-closed only resets the miss counter.

    Defends against an audit-row leak: a ping that succeeds when the
    gate was never tripped MUST NOT emit ``exiting_fail_closed``. The
    counter still resets to 0 (idempotent on already-zero).
    """
    from alfred.security.capability_gate._gate import RealGate

    sink, emitted = _make_spy_sink()
    backend = _make_failing_backend()
    backend.ping = AsyncMock(return_value=None)
    gate = await RealGate.create(backend=backend, audit_sink=sink, start_heartbeat=False)
    # Simulate a previous transient failure that didn't reach the
    # threshold — counter is mid-air; gate is still open.
    gate._missed_heartbeats = 3

    await _drive_one_succeeding_iteration(gate, backend)

    assert gate._fail_closed is False
    assert gate._missed_heartbeats == 0
    assert emitted == []


async def test_heartbeat_loop_propagates_cancellation_from_ping() -> None:
    """A :class:`asyncio.CancelledError` raised by ``ping`` propagates cleanly.

    The loop body has an explicit ``except asyncio.CancelledError: raise``
    arm so the bare-Exception fallback never swallows shutdown signals.
    This test pins that contract — without it, a future refactor that
    consolidates the except handlers could silently swallow cancellation.
    """
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_failing_backend()
    backend.ping = AsyncMock(side_effect=asyncio.CancelledError)
    gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=False)

    with pytest.raises(asyncio.CancelledError):
        await gate._heartbeat_loop()

    # The counter is untouched because the cancellation arm runs before
    # the failure-arm increment.
    assert gate._missed_heartbeats == 0
    assert gate._fail_closed is False


# ---------------------------------------------------------------------------
# _emit_gate_unavailable_audit shape — schema-symmetric + UUID4 correlation_id.
# ---------------------------------------------------------------------------


async def test_emit_gate_unavailable_audit_entering_shape() -> None:
    """Entering-fail-closed emit produces one schema-shaped row.

    The spy in :func:`_make_spy_sink` asserts symmetric-strict subject
    keys, so this test only needs to verify the value shape:
    ``state_transition``, ``denied_dispatch_count=None``, the
    ``backing_store_error_type`` string, and a UUID4 correlation_id.
    """
    from alfred.security.capability_gate._gate import RealGate

    sink, emitted = _make_spy_sink()
    gate = await RealGate.create(
        backend=_make_failing_backend(),
        audit_sink=sink,
        start_heartbeat=False,
    )

    await gate._emit_gate_unavailable_audit(
        state_transition="entering_fail_closed",
        denied_dispatch_count=None,
        backing_store_error_type="ConnectionError",
    )

    assert len(emitted) == 1
    row = emitted[0]
    assert row["event"] == "supervisor.capability_gate_unavailable"
    assert row["state_transition"] == "entering_fail_closed"
    assert row["denied_dispatch_count"] is None
    assert row["backing_store_error_type"] == "ConnectionError"
    # CR-139 finding #6 / spec §8.1: UUID4 + RFC4122 variant explicitly.
    # ``uuid.UUID(s)`` accepts any version including v1 (which leaks
    # MAC + timestamp); pinning version and variant defends against
    # drift to a leakable / deterministic format.
    parsed = uuid.UUID(row["correlation_id"])
    assert parsed.version == 4
    assert parsed.variant == uuid.RFC_4122


async def test_emit_gate_unavailable_audit_exiting_shape() -> None:
    """Exiting-fail-closed emit carries the cumulative ``denied_dispatch_count``.

    Spec §8.1: operators consume the exit row's count to quantify what
    the outage blocked. ``backing_store_error_type`` is ``None`` on the
    exit (recovery is not an error).
    """
    from alfred.security.capability_gate._gate import RealGate

    sink, emitted = _make_spy_sink()
    gate = await RealGate.create(
        backend=_make_failing_backend(),
        audit_sink=sink,
        start_heartbeat=False,
    )

    await gate._emit_gate_unavailable_audit(
        state_transition="exiting_fail_closed",
        denied_dispatch_count=99,
        backing_store_error_type=None,
    )

    assert len(emitted) == 1
    row = emitted[0]
    assert row["state_transition"] == "exiting_fail_closed"
    assert row["denied_dispatch_count"] == 99
    assert row["backing_store_error_type"] is None


# ---------------------------------------------------------------------------
# stop_heartbeat — both the running-task arm and the no-task no-op arm.
# ---------------------------------------------------------------------------


async def test_stop_heartbeat_cancels_running_task() -> None:
    """``stop_heartbeat`` cancels the background task started by ``create``.

    Exercises the ``if task is not None and not task.done(): task.cancel()``
    branch in :meth:`RealGate.stop_heartbeat` — the production graceful-
    shutdown path.
    """
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_failing_backend()
    backend.ping = AsyncMock(return_value=None)
    gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=True)
    assert gate._heartbeat_task is not None

    gate.stop_heartbeat()

    with pytest.raises(asyncio.CancelledError):
        await gate._heartbeat_task


async def test_stop_heartbeat_is_no_op_when_task_never_started() -> None:
    """``stop_heartbeat`` is safe when ``start_heartbeat=False`` was used.

    Production tests / dev bootstrap construct the gate with
    ``start_heartbeat=False``. A ``stop_heartbeat`` call on shutdown
    MUST NOT raise even though no task was ever scheduled — the docstring
    pins this as a documented contract. Exercises the ``task is None``
    branch.
    """
    from alfred.security.capability_gate._gate import RealGate

    gate = await RealGate.create(
        backend=_make_failing_backend(),
        audit_sink=_no_op_sink(),
        start_heartbeat=False,
    )
    assert gate._heartbeat_task is None

    # Must not raise.
    gate.stop_heartbeat()

    assert gate._heartbeat_task is None
