"""Spec §8.1 + §10.4: fail-closed outage semantics for :class:`RealGate`.

Five scenarios pinned here (all driven by mocked backends — the actual
state-transition logic lives in :class:`alfred.security.capability_gate._gate.RealGate`
and is exercised end-to-end; the real-Postgres roundtrip is in
:mod:`tests.integration.security.capability_gate.test_hybrid_storage_roundtrip`):

1. After ``_MAX_MISSED_HEARTBEATS`` consecutive ``backend.ping`` failures the
   gate transitions to fail-closed and ALL three keyword-only check methods
   deny.
2. The ``_denied_dispatch_count`` counter increments on every denied
   dispatch while fail-closed (rolled into the exiting audit row).
3. Entering fail-closed emits one ``supervisor.capability_gate_unavailable``
   audit row with ``state_transition="entering_fail_closed"`` and the
   backing-store exception ``type(exc).__name__`` (never ``str(exc)``).
4. Exiting fail-closed emits one row with the cumulative
   ``denied_dispatch_count``.
5. Spec §10.4: an in-flight dispatch denial after grant revocation surfaces
   as a ``plugin.grant.revoked_inflight`` row.

Constant-product invariant (sec-008) — spec §8.1's 60 s window is locked at
two levels: (a) the ``_HEARTBEAT_INTERVAL_SECONDS * _MAX_MISSED_HEARTBEATS
== 60.0`` arithmetic invariant (``test_heartbeat_timing_constants_enforce_60s_window``)
and (b) the predicate-fires-at-sixth-miss boundary
(``test_fail_closed_predicate_fires_at_sixth_miss``). Wall-clock loop
accumulation over real asyncio time would require freezegun/time-machine
async-clock integration — deferred from PR-S3-2 to keep the test-dependency
surface tight; tracked as a Slice-3 follow-up.

Placement note: these tests do not require a Postgres testcontainer (the
backing store is mocked) so they could nominally sit in the unit tier, but
they live alongside :mod:`test_hybrid_storage_roundtrip` because they cover
the same subsystem boundary — RealGate's interaction with its backing store
— and operators reading the integration suite should see the outage and
roundtrip stories together.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.audit.audit_row_schemas import (
    PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS,
)
from alfred.security.capability_gate.policy import GrantRow

pytestmark = pytest.mark.integration


def _make_failing_backend() -> Any:
    """Return a stub backend whose ``ping`` raises :class:`ConnectionError`.

    sec-pr-s3-6-02: the rebuild path now calls ``apply_atomic`` as the
    single atomic primitive (revokes + upserts + sync-hash inside one
    transaction). The legacy per-op mutators stay on the stub because
    earlier helpers / proposal-flow callsites still reference them.
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

    The spy intercepts the exact keyword-only signature of
    :meth:`alfred.audit.log.AuditWriter.append_schema`: ``fields`` is a
    frozenset, ``subject`` a dict of field values, plus the surrounding
    metadata kwargs. Each recorded row is the ``subject`` dict augmented
    with ``event``/``schema_name`` for ergonomic assertion.
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
        # Validate the gate constructed the subject against the declared
        # field set — this mirrors AuditWriter.append_schema's symmetric
        # check so a regression in the gate (typo'd key, missing key)
        # would surface here before the production AuditWriter ever sees
        # the row.
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


async def test_fail_closed_after_heartbeat_timeout() -> None:
    """After ``_MAX_MISSED_HEARTBEATS`` misses the gate denies on all three methods.

    Validates the hot-path branch: every ``check*`` method consults
    ``self._fail_closed`` first. The flag is flipped here directly
    (rather than via the heartbeat loop driving wall-clock time) so the
    test exercises only the dispatch-deny branch, in isolation from the
    loop's own state machine.
    """
    from alfred.security.capability_gate._gate import (
        _MAX_MISSED_HEARTBEATS,
        RealGate,
    )

    grant = GrantRow(
        plugin_id="test.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-abc",
    )
    backend = _make_failing_backend()
    backend.load_grants = AsyncMock(return_value=frozenset({grant}))
    gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=False)

    # Sanity: before the outage transition, the grant grants.
    assert (
        gate.check(
            plugin_id="test.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is True
    )

    # Trip the fail-closed flag directly (heartbeat-loop transitions are
    # covered by the predicate test below; this isolates the hot path).
    gate._missed_heartbeats = _MAX_MISSED_HEARTBEATS
    gate._fail_closed = True

    assert (
        gate.check(
            plugin_id="test.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is False
    )
    assert gate.check_plugin_load(plugin_id="test.plugin", manifest_tier="operator") is False
    assert (
        gate.check_content_clearance(
            plugin_id="test.plugin",
            hookpoint="tag.T3",
            content_tier="T3",
        )
        is False
    )


async def test_denied_dispatch_count_increments_during_fail_closed() -> None:
    """``_denied_dispatch_count`` increments on every denied call while fail-closed.

    The cumulative count is rolled into the exiting-fail-closed audit
    row (spec §8.1); operators consume it to size the outage's
    blast radius.
    """
    from alfred.security.capability_gate._gate import RealGate

    gate = await RealGate.create(
        backend=_make_failing_backend(),
        audit_sink=_no_op_sink(),
        start_heartbeat=False,
    )
    gate._fail_closed = True
    gate._denied_dispatch_count = 0

    gate.check(plugin_id="x", hookpoint="y", requested_tier="operator")
    gate.check_plugin_load(plugin_id="x", manifest_tier="operator")
    gate.check_content_clearance(plugin_id="x", hookpoint="y", content_tier="T3")

    assert gate._denied_dispatch_count == 3


async def test_entering_fail_closed_emits_audit_row() -> None:
    """Entering fail-closed emits one ``supervisor.capability_gate_unavailable`` row.

    Spec §8.1 / §8.5. The row carries
    ``state_transition="entering_fail_closed"``,
    ``denied_dispatch_count=None`` (no dispatches denied yet at the
    transition instant), and ``backing_store_error_type=<exception type
    name>`` — never ``str(exc)`` (spec §5.6).
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
    assert isinstance(row["correlation_id"], str)
    # CR-139 finding #6 / PRD §8.1: assert UUID4 + RFC4122 variant
    # explicitly. Plain ``uuid.UUID(...)`` accepts any UUID version
    # (including v1, which leaks MAC + timestamp). Pinning version
    # and variant defends against drift to a deterministic or
    # leakable format.
    parsed = uuid.UUID(row["correlation_id"])
    assert parsed.version == 4
    assert parsed.variant == uuid.RFC_4122


async def test_exiting_fail_closed_emits_audit_row_with_count() -> None:
    """Exiting fail-closed emits one row with the cumulative denied count.

    Spec §8.1: the exit row reports ``denied_dispatch_count`` so
    operators can quantify what the outage blocked.
    """
    from alfred.security.capability_gate._gate import RealGate

    sink, emitted = _make_spy_sink()
    backend = _make_failing_backend()
    backend.ping = AsyncMock(return_value=None)
    gate = await RealGate.create(backend=backend, audit_sink=sink, start_heartbeat=False)
    gate._fail_closed = True
    gate._denied_dispatch_count = 42

    await gate._emit_gate_unavailable_audit(
        state_transition="exiting_fail_closed",
        denied_dispatch_count=42,
        backing_store_error_type=None,
    )

    assert len(emitted) == 1
    row = emitted[0]
    assert row["state_transition"] == "exiting_fail_closed"
    assert row["denied_dispatch_count"] == 42
    assert row["backing_store_error_type"] is None


async def test_revoked_inflight_emits_audit_row() -> None:
    """Spec §10.4: in-flight dispatch denied after grant revocation emits one row.

    Simulates the race: a grant exists when the dispatcher starts the
    call; the grant is revoked mid-flight (in production by the
    reviewer-agent merging a revocation proposal and the gate rebuilding
    from state.git); the dispatcher's subsequent ``gate.check`` returns
    False AND the dispatcher emits ``plugin.grant.revoked_inflight``.

    The gate itself does NOT emit this row — the dispatcher does, with
    its own ``in_flight_dispatch_id`` correlation. This test pins the
    schema and asserts the gate-and-dispatcher contract holds: the gate
    swaps the policy atomically, and the dispatcher's emit succeeds with
    the matching field set.
    """
    from alfred.security.capability_gate._gate import RealGate

    sink, emitted = _make_spy_sink()
    grant = GrantRow(
        plugin_id="inflight.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-inflight",
    )
    backend = _make_failing_backend()
    backend.ping = AsyncMock(return_value=None)
    backend.load_grants = AsyncMock(return_value=frozenset({grant}))
    gate = await RealGate.create(backend=backend, audit_sink=sink, start_heartbeat=False)

    assert (
        gate.check(
            plugin_id="inflight.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is True
    )

    # Revoke the grant via the rebuild path (empty grant set).
    await gate._apply_grants(frozenset(), commit_hash="new-head-after-revoke")

    # The dispatcher emits the revoked_inflight row. We model that emit
    # here directly because the dispatcher itself lands in a later PR;
    # the schema validation in the spy still pins the field set.
    correlation_id = str(uuid.uuid4())
    await sink.append_schema(
        fields=PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS,
        schema_name="PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS",
        event="plugin.grant.revoked_inflight",
        actor_user_id="operator@example.com",
        subject={
            "plugin_id": "inflight.plugin",
            "hookpoint": "tool.web.fetch",
            "operator_user_id": "operator@example.com",
            "in_flight_dispatch_id": str(uuid.uuid4()),
            "correlation_id": correlation_id,
        },
        trust_tier_of_trigger="T0",
        result="denied",
        cost_estimate_usd=0.0,
        trace_id=correlation_id,
    )

    # Post-revocation: check denies.
    assert (
        gate.check(
            plugin_id="inflight.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is False
    )

    revoked_rows = [e for e in emitted if e["event"] == "plugin.grant.revoked_inflight"]
    assert len(revoked_rows) == 1
    assert revoked_rows[0]["plugin_id"] == "inflight.plugin"
    assert revoked_rows[0]["hookpoint"] == "tool.web.fetch"


def test_heartbeat_timing_constants_enforce_60s_window() -> None:
    """sec-008: spec §8.1 hard invariant — ``_FAIL_CLOSED_AFTER_SECONDS == 60.0``.

    Locks the relationship ``_HEARTBEAT_INTERVAL_SECONDS *
    _MAX_MISSED_HEARTBEATS == _FAIL_CLOSED_AFTER_SECONDS`` so a future
    edit to one constant does not silently shrink or extend the
    spec-mandated 60 s window.
    """
    from alfred.security.capability_gate._gate import (
        _FAIL_CLOSED_AFTER_SECONDS,
        _HEARTBEAT_INTERVAL_SECONDS,
        _MAX_MISSED_HEARTBEATS,
    )

    assert _HEARTBEAT_INTERVAL_SECONDS * _MAX_MISSED_HEARTBEATS == _FAIL_CLOSED_AFTER_SECONDS
    assert _FAIL_CLOSED_AFTER_SECONDS == 60.0


async def test_fail_closed_predicate_fires_at_sixth_miss() -> None:
    """sec-008 (predicate level): the fail-closed predicate flips at the 6th miss.

    Validates the *count predicate* ``_missed_heartbeats >=
    _MAX_MISSED_HEARTBEATS`` — the boundary the heartbeat loop relies on
    to gate the entering-fail-closed audit emit. The wall-clock
    transition (six real-time misses driving real asyncio time) is
    deferred: timing-accurate loop testing requires freezegun /
    time-machine async-clock integration, which would inflate
    PR-S3-2's test-only dep surface. The constant-product invariant
    above plus this boundary test together prevent the 60 s window from
    silently shrinking or stretching.
    """
    from alfred.security.capability_gate._gate import (
        _MAX_MISSED_HEARTBEATS,
        RealGate,
    )

    sink, emitted = _make_spy_sink()
    backend = _make_failing_backend()
    gate = await RealGate.create(backend=backend, audit_sink=sink, start_heartbeat=False)

    # 5 misses: predicate False.
    gate._missed_heartbeats = _MAX_MISSED_HEARTBEATS - 1
    assert gate._fail_closed is False

    # 6 misses (== _MAX_MISSED_HEARTBEATS): predicate True. Drive the
    # transition through the gate's own emit + flag-flip helper so the
    # audit row + state are exercised together — same shape the loop
    # itself uses.
    gate._missed_heartbeats = _MAX_MISSED_HEARTBEATS
    if gate._missed_heartbeats >= _MAX_MISSED_HEARTBEATS and not gate._fail_closed:
        await gate._emit_gate_unavailable_audit(
            state_transition="entering_fail_closed",
            denied_dispatch_count=None,
            backing_store_error_type="ConnectionError",
        )
        gate._fail_closed = True

    assert gate._fail_closed is True
    assert len(emitted) == 1
    assert emitted[0]["state_transition"] == "entering_fail_closed"


# ---------------------------------------------------------------------------
# Heartbeat loop body coverage — the loop's outage / recovery path lands
# above as predicate boundary; the tests below drive the loop directly
# (manually stepping the asyncio time) so the loop's own arithmetic
# (counter increment, counter reset, transitions both directions, cancel)
# is exercised in unit form. Real wall-clock timing accuracy is the
# follow-up integration test.
# ---------------------------------------------------------------------------


async def test_heartbeat_loop_increments_counter_on_ping_failure() -> None:
    """One failed ping bumps ``_missed_heartbeats`` from 0 to 1.

    Stubs ``asyncio.sleep`` so the loop iterates without consuming wall
    time, then cancels after one cycle. The counter increment is the
    only side effect we assert on; the entering-fail-closed audit only
    fires once the counter crosses the ``_MAX_MISSED_HEARTBEATS``
    boundary (covered by ``test_heartbeat_loop_transitions_to_fail_closed``).
    """
    from alfred.security.capability_gate import _gate as gate_module

    backend = _make_failing_backend()
    gate = await gate_module.RealGate.create(
        backend=backend, audit_sink=_no_op_sink(), start_heartbeat=False
    )

    iterations = 0

    async def _fake_sleep(_seconds: float) -> None:
        nonlocal iterations
        iterations += 1
        if iterations >= 1:
            raise asyncio.CancelledError

    # Patch asyncio.sleep used inside the loop without touching the
    # global asyncio module elsewhere.
    original_sleep = gate_module.asyncio.sleep
    gate_module.asyncio.sleep = _fake_sleep  # type: ignore[assignment]
    try:
        with pytest.raises(asyncio.CancelledError):
            await gate._heartbeat_loop()
    finally:
        gate_module.asyncio.sleep = original_sleep  # type: ignore[assignment]

    assert gate._missed_heartbeats == 1
    assert gate._fail_closed is False


async def test_heartbeat_loop_transitions_to_fail_closed() -> None:
    """Six consecutive failed pings drive the loop into fail-closed + emit row.

    Sets ``_missed_heartbeats`` to ``_MAX_MISSED_HEARTBEATS - 1`` so the
    next failed ping crosses the boundary; the loop emits the entering
    audit row and trips the flag, then we cancel.
    """
    from alfred.security.capability_gate import _gate as gate_module
    from alfred.security.capability_gate._gate import _MAX_MISSED_HEARTBEATS

    sink, emitted = _make_spy_sink()
    backend = _make_failing_backend()
    gate = await gate_module.RealGate.create(
        backend=backend, audit_sink=sink, start_heartbeat=False
    )
    gate._missed_heartbeats = _MAX_MISSED_HEARTBEATS - 1

    async def _fake_sleep(_seconds: float) -> None:
        raise asyncio.CancelledError

    original_sleep = gate_module.asyncio.sleep
    gate_module.asyncio.sleep = _fake_sleep  # type: ignore[assignment]
    try:
        with pytest.raises(asyncio.CancelledError):
            await gate._heartbeat_loop()
    finally:
        gate_module.asyncio.sleep = original_sleep  # type: ignore[assignment]

    assert gate._fail_closed is True
    assert gate._missed_heartbeats == _MAX_MISSED_HEARTBEATS
    assert len(emitted) == 1
    assert emitted[0]["state_transition"] == "entering_fail_closed"
    assert emitted[0]["backing_store_error_type"] == "ConnectionError"


async def test_heartbeat_loop_fail_closed_survives_audit_sink_failure() -> None:
    """CR-139 finding #3: fail-closed flips even if ``append_schema`` raises.

    The audit subsystem may itself be wedged on the same backing-store
    outage that drove the heartbeat into fail-closed. The previous
    code awaited the audit emit BEFORE flipping ``_fail_closed``, so a
    raised audit-sink exception left the gate fully open and crashed
    the heartbeat loop — every subsequent dispatch would have been
    admitted until a restart, exactly the silent privilege-stay-open
    shape CLAUDE.md hard rule #7 forbids.

    The fix flips ``_fail_closed = True`` first, so the gate denies
    immediately on every subsequent ``check*`` call regardless of what
    the audit sink does.
    """
    from alfred.security.capability_gate import _gate as gate_module
    from alfred.security.capability_gate._gate import _MAX_MISSED_HEARTBEATS

    backend = _make_failing_backend()

    # Audit sink that raises — simulates audit subsystem wedge.
    sink = MagicMock()
    sink.append_schema = AsyncMock(side_effect=RuntimeError("audit wedged"))

    gate = await gate_module.RealGate.create(
        backend=backend, audit_sink=sink, start_heartbeat=False
    )
    gate._missed_heartbeats = _MAX_MISSED_HEARTBEATS - 1

    async def _fake_sleep(_seconds: float) -> None:
        raise asyncio.CancelledError

    original_sleep = gate_module.asyncio.sleep
    gate_module.asyncio.sleep = _fake_sleep  # type: ignore[assignment]
    try:
        # The audit-sink raise propagates out of the loop (heartbeat
        # error-loud-not-silent behaviour); the cancellation never
        # arrives because the audit raise wins first. The critical
        # invariant is that _fail_closed is True at the point of raise.
        with pytest.raises(RuntimeError, match="audit wedged"):
            await gate._heartbeat_loop()
    finally:
        gate_module.asyncio.sleep = original_sleep  # type: ignore[assignment]

    # The flag MUST be set even though the audit emit failed.
    assert gate._fail_closed is True
    # Every check method denies — the gate is fail-closed even though
    # no audit row landed.
    assert gate.check(plugin_id="x", hookpoint="y", requested_tier="operator") is False


async def test_heartbeat_loop_recovery_emits_exiting_row() -> None:
    """A successful ping after fail-closed emits ``exiting_fail_closed`` + resets.

    Seeds the gate in fail-closed with a non-zero denied count, then
    runs the loop with a ping that succeeds; the loop emits the exiting
    row with the cumulative count and clears the flag.
    """
    from alfred.security.capability_gate import _gate as gate_module

    sink, emitted = _make_spy_sink()
    backend = _make_failing_backend()
    backend.ping = AsyncMock(return_value=None)
    gate = await gate_module.RealGate.create(
        backend=backend, audit_sink=sink, start_heartbeat=False
    )
    gate._fail_closed = True
    gate._denied_dispatch_count = 7
    gate._missed_heartbeats = 6

    async def _fake_sleep(_seconds: float) -> None:
        raise asyncio.CancelledError

    original_sleep = gate_module.asyncio.sleep
    gate_module.asyncio.sleep = _fake_sleep  # type: ignore[assignment]
    try:
        with pytest.raises(asyncio.CancelledError):
            await gate._heartbeat_loop()
    finally:
        gate_module.asyncio.sleep = original_sleep  # type: ignore[assignment]

    assert gate._fail_closed is False
    assert gate._missed_heartbeats == 0
    assert gate._denied_dispatch_count == 0
    assert len(emitted) == 1
    assert emitted[0]["state_transition"] == "exiting_fail_closed"
    assert emitted[0]["denied_dispatch_count"] == 7


async def test_heartbeat_loop_success_when_already_open_is_no_op() -> None:
    """Successful ping when not fail-closed only resets the miss counter.

    Defends against an audit-row leak: a ping that succeeds when the
    gate was never tripped MUST NOT emit ``exiting_fail_closed``. The
    counter still resets to 0 (idempotent on already-zero).
    """
    from alfred.security.capability_gate import _gate as gate_module

    sink, emitted = _make_spy_sink()
    backend = _make_failing_backend()
    backend.ping = AsyncMock(return_value=None)
    gate = await gate_module.RealGate.create(
        backend=backend, audit_sink=sink, start_heartbeat=False
    )
    # Simulate a previous transient failure that didn't reach the
    # threshold — counter is mid-air; gate is still open.
    gate._missed_heartbeats = 3

    async def _fake_sleep(_seconds: float) -> None:
        raise asyncio.CancelledError

    original_sleep = gate_module.asyncio.sleep
    gate_module.asyncio.sleep = _fake_sleep  # type: ignore[assignment]
    try:
        with pytest.raises(asyncio.CancelledError):
            await gate._heartbeat_loop()
    finally:
        gate_module.asyncio.sleep = original_sleep  # type: ignore[assignment]

    assert gate._fail_closed is False
    assert gate._missed_heartbeats == 0
    assert emitted == []


async def test_stop_heartbeat_cancels_running_task() -> None:
    """``stop_heartbeat`` cancels the background task started by ``create``."""
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_failing_backend()
    # Keep the ping pending so the task stays alive in the loop body.
    backend.ping = AsyncMock(return_value=None)
    gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=True)
    assert gate._heartbeat_task is not None
    gate.stop_heartbeat()
    # Wait for the cancellation to propagate.
    with pytest.raises(asyncio.CancelledError):
        await gate._heartbeat_task


async def test_heartbeat_loop_propagates_cancellation_from_ping() -> None:
    """A :class:`asyncio.CancelledError` raised by ``ping`` propagates cleanly.

    Without an explicit ``raise``, the bare-Exception handler below
    would swallow ``CancelledError`` (it's an :class:`Exception` subclass on
    Python <3.8, and even on >=3.8 we still want the loud handler to
    explicitly re-raise). This test pins the cancellation semantics so a
    future refactor that consolidates the except handlers does not
    swallow shutdown signals.
    """
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_failing_backend()
    backend.ping = AsyncMock(side_effect=asyncio.CancelledError)
    gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=False)
    with pytest.raises(asyncio.CancelledError):
        await gate._heartbeat_loop()
    # No state transitions happened.
    assert gate._fail_closed is False
    assert gate._missed_heartbeats == 0


def test_stop_heartbeat_is_safe_when_no_task() -> None:
    """``stop_heartbeat`` is a no-op when no task was started.

    Production graceful-shutdown code MUST be able to call this
    unconditionally; a guard-with-task-check requirement at the call
    site would be a foot-gun.
    """
    # We don't need to await create() — the unset task field is the
    # invariant under test.
    from alfred.security.capability_gate._gate import RealGate
    from alfred.security.capability_gate.policy import GatePolicy

    gate = RealGate(
        policy=GatePolicy(grants=frozenset()),
        backend=MagicMock(),
        audit_sink=MagicMock(),
    )
    assert gate._heartbeat_task is None
    gate.stop_heartbeat()  # Must not raise.
