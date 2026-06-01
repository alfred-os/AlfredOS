"""Supervisor-side capability-gate fail-closed integration (spec §10.4, §8.1).

The supervisor wraps :class:`alfred.security.capability_gate.RealGate` with
a polling :class:`CapabilityGateMonitor` that:

* Probes ``gate.is_backing_store_available()`` every heartbeat.
* Emits ``supervisor.capability_gate_unavailable`` audit rows on
  state-transition (entering fail-closed AND exiting fail-closed) —
  per-dispatch denial rows live in :class:`RealGate` itself (rate-limited
  at 1/sec/plugin_id; spec §8.1).
* Surfaces a ``denied_dispatch_count`` rollup on the exiting row so the
  audit graph can answer "how many dispatches did we deny during this
  outage" without joining every per-dispatch row.
* Threads a per-outage ``correlation_id`` (err-014) so the entering and
  exiting rows of the same outage share a join key.

Distinct from PR-S3-2's gate-internal test (
``tests/unit/security/capability_gate/test_fail_closed_outage.py``):
that test pins the gate's internal heartbeat. This test pins the
supervisor's outer poll loop that wraps the gate — supervisor-level
contract, gate behaviour mocked.

60-second window note (spec §8.1): the 60s in-process-subscriber grace
window is enforced inside RealGate; the supervisor monitor's job is to
surface the state transition the moment the gate reports unavailable,
so the operator sees the outage immediately rather than 60s later.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.audit.audit_row_schemas import SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS
from alfred.supervisor.capability_monitor import CapabilityGateMonitor


@pytest.fixture
def mock_gate() -> MagicMock:
    """Gate stub exposing only the surface CapabilityGateMonitor reads.

    The monitor's structural Protocol requires one method —
    ``is_backing_store_available() -> bool``. Tests flip the return value
    between calls to drive the state machine through entering / exiting
    fail-closed without booting a real RealGate + Postgres backend.
    """
    gate = MagicMock()
    gate.is_backing_store_available = MagicMock(return_value=True)
    return gate


@pytest.fixture
def audit() -> AsyncMock:
    """Audit writer stub — ``append_schema`` is the only method called.

    The capability monitor uses ``append_schema`` (not bare ``append``) so
    the typed field-set guard catches drift between
    :data:`SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS` and the emit
    site. AsyncMock makes the awaitable signature trivial.
    """
    writer = AsyncMock()
    writer.append_schema = AsyncMock()
    return writer


async def test_gate_unavailable_emits_entering_fail_closed(
    mock_gate: MagicMock, audit: AsyncMock
) -> None:
    """The first heartbeat that sees ``available=False`` emits the entering row."""
    mock_gate.is_backing_store_available.return_value = False
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)
    await monitor.run_one_heartbeat()

    audit.append_schema.assert_awaited()
    events = [call.kwargs["event"] for call in audit.append_schema.await_args_list]
    assert "supervisor.capability_gate_unavailable" in events
    entering = next(
        call
        for call in audit.append_schema.await_args_list
        if call.kwargs["event"] == "supervisor.capability_gate_unavailable"
    )
    assert entering.kwargs["subject"]["state_transition"] == "entering_fail_closed"
    assert entering.kwargs["subject"]["denied_dispatch_count"] == 0
    assert entering.kwargs["subject"]["backing_store_error_type"] == "unavailable"
    # Schema constant identity — symmetric-validation guard surfaces typos.
    assert entering.kwargs["fields"] is SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS
    assert entering.kwargs["schema_name"] == "SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS"


async def test_gate_recovery_emits_exiting_fail_closed(
    mock_gate: MagicMock, audit: AsyncMock
) -> None:
    """Recovery from ``available=False`` → ``True`` emits the exiting row.

    Two emits total — entering AND exiting — driven by two heartbeats. The
    monitor MUST NOT emit on every heartbeat — only on transitions.
    """
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)
    # First: unavailable
    mock_gate.is_backing_store_available.return_value = False
    await monitor.run_one_heartbeat()
    # Then: recover
    mock_gate.is_backing_store_available.return_value = True
    await monitor.run_one_heartbeat()

    transitions = [
        call.kwargs["subject"]["state_transition"]
        for call in audit.append_schema.await_args_list
        if call.kwargs["event"] == "supervisor.capability_gate_unavailable"
    ]
    assert transitions == ["entering_fail_closed", "exiting_fail_closed"]


async def test_no_emission_when_gate_stays_available(
    mock_gate: MagicMock, audit: AsyncMock
) -> None:
    """A healthy steady state emits nothing — emits are transition-only."""
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)
    mock_gate.is_backing_store_available.return_value = True

    for _ in range(5):
        await monitor.run_one_heartbeat()

    audit.append_schema.assert_not_awaited()


async def test_no_double_emission_when_gate_stays_unavailable(
    mock_gate: MagicMock, audit: AsyncMock
) -> None:
    """Sustained unavailability emits one entering row only — not one per beat.

    A 60s outage running a 5s heartbeat would otherwise produce 12 entering
    rows. The transition discipline keeps the audit log a join key, not a
    duplicated event stream.
    """
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)
    mock_gate.is_backing_store_available.return_value = False

    for _ in range(5):
        await monitor.run_one_heartbeat()

    assert audit.append_schema.await_count == 1


async def test_entering_and_exiting_rows_share_correlation_id(
    mock_gate: MagicMock, audit: AsyncMock
) -> None:
    """err-014: both rows of a single outage carry the same ``correlation_id``.

    The entering row's correlation_id is generated at transition time and
    persisted on the monitor until the exiting transition reads it. The
    audit graph then joins entering + exiting rows on the shared key —
    making "how long did this outage last" a one-query answer.
    """
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)
    mock_gate.is_backing_store_available.return_value = False
    await monitor.run_one_heartbeat()
    mock_gate.is_backing_store_available.return_value = True
    await monitor.run_one_heartbeat()

    subjects = [
        call.kwargs["subject"]
        for call in audit.append_schema.await_args_list
        if call.kwargs["event"] == "supervisor.capability_gate_unavailable"
    ]
    assert len(subjects) == 2
    assert subjects[0]["correlation_id"] != ""
    assert subjects[0]["correlation_id"] == subjects[1]["correlation_id"]


async def test_denied_dispatch_count_rolled_into_exiting_row(
    mock_gate: MagicMock, audit: AsyncMock
) -> None:
    """err-015: ``denied_dispatch_count`` in the exiting row matches actual denials.

    Spec §10.4 requires per-dispatch denied rows AND a rollup in the
    exiting row. The monitor counts denials between entering and exiting
    transitions; the rollup is a quick "how many dispatches did this
    outage kill" answer that beats aggregating per-dispatch rows.
    """
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)
    mock_gate.is_backing_store_available.return_value = False
    await monitor.run_one_heartbeat()

    for _ in range(3):
        monitor.record_denied_dispatch()

    mock_gate.is_backing_store_available.return_value = True
    await monitor.run_one_heartbeat()

    exiting = next(
        call.kwargs["subject"]
        for call in audit.append_schema.await_args_list
        if call.kwargs["event"] == "supervisor.capability_gate_unavailable"
        and call.kwargs["subject"]["state_transition"] == "exiting_fail_closed"
    )
    assert exiting["denied_dispatch_count"] == 3


async def test_record_denied_dispatch_no_op_when_not_fail_closed(
    mock_gate: MagicMock, audit: AsyncMock
) -> None:
    """``record_denied_dispatch`` outside fail-closed is a no-op.

    The counter only meaningfully exists between entering and exiting
    transitions. A caller racing the gate (denial counted before the
    monitor sees the unavailability transition) must NOT inflate the
    counter into a later outage's rollup.
    """
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)
    # No fail-closed transition observed yet — counter ignores the call.
    monitor.record_denied_dispatch()
    monitor.record_denied_dispatch()

    # Now drive a fresh outage.
    mock_gate.is_backing_store_available.return_value = False
    await monitor.run_one_heartbeat()
    mock_gate.is_backing_store_available.return_value = True
    await monitor.run_one_heartbeat()

    exiting = next(
        call.kwargs["subject"]
        for call in audit.append_schema.await_args_list
        if call.kwargs["event"] == "supervisor.capability_gate_unavailable"
        and call.kwargs["subject"]["state_transition"] == "exiting_fail_closed"
    )
    # Pre-outage denials are dropped on the floor; rollup is 0.
    assert exiting["denied_dispatch_count"] == 0


async def test_emit_uses_supervisor_persona_and_t0_trust_tier(
    mock_gate: MagicMock, audit: AsyncMock
) -> None:
    """Attribution pins: actor_persona='supervisor', trust_tier_of_trigger='T0'.

    Supervisor audit rows are NEVER attributed to Alfred (the default
    actor_persona) — the supervisor is its own attribution surface. T0 is
    pinned because the row describes internal system state, never
    T-tiered user content.
    """
    mock_gate.is_backing_store_available.return_value = False
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)
    await monitor.run_one_heartbeat()

    call = next(
        c
        for c in audit.append_schema.await_args_list
        if c.kwargs["event"] == "supervisor.capability_gate_unavailable"
    )
    assert call.kwargs["actor_persona"] == "supervisor"
    assert call.kwargs["trust_tier_of_trigger"] == "T0"
    # actor_user_id is None — the row has no human actor (operator-cancel
    # is the only supervisor row that does, and that's breaker.reset).
    assert call.kwargs["actor_user_id"] is None
    # Cost fields are zero — supervisor monitoring is internal, never billed.
    assert call.kwargs["cost_estimate_usd"] == 0.0


async def test_correlation_ids_differ_across_outages(
    mock_gate: MagicMock, audit: AsyncMock
) -> None:
    """Each outage gets a fresh ``correlation_id``.

    Outage A's entering+exiting share a key; outage B's pair shares a
    distinct key. Joining on correlation_id partitions the audit stream
    into discrete outages without a window function.
    """
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)

    # Outage A
    mock_gate.is_backing_store_available.return_value = False
    await monitor.run_one_heartbeat()
    mock_gate.is_backing_store_available.return_value = True
    await monitor.run_one_heartbeat()

    # Outage B
    mock_gate.is_backing_store_available.return_value = False
    await monitor.run_one_heartbeat()
    mock_gate.is_backing_store_available.return_value = True
    await monitor.run_one_heartbeat()

    subjects = [
        call.kwargs["subject"]
        for call in audit.append_schema.await_args_list
        if call.kwargs["event"] == "supervisor.capability_gate_unavailable"
    ]
    # 4 emits: entering_A, exiting_A, entering_B, exiting_B
    assert len(subjects) == 4
    cid_a = subjects[0]["correlation_id"]
    cid_b = subjects[2]["correlation_id"]
    assert cid_a == subjects[1]["correlation_id"]
    assert cid_b == subjects[3]["correlation_id"]
    assert cid_a != cid_b


# ---------------------------------------------------------------------------
# Protocol stub coverage — exercise the NotImplementedError bodies so the
# coverage gate (100% on this file) does not flag the stubs as dead. Mirrors
# the pattern in tests/unit/supervisor/test_plugin_lifecycle.py.
# ---------------------------------------------------------------------------


def test_gate_probe_protocol_body_raises() -> None:
    """The _GateProbe Protocol stub body is exercised so coverage counts it."""
    from alfred.supervisor.capability_monitor import _GateProbe

    class _Stub(_GateProbe):
        def is_backing_store_available(self) -> bool:
            return _GateProbe.is_backing_store_available(self)

    with pytest.raises(NotImplementedError):
        _Stub().is_backing_store_available()


async def test_audit_sink_protocol_body_raises() -> None:
    """The _AuditSink Protocol stub body is exercised so coverage counts it."""
    from alfred.supervisor.capability_monitor import _AuditSink

    class _Stub(_AuditSink):
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
            await _AuditSink.append_schema(
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
            fields=SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS,
            schema_name="SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS",
            event="x",
            actor_user_id=None,
            subject={},
            trust_tier_of_trigger="T0",
            result="success",
            cost_estimate_usd=0.0,
            trace_id="t",
        )


async def test_emit_transition_direct_with_no_outage_id_falls_back_to_fresh_uuid(
    mock_gate: MagicMock, audit: AsyncMock
) -> None:
    """Defensive fallback: ``_emit_transition`` invoked without an outage id mints one.

    The constructor leaves ``_outage_correlation_id`` at ``None``; the normal
    entering branch sets it before ``_emit_transition`` is called. This test
    exercises the defensive ``or str(uuid.uuid4())`` fallback so the coverage
    gate flags any future drift that makes the fallback unreachable.
    """
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)
    # Outage id is None (no entering transition observed) — defensive
    # fallback in _emit_transition mints a fresh id rather than write
    # ``None`` to the audit row.
    await monitor._emit_transition(
        state_transition="entering_fail_closed",
        denied_dispatch_count=0,
        backing_store_error_type="unavailable",
    )
    call = audit.append_schema.await_args_list[0]
    cid = call.kwargs["subject"]["correlation_id"]
    assert isinstance(cid, str)
    assert cid != ""


async def test_denied_count_resets_between_outages(mock_gate: MagicMock, audit: AsyncMock) -> None:
    """Denials counted during outage A do NOT contaminate outage B's rollup."""
    monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit)

    # Outage A: 2 denials between entering and exiting.
    mock_gate.is_backing_store_available.return_value = False
    await monitor.run_one_heartbeat()
    monitor.record_denied_dispatch()
    monitor.record_denied_dispatch()
    mock_gate.is_backing_store_available.return_value = True
    await monitor.run_one_heartbeat()

    # Outage B: zero denials.
    mock_gate.is_backing_store_available.return_value = False
    await monitor.run_one_heartbeat()
    mock_gate.is_backing_store_available.return_value = True
    await monitor.run_one_heartbeat()

    exiting_subjects = [
        call.kwargs["subject"]
        for call in audit.append_schema.await_args_list
        if call.kwargs["event"] == "supervisor.capability_gate_unavailable"
        and call.kwargs["subject"]["state_transition"] == "exiting_fail_closed"
    ]
    assert exiting_subjects[0]["denied_dispatch_count"] == 2
    assert exiting_subjects[1]["denied_dispatch_count"] == 0
