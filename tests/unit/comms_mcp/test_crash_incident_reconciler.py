"""CrashIncidentReconciler — the core-side crash-dedup correlation (G6-2b-2b / #288)."""

from __future__ import annotations

from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler


def test_gateway_crash_opens_one_incident() -> None:
    reconciler = CrashIncidentReconciler()
    result = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    assert result.crash_signal_source == "gateway"
    assert result.duplicate is False
    assert result.crash_incident_id  # a stable non-empty handle
    incidents = reconciler.incidents("discord")
    assert len(incidents) == 1
    assert incidents[0].host_restart_seq == 0
    assert incidents[0].crash_signal_source == "gateway"


def test_child_before_gateway_common_order_folds_to_one_incident() -> None:
    """SEC-01 (the load-bearing fix): the COMMON order is child-before-gateway.

    The in-child diagnostic fires as the child dies — BEFORE the gateway observes
    process-exit and emits its seq-bearing ``crashed`` frame. ``note_incarnation``
    is what the observer calls on an accepted ``up`` (the production call site), so
    by the time the child crash arrives the reconciler already knows the serving
    incarnation. Without the up-advance, the child would fold into a stale
    incarnation and the gateway crash would open a fresh one -> two incidents.
    """
    reconciler = CrashIncidentReconciler()
    # Adapter reached its 2nd serving incarnation (after one restart). The observer
    # advances the reconciler on the up frame (host_restart_seq=1 = the run STARTED).
    reconciler.note_incarnation(adapter_id="discord", host_restart_seq=1)
    # The in-child diagnostic arrives FIRST, tagged to the current incarnation (1).
    child = reconciler.observe_child_crash(adapter_id="discord")
    assert child.crash_signal_source == "child"
    assert child.host_restart_seq == 1
    # The authoritative gateway crash for incarnation 1 arrives next -> SAME incident.
    gateway = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=1)
    assert gateway.crash_incident_id == child.crash_incident_id
    assert gateway.crash_signal_source == "both"
    assert len(reconciler.incidents("discord")) == 1


def test_gateway_then_child_same_incarnation_folds_to_one_incident() -> None:
    reconciler = CrashIncidentReconciler()
    gateway = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    child = reconciler.observe_child_crash(adapter_id="discord")
    assert child.crash_incident_id == gateway.crash_incident_id
    assert child.crash_signal_source == "both"
    assert len(reconciler.incidents("discord")) == 1


def test_distinct_incarnations_are_distinct_incidents() -> None:
    reconciler = CrashIncidentReconciler()
    first = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    reconciler.note_incarnation(adapter_id="discord", host_restart_seq=1)
    second = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=1)
    assert first.crash_incident_id != second.crash_incident_id
    assert len(reconciler.incidents("discord")) == 2
