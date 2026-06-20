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
