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
    # An adapter with no observed crash has no incidents (the read surface never
    # invents state; trust-boundary read).
    assert reconciler.incidents("never-seen") == ()


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


def test_duplicate_gateway_crash_is_marked_not_dropped() -> None:
    reconciler = CrashIncidentReconciler()
    first = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    second = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    assert first.duplicate is False
    # A replayed/forged gateway crash for the SAME incarnation folds (no new
    # incident) but is FLAGGED duplicate so the caller STILL audits it loudly.
    assert second.duplicate is True
    assert second.crash_incident_id == first.crash_incident_id
    assert len(reconciler.incidents("discord")) == 1


def test_duplicate_child_crash_is_marked_not_dropped() -> None:
    # TE-1/TE-3 (branch coverage): a second in-child crash for the same incarnation
    # folds + is flagged duplicate, never dropped (hard rule #7).
    reconciler = CrashIncidentReconciler()
    first = reconciler.observe_child_crash(adapter_id="discord")
    second = reconciler.observe_child_crash(adapter_id="discord")
    assert first.duplicate is False
    assert second.duplicate is True
    assert second.crash_incident_id == first.crash_incident_id
    assert len(reconciler.incidents("discord")) == 1


def test_forged_child_crash_cannot_mask_a_later_real_gateway_crash() -> None:
    reconciler = CrashIncidentReconciler()
    # A forged in-child crash with no prior incarnation -> a child-only incident at 0.
    forged = reconciler.observe_child_crash(adapter_id="discord")
    assert forged.crash_signal_source == "child"
    # A genuine gateway crash for a LATER incarnation opens its OWN incident.
    reconciler.note_incarnation(adapter_id="discord", host_restart_seq=2)
    real = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=2)
    assert real.crash_incident_id != forged.crash_incident_id
    assert real.crash_signal_source == "gateway"
    assert len(reconciler.incidents("discord")) == 2


def test_incident_history_is_bounded() -> None:
    reconciler = CrashIncidentReconciler()
    for seq in range(200):
        reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=seq)
    # Bounded so a crash-loop cannot grow the map unboundedly (audit log is durable).
    # 200 distinct incarnations crashed but exactly _MAX_INCIDENTS_PER_ADAPTER are
    # retained — assert the exact cap so a retention regression BELOW it also fails.
    assert len(reconciler.incidents("discord")) == 64


def test_incidents_read_surface_returns_views_for_in_process_reader() -> None:
    # 2b-2c reads the per-adapter incident view IN-PROCESS (the daemon holds the
    # reconciler). This asserts the read surface contract the render will consume.
    reconciler = CrashIncidentReconciler()
    reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    views = reconciler.incidents("discord")
    assert views[0].adapter_id == "discord"
    assert views[0].crash_signal_source in {"gateway", "child", "both"}
    assert reconciler.incidents("unknown-adapter") == ()


def test_adapter_ids_enumerates_every_observed_adapter() -> None:
    # G6-2b-2c (#288): the additive enumeration read the daemon control plane folds
    # into the live status result. Assert against a SORTED LITERAL (not x == x) so a
    # silent omission fails.
    reconciler = CrashIncidentReconciler()
    reconciler.observe_gateway_crash(adapter_id="tui", host_restart_seq=0)
    reconciler.note_incarnation(adapter_id="discord", host_restart_seq=2)
    assert sorted(reconciler.adapter_ids()) == ["discord", "tui"]


def test_adapter_ids_empty_before_any_observation() -> None:
    assert CrashIncidentReconciler().adapter_ids() == ()


def test_current_incarnation_reports_latest_seq_seen() -> None:
    reconciler = CrashIncidentReconciler()
    reconciler.note_incarnation(adapter_id="discord", host_restart_seq=3)
    assert reconciler.current_incarnation("discord") == 3
    # A later gateway crash at a higher seq advances it.
    reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=5)
    assert reconciler.current_incarnation("discord") == 5


def test_current_incarnation_is_zero_for_unseen_adapter() -> None:
    # ``.get`` -> no state-invention: an unseen adapter reports 0, and querying it
    # does NOT register it (the read never mutates).
    reconciler = CrashIncidentReconciler()
    assert reconciler.current_incarnation("never-seen") == 0
    assert reconciler.adapter_ids() == ()
