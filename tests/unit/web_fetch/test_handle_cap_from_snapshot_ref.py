"""``HandleCapConfig.from_snapshot_ref`` derefs per call (PR-S4-4 Task 16)."""

from __future__ import annotations

from alfred.plugins.web_fetch.handle_cap import HandleCapConfig
from alfred.policies.snapshot_ref import PoliciesSnapshotRef
from tests.unit.policies._factories import make_policies, make_snapshot
from tests.unit.policies._watcher_harness import swap_snapshot


def test_from_snapshot_ref_maps_cap() -> None:
    model = make_policies(handle_caps={"web_fetch_max_concurrent_handles_per_user": 12})
    ref = PoliciesSnapshotRef(make_snapshot(policies=model))
    assert HandleCapConfig.from_snapshot_ref(ref).per_user == 12


def test_from_snapshot_ref_reflects_swap_on_next_call() -> None:
    ref = PoliciesSnapshotRef(
        make_snapshot(
            policies=make_policies(handle_caps={"web_fetch_max_concurrent_handles_per_user": 5})
        )
    )
    assert HandleCapConfig.from_snapshot_ref(ref).per_user == 5
    # Swap through the PUBLIC audit-then-swap path (CR round-3 Finding 6).
    swap_snapshot(
        ref,
        make_snapshot(
            policies=make_policies(handle_caps={"web_fetch_max_concurrent_handles_per_user": 9})
        ),
    )
    assert HandleCapConfig.from_snapshot_ref(ref).per_user == 9
