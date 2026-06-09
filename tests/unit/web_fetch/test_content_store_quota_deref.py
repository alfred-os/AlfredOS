"""``ContentStore.session_total_quota`` derefs per call (PR-S4-4 Task 17)."""

from __future__ import annotations

from alfred.plugins.web_fetch.content_store import ContentStore
from alfred.policies.snapshot_ref import PoliciesSnapshotRef
from tests.unit.policies._factories import make_policies, make_snapshot
from tests.unit.policies._watcher_harness import swap_snapshot


def test_quota_none_without_ref() -> None:
    store = ContentStore(redis_url="redis://localhost:6379/0")
    assert store.session_total_quota() is None


def test_quota_reads_active_snapshot() -> None:
    ref = PoliciesSnapshotRef(
        make_snapshot(policies=make_policies(rate_limits={"web_fetch_per_session_total": 200}))
    )
    store = ContentStore(redis_url="redis://localhost:6379/0", policies_ref=ref)
    assert store.session_total_quota() == 200


def test_quota_reflects_swap_on_next_call() -> None:
    ref = PoliciesSnapshotRef(
        make_snapshot(policies=make_policies(rate_limits={"web_fetch_per_session_total": 200}))
    )
    store = ContentStore(redis_url="redis://localhost:6379/0", policies_ref=ref)
    assert store.session_total_quota() == 200
    # Swap through the PUBLIC audit-then-swap path (CR round-3 Finding 6).
    swap_snapshot(
        ref,
        make_snapshot(policies=make_policies(rate_limits={"web_fetch_per_session_total": 500})),
    )
    assert store.session_total_quota() == 500
