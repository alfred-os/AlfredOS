"""``RateLimitConfig.from_snapshot_ref`` derefs per call (PR-S4-4 Task 15).

The classmethod reads ``ref.current()`` every time it is called so a watcher
swap between two calls is reflected in the next-built config (proving the
migration is ``from_snapshot_ref``, not a one-shot ``from_snapshot``).
"""

from __future__ import annotations

from alfred.plugins.web_fetch.rate_limit import RateLimitConfig
from alfred.policies.snapshot_ref import PoliciesSnapshotRef
from tests.unit.policies._factories import make_policies, make_snapshot


def test_from_snapshot_ref_maps_fields() -> None:
    model = make_policies(rate_limits={"web_fetch_per_user_per_hour": 90})
    ref = PoliciesSnapshotRef(make_snapshot(policies=model))
    cfg = RateLimitConfig.from_snapshot_ref(ref)
    assert cfg.per_user_daily == 90


def test_from_snapshot_ref_reflects_swap_on_next_call() -> None:
    first = make_snapshot(policies=make_policies(rate_limits={"web_fetch_per_user_per_hour": 60}))
    ref = PoliciesSnapshotRef(first)
    assert RateLimitConfig.from_snapshot_ref(ref).per_user_daily == 60
    # Simulate a swap by replacing the ref's active snapshot directly.
    ref._current = make_snapshot(  # type: ignore[attr-defined]
        policies=make_policies(rate_limits={"web_fetch_per_user_per_hour": 120})
    )
    assert RateLimitConfig.from_snapshot_ref(ref).per_user_daily == 120
