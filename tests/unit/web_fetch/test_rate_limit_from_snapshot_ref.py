"""``RateLimitConfig.from_snapshot_ref`` is units-honest + derefs per call.

CR round-3 Finding 1 (#225): the classmethod returns the spec §7.7 DEFAULTS and
does NOT derive the DAILY ``per_user_daily`` bucket from the HOURLY
``web_fetch_per_user_per_hour`` field (an hour-as-day units bug). The consumer
is dormant until #225 reconciles ``PoliciesV1`` with a correctly-unit'd daily
field. The per-call ``ref.current()`` deref still runs so the hot-reload wiring
contract is exercised (proving the migration is ``from_snapshot_ref``, not a
one-shot ``from_snapshot``).
"""

from __future__ import annotations

from alfred.plugins.web_fetch.rate_limit import (
    _DEFAULT_PER_DOMAIN_PER_MINUTE,
    _DEFAULT_PER_USER_DAILY,
    _DEFAULT_PER_USER_PER_MINUTE,
    RateLimitConfig,
)
from alfred.policies.snapshot_ref import PoliciesSnapshotRef
from tests.unit.policies._factories import make_policies, make_snapshot
from tests.unit.policies._watcher_harness import swap_snapshot


def test_from_snapshot_ref_returns_units_honest_defaults() -> None:
    """The hourly field is NOT wired into the daily bucket (Finding 1 / #225)."""
    model = make_policies(rate_limits={"web_fetch_per_user_per_hour": 90})
    ref = PoliciesSnapshotRef(make_snapshot(policies=model))
    cfg = RateLimitConfig.from_snapshot_ref(ref)
    # Defaults, NOT the hourly 90 mis-mapped into the daily bucket.
    assert cfg.per_user_daily == _DEFAULT_PER_USER_DAILY
    assert cfg.per_domain_per_minute == _DEFAULT_PER_DOMAIN_PER_MINUTE
    assert cfg.per_user_per_minute == _DEFAULT_PER_USER_PER_MINUTE


def test_from_snapshot_ref_derefs_active_snapshot_per_call() -> None:
    """The per-call deref runs (hot-reload contract) even though no field maps yet.

    Swaps through the PUBLIC audit-then-swap path (Finding 6). Until #225 wires a
    correctly-unit'd daily field, both builds yield defaults regardless of the
    swapped hourly value — the assertion that matters is the deref does not raise
    and the contract stays live for #225.
    """
    ref = PoliciesSnapshotRef(
        make_snapshot(policies=make_policies(rate_limits={"web_fetch_per_user_per_hour": 60}))
    )
    assert RateLimitConfig.from_snapshot_ref(ref).per_user_daily == _DEFAULT_PER_USER_DAILY
    swap_snapshot(
        ref,
        make_snapshot(policies=make_policies(rate_limits={"web_fetch_per_user_per_hour": 120})),
    )
    assert RateLimitConfig.from_snapshot_ref(ref).per_user_daily == _DEFAULT_PER_USER_DAILY
