"""Tests for ``InProcessTokenBucketRateLimiter`` — PR D1 production limiter.

The load-bearing test is
:func:`test_read_only_user_refused_regardless_of_override` — the spec line
223 security invariant. Renaming or removing it without a coordinated
spec update breaks the spec-to-code traceability the architect relies on
to audit Slice-2 trust-boundary changes.

Other coverage:

* Authorization-tier defaults (standard 30/min, trusted 60/min, operator
  unlimited).
* ``User.rate_limit_per_min`` override wins over the tier default — but
  ONLY when authorization is not READ_ONLY (defense in depth).
* Token-bucket recovery cadence under an injected clock.
* Per-user independence.
* Soft-deleted-user short-circuit.
* ``reset()`` semantics.
* ``health()`` snapshot shape.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from alfred.identity.models import Authorization, User
from alfred.identity.rate_limit import (
    AUTH_DEFAULT_PER_MIN,
    InProcessTokenBucketRateLimiter,
    RateLimiterHealth,
)


def _user(
    *,
    slug: str = "alice",
    authorization: Authorization = Authorization.STANDARD,
    rate_limit_per_min: int | None = None,
    deleted_at: datetime | None = None,
) -> User:
    """Construct a non-persisted ``User`` row for unit-test scenarios.

    Uses the documented ORM constructor so the test exercises the same
    surface the resolver hands out at runtime.
    """
    return User(
        slug=slug,
        display_name=slug.title(),
        authorization=authorization.value,
        daily_budget_usd=5.0,
        language="en-US",
        rate_limit_per_min=rate_limit_per_min,
        rate_limit_per_day=None,
        deleted_at=deleted_at,
    )


class _FakeClock:
    """Hand-cranked monotonic clock for the recovery-cadence tests."""

    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


# ---------- Security invariant: READ_ONLY refusal is FIRST ----------


@pytest.mark.asyncio
async def test_read_only_user_refused_regardless_of_override() -> None:
    """READ_ONLY users are refused even with a generous ``rate_limit_per_min``.

    THIS IS THE LOAD-BEARING TEST OF THE PROTOCOL (spec §2 line 223).
    If a future refactor reads ``user.rate_limit_per_min`` before the
    READ_ONLY check, this test fails — and the spec-to-code traceability
    that depends on this test name surfaces the regression.
    """
    limiter = InProcessTokenBucketRateLimiter()
    read_only = _user(
        slug="curious",
        authorization=Authorization.READ_ONLY,
        rate_limit_per_min=30,  # override that MUST be ignored
    )
    assert await limiter.allow(read_only) is False
    # The refusal must register against the health counter even though
    # we never built a bucket for the user.
    assert limiter.health().total_refusals_since_start == 1
    assert limiter.health().active_user_count == 0


@pytest.mark.asyncio
async def test_read_only_reset_is_noop() -> None:
    limiter = InProcessTokenBucketRateLimiter()
    read_only = _user(authorization=Authorization.READ_ONLY)
    await limiter.reset(read_only.slug)
    assert await limiter.allow(read_only) is False


# ---------- Tier defaults ----------


@pytest.mark.asyncio
async def test_standard_default_30_per_min() -> None:
    clock = _FakeClock()
    limiter = InProcessTokenBucketRateLimiter(time_source=clock)
    standard = _user(authorization=Authorization.STANDARD)
    for _ in range(30):
        assert await limiter.allow(standard) is True
    assert await limiter.allow(standard) is False
    # Advance one minute; the bucket refills to full.
    clock.advance(60.0)
    assert await limiter.allow(standard) is True


@pytest.mark.asyncio
async def test_trusted_default_60_per_min() -> None:
    clock = _FakeClock()
    limiter = InProcessTokenBucketRateLimiter(time_source=clock)
    trusted = _user(authorization=Authorization.TRUSTED, slug="trusty")
    for _ in range(60):
        assert await limiter.allow(trusted) is True
    assert await limiter.allow(trusted) is False


@pytest.mark.asyncio
async def test_operator_unlimited() -> None:
    """Operators short-circuit the bucket math entirely."""
    limiter = InProcessTokenBucketRateLimiter()
    operator = _user(authorization=Authorization.OPERATOR, slug="op")
    # 1000 calls in tight succession — every one returns True.
    results = [await limiter.allow(operator) for _ in range(1000)]
    assert all(results)
    # No bucket created for the operator (short-circuit path).
    assert limiter.health().active_user_count == 0


# ---------- Override behaviour ----------


@pytest.mark.asyncio
async def test_explicit_override_wins_over_default() -> None:
    """Override wins for non-READ_ONLY tiers."""
    clock = _FakeClock()
    limiter = InProcessTokenBucketRateLimiter(time_source=clock)
    user = _user(authorization=Authorization.STANDARD, rate_limit_per_min=5)
    for _ in range(5):
        assert await limiter.allow(user) is True
    assert await limiter.allow(user) is False


@pytest.mark.asyncio
async def test_zero_override_denies_everything() -> None:
    """A legitimate zero override (operator-set deny) refuses every call."""
    limiter = InProcessTokenBucketRateLimiter()
    user = _user(authorization=Authorization.STANDARD, rate_limit_per_min=0)
    assert await limiter.allow(user) is False


# ---------- Multi-user independence ----------


@pytest.mark.asyncio
async def test_per_user_independence() -> None:
    """Alice draining her bucket doesn't affect Bob's."""
    clock = _FakeClock()
    limiter = InProcessTokenBucketRateLimiter(time_source=clock)
    alice = _user(slug="alice", authorization=Authorization.STANDARD)
    bob = _user(slug="bob", authorization=Authorization.STANDARD)
    for _ in range(30):
        assert await limiter.allow(alice) is True
    assert await limiter.allow(alice) is False
    # Bob still has a full 30.
    for _ in range(30):
        assert await limiter.allow(bob) is True
    assert await limiter.allow(bob) is False


# ---------- Recovery + reset ----------


@pytest.mark.asyncio
async def test_token_bucket_recovery() -> None:
    """At minute boundary, a drained bucket is fully refilled."""
    clock = _FakeClock()
    limiter = InProcessTokenBucketRateLimiter(time_source=clock)
    user = _user(authorization=Authorization.STANDARD)
    for _ in range(30):
        assert await limiter.allow(user) is True
    assert await limiter.allow(user) is False
    clock.advance(60.0)
    # Full minute → bucket refills to capacity.
    for _ in range(30):
        assert await limiter.allow(user) is True


@pytest.mark.asyncio
async def test_reset_clears_bucket() -> None:
    """``reset()`` drops the bucket; the next ``allow()`` starts at full capacity."""
    limiter = InProcessTokenBucketRateLimiter()
    user = _user(authorization=Authorization.STANDARD, rate_limit_per_min=2)
    assert await limiter.allow(user) is True
    assert await limiter.allow(user) is True
    assert await limiter.allow(user) is False
    await limiter.reset(user.slug)
    # Fresh bucket — first call allowed.
    assert await limiter.allow(user) is True


# ---------- Defense in depth ----------


@pytest.mark.asyncio
async def test_soft_deleted_user_short_circuit() -> None:
    """A soft-deleted user is refused without consuming a token.

    The resolver should never hand a soft-deleted row to the limiter,
    but the limiter's defense-in-depth catches a regression up the
    stack.
    """
    limiter = InProcessTokenBucketRateLimiter()
    deleted = _user(authorization=Authorization.STANDARD, deleted_at=datetime.now(UTC))
    assert await limiter.allow(deleted) is False
    assert limiter.health().total_refusals_since_start == 1
    assert limiter.health().active_user_count == 0


# ---------- Health snapshot ----------


@pytest.mark.asyncio
async def test_health_snapshot_shape() -> None:
    limiter = InProcessTokenBucketRateLimiter()
    alice = _user(slug="alice", authorization=Authorization.STANDARD)
    bob = _user(slug="bob", authorization=Authorization.STANDARD)
    await limiter.allow(alice)
    await limiter.allow(bob)
    health = limiter.health()
    assert isinstance(health, RateLimiterHealth)
    assert health.active_user_count == 2
    assert health.total_allowed_since_start == 2
    assert health.total_refusals_since_start == 0


# ---------- Default table sanity ----------


def test_auth_default_table_is_immutable() -> None:
    """``AUTH_DEFAULT_PER_MIN`` is a frozen mapping."""
    with pytest.raises(TypeError):
        # MappingProxyType raises TypeError on __setitem__.
        AUTH_DEFAULT_PER_MIN[Authorization.STANDARD] = 9999  # type: ignore[index]


def test_auth_default_table_matches_spec_values() -> None:
    """Authorization defaults match the spec §3 line 478-483 table."""
    assert AUTH_DEFAULT_PER_MIN[Authorization.READ_ONLY] == 0
    assert AUTH_DEFAULT_PER_MIN[Authorization.STANDARD] == 30
    assert AUTH_DEFAULT_PER_MIN[Authorization.TRUSTED] == 60
    assert AUTH_DEFAULT_PER_MIN[Authorization.OPERATOR] is None


# ---------- Tier-default fallback when override is missing ----------


@pytest.mark.asyncio
async def test_unlimited_non_operator_tier_returns_true() -> None:
    """Hypothetical NULL-default tier with no override falls through to True.

    Defensive check on the ``per_min is None`` branch — exercised here by
    monkey-patching the default table for one user. (Production never
    hits this branch because OPERATOR is already short-circuited above.)
    """
    limiter = InProcessTokenBucketRateLimiter()
    user = _user(authorization=Authorization.TRUSTED)
    # Force the per-min lookup to None on the TRUSTED tier.
    original = AUTH_DEFAULT_PER_MIN.get(Authorization.TRUSTED)
    # MappingProxyType is read-only; we patch the underlying mapping via
    # a fresh limiter and a stub. Simpler: shadow the lookup.
    from alfred.identity import rate_limit as rl_mod

    monkeypatch_target: Any = {
        Authorization.READ_ONLY: 0,
        Authorization.STANDARD: 30,
        Authorization.TRUSTED: None,
        Authorization.OPERATOR: None,
    }
    rl_mod.AUTH_DEFAULT_PER_MIN = monkeypatch_target  # type: ignore[misc]
    try:
        assert await limiter.allow(user) is True
    finally:
        # Restore. The frozen MappingProxyType wrapper is what we want
        # back in module-state; rebuild it the same way the module did.
        from types import MappingProxyType

        rl_mod.AUTH_DEFAULT_PER_MIN = MappingProxyType(  # type: ignore[misc]
            {
                Authorization.READ_ONLY: 0,
                Authorization.STANDARD: 30,
                Authorization.TRUSTED: original,
                Authorization.OPERATOR: None,
            }
        )
