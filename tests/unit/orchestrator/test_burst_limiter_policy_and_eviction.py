"""``BurstLimiter.from_policy`` config read + LRU bucket eviction (Tasks 18-19, perf-001).

``from_policy`` reads ``capacity_tokens`` / ``refill_seconds`` from the shared
``BurstLimiterPolicy`` (single source of truth; PR-S4-4 contract anchor).
``drop_after_seconds`` is a comms-side constructor default not carried by the
shared policy (see ``BurstLimiter`` docstring + the PR commit rationale).

perf-001: the per-key bucket map is LRU-bounded. Past the cap the
least-recently-used bucket is evicted so an adversary cannot exhaust host
memory by cycling distinct ``(user, persona)`` keys.
"""

from __future__ import annotations

from alfred.orchestrator.burst_limiter import Acquired, BurstLimiter
from alfred.policies.model import BurstLimiterPolicy

from ._burst_spies import SpyAuditWriter


async def test_from_policy_reads_capacity_and_refill() -> None:
    policy = BurstLimiterPolicy(capacity_tokens=3, refill_seconds=10.0)
    limiter = BurstLimiter.from_policy(policy, audit_writer=SpyAuditWriter())
    # capacity=3 -> three instant acquires, then tokens_remaining hits 0.
    results = [
        await limiter.acquire(canonical_user_id="u", persona="alfred") for _ in range(3)
    ]
    assert all(isinstance(r, Acquired) for r in results)
    assert results[-1].tokens_remaining == 0  # type: ignore[union-attr]


async def test_from_policy_default_drop_after_seconds() -> None:
    limiter = BurstLimiter.from_policy(
        BurstLimiterPolicy(), audit_writer=SpyAuditWriter()
    )
    assert limiter.drop_after_seconds == 30.0


async def test_lru_eviction_caps_bucket_count() -> None:
    limiter = BurstLimiter(
        capacity_tokens=5,
        refill_seconds=5.0,
        audit_writer=SpyAuditWriter(),
        max_tracked_buckets=2,
    )
    await limiter.acquire(canonical_user_id="u_a", persona="alfred")
    await limiter.acquire(canonical_user_id="u_b", persona="alfred")
    await limiter.acquire(canonical_user_id="u_c", persona="alfred")  # evicts u_a (LRU)
    assert limiter.tracked_bucket_count == 2
    # u_a was evicted: its bucket is fresh again (full capacity).
    r = await limiter.acquire(canonical_user_id="u_a", persona="alfred")
    assert isinstance(r, Acquired)
    assert r.tokens_remaining == 4


async def test_lru_recently_used_bucket_survives() -> None:
    limiter = BurstLimiter(
        capacity_tokens=5,
        refill_seconds=5.0,
        audit_writer=SpyAuditWriter(),
        max_tracked_buckets=2,
    )
    await limiter.acquire(canonical_user_id="u_a", persona="alfred")
    await limiter.acquire(canonical_user_id="u_b", persona="alfred")
    # Touch u_a again -> u_b becomes LRU.
    await limiter.acquire(canonical_user_id="u_a", persona="alfred")
    await limiter.acquire(canonical_user_id="u_c", persona="alfred")  # evicts u_b
    # u_a survived: only 3 tokens left (consumed twice).
    r = await limiter.acquire(canonical_user_id="u_a", persona="alfred")
    assert isinstance(r, Acquired)
    assert r.tokens_remaining == 2
