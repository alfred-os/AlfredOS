"""Per-(canonical_user_id, persona) bucket independence (Task 15)."""

from __future__ import annotations

from alfred.orchestrator.burst_limiter import Acquired, BurstLimiter

from ._burst_spies import SpyAuditWriter


async def test_independent_buckets() -> None:
    limiter = BurstLimiter(capacity_tokens=5, refill_seconds=5.0, audit_writer=SpyAuditWriter())
    for _ in range(5):
        assert isinstance(
            await limiter.acquire(canonical_user_id="u_a", persona="alfred"),
            Acquired,
        )
    # u_a/alfred is drained, but u_b/alfred is a fresh bucket.
    r = await limiter.acquire(canonical_user_id="u_b", persona="alfred")
    assert isinstance(r, Acquired)
    assert r.tokens_remaining == 4
    # u_a/oracle is also independent.
    r = await limiter.acquire(canonical_user_id="u_a", persona="oracle")
    assert isinstance(r, Acquired)
    assert r.tokens_remaining == 4
