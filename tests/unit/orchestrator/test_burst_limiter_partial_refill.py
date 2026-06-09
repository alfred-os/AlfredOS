"""Partial-refill (<1 token) path + real-sleep default (Task 14 edge coverage).

Covers the refill branch where elapsed time restores a *fractional* token
(still below one), and the production ``asyncio.sleep`` back-pressure path
that the deterministic tests stub out.
"""

from __future__ import annotations

import pytest

from alfred.orchestrator.burst_limiter import Acquired, BurstLimiter

from ._burst_spies import SpyAuditWriter


class _FakeMonotonic:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


async def test_partial_refill_below_one_token_backpressures() -> None:
    audit = SpyAuditWriter()
    mono = _FakeMonotonic()
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        mono.advance(seconds)

    limiter = BurstLimiter(
        capacity_tokens=1,
        refill_seconds=5.0,
        audit_writer=audit,
        monotonic=mono,
        sleep=fake_sleep,
    )
    await limiter.acquire(canonical_user_id="u", persona="alfred")  # tokens -> 0
    # Advance half a refill interval: tokens refill to 0.5 (still < 1).
    mono.advance(2.5)
    result = await limiter.acquire(canonical_user_id="u", persona="alfred")
    assert isinstance(result, Acquired)
    # Needed the remaining 0.5 token -> ~2.5s wait.
    assert result.waited_seconds == pytest.approx(2.5, rel=0.01)
    assert slept[0] == pytest.approx(2.5, rel=0.01)


async def test_real_sleep_backpressure_path() -> None:
    # Exercises the default asyncio.sleep injection with a tiny real wait so
    # the production sleep path is covered.
    limiter = BurstLimiter(
        capacity_tokens=1,
        refill_seconds=0.01,
        audit_writer=SpyAuditWriter(),
    )
    await limiter.acquire(canonical_user_id="u", persona="alfred")
    result = await limiter.acquire(canonical_user_id="u", persona="alfred")
    assert isinstance(result, Acquired)
    assert result.waited_seconds > 0
