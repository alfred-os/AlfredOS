"""``BurstLimiter`` dataclasses + capacity/refill core (Tasks 13-14).

Capacity 5, 1 token / 5s refill. A burst of 5 acquires succeeds instantly; the
6th waits ~5s for a refill. The clock is mocked so the test runs in subsecond
wall time. Refill math uses ``time.monotonic()`` (comms-003).
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from alfred.orchestrator.burst_limiter import Acquired, BurstLimiter, Dropped

from ._burst_spies import SpyAuditWriter


class _FakeMonotonic:
    """Deterministic monotonic clock; advances only when a test tells it to."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def test_acquired_is_frozen() -> None:
    a = Acquired(tokens_remaining=4, waited_seconds=0.0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.tokens_remaining = 0  # type: ignore[misc]


def test_dropped_carries_bucket_empty_since() -> None:
    now = datetime.now(UTC)
    d = Dropped(waited_seconds=30.0, bucket_empty_since=now)
    assert d.bucket_empty_since == now


async def test_burst_of_five_succeeds_instantly() -> None:
    mono = _FakeMonotonic()
    limiter = BurstLimiter(
        capacity_tokens=5,
        refill_seconds=5.0,
        audit_writer=SpyAuditWriter(),
        monotonic=mono,
    )
    for i in range(5):
        result = await limiter.acquire(canonical_user_id="u", persona="alfred")
        assert isinstance(result, Acquired)
        assert result.waited_seconds == 0.0
        assert result.tokens_remaining == 4 - i


async def test_sixth_acquire_waits_for_refill() -> None:
    mono = _FakeMonotonic()
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        mono.advance(seconds)

    limiter = BurstLimiter(
        capacity_tokens=5,
        refill_seconds=5.0,
        audit_writer=SpyAuditWriter(),
        monotonic=mono,
        sleep=fake_sleep,
    )
    for _ in range(5):
        await limiter.acquire(canonical_user_id="u", persona="alfred")
    result = await limiter.acquire(canonical_user_id="u", persona="alfred")
    assert isinstance(result, Acquired)
    # Waited ~5s (one refill interval) for the next token.
    assert result.waited_seconds == pytest.approx(5.0, rel=0.01)
    assert slept and slept[0] == pytest.approx(5.0, rel=0.01)


async def test_refill_restores_one_token_after_interval() -> None:
    mono = _FakeMonotonic()
    limiter = BurstLimiter(
        capacity_tokens=5,
        refill_seconds=5.0,
        audit_writer=SpyAuditWriter(),
        monotonic=mono,
    )
    for _ in range(5):
        await limiter.acquire(canonical_user_id="u", persona="alfred")
    # Advance one refill interval: exactly one token returns.
    mono.advance(5.0)
    result = await limiter.acquire(canonical_user_id="u", persona="alfred")
    assert isinstance(result, Acquired)
    assert result.waited_seconds == 0.0
