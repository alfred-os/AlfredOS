"""``COMMS_INBOUND_BUDGET_CAPPED_FIELDS`` emit on backpressure (Task 16)."""

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


async def test_emits_capped_audit_row_when_waited() -> None:
    audit = SpyAuditWriter()
    mono = _FakeMonotonic()

    async def fake_sleep(seconds: float) -> None:
        mono.advance(seconds)

    limiter = BurstLimiter(
        capacity_tokens=1,
        refill_seconds=0.1,
        audit_writer=audit,
        monotonic=mono,
        sleep=fake_sleep,
    )
    await limiter.acquire(canonical_user_id="u", persona="alfred")  # consumes token
    result = await limiter.acquire(canonical_user_id="u", persona="alfred")  # waits ~0.1s
    assert isinstance(result, Acquired)
    assert result.waited_seconds > 0

    capped = audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
    assert len(capped) == 1
    row = capped[0]
    assert row["dropped"] is False
    assert row["wait_seconds"] == pytest.approx(result.waited_seconds, rel=0.1)
    assert row["persona"] == "alfred"
    assert row["canonical_user_id"] == "u"
    assert "tokens_available" in row
    assert "language" in row


async def test_no_capped_row_when_token_available() -> None:
    audit = SpyAuditWriter()
    limiter = BurstLimiter(capacity_tokens=5, refill_seconds=5.0, audit_writer=audit)
    await limiter.acquire(canonical_user_id="u", persona="alfred")
    assert audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS") == []
