"""Drop after ``drop_after_seconds`` of bucket-empty (Task 17).

When the projected wait to acquire a token exceeds ``drop_after_seconds`` the
limiter returns ``Dropped`` and emits BOTH the capped row (``dropped=True``)
and the distinct ``comms.inbound.dropped`` audit event (NOT a hookpoint).
"""

from __future__ import annotations

from alfred.orchestrator.burst_limiter import BurstLimiter, Dropped

from ._burst_spies import SpyAuditWriter


class _FakeMonotonic:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


async def test_drops_after_drop_after_seconds() -> None:
    audit = SpyAuditWriter()
    mono = _FakeMonotonic()

    async def fake_sleep(seconds: float) -> None:
        mono.advance(seconds)

    limiter = BurstLimiter(
        capacity_tokens=1,
        refill_seconds=300.0,
        drop_after_seconds=0.5,
        audit_writer=audit,
        monotonic=mono,
        sleep=fake_sleep,
    )
    await limiter.acquire(canonical_user_id="u", persona="alfred")  # consumes; empty
    result = await limiter.acquire(canonical_user_id="u", persona="alfred")
    assert isinstance(result, Dropped)
    assert result.waited_seconds >= 0.5

    capped = audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
    assert capped[-1]["dropped"] is True
    dropped = audit.rows_with_event("comms.inbound.dropped")
    assert len(dropped) == 1
    assert dropped[0]["canonical_user_id"] == "u"
    assert dropped[0]["persona"] == "alfred"
