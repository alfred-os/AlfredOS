"""``BurstLimiterPolicy`` default + bounds (PR-S4-4 Task 3, foundation gap #1).

Cross-PR contract anchor: PR-S4-8's ``BurstLimiter`` reads
``capacity_tokens`` / ``refill_seconds`` from this model. The default
(5 tokens, 5.0 s refill) is pinned here so PR-S4-8 cannot drift the
shape silently. ``BurstLimiterPolicy`` ships in THIS PR (closure
arch-002 / foundation gap #1) even though PR-S4-0a was supposed to.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from alfred.policies.model import BurstLimiterPolicy


def test_default_matches_pr_s4_8_contract() -> None:
    p = BurstLimiterPolicy()
    assert p.capacity_tokens == 5
    assert p.refill_seconds == 5.0


@given(
    capacity=st.integers(min_value=1, max_value=100),
    refill=st.floats(min_value=0.5, max_value=60.0, allow_nan=False),
)
def test_valid_bounds_accepted(capacity: int, refill: float) -> None:
    p = BurstLimiterPolicy(capacity_tokens=capacity, refill_seconds=refill)
    assert p.capacity_tokens == capacity
    assert p.refill_seconds == refill


@pytest.mark.parametrize("capacity", [0, -1, 101])
def test_capacity_out_of_bounds_rejected(capacity: int) -> None:
    with pytest.raises(ValidationError):
        BurstLimiterPolicy(capacity_tokens=capacity)


@pytest.mark.parametrize("refill", [0.0, 0.4, 60.1])
def test_refill_out_of_bounds_rejected(refill: float) -> None:
    with pytest.raises(ValidationError):
        BurstLimiterPolicy(refill_seconds=refill)


def test_burst_limiter_is_frozen() -> None:
    p = BurstLimiterPolicy()
    with pytest.raises(ValidationError):
        p.capacity_tokens = 9  # type: ignore[misc]
