"""Tests for the daily / per-call budget guard."""

from __future__ import annotations

import datetime as dt
from unittest.mock import MagicMock

import pytest

from alfred.budget.guard import BudgetExhaustedError, BudgetGuard, PerCallCapExceededError
from alfred.providers.base import CompletionRequest, Message


class TestBudgetGuard:
    def test_allows_calls_within_daily_budget(self) -> None:
        guard = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)
        guard.check_and_charge(0.05)  # ok
        guard.check_and_charge(0.05)  # still ok
        assert guard.spent_today() == 0.10

    def test_rejects_single_call_over_per_call_cap(self) -> None:
        guard = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)
        with pytest.raises(PerCallCapExceededError):
            guard.check_and_charge(0.20)

    def test_blocks_when_daily_budget_exhausted(self) -> None:
        guard = BudgetGuard(daily_usd=0.10, per_call_max_usd=0.10)
        guard.check_and_charge(0.10)
        with pytest.raises(BudgetExhaustedError):
            guard.check_and_charge(0.01)

    def test_budget_resets_on_new_day(self) -> None:
        guard = BudgetGuard(daily_usd=0.10, per_call_max_usd=0.10)
        guard.check_and_charge(0.10)
        # Simulate the day rolling over by tickling internal state.
        guard._day = dt.datetime.now(dt.UTC).date() - dt.timedelta(days=1)
        guard._spent = 0.10
        # The next check sees a new day and resets.
        guard.check_and_charge(0.05)
        assert guard.spent_today() == 0.05


class TestWouldExceed:
    """Coverage for the pre-call ``would_exceed`` predicate.

    ``check_and_charge`` raises after the call; ``would_exceed`` is what the
    orchestrator uses BEFORE the call to refuse over-budget requests without
    spending money on them. Distinct code path; needs its own coverage.
    """

    def test_would_exceed_returns_true_when_estimate_over_per_call_cap(self) -> None:
        guard = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)
        # 0.20 > 0.10 per-call cap, regardless of daily budget headroom.
        assert guard.would_exceed(0.20) is True

    def test_would_exceed_returns_true_when_daily_remaining_insufficient(self) -> None:
        guard = BudgetGuard(daily_usd=0.10, per_call_max_usd=0.10)
        guard.check_and_charge(0.08)
        # 0.08 already spent; 0.05 more would push us to 0.13 > 0.10 daily cap.
        assert guard.would_exceed(0.05) is True

    def test_would_exceed_returns_false_when_within_caps(self) -> None:
        guard = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)
        assert guard.would_exceed(0.05) is False

    def test_would_exceed_rolls_day_when_called_at_midnight_boundary(self) -> None:
        guard = BudgetGuard(daily_usd=0.10, per_call_max_usd=0.10)
        guard.check_and_charge(0.10)  # daily cap fully spent
        # Roll the clock back by a day via internal state — same pattern as
        # test_budget_resets_on_new_day above. would_exceed must re-evaluate
        # against the fresh day, not yesterday's spend.
        guard._day = dt.datetime.now(dt.UTC).date() - dt.timedelta(days=1)
        guard._spent = 0.10
        assert guard.would_exceed(0.05) is False


class TestNonNegativeInvariants:
    """The guard rejects negative caps and costs at every boundary.

    A negative ``cost_usd`` in ``check_and_charge`` would subtract from the
    running total and silently refund past spend, opening a daily-cap bypass.
    A negative cap in the constructor would produce nonsense reads from
    ``would_exceed`` / ``spent_today``. These tests pin the invariants so a
    future provider that returns a negative cost surfaces the bug loudly.
    """

    def test_constructor_rejects_negative_daily_cap(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            BudgetGuard(daily_usd=-1.0, per_call_max_usd=0.10)

    def test_constructor_rejects_negative_per_call_cap(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            BudgetGuard(daily_usd=1.0, per_call_max_usd=-0.01)

    def test_check_and_charge_rejects_negative_cost(self) -> None:
        guard = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)
        with pytest.raises(ValueError, match="non-negative"):
            guard.check_and_charge(-0.01)
        # Running total must remain untouched after the rejection.
        assert guard.spent_today() == 0.0

    def test_would_exceed_rejects_negative_cost(self) -> None:
        guard = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)
        with pytest.raises(ValueError, match="non-negative"):
            guard.would_exceed(-0.01)


class TestEstimateFor:
    def test_estimate_for_returns_per_call_cap_as_slice_1_conservative_estimate(self) -> None:
        guard = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)
        # Slice 1 is intentionally conservative: every request is estimated at
        # the per-call cap so would_exceed reduces to "is there cap-worth of
        # budget left?". Slice 2 lands token-aware estimation.
        request = CompletionRequest(messages=[Message(role="user", content="hi")])
        assert guard.estimate_for(request) == 0.10

    def test_estimate_for_ignores_request_contents(self) -> None:
        # Defends the slice-1 contract: until the token-aware estimator lands,
        # a 10-token and a 10000-token request must price the same.
        guard = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.07)
        small = CompletionRequest(messages=[Message(role="user", content="hi")])
        big_msg = "x " * 5000
        big = CompletionRequest(messages=[Message(role="user", content=big_msg)])
        assert guard.estimate_for(small) == guard.estimate_for(big) == 0.07
        # MagicMock stands in for a request shape that doesn't yet exist —
        # confirms estimate_for never even reads the request.
        assert guard.estimate_for(MagicMock()) == 0.07
