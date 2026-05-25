"""Slice-1 budget guard.

Enforces a per-call cost cap and a per-day spend cap. The orchestrator calls
``check_and_charge(estimated_cost)`` BEFORE making the provider call (using an
estimate based on prompt tokens) and ``check_and_charge(actual_cost)`` AFTER
(reconciling). For Slice 1 we use a single charge after the call for
simplicity; per-call upfront estimation lands in Slice 2 with the prompt cache.
"""

from __future__ import annotations

import datetime as dt
import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from alfred.providers.base import CompletionRequest


class BudgetError(RuntimeError):
    """Base for budget-related errors."""


class PerCallCapExceededError(BudgetError):
    """A single call would exceed the per-call cost cap."""


class BudgetExhaustedError(BudgetError):
    """The daily budget is exhausted."""


class BudgetGuard:
    def __init__(self, *, daily_usd: float, per_call_max_usd: float) -> None:
        # Refuse construction with negative caps: a negative cap turns every
        # call into an automatic cap-breach (good) but also lets `would_exceed`
        # / `check_and_charge` produce nonsense for callers reading the values
        # back. Settings already rejects non-positive values at the config
        # boundary; this is the defense in depth for hand-constructed guards
        # (tests, future personas building their own bounded sub-guards).
        # Finite + non-negative: NaN/inf would corrupt `_spent` once charged
        # (`NaN + x` stays `NaN`; cap comparisons silently stop working) and
        # negative caps invert the meaning of the gate.
        if not (math.isfinite(daily_usd) and math.isfinite(per_call_max_usd)):
            raise ValueError(
                "BudgetGuard caps must be finite "
                f"(daily_usd={daily_usd}, per_call_max_usd={per_call_max_usd})"
            )
        if daily_usd < 0 or per_call_max_usd < 0:
            raise ValueError(
                "BudgetGuard caps must be non-negative "
                f"(daily_usd={daily_usd}, per_call_max_usd={per_call_max_usd})"
            )
        self._daily_usd = daily_usd
        self._per_call_max_usd = per_call_max_usd
        self._day = dt.datetime.now(dt.UTC).date()
        self._spent = 0.0

    def _roll_day_if_needed(self) -> None:
        today = dt.datetime.now(dt.UTC).date()
        if today != self._day:
            self._day = today
            self._spent = 0.0

    def check_and_charge(self, cost_usd: float) -> None:
        # A negative `cost_usd` would decrease `_spent` and effectively refund
        # past spend — a free path to bypass the daily cap on subsequent
        # calls. NaN/inf would poison `_spent` once added; cap comparisons
        # stop working. Refuse both at the boundary so providers / tests
        # surface the bug loudly rather than corrupting the running total.
        if not math.isfinite(cost_usd):
            raise ValueError(f"cost_usd must be finite, got {cost_usd}")
        if cost_usd < 0:
            raise ValueError(f"cost_usd must be non-negative, got {cost_usd}")
        if cost_usd > self._per_call_max_usd:
            raise PerCallCapExceededError(
                f"call cost ${cost_usd:.4f} exceeds per-call cap ${self._per_call_max_usd:.2f}"
            )
        self._roll_day_if_needed()
        if self._spent + cost_usd > self._daily_usd:
            raise BudgetExhaustedError(
                f"daily budget ${self._daily_usd:.2f} exhausted (spent ${self._spent:.4f})"
            )
        self._spent += cost_usd

    def estimate_for(self, _request: CompletionRequest) -> float:
        """Estimate the USD cost of a provider call before sending it.

        Slice-1 returns a conservative flat-rate estimate (the per-call cap
        itself) so ``would_exceed`` becomes "is there even cap-worth of budget
        left?". Slice-2 replaces this with a token-aware estimate that reads
        the request's message tokens and the routed provider's published rates.
        Kept as a method (not a property) so slice-2's async token-counting
        path is a drop-in. The leading underscore on ``_request`` flags the
        slice-1 intentional non-use to ruff/pyright; slice-2 will rename.
        """
        return self._per_call_max_usd

    def would_exceed(self, cost_usd: float) -> bool:
        """Return True iff charging ``cost_usd`` would breach either cap.

        Called by the orchestrator BEFORE the provider call so an over-budget
        request is refused without spending money on it. ``check_and_charge``
        reconciles to the actual cost after the call.
        """
        # Mirror `check_and_charge`'s non-negative invariant: a negative
        # `cost_usd` would falsely report "not exceeded" for a request whose
        # actual sign is the bug. Surface it loudly rather than letting it
        # propagate as a free pass through the pre-check. Finite check
        # rejects NaN/inf for the same reason as the constructor.
        if not math.isfinite(cost_usd):
            raise ValueError(f"cost_usd must be finite, got {cost_usd}")
        if cost_usd < 0:
            raise ValueError(f"cost_usd must be non-negative, got {cost_usd}")
        if cost_usd > self._per_call_max_usd:
            return True
        self._roll_day_if_needed()
        return self._spent + cost_usd > self._daily_usd

    def spent_today(self) -> float:
        self._roll_day_if_needed()
        return self._spent
