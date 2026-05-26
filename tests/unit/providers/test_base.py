"""Tests for the provider plugin contract models.

Field validators here are load-bearing for budget integrity: a negative cost
slipped into a CompletionResponse would let the budget guard's running total
go backwards and bypass the daily cap.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.providers.base import CompletionRequest, CompletionResponse, Message


class TestCompletionRequestValidators:
    def test_max_tokens_positive_accepts_default(self) -> None:
        # Sanity: the default value (1024) survives validation.
        req = CompletionRequest(messages=[Message(role="user", content="hi")])
        assert req.max_tokens == 1024

    def test_max_tokens_positive_accepts_one(self) -> None:
        req = CompletionRequest(messages=[Message(role="user", content="hi")], max_tokens=1)
        assert req.max_tokens == 1

    def test_max_tokens_rejects_zero(self) -> None:
        with pytest.raises(ValidationError, match="max_tokens must be > 0"):
            CompletionRequest(messages=[Message(role="user", content="hi")], max_tokens=0)

    def test_max_tokens_rejects_negative(self) -> None:
        with pytest.raises(ValidationError, match="max_tokens must be > 0"):
            CompletionRequest(messages=[Message(role="user", content="hi")], max_tokens=-5)


class TestCompletionResponseValidators:
    def _ok_kwargs(self, **overrides: object) -> dict[str, object]:
        base: dict[str, object] = {
            "content": "hi",
            "tokens_in": 1,
            "tokens_out": 1,
            "cost_usd": 0.0001,
            "model": "deepseek-chat",
        }
        base.update(overrides)
        return base

    def test_zero_values_are_allowed(self) -> None:
        # Zero usage/cost is legal (e.g. cached responses); only negatives bite.
        resp = CompletionResponse(**self._ok_kwargs(tokens_in=0, tokens_out=0, cost_usd=0.0))  # type: ignore[arg-type]
        assert resp.tokens_in == 0
        assert resp.cost_usd == 0.0

    def test_negative_tokens_in_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must be >= 0"):
            CompletionResponse(**self._ok_kwargs(tokens_in=-1))  # type: ignore[arg-type]

    def test_negative_tokens_out_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must be >= 0"):
            CompletionResponse(**self._ok_kwargs(tokens_out=-1))  # type: ignore[arg-type]

    def test_negative_cost_rejected(self) -> None:
        # Defends the budget guard: a negative cost would refund past spend.
        with pytest.raises(ValidationError, match="must be >= 0"):
            CompletionResponse(**self._ok_kwargs(cost_usd=-0.01))  # type: ignore[arg-type]
