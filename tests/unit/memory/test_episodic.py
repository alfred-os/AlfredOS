"""Tests for the episodic memory writer/loader."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.memory.episodic import EpisodicMemory
from alfred.memory.models import Episode


def _mock_session() -> AsyncMock:
    """AsyncSession surrogate: `add` is sync (override the AsyncMock default);
    `flush` / `execute` stay async."""
    session = AsyncMock()
    session.add = MagicMock()
    return session


@pytest.mark.asyncio
class TestEpisodicMemory:
    async def test_record_writes_user_and_assistant_turns_in_order(self) -> None:
        session = _mock_session()
        mem = EpisodicMemory(session=session)
        await mem.record(
            user_id="operator",
            role="user",
            content="hi",
            trust_tier="T2",
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            language="en-US",
        )
        await mem.record(
            user_id="operator",
            role="assistant",
            content="hi back",
            # ADR-0008: assistant output in Slice 1 is T2, not T0 (at-most-as-
            # trusted as the T2 input that triggered it). T0 is reserved for
            # AlfredOS internals.
            trust_tier="T2",
            tokens_in=10,
            tokens_out=3,
            cost_usd=0.00001,
            language="en-US",
        )
        assert session.add.call_count == 2
        assert session.flush.await_count == 2
        # Assert the persisted ORDER and PAYLOAD, not just counts. Counts pass
        # even if the writer swaps the two adds — exactly the regression class
        # this test exists to catch.
        first = session.add.call_args_list[0].args[0]
        second = session.add.call_args_list[1].args[0]
        assert first.role == "user"
        assert first.content == "hi"
        assert first.trust_tier == "T2"
        assert second.role == "assistant"
        assert second.content == "hi back"
        assert second.trust_tier == "T2"

    async def test_recent_returns_last_n_turns_oldest_first(self) -> None:
        session = _mock_session()
        e1 = Episode(user_id="operator", role="user", content="a", trust_tier="T2")
        # ADR-0008: Slice-1 assistant turns are T2, not T0.
        e2 = Episode(user_id="operator", role="assistant", content="b", trust_tier="T2")

        result = MagicMock()
        result.scalars.return_value.all.return_value = [e2, e1]  # DB returned newest first
        session.execute = AsyncMock(return_value=result)

        mem = EpisodicMemory(session=session)
        turns = await mem.recent(user_id="operator", limit=2)
        # Caller-facing list is in chronological order (oldest first).
        assert [t.content for t in turns] == ["a", "b"]
