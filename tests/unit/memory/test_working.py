"""Tests for the working-memory turn buffer."""

from __future__ import annotations

import pytest

from alfred.memory.working import WorkingMemory


@pytest.mark.asyncio
class TestWorkingMemory:
    async def test_appends_and_returns_turns_in_order(self) -> None:
        mem = WorkingMemory(max_turns=10)
        await mem.append(role="user", content="hi")
        await mem.append(role="assistant", content="hello")
        turns = await mem.turns()
        assert [t.role for t in turns] == ["user", "assistant"]
        assert turns[1].content == "hello"

    async def test_evicts_oldest_when_over_capacity(self) -> None:
        mem = WorkingMemory(max_turns=2)
        await mem.append(role="user", content="one")
        await mem.append(role="assistant", content="two")
        await mem.append(role="user", content="three")
        turns = await mem.turns()
        assert [t.content for t in turns] == ["two", "three"]

    async def test_clear_empties_the_buffer(self) -> None:
        mem = WorkingMemory(max_turns=4)
        await mem.append(role="user", content="hi")
        await mem.clear()
        assert await mem.turns() == []


class TestMaxTurnsValidation:
    """``max_turns`` must be a positive int.

    ``deque(maxlen=0)`` silently drops every append (and a negative maxlen is
    nonsense), so a 0/negative value would disable retained context for the
    entire conversation without any signal. Pin the invariant at construction
    so the misconfig surfaces immediately.
    """

    def test_rejects_zero_max_turns(self) -> None:
        with pytest.raises(ValueError, match="max_turns must be > 0"):
            WorkingMemory(max_turns=0)

    def test_rejects_negative_max_turns(self) -> None:
        with pytest.raises(ValueError, match="max_turns must be > 0"):
            WorkingMemory(max_turns=-1)
