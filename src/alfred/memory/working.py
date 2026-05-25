"""In-process working memory for Slice 1.

A bounded FIFO buffer of the most recent N turns. Used by the orchestrator
to assemble the prompt for the next provider call. Slice 4+ adds richer
memory layers; Slice 1 keeps this dirt simple.

Per ADR-0002, the public interface is async (even though the slice-1 body is
sync against a `deque`) so the slice-3 Redis swap is purely backend-internal.
Mutations and reads serialize through `asyncio.Lock` for the same reason.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass

from alfred.providers.base import Role


@dataclass(slots=True, frozen=True)
class Turn:
    role: Role
    content: str


class WorkingMemory:
    """A bounded async buffer of recent conversation turns for one (persona, user) pair."""

    def __init__(self, *, max_turns: int = 40) -> None:
        # `deque(maxlen=0)` silently drops every append, which would silently
        # disable retained context across an entire conversation — surface
        # the bug at construction. Same reasoning for negative values: deque
        # accepts negatives but the semantics ("retain N turns where N<0") are
        # nonsense and almost always indicate a config/wiring bug upstream.
        if max_turns <= 0:
            raise ValueError(f"max_turns must be > 0, got {max_turns}")
        self._buf: deque[Turn] = deque(maxlen=max_turns)
        self._lock = asyncio.Lock()

    async def append(self, *, role: Role, content: str) -> None:
        async with self._lock:
            self._buf.append(Turn(role=role, content=content))

    async def turns(self) -> list[Turn]:
        async with self._lock:
            return list(self._buf)

    async def clear(self) -> None:
        async with self._lock:
            self._buf.clear()
