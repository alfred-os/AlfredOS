"""Unit: ``build_working_memory_pool`` constructs a wired ``WorkingMemoryPool``.

PR-S4-11c-1 extracts the smoke test's inline pool wiring into a reusable
builder. The assertions:

* the returned object is a real :class:`WorkingMemoryPool`, and
* the acquire/release lifecycle the orchestrator adapter drives each turn
  works end-to-end against a stubbed-empty episodic backend (no Postgres):
  ``acquire(key)`` rehydrates one shared :class:`WorkingMemory`, a second
  acquire of the same key returns the SAME instance, and ``release`` returns
  it to the pool without raising.

The builder takes the resolved ``session_scope`` + ``episodic_factory`` from
the caller (``build_orchestrator`` passes the production ones); here we inject
a no-op scope and an empty-episodic factory so the unit test stays
Postgres-free while still exercising the real acquire/release machinery.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from alfred.cli._bootstrap import build_working_memory_pool
from alfred.memory.working import WorkingMemory
from alfred.memory.working_pool import WorkingMemoryPool


class _EmptyEpisodic:
    """Episodic stub whose ``recent`` returns no rows — empty rehydrate."""

    async def recent(self, *, user_id: str, persona: str, limit: int) -> list[Any]:
        return []


@asynccontextmanager
async def _noop_scope() -> AsyncIterator[None]:
    """Session scope that yields nothing — the empty episodic ignores it."""
    yield None


def _settings() -> Any:
    """Duck-typed settings carrying only the pool-cap override field."""

    class _S:
        working_memory_pool_max = None

    return _S()


def test_build_working_memory_pool_returns_pool() -> None:
    pool = build_working_memory_pool(
        _settings(),
        episodic_factory=lambda _session: _EmptyEpisodic(),
        session_scope=_noop_scope,
    )
    assert isinstance(pool, WorkingMemoryPool)


async def test_build_working_memory_pool_acquire_release_lifecycle() -> None:
    pool = build_working_memory_pool(
        _settings(),
        episodic_factory=lambda _session: _EmptyEpisodic(),
        session_scope=_noop_scope,
    )
    key = ("alfred", "operator")

    wm = await pool.acquire(key)
    assert isinstance(wm, WorkingMemory)

    # Same key, still in use → same shared instance (the pool's one-rehydrate
    # contract the smoke test relies on).
    wm_again = await pool.acquire(key)
    assert wm_again is wm

    await pool.release(key, wm)
    await pool.release(key, wm_again)


def test_build_working_memory_pool_honours_settings_cap_override() -> None:
    """An operator ``working_memory_pool_max`` override flows into the pool.

    The cap is observable only through the private ``_max_entries`` the cap
    policy reads; assert the builder threaded the settings field rather than
    leaving the pool on its floor-of-50 default.
    """

    class _S:
        working_memory_pool_max = 77

    pool = build_working_memory_pool(
        _S(),
        episodic_factory=lambda _session: _EmptyEpisodic(),
        session_scope=_noop_scope,
    )
    # ``_cap()`` is the only observable of the override; assert through it.
    assert pool._cap() == 77
