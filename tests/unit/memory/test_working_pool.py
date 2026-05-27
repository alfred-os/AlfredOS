"""Tests for the per-(persona, user_id) WorkingMemoryPool.

PR-B Phase 2 contract tests. The pool is the orchestrator's top-of-turn
acquisition point for per-user working memory — every assertion here is a
release-blocker, especially the concurrency tests around lazy rehydrate
(any cross-user smear or double-rehydrate is a memory-correctness bug
that would surface as wrong-prompt-to-LLM).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from alfred.memory.episodic import EpisodicMemory
from alfred.memory.models import Episode
from alfred.memory.working import WorkingMemory
from alfred.memory.working_pool import WorkingMemoryPool


class _FakeEpisodic:
    """In-memory ``EpisodicMemory.recent`` stand-in that counts calls.

    PR-B Phase 2 doesn't need the writer surface here — the pool only
    calls ``recent(...)`` on rehydrate. Counting lets the concurrency
    test prove single-rehydrate-per-key.
    """

    def __init__(self, *, rows: list[Episode] | None = None, sleep: float = 0.0) -> None:
        self._rows = rows or []
        self._sleep = sleep
        self.calls: list[dict[str, object]] = []

    async def recent(
        self, *, user_id: str, limit: int = 20, persona: str | None = None
    ) -> list[Episode]:
        self.calls.append({"user_id": user_id, "limit": limit, "persona": persona})
        if self._sleep:
            await asyncio.sleep(self._sleep)
        return [
            r
            for r in self._rows
            if r.user_id == user_id and (persona is None or r.persona == persona)
        ]


@asynccontextmanager
async def _noop_session_scope() -> AsyncIterator[object]:
    """Yield a sentinel — the fake episodic doesn't touch the session."""
    yield object()


def _make_pool(
    episodic: _FakeEpisodic,
    *,
    max_entries: int | None = None,
    active_user_count: int = 1,
) -> WorkingMemoryPool:
    return WorkingMemoryPool(
        episodic_factory=lambda _s: cast(EpisodicMemory, episodic),
        pool_session_scope=_noop_session_scope,
        max_entries=max_entries,
        active_user_count=lambda: active_user_count,
    )


@pytest.mark.asyncio
class TestAcquireBasics:
    async def test_acquire_returns_wm_instance(self) -> None:
        pool = _make_pool(_FakeEpisodic())
        wm = await pool.acquire(("alfred", "alice"))
        assert isinstance(wm, WorkingMemory)

    async def test_acquire_same_key_returns_same_instance(self) -> None:
        pool = _make_pool(_FakeEpisodic())
        wm1 = await pool.acquire(("alfred", "alice"))
        await pool.release(("alfred", "alice"), wm1)
        wm2 = await pool.acquire(("alfred", "alice"))
        assert wm1 is wm2

    async def test_persona_key_independence(self) -> None:
        pool = _make_pool(_FakeEpisodic())
        wm_alfred = await pool.acquire(("alfred", "alice"))
        wm_lucius = await pool.acquire(("lucius", "alice"))
        assert wm_alfred is not wm_lucius


@pytest.mark.asyncio
class TestRehydrate:
    async def test_rehydrate_populates_working_memory_from_episodic(self) -> None:
        rows = [
            Episode(user_id="alice", persona="alfred", role="user", content="hi", trust_tier="T2"),
            Episode(
                user_id="alice",
                persona="alfred",
                role="assistant",
                content="hello",
                trust_tier="T2",
            ),
        ]
        episodic = _FakeEpisodic(rows=rows)
        pool = _make_pool(episodic)
        wm = await pool.acquire(("alfred", "alice"))
        turns = await wm.turns()
        assert [t.content for t in turns] == ["hi", "hello"]
        assert episodic.calls[0]["persona"] == "alfred"
        assert episodic.calls[0]["user_id"] == "alice"

    async def test_concurrent_lazy_rehydrate_runs_once(self) -> None:
        """The PR-B acceptance gate: N concurrent acquires of the same key
        produce exactly ONE rehydrate call. The per-key lock is what makes
        this true; without it, every concurrent acquire would race the
        episodic-load and we'd get N duplicate WorkingMemory instances
        (and N duplicate sets of rehydrated turns)."""
        episodic = _FakeEpisodic(sleep=0.01)  # widen the race window
        pool = _make_pool(episodic)
        results = await asyncio.gather(*(pool.acquire(("alfred", "alice")) for _ in range(16)))
        assert len(episodic.calls) == 1
        first = results[0]
        for r in results[1:]:
            assert r is first


@pytest.mark.asyncio
class TestLRUEviction:
    async def test_release_marks_idle_for_lru(self) -> None:
        pool = _make_pool(_FakeEpisodic(), max_entries=2)
        wm_a = await pool.acquire(("alfred", "alice"))
        await pool.release(("alfred", "alice"), wm_a)
        wm_b = await pool.acquire(("alfred", "bob"))
        await pool.release(("alfred", "bob"), wm_b)
        # Filling the cap should now evict the LRU idle one (alice).
        await pool.acquire(("alfred", "carol"))
        # Re-acquiring alice should miss the cache and rehydrate fresh.
        wm_a2 = await pool.acquire(("alfred", "alice"))
        assert wm_a2 is not wm_a

    async def test_lru_skips_in_use(self) -> None:
        """LRU MUST NOT evict an in-use entry. Acquire A, B, C with pool_max=2;
        re-acquire A (now in-use); D should evict B (idle, LRU), not A.
        Eviction of an in-use entry would orphan the orchestrator mid-turn."""
        pool = _make_pool(_FakeEpisodic(), max_entries=2)
        wm_a = await pool.acquire(("alfred", "alice"))
        await pool.release(("alfred", "alice"), wm_a)
        wm_b = await pool.acquire(("alfred", "bob"))
        await pool.release(("alfred", "bob"), wm_b)
        # Re-acquire A — it's now in-use AND most-recently-touched.
        wm_a_again = await pool.acquire(("alfred", "alice"))
        assert wm_a_again is wm_a
        # D forces an eviction. B (idle) is the victim; A (in-use) survives.
        await pool.acquire(("alfred", "dave"))
        # B should be gone — re-acquiring it produces a NEW instance.
        wm_b2 = await pool.acquire(("alfred", "bob"))
        assert wm_b2 is not wm_b
        # A is still the same instance — never evicted because in-use.
        wm_a_still = await pool.acquire(("alfred", "alice"))
        assert wm_a_still is wm_a


@pytest.mark.asyncio
class TestEvict:
    async def test_evict_removes_unconditionally(self) -> None:
        pool = _make_pool(_FakeEpisodic())
        wm = await pool.acquire(("alfred", "alice"))
        await pool.release(("alfred", "alice"), wm)
        pool.evict(("alfred", "alice"))
        wm2 = await pool.acquire(("alfred", "alice"))
        assert wm2 is not wm

    async def test_evict_then_release_is_noop(self) -> None:
        """Mid-turn evict (e.g. IdentityResolver.remove) followed by the
        orchestrator's finally-block release MUST NOT raise. Spec policy:
        release is a no-op when the entry is gone."""
        pool = _make_pool(_FakeEpisodic())
        wm = await pool.acquire(("alfred", "alice"))
        pool.evict(("alfred", "alice"))  # force-remove while in-use
        # Should NOT raise.
        await pool.release(("alfred", "alice"), wm)


@pytest.mark.asyncio
class TestPerKeyLock:
    async def test_per_key_asyncio_lock(self) -> None:
        """Two acquires of DIFFERENT keys must not serialise on each other.

        We start two acquires; the slow one holds its rehydrate for 50ms.
        If keys shared a lock, the fast one would wait ~50ms behind the slow
        one. With per-key locks, they overlap and total ≈ slow one alone.
        """
        slow_ep = _FakeEpisodic(sleep=0.05)
        # Both use the same pool; the pool internally owns the locks.
        pool = _make_pool(slow_ep)
        t0 = asyncio.get_event_loop().time()
        await asyncio.gather(
            pool.acquire(("alfred", "alice")),
            pool.acquire(("alfred", "bob")),
        )
        elapsed = asyncio.get_event_loop().time() - t0
        # Strict serial would be ~100ms; per-key parallel is ~50ms. Use 80ms
        # as a comfortable upper bound that still catches a regression to
        # shared-lock behaviour.
        assert elapsed < 0.08, f"keys appear to share a lock; elapsed={elapsed:.3f}s"


@pytest.mark.asyncio
class TestCapPrecedence:
    async def test_cap_precedence_operator_override_wins(self) -> None:
        pool = _make_pool(_FakeEpisodic(), max_entries=50, active_user_count=1000)
        # Internal probe is fine: the cap formula is a public contract.
        assert pool._cap() == 50

    async def test_cap_precedence_auto_formula_when_unset(self) -> None:
        pool = _make_pool(_FakeEpisodic(), max_entries=None, active_user_count=30)
        # max(50, 30 * 2) = 60.
        assert pool._cap() == 60

    async def test_cap_floor_is_fifty(self) -> None:
        pool = _make_pool(_FakeEpisodic(), max_entries=None, active_user_count=1)
        # max(50, 1 * 2) = 50.
        assert pool._cap() == 50


@pytest.mark.asyncio
class TestMidTurnEviction:
    @settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(n=st.integers(min_value=2, max_value=8))
    async def test_mid_turn_eviction_does_not_break_release(self, n: int) -> None:
        """Property: N concurrent acquire/release pairs against pool_max=1
        never raise from release(), even when the LRU policy is evicting
        siblings between the acquire and the release."""
        pool = _make_pool(_FakeEpisodic(), max_entries=1)

        async def turn(uid: str) -> None:
            wm = await pool.acquire(("alfred", uid))
            await asyncio.sleep(0)  # yield so other turns can race
            await pool.release(("alfred", uid), wm)

        await asyncio.gather(*(turn(f"u{i}") for i in range(n)))
