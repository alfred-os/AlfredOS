"""Per-(persona, user_id) WorkingMemory pool.

Owned by alfred-memory-engineer per PR-B spec §3 lines 458-470. The
orchestrator (adapter, Slice 2+) calls :py:meth:`WorkingMemoryPool.acquire`
at top-of-turn and :py:meth:`release` in its ``finally`` clause. A per-key
``asyncio.Lock`` registry serialises lazy rehydrate so concurrent acquires
of the same key produce exactly ONE episodic-load (the PR-B acceptance
gate). LRU eviction operates on idle entries only — an in-use entry can
never be evicted by the cap-driven trim — and the explicit
:py:meth:`evict` escape hatch is what ``IdentityResolver.remove`` calls
when a platform identity is unlinked mid-turn.

The key type is ``tuple[str, str]`` (persona, user_id). Slice 2's first
component is always ``"alfred"``; Slice 4+ widens it for Lucius / Oracle /
Diana. Keeping the persona in the key (rather than splitting per-persona
pools) means the cap is uniform across personas and the eviction policy
sees the whole picture.

Cap precedence:
    * Operator override (``max_entries=N``) wins unconditionally.
    * Otherwise ``max(50, active_user_count() * 2)`` — the floor of 50
      keeps small deployments from thrashing; the ``*2`` headroom covers
      personas-per-user growth in Slice 4+.

Release-on-evicted-key is a deliberate no-op (NOT an error): a mid-turn
``evict()`` followed by the orchestrator's ``finally``-block ``release()``
must not raise — see the PR-B spec policy and the mid-turn-eviction
property test.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working import WorkingMemory

Key = tuple[str, str]
"""(persona, user_id). Persona first so per-persona analytics can group easily."""


@dataclass
class _PoolEntry:
    """One pooled :class:`WorkingMemory` plus its idle-since timestamp."""

    wm: WorkingMemory
    # ``time.monotonic`` not ``time.time``: LRU only needs ordering, and
    # monotonic is immune to wall-clock jumps (ntp slew, DST, manual set).
    last_released_at: float = field(default_factory=time.monotonic)


class WorkingMemoryPool:
    """Per-key pool of lazy-rehydrated :class:`WorkingMemory` buffers."""

    def __init__(
        self,
        *,
        episodic_factory: Callable[[AsyncSession], EpisodicMemory],
        pool_session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
        max_entries: int | None = None,
        active_user_count: Callable[[], int] = lambda: 1,
    ) -> None:
        self._episodic_factory = episodic_factory
        self._pool_session_scope = pool_session_scope
        self._max_entries = max_entries
        self._active_user_count = active_user_count
        self._entries: dict[Key, _PoolEntry] = {}
        # Per-key lock registry. Locks live as long as the key has been
        # touched — they're cheap (a couple of pointers) and rotating them
        # would re-introduce the race they exist to prevent.
        self._locks: dict[Key, asyncio.Lock] = {}
        self._in_use: set[Key] = set()

    def _cap(self) -> int:
        """Resolve the effective per-process pool cap.

        Operator override wins; otherwise ``max(50, active_user_count * 2)``.
        The floor of 50 keeps single-user deployments from thrashing on
        the very first persona switch.
        """
        if self._max_entries is not None:
            return self._max_entries
        return max(50, self._active_user_count() * 2)

    def _get_lock(self, key: Key) -> asyncio.Lock:
        """Return the per-key lock, creating it on first touch.

        We cannot use ``setdefault`` with a fresh ``asyncio.Lock()`` literal
        because that would allocate-and-drop a Lock on every call. The
        explicit get-or-create avoids the churn on the common hit path.
        """
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    async def _rehydrate(self, key: Key) -> WorkingMemory:
        """Build a fresh WorkingMemory and prefill it from episodic.

        Slice 2 uses the default ``max_turns`` — Slice 3 will thread a
        per-user override once Redis takes over the backing store. The
        episodic query is per-persona so persona context never leaks
        across persona boundaries (PRD §5.3 / per-persona-per-user spec).
        """
        persona, user_id = key
        wm = WorkingMemory()
        async with self._pool_session_scope() as session:
            episodic = self._episodic_factory(session)
            recent = await episodic.recent(user_id=user_id, persona=persona, limit=20)
        for ep in recent:
            # ``Episode.role`` is a string column; ``WorkingMemory.append``
            # is typed against ``providers.base.Role`` (a Literal). The
            # CLI's slice-1 wire-in does the same cast — see cli/main.py.
            await wm.append(role=ep.role, content=ep.content)  # type: ignore[arg-type]
        return wm

    async def acquire(self, key: Key) -> WorkingMemory:
        """Return the pooled :class:`WorkingMemory` for ``key``, rehydrating once.

        Concurrent acquires of the same key serialise on the per-key lock
        and produce ONE shared WorkingMemory; concurrent acquires of
        DIFFERENT keys do not block one another. The cap trim happens
        BEFORE marking the new entry in-use so the freshly-acquired key
        cannot evict itself (it's the most-recently-touched entry; the
        cap trim only targets idle entries anyway).
        """
        lock = self._get_lock(key)
        async with lock:
            entry = self._entries.get(key)
            if entry is None:
                wm = await self._rehydrate(key)
                entry = _PoolEntry(wm=wm)
                self._entries[key] = entry
                # Trim BEFORE marking in-use so the brand-new key isn't a
                # candidate. (LRU only considers idle keys anyway, but this
                # is the clearer invariant.)
                self._evict_to_cap()
            self._in_use.add(key)
            return entry.wm

    async def release(self, key: Key, wm: WorkingMemory) -> None:
        """Mark ``key`` idle for LRU. No-op if evicted under us.

        Mid-turn ``evict()`` (IdentityResolver.remove) can drop the entry
        between acquire and release; the orchestrator's finally-block
        release MUST NOT raise in that case. ``wm`` is unused at slice-2
        — kept in the signature so a future "release dirty state back to
        backing store" change doesn't churn callers.
        """
        del wm  # reserved for slice-3 dirty-write-back; intentionally unused.
        self._in_use.discard(key)
        entry = self._entries.get(key)
        if entry is None:
            return
        entry.last_released_at = time.monotonic()

    def evict(self, key: Key) -> None:
        """Force-remove ``key`` from the pool (idempotent).

        Called by ``IdentityResolver.remove`` when a platform identity is
        unlinked. In-use entries CAN be force-evicted — that's the whole
        point of having a separate escape hatch — and any in-flight
        ``release()`` for that key will no-op.

        The per-key lock is INTENTIONALLY kept alive — locks are immortal in
        this registry. Dropping the lock here would split the single-rehydrate
        contract: an in-flight ``acquire()`` may already hold the old lock and
        be awaiting ``_rehydrate``; a fresh ``acquire()`` after evict would
        then ``setdefault`` a new lock and run a parallel rehydrate, producing
        two WorkingMemory objects for the same key. Locks are a couple of
        pointers each, so the bounded leak (one lock per ever-touched key) is
        the right trade against a correctness bug. A re-registered slug
        reuses the same lock harmlessly: contention is on the slug-shaped
        key, not the identity behind it.
        """
        self._entries.pop(key, None)
        self._in_use.discard(key)

    def _evict_to_cap(self) -> None:
        """Trim idle entries oldest-first until we're at or below the cap.

        In-use entries are NEVER eviction candidates — orphaning a
        mid-turn WorkingMemory would silently smear context across turns.
        If the cap is below the in-use count, the pool temporarily
        oversubscribes; the next release will resolve the overshoot.
        """
        cap = self._cap()
        if len(self._entries) <= cap:
            return
        idle_keys = sorted(
            (k for k in self._entries if k not in self._in_use),
            key=lambda k: self._entries[k].last_released_at,
        )
        # Pop oldest idle until we're under cap or out of idle candidates.
        # Locks are immortal (see :meth:`evict` docstring); only the entry is
        # dropped here. A future acquire on the same key reuses the lock and
        # rehydrates fresh — exactly the single-rehydrate guarantee callers
        # rely on.
        while len(self._entries) > cap and idle_keys:
            victim = idle_keys.pop(0)
            self._entries.pop(victim, None)
