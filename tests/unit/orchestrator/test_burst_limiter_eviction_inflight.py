"""Eviction must never drop a key with an in-flight ``acquire()`` (CR #232).

``acquire()`` holds the per-key lock across ``_backpressure()``'s sleep. The LRU
eviction in ``_evict_if_needed`` runs from a CONCURRENT acquire for a different
key, and -- before the fix -- could ``popitem`` the bucket + lock of the key
that is mid-flight. The next acquire for that same ``(canonical_user_id,
persona)`` then allocated a fresh full bucket and a brand-new lock, bypassing the
outstanding wait/drop state entirely: under key churn, eviction became a
same-key rate-limit bypass.

The fix refcounts in-flight keys and skips them during eviction, evicting the
oldest IDLE key instead. These tests pin both halves: the in-flight key's bucket
+ lock survive churn, and idle keys are still evicted so the memory bound holds.
"""

from __future__ import annotations

import asyncio

from alfred.orchestrator.burst_limiter import Acquired, BurstLimiter

from ._burst_spies import SpyAuditWriter

_VICTIM_KEY = ("victim", "alfred")


async def test_inflight_key_bucket_and_lock_survive_churn() -> None:
    # capacity=1 so the second same-key acquire must back-pressure (hold the
    # lock across the sleep). max_tracked_buckets=1 makes eviction maximally
    # aggressive: any new key would otherwise evict the held one.
    churn_started = asyncio.Event()
    release_sleep = asyncio.Event()

    async def fake_sleep(_seconds: float) -> None:
        # We are now INSIDE _backpressure, holding the victim key's lock. Let
        # the churn task run while we are parked here, then wait for its signal.
        churn_started.set()
        await release_sleep.wait()

    limiter = BurstLimiter(
        capacity_tokens=1,
        refill_seconds=1.0,
        drop_after_seconds=30.0,
        audit_writer=SpyAuditWriter(),
        max_tracked_buckets=1,
        sleep=fake_sleep,
    )

    # Drain the victim's single token so the next acquire back-pressures.
    first = await limiter.acquire(canonical_user_id="victim", persona="alfred")
    assert isinstance(first, Acquired)

    # Capture the live bucket + lock objects for the victim key.
    victim_bucket = limiter._buckets[_VICTIM_KEY]
    victim_lock = limiter._locks[_VICTIM_KEY]

    async def victim_backpressure() -> Acquired | object:
        return await limiter.acquire(canonical_user_id="victim", persona="alfred")

    async def churn() -> None:
        await churn_started.wait()
        # Push a flood of distinct keys past the cap while the victim is parked
        # mid-backpressure. With the bug, this evicts the victim's bucket+lock.
        for i in range(20):
            await limiter.acquire(canonical_user_id=f"churn_{i}", persona="alfred")
        release_sleep.set()

    victim_task = asyncio.create_task(victim_backpressure())
    churn_task = asyncio.create_task(churn())
    await asyncio.gather(victim_task, churn_task)

    assert isinstance(victim_task.result(), Acquired)

    # The in-flight key MUST still be tracked, and it MUST be the SAME bucket +
    # lock objects -- not a fresh full bucket re-minted after a mid-flight evict.
    assert _VICTIM_KEY in limiter._buckets, "in-flight key was evicted mid-acquire"
    assert limiter._buckets[_VICTIM_KEY] is victim_bucket
    assert limiter._locks[_VICTIM_KEY] is victim_lock


async def test_all_keys_in_flight_no_eviction() -> None:
    # When EVERY tracked key has an in-flight acquire, eviction must drop
    # nothing rather than corrupt a parked coroutine (the ``None`` branch of
    # ``_oldest_idle_key``). The map is allowed to overshoot the cap until a key
    # goes idle. Two distinct keys are parked mid-backpressure while a third
    # acquire forces an eviction pass with no idle candidate.
    parked = asyncio.Event()
    release = asyncio.Event()
    park_count = [0]

    async def fake_sleep(_seconds: float) -> None:
        park_count[0] += 1
        if park_count[0] >= 2:
            parked.set()
        await release.wait()

    # max_tracked_buckets=2 keeps both a and b resident through their drains;
    # the eviction pressure comes only when c is added (len 3 > 2).
    limiter = BurstLimiter(
        capacity_tokens=1,
        refill_seconds=1.0,
        drop_after_seconds=30.0,
        audit_writer=SpyAuditWriter(),
        max_tracked_buckets=2,
        sleep=fake_sleep,
    )

    # Drain both keys so their follow-up acquires back-pressure (and park).
    await limiter.acquire(canonical_user_id="a", persona="alfred")
    await limiter.acquire(canonical_user_id="b", persona="alfred")

    park_a = asyncio.create_task(limiter.acquire(canonical_user_id="a", persona="alfred"))
    park_b = asyncio.create_task(limiter.acquire(canonical_user_id="b", persona="alfred"))
    await parked.wait()

    # Both a and b are now in-flight (active). A fresh key acquire runs an
    # eviction pass that finds NO idle key -> nothing is evicted, both survive.
    await limiter.acquire(canonical_user_id="c", persona="alfred")
    assert ("a", "alfred") in limiter._buckets
    assert ("b", "alfred") in limiter._buckets

    release.set()
    await asyncio.gather(park_a, park_b)


async def test_same_key_concurrent_acquires_refcount_decrements() -> None:
    # Two concurrent acquires for the SAME key drive the refcount to 2. As each
    # finishes the count decrements one at a time, so it stays > 0 (the key is
    # still in-flight) until the last finishes -- exercising the partial-release
    # branch of the active refcount.
    release = asyncio.Event()
    parked = [0]

    async def fake_sleep(_seconds: float) -> None:
        parked[0] += 1
        await release.wait()

    limiter = BurstLimiter(
        capacity_tokens=2,
        refill_seconds=1.0,
        drop_after_seconds=30.0,
        audit_writer=SpyAuditWriter(),
        sleep=fake_sleep,
    )
    # Drain both tokens so the next two same-key acquires back-pressure.
    await limiter.acquire(canonical_user_id="k", persona="alfred")
    await limiter.acquire(canonical_user_id="k", persona="alfred")

    t1 = asyncio.create_task(limiter.acquire(canonical_user_id="k", persona="alfred"))
    t2 = asyncio.create_task(limiter.acquire(canonical_user_id="k", persona="alfred"))
    await asyncio.sleep(0)  # let both register as in-flight
    assert limiter._active[("k", "alfred")] == 2

    release.set()
    results = await asyncio.gather(t1, t2)
    assert all(isinstance(r, Acquired) for r in results)
    # Both released: the key is no longer in-flight.
    assert ("k", "alfred") not in limiter._active


async def test_idle_keys_are_still_evicted() -> None:
    # No in-flight acquires: the memory bound must still hold (regression guard
    # that the refcount skip does not disable eviction outright).
    limiter = BurstLimiter(
        capacity_tokens=5,
        refill_seconds=5.0,
        audit_writer=SpyAuditWriter(),
        max_tracked_buckets=2,
    )
    for i in range(10):
        await limiter.acquire(canonical_user_id=f"u_{i}", persona="alfred")
    assert limiter.tracked_bucket_count == 2
