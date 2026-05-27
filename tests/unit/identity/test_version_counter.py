"""Unit tests for ``alfred.identity.version_counter.IdentityVersionCounter``.

The counter is a bump-on-mutate primitive: it starts at zero, strictly
increases by one on every :meth:`bump`, and is safe to bump concurrently
from multiple threads / coroutines (the listener task in T12 lives on a
different loop-thread than the resolver in T11).

These tests pin the three guarantees consumers rely on:

* monotonic — every bump advances ``current()`` by exactly one,
* deterministic — N bumps yield version N regardless of how they're
  scheduled,
* lock-correct — concurrent bumps never lose updates.
"""

from __future__ import annotations

import asyncio

from hypothesis import given, settings
from hypothesis import strategies as st

from alfred.identity.version_counter import IdentityVersionCounter


def test_current_starts_at_zero() -> None:
    counter = IdentityVersionCounter()

    assert counter.current() == 0


def test_bump_increments_monotonically() -> None:
    counter = IdentityVersionCounter()

    counter.bump()
    counter.bump()
    counter.bump()

    assert counter.current() == 3


@given(n=st.integers(min_value=0, max_value=200))
@settings(max_examples=50)
def test_n_bumps_yield_n_version(n: int) -> None:
    counter = IdentityVersionCounter()

    for _ in range(n):
        counter.bump()

    assert counter.current() == n


def test_concurrent_bump_no_lost_updates() -> None:
    counter = IdentityVersionCounter()

    async def _bump_once() -> None:
        # Yield once so the scheduler actually interleaves the coroutines
        # instead of running them serially.
        await asyncio.sleep(0)
        counter.bump()

    async def _race() -> None:
        async with asyncio.TaskGroup() as tg:
            for _ in range(100):
                tg.create_task(_bump_once())

    asyncio.run(_race())

    assert counter.current() == 100
