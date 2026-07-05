"""Hypothesis stateful property: ZCARD(alfred:handles:user:{u}) <= cap
for all interleavings of reserve / release / expire / aclose.

Complements the example-based race tests in test_handle_cap.py (which fix
n=2 / n=6). The state machine explores random interleavings and shrinks
to a minimal counterexample on any invariant violation.

Event-loop discipline: we maintain ONE asyncio loop per state-machine
instance and drive every async method through it via ``_run`` (i.e.
``loop.run_until_complete``). Calling ``asyncio.run`` per rule would build
+ tear down a fresh loop on every step, which breaks the
``redis.asyncio`` connection-pool's loop affinity (the pool binds to the
loop on first use; subsequent loops see "got Future attached to a
different loop" errors) and makes shrinking flaky. This shape matches the
perf-006 precedent of a process-long-lived client.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Iterator
from typing import TypeVar, cast

import pytest
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    rule,
    run_state_machine_as_test,
)
from hypothesis.strategies import DataObject
from testcontainers.redis import RedisContainer

from alfred.plugins.web_fetch.errors import WebFetchRateLimited
from alfred.plugins.web_fetch.handle_cap import HandleCap, HandleCapConfig

_T = TypeVar("_T")


@pytest.fixture(scope="module")
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:8-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


class HandleCapStateMachine(RuleBasedStateMachine):
    """State machine modelling reserve / release / direct-expire operations
    against a per-user ZSET with cap=3. Invariant: ZCARD(any user) <= 3.

    One loop per state-machine instance; never ``asyncio.run`` in rules.
    """

    CAP = 3

    def __init__(self, redis_url: str) -> None:
        super().__init__()
        self.loop = asyncio.new_event_loop()
        self.hc = HandleCap(
            redis_url=redis_url,
            config=HandleCapConfig(per_user=self.CAP),
        )
        self.user_id = f"user-{uuid.uuid4()}"
        self.live: set[str] = set()

    def _run(self, coro: Awaitable[_T]) -> _T:
        return self.loop.run_until_complete(coro)

    @rule(handle_id=st.uuids().map(str))
    def reserve(self, handle_id: str) -> None:
        try:
            self._run(
                self.hc.try_reserve(
                    user_id=self.user_id,
                    handle_id=handle_id,
                    handle_ttl_seconds=60,
                )
            )
            self.live.add(handle_id)
        except WebFetchRateLimited:
            pass

    @rule(data=st.data())
    def release(self, data: DataObject) -> None:
        if not self.live:
            return
        h = data.draw(st.sampled_from(sorted(self.live)))
        self._run(self.hc.release(user_id=self.user_id, handle_id=h))
        self.live.discard(h)

    @rule()
    def force_expire(self) -> None:
        """Direct Redis manipulation to simulate TTL eviction.
        Sets all member scores to 0 (deeply in the past)."""

        async def _expire() -> None:
            client = await self.hc._get_client()
            key = f"alfred:handles:user:{self.user_id}"
            members = cast("list[bytes]", await client.zrange(key, 0, -1))
            if members:
                await client.zadd(key, {m.decode(): 0 for m in members})

        self._run(_expire())
        # Next reserve will ZREMRANGEBYSCORE -inf <now_ms>, which clears them.
        self.live.clear()

    @invariant()
    def zcard_never_exceeds_cap(self) -> None:
        async def _check() -> None:
            client = await self.hc._get_client()
            card = await client.zcard(
                f"alfred:handles:user:{self.user_id}",
            )
            assert card <= self.CAP, f"ZCARD={card} exceeded cap={self.CAP}"

        self._run(_check())

    def teardown(self) -> None:
        try:
            self._run(self.hc.aclose())
        finally:
            self.loop.close()


def test_handle_cap_invariant_under_random_interleavings(
    redis_url: str,
) -> None:
    # Bind the per-run redis_url via a thin factory subclass so the state
    # machine constructor signature stays parameter-free (Hypothesis
    # instantiates the class with no kwargs).
    class _BoundSM(HandleCapStateMachine):
        def __init__(self) -> None:
            super().__init__(redis_url=redis_url)

    run_state_machine_as_test(_BoundSM)  # type: ignore[no-untyped-call]  # reason: hypothesis stateful API lacks stubs
