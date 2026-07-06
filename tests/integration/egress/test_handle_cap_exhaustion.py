"""Integration: the real Redis-backed HandleCap per-user concurrency bound (#339 PR4a).

Proves the Lua-atomic reserve/release the #339 PR4a dispatch path relies on:
5 concurrent reserves for one user succeed; the 6th is refused with
WebFetchRateLimited(bucket='handle_cap'); a release frees exactly one slot; a
different user is unaffected (per-user, not global).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from testcontainers.redis import RedisContainer

from alfred.plugins.web_fetch.errors import WebFetchRateLimited
from alfred.plugins.web_fetch.handle_cap import HandleCap, HandleCapConfig

pytestmark = pytest.mark.integration


@pytest.fixture
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:8-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


@pytest.mark.asyncio
async def test_sixth_reserve_refused_then_release_frees_a_slot(redis_url: str) -> None:
    cap = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=5))
    try:
        ids = [f"h-{i}" for i in range(5)]
        await asyncio.gather(
            *[cap.try_reserve(user_id="u-1", handle_id=h, handle_ttl_seconds=120) for h in ids]
        )
        # 6th is refused atomically.
        with pytest.raises(WebFetchRateLimited) as exc:
            await cap.try_reserve(user_id="u-1", handle_id="h-6", handle_ttl_seconds=120)
        assert exc.value.bucket == "handle_cap"
        # A different user is unaffected (per-user, not global).
        await cap.try_reserve(user_id="u-2", handle_id="h-a", handle_ttl_seconds=120)
        # Releasing one of u-1's slots frees exactly one — the retry now succeeds.
        await cap.release(user_id="u-1", handle_id=ids[0])
        await cap.try_reserve(user_id="u-1", handle_id="h-6", handle_ttl_seconds=120)
    finally:
        await cap.aclose()
