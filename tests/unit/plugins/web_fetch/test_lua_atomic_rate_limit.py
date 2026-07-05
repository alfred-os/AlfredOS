"""Lua-atomic rate-limit tests (spec §7.7, §7a.2).

All three rate checks (per-domain, per-user, per-user-daily) execute as
ONE Lua script in a single Redis round-trip — prevents race conditions
from concurrent requests slipping past the per-domain limit.

Tests run against a real testcontainers Redis instance — the Lua-atomic
guarantee depends on actual Redis behaviour; a mock would defeat the
purpose of the test.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio
from testcontainers.redis import RedisContainer

from alfred.plugins.web_fetch.errors import WebFetchRateLimited
from alfred.plugins.web_fetch.rate_limit import RateLimitConfig, RateLimiter


@pytest.fixture(scope="module")
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:8-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


@pytest_asyncio.fixture
async def limiter(redis_url: str) -> AsyncIterator[RateLimiter]:
    """Function-scoped limiter — fresh client per test, same Redis container.

    The per-test config uses tight limits (3 / 5 / 10) so each test can
    exhaust a bucket in a handful of calls.
    """
    cfg = RateLimitConfig(
        per_domain_per_minute=3,
        per_user_per_minute=5,
        per_user_daily=10,
    )
    lim = RateLimiter(redis_url=redis_url, config=cfg)
    try:
        yield lim
    finally:
        await lim.close()


def _unique_domain() -> str:
    return f"domain-{time.monotonic_ns()}.test"


def _unique_user() -> str:
    return f"user-{time.monotonic_ns()}"


@pytest.mark.asyncio
async def test_under_limit_allows(limiter: RateLimiter) -> None:
    """First request against a fresh bucket succeeds with no raise."""
    await limiter.check_and_increment(domain=_unique_domain(), user_id=_unique_user())


@pytest.mark.asyncio
async def test_per_domain_limit_enforced(limiter: RateLimiter) -> None:
    """Exceeding the per-domain limit raises WebFetchRateLimited bucket='per_domain'."""
    domain = _unique_domain()
    user_id = _unique_user()
    for _ in range(3):
        await limiter.check_and_increment(domain=domain, user_id=user_id)
    with pytest.raises(WebFetchRateLimited) as exc_info:
        await limiter.check_and_increment(domain=domain, user_id=user_id)
    assert exc_info.value.bucket == "per_domain"


@pytest.mark.asyncio
async def test_per_user_limit_enforced(limiter: RateLimiter) -> None:
    """Exceeding the per-user limit raises bucket='per_user'.

    Spreads across multiple unique domains so the per-domain limit is
    not the cause of the refusal.
    """
    user_id = _unique_user()
    for _ in range(5):
        # Each request hits a distinct domain so the per-domain bucket
        # is not the rate-limiting factor.
        await limiter.check_and_increment(domain=_unique_domain(), user_id=user_id)
    with pytest.raises(WebFetchRateLimited) as exc_info:
        await limiter.check_and_increment(domain=_unique_domain(), user_id=user_id)
    assert exc_info.value.bucket == "per_user"


@pytest.mark.asyncio
async def test_per_user_daily_limit_enforced(limiter: RateLimiter) -> None:
    """Exceeding the per-user daily budget raises bucket='daily_budget'.

    Uses a fresh user_id so the daily counter starts at 0. The per-user
    sliding-window counter is also incremented — we need to use a config
    where the per-user-per-minute limit is greater than the daily limit
    so the daily bucket trips first. Default config has per_user=5,
    daily=10, so per_user trips first. This test constructs a per-test
    limiter with per_user=100 to isolate the daily trip.
    """
    redis_url = limiter.redis_url
    cfg = RateLimitConfig(
        per_domain_per_minute=1000,
        per_user_per_minute=1000,
        per_user_daily=5,
    )
    daily_limiter = RateLimiter(redis_url=redis_url, config=cfg)
    try:
        user_id = _unique_user()
        for _ in range(5):
            await daily_limiter.check_and_increment(domain=_unique_domain(), user_id=user_id)
        with pytest.raises(WebFetchRateLimited) as exc_info:
            await daily_limiter.check_and_increment(domain=_unique_domain(), user_id=user_id)
        assert exc_info.value.bucket == "daily_budget"
    finally:
        await daily_limiter.close()


@pytest.mark.asyncio
async def test_race_condition_prevention(redis_url: str) -> None:
    """Two concurrent requests that together exceed the limit: exactly one wins.

    Spec §7a.2 explicitly requires Lua-atomic semantics here — a
    pipeline-based approach would let both calls observe count=0 and
    both succeed, breaking the limit.
    """
    cfg = RateLimitConfig(
        per_domain_per_minute=1,
        per_user_per_minute=100,
        per_user_daily=100,
    )
    lim = RateLimiter(redis_url=redis_url, config=cfg)
    try:
        domain = _unique_domain()
        user_id = _unique_user()

        results: list[bool | WebFetchRateLimited] = []

        async def attempt() -> None:
            try:
                await lim.check_and_increment(domain=domain, user_id=user_id)
                results.append(True)
            except WebFetchRateLimited as e:
                results.append(e)

        async with asyncio.TaskGroup() as tg:
            tg.create_task(attempt())
            tg.create_task(attempt())

        successes = [r for r in results if r is True]
        failures = [r for r in results if isinstance(r, WebFetchRateLimited)]
        assert len(successes) == 1, f"expected exactly one success, got {results}"
        assert len(failures) == 1, f"expected exactly one failure, got {results}"
    finally:
        await lim.close()


@pytest.mark.asyncio
async def test_zero_limit_refuses_immediately(redis_url: str) -> None:
    """A configured limit of 0 must refuse the very first request."""
    cfg = RateLimitConfig(
        per_domain_per_minute=0,
        per_user_per_minute=100,
        per_user_daily=100,
    )
    lim = RateLimiter(redis_url=redis_url, config=cfg)
    try:
        with pytest.raises(WebFetchRateLimited) as exc_info:
            await lim.check_and_increment(domain=_unique_domain(), user_id=_unique_user())
        assert exc_info.value.bucket == "per_domain"
    finally:
        await lim.close()


@pytest.mark.asyncio
async def test_close_is_idempotent(limiter: RateLimiter) -> None:
    """Closing twice must not raise — supervisor SIGKILL paths."""
    await limiter.close()
    await limiter.close()


def test_default_config_matches_spec() -> None:
    """Default config (no overrides) matches spec §7.7."""
    cfg = RateLimitConfig()
    assert cfg.per_domain_per_minute == 10
    assert cfg.per_user_per_minute == 30
    assert cfg.per_user_daily == 100


def test_redis_url_property_exposed(redis_url: str) -> None:
    """The dispatcher needs to read the URL to construct a shared store
    on the same Redis (perf-006 connection-pool reuse)."""
    lim = RateLimiter(redis_url=redis_url)
    assert lim.redis_url == redis_url


# ──────────────────────────────────────────────────────────────────────
# #197 — defensive arm: Lua-script unexpected-return-value loud failure
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unexpected_lua_return_raises_runtime_error(limiter: RateLimiter) -> None:
    """#197: an unexpected return value from the Lua script raises
    :class:`RuntimeError` rather than silently degrading.

    The Lua script's contract is to return one of
    ``b"ok"`` / ``b"per_domain"`` / ``b"per_user"`` / ``b"daily_budget"``.
    A future drift on the Lua side (refactor mistake, library upgrade
    that swaps the return shape) would otherwise let the limiter
    silently fall through — depending on which arm of the if-chain
    fires next, the request could be ALLOWED past a legitimate bucket
    (a security regression) or REFUSED with a misleading bucket
    attribution (a forensic regression). Either way, the operator's
    audit trail would be wrong.

    The defensive ``if bucket_str not in (...)`` arm catches the drift
    at the boundary and raises a loud :class:`RuntimeError` naming the
    unexpected value. Pin via patching the script accessor so the test
    does not depend on real Lua misbehaviour (which would be a Redis
    bug, not ours).
    """
    from unittest.mock import AsyncMock

    # Replace the script accessor with one whose returned callable
    # produces an unexpected value. The accessor itself is async — it
    # returns the cached script object — so AsyncMock with a custom
    # return_value matches the interface.
    bad_script = AsyncMock(return_value=b"surprise_bucket_value")
    limiter._get_script = AsyncMock(return_value=bad_script)  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="unexpected bucket"):
        await limiter.check_and_increment(domain=_unique_domain(), user_id=_unique_user())

    # The unexpected value appears in the error message verbatim so an
    # operator chasing the drift has the literal Lua return on the
    # raised exception — no extra grepping required.
    bad_script.assert_awaited_once()
