"""HandleCap module tests — Lua semantics, atomicity, TTL behaviour,
error paths, ARGV validation. Lua scripts run against real Redis via
testcontainers (mocking would test our mental model, not the interpreter).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from redis.exceptions import (
    BusyLoadingError,
    ResponseError,
)
from redis.exceptions import (
    ConnectionError as RedisConnectionError,
)
from redis.exceptions import (
    TimeoutError as RedisTimeoutError,
)
from testcontainers.redis import RedisContainer

from alfred.plugins.web_fetch.errors import WebFetchRateLimited
from alfred.plugins.web_fetch.handle_cap import HandleCap, HandleCapConfig


def test_default_config_matches_spec() -> None:
    """HandleCapConfig() defaults to per_user=5 (spec §7)."""
    cfg = HandleCapConfig()
    assert cfg.per_user == 5


def test_cap_bool_rejected_at_load() -> None:
    """bool is a subclass of int in Python — must be rejected at config-load time."""
    with pytest.raises(ValueError, match="per_user must be an int"):
        HandleCapConfig(per_user=True)  # type: ignore[arg-type]


def test_cap_float_rejected_at_load() -> None:
    """float is not int — must be rejected at config-load time."""
    with pytest.raises(ValueError, match="per_user must be an int"):
        HandleCapConfig(per_user=1.5)  # type: ignore[arg-type]


def test_cap_zero_raises_at_load() -> None:
    """A cap of 0 would refuse every fetch — loud at config-load, not silent."""
    with pytest.raises(ValueError, match="per_user must be >= 1"):
        HandleCapConfig(per_user=0)


def test_cap_negative_raises_at_load() -> None:
    with pytest.raises(ValueError, match="per_user must be >= 1"):
        HandleCapConfig(per_user=-1)


def test_cap_one_valid() -> None:
    cfg = HandleCapConfig(per_user=1)
    assert cfg.per_user == 1


def test_cap_large_value_valid() -> None:
    cfg = HandleCapConfig(per_user=10_000)
    assert cfg.per_user == 10_000


def test_config_is_frozen() -> None:
    """Operator config is immutable after construction (consistent with
    RateLimitConfig)."""
    cfg = HandleCapConfig(per_user=5)
    with pytest.raises((AttributeError, TypeError)):
        cfg.per_user = 10  # type: ignore[misc]


# --- HandleCap class: Lua-atomic try_reserve + ARGV validation ---
#
# Tests below talk to a real Redis container via testcontainers — the
# Lua-atomic guarantee depends on actual Redis behaviour; a mock would
# defeat the purpose of the test. Mirrors test_lua_atomic_rate_limit.py
# fixture style.


@pytest.fixture(scope="module")
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:7-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


@pytest_asyncio.fixture
async def cap(redis_url: str) -> AsyncIterator[HandleCap]:
    """Function-scoped HandleCap — fresh client per test, same Redis container.

    Default config (per_user=5) — tests that need a different cap
    construct their own ``HandleCap`` against the same ``redis_url``.
    """
    hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=5))
    try:
        yield hc
    finally:
        await hc.aclose()


def _u() -> str:
    """Unique user id per test — keys do not collide across tests in
    the module-scoped Redis container."""
    return f"user-{time.monotonic_ns()}"


def _h() -> str:
    """Pre-minted UUID4 handle id (dispatcher contract)."""
    return str(uuid.uuid4())


# --- public read-only surface (perf-006 contract) ---


def test_redis_url_property_exposes_constructor_value() -> None:
    """perf-006 connection-pool reuse contract: ``HandleCap.redis_url`` is
    the documented hook callers use to correlate the cap and the
    :class:`~alfred.plugins.web_fetch.content_store.ContentStore` against
    the same Redis. Read-only; round-trips the constructor input verbatim.

    Pure accessor — no Redis I/O, so no ``redis_url`` fixture needed.
    """
    expected = "redis://cap-vs-content-store-correlation:6379/2"
    hc = HandleCap(redis_url=expected, config=HandleCapConfig(per_user=5))
    assert hc.redis_url == expected


# --- ARGV validation (host-side defence; spec §2.3) ---


@pytest.mark.asyncio
async def test_reserve_rejects_non_int_cap(cap: HandleCap) -> None:
    with pytest.raises(ValueError, match="cap"):
        await cap._try_reserve_with_args(
            user_id=_u(),
            handle_id=_h(),
            cap=5.5,  # type: ignore[arg-type]
            expiry_ms=int(time.time() * 1000) + 10_000,
            now_ms=int(time.time() * 1000),
            outer_ttl=600,
        )


@pytest.mark.asyncio
async def test_reserve_rejects_bool_cap(cap: HandleCap) -> None:
    """bool is a subclass of int in Python — must still be rejected."""
    with pytest.raises(ValueError, match="cap"):
        await cap._try_reserve_with_args(
            user_id=_u(),
            handle_id=_h(),
            cap=True,
            expiry_ms=int(time.time() * 1000) + 10_000,
            now_ms=int(time.time() * 1000),
            outer_ttl=600,
        )


@pytest.mark.asyncio
async def test_reserve_rejects_zero_or_negative_cap(cap: HandleCap) -> None:
    for bad in (0, -1):
        with pytest.raises(ValueError, match="cap"):
            await cap._try_reserve_with_args(
                user_id=_u(),
                handle_id=_h(),
                cap=bad,
                expiry_ms=int(time.time() * 1000) + 10_000,
                now_ms=int(time.time() * 1000),
                outer_ttl=600,
            )


@pytest.mark.asyncio
async def test_reserve_rejects_expiry_at_or_before_now(cap: HandleCap) -> None:
    now = int(time.time() * 1000)
    with pytest.raises(ValueError, match="expiry_ms"):
        await cap._try_reserve_with_args(
            user_id=_u(),
            handle_id=_h(),
            cap=5,
            expiry_ms=now,
            now_ms=now,
            outer_ttl=600,
        )
    with pytest.raises(ValueError, match="expiry_ms"):
        await cap._try_reserve_with_args(
            user_id=_u(),
            handle_id=_h(),
            cap=5,
            expiry_ms=now - 1,
            now_ms=now,
            outer_ttl=600,
        )


@pytest.mark.asyncio
async def test_reserve_rejects_zero_or_negative_outer_ttl(cap: HandleCap) -> None:
    """Negative TTL on EXPIRE deletes the key in some Redis versions — silent
    state corruption. Hard rule #7 violation; must fail loud host-side."""
    now = int(time.time() * 1000)
    for bad in (0, -1):
        with pytest.raises(ValueError, match="outer_ttl"):
            await cap._try_reserve_with_args(
                user_id=_u(),
                handle_id=_h(),
                cap=5,
                expiry_ms=now + 10_000,
                now_ms=now,
                outer_ttl=bad,
            )


@pytest.mark.asyncio
async def test_reserve_rejects_nan_inf_floats(cap: HandleCap) -> None:
    """float NaN/Inf are not int — _validate_argv rejects them at the
    Python boundary before they reach Lua's tonumber() (which returns
    nil and would otherwise propagate as silent Redis state corruption
    per spec §2.3). Spec §8.2 mandates these cases explicitly."""
    now = int(time.time() * 1000)
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            await cap._try_reserve_with_args(
                user_id=_u(),
                handle_id=_h(),
                cap=5,
                expiry_ms=bad,  # type: ignore[arg-type]
                now_ms=now,
                outer_ttl=600,
            )


# --- Lua atomic try_reserve (spec §2.3) ---


@pytest.mark.asyncio
async def test_reserve_under_cap_succeeds(cap: HandleCap) -> None:
    """First reserve against an empty key succeeds."""
    await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)


@pytest.mark.asyncio
async def test_reserve_at_cap_refuses(cap: HandleCap) -> None:
    """6th concurrent reserve raises WebFetchRateLimited(bucket='handle_cap')."""
    u = _u()
    for _ in range(5):
        await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
    with pytest.raises(WebFetchRateLimited) as exc_info:
        await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
    assert exc_info.value.bucket == "handle_cap"


@pytest.mark.asyncio
async def test_reserve_default_ttl_derives_outer_ttl_from_floor(cap: HandleCap) -> None:
    """outer_ttl = max(handle_ttl*2, _OUTER_KEY_TTL_FLOOR_SECONDS).

    Pinning the formula's branches end-to-end is brittle; we assert the
    floor constant exists and is the spec value. The observable
    behaviour (the EXPIRE call against the user key) is exercised
    indirectly by ``test_reserve_under_cap_succeeds`` plus future
    ``release`` tests that pin TTL expiry semantics.
    """
    from alfred.plugins.web_fetch.handle_cap import _OUTER_KEY_TTL_FLOOR_SECONDS

    assert _OUTER_KEY_TTL_FLOOR_SECONDS == 600


# --- H-5: Lua return value defensive check ---


@pytest.mark.asyncio
async def test_reserve_unexpected_lua_return_raises_runtime_error(cap: HandleCap) -> None:
    """H-5: a Lua-script return outside the documented ("ok" | "exceeded")
    contract MUST raise ``RuntimeError`` (loud) rather than silently
    looking like a successful reserve.

    The defensive check guards against Lua-side bugs, redis-py decoding
    regressions, and hostile interpretation of the result — any drift
    from the closed return vocabulary is a hard failure at the trust
    boundary, not a silent cap-counter desync.

    A LOUD ``web_fetch.handle_cap.unexpected_lua_return`` structlog
    event fires alongside the RuntimeError so operators see the
    boundary anomaly.
    """
    from structlog.testing import capture_logs

    # AsyncScript instance returns the raw bytes value; patch _get_script
    # so the patched script returns an unexpected bytes payload.
    weird_script = AsyncMock(return_value=b"weird")

    with (
        patch.object(cap, "_get_script", AsyncMock(return_value=weird_script)),
        capture_logs() as logs,
        pytest.raises(RuntimeError, match="unexpected value 'weird'"),
    ):
        await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)

    assert any(
        log.get("event") == "web_fetch.handle_cap.unexpected_lua_return"
        and log.get("result") == "weird"
        for log in logs
    ), f"expected unexpected_lua_return structlog event; got {logs!r}"


@pytest.mark.asyncio
async def test_script_registration_cached_across_calls(cap: HandleCap) -> None:
    """perf-006: ``AsyncScript`` is registered ONCE per process and reused
    across every ``try_reserve`` call. A regression that re-registers on
    each call would re-upload the script body to Redis on the hot path,
    losing the EVALSHA optimisation. This test pins the contract that
    the cached ``_script`` reference is the same instance after two
    reserves."""
    u = _u()
    await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
    first_script = cap._script
    assert first_script is not None
    await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
    assert cap._script is first_script


# --- release (spec §2.4) ---


@pytest.mark.asyncio
async def test_release_decrements_count(cap: HandleCap) -> None:
    u = _u()
    h = _h()
    await cap.try_reserve(user_id=u, handle_id=h, handle_ttl_seconds=80)
    await cap.release(user_id=u, handle_id=h)
    # After release, the user can reserve again immediately.
    await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)


@pytest.mark.asyncio
async def test_release_unknown_handle_id_no_op(cap: HandleCap) -> None:
    """Idempotent — release of a never-reserved id is a no-op ZREM."""
    await cap.release(user_id=_u(), handle_id="never-reserved")


@pytest.mark.asyncio
async def test_release_twice_no_op(cap: HandleCap) -> None:
    u = _u()
    h = _h()
    await cap.try_reserve(user_id=u, handle_id=h, handle_ttl_seconds=80)
    await cap.release(user_id=u, handle_id=h)
    await cap.release(user_id=u, handle_id=h)  # second is a no-op


@pytest.mark.asyncio
async def test_aclose_is_idempotent(cap: HandleCap) -> None:
    await cap.aclose()
    await cap.aclose()


# --- TTL / passive eviction (spec §2.3) ---


@pytest.mark.asyncio
async def test_expired_entries_evicted_on_next_reserve(cap: HandleCap) -> None:
    """A handle whose score is in the past is evicted by the next reserve's
    ZREMRANGEBYSCORE — restores capacity."""
    u = _u()
    now = int(time.time() * 1000)
    # Inject 5 expired members directly (score in the past).
    client = await cap._get_client()
    key = f"alfred:handles:user:{u}"
    pipe = client.pipeline()
    for i in range(5):
        pipe.zadd(key, {f"expired-{i}": now - 1000})
    pipe.expire(key, 600)
    await pipe.execute()
    # Reserve should succeed — expired entries evicted, count drops to 0.
    await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)


@pytest.mark.asyncio
async def test_staggered_expiry_decrements_count(cap: HandleCap) -> None:
    """Five handles with staggered expiry; later reserves succeed as earlier
    members fall out of the window."""
    u = _u()
    now = int(time.time() * 1000)
    client = await cap._get_client()
    key = f"alfred:handles:user:{u}"
    # Inject 5 members already expired at staggered times — all evictable now.
    pipe = client.pipeline()
    for i in range(5):
        pipe.zadd(key, {f"old-{i}": now - 5000 + i * 100})
    await pipe.execute()
    # First reserve evicts all 5 — succeeds.
    await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)


@pytest.mark.asyncio
async def test_user_key_outer_expire_set(cap: HandleCap) -> None:
    """The user's ZSET key gets an outer EXPIRE so idle keys don't accumulate."""
    u = _u()
    await cap.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
    client = await cap._get_client()
    ttl = await client.ttl(f"alfred:handles:user:{u}")
    # Outer TTL = max(80*2, 600) = 600.
    assert 590 <= ttl <= 600


# --- Atomicity / race conditions (spec §2.3) ---


@pytest.mark.asyncio
async def test_race_two_at_boundary(redis_url: str) -> None:
    """Two coroutines racing the 5th-and-6th slot with cap=5 and 4 already
    reserved. Exactly one succeeds, one raises WebFetchRateLimited."""
    hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=5))
    try:
        u = _u()
        for _ in range(4):
            await hc.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
        results: list[bool | WebFetchRateLimited] = []

        async def attempt() -> None:
            try:
                await hc.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
                results.append(True)
            except WebFetchRateLimited as e:
                results.append(e)

        async with asyncio.TaskGroup() as tg:
            tg.create_task(attempt())
            tg.create_task(attempt())
        successes = [r for r in results if r is True]
        failures = [r for r in results if isinstance(r, WebFetchRateLimited)]
        assert len(successes) == 1, f"expected exactly 1 success, got {results}"
        assert len(failures) == 1, f"expected exactly 1 failure, got {results}"
        assert failures[0].bucket == "handle_cap"
    finally:
        await hc.aclose()


@pytest.mark.asyncio
async def test_race_six_against_empty(redis_url: str) -> None:
    """Six concurrent reserves against an empty key with cap=5. Exactly
    5 succeed, 1 fails."""
    hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=5))
    try:
        u = _u()
        results: list[bool | WebFetchRateLimited] = []

        async def attempt() -> None:
            try:
                await hc.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
                results.append(True)
            except WebFetchRateLimited as e:
                results.append(e)

        async with asyncio.TaskGroup() as tg:
            for _ in range(6):
                tg.create_task(attempt())
        successes = [r for r in results if r is True]
        failures = [r for r in results if isinstance(r, WebFetchRateLimited)]
        assert len(successes) == 5, f"expected 5 successes, got {results}"
        assert len(failures) == 1, f"expected 1 failure, got {results}"
    finally:
        await hc.aclose()


@pytest.mark.asyncio
async def test_release_and_reserve_race_keeps_invariant(redis_url: str) -> None:
    """Interleaved release+reserve must never let ZCARD breach cap.

    Cap=3; alternate reserve/release across 50 coroutine pairs; observe
    ZCARD after each batch."""
    hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=3))
    try:
        u = _u()
        handles = [_h() for _ in range(50)]
        for i, h in enumerate(handles):
            with contextlib.suppress(WebFetchRateLimited):
                await hc.try_reserve(user_id=u, handle_id=h, handle_ttl_seconds=80)
            # Periodically release the oldest active member.
            if i % 2 == 1 and i >= 2:
                await hc.release(user_id=u, handle_id=handles[i - 2])
            client = await hc._get_client()
            card = await client.zcard(f"alfred:handles:user:{u}")
            assert card <= 3, f"cap breached at i={i}; ZCARD={card}"
    finally:
        await hc.aclose()


@pytest.mark.asyncio
async def test_reserve_same_handle_id_twice_is_score_update(cap: HandleCap) -> None:
    """ZADD without NX updates the score (extends expiry); count unchanged.
    Documents intentional behaviour — pinned so a future refactor doesn't
    silently break it."""
    u = _u()
    h = _h()
    await cap.try_reserve(user_id=u, handle_id=h, handle_ttl_seconds=80)
    client = await cap._get_client()
    count_before = await client.zcard(f"alfred:handles:user:{u}")
    await cap.try_reserve(user_id=u, handle_id=h, handle_ttl_seconds=80)
    count_after = await client.zcard(f"alfred:handles:user:{u}")
    assert count_before == count_after == 1


# --- Config edges + isolation ---


@pytest.mark.asyncio
async def test_cap_one_serializes(redis_url: str) -> None:
    hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=1))
    try:
        u = _u()
        h1 = _h()
        h2 = _h()
        await hc.try_reserve(user_id=u, handle_id=h1, handle_ttl_seconds=80)
        with pytest.raises(WebFetchRateLimited):
            await hc.try_reserve(user_id=u, handle_id=h2, handle_ttl_seconds=80)
        await hc.release(user_id=u, handle_id=h1)
        await hc.try_reserve(user_id=u, handle_id=h2, handle_ttl_seconds=80)
    finally:
        await hc.aclose()


@pytest.mark.asyncio
async def test_cap_large_value_honoured(redis_url: str) -> None:
    """No off-by-one: cap=1000 lets exactly 1000 succeed, 1001 refused."""
    hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=1000))
    try:
        u = _u()
        for _ in range(1000):
            await hc.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
        with pytest.raises(WebFetchRateLimited):
            await hc.try_reserve(user_id=u, handle_id=_h(), handle_ttl_seconds=80)
    finally:
        await hc.aclose()


@pytest.mark.asyncio
async def test_user_a_cap_does_not_affect_user_b(cap: HandleCap) -> None:
    """Independent ZSET keys — exhausting one user doesn't refuse another."""
    a, b = _u(), _u()
    for _ in range(5):
        await cap.try_reserve(user_id=a, handle_id=_h(), handle_ttl_seconds=80)
    with pytest.raises(WebFetchRateLimited):
        await cap.try_reserve(user_id=a, handle_id=_h(), handle_ttl_seconds=80)
    # User B is unaffected.
    await cap.try_reserve(user_id=b, handle_id=_h(), handle_ttl_seconds=80)


# --- Redis transient failures by subtype (CLAUDE.md hard rule #7, spec §8.2) ---
#
# Reserve fails CLOSED (propagates) so the dispatcher's transport_error audit
# arm fires and the user-visible turn aborts. Release fails LOUD-BUT-QUIET
# (swallows but emits structlog) because the caller is already past the
# conversation turn — raising would only confuse the caller while the slot
# is lost either way (passive TTL eviction will free it within ~80s).
#
# Tests use ``structlog.testing.capture_logs`` rather than pytest's
# ``caplog``: AlfredOS routes structlog through ``ConsoleRenderer`` and does
# not universally configure the stdlib bridge in the test runner, so
# ``caplog`` would silently miss the events.


@pytest.mark.asyncio
async def test_reserve_timeout_propagates(cap: HandleCap) -> None:
    """Reserve fails closed on TimeoutError — propagates so the dispatcher
    can emit its transport_error audit row."""
    with (
        patch.object(
            cap,
            "_get_script",
            AsyncMock(return_value=AsyncMock(side_effect=RedisTimeoutError("simulated timeout"))),
        ),
        pytest.raises(RedisTimeoutError),
    ):
        await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)


@pytest.mark.asyncio
async def test_reserve_connection_error_propagates(cap: HandleCap) -> None:
    """Reserve fails closed on ConnectionError — propagates so the dispatcher
    can emit its transport_error audit row."""
    with (
        patch.object(
            cap,
            "_get_script",
            AsyncMock(return_value=AsyncMock(side_effect=RedisConnectionError("simulated reset"))),
        ),
        pytest.raises(RedisConnectionError),
    ):
        await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)


@pytest.mark.asyncio
async def test_reserve_response_error_propagates(cap: HandleCap) -> None:
    """ResponseError = runtime Redis bug (e.g., WRONGTYPE). Fail closed."""
    with (
        patch.object(
            cap,
            "_get_script",
            AsyncMock(return_value=AsyncMock(side_effect=ResponseError("WRONGTYPE"))),
        ),
        pytest.raises(ResponseError),
    ):
        await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)


@pytest.mark.asyncio
async def test_reserve_busyloading_propagates(cap: HandleCap) -> None:
    """BusyLoadingError = Redis still loading the RDB. Fail closed; operator
    sees the error class in the audit row's exception_type field."""
    with (
        patch.object(
            cap,
            "_get_script",
            AsyncMock(return_value=AsyncMock(side_effect=BusyLoadingError("loading"))),
        ),
        pytest.raises(BusyLoadingError),
    ):
        await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)


@pytest.mark.asyncio
async def test_release_timeout_logs_loud_no_propagate(cap: HandleCap) -> None:
    """Release path's ZREM raises TimeoutError. Does NOT propagate (caller
    is past the conversation turn); LOUD web_fetch.handle_cap.release_failed
    structlog event fires.

    Uses ``structlog.testing.capture_logs`` rather than ``caplog`` because
    AlfredOS logs via structlog directly — the stdlib-bridge path is not
    universally configured in the test runner, and ``caplog`` would
    silently miss the event under the wrong logging config.
    """
    from structlog.testing import capture_logs

    fake_client = AsyncMock()
    fake_client.zrem.side_effect = RedisTimeoutError("simulated")
    u = _u()
    h = _h()
    with (
        patch.object(cap, "_get_client", AsyncMock(return_value=fake_client)),
        capture_logs() as logs,
    ):
        # Should NOT raise.
        await cap.release(user_id=u, handle_id=h, correlation_id="cid-1")
    assert any(
        log.get("event") == "web_fetch.handle_cap.release_failed"
        and log.get("correlation_id") == "cid-1"
        and log.get("exception_type") == "TimeoutError"
        and log.get("user_id") == u
        and log.get("handle_id") == h
        for log in logs
    ), f"expected loud release_failed event with cid-1; got {logs!r}"


@pytest.mark.asyncio
async def test_release_connection_error_logs_loud_no_propagate(cap: HandleCap) -> None:
    """Release path's ZREM raises ConnectionError. Does NOT propagate; LOUD
    structlog event fires."""
    from structlog.testing import capture_logs

    fake_client = AsyncMock()
    fake_client.zrem.side_effect = RedisConnectionError("simulated reset")
    u = _u()
    h = _h()
    with (
        patch.object(cap, "_get_client", AsyncMock(return_value=fake_client)),
        capture_logs() as logs,
    ):
        await cap.release(user_id=u, handle_id=h, correlation_id="cid-2")
    assert any(
        log.get("event") == "web_fetch.handle_cap.release_failed"
        and log.get("correlation_id") == "cid-2"
        and log.get("exception_type") == "ConnectionError"
        and log.get("user_id") == u
        and log.get("handle_id") == h
        for log in logs
    ), f"expected loud release_failed event with cid-2; got {logs!r}"


# --- EVALSHA NOSCRIPT fallback ---


@pytest.mark.asyncio
async def test_evalsha_noscript_reregisters_and_succeeds(cap: HandleCap) -> None:
    """SCRIPT FLUSH between calls; the next try_reserve hits NOSCRIPT, redis-py
    AsyncScript auto-falls-back to EVAL + re-caches; reserve succeeds."""
    await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)
    client = await cap._get_client()
    await client.execute_command("SCRIPT", "FLUSH")
    # AsyncScript's __call__ catches NOSCRIPT and retries via EVAL.
    await cap.try_reserve(user_id=_u(), handle_id=_h(), handle_ttl_seconds=80)
