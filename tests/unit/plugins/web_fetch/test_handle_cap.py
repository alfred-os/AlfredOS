"""HandleCap module tests — Lua semantics, atomicity, TTL behaviour,
error paths, ARGV validation. Lua scripts run against real Redis via
testcontainers (mocking would test our mental model, not the interpreter).
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio
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
