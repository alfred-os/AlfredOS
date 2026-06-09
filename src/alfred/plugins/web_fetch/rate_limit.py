"""Lua-atomic sliding-window rate limits for web.fetch (spec §7.7, §7a.2).

All three rate checks (per-domain, per-user, per-user-daily) execute as
a **single** Lua script in one Redis round-trip. The Lua-atomic
guarantee is non-negotiable: a pipeline-based GET/SET pair would let
concurrent requests both observe ``count=0`` and both succeed,
breaking the limit. The integration test
``tests/unit/plugins/web_fetch/test_lua_atomic_rate_limit.test_race_condition_prevention``
pins this property against a real Redis container.

Redis key namespace (spec §7.7):

* ``alfred:rate:{domain}`` — per-domain sliding window (sorted set;
  members are unique millisecond-tick markers, scores are timestamps).
* ``alfred:rate:user:{user_id}`` — per-user sliding window (same
  shape).
* ``alfred:fetch_budget:{user_id}:{YYYY-MM-DD}`` — per-user daily
  budget (integer counter; TTL = 48h for midnight-boundary safety).

The two sliding-window keys also have a sibling ``...:seq`` counter key
used by the Lua script to mint a per-tick uniqueness suffix on the
ZSET member. This is the **perf-011 fix**: without the suffix, two
requests landing in the same millisecond would ZADD the same member
(``"<now_ms>"``), which Redis treats as a SET-update of the existing
score — silently dropping one of the requests from the count. The
suffix (``"<now_ms>:<seq>"``) makes every member unique so ZCARD is an
honest count.

Performance: the script does three ``ZREMRANGEBYSCORE`` + three
``ZCARD`` + an INCR — all O(log N) or O(1). For Slice-3 default limits
(10 / 30 / 100) the window holds at most ~100 entries, so the script
runs in tens of microseconds on local Redis. The hot path is a single
``EVALSHA`` round-trip (the script is registered once per process).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, cast

import redis.asyncio as aioredis
import structlog
from redis.commands.core import AsyncScript

from alfred.audit.audit_row_schemas import RateLimitBucket
from alfred.plugins.web_fetch.errors import WebFetchRateLimited

if TYPE_CHECKING:
    from alfred.policies.snapshot_ref import PoliciesSnapshotRef

_log = structlog.get_logger(__name__)

# Defaults pinned in spec §7.7. Operators tune via config/policies.yaml;
# a missing override yields these values, NOT silently uncapped fetching.
_DEFAULT_PER_DOMAIN_PER_MINUTE: Final[int] = 10
_DEFAULT_PER_USER_PER_MINUTE: Final[int] = 30
_DEFAULT_PER_USER_DAILY: Final[int] = 100

_WINDOW_SECONDS: Final[int] = 60
_DAILY_TTL_SECONDS: Final[int] = 48 * 3600  # 48h: midnight-boundary safety

# Single Lua script: check all three limits atomically.
#
#   KEYS[1] = domain_key   (alfred:rate:{domain})
#   KEYS[2] = user_key     (alfred:rate:user:{user_id})
#   KEYS[3] = daily_key    (alfred:fetch_budget:{user_id}:{YYYY-MM-DD})
#   ARGV[1] = domain_limit
#   ARGV[2] = user_limit
#   ARGV[3] = daily_limit
#   ARGV[4] = window_seconds
#   ARGV[5] = daily_ttl_seconds
#   ARGV[6] = now_ms
#
# Returns one of: "ok" | "per_domain" | "per_user" | "daily_budget".
#
# perf-011: ZADD member = "<now_ms>:<seq>" where <seq> is an INCR on
# a sibling key. Without the suffix, two requests landing in the same
# millisecond would ZADD with the same member and Redis would treat
# the second as a SET-update (overwriting the score), silently
# dropping one entry from the count. The suffix guarantees uniqueness.
_RATE_LIMIT_SCRIPT: Final[str] = """
local domain_key = KEYS[1]
local user_key   = KEYS[2]
local daily_key  = KEYS[3]
local domain_limit = tonumber(ARGV[1])
local user_limit   = tonumber(ARGV[2])
local daily_limit  = tonumber(ARGV[3])
local window_s     = tonumber(ARGV[4])
local window_ms    = window_s * 1000
local daily_ttl    = tonumber(ARGV[5])
local now_ms       = tonumber(ARGV[6])
local cutoff_ms    = now_ms - window_ms

-- Per-domain sliding window
redis.call('ZREMRANGEBYSCORE', domain_key, '-inf', cutoff_ms)
local domain_count = redis.call('ZCARD', domain_key)
if domain_count >= domain_limit then
    return 'per_domain'
end

-- Per-user sliding window
redis.call('ZREMRANGEBYSCORE', user_key, '-inf', cutoff_ms)
local user_count = redis.call('ZCARD', user_key)
if user_count >= user_limit then
    return 'per_user'
end

-- Per-user daily budget
local daily_count = tonumber(redis.call('GET', daily_key) or '0')
if daily_count >= daily_limit then
    return 'daily_budget'
end

-- All three checks passed — increment all three counters.
-- perf-011: use INCR-derived seq suffix for ZSET member uniqueness.
local seq_domain = redis.call('INCR', domain_key .. ':seq')
local seq_user   = redis.call('INCR', user_key   .. ':seq')
local domain_expire = window_s + 5
redis.call('ZADD', domain_key, now_ms, now_ms .. ':' .. seq_domain)
redis.call('EXPIRE', domain_key, domain_expire)
redis.call('EXPIRE', domain_key .. ':seq', domain_expire)
redis.call('ZADD', user_key, now_ms, now_ms .. ':' .. seq_user)
redis.call('EXPIRE', user_key, domain_expire)
redis.call('EXPIRE', user_key .. ':seq', domain_expire)
redis.call('INCR', daily_key)
redis.call('EXPIRE', daily_key, daily_ttl)

return 'ok'
"""


@dataclass(frozen=True, slots=True)
class RateLimitConfig:
    """Per-deployment rate-limit knobs.

    All three limits are independent — the most restrictive trips first.
    Operators tune via ``config/policies.yaml``; a missing override
    yields the spec §7.7 defaults (10 / 30 / 100), NOT silently
    uncapped fetching.
    """

    per_domain_per_minute: int = _DEFAULT_PER_DOMAIN_PER_MINUTE
    per_user_per_minute: int = _DEFAULT_PER_USER_PER_MINUTE
    per_user_daily: int = _DEFAULT_PER_USER_DAILY

    @classmethod
    def from_snapshot_ref(cls, ref: PoliciesSnapshotRef) -> RateLimitConfig:
        """Build a config from the active policy snapshot (PR-S4-4 hot-reload).

        Derefs ``ref.current()`` on EVERY call (per-iteration deref, core-003)
        so a watcher swap is reflected the next time a caller rebuilds the
        config — no plugin-host restart required. The per-domain / per-minute
        knobs are not yet operator-tunable in ``PoliciesV1`` and keep their
        spec §7.7 defaults; ``per_user_daily`` reads the hot-reloadable
        ``rate_limits.web_fetch_per_user_per_hour`` budget.
        """
        snapshot = ref.current()
        return cls(per_user_daily=snapshot.policies.rate_limits.web_fetch_per_user_per_hour)


class RateLimiter:
    """Three-bucket rate limiter backed by a single Lua-atomic Redis script.

    Construction is one-shot per plugin host process (perf-006); the
    same instance is shared across all fetches. The Lua script is
    registered lazily on first ``check_and_increment`` call and reused
    via ``EVALSHA`` for the rest of the process lifetime.
    """

    def __init__(self, redis_url: str, config: RateLimitConfig | None = None) -> None:
        self._redis_url = redis_url
        self._config = config or RateLimitConfig()
        self._client: aioredis.Redis | None = None
        self._script: AsyncScript | None = None

    @property
    def redis_url(self) -> str:
        """Exposed so the dispatcher can construct a shared
        :class:`ContentStore` on the same Redis (perf-006 connection-pool
        reuse contract)."""
        return self._redis_url

    async def _get_script(self) -> AsyncScript:
        if self._client is None:
            # decode_responses=False so the Lua return value comes back
            # as ``bytes`` consistently across Redis client versions.
            self._client = aioredis.from_url(self._redis_url, decode_responses=False)
        if self._script is None:
            self._script = self._client.register_script(_RATE_LIMIT_SCRIPT)
        return self._script

    async def check_and_increment(self, *, domain: str, user_id: str) -> None:
        """Check all three rate limits and increment counters in one
        atomic Redis round-trip.

        Args:
            domain: The hostname portion of the URL being fetched
                (``urlparse(url).netloc``). Used to key the per-domain
                bucket.
            user_id: The canonical user id of the conversation turn.
                Used to key the per-user-per-minute and per-user-daily
                buckets.

        Raises:
            WebFetchRateLimited: any of the three limits is exhausted.
                The exception's ``.bucket`` attribute is one of
                ``"per_domain"`` / ``"per_user"`` / ``"daily_budget"``
                so the audit row can record the typed bucket without
                string-parsing the message.
        """
        # Compute the daily-key date in UTC so a deployment spanning
        # midnight does not double-count or under-count on the
        # transition. The 48h TTL gives the prior day's key time to
        # decay naturally without overlapping the next day.
        #
        # CR-146 minor: derive ``today`` and ``now_ms`` from one
        # ``datetime.now(tz=UTC)`` call so a request that lands exactly
        # at the 00:00 UTC boundary cannot get its date-key from one
        # day and its timestamp from the next. The PRD §7.7 daily-
        # rollover contract is meaningful at that exact boundary; a
        # second ``now()`` could yield a daily_key from yesterday with
        # an EXPIRESAT-style timestamp from today, miscounting the
        # request against the wrong day's budget.
        now = datetime.now(tz=UTC)
        today = now.strftime("%Y-%m-%d")
        domain_key = f"alfred:rate:{domain}"
        user_key = f"alfred:rate:user:{user_id}"
        daily_key = f"alfred:fetch_budget:{user_id}:{today}"
        now_ms = int(now.timestamp() * 1000)

        script = await self._get_script()
        # Lua return is bytes under decode_responses=False; redis-py
        # types it as the broader ``bytes | str | int | list`` union,
        # so cast to bytes to keep the rest of the function honest.
        raw = await script(
            keys=[domain_key, user_key, daily_key],
            args=[
                str(self._config.per_domain_per_minute),
                str(self._config.per_user_per_minute),
                str(self._config.per_user_daily),
                str(_WINDOW_SECONDS),
                str(_DAILY_TTL_SECONDS),
                str(now_ms),
            ],
        )
        bucket_str = cast("bytes", raw).decode("ascii")
        if bucket_str == "ok":
            return
        if bucket_str not in ("per_domain", "per_user", "daily_budget"):
            # Defensive: Lua should never return anything else; loud-fail if it does.
            msg = f"RateLimiter Lua script returned unexpected bucket {bucket_str!r}"
            raise RuntimeError(msg)
        bucket = cast("RateLimitBucket", bucket_str)
        _log.warning(
            "web_fetch.rate_limit.exceeded",
            domain=domain,
            user_id=user_id,
            bucket=bucket,
        )
        raise WebFetchRateLimited(bucket)

    async def close(self) -> None:
        """Idempotent close — drop the underlying Redis client.

        Supervisor SIGKILL paths call this defensively; calling it more
        than once must not raise.
        """
        if self._client is not None:
            client = self._client
            self._client = None
            self._script = None
            await client.aclose()


__all__ = ["RateLimitConfig", "RateLimiter"]
