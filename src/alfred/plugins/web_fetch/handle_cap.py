"""Per-user concurrent ContentHandle cap.

Spec §7.10 / docs/superpowers/specs/2026-06-02-handle-cap-design.md.

Sibling of :class:`~alfred.plugins.web_fetch.rate_limit.RateLimiter`. Where
the rate limiter bounds request rate, ``HandleCap`` bounds the number of
live :class:`~alfred.security.quarantine.ContentHandle` instances a single
user has outstanding in Redis — the resource the cap exists to protect.

Lifecycle
---------

:class:`HandleCap` is constructed ONCE per plugin host process at
startup, alongside :class:`~alfred.plugins.web_fetch.rate_limit.RateLimiter`
and :class:`~alfred.plugins.web_fetch.content_store.ContentStore`. The
dispatcher receives it as a kwarg through every dispatch; there is no
per-request construction. This matches the perf-006 precedent —
``RateLimiter`` mints + owns its ``redis.asyncio.Redis`` client across
the process lifetime (see ``rate_limit.py:144-173``). :meth:`HandleCap.aclose`
is idempotent and runs on process shutdown / supervisor SIGKILL paths.

See ``docs/superpowers/specs/2026-06-02-handle-cap-design.md`` for the
full design rationale, the disputed-item resolutions, and the review-pass
audit trail.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast

import redis.asyncio as aioredis
import structlog
from redis.commands.core import AsyncScript
from redis.exceptions import RedisError

from alfred.plugins.web_fetch.errors import WebFetchRateLimited

if TYPE_CHECKING:
    from alfred.policies.snapshot_ref import PoliciesSnapshotRef

_log = structlog.get_logger(__name__)

_DEFAULT_PER_USER_CAP: int = 5
"""Slice-3 spec §7.10 line 591 default. Operators tune via
``config/policies.yaml`` ``web_fetch.max_concurrent_handles_per_user``."""


@dataclass(frozen=True, slots=True)
class HandleCapConfig:
    """Per-deployment knobs for :class:`HandleCap`.

    A misconfigured cap (≤ 0) fails loud at config-load time, not silently
    at first fetch — matches the ``RateLimitConfig`` precedent.
    """

    per_user: int = _DEFAULT_PER_USER_CAP

    def __post_init__(self) -> None:
        if isinstance(self.per_user, bool) or not isinstance(self.per_user, int):
            msg = (
                f"HandleCapConfig.per_user must be an int >= 1; got {type(self.per_user).__name__}."
            )
            raise ValueError(msg)
        if self.per_user < 1:
            msg = (
                f"HandleCapConfig.per_user must be >= 1; got {self.per_user}. "
                "A cap of 0 would refuse every fetch."
            )
            raise ValueError(msg)

    @classmethod
    def from_snapshot_ref(cls, ref: PoliciesSnapshotRef) -> HandleCapConfig:
        """Build a config from the active policy snapshot (PR-S4-4 hot-reload).

        Derefs ``ref.current()`` on EVERY call (per-iteration deref, core-003)
        so a watcher swap to
        ``handle_caps.web_fetch_max_concurrent_handles_per_user`` is reflected
        the next time a caller rebuilds the config — no plugin-host restart.
        """
        snapshot = ref.current()
        return cls(per_user=snapshot.policies.handle_caps.web_fetch_max_concurrent_handles_per_user)


_OUTER_KEY_TTL_FLOOR_SECONDS: Final[int] = 600
"""Floor for the ZSET key's outer EXPIRE. Bounds empty-key keyspace at ~80B
per idle user * 10K users ~= 1MB held <=10 min. Prevents thrash when
``handle_ttl`` is short. See spec §2.3."""


_KEY_PREFIX_USER: Final[str] = "alfred:handles:user:"
"""Per-user ZSET namespace. Sibling of ``alfred:rate:user:{user_id}`` —
distinct prefix so a misrouted command against one cannot perturb the
other's key space."""


# Single Lua script: atomic check-and-reserve in one Redis round-trip.
#
# Order matters:
#   1. ZREMRANGEBYSCORE — passive eviction of TTL-expired handles. This
#      is the ONLY mechanism by which TTL expiry reduces the live count
#      (Redis keyspace notifications are unreliable for accounting).
#   2. ZCARD — count after eviction.
#   3. ZADD + EXPIRE — only if under cap.
#
# A pipeline-based ZCARD-then-ZADD pair would let two concurrent reserves
# both observe ``live == cap - 1`` and both succeed, blowing the cap.
# Lua execution is single-threaded inside Redis, so the script body is
# the atomic unit.
#
# Returns exactly one of: "ok" | "exceeded". Any other path is a bug.
_RESERVE_SCRIPT: Final[str] = """
-- KEYS[1] = alfred:handles:user:{user_id}
-- ARGV[1] = cap (int >= 1)
-- ARGV[2] = handle_id (UUID4 string)
-- ARGV[3] = expiry_ms (int > now_ms)
-- ARGV[4] = now_ms (int > 0)
-- ARGV[5] = outer_ttl (int > 0)
-- Returns "ok" | "exceeded"

local key = KEYS[1]
local cap = tonumber(ARGV[1])
local handle_id = ARGV[2]
local expiry_ms = tonumber(ARGV[3])
local now_ms = tonumber(ARGV[4])
local outer_ttl = tonumber(ARGV[5])

-- Passive eviction of TTL-expired handles. ONLY mechanism by which TTL
-- expiry reduces the count (keyspace notifications are unreliable).
redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms)

local live = redis.call('ZCARD', key)
if live >= cap then
    return 'exceeded'
end

redis.call('ZADD', key, expiry_ms, handle_id)
redis.call('EXPIRE', key, outer_ttl)
return 'ok'
"""


def _validate_argv(
    *,
    cap: int,
    expiry_ms: int,
    now_ms: int,
    outer_ttl: int,
) -> None:
    """Host-side ARGV validation BEFORE EVALSHA.

    Lua's ``tonumber`` returns ``nil`` on non-numeric / NaN / Inf input;
    ``ZADD key, nil, member`` raises a Lua-level error; ``EXPIRE key, nil``
    does the same; a NEGATIVE TTL value passed to ``EXPIRE`` DELETES the
    key in some Redis versions (silent state corruption). All
    ``CLAUDE.md`` hard rule #7 violations. Validate host-side and raise
    :class:`ValueError` loud so the dispatcher's typed-exception ladder
    catches the bug at the trust boundary instead of leaving the cap
    counter desynchronised from real Redis memory.

    Raises:
        ValueError: any of ``cap``, ``expiry_ms``, ``now_ms``,
            ``outer_ttl`` is not a positive ``int`` (``bool`` is
            explicitly rejected even though it subclasses ``int``), or
            ``expiry_ms`` is not strictly greater than ``now_ms``.
    """
    for name, value in (
        ("cap", cap),
        ("expiry_ms", expiry_ms),
        ("now_ms", now_ms),
        ("outer_ttl", outer_ttl),
    ):
        # bool is a subclass of int in Python — exclude explicitly so a
        # caller's ``True`` / ``False`` cannot slip past the type check
        # and end up as ARGV[1] = "True" → tonumber() returns nil.
        if isinstance(value, bool) or not isinstance(value, int):
            msg = f"HandleCap ARGV {name!r} must be int, got {type(value).__name__}"
            raise ValueError(msg)
        if value <= 0:
            msg = f"HandleCap ARGV {name!r} must be > 0, got {value}"
            raise ValueError(msg)
    if expiry_ms <= now_ms:
        msg = f"HandleCap ARGV 'expiry_ms' ({expiry_ms}) must be > 'now_ms' ({now_ms})"
        raise ValueError(msg)


class HandleCap:
    """Per-user concurrent ContentHandle bound (spec §2-§2.4).

    Constructor takes ``redis_url`` + :class:`HandleCapConfig`. Constructs
    a long-lived ``redis.asyncio.Redis`` client on first use (perf-006
    precedent — matches :class:`~alfred.plugins.web_fetch.rate_limit.RateLimiter`
    ``_client`` lifecycle). The Lua script is registered once per
    process via :class:`~redis.commands.core.AsyncScript` and reused via
    EVALSHA with automatic NOSCRIPT fallback.

    The class is constructed ONCE per plugin host process — see the
    module docstring's *Lifecycle* section. Per-request construction
    would re-upload the script on the hot path and lose the EVALSHA
    optimisation.

    Failure model (CLAUDE.md hard rule #7)
    --------------------------------------
    * :meth:`try_reserve` fails CLOSED on any
      :class:`~redis.exceptions.RedisError` subtype (Timeout, Connection,
      Response, BusyLoading, …). The exception propagates uncaught out of
      the dispatcher's Step 3b reserve gate (#339 PR4a) — there is no
      dedicated dispatcher ``transport_error`` audit arm for this path;
      the fault is audited LOUD one layer up by the ``dispatch_tool``
      chokepoint's ``except Exception -> unexpected_error/fault`` catch-all,
      and the conversation turn aborts.
    * :meth:`release` fails LOUD-BUT-QUIET on the same subtypes. The
      caller is already past the conversation turn; re-raising would
      only confuse the caller while the slot is lost either way. Instead
      a LOUD :func:`structlog.get_logger.error` event
      ``web_fetch.handle_cap.release_failed`` fires; passive TTL
      eviction frees the slot within ~120s.

    The structlog event IS the security signal — there is no dedicated
    typed exception class for this case. This is the *structlog-only
    signal* pattern matching the
    :mod:`~alfred.plugins.web_fetch.canary_scanner` ``err-002``
    precedent (see ``canary_scanner.py`` line 425 — quarantine-failed
    branch). Follow-up issue tracks promoting this to a dedicated typed
    event class once the audit vocabulary stabilises across releasers
    (handle-cap, rate-limit, canary-scanner, content-store).
    """

    def __init__(
        self,
        *,
        redis_url: str,
        config: HandleCapConfig | None = None,
    ) -> None:
        self._redis_url = redis_url
        self._config = config or HandleCapConfig()
        self._client: aioredis.Redis | None = None
        self._script: AsyncScript | None = None
        # Serialises lazy first-use init of ``_client`` / ``_script``.
        # ``HandleCap`` is one-per-host and shared across concurrent fetches,
        # so a cold-start burst would race the unguarded `if X is None:`
        # checks below and mint duplicate redis-py clients (each owning its
        # own connection pool) or duplicate ``register_script`` calls (which
        # the AsyncScript registry tolerates but wastes a SCRIPT LOAD). The
        # lock is acquired once per cold start; the steady-state hot path
        # short-circuits before entering it.
        self._init_lock = asyncio.Lock()

    @property
    def redis_url(self) -> str:
        """Exposed so callers can correlate the cap and the
        :class:`~alfred.plugins.web_fetch.content_store.ContentStore`
        share the same Redis (perf-006 connection-pool reuse contract)."""
        return self._redis_url

    async def _get_client(self) -> aioredis.Redis:
        # Fast-path: assume initialised; only take the lock on cold start.
        if self._client is not None:
            return self._client
        async with self._init_lock:
            # Re-check under the lock — a peer task may have minted the
            # client between the fast-path check and lock acquisition.
            if self._client is None:
                # decode_responses=False so the Lua return value comes back
                # as ``bytes`` consistently across redis-py versions (matches
                # RateLimiter._get_script's contract).
                self._client = aioredis.from_url(
                    self._redis_url,
                    decode_responses=False,
                )
        return self._client

    async def _get_script(self) -> AsyncScript:
        client = await self._get_client()
        # Fast-path: assume registered; only take the lock on cold start.
        if self._script is not None:
            return self._script
        async with self._init_lock:
            # Re-check under the lock — a peer task may have registered
            # the script between the fast-path check and lock acquisition.
            if self._script is None:
                self._script = client.register_script(_RESERVE_SCRIPT)
        return self._script

    async def try_reserve(
        self,
        *,
        user_id: str,
        handle_id: str,
        handle_ttl_seconds: int,
    ) -> None:
        """Atomically reserve one cap slot for ``user_id``.

        Args:
            user_id: Canonical user id (slug-format, closed character set).
            handle_id: UUID4 pre-minted by the dispatcher.
            handle_ttl_seconds: TTL of the content body in Redis. Used
                to compute the ZSET member's expiry score.

        Raises:
            WebFetchRateLimited: cap exceeded; ``.bucket == "handle_cap"``.
            ValueError: invalid ARGV (non-int, non-positive, expiry <= now)
                — propagates from :func:`_validate_argv`.
        """
        now_ms = int(time.time() * 1000)
        expiry_ms = now_ms + handle_ttl_seconds * 1000
        outer_ttl = max(
            handle_ttl_seconds * 2,
            _OUTER_KEY_TTL_FLOOR_SECONDS,
        )
        await self._try_reserve_with_args(
            user_id=user_id,
            handle_id=handle_id,
            cap=self._config.per_user,
            expiry_ms=expiry_ms,
            now_ms=now_ms,
            outer_ttl=outer_ttl,
        )

    async def _try_reserve_with_args(
        self,
        *,
        user_id: str,
        handle_id: str,
        cap: int,
        expiry_ms: int,
        now_ms: int,
        outer_ttl: int,
    ) -> None:
        """Lower-level reserve — exposes the raw ARGV for testability.

        The ARGV validator runs BEFORE the Lua script so a malformed
        input cannot induce silent Redis state corruption. Tests pin
        the validator boundary directly via this entry point so a
        regression in :meth:`try_reserve`'s ARGV derivation (e.g. a
        future operator override that lets ``handle_ttl_seconds`` go
        non-positive) cannot bypass the host-side check.
        """
        _validate_argv(
            cap=cap,
            expiry_ms=expiry_ms,
            now_ms=now_ms,
            outer_ttl=outer_ttl,
        )
        script = await self._get_script()
        key = f"{_KEY_PREFIX_USER}{user_id}"
        raw = await script(
            keys=[key],
            args=[
                str(cap),
                handle_id,
                str(expiry_ms),
                str(now_ms),
                str(outer_ttl),
            ],
        )
        result = cast("bytes", raw).decode("ascii")
        if result == "exceeded":
            _log.warning(
                "web_fetch.handle_cap.exceeded",
                user_id=user_id,
                handle_id=handle_id,
            )
            raise WebFetchRateLimited("handle_cap")
        # H-5: defensive check on the Lua return value. The script
        # docstring pins exactly two legal returns ("ok" | "exceeded"); a
        # Lua-side bug, a redis-py decoding regression, or a hostile
        # interpretation of the result must not silently look like a
        # successful reserve. Treat any other return as a hard failure
        # so the dispatcher's typed-exception ladder catches the
        # boundary anomaly at the trust-boundary instead of leaving the
        # cap counter desynced from real Redis state.
        if result != "ok":
            _log.error(
                "web_fetch.handle_cap.unexpected_lua_return",
                user_id=user_id,
                handle_id=handle_id,
                result=result,
            )
            msg = f"HandleCap Lua script returned unexpected value {result!r}"
            raise RuntimeError(msg)

    async def release(
        self,
        *,
        user_id: str,
        handle_id: str,
        correlation_id: str | None = None,
    ) -> None:
        """Idempotent ZREM. Safe to call after passive TTL has already evicted.

        No Lua needed — single-command ZREM is atomic by itself.

        A Redis transient error on release does NOT propagate (the caller is
        already past the conversation turn; raising would only confuse the
        caller while losing the slot anyway). Instead a LOUD
        ``web_fetch.handle_cap.release_failed`` structlog event fires so
        operators see the stuck reservation; passive TTL eviction will free
        the slot within ~120s. The user's effective cap is reduced by 1
        between the failed ZREM and the eviction.

        ``correlation_id`` is optional but the dispatcher always supplies
        it so operators can grep the structlog event back to the
        originating ``web.fetch`` turn. This matches the structlog-only
        signal pattern documented in the class docstring (``err-002``
        precedent in :mod:`~alfred.plugins.web_fetch.canary_scanner` —
        no separate exception class; the structlog event IS the security
        signal until the audit vocabulary stabilises).

        Args:
            user_id: same canonical id used at ``try_reserve`` time.
            handle_id: the UUID4 the dispatcher pre-minted.
            correlation_id: optional structlog correlation tag.
        """
        client = await self._get_client()
        key = f"{_KEY_PREFIX_USER}{user_id}"
        try:
            await client.zrem(key, handle_id)
        except RedisError as exc:
            # Deliberately swallowed — see method docstring + class
            # docstring's *Failure model* section. Type name only — never
            # ``str(exc)`` / ``exc.args``: Redis error messages can echo
            # protocol fragments that include T3 content (spec §5.6,
            # mirrors canary_scanner.py:err-002).
            _log.error(
                "web_fetch.handle_cap.release_failed",
                user_id=user_id,
                handle_id=handle_id,
                correlation_id=correlation_id,
                exception_type=type(exc).__name__,
                note=(
                    "ZREM failed; cap slot held until passive TTL (~120s). "
                    "User's effective cap is reduced by 1 until eviction."
                ),
            )

    async def aclose(self) -> None:
        """Idempotent close — supervisor SIGKILL paths.

        Drops the underlying Redis client and the cached script
        reference. Calling more than once must not raise; the second
        call observes ``self._client is None`` and returns.
        """
        if self._client is not None:
            client = self._client
            self._client = None
            self._script = None
            await client.aclose()


__all__ = ["HandleCap", "HandleCapConfig"]
