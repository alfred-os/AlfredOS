"""AlfredOS per-user rate-limiter Protocol surface.

This module defines the **seam** that the orchestrator and other consumers
depend on; the concrete in-process token-bucket implementation
(``InProcessTokenBucketRateLimiter``) lives in PR D1.

Why a Protocol-first stub:

* ``IdentityResolver`` (T11) takes a ``RateLimiter`` for type hints. Shipping
  the Protocol now keeps PR A self-contained without dragging in the token
  bucket.
* PR B tests + the Slice-1/2 CLI wire-up need a no-op double they can wire
  in until PR D1 ships the in-process token bucket. :class:`NullRateLimiter`
  is the public stand-in; it is production-acceptable for single-operator
  deployments where every authenticated caller is the operator (operators
  have unlimited rate-limit defaults), but the production
  ``InProcessTokenBucketRateLimiter`` from PR D1 is required as soon as
  multi-user authorization tiers (``READ_ONLY``) actually route through the
  orchestrator.

Security note: ``allow()`` takes the full ``User`` rather than a slug because
the concrete limiter must consult ``user.authorization`` —
``Authorization.READ_ONLY`` returns ``False`` unconditionally (spec §2
line 223). Passing the typed ``User`` at the seam makes that gate
impossible to forget at call sites. The null double does NOT enforce that
invariant (it's a no-op); the production limiter in PR D1 does.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Protocol

from alfred.identity.models import Authorization, User


@dataclass(frozen=True)
class RateLimiterHealth:
    """Snapshot of limiter state for ``alfred status`` / metrics surfaces.

    Process-lifetime counters — restarts reset them. Operators correlate
    against the audit log for durable history.

    ``active_user_count`` + ``total_refusals_since_start`` were the
    original Slice-1 fields; ``total_allowed_since_start`` was added by
    PR D1 to give operators an allow/refuse ratio at a glance. The PR D1
    field is optional (defaulted to ``0``) so the slice-1
    :class:`NullRateLimiter` keeps its existing constructor call site
    working without churn.
    """

    active_user_count: int
    total_refusals_since_start: int
    total_allowed_since_start: int = 0


class RateLimiter(Protocol):
    """Per-user rate-limiting seam.

    Implementations decide policy (token bucket, leaky bucket, sliding
    window). Consumers depend only on this surface.
    """

    async def allow(self, user: User) -> bool:
        """Return True if ``user`` may proceed; False if they're rate-limited.

        Concrete implementations MUST return False unconditionally for
        ``user.authorization == Authorization.READ_ONLY`` (spec §2 line 223,
        architect-002).
        """
        # Protocol bodies must declare *some* body; ``raise`` is preferred
        # over ``...`` so accidental instantiation fails loudly, and so
        # CodeQL's py/ineffectual-statement doesn't flag the ellipsis.
        raise NotImplementedError

    async def reset(self, user_id: str) -> None:
        """Clear any accumulated state for the given user slug.

        Called on authorization changes and on explicit operator action.
        """
        raise NotImplementedError

    def health(self) -> RateLimiterHealth:
        """Return a point-in-time snapshot for surfaces like ``alfred status``."""
        raise NotImplementedError


class NullRateLimiter:
    """No-op rate limiter — always allows, tracks only the lifetime refusal counter.

    Production-acceptable for Slice-1/2 single-operator deployments per
    ADR-0010: every authenticated caller is the operator, and operators
    have unlimited rate-limit defaults, so there is no policy decision to
    make. PR D1 ships :class:`InProcessTokenBucketRateLimiter`, which is
    required as soon as multi-user authorization tiers (``READ_ONLY``)
    actually route through the orchestrator — that limiter enforces the
    ``READ_ONLY`` gate this double deliberately skips.

    Exported in ``__all__`` (see :mod:`alfred.identity`) so the slice-1 CLI
    bootstrap and the slice-2 TUI wire-up can import it without reaching
    into private names.
    """

    def __init__(self) -> None:
        self._refusals = 0

    async def allow(self, user: User) -> bool:  # noqa: ARG002 — Protocol surface; param unused in no-op
        return True

    async def reset(self, user_id: str) -> None:  # noqa: ARG002 — Protocol surface; param unused in no-op
        return None

    def health(self) -> RateLimiterHealth:
        return RateLimiterHealth(active_user_count=0, total_refusals_since_start=self._refusals)


# ---------------------------------------------------------------------------
# Slice-2 production rate limiter (PR D1)
# ---------------------------------------------------------------------------


# Authorization-tier defaults. ``None`` means unlimited (operator). Per spec
# §3 line 478-483. Wrapped in ``MappingProxyType`` so the lookup table is
# immutable at the value level (CLAUDE.md "immutability by default").
AUTH_DEFAULT_PER_MIN: Final[MappingProxyType[Authorization, int | None]] = MappingProxyType(
    {
        Authorization.READ_ONLY: 0,
        Authorization.STANDARD: 30,
        Authorization.TRUSTED: 60,
        Authorization.OPERATOR: None,
    }
)


class _Bucket:
    """One user's token bucket.

    Capacity is the per-minute allowance. Tokens refill linearly at
    ``capacity / 60`` per second so a steady-state caller paces uniformly
    rather than burning the entire minute's budget in one burst.

    Implementation note: ``time.monotonic`` is the right clock — wall-clock
    jumps (NTP correction, manual change) would otherwise let a caller
    double-spend their bucket. ``monotonic`` never goes backwards.
    """

    __slots__ = ("capacity", "last_refill", "tokens")

    def __init__(self, *, capacity: int, now: float) -> None:
        self.capacity = capacity
        # Start at full capacity so a fresh user can immediately spend.
        self.tokens: float = float(capacity)
        self.last_refill: float = now

    def take_one(self, *, now: float) -> bool:
        """Attempt to consume one token. Returns True iff a token was taken."""
        # Refill: linear refill rate of (capacity / 60) per second.
        elapsed = now - self.last_refill
        if elapsed > 0:
            refilled = elapsed * (self.capacity / 60.0)
            self.tokens = min(float(self.capacity), self.tokens + refilled)
            self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class InProcessTokenBucketRateLimiter:
    """Per-user token-bucket limiter — Slice-2 production implementation.

    The ``allow()`` method is the security gate that enforces the
    READ_ONLY refusal invariant (spec §2 line 223). The first line of
    the method MUST be the READ_ONLY check; ``test_rate_limit`` pins
    this with the load-bearing
    ``test_read_only_user_refused_regardless_of_override`` assertion.

    Concurrency: a per-user-slug ``asyncio.Lock`` registry serialises
    the take-token critical section. The registry itself is guarded by
    a registry-level lock so two simultaneous first-touches don't
    create two different lock instances. Same pattern as
    :class:`alfred.memory.working_pool.WorkingMemoryPool`.

    The clock is injectable for tests via ``time_source`` so the recovery
    cadence test can advance time without sleeping for 60 seconds.
    """

    def __init__(self, *, time_source: Callable[[], float] | None = None) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._registry_lock = asyncio.Lock()
        # Counter snapshot consumed by ``health()``.
        self._total_allowed: int = 0
        self._total_refused: int = 0
        # The clock. Default to ``time.monotonic`` (wall-clock-safe).
        self._now: Callable[[], float] = time_source if time_source is not None else time.monotonic

    def _clock(self) -> float:
        return float(self._now())

    async def _get_lock(self, slug: str) -> asyncio.Lock:
        async with self._registry_lock:
            lock = self._locks.get(slug)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[slug] = lock
            return lock

    async def allow(self, user: User) -> bool:
        """Decide whether ``user`` may proceed.

        Order of checks (security-invariant; do not reorder without
        updating spec §2 line 223):

        1. ``Authorization.READ_ONLY`` short-circuits to False — even
           if ``user.rate_limit_per_min`` is set, the override is
           ignored because the check ran first.
        2. Soft-deleted users (``deleted_at IS NOT NULL``) short-circuit
           to False — defense in depth; the resolver should never hand
           the limiter a soft-deleted user.
        3. ``Authorization.OPERATOR`` short-circuits to True (unlimited).
        4. Otherwise resolve the per-minute cap from ``user.rate_limit_per_min``
           (override) or :data:`AUTH_DEFAULT_PER_MIN` (tier default) and
           take a token from the bucket.
        """
        # Normalize ``user.authorization`` to the enum up-front. SQLAlchemy
        # may hand back either the ``Authorization`` member (when the ORM
        # column type registered the enum) or the bare value-string (when
        # a fresh row is built in tests). Comparing against ``.value``
        # would miss the enum-member case and silently let READ_ONLY slip
        # past the gate. ``Authorization(x)`` is the identity on a member
        # and a coercion on a string, so this one line covers both.
        auth = Authorization(user.authorization)
        # Step 1 — READ_ONLY security invariant. THIS MUST BE THE FIRST
        # SUBSTANTIVE CHECK. See spec §2 line 223.
        if auth is Authorization.READ_ONLY:
            self._total_refused += 1
            return False
        # Step 2 — soft-delete defense-in-depth.
        if user.deleted_at is not None:
            self._total_refused += 1
            return False
        # Step 3 — operator short-circuit.
        if auth is Authorization.OPERATOR:
            self._total_allowed += 1
            return True
        # Step 4 — bucket lookup. Override wins when set.
        per_min: int | None
        if user.rate_limit_per_min is not None:
            per_min = user.rate_limit_per_min
        else:
            per_min = AUTH_DEFAULT_PER_MIN.get(auth)
        if per_min is None:
            # Defensive: any tier whose default is ``None`` is unlimited.
            # Only OPERATOR carries that default, and we already short-
            # circuited; reaching here means an admin set a NULL override
            # on a non-operator tier (shouldn't happen — the schema CHECK
            # allows NULL but ``alfred user set`` defends against it).
            self._total_allowed += 1
            return True
        if per_min <= 0:
            # Explicit zero override (or pathological negative) means
            # "deny everything". Treat as a refusal so the audit reflects
            # the choice.
            self._total_refused += 1
            return False
        slug = user.slug
        lock = await self._get_lock(slug)
        async with lock:
            bucket = self._buckets.get(slug)
            now = self._clock()
            if bucket is None or bucket.capacity != per_min:
                # Re-init the bucket when the cap changes (override flip
                # mid-session). Discards any accumulated debt — operators
                # consider that intentional.
                bucket = _Bucket(capacity=per_min, now=now)
                self._buckets[slug] = bucket
            allowed = bucket.take_one(now=now)
            if allowed:
                self._total_allowed += 1
            else:
                self._total_refused += 1
            return allowed

    async def reset(self, user_id: str) -> None:
        """Drop the bucket for ``user_id`` so the next ``allow()`` starts fresh.

        Called from CLI surfaces on authorization changes (e.g.
        ``alfred user set --authorization standard``) so the previous
        tier's bucket doesn't leak into the new tier's policy.
        """
        lock = await self._get_lock(user_id)
        async with lock:
            self._buckets.pop(user_id, None)

    def health(self) -> RateLimiterHealth:
        """Return the lifetime-counter snapshot.

        ``active_user_count`` reflects the number of live buckets — one
        per user that has hit the limiter at least once since startup
        (read_only / operator users that short-circuit never get a
        bucket).
        """
        return RateLimiterHealth(
            active_user_count=len(self._buckets),
            total_refusals_since_start=self._total_refused,
            total_allowed_since_start=self._total_allowed,
        )
