"""``BurstLimiter`` — per-(canonical_user_id, persona) token bucket (PR-S4-8, #152).

Honest new Slice-4 scope (sec-008 round-3): the Slice-2 ``BudgetGuard`` caps
USD-per-day; it cannot stop a sub-second burst of quarantined-extract calls
driven by a flood of inbound comms messages. This primitive does.

Algorithm — token bucket, ``time.monotonic()`` refill math (comms-003):

* Each ``(canonical_user_id, persona)`` key owns a bucket holding up to
  ``capacity_tokens`` tokens, refilling at 1 token per ``refill_seconds``.
* ``acquire`` refills based on elapsed *monotonic* time (NTP step / DST shift
  cannot corrupt the running balance), then:
  - if a whole token is available, consumes it and returns ``Acquired`` with
    ``waited_seconds == 0`` (the fast path);
  - else computes the wait until the next token. If that wait exceeds
    ``drop_after_seconds`` the message is dropped (``Dropped``); otherwise the
    caller is back-pressured (``await sleep(wait)``) and then served.

Audit (CLAUDE.md hard rule #7 — security paths are loud):

* every back-pressure or drop emits a ``COMMS_INBOUND_BUDGET_CAPPED_FIELDS``
  row (``dropped`` distinguishes the two);
* a hard drop additionally emits the distinct ``comms.inbound.dropped`` audit
  event (NOT a hookpoint — it is a terminal observability row).

perf-001 — bucket eviction: the per-key bucket map is an ``OrderedDict`` capped
at ``max_tracked_buckets`` (default 10_000) with LRU eviction. An adversary
cycling distinct keys cannot exhaust host memory; the per-key ``asyncio.Lock``
is evicted alongside its bucket.

In-flight safety (CR #232). ``acquire`` holds the per-key lock across
``_backpressure``'s ``await sleep``, so a CONCURRENT acquire for a different key
must not evict the parked key's bucket + lock out from under it — doing so would
let the next same-key acquire mint a fresh full bucket and a new lock,
bypassing the outstanding wait (a same-key rate-limit bypass under churn). Keys
with an in-flight acquire are refcounted (``_active``) and SKIPPED by eviction;
only idle keys are dropped, so the memory bound still holds.

``drop_after_seconds`` home (reviewer note): the shared ``BurstLimiterPolicy``
(``alfred.policies.model``) is a cross-PR contract anchor pinned by
``tests/unit/policies/test_burst_limiter_policy_defaults.py`` and consumed by
PR-S4-4; it carries only ``capacity_tokens`` / ``refill_seconds``. Adding a
field would move that contract and force PR-S4-4's pinned test to change.
``drop_after_seconds`` is a comms-only concern no other consumer needs, so it
lives as a ``BurstLimiter`` constructor default (30.0) instead — keeping the
shared policy untouched.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol

from alfred.audit import audit_row_schemas
from alfred.policies.model import BurstLimiterPolicy


class _AuditWriterLike(Protocol):
    """Structural type for the audit-writer dependency.

    The real :class:`alfred.audit.log.AuditWriter` satisfies this by virtue of
    its ``append`` / ``append_schema`` coroutine signatures; tests inject a
    spy. ``**kwargs`` is typed ``Any`` because the writer's keyword surface is
    wide and stable on the concrete class — the limiter forwards a fixed set
    of named arguments at each call site.
    """

    async def append(self, **kwargs: Any) -> None: ...

    async def append_schema(self, **kwargs: Any) -> None: ...


# Defaults — mirror ``BurstLimiterPolicy`` so a bare ``BurstLimiter()`` and a
# ``BurstLimiter.from_policy(BurstLimiterPolicy())`` behave identically.
_DEFAULT_CAPACITY: Final[int] = 5
_DEFAULT_REFILL_SECONDS: Final[float] = 5.0
_DEFAULT_DROP_AFTER_SECONDS: Final[float] = 30.0
_DEFAULT_MAX_TRACKED_BUCKETS: Final[int] = 10_000

# Audit-row defaults for fields the caller did not thread through. The
# reference plugin exercises ``acquire`` without an adapter/language; real
# inbound callers pass them from the resolved identity.
_DEFAULT_ADAPTER_ID: Final[str] = "unknown"
_DEFAULT_LANGUAGE: Final[str] = "en-US"

_DROPPED_EVENT: Final[str] = "comms.inbound.dropped"


@dataclass(frozen=True)
class Acquired:
    """A token was granted (possibly after back-pressure waiting)."""

    tokens_remaining: int
    waited_seconds: float


@dataclass(frozen=True)
class Dropped:
    """The bucket stayed empty past ``drop_after_seconds``; the message is dropped."""

    waited_seconds: float
    bucket_empty_since: datetime


@dataclass
class _BucketState:
    """Mutable per-key token-bucket state. Monotonic timestamps only."""

    tokens: float
    last_refill_monotonic: float
    empty_since_monotonic: float | None


async def _real_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


class BurstLimiter:
    """Per-(canonical_user_id, persona) token-bucket rate limiter.

    ``monotonic`` and ``sleep`` are injectable so tests drive time
    deterministically; production uses ``time.monotonic`` and
    ``asyncio.sleep``.
    """

    def __init__(
        self,
        *,
        capacity_tokens: int = _DEFAULT_CAPACITY,
        refill_seconds: float = _DEFAULT_REFILL_SECONDS,
        drop_after_seconds: float = _DEFAULT_DROP_AFTER_SECONDS,
        audit_writer: _AuditWriterLike,
        max_tracked_buckets: int = _DEFAULT_MAX_TRACKED_BUCKETS,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = _real_sleep,
    ) -> None:
        self._capacity = capacity_tokens
        self._refill_seconds = refill_seconds
        self._drop_after_seconds = drop_after_seconds
        self._audit = audit_writer
        self._max_tracked_buckets = max_tracked_buckets
        self._monotonic = monotonic
        self._sleep = sleep
        # LRU-ordered: most-recently-used at the end (``move_to_end``).
        self._buckets: OrderedDict[tuple[str, str], _BucketState] = OrderedDict()
        self._locks: OrderedDict[tuple[str, str], asyncio.Lock] = OrderedDict()
        # Refcount of in-flight ``acquire`` calls per key (CR #232). A key with
        # ``_active[key] > 0`` is mid-acquire (its lock is held, possibly across
        # a back-pressure sleep) and must NOT be evicted.
        self._active: dict[tuple[str, str], int] = {}

    @classmethod
    def from_policy(
        cls,
        policy: BurstLimiterPolicy,
        *,
        audit_writer: _AuditWriterLike,
        drop_after_seconds: float = _DEFAULT_DROP_AFTER_SECONDS,
        max_tracked_buckets: int = _DEFAULT_MAX_TRACKED_BUCKETS,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = _real_sleep,
    ) -> BurstLimiter:
        """Build a limiter reading capacity/refill from the shared policy.

        Single source of truth for ``capacity_tokens`` / ``refill_seconds``
        (PR-S4-4 contract anchor). ``drop_after_seconds`` stays a comms-side
        knob — see the module docstring's reviewer note.
        """
        return cls(
            capacity_tokens=policy.capacity_tokens,
            refill_seconds=policy.refill_seconds,
            drop_after_seconds=drop_after_seconds,
            audit_writer=audit_writer,
            max_tracked_buckets=max_tracked_buckets,
            monotonic=monotonic,
            sleep=sleep,
        )

    @property
    def drop_after_seconds(self) -> float:
        return self._drop_after_seconds

    @property
    def tracked_bucket_count(self) -> int:
        return len(self._buckets)

    async def acquire(
        self,
        *,
        canonical_user_id: str,
        persona: str,
        adapter_id: str = _DEFAULT_ADAPTER_ID,
        language: str = _DEFAULT_LANGUAGE,
    ) -> Acquired | Dropped:
        """Acquire one token for ``(canonical_user_id, persona)``.

        Returns ``Acquired`` on the fast path or after back-pressure; returns
        ``Dropped`` when the projected wait exceeds ``drop_after_seconds``.
        """
        key = (canonical_user_id, persona)
        # Mark the key in-flight BEFORE taking the lock so eviction skips it the
        # whole time this call is parked on the lock or its back-pressure sleep
        # (CR #232). Decremented in ``finally`` so an exception cannot pin a key.
        self._active[key] = self._active.get(key, 0) + 1
        try:
            lock = self._lock_for(key)
            async with lock:
                bucket = self._bucket_for(key)
                now = self._monotonic()
                self._refill(bucket, now)

                if bucket.tokens >= 1.0:
                    bucket.tokens -= 1.0
                    # A consumed-to-empty bucket starts its empty clock.
                    if bucket.tokens < 1.0:
                        bucket.empty_since_monotonic = now
                    return Acquired(tokens_remaining=int(bucket.tokens), waited_seconds=0.0)

                # No whole token: compute the wait until the next one. The bucket
                # is necessarily below one token here, so its empty clock was set
                # either at the consuming acquire or by ``_refill`` — never None.
                deficit = 1.0 - bucket.tokens
                wait_seconds = deficit * self._refill_seconds
                empty_since = bucket.empty_since_monotonic
                assert empty_since is not None  # invariant guard (see comment above)

                if wait_seconds > self._drop_after_seconds:
                    return await self._drop(
                        bucket=bucket,
                        empty_since_monotonic=empty_since,
                        now=now,
                        canonical_user_id=canonical_user_id,
                        persona=persona,
                        adapter_id=adapter_id,
                        language=language,
                    )

                return await self._backpressure(
                    bucket=bucket,
                    wait_seconds=wait_seconds,
                    canonical_user_id=canonical_user_id,
                    persona=persona,
                    adapter_id=adapter_id,
                    language=language,
                )
        finally:
            remaining = self._active[key] - 1
            if remaining:
                self._active[key] = remaining
            else:
                del self._active[key]

    # ----- internals -------------------------------------------------------

    def _refill(self, bucket: _BucketState, now: float) -> None:
        elapsed = now - bucket.last_refill_monotonic
        if elapsed <= 0:
            return
        refilled = elapsed / self._refill_seconds
        bucket.tokens = min(float(self._capacity), bucket.tokens + refilled)
        bucket.last_refill_monotonic = now
        if bucket.tokens >= 1.0:
            # A whole token is available again; the empty window has closed.
            # (When refill leaves the bucket below one token the empty clock
            # set at the consuming acquire stays put — see ``acquire``.)
            bucket.empty_since_monotonic = None

    async def _backpressure(
        self,
        *,
        bucket: _BucketState,
        wait_seconds: float,
        canonical_user_id: str,
        persona: str,
        adapter_id: str,
        language: str,
    ) -> Acquired:
        await self._sleep(wait_seconds)
        now = self._monotonic()
        self._refill(bucket, now)
        bucket.tokens -= 1.0
        bucket.empty_since_monotonic = now if bucket.tokens < 1.0 else None
        await self._emit_capped(
            tokens_available=bucket.tokens,
            wait_seconds=wait_seconds,
            dropped=False,
            canonical_user_id=canonical_user_id,
            persona=persona,
            adapter_id=adapter_id,
            language=language,
        )
        return Acquired(tokens_remaining=int(bucket.tokens), waited_seconds=wait_seconds)

    async def _drop(
        self,
        *,
        bucket: _BucketState,
        empty_since_monotonic: float,
        now: float,
        canonical_user_id: str,
        persona: str,
        adapter_id: str,
        language: str,
    ) -> Dropped:
        wait_seconds = self._drop_after_seconds
        # Display value: derive an aware wall-clock instant for the empty
        # window start from the monotonic delta (monotonic has no epoch).
        empty_for = now - empty_since_monotonic
        bucket_empty_since = datetime.now(UTC) - timedelta(seconds=empty_for)
        await self._emit_capped(
            tokens_available=bucket.tokens,
            wait_seconds=wait_seconds,
            dropped=True,
            canonical_user_id=canonical_user_id,
            persona=persona,
            adapter_id=adapter_id,
            language=language,
        )
        await self._audit.append(
            event=_DROPPED_EVENT,
            actor_user_id=canonical_user_id,
            subject={
                "adapter_id": adapter_id,
                "canonical_user_id": canonical_user_id,
                "persona": persona,
                "bucket_empty_since": bucket_empty_since.isoformat(),
            },
            trust_tier_of_trigger="T3",
            result="dropped",
            cost_estimate_usd=0.0,
            trace_id=canonical_user_id,
            language=language,
        )
        return Dropped(waited_seconds=wait_seconds, bucket_empty_since=bucket_empty_since)

    async def _emit_capped(
        self,
        *,
        tokens_available: float,
        wait_seconds: float,
        dropped: bool,
        canonical_user_id: str,
        persona: str,
        adapter_id: str,
        language: str,
    ) -> None:
        await self._audit.append_schema(
            fields=audit_row_schemas.COMMS_INBOUND_BUDGET_CAPPED_FIELDS,
            schema_name="COMMS_INBOUND_BUDGET_CAPPED_FIELDS",
            event="comms.inbound.budget_capped",
            actor_user_id=canonical_user_id,
            subject={
                "adapter_id": adapter_id,
                "canonical_user_id": canonical_user_id,
                "persona": persona,
                "tokens_available": tokens_available,
                "wait_seconds": wait_seconds,
                "dropped": dropped,
                "observed_at": datetime.now(UTC).isoformat(),
                "language": language,
            },
            trust_tier_of_trigger="T3",
            result="dropped" if dropped else "capped",
            cost_estimate_usd=0.0,
            trace_id=canonical_user_id,
            language=language,
        )

    def _bucket_for(self, key: tuple[str, str]) -> _BucketState:
        existing = self._buckets.get(key)
        if existing is not None:
            self._buckets.move_to_end(key)
            return existing
        now = self._monotonic()
        bucket = _BucketState(
            tokens=float(self._capacity),
            last_refill_monotonic=now,
            empty_since_monotonic=None,
        )
        self._buckets[key] = bucket
        self._evict_if_needed()
        return bucket

    def _lock_for(self, key: tuple[str, str]) -> asyncio.Lock:
        existing = self._locks.get(key)
        if existing is not None:
            self._locks.move_to_end(key)
            return existing
        lock = asyncio.Lock()
        self._locks[key] = lock
        return lock

    def _evict_if_needed(self) -> None:
        while len(self._buckets) > self._max_tracked_buckets:
            evict_key = self._oldest_idle_key()
            if evict_key is None:
                # Every tracked key has an in-flight acquire (CR #232): evicting
                # any of them would drop a bucket/lock out from under a parked
                # coroutine. Leave the map over-cap until a key goes idle — the
                # overshoot is bounded by the number of concurrent acquirers.
                return
            del self._buckets[evict_key]
            # Evict the matching lock too (locks share the bucket lifetime).
            self._locks.pop(evict_key, None)

    def _oldest_idle_key(self) -> tuple[str, str] | None:
        """Return the LRU-oldest key with NO in-flight acquire, or ``None``."""
        for candidate in self._buckets:
            if self._active.get(candidate, 0) == 0:
                return candidate
        return None


__all__ = ["Acquired", "BurstLimiter", "Dropped"]
