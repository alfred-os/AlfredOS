"""AlfredOS per-user rate-limiter Protocol surface.

This module defines the **seam** that the orchestrator and other consumers
depend on; the concrete in-process token-bucket implementation
(``InProcessTokenBucketRateLimiter``) lives in PR D1.

Why a Protocol-first stub:

* ``IdentityResolver`` (T11) takes a ``RateLimiter`` for type hints. Shipping
  the Protocol now keeps PR A self-contained without dragging in the token
  bucket.
* PR B tests need a no-op double they can wire in. ``_NullRateLimiter`` is
  test-only (leading underscore, intentionally not in ``__all__``).

Security note: ``allow()`` takes the full ``User`` rather than a slug because
the concrete limiter must consult ``user.authorization`` —
``Authorization.READ_ONLY`` returns ``False`` unconditionally (spec §2
line 223). Passing the typed ``User`` at the seam makes that gate
impossible to forget at call sites. The null double does NOT enforce that
invariant (it's a test no-op); the production limiter in PR D1 does.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from alfred.identity.models import User


@dataclass(frozen=True)
class RateLimiterHealth:
    """Snapshot of limiter state for ``alfred status`` / metrics surfaces.

    ``total_refusals_since_start`` is a process-lifetime counter — restarts
    reset it. Operators correlate against the audit log for durable history.
    """

    active_user_count: int
    total_refusals_since_start: int


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
        ...

    async def reset(self, user_id: str) -> None:
        """Clear any accumulated state for the given user slug.

        Called on authorization changes and on explicit operator action.
        """
        ...

    def health(self) -> RateLimiterHealth:
        """Return a point-in-time snapshot for surfaces like ``alfred status``."""
        ...


class _NullRateLimiter:
    """No-op test double — always allows, never tracks state.

    Intentionally NOT in ``__all__``: this is for tests + PR B wiring only.
    The production path uses ``InProcessTokenBucketRateLimiter`` (PR D1),
    which enforces the ``READ_ONLY`` gate that this double deliberately
    skips.
    """

    def __init__(self) -> None:
        self._refusals = 0

    async def allow(self, user: User) -> bool:  # noqa: ARG002 — Protocol surface; param unused in no-op
        return True

    async def reset(self, user_id: str) -> None:  # noqa: ARG002 — Protocol surface; param unused in no-op
        return None

    def health(self) -> RateLimiterHealth:
        return RateLimiterHealth(active_user_count=0, total_refusals_since_start=self._refusals)
