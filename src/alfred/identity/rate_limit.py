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
