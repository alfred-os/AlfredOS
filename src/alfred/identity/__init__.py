"""AlfredOS identity layer.

Multi-user identity, platform-binding, and per-user resolution. Public surface
is intentionally narrow:

* ``User`` / ``PlatformIdentity`` — SQLAlchemy ORMs.
* ``Authorization`` / ``Platform`` — closed-domain enums (snake_case in DB; the
  Typer CLI accepts kebab-case and normalises at the boundary).
* ``IdentityResolver`` — the only legitimate accessor for the two ORMs.
* ``IdentityVersionCounter`` — bump-on-mutate primitive subscribed by the
  resolver's in-process LRU and (in PR B) by ``BudgetGuard``.
* Error types — ``OperatorAlreadyExistsError``, ``LastOperatorRemovalRefusedError``,
  ``OperatorSlugCollisionError``, ``IdentityResolutionError``.
"""

from __future__ import annotations

from alfred.identity.errors import (
    IdentityError,
    IdentityResolutionError,
    LastOperatorRemovalRefusedError,
    OperatorAlreadyExistsError,
    OperatorSlugCollisionError,
)
from alfred.identity.models import (
    Authorization,
    Platform,
    PlatformIdentity,
    User,
)
from alfred.identity.rate_limit import (
    RateLimiter,
    RateLimiterHealth,
)
from alfred.identity.rate_limit import (
    _NullRateLimiter as _NullRateLimiter,  # test-only re-export; intentionally absent from __all__
)
from alfred.identity.resolver import IdentityResolver
from alfred.identity.slug import derive_slug
from alfred.identity.version_counter import IdentityVersionCounter

__all__ = [
    "Authorization",
    "IdentityError",
    "IdentityResolutionError",
    "IdentityResolver",
    "IdentityVersionCounter",
    "LastOperatorRemovalRefusedError",
    "OperatorAlreadyExistsError",
    "OperatorSlugCollisionError",
    "Platform",
    "PlatformIdentity",
    "RateLimiter",
    "RateLimiterHealth",
    "User",
    "derive_slug",
]
