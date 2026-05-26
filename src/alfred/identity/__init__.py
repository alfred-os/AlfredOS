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

__all__ = [
    "IdentityError",
    "IdentityResolutionError",
    "LastOperatorRemovalRefusedError",
    "OperatorAlreadyExistsError",
    "OperatorSlugCollisionError",
]
