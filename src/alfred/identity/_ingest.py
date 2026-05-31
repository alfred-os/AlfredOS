"""Ingress trust-tier derivation - role x adapter classification.

This module owns the ONLY legitimate place where raw identity +
adapter metadata is translated into a TrustTier for a user's message.
It lives in alfred.identity (NOT in alfred.orchestrator.core) because
the orchestrator's invariant is that input arrives already-tagged at
its boundary - placing this logic in core.py would violate that.

Each CommsAdapter calls _ingest_tier at its ingress boundary before
passing tagged content to the orchestrator.

Rule (spec §3.6):

- TUI + operator role -> T1 (operator tier: highest-trust, TUI only)
- Discord + operator role -> T2 (Discord is broadcast-shaped, never T1)
- Any role + any adapter -> T2 otherwise (safe default)

T1 outbound channel is TUI stdout only in Slice 3.
The ``.authorization`` field on User is a ``Mapped[str]`` column - compare
against ``Authorization.OPERATOR.value`` (a str), not the enum itself,
per resolver.py:183 comment and the existing usage pattern.

See ADR-0017, spec §3.6.
"""

from __future__ import annotations

from alfred.identity.models import Authorization
from alfred.security.tiers import T1, T2, TrustTier


def _ingest_tier(user: object, adapter_name: str) -> type[TrustTier]:
    """Derive ingress trust tier from the role x adapter pair.

    Args:
        user: Any object with an ``authorization`` attribute (``Mapped[str]``).
            Typically :class:`alfred.identity.models.User`; typed as ``object``
            here to avoid circular imports at the identity boundary.
        adapter_name: The ``CommsAdapter.name`` string (e.g. ``"tui"``,
            ``"discord"``).

    Returns:
        ``T1`` for TUI + operator; ``T2`` for all other combinations.

    Spec §3.6 is explicit: Discord is broadcast-shaped and never T1 even
    for operator-role users. This invariant is hard-coded here rather than
    left to per-adapter configuration to prevent misconfiguration drift.
    """
    authorization: str = getattr(user, "authorization", "")
    if adapter_name == "tui" and authorization == Authorization.OPERATOR.value:
        return T1
    return T2
