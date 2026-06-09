"""Comms-MCP hookpoint declarations (PR-S4-8, #152, spec §10).

Two hookpoints, both ``fail_closed=True`` + ``allow_error_substitution=False``:

* ``comms.inbound.t3_promoted`` — fired by the host after an inbound body is
  promoted across the T3 boundary. ``carrier_tier=T3`` (it observes T3-derived
  context). Subscribable by the system + operator tiers only
  (:data:`SYSTEM_OPERATOR_TIERS`) — a quarantined (``user-plugin``) subscriber
  is refused so an untrusted plugin cannot observe the promotion event.
* ``comms.adapter.crashed`` — fired when an adapter reports an unrecoverable
  crash. ``carrier_tier=T0`` (host-internal supervisor signal). Subscribable by
  every tier (:data:`OPEN_TIERS`) — operators and authenticated personas may
  observe a crash.

Reality note (foundation gap). ``register_hookpoint``'s ``carrier_tier`` is the
:class:`alfred.security.tiers.TrustTier` *class* (``T3`` / ``T0``), NOT a string;
``subscribable_tiers`` uses the ``"system"``/``"operator"``/``"user-plugin"``
vocabulary, NOT ``"T0"``/``"T1"``. The plan's pseudocode used string tiers; the
real registry API is what ships here.

Registration follows the per-subsystem :func:`declare_hookpoints` precedent
(``alfred.security.quarantine`` / ``alfred.identity._ingest``). The two names are
listed in :data:`alfred.hooks._known_hookpoints.KNOWN_HOOKPOINTS` under this
module so the drift detector imports it on its full-import sweep. The
module-bottom call runs the declaration at import time.

The ``comms.adapter.binding_requested`` and ``comms.adapter.rate_limit_signal``
hookpoints belong to PR-S4-9 (§3 index) and are intentionally NOT registered
here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from alfred.hooks import get_registry
from alfred.hooks.registry import OPEN_TIERS, SYSTEM_OPERATOR_TIERS
from alfred.security.tiers import T0, T3

if TYPE_CHECKING:
    from alfred.hooks.registry import HookRegistry

INBOUND_T3_PROMOTED_HOOKPOINT = "comms.inbound.t3_promoted"
ADAPTER_CRASHED_HOOKPOINT = "comms.adapter.crashed"


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Register the two comms-MCP hookpoints (spec §10).

    Idempotent against the active registry (the registry's re-declaration guard
    is a no-op on identical metadata), so a test fixture that swaps the registry
    and re-imports this module re-runs the declaration safely.

    Args:
        registry: Optional override for tests that declare against a
            non-singleton registry. Defaults to :func:`get_registry`.
    """
    target = registry if registry is not None else get_registry()
    target.register_hookpoint(
        name=INBOUND_T3_PROMOTED_HOOKPOINT,
        subscribable_tiers=SYSTEM_OPERATOR_TIERS,
        refusable_tiers=frozenset(),
        fail_closed=True,
        carrier_tier=T3,
        allow_error_substitution=False,
    )
    target.register_hookpoint(
        name=ADAPTER_CRASHED_HOOKPOINT,
        subscribable_tiers=OPEN_TIERS,
        refusable_tiers=frozenset(),
        fail_closed=True,
        carrier_tier=T0,
        allow_error_substitution=False,
    )


# Module-bottom call — runs at import time so the hookpoints are declared
# before any subscriber registration or dispatch lands (mirrors
# ``alfred.security.quarantine``).
declare_hookpoints()


__all__ = [
    "ADAPTER_CRASHED_HOOKPOINT",
    "INBOUND_T3_PROMOTED_HOOKPOINT",
    "declare_hookpoints",
]
