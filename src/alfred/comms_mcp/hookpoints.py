"""Comms-MCP hookpoint declarations (PR-S4-8, #152, spec §10).

The spec §10 table is the single source of truth. The two hookpoints DIVERGE in
both tier-set and ``fail_closed``:

* ``comms.inbound.t3_promoted`` — fired by the host after an inbound body is
  promoted across the T3 boundary. ``carrier_tier=T3`` (it carries the inbound
  body — the narrowest tier), ``fail_closed=True``,
  ``allow_error_substitution=False``. Subscribable by the **system tier only**
  (:data:`SYSTEM_ONLY_TIERS`): the event carries T3, so neither operators nor
  untrusted ``user-plugin`` subscribers may observe it.
* ``comms.adapter.crashed`` — fired when an adapter reports an unrecoverable
  crash. ``carrier_tier=T0`` (a daemon event). ``fail_closed=False``: it is an
  observation-only crash event (spec §10's closing paragraph lists it among the
  three ``fail_closed=False`` hookpoints) — a misbehaving subscriber must NOT
  fail-close the originating action, and a comms-adapter crash must not bring
  down the daemon. Subscribable by system + operator
  (:data:`SYSTEM_OPERATOR_TIERS`) — operators may observe a crash, but untrusted
  ``user-plugin`` subscribers may NOT.

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
from alfred.hooks.registry import SYSTEM_ONLY_TIERS, SYSTEM_OPERATOR_TIERS
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
    # Spec §10: T3 carrier -> narrowest subscribable tier (system only).
    target.register_hookpoint(
        name=INBOUND_T3_PROMOTED_HOOKPOINT,
        subscribable_tiers=SYSTEM_ONLY_TIERS,
        refusable_tiers=frozenset(),
        fail_closed=True,
        carrier_tier=T3,
        allow_error_substitution=False,
    )
    # Spec §10: observation-only crash event -> fail_closed=False, system +
    # operator (NOT user-plugin — an untrusted plugin must not observe crashes).
    target.register_hookpoint(
        name=ADAPTER_CRASHED_HOOKPOINT,
        subscribable_tiers=SYSTEM_OPERATOR_TIERS,
        refusable_tiers=frozenset(),
        fail_closed=False,
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
