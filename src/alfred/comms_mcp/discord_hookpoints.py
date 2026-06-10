"""Discord comms-MCP hookpoint declarations (PR-S4-9 Task A3, #206, spec §10).

Two hookpoints land here, both fired by the HOST (never by an adapter):

* ``comms.adapter.binding_requested`` — fired when ``process_inbound_message``
  resolves an inbound from an UNBOUND platform user and emits a binding request.
  ``carrier_tier=T3``: the event is occasioned by adversary-authorable inbound
  content (the unknown user's first contact), so it is a T3 carrier. Unlike
  ``comms.inbound.t3_promoted`` (which carries the raw T3 BODY and is therefore
  ``SYSTEM_ONLY``), this event carries only host-derived, hashed identity
  metadata — no raw T3 body — so operators MAY observe it
  (:data:`SYSTEM_OPERATOR_TIERS`). ``fail_closed=False`` +
  ``allow_error_substitution=True``: a misbehaving subscriber must not block the
  binding-request flow, and the recoverable-carrier semantic is opted in.

* ``comms.adapter.rate_limit_signal`` — fired when the host's rate-limit handler
  processes a platform 429 (Discord ``adapter.rate_limit_signal`` notification)
  and pauses the :class:`alfred.comms_mcp.outbound_queue.OutboundQueue`.
  ``carrier_tier=T0``: a daemon-internal operational signal (retry-after window,
  endpoint) with no user content. ``SYSTEM_OPERATOR_TIERS`` so operators can
  observe rate-limit pressure; ``fail_closed=False`` so a subscriber error never
  blocks outbound recovery.

Registration follows the per-subsystem :func:`declare_hookpoints` precedent
(``alfred.comms_mcp.hookpoints`` for the PR-S4-8 pair). The two names are listed
in :data:`alfred.hooks._known_hookpoints.KNOWN_HOOKPOINTS` under THIS module so
the drift detector (``test_known_hookpoints_sync``) imports it on its full-import
sweep. The module-bottom call runs the declaration at import time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from alfred.hooks import get_registry
from alfred.hooks.registry import SYSTEM_OPERATOR_TIERS
from alfred.security.tiers import T0, T3

if TYPE_CHECKING:
    from alfred.hooks.registry import HookRegistry

BINDING_REQUESTED_HOOKPOINT = "comms.adapter.binding_requested"
RATE_LIMIT_SIGNAL_HOOKPOINT = "comms.adapter.rate_limit_signal"


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Register the two PR-S4-9 Discord hookpoints (spec §10).

    Idempotent against the active registry (the registry's re-declaration guard
    is a no-op on identical metadata), so a test fixture that swaps the registry
    and re-imports this module re-runs the declaration safely.

    Args:
        registry: Optional override for tests that declare against a
            non-singleton registry. Defaults to :func:`get_registry`.
    """
    target = registry if registry is not None else get_registry()
    # T3 carrier but operator-observable: the event carries only hashed identity
    # metadata, never the raw T3 body (which stays SYSTEM_ONLY on t3_promoted).
    target.register_hookpoint(
        name=BINDING_REQUESTED_HOOKPOINT,
        subscribable_tiers=SYSTEM_OPERATOR_TIERS,
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=T3,
        allow_error_substitution=True,
    )
    # T0 operational signal (retry-after window) — no user content.
    target.register_hookpoint(
        name=RATE_LIMIT_SIGNAL_HOOKPOINT,
        subscribable_tiers=SYSTEM_OPERATOR_TIERS,
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=T0,
        allow_error_substitution=True,
    )


# Module-bottom call — runs at import time so the hookpoints are declared before
# any subscriber registration or dispatch lands (mirrors
# ``alfred.comms_mcp.hookpoints``).
declare_hookpoints()


__all__ = [
    "BINDING_REQUESTED_HOOKPOINT",
    "RATE_LIMIT_SIGNAL_HOOKPOINT",
    "declare_hookpoints",
]
