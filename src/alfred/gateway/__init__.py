"""The ``alfred-gateway`` process — the always-up, payload-blind front door.

Spec A (the Comms-Resume Gateway). The gateway terminates the client connection on
a stable client-facing socket and relays to the core, holding the client across core
restarts and signalling link gaps so the client can paint a reconnect banner.

This package is built in two PRs:

* **G3-3a (this cut)** — the stable kernel: the pure :class:`LinkStateMachine` +
  control-frame derivation (the spec §9 invariant) and the thin
  :class:`GatewayClientListener` (client-facing socket + control-frame emit). NO
  core dial, NO seq/ack relay.
* **G3-3b** — the core-facing half + the runnable process (``GatewayCoreLink``, the
  relay loop, metrics, the ``alfred gateway`` CLI).
"""

from __future__ import annotations

from alfred.gateway._control_frames import control_notification
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink, GatewayCoreLinkError
from alfred.gateway.link_state import (
    GatewayLinkEvent,
    GatewayLinkState,
    GatewayLinkStateError,
    LinkControl,
    LinkStateMachine,
)

__all__ = [
    "GatewayClientListener",
    "GatewayCoreLink",
    "GatewayCoreLinkError",
    "GatewayLinkEvent",
    "GatewayLinkState",
    "GatewayLinkStateError",
    "LinkControl",
    "LinkStateMachine",
    "control_notification",
]
