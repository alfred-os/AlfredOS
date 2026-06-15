"""``LinkControl`` -> wire-notification mapping (Spec A G3-3b / ADR-0032).

The single bind point between the pure :class:`~alfred.gateway.link_state.LinkControl`
emit-vocabulary and the wire-level :data:`~alfred.gateway.client_listener.LinkControlNotification`
models. It lives in its OWN module — not in ``link_state`` — so the pure state machine
stays dependency-light (``enum`` + ``alfred.errors`` only) and never imports the wire
``comms_mcp.protocol`` models; the map that DOES need them is isolated here.

**Exhaustive by construction (fail-loud, CLAUDE.md hard rule #7).** A future
:class:`LinkControl` member with no mapping is an :func:`typing.assert_never` failure,
never a silent ``KeyError`` default — a state the machine can emit but the gateway
cannot frame is a bug, not a no-op.
"""

from __future__ import annotations

from typing import assert_never

from alfred.comms_mcp.protocol import (
    LinkReconnectingNotification,
    LinkRestoredNotification,
    LinkUnavailableNotification,
)
from alfred.gateway.client_listener import LinkControlNotification
from alfred.gateway.link_state import LinkControl


def control_notification(control: LinkControl) -> LinkControlNotification:
    """Map a :class:`LinkControl` to the id-less wire notification it frames.

    Exhaustive over :class:`LinkControl`: a future member without a mapping trips
    :func:`assert_never` (a loud failure), never a silent default.
    """
    match control:
        case LinkControl.RECONNECTING:
            return LinkReconnectingNotification()
        case LinkControl.RESTORED:
            return LinkRestoredNotification()
        case LinkControl.UNAVAILABLE:
            return LinkUnavailableNotification()
    # Statically unreachable: mypy + pyright prove the match is exhaustive over
    # LinkControl, so this fires ONLY if a future member is added without a case —
    # a loud failure, never a silent default (the exhaustiveness test pins it too).
    assert_never(control)  # pragma: no cover


__all__ = ["control_notification"]
