"""Fail-loud typed errors for the egress plane (Spec C §6/§7, epic #333).

* IOPlaneUnavailableError — the gateway egress proxy is unreachable, so ALL
  external I/O is down. Loud, audited, bounded.
* EgressRelayUnavailableError — the gateway mode-(b) tool-egress relay could not
  bind (a fail-closed start refusal). A subtype of IOPlaneUnavailableError so
  generic I/O-plane handling applies, but distinct so the start renders a
  relay-specific refusal + exit, separate from the CONNECT proxy's.
* EgressDeniedError — a destination-allowlist / DLP denial. Surfaced distinctly.

Both root at AlfredError. ``reason`` is a closed-vocabulary audit token (stable,
NOT localised); the rendered message goes through t(). The EgressDeniedError ctor
param is ``deny_reason`` (the specific denial), deliberately NOT named ``reason``
so it never shadows the class-level ``reason`` audit token.
"""

from __future__ import annotations

from alfred.errors import AlfredError
from alfred.i18n import t


class IOPlaneUnavailableError(AlfredError):
    """The gateway egress proxy is unreachable — total external-I/O outage."""

    reason = "io_plane_unavailable"

    def __init__(self, *, detail: str) -> None:
        self.detail = detail
        super().__init__(t("egress.io_plane_unavailable", detail=detail))


class EgressRelayUnavailableError(IOPlaneUnavailableError):
    """The gateway mode-(b) tool-egress relay could not bind — fail-closed start refusal.

    A subtype of :class:`IOPlaneUnavailableError` (the relay IS an egress I/O plane,
    so generic I/O-plane handling still applies), but DISTINCT so the gateway start
    catches it FIRST and renders a relay-specific refusal + exit code, separate from
    the CONNECT proxy's bind-failed line.
    """

    reason = "egress_relay_unavailable"

    def __init__(self, *, detail: str) -> None:
        self.detail = detail
        # Bypass IOPlaneUnavailableError.__init__ (its message is proxy-flavoured);
        # set the relay-specific message on the AlfredError base directly.
        AlfredError.__init__(self, t("egress.relay_unavailable", detail=detail))


class EgressDeniedError(AlfredError):
    """An egress call was refused by the destination allowlist or the DLP pass."""

    reason = "egress_denied"

    def __init__(self, *, destination: str, deny_reason: str) -> None:
        self.destination = destination
        self.deny_reason = deny_reason
        super().__init__(t("egress.denied", destination=destination, reason=deny_reason))


class EgressInDoubtError(AlfredError):
    """A prior fire for this egress-id is in-doubt (committed_no_response) and the
    caller did not declare the request idempotent.

    Refuses by default (Spec C §5 H3): re-firing a non-idempotent call whose
    outcome is unknown risks a double side-effect. The relay client raises this
    when ``commit_intent`` returns ``IntentInDoubt`` and ``_RawToolRequest.idempotent``
    is ``False``. For idempotent refires, the client forwards ``egress_id`` as the
    remote ``Idempotency-Key`` header instead of raising.
    """

    reason = "egress_in_doubt"

    def __init__(self, *, destination: str) -> None:
        self.destination = destination
        super().__init__(t("egress.in_doubt", destination=destination))


__all__ = [
    "EgressDeniedError",
    "EgressInDoubtError",
    "EgressRelayUnavailableError",
    "IOPlaneUnavailableError",
]
