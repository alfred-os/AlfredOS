"""Fail-loud typed errors for the egress plane (Spec C §6/§7, epic #333).

* IOPlaneUnavailableError — the gateway egress proxy is unreachable, so ALL
  external I/O is down. Loud, audited, bounded.
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


class EgressDeniedError(AlfredError):
    """An egress call was refused by the destination allowlist or the DLP pass."""

    reason = "egress_denied"

    def __init__(self, *, destination: str, deny_reason: str) -> None:
        self.destination = destination
        self.deny_reason = deny_reason
        super().__init__(t("egress.denied", destination=destination, reason=deny_reason))


__all__ = ["EgressDeniedError", "IOPlaneUnavailableError"]
