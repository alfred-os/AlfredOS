"""Gateway-local egress-CONNECT audit (structlog tier + closed vocab) — Spec C G7-1b (#333).

Models :func:`alfred.gateway.ingress_audit.record_ingress_refusal`. The gateway holds **no
DB session and no signing key** (``ingress_audit``: "Gateway audit is structlog-only … the
gateway holds no signing key"), so this ships the gateway-local **structlog tier** only; the
durable SIGNED reconcile into the core audit log is a deferred ADR-0040 residual (G7-5,
mirroring the G6-2b durable-audit disposition) — this path does **not** claim CLAUDE.md
hard-rule-7 durable audit.

The per-CONNECT outcome COUNTER (``gateway_egress_connect_total{outcome}``) lives in
:mod:`alfred.gateway.egress_proxy` (the producer). This module owns the audit VOCABULARY:

* :class:`EgressDenyReason` — the CLOSED denial-reason set, declared once so a reason token
  cannot drift across the proxy's refusal sites;
* :func:`record_egress_connect` — a FIELD-ALLOWLISTED structlog emitter
  (``{destination, reason}`` only; never a body / ``Host:`` header / resolved IP / userinfo),
  so payload-blindness (hard rule #5) is structural, not merely conventional;
* :func:`reason_i18n_key` — the operator-rendered presentation key (the reason TOKENS stay
  stable English identifiers; only the rendered presentation is localised through ``t()``).
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from typing import Final

import structlog

log = structlog.get_logger(__name__)


class EgressDenyReason(enum.Enum):
    """The closed vocabulary of gateway egress CONNECT-denial reasons (Spec C G7-1b).

    Declared ONCE so every proxy refusal site (literal-IP, default-deny, resolved-IP guard,
    malformed handshake) draws from the same set — no free-form reason strings.
    """

    DESTINATION_NOT_ALLOWLISTED = "destination_not_allowlisted"
    LITERAL_IP_TARGET = "literal_ip_target"
    RESOLVED_IP_NOT_GLOBAL = "resolved_ip_not_global"
    MALFORMED_CONNECT = "malformed_connect"


# The two egress-CONNECT audit events the proxy emits. A closed set so a typo'd / unknown
# event is a loud wiring bug (hard rule #7), never silently logged.
EGRESS_CONNECT_ALLOWED_EVENT: Final[str] = "gateway.egress.connect_allowed"
EGRESS_CONNECT_DENIED_EVENT: Final[str] = "gateway.egress.connect_denied"
_EGRESS_EVENTS: Final[frozenset[str]] = frozenset(
    {EGRESS_CONNECT_ALLOWED_EVENT, EGRESS_CONNECT_DENIED_EVENT}
)

# The EXACT field set for each egress-CONNECT audit event. An ALLOWED row carries only the
# ``destination`` authority; a DENIED row also carries the closed-vocab ``reason``. The sink
# enforces these EXACTLY (not as a subset) so a wiring bug that DROPS a required field — or
# adds one — fails loud (hard rule #7), and there is NOWHERE to put a body / ``Host:`` header /
# resolved IP / proxy userinfo, so the row is payload-blind by construction (hard rule #5).
EGRESS_CONNECT_ALLOWED_FIELDS: Final[frozenset[str]] = frozenset({"destination"})
EGRESS_CONNECT_DENIED_FIELDS: Final[frozenset[str]] = frozenset({"destination", "reason"})
# The union ceiling (every field that may EVER appear on an egress audit row).
EGRESS_CONNECT_AUDIT_FIELDS: Final[frozenset[str]] = (
    EGRESS_CONNECT_ALLOWED_FIELDS | EGRESS_CONNECT_DENIED_FIELDS
)

# The i18n key prefix for operator-rendered denial reasons (anchored for pybabel in
# ``alfred.i18n._spec_c_reserve``). A reason renders via ``t(reason_i18n_key(reason))``.
_REASON_KEY_PREFIX: Final[str] = "gateway.egress.denied."

_DENY_REASON_VALUES: Final[frozenset[str]] = frozenset(r.value for r in EgressDenyReason)


def reason_i18n_key(reason: EgressDenyReason) -> str:
    """The catalog key an operator-facing renderer uses for ``reason`` (i18n discipline)."""
    return f"{_REASON_KEY_PREFIX}{reason.value}"


def record_egress_connect(event: str, fields: Mapping[str, object]) -> None:
    """Emit ONE field-allowlisted egress-CONNECT audit row (the proxy's audit sink).

    The proxy passes a closed-vocab ``event`` plus a ``{destination[, reason]}`` field map.
    This sink fails LOUD (hard rule #7) on any wiring deviation, then logs the row — a
    DENIAL at ``warning`` (a refusal must be loud), an ALLOW at ``info`` (normal operation):

    * an ``event`` outside the closed set is a wiring bug → ``ValueError``;
    * a field map that does not EXACTLY match the event's expected set (a missing required
      field, OR a field outside it — e.g. a resolved IP) breaches the schema /
      payload-blindness floor → ``ValueError``;
    * a denial whose ``reason`` is outside :class:`EgressDenyReason` is a free-form reason →
      ``ValueError``.
    """
    if event not in _EGRESS_EVENTS:
        raise ValueError(f"egress audit: unknown event {event!r}")
    expected = (
        EGRESS_CONNECT_DENIED_FIELDS
        if event == EGRESS_CONNECT_DENIED_EVENT
        else EGRESS_CONNECT_ALLOWED_FIELDS
    )
    if set(fields) != expected:
        raise ValueError(
            f"egress audit: {event} row fields {sorted(fields)} must be EXACTLY "
            f"{sorted(expected)} (missing or non-allowlisted field — hard rules #5/#7)"
        )
    if event == EGRESS_CONNECT_DENIED_EVENT:
        if fields.get("reason") not in _DENY_REASON_VALUES:
            raise ValueError(
                f"egress audit: denied row has non-vocabulary reason {fields.get('reason')!r}"
            )
        log.warning(event, **fields)
    else:
        log.info(event, **fields)


__all__ = [
    "EGRESS_CONNECT_ALLOWED_EVENT",
    "EGRESS_CONNECT_ALLOWED_FIELDS",
    "EGRESS_CONNECT_AUDIT_FIELDS",
    "EGRESS_CONNECT_DENIED_EVENT",
    "EGRESS_CONNECT_DENIED_FIELDS",
    "EgressDenyReason",
    "reason_i18n_key",
    "record_egress_connect",
]
