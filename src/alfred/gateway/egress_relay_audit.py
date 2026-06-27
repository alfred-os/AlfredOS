"""Gateway-local mode-(b) tool-egress relay audit (structlog tier + closed vocab) — G7-2b (#333).

Models :mod:`alfred.gateway.egress_audit` (the CONNECT-proxy audit). The gateway
holds **no DB session and no signing key** (ADR-0036), so this ships the
gateway-local **structlog tier** only; the durable SIGNED reconcile into the core
audit log is a deferred ADR-0040 residual (G7-5). A gateway DLP / canary trip is
*also* surfaced core-side off the typed ``EgressDeniedError`` the in-core relay
client raises (H2/H5) — that is where the HARD-rule-#7 durable row is written.

Distinct from the CONNECT proxy's audit on purpose: the relay is **not**
payload-blind (it inspects the body), so its forwarded row carries more shape
(method / status / egress-id / redaction count) than the CONNECT
``{destination, reason}`` set — but it still has NOWHERE to put a body / header /
resolved IP, so the row stays payload-blind by construction (hard rule #5). This
module owns:

* :class:`EgressRelayDenyReason` — the CLOSED deny-reason set, declared once;
* :func:`record_egress_relay` — a PER-EVENT field-allowlisted structlog emitter;
* :func:`reason_i18n_key` — the operator-rendered presentation key (reason TOKENS
  stay stable English identifiers; only the rendered presentation is localised);
* :data:`GATEWAY_EGRESS_RELAY` — the per-outcome Counter (the relay increments it).
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from typing import Final

import structlog
from prometheus_client import Counter

log = structlog.get_logger(__name__)


class EgressRelayDenyReason(enum.Enum):
    """The closed vocabulary of mode-(b) relay deny reasons (Spec C G7-2b).

    Declared ONCE so every refusal site in :mod:`alfred.gateway.egress_relay`
    (SSRF chain, gateway DLP second pass, canary, response cap, framing, redirect)
    draws from the same set — no free-form reason strings.
    """

    DESTINATION_NOT_ALLOWLISTED = "destination_not_allowlisted"
    LITERAL_IP_TARGET = "literal_ip_target"
    RESOLVED_IP_NOT_GLOBAL = "resolved_ip_not_global"
    DLP_REDACTED = "dlp_redacted"
    CANARY_TRIPPED = "canary_tripped"
    RESPONSE_TOO_LARGE = "response_too_large"
    MALFORMED_ENVELOPE = "malformed_envelope"
    UPSTREAM_REDIRECT_REFUSED = "upstream_redirect_refused"


# The three relay audit events. A closed set so a typo'd / unknown event is a loud
# wiring bug (hard rule #7), never silently logged. The canary trip gets its own
# event (separate from a routine deny) so it can drive distinct alerting.
EGRESS_RELAY_FORWARDED_EVENT: Final[str] = "gateway.egress.relay_forwarded"
EGRESS_RELAY_DENIED_EVENT: Final[str] = "gateway.egress.relay_denied"
EGRESS_RELAY_CANARY_EVENT: Final[str] = "gateway.egress.relay_canary_tripped"
_EVENTS: Final[frozenset[str]] = frozenset(
    {EGRESS_RELAY_FORWARDED_EVENT, EGRESS_RELAY_DENIED_EVENT, EGRESS_RELAY_CANARY_EVENT}
)

# The EXACT field set per event. A FORWARDED row carries the egress shape but no
# payload; a DENIED / CANARY row carries the authority + the closed-vocab reason.
# The sink enforces these EXACTLY (not a subset) so a wiring bug that DROPS a
# required field — or ADDS one (e.g. a body / header) — fails loud (hard rules
# #5/#7).
EGRESS_RELAY_FORWARDED_FIELDS: Final[frozenset[str]] = frozenset(
    {"destination", "method", "status", "egress_id", "dlp_redactions"}
)
EGRESS_RELAY_DENIED_FIELDS: Final[frozenset[str]] = frozenset({"destination", "reason"})
EGRESS_RELAY_CANARY_FIELDS: Final[frozenset[str]] = frozenset({"destination", "reason"})

# Events whose row carries a closed-vocab ``reason`` (both deny shapes).
_REASON_EVENTS: Final[frozenset[str]] = frozenset(
    {EGRESS_RELAY_DENIED_EVENT, EGRESS_RELAY_CANARY_EVENT}
)

# The i18n key prefix for operator-rendered relay deny reasons (anchored for
# pybabel in ``alfred.i18n._spec_c_reserve``). A reason renders via
# ``t(reason_i18n_key(reason))``. Both deny shapes share the one ``relay_denied``
# presentation namespace.
_REASON_KEY_PREFIX: Final[str] = "gateway.egress.relay_denied."

_DENY_REASON_VALUES: Final[frozenset[str]] = frozenset(r.value for r in EgressRelayDenyReason)

# Per-outcome relay Counter (provisional; G7-5 owns the canonical egress metric/
# alert set). Default registry so the gateway /metrics exposition serves it.
GATEWAY_EGRESS_RELAY: Final[Counter] = Counter(
    "gateway_egress_relay_total",
    "Gateway mode-(b) inspecting tool-egress relay outcomes (provisional; G7-5 finalises).",
    ["outcome"],
)


def _expected_fields(event: str) -> frozenset[str]:
    if event == EGRESS_RELAY_FORWARDED_EVENT:
        return EGRESS_RELAY_FORWARDED_FIELDS
    if event == EGRESS_RELAY_DENIED_EVENT:
        return EGRESS_RELAY_DENIED_FIELDS
    return EGRESS_RELAY_CANARY_FIELDS


def reason_i18n_key(reason: EgressRelayDenyReason) -> str:
    """The catalog key an operator-facing renderer uses for ``reason`` (i18n discipline)."""
    return f"{_REASON_KEY_PREFIX}{reason.value}"


def record_egress_relay(event: str, fields: Mapping[str, object]) -> None:
    """Emit ONE field-allowlisted mode-(b) relay audit row (the relay's audit sink).

    Fails LOUD (hard rule #7) on any wiring deviation, then logs the row — a
    FORWARD at ``info`` (normal operation), a DENY at ``warning`` (a refusal must
    be loud), a CANARY trip at ``error`` (a security event warrants the loudest
    tier):

    * an ``event`` outside the closed set is a wiring bug → ``ValueError``;
    * a field map that does not EXACTLY match the event's expected set (a missing
      required field, OR a field outside it — e.g. a body) breaches the schema /
      payload-blindness floor → ``ValueError``;
    * a deny / canary whose ``reason`` is outside :class:`EgressRelayDenyReason`
      is a free-form reason → ``ValueError``.
    """
    if event not in _EVENTS:
        raise ValueError(f"egress relay audit: unknown event {event!r}")
    expected = _expected_fields(event)
    if set(fields) != expected:
        raise ValueError(
            f"egress relay audit: {event} row fields {sorted(fields)} must be EXACTLY "
            f"{sorted(expected)} (missing or non-allowlisted field — hard rules #5/#7)"
        )
    if event in _REASON_EVENTS:
        if fields.get("reason") not in _DENY_REASON_VALUES:
            raise ValueError(
                f"egress relay audit: {event} row has non-vocabulary reason "
                f"{fields.get('reason')!r}"
            )
        if event == EGRESS_RELAY_CANARY_EVENT:
            log.error(event, **fields)
        else:
            log.warning(event, **fields)
    else:
        log.info(event, **fields)


__all__ = [
    "EGRESS_RELAY_CANARY_EVENT",
    "EGRESS_RELAY_CANARY_FIELDS",
    "EGRESS_RELAY_DENIED_EVENT",
    "EGRESS_RELAY_DENIED_FIELDS",
    "EGRESS_RELAY_FORWARDED_EVENT",
    "EGRESS_RELAY_FORWARDED_FIELDS",
    "GATEWAY_EGRESS_RELAY",
    "EgressRelayDenyReason",
    "reason_i18n_key",
    "record_egress_relay",
]
