"""Gateway-local mode-(b) relay audit vocabulary (Spec C G7-2b, #333).

Mirrors :mod:`tests.unit.gateway.test_egress_audit`. The relay audit is the
gateway's structlog tier (it holds no DB session / signing key — ADR-0036; the
durable signed reconcile is a deferred ADR-0040 residual). These tests pin the
closed deny vocabulary, the PER-EVENT field-allowlist (distinct from the CONNECT
proxy's ``{destination, reason}`` set — payload-blind by construction), the i18n
reason-key mapping, and the loud-on-wiring-bug behaviour. 100% line+branch from
unit data.
"""

from __future__ import annotations

import pytest
import structlog

from alfred.gateway.egress_relay_audit import (
    EGRESS_RELAY_CANARY_EVENT,
    EGRESS_RELAY_DENIED_EVENT,
    EGRESS_RELAY_FORWARDED_EVENT,
    GATEWAY_EGRESS_RELAY,
    EgressRelayDenyReason,
    reason_i18n_key,
    record_egress_relay,
)


def _forwarded_fields() -> dict[str, object]:
    return {
        "destination": "api.example.com:443",
        "method": "GET",
        "status": 200,
        "egress_id": "a" * 64,
        "dlp_redactions": 0,
    }


def test_deny_reason_vocabulary_is_closed() -> None:
    """The eight relay deny reasons — declared once, cannot drift across B4's sites."""
    assert {r.value for r in EgressRelayDenyReason} == {
        "destination_not_allowlisted",
        "literal_ip_target",
        "resolved_ip_not_global",
        "dlp_redacted",
        "canary_tripped",
        "response_too_large",
        "malformed_envelope",
        "upstream_redirect_refused",
    }


def test_forwarded_field_set_is_exact() -> None:
    with structlog.testing.capture_logs() as logs:
        record_egress_relay(EGRESS_RELAY_FORWARDED_EVENT, _forwarded_fields())
    assert len(logs) == 1
    assert logs[0]["event"] == EGRESS_RELAY_FORWARDED_EVENT
    assert logs[0]["log_level"] == "info"  # a forward is normal operation
    assert logs[0]["destination"] == "api.example.com:443"
    assert logs[0]["status"] == 200


def test_denied_emits_warning_row() -> None:
    with structlog.testing.capture_logs() as logs:
        record_egress_relay(
            EGRESS_RELAY_DENIED_EVENT,
            {
                "destination": "evil.example:443",
                "reason": EgressRelayDenyReason.DESTINATION_NOT_ALLOWLISTED.value,
            },
        )
    assert logs[0]["event"] == EGRESS_RELAY_DENIED_EVENT
    assert logs[0]["log_level"] == "warning"  # a refusal is loud (hard rule #7)
    assert logs[0]["reason"] == "destination_not_allowlisted"


def test_canary_emits_error_row() -> None:
    """A canary trip is a SECURITY EVENT — louder than a routine policy denial."""
    with structlog.testing.capture_logs() as logs:
        record_egress_relay(
            EGRESS_RELAY_CANARY_EVENT,
            {
                "destination": "api.example.com:443",
                "reason": EgressRelayDenyReason.CANARY_TRIPPED.value,
            },
        )
    assert logs[0]["event"] == EGRESS_RELAY_CANARY_EVENT
    assert logs[0]["log_level"] == "error"
    assert logs[0]["reason"] == "canary_tripped"


def test_unknown_event_raises() -> None:
    with pytest.raises(ValueError, match="unknown event"):
        record_egress_relay("gateway.egress.something_else", {"destination": "h:443"})


def test_forwarded_extra_field_raises() -> None:
    with pytest.raises(ValueError, match="EXACTLY"):
        record_egress_relay(EGRESS_RELAY_FORWARDED_EVENT, {**_forwarded_fields(), "body": "leak"})


def test_forwarded_missing_field_raises() -> None:
    fields = _forwarded_fields()
    del fields["status"]
    with pytest.raises(ValueError, match="EXACTLY"):
        record_egress_relay(EGRESS_RELAY_FORWARDED_EVENT, fields)


def test_denied_missing_destination_raises() -> None:
    with pytest.raises(ValueError, match="EXACTLY"):
        record_egress_relay(
            EGRESS_RELAY_DENIED_EVENT,
            {"reason": EgressRelayDenyReason.MALFORMED_ENVELOPE.value},
        )


def test_forwarded_with_a_reason_field_raises() -> None:
    """A forwarded row must NOT carry a deny ``reason`` — wrong schema for the event."""
    with pytest.raises(ValueError, match="EXACTLY"):
        record_egress_relay(
            EGRESS_RELAY_FORWARDED_EVENT, {**_forwarded_fields(), "reason": "dlp_redacted"}
        )


def test_denied_non_vocabulary_reason_raises() -> None:
    with pytest.raises(ValueError, match="non-vocabulary reason"):
        record_egress_relay(
            EGRESS_RELAY_DENIED_EVENT, {"reason": "made_up", "destination": "h:443"}
        )


def test_canary_non_vocabulary_reason_raises() -> None:
    with pytest.raises(ValueError, match="non-vocabulary reason"):
        record_egress_relay(
            EGRESS_RELAY_CANARY_EVENT, {"reason": "made_up", "destination": "h:443"}
        )


@pytest.mark.parametrize("reason", list(EgressRelayDenyReason))
def test_reason_i18n_key(reason: EgressRelayDenyReason) -> None:
    assert reason_i18n_key(reason) == f"gateway.egress.relay_denied.{reason.value}"


@pytest.mark.parametrize("reason", list(EgressRelayDenyReason))
def test_every_deny_reason_passes_the_sink(reason: EgressRelayDenyReason) -> None:
    """Drift guard: every closed-vocab reason B4 emits passes the sink unmodified."""
    with structlog.testing.capture_logs() as logs:
        record_egress_relay(
            EGRESS_RELAY_DENIED_EVENT, {"reason": reason.value, "destination": "h:443"}
        )
    assert logs[0]["reason"] == reason.value


def test_forwarded_non_string_value_raises() -> None:
    """Value-shape floor (CR review): a non-str smuggled through an allowlisted key
    (here a nested object via ``destination``) is rejected — names alone aren't enough."""
    with pytest.raises(ValueError, match="value-shape floor"):
        record_egress_relay(
            EGRESS_RELAY_FORWARDED_EVENT, {**_forwarded_fields(), "destination": {"leak": "body"}}
        )


def test_forwarded_non_int_status_raises() -> None:
    with pytest.raises(ValueError, match="value-shape floor"):
        record_egress_relay(EGRESS_RELAY_FORWARDED_EVENT, {**_forwarded_fields(), "status": "200"})


def test_forwarded_bool_status_raises() -> None:
    # bool is an int subclass; a ``status`` of True is a wiring bug, not a status code.
    with pytest.raises(ValueError, match="value-shape floor"):
        record_egress_relay(EGRESS_RELAY_FORWARDED_EVENT, {**_forwarded_fields(), "status": True})


def test_counter_has_outcome_label() -> None:
    # Pin the required ``outcome`` label WITHOUT incrementing — mutating the
    # process-global default-registry counter would make later value-based
    # assertions order-dependent (CR review). ``.labels(...)`` registers/validates
    # the label set without bumping the count.
    GATEWAY_EGRESS_RELAY.labels(outcome="forwarded")
    GATEWAY_EGRESS_RELAY.labels(outcome="denied")
    GATEWAY_EGRESS_RELAY.labels(outcome="error")
