"""Gateway-local egress-CONNECT audit (Spec C G7-1b, #333).

The audit sink is the gateway's structlog tier (it holds no DB session / signing key —
the durable signed reconcile is a deferred ADR-0040 residual). These tests pin the closed
denial vocabulary, the field-allowlist payload-blindness floor, the i18n reason-key
mapping, and the loud-on-wiring-bug behaviour. They drive 100% line+branch from unit tests
so the two-gates coverage gate never depends on integration coverage.
"""

from __future__ import annotations

import pytest
import structlog

from alfred.gateway.egress_audit import (
    EGRESS_CONNECT_ALLOWED_EVENT,
    EGRESS_CONNECT_AUDIT_FIELDS,
    EGRESS_CONNECT_DENIED_EVENT,
    EgressDenyReason,
    reason_i18n_key,
    record_egress_connect,
)


def test_deny_reason_vocabulary_is_closed() -> None:
    """The four refusal reasons the proxy can emit — declared once, cannot drift."""
    assert {r.value for r in EgressDenyReason} == {
        "destination_not_allowlisted",
        "literal_ip_target",
        "resolved_ip_not_global",
        "malformed_connect",
    }


def test_audit_field_allowlist_is_destination_and_reason_only() -> None:
    """The payload-blindness floor: there is NOWHERE to put a body / Host header / IP."""
    assert frozenset({"destination", "reason"}) == EGRESS_CONNECT_AUDIT_FIELDS


@pytest.mark.parametrize("reason", list(EgressDenyReason))
def test_reason_i18n_key(reason: EgressDenyReason) -> None:
    """An operator-facing renderer resolves a reason via its stable catalog key."""
    assert reason_i18n_key(reason) == f"gateway.egress.denied.{reason.value}"


def test_record_allowed_emits_info_row() -> None:
    with structlog.testing.capture_logs() as logs:
        record_egress_connect(
            EGRESS_CONNECT_ALLOWED_EVENT, {"destination": "api.anthropic.com:443"}
        )
    assert len(logs) == 1
    assert logs[0]["event"] == EGRESS_CONNECT_ALLOWED_EVENT
    assert logs[0]["log_level"] == "info"  # an allow is normal operation
    assert logs[0]["destination"] == "api.anthropic.com:443"


def test_record_denied_emits_warning_row() -> None:
    with structlog.testing.capture_logs() as logs:
        record_egress_connect(
            EGRESS_CONNECT_DENIED_EVENT,
            {
                "reason": EgressDenyReason.DESTINATION_NOT_ALLOWLISTED.value,
                "destination": "evil.example:443",
            },
        )
    assert len(logs) == 1
    assert logs[0]["event"] == EGRESS_CONNECT_DENIED_EVENT
    assert logs[0]["log_level"] == "warning"  # a refusal is loud (hard rule #7)
    assert logs[0]["reason"] == "destination_not_allowlisted"


def test_record_unknown_event_raises() -> None:
    """A non-vocabulary event is a wiring bug — loud, never silently logged."""
    with pytest.raises(ValueError, match="unknown event"):
        record_egress_connect("gateway.egress.something_else", {"destination": "h:443"})


def test_record_extra_field_raises() -> None:
    """A field outside the allowlist (e.g. the resolved IP) is refused — the floor is structural."""
    with pytest.raises(ValueError, match="EXACTLY"):
        record_egress_connect(
            EGRESS_CONNECT_ALLOWED_EVENT,
            {"destination": "h:443", "resolved_ip": "1.1.1.1"},
        )


def test_record_denied_missing_destination_raises() -> None:
    """A MISSING required field (``destination``) fails loud — the set is exact, not a subset."""
    with pytest.raises(ValueError, match="EXACTLY"):
        record_egress_connect(
            EGRESS_CONNECT_DENIED_EVENT,
            {"reason": EgressDenyReason.MALFORMED_CONNECT.value},
        )


def test_record_allowed_with_a_reason_field_raises() -> None:
    """An allowed row carries ONLY ``destination`` — a stray ``reason`` is the wrong schema."""
    with pytest.raises(ValueError, match="EXACTLY"):
        record_egress_connect(
            EGRESS_CONNECT_ALLOWED_EVENT,
            {"destination": "h:443", "reason": "destination_not_allowlisted"},
        )


def test_record_denied_non_vocabulary_reason_raises() -> None:
    with pytest.raises(ValueError, match="non-vocabulary reason"):
        record_egress_connect(
            EGRESS_CONNECT_DENIED_EVENT, {"reason": "made_up", "destination": "h:443"}
        )


@pytest.mark.parametrize("reason", list(EgressDenyReason))
def test_every_proxy_deny_reason_is_accepted(reason: EgressDenyReason) -> None:
    """Drift guard: every closed-vocab reason the proxy emits passes the sink unmodified."""
    with structlog.testing.capture_logs() as logs:
        record_egress_connect(
            EGRESS_CONNECT_DENIED_EVENT, {"reason": reason.value, "destination": "h:443"}
        )
    assert logs[0]["reason"] == reason.value
