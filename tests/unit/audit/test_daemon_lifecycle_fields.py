"""DAEMON_LIFECYCLE_FIELDS field-set (Spec A G1 / ADR-0033) (#237)."""

from __future__ import annotations

from alfred.audit.audit_row_schemas import DAEMON_LIFECYCLE_FIELDS


def test_lifecycle_fields_are_exact() -> None:
    assert (
        frozenset({"boot_id", "epoch", "phase", "reason", "occurred_at"}) == DAEMON_LIFECYCLE_FIELDS
    )
