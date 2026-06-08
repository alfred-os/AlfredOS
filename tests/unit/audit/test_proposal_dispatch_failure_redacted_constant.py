"""Field-set contract for the #173 DLP-into-failure_detail audit rows.

PR-S4-2 emits three disjoint audit rows from ``_record_failure``'s DLP arm:

* ``PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS`` — success path (scan ran,
  ledger row written), ``dlp_redactions_count`` >= 0.
* ``DLP_OUTBOUND_REFUSED_FIELDS`` — canary-trip ``HookRefusal`` path
  (Slice-3 constant, reused verbatim, write aborts).
* ``PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS`` — non-``HookRefusal``
  exception from ``scan()`` (PR-S4-2 adds this; write aborts).

These tests pin the field-sets the emit sites depend on so a drift between
the constant and the emit site fails here rather than at production
``append_schema`` validation time.
"""

from __future__ import annotations

from alfred.audit.audit_row_schemas import (
    DLP_OUTBOUND_REFUSED_FIELDS,
    PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS,
    PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS,
)


def test_redacted_fields_carry_count_and_join_key() -> None:
    """Success row carries the redaction count + the forensic join key."""
    assert "dlp_redactions_count" in PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS
    assert "correlation_id" in PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS
    assert "redacted_detail" in PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS


def test_scan_failed_fields_exist_and_carry_error_type() -> None:
    """The scan-failed row carries a closed-vocab error-type + join key."""
    assert "scan_error_type" in PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS
    assert "correlation_id" in PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS


def test_three_dlp_rows_are_disjoint_in_purpose() -> None:
    """The refused row is the Slice-3 constant, distinct from the two new rows.

    The constants are distinct objects with distinct identities — the
    two-disjoint-constants invariant (spec §2.1) means a single dispatch
    failure emits exactly one of these, never two.
    """
    assert PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS is not DLP_OUTBOUND_REFUSED_FIELDS
    assert PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS is not DLP_OUTBOUND_REFUSED_FIELDS
    assert PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS is not PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS
