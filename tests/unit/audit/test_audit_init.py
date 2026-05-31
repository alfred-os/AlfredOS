"""Verify alfred.audit public surface includes audit_row_schemas per spec §13."""

from alfred import audit
from alfred.audit import AuditEntry, AuditWriter, audit_row_schemas


def test_audit_row_schemas_importable_from_package() -> None:
    """audit_row_schemas is directly importable from alfred.audit (spec §13)."""
    assert hasattr(audit, "audit_row_schemas")
    assert audit_row_schemas is audit.audit_row_schemas


def test_audit_writer_importable() -> None:
    """AuditWriter remains accessible from alfred.audit after the update."""
    assert AuditWriter is not None


def test_audit_entry_importable() -> None:
    """AuditEntry remains accessible from alfred.audit after the update."""
    assert AuditEntry is not None
