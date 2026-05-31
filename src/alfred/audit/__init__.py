"""Alfred audit package.

Public surface (spec §13):
- audit_row_schemas: Final[frozenset[str]] constants for all Slice-3 audit row families.
- AuditWriter: the append-only audit log writer.
- AuditEntry: the SQLAlchemy audit log row model.

Slice-3 callers should prefer ``AuditWriter.append_schema()`` over
``AuditWriter.append()``: the schema variant validates ``subject`` keys
against a typed field-list constant from ``alfred.audit.audit_row_schemas``
and produces a richer error message naming the relevant constant.

Downstream PRs import: ``from alfred.audit import audit_row_schemas``
No subsystem needs to import deeper than this package.
"""

from alfred.audit import audit_row_schemas as audit_row_schemas
from alfred.audit.log import AuditWriter as AuditWriter
from alfred.memory.models import AuditEntry as AuditEntry

__all__ = ["AuditEntry", "AuditWriter", "audit_row_schemas"]
