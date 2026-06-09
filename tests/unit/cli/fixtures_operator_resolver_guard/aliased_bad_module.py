"""Negative fixture: emits an operator-attributed row via an ALIASED import.

CR-227 round-2 finding 6: a module can ``from ... import
SUPERVISOR_BREAKER_RESET_FIELDS as _FIELDS`` (alias) so the raw constant
identifier never appears as an ``ast.Name``. The guard must still recognise
the alias as a reference to the operator-attributed schema constant and flag
the missing resolver. NOT imported at runtime.
"""

from __future__ import annotations

from alfred.audit.audit_row_schemas import SUPERVISOR_BREAKER_RESET_FIELDS as _FIELDS


async def emit_without_resolver(audit: object) -> None:
    await audit.append_schema(  # type: ignore[attr-defined]
        fields=_FIELDS,
        schema_name="SUPERVISOR_BREAKER_RESET_FIELDS",
        subject={"operator_user_id": "unknown"},
    )
