"""Negative fixture: emits an operator-attributed row WITHOUT the resolver.

Used only by ``test_operator_resolver_consumed.py`` to prove the AST guard
catches a missing-resolver bug. NOT imported at runtime.
"""

from __future__ import annotations

from alfred.audit.audit_row_schemas import SUPERVISOR_BREAKER_RESET_FIELDS


async def emit_without_resolver(audit: object) -> None:
    await audit.append_schema(  # type: ignore[attr-defined]
        fields=SUPERVISOR_BREAKER_RESET_FIELDS,
        schema_name="SUPERVISOR_BREAKER_RESET_FIELDS",
        subject={"operator_user_id": "unknown"},
    )
