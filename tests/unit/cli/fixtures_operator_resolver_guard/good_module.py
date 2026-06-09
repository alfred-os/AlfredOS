"""Positive fixture: emits an operator-attributed row AND consumes the resolver."""

from __future__ import annotations

from alfred.audit.audit_row_schemas import SUPERVISOR_BREAKER_RESET_FIELDS


def _resolve_operator_session_or_refuse() -> str:
    return "7"


async def emit_with_resolver(audit: object) -> None:
    operator_user_id = _resolve_operator_session_or_refuse()
    await audit.append_schema(  # type: ignore[attr-defined]
        fields=SUPERVISOR_BREAKER_RESET_FIELDS,
        schema_name="SUPERVISOR_BREAKER_RESET_FIELDS",
        subject={"operator_user_id": operator_user_id},
    )
