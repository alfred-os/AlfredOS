"""Shared spy audit-writer for the policies unit suite.

Mirrors the real :meth:`alfred.audit.log.AuditWriter.append_schema` keyword
signature so a test can assert against the exact ``subject`` payload the
production writer would persist. Optionally raises a chosen exception on the
Nth call to drive the audit-write-failure paths (closure sec-4 / err-011).
"""

from __future__ import annotations

from typing import Any


class SpyAudit:
    """Records every ``append_schema`` call; optionally raises on cue."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._raise_on_schema: dict[str, BaseException] = {}

    def raise_on(self, schema_name: str, exc: BaseException) -> None:
        """Arrange for the NEXT ``append_schema`` with ``schema_name`` to raise."""
        self._raise_on_schema[schema_name] = exc

    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, Any],
        trust_tier_of_trigger: str,
        result: str,
        cost_estimate_usd: float,
        trace_id: str,
        actor_persona: str = "alfred",
        persona_id: str | None = None,
        cost_actual_usd: float | None = None,
        language: str = "en-US",
    ) -> None:
        # Validate symmetrically like the real writer so a wrong subject shape
        # fails the test the same way production would.
        missing = fields - subject.keys()
        extra = subject.keys() - fields
        if missing or extra:
            raise ValueError(
                f"SpyAudit {schema_name}: missing={sorted(missing)} extra={sorted(extra)}"
            )
        self.calls.append(
            {
                "schema_name": schema_name,
                "event": event,
                "subject": subject,
                "result": result,
                "trust_tier_of_trigger": trust_tier_of_trigger,
            }
        )
        exc = self._raise_on_schema.pop(schema_name, None)
        if exc is not None:
            raise exc

    def subjects_for(self, schema_name: str) -> list[dict[str, Any]]:
        return [c["subject"] for c in self.calls if c["schema_name"] == schema_name]
