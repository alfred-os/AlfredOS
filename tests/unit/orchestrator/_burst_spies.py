"""Shared test doubles for ``BurstLimiter`` unit tests.

``SpyAuditWriter`` records every ``append_schema`` / ``append`` call so tests
can assert which audit rows fired. The query helpers mirror the plan's
``rows_with_schema`` / ``rows_with_event`` API.
"""

from __future__ import annotations

from typing import Any


class SpyAuditWriter:
    """Records audit-row emissions in memory for assertions."""

    def __init__(self) -> None:
        self.schema_rows: list[dict[str, Any]] = []
        self.event_rows: list[dict[str, Any]] = []

    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        subject: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        # Validate symmetric keys the way the real writer does, so a test
        # catches a drifted field set instead of silently passing.
        missing = fields - subject.keys()
        extra = subject.keys() - fields
        if missing or extra:
            msg = (
                f"append_schema {schema_name}: missing={sorted(missing)} "
                f"extra={sorted(extra)}"
            )
            raise AssertionError(msg)
        self.schema_rows.append(
            {"schema_name": schema_name, "event": event, **subject}
        )

    async def append(
        self,
        *,
        event: str,
        subject: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        self.event_rows.append({"event": event, **subject})

    def rows_with_schema(self, schema_name: str) -> list[dict[str, Any]]:
        return [r for r in self.schema_rows if r["schema_name"] == schema_name]

    def rows_with_event(self, event: str) -> list[dict[str, Any]]:
        return [r for r in self.event_rows if r["event"] == event]
