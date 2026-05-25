"""Slice 1 audit log writer.

Writes append-only entries to the `audit_log` table. Failed writes raise
loudly — the caller decides whether to quarantine. Future slices add signing
and integration with the internal git repo.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from alfred.memory.models import AuditEntry


class AuditWriter:
    """Append-only writer for the audit log."""

    def __init__(self, *, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self,
        *,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, Any],
        trust_tier_of_trigger: str,
        result: str,
        cost_estimate_usd: float,
        trace_id: str,
        actor_persona: str = "alfred",
        cost_actual_usd: float | None = None,
        language: str = "en-US",
    ) -> None:
        """Record a single audit entry. Raises if persistence fails.

        `language` is a BCP-47 tag (e.g. "en-US", "ja-JP"). Every audit row
        carries it because CLAUDE.md i18n rule #3 requires every stored
        user-content row to have a language field — and the audit log is one
        such row (subject often contains a user-content excerpt). Default
        "en-US" preserves backward-compat for paths not yet threaded with
        language; new callers MUST pass language explicitly. The orchestrator
        passes it from `Settings.operator_language`.
        """
        entry = AuditEntry(
            trace_id=trace_id,
            event=event,
            actor_user_id=actor_user_id,
            actor_persona=actor_persona,
            subject=subject,
            trust_tier_of_trigger=trust_tier_of_trigger,
            result=result,
            cost_estimate_usd=cost_estimate_usd,
            cost_actual_usd=cost_actual_usd,
            language=language,
        )
        self._session.add(entry)
        await self._session.flush()
