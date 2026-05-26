"""Slice 1 audit log writer.

Writes append-only entries to the `audit_log` table. Failed writes raise
loudly — the caller decides whether to quarantine. Future slices add signing
and integration with the internal git repo.

Session boundary
----------------
``AuditWriter`` owns its own transaction. Callers pass a ``session_factory``
(an async-context-manager factory shaped exactly like
``alfred.memory.db.build_session_scope``'s output) and ``.append`` opens it,
writes the row, and commits — independent of whatever transaction the caller
is running for user-content writes. This is **load-bearing** for CLAUDE.md
hard rule #7: a failed user-content turn (provider error, budget block,
cancellation) MUST still produce an audit row. Sharing a session with the
caller would mean the caller's ``rollback()`` wipes the audit write, leaving
the operator with no record that anything happened.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from alfred.memory.models import AuditEntry


class AuditWriter:
    """Append-only writer for the audit log.

    Each ``.append()`` opens a fresh session from ``session_factory``, writes
    the row, and commits — so audit persistence is decoupled from any caller
    transaction that may roll back.
    """

    def __init__(
        self,
        *,
        session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_factory = session_factory

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

        Opens its own session+transaction via ``session_factory`` so the row
        survives even if the caller's outer transaction rolls back (CLAUDE.md
        hard rule #7 — see module docstring).
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
        async with self._session_factory() as session:
            session.add(entry)
            await session.flush()
