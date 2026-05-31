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

    Slice-3 callers should prefer ``append_schema()`` over ``append()``: the
    schema variant validates ``subject`` keys against a typed field-list
    constant from ``alfred.audit.audit_row_schemas`` and produces a richer
    error message naming the relevant constant.
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
        persona_id: str | None = None,
        cost_actual_usd: float | None = None,
        language: str = "en-US",
    ) -> None:
        """Record a single audit entry. Raises if persistence fails.

        ``language`` is a BCP-47 tag (e.g. "en-US", "ja-JP"). Every audit row
        carries it because CLAUDE.md i18n rule #3 requires every stored
        user-content row to have a language field — and the audit log is one
        such row (subject often contains a user-content excerpt). Default
        ``"en-US"`` preserves backward-compat for paths not yet threaded with
        language; new callers MUST pass language explicitly. The orchestrator
        passes it from ``Settings.operator_language``.

        ``persona_id`` is the Slice-2 per-row attribution column added in
        migration 0004 (nullable). Identifies WHICH persona authored the
        action so the audit graph can attribute multi-persona traffic
        (Slice 5+) without a join. Defaults to ``None`` for pre-multi-
        persona callers; the orchestrator passes ``"alfred"`` so Slice-1+2
        rows are non-null. Distinct from ``actor_persona`` so downstream
        readers of that column keep working untouched.

        Opens its own session+transaction via ``session_factory`` so the row
        survives even if the caller's outer transaction rolls back (CLAUDE.md
        hard rule #7 — see module docstring).
        """
        entry = AuditEntry(
            trace_id=trace_id,
            event=event,
            actor_user_id=actor_user_id,
            actor_persona=actor_persona,
            persona_id=persona_id,
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
        """Record a single audit entry, validating subject keys against ``fields``.

        ``fields`` is a ``Final[frozenset[str]]`` constant from
        ``alfred.audit.audit_row_schemas`` naming every key the audit row in
        that family carries. ``schema_name`` is the importable identifier of
        that constant (e.g. ``"PLUGIN_LIFECYCLE_FIELDS"``) — threaded through
        so the raised ``ValueError`` can name it explicitly, letting an
        on-call engineer fix the emit site without grepping back to the
        caller to discover which constant was passed.

        Validation is **symmetric**: the method raises if ``subject`` is
        missing any declared field *or* if it carries unexpected keys.
        Symmetry matters because the unexpected-key leg defends against two
        real failure modes — a typo'd field name (``"plugin_iid"`` instead
        of ``"plugin_id"``) silently shadowing the real field, and an
        emitter accidentally persisting a T3 fragment (``str(exc)``,
        ``exc.args``) into JSONB. Spec §5.6 forbids the latter; the
        symmetric check is the runtime guard.

        All other parameters forward directly to ``append()``. See ``append()``
        docstring for parameter semantics. Cross-reference:
        ``alfred.audit.audit_row_schemas`` for the full constant catalogue.

        Raises:
            ValueError: If ``fields`` is empty, or if ``subject`` is missing
                declared fields, or if ``subject`` carries fields not declared
                in ``fields``. The message names ``schema_name`` so callers can
                fix the emit site without reading the constant definition.

        This method lands in PR-S3-0a so every downstream Slice-3 PR (S3-3a,
        S3-4, S3-2, S3-3b, S3-5) that emits an audit row can use the typed
        helper rather than constructing the ``append()`` signature manually.
        Cross-reference: rvw-001 (Critical), Cluster 4 in plan-review fixup.
        """
        if not fields:
            msg = (
                f"append_schema for event={event!r}: fields must be non-empty; "
                f"pass a constant from alfred.audit.audit_row_schemas"
            )
            raise ValueError(msg)
        missing = fields - subject.keys()
        extra = subject.keys() - fields
        if missing or extra:
            msg_parts = [f"append_schema for event={event!r} (schema={schema_name})"]
            if missing:
                msg_parts.append(f"subject missing required fields: {sorted(missing)!r}")
            if extra:
                msg_parts.append(f"subject has unexpected fields: {sorted(extra)!r}")
            msg_parts.append(
                f"declared fields for {schema_name} are {sorted(fields)!r}; "
                f"consult alfred.audit.audit_row_schemas.{schema_name}"
            )
            raise ValueError("; ".join(msg_parts))
        await self.append(
            event=event,
            actor_user_id=actor_user_id,
            subject=subject,
            trust_tier_of_trigger=trust_tier_of_trigger,
            result=result,
            cost_estimate_usd=cost_estimate_usd,
            trace_id=trace_id,
            actor_persona=actor_persona,
            persona_id=persona_id,
            cost_actual_usd=cost_actual_usd,
            language=language,
        )
