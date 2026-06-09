"""``DefaultOperatorSessionResolver`` — the host-side operator resolver (#153).

Implements the ``OperatorResolverProtocol`` (``alfred.supervisor.protocols``,
async ``resolve() -> str``) shipped in PR-S4-1. Every operator-attributed
CLI command resolves the session file at ``~/.config/alfred/session`` into
the canonical ``User.id`` (stringified) via this class.

Resolution pipeline (each refusal emits exactly one
``OPERATOR_SESSION_REFUSED`` audit row + the ``operator.session.refused``
hookpoint, then raises a typed exception):

1. Load the session file (TOCTOU-safe — ``load_session_file``).
2. Refuse if ``expires_at`` is in the past.
3. Refuse if the file's ``host`` differs from the live hostname.
4. Refuse if the live machine-id hash differs from the file's (replay).
5. Look up the ``operator_sessions`` row by ``token_hash`` on the unique
   index (non-revoked). Refuse if absent (``token_unknown``).
6. Refuse if the DB row's ``user_id`` disagrees with the file's
   (``token_user_mismatch`` — the token is authoritative, closure 11).
7. Refuse if the bound ``User`` is soft-deleted (``user_revoked``).

A 250ms hard timeout wraps the whole pipeline via ``asyncio.wait_for``
(err-008) so the resolver never hangs a CLI command silently. All deps
are injected (arch-3): no global state.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Protocol

from sqlalchemy import select

from alfred.audit.audit_row_schemas import OPERATOR_SESSION_REFUSED_FIELDS
from alfred.identity.models import User
from alfred.identity.operator_session import (
    OperatorSessionExpired,
    OperatorSessionFile,
    OperatorSessionHostMismatch,
    OperatorSessionMachineIdMismatch,
    OperatorSessionTimeout,
    OperatorSessionTokenUnknown,
    OperatorSessionTokenUserMismatch,
    OperatorSessionUserRevoked,
    compute_machine_id_hash,
    compute_token_hash,
    load_session_file,
)
from alfred.memory.models import OperatorSession as OperatorSessionRow

_REFUSED_HOOKPOINT = "operator.session.refused"


class _BrokerLike(Protocol):
    def get(self, name: str) -> str: ...


class _MachineIdLike(Protocol):
    async def read_raw(self) -> bytes: ...


class _AuditLike(Protocol):
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
        actor_persona: str = ...,
        persona_id: str | None = ...,
        cost_actual_usd: float | None = ...,
        language: str = ...,
    ) -> None: ...


class _HookDispatcher(Protocol):
    async def __call__(self, name: str, payload: dict[str, Any]) -> None: ...


type _SessionScope = Callable[[], AbstractAsyncContextManager[Any]]


class DefaultOperatorSessionResolver:
    """Concrete operator resolver wired from ``cli/_bootstrap.py`` (arch-1, arch-3).

    All collaborators are injected; the class holds no module-level or
    global state. ``host`` and ``session_file_path`` are supplied at
    construction so the unit tests can substitute a temp ``HOME`` without
    monkeypatching ``os.environ``.
    """

    _hard_timeout_s: ClassVar[float] = 0.250

    def __init__(
        self,
        *,
        session_scope: _SessionScope,
        secret_broker: _BrokerLike,
        machine_id_provider: _MachineIdLike,
        audit_writer: _AuditLike,
        hook_dispatcher: _HookDispatcher,
        host: str,
        session_file_path: Path,
        now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._session_scope = session_scope
        self._secret_broker = secret_broker
        self._machine_id_provider = machine_id_provider
        self._audit = audit_writer
        self._hooks = hook_dispatcher
        self._host = host
        self._session_file_path = session_file_path
        self._now_fn = now_fn

    async def resolve(self) -> str:
        """Return the canonical ``User.id`` (stringified) of the operator.

        Raises a typed ``OperatorSession*`` exception on any refusal, and
        ``OperatorSessionTimeout`` if the pipeline exceeds 250ms.
        """
        try:
            return await asyncio.wait_for(self._resolve_inner(), timeout=self._hard_timeout_s)
        except TimeoutError as exc:
            raise OperatorSessionTimeout(
                f"operator-session resolution exceeded {self._hard_timeout_s}s",
            ) from exc

    async def _resolve_inner(self) -> str:
        session = load_session_file(self._session_file_path)
        pepper = self._secret_broker.get("audit.hash_pepper").encode("utf-8")
        now = self._now_fn()

        if session.expires_at < now:
            await self._emit_refused(session, reason="expired")
            raise OperatorSessionExpired(f"session expired at {session.expires_at.isoformat()}")

        if session.host != self._host:
            await self._emit_refused(session, reason="host_mismatch")
            raise OperatorSessionHostMismatch(
                f"session host {session.host!r} != live host {self._host!r}",
            )

        live_hash = await compute_machine_id_hash(provider=self._machine_id_provider, pepper=pepper)
        if session.machine_id_hash != live_hash:
            await self._emit_refused(session, reason="machine_mismatch")
            raise OperatorSessionMachineIdMismatch("machine-id hash mismatch (session replay)")

        token_hash = compute_token_hash(token=session.token.get_secret_value(), pepper=pepper)
        row = await self._lookup_row(token_hash)
        if row is None:
            await self._emit_refused(session, reason="token_unknown")
            raise OperatorSessionTokenUnknown("no active operator_sessions row for token")

        db_user_id, user_deleted_at = row
        if db_user_id != session.user_id:
            await self._emit_refused(
                session, reason="token_user_mismatch", resolved_user_id=db_user_id
            )
            raise OperatorSessionTokenUserMismatch(
                f"file claims user {session.user_id}, token owned by {db_user_id}",
            )

        if user_deleted_at is not None:
            await self._emit_refused(session, reason="user_revoked", resolved_user_id=db_user_id)
            raise OperatorSessionUserRevoked(f"user {db_user_id} is soft-deleted")

        return str(db_user_id)

    async def _lookup_row(self, token_hash: str) -> tuple[int, datetime | None] | None:
        """Look up (User.id, User.deleted_at) for a non-revoked token row.

        Single-row lookup on the ``uq_operator_sessions_token_hash`` unique
        index joined to ``users`` — the 5ms p99 budget (spec §6.4) absorbs
        the one round-trip per CLI invocation; the resolver does not cache.
        """
        stmt = (
            select(User.id, User.deleted_at)
            .join(OperatorSessionRow, OperatorSessionRow.user_id == User.id)
            .where(
                OperatorSessionRow.token_hash == token_hash,
                OperatorSessionRow.revoked_at.is_(None),
            )
        )
        async with self._session_scope() as db:
            result = await db.execute(stmt)
            row = result.first()
        if row is None:
            return None
        return (int(row[0]), row[1])

    async def _emit_refused(
        self,
        session: OperatorSessionFile,
        *,
        reason: str,
        resolved_user_id: int | None = None,
    ) -> None:
        """Emit the audit row + refused hookpoint for one refusal.

        ``attempted_user_id`` is the file's self-claimed ``user_id`` as a
        string. Because the file model coerces ``user_id`` to ``int``,
        the value is always ``^[0-9]+$`` — no attacker-controlled bytes
        reach the audit log (sec-4). ``resolved_user_id`` is the DB-owner
        of the token (set only for the mismatch / revoked branches).
        """
        refused_at = self._now_fn()
        subject: dict[str, Any] = {
            "attempted_user_id": str(session.user_id),
            "resolved_user_id": str(resolved_user_id) if resolved_user_id is not None else None,
            "reason": reason,
            "host": session.host,
            "machine_id_hash": session.machine_id_hash,
            "refused_at": refused_at.isoformat(),
            "via": "resolve",
        }
        await self._audit.append_schema(
            fields=OPERATOR_SESSION_REFUSED_FIELDS,
            schema_name="OPERATOR_SESSION_REFUSED_FIELDS",
            event="operator.session.refused",
            actor_user_id=None,
            subject=subject,
            trust_tier_of_trigger="T1",
            result="refused",
            cost_estimate_usd=0.0,
            trace_id=f"operator-session-refused-{reason}",
        )
        await self._hooks(_REFUSED_HOOKPOINT, dict(subject))


__all__ = ["DefaultOperatorSessionResolver"]
