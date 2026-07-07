"""Durable tri-state side-effecting-egress dedup store (Spec C §5, G7-2a).

The at-most-once guard the egress plane needs: the core stamps a deterministic,
injective ``egress_id`` (see :mod:`alfred.egress.egress_id`) and commits a
TRI-STATE row keyed on it BEFORE the external side-effect runs, then records the
post-extraction response after. A re-run of the turn — a core restart mid-turn, a
Spec A replay — re-derives the same id and short-circuits.

Three observable states (the absent row is the implicit third):

* **IntentFresh** — no row existed; THIS caller won the insert and must fire.
* **IntentReplayComplete** — a ``committed_with_response`` row exists; the caller
  returns the stored **T2** response flagged ``deduplicated`` (never re-fires,
  never re-extracts raw T3 — HARD rule #5).
* **IntentInDoubt** — a ``committed_no_response`` row exists; a prior caller
  committed the intent but its outcome is unknown (it may have fired). The caller
  decides the policy (default: refuse — see the relay client's H3 handling); the
  store only reports the state, it does not re-fire.

Atomicity rides a single ``INSERT … ON CONFLICT (egress_id) DO NOTHING
RETURNING`` — Postgres returns a row IFF this caller won the insert, and ON
CONFLICT blocks the loser until the winner commits, so the loser's subsequent
``SELECT`` sees the committed row (no read-then-write window). The store owns its
transactional ``session_scope`` and opens a SEPARATE session per call, so
``commit_intent`` commits the intent row durably BEFORE the caller fires
(commit-then-fire): a later exception in the caller's own scope cannot roll the
intent back.

A genuine DB failure PROPAGATES — the commit-once decision is part of the egress
trust boundary, so a failed commit fails LOUD (HARD rule #7), never collapsing
into a fire/replay decision.
"""

from __future__ import annotations

import datetime as dt
import hmac
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any, Protocol, cast, runtime_checkable

import sqlalchemy as sa
from sqlalchemy import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.egress.egress_id import EgressIdIntegrityError
from alfred.errors import AlfredError
from alfred.i18n import t

# The closed state vocabulary (pinned by the ck_egress_idempotency_state CHECK):
# 'committed_no_response' (the insert default) and 'committed_with_response'. The
# SQL embeds the no-response literal directly; this constant names the state the
# Python branches test for, so a typo can't silently mis-route a replay.
_STATE_WITH_RESPONSE = "committed_with_response"

# Single source of truth for the commit-once SQL. ``state`` is stamped
# ``committed_no_response`` on the fresh insert; ``committed_at`` is filled by the
# column ``server_default now()``. ``RETURNING`` yields a row only on a fresh
# insert; ON CONFLICT DO NOTHING suppresses the duplicate (zero rows -> "exists").
_COMMIT_INTENT_SQL = sa.text(
    "INSERT INTO egress_idempotency "
    "(egress_id, adapter_id, inbound_id, session_id, call_index, body_hash, state) "
    "VALUES (:egress_id, :adapter_id, :inbound_id, :session_id, :call_index, :body_hash, "
    "'committed_no_response') "
    "ON CONFLICT (egress_id) DO NOTHING "
    "RETURNING egress_id"
)

# Read the existing row's integrity + state on a conflict (same transaction).
_SELECT_INTENT_SQL = sa.text(
    "SELECT body_hash, state, response, language FROM egress_idempotency "
    "WHERE egress_id = :egress_id"
)

# Tri-state transition: only a ``committed_no_response`` row advances. A row that
# is already ``committed_with_response`` matches zero rows -> the caller treats it
# as the idempotent no-op (MEM-3), distinguished from an unknown id by the probe.
_RECORD_RESPONSE_SQL = sa.text(
    "UPDATE egress_idempotency SET state = 'committed_with_response', "
    "response = :response, language = :language "
    "WHERE egress_id = :egress_id AND state = 'committed_no_response'"
)

_SELECT_STATE_SQL = sa.text("SELECT state FROM egress_idempotency WHERE egress_id = :egress_id")

# TTL retention sweep to the replay window (backed by ix_egress_idempotency_committed_at).
_PRUNE_SQL = sa.text("DELETE FROM egress_idempotency WHERE committed_at < :older_than")


@dataclass(frozen=True, slots=True)
class IntentFresh:
    """No row existed — this caller won the insert and must fire the side-effect."""


@dataclass(frozen=True, slots=True)
class IntentReplayComplete:
    """A ``committed_with_response`` row exists — replay the stored T2, do not re-fire."""

    response: str
    language: str | None


@dataclass(frozen=True, slots=True)
class IntentInDoubt:
    """A ``committed_no_response`` row exists — a prior fire's outcome is unknown."""


CommitIntentResult = IntentFresh | IntentReplayComplete | IntentInDoubt


class EgressLedgerStateError(AlfredError):
    """A ledger transition was requested for an egress-id that has no intent row.

    A caller-contract violation: ``record_response`` must follow a winning
    ``commit_intent``. Fails loud (HARD rule #7) rather than silently no-op'ing a
    response that belongs to no committed intent.
    """

    reason = "egress_ledger_state"

    def __init__(self, *, egress_id: str) -> None:
        self.egress_id = egress_id
        super().__init__(t("egress.ledger_unknown_egress_id", egress_id=egress_id))


@runtime_checkable
class EgressIdempotencyStore(Protocol):
    """Durable tri-state at-most-once commit on a deterministic ``egress_id`` (Spec C §5)."""

    async def commit_intent(
        self,
        *,
        egress_id: str,
        adapter_id: str,
        inbound_id: str,
        session_id: str,
        call_index: int,
        body_hash: str,
    ) -> CommitIntentResult:
        """Atomically claim ``egress_id``; report fresh / replay-complete / in-doubt.

        A duplicate ``egress_id`` whose stored ``body_hash`` differs raises
        :class:`EgressIdIntegrityError` (a non-deterministic re-run) — compared in
        constant time, value-free. Raises ``SQLAlchemyError`` on a genuine DB
        failure (fail-loud; never swallowed into a fire/replay decision).
        """
        ...

    async def record_response(self, *, egress_id: str, response: str, language: str | None) -> None:
        """Advance a ``committed_no_response`` intent to ``committed_with_response``.

        Idempotent on an already-recorded row (MEM-3): a second call is a no-op and a
        differing ``response`` is NOT re-applied — the egress-id pins one logical call to
        one stored T2. Body integrity is fixed at ``commit_intent`` (the body-hash
        compare); ``record_response`` does not re-verify it. Raises
        :class:`EgressLedgerStateError` if no intent row exists.
        """
        ...

    async def get_state(self, *, egress_id: str) -> str | None:
        """Read the committed state of an intent WITHOUT firing or mutating.

        Returns ``"committed_no_response"`` (intent committed, response not yet
        recorded — the in-doubt state), ``"committed_with_response"`` (completed),
        or ``None`` (no row — nothing was committed). A pure read: unlike
        ``commit_intent`` it performs no INSERT and cannot re-fire a side effect,
        so it is safe to call from a post-timeout audit path (#347 blocker 2).
        """
        ...

    async def prune_expired(self, *, older_than: dt.datetime) -> int:
        """Delete rows committed before ``older_than`` (TTL sweep); returns the count."""
        ...


class PostgresEgressIdempotencyStore:
    """Postgres-backed :class:`EgressIdempotencyStore`.

    Owns its transactional ``session_scope`` (the daemon-built
    ``build_session_scope(settings)`` callable) — the same injected-durable-writer
    shape the inbound ledger uses, so the caller never handles a raw DB session.
    """

    def __init__(
        self,
        *,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_scope = session_scope

    async def commit_intent(
        self,
        *,
        egress_id: str,
        adapter_id: str,
        inbound_id: str,
        session_id: str,
        call_index: int,
        body_hash: str,
    ) -> CommitIntentResult:
        async with self._session_scope() as session:
            inserted = await session.execute(
                _COMMIT_INTENT_SQL,
                {
                    "egress_id": egress_id,
                    "adapter_id": adapter_id,
                    "inbound_id": inbound_id,
                    "session_id": session_id,
                    "call_index": call_index,
                    "body_hash": body_hash,
                },
            )
            if inserted.scalar_one_or_none() is not None:
                return IntentFresh()

            row = (await session.execute(_SELECT_INTENT_SQL, {"egress_id": egress_id})).one()
            # Constant-time compare — the mismatch surface must not be a body oracle.
            if not hmac.compare_digest(row.body_hash, body_hash):
                raise EgressIdIntegrityError(egress_id=egress_id)
            if row.state == _STATE_WITH_RESPONSE:
                # The ck_egress_idempotency_response_matches_state CHECK guarantees a
                # non-NULL response on a committed_with_response row — Postgres enforces it
                # on every write (proven by the negative test below). Cast rather than
                # assert so the invariant does not ride a runtime check that `python -O`
                # would strip.
                return IntentReplayComplete(response=cast(str, row.response), language=row.language)
            return IntentInDoubt()

    async def record_response(self, *, egress_id: str, response: str, language: str | None) -> None:
        async with self._session_scope() as session:
            updated = cast(
                "CursorResult[Any]",
                await session.execute(
                    _RECORD_RESPONSE_SQL,
                    {"egress_id": egress_id, "response": response, "language": language},
                ),
            )
            if updated.rowcount == 1:
                return
            # Zero rows: either already recorded (idempotent replay) or unknown id.
            existing = (
                await session.execute(_SELECT_STATE_SQL, {"egress_id": egress_id})
            ).scalar_one_or_none()
            if existing == _STATE_WITH_RESPONSE:
                return
            raise EgressLedgerStateError(egress_id=egress_id)

    async def get_state(self, *, egress_id: str) -> str | None:
        async with self._session_scope() as session:
            row = (
                await session.execute(_SELECT_STATE_SQL, {"egress_id": egress_id})
            ).scalar_one_or_none()
            return cast("str | None", row)

    async def prune_expired(self, *, older_than: dt.datetime) -> int:
        async with self._session_scope() as session:
            result = cast(
                "CursorResult[Any]",
                await session.execute(_PRUNE_SQL, {"older_than": older_than}),
            )
            return result.rowcount


__all__ = [
    "CommitIntentResult",
    "EgressIdempotencyStore",
    "EgressLedgerStateError",
    "IntentFresh",
    "IntentInDoubt",
    "IntentReplayComplete",
    "PostgresEgressIdempotencyStore",
]
