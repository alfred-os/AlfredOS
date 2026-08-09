"""Durable turn-side-effect idempotency ledger (#410 PR1).

The forwarded dispatched-edge path
(:func:`alfred.comms_mcp.inbound.process_inbound_message` with
``commit_at_dispatch_edge=True``) leaves a failed frame NOT committed, so the
forwarding leg replays it (ADR-0039 item 4). A resumed
:meth:`alfred.orchestrator.core.Orchestrator._handle_turn` re-runs from
scratch, which — absent this ledger — re-appends the user/assistant turns to
the live in-process :class:`~alfred.memory.working.WorkingMemory` buffer and
re-writes both episodic rows (ADR-0049's accepted residual, narrowed by #410
to include the working-memory exposure ADR-0049 did not name). This ledger
makes each of those two effects apply AT MOST ONCE per committed
``(adapter_id, inbound_id)``.

**The budget charge is deliberately NOT gated by this ledger** (a #410 design
correction found during the `/review-plan` fleet pass, after an earlier draft
gated it too). ``check_and_charge`` fires once per Act-loop iteration, not
once per turn attempt — a single boolean gate is sound only while the Act
loop is guaranteed to run exactly one iteration (tools off). Gating it would
silently under-count real spend the instant a future PR enables
multi-iteration turns — the unsafe direction for a cost-control boundary.
Leaving it ungated restores ADR-0049's ORIGINAL accepted residual (bounded
over-charge, the safe direction) and composes correctly with the #410 PR2
replay journal for free: a fast-forwarded tool call never re-invokes the
provider, so only genuinely new post-resume completions are ever charged.

Durable-across-restart on purpose, same rationale as the sibling
:class:`~alfred.memory.forwarded_dispatch_attempts.ForwardedDispatchAttemptStore`:
the forwarded-edge replay happens ACROSS core restarts, so an in-memory guard
would reset exactly when it is needed.

Each ``try_apply_*`` method is a single ``INSERT ... ON CONFLICT (adapter_id,
inbound_id) DO UPDATE ... WHERE <column> = FALSE RETURNING <column>``
statement — no read-then-write window. A row is returned (mapped to
``True``, "proceed") only when this call is the one that flips the column
from FALSE to TRUE (either via the fresh INSERT or via a WHERE-qualified
UPDATE); a conflicting call that finds the column already TRUE returns no
row (mapped to ``False``, "already applied, skip"). The two columns share
ONE row per ``(adapter_id, inbound_id)`` (not two tables) since they are two
facets of the SAME turn attempt and must never be attributed to different
inbound frames.

**Composite key, not `inbound_id` alone** (a #410 design correction found
during the `/review-plan` fleet pass): ``inbound_id`` is a free-form,
per-adapter-minted opaque string (``src/alfred/comms_mcp/protocol.py``, the
same reasoning the sibling ``inbound_idempotency`` migration 0018 and
``forwarded_dispatch_attempts`` migration 0020 both document for their own
composite ``(adapter_id, inbound_id)`` keys) — a single-column key would let
two DIFFERENT adapters' turns collide on the same ``inbound_id`` string and
silently gate-skip each other's unrelated content.

**Caller contract:** call the relevant ``try_apply_*`` gate BEFORE performing
the guarded effect — the only sound order for a check-then-act idempotency
gate (a "do the effect, then mark" order would let two sequential/concurrent
attempts both pass an unmarked check and both perform the effect,
reintroducing the exact duplication this ledger exists to prevent). The one
accepted residual: a genuine process crash — SIGKILL, OOM, host reboot, NOT
the realistic "process alive, outbound-send failed" scenario ADR-0049
describes and this ledger actually targets — landing in the sub-millisecond
window between the gate's commit and the guarded write's own completion
could theoretically lose that turn's content. Accepted as a residual bounded
to that narrow crash class; see Task 4's crash-injection test for the exact
scope pinned.

A genuine DB failure (``SQLAlchemyError``) PROPAGATES — never caught and
collapsed into a boolean, which could either silently re-permit a blocked
side effect or silently block a permitted one.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

__all__ = [
    "PostgresTurnSideEffectLedger",
    "TurnSideEffectLedger",
]

# One statement per column: a fresh INSERT (no existing row) sets the named
# column TRUE and leaves the OTHER column at its column DEFAULT (FALSE); a
# conflict re-targets the SAME row and updates ONLY the named column, guarded
# by "was it FALSE" so a second attempt at the same gate returns no row.
_TRY_APPLY_USER_TURN_SQL = sa.text(
    "INSERT INTO turn_side_effect_ledger (adapter_id, inbound_id, user_turn_applied) "
    "VALUES (:adapter_id, :inbound_id, TRUE) "
    "ON CONFLICT (adapter_id, inbound_id) DO UPDATE SET user_turn_applied = TRUE "
    "WHERE turn_side_effect_ledger.user_turn_applied = FALSE "
    "RETURNING user_turn_applied"
)

_TRY_APPLY_ASSISTANT_TURN_SQL = sa.text(
    "INSERT INTO turn_side_effect_ledger (adapter_id, inbound_id, assistant_turn_applied) "
    "VALUES (:adapter_id, :inbound_id, TRUE) "
    "ON CONFLICT (adapter_id, inbound_id) DO UPDATE SET assistant_turn_applied = TRUE "
    "WHERE turn_side_effect_ledger.assistant_turn_applied = FALSE "
    "RETURNING assistant_turn_applied"
)


@runtime_checkable
class TurnSideEffectLedger(Protocol):
    """Durable per-``(adapter_id, inbound_id)`` at-most-once gate for two turn side effects."""

    async def try_apply_user_turn(self, *, adapter_id: str, inbound_id: str) -> bool:
        """Return ``True`` iff the caller should apply the user-turn write now."""
        ...

    async def try_apply_assistant_turn(self, *, adapter_id: str, inbound_id: str) -> bool:
        """Return ``True`` iff the caller should apply the assistant-turn write now."""
        ...


class PostgresTurnSideEffectLedger:
    """Postgres-backed :class:`TurnSideEffectLedger`.

    Owns its OWN ``session_scope`` — a fresh, immediately-committing
    transaction per call, INDEPENDENT of the per-turn ``session`` in
    :meth:`Orchestrator._handle_turn`. This is load-bearing: the per-turn
    session rolls back on a deadline/exception, but a live in-process
    ``WorkingMemory.append`` does NOT roll back with it. If this ledger
    shared the per-turn session, a rollback would un-mark an already-applied
    working-memory append, and the next resume would re-apply it — exactly
    the bug this ledger exists to prevent. Same shape as
    :class:`~alfred.memory.forwarded_dispatch_attempts.PostgresForwardedDispatchAttemptStore`.
    """

    def __init__(
        self,
        *,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_scope = session_scope

    async def try_apply_user_turn(self, *, adapter_id: str, inbound_id: str) -> bool:
        async with self._session_scope() as session:
            result = await session.execute(
                _TRY_APPLY_USER_TURN_SQL, {"adapter_id": adapter_id, "inbound_id": inbound_id}
            )
            return result.scalar_one_or_none() is not None

    async def try_apply_assistant_turn(self, *, adapter_id: str, inbound_id: str) -> bool:
        async with self._session_scope() as session:
            result = await session.execute(
                _TRY_APPLY_ASSISTANT_TURN_SQL,
                {"adapter_id": adapter_id, "inbound_id": inbound_id},
            )
            return result.scalar_one_or_none() is not None
