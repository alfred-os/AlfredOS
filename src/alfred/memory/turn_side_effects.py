"""Durable turn-side-effect idempotency ledger (#410 PR1, transactional revision).

The forwarded dispatched-edge path
(:func:`alfred.comms_mcp.inbound.process_inbound_message` with
``commit_at_dispatch_edge=True``) leaves a failed frame NOT committed, so the
forwarding leg replays it (ADR-0039 item 4). A resumed turn re-runs from
scratch, which — absent this ledger — re-appends the user/assistant turns to
the live in-process :class:`~alfred.memory.working.WorkingMemory` buffer and
re-writes both episodic rows. This ledger makes each of those two effects
apply AT MOST ONCE per committed ``(adapter_id, inbound_id)``.

**Transactional contract (ADR-0062 — this INVERTS the original PR1 design):**
each ``try_apply_*`` call executes on the CALLER's :class:`AsyncSession`,
inside the caller's transaction. The gate and the guarded episodic write
commit or roll back TOGETHER: a mid-phase rollback un-marks the gate in
lockstep with the write it guards, so a replay after any failure correctly
sees "not yet applied" and retries — never "applied but missing" (the
data-loss bug the original independent-session design had). The ledger never
calls ``commit()``/``rollback()`` itself and holds no session of its own.

The caller is :meth:`alfred.orchestrator.core.Orchestrator`'s Phase A/C —
each a SHORT-LIVED transaction (ledger UPSERT + one episodic write) that
closes before any provider call, so the row lock a losing concurrent attempt
waits on is held for milliseconds, and an orphaned (crashed-caller) lock is
reclaimed by the TURN pool's ``idle_in_transaction_session_timeout``.

**Deliberate divergence from the sibling**
:class:`~alfred.memory.forwarded_dispatch_attempts.ForwardedDispatchAttemptStore`:
that store's own-independent-session design is CORRECT for what IT guards (a
retry counter, not a durability claim about another write). This ledger's
original copy of that pattern was a mis-transfer, not a second instance of a
shared design — recorded in ADR-0062 so the deviation reads as deliberate.

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

Durable-across-restart on purpose: the forwarded-edge replay happens ACROSS
core restarts, so an in-memory guard would reset exactly when it is needed.

Each ``try_apply_*`` method is a single ``INSERT ... ON CONFLICT (adapter_id,
inbound_id) DO UPDATE ... WHERE <column> = FALSE RETURNING <column>``
statement — no read-then-write window. A row is returned (mapped to
``True``, "proceed") only when this call is the one that flips the column
from FALSE to TRUE (either via the fresh INSERT or via a WHERE-qualified
UPDATE); a conflicting call that finds the column already TRUE returns no
row (mapped to ``False``, "already applied, skip"). Under READ COMMITTED a
concurrent second transaction on the same key blocks on the row lock until
the first resolves: first committed => the ``WHERE ... = FALSE`` guard denies
the second; first rolled back => the second's insert wins. The two columns
share ONE row per ``(adapter_id, inbound_id)`` (not two tables) since they
are two facets of the SAME turn attempt and must never be attributed to
different inbound frames.

**Composite key, not `inbound_id` alone** (a #410 design correction found
during the `/review-plan` fleet pass): ``inbound_id`` is a free-form,
per-adapter-minted opaque string (``src/alfred/comms_mcp/protocol.py``, the
same reasoning the sibling ``inbound_idempotency`` migration 0018 and
``forwarded_dispatch_attempts`` migration 0020 both document for their own
composite ``(adapter_id, inbound_id)`` keys) — a single-column key would let
two DIFFERENT adapters' turns collide on the same ``inbound_id`` string and
silently gate-skip each other's unrelated content.

**Caller contract:** call the relevant ``try_apply_*`` gate at the START of
the same transaction that performs the guarded episodic write, and defer any
NON-transactional twin effect (the in-process working-memory append) until
AFTER that transaction commits. The residual this leaves is an orphaned USER
episodic row when Phase B fails after Phase A committed — accepted (ADR-0062)
as strictly better than the alternative (losing the user's message entirely):
replay re-denies the user gate, allows the assistant gate, and converges.

A genuine DB failure (``SQLAlchemyError``) PROPAGATES — never caught and
collapsed into a boolean, which could either silently re-permit a blocked
side effect or silently block a permitted one.
"""

from __future__ import annotations

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
    """Durable per-``(adapter_id, inbound_id)`` at-most-once gate, caller-transactional."""

    async def try_apply_user_turn(
        self, session: AsyncSession, *, adapter_id: str, inbound_id: str
    ) -> bool:
        """Return ``True`` iff the caller should apply the user-turn write now.

        Executes inside ``session``'s transaction; commit/rollback are the
        caller's, so the gate travels with the guarded write.
        """
        ...

    async def try_apply_assistant_turn(
        self, session: AsyncSession, *, adapter_id: str, inbound_id: str
    ) -> bool:
        """Return ``True`` iff the caller should apply the assistant-turn write now."""
        ...


class PostgresTurnSideEffectLedger:
    """Postgres-backed :class:`TurnSideEffectLedger`.

    Stateless on purpose: every call runs its single atomic UPSERT on the
    caller's session, inside the caller's transaction. There is no
    constructor seam through which an independent session/scope could be
    re-introduced — the shape of the class IS the transactional contract.
    """

    async def try_apply_user_turn(
        self, session: AsyncSession, *, adapter_id: str, inbound_id: str
    ) -> bool:
        result = await session.execute(
            _TRY_APPLY_USER_TURN_SQL, {"adapter_id": adapter_id, "inbound_id": inbound_id}
        )
        return result.scalar_one_or_none() is not None

    async def try_apply_assistant_turn(
        self, session: AsyncSession, *, adapter_id: str, inbound_id: str
    ) -> bool:
        result = await session.execute(
            _TRY_APPLY_ASSISTANT_TURN_SQL,
            {"adapter_id": adapter_id, "inbound_id": inbound_id},
        )
        return result.scalar_one_or_none() is not None
