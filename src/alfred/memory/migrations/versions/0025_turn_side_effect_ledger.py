"""turn_side_effect_ledger — #410 PR1 at-most-once guard for turn-start/turn-end.

Revision ID: 0025
Revises: 0024
Create Date: 2026-08-07 00:00:00.000000

#410 PR1. The forwarded dispatched-edge path
(:func:`alfred.comms_mcp.inbound.process_inbound_message` with
``commit_at_dispatch_edge=True``) leaves a failed frame NOT committed, so the
forwarding leg replays it — and, absent this table, a resumed
``Orchestrator._handle_turn`` re-applies the user-turn write and the
assistant-turn write (ADR-0049's accepted residual, widened by #410 to also
cover the previously-unnamed in-process ``WorkingMemory`` double-append).
The budget charge is deliberately NOT gated by this table — see
``src/alfred/memory/turn_side_effects.py`` for why. This migration adds the
durable per-``(adapter_id, inbound_id)`` ledger that makes the two writes
at-most-once — see that module for the atomic UPSERT contract.

Composite ``(adapter_id, inbound_id)`` PRIMARY KEY, mirroring the sibling
``inbound_idempotency`` (migration 0018) and ``forwarded_dispatch_attempts``
(migration 0020) ledgers: ``inbound_id`` is a free-form, per-adapter-minted
opaque string, so a single-column key would collapse every adapter into one
shared id namespace — scoping by the host-validated ``adapter_id`` isolates
each adapter's namespace.

Strictly additive: a new table, no existing columns touched, no cross-table
CHECK constraint. Downgrade drops the table — no destructive row deletion
needed (unlike migration 0020's ``ck_audit_log_result`` widen/narrow), so no
loud-NOTICE deletion step applies here.

Unlike ``egress_idempotency`` (migration 0023), this table ships with no
retention index or pruning story — it grows unbounded, a known gap accepted
for this PR (matching PR2's journal table identical risk note). Both should be
addressed together in a shared prune-on-``commit_once`` sweep rather than
solved independently. Tracked as a follow-up, to be filed alongside PR1/PR2
planning (see PR3 Task 6 for the gap-filing pattern).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | Sequence[str] | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

__all__ = [
    "branch_labels",
    "depends_on",
    "down_revision",
    "downgrade",
    "revision",
    "upgrade",
]


def upgrade() -> None:
    """Create the turn_side_effect_ledger table."""
    op.create_table(
        "turn_side_effect_ledger",
        sa.Column("adapter_id", sa.String(128), nullable=False),
        sa.Column("inbound_id", sa.String(255), nullable=False),
        sa.Column("user_turn_applied", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "assistant_turn_applied", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("adapter_id", "inbound_id", name="pk_turn_side_effect_ledger"),
        sa.CheckConstraint(
            "char_length(adapter_id) BETWEEN 1 AND 128",
            name="ck_turn_side_effect_ledger_adapter_id_length",
        ),
        sa.CheckConstraint(
            "char_length(inbound_id) BETWEEN 1 AND 255",
            name="ck_turn_side_effect_ledger_inbound_id_length",
        ),
    )


def downgrade() -> None:
    """Drop the turn_side_effect_ledger table."""
    op.execute("DROP TABLE IF EXISTS turn_side_effect_ledger")
