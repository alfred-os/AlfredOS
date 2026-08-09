"""tool_call_journal — #410 PR2 deterministic tool-dispatch replay log.

Revision ID: 0026
Revises: 0025
Create Date: 2026-08-07 00:00:00.000000

#410 PR2. Records the committed ordered tool-dispatch decision — ``(adapter_id,
inbound_id, call_index) -> (iteration, tool_call)`` — BEFORE each dispatch, so
a forwarded-path resume (ADR-0039 item 4) can fast-forward through the
already-decided prefix via the SAME `dispatch_tool` call the normal path
uses, instead of asking a fresh, possibly non-deterministic planner. See
``src/alfred/memory/replay_journal.py`` for the full contract and why
``tool_arguments`` is a JSON-serialized TEXT column, not native JSONB.

Composite ``(adapter_id, inbound_id, call_index)`` PRIMARY KEY: ``call_index``
is the per-turn monotonic dispatch ordinal (already used across this
codebase as the Spec C egress-id input, `src/alfred/egress/egress_id.py:62`)
— unique only WITHIN one ``(adapter_id, inbound_id)`` pair. Mirrors the
composite-key precedent of ``forwarded_dispatch_attempts`` (migration 0020)
and ``turn_side_effect_ledger`` (migration 0025, #410 PR1): ``inbound_id``
alone is a free-form, per-adapter-minted opaque string, so a key omitting
``adapter_id`` would let two different adapters' turns collide.

``tool_arguments_json`` carries a 256 KB CHECK-constraint size cap, matching
the codebase's other JSON payload columns (migration 0013's identical cap on
``policies_json``) — the payload is attacker-influenced (a T3-derived
planner decision), so an unbounded column is a real storage-exhaustion
surface.

Strictly additive: a new table, no existing columns touched, no cross-table
CHECK constraint.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str | Sequence[str] | None = "0025"
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

# Matches migration 0013's cap on policies_json — see module docstring.
_MAX_TOOL_ARGUMENTS_JSON_BYTES = 256 * 1024


def upgrade() -> None:
    """Create the tool_call_journal table."""
    op.create_table(
        "tool_call_journal",
        sa.Column("adapter_id", sa.String(128), nullable=False),
        sa.Column("inbound_id", sa.String(255), nullable=False),
        sa.Column("call_index", sa.Integer(), nullable=False),
        sa.Column("iteration", sa.Integer(), nullable=False),
        sa.Column("tool_call_id", sa.String(255), nullable=False),
        sa.Column("tool_name", sa.String(255), nullable=False),
        sa.Column("tool_arguments_json", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint(
            "adapter_id", "inbound_id", "call_index", name="pk_tool_call_journal"
        ),
        sa.CheckConstraint(
            "char_length(adapter_id) BETWEEN 1 AND 128",
            name="ck_tool_call_journal_adapter_id_length",
        ),
        sa.CheckConstraint(
            "char_length(inbound_id) BETWEEN 1 AND 255",
            name="ck_tool_call_journal_inbound_id_length",
        ),
        sa.CheckConstraint(
            "call_index >= 0",
            name="ck_tool_call_journal_call_index_non_negative",
        ),
        sa.CheckConstraint(
            "iteration >= 0",
            name="ck_tool_call_journal_iteration_non_negative",
        ),
        sa.CheckConstraint(
            f"octet_length(tool_arguments_json) <= {_MAX_TOOL_ARGUMENTS_JSON_BYTES}",
            name="ck_tool_call_journal_tool_arguments_json_length",
        ),
    )


def downgrade() -> None:
    """Drop the tool_call_journal table."""
    op.execute("DROP TABLE IF EXISTS tool_call_journal")
