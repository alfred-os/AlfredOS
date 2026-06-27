"""egress_idempotency — durable tri-state side-effecting-egress dedup ledger (Spec C §5, G7-2a).

Revision ID: 0023
Revises: 0022

A tool egress (web POST, email) crosses a money/side-effect boundary, so a
re-run of a turn — a core restart mid-turn, a Spec A replay — must not
double-fire it. The core stamps a deterministic, injective ``egress_id`` (a
sha256 hexdigest) and commits a TRI-STATE row keyed on it: first
``committed_no_response`` BEFORE the side-effect, then ``committed_with_response``
after the response is extracted (the absent row is the implicit third state). A
duplicate ``egress_id`` replays the stored response rather than re-firing.

Unlike the inbound ledger (0018, which stores no body), this ledger carries a
``response`` column — but it stores the POST-extraction **T2** result, NEVER the
raw T3 tool response, so a duplicate-egress replay can never re-hand raw T3 to
the orchestrator (HARD rule #5). Because that row holds user-derived content it
carries a BCP-47 ``language`` tag (i18n hard-rule #3).

Two CHECK constraints pin the closed state vocabulary and the
state<->response invariant (a no-response row has a NULL response and vice
versa); the ``committed_at`` index backs the TTL retention sweep.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | Sequence[str] | None = "0022"
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
    """Create the tri-state egress_idempotency ledger + retention index."""
    op.create_table(
        "egress_idempotency",
        sa.Column("egress_id", sa.String(64), nullable=False),
        sa.Column("adapter_id", sa.String(128), nullable=False),
        sa.Column("inbound_id", sa.String(255), nullable=False),
        sa.Column("session_id", sa.String(255), nullable=False),
        sa.Column("call_index", sa.Integer, nullable=False),
        sa.Column("body_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("response", sa.Text, nullable=True),
        sa.Column("language", sa.String(16), nullable=True),
        sa.Column(
            "committed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("egress_id", name="pk_egress_idempotency"),
        sa.CheckConstraint(
            "state IN ('committed_no_response', 'committed_with_response')",
            name="ck_egress_idempotency_state",
        ),
        sa.CheckConstraint(
            "(state = 'committed_no_response') = (response IS NULL)",
            name="ck_egress_idempotency_response_matches_state",
        ),
    )
    op.create_index(
        "ix_egress_idempotency_committed_at",
        "egress_idempotency",
        ["committed_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the ledger; replays across the revert re-fire (bounded fail-safe)."""
    op.drop_index(
        "ix_egress_idempotency_committed_at",
        table_name="egress_idempotency",
        if_exists=True,
    )
    op.execute("DROP TABLE IF EXISTS egress_idempotency")
