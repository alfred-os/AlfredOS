"""inbound_idempotency — durable inbound accept-once ledger (Spec A / G0).

Revision ID: 0018
Revises: 0017

The Comms-Resume Gateway (Spec A, decision 4) requires the core to commit
"this inbound was accepted exactly once" keyed on a durable wire ``inbound_id``
BEFORE any side effect (audit / extract / ingest / dispatch). A replayed frame
(gateway buffer replay after a core restart) short-circuits on the existing row
so none of the side effects re-run.

Dedup ledger, NOT a content store: holds the wire id, the originating adapter,
and a commit timestamp — and deliberately NO message body, NO user text, NO
platform_user_id. Per CLAUDE.md i18n hard-rule #3 the ``language`` column binds
rows holding user text; this row holds none, so it carries no ``language``
column (and never holds T3 bytes).

Composite ``(adapter_id, inbound_id)`` PRIMARY KEY: ``inbound_id`` is a
free-form plugin-minted opaque string, so a single-column key would put every
adapter into one shared id namespace — a buggy/malicious adapter reusing another
adapter's id would silently drop a distinct real message (denial-of-delivery).
Scoping by the host-validated ``adapter_id`` isolates each adapter's namespace.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | Sequence[str] | None = "0017"
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
    """Create the inbound_idempotency dedup ledger + retention index."""
    op.create_table(
        "inbound_idempotency",
        sa.Column("inbound_id", sa.String(255), nullable=False),
        sa.Column("adapter_id", sa.String(128), nullable=False),
        sa.Column(
            "committed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("adapter_id", "inbound_id", name="pk_inbound_idempotency"),
        sa.CheckConstraint(
            "char_length(inbound_id) BETWEEN 1 AND 255",
            name="ck_inbound_idempotency_inbound_id_length",
        ),
        sa.CheckConstraint(
            "char_length(adapter_id) BETWEEN 1 AND 128",
            name="ck_inbound_idempotency_adapter_id_length",
        ),
    )
    op.create_index(
        "ix_inbound_idempotency_committed_at",
        "inbound_idempotency",
        ["committed_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the ledger; replays across the revert re-execute (bounded fail-safe)."""
    op.drop_index(
        "ix_inbound_idempotency_committed_at",
        table_name="inbound_idempotency",
        if_exists=True,
    )
    op.execute("DROP TABLE IF EXISTS inbound_idempotency")
