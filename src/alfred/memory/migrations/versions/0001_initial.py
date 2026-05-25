"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-05-25 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "episodes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("persona", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("trust_tier", sa.String(length=4), nullable=False),
        sa.Column("language", sa.String(length=16), nullable=False),
        sa.Column("tokens_in", sa.Integer(), nullable=False),
        sa.Column("tokens_out", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Float(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_episodes_user_id"), "episodes", ["user_id"], unique=False)
    op.create_index(
        "ix_episodes_user_id_created_at",
        "episodes",
        ["user_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=False),
        sa.Column("event", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.String(length=64), nullable=True),
        sa.Column("actor_persona", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.JSON(), nullable=False),
        sa.Column("trust_tier_of_trigger", sa.String(length=4), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("cost_estimate_usd", sa.Float(), nullable=False),
        sa.Column("cost_actual_usd", sa.Float(), nullable=True),
        sa.Column("language", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_audit_log_trace_id"), "audit_log", ["trace_id"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_audit_log_trace_id"), table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index("ix_episodes_user_id_created_at", table_name="episodes")
    op.drop_index(op.f("ix_episodes_user_id"), table_name="episodes")
    op.drop_table("episodes")
