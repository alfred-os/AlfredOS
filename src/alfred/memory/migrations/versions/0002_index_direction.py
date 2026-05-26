"""correct episodes index direction + drop shadow user_id index

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-26 00:00:00.000000

Two related fixes in a single revision so the live schema lands on the same
indexes the SQLAlchemy model declares:

1. `ix_episodes_user_id_created_at` is recreated with `created_at DESC`. The
   hot path is `WHERE user_id = ? ORDER BY created_at DESC LIMIT N` from
   `EpisodicMemory.recent()`. An ASC composite forces Postgres into a backward
   scan; a DESC second column lets it serve the query as a forward scan.

2. `ix_episodes_user_id` (the standalone single-column index Alembic created
   from `index=True` on the `user_id` column) is dropped. The composite above
   already covers `WHERE user_id = ?` as a leftmost-column scan, so the
   standalone duplicated maintenance cost on every write for zero query benefit.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Drop shadow user_id index and recreate the composite with DESC ordering."""
    op.drop_index("ix_episodes_user_id", table_name="episodes")
    op.drop_index("ix_episodes_user_id_created_at", table_name="episodes")
    op.create_index(
        "ix_episodes_user_id_created_at",
        "episodes",
        ["user_id", sa.text("created_at DESC")],
        unique=False,
    )


def downgrade() -> None:
    """Restore the original ASC composite and the shadow user_id index."""
    op.drop_index("ix_episodes_user_id_created_at", table_name="episodes")
    op.create_index(
        "ix_episodes_user_id_created_at",
        "episodes",
        ["user_id", "created_at"],
        unique=False,
    )
    op.create_index(op.f("ix_episodes_user_id"), "episodes", ["user_id"], unique=False)
