"""capability_gate_sync — commit-hash cache for RealGate

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-31 00:00:00.000000

``capability_gate_sync`` holds a SINGLETON row tracking the state.git HEAD
commit hash at the last time RealGate (PR-S3-2) rebuilt ``plugin_grants``
from state.git. On AlfredOS startup, RealGate checks whether the stored
hash differs from the current state.git HEAD; if so, it rebuilds
``plugin_grants`` (spec §8.1).

Singleton enforcement (mem-004)
-------------------------------

* ``id`` is INTEGER PRIMARY KEY with ``CHECK (id = 1)`` — NOT UUID.
* Each RealGate sync uses an ``ON CONFLICT (id) DO UPDATE`` upsert with
  ``id = 1``.
* This guarantees exactly one row at all times without application-layer
  coordination. A UUID PK with ``default=uuid4`` would create a new row
  on every INSERT that omits ``id`` — RealGate's staleness check would
  be non-deterministic.

Column naming (mem-002)
-----------------------

* Column is ``commit_hash`` (NOT ``state_git_commit_hash``) so the PR-S3-2
  PostgresBackend SQL matches exactly. The upsert includes ``synced_at``
  (the column is NOT NULL with ``server_default=NOW()`` for raw-SQL writers
  that omit it; ORM and explicit writers supply it directly):

  .. code-block:: sql

     SELECT commit_hash, synced_at FROM capability_gate_sync WHERE id = 1;
     INSERT INTO capability_gate_sync (id, commit_hash, synced_at)
       VALUES (1, :h, :ts)
       ON CONFLICT (id) DO UPDATE
       SET commit_hash = EXCLUDED.commit_hash,
           synced_at   = EXCLUDED.synced_at;

Columns
-------

* ``id`` — INTEGER PRIMARY KEY CHECK (id = 1), singleton sentinel.
* ``commit_hash`` — 40-char SHA, or NULL before first sync (spec §15.4
  step 2).
* ``synced_at`` — timestamp (with tz) of the last successful sync.
  ``server_default=NOW()`` so raw-SQL writers that omit the column still
  get a DB-supplied timestamp (mem-005); the Python ORM ``default=_now``
  in :class:`CapabilityGateSync` continues to populate the instance on
  ORM-shaped INSERTs without requiring a refresh.

Downgrade: DROP TABLE — re-derived from state.git on next startup
(spec §13). No data preservation.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Alembic reads ``revision`` / ``down_revision`` / ``branch_labels`` /
# ``depends_on`` via module introspection (see ``alembic.script.revision``).
# Declaring them in ``__all__`` silences CodeQL's py/unused-global-variable
# false positive — same pattern as migrations 0004-0008.
__all__ = [
    "branch_labels",
    "depends_on",
    "down_revision",
    "downgrade",
    "revision",
    "upgrade",
]


def upgrade() -> None:
    """Create capability_gate_sync singleton table."""
    op.create_table(
        "capability_gate_sync",
        # mem-004: INTEGER PK with CHECK enforces the singleton row contract.
        # A UUID PK with default=uuid4 would create a new row on every INSERT
        # that omits the id — RealGate's staleness check would be
        # non-deterministic.
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        # mem-002: column is 'commit_hash' to match PR-S3-2 PostgresBackend SQL.
        sa.Column("commit_hash", sa.String(64), nullable=True),
        sa.Column(
            "synced_at",
            sa.DateTime(timezone=True),
            # mem-005: DB-level NOW() default so raw-SQL writers (Alembic
            # data ops, psql) that omit synced_at still get a populated
            # value — the Python ORM default in models.CapabilityGateSync
            # does not run for non-ORM INSERT paths.
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("id = 1", name="ck_capability_gate_sync_singleton"),
    )


def downgrade() -> None:
    """Drop capability_gate_sync. Re-derived from state.git on next startup."""
    op.drop_table("capability_gate_sync")
