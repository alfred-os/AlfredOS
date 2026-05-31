"""plugin_grants — Postgres projection of state.git capability grants

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-31 00:00:00.000000

``plugin_grants`` is the Postgres runtime cache for the state.git
capability grant tree. ``RealGate`` (PR-S3-2) reads from this table for
millisecond-latency hot-path capability checks; the table is rebuilt from
state.git when the commit hash stored in ``capability_gate_sync``
(migration 0009) differs from the current HEAD (spec §8.1).

Columns
-------

* ``id`` — UUID primary key.
* ``created_at`` — write timestamp (with tz).
* ``plugin_id`` — MCP plugin identifier (e.g. ``"alfred.quarantined-llm"``).
* ``subscriber_tier`` — closed domain
  ``{'system', 'operator', 'user-plugin'}``. Spec §4.3 naming rule: this
  is the hook-subscription axis, NOT a content trust tier.
* ``hookpoint`` — dotted action name (e.g.
  ``"security.quarantined.extract"``).
* ``content_tier`` — content trust tier the grant permits
  (``'T0' | 'T1' | 'T2' | 'T3' | NULL``). ``NULL`` means no content-tier
  restriction. Two-axis naming rule per spec §4.3.
* ``operator_user_id`` — canonical_user_id of the operator who created the
  grant (nullable for legacy / system-installed grants).
* ``proposal_branch`` — state.git proposal branch name (e.g.
  ``"proposal/policy-grant-abc"``).
* ``correlation_id`` — UUID-shaped audit-trail linkage.
* ``state`` — closed domain
  ``{'requested', 'approved', 'denied', 'revoked'}``.
* ``state_git_commit_hash`` — state.git HEAD at the time this row was
  written; the staleness check in 0009's table compares against this.

Constraints
-----------

* ``ck_plugin_grants_state`` — closed-domain CHECK on ``state``.
* ``ck_plugin_grants_subscriber_tier`` — closed-domain CHECK on the
  subscriber-tier axis.
* ``ck_plugin_grants_content_tier`` — NULL or one of ``T0/T1/T2/T3``.
* ``uq_plugin_grants_plugin_hook_tier`` — UNIQUE on
  ``(plugin_id, hookpoint, subscriber_tier)``. This is the ON CONFLICT
  target the PR-S3-2 ``PostgresBackend.upsert_grant`` SQL relies on; the
  round-trip test pins it so a future refactor cannot quietly drop the
  constraint.

Indexes
-------

* ``ix_plugin_grants_plugin_id_state`` — hot-path lookup for "all
  grants in state X for plugin Y" (RealGate startup rebuild).
* ``ix_plugin_grants_hookpoint`` — hot-path lookup for "all grants on
  hookpoint Z" (capability gate runtime check).

Downgrade: DROP TABLE — the table is fully rebuildable from state.git
(spec §13). No data preservation.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | Sequence[str] | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Alembic reads ``revision`` / ``down_revision`` / ``branch_labels`` /
# ``depends_on`` via module introspection (see ``alembic.script.revision``).
# Declaring them in ``__all__`` silences CodeQL's py/unused-global-variable
# false positive — same pattern as migrations 0004 / 0005 / 0006 / 0007.
__all__ = [
    "branch_labels",
    "depends_on",
    "down_revision",
    "downgrade",
    "revision",
    "upgrade",
]


def upgrade() -> None:
    """Create plugin_grants table."""
    op.create_table(
        "plugin_grants",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("plugin_id", sa.String(128), nullable=False),
        sa.Column("subscriber_tier", sa.String(32), nullable=False),
        sa.Column("hookpoint", sa.String(128), nullable=False),
        # NULL = no content-tier restriction; otherwise one of T0/T1/T2/T3.
        sa.Column("content_tier", sa.String(8), nullable=True),
        sa.Column("operator_user_id", sa.String(64), nullable=True),
        sa.Column("proposal_branch", sa.String(256), nullable=True),
        sa.Column("correlation_id", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("state_git_commit_hash", sa.String(64), nullable=True),
        sa.CheckConstraint(
            "state IN ('requested', 'approved', 'denied', 'revoked')",
            name="ck_plugin_grants_state",
        ),
        sa.CheckConstraint(
            "subscriber_tier IN ('system', 'operator', 'user-plugin')",
            name="ck_plugin_grants_subscriber_tier",
        ),
        sa.CheckConstraint(
            "content_tier IS NULL OR content_tier IN ('T0', 'T1', 'T2', 'T3')",
            name="ck_plugin_grants_content_tier",
        ),
        # mem-003: UNIQUE must match PR-S3-2's ON CONFLICT target exactly.
        # PostgresBackend.upsert_grant issues:
        #     INSERT ... ON CONFLICT (plugin_id, hookpoint, subscriber_tier)
        #         DO UPDATE ...
        # Without this constraint, every upsert raises InvalidColumnReference.
        sa.UniqueConstraint(
            "plugin_id",
            "hookpoint",
            "subscriber_tier",
            name="uq_plugin_grants_plugin_hook_tier",
        ),
    )
    op.create_index(
        "ix_plugin_grants_plugin_id_state",
        "plugin_grants",
        ["plugin_id", "state"],
    )
    op.create_index(
        "ix_plugin_grants_hookpoint",
        "plugin_grants",
        ["hookpoint"],
    )


def downgrade() -> None:
    """Drop plugin_grants. Rebuildable from state.git."""
    op.drop_index("ix_plugin_grants_hookpoint", table_name="plugin_grants")
    op.drop_index("ix_plugin_grants_plugin_id_state", table_name="plugin_grants")
    op.drop_table("plugin_grants")
