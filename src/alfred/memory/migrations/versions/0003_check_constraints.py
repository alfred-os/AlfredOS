"""enforce trust-tier + audit-result domains via CHECK constraints

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-26 00:00:00.000000

PRD §7.1 names `trust_tier` and `audit.result` as closed-domain enums. The
ORM declared them as plain ``String`` columns until now, which let a buggy
writer (or a hand-edited row) sneak invalid values past the type layer and
have downstream code trust them. This migration adds the DB-level guardrails:

* ``episodes.trust_tier`` ∈ {T0, T1, T2, T3}
* ``episodes.role`` ∈ {user, assistant}
* ``audit_log.trust_tier_of_trigger`` ∈ {T0, T1, T2, T3}
* ``audit_log.result`` ∈ {success, budget_blocked, budget_overrun,
  provider_failed, cancelled}

The ``cancelled`` value is included in the enum even though Slice-1 only
writes it from the orchestrator's user-cancel branch; the audit row for a
cancelled turn lives outside the per-turn transaction (see
``Orchestrator.handle_user_message``) so the CHECK MUST accept it from day
one.

A fresh Slice-1 database has no rows yet, so no backfill or validation is
needed before adding these constraints. For an upgrade from an unreleased
pre-Slice-1 build that already has rows, an operator must
``UPDATE … SET …`` invalid values first; the CHECK will refuse to create
otherwise.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add CHECK constraints on the trust-tier and audit-result domains."""
    op.create_check_constraint(
        "ck_episodes_trust_tier",
        "episodes",
        "trust_tier IN ('T0', 'T1', 'T2', 'T3')",
    )
    op.create_check_constraint(
        "ck_episodes_role",
        "episodes",
        "role IN ('user', 'assistant')",
    )
    op.create_check_constraint(
        "ck_audit_log_trust_tier_of_trigger",
        "audit_log",
        "trust_tier_of_trigger IN ('T0', 'T1', 'T2', 'T3')",
    )
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        "result IN ('success', 'budget_blocked', 'budget_overrun', 'provider_failed', 'cancelled')",
    )


def downgrade() -> None:
    """Remove the CHECK constraints. Reverting weakens the domain guarantees."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.drop_constraint("ck_audit_log_trust_tier_of_trigger", "audit_log", type_="check")
    op.drop_constraint("ck_episodes_role", "episodes", type_="check")
    op.drop_constraint("ck_episodes_trust_tier", "episodes", type_="check")
