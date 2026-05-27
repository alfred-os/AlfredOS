"""users + platform_identities; per-row persona_id columns; operator backfill

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-26 00:00:00.000000

Spec §2 line 228-268. One transaction with ``SET LOCAL statement_timeout = '60s'``.
Idempotent — ``ON CONFLICT (slug) DO NOTHING`` on the operator insert. Collision
refusal raises ``OperatorSlugCollisionError`` (a ``CommandError`` subclass) so
Alembic surfaces the message at exit 1 rather than crashing.

Structure
---------

The upgrade is split into three composable helpers (``_create_tables``,
``_add_persona_id_columns``, ``_install_operator``) so the integration test
can compose the first two stages, inject a colliding row, then call
``_install_operator`` to exercise the collision-refusal path on a real
database. Alembic loads each migration via its own ``ScriptDirectory`` so
the test can't simply ``monkeypatch.setattr`` on a module-global; calling
the helpers directly is the cleanest reproducible seam.

Spec-vs-reality reconciliation
------------------------------

The plan (PR A T7) calls for adding ``language`` + ``persona_id`` to both
``episodes`` and ``audit_log`` as nullable. ``language`` already shipped in
Slice-1 migration ``0001`` as ``String(16) NOT NULL`` because CLAUDE.md i18n
rule #3 mandated it from day one. Re-adding it here would be a no-op at best
and a destructive DROP-then-ADD at worst, so this migration only adds
``persona_id`` (the genuinely new per-row column). The Slice-1 ``language``
NOT-NULL invariant is preserved unchanged. The orchestrator (PR B Task 9 +
PR-A T15) will start populating ``persona_id`` for new rows; old rows stay
NULL because the migration deliberately does not back-fill stored content.

Slug-collision pre-check (security invariant)
---------------------------------------------

Before inserting the operator row, the migration queries for any existing
``users`` row at the same slug whose ``authorization != 'operator'``. If
found, the migration aborts with ``OperatorSlugCollisionError`` carrying the
remediation string (re-run with ``ALFRED_OPERATOR_NAME=<unique-name>``).
Silent backfill in this case would re-attribute the colliding user's audit
history to the operator — a privilege-escalation footgun the gate exists to
slam shut.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

from alfred.identity.errors import OperatorSlugCollisionError
from alfred.identity.slug import derive_slug

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _operator_name() -> str:
    """Operator's human-readable name from env; defaults to ``"operator"``."""
    return os.environ.get("ALFRED_OPERATOR_NAME", "operator")


def _operator_language() -> str:
    """Operator's BCP-47 language tag from env; defaults to ``"en-US"``."""
    return os.environ.get("ALFRED_OPERATOR_LANGUAGE", "en-US")


def _operator_budget() -> float:
    """Operator's daily USD budget from env; defaults to $1.00."""
    return float(os.environ.get("ALFRED_DAILY_BUDGET_USD", "1.0"))


def _create_tables() -> None:
    """Create ``users`` + ``platform_identities`` with constraints + partial-unique index."""
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("slug", sa.Text(), nullable=False, unique=True),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("authorization", sa.Text(), nullable=False),
        sa.Column("daily_budget_usd", sa.Float(), nullable=False),
        sa.Column("language", sa.Text(), nullable=False),
        sa.Column("rate_limit_per_min", sa.Integer(), nullable=True),
        sa.Column("rate_limit_per_day", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        # ``authorization`` is a Postgres reserved keyword (per the SQL
        # standard: GRANT…AUTHORIZATION). Bare in a CHECK expression PG
        # parses it as the keyword and rejects the constraint; quote it so
        # the column reference survives DDL emission unambiguously.
        sa.CheckConstraint(
            "\"authorization\" IN ('read_only', 'standard', 'trusted', 'operator')",
            name="ck_users_authorization",
        ),
        sa.CheckConstraint(
            "daily_budget_usd > 0",
            name="ck_users_daily_budget_usd_positive",
        ),
        sa.CheckConstraint(
            "rate_limit_per_min IS NULL OR rate_limit_per_min >= 0",
            name="ck_users_rate_limit_per_min_nonneg",
        ),
        sa.CheckConstraint(
            "rate_limit_per_day IS NULL OR rate_limit_per_day >= 0",
            name="ck_users_rate_limit_per_day_nonneg",
        ),
    )

    op.create_table(
        "platform_identities",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("platform", sa.Text(), nullable=False),
        sa.Column("platform_id", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "platform IN ('tui', 'discord')",
            name="ck_platform_identities_platform",
        ),
        sa.UniqueConstraint(
            "platform",
            "platform_id",
            name="uq_platform_identity_platform_platform_id",
        ),
    )
    # Per-user uniqueness restricted to live bindings — Alembic has no
    # first-class partial-unique-index helper, so emit raw DDL. Name matches
    # the ORM Index declaration in src/alfred/identity/models.py so
    # alembic-autogenerate stays a no-op in downstream slices.
    op.execute(
        "CREATE UNIQUE INDEX uq_platform_identities_user_id_platform_active "
        "ON platform_identities (user_id, platform) "
        "WHERE deleted_at IS NULL"
    )


def _add_persona_id_columns() -> None:
    """Add nullable ``persona_id`` to ``episodes`` + ``audit_log``.

    ``language`` already ships from migration 0001 as NOT NULL — see module
    docstring's reconciliation note for why this migration deliberately does
    not re-add it.
    """
    # ``String(length=64)`` matches the ORM (``src/alfred/memory/models.py``);
    # ``sa.Text()`` would drift the schema and cause downstream alembic
    # autogenerate to repeatedly propose column-type "fixes".
    op.add_column("episodes", sa.Column("persona_id", sa.String(length=64), nullable=True))
    op.add_column("audit_log", sa.Column("persona_id", sa.String(length=64), nullable=True))


def _install_operator(conn: Any) -> None:
    """Pre-check slug collision, then insert operator + TUI binding + backfill.

    Raises ``OperatorSlugCollisionError`` if a non-operator users row
    already squats the canonical slug. The pre-check is the security
    invariant — silently no-opping the insert (via ``ON CONFLICT``) would
    cause the subsequent UPDATE to re-attribute every old audit row to a
    different user.
    """
    operator_name = _operator_name()
    operator_slug = derive_slug(operator_name)

    existing = conn.execute(
        text(
            'SELECT slug, display_name, "authorization" FROM users '
            "WHERE slug = :slug AND \"authorization\" != 'operator'"
        ),
        {"slug": operator_slug},
    ).first()
    if existing is not None:
        raise OperatorSlugCollisionError(
            f"slug '{operator_slug}' already in use by non-operator user "
            f"'{existing.display_name}'; re-run with "
            f"ALFRED_OPERATOR_NAME=<unique-name> alembic upgrade head"
        )

    # Operator insert — idempotent under ON CONFLICT so re-running
    # ``alembic upgrade head`` is a clean no-op. ``authorization`` is
    # quoted because PG reserves it (see CHECK in ``_create_tables`` for
    # the same reason).
    conn.execute(
        text(
            'INSERT INTO users (slug, display_name, "authorization", daily_budget_usd, '
            "language, created_at) VALUES (:slug, :name, 'operator', :budget, :lang, now()) "
            "ON CONFLICT (slug) DO NOTHING"
        ),
        {
            "slug": operator_slug,
            "name": operator_name,
            "budget": _operator_budget(),
            "lang": _operator_language(),
        },
    )

    # Resolve the operator's surrogate id (works whether we just inserted
    # it or hit the ON CONFLICT branch on a re-run).
    operator_id = conn.execute(
        text("SELECT id FROM users WHERE slug = :slug"),
        {"slug": operator_slug},
    ).scalar_one()

    # TUI platform-identity row for the operator. The ``platform_id`` for
    # the TUI is the operator's display name (the TUI has no platform-
    # native snowflake equivalent).
    conn.execute(
        text(
            "INSERT INTO platform_identities (user_id, platform, platform_id, created_at) "
            "VALUES (:uid, 'tui', :name, now()) "
            "ON CONFLICT (platform, platform_id) DO NOTHING"
        ),
        {"uid": operator_id, "name": operator_name},
    )

    # Backfill — only rows whose literal user_id differs from the canonical
    # slug get rewritten. The WHERE clause makes the UPDATE a true no-op
    # when the literal already equals the slug (the common default case).
    conn.execute(
        text("UPDATE episodes SET user_id = :slug WHERE user_id != :slug"),
        {"slug": operator_slug},
    )
    conn.execute(
        text(
            "UPDATE audit_log SET actor_user_id = :slug "
            "WHERE actor_user_id IS NOT NULL AND actor_user_id != :slug"
        ),
        {"slug": operator_slug},
    )


def upgrade() -> None:
    """Create users + platform_identities, add persona_id columns, backfill operator."""
    conn = op.get_bind()
    # Cap the migration at 60s so a runaway backfill on a corrupted DB
    # fails loudly instead of holding the deploy-time lock indefinitely.
    conn.execute(text("SET LOCAL statement_timeout = '60s'"))

    _create_tables()
    _add_persona_id_columns()
    _install_operator(conn)


def downgrade() -> None:
    """Drop the persona_id columns + two tables. 0003-shape row content survives."""
    op.drop_column("audit_log", "persona_id")
    op.drop_column("episodes", "persona_id")
    op.execute("DROP INDEX IF EXISTS uq_platform_identities_user_id_platform_active")
    op.drop_table("platform_identities")
    op.drop_table("users")
