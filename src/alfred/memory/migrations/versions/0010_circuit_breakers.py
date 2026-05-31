"""circuit_breakers — persisted state for supervisor circuit breakers

Revision ID: 0010
Revises: 0009
Create Date: 2026-06-01 00:00:00.000000

``circuit_breakers`` holds one row per supervised component
(e.g. ``"quarantined-llm"``, ``"web-fetch"``) with the breaker's live
state plus the most-recent-trip metadata. On AlfredOS startup, the
supervisor loads each row and stays OPEN if ``last_trip_at < 1h`` ago —
this is the flap protection on rolling restarts (spec §10.6).

Columns
-------

* ``component_id`` — natural primary key. The supervisor's restore SELECT
  targets this name (one row per supervised component, no surrogate UUID).
* ``state`` — live breaker state, closed domain
  ``{'CLOSED', 'OPEN', 'HALF_OPEN'}`` enforced by the CHECK constraint.
  Default ``'CLOSED'`` for raw-SQL writers that omit it.
* ``trip_count`` — total trips since first deploy. Default 0.
* ``last_trip_at`` — timestamptz of the most-recent trip; NULL for a
  fresh row that has never tripped.
* ``last_failure_type`` — Python exception class name only
  (e.g. ``"SubprocessExitedError"``). Never ``str(exc)`` per spec §5.6
  (T3 fragment risk from the plugin subprocess). 128-char limit so a
  stray ``str(exc)`` truncates rather than overflows.
* ``breaker_state`` — mirrors
  :data:`SUPERVISOR_BREAKER_TRIPPED_FIELDS["breaker_state"]` audit-row
  field; always ``"OPEN"`` at trip time. Captured snapshot, distinct
  from ``state`` (the live value). Default ``'CLOSED'`` (no trip yet).
* ``correlation_id`` — mirrors
  :data:`SUPERVISOR_BREAKER_TRIPPED_FIELDS["correlation_id"]`; the
  correlation id of the most-recent trip event. Lets operators pivot
  from a breaker row to the audit-log entry that opened it. Default
  empty string (never tripped).

Constraints
-----------

* ``ck_circuit_breakers_state`` — closed-domain CHECK on ``state``. A
  buggy writer (or hand-edited row) cannot smuggle an invalid value past
  the type layer and have downstream code trust it.

server_default rationale (mem-005 pattern)
------------------------------------------

``state``, ``trip_count``, ``breaker_state``, ``correlation_id`` all
declare ``server_default=`` so raw-SQL writers (Alembic data ops, psql,
integration fixtures that only supply ``component_id``) get DB-supplied
defaults matching the ORM ``default=``. The ORM-side defaults continue
to populate transient instances at flush time without a refresh.

Downgrade: DROP TABLE. Breaker state is transient — the next run
re-discovers failures organically. Operators who need the trip history
snapshot the table BEFORE downgrading (loud-destruction pattern shared
with migrations 0006 / 0007).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: str | Sequence[str] | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Alembic reads ``revision`` / ``down_revision`` / ``branch_labels`` /
# ``depends_on`` via module introspection (see ``alembic.script.revision``).
# Declaring them in ``__all__`` silences CodeQL's py/unused-global-variable
# false positive — same pattern as migrations 0004-0009.
__all__ = [
    "branch_labels",
    "depends_on",
    "down_revision",
    "downgrade",
    "revision",
    "upgrade",
]


def upgrade() -> None:
    """Create circuit_breakers table."""
    op.create_table(
        "circuit_breakers",
        sa.Column("component_id", sa.String(128), primary_key=True),
        sa.Column(
            "state",
            sa.String(16),
            nullable=False,
            server_default="CLOSED",
        ),
        sa.Column(
            "trip_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "last_trip_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        # Python exception class name only; never str(exc) — spec §5.6 T3 risk.
        sa.Column("last_failure_type", sa.String(128), nullable=True),
        # Mirrors SUPERVISOR_BREAKER_TRIPPED_FIELDS["breaker_state"] —
        # always "OPEN" at trip time. Captured snapshot, not live state.
        sa.Column(
            "breaker_state",
            sa.String(16),
            nullable=False,
            server_default="CLOSED",
        ),
        # Mirrors SUPERVISOR_BREAKER_TRIPPED_FIELDS["correlation_id"] —
        # most-recent trip's correlation id. Empty string until first trip.
        sa.Column(
            "correlation_id",
            sa.String(64),
            nullable=False,
            server_default="",
        ),
        sa.CheckConstraint(
            "state IN ('CLOSED', 'OPEN', 'HALF_OPEN')",
            name="ck_circuit_breakers_state",
        ),
    )


def downgrade() -> None:
    """Drop circuit_breakers. Breaker state is transient — re-discovered next run.

    Destructive: trip history is lost. Operators who care should snapshot
    the table BEFORE running this downgrade. Loud-destruction pattern
    shared with migrations 0006 / 0007 / 0009.
    """
    op.drop_table("circuit_breakers")
