"""processed_proposals — replay-safety ledger for side-effecting dispatch

Revision ID: 0011
Revises: 0010
Create Date: 2026-06-05 00:00:00.000000

ADR-0021 — two new tables underpin the merged-proposal dispatch loop:

* ``processed_proposals`` — composite-PK ``(proposal_type, proposal_id)``
  ledger of every dispatched proposal. The PK + the HEAD-diff walk give
  the at-most-once guarantee per ADR-0021 §Atomicity model.
* ``processed_proposals_head`` — single-row sentinel tracking the last
  state.git HEAD the dispatcher walked from. ``head_sha`` starts NULL;
  the first dispatch cycle detects NULL and bootstraps from
  ``git rev-parse origin/main`` (forward-from-now semantics — existing
  blobs are not reprocessed).

The migration MUST NOT call subprocess or git. Rejected alternative A6 in
ADR-0021: ``/var/lib/alfred/state.git`` does not exist at fresh-install
migration time on every deployment shape. The bootstrap happens at first
dispatch-cycle execution, not at migration time.

Columns
-------

``processed_proposals``:

* ``proposal_type`` / ``proposal_id`` — composite PK. String(64) each —
  matches the writer's 16-hex id width with headroom for future composed
  discriminators (per ADR-0018 ``web-allowlist-<action>``).
* ``blob_sha`` — String(40), NOT NULL. The content hash of the JSON blob
  on the merge commit.
* ``commit_sha`` — String(40), NOT NULL. The merge-commit SHA. The
  non-repudiable forensic join key per ADR-0021 §Threat model;
  ``operator_user_id`` is self-claimed forensic context only.
* ``processed_at`` — timestamptz, NOT NULL, ``server_default now()``.
* ``result`` — String(32), NOT NULL. Closed vocab pinned by
  ``ck_processed_proposals_result``.
* ``handler_version`` — int, NOT NULL, default 1.
* ``failure_kind`` — String(48), nullable. Six-value closed vocab per
  spec §2.5, enforced via ``ck_processed_proposals_failure_kind`` at the
  DB layer in addition to the dispatcher's ``Literal``-narrowed call
  sites. Defense-in-depth: a future emit-site refactor that drops the
  ``Literal`` narrowing still cannot land an un-known kind in the ledger.
* ``failure_detail`` — String(512), nullable. Currently truncated only;
  DLP redaction (``OutboundDlp.scan``) is tracked at
  `#173 <https://github.com/alfred-os/AlfredOS/issues/173>`_. Today's
  emit sites pass closed-vocab strings (``type(exc).__name__``, the
  handler-returned reason from :meth:`DispatchOutcome.failed`) so the
  realised leak surface is small, but a future emit site that drops a
  Pydantic-validation-error message into this field would carry verbatim
  T3 fragments — #173 wires the scanner at this boundary.
* ``operator_user_id`` — String(64), nullable. Matches
  ``PluginGrant.operator_user_id`` and ``AuditEntry.actor_user_id``.

``processed_proposals_head``:

* ``id`` — int, PK. The CheckConstraint pins ``id = 1`` so the table is
  provably single-row even from raw SQL.
* ``head_sha`` — String(40), nullable. Bootstrap-pending after migration.
* ``updated_at`` — timestamptz, NOT NULL, ``server_default now()``,
  ``onupdate now()``.

Downgrade: DROP TABLE on both. The state is transient — the next run
re-discovers the policies/breaker-resets/ contents organically. Operators
who need the dispatch history snapshot the table BEFORE downgrading
(loud-destruction pattern shared with migrations 0006 / 0007 / 0010).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: str | Sequence[str] | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Alembic reads ``revision`` / ``down_revision`` / ``branch_labels`` /
# ``depends_on`` via module introspection (see ``alembic.script.revision``).
# Declaring them in ``__all__`` silences CodeQL's py/unused-global-variable
# false positive — same pattern as migrations 0004-0010.
__all__ = [
    "branch_labels",
    "depends_on",
    "down_revision",
    "downgrade",
    "revision",
    "upgrade",
]


def upgrade() -> None:
    """Create processed_proposals + processed_proposals_head; seed sentinel NULL.

    No subprocess / git calls (ADR-0021 §A6) — sentinel row inserts with
    ``head_sha = NULL`` and the first dispatch cycle bootstraps from
    ``git rev-parse origin/main`` at runtime.
    """
    op.create_table(
        "processed_proposals",
        sa.Column("proposal_type", sa.String(64), primary_key=True, nullable=False),
        sa.Column("proposal_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("blob_sha", sa.String(40), nullable=False),
        sa.Column("commit_sha", sa.String(40), nullable=False),
        sa.Column(
            "processed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("result", sa.String(32), nullable=False),
        sa.Column(
            "handler_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
        sa.Column("failure_kind", sa.String(48), nullable=True),
        sa.Column("failure_detail", sa.String(512), nullable=True),
        sa.Column("operator_user_id", sa.String(64), nullable=True),
        sa.CheckConstraint(
            # CR rework round-1 (MEDIUM/LOW): ``skipped_already_processed``
            # is dropped from the closed set. The dispatcher's replay
            # path returns early (:func:`_dispatch_one` composite-PK
            # short-circuit) WITHOUT inserting a ledger row, so the
            # value was never written. Keeping it in the CHECK was a
            # vestigial allowance from an earlier draft that wrote a
            # marker row on the skip path.
            "result IN ('applied', 'failed_handler', 'failed_parse', 'failed_unknown_type')",
            name="ck_processed_proposals_result",
        ),
        sa.CheckConstraint(
            # HIGH #8: defense-in-depth on top of the dispatcher's
            # ``Literal``-narrowed call sites in :func:`_record_failure`.
            # ``NULL`` is permitted because the ``applied`` path leaves
            # the column NULL; every failure path narrows to one of the
            # six closed-vocab values.
            "failure_kind IS NULL OR failure_kind IN ("
            "'handler_returned_failed', 'handler_uncaught_exception', "
            "'payload_validation', 'unknown_proposal_type', "
            "'blob_not_found', 'handler_timeout')",
            name="ck_processed_proposals_failure_kind",
        ),
        sa.CheckConstraint(
            # CR-rework round-2 MAJOR T4: result x failure_kind invariant.
            # The two columns are coupled — the ``applied`` row family
            # MUST leave ``failure_kind`` NULL (success carries no
            # failure discriminator), and every ``failed_*`` row family
            # MUST carry a non-NULL ``failure_kind`` (otherwise the
            # operator-visible row is "this proposal failed but we don't
            # know how" — a silent-drop variant). The dispatcher's
            # call-site Literals already encode this invariant, but
            # without the CHECK a future refactor that drops the typing
            # narrowing could land an incoherent row in the ledger.
            "(result = 'applied' AND failure_kind IS NULL) "
            "OR (result IN ('failed_handler', 'failed_parse', "
            "'failed_unknown_type') AND failure_kind IS NOT NULL)",
            name="ck_processed_proposals_result_failure_kind_consistency",
        ),
    )

    op.create_table(
        "processed_proposals_head",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("head_sha", sa.String(40), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("id = 1", name="ck_processed_proposals_head_singleton"),
    )

    # Seed the single sentinel row with head_sha = NULL. The dispatch
    # loop's first cycle detects NULL and bootstraps to
    # ``git rev-parse origin/main`` at runtime — NOT here, per ADR-0021
    # §A6. ``updated_at`` falls back to the column server_default.
    op.execute("INSERT INTO processed_proposals_head (id, head_sha) VALUES (1, NULL)")


def downgrade() -> None:
    """Drop both tables. Dispatch ledger is transient — next run rediscovers.

    Loud-destruction pattern: dispatch history is lost on downgrade.
    Operators who care about the forensic record snapshot the table
    BEFORE running this downgrade.
    """
    op.drop_table("processed_proposals_head")
    op.drop_table("processed_proposals")
