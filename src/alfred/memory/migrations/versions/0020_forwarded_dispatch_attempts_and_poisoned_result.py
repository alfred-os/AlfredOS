"""forwarded_dispatch_attempts ledger + audit_log.result CHECK poisoned value

Revision ID: 0020
Revises: 0019
Create Date: 2026-06-22 00:00:00.000000

Spec B G6-7-5 (#309, ADR-0039 item 4b). The forwarded dispatched-edge path
(:func:`alfred.comms_mcp.inbound.process_inbound_message` with
``commit_at_dispatch_edge=True``) leaves a failed frame NOT committed / NOT
observed so the forwarding leg replays it. This migration adds the DURABLE
per-``(adapter_id, inbound_id)`` ``forwarded_dispatch_attempts`` ledger that
BOUNDS that replay (an in-memory counter would reset exactly when the bound is
needed — replay happens across core restarts), and extends
``ck_audit_log_result`` with the ``'poisoned'`` discriminator emitted when the
replay bound is exhausted (DISTINCT from ``'dispatch_failed'`` so the
still-replaying and the give-up rows are distinguishable in the log).

Composite ``(adapter_id, inbound_id)`` PRIMARY KEY mirrors the sibling
``inbound_idempotency`` ledger (migration 0018): ``inbound_id`` is a free-form
plugin-minted opaque string, so a single-column key would collapse every
adapter into one shared id namespace — scoping by the host-validated
``adapter_id`` isolates each adapter's namespace. The bounded ``char_length``
CHECKs mirror the ORM ``String(128)`` / ``String(255)`` types in
``src/alfred/memory/models.py`` (the load-bearing DB-layer enforcement).

Strictly additive at upgrade time — a new table plus a widened CHECK domain;
no rows are modified, no existing columns added (the poisoned row marshals into
the existing ``subject`` JSONB column).

Downgrade: drop the new table, and revert the CHECK to the migration-0019
domain. Rows whose ``result`` is in the poisoned-only set are DELETED before the
constraint is restored (the loud-destruction discipline carried from migrations
0005/0006/0007/0014/0016/0017/0019 — a Postgres NOTICE names the deleted-row
count so an operator sees the destruction). Source of truth: every value here
MUST also be in the ``ck_audit_log_result`` CheckConstraint of the
``AuditEntry`` ORM model in ``src/alfred/memory/models.py``; CI's
migration-roundtrip test catches drift.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | Sequence[str] | None = "0019"
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


# Migration-0017 head domain — copied VERBATIM from 0019's _BASE_RESULTS (its
# upgrade output is _BASE_RESULTS + _DISPATCH_FAILED_ADDITIONS). Source of truth
# is the AuditEntry ORM model in src/alfred/memory/models.py.
_BASE_RESULTS: tuple[str, ...] = (
    "success",
    "budget_blocked",
    "budget_overrun",
    "provider_failed",
    "cancelled",
    "refused",
    "refused_unknown_user",
    "rate_limited",
    "dlp_failed",
    "split_failed",
    "send_failed",
    "recovery_send_failed",
    "login_failed",
    "gateway_unhealthy",
    "unknown_budget_user",
    "fault",
    "bypass",
    "extracted",
    "malformed_exhausted",
    "load_refused",
    "crashed",
    "quarantined",
    "reloaded",
    "requested",
    "approved",
    "denied",
    "revoked",
    "tripped",
    "reset",
    "content_expired",
    # Slice-4 (migration 0014).
    "dispatched_with_redactions",
    "dispatched_clean",
    "recursion_refused",
    "audit_row_emitted",
    # Slice-4 (migration 0016) — PR-S4-8 comms-MCP.
    "promoted",
    "binding_requested",
    "dropped",
    "capped",
    "allowed",
    "failed",
    "restart_requested",
    # Slice-4 (migration 0017) — PR-S4-11b supervisor-shutdown / reset.
    "cancelled_with_errors",
    "persistence_failed",
)


# Spec B G6-7-4 (#309, migration 0019) dispatched-edge dispatch-failure value.
_DISPATCH_FAILED_ADDITIONS: tuple[str, ...] = ("dispatch_failed",)


# Spec B G6-7-5 (#309) replay-bound-exhausted discriminator.
_POISONED_ADDITIONS: tuple[str, ...] = ("poisoned",)


def _result_in_clause(values: tuple[str, ...]) -> str:
    """Return the SQL fragment for ``result IN (..)`` with quoted values."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Create the forwarded_dispatch_attempts ledger + extend the result CHECK."""
    op.create_table(
        "forwarded_dispatch_attempts",
        sa.Column("adapter_id", sa.String(128), nullable=False),
        sa.Column("inbound_id", sa.String(255), nullable=False),
        sa.Column(
            "attempt_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "first_failed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "last_failed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("adapter_id", "inbound_id", name="pk_forwarded_dispatch_attempts"),
        sa.CheckConstraint(
            "char_length(adapter_id) BETWEEN 1 AND 128",
            name="ck_forwarded_dispatch_attempts_adapter_id_length",
        ),
        sa.CheckConstraint(
            "char_length(inbound_id) BETWEEN 1 AND 255",
            name="ck_forwarded_dispatch_attempts_inbound_id_length",
        ),
    )
    # Retention index mirroring the sibling inbound_idempotency ledger's
    # ``ix_inbound_idempotency_committed_at`` (migration 0018). Rows here are
    # long-lived; a future age-based GC sweep (tracked follow-up, deferred this
    # slice) prunes by ``last_failed_at`` — the index keeps that sweep off a
    # seq-scan and the two ledgers symmetric.
    op.create_index(
        "ix_forwarded_dispatch_attempts_last_failed_at",
        "forwarded_dispatch_attempts",
        ["last_failed_at"],
        unique=False,
    )
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _DISPATCH_FAILED_ADDITIONS + _POISONED_ADDITIONS),
    )


def downgrade() -> None:
    """Revert CHECK to the 0019 domain (deleting poisoned rows loudly), drop the table."""
    quoted_additions = ", ".join(f"'{v}'" for v in _POISONED_ADDITIONS)
    downgrade_delete_sql = f"""
DO $$
DECLARE
  deleted_count integer;
BEGIN
  DELETE FROM audit_log WHERE result IN ({quoted_additions});
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE NOTICE
    'migration 0020 downgrade deleted % audit_log row(s) with the poisoned result value',
    deleted_count;
END $$;
"""  # noqa: S608
    op.execute(downgrade_delete_sql)
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _DISPATCH_FAILED_ADDITIONS),
    )
    op.drop_index(
        "ix_forwarded_dispatch_attempts_last_failed_at",
        table_name="forwarded_dispatch_attempts",
        if_exists=True,
    )
    op.execute("DROP TABLE IF EXISTS forwarded_dispatch_attempts")
