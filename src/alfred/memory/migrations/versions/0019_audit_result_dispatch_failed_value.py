"""extend audit_log.result CHECK with the dispatched-edge dispatch_failed value

Revision ID: 0019
Revises: 0018
Create Date: 2026-06-22 00:00:00.000000

Spec B G6-7-4 (#309, ADR-0039 item 4). The gateway dispatched-edge forwarded path
(:func:`alfred.comms_mcp.inbound.process_inbound_message` with
``commit_at_dispatch_edge=True``) commits + observes AFTER a successful dispatch.
On a dispatch FAILURE it deliberately leaves the frame NOT committed / NOT
observed so the forwarding leg replays it, and emits a SIGNED audit row with a
DISTINCT ``result="dispatch_failed"`` discriminator (never the ``"dropped"``
replay value, so the two are distinguishable in the log). That value was not in
the migration-0016/0017 ``ck_audit_log_result`` domain, so the INSERT would crash
with a ``CheckViolation`` against real Postgres without this extension.

Strictly additive at upgrade time — no rows are modified, no new columns added
(the dispatch_failed row marshals into the existing ``subject`` JSONB column).

Downgrade: revert CHECK to the migration-0017 domain. Rows whose ``result`` is in
the dispatch-failed-only set are DELETED before the constraint is restored (the
loud-destruction discipline carried from migrations 0005/0006/0007/0014/0016/0017
— a Postgres NOTICE names the deleted-row count so an operator sees the
destruction). Source of truth: every value here MUST also be in the
``ck_audit_log_result`` CheckConstraint of the ``AuditEntry`` ORM model in
``src/alfred/memory/models.py``; CI's migration-roundtrip test catches drift.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0019"
down_revision: str | Sequence[str] | None = "0018"
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


# Migration-0017 head domain — must match 0017's upgrade output exactly
# (its _BASE_RESULTS + _SUPERVISOR_SHUTDOWN_ADDITIONS). Source of truth is the
# AuditEntry ORM model in src/alfred/memory/models.py.
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


# Spec B G6-7-4 (#309) dispatched-edge dispatch-failure result value.
_DISPATCH_FAILED_ADDITIONS: tuple[str, ...] = ("dispatch_failed",)


def _result_in_clause(values: tuple[str, ...]) -> str:
    """Return the SQL fragment for ``result IN (..)`` with quoted values."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Extend ck_audit_log_result with the dispatched-edge dispatch_failed value."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _DISPATCH_FAILED_ADDITIONS),
    )


def downgrade() -> None:
    """Revert CHECK to the 0017 domain, deleting dispatch_failed rows loudly."""
    quoted_additions = ", ".join(f"'{v}'" for v in _DISPATCH_FAILED_ADDITIONS)
    downgrade_delete_sql = f"""
DO $$
DECLARE
  deleted_count integer;
BEGIN
  DELETE FROM audit_log WHERE result IN ({quoted_additions});
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE NOTICE
    'migration 0019 downgrade deleted % audit_log row(s) with the dispatch_failed result value',
    deleted_count;
END $$;
"""  # noqa: S608
    op.execute(downgrade_delete_sql)
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS),
    )
