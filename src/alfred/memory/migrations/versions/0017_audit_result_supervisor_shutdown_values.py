"""extend audit_log.result CHECK with supervisor-shutdown result values

Revision ID: 0017
Revises: 0016
Create Date: 2026-06-11 00:00:00.000000

PR-S4-11b DEFECT 2 (UAT-proven). ``Supervisor.stop()`` and
``Supervisor.reset_breaker()`` emit ``result`` discriminators that were never in
the ``ck_audit_log_result`` CHECK domain (last extended by migration 0016 for the
PR-S4-8 comms values), so the shutdown / reset audit INSERT crashed with a
``CheckViolation`` against real Postgres:

* ``cancelled_with_errors`` — ``supervisor.lifecycle.stopped`` force-cancel row:
  a supervised plugin (e.g. an idle comms pump that never observed the shutdown
  signal, or a genuinely wedged plugin) exceeded the graceful-drain budget, so
  the supervisor force-cancelled the runner TaskGroup and captured the aggregated
  ``BaseException``. Emitted by ``Supervisor.stop`` (``src/alfred/supervisor/core.py``).
* ``persistence_failed`` — the breaker-state persistence write failed mid-shutdown
  (``Supervisor.stop``) or mid-reset (``Supervisor.reset_breaker``); the row records
  the unclean persistence so the audit graph carries it BEFORE the SQLAlchemyError
  re-raises (err-002, CLAUDE.md hard rule #7 — a failed write is loud, never silent).

Both values are emitted by the supervisor on the SHUTDOWN / reset path; this PR
owns them. The common (DEFECT-1-fixed) stop is clean ``success`` (already in the
domain) — but the force-cancel path for a genuinely wedged plugin, and the
persistence-failure path, MUST NOT crash the audit write.

Strictly additive at upgrade time — no rows are modified. No new columns are
added to ``audit_log``; the supervisor rows marshal into the existing ``subject``
JSONB column.

Downgrade: revert CHECK to the migration-0016 domain. Rows whose ``result`` is in
the supervisor-shutdown-only set are DELETED before the constraint is restored
(the loud-destruction discipline carried from migrations 0005/0006/0007/0014/0016
— a Postgres NOTICE names the deleted-row count so an operator sees the
destruction).
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0017"
down_revision: str | Sequence[str] | None = "0016"
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


# Migration-0016 head domain — must match 0016's upgrade output exactly (its
# _BASE_RESULTS + _COMMS_ADDITIONS). Source of truth is the AuditEntry ORM model
# in src/alfred/memory/models.py.
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
)


# PR-S4-11b (#237) supervisor-shutdown / reset result values.
_SUPERVISOR_SHUTDOWN_ADDITIONS: tuple[str, ...] = (
    "cancelled_with_errors",
    "persistence_failed",
)


def _result_in_clause(values: tuple[str, ...]) -> str:
    """Return the SQL fragment for ``result IN (..)`` with quoted values."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Extend ck_audit_log_result with the supervisor-shutdown result values."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _SUPERVISOR_SHUTDOWN_ADDITIONS),
    )


def downgrade() -> None:
    """Revert CHECK to the 0016 domain, deleting supervisor-shutdown rows loudly."""
    quoted_additions = ", ".join(f"'{v}'" for v in _SUPERVISOR_SHUTDOWN_ADDITIONS)
    downgrade_delete_sql = f"""
DO $$
DECLARE
  deleted_count integer;
BEGIN
  DELETE FROM audit_log WHERE result IN ({quoted_additions});
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE NOTICE
    'migration 0017 downgrade deleted % audit_log row(s) with supervisor-shutdown result values',
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
