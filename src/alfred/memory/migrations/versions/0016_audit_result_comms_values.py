"""extend audit_log.result CHECK with PR-S4-8 comms-MCP result values

Revision ID: 0016
Revises: 0015
Create Date: 2026-06-09 00:00:00.000000

PR-S4-8 (#152) adds the comms-MCP host-side inbound path, whose audit rows
carry ``result`` discriminators outside the Slice-4 (migration 0014) domain:

* ``promoted`` — ``COMMS_INBOUND_T3_PROMOTION_FIELDS`` success row: a comms
  inbound body passed the burst gate + quarantined extract and was promoted to
  orchestrator-readable T3-derived structured data (spec §8.10 / §9).
* ``binding_requested`` — ``COMMS_BINDING_REQUESTED_FIELDS``: ``IdentityResolver``
  returned ``None`` (first-contact / unbound platform user); the binding flow's
  out-of-band verification phrase is Slice-5 scope.
* ``dropped`` — ``COMMS_INBOUND_BUDGET_CAPPED_FIELDS`` hard-drop row: the
  per-(user, persona) burst limiter stayed empty past ``drop_after_seconds``, or
  the pre-resolution coarse limiter refused before the resolver ran (sec-003).
* ``allowed`` — the ``alfred/hooks.register`` post-handshake disposition the
  comms-wired :class:`AlfredPluginSession` emits when a notification method is
  permitted (Wave-3 session extension).
* ``failed`` — ``COMMS_HANDLER_FAILED_FIELDS``: a comms notification handler
  raised; the loud audit row lands before the err-007 re-raise.

Strictly additive at upgrade time — no rows are modified. No new columns are
added to ``audit_log``; the PR-S4-8 ``COMMS_*_FIELDS`` constants marshal into
the existing ``subject`` JSONB column, following the migration-0014 discipline.

Downgrade: revert CHECK to the migration-0014 domain. Rows whose ``result`` is
in the comms-only set are DELETED before the constraint is restored (the
loud-destruction discipline carried from migrations 0005/0006/0007/0014 — a
Postgres NOTICE names the deleted-row count so an operator sees the destruction).
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0016"
down_revision: str | Sequence[str] | None = "0015"
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


# Migration-0014 head domain — must match 0014's upgrade output exactly. Source
# of truth is the AuditEntry ORM model in src/alfred/memory/models.py.
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
)


# PR-S4-8 (#152) comms-MCP inbound + session-dispatch result values.
_COMMS_ADDITIONS: tuple[str, ...] = (
    "promoted",
    "binding_requested",
    "dropped",
    "allowed",
    "failed",
)


def _result_in_clause(values: tuple[str, ...]) -> str:
    """Return the SQL fragment for ``result IN (..)`` with quoted values."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Extend ck_audit_log_result with the PR-S4-8 comms-MCP result values."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _COMMS_ADDITIONS),
    )


def downgrade() -> None:
    """Revert CHECK to the migration-0014 domain, deleting comms-only rows loudly."""
    quoted_additions = ", ".join(f"'{v}'" for v in _COMMS_ADDITIONS)
    downgrade_delete_sql = f"""
DO $$
DECLARE
  deleted_count integer;
BEGIN
  DELETE FROM audit_log WHERE result IN ({quoted_additions});
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE NOTICE
    'migration 0016 downgrade deleted % audit_log row(s) with comms-MCP result values',
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
