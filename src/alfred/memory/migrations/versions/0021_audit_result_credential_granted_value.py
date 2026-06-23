"""extend audit_log.result CHECK with the credential-grant ``granted`` value

Revision ID: 0021
Revises: 0020
Create Date: 2026-06-23 00:00:00.000000

Spec B G6-3 (#288 / #309, ADR-0036). The core-side credential resolver
(:class:`alfred.comms_mcp.adapter_credential_resolver.CoreAdapterCredentialResolver`)
writes a SIGNED ``core.adapter.spawn_grant`` audit row whenever it releases a
platform credential to the gateway over the trusted ADR-0031 leg. That row carries
a closed-vocab ``result`` of ``'granted'`` (the refusal sibling already uses the
in-domain ``'refused'``). The G6-3 resolver + its
:data:`alfred.audit.audit_row_schemas.CORE_ADAPTER_SPAWN_GRANT_FIELDS` family shipped
with the ``'granted'`` outcome, but no migration ever added that value to
``ck_audit_log_result`` — so the grant INSERT crashes with a ``CheckViolation``
against real Postgres. The resolver's unit tests + the adversarial corpus use an
append-only ``audit`` double that never enforces the constraint, so the gap stayed
invisible until the G6-7-7 e2e drove the first REAL credential round-trip against
real Postgres. Migration 0021 extends the CHECK so the grant result is accepted.

Strictly additive at upgrade time — no rows are modified, no new columns added (the
grant row marshals into the existing ``subject`` JSONB column).

Downgrade: revert CHECK to the migration-0020 domain. Rows whose ``result`` is in
the granted-only set are DELETED before the constraint is restored (the
loud-destruction discipline carried from migrations
0005/0006/0007/0014/0016/0017/0019/0020 — a Postgres NOTICE names the deleted-row
count so an operator sees the destruction). Source of truth: every value here MUST
also be in the ``ck_audit_log_result`` CheckConstraint of the ``AuditEntry`` ORM
model in ``src/alfred/memory/models.py``; CI's migration-roundtrip test catches drift.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0021"
down_revision: str | Sequence[str] | None = "0020"
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


# Migration-0020 head domain — copied VERBATIM from 0020's full upgrade output
# (its _BASE_RESULTS + _DISPATCH_FAILED_ADDITIONS + _POISONED_ADDITIONS). Source of
# truth is the AuditEntry ORM model in src/alfred/memory/models.py.
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
    # Spec B G6-7-4 (migration 0019) dispatched-edge dispatch-failure value.
    "dispatch_failed",
    # Spec B G6-7-5 (migration 0020) replay-bound-exhausted discriminator.
    "poisoned",
)


# Spec B G6-3 (#288) credential-grant result value.
_GRANTED_ADDITIONS: tuple[str, ...] = ("granted",)


def _result_in_clause(values: tuple[str, ...]) -> str:
    """Return the SQL fragment for ``result IN (..)`` with quoted values."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Extend ck_audit_log_result with the credential-grant granted value."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _GRANTED_ADDITIONS),
    )


def downgrade() -> None:
    """Revert CHECK to the 0020 domain, deleting granted rows loudly."""
    quoted_additions = ", ".join(f"'{v}'" for v in _GRANTED_ADDITIONS)
    downgrade_delete_sql = f"""
DO $$
DECLARE
  deleted_count integer;
BEGIN
  DELETE FROM audit_log WHERE result IN ({quoted_additions});
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE NOTICE
    'migration 0021 downgrade deleted % audit_log row(s) with the granted result value',
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
