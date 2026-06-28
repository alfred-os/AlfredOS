"""extend audit_log.result CHECK with egress-relay refusal result values

Revision ID: 0024
Revises: 0023
Create Date: 2026-06-28 00:00:00.000000

Spec C G7-2c-1 (#333). The in-core ``RelayEgressClient._audit_refused`` helper
writes a durable ``security.egress_relay_refused`` audit row on every refusal
path (deny / io-down / in-doubt). The ``result`` column carries a closed-vocab
token from the three refusal paths:

* ``"in_doubt"``            — intent committed but outcome unknown; non-idempotent
                              request refused (H3 policy, ``EgressInDoubtError``).
* ``"io_plane_unavailable"``— gateway relay unreachable, truncated frame, timeout,
                              or malformed reply (``IOPlaneUnavailableError``).
* ``"denied"``              — already in the domain since migration 0007 (the Slice-3
                              plugin-grant audit vocabulary). No new migration was
                              needed for ``"denied"`` itself; it is listed here for
                              documentation completeness.

Both new values are DYNAMIC at the ``_audit_refused`` call site
(``relay_client.py``) — the static guard in
``tests/unit/audit/test_audit_log_result_domain_closed.py`` cannot see them, so
they were MANUALLY AUDITED (G7-2c-1 C1 pass) and closed by this migration.

Strictly additive at upgrade time — no rows are modified, no new columns added.

Downgrade: revert CHECK to the migration-0023 domain. Rows whose ``result`` is in
the 0024-only set are DELETED before the constraint is restored (the
loud-destruction discipline carried from prior migrations).
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0024"
down_revision: str | Sequence[str] | None = "0023"
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


# Migration-0023 head domain — copied VERBATIM from 0022's _BASE_RESULTS +
# _GAP_ADDITIONS (0022 was the last to widen the domain; 0023 added no new
# result values). Source of truth is the AuditEntry ORM model CHECK.
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
    "dispatched_with_redactions",
    "dispatched_clean",
    "recursion_refused",
    "audit_row_emitted",
    "promoted",
    "binding_requested",
    "dropped",
    "capped",
    "allowed",
    "failed",
    "restart_requested",
    "cancelled_with_errors",
    "persistence_failed",
    "dispatch_failed",
    "poisoned",
    "granted",
    "transport_failed",
    "protocol_violation",
    "post_stage_refused",
    "dlp_scan_error",
    "domain_not_allowed",
    "internal_ip_refused",
    "transport_error",
    "handle_id_mismatch",
    "dispatch_param_invalid",
    "dispatch_shape_error",
    "ok",
    "rolled_back",
    "drift_detected",
    "modified",
)


# Spec C G7-2c-1 (#333) — the two new egress-relay refusal result values.
# ``"denied"`` is already in _BASE_RESULTS (migration 0007); not repeated here.
_EGRESS_RELAY_REFUSED_ADDITIONS: tuple[str, ...] = (
    # RelayEgressClient._audit_refused: in-doubt + non-idempotent path (H3).
    "in_doubt",
    # RelayEgressClient._audit_refused: gateway unreachable / truncated / timeout.
    "io_plane_unavailable",
)


def _result_in_clause(values: tuple[str, ...]) -> str:
    """Return the SQL fragment for ``result IN (..)`` with quoted values."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Extend ck_audit_log_result with the two egress-relay refusal result values."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _EGRESS_RELAY_REFUSED_ADDITIONS),
    )


def downgrade() -> None:
    """Revert CHECK to the 0023 domain, deleting the 0024-only rows loudly."""
    quoted_additions = ", ".join(f"'{v}'" for v in _EGRESS_RELAY_REFUSED_ADDITIONS)
    downgrade_delete_sql = f"""
DO $$
DECLARE
  deleted_count integer;
BEGIN
  DELETE FROM audit_log WHERE result IN ({quoted_additions});
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE NOTICE
    'migration 0024 downgrade deleted % audit_log row(s) with a 0024-only result value',
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
