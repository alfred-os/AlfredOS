"""extend audit_log.result CHECK with the 14 latent-gap result values

Revision ID: 0022
Revises: 0021
Create Date: 2026-06-24 00:00:00.000000

Issue #252 / #320. The ``audit_log.result`` column is a CLOSED CHECK domain
(``ck_audit_log_result``). Over Slices 3-4 and the gateway program, several
audit writers shipped a NEW ``result`` literal WITHOUT a migration adding that
value to the CHECK. Each is the SAME bug class as the #309/G6-3 ``'granted'``
gap that migration 0021 closed: the writer's unit + adversarial tests use an
append-only ``audit`` double that never enforces the constraint, so a real row
carrying the value would crash with a Postgres ``CheckViolation`` — but only
against real Postgres, which those writers' tests never exercise.

The #320 static guard
(``tests/unit/audit/test_audit_log_result_domain_closed.py``) AST-walks every
literal ``result=`` value written at both audit_log write paths
(``AuditWriter.append`` / ``.append_schema`` call sites AND direct
``AuditEntry(...)`` construction) and asserts each is a member of this CHECK. It
surfaced 13 genuinely-missing LITERAL values; an adversarial security review
added a 14th (``post_stage_refused``) reached via a DYNAMIC helper-param flow the
static guard cannot see. All 14 are confirmed to target the ``audit_log.result``
column via the real ``AuditWriter`` — NOT a conflated look-alike column such as
``dlp_scan_result`` / ``trust_tier_of_result`` / ``hook_result``:

* ``transport_failed``     — #252; quarantine.py ``quarantine.transport_failed``
                             (the issue that triggered this PR).
* ``protocol_violation``   — #134/#158; quarantine.py ``quarantine.protocol_violation``
                             (the sibling the transport_failed docstring names).
* ``post_stage_refused``   — C1 (adversarial review); quarantine.py post-stage
                             T3 canary/DLP refusal (``_emit_extract_audit`` param,
                             DYNAMIC — invisible to the static guard).
* ``dlp_scan_error``       — #134; web_fetch ``tool.web.fetch`` (DLP scanner outage).
* ``domain_not_allowed``   — #134; web_fetch ``tool.web.fetch`` (allowlist refusal).
* ``internal_ip_refused``  — #134; web_fetch ``tool.web.fetch`` (SSRF host-IP guard).
* ``transport_error``      — #157; web_fetch ``tool.web.fetch`` (fetch transport crash).
* ``handle_id_mismatch``   — #157; web_fetch ``tool.web.fetch`` (handle-id equality guard).
* ``dispatch_param_invalid`` — #147; web_fetch ``tool.web.fetch`` (Pydantic param refusal).
* ``dispatch_shape_error`` — #147; web_fetch ``tool.web.fetch`` (dispatch-shape refusal).
* ``ok``                   — #157; web_fetch ``tool.web.fetch`` (success row).
* ``rolled_back``          — capability-gate ``plugin.grant.rebuilt`` (grant-projection rebuild).
* ``drift_detected``       — comms ``comms.addressing.drift`` (addressing-drift detector).
* ``modified``             — CLI DLP outbound audit sink (outbound content modified).

Strictly additive at upgrade time — no rows are modified, no new columns added.

Downgrade: revert CHECK to the migration-0021 domain. Rows whose ``result`` is in
the 0022-only set are DELETED before the constraint is restored (the
loud-destruction discipline carried from migrations
0005/0006/0007/0014/0016/0017/0019/0020/0021 — a Postgres NOTICE names the
deleted-row count so an operator sees the destruction). Source of truth: every
value here MUST also be in the ``ck_audit_log_result`` CheckConstraint of the
``AuditEntry`` ORM model in ``src/alfred/memory/models.py``; CI's
migration-roundtrip test catches drift, and the #320 static guard fails fast if a
writer adds a value neither here nor in the model CHECK.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0022"
down_revision: str | Sequence[str] | None = "0021"
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


# Migration-0021 head domain — copied VERBATIM from 0021's full upgrade output
# (its _BASE_RESULTS + _GRANTED_ADDITIONS). Source of truth is the AuditEntry ORM
# model in src/alfred/memory/models.py.
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
    # Spec B G6-3 (migration 0021, #288) credential-grant result value.
    "granted",
)


# Issue #252 / #320 — the 14 latent-gap result values: 13 the static guard
# surfaced as literals + ``post_stage_refused`` (C1, adversarial review) reached
# via a dynamic helper-param flow. Each targets the ``audit_log.result`` column
# via the real ``AuditWriter``; see the module docstring for the per-value emit
# site + provenance. Order groups by subsystem (quarantine, web_fetch,
# capability-gate / comms / CLI-DLP).
_GAP_ADDITIONS: tuple[str, ...] = (
    # Quarantine extractor (security/quarantine.py).
    "transport_failed",  # #252 — the triggering issue.
    "protocol_violation",  # #134/#158 — the transport_failed sibling.
    "post_stage_refused",  # C1 (adversarial review) — T3 post-stage
    # canary/DLP-refusal row; DYNAMIC at the emit site (flows through the
    # _emit_extract_audit ``audit_result`` param, quarantine.py:807→1261), so the
    # static guard cannot see it. Manually audited + closed here.
    # web.fetch tool dispatcher (plugins/web_fetch/fetch_dispatcher.py).
    "dlp_scan_error",  # #134
    "domain_not_allowed",  # #134
    "internal_ip_refused",  # #134
    "transport_error",  # #157
    "handle_id_mismatch",  # #157
    "dispatch_param_invalid",  # #147
    "dispatch_shape_error",  # #147
    "ok",  # #157 — web.fetch success row.
    # Capability-gate grant-projection rebuild (security/capability_gate/_gate.py).
    "rolled_back",
    # Comms addressing-drift detector (comms_mcp/addressing_drift.py).
    "drift_detected",
    # CLI outbound DLP audit sink (cli/_bootstrap.py).
    "modified",
)


def _result_in_clause(values: tuple[str, ...]) -> str:
    """Return the SQL fragment for ``result IN (..)`` with quoted values."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Extend ck_audit_log_result with the 14 latent-gap result values."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _GAP_ADDITIONS),
    )


def downgrade() -> None:
    """Revert CHECK to the 0021 domain, deleting the 0022-only rows loudly."""
    quoted_additions = ", ".join(f"'{v}'" for v in _GAP_ADDITIONS)
    downgrade_delete_sql = f"""
DO $$
DECLARE
  deleted_count integer;
BEGIN
  DELETE FROM audit_log WHERE result IN ({quoted_additions});
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE NOTICE
    'migration 0022 downgrade deleted % audit_log row(s) with a 0022-only result value',
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
