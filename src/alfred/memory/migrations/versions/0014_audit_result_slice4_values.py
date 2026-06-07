"""extend audit_log.result CHECK constraint with Slice-4 result values

Revision ID: 0014
Revises: 0013
Create Date: 2026-06-07 00:00:00.000000

Slice 4 introduces new emit sites — DLP-into-failure_detail (PR-S4-2),
carrier substitution (PR-S4-3 / ADR-0022), policies hot-reload (PR-S4-4 /
ADR-0023), CLI operator session (PR-S4-5), sandbox launcher (PR-S4-6) —
each of which writes audit rows whose ``result`` discriminator is
outside the Slice-3 closed-vocab domain. This migration extends
``ck_audit_log_result`` to accept the 4 new values listed in spec §13
plus the round-2 closure-block recipes. It is strictly additive at
upgrade time — no rows are modified.

Slice-4 *_FIELDS constants (PR-S4-0a, see ``src/alfred/audit/audit_row_schemas.py``)
describe row-family field SHAPES, which the writers marshal into the
existing ``subject`` JSONB column. No new columns are added to
``audit_log``; this follows the established Slice-3 discipline
(migration 0007 extended only the closed-vocab CHECK).

New result values (spec §13 + round-2 closures):

* ``dispatched_with_redactions`` — PR-S4-2 round-2 closure 2: success
  path of ``_record_failure`` when ``dlp_redactions_count > 0``. Distinct
  from ``refused`` (which fires on DLP-block) so an audit-graph consumer
  can diff dispatch-with-redactions vs DLP-refusal at the result-vocab
  level alone.
* ``dispatched_clean`` — PR-S4-2 closure 2: success path when
  ``dlp_redactions_count == 0``.
* ``recursion_refused`` — PR-S4-3 carrier-substitution refusal:
  fires at both registration time and dispatch time when an
  ``error``-stage subscriber targets a meta-hookpoint whose
  ``allow_error_substitution=False`` (e.g. ``hooks.carrier_substituted``).
* ``audit_row_emitted`` — generic attestation result value used by
  the PR-S4-4 round-2 closure 7 audit-write-failure path (the policy-
  watcher emits ``CONFIG_RELOAD_REJECTED_FIELDS`` with
  ``reason="audit_write_failed"``; the result value attests that an
  audit row was recorded, not the specific failure mode). Used by
  Slice-4 adversarial corpus when the expected outcome is that a
  named audit-row schema fired. New values added later that fall
  under this shape join here rather than spawning per-event values.

Naming discipline: only the 4 values listed above land here. A future
event whose disposition does not fit gets its own migration with its
own justification — same load-bearing-seam discipline as migrations
0005 / 0006 / 0007.

Downgrade: revert CHECK to the 0007 (Slice-3) domain. Rows whose
``result`` is in the Slice-4-only set are deleted before the constraint
is restored (loud-destruction pattern from Slice-2.5 / Slice-3
downgrades — operators who care about Slice-4 audit history snapshot
the table BEFORE downgrading).
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0014"
down_revision: str | Sequence[str] | None = "0013"
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


# Slice-1 / Slice-2 / Slice-2.5 / Slice-3 closed-vocab baseline — must
# match the 0007 upgrade output exactly. Source of truth is the
# AuditEntry ORM model in src/alfred/memory/models.py (which always
# reflects the latest migration head).
_BASE_RESULTS: tuple[str, ...] = (
    # Slice-1 (migration 0003) base set.
    "success",
    "budget_blocked",
    "budget_overrun",
    "provider_failed",
    "cancelled",
    # Slice-2 (migration 0005) comms-adapter outcomes.
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
    # Slice-2.5 (migration 0006) hook-trace dispositions.
    "fault",
    "bypass",
    # Slice-3 (migration 0007).
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
)


# Slice-4 additions (spec §13 + round-2 closure recipes).
_SLICE_4_ADDITIONS: tuple[str, ...] = (
    "dispatched_with_redactions",
    "dispatched_clean",
    "recursion_refused",
    "audit_row_emitted",
)


def _result_in_clause(values: tuple[str, ...]) -> str:
    """Return the SQL fragment for ``result IN (..)`` with quoted values."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Extend ck_audit_log_result with Slice-4 closed-vocab values."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _SLICE_4_ADDITIONS),
    )


def downgrade() -> None:
    """Revert CHECK to the Slice-3 (migration 0007) domain.

    Rows whose ``result`` is in the Slice-4-only set are DELETED before
    the constraint is restored — same loud-destruction discipline as
    migrations 0005 / 0006 / 0007. Operators who care about Slice-4
    audit history MUST snapshot the table before downgrading.

    PR #210 sec + reviewer round-2 closure: a Postgres NOTICE is emitted
    naming the deleted-row count so an operator running ``alembic
    downgrade`` sees the destruction in their terminal output instead
    of having it happen silently. The notice cannot be suppressed by
    the alembic driver.
    """
    # SQL string values come from the _SLICE_4_ADDITIONS tuple literal at
    # module-load time — no user input crosses this boundary, so the
    # S608 string-based-query lint is a false positive here. The single
    # exemption on the literal below covers all interpolations.
    quoted_additions = ", ".join(f"'{v}'" for v in _SLICE_4_ADDITIONS)
    downgrade_delete_sql = f"""
DO $$
DECLARE
  deleted_count integer;
BEGIN
  DELETE FROM audit_log WHERE result IN ({quoted_additions});
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE NOTICE
    'migration 0014 downgrade deleted % audit_log row(s) with Slice-4 result values',
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
