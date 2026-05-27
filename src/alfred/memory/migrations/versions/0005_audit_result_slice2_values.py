"""extend audit_log.result enum for Slice-2 comms-adapter results

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-27 00:00:00.000000

PR D2 (Discord adapter) writes audit rows with ``result`` values the
Slice-1 CHECK constraint refuses: ``refused`` (allowlist + read_only +
rate-limited refusals), ``refused_unknown_user`` (unknown-DM branch),
``rate_limited`` (non-read_only token-bucket refusal), ``dlp_failed`` /
``split_failed`` / ``send_failed`` (the three err-003 outbound branches),
``recovery_send_failed`` (recursion-guarded recovery message branch),
``login_failed`` and ``gateway_unhealthy`` (the reconnect classification
table's exit-code branches), and ``unknown_budget_user`` (PR B's 7th
audit branch that already exists but was never added to the CHECK).

This migration replaces the Slice-1 CHECK constraint with an extended
domain that admits every value Slice-2 writes. We do NOT drop the
column or rebuild the table — Alembic's
``op.create_check_constraint`` / ``op.drop_constraint`` pair swaps the
constraint in place without rewriting rows.

Adding values is additive — no backfill needed. Downgrade reverts to
the Slice-1 domain, which means any Slice-2-written row referencing
the new values would fail re-validation. The downgrade therefore drops
all rows whose ``result`` is in the new set; this is destructive but
the only way to get back to the narrow Slice-1 domain. Operators are
warned in the docstring.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Alembic reads ``revision`` / ``down_revision`` / ``branch_labels`` /
# ``depends_on`` via module introspection (see alembic.script.revision).
# Static analysers (CodeQL's py/unused-global-variable) can't see that
# reflective access — declaring them in ``__all__`` makes the contract
# with Alembic explicit and silences the false-positive alert. Same
# pattern as migration 0004.
__all__ = [
    "branch_labels",
    "depends_on",
    "down_revision",
    "downgrade",
    "revision",
    "upgrade",
]


# Slice-1 base values (from 0003) — kept intact.
_SLICE_1_RESULTS = (
    "success",
    "budget_blocked",
    "budget_overrun",
    "provider_failed",
    "cancelled",
)
# PR D2 + PR B additions. ``unknown_budget_user`` is PR B's 7th branch;
# the rest are PR D2 comms-adapter outcomes.
_SLICE_2_ADDITIONS = (
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
)


def _result_in_clause(values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Replace the audit_log.result CHECK with the Slice-2 extended domain."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_SLICE_1_RESULTS + _SLICE_2_ADDITIONS),
    )


def downgrade() -> None:
    """Restore the Slice-1 narrow domain.

    Destructive: deletes any rows whose ``result`` is in the
    Slice-2-only set. There is no way to round-trip Slice-2 rows
    through the Slice-1 CHECK; operators who care about the audit
    history should snapshot the table BEFORE downgrading.
    """
    # The values are module-level constants (never user-controlled),
    # so the f-string is safe. Ruff S608 flags string-formatted SQL by
    # default; the noqa documents the constant-controlled values.
    quoted_additions = ", ".join(f"'{v}'" for v in _SLICE_2_ADDITIONS)
    op.execute(f"DELETE FROM audit_log WHERE result IN ({quoted_additions})")  # noqa: S608
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_SLICE_1_RESULTS),
    )
