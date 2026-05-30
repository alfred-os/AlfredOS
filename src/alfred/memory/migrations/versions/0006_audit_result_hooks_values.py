"""extend audit_log.result enum for Slice-2.5 hook-trace dispositions

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-30 00:00:00.000000

Slice-2.5 PR-B Task 7 ships :class:`alfred.memory.hooks_audit_sink.EpisodicAuditSink`,
the adapter that maps PR-A's six ``HOOKS_*`` hook-trace event identifiers
onto :meth:`alfred.audit.log.AuditWriter.append`. The adapter's §0 result-
disposition table normalises those six events onto three distinct ``result``
values:

* ``"refused"`` — already in the 0005 domain (covers ``hooks.refusal`` and
  ``hooks.unauthorized_refusal``).
* ``"fault"`` — NEW. Used for ``hooks.chain_timeout``,
  ``hooks.subscriber_error``, and ``hooks.error_suppressed``: the three
  events that mark the chain entering a fault state the operator must see.
* ``"bypass"`` — NEW. Used for ``hooks.reentry_bypass``: the dispatcher
  detected hookpoint re-entry (sec-008) and skipped the inner chain on
  purpose. Operator-visible because a bypass means a subscriber's
  registered intent was NOT honoured.

Without this migration, four of six adapter emit paths would IntegrityError
on the 0005 CHECK constraint at first production write. PR-B's unit suite
mocks :meth:`AuditWriter.append` so the constraint is never exercised; the
PoC integration test that DOES exercise it (Task 8/9) catches a regression
on the same SHA.

Adding values is additive — no backfill needed. Downgrade reverts to the
0005 domain, which means any rows referencing ``"fault"`` / ``"bypass"``
would fail re-validation; the downgrade therefore drops them (same loud-
destruction pattern as 0005's downgrade — operators who care about the
hook-trace audit history snapshot the table BEFORE downgrading).

Naming discipline: only ``"fault"`` and ``"bypass"`` land here — not a
speculative ``"accepted"`` / ``"degraded"`` / etc. A future event whose
disposition does not fit either of these three values lands as its own
migration with its own justification (§0 result-disposition table is a
load-bearing seam, not a free-text column).
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: str | Sequence[str] | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Alembic reads ``revision`` / ``down_revision`` / ``branch_labels`` /
# ``depends_on`` via module introspection (see alembic.script.revision).
# Static analysers (CodeQL's py/unused-global-variable) can't see that
# reflective access — declaring them in ``__all__`` makes the contract
# with Alembic explicit and silences the false-positive alert. Same
# pattern as migrations 0004 / 0005.
__all__ = [
    "branch_labels",
    "depends_on",
    "down_revision",
    "downgrade",
    "revision",
    "upgrade",
]


# 0005 base values (Slice-1 + Slice-2). Kept intact — this migration is
# strictly additive at upgrade time.
_BASE_RESULTS = (
    # Slice-1 (0003).
    "success",
    "budget_blocked",
    "budget_overrun",
    "provider_failed",
    "cancelled",
    # Slice-2 (0005) — comms-adapter outcomes.
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
# Slice-2.5 (PR-B Task 7) additions — the two new dispositions
# :class:`EpisodicAuditSink` writes per its §0 result-disposition table.
_SLICE_2_5_ADDITIONS = (
    "fault",
    "bypass",
)


def _result_in_clause(values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Replace the audit_log.result CHECK with the Slice-2.5 extended domain."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _SLICE_2_5_ADDITIONS),
    )


def downgrade() -> None:
    """Restore the 0005 narrow domain.

    Destructive: deletes any rows whose ``result`` is in the
    Slice-2.5-only set (``"fault"`` / ``"bypass"``). There is no way to
    round-trip a hook-trace row through the 0005 CHECK; operators who
    care about hook-trace history should snapshot the table BEFORE
    downgrading. Same pattern as 0005's downgrade.
    """
    # The values are module-level constants (never user-controlled),
    # so the f-string is safe. Ruff S608 flags string-formatted SQL by
    # default; the noqa documents the constant-controlled values.
    quoted_additions = ", ".join(f"'{v}'" for v in _SLICE_2_5_ADDITIONS)
    op.execute(f"DELETE FROM audit_log WHERE result IN ({quoted_additions})")  # noqa: S608
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS),
    )
