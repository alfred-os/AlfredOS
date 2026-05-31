"""extend audit_log.result CHECK constraint with Slice-3 result values

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-31 00:00:00.000000

Slice 3 introduces five new emitter subsystems (``plugins/``,
``supervisor/``, ``security/``, ``orchestrator/``, ``identity/``) that write
audit rows with result values outside the Slice-2.5 domain. This migration
extends ``ck_audit_log_result`` to accept the 13 new values listed in spec
§13. It is strictly additive at upgrade time — no rows are modified.

New result values (spec §13 migration table):

* ``extracted`` — quarantine.extract: structured data extracted from a T3
  payload through the dual-LLM split.
* ``malformed_exhausted`` — quarantine.extract: retries exhausted on
  malformed quarantined-LLM output.
* ``load_refused`` — plugin.lifecycle: plugin load refused at handshake.
* ``crashed`` — plugin.lifecycle: subprocess exited unexpectedly.
* ``quarantined`` — plugin.lifecycle: circuit breaker tripped / protocol
  violation observed.
* ``reloaded`` — plugin.lifecycle: successful restart after crash.
* ``requested`` — plugin.grant: grant proposal submitted.
* ``approved`` — plugin.grant: grant proposal approved by operator.
* ``denied`` — plugin.grant: grant proposal denied.
* ``revoked`` — plugin.grant: grant revoked.
* ``tripped`` — supervisor.breaker: circuit breaker opened.
* ``reset`` — supervisor.breaker: breaker reset by operator.
* ``content_expired`` — web.fetch / quarantine.extract: ContentHandle TTL
  expired before pop.

Naming discipline: only the 13 values listed in spec §13 land here — not
a speculative ``accepted`` / ``degraded`` / etc. A future event whose
disposition does not fit either of the values above lands as its own
migration with its own justification (same load-bearing-seam discipline
as migration 0006).

Downgrade: revert CHECK to the 0006 domain. Rows whose ``result`` is in
the Slice-3-only set are deleted before the constraint is restored
(same loud-destruction pattern as 0005/0006 downgrades — operators who
care about the Slice-3 audit history snapshot the table BEFORE
downgrading).
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | Sequence[str] | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Alembic reads ``revision`` / ``down_revision`` / ``branch_labels`` /
# ``depends_on`` via module introspection (see ``alembic.script.revision``).
# Static analysers (CodeQL's py/unused-global-variable) can't see that
# reflective access — declaring them in ``__all__`` makes the contract
# with Alembic explicit and silences the false-positive alert. Same
# pattern as migrations 0004 / 0005 / 0006.
__all__ = [
    "branch_labels",
    "depends_on",
    "down_revision",
    "downgrade",
    "revision",
    "upgrade",
]


# 0006 base domain — Slice-1 + Slice-2 + Slice-2.5 values. Kept intact —
# this migration is strictly additive at upgrade time. If a future
# migration drops a value, it MUST be a separate revision with its own
# down-migration story for any rows referencing it.
_BASE_RESULTS: tuple[str, ...] = (
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
    # Slice-2.5 (0006) — hook-trace dispositions.
    "fault",
    "bypass",
)

# Slice-3 additions (spec §13). Ordering follows the spec migration table.
_SLICE_3_ADDITIONS: tuple[str, ...] = (
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


def _result_in_clause(values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"result IN ({quoted})"


def upgrade() -> None:
    """Replace ``ck_audit_log_result`` with the Slice-3 extended domain."""
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS + _SLICE_3_ADDITIONS),
    )


def downgrade() -> None:
    """Restore the 0006 narrow domain.

    Destructive: deletes any rows whose ``result`` is in the Slice-3-only
    set. There is no way to round-trip a Slice-3 row through the 0006
    CHECK; operators who care about Slice-3 audit history snapshot the
    table BEFORE downgrading. Same pattern as 0005's and 0006's
    downgrades.
    """
    # Values are module-level constants (never user-controlled), so the
    # f-string is safe. Ruff S608 flags string-formatted SQL by default;
    # the noqa documents the constant-controlled values — same pattern
    # as migration 0006.
    quoted_additions = ", ".join(f"'{v}'" for v in _SLICE_3_ADDITIONS)
    op.execute(f"DELETE FROM audit_log WHERE result IN ({quoted_additions})")  # noqa: S608
    op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
    op.create_check_constraint(
        "ck_audit_log_result",
        "audit_log",
        _result_in_clause(_BASE_RESULTS),
    )
