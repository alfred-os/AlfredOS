"""sandbox_policy_registry — launcher policy-resolution observability
(Slice-4 PR-S4-6 / ADR-0015).

Revision ID: 0015
Revises: 0014
Create Date: 2026-06-07 00:00:00.000000

See ADR-0015 (containerised quarantined-LLM) and
``docs/superpowers/plans/2026-06-07-slice-4-pr-s4-0b-migrations-infra-i18n.md``
§D for the contract this migration realises.

``sandbox_policy_registry`` records the most recent
``bin/alfred-plugin-launcher.sh`` policy-resolution result per
``(plugin_id, host_os)``. Read-only observability — the launcher does
NOT consult this table at spawn time (the live policy is in the
plugin's manifest + the policy file on disk). Operators query it to
confirm every plugin's expected policy matches the resolved one
across OSes.

Columns
-------

* ``plugin_id`` — matches the plugin's manifest ``[plugin] id`` (the
  Slice-3 ``PluginGrant.plugin_id`` shape from migration 0008 — String(128)). Part of the
  composite PK.
* ``policy_ref`` — relative path to the policy file under
  ``config/sandbox/`` or ``~/.config/alfred/sandbox/`` (e.g.
  ``quarantined-llm.linux.bwrap``). Max 255 chars (filesystem MAX_PATH
  ceiling).
* ``host_os`` — closed-domain Literal ``{linux, macos, windows}``.
  Part of the composite PK. CHECK pins the closed vocab.
* ``last_resolved_at`` — timestamptz of the most-recent resolution.
  Updated by the launcher every time it resolves a policy for this
  ``(plugin, OS)``; older rows are not preserved (this table is the
  "latest state" snapshot, not a history log).
* ``resolution_result`` — closed-domain Literal covering every
  launcher outcome from spec §7.2 plus the stub-used escape hatch.
  CHECK pins the closed vocab.

Indexes
-------

* PRIMARY KEY on ``(plugin_id, host_os)`` named
  ``uq_sandbox_policy_registry_plugin_host_os`` — composite uniqueness
  enforces "one row per plugin per OS" and gives the launcher its
  natural UPSERT key.

Constraints
-----------

* ``ck_sandbox_policy_registry_host_os`` — closed vocab
  ``{linux, macos, windows}``.
* ``ck_sandbox_policy_registry_resolution_result`` — closed vocab
  covering all spec §7.2 launcher outcomes.

Downgrade
---------

DROP TABLE. Observability only; no operational state. Symmetric
fail-soft via ``op.execute("DROP TABLE IF EXISTS ...")`` so a retried
rollback after a transient ops error completes cleanly. A NOTICE is
emitted with the dropped-row count so operators see the destruction
in their terminal output rather than having it happen silently
(PR #210 sec-corroborated discipline).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | Sequence[str] | None = "0014"
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


_HOST_OS_VALUES: tuple[str, ...] = ("linux", "macos", "windows")

_RESOLUTION_RESULT_VALUES: tuple[str, ...] = (
    "resolved",
    "refused_policy_missing",
    "refused_unreadable",
    "refused_os_mismatch",
    "stub_used",
)


def _in_clause(column: str, values: tuple[str, ...]) -> str:
    """Return the SQL fragment ``<column> IN (..)`` with quoted values."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    """Create sandbox_policy_registry table + composite PK + CHECK constraints."""
    op.create_table(
        "sandbox_policy_registry",
        sa.Column("plugin_id", sa.String(128), nullable=False),
        sa.Column("host_os", sa.String(16), nullable=False),
        sa.Column("policy_ref", sa.String(255), nullable=False),
        sa.Column("last_resolved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolution_result", sa.String(32), nullable=False),
        sa.PrimaryKeyConstraint(
            "plugin_id",
            "host_os",
            name="uq_sandbox_policy_registry_plugin_host_os",
        ),
        sa.CheckConstraint(
            _in_clause("host_os", _HOST_OS_VALUES),
            name="ck_sandbox_policy_registry_host_os",
        ),
        sa.CheckConstraint(
            _in_clause("resolution_result", _RESOLUTION_RESULT_VALUES),
            name="ck_sandbox_policy_registry_resolution_result",
        ),
        # PR #211 sec/mem closure: pin plugin_id to the snake_case
        # closed shape used by ``PluginGrant.plugin_id`` so a typo'd
        # / upper-cased writer-side id cannot silently shard the
        # composite PK ("one row per plugin per OS").
        sa.CheckConstraint(
            "plugin_id ~ '^[a-z0-9_]{1,128}$'",
            name="ck_sandbox_policy_registry_plugin_id_format",
        ),
        # PR #211 sec closure: policy_ref MUST be a relative path under
        # the operator sandbox-policy directory. Refuse absolute paths
        # and parent-directory escapes. Per ADR-0015 the resolver
        # canonicalises this against the launcher root at runtime; this
        # CHECK is the DB-layer defence-in-depth.
        sa.CheckConstraint(
            "policy_ref NOT LIKE '/%' AND policy_ref NOT LIKE '%..%'",
            name="ck_sandbox_policy_registry_policy_ref_relative",
        ),
    )


def downgrade() -> None:
    """Drop sandbox_policy_registry; observability lost on revert.

    Symmetric fail-soft via ``DROP TABLE IF EXISTS``. A Postgres NOTICE
    is emitted with the dropped-row count so operators see the
    destruction in their terminal output rather than having it happen
    silently (PR #210 sec-corroborated discipline).
    """
    drop_sql = """
DO $$
DECLARE
  row_count integer;
BEGIN
  IF to_regclass('public.sandbox_policy_registry') IS NULL THEN
    RAISE NOTICE
      'migration 0015 downgrade — sandbox_policy_registry already absent, no-op';
  ELSE
    SELECT COUNT(*) INTO row_count FROM sandbox_policy_registry;
    RAISE NOTICE
      'migration 0015 downgrade dropping sandbox_policy_registry with % row(s)',
      row_count;
    DROP TABLE sandbox_policy_registry;
  END IF;
END $$;
"""
    op.execute(drop_sql)
