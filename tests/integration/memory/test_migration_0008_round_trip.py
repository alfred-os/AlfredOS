"""Round-trip tests for migration 0008 — plugin_grants Postgres projection.

Migration 0008 creates ``plugin_grants``, the Postgres runtime cache for
the state.git capability grant tree (spec §8.1, §13). RealGate (PR-S3-2)
reads from this table for millisecond-latency hot-path capability checks;
the table is rebuilt from state.git when the commit hash stored in
``capability_gate_sync`` (migration 0009) differs from the current HEAD.

Pinned invariants:

* The table exists after upgrade-to-0008 and contains the columns spec
  §13 documents (``id``, ``created_at``, ``plugin_id``, ``subscriber_tier``,
  ``hookpoint``, ``content_tier``, ``operator_user_id``,
  ``proposal_branch``, ``correlation_id``, ``state``,
  ``state_git_commit_hash``).
* The UNIQUE constraint on ``(plugin_id, hookpoint, subscriber_tier)``
  matches the PR-S3-2 ``PostgresBackend.upsert_grant`` ON CONFLICT target —
  without this, every upsert ``InvalidColumnReference``s.
* ``state`` is the closed domain
  ``{'requested', 'approved', 'denied', 'revoked'}``.
* ``subscriber_tier`` is the closed domain
  ``{'system', 'operator', 'user-plugin'}``.
* ``content_tier`` is either NULL or one of ``T0/T1/T2/T3`` (spec §4.3
  two-axis naming rule — subscriber_tier is the hook-subscription axis,
  content_tier is the trust-tier axis).
* Downgrade DROPs the table cleanly (table is fully rebuildable from
  state.git per spec §13).
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from alembic import command, config
from sqlalchemy import Engine, exc, inspect, text

pytestmark = pytest.mark.integration


@pytest.fixture
def alembic_cfg(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> config.Config:
    """Alembic Config pointed at the per-test container.

    Same wiring as ``test_migration_0007_round_trip.py`` — both env-var
    and Config sqlalchemy.url so the migration env covers either code
    path without surprise.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


def _insert_grant(
    engine: Engine,
    *,
    plugin_id: str,
    subscriber_tier: str = "system",
    hookpoint: str = "security.quarantined.extract",
    content_tier: str | None = "T3",
    state: str = "approved",
    correlation_id: str | None = None,
    operator_user_id: str = "operator-001",
    proposal_branch: str = "proposal/policy-grant-test",
    commit_hash: str = "abc123def456",
) -> None:
    """Insert one plugin_grants row at the current schema."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO plugin_grants "
                "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                " content_tier, operator_user_id, proposal_branch, "
                " correlation_id, state, state_git_commit_hash) "
                "VALUES (:id, :ts, :pid, :stier, :hp, :ctier, :uid, :branch, "
                "        :cid, :state, :hash)"
            ),
            {
                "id": str(uuid.uuid4()),
                "ts": dt.datetime.now(dt.UTC),
                "pid": plugin_id,
                "stier": subscriber_tier,
                "hp": hookpoint,
                "ctier": content_tier,
                "uid": operator_user_id,
                "branch": proposal_branch,
                "cid": correlation_id or str(uuid.uuid4()),
                "state": state,
                "hash": commit_hash,
            },
        )


def test_0008_upgrade_creates_plugin_grants_table(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """After upgrade to 0008, plugin_grants exists with the spec §13 columns."""
    command.upgrade(alembic_cfg, "0008")
    insp = inspect(postgres_engine)
    assert "plugin_grants" in insp.get_table_names()
    cols = {c["name"] for c in insp.get_columns("plugin_grants")}
    assert cols >= {
        "id",
        "created_at",
        "plugin_id",
        "subscriber_tier",
        "hookpoint",
        "content_tier",
        "operator_user_id",
        "proposal_branch",
        "correlation_id",
        "state",
        "state_git_commit_hash",
    }
    # mem-003: PR-S3-2 PostgresBackend.upsert_grant relies on a UNIQUE on
    # (plugin_id, hookpoint, subscriber_tier) as its ON CONFLICT target.
    # Missing constraint → every upsert InvalidColumnReferences.
    unique_constraints = {uc["name"] for uc in insp.get_unique_constraints("plugin_grants")}
    assert "uq_plugin_grants_plugin_hook_tier" in unique_constraints


def test_0008_plugin_grants_accepts_valid_row(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """plugin_grants accepts a row with all required fields, content_tier set."""
    command.upgrade(alembic_cfg, "0008")
    _insert_grant(
        postgres_engine,
        plugin_id="alfred.quarantined-llm",
        subscriber_tier="system",
        hookpoint="security.quarantined.extract",
        content_tier="T3",
        state="approved",
    )


def test_0008_plugin_grants_accepts_null_content_tier(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """plugin_grants accepts a row with NULL content_tier (no restriction)."""
    command.upgrade(alembic_cfg, "0008")
    _insert_grant(
        postgres_engine,
        plugin_id="alfred.web-fetch",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        state="approved",
    )


def test_0008_plugin_grants_rejects_invalid_state(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """plugin_grants rejects an unrecognised state value (closed-domain CHECK)."""
    command.upgrade(alembic_cfg, "0008")
    with pytest.raises(exc.IntegrityError):
        _insert_grant(
            postgres_engine,
            plugin_id="alfred.quarantined-llm",
            state="totally_made_up",
        )


def test_0008_plugin_grants_rejects_invalid_subscriber_tier(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """plugin_grants rejects a subscriber_tier outside the spec §4.3 domain."""
    command.upgrade(alembic_cfg, "0008")
    with pytest.raises(exc.IntegrityError):
        _insert_grant(
            postgres_engine,
            plugin_id="alfred.quarantined-llm",
            subscriber_tier="god-mode",
        )


def test_0008_plugin_grants_rejects_invalid_content_tier(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """plugin_grants rejects a content_tier outside ``T0`` / ``T1`` / ``T2`` / ``T3``."""
    command.upgrade(alembic_cfg, "0008")
    with pytest.raises(exc.IntegrityError):
        _insert_grant(
            postgres_engine,
            plugin_id="alfred.quarantined-llm",
            content_tier="T99",
        )


def test_0008_plugin_grants_upsert_on_conflict_target(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """Upsert on (plugin_id, hookpoint, subscriber_tier) leaves exactly one row.

    Verifies the ON CONFLICT target used by PR-S3-2's
    ``PostgresBackend.upsert_grant``. Without the UNIQUE constraint, every
    upsert raises ``InvalidColumnReference``. The test pins the production
    SQL shape so a future refactor cannot quietly drop the constraint.
    """
    command.upgrade(alembic_cfg, "0008")
    plugin_id = "alfred.test-upsert"
    hookpoint = "test.upsert.hook"
    tier = "operator"
    row_base = {
        "ts": dt.datetime.now(dt.UTC),
        "pid": plugin_id,
        "tier": tier,
        "hp": hookpoint,
        "uid": "operator-001",
        "branch": "proposal/upsert-test",
        "hash": "abc123",
    }
    with postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO plugin_grants "
                "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                " content_tier, operator_user_id, proposal_branch, "
                " correlation_id, state, state_git_commit_hash) "
                "VALUES (gen_random_uuid(), :ts, :pid, :tier, :hp, NULL, :uid, "
                "        :branch, gen_random_uuid()::text, 'requested', :hash)"
            ),
            row_base,
        )
        # Same triple, different state — must upsert in place, not insert.
        conn.execute(
            text(
                "INSERT INTO plugin_grants "
                "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                " content_tier, operator_user_id, proposal_branch, "
                " correlation_id, state, state_git_commit_hash) "
                "VALUES (gen_random_uuid(), :ts, :pid, :tier, :hp, NULL, :uid, "
                "        :branch, gen_random_uuid()::text, 'approved', :hash) "
                "ON CONFLICT (plugin_id, hookpoint, subscriber_tier) "
                "DO UPDATE SET state = EXCLUDED.state"
            ),
            row_base,
        )
        count = conn.execute(
            text(
                "SELECT COUNT(*) FROM plugin_grants "
                "WHERE plugin_id = :pid AND hookpoint = :hp "
                "AND subscriber_tier = :tier"
            ),
            {"pid": plugin_id, "hp": hookpoint, "tier": tier},
        ).scalar()
        assert count == 1, f"Expected one row after upsert, got {count}"
        final_state = conn.execute(
            text(
                "SELECT state FROM plugin_grants "
                "WHERE plugin_id = :pid AND hookpoint = :hp "
                "AND subscriber_tier = :tier"
            ),
            {"pid": plugin_id, "hp": hookpoint, "tier": tier},
        ).scalar()
        assert final_state == "approved"


def test_0008_downgrade_drops_plugin_grants(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """Downgrade from 0008 drops plugin_grants (rebuildable from state.git)."""
    command.upgrade(alembic_cfg, "0008")
    insp = inspect(postgres_engine)
    assert "plugin_grants" in insp.get_table_names()

    command.downgrade(alembic_cfg, "0007")
    insp_after = inspect(postgres_engine)
    assert "plugin_grants" not in insp_after.get_table_names()
