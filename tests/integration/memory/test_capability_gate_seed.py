"""Integration test: capability_gate_sync seeding on a fresh database.

Asserts that after migrations 0007-0009 are applied to a fresh DB (i.e.
``alembic upgrade head``), ``capability_gate_sync`` exists and can accept
the initial seed row that ``alfred plugin grant init`` writes per spec
§15.4 step 2.

This complements the migration-0009 round-trip test by exercising the
upgrade-to-HEAD path (not just upgrade-to-0009), which is the path
``bin/alfred-setup.sh`` and the docker-compose bootstrap take. If a
future revision lands between 0009 and HEAD that breaks the singleton-
row contract, this test catches it.

Invariants pinned:

* ``capability_gate_sync`` table is present after ``alembic upgrade head``.
* The initial seed row with the empty-commit sentinel
  (``"0000000000000000000000000000000000000000"``) is accepted (spec
  §15.4 step 2).
* NULL ``commit_hash`` is accepted (pre-init state).
* mem-002: column is ``commit_hash`` (NOT ``state_git_commit_hash``).
* mem-004: ``id`` is INTEGER ``1`` (singleton sentinel), not UUID.
"""

from __future__ import annotations

import datetime as dt

import pytest
from alembic import command, config
from sqlalchemy import Engine, inspect, text

pytestmark = pytest.mark.integration

# The empty-commit-tree hash a fresh state.git seeds with — spec §15.4 step 2.
# It is the SHA-1 of an empty Git object directory; used as a sentinel so the
# staleness check has a stable "never synced" value rather than NULL during the
# brief window after init but before first sync.
_EMPTY_TREE_HASH = "0" * 40


@pytest.fixture
def alembic_cfg(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> config.Config:
    """Alembic Config pointed at the per-test container — shaped like the others."""
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


def test_capability_gate_sync_table_present_after_head(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """After ``alembic upgrade head``, ``capability_gate_sync`` exists.

    Catches a future revision that breaks the table's existence — e.g. a
    schema cleanup that DROPs it without re-creation. The migration chain
    is contiguous so HEAD lands at 0009 today, but the test stays
    head-relative deliberately: any future revision must keep the table.
    """
    command.upgrade(alembic_cfg, "head")
    insp = inspect(postgres_engine)
    assert "capability_gate_sync" in insp.get_table_names()


def test_capability_gate_sync_seed_row_written_at_head(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """A seed row (the ``alfred plugin grant init`` write) is accepted at HEAD.

    mem-002: column is ``commit_hash``; mem-004: ``id`` must be ``1``.
    """
    command.upgrade(alembic_cfg, "head")
    with postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO capability_gate_sync "
                "(id, commit_hash, synced_at) "
                "VALUES (1, :hash, :ts) "
                "ON CONFLICT (id) DO UPDATE "
                "SET commit_hash = EXCLUDED.commit_hash, "
                "    synced_at = EXCLUDED.synced_at"
            ),
            {"hash": _EMPTY_TREE_HASH, "ts": dt.datetime.now(dt.UTC)},
        )
        hash_val = conn.execute(text("SELECT commit_hash FROM capability_gate_sync")).scalar()
        assert hash_val == _EMPTY_TREE_HASH


def test_capability_gate_sync_allows_null_hash_at_head(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """NULL ``commit_hash`` is accepted (pre-init state)."""
    command.upgrade(alembic_cfg, "head")
    with postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO capability_gate_sync "
                "(id, commit_hash, synced_at) "
                "VALUES (1, NULL, :ts) "
                "ON CONFLICT (id) DO UPDATE "
                "SET commit_hash = NULL, "
                "    synced_at = EXCLUDED.synced_at"
            ),
            {"ts": dt.datetime.now(dt.UTC)},
        )
        hash_val = conn.execute(text("SELECT commit_hash FROM capability_gate_sync")).scalar()
        assert hash_val is None
