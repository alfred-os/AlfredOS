"""Round-trip tests for migration 0009 — capability_gate_sync singleton.

Migration 0009 creates ``capability_gate_sync`` — a SINGLETON row holding
the state.git HEAD commit hash at the last time RealGate (PR-S3-2) rebuilt
``plugin_grants`` from state.git. RealGate compares this against the
current HEAD on startup; mismatch → rebuild (spec §8.1).

Pinned invariants:

* The table exists after upgrade-to-0009 with columns ``id`` /
  ``commit_hash`` / ``synced_at``.
* The column name is ``commit_hash`` (NOT ``state_git_commit_hash``) —
  mem-002: PR-S3-2 ``PostgresBackend`` SQL targets this exact name.
* The primary key is INTEGER with ``CHECK (id = 1)`` (singleton
  sentinel) — mem-004: UUID PKs would create a new row on every INSERT
  that omits ``id``, making the staleness check non-deterministic.
* Singleton upsert via ``ON CONFLICT (id) DO UPDATE`` leaves exactly one
  row after N inserts.
* Inserting any row with ``id != 1`` raises ``IntegrityError``.
* ``commit_hash`` may be NULL (pre-``alfred plugin grant init`` state,
  spec §15.4 step 2).
* Downgrade DROPs the table cleanly (re-derived from state.git on next
  startup per spec §13).
"""

from __future__ import annotations

import datetime as dt

import pytest
from alembic import command, config
from sqlalchemy import Engine, exc, inspect, text

pytestmark = pytest.mark.integration


@pytest.fixture
def alembic_cfg(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> config.Config:
    """Alembic Config pointed at the per-test container.

    Same wiring as the 0007/0008 round-trip tests — both env-var and
    Config sqlalchemy.url so the migration env covers either code path
    without surprise.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


def test_0009_upgrade_creates_capability_gate_sync(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """After upgrade to 0009, capability_gate_sync exists with the spec columns.

    mem-002 / mem-004 pinned: column is ``commit_hash`` (not
    ``state_git_commit_hash``); PK is INTEGER (not UUID).
    """
    command.upgrade(alembic_cfg, "0009")
    insp = inspect(postgres_engine)
    assert "capability_gate_sync" in insp.get_table_names()
    cols = {c["name"]: c for c in insp.get_columns("capability_gate_sync")}
    # mem-002: column is 'commit_hash', NOT 'state_git_commit_hash'.
    assert "commit_hash" in cols
    assert "state_git_commit_hash" not in cols
    assert set(cols.keys()) >= {"id", "commit_hash", "synced_at"}
    # mem-004: id is INTEGER (not UUID) so the singleton CHECK can pin id=1.
    id_type = str(cols["id"]["type"]).upper()
    assert "INT" in id_type, f"Expected INTEGER-shaped id column, got {id_type!r}"


def test_0009_capability_gate_sync_singleton_upsert(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """N upserts on id=1 leave exactly one row; commit_hash reflects the last write.

    mem-004: PR-S3-2 ``PostgresBackend.set_sync_hash`` uses
    ``INSERT (id, commit_hash) VALUES (1, :h) ON CONFLICT (id) DO UPDATE``.
    The singleton sentinel removes the need for application-level
    coordination — the DB itself guarantees one row.
    """
    command.upgrade(alembic_cfg, "0009")
    with postgres_engine.begin() as conn:
        # First upsert seeds the singleton row.
        conn.execute(
            text(
                "INSERT INTO capability_gate_sync "
                "(id, commit_hash, synced_at) "
                "VALUES (1, :hash, :ts) "
                "ON CONFLICT (id) DO UPDATE "
                "SET commit_hash = EXCLUDED.commit_hash, "
                "    synced_at = EXCLUDED.synced_at"
            ),
            {"hash": "abc123", "ts": dt.datetime.now(dt.UTC)},
        )
        # Second upsert updates the same row in place.
        conn.execute(
            text(
                "INSERT INTO capability_gate_sync "
                "(id, commit_hash, synced_at) "
                "VALUES (1, :hash, :ts) "
                "ON CONFLICT (id) DO UPDATE "
                "SET commit_hash = EXCLUDED.commit_hash, "
                "    synced_at = EXCLUDED.synced_at"
            ),
            {"hash": "def456", "ts": dt.datetime.now(dt.UTC)},
        )
        count = conn.execute(text("SELECT COUNT(*) FROM capability_gate_sync")).scalar()
        assert count == 1, f"Expected singleton row, got {count}"
        hash_val = conn.execute(text("SELECT commit_hash FROM capability_gate_sync")).scalar()
        assert hash_val == "def456"


def test_0009_capability_gate_sync_rejects_second_id(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """Inserting id != 1 raises IntegrityError.

    Closes the loophole where a future caller could insert id=2 and leave
    two rows in the singleton table. The CHECK (id = 1) constraint
    enforces the contract at the DB layer.
    """
    command.upgrade(alembic_cfg, "0009")
    with pytest.raises(exc.IntegrityError), postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO capability_gate_sync "
                "(id, commit_hash, synced_at) "
                "VALUES (2, :hash, :ts)"
            ),
            {"hash": "xyz", "ts": dt.datetime.now(dt.UTC)},
        )


def test_0009_capability_gate_sync_allows_null_commit_hash(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """commit_hash is nullable — pre-``alfred plugin grant init`` state.

    Per spec §15.4 step 2, the column is seeded NULL until the first
    state.git sync; the test pins that the column declaration permits it.
    """
    command.upgrade(alembic_cfg, "0009")
    with postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO capability_gate_sync "
                "(id, commit_hash, synced_at) "
                "VALUES (1, NULL, :ts)"
            ),
            {"ts": dt.datetime.now(dt.UTC)},
        )
        hash_val = conn.execute(text("SELECT commit_hash FROM capability_gate_sync")).scalar()
        assert hash_val is None


def test_0009_downgrade_drops_capability_gate_sync(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """Downgrade from 0009 drops capability_gate_sync (re-derived on startup)."""
    command.upgrade(alembic_cfg, "0009")
    insp = inspect(postgres_engine)
    assert "capability_gate_sync" in insp.get_table_names()

    command.downgrade(alembic_cfg, "0008")
    insp_after = inspect(postgres_engine)
    assert "capability_gate_sync" not in insp_after.get_table_names()
