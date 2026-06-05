"""Round-trip tests for migration 0011 — processed_proposals ledger + sentinel.

ADR-0021 — the dispatcher's at-most-once guarantee is built on
``processed_proposals`` (composite-PK ledger) + ``processed_proposals_head``
(single-row sentinel). The migration MUST:

* Create both tables with the spec column shapes.
* Pin the closed-vocab ``result`` domain via CHECK.
* Pin the sentinel-singleton invariant via CHECK on ``id = 1``.
* Seed the sentinel row with ``head_sha = NULL`` so the first dispatch
  cycle bootstraps from ``git rev-parse origin/main`` (forward-from-now
  semantics — rejected alternative A6 of subprocess-at-migration-time).
* Downgrade cleanly (transient state, re-discovered next run).

Pinning these at the DB layer means a regression on either side (model
shape or migration) surfaces here, not at production-startup time when
the dispatch loop's first INSERT raises a constraint violation.
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

    Same wiring as the sibling migration round-trips — both env-var and
    Config sqlalchemy.url so the migration env covers either code path
    without surprise.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


def test_0011_upgrade_creates_processed_proposals(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """After upgrade to 0011, both tables exist with the spec columns.

    Pins the column surface against ``ProcessedProposal`` /
    ``ProcessedProposalsHead`` in :mod:`alfred.memory.models`.
    """
    command.upgrade(alembic_cfg, "0011")
    insp = inspect(postgres_engine)
    assert "processed_proposals" in insp.get_table_names()
    assert "processed_proposals_head" in insp.get_table_names()
    cols = {c["name"]: c for c in insp.get_columns("processed_proposals")}
    assert set(cols.keys()) == {
        "proposal_type",
        "proposal_id",
        "blob_sha",
        "commit_sha",
        "processed_at",
        "result",
        "handler_version",
        "failure_kind",
        "failure_detail",
        "operator_user_id",
    }
    pk = insp.get_pk_constraint("processed_proposals")
    assert set(pk["constrained_columns"]) == {"proposal_type", "proposal_id"}


def test_0011_seeds_sentinel_row_with_null_head_sha(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """The migration inserts the sentinel row with head_sha = NULL.

    Rejected alternative A6 in ADR-0021 — subprocess-at-migration-time
    was rejected because /var/lib/alfred/state.git does not exist at
    fresh-install migration time. The first dispatch cycle detects NULL
    and bootstraps from ``git rev-parse origin/main``; the migration's
    job is just to seed the row, NOT to populate head_sha.
    """
    command.upgrade(alembic_cfg, "0011")
    with postgres_engine.begin() as conn:
        rows = conn.execute(text("SELECT id, head_sha FROM processed_proposals_head")).all()
    assert len(rows) == 1
    assert rows[0].id == 1
    assert rows[0].head_sha is None


def test_0011_sentinel_singleton_check_rejects_second_row(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """ck_processed_proposals_head_singleton pins id = 1; row 2 fails."""
    command.upgrade(alembic_cfg, "0011")
    with pytest.raises(exc.IntegrityError), postgres_engine.begin() as conn:
        conn.execute(text("INSERT INTO processed_proposals_head (id, head_sha) VALUES (2, NULL)"))


def test_0011_result_check_constraint_rejects_invalid_value(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """result column rejects values outside the closed vocab.

    Five values per ADR-0021: applied, failed_handler, failed_parse,
    failed_unknown_type, skipped_already_processed. A future widening
    lands by extending the CHECK + the migration that adds the value.
    """
    command.upgrade(alembic_cfg, "0011")
    with pytest.raises(exc.IntegrityError), postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO processed_proposals "
                "(proposal_type, proposal_id, blob_sha, commit_sha, result) "
                "VALUES (:pt, :pid, :bs, :cs, :r)"
            ),
            {
                "pt": "breaker-reset",
                "pid": "abc",
                "bs": "a" * 40,
                "cs": "b" * 40,
                "r": "totally-bogus",
            },
        )


def test_0011_result_failure_kind_consistency_rejects_applied_with_failure_kind(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """``applied`` rows MUST leave ``failure_kind`` NULL — CHECK rejects the contradiction.

    CR-rework round-2 MAJOR T4: a row claiming ``result='applied'`` cannot
    also carry a ``failure_kind`` value — the two columns encode a
    coupled invariant (success carries no failure discriminator). The
    dispatcher's call-site Literals don't write this shape today, but
    the CHECK is the defense-in-depth boundary against a future
    refactor regression.
    """
    command.upgrade(alembic_cfg, "0011")
    with pytest.raises(exc.IntegrityError), postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO processed_proposals "
                "(proposal_type, proposal_id, blob_sha, commit_sha, result, "
                "failure_kind) "
                "VALUES (:pt, :pid, :bs, :cs, :r, :fk)"
            ),
            {
                "pt": "breaker-reset",
                "pid": "appliedfailkind1",
                "bs": "a" * 40,
                "cs": "b" * 40,
                "r": "applied",
                # An "applied" row with a non-NULL failure_kind is the
                # operator-confusing shape the CHECK is designed to refuse.
                "fk": "handler_returned_failed",
            },
        )


def test_0011_result_failure_kind_consistency_rejects_failed_with_null_failure_kind(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """``failed_*`` rows MUST carry a non-NULL ``failure_kind`` — CHECK refuses the silent gap.

    CR-rework round-2 MAJOR T4: a row claiming ``result='failed_handler'``
    (or ``failed_parse`` / ``failed_unknown_type``) without a
    ``failure_kind`` is "this proposal failed but we don't know how" —
    a silent-drop variant. The CHECK refuses every ``failed_*`` row
    that does not carry a discriminator.
    """
    command.upgrade(alembic_cfg, "0011")
    with pytest.raises(exc.IntegrityError), postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO processed_proposals "
                "(proposal_type, proposal_id, blob_sha, commit_sha, result) "
                "VALUES (:pt, :pid, :bs, :cs, :r)"
            ),
            {
                "pt": "breaker-reset",
                "pid": "failednullkind11",
                "bs": "a" * 40,
                "cs": "b" * 40,
                # A "failed_*" row that omits failure_kind would leave the
                # operator without a discriminator. The CHECK refuses it.
                "r": "failed_handler",
            },
        )


def test_0011_composite_pk_rejects_duplicate(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """A second INSERT for the same (proposal_type, proposal_id) is rejected.

    This is the replay-safety contract — the dispatcher SELECTs this PK
    BEFORE invoking the handler. The DB enforces the uniqueness at the
    storage layer so a write race cannot smuggle a duplicate.
    """
    command.upgrade(alembic_cfg, "0011")
    with postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO processed_proposals "
                "(proposal_type, proposal_id, blob_sha, commit_sha, result) "
                "VALUES (:pt, :pid, :bs, :cs, :r)"
            ),
            {
                "pt": "breaker-reset",
                "pid": "dup",
                "bs": "a" * 40,
                "cs": "b" * 40,
                "r": "applied",
            },
        )
    with pytest.raises(exc.IntegrityError), postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO processed_proposals "
                "(proposal_type, proposal_id, blob_sha, commit_sha, result) "
                "VALUES (:pt, :pid, :bs, :cs, :r)"
            ),
            {
                "pt": "breaker-reset",
                "pid": "dup",
                "bs": "a" * 40,
                "cs": "b" * 40,
                "r": "applied",
            },
        )


def test_0011_server_defaults_populate_omitted_columns(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """A minimal INSERT relies on server_default for processed_at + handler_version."""
    command.upgrade(alembic_cfg, "0011")
    with postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO processed_proposals "
                "(proposal_type, proposal_id, blob_sha, commit_sha, result) "
                "VALUES (:pt, :pid, :bs, :cs, :r)"
            ),
            {
                "pt": "breaker-reset",
                "pid": "minimal",
                "bs": "a" * 40,
                "cs": "b" * 40,
                "r": "applied",
            },
        )
        row = conn.execute(
            text(
                "SELECT processed_at, handler_version, failure_kind, failure_detail, "
                "operator_user_id "
                "FROM processed_proposals WHERE proposal_id = :pid"
            ),
            {"pid": "minimal"},
        ).one()
        # server_default populated processed_at + handler_version
        assert row.processed_at is not None
        assert row.handler_version == 1
        # Failure columns nullable + unset on the applied path.
        assert row.failure_kind is None
        assert row.failure_detail is None
        assert row.operator_user_id is None


def test_0011_full_row_round_trips(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """A full row with failure metadata round-trips byte-equal.

    Pins that the column lengths declared in the migration accept the
    spec-documented bounds (failure_kind String(48), failure_detail
    String(512), operator_user_id String(64)).
    """
    command.upgrade(alembic_cfg, "0011")
    processed_at = dt.datetime(2026, 6, 5, 12, 0, 0, tzinfo=dt.UTC)
    with postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO processed_proposals "
                "(proposal_type, proposal_id, blob_sha, commit_sha, processed_at, "
                "result, handler_version, failure_kind, failure_detail, "
                "operator_user_id) "
                "VALUES (:pt, :pid, :bs, :cs, :pa, :r, :hv, :fk, :fd, :ou)"
            ),
            {
                "pt": "breaker-reset",
                "pid": "abc123def4567890",
                "bs": "a" * 40,
                "cs": "b" * 40,
                "pa": processed_at,
                "r": "failed_handler",
                "hv": 1,
                "fk": "handler_returned_failed",
                "fd": "component_id_not_registered",
                "ou": "operator-1",
            },
        )
        row = conn.execute(
            text(
                "SELECT proposal_type, proposal_id, blob_sha, commit_sha, "
                "processed_at, result, handler_version, failure_kind, "
                "failure_detail, operator_user_id "
                "FROM processed_proposals WHERE proposal_id = :pid"
            ),
            {"pid": "abc123def4567890"},
        ).one()
        assert row.proposal_type == "breaker-reset"
        assert row.blob_sha == "a" * 40
        assert row.commit_sha == "b" * 40
        assert row.processed_at == processed_at
        assert row.result == "failed_handler"
        assert row.handler_version == 1
        assert row.failure_kind == "handler_returned_failed"
        assert row.failure_detail == "component_id_not_registered"
        assert row.operator_user_id == "operator-1"


def test_0011_downgrade_drops_both_tables(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """Downgrade from 0011 drops both tables cleanly.

    Dispatch state is transient — the next run re-discovers via the
    HEAD-diff walk against state.git. Operators wanting forensic
    history snapshot the tables BEFORE downgrading.
    """
    command.upgrade(alembic_cfg, "0011")
    insp = inspect(postgres_engine)
    assert "processed_proposals" in insp.get_table_names()
    assert "processed_proposals_head" in insp.get_table_names()

    command.downgrade(alembic_cfg, "0010")
    insp_after = inspect(postgres_engine)
    assert "processed_proposals" not in insp_after.get_table_names()
    assert "processed_proposals_head" not in insp_after.get_table_names()


def test_0011_revision_metadata(alembic_cfg: config.Config) -> None:
    """Migration declares revision='0011' and down_revision='0010'.

    Catches accidental copy-paste reuse of a sibling migration's revision
    id — the most catastrophic Alembic mistake (silent linearisation
    breakage).
    """
    import importlib

    mod = importlib.import_module(
        "alfred.memory.migrations.versions.0011_processed_proposals",
    )
    assert mod.revision == "0011"
    assert mod.down_revision == "0010"
