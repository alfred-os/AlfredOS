"""Round-trip test for migration 0020 — forwarded_dispatch_attempts + poisoned result.

Spec B G6-7-5 (#309, ADR-0039 item 4b). Migration 0020 creates the DURABLE
per-``(adapter_id, inbound_id)`` ``forwarded_dispatch_attempts`` ledger that
bounds the forwarded dispatched-edge replay, and extends ``ck_audit_log_result``
with the ``'poisoned'`` discriminator emitted when that replay bound is
exhausted (DISTINCT from ``'dispatch_failed'``). This test drives a real
Postgres container so the table is created and the CHECK is enforced at the DB
layer (the unit-tier ``audit`` doubles never exercise the constraint).
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
import sqlalchemy as sa
from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig

ALEMBIC_INI_PATH = "alembic.ini"

pytestmark = pytest.mark.integration

# Mirror migration 0020's ``_POISONED_ADDITIONS`` exactly so the test breaks if
# the migration's added result set drifts from what the replay-bound-exhausted
# path actually writes.
_POISONED_RESULTS = ("poisoned",)

# Pin every assertion to revision ``0020`` — NOT ``head`` — so this file keeps
# isolating the 0020 changes.
_REV = "0020"


@pytest.fixture
def alembic_cfg(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> AlembicConfig:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = AlembicConfig(ALEMBIC_INI_PATH)
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


def _insert_user(engine: sa.Engine, slug: str) -> int:
    with engine.begin() as conn:
        row = conn.execute(
            sa.text(
                "INSERT INTO users "
                '(slug, display_name, "authorization", daily_budget_usd, language) '
                "VALUES (:slug, :name, 'operator', 1.0, 'en') "
                "RETURNING id"
            ),
            {"slug": slug, "name": f"user-{slug}"},
        ).one()
    return int(row[0])


def _insert_audit_row(engine: sa.Engine, *, result: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO audit_log "
                "(id, created_at, trace_id, event, actor_persona, subject, "
                " trust_tier_of_trigger, result, cost_estimate_usd, language) "
                "VALUES (:id, :created_at, :trace_id, :event, 'gateway', '{}'::json, "
                " 'T0', :result, 0.0, 'en-US')"
            ),
            {
                "id": str(uuid.uuid4()),
                "created_at": dt.datetime.now(dt.UTC),
                "trace_id": f"trace-{result}",
                "event": "gateway.inbound.poisoned",
                "result": result,
            },
        )


def _insert_forwarded_attempt(engine: sa.Engine, *, adapter_id: str, inbound_id: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO forwarded_dispatch_attempts (adapter_id, inbound_id) "
                "VALUES (:adapter_id, :inbound_id)"
            ),
            {"adapter_id": adapter_id, "inbound_id": inbound_id},
        )


def test_0020_creates_forwarded_dispatch_attempts_with_composite_pk(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    """After upgrade to 0020 the ledger exists with the composite PK columns."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        insp = sa.inspect(engine)
        cols = {c["name"] for c in insp.get_columns("forwarded_dispatch_attempts")}
        assert cols == {
            "adapter_id",
            "inbound_id",
            "attempt_count",
            "first_failed_at",
            "last_failed_at",
        }
        pk = insp.get_pk_constraint("forwarded_dispatch_attempts")
        # Composite (adapter_id, inbound_id) — each adapter's id namespace is isolated.
        assert set(pk["constrained_columns"]) == {"adapter_id", "inbound_id"}
        # Retention index on last_failed_at — mirrors sibling inbound_idempotency's
        # ix_inbound_idempotency_committed_at so a future age-based GC sweep
        # prunes off an index instead of a seq-scan.
        index_names = {ix["name"] for ix in insp.get_indexes("forwarded_dispatch_attempts")}
        assert "ix_forwarded_dispatch_attempts_last_failed_at" in index_names
    finally:
        engine.dispose()


@pytest.mark.parametrize("result", _POISONED_RESULTS)
def test_0020_accepts_poisoned_result_value(
    alembic_cfg: AlembicConfig, postgres_url: str, result: str
) -> None:
    """After upgrade to 0020, the replay-bound-exhausted result is accepted."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        _insert_audit_row(engine, result=result)  # must not raise (CheckViolation pre-0020)
        with engine.begin() as conn:
            count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = :r"),
                {"r": result},
            ).scalar_one()
        assert count == 1
    finally:
        engine.dispose()


def test_0020_still_refuses_unknown_result(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
    """The CHECK is still closed — an unknown result value is refused."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="not_a_real_value")
    finally:
        engine.dispose()


def test_0020_rejects_empty_adapter_id_via_char_length_check(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    """The ``BETWEEN 1 AND 128`` CHECK rejects an empty adapter_id.

    The over-length bound is already enforced by the ``String(128)`` varchar
    type (it raises ``DataError``/StringDataRightTruncation before the CHECK),
    so the lower bound is what proves the named ``char_length`` CHECK is the
    load-bearing constraint: an empty string passes the varchar cap but trips
    the ``BETWEEN 1 AND 128`` CHECK with a ``CheckViolation``/IntegrityError.
    """
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        with pytest.raises(sa.exc.IntegrityError):
            _insert_forwarded_attempt(engine, adapter_id="", inbound_id="i")
    finally:
        engine.dispose()


def test_0020_downgrade_deletes_poisoned_rows_and_drops_table(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    """The destructive downgrade: poisoned rows deleted, 0019 rejects them, table dropped.

    ``0020.downgrade()`` reverts the CHECK to the migration-0019 domain and
    LOUDLY deletes any audit_log row carrying the 0020-only ``poisoned`` value
    (the ``RAISE NOTICE`` destruction discipline carried from
    0005/0006/0007/0014/0016/0017/0019), then drops the ledger table.
    """
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        _insert_audit_row(engine, result="poisoned")  # deleted by downgrade
        _insert_audit_row(engine, result="dispatch_failed")  # 0019-domain row survives

        alembic_command.downgrade(alembic_cfg, "0019")

        with engine.begin() as conn:
            poisoned_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'poisoned'")
            ).scalar_one()
            surviving_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'dispatch_failed'")
            ).scalar_one()
        assert poisoned_count == 0, "downgrade must delete 0020-only rows"
        assert surviving_count == 1, "downgrade must not touch 0019-domain rows"

        insp = sa.inspect(engine)
        table_names = insp.get_table_names()
        assert "forwarded_dispatch_attempts" not in table_names
        # The retention index is explicitly dropped before the table; with the
        # table gone, the index name appears nowhere in the schema.
        all_index_names = {ix["name"] for tbl in table_names for ix in insp.get_indexes(tbl)}
        assert "ix_forwarded_dispatch_attempts_last_failed_at" not in all_index_names

        # The restored 0019 CHECK refuses the poisoned result value again.
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="poisoned")
    finally:
        engine.dispose()
