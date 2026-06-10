"""Round-trip test for migration 0017 — supervisor shutdown audit result values.

PR-S4-11b DEFECT 2 (UAT-proven). ``Supervisor.stop()`` can legitimately emit a
``supervisor.lifecycle.stopped`` row with ``result='cancelled_with_errors'`` (the
force-cancel path, when a genuinely wedged plugin exceeds the graceful-drain
budget) or ``result='persistence_failed'`` (a Postgres write failure mid-shutdown
when breaker state can't be persisted). Neither value was in the
``ck_audit_log_result`` CHECK domain (last extended by migration 0016 for the
PR-S4-8 comms values), so the shutdown audit INSERT crashed with a
``CheckViolation`` against real Postgres — a raw asyncpg/SQLAlchemy traceback to
the operator's terminal and NO clean shutdown row. Migration 0017 extends the
CHECK so the supervisor's full shutdown result vocabulary is accepted.

This test drives a real Postgres container so the CHECK is enforced at the DB
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

# Mirror migration 0017's ``_SUPERVISOR_SHUTDOWN_ADDITIONS`` exactly so the test
# breaks if the migration's added result set drifts from what the supervisor
# shutdown emitters actually write (``Supervisor.stop`` / ``reset_breaker``).
_SUPERVISOR_SHUTDOWN_RESULTS = (
    "cancelled_with_errors",
    "persistence_failed",
)


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
                "VALUES (:id, :created_at, :trace_id, :event, 'supervisor', '{}'::json, "
                " 'T0', :result, 0.0, 'en-US')"
            ),
            {
                "id": str(uuid.uuid4()),
                "created_at": dt.datetime.now(dt.UTC),
                "trace_id": f"trace-{result}",
                "event": "supervisor.lifecycle.stopped",
                "result": result,
            },
        )


# Pin every assertion to revision ``0017`` — NOT ``head`` — so this file keeps
# isolating the 0017 CHECK change.
_REV = "0017"


@pytest.mark.parametrize("result", _SUPERVISOR_SHUTDOWN_RESULTS)
def test_0017_accepts_supervisor_shutdown_result_values(
    alembic_cfg: AlembicConfig, postgres_url: str, result: str
) -> None:
    """After upgrade to 0017, each supervisor shutdown result is accepted."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        _insert_audit_row(engine, result=result)  # must not raise (CheckViolation pre-0017)
        with engine.begin() as conn:
            count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = :r"),
                {"r": result},
            ).scalar_one()
        assert count == 1
    finally:
        engine.dispose()


def test_0016_refuses_cancelled_with_errors(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
    """Pre-0017 (at revision 0016) the CHECK rejects ``cancelled_with_errors``.

    Proves the gap UAT hit: the supervisor shutdown row crashed against the
    migration-0016 CHECK. With 0017 not yet applied, the INSERT must raise an
    IntegrityError (the CheckViolation), so the fix is genuinely the new
    migration rather than something already present.
    """
    alembic_command.upgrade(alembic_cfg, "0016")
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="cancelled_with_errors")
    finally:
        engine.dispose()


def test_0017_still_refuses_unknown_result(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
    """The CHECK is still closed — an unknown result value is refused."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="not_a_real_result")
    finally:
        engine.dispose()


def test_0017_downgrade_deletes_shutdown_rows_and_restores_0016_check(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    """The destructive downgrade path: supervisor rows deleted; 0016 rejects them.

    ``0017.downgrade()`` reverts the CHECK to the migration-0016 domain and
    LOUDLY deletes any audit_log row carrying a 0017-only result value (the
    ``RAISE NOTICE`` destruction discipline carried from 0005/0006/0007/0014/0016).
    """
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        _insert_audit_row(engine, result="cancelled_with_errors")  # deleted by downgrade
        _insert_audit_row(engine, result="success")  # base-domain row survives

        alembic_command.downgrade(alembic_cfg, "0016")

        with engine.begin() as conn:
            shutdown_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'cancelled_with_errors'")
            ).scalar_one()
            base_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'success'")
            ).scalar_one()
        assert shutdown_count == 0, "downgrade must delete 0017-only rows"
        assert base_count == 1, "downgrade must not touch base-domain rows"

        # The restored 0016 CHECK refuses the shutdown result values again.
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="cancelled_with_errors")
    finally:
        engine.dispose()
