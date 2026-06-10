"""Round-trip test for migration 0016 — comms-MCP audit result values (#152).

PR-S4-8 adds comms inbound + session-dispatch audit rows whose ``result``
discriminators (``promoted`` / ``binding_requested`` / ``dropped`` / ``allowed``
/ ``failed``) are outside the migration-0014 domain. Migration 0016 extends
``ck_audit_log_result`` to accept them. This test drives a real Postgres
container so the CHECK is enforced at the DB layer.
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

# Mirror migration 0016's ``_COMMS_ADDITIONS`` exactly so the test breaks if the
# migration's comms-only result set drifts from what the audit emitters use.
_COMMS_RESULTS = (
    "promoted",
    "binding_requested",
    "dropped",
    "capped",
    "allowed",
    "failed",
    "restart_requested",
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
                "VALUES (:id, :created_at, :trace_id, :event, 'alfred', '{}'::json, "
                " 'T3', :result, 0.0, 'en-US')"
            ),
            {
                "id": str(uuid.uuid4()),
                "created_at": dt.datetime.now(dt.UTC),
                "trace_id": f"trace-{result}",
                "event": "comms.test",
                "result": result,
            },
        )


# Pin every assertion to revision ``0016`` — NOT ``head`` — so this file keeps
# isolating the 0016 CHECK change. With ``head`` a later migration that also
# permits these values (or restores the constraint) would mask a broken 0016.
_REV = "0016"


@pytest.mark.parametrize("result", _COMMS_RESULTS)
def test_0016_accepts_comms_result_values(
    alembic_cfg: AlembicConfig, postgres_url: str, result: str
) -> None:
    """After upgrade to 0016, every comms result value is accepted by the CHECK."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        _insert_audit_row(engine, result=result)  # must not raise
        with engine.begin() as conn:
            count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = :r"),
                {"r": result},
            ).scalar_one()
        assert count == 1
    finally:
        engine.dispose()


def test_0016_still_refuses_unknown_result(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
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


def test_0016_downgrade_deletes_comms_rows_and_restores_0015_check(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    """The destructive downgrade path: comms rows are deleted; 0015 rejects them.

    ``0016.downgrade()`` reverts the CHECK to the migration-0014 domain and
    LOUDLY deletes any audit_log row carrying a comms-only result value (the
    ``RAISE NOTICE`` destruction discipline). This guards that rollback contract
    so it cannot regress silently: a comms row inserted under 0016 must be gone
    after the downgrade, a base-domain row must survive, and re-inserting a comms
    result against the restored 0015 CHECK must be refused.
    """
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        # A comms-only row (deleted by downgrade) + a base-domain row (survives).
        _insert_audit_row(engine, result="promoted")
        _insert_audit_row(engine, result="success")

        alembic_command.downgrade(alembic_cfg, "0015")

        with engine.begin() as conn:
            comms_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'promoted'")
            ).scalar_one()
            base_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'success'")
            ).scalar_one()
        assert comms_count == 0, "downgrade must delete comms-only rows"
        assert base_count == 1, "downgrade must not touch base-domain rows"

        # The restored 0015 CHECK refuses comms result values again.
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="promoted")
    finally:
        engine.dispose()
