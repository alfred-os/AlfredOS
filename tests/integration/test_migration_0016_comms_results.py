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

_COMMS_RESULTS = ("promoted", "binding_requested", "dropped", "allowed", "failed")


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


@pytest.mark.parametrize("result", _COMMS_RESULTS)
def test_0016_accepts_comms_result_values(
    alembic_cfg: AlembicConfig, postgres_url: str, result: str
) -> None:
    """After upgrade head, every comms result value is accepted by the CHECK."""
    alembic_command.upgrade(alembic_cfg, "head")
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
    alembic_command.upgrade(alembic_cfg, "head")
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="not_a_real_result")
    finally:
        engine.dispose()
