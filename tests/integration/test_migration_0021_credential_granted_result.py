"""Round-trip test for migration 0021 — credential-grant ``granted`` result.

Spec B G6-3 (#288 / #309, ADR-0036). The core-side credential resolver
(:class:`alfred.comms_mcp.adapter_credential_resolver.CoreAdapterCredentialResolver`)
writes a SIGNED ``core.adapter.spawn_grant`` audit row carrying a closed-vocab
``result='granted'`` whenever it releases a platform credential to the gateway over
the trusted leg. That value was never added to the migration-0020 ``ck_audit_log_result``
domain, so the grant INSERT crashed with a ``CheckViolation`` against real Postgres
(the resolver's unit tests use an append-only ``audit`` double that never enforces the
constraint, so the gap stayed invisible until the G6-7-7 e2e drove the first REAL
credential round-trip). Migration 0021 extends the CHECK so the grant result is
accepted.

This test drives a real Postgres container so the CHECK is enforced at the DB layer
(the unit-tier ``audit`` doubles never exercise the constraint).
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

# Mirror migration 0021's ``_GRANTED_ADDITIONS`` exactly so the test breaks if the
# migration's added result set drifts from what the credential resolver actually
# writes on a successful grant.
_GRANTED_RESULTS = ("granted",)


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
                " 'T0', :result, 0.0, 'en-US')"
            ),
            {
                "id": str(uuid.uuid4()),
                "created_at": dt.datetime.now(dt.UTC),
                "trace_id": f"trace-{result}",
                "event": "core.adapter.spawn_grant",
                "result": result,
            },
        )


# Pin every assertion to revision ``0021`` — NOT ``head`` — so this file keeps
# isolating the 0021 CHECK change.
_REV = "0021"


@pytest.mark.parametrize("result", _GRANTED_RESULTS)
def test_0021_accepts_granted_result_value(
    alembic_cfg: AlembicConfig, postgres_url: str, result: str
) -> None:
    """After upgrade to 0021, the credential-grant result is accepted."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        _insert_audit_row(engine, result=result)  # must not raise (CheckViolation pre-0021)
        with engine.begin() as conn:
            count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = :r"),
                {"r": result},
            ).scalar_one()
        assert count == 1
    finally:
        engine.dispose()


def test_0020_refuses_granted(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
    """Pre-0021 (at revision 0020) the CHECK rejects ``granted``.

    Proves the gap the G6-7-7 e2e surfaced: the credential-grant row would crash
    against the migration-0020 CHECK. With 0021 not yet applied, the INSERT must
    raise an IntegrityError (the CheckViolation), so the fix is genuinely the new
    migration rather than something already present.
    """
    alembic_command.upgrade(alembic_cfg, "0020")
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="granted")
    finally:
        engine.dispose()


def test_0021_still_refuses_unknown_result(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
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


def test_0021_downgrade_deletes_granted_rows_and_restores_0020_check(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    """The destructive downgrade path: granted rows deleted; 0020 rejects them.

    ``0021.downgrade()`` reverts the CHECK to the migration-0020 domain and LOUDLY
    deletes any audit_log row carrying the 0021-only ``granted`` result value (the
    ``RAISE NOTICE`` destruction discipline carried from
    0005/0006/0007/0014/0016/0017/0019/0020).
    """
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        _insert_audit_row(engine, result="granted")  # deleted by downgrade
        _insert_audit_row(engine, result="success")  # base-domain row survives

        alembic_command.downgrade(alembic_cfg, "0020")

        with engine.begin() as conn:
            granted_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'granted'")
            ).scalar_one()
            base_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'success'")
            ).scalar_one()
        assert granted_count == 0, "downgrade must delete 0021-only rows"
        assert base_count == 1, "downgrade must not touch base-domain rows"

        # The restored 0020 CHECK refuses the granted result value again.
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="granted")
    finally:
        engine.dispose()
