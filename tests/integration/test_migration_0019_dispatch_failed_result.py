"""Round-trip test for migration 0019 — dispatched-edge dispatch_failed result.

Spec B G6-7-4 (#309, ADR-0039 item 4). The gateway dispatched-edge forwarded
path (:func:`alfred.comms_mcp.inbound.process_inbound_message` with
``commit_at_dispatch_edge=True``) commits + observes AFTER a successful
dispatch. On a dispatch FAILURE it deliberately leaves the frame NOT committed /
NOT observed so the forwarding leg replays it, and emits a SIGNED audit row with
a DISTINCT ``result='dispatch_failed'`` discriminator (never the ``'dropped'``
replay value, so the two are distinguishable in the log). That value was not in
the migration-0016/0017 ``ck_audit_log_result`` domain, so the shutdown audit
INSERT crashed with a ``CheckViolation`` against real Postgres. Migration 0019
extends the CHECK so the dispatched-edge dispatch-failure result is accepted.

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

# Mirror migration 0019's ``_DISPATCH_FAILED_ADDITIONS`` exactly so the test
# breaks if the migration's added result set drifts from what the dispatched-edge
# forwarded path actually writes on a dispatch failure.
_DISPATCH_FAILED_RESULTS = ("dispatch_failed",)


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
                "event": "gateway.inbound.dispatch_failed",
                "result": result,
            },
        )


# Pin every assertion to revision ``0019`` — NOT ``head`` — so this file keeps
# isolating the 0019 CHECK change.
_REV = "0019"


@pytest.mark.parametrize("result", _DISPATCH_FAILED_RESULTS)
def test_0019_accepts_dispatch_failed_result_value(
    alembic_cfg: AlembicConfig, postgres_url: str, result: str
) -> None:
    """After upgrade to 0019, each dispatched-edge dispatch-failure result is accepted."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        _insert_audit_row(engine, result=result)  # must not raise (CheckViolation pre-0019)
        with engine.begin() as conn:
            count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = :r"),
                {"r": result},
            ).scalar_one()
        assert count == 1
    finally:
        engine.dispose()


def test_0018_refuses_dispatch_failed(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
    """Pre-0019 (at revision 0018) the CHECK rejects ``dispatch_failed``.

    Proves the gap the reviewer flagged: the dispatched-edge dispatch-failure row
    would crash against the migration-0017 CHECK. With 0019 not yet applied, the
    INSERT must raise an IntegrityError (the CheckViolation), so the fix is
    genuinely the new migration rather than something already present.
    """
    alembic_command.upgrade(alembic_cfg, "0018")
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="dispatch_failed")
    finally:
        engine.dispose()


def test_0019_still_refuses_unknown_result(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
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


def test_0019_downgrade_deletes_dispatch_failed_rows_and_restores_0018_check(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    """The destructive downgrade path: dispatch_failed rows deleted; 0018 rejects them.

    ``0019.downgrade()`` reverts the CHECK to the migration-0017 domain and
    LOUDLY deletes any audit_log row carrying a 0019-only result value (the
    ``RAISE NOTICE`` destruction discipline carried from
    0005/0006/0007/0014/0016/0017).
    """
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        _insert_audit_row(engine, result="dispatch_failed")  # deleted by downgrade
        _insert_audit_row(engine, result="success")  # base-domain row survives

        alembic_command.downgrade(alembic_cfg, "0018")

        with engine.begin() as conn:
            dispatch_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'dispatch_failed'")
            ).scalar_one()
            base_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'success'")
            ).scalar_one()
        assert dispatch_count == 0, "downgrade must delete 0019-only rows"
        assert base_count == 1, "downgrade must not touch base-domain rows"

        # The restored 0018 CHECK refuses the dispatch_failed result value again.
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="dispatch_failed")
    finally:
        engine.dispose()
