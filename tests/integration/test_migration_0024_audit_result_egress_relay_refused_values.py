"""Round-trip test for migration 0024 — egress-relay refusal result values.

Spec C G7-2c-1 (#333).  The in-core ``RelayEgressClient._audit_refused`` helper
writes a durable ``security.egress_relay_refused`` audit row on every refusal
path.  The ``result`` column carries one of two new closed-vocab tokens:

* ``"in_doubt"``            — in-doubt + non-idempotent refusal (EgressInDoubtError).
* ``"io_plane_unavailable"``— gateway relay unreachable / truncated frame / timeout.

Migration 0024 extends ``ck_audit_log_result`` to accept these values.  Without
the migration, ``_audit_refused`` would raise a ``CheckViolation`` against real
Postgres (unit-tier audit doubles never enforce the constraint, so the gap stays
invisible until a real relay call drives the first refusal path).

This test drives a real Postgres container so the CHECK is enforced at the DB
layer — mirroring the 0021/0022 pattern.
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

# Mirror migration 0024's ``_EGRESS_RELAY_REFUSED_ADDITIONS`` exactly so the
# test breaks if the migration's added result set drifts from what
# ``RelayEgressClient._audit_refused`` actually writes on a refusal path.
_EGRESS_RELAY_REFUSED_VALUES = ("in_doubt", "io_plane_unavailable")


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
                "event": "security.egress_relay_refused",
                "result": result,
            },
        )


# Pin every assertion to revision ``0024`` — NOT ``head`` — so this file keeps
# isolating the 0024 CHECK change.
_REV = "0024"


@pytest.mark.parametrize("result", _EGRESS_RELAY_REFUSED_VALUES)
def test_0024_accepts_egress_relay_refused_result_values(
    alembic_cfg: AlembicConfig, postgres_url: str, result: str
) -> None:
    """After upgrade to 0024, the egress-relay refusal result values are accepted."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, f"op-{result.replace('_', '-')}")
        _insert_audit_row(engine, result=result)  # must not raise (CheckViolation pre-0024)
        with engine.begin() as conn:
            count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = :r"),
                {"r": result},
            ).scalar_one()
        assert count == 1
    finally:
        engine.dispose()


@pytest.mark.parametrize("result", _EGRESS_RELAY_REFUSED_VALUES)
def test_0023_refuses_egress_relay_refused_values(
    alembic_cfg: AlembicConfig, postgres_url: str, result: str
) -> None:
    """Pre-0024 (at revision 0023) the CHECK rejects the egress-relay refusal values.

    Proves the gap G7-2c-1 surfaced: the refusal row would crash against the
    migration-0023 CHECK.  With 0024 not yet applied, the INSERT must raise an
    IntegrityError (CheckViolation), so the fix is genuinely the new migration
    rather than something already present.
    """
    alembic_command.upgrade(alembic_cfg, "0023")
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, f"op-pre-{result.replace('_', '-')}")
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result=result)
    finally:
        engine.dispose()


def test_0024_still_refuses_unknown_result(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
    """The CHECK is still closed — an unknown result value is refused at 0024."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op-unknown")
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="not_a_real_result")
    finally:
        engine.dispose()


def test_0024_downgrade_deletes_egress_relay_refused_rows_and_restores_0023_check(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    """The destructive downgrade path: 0024-only rows deleted; 0023 rejects them.

    ``0024.downgrade()`` reverts the CHECK to the migration-0023 domain and LOUDLY
    deletes any audit_log row carrying the 0024-only result values (the
    ``RAISE NOTICE`` destruction discipline carried from
    0005/0006/0007/0014/0016/0017/0019/0020/0021/0022).
    """
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op-downgrade")
        _insert_audit_row(engine, result="in_doubt")  # deleted by downgrade
        _insert_audit_row(engine, result="io_plane_unavailable")  # deleted by downgrade
        _insert_audit_row(engine, result="success")  # base-domain row survives

        alembic_command.downgrade(alembic_cfg, "0023")

        with engine.begin() as conn:
            in_doubt_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'in_doubt'")
            ).scalar_one()
            io_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'io_plane_unavailable'")
            ).scalar_one()
            base_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'success'")
            ).scalar_one()
        assert in_doubt_count == 0, "downgrade must delete 0024-only in_doubt rows"
        assert io_count == 0, "downgrade must delete 0024-only io_plane_unavailable rows"
        assert base_count == 1, "downgrade must not touch base-domain rows"

        # The restored 0023 CHECK refuses the 0024-only result values again.
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="in_doubt")
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="io_plane_unavailable")
    finally:
        engine.dispose()
