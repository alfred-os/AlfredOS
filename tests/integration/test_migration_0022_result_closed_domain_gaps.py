"""Round-trip test for migration 0022 — the 14 latent-gap ``result`` values.

Issue #252 / #320. Several audit writers (the quarantine extractor, the
``web.fetch`` tool dispatcher, the capability-gate grant rebuild, the comms
addressing-drift detector, the CLI outbound-DLP sink) shipped a new
``audit_log.result`` value WITHOUT a migration adding it to
``ck_audit_log_result``. Each is the same bug class as the #309/G6-3
``'granted'`` gap migration 0021 closed: the writers' unit + adversarial tests
use an append-only ``audit`` double that never enforces the constraint, so a
real row carrying the value would crash with a ``CheckViolation`` against real
Postgres. The #320 static guard surfaced 13 as literals; an adversarial review
added a 14th (``post_stage_refused``), reached via a dynamic helper-param flow
the static guard cannot see. Migration 0022 extends the CHECK so all 14 are
accepted.

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

# Mirror migration 0022's ``_GAP_ADDITIONS`` exactly so the test breaks if the
# migration's added result set drifts from what the writers actually emit.
_GAP_RESULTS = (
    "transport_failed",
    "protocol_violation",
    "post_stage_refused",  # C1 (adversarial review) — dynamic emit site; closed here too.
    "dlp_scan_error",
    "domain_not_allowed",
    "internal_ip_refused",
    "transport_error",
    "handle_id_mismatch",
    "dispatch_param_invalid",
    "dispatch_shape_error",
    "ok",
    "rolled_back",
    "drift_detected",
    "modified",
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
                " 'T0', :result, 0.0, 'en-US')"
            ),
            {
                "id": str(uuid.uuid4()),
                "created_at": dt.datetime.now(dt.UTC),
                "trace_id": f"trace-{result}",
                "event": "test.migration.0022",
                "result": result,
            },
        )


# Pin every assertion to revision ``0022`` — NOT ``head`` — so this file keeps
# isolating the 0022 CHECK change.
_REV = "0022"


@pytest.mark.parametrize("result", _GAP_RESULTS)
def test_0022_accepts_gap_result_value(
    alembic_cfg: AlembicConfig, postgres_url: str, result: str
) -> None:
    """After upgrade to 0022, each previously-missing result value is accepted."""
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        _insert_audit_row(engine, result=result)  # must not raise (CheckViolation pre-0022)
        with engine.begin() as conn:
            count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = :r"),
                {"r": result},
            ).scalar_one()
        assert count == 1
    finally:
        engine.dispose()


@pytest.mark.parametrize("result", _GAP_RESULTS)
def test_0021_refuses_gap_value(alembic_cfg: AlembicConfig, postgres_url: str, result: str) -> None:
    """Pre-0022 (at revision 0021) the CHECK rejects every gap value.

    Proves the gap the #320 guard surfaced: each row would crash against the
    migration-0021 CHECK. With 0022 not yet applied the INSERT must raise an
    IntegrityError (the CheckViolation), so the fix is genuinely the new
    migration rather than something already present.
    """
    alembic_command.upgrade(alembic_cfg, "0021")
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result=result)
    finally:
        engine.dispose()


def test_0022_still_refuses_unknown_result(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
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


def test_0022_downgrade_deletes_gap_rows_and_restores_0021_check(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    """The destructive downgrade path: gap rows deleted; 0021 rejects them.

    ``0022.downgrade()`` reverts the CHECK to the migration-0021 domain and
    LOUDLY deletes any audit_log row carrying a 0022-only result value (the
    ``RAISE NOTICE`` destruction discipline carried from
    0005/0006/0007/0014/0016/0017/0019/0020/0021).
    """
    alembic_command.upgrade(alembic_cfg, _REV)
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = sa.create_engine(sync_url, future=True)
    try:
        _insert_user(engine, "op")
        for result in _GAP_RESULTS:
            _insert_audit_row(engine, result=result)  # all deleted by downgrade
        _insert_audit_row(engine, result="success")  # base-domain row survives

        alembic_command.downgrade(alembic_cfg, "0021")

        with engine.begin() as conn:
            gap_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = ANY(:vals)"),
                {"vals": list(_GAP_RESULTS)},
            ).scalar_one()
            base_count = conn.execute(
                sa.text("SELECT count(*) FROM audit_log WHERE result = 'success'")
            ).scalar_one()
        assert gap_count == 0, "downgrade must delete all 0022-only rows"
        assert base_count == 1, "downgrade must not touch base-domain rows"

        # The restored 0021 CHECK refuses a 0022-only result value again.
        with pytest.raises(sa.exc.IntegrityError):
            _insert_audit_row(engine, result="transport_failed")
    finally:
        engine.dispose()
