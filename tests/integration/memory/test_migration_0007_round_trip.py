"""Round-trip tests for migration 0007 — Slice-3 audit_log.result values.

Migration 0007 extends ``ck_audit_log_result`` with the 13 new Slice-3
result values listed in spec §13. The test is shaped after
``test_migration_0004_backfill.py``: function-scoped Postgres testcontainer
(via :func:`tests.integration.conftest.postgres_url` /
:func:`tests.integration.conftest.postgres_engine`), Alembic for stepping
through revisions, raw SQL for inserting / inspecting rows so the test does
not couple to ORM shapes that themselves change across revisions.

Per the alfred-memory-engineer quality bar, migration coverage runs against
a real Postgres — the CHECK-constraint violations the test asserts are a DB
contract, not a Python one, and an in-memory fake would let the contract
silently regress.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from alembic import command, config
from sqlalchemy import Engine, exc, text

pytestmark = pytest.mark.integration

# Slice-2.5 closed domain (migration 0006 head). Kept here as the reference
# set the test asserts is still accepted after the 0007 upgrade — i.e. the
# upgrade is strictly additive at the DB layer.
SLICE_2_5_RESULTS: tuple[str, ...] = (
    "success",
    "budget_blocked",
    "budget_overrun",
    "provider_failed",
    "cancelled",
    "refused",
    "refused_unknown_user",
    "rate_limited",
    "dlp_failed",
    "split_failed",
    "send_failed",
    "recovery_send_failed",
    "login_failed",
    "gateway_unhealthy",
    "unknown_budget_user",
    "fault",
    "bypass",
)

# Slice-3 additions (spec §13). These are the values that MUST be accepted
# after upgrade-to-0007 and MUST be rejected after downgrade-to-0006.
SLICE_3_ONLY_RESULTS: tuple[str, ...] = (
    "extracted",
    "malformed_exhausted",
    "load_refused",
    "crashed",
    "quarantined",
    "reloaded",
    "requested",
    "approved",
    "denied",
    "revoked",
    "tripped",
    "reset",
    "content_expired",
)


@pytest.fixture
def alembic_cfg(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> config.Config:
    """Alembic Config pointed at the per-test container.

    The migration ``env.py`` resolves the DB URL from ``ALFRED_DATABASE_URL``
    first (so it can run without Settings construction); we publish the
    container URL there as well as on the Config object — covers both code
    paths in ``env.py`` without surprise. Same pattern as
    ``test_migration_0004_backfill.py``.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


def _insert_audit_row(engine: Engine, *, result_value: str) -> None:
    """Insert one audit_log row at the current schema.

    Raw SQL because the ORM's :class:`alfred.memory.models.AuditEntry`
    CHECK string is the Slice-2.5 domain at HEAD of this branch — using the
    ORM here would couple test inputs to that frozen domain instead of
    exercising the DB CHECK the migration installs.

    Explicit values for every NOT NULL column (``actor_persona``,
    ``subject``, ``cost_estimate_usd``) — Postgres applies SQLAlchemy ORM
    defaults at flush time, not at the DB layer, so raw-SQL inserts must
    name them or they NotNullViolation.
    """
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_log "
                "(id, created_at, trace_id, event, actor_persona, subject, "
                " trust_tier_of_trigger, result, cost_estimate_usd, language) "
                "VALUES (:id, :ts, :trace, :event, 'alfred', '{}', :tier, "
                "        :result, 0.0, :lang)"
            ),
            {
                "id": str(uuid.uuid4()),
                "ts": dt.datetime.now(dt.UTC),
                "trace": "test-trace-0007",
                "event": "test.event",
                "tier": "T2",
                "result": result_value,
                "lang": "en-US",
            },
        )


def test_0007_upgrade_accepts_slice3_results(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """After upgrade to 0007, every Slice-3 result value is accepted."""
    command.upgrade(alembic_cfg, "0007")
    for result_val in SLICE_3_ONLY_RESULTS:
        _insert_audit_row(postgres_engine, result_value=result_val)


def test_0007_upgrade_still_accepts_slice25_results(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """After upgrade to 0007, every Slice-2.5 result value is still accepted."""
    command.upgrade(alembic_cfg, "0007")
    for result_val in SLICE_2_5_RESULTS:
        _insert_audit_row(postgres_engine, result_value=result_val)


def test_0007_upgrade_rejects_unknown_result(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """After upgrade to 0007, an unrecognised result value raises IntegrityError.

    Pins the closed-domain invariant: the CHECK has not silently
    been weakened into an open enum.
    """
    command.upgrade(alembic_cfg, "0007")
    with pytest.raises(exc.IntegrityError):
        _insert_audit_row(postgres_engine, result_value="not_a_real_result")


def test_0007_downgrade_rejects_slice3_results(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """Downgrade to 0006 reverts the CHECK; Slice-3 inserts then IntegrityError.

    Loud-destruction guarantee — operators who care about Slice-3 audit
    history snapshot BEFORE downgrading. The destructive ``DELETE`` is
    covered by the upgrade-then-row-then-downgrade scenario in
    :func:`test_0007_downgrade_deletes_slice3_rows`.
    """
    command.upgrade(alembic_cfg, "0007")
    command.downgrade(alembic_cfg, "0006")
    with pytest.raises(exc.IntegrityError):
        _insert_audit_row(postgres_engine, result_value="extracted")


def test_0007_downgrade_deletes_slice3_rows(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """Downgrade deletes any rows whose ``result`` is Slice-3-only.

    The migration documents this as the destructive trade-off (same
    pattern as 0005/0006 downgrades). Round-trip the invariant so a
    future refactor that quietly drops the DELETE step trips a red test
    instead of leaving rows that re-violate the restored CHECK.
    """
    command.upgrade(alembic_cfg, "0007")
    _insert_audit_row(postgres_engine, result_value="extracted")
    _insert_audit_row(postgres_engine, result_value="approved")
    # Survivor row at a Slice-2.5 value so the count assertion is meaningful.
    _insert_audit_row(postgres_engine, result_value="success")

    with postgres_engine.begin() as conn:
        before = conn.scalar(text("SELECT COUNT(*) FROM audit_log"))
    assert before == 3

    command.downgrade(alembic_cfg, "0006")

    with postgres_engine.begin() as conn:
        after = conn.scalar(text("SELECT COUNT(*) FROM audit_log"))
        survivors = conn.execute(text("SELECT result FROM audit_log")).scalars().all()
    assert after == 1
    assert survivors == ["success"]
