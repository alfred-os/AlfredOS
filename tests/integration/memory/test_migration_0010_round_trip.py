"""Round-trip tests for migration 0010 — circuit_breakers state persistence.

Migration 0010 creates ``circuit_breakers`` — one row per supervised
component (e.g. ``"quarantined-llm"``, ``"web-fetch"``) holding the
breaker's live state plus the most-recent trip metadata. On process
restart, the supervisor loads this table and stays OPEN if
``last_trip_at < 1h`` ago (spec §10.6 flap protection on rolling
restarts).

Pinned invariants:

* The table exists after upgrade-to-0010 with columns ``component_id`` /
  ``state`` / ``trip_count`` / ``last_trip_at`` / ``last_failure_type``
  / ``breaker_state`` / ``correlation_id``.
* ``component_id`` is the primary key — natural key, not a surrogate
  UUID. The supervisor's restore path uses ``SELECT ... WHERE
  component_id = ?``.
* ``state`` has a CHECK constraint pinning the closed domain to
  ``{'CLOSED', 'OPEN', 'HALF_OPEN'}`` — the migration enforces this at
  the DB layer so a buggy writer can't smuggle in an invalid value.
* ``server_default`` populates ``state``, ``trip_count``, and timestamp
  columns when a raw-SQL writer omits them. Mirrors the
  mem-005 / 0009 pattern.
* ``last_trip_at`` and ``last_failure_type`` are nullable — a fresh row
  (never tripped) has no trip metadata.
* Inserting an invalid ``state`` raises ``IntegrityError``.
* Downgrade DROPs the table cleanly (transient state — re-discovered on
  next run per spec §10.6).

The integration test boots a real Postgres testcontainer (no mocks) so
DB-level semantics (CHECK enforcement, server_default behaviour, schema
shape) are pinned against the actual engine that ships in production.
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

    Same wiring as the 0007 / 0008 / 0009 round-trip tests — both env-var
    and Config sqlalchemy.url so the migration env covers either code path
    without surprise.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


def test_0010_upgrade_creates_circuit_breakers(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """After upgrade to 0010, circuit_breakers exists with the spec columns.

    Pins the column surface against the model in
    :mod:`alfred.memory.models` and the audit-row schema in
    :data:`SUPERVISOR_BREAKER_TRIPPED_FIELDS`.
    """
    command.upgrade(alembic_cfg, "0010")
    insp = inspect(postgres_engine)
    assert "circuit_breakers" in insp.get_table_names()
    cols = {c["name"]: c for c in insp.get_columns("circuit_breakers")}
    assert set(cols.keys()) >= {
        "component_id",
        "state",
        "trip_count",
        "last_trip_at",
        "last_failure_type",
        "breaker_state",
        "correlation_id",
    }
    # component_id is the natural primary key (not a surrogate UUID) so
    # the supervisor's restore SELECT can target it by name.
    pk = insp.get_pk_constraint("circuit_breakers")
    assert pk["constrained_columns"] == ["component_id"]


def test_0010_server_defaults_populate_omitted_columns(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """Raw-SQL INSERT omitting state/trip_count/breaker_state/correlation_id works.

    The server_default values mirror the model defaults — a raw-SQL writer
    (Alembic data ops, psql) that supplies only the component_id still
    gets a valid row with state='CLOSED', trip_count=0.
    """
    command.upgrade(alembic_cfg, "0010")
    with postgres_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO circuit_breakers (component_id) VALUES (:cid)"),
            {"cid": "quarantined-llm"},
        )
        row = conn.execute(
            text(
                "SELECT state, trip_count, last_trip_at, last_failure_type, "
                "breaker_state, correlation_id "
                "FROM circuit_breakers WHERE component_id = :cid"
            ),
            {"cid": "quarantined-llm"},
        ).one()
        assert row.state == "CLOSED"
        assert row.trip_count == 0
        # last_trip_at + last_failure_type are nullable — fresh row never tripped.
        assert row.last_trip_at is None
        assert row.last_failure_type is None
        # breaker_state + correlation_id have server_defaults populating them.
        assert row.breaker_state == "CLOSED"
        assert row.correlation_id == ""


def test_0010_state_check_constraint_rejects_invalid(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """state column rejects values outside the closed domain.

    The CHECK constraint pins ``state IN ('CLOSED', 'OPEN', 'HALF_OPEN')``
    so a buggy writer (or a hand-edited row) can't smuggle an invalid
    value past the type layer and have downstream code trust it.
    """
    command.upgrade(alembic_cfg, "0010")
    with pytest.raises(exc.IntegrityError), postgres_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO circuit_breakers (component_id, state) VALUES (:cid, :state)"),
            {"cid": "bogus", "state": "BROKEN"},
        )


def test_0010_full_trip_row_round_trips(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """A trip-event row carrying all the audit-mirror fields persists exactly.

    breaker_state and correlation_id mirror the
    :data:`SUPERVISOR_BREAKER_TRIPPED_FIELDS` audit-row fields; this test
    pins that they survive the DB round-trip unchanged.
    """
    command.upgrade(alembic_cfg, "0010")
    trip_at = dt.datetime(2026, 5, 31, 12, 0, 0, tzinfo=dt.UTC)
    with postgres_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO circuit_breakers "
                "(component_id, state, trip_count, last_trip_at, "
                " last_failure_type, breaker_state, correlation_id) "
                "VALUES (:cid, :st, :tc, :ta, :ft, :bs, :corr)"
            ),
            {
                "cid": "quarantined-llm",
                "st": "OPEN",
                "tc": 1,
                "ta": trip_at,
                "ft": "SubprocessExitedError",
                "bs": "OPEN",
                "corr": "01J0Z3K4ABCDEF",
            },
        )
        row = conn.execute(
            text(
                "SELECT state, trip_count, last_trip_at, last_failure_type, "
                "breaker_state, correlation_id "
                "FROM circuit_breakers WHERE component_id = :cid"
            ),
            {"cid": "quarantined-llm"},
        ).one()
        assert row.state == "OPEN"
        assert row.trip_count == 1
        assert row.last_trip_at == trip_at
        assert row.last_failure_type == "SubprocessExitedError"
        # At trip time, breaker_state mirrors live state, both "OPEN".
        assert row.breaker_state == "OPEN"
        assert row.correlation_id == "01J0Z3K4ABCDEF"


def test_0010_component_id_is_primary_key_no_duplicates(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """Two inserts with the same component_id raise IntegrityError.

    Pins the PK contract — without it, the supervisor's idempotent upsert
    would silently duplicate rows on restart.
    """
    command.upgrade(alembic_cfg, "0010")
    with postgres_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO circuit_breakers (component_id) VALUES (:cid)"),
            {"cid": "quarantined-llm"},
        )
    with pytest.raises(exc.IntegrityError), postgres_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO circuit_breakers (component_id) VALUES (:cid)"),
            {"cid": "quarantined-llm"},
        )


def test_0010_downgrade_drops_circuit_breakers(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
) -> None:
    """Downgrade from 0010 drops circuit_breakers cleanly.

    Breaker state is transient — the next run re-discovers failures
    organically per spec §10.6. Downgrade does NOT preserve the table.
    """
    command.upgrade(alembic_cfg, "0010")
    insp = inspect(postgres_engine)
    assert "circuit_breakers" in insp.get_table_names()

    command.downgrade(alembic_cfg, "0009")
    insp_after = inspect(postgres_engine)
    assert "circuit_breakers" not in insp_after.get_table_names()


def test_0010_revision_metadata(
    alembic_cfg: config.Config,
) -> None:
    """Migration declares revision='0010' and down_revision='0009'.

    Catches accidental copy-paste reuse of a sibling migration's revision
    id — the most catastrophic Alembic mistake (silent linearisation
    breakage).
    """
    import importlib

    mod = importlib.import_module(
        "alfred.memory.migrations.versions.0010_circuit_breakers",
    )
    assert mod.revision == "0010"
    assert mod.down_revision == "0009"
