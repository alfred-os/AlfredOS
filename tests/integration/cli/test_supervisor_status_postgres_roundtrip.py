"""Integration round-trip: ``alfred supervisor status`` reads real Postgres.

Issue #154 / ADR-0020 (revised): pins the end-to-end Postgres path of
``alfred supervisor status``. A real Postgres container is spun up via
testcontainers, two ``CircuitBreakerState`` rows are inserted via the
sync engine, ``DATABASE_URL`` is exported to the CLI subprocess context,
and the rendered table is asserted to contain both rows.

A third row is inserted mid-test to simulate the supervisor's
``CircuitBreaker.save_to_db`` writing a new component while the CLI is
between invocations — pins the freshness contract documented in the
runbook ("rows reflect supervisor's last save_to_db write; typically
lags by <=1 supervisor cycle").

The CLI helper is invoked via ``typer.testing.CliRunner`` against the
sync ``DATABASE_URL`` — the same engine builder the production CLI
uses. ``CircuitBreakerState`` is the production ORM model; ``Base.metadata.create_all``
creates the table without running alembic (the integration test owns
the schema axis for this surface, separate from the migration round-trip
test that covers alembic).
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import sessionmaker
from testcontainers.postgres import PostgresContainer
from typer.testing import CliRunner

from alfred.cli.supervisor import supervisor_app
from alfred.memory.models import Base, CircuitBreakerState

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Satisfy Settings' required ``ALFRED_DEEPSEEK_API_KEY`` field.

    CR-156 round-7 BLOCKER #1: ``_resolve_database_url`` now routes
    through ``sync_db_url(load_settings_or_die())``; Settings refuses
    to construct without the API key. The integration round-trip
    exercises the CLI surface end-to-end, so the fixture sets a non-
    placeholder dummy so the read path can reach Postgres.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test-key-not-placeholder")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


@pytest.fixture
def postgres_sync_engine() -> Iterator[tuple[Engine, str]]:
    """Spin up a Postgres container; yield the sync engine and its DATABASE_URL.

    Per-test container (testcontainers default): each scenario gets a
    clean ``circuit_breakers`` table so a previous test's persisted
    state cannot leak into the next test's read path. The ~5s container
    startup is the price of isolation.

    Returns the engine + the URL the CLI's ``_resolve_database_url``
    consumes via ``DATABASE_URL``. The URL uses the ``+psycopg`` driver
    because the CLI is synchronous; the production async runtime uses
    a different URL prefix.
    """
    with PostgresContainer("postgres:18") as pg:
        # testcontainers default URL uses ``postgresql+psycopg2``; the
        # production CLI consumes ``postgresql+psycopg`` (psycopg 3). The
        # sync driver shape parity matters: ``_list_breaker_states`` will
        # bind whatever driver the URL names.
        raw_url = pg.get_connection_url()
        sync_url = raw_url.replace("postgresql+psycopg2", "postgresql+psycopg")
        engine = create_engine(sync_url, future=True)
        try:
            Base.metadata.create_all(engine)
            yield engine, sync_url
        finally:
            engine.dispose()


def test_status_round_trip_renders_inserted_breaker_rows(
    postgres_sync_engine: tuple[Engine, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real-Postgres end-to-end: two rows → two rows rendered → third row mid-test.

    Pins the freshness contract: the CLI re-reads on every invocation,
    so rows inserted between two ``alfred supervisor status`` runs
    appear in the second run's output. This is the same staleness model
    ``alfred audit log`` uses against the audit Postgres projection.
    """
    engine, sync_url = postgres_sync_engine
    monkeypatch.setenv("ALFRED_DATABASE_URL", sync_url)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        session.add(
            CircuitBreakerState(
                component_id="quarantined-llm",
                state="OPEN",
                trip_count=3,
                last_trip_at=dt.datetime(2026, 6, 5, 12, 0, 0, tzinfo=dt.UTC),
                last_failure_type="ProviderRefused",
                breaker_state="OPEN",
                correlation_id="trip-1",
            )
        )
        session.add(
            CircuitBreakerState(
                component_id="web-fetch",
                state="CLOSED",
                trip_count=0,
                last_trip_at=None,
                last_failure_type=None,
                breaker_state="CLOSED",
                correlation_id="",
            )
        )
        session.commit()

    runner = CliRunner()
    result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "quarantined-llm" in result.output
    assert "web-fetch" in result.output
    # CR-156 round-7 MEDIUM #13: line-anchored regex pins the OPEN label
    # to the ``quarantined-llm`` row specifically. The bare ``"OPEN" in
    # result.output`` assertion previously matched the ``HALF_OPEN``
    # substring on any row, so a regression that flipped a HALF_OPEN
    # row to render the wrong label would not surface. The whitespace
    # gap between columns is ``  `` (two spaces) per the renderer; the
    # regex tolerates the dynamic column width by greedily consuming
    # the first whitespace run.
    assert re.search(r"^quarantined-llm\s+OPEN\s+3\b", result.output, re.MULTILINE), result.output

    # Insert a third row mid-test — simulating the supervisor's
    # ``CircuitBreaker.save_to_db`` writing a new component between two
    # operator polls. The next status invocation MUST see it.
    with session_factory() as session:
        session.add(
            CircuitBreakerState(
                component_id="comms-discord",
                state="HALF_OPEN",
                trip_count=1,
                last_trip_at=dt.datetime(2026, 6, 5, 12, 5, 0, tzinfo=dt.UTC),
                last_failure_type="ConnectionRefused",
                breaker_state="OPEN",
                correlation_id="trip-2",
            )
        )
        session.commit()

    result_after = runner.invoke(supervisor_app, ["status"])
    assert result_after.exit_code == 0, (result_after.output, result_after.stderr)
    # All three rows visible — including the mid-test insertion.
    assert "quarantined-llm" in result_after.output
    assert "web-fetch" in result_after.output
    assert "comms-discord" in result_after.output
    # CR-156 round-7 MEDIUM #13: pin the HALF_OPEN label to the
    # ``comms-discord`` row so a regression that swaps the state column
    # across rows surfaces here.
    assert re.search(r"^comms-discord\s+HALF_OPEN\s+1\b", result_after.output, re.MULTILINE), (
        result_after.output
    )


def test_status_round_trip_renders_no_components_yet_on_empty_table(
    postgres_sync_engine: tuple[Engine, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty ``circuit_breakers`` → ``no_components_yet`` hint + exit 0.

    The empty-state operator surface is materially distinct from
    ``postgres_unavailable``: the stack is up, the read path works,
    there is just nothing to render yet. Exit 0 because the operator
    action is "wait", not "investigate".
    """
    _engine, sync_url = postgres_sync_engine
    monkeypatch.setenv("ALFRED_DATABASE_URL", sync_url)

    runner = CliRunner()
    result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    # The localised body uses "supervised components" / "No supervised".
    assert "components" in result.output.lower()
