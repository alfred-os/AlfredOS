"""Integration round-trip: ``alfred supervisor proposals`` against real Postgres.

ADR-0021 #171 §Operator visibility — pins the end-to-end Postgres path
of the new operator-facing surface:

* ``alfred supervisor proposals`` lists ``processed_proposals`` rows
  with the column set documented in the runbook.
* ``alfred supervisor proposals --since 1h`` scopes to a window
  (CR rework round-1 HIGH #13 — replaced the binary ``--recent`` flag).
* ``_recent_dispatch_counts`` returns the applied / failed counts the
  status footer renders. ``pending`` was dropped per CR rework round-1
  HIGH #11 (always 0 — the loop is monotonically forward, so the slot
  lied to the operator).

Same shape as :mod:`tests.integration.cli.test_supervisor_status_postgres_roundtrip`
— per-test Postgres container, sync CLI engine path, real ``CliRunner``
invocation against the URL exposed via ``ALFRED_DATABASE_URL``.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import sessionmaker
from testcontainers.postgres import PostgresContainer
from typer.testing import CliRunner

from alfred.cli.supervisor import (
    _list_proposals,
    _recent_dispatch_counts,
    supervisor_app,
)
from alfred.memory.models import Base, ProcessedProposal

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Satisfy Settings' API-key requirement (same as the status round-trip)."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test-key-not-placeholder")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


@pytest.fixture
def postgres_sync_engine() -> Iterator[tuple[Engine, str]]:
    """Spin up Postgres; yield the sync engine + the asyncpg-rewritten URL."""
    with PostgresContainer("postgres:18") as pg:
        raw_url = pg.get_connection_url()
        sync_url = raw_url.replace("postgresql+psycopg2", "postgresql+psycopg")
        engine = create_engine(sync_url, future=True)
        try:
            Base.metadata.create_all(engine)
            yield engine, sync_url
        finally:
            engine.dispose()


def _insert_proposal(
    engine: Engine,
    *,
    proposal_id: str,
    result: str,
    failure_kind: str | None = None,
    operator_user_id: str = "operator-1",
    processed_at: dt.datetime | None = None,
) -> None:
    """Insert a ProcessedProposal row through the production ORM model."""
    sm = sessionmaker(bind=engine, expire_on_commit=False)
    with sm() as session:
        session.add(
            ProcessedProposal(
                proposal_type="breaker-reset",
                proposal_id=proposal_id,
                blob_sha="a" * 40,
                commit_sha="b" * 40,
                result=result,
                handler_version=1,
                failure_kind=failure_kind,
                failure_detail=None,
                operator_user_id=operator_user_id,
                processed_at=processed_at or dt.datetime.now(dt.UTC),
            )
        )
        session.commit()


def test_list_proposals_round_trip_against_postgres(
    postgres_sync_engine: tuple[Engine, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_list_proposals`` reads rows through the production sync engine."""
    engine, sync_url = postgres_sync_engine
    monkeypatch.setenv("ALFRED_DATABASE_URL", sync_url)
    _insert_proposal(engine, proposal_id="abc", result="applied")
    _insert_proposal(
        engine,
        proposal_id="xyz",
        result="failed_handler",
        # Closed vocab per spec §2.5 / ``ck_processed_proposals_failure_kind``.
        failure_kind="handler_returned_failed",
    )

    rows = _list_proposals()
    by_id = {r["proposal_id"]: r for r in rows}
    assert by_id["abc"]["result"] == "applied"
    assert by_id["xyz"]["failure_kind"] == "handler_returned_failed"


def test_list_proposals_since_filters_old_rows(
    postgres_sync_engine: tuple[Engine, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``since`` scopes the listing to the supplied window.

    CR rework round-1 HIGH #13: ``--recent`` (binary, 1h) was replaced
    with ``--since DURATION``; the helper now takes a
    :class:`datetime.timedelta`. ``since=None`` returns every row
    (the ``--all`` escape hatch).
    """
    engine, sync_url = postgres_sync_engine
    monkeypatch.setenv("ALFRED_DATABASE_URL", sync_url)
    now = dt.datetime.now(dt.UTC)
    _insert_proposal(
        engine, proposal_id="old", result="applied", processed_at=now - dt.timedelta(hours=2)
    )
    _insert_proposal(engine, proposal_id="recent", result="applied", processed_at=now)

    all_rows = _list_proposals(since=None, limit=None)
    recent_rows = _list_proposals(since=dt.timedelta(hours=1))
    assert {r["proposal_id"] for r in all_rows} == {"old", "recent"}
    assert {r["proposal_id"] for r in recent_rows} == {"recent"}


def test_recent_dispatch_counts_groups_by_result(
    postgres_sync_engine: tuple[Engine, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The counts helper groups recent rows by closed-vocab result.

    CR rework round-1 HIGH #11: ``pending`` was dropped from the
    surface — it was always 0 (the dispatcher loop is monotonically
    forward; merged blobs either appear in the ledger or have not yet
    been walked) and lying to the operator. The footer surface now
    reports only ``applied`` + ``failed``.
    """
    engine, sync_url = postgres_sync_engine
    monkeypatch.setenv("ALFRED_DATABASE_URL", sync_url)
    _insert_proposal(engine, proposal_id="a", result="applied")
    _insert_proposal(engine, proposal_id="b", result="applied")
    # CR-rework round-2 MAJOR T4: ``failed_*`` rows must carry a
    # non-NULL ``failure_kind`` to satisfy
    # ``ck_processed_proposals_result_failure_kind_consistency``.
    _insert_proposal(
        engine,
        proposal_id="c",
        result="failed_handler",
        failure_kind="handler_returned_failed",
    )

    counts = _recent_dispatch_counts()
    assert counts == {"applied": 2, "failed": 1}


def test_proposals_subcommand_renders_real_rows_via_cli(
    postgres_sync_engine: tuple[Engine, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: real CliRunner invocation against the real read path."""
    engine, sync_url = postgres_sync_engine
    monkeypatch.setenv("ALFRED_DATABASE_URL", sync_url)
    _insert_proposal(engine, proposal_id="abc", result="applied")

    runner = CliRunner()
    result = runner.invoke(supervisor_app, ["proposals"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "abc" in result.output
    assert "applied" in result.output
