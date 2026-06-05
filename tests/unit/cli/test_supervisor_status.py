"""Unit tests for ``alfred supervisor status`` — sync Postgres read path.

Issue #154 / ADR-0020 (revised): replaces the
``NotImplementedError``-raising placeholder ``_list_breaker_states`` with a
sync SQLAlchemy read against the ``circuit_breakers`` Postgres table. The
CLI no longer needs a supervisor handle for status; the freshness contract
is "rows reflect the supervisor's last ``CircuitBreaker.save_to_db`` write"
per ``docs/runbooks/slice-3-supervisor.md``.

The unit-level tests cover the synchronous helpers in isolation:

* ``_list_breaker_states`` reads rows out of Postgres into the
  ``BreakerStateRow`` shape the renderer consumes.
* ``_resolve_database_url`` routes through Settings/bootstrap resolution
  (``load_settings_or_die`` → ``sync_db_url``), so an unset
  ``DATABASE_URL`` falls back to the Settings default URL and the
  ``+asyncpg`` → ``+psycopg`` driver rewrite runs unconditionally for
  the sync read path. The resolver does NOT raise on a missing env var
  (CR-156 round-7 BLOCKER #1); Postgres-unreachable surfaces as
  :class:`OperationalError` at engine-construction / query time and is
  routed through the ``postgres_unavailable`` arm of
  ``supervisor_status``.
* ``supervisor_status`` handler arms route ``OperationalError`` through the
  ``postgres_unavailable`` catalog key and the empty-table case through the
  ``no_components_yet`` key.

Integration round-trip (real Postgres via testcontainers) lives in
``tests/integration/cli/test_supervisor_status_postgres_roundtrip.py``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import OperationalError, ProgrammingError
from typer.testing import CliRunner

from alfred.cli.supervisor import supervisor_app


@pytest.fixture(autouse=True)
def _settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Satisfy Settings' required ``ALFRED_DEEPSEEK_API_KEY`` field.

    CR-156 round-7 BLOCKER #1: ``_resolve_database_url`` now routes
    through ``sync_db_url(load_settings_or_die())``. Every test that
    invokes the status command (directly or indirectly) needs Settings
    to construct without raising the placeholder/missing-key validator
    error. Setting a non-placeholder dummy here keeps the tests focused
    on the read path; the placeholder-validator path has its own
    dedicated tests under ``tests/unit/config/``.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test-key-not-placeholder")


@pytest.fixture()
def runner() -> CliRunner:
    """Typer runner — Click 8.2 separates stdout/stderr by default."""
    return CliRunner()


# ---------------------------------------------------------------------------
# _resolve_database_url
# ---------------------------------------------------------------------------


def test_resolve_database_url_keeps_explicit_psycopg_driver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit ``+psycopg`` URL passes through unchanged.

    The supervisor and the CLI must read from the same Postgres instance.
    An operator who has already configured the sync driver should not
    have their URL silently rewritten.
    """
    from alfred.cli.supervisor import _resolve_database_url

    monkeypatch.setenv(
        "ALFRED_DATABASE_URL", "postgresql+psycopg://user:pass@localhost:5432/alfred"
    )
    assert _resolve_database_url() == "postgresql+psycopg://user:pass@localhost:5432/alfred"


def test_resolve_database_url_rewrites_asyncpg_to_psycopg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``postgresql+asyncpg://`` → ``postgresql+psycopg://`` (BLOCKER #1).

    The default Slice-1 ``Settings.database_url`` shape is the async
    driver because the runtime is async-first. The supervisor CLI is
    synchronous, so the URL must be rewritten before SQLAlchemy
    constructs the sync engine — otherwise the operator hits
    ``ModuleNotFoundError: No module named 'asyncpg'`` because the CLI
    bundle ships ``psycopg`` only. ``_resolve_database_url`` reuses
    ``sync_db_url`` from the shared bootstrap, which every other sync
    CLI surface already honours (identity resolver, audit writer).
    """
    from alfred.cli.supervisor import _resolve_database_url

    monkeypatch.setenv(
        "ALFRED_DATABASE_URL", "postgresql+asyncpg://user:pass@localhost:5432/alfred"
    )
    assert _resolve_database_url() == "postgresql+psycopg://user:pass@localhost:5432/alfred"


def test_resolve_database_url_adds_psycopg_when_driver_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``postgresql://`` (no driver) → ``postgresql+psycopg://`` (BLOCKER #1).

    When the operator omits the driver token, SQLAlchemy would fall
    back to its default driver (psycopg2 — a dev-tooling-only
    dependency on this project). Pinning ``+psycopg`` explicitly keeps
    the sync engine on the supported driver. Matches the
    ``sync_db_url`` contract documented in
    :mod:`alfred.cli._bootstrap`.
    """
    from alfred.cli.supervisor import _resolve_database_url

    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql://user:pass@localhost:5432/alfred")
    assert _resolve_database_url() == "postgresql+psycopg://user:pass@localhost:5432/alfred"


# ---------------------------------------------------------------------------
# _list_breaker_states
# ---------------------------------------------------------------------------


def test_list_breaker_states_returns_rows_from_postgres(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Populated ``circuit_breakers`` → ``BreakerStateRow`` dicts.

    Spec §3.2 + §3.3: the helper materialises rows into the shape the
    renderer consumes (``component``, ``state``, ``trip_count``,
    ``last_trip_at``). The renderer code stays unchanged across the
    placeholder → Postgres swap.
    """
    import datetime as dt

    from alfred.cli import supervisor as supervisor_module

    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/test")

    # ORM-row stand-ins; only the column attributes the helper reads matter.
    row_open = MagicMock()
    row_open.component_id = "quarantined-llm"
    row_open.state = "OPEN"
    row_open.trip_count = 3
    row_open.last_trip_at = dt.datetime(2026, 6, 5, 12, 0, 0, tzinfo=dt.UTC)
    row_closed = MagicMock()
    row_closed.component_id = "web-fetch"
    row_closed.state = "CLOSED"
    row_closed.trip_count = 0
    row_closed.last_trip_at = None

    fake_session = MagicMock()
    # ``session.execute(select(...)).scalars().all()`` is the read shape.
    fake_session.execute.return_value.scalars.return_value.all.return_value = [
        row_open,
        row_closed,
    ]
    fake_session_cm = MagicMock()
    fake_session_cm.__enter__.return_value = fake_session
    fake_session_cm.__exit__.return_value = False
    fake_sessionmaker = MagicMock(return_value=fake_session_cm)

    fake_engine = MagicMock()

    with (
        patch.object(supervisor_module, "create_engine", return_value=fake_engine),
        patch.object(supervisor_module, "sessionmaker", return_value=fake_sessionmaker),
    ):
        rows = supervisor_module._list_breaker_states()

    assert rows == [
        {
            "component": "quarantined-llm",
            "state": "OPEN",
            "trip_count": 3,
            "last_trip_at": dt.datetime(2026, 6, 5, 12, 0, 0, tzinfo=dt.UTC),
        },
        {
            "component": "web-fetch",
            "state": "CLOSED",
            "trip_count": 0,
            "last_trip_at": None,
        },
    ]
    # Engine is disposed when the helper exits.
    fake_engine.dispose.assert_called_once()


def test_list_breaker_states_returns_empty_on_empty_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty ``circuit_breakers`` → empty list (caller renders the empty hint).

    The empty-list disposition is the `no_components_yet` operator
    surface; it is materially distinct from `postgres_unavailable` (which
    fails closed with exit 1).
    """
    from alfred.cli import supervisor as supervisor_module

    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/test")

    fake_session = MagicMock()
    fake_session.execute.return_value.scalars.return_value.all.return_value = []
    fake_session_cm = MagicMock()
    fake_session_cm.__enter__.return_value = fake_session
    fake_session_cm.__exit__.return_value = False
    fake_sessionmaker = MagicMock(return_value=fake_session_cm)
    fake_engine = MagicMock()

    with (
        patch.object(supervisor_module, "create_engine", return_value=fake_engine),
        patch.object(supervisor_module, "sessionmaker", return_value=fake_sessionmaker),
    ):
        assert supervisor_module._list_breaker_states() == []
    fake_engine.dispose.assert_called_once()


def test_list_breaker_states_propagates_operational_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``OperationalError`` from the session context propagates to the caller.

    The CLI handler catches the exception and routes it through the
    ``postgres_unavailable`` catalog key. Pin the typed propagation so a
    future refactor cannot swallow connection-failure shapes inside
    ``_list_breaker_states``.
    """
    from alfred.cli import supervisor as supervisor_module

    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/test")

    fake_session_cm = MagicMock()
    fake_session_cm.__enter__.side_effect = OperationalError(
        "SELECT 1", {}, Exception("connection refused")
    )
    fake_sessionmaker = MagicMock(return_value=fake_session_cm)
    fake_engine = MagicMock()

    with (
        patch.object(supervisor_module, "create_engine", return_value=fake_engine),
        patch.object(supervisor_module, "sessionmaker", return_value=fake_sessionmaker),
        pytest.raises(OperationalError),
    ):
        supervisor_module._list_breaker_states()
    # Engine MUST still be disposed even on the failure path.
    fake_engine.dispose.assert_called_once()


def test_list_breaker_states_falls_back_to_settings_default_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No ``DATABASE_URL`` → resolved Settings default + driver rewrite.

    CR-156 (#154 round-7 BLOCKER #1): ``_resolve_database_url`` now
    consults :func:`load_settings_or_die`, which returns the Settings
    default ``postgresql+asyncpg://alfred:alfred@localhost:5432/alfred``
    when no env var is set. The resolver rewrites that to the
    sync-driver shape (``+psycopg``) before SQLAlchemy sees it. Pin
    the URL the engine is built against so the rewrite contract is
    locked at the call boundary.
    """
    from alfred.cli import supervisor as supervisor_module

    monkeypatch.delenv("ALFRED_DATABASE_URL", raising=False)
    fake_engine = MagicMock()
    fake_session = MagicMock()
    fake_session.execute.return_value.scalars.return_value.all.return_value = []
    fake_session_cm = MagicMock()
    fake_session_cm.__enter__.return_value = fake_session
    fake_session_cm.__exit__.return_value = False
    fake_sessionmaker = MagicMock(return_value=fake_session_cm)

    captured_urls: list[str] = []

    def _capture_create_engine(url: str, **_: object) -> MagicMock:
        captured_urls.append(url)
        return fake_engine

    with (
        patch.object(supervisor_module, "create_engine", side_effect=_capture_create_engine),
        patch.object(supervisor_module, "sessionmaker", return_value=fake_sessionmaker),
    ):
        supervisor_module._list_breaker_states()

    assert captured_urls, "create_engine was not invoked"
    # The Settings-default async URL is rewritten to the sync-psycopg
    # shape before SQLAlchemy sees it.
    assert "+psycopg" in captured_urls[0]
    assert "+asyncpg" not in captured_urls[0]


# ---------------------------------------------------------------------------
# supervisor_status handler arms
# ---------------------------------------------------------------------------


def test_status_renders_rows_from_postgres(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The status command renders rows + the spec §11.3 freshness footer.

    The footer is the operator-visible expression of the freshness
    contract (CR-156 round-7 MEDIUM #14 / docs/runbooks/slice-3-supervisor.md):
    a row reflects the supervisor's last ``save_to_db`` write, typically
    <=1 second old. Pinning the footer in the happy path here means a
    regression that drops the footer line from the renderer surfaces
    loud, instead of silently breaking the contract on a T1 surface.
    """
    from alfred.i18n import t

    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/test")
    rows = [
        {
            "component": "quarantined-llm",
            "state": "OPEN",
            "trip_count": 3,
            "last_trip_at": None,
        },
        {
            "component": "web-fetch",
            "state": "CLOSED",
            "trip_count": 0,
            "last_trip_at": None,
        },
    ]
    with patch("alfred.cli.supervisor._list_breaker_states", return_value=rows):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "quarantined-llm" in result.output
    assert "web-fetch" in result.output
    assert t("cli.supervisor.status.freshness_footer") in result.output


def test_status_postgres_unavailable_on_operational_error(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``OperationalError`` from the read path → ``postgres_unavailable`` + exit 1.

    Spec §2.1 failure table: ``DATABASE_URL`` unset OR Postgres
    unreachable both surface through the same operator-targeted key.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/test")
    op_err = OperationalError("SELECT 1", {}, Exception("connection refused"))
    with patch(
        "alfred.cli.supervisor._list_breaker_states",
        side_effect=op_err,
    ):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    # Operator hint mentions Postgres + suggests checking the stack.
    assert "Postgres" in combined or "postgres" in combined.lower()


def test_status_postgres_unavailable_when_runtime_error_from_resolver(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defensive RuntimeError arm: any RuntimeError from the read path
    routes through ``postgres_unavailable`` + exit 1.

    CR-156 (#154 round-7 BLOCKER #1): the resolver no longer raises
    on missing ``DATABASE_URL`` (Settings has a default; the rewrite
    routes through ``sync_db_url``). The handler arm survives as a
    defensive net for any other RuntimeError shape that bubbles out
    of the read path — Settings construction failures route through
    :func:`load_settings_or_die`'s ``typer.Exit(2)`` instead, so the
    arm catches the residual "something went wrong below the typed
    OperationalError envelope" surface.
    """
    monkeypatch.delenv("ALFRED_DATABASE_URL", raising=False)
    with patch(
        "alfred.cli.supervisor._list_breaker_states",
        side_effect=RuntimeError("unexpected read failure"),
    ):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "Postgres" in combined or "postgres" in combined.lower()


def test_status_routes_programming_error_to_schema_not_initialised(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ProgrammingError`` from the read path → ``schema_not_initialised`` + exit 1.

    CR-156 round-7 BLOCKER #4: the only realistic operator scenario for
    ``ProgrammingError`` is the un-migrated database — ``circuit_breakers``
    does not exist yet. The handler arm surfaces a localised hint naming
    the remediation (``alfred-stack migrate`` / ``alembic upgrade head``)
    rather than letting a raw SQLAlchemy traceback hit the operator
    surface. CLAUDE.md hard rule #7 forbids silent failure on T1
    surfaces; this is the loud, actionable failure shape.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/test")
    prog_err = ProgrammingError("SELECT * FROM circuit_breakers", {}, Exception("UndefinedTable"))
    with patch(
        "alfred.cli.supervisor._list_breaker_states",
        side_effect=prog_err,
    ):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    # The remediation vocabulary surfaces — operator can act on it.
    assert "migrate" in combined.lower() or "alembic" in combined.lower()


def test_status_no_components_yet_on_empty_rows(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty ``circuit_breakers`` → ``no_components_yet`` + exit 0.

    The empty-state hint exits 0 — the supervisor exists, the read path
    works, there's just nothing to render yet. Operator action is to
    wait, not to investigate.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/test")
    with patch("alfred.cli.supervisor._list_breaker_states", return_value=[]):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    combined = result.output or ""
    # The catalog body uses "No supervised components" or "components"
    # in the localised body.
    assert "components" in combined.lower() or "no " in combined.lower()


def test_status_renders_all_three_breaker_states_with_unknown(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OPEN / CLOSED / HALF_OPEN / unknown each route through the localised label.

    CR-149 round-3: an unknown enum value renders the explicit
    ``UNKNOWN`` label rather than silently masquerading as CLOSED. The
    Postgres swap MUST preserve this contract.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/test")
    rows = [
        {
            "component": "comp-open",
            "state": "OPEN",
            "trip_count": 3,
            "last_trip_at": "2026-05-31T10:00:00Z",
        },
        {
            "component": "comp-closed",
            "state": "CLOSED",
            "trip_count": 0,
            "last_trip_at": None,
        },
        {
            "component": "comp-half",
            "state": "HALF_OPEN",
            "trip_count": 1,
            "last_trip_at": "2026-05-31T11:00:00Z",
        },
        {
            "component": "comp-unknown",
            "state": "BOGUS",
            "trip_count": 0,
            "last_trip_at": None,
        },
    ]
    with patch("alfred.cli.supervisor._list_breaker_states", return_value=rows):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "comp-open" in result.output
    assert "comp-closed" in result.output
    assert "comp-half" in result.output
    assert "comp-unknown" in result.output
    assert "BOGUS" not in result.output
    assert "UNKNOWN" in result.output
