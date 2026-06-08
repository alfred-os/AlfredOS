"""Unit tests for ``alfred supervisor proposals`` — Task 9 of #171.

Operator visibility surface per ADR-0021 §Operator visibility:

* ``alfred supervisor proposals`` — table of processed_proposals rows
  (proposal_type, proposal_id, result, failure_kind, operator_user_id,
  processed_at).
* ``alfred supervisor proposals --since DURATION`` (default 1h) — scope
  by processed_at window. CR rework round-1 HIGH #13 replaced the
  binary ``--recent`` flag.
* ``alfred supervisor proposals --limit N`` (default 20) — bound the
  row count; ``--all`` escape hatch removes both filters.

The CLI is synchronous (Typer) so the read goes through a sync
SQLAlchemy engine bound to ``Settings.database_url`` (same pattern as
``alfred supervisor status``). Tests inject the list-helper to avoid
spinning up Postgres for the unit tier.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
from typer.testing import CliRunner

from alfred.cli.supervisor import supervisor_app


@pytest.fixture(autouse=True)
def _settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Satisfy Settings construction."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test-key-not-placeholder")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


@pytest.fixture()
def runner() -> CliRunner:
    """Typer runner — Click 8.2 separates stdout/stderr by default."""
    return CliRunner()


def _row(
    *,
    proposal_type: str = "breaker-reset",
    proposal_id: str = "abc",
    result: str = "applied",
    failure_kind: str | None = None,
    operator_user_id: str | None = "operator-1",
    processed_at: dt.datetime | None = None,
) -> dict[str, Any]:
    """Build a renderer row dict shaped like _list_proposals would return."""
    return {
        "proposal_type": proposal_type,
        "proposal_id": proposal_id,
        "result": result,
        "failure_kind": failure_kind,
        "operator_user_id": operator_user_id,
        "processed_at": processed_at or dt.datetime(2026, 6, 5, 12, 0, 0, tzinfo=dt.UTC),
    }


# ---------------------------------------------------------------------------
# Subcommand surface
# ---------------------------------------------------------------------------


def test_proposals_subcommand_registered_on_supervisor_app(runner: CliRunner) -> None:
    """``alfred supervisor proposals --help`` resolves without error."""
    result = runner.invoke(supervisor_app, ["proposals", "--help"])
    assert result.exit_code == 0, (result.output, result.stderr)


def test_proposals_subcommand_renders_columns(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The table includes proposal_type, proposal_id, result, failure_kind,
    operator_user_id, processed_at columns.
    """
    monkeypatch.setattr(
        "alfred.cli.supervisor._list_proposals",
        lambda *, since=None, limit=None: [_row()],
    )
    result = runner.invoke(supervisor_app, ["proposals"])
    assert result.exit_code == 0, (result.output, result.stderr)
    out = result.output
    # The per-row content lands.
    assert "breaker-reset" in out
    assert "abc" in out
    assert "applied" in out
    assert "operator-1" in out


def test_proposals_subcommand_renders_legend(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR rework round-1 HIGH #13: legend explains the closed result vocab."""
    monkeypatch.setattr(
        "alfred.cli.supervisor._list_proposals",
        lambda *, since=None, limit=None: [_row()],
    )
    result = runner.invoke(supervisor_app, ["proposals"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "Result values" in result.output
    assert "failed_handler" in result.output


def test_proposals_subcommand_renders_uppercase_headers(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR rework round-1 HIGH #13: uppercase headers (TYPE / ID / ...)."""
    monkeypatch.setattr(
        "alfred.cli.supervisor._list_proposals",
        lambda *, since=None, limit=None: [_row()],
    )
    result = runner.invoke(supervisor_app, ["proposals"])
    assert result.exit_code == 0, (result.output, result.stderr)
    for header in ("TYPE", "ID", "RESULT", "FAILURE", "OPERATOR", "PROCESSED AT"):
        assert header in result.output, f"header {header!r} missing"


def test_proposals_subcommand_renders_failure_kind_for_failed_row(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed_handler row shows failure_kind in the table."""
    monkeypatch.setattr(
        "alfred.cli.supervisor._list_proposals",
        lambda *, since=None, limit=None: [
            _row(
                result="failed_handler",
                failure_kind="component_id_not_registered",
            )
        ],
    )
    result = runner.invoke(supervisor_app, ["proposals"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "failed_handler" in result.output
    assert "component_id_not_registered" in result.output


def test_proposals_subcommand_since_threads_through_as_timedelta(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR rework round-1 HIGH #13: ``--since 24h`` resolves to a 24-hour delta."""
    captured: dict[str, Any] = {}

    def _capture(*, since: dt.timedelta | None = None, limit: int | None = None) -> list[Any]:
        captured["since"] = since
        captured["limit"] = limit
        return []

    monkeypatch.setattr("alfred.cli.supervisor._list_proposals", _capture)

    runner.invoke(supervisor_app, ["proposals", "--since", "24h"])
    assert captured.get("since") == dt.timedelta(hours=24)


def test_proposals_subcommand_since_default_is_one_hour(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default ``--since 1h`` preserves the previous ``--recent`` semantic."""
    captured: dict[str, Any] = {}

    def _capture(*, since: dt.timedelta | None = None, limit: int | None = None) -> list[Any]:
        captured["since"] = since
        return []

    monkeypatch.setattr("alfred.cli.supervisor._list_proposals", _capture)

    runner.invoke(supervisor_app, ["proposals"])
    assert captured.get("since") == dt.timedelta(hours=1)


def test_proposals_subcommand_all_passes_none_for_since_and_limit(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--all`` clears both ``--since`` and ``--limit`` for forensic export."""
    captured: dict[str, Any] = {}

    def _capture(*, since: dt.timedelta | None = None, limit: int | None = None) -> list[Any]:
        captured["since"] = since
        captured["limit"] = limit
        return []

    monkeypatch.setattr("alfred.cli.supervisor._list_proposals", _capture)

    runner.invoke(supervisor_app, ["proposals", "--all"])
    assert captured.get("since") is None
    assert captured.get("limit") is None


def test_proposals_subcommand_limit_threads_through(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--limit 5`` threads through to the helper."""
    captured: dict[str, Any] = {}

    def _capture(*, since: dt.timedelta | None = None, limit: int | None = None) -> list[Any]:
        captured["limit"] = limit
        return []

    monkeypatch.setattr("alfred.cli.supervisor._list_proposals", _capture)
    runner.invoke(supervisor_app, ["proposals", "--limit", "5"])
    assert captured.get("limit") == 5


def test_proposals_subcommand_rejects_malformed_since(runner: CliRunner) -> None:
    """A malformed ``--since`` exits non-zero via the parser refusal."""
    result = runner.invoke(supervisor_app, ["proposals", "--since", "notaduration"])
    assert result.exit_code != 0


def test_proposals_subcommand_rejects_zero_since(runner: CliRunner) -> None:
    """``--since 0h`` is rejected — duration must be positive."""
    result = runner.invoke(supervisor_app, ["proposals", "--since", "0h"])
    assert result.exit_code != 0


def test_proposals_subcommand_empty_renders_localised_message(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty result set renders a localised 'no proposals yet' body."""
    monkeypatch.setattr(
        "alfred.cli.supervisor._list_proposals",
        lambda *, since=None, limit=None: [],
    )
    # ALFRED_DEEPSEEK_API_KEY + ALFRED_ENVIRONMENT are already set by the
    # autouse ``_settings_env`` fixture; no redundant setup here (CR #13).
    result = runner.invoke(supervisor_app, ["proposals"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "proposals" in result.output.lower()
    # Empty body now names the dispatch-cycle interval.
    assert "30" in result.output


# ---------------------------------------------------------------------------
# Status footer
# ---------------------------------------------------------------------------


def test_supervisor_status_renders_proposal_dispatch_footer(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The status command's footer reports recent-dispatch counts.

    ADR-0021 §Operator visibility: counts of applied / failed proposals
    from the last hour. CR rework round-1 HIGH #11: pending was always
    0 and lied to the operator; dropped from the surface.
    """
    monkeypatch.setattr("alfred.cli.supervisor._list_breaker_states", list)
    monkeypatch.setattr(
        "alfred.cli.supervisor._recent_dispatch_counts",
        lambda: {"applied": 3, "failed": 1},
    )
    result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    # The recent-dispatch numbers surface in the footer.
    assert "3" in result.output
    assert "1" in result.output
    # ``pending`` was dropped — the footer must NOT mention it.
    assert "pending" not in result.output.lower()


def test_supervisor_status_renders_recent_dispatch_zero_counts(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Footer renders even when every count is zero."""
    monkeypatch.setattr("alfred.cli.supervisor._list_breaker_states", list)
    monkeypatch.setattr(
        "alfred.cli.supervisor._recent_dispatch_counts",
        lambda: {"applied": 0, "failed": 0},
    )
    result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    # The footer label still renders (we're not gating on non-zero counts).
    assert "dispatch" in result.output.lower() or "proposal" in result.output.lower()


def test_supervisor_status_dispatch_footer_routes_postgres_outage_to_localised_hint(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR rework round-1 HIGH #12: OperationalError emits the unavailable hint.

    The breaker-table contract still holds (status exits 0); only the
    footer surface lands the unavailability message on stderr.
    """
    from sqlalchemy.exc import OperationalError

    def _boom() -> dict[str, int]:
        raise OperationalError("cannot connect", {}, None)

    monkeypatch.setattr("alfred.cli.supervisor._list_breaker_states", list)
    monkeypatch.setattr("alfred.cli.supervisor._recent_dispatch_counts", _boom)

    result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    combined = (result.output or "") + (result.stderr or "")
    assert "unavailable" in combined.lower()


def test_supervisor_status_dispatch_footer_propagates_unknown_error(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR rework round-1 HIGH #12: non-narrowed exceptions propagate loudly."""

    def _boom() -> dict[str, int]:
        raise RuntimeError("programmer bug")

    monkeypatch.setattr("alfred.cli.supervisor._list_breaker_states", list)
    monkeypatch.setattr("alfred.cli.supervisor._recent_dispatch_counts", _boom)

    result = runner.invoke(supervisor_app, ["status"])
    # CLAUDE.md hard rule #7: unknown error is loud, not silently swallowed.
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Proposals subcommand failure-mode dispatch
# ---------------------------------------------------------------------------


def test_proposals_subcommand_routes_operational_error_to_localised_hint(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OperationalError → postgres_unavailable hint + exit 1."""
    from sqlalchemy.exc import OperationalError

    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise OperationalError("cannot connect", {}, None)

    monkeypatch.setattr("alfred.cli.supervisor._list_proposals", _raise)
    result = runner.invoke(supervisor_app, ["proposals"])
    assert result.exit_code == 1, (result.output, result.stderr)
    combined = (result.output or "") + (result.stderr or "")
    assert "postgres" in combined.lower() or "database" in combined.lower()


def test_proposals_subcommand_routes_programming_error_to_localised_hint(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ProgrammingError → schema_not_initialised hint + exit 1."""
    from sqlalchemy.exc import ProgrammingError

    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise ProgrammingError("relation does not exist", {}, None)

    monkeypatch.setattr("alfred.cli.supervisor._list_proposals", _raise)
    result = runner.invoke(supervisor_app, ["proposals"])
    assert result.exit_code == 1, (result.output, result.stderr)
    combined = (result.output or "") + (result.stderr or "")
    assert "migrate" in combined.lower() or "alembic" in combined.lower()
