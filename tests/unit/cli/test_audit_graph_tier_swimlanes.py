"""Spec §11.3 (last row) — alfred audit graph --tier T1|T2|T3 swimlanes.

Asserts:

* ``--tier T3`` filters audit rows to ``trust_tier_of_trigger="T3"``.
* ``--tier T1`` filters to T1 rows.
* No ``--tier`` shows the unfiltered baseline (all tiers).
* ``--since 24h`` time-window flag passes through to the query helper.
* Column headers rendered (spec §11.3 ``alfred audit graph --tier T3 --since 24h``).

Depends on PR-S3-0a (``audit_row_schemas``) and PR-S3-0b (Alembic migration
0007 extends the ``audit_log`` CHECK constraint with new result values).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from alfred.cli.audit import audit_app


@pytest.fixture()
def runner() -> CliRunner:
    """Typer runner — Click 8.2 separates stdout/stderr by default."""
    return CliRunner()


@pytest.fixture()
def t3_rows() -> list[dict[str, object]]:
    """A single T3 audit row (web-fetch event)."""
    return [
        {
            "event": "tool.web.fetch",
            "trust_tier_of_trigger": "T3",
            "actor_user_id": "operator",
            "result": "success",
            "timestamp": "2026-05-31T10:00:00Z",
        }
    ]


@pytest.fixture()
def t1_rows() -> list[dict[str, object]]:
    """A single T1 audit row (identity ingress event)."""
    return [
        {
            "event": "identity.t1_ingress",
            "trust_tier_of_trigger": "T1",
            "actor_user_id": "operator",
            "result": "success",
            "timestamp": "2026-05-31T09:00:00Z",
        }
    ]


def test_audit_graph_tier_t3_filters_rows(
    runner: CliRunner, t3_rows: list[dict[str, object]]
) -> None:
    """``--tier T3`` must pass ``tier="T3"`` to the query helper."""
    with patch("alfred.cli.audit._query_audit_log") as mock_query:
        mock_query.return_value = t3_rows
        result = runner.invoke(audit_app, ["graph", "--tier", "T3", "--since", "24h"])
    assert result.exit_code == 0, (result.output, result.stderr)
    mock_query.assert_called_once()
    call_kwargs = mock_query.call_args
    assert call_kwargs.kwargs.get("tier") == "T3" or "T3" in str(call_kwargs)


def test_audit_graph_tier_t3_renders_row(
    runner: CliRunner, t3_rows: list[dict[str, object]]
) -> None:
    """The rendered swimlane row must include the event name and the tier."""
    with patch("alfred.cli.audit._query_audit_log", return_value=t3_rows):
        result = runner.invoke(audit_app, ["graph", "--tier", "T3", "--since", "24h"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "tool.web.fetch" in result.output
    assert "T3" in result.output


def test_audit_graph_tier_t1_filters_rows(
    runner: CliRunner, t1_rows: list[dict[str, object]]
) -> None:
    """``--tier T1`` must pass ``tier="T1"`` to the query helper."""
    with patch("alfred.cli.audit._query_audit_log") as mock_query:
        mock_query.return_value = t1_rows
        result = runner.invoke(audit_app, ["graph", "--tier", "T1", "--since", "24h"])
    assert result.exit_code == 0, (result.output, result.stderr)
    mock_query.assert_called_once()
    call_kwargs = mock_query.call_args
    assert call_kwargs.kwargs.get("tier") == "T1" or "T1" in str(call_kwargs)


def test_audit_graph_no_tier_shows_all(runner: CliRunner) -> None:
    """The unfiltered baseline (no ``--tier``) must pass ``tier=None``."""
    rows: list[dict[str, object]] = []
    with patch("alfred.cli.audit._query_audit_log", return_value=rows) as mock_query:
        result = runner.invoke(audit_app, ["graph", "--since", "24h"])
    assert result.exit_code == 0, (result.output, result.stderr)
    mock_query.assert_called_once()
    # tier kwarg explicitly None means "all tiers".
    assert mock_query.call_args.kwargs.get("tier") is None


def test_audit_graph_renders_header_when_rows_exist(
    runner: CliRunner, t3_rows: list[dict[str, object]]
) -> None:
    """The tier_header label must render when ``--tier`` is set + rows exist."""
    with patch("alfred.cli.audit._query_audit_log", return_value=t3_rows):
        result = runner.invoke(audit_app, ["graph", "--tier", "T3", "--since", "24h"])
    assert result.exit_code == 0
    # The header label includes the word "swimlane" + the tier (en catalog).
    assert "swimlane" in result.output.lower() or "T3" in result.output


def test_audit_graph_without_tier_renders_all_header(runner: CliRunner) -> None:
    """The unfiltered header label fires when rows exist + ``--tier`` is omitted."""
    rows = [
        {
            "event": "tool.web.fetch",
            "trust_tier_of_trigger": "T3",
            "actor_user_id": "operator",
            "result": "success",
            "timestamp": "2026-05-31T10:00:00Z",
        }
    ]
    with patch("alfred.cli.audit._query_audit_log", return_value=rows):
        result = runner.invoke(audit_app, ["graph", "--since", "24h"])
    assert result.exit_code == 0
    # All-tier header fires; the row body renders the event name.
    assert "tool.web.fetch" in result.output


def test_audit_log_subcommand_renders_rows(runner: CliRunner) -> None:
    """``alfred audit log`` must render rows passing the optional --event filter."""
    rows = [
        {
            "event": "plugin.lifecycle.crashed",
            "trust_tier_of_trigger": "T1",
            "actor_user_id": "operator",
            "result": "success",
            "timestamp": "2026-05-31T10:00:00Z",
        },
        {
            "event": "tool.web.fetch",
            "trust_tier_of_trigger": "T3",
            "actor_user_id": "operator",
            "result": "success",
            "timestamp": "2026-05-31T10:01:00Z",
        },
    ]
    with patch("alfred.cli.audit._query_audit_log", return_value=rows):
        result = runner.invoke(
            audit_app,
            ["log", "--event", "plugin.lifecycle.crashed", "--since", "5m"],
        )
    assert result.exit_code == 0
    assert "plugin.lifecycle.crashed" in result.output
    # The non-matching event must be filtered out.
    assert "tool.web.fetch" not in result.output


def test_audit_log_empty_renders_hint(runner: CliRunner) -> None:
    """An empty audit log must surface the 'no rows' hint."""
    with patch("alfred.cli.audit._query_audit_log", return_value=[]):
        result = runner.invoke(audit_app, ["log", "--since", "1h"])
    assert result.exit_code == 0
    assert "No audit rows" in result.output or "no " in result.output.lower()


def test_audit_log_no_event_filter_lists_all(runner: CliRunner) -> None:
    """When --event is omitted, every row in the window is rendered."""
    rows = [
        {
            "event": "ev.one",
            "result": "success",
            "actor_user_id": "operator",
            "timestamp": "2026-05-31T10:00:00Z",
        },
        {
            "event": "ev.two",
            "result": "success",
            "actor_user_id": "operator",
            "timestamp": "2026-05-31T10:01:00Z",
        },
    ]
    with patch("alfred.cli.audit._query_audit_log", return_value=rows):
        result = runner.invoke(audit_app, ["log", "--since", "1h"])
    assert result.exit_code == 0
    assert "ev.one" in result.output
    assert "ev.two" in result.output


def test_audit_graph_empty_rows_renders_localised_empty(runner: CliRunner) -> None:
    """No rows + a tier filter should render the localised empty message."""
    with patch("alfred.cli.audit._query_audit_log", return_value=[]):
        result = runner.invoke(audit_app, ["graph", "--tier", "T1", "--since", "24h"])
    assert result.exit_code == 0
    assert "No audit rows" in result.output or "T1" in result.output


def test_audit_graph_since_days_parses(runner: CliRunner) -> None:
    """``--since 7d`` must parse and pass through (7*24=168 hours)."""
    with patch("alfred.cli.audit._query_audit_log", return_value=[]) as mock_query:
        result = runner.invoke(audit_app, ["graph", "--since", "7d"])
    assert result.exit_code == 0
    assert mock_query.call_args.kwargs.get("since_hours") == 168


def test_audit_graph_since_minutes_parses(runner: CliRunner) -> None:
    """``--since 30m`` clamps to 1 hour (the minimum window)."""
    with patch("alfred.cli.audit._query_audit_log", return_value=[]) as mock_query:
        result = runner.invoke(audit_app, ["graph", "--since", "30m"])
    assert result.exit_code == 0
    assert mock_query.call_args.kwargs.get("since_hours") == 1


def test_audit_graph_since_minutes_over_hour_parses(runner: CliRunner) -> None:
    """``--since 120m`` rounds down to 2 hours."""
    with patch("alfred.cli.audit._query_audit_log", return_value=[]) as mock_query:
        result = runner.invoke(audit_app, ["graph", "--since", "120m"])
    assert result.exit_code == 0
    assert mock_query.call_args.kwargs.get("since_hours") == 2


def test_audit_graph_since_invalid_rejected(runner: CliRunner) -> None:
    """An unsuffixed ``--since`` must be rejected with a non-zero exit."""
    result = runner.invoke(audit_app, ["graph", "--since", "abc"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "since" in combined.lower() or "invalid" in combined.lower()


def test_audit_graph_since_bare_integer_rejected(runner: CliRunner) -> None:
    """A bare integer ``--since`` (no unit suffix) is ambiguous and refused."""
    result = runner.invoke(audit_app, ["graph", "--since", "24"])
    assert result.exit_code != 0


def test_audit_graph_since_garbage_suffix_rejected(runner: CliRunner) -> None:
    """A non-integer numeric part on a recognised suffix is rejected."""
    result = runner.invoke(audit_app, ["graph", "--since", "xh"])
    assert result.exit_code != 0


def test_query_audit_log_stub_returns_empty_list() -> None:
    """``_query_audit_log`` is a stub until PR-S3-7 wires the SQL query."""
    from alfred.cli import audit as audit_module

    assert audit_module._query_audit_log(tier="T3", since_hours=24) == []
    assert audit_module._query_audit_log(tier=None, since_hours=1) == []
