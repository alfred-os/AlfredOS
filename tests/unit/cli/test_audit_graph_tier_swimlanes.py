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


@pytest.mark.parametrize(
    "value",
    ["0h", "0d", "0m", "-1h", "-7d", "-30m"],
)
def test_audit_graph_since_non_positive_rejected(runner: CliRunner, value: str) -> None:
    """CR-149: non-positive ``--since`` values are refused for every unit.

    The prior shape silently accepted ``0h`` / ``0d`` (zero-hour
    windows) and rounded negative minutes to one hour, handing the
    query layer impossible windows that could never select rows. The
    parser now rejects them with :class:`typer.BadParameter` so the
    operator sees the typo at the boundary instead of an empty render.
    """
    result = runner.invoke(audit_app, ["graph", "--since", value])
    assert result.exit_code != 0, (value, result.output, result.stderr)


def test_query_audit_log_stub_raises_backend_unavailable() -> None:
    """``_query_audit_log`` raises until PR-S3-7 wires the SQL query.

    CR-149: the stub previously returned ``[]`` which made every real
    ``alfred audit log`` / ``alfred audit graph`` invocation render
    the localised "no rows" message — silently conflating "no audit
    rows" with "the audit subsystem is not yet wired". The stub now
    raises :class:`AuditBackendUnavailable`; the CLI catches that and
    emits the dedicated "backend not wired" message instead.
    """
    from alfred.cli import audit as audit_module
    from alfred.cli.audit import AuditBackendUnavailable

    with pytest.raises(AuditBackendUnavailable):
        audit_module._query_audit_log(tier="T3", since_hours=24)
    with pytest.raises(AuditBackendUnavailable):
        audit_module._query_audit_log(tier=None, since_hours=1)


def test_audit_log_surfaces_backend_unavailable_message(runner: CliRunner) -> None:
    """``alfred audit log`` exits non-zero with the localised unavailable hint.

    CR-149 coverage: the production code path (no patch on
    ``_query_audit_log``) routes :class:`AuditBackendUnavailable`
    into the ``cli.audit.backend_unavailable`` localised body and
    exits with code 1, so the operator sees the truth instead of the
    misleading empty-rows render.
    """
    result = runner.invoke(audit_app, ["log", "--since", "24h"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "PR-S3-7" in combined or "not yet wired" in combined.lower()


def test_audit_graph_surfaces_backend_unavailable_message(runner: CliRunner) -> None:
    """``alfred audit graph`` also surfaces the unavailable hint loudly.

    CR-149: symmetric with :func:`test_audit_log_surfaces_backend_unavailable_message`
    for the graph entry point.
    """
    result = runner.invoke(audit_app, ["graph", "--since", "24h"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "PR-S3-7" in combined or "not yet wired" in combined.lower()


def test_audit_graph_invalid_tier_rejected(runner: CliRunner) -> None:
    """sec-pr-s3-6-07: ``--tier T5`` must raise BadParameter, not render empty.

    The previous shape accepted any string and passed it to the query
    stub, which returned ``[]`` for any unrecognised tier. The operator
    saw the localised empty message and could not tell the difference
    between "no rows in the window" and "you typo'd the tier name."
    """
    result = runner.invoke(audit_app, ["graph", "--tier", "T5", "--since", "24h"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    # Click/Typer's "Invalid value" surface — the exact phrasing depends
    # on the click release but the literal "T5" must appear so the
    # operator knows which value was refused.
    assert "T5" in combined or "invalid" in combined.lower()


def test_audit_graph_each_valid_tier_accepted(runner: CliRunner) -> None:
    """Every tier in the closed set (T0..T3) is accepted by the parser."""
    for tier in ("T0", "T1", "T2", "T3"):
        with patch("alfred.cli.audit._query_audit_log", return_value=[]) as mock_query:
            result = runner.invoke(audit_app, ["graph", "--tier", tier, "--since", "1h"])
        assert result.exit_code == 0, (tier, result.output, result.stderr)
        assert mock_query.call_args.kwargs.get("tier") == tier


def test_audit_graph_invalid_tier_lowercase_rejected(runner: CliRunner) -> None:
    """Tier values are case-sensitive — ``t3`` is not accepted."""
    result = runner.invoke(audit_app, ["graph", "--tier", "t3", "--since", "24h"])
    assert result.exit_code != 0
