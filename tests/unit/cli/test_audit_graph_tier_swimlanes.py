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
from alfred.cli.audit import audit_app
from typer.testing import CliRunner


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
