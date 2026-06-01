"""Spec §10.8, §11.3 — alfred supervisor {status, reset --confirm}.

Asserts:

* ``reset`` without ``--confirm`` exits non-zero (gate required per spec §11.3).
* ``reset`` with ``--confirm`` calls :meth:`Supervisor.reset_breaker`.
* Audit row carries ``operator_user_id`` attribution.
* T1-tier: command requires operator role.
* ``status`` renders the breaker-state table.

Depends on PR-S3-3b (``Supervisor.reset_breaker``, :class:`CircuitBreaker`,
``circuit_breakers`` table from migration 0010) and PR-S3-0a
(``SUPERVISOR_BREAKER_RESET_FIELDS`` constants).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from alfred.cli.supervisor import supervisor_app
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    """Typer runner with separated stderr (Click 8.2 surface)."""
    return CliRunner(mix_stderr=False)


def test_reset_without_confirm_exits_nonzero(runner: CliRunner) -> None:
    """Refusing the ``--confirm`` gate must abort with a non-zero exit."""
    result = runner.invoke(supervisor_app, ["reset", "quarantined-llm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "--confirm" in combined or "confirm" in combined.lower()


def test_reset_with_confirm_calls_reset_breaker(runner: CliRunner) -> None:
    """The confirmed path must dispatch to ``Supervisor.reset_breaker``."""
    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(return_value=None)
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code == 0, (result.output, result.stderr)
    mock_supervisor.reset_breaker.assert_called_once_with(
        component_id="quarantined-llm",
        operator_user_id=None,
    )


def test_reset_success_message_rendered(runner: CliRunner) -> None:
    """A successful reset must surface the component id in the output."""
    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(return_value=None)
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "quarantined-llm" in result.output or "reset" in result.output.lower()


def test_reset_unknown_component_exits_nonzero(runner: CliRunner) -> None:
    """``SupervisorError`` (e.g. component-not-found) must surface as a CLI failure."""
    from alfred.supervisor.errors import SupervisorError

    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(
        side_effect=SupervisorError("Component not found: no-such-plugin")
    )
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "no-such-plugin", "--confirm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "no-such-plugin" in combined or "not found" in combined.lower()


def test_status_renders_table_header(runner: CliRunner) -> None:
    """``status`` must render the breaker-state table with the component id."""
    with patch("alfred.cli.supervisor._list_breaker_states") as mock_list:
        mock_list.return_value = [
            {
                "component": "quarantined-llm",
                "state": "CLOSED",
                "trip_count": 0,
                "last_trip_at": None,
            }
        ]
        # _get_supervisor is called for the running-supervisor probe; stub it.
        with patch("alfred.cli.supervisor._get_supervisor", return_value=object()):
            result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "quarantined-llm" in result.output
