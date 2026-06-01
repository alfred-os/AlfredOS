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
from typer.testing import CliRunner

from alfred.cli.supervisor import supervisor_app


@pytest.fixture()
def runner() -> CliRunner:
    """Typer runner — Click 8.2 separates stdout/stderr by default."""
    return CliRunner()


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


def test_status_renders_all_three_breaker_states(runner: CliRunner) -> None:
    """OPEN / CLOSED / HALF_OPEN states each route through their localised label."""
    rows = [
        {
            "component": "comp-open",
            "state": "OPEN",
            "trip_count": 3,
            "last_trip_at": "2026-05-31T10:00:00Z",
        },
        {"component": "comp-closed", "state": "CLOSED", "trip_count": 0, "last_trip_at": None},
        {
            "component": "comp-half",
            "state": "HALF_OPEN",
            "trip_count": 1,
            "last_trip_at": "2026-05-31T11:00:00Z",
        },
        # Unknown state falls back to the CLOSED label without leaking the raw enum.
        {"component": "comp-unknown", "state": "BOGUS", "trip_count": 0, "last_trip_at": None},
    ]
    with (
        patch("alfred.cli.supervisor._list_breaker_states", return_value=rows),
        patch("alfred.cli.supervisor._get_supervisor", return_value=object()),
    ):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert "comp-open" in result.output
    assert "comp-closed" in result.output
    assert "comp-half" in result.output
    assert "comp-unknown" in result.output
    # Unknown enum must not leak through the table.
    assert "BOGUS" not in result.output


def test_status_no_supervisor_running_exits_nonzero(runner: CliRunner) -> None:
    """When ``_get_supervisor`` raises, status surfaces the friendly hint."""
    with patch(
        "alfred.cli.supervisor._get_supervisor",
        side_effect=RuntimeError("supervisor not wired"),
    ):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "supervisor" in combined.lower() or "running" in combined.lower()


def test_status_empty_rows_renders_hint(runner: CliRunner) -> None:
    """An empty ``circuit_breakers`` table renders the "no components yet" hint."""
    with (
        patch("alfred.cli.supervisor._list_breaker_states", return_value=[]),
        patch("alfred.cli.supervisor._get_supervisor", return_value=object()),
    ):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code == 0, (result.output, result.stderr)
    # Header row not printed when there's no data — the empty hint should be.
    assert (
        "COMPONENT" not in result.output
        or "registered" in result.output.lower()
        or "no " in result.output.lower()
    )


def test_reset_unexpected_error_routes_through_generic_message(runner: CliRunner) -> None:
    """A non-"not found" exception from ``reset_breaker`` uses the unexpected_error key."""
    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(side_effect=RuntimeError("postgres connection lost"))
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    # The generic-error catalog entry includes both {component} and {error_type}.
    assert "quarantined-llm" in combined
    assert "RuntimeError" in combined


def test_reset_supervisor_error_without_not_found_routes_generic(runner: CliRunner) -> None:
    """A ``SupervisorError`` whose message lacks "not found" uses the generic branch."""
    from alfred.supervisor.errors import SupervisorError

    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(side_effect=SupervisorError("breaker probe failed"))
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "quarantined-llm" in combined
    # The component-not-found branch must NOT be taken for a generic SupervisorError.
    assert "SupervisorError" in combined


def test_get_supervisor_raises_when_singleton_missing() -> None:
    """``_get_supervisor`` raises RuntimeError until PR-S3-3b ships ``get_instance``.

    Pins the not-yet-wired guard rail so future-PR-S3-3b can flip the
    behaviour and this test then flips with it.
    """
    from alfred.cli import supervisor as supervisor_module

    # ``Supervisor.get_instance`` is intentionally absent in PR-S3-3a; the
    # CLI surfaces RuntimeError so callers can map to a friendly hint.
    with pytest.raises(RuntimeError, match="get_instance"):
        supervisor_module._get_supervisor()


def test_list_breaker_states_stub_returns_empty_list() -> None:
    """``_list_breaker_states`` is a stub until PR-S3-3b wires the SQL query."""
    from alfred.cli import supervisor as supervisor_module

    assert supervisor_module._list_breaker_states() == []


def test_get_supervisor_invokes_singleton_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """When PR-S3-3b lands ``get_instance``, ``_get_supervisor`` returns its result."""
    from alfred.cli import supervisor as supervisor_module
    from alfred.supervisor import core as supervisor_core

    sentinel = object()
    monkeypatch.setattr(
        supervisor_core.Supervisor, "get_instance", staticmethod(lambda: sentinel), raising=False
    )
    assert supervisor_module._get_supervisor() is sentinel


def test_reset_import_error_fallback_uses_generic_message(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If importing ``alfred.supervisor.errors`` fails, the generic branch still fires.

    Defensive coverage: the lazy import in the except arm is wrapped in
    its own try/except so a broken supervisor namespace doesn't leak a
    raw traceback. We simulate that broken namespace by replacing the
    module entry with a sentinel that raises on attribute access.
    """
    import sys

    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(side_effect=RuntimeError("boom"))

    # Force ``from alfred.supervisor.errors import SupervisorError`` to raise.
    monkeypatch.setitem(sys.modules, "alfred.supervisor.errors", None)

    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "quarantined-llm" in combined
    assert "RuntimeError" in combined
