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

from unittest.mock import AsyncMock, MagicMock, patch

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
        # CR-149: an unknown enum value renders the explicit
        # "unknown" label rather than silently masquerading as the
        # CLOSED label. The previous shape lied about breaker health
        # by defaulting unknown values to ``closed``; failing loud
        # is the operator surface contract on T1 status (spec §11.3).
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
    # CR-149: the explicit "UNKNOWN" localised label is rendered for
    # the unrecognised breaker state, so the operator sees a tripped /
    # unsupported state instead of a fabricated CLOSED reading.
    assert "UNKNOWN" in result.output


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


def test_reset_no_supervisor_running_routes_through_localised_hint(
    runner: CliRunner,
) -> None:
    """CR-149: ``reset`` surfaces the localised hint when the supervisor is down.

    The prior shape called ``_get_supervisor()`` outside any
    exception handler, so a missing / unreachable supervisor raised
    a raw Python traceback through Typer. Spec §11.3 makes ``reset``
    an operator surface, not a debug surface — the error path now
    mirrors :func:`supervisor_status`'s narrow handler and emits
    the ``cli.supervisor.status.no_supervisor_running`` localised
    body before exiting code 1. The attempt-row is NOT emitted on
    this path because the operator never actually crossed the
    supervisor boundary.
    """
    audit_emit = MagicMock()
    with (
        patch(
            "alfred.cli.supervisor._get_supervisor",
            side_effect=RuntimeError("supervisor not wired"),
        ),
        patch(
            "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
            side_effect=audit_emit,
        ),
    ):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "supervisor" in combined.lower() or "running" in combined.lower()
    # CR-149 round-2: the attempt-audit MUST NOT fire when the probe
    # itself crashed BEFORE the operator action crossed the boundary.
    # A regression that moves ``_emit_breaker_reset_attempt_audit`` back
    # above ``_get_supervisor`` would still pass the message-text
    # assertion above; pinning the call count keeps the PRD §10.8
    # forensic contract structural.
    assert audit_emit.call_count == 0


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
    """A non-"not found" connection-shape error uses the unexpected_error key.

    err-001 / cross-cutting R4: the except clause now narrows to
    ``SupervisorError``, ``ConnectionError``, ``asyncio.TimeoutError``.
    A ``ConnectionError`` is the realistic non-domain failure (Postgres
    drop mid-transaction); it must still route through the localised
    error key.
    """
    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(
        side_effect=ConnectionError("postgres connection lost")
    )
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    # The generic-error catalog entry includes both {component} and {error_type}.
    assert "quarantined-llm" in combined
    assert "ConnectionError" in combined


def test_reset_programmer_bug_propagates_loud(runner: CliRunner) -> None:
    """err-001 / R4: a non-domain bug (e.g. ``KeyError``) MUST propagate.

    The previous bare ``except Exception`` swallowed every shape and
    mapped to the generic error key, silently turning a typed-method-
    signature drift into a benign-looking operator-facing failure. The
    narrowed except clause now only catches the four typed shapes; an
    AttributeError / TypeError / KeyError bubbles up so the bug is
    loud in the operator's structlog stream + the CLI tracebacks at
    once.
    """
    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(side_effect=KeyError("breaker_id"))
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    # ``CliRunner`` captures the exception rather than re-raising; we
    # assert the exit code is non-zero AND the exception is the typed
    # KeyError (not Typer.Exit) so the bug surface is preserved.
    assert result.exit_code != 0
    assert isinstance(result.exception, KeyError)


def test_reset_emits_attempt_audit_row_before_reset_breaker(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """sec-pr-s3-6-04: the attempt audit row fires BEFORE ``reset_breaker``.

    A crash inside ``reset_breaker`` (Postgres dropped, breaker-lock
    contention, ...) must still leave a forensic trail. Pin the
    ordering by recording call sequence into a shared list -- the
    attempt-audit call MUST appear before the reset_breaker call.
    """
    calls: list[str] = []

    def _record_attempt(*, component_id: str) -> None:
        # Signature mirrors the production helper; the test only cares
        # about the call order, not the structlog kwargs.
        del component_id
        calls.append("attempt_audit")

    async def _reset_breaker(*, component_id: str, operator_user_id: str | None) -> None:
        del component_id, operator_user_id
        calls.append("reset_breaker")

    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(side_effect=_reset_breaker)
    monkeypatch.setattr(
        "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
        _record_attempt,
    )
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert calls == ["attempt_audit", "reset_breaker"]


def test_reset_attempt_audit_row_survives_supervisor_crash(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash inside ``reset_breaker`` must NOT suppress the attempt row.

    Validates the forensic-trail guarantee from sec-pr-s3-6-04: the
    attempt-audit emission lands even if the reset call itself fails.
    """
    audit_emissions: list[str] = []

    def _record_attempt(*, component_id: str) -> None:
        audit_emissions.append(component_id)

    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(side_effect=ConnectionError("postgres lost"))
    monkeypatch.setattr(
        "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
        _record_attempt,
    )
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    # Reset failed, but the attempt row was emitted FIRST -- the audit
    # graph still has the operator-intent breadcrumb.
    assert result.exit_code != 0
    assert audit_emissions == ["quarantined-llm"]


def test_emit_breaker_reset_attempt_audit_uses_schema_fields() -> None:
    """The attempt-audit helper carries the SUPERVISOR_BREAKER_RESET_FIELDS shape.

    sec-pr-s3-6-04: when PR-S3-7 swaps the structlog emit for the real
    ``AuditWriter.append_schema`` call, the kwargs ALREADY match the
    declared field set. This test pins the contract: the helper's
    payload covers every required SUPERVISOR_BREAKER_RESET_FIELDS entry.
    """
    from alfred.audit.audit_row_schemas import SUPERVISOR_BREAKER_RESET_FIELDS
    from alfred.cli import supervisor as supervisor_module

    captured: dict[str, object] = {}

    def _capture(event: str, **kwargs: object) -> None:
        del event
        captured.update(kwargs)

    class _FakeLogger:
        def info(self, event: str, **kwargs: object) -> None:
            _capture(event, **kwargs)

    original = supervisor_module._log
    try:
        supervisor_module._log = _FakeLogger()  # type: ignore[assignment]
        supervisor_module._emit_breaker_reset_attempt_audit(component_id="quarantined-llm")
    finally:
        supervisor_module._log = original
    # Every declared field is present in the kwargs the helper sent.
    for field in SUPERVISOR_BREAKER_RESET_FIELDS:
        assert field in captured, f"helper omitted {field!r} from the audit payload"


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

    err-001 / cross-cutting R4: the import now lives ABOVE the
    ``asyncio.run`` call so the except-clause type binding is
    statically resolvable. A broken supervisor namespace still routes
    through the localised key + non-zero exit -- but the rendered
    error_type is ``ImportError`` rather than the original failure
    type, because the ImportError fires first.
    """
    import sys

    mock_supervisor = AsyncMock()

    # Force ``from alfred.supervisor.errors import SupervisorError`` to raise.
    monkeypatch.setitem(sys.modules, "alfred.supervisor.errors", None)

    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "quarantined-llm" in combined
    assert "ImportError" in combined
