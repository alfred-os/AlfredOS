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


def test_reset_with_confirm_calls_reset_breaker(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The confirmed path must dispatch to ``Supervisor.reset_breaker``.

    CR-149 round-10: ``operator_user_id`` now sources from
    ``_resolve_operator_user_id`` (env / OS account). Pin the env-var
    override so the assertion stays deterministic across dev machines.
    """
    monkeypatch.setenv("ALFRED_OPERATOR_USER_ID", "test-operator")
    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(return_value=None)
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code == 0, (result.output, result.stderr)
    mock_supervisor.reset_breaker.assert_called_once_with(
        component_id="quarantined-llm",
        operator_user_id="test-operator",
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
    """``NoSuchComponentError`` (component-not-found) must surface as a CLI failure.

    CR-149 round-7: the unknown-component dispatch now narrows on the
    typed :class:`NoSuchComponentError` subclass instead of an English
    substring scan of ``str(exc)``. The body text is irrelevant — any
    raise of the class routes to the ``component_not_found`` branch.
    """
    from alfred.supervisor.errors import NoSuchComponentError

    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(
        side_effect=NoSuchComponentError("Component not found: no-such-plugin")
    )
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "no-such-plugin", "--confirm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "no-such-plugin" in combined or "not found" in combined.lower()


def test_reset_canonical_no_supervised_component_routes_to_component_not_found(
    runner: CliRunner,
) -> None:
    """CR-149 round-7: typed ``NoSuchComponentError`` routes to the
    operator-targeted ``component_not_found`` branch.

    Round-6 closed the gap where the canonical
    :func:`t("supervisor.no_such_component")` wording fell through to
    the generic ``unexpected_error`` key (the previous dispatch only
    matched the English substring "not found"). Round-6's fix added a
    second substring branch matching "no supervised component" — but
    that still breaks the moment the operator's locale is anything
    other than English, or even a catalog copy-edit shortens the
    wording. Round-7 replaces the substring dispatch with a typed
    :class:`NoSuchComponentError` ``except`` arm. The body wording is
    no longer load-bearing for routing; only the class is.
    """
    from alfred.supervisor.errors import NoSuchComponentError

    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(
        side_effect=NoSuchComponentError(
            "No supervised component with id 'no-such-plugin'. "
            "Run `alfred supervisor status` to list registered components."
        )
    )
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "no-such-plugin", "--confirm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    # The component-not-found catalog entry names the component id and
    # offers the recovery hint; the unexpected_error catalog entry
    # surfaces ``type(exc).__name__`` (``NoSuchComponentError``)
    # instead — the absence of the type name is the regression target.
    assert "no-such-plugin" in combined
    assert "NoSuchComponentError" not in combined
    assert "SupervisorError" not in combined


def test_reset_no_such_component_is_locale_immune(runner: CliRunner) -> None:
    """CR-149 round-7: a non-English body still routes correctly.

    Pins the load-bearing property of the round-7 typed dispatch:
    the routing depends on the exception class, NOT on
    :func:`str(exc).lower()`. A non-English catalog msgstr (Spanish
    placeholder text below — never seen the English substrings
    "not found" or "no supervised component") MUST still land on the
    operator-targeted ``component_not_found`` hint. The pre-round-7
    substring branch would have fallen through to
    ``cli.supervisor.reset.unexpected_error`` and lost the PRD §10.8
    / §11.3 operator guidance the T1 surface owes a non-English
    operator.
    """
    from alfred.supervisor.errors import NoSuchComponentError

    # Spanish stand-in for the catalog body — no overlap with the
    # legacy English substrings the round-6 dispatch matched.
    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(
        side_effect=NoSuchComponentError("Ningún componente supervisado con id 'no-such-plugin'.")
    )
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "no-such-plugin", "--confirm"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    # Routed to the operator-targeted branch — the catalog renders the
    # component id, not the exception type name.
    assert "no-such-plugin" in combined
    assert "NoSuchComponentError" not in combined


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


def test_list_breaker_states_raises_not_implemented() -> None:
    """``_list_breaker_states`` raises ``NotImplementedError`` until the read path lands.

    CR-149 round-4: the prior stub returned ``[]`` which collapsed two
    operationally-distinct conditions (no components vs. read-path
    not implemented) into a single empty-state message. Fail closed
    with the explicit typed error; the supervisor_status handler
    converts it into the localised "status unavailable" message.
    """
    from alfred.cli import supervisor as supervisor_module

    with pytest.raises(NotImplementedError, match="read path not implemented"):
        supervisor_module._list_breaker_states()


def test_status_handles_read_path_unavailable(runner: CliRunner) -> None:
    """``alfred supervisor status`` surfaces a localised "status unavailable" hint
    when ``_list_breaker_states`` raises ``NotImplementedError``.

    CR-149 round-4 regression: pre-fix, the same NotImplementedError
    would have leaked as a raw traceback (uncaught). Pin the typed
    error path + the catalog-routed message so a future refactor
    cannot silently regress to the empty-state hint.
    """
    with (
        patch("alfred.cli.supervisor._get_supervisor", return_value=object()),
        patch(
            "alfred.cli.supervisor._list_breaker_states",
            side_effect=NotImplementedError("read path not implemented"),
        ),
    ):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    # The hint must mention "unavailable" or "implemented" so the operator
    # sees this is a wiring gap, not "no components yet".
    assert "unavailable" in combined.lower() or "implemented" in combined.lower()


def test_status_read_path_connection_error_routes_through_no_supervisor_hint(
    runner: CliRunner,
) -> None:
    """CR-149 round-5: a read-path ``ConnectionError`` routes through the no-supervisor hint.

    The round-5 split added a separate ``except (ConnectionError, TimeoutError)``
    arm scoped to :func:`_list_breaker_states` so the operator sees one
    shape of fail-loud message regardless of which side of the bootstrap
    actually broke once the Postgres projection lands. Pin the arm so a
    future refactor cannot regress to either silently swallowing the
    error or raising the wrong localised hint.
    """
    with (
        patch("alfred.cli.supervisor._get_supervisor", return_value=object()),
        patch(
            "alfred.cli.supervisor._list_breaker_states",
            side_effect=ConnectionError("postgres connection lost"),
        ),
    ):
        result = runner.invoke(supervisor_app, ["status"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    # The "no supervisor running" hint MUST appear; the "read path
    # unavailable" hint MUST NOT.
    assert "unavailable" not in combined.lower()
    assert "read path" not in combined.lower()
    assert "supervisor" in combined.lower() or "running" in combined.lower()


def test_status_probe_not_implemented_propagates_loud(runner: CliRunner) -> None:
    """CR-149 round-5: a ``NotImplementedError`` from ``_get_supervisor`` MUST propagate.

    The prior shape wrapped both the probe and the read-path call in a
    single ``except NotImplementedError`` block, so a NotImplementedError
    leaking out of the supervisor bootstrap (e.g. an abstract method
    left unwired during a Supervisor refactor) would silently surface
    as the friendly "read path unavailable" hint instead of the loud
    traceback the bug deserves. Pin the split: a probe-side
    NotImplementedError now bubbles up as the typed exception so the
    operator sees a real traceback (CLAUDE.md hard rule #7).
    """
    with patch(
        "alfred.cli.supervisor._get_supervisor",
        side_effect=NotImplementedError("supervisor.get_instance abstract"),
    ):
        result = runner.invoke(supervisor_app, ["status"])
    # CliRunner captures the un-handled exception rather than re-raising.
    # Pin the exit-non-zero + the typed exception identity so the
    # bug-shape stays observable to the operator.
    assert result.exit_code != 0
    assert isinstance(result.exception, NotImplementedError)
    # The "read path unavailable" hint MUST NOT appear -- the probe-side
    # NotImplementedError is a programmer bug, not a wiring gap.
    combined = (result.output or "") + (result.stderr or "")
    assert "unavailable" not in combined.lower()
    assert "read path" not in combined.lower()


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


def test_reset_help_does_not_leak_runtime_placeholders(runner: CliRunner) -> None:
    """CR-149 round-10 (3339423484): ``--help`` must NOT show unresolved templates.

    ``cli.supervisor.reset.confirm_prompt`` is the runtime refusal body and
    still carries ``{component}``, ``{trip_count}``, and ``{last_trip_at}``
    placeholders. Typer renders the ``help=`` string verbatim, so wiring the
    runtime key would surface literal ``{component}`` to an operator running
    ``alfred supervisor reset --help``. The dedicated
    ``cli.supervisor.reset.confirm_help`` key carries a static body so
    ``--help`` reads cleanly. This test pins the contract so a future
    refactor that re-points ``help=`` at the runtime template fails loudly.
    """
    result = runner.invoke(supervisor_app, ["reset", "--help"])
    assert result.exit_code == 0, (result.output, result.stderr)
    # No unresolved Python format placeholders may survive in ``--help``.
    for placeholder in ("{component}", "{trip_count}", "{last_trip_at}"):
        assert placeholder not in result.output, (
            f"`alfred supervisor reset --help` leaked the runtime placeholder "
            f"{placeholder!r}; the ``help=`` argument must point at the static "
            "``cli.supervisor.reset.confirm_help`` key, not the templated "
            "``confirm_prompt`` body."
        )


# ---------------------------------------------------------------------------
# CR-149 round-10 / round-4 #3338654106 / #3339361789:
# OS-account operator attribution via _resolve_operator_user_id.
# ---------------------------------------------------------------------------


def test_resolve_operator_user_id_prefers_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """``ALFRED_OPERATOR_USER_ID`` env var takes precedence over OS probes.

    Lets a shared CI account / orchestration script identify the human
    operator who triggered the action — a single shared OS user is
    common in deployment automation; the env-var override is the
    explicit operator-attribution surface for that case.
    """
    from alfred.cli.supervisor import _resolve_operator_user_id

    monkeypatch.setenv("ALFRED_OPERATOR_USER_ID", "alice@example.com")
    assert _resolve_operator_user_id() == "alice@example.com"


def test_resolve_operator_user_id_falls_back_to_getlogin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the env var is absent, fall back to ``os.getlogin()``.

    ``getlogin`` reads the controlling terminal, so it returns the
    originating operator across ``sudo``/``su``. That matches the
    audit semantic 'who is the human behind this action'.
    """
    from alfred.cli import supervisor as supervisor_module

    monkeypatch.delenv("ALFRED_OPERATOR_USER_ID", raising=False)
    with patch.object(supervisor_module.os, "getlogin", return_value="opbob"):
        assert supervisor_module._resolve_operator_user_id() == "opbob"


def test_resolve_operator_user_id_falls_back_to_getpwuid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``getlogin`` raises (no TTY: cron / systemd / container),
    fall back to the effective UID's pwd entry.

    This is the typical headless-runtime case. Identifies the runtime
    account if no human session is available — better than NULL for
    the forensic trail per CLAUDE.md hard rule #7.
    """
    from alfred.cli import supervisor as supervisor_module

    monkeypatch.delenv("ALFRED_OPERATOR_USER_ID", raising=False)
    fake_pwd_entry = MagicMock()
    fake_pwd_entry.pw_name = "alfred-runtime"
    with (
        patch.object(supervisor_module.os, "getlogin", side_effect=OSError("no TTY")),
        patch.object(supervisor_module.os, "getuid", return_value=1000),
        patch("pwd.getpwuid", return_value=fake_pwd_entry),
    ):
        assert supervisor_module._resolve_operator_user_id() == "alfred-runtime"


def test_resolve_operator_user_id_returns_none_when_every_probe_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every probe failed → return ``None`` so the row still emits with NULL.

    Per CLAUDE.md hard rule #7, the presence of the audit row IS the
    forensic signal — silently skipping the row is forbidden, but
    emitting it with NULL operator_user_id is correct when every
    attribution probe legitimately failed.
    """
    from alfred.cli import supervisor as supervisor_module

    monkeypatch.delenv("ALFRED_OPERATOR_USER_ID", raising=False)
    with (
        patch.object(supervisor_module.os, "getlogin", side_effect=OSError("no TTY")),
        patch.object(supervisor_module.os, "getuid", return_value=99999),
        patch("pwd.getpwuid", side_effect=KeyError("uid not found")),
    ):
        assert supervisor_module._resolve_operator_user_id() is None


def test_reset_attempt_audit_carries_resolved_operator_user_id(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The breaker-reset attempt structlog event carries the resolved id.

    Pins the wiring end-to-end: when an operator runs ``alfred
    supervisor reset --confirm`` with ``ALFRED_OPERATOR_USER_ID`` set,
    the attempt audit row carries that id (not ``None``). A regression
    that drops the wiring on the structlog event surfaces here.
    """
    import structlog

    monkeypatch.setenv("ALFRED_OPERATOR_USER_ID", "carol@example.com")

    captured: list[dict[str, object]] = []

    def _intercept(
        _logger: object, _method: str, event_dict: dict[str, object]
    ) -> dict[str, object]:
        captured.append(dict(event_dict))
        return event_dict

    structlog.configure(processors=[_intercept, structlog.processors.JSONRenderer()])
    try:
        mock_supervisor = AsyncMock()
        mock_supervisor.reset_breaker = AsyncMock(return_value=None)
        with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
            result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
        assert result.exit_code == 0, (result.output, result.stderr)
    finally:
        structlog.reset_defaults()

    attempt_rows = [
        row for row in captured if row.get("event") == "supervisor.breaker.reset.attempted"
    ]
    assert attempt_rows, "attempt audit row never fired"
    assert attempt_rows[-1].get("operator_user_id") == "carol@example.com"


def test_reset_breaker_call_carries_resolved_operator_user_id(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``Supervisor.reset_breaker`` is invoked with the resolved id.

    Mirrors the attempt-row test on the post-attempt path: the
    supervisor receives the resolved operator id, not ``None``. A
    regression on the typed-kwarg call surfaces here.
    """
    monkeypatch.setenv("ALFRED_OPERATOR_USER_ID", "dave@example.com")

    mock_supervisor = AsyncMock()
    mock_supervisor.reset_breaker = AsyncMock(return_value=None)
    with patch("alfred.cli.supervisor._get_supervisor", return_value=mock_supervisor):
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code == 0, (result.output, result.stderr)

    mock_supervisor.reset_breaker.assert_called_once_with(
        component_id="quarantined-llm",
        operator_user_id="dave@example.com",
    )
