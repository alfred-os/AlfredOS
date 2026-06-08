"""Unit tests for the surviving ``alfred supervisor reset`` surfaces.

Issue #154 / ADR-0020: the reset command's active dispatch path is
deferred to [#171](https://github.com/alfred-os/AlfredOS/issues/171) and
the rewritten body is tested in
``tests/unit/cli/test_supervisor_reset.py``. The contracts that survive
the rewrite live here:

* ``--confirm`` is accepted but currently a no-op — the deferred-to-#171
  body fails fast irrespective of the flag (BLOCKER #6); the flag stays
  in the parser so scripts that pass it today don't break the day #171
  wires the real reset. The non-zero-exit pin lives in
  ``test_reset_without_confirm_exits_nonzero``.
* ``--help`` does not leak runtime placeholders (CR-149 round-10).
* The forensic-attempt audit helper's payload covers
  ``SUPERVISOR_BREAKER_RESET_FIELDS``.
* ``_resolve_operator_user_id`` precedence (env / getlogin / getpwuid /
  None) and its end-to-end wiring through the attempt-row structlog
  event.

Tests that mocked ``_get_supervisor`` or ``Supervisor.reset_breaker``
have been removed — those call sites no longer exist in the rewritten
body.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from alfred.cli.supervisor import supervisor_app


@pytest.fixture()
def runner() -> CliRunner:
    """Typer runner — Click 8.2 separates stdout/stderr by default."""
    return CliRunner()


def test_reset_without_confirm_exits_nonzero(runner: CliRunner) -> None:
    """ADR-0021 #171: ``--confirm`` regains its gating semantic.

    Without ``--confirm`` the reset request exits non-zero without
    writing a proposal. The body points operators at the required
    flag so the recovery action is obvious. BLOCKER #6 semantic from
    #154 is preserved — operators must explicitly confirm destructive
    actions.
    """
    result = runner.invoke(supervisor_app, ["reset", "quarantined-llm"])
    assert result.exit_code != 0, (result.output, result.stderr)
    combined = (result.output or "") + (result.stderr or "")
    # The confirm_required body names the flag operators need to add.
    assert "--confirm" in combined


def test_emit_breaker_reset_attempt_audit_uses_schema_fields() -> None:
    """The attempt-audit helper carries the SUPERVISOR_BREAKER_RESET_FIELDS shape.

    sec-pr-s3-6-04: when #171 swaps the structlog emit for the real
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
    # CR-156 round-7 MEDIUM #12: the attempt row is emitted BEFORE the
    # reset itself runs, so the helper cannot yet know the breaker's
    # actual state. The CR-149 round-2 invariant pinned ``old_state`` /
    # ``new_state`` / ``trip_count`` to ``None`` as the explicit "not
    # yet known" sentinel — anything else (e.g. unconditional
    # ``OPEN`` → ``CLOSED``) would write false transition data into
    # the forensic trail. This block locks the null-state invariant
    # against regression.
    assert captured["old_state"] is None
    assert captured["new_state"] is None
    assert captured["trip_count"] is None


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
    the attempt audit row carries that id (not ``None``).

    ADR-0021 #171: reset now writes a state.git proposal and exits 0
    when the queue succeeds; the attempt row still fires before the
    proposal write (CR-149 forensic-trail invariant) so this assertion
    holds regardless of the eventual proposal-write outcome.
    """
    import structlog

    from alfred.cli._state_git import ProposalResult

    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test-key-not-placeholder")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_OPERATOR_USER_ID", "carol@example.com")
    monkeypatch.setattr(
        "alfred.cli.supervisor.queue_proposal_or_exit",
        lambda **_kw: ProposalResult(proposal_id="abc", branch="proposal/breaker-reset-abc"),
    )

    captured: list[dict[str, object]] = []

    def _intercept(
        _logger: object, _method: str, event_dict: dict[str, object]
    ) -> dict[str, object]:
        captured.append(dict(event_dict))
        return event_dict

    structlog.configure(processors=[_intercept, structlog.processors.JSONRenderer()])
    try:
        result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
        # Reset now exits 0 when the proposal queues cleanly.
        assert result.exit_code == 0, (result.output, result.stderr)
    finally:
        structlog.reset_defaults()

    attempt_rows = [
        row for row in captured if row.get("event") == "supervisor.breaker.reset.attempted"
    ]
    assert attempt_rows, "attempt audit row never fired"
    assert attempt_rows[-1].get("operator_user_id") == "carol@example.com"


# Removed in #154 / ADR-0020 (revised):
#   * test_reset_with_confirm_calls_reset_breaker
#   * test_reset_success_message_rendered
#   * test_reset_unknown_component_exits_nonzero
#   * test_reset_canonical_no_supervised_component_routes_to_component_not_found
#   * test_reset_no_such_component_is_locale_immune
#   * test_reset_no_supervisor_running_routes_through_localised_hint
#   * test_reset_unexpected_error_routes_through_generic_message
#   * test_reset_programmer_bug_propagates_loud
#   * test_reset_emits_attempt_audit_row_before_reset_breaker
#   * test_reset_attempt_audit_row_survives_supervisor_crash
#   * test_reset_supervisor_error_without_not_found_routes_generic
#   * test_get_supervisor_raises_when_singleton_missing
#   * test_get_supervisor_invokes_singleton_when_available
#   * test_reset_import_error_fallback_uses_generic_message
#   * test_reset_breaker_call_carries_resolved_operator_user_id
#
# These tests mocked ``_get_supervisor`` or ``Supervisor.reset_breaker``
# call sites that no longer exist in the rewritten reset body. The
# deferred-to-#171 path is tested in
# ``tests/unit/cli/test_supervisor_reset.py``.
#
# Removed in #154 / Task 2 (status path):
#   * test_list_breaker_states_raises_not_implemented
#   * test_status_handles_read_path_unavailable
#   * test_status_read_path_connection_error_routes_through_no_supervisor_hint
#   * test_status_probe_not_implemented_propagates_loud
#   * test_status_no_supervisor_running_exits_nonzero
#   * test_status_renders_table_header
#   * test_status_renders_all_three_breaker_states
#   * test_status_empty_rows_renders_hint
#
# The new sync-Postgres-read contracts for status live in
# ``tests/unit/cli/test_supervisor_status.py``.
