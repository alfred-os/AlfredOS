"""Unit tests for ``alfred supervisor reset`` — deferred-to-#171 path.

Issue #154 / ADR-0020 (revised): the reset command fails fast on the
[#171](https://github.com/alfred-os/AlfredOS/issues/171) deferral
irrespective of ``--confirm``; the flag is preserved in the parser so
scripts that pass it today don't break the day #171 wires the real
reset. The forensic-attempt audit row (CR-149 round-2 forensic-trail
invariant) still emits on every invocation, since the operator-intent
breadcrumb survives the deferral. Until #171 ships:

* ``--confirm`` is a no-op — present in the parser so existing scripts
  keep working, but the deferred-hint fires on every invocation.
* ``_emit_breaker_reset_attempt_audit`` fires BEFORE the deferred-hint
  emission — pinning the audit-graph breadcrumb invariant.
* The localised ``cli.supervisor.reset.deferred_to_issue_171`` hint
  prints to stderr; the body names the workarounds and the tracking
  issue per the runbook.
* Exit code 1 — the request is not fulfilled.

Tests that previously mocked ``_get_supervisor`` or
``Supervisor.reset_breaker`` for the reset path are removed; both call
sites no longer exist in the rewritten body.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from alfred.cli.supervisor import supervisor_app


@pytest.fixture()
def runner() -> CliRunner:
    """Typer runner — Click 8.2 separates stdout/stderr by default."""
    return CliRunner()


def test_reset_with_confirm_emits_audit_then_prints_deferred_hint_and_exits_nonzero(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The confirmed reset path: forensic audit + deferred hint + exit 1.

    Pin every property of the rewritten body:

    * ``_emit_breaker_reset_attempt_audit`` is invoked exactly once with
      the operator-supplied ``component_id``. The CR-149 round-2
      forensic-trail invariant — operator intent always lands in the
      audit graph — survives the rewrite.
    * The localised deferred-hint body appears on stderr and mentions
      #171, the workarounds, and the runbook anchor.
    * Exit code is 1 — the request is not fulfilled.
    * ``_get_supervisor`` and ``asyncio.run`` are never called.

    The last assertion is structural: the rewritten body has dropped
    both call sites entirely, so a future regression that re-adds them
    fails this test before it lands an unintended side effect.
    """
    audit_calls: list[str] = []

    def _record_attempt(*, component_id: str) -> None:
        audit_calls.append(component_id)

    monkeypatch.setattr(
        "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
        _record_attempt,
    )

    # ``_get_supervisor`` MUST be gone from the module. A patch.object
    # would raise ``AttributeError`` on the missing attribute, so we
    # confirm absence at the import-level instead.
    from alfred.cli import supervisor as supervisor_module

    assert not hasattr(supervisor_module, "_get_supervisor"), (
        "`_get_supervisor` survived the #154 rewrite; the reset path "
        "should no longer probe a supervisor handle (ADR-0020)."
    )

    # ``asyncio`` is the legacy reset-dispatch escape hatch — the
    # rewritten body no longer imports it, so the module attribute is
    # gone. Absence at the module level is the structural pin: a
    # regression that re-adds ``asyncio.run(...)`` would have to first
    # re-import ``asyncio`` at the top of the module and would surface
    # here.
    assert not hasattr(supervisor_module, "asyncio"), (
        "`asyncio` survived the #154 reset rewrite; the deferred path "
        "no longer runs an async coroutine via asyncio.run."
    )

    result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])

    assert result.exit_code == 1, (result.output, result.stderr)
    assert audit_calls == ["quarantined-llm"]

    # The localised body names #171 + the operator workarounds + the
    # runbook anchor. Fingerprint each load-bearing noun.
    combined = (result.output or "") + (result.stderr or "")
    assert "#171" in combined
    # Workaround 1 names ``restart``.
    assert "restart" in combined.lower()
    # Workaround 2 names the direct ``circuit_breakers`` UPDATE.
    assert "circuit_breakers" in combined
    # Runbook anchor mentioned so the operator has the deeper-dive link.
    assert "runbooks" in combined.lower() or "runbook" in combined.lower()
    # Component id appears in the body so operators see WHICH reset
    # they just attempted.
    assert "quarantined-llm" in combined


def test_reset_emits_audit_and_deferred_hint_with_or_without_confirm(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CR-156 round-7 HIGH #6: ``--confirm`` no longer gates the deferred-hint.

    The previous two-step UX (refusal body + rerun hint, gated by the
    flag) added cognitive load without adding safety — there's no
    destructive action behind the flag until #171 ships. The deferred
    path now fails fast irrespective of the flag, so operators see the
    same actionable error on both invocations. This pins the new
    contract: behaviour is identical for ``--confirm`` and no
    ``--confirm`` — same audit row, same hint, same exit code.

    ``--confirm`` is kept in the parser so scripts that pass it today
    do not break the day #171 lands.
    """
    audit_calls: list[str] = []

    def _record_attempt(*, component_id: str) -> None:
        audit_calls.append(component_id)

    monkeypatch.setattr(
        "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
        _record_attempt,
    )

    # Without ``--confirm``.
    result_bare = runner.invoke(supervisor_app, ["reset", "quarantined-llm"])
    # With ``--confirm``.
    result_confirm = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])

    # Both exit 1 — the request is not fulfilled either way.
    assert result_bare.exit_code == 1, (result_bare.output, result_bare.stderr)
    assert result_confirm.exit_code == 1, (result_confirm.output, result_confirm.stderr)
    # Both emit the forensic-attempt audit row.
    assert audit_calls == ["quarantined-llm", "quarantined-llm"]
    # Both show the deferred-hint body — naming #171 + the component.
    for result in (result_bare, result_confirm):
        combined = (result.output or "") + (result.stderr or "")
        assert "#171" in combined
        assert "quarantined-llm" in combined


def test_reset_emits_audit_before_deferred_hint(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ordering invariant: the audit row lands BEFORE the deferred hint prints.

    The audit row IS the forensic breadcrumb. If the helper raised and
    the hint emission had already run, operators would see "your request
    was deferred" with no audit trace of the attempt — exactly the
    silent-skip shape CLAUDE.md hard rule #7 forbids on T1 surfaces.
    """
    sequence: list[str] = []

    def _record_attempt(*, component_id: str) -> None:
        del component_id
        sequence.append("audit")

    # Intercept the localised hint emission by patching typer.echo.
    real_echo = MagicMock()

    def _echo_recording(*args: object, **kwargs: object) -> None:
        del args, kwargs
        sequence.append("echo")
        real_echo()

    monkeypatch.setattr(
        "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
        _record_attempt,
    )
    monkeypatch.setattr("alfred.cli.supervisor.typer.echo", _echo_recording)

    result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code == 1, (result.output, result.stderr)
    # Audit MUST land before the hint echoes. Both must occur.
    assert sequence[0] == "audit", sequence
    assert "echo" in sequence
