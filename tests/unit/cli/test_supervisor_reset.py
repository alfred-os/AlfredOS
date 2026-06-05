"""Unit tests for ``alfred supervisor reset`` — Task 8 of #171.

Issue #171 closes the deferred-to-#171 hint: the reset command now
queues a typed ``BreakerResetProposal`` via the canonical writer.
ADR-0021 §CLI rewire: ``--confirm`` is reinstated as a real gate (the
no-op semantic from #154 was justified only while the underlying reset
was deferred; now reset performs actual state mutation, so explicit
confirmation is meaningful again).

Pinned invariants:

* ``_emit_breaker_reset_attempt_audit`` still fires on every confirmed
  invocation BEFORE the proposal write (CR-149 forensic-trail
  invariant is preserved — operator intent always lands in the audit
  graph even if the state.git write fails mid-flight).
* The localised ``cli.supervisor.reset.proposal_submitted`` body
  prints to stderr/stdout naming the ``proposal_id``, ``branch``,
  ``interval`` placeholders + the ``alfred supervisor proposals
  --recent`` follow-up.
* Exit code 0 on success — the request landed.
* Without ``--confirm`` the command exits non-zero without writing a
  proposal (BLOCKER #6 semantic from #154 is preserved).
* ``cli.supervisor.reset.deferred_to_issue_171`` is tombstoned — no
  longer emitted on any code path.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from alfred.cli.supervisor import supervisor_app


@pytest.fixture(autouse=True)
def _settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Satisfy Settings' required ``ALFRED_DEEPSEEK_API_KEY`` field.

    The reset command now consults ``Settings.proposal_dispatch_interval_s``
    via ``load_settings_or_die`` to render the {interval} placeholder in
    the submitted body. Every test that invokes the command needs
    Settings to construct without raising the placeholder/missing-key
    validator error.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test-key-not-placeholder")


@pytest.fixture()
def runner() -> CliRunner:
    """Typer runner — Click 8.2 separates stdout/stderr by default."""
    return CliRunner()


# ---------------------------------------------------------------------------
# Confirmed path → proposal write + submitted body + exit 0
# ---------------------------------------------------------------------------


def test_reset_with_confirm_writes_breaker_reset_proposal_via_queue_helper(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--confirm`` invokes ``queue_proposal_or_exit`` with a typed payload."""
    from alfred.cli._state_git import ProposalResult
    from alfred.state.proposal_payloads import BreakerResetProposal

    captured: dict[str, object] = {}

    def _fake_queue(**kwargs: object) -> ProposalResult:
        captured.update(kwargs)
        return ProposalResult(proposal_id="abc123def4567890", branch="proposal/breaker-reset-abc")

    monkeypatch.setattr("alfred.cli.supervisor.queue_proposal_or_exit", _fake_queue)
    # The attempt-audit emitter still fires; capture it so we can assert
    # ordering separately.
    monkeypatch.setattr(
        "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
        MagicMock(),
    )

    result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code == 0, (result.output, result.stderr)

    payload = captured.get("payload")
    assert isinstance(payload, BreakerResetProposal)
    assert payload.component_id == "quarantined-llm"
    # The helper auto-fills proposal_branch + correlation_id; the caller
    # passes the rest via audit_subject_partial.
    audit_subject = captured.get("audit_subject_partial")
    assert isinstance(audit_subject, dict)
    assert audit_subject.get("component_id") == "quarantined-llm"
    assert audit_subject.get("trust_tier_of_trigger") == "T1"


def test_reset_with_confirm_emits_attempt_audit_before_proposal_write(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The forensic-attempt audit row lands BEFORE the proposal write.

    Preserves the CR-149 round-2 invariant: operator intent always
    lands in the audit graph even if the state.git write fails.
    """
    sequence: list[str] = []

    def _record_attempt(*, component_id: str) -> None:
        del component_id
        sequence.append("audit_attempt")

    def _fake_queue(**kwargs: object) -> object:
        sequence.append("proposal_write")
        from alfred.cli._state_git import ProposalResult

        return ProposalResult(proposal_id="abc", branch="proposal/breaker-reset-abc")

    monkeypatch.setattr(
        "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
        _record_attempt,
    )
    monkeypatch.setattr("alfred.cli.supervisor.queue_proposal_or_exit", _fake_queue)

    result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert sequence == ["audit_attempt", "proposal_write"], sequence


def test_reset_with_confirm_passes_submitted_kwargs_to_queue_helper(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Submitted-body kwargs include component + interval; key points at proposals subcommand.

    The catalog key shape matches the cli.web.allowlist.add.pending_review
    precedent (proposal_id + branch + 'Check status with:' follow-up),
    extended with the {interval} placeholder so the operator knows the
    dispatch-cycle cadence + {component} for the request context.

    The helper itself renders the body via ``typer.echo(t(key, **kwargs))``;
    this test captures the kwargs at the call boundary and pins them so
    a future refactor that drops one placeholder surfaces here, not at
    operator runtime.
    """
    from alfred.cli._state_git import ProposalResult

    captured: dict[str, object] = {}

    def _fake_queue(**kwargs: object) -> ProposalResult:
        captured.update(kwargs)
        return ProposalResult(
            proposal_id="abc123def4567890",
            branch="proposal/breaker-reset-abc123def4567890",
        )

    monkeypatch.setattr(
        "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
        MagicMock(),
    )
    monkeypatch.setattr("alfred.cli.supervisor.queue_proposal_or_exit", _fake_queue)

    result = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    assert result.exit_code == 0, (result.output, result.stderr)

    assert captured.get("pending_review_key") == "cli.supervisor.reset.proposal_submitted"
    extra = captured.get("pending_review_extra_kwargs")
    assert isinstance(extra, dict)
    assert extra.get("component") == "quarantined-llm"
    # Interval threads through from Settings.proposal_dispatch_interval_s.
    assert extra.get("interval") == 30


def test_register_proposal_keys_for_pybabel_renders_live_bodies() -> None:
    """The pybabel-anchor shim returns rendered (not template) strings.

    Mirrors the contract pinned for the cli/web.py and cli/plugin.py
    sibling shims — the shim is the only static-extraction surface that
    keeps the proposal-flow keys (denied + proposal_submitted) live
    in the catalog across pybabel update runs.
    """
    from alfred.cli.supervisor import _register_proposal_keys_for_pybabel

    rendered = _register_proposal_keys_for_pybabel()
    assert len(rendered) == 2
    # Neither rendered string survives unresolved Python-format markers.
    for body in rendered:
        assert "{" not in body and "}" not in body
        assert body  # non-empty


def test_reset_proposal_submitted_catalog_body_renders_with_placeholders() -> None:
    """The catalog body resolves with every placeholder the call site provides.

    Pins the {component} / {branch} / {proposal_id} / {interval} contract
    independently from the CLI dispatch — a future catalog edit that
    drops or renames a placeholder surfaces here.
    """
    from alfred.i18n import t

    body = t(
        "cli.supervisor.reset.proposal_submitted",
        component="quarantined-llm",
        branch="proposal/breaker-reset-abc",
        proposal_id="abc",
        interval=30,
    )
    assert "quarantined-llm" in body
    assert "proposal/breaker-reset-abc" in body
    assert "abc" in body
    assert "30" in body
    assert "alfred supervisor proposals" in body


# ---------------------------------------------------------------------------
# --confirm gate restored (BLOCKER #6 preserved)
# ---------------------------------------------------------------------------


def test_reset_without_confirm_does_not_write_proposal(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omitting ``--confirm`` exits without invoking the proposal writer."""
    queue_called = MagicMock()
    monkeypatch.setattr("alfred.cli.supervisor.queue_proposal_or_exit", queue_called)
    monkeypatch.setattr(
        "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
        MagicMock(),
    )

    result = runner.invoke(supervisor_app, ["reset", "quarantined-llm"])
    # The flag IS a gate again — exit non-zero, no proposal written.
    assert result.exit_code != 0, (result.output, result.stderr)
    queue_called.assert_not_called()


# ---------------------------------------------------------------------------
# Tombstone: the deferred-to-#171 hint is gone
# ---------------------------------------------------------------------------


def test_reset_never_emits_deferred_to_issue_171_hint(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The deferred-hint catalog key is no longer reached on any code path."""
    from alfred.cli._state_git import ProposalResult

    monkeypatch.setattr(
        "alfred.cli.supervisor._emit_breaker_reset_attempt_audit",
        MagicMock(),
    )
    monkeypatch.setattr(
        "alfred.cli.supervisor.queue_proposal_or_exit",
        lambda **_kw: ProposalResult(proposal_id="x", branch="proposal/x"),
    )
    # Confirmed run.
    result_confirm = runner.invoke(supervisor_app, ["reset", "quarantined-llm", "--confirm"])
    # Bare run (no confirm).
    result_bare = runner.invoke(supervisor_app, ["reset", "quarantined-llm"])
    # Neither output should carry the deferred-hint copy ("deferred to #171").
    for r in (result_confirm, result_bare):
        combined = (r.output or "") + (r.stderr or "")
        assert "deferred to #171" not in combined.lower()
