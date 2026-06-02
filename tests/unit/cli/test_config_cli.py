"""Spec §11.2/§11.3 — ``alfred config`` two-track set/get/list.

Pins these invariants for the sub-app shipped in PR-S3-6:

* **Low-blast keys** mutate ``config/policies.yaml`` directly, without a
  reviewer-gate (hot-reload paths only narrow within the existing trust
  surface). The closed set is enumerated in :data:`_KEY_TO_YAML_PATH`:
  ``web-fetch-budget``, ``operator-fetch-budget``,
  ``extraction-max-retries``, ``action-deadline``, ``user-agent``.
* **High-blast keys** queue a reviewer-gated state.git proposal. The
  only declared high-blast key for PR-S3-6 is ``quarantined-provider``
  (spec §11.1).
* **Unknown keys** are refused with a localised error that enumerates
  the valid set (devex-012 in plan §1011) so the operator has an
  immediate recovery path.
* ``get`` reads ``policies.yaml`` and emits a ``key = value`` line; an
  unset key emits a localised "not set" notice rather than empty stdout.
* ``list`` walks ``policies.yaml`` recursively and prints each leaf as a
  dotted key.
* :class:`StateGitError` on the high-blast path surfaces on stderr with
  a non-zero exit code (CLAUDE.md hard rule #7).
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from alfred.cli._state_git import ProposalResult, StateGitError
from alfred.cli.config import config_app


@pytest.fixture()
def runner() -> CliRunner:
    """Typer test runner (Click 8.2 — separate stdout/stderr properties)."""
    return CliRunner()


# ---------------------------------------------------------------------------
# set — low-blast path (policies.yaml direct write)
# ---------------------------------------------------------------------------


def test_set_low_blast_writes_int_to_policies_yaml(runner: CliRunner, tmp_path: Path) -> None:
    """``web-fetch-budget 50`` writes ``50`` (as int) under web_fetch."""
    policies = tmp_path / "policies.yaml"
    policies.write_text("web_fetch:\n  user_daily_budget: 100\n")
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "web-fetch-budget", "50"])
    assert result.exit_code == 0, result.stderr
    content = policies.read_text()
    assert "50" in content
    assert "user_daily_budget: 50" in content


def test_set_low_blast_creates_parent_keys(runner: CliRunner, tmp_path: Path) -> None:
    """Setting a key whose parent doesn't exist yet creates the parent."""
    policies = tmp_path / "policies.yaml"
    policies.write_text("orchestrator:\n  unrelated: yes\n")
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "user-agent", "AlfredOS/test"])
    assert result.exit_code == 0, result.stderr
    content = policies.read_text()
    assert "user_agent: AlfredOS/test" in content


def test_set_unknown_key_lists_valid_keys(runner: CliRunner, tmp_path: Path) -> None:
    """Unknown key → stderr lists every valid key (devex-012 in plan §1011)."""
    policies = tmp_path / "policies.yaml"
    policies.write_text("")
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "no-such-key", "1"])
    assert result.exit_code != 0
    assert "web-fetch-budget" in result.stderr
    assert "quarantined-provider" in result.stderr


# ---------------------------------------------------------------------------
# set — high-blast path (state.git reviewer-gated proposal)
# ---------------------------------------------------------------------------


def test_set_high_blast_quarantined_provider_queues_proposal(
    runner: CliRunner,
) -> None:
    """``quarantined-provider anthropic`` writes a state.git proposal.

    Spec §11.1: changing the quarantined provider is the highest-blast
    config knob — it routes the dual-LLM split through a different
    vendor. Always reviewer-gated.
    """
    proposal = ProposalResult(
        proposal_id="cc778899cc778899",
        branch="proposal/config-quarantined-provider-cc778899cc778899",
    )
    with patch("alfred.cli.config._state_git_client") as mock_client:
        mock_client.create_proposal_from_payload.return_value = proposal
        result = runner.invoke(config_app, ["set", "quarantined-provider", "anthropic"])
    assert result.exit_code == 0, result.stderr
    # ADR-0018: the typed payload replaced the (proposal_type, dict)
    # surface. Assert against the Pydantic model instead.
    from alfred.state.proposal_payloads import ConfigSetProposal

    call_kwargs = mock_client.create_proposal_from_payload.call_args.kwargs
    payload = call_kwargs["payload"]
    assert isinstance(payload, ConfigSetProposal)
    assert payload.config_key == "quarantined-provider"
    assert payload.value == "anthropic"
    assert proposal.branch in result.stdout


def test_set_high_blast_uses_pending_review_language(runner: CliRunner) -> None:
    """High-blast path MUST NOT print a success message — it's queued."""
    proposal = ProposalResult(
        proposal_id="cc778899cc778899",
        branch="proposal/config-quarantined-provider-cc778899cc778899",
    )
    with patch("alfred.cli.config._state_git_client") as mock_client:
        mock_client.create_proposal_from_payload.return_value = proposal
        result = runner.invoke(config_app, ["set", "quarantined-provider", "anthropic"])
    assert "now active" not in result.stdout.lower()
    assert "pending" in result.stdout.lower() or "proposal" in result.stdout.lower()


def test_set_high_blast_surfaces_state_git_error(runner: CliRunner) -> None:
    """state.git failure on the high-blast path surfaces on stderr."""
    with patch("alfred.cli.config._state_git_client") as mock_client:
        mock_client.create_proposal_from_payload.side_effect = StateGitError("push refused")
        result = runner.invoke(config_app, ["set", "quarantined-provider", "anthropic"])
    assert result.exit_code != 0
    assert result.stderr.strip() != ""


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


def test_get_reads_int_value_from_policies_yaml(runner: CliRunner, tmp_path: Path) -> None:
    """``get web-fetch-budget`` reads the int value from policies.yaml."""
    policies = tmp_path / "policies.yaml"
    policies.write_text("web_fetch:\n  user_daily_budget: 75\n")
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["get", "web-fetch-budget"])
    assert result.exit_code == 0, result.stderr
    assert "75" in result.stdout


def test_get_unset_key_emits_localised_notice(runner: CliRunner, tmp_path: Path) -> None:
    """An unset key emits a localised "not set" notice, not empty stdout.

    Empty stdout would be misread by an operator as "value is empty";
    the explicit notice differentiates "key has no value yet" from
    "value is the empty string".
    """
    policies = tmp_path / "policies.yaml"
    policies.write_text("")
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["get", "web-fetch-budget"])
    assert result.exit_code == 0, result.stderr
    assert result.stdout.strip() != ""


def test_get_unknown_key_lists_valid_keys(runner: CliRunner) -> None:
    """Unknown key → stderr lists every valid key."""
    result = runner.invoke(config_app, ["get", "no-such-key"])
    assert result.exit_code != 0
    assert "web-fetch-budget" in result.stderr


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def test_list_walks_policies_yaml_recursively(runner: CliRunner, tmp_path: Path) -> None:
    """``list`` prints every leaf as a dotted key."""
    policies = tmp_path / "policies.yaml"
    policies.write_text(
        "web_fetch:\n  user_daily_budget: 100\norchestrator:\n  action_deadline_seconds: 30\n"
    )
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["list"])
    assert result.exit_code == 0, result.stderr
    assert "web_fetch.user_daily_budget" in result.stdout
    assert "orchestrator.action_deadline_seconds" in result.stdout
    assert "100" in result.stdout
    assert "30" in result.stdout


def test_list_empty_yaml_emits_localised_notice(runner: CliRunner, tmp_path: Path) -> None:
    """An empty (or missing) policies.yaml emits a localised notice."""
    policies = tmp_path / "absent.yaml"
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["list"])
    assert result.exit_code == 0, result.stderr
    assert result.stdout.strip() != ""


# ---------------------------------------------------------------------------
# coverage-closing fixups — missing-file branches for set/get + empty list
# ---------------------------------------------------------------------------


def test_set_low_blast_creates_policies_yaml_when_missing(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Setting a low-blast key when policies.yaml does not exist creates it.

    The setup path normally seeds an empty ``policies.yaml`` during
    ``alfred-setup``, but a manually-wiped deployment can hit this
    branch. Without it, the operator would have to ``touch`` the file
    before any ``alfred config set`` call worked — a UX trap. The yaml
    helper treats absent as empty-dict so the first set seeds the file.
    """
    policies = tmp_path / "fresh" / "policies.yaml"
    assert not policies.exists()
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "web-fetch-budget", "25"])
    assert result.exit_code == 0, result.stderr
    assert policies.exists()
    assert "user_daily_budget: 25" in policies.read_text()


def test_get_returns_localised_notice_when_policies_yaml_missing(
    runner: CliRunner, tmp_path: Path
) -> None:
    """``get`` on a missing policies.yaml emits the same "not set" notice.

    Distinguishing "file absent" from "key absent" is intentionally NOT
    surfaced to the operator: in both cases the value is not set.
    Pinning the missing-file path keeps the CLI from regressing into a
    raw ``FileNotFoundError`` traceback on a fresh / wiped deployment.
    """
    policies = tmp_path / "never_existed.yaml"
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["get", "web-fetch-budget"])
    assert result.exit_code == 0, result.stderr
    assert result.stdout.strip() != ""


def test_list_existing_but_empty_yaml_emits_localised_notice(
    runner: CliRunner, tmp_path: Path
) -> None:
    """A policies.yaml that exists but parses to empty also emits the notice.

    The previous ``absent.yaml`` test covered the missing-file leg; this
    one covers the file-exists-but-empty leg (operator ``touch`` after
    setup, or YAML parsed to ``None``). Both legs route to the same
    localised hint so silent-blank output cannot be misread as
    "no policies are configured".
    """
    policies = tmp_path / "policies.yaml"
    policies.write_text("")
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["list"])
    assert result.exit_code == 0, result.stderr
    assert result.stdout.strip() != ""


# ---------------------------------------------------------------------------
# err-002: malformed YAML routes through a localised error (no raw traceback)
# ---------------------------------------------------------------------------


def test_set_malformed_yaml_emits_localised_error(runner: CliRunner, tmp_path: Path) -> None:
    """A YAML parse failure in ``set`` surfaces the localised malformed_yaml key.

    err-002: previously the raw ``yaml.YAMLError`` traceback hit the
    operator's terminal, bypassing the t() layer. The wrapper now
    routes through ``cli.config.error.malformed_yaml`` so the operator
    sees the file path + a recovery hint.
    """
    policies = tmp_path / "policies.yaml"
    # Unbalanced bracket + missing key -- guaranteed YAMLError shape.
    policies.write_text("web_fetch: { user_daily_budget:\n  - 1\n  -\n")
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "web-fetch-budget", "10"])
    assert result.exit_code != 0
    assert str(policies) in result.stderr
    # The localised error names the policy file + a recovery hint
    # (rerunning the command). The literal "malformed" is in the
    # canonical English text the catalog defines.
    assert "malformed" in result.stderr.lower() or "yaml" in result.stderr.lower()


def test_get_malformed_yaml_emits_localised_error(runner: CliRunner, tmp_path: Path) -> None:
    """``get`` on a malformed policies.yaml surfaces the localised key."""
    policies = tmp_path / "policies.yaml"
    policies.write_text("not: valid: yaml: with: too: many: colons:\n  - {")
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["get", "web-fetch-budget"])
    assert result.exit_code != 0
    assert str(policies) in result.stderr


def test_list_malformed_yaml_emits_localised_error(runner: CliRunner, tmp_path: Path) -> None:
    """``list`` on a malformed policies.yaml surfaces the localised key."""
    policies = tmp_path / "policies.yaml"
    policies.write_text("web_fetch: { broken")
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["list"])
    assert result.exit_code != 0
    assert str(policies) in result.stderr


def test_safe_load_yaml_top_level_scalar_rejected(tmp_path: Path) -> None:
    """A top-level YAML scalar (e.g. ``42``) routes through the malformed key.

    The CLI helpers all assume a top-level mapping; if a downstream
    consumer hands in a scalar / list / string we surface the same
    localised error rather than a downstream ``AttributeError``.
    """
    from alfred.cli import config as config_module

    policies = tmp_path / "policies.yaml"
    policies.write_text("just_a_string")
    runner = CliRunner()
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["list"])
    assert result.exit_code != 0
    assert str(policies) in result.stderr

    # Direct helper invocation exercises the top-level-non-dict branch.
    with patch("alfred.cli.config._policies_yaml_path", policies):
        # The helper itself raises typer.Exit; route through a CLI command
        # to confirm the exit is surfaced.
        del config_module  # quiet ARG001 -- we exercised via the CLI


# ---------------------------------------------------------------------------
# sec-pr-s3-6-06: atomic-rename semantics on the low-blast write path
# ---------------------------------------------------------------------------


def test_set_low_blast_uses_atomic_rename(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The set path writes via tempfile + os.replace (not direct write).

    sec-pr-s3-6-06: previously ``write_text`` truncated the target then
    streamed bytes -- a crash mid-write left an empty policies.yaml.
    Pin the atomic-rename pattern by counting ``os.replace`` calls
    against the policies path.
    """
    import os as os_module

    policies = tmp_path / "policies.yaml"
    policies.write_text("web_fetch:\n  user_daily_budget: 100\n")

    real_replace = os_module.replace
    replace_calls: list[tuple[str, str]] = []

    def _counting_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        replace_calls.append((str(src), str(dst)))
        real_replace(src, dst)

    monkeypatch.setattr("alfred.cli.config.os.replace", _counting_replace)
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "web-fetch-budget", "50"])
    assert result.exit_code == 0, result.stderr
    # Exactly one rename targeted the policies file.
    assert len(replace_calls) == 1
    src, dst = replace_calls[0]
    assert dst == str(policies)
    # The tempfile lived in the same directory so the rename is atomic.
    assert Path(src).parent == Path(dst).parent


def test_atomic_write_text_cleans_tempfile_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash inside ``os.replace`` must NOT leave a stray ``.tmp`` dropping.

    sec-pr-s3-6-06: the cleanup branch unlinks the tempfile on any
    failure path so the parent directory does not accumulate
    ``.policies.yaml.<random>.tmp`` debris from interrupted writes.
    """
    from alfred.cli.config import _atomic_write_text

    target = tmp_path / "policies.yaml"

    def _failing_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        del dst
        # Confirm the tempfile exists at the failure point so the cleanup
        # branch has something to remove.
        assert Path(src).exists()
        msg = "simulated mid-rename crash"
        raise OSError(msg)

    monkeypatch.setattr("alfred.cli.config.os.replace", _failing_replace)
    with pytest.raises(OSError, match="simulated mid-rename crash"):
        _atomic_write_text(target, "should-not-land")
    # No tempfiles left behind in the target directory.
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".policies.yaml.")]
    assert leftovers == []


# ---------------------------------------------------------------------------
# sec-pr-s3-6-01 — closed-set quarantined-provider validator wiring
# ---------------------------------------------------------------------------


def test_set_quarantined_provider_refuses_unknown_provider(
    runner: CliRunner,
) -> None:
    """``set quarantined-provider openai`` raises BadParameter.

    sec-pr-s3-6-01: only the closed set of declared providers
    (``anthropic`` + ``deepseek`` today) is allowed. An unknown
    provider id would otherwise land in a state.git proposal that the
    reviewer either has to notice or merge — the validator closes the
    parse-time refusal surface.
    """
    with patch("alfred.cli.config._state_git_client") as mock_client:
        result = runner.invoke(config_app, ["set", "quarantined-provider", "openai"])
    assert result.exit_code == 2
    # No proposal write — refusal short-circuited before the state.git call.
    mock_client.create_proposal_from_payload.assert_not_called()


def test_set_quarantined_provider_refuses_path_traversal(
    runner: CliRunner,
) -> None:
    """``set quarantined-provider ../etc/passwd`` raises BadParameter.

    The path-traversal canary on the high-blast knob: outside the
    closed set, refused with a localised body that enumerates the
    valid providers.
    """
    with patch("alfred.cli.config._state_git_client") as mock_client:
        result = runner.invoke(
            config_app,
            ["set", "quarantined-provider", "../../../etc/passwd"],
        )
    assert result.exit_code == 2
    mock_client.create_proposal_from_payload.assert_not_called()


def test_set_quarantined_provider_refuses_mixed_case_id(runner: CliRunner) -> None:
    """``set quarantined-provider Anthropic`` raises BadParameter.

    Validator is case-sensitive on purpose so the operator does not
    end up with a saved-vs-displayed mismatch on the next
    ``config get`` call.
    """
    with patch("alfred.cli.config._state_git_client") as mock_client:
        result = runner.invoke(
            config_app,
            ["set", "quarantined-provider", "Anthropic"],
        )
    assert result.exit_code == 2
    mock_client.create_proposal_from_payload.assert_not_called()


# ---------------------------------------------------------------------------
# Stage 3 (arch-001 / cross-cutting R2): per-CLI audit-row emission
# ---------------------------------------------------------------------------


def test_set_high_blast_emits_audit_row_before_state_git_write(
    runner: CliRunner,
) -> None:
    """High-blast ``config set`` emits ``config.set.requested`` BEFORE state.git."""
    call_order: list[tuple[str, dict[str, object]]] = []

    def _log_info(event: str, **kwargs: object) -> None:
        call_order.append((f"audit:{event}", dict(kwargs)))

    with (
        patch("alfred.cli.config._state_git_client") as mock_client,
        patch("alfred.cli._state_git._log") as mock_log,
    ):
        mock_log.info = _log_info

        def _side_effect(**_: object) -> ProposalResult:
            call_order.append(("state_git", {}))
            return ProposalResult(
                proposal_id="ff001122ff001122",
                branch="proposal/config-quarantined-provider-ff001122ff001122",
            )

        mock_client.create_proposal_from_payload.side_effect = _side_effect
        result = runner.invoke(
            config_app,
            ["set", "quarantined-provider", "anthropic"],
        )
    assert result.exit_code == 0, result.stderr
    audit_indices = [i for i, (label, _) in enumerate(call_order) if label.startswith("audit:")]
    state_indices = [i for i, (label, _) in enumerate(call_order) if label == "state_git"]
    assert len(audit_indices) == 1, call_order
    assert audit_indices[0] < state_indices[0]
    # Audit subject carries config_key but NOT the value (CLAUDE.md
    # hard rule #6: a future high-blast knob whose value carries
    # secret material would silently leak otherwise).
    _, audit_kwargs = call_order[audit_indices[0]]
    assert audit_kwargs["config_key"] == "quarantined-provider"
    assert "value" not in audit_kwargs


def test_set_low_blast_emits_no_audit_row(runner: CliRunner, tmp_path: Path) -> None:
    """Low-blast keys (no reviewer gate) MUST NOT emit ``config.set.requested``.

    The CLI mutates ``policies.yaml`` directly for these — there is no
    proposal flow to anchor an audit row to. The row family is the
    high-blast-only signal.
    """
    audit_events: list[str] = []

    def _log_info(event: str, **_: object) -> None:
        audit_events.append(event)

    yaml_path = tmp_path / "policies.yaml"

    with (
        patch("alfred.cli.config._policies_yaml_path", yaml_path),
        patch("alfred.cli._state_git._log") as mock_log,
    ):
        mock_log.info = _log_info
        result = runner.invoke(config_app, ["set", "web-fetch-budget", "30"])
    assert result.exit_code == 0, result.stderr
    assert "config.set.requested" not in audit_events


def test_set_high_blast_emits_no_audit_row_when_validator_refuses(
    runner: CliRunner,
) -> None:
    """A parser-time refusal of the high-blast value MUST NOT emit a row."""
    audit_events: list[str] = []

    def _log_info(event: str, **_: object) -> None:
        audit_events.append(event)

    with (
        patch("alfred.cli.config._state_git_client") as mock_client,
        patch("alfred.cli._state_git._log") as mock_log,
    ):
        mock_log.info = _log_info
        result = runner.invoke(
            config_app,
            ["set", "quarantined-provider", "../../etc/passwd"],
        )
    assert result.exit_code != 0
    assert "config.set.requested" not in audit_events
    mock_client.create_proposal_from_payload.assert_not_called()


def test_set_high_blast_emits_audit_row_even_on_state_git_failure(
    runner: CliRunner,
) -> None:
    """A state.git failure leaves the operator-intent audit row."""
    audit_events: list[str] = []

    def _log_info(event: str, **_: object) -> None:
        audit_events.append(event)

    with (
        patch("alfred.cli.config._state_git_client") as mock_client,
        patch("alfred.cli._state_git._log") as mock_log,
    ):
        mock_log.info = _log_info
        mock_client.create_proposal_from_payload.side_effect = StateGitError("nope")
        result = runner.invoke(
            config_app,
            ["set", "quarantined-provider", "anthropic"],
        )
    assert result.exit_code != 0
    assert "config.set.requested" in audit_events
