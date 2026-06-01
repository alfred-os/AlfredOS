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
        mock_client.create_proposal.return_value = proposal
        result = runner.invoke(config_app, ["set", "quarantined-provider", "anthropic"])
    assert result.exit_code == 0, result.stderr
    call_kwargs = mock_client.create_proposal.call_args.kwargs
    assert call_kwargs["proposal_type"] == "config-quarantined-provider"
    assert call_kwargs["payload"] == {
        "key": "quarantined-provider",
        "value": "anthropic",
    }
    assert proposal.branch in result.stdout


def test_set_high_blast_uses_pending_review_language(runner: CliRunner) -> None:
    """High-blast path MUST NOT print a success message — it's queued."""
    proposal = ProposalResult(
        proposal_id="cc778899cc778899",
        branch="proposal/config-quarantined-provider-cc778899cc778899",
    )
    with patch("alfred.cli.config._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = proposal
        result = runner.invoke(config_app, ["set", "quarantined-provider", "anthropic"])
    assert "now active" not in result.stdout.lower()
    assert "pending" in result.stdout.lower() or "proposal" in result.stdout.lower()


def test_set_high_blast_surfaces_state_git_error(runner: CliRunner) -> None:
    """state.git failure on the high-blast path surfaces on stderr."""
    with patch("alfred.cli.config._state_git_client") as mock_client:
        mock_client.create_proposal.side_effect = StateGitError("push refused")
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
