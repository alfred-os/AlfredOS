"""Spec §11.3 reviewer-gated async UX — ``alfred web allowlist`` sub-app.

Pins these invariants for the sub-app shipped in PR-S3-6:

* ``alfred web allowlist add <domain> [--path-prefix /v1/]`` writes a
  ``web-allowlist-add`` proposal via the module-level
  :class:`StateGitProposalClient` and prints the canonical pending-review
  block. The grant is queued — NOT activated until the reviewer approves.
* ``alfred web allowlist remove <domain>`` writes a
  ``web-allowlist-remove`` proposal with the same async-UX.
* ``alfred web allowlist list`` reads from the pluggable
  :func:`_list_allowlist_entries` seam so tests inject fake rows
  without touching Postgres.
* :class:`StateGitError` from either reviewer-gated path surfaces on
  stderr with a non-zero exit code (CLAUDE.md hard rule #7).

The tests deliberately mirror :mod:`tests.unit.cli.test_plugin_cli`'s
structure — both sub-apps share the state.git proposal flow and a
divergent test shape would mask a regression in either surface.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from alfred.cli._state_git import ProposalResult, StateGitError
from alfred.cli.web import web_app


@pytest.fixture()
def runner() -> CliRunner:
    """Typer test runner.

    Click 8.2 dropped ``mix_stderr``; ``Result.stdout`` and
    ``Result.stderr`` are always separate properties now.
    """
    return CliRunner()


@pytest.fixture()
def mock_add_proposal() -> ProposalResult:
    """Canned ``web-allowlist-add`` proposal result.

    Branch shape ``proposal/web-allowlist-add-<16-hex>`` mirrors the
    writer's canonical schema (see :mod:`alfred.cli._state_git`).
    """
    return ProposalResult(
        proposal_id="ff001122ff001122",
        branch="proposal/web-allowlist-add-ff001122ff001122",
    )


@pytest.fixture()
def mock_remove_proposal() -> ProposalResult:
    """Canned ``web-allowlist-remove`` proposal result."""
    return ProposalResult(
        proposal_id="aa334455aa334455",
        branch="proposal/web-allowlist-remove-aa334455aa334455",
    )


# ---------------------------------------------------------------------------
# allowlist add
# ---------------------------------------------------------------------------


def test_allowlist_add_prints_proposal_branch(
    runner: CliRunner, mock_add_proposal: ProposalResult
) -> None:
    """Operator sees the proposal branch name to git show the proposal."""
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_add_proposal
        result = runner.invoke(web_app, ["allowlist", "add", "example.com"])
    assert result.exit_code == 0, result.stderr
    assert mock_add_proposal.branch in result.stdout


def test_allowlist_add_uses_pending_review_language(
    runner: CliRunner, mock_add_proposal: ProposalResult
) -> None:
    """Add is queued — operator MUST NOT see "now allowed" text.

    Spec §11.1: adding a domain to the allowlist widens the trust
    surface and requires reviewer-gate approval. The CLI cannot
    truthfully claim the domain is fetchable until the proposal merges.
    """
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_add_proposal
        result = runner.invoke(web_app, ["allowlist", "add", "example.com"])
    assert "now allowed" not in result.stdout.lower()
    assert "is now fetchable" not in result.stdout.lower()
    assert "pending" in result.stdout.lower() or "proposal" in result.stdout.lower()


def test_allowlist_add_payload_carries_domain_and_path_prefix(
    runner: CliRunner, mock_add_proposal: ProposalResult
) -> None:
    """The proposal payload carries domain + path_prefix as structured fields.

    CLAUDE.md hard rule #6: payloads are structured dicts of identifiers
    + policy knobs; the reviewer reads these to decide approve/reject.
    Defaulting path_prefix to ``/`` matches the spec §7.4 normalisation.
    """
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_add_proposal
        runner.invoke(web_app, ["allowlist", "add", "api.example.com", "--path-prefix", "/v1/"])
    call_kwargs = mock_client.create_proposal.call_args.kwargs
    assert call_kwargs["proposal_type"] == "web-allowlist-add"
    assert call_kwargs["payload"] == {
        "domain": "api.example.com",
        "path_prefix": "/v1/",
    }


def test_allowlist_add_default_path_prefix_is_root(
    runner: CliRunner, mock_add_proposal: ProposalResult
) -> None:
    """When --path-prefix is omitted, the payload defaults to ``/``."""
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_add_proposal
        runner.invoke(web_app, ["allowlist", "add", "example.com"])
    call_kwargs = mock_client.create_proposal.call_args.kwargs
    assert call_kwargs["payload"]["path_prefix"] == "/"


def test_allowlist_add_surfaces_state_git_error(runner: CliRunner) -> None:
    """State.git failure surfaces on stderr (CLAUDE.md hard rule #7)."""
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal.side_effect = StateGitError("push refused")
        result = runner.invoke(web_app, ["allowlist", "add", "example.com"])
    assert result.exit_code != 0
    assert result.stderr.strip() != ""


# ---------------------------------------------------------------------------
# allowlist remove
# ---------------------------------------------------------------------------


def test_allowlist_remove_prints_proposal_branch(
    runner: CliRunner, mock_remove_proposal: ProposalResult
) -> None:
    """Remove is reviewer-gated; same async-UX as add."""
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_remove_proposal
        result = runner.invoke(web_app, ["allowlist", "remove", "example.com"])
    assert result.exit_code == 0, result.stderr
    assert mock_remove_proposal.branch in result.stdout


def test_allowlist_remove_payload_carries_domain(
    runner: CliRunner, mock_remove_proposal: ProposalResult
) -> None:
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_remove_proposal
        runner.invoke(web_app, ["allowlist", "remove", "example.com"])
    call_kwargs = mock_client.create_proposal.call_args.kwargs
    assert call_kwargs["proposal_type"] == "web-allowlist-remove"
    assert call_kwargs["payload"] == {"domain": "example.com"}


def test_allowlist_remove_surfaces_state_git_error(runner: CliRunner) -> None:
    """State.git failure on the remove path surfaces too."""
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal.side_effect = StateGitError("nope")
        result = runner.invoke(web_app, ["allowlist", "remove", "example.com"])
    assert result.exit_code != 0
    assert result.stderr.strip() != ""


# ---------------------------------------------------------------------------
# allowlist list
# ---------------------------------------------------------------------------


def test_allowlist_list_renders_rows(runner: CliRunner) -> None:
    """``allowlist list`` renders projection rows via the injectable seam."""
    rows: list[dict[str, object]] = [
        {
            "domain": "api.example.com",
            "path_prefix": "/v1/",
            "granted_by": "operator",
            "granted_at": "2026-05-31",
        },
        {
            "domain": "static.example.com",
            "path_prefix": "/",
            "granted_by": "operator",
            "granted_at": "2026-06-01",
        },
    ]
    with patch("alfred.cli.web._list_allowlist_entries", return_value=rows):
        result = runner.invoke(web_app, ["allowlist", "list"])
    assert result.exit_code == 0, result.stderr
    assert "api.example.com" in result.stdout
    assert "static.example.com" in result.stdout
    assert "/v1/" in result.stdout
    assert "operator" in result.stdout


def test_allowlist_list_empty_emits_hint(runner: CliRunner) -> None:
    """Empty projection MUST emit a localised hint, not silent-blank.

    devex-011 parity with the plugin CLI: silent-blank is misread as
    "no domains allowed" when it really means "no rows in the projection
    yet" (e.g. a fresh deployment with no operator-added entries).
    """
    with patch("alfred.cli.web._list_allowlist_entries", return_value=[]):
        result = runner.invoke(web_app, ["allowlist", "list"])
    assert result.exit_code == 0
    assert result.stdout.strip() != ""


def test_list_allowlist_entries_default_is_empty_list() -> None:
    """The pre-PR-S3-7 ``_list_allowlist_entries`` stub returns ``[]``.

    Same projection-seam invariant as the plugin sub-app's
    ``_list_pending_grants``: a fresh deployment has no operator-added
    allowlist rows, so the seam returning anything other than ``[]``
    until PR-S3-7 wires the Postgres ``web_allowlist`` projection would
    be a silent-fake bug. Pinning the default keeps any drift visible.
    """
    from alfred.cli.web import _list_allowlist_entries

    assert _list_allowlist_entries() == []
