"""Spec §11.3 reviewer-gated async UX — ``alfred plugin`` sub-app.

Pins these invariants for the sub-app shipped in PR-S3-6:

* ``alfred plugin grant <plugin> <tier> <hookpoint>`` writes a state.git
  proposal via the module-level :class:`StateGitProposalClient` and prints
  the resulting proposal branch + follow-up ``grant status`` command.
* The output is the pending-review variant, NOT a success message — the
  grant is queued, not active (spec §11.1 reviewer-gate + human approval).
* A :class:`StateGitError` from the client surfaces as a localised
  operator-facing error on stderr with a non-zero exit code (CLAUDE.md
  hard rule #7 — no silent failures in security paths).
* ``alfred plugin grant list --pending`` reads from the pluggable
  ``_list_pending_grants`` seam so tests inject fake projection rows
  without touching Postgres.
* ``alfred plugin grant status <proposal_id>`` echoes the canonical
  branch name so the operator can ``git`` against state.git directly.
* ``alfred plugin revoke <plugin>`` writes a ``policy-revoke`` proposal
  with identical async-UX (queued, not yet applied).
* ``alfred plugin list`` / ``alfred plugin show`` return ``exit_code=2``
  with a not-implemented-yet message (devex-011 in plan §548 — we MUST
  NOT emit silent-empty output that an operator misreads as
  "no plugins loaded"; the full Postgres-projection query lands in
  PR-S3-7).

The pure-CLI coverage here is sufficient because the production code
paths under test (i) shell out to ``git`` via the
:class:`StateGitProposalClient` which already has its own
end-to-end coverage in :mod:`tests.unit.cli.test_state_git`, and
(ii) read from an injectable seam (``_list_pending_grants``) that the
PR-S3-7 wiring will replace wholesale. Both legs are mocked so the test
suite stays sub-second.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from alfred.cli._state_git import ProposalResult, StateGitError
from alfred.cli.plugin import plugin_app


@pytest.fixture()
def runner() -> CliRunner:
    """Typer test runner.

    Click 8.2 (which ships with Typer 0.16+) dropped the ``mix_stderr``
    kwarg — ``Result.stdout`` and ``Result.stderr`` are always separate
    properties now, so every error-path assertion below pins that the
    localised message lands on stderr without per-runner configuration.
    """
    return CliRunner()


@pytest.fixture(autouse=True)
def _stub_validator_hookpoint_registry() -> object:
    """Pin the closed-set hookpoint registry for every test in this module.

    sec-pr-s3-6-01 wires :func:`alfred.cli._validators.validate_hookpoint`
    into the ``grant`` dispatcher. The validator reads the live
    HookRegistry singleton; under pytest the singleton's ``_hookpoints``
    map is empty (no publisher's ``declare_hookpoints`` ran in this
    fresh process), so a plain ``alfred plugin grant ... plugin.grant.requested``
    would surface the empty-registry refusal.

    The fixture pins the closed iterable for every test so the validator
    behaves as it does in production (publisher modules imported,
    registry populated) without coupling these CLI tests to whichever
    publisher modules the pytest collector happens to import first.
    Tests that need the empty-registry branch patch the seam locally.
    """
    with patch(
        "alfred.cli._validators._known_hookpoints_provider",
        lambda: (
            "plugin.grant.requested",
            "plugin.grant.approved",
            "plugin.grant.denied",
            "plugin.grant.revoked",
        ),
    ) as p:
        yield p


@pytest.fixture()
def mock_proposal() -> ProposalResult:
    """A canned proposal-result the StateGitProposalClient would return.

    Branch shape ``proposal/policy-grant-<16-hex>`` mirrors the writer's
    canonical schema (see plan §164 + ``_state_git.py``'s ``_BRANCH_PREFIX``).
    """
    return ProposalResult(
        proposal_id="abc12345abc12345",
        branch="proposal/policy-grant-abc12345abc12345",
    )


# ---------------------------------------------------------------------------
# grant <plugin> <tier> <hookpoint>
# ---------------------------------------------------------------------------


def test_grant_prints_proposal_branch(runner: CliRunner, mock_proposal: ProposalResult) -> None:
    """Operator sees the branch name so they can git show the proposal."""
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_proposal
        result = runner.invoke(
            plugin_app,
            ["grant", "alfred.web-fetch", "system", "plugin.grant.requested"],
        )
    assert result.exit_code == 0, result.stderr
    assert mock_proposal.branch in result.stdout


def test_grant_prints_follow_up_status_command(
    runner: CliRunner, mock_proposal: ProposalResult
) -> None:
    """The follow-up ``grant status`` command is shown verbatim so an
    operator can copy-paste it without guessing the proposal_id."""
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_proposal
        result = runner.invoke(
            plugin_app,
            ["grant", "alfred.web-fetch", "system", "plugin.grant.requested"],
        )
    assert "alfred plugin grant status" in result.stdout
    assert mock_proposal.proposal_id in result.stdout


def test_grant_uses_pending_review_not_success(
    runner: CliRunner, mock_proposal: ProposalResult
) -> None:
    """Grant is queued — the operator MUST NOT see "now active" text.

    Spec §11.1: reviewer-gated changes are asynchronous. The CLI cannot
    truthfully claim the grant is in effect until the reviewer merges
    the proposal branch and RealGate.rebuild_from_state_git fires.
    """
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_proposal
        result = runner.invoke(
            plugin_app,
            ["grant", "alfred.web-fetch", "system", "plugin.grant.requested"],
        )
    assert "now active" not in result.stdout.lower()
    assert "is now granted" not in result.stdout.lower()
    # Pending/proposal language must surface so the operator understands
    # they have to wait for reviewer approval.
    assert "pending" in result.stdout.lower() or "proposal" in result.stdout.lower()


def test_grant_passes_structured_payload_to_client(
    runner: CliRunner, mock_proposal: ProposalResult
) -> None:
    """The proposal payload carries the three CLI args as structured fields.

    CLAUDE.md hard rule #6: payloads are structured dicts of identifiers
    + policy knobs — never raw secret values. The reviewer reads these
    fields to decide approve/reject, so the field shape is load-bearing.
    """
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_proposal
        runner.invoke(
            plugin_app,
            ["grant", "alfred.web-fetch", "system", "plugin.grant.requested"],
        )
    mock_client.create_proposal.assert_called_once()
    call_kwargs = mock_client.create_proposal.call_args.kwargs
    assert call_kwargs["proposal_type"] == "policy-grant"
    payload = call_kwargs["payload"]
    assert payload["plugin_id"] == "alfred.web-fetch"
    assert payload["subscriber_tier"] == "system"
    assert payload["hookpoint"] == "plugin.grant.requested"


def test_grant_surfaces_state_git_error_on_stderr(runner: CliRunner) -> None:
    """A failed proposal write MUST surface — CLAUDE.md hard rule #7."""
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        mock_client.create_proposal.side_effect = StateGitError(
            "state.git command failed: git push"
        )
        result = runner.invoke(
            plugin_app,
            ["grant", "alfred.web-fetch", "system", "plugin.grant.requested"],
        )
    assert result.exit_code != 0
    assert "state.git" in result.stderr or "denied" in result.stderr.lower()


# ---------------------------------------------------------------------------
# grant status <proposal_id>
# ---------------------------------------------------------------------------


def test_grant_status_echoes_canonical_branch(runner: CliRunner) -> None:
    """``grant status`` echoes the canonical proposal branch name.

    Until PR-S3-7 wires the Postgres ``plugin_grants`` projection query,
    the status command emits the pending-with-branch message — explicit
    placeholder so an operator knows where the proposal lives.
    """
    result = runner.invoke(plugin_app, ["grant", "status", "abc12345abc12345"])
    assert result.exit_code == 0, result.stderr
    assert "proposal/policy-grant-abc12345abc12345" in result.stdout


# ---------------------------------------------------------------------------
# grant list --pending
# ---------------------------------------------------------------------------


def test_grant_list_pending_renders_projection_rows(runner: CliRunner) -> None:
    """``grant list --pending`` reads the injectable projection seam."""
    rows: list[dict[str, object]] = [
        {
            "proposal_id": "abc12345abc12345",
            "plugin_id": "alfred.web-fetch",
            "subscriber_tier": "system",
            "hookpoint": "tool.web.fetch",
            "status": "pending",
        }
    ]
    with patch("alfred.cli.plugin._list_pending_grants", return_value=rows):
        result = runner.invoke(plugin_app, ["grant", "list", "--pending"])
    assert result.exit_code == 0, result.stderr
    assert "alfred.web-fetch" in result.stdout
    assert "system" in result.stdout


def test_grant_list_pending_empty_emits_hint(runner: CliRunner) -> None:
    """Empty projection emits a localised hint, NOT silent-blank output."""
    with patch("alfred.cli.plugin._list_pending_grants", return_value=[]):
        result = runner.invoke(plugin_app, ["grant", "list", "--pending"])
    assert result.exit_code == 0
    assert result.stdout.strip() != ""


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


def test_revoke_writes_policy_revoke_proposal(runner: CliRunner) -> None:
    """``revoke`` is reviewer-gated; same async-UX as grant."""
    mock_proposal = ProposalResult(
        proposal_id="deadbeefdeadbeef",
        branch="proposal/policy-revoke-deadbeefdeadbeef",
    )
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        mock_client.create_proposal.return_value = mock_proposal
        result = runner.invoke(plugin_app, ["revoke", "alfred.web-fetch"])
    assert result.exit_code == 0, result.stderr
    call_kwargs = mock_client.create_proposal.call_args.kwargs
    assert call_kwargs["proposal_type"] == "policy-revoke"
    assert call_kwargs["payload"] == {"plugin_id": "alfred.web-fetch"}
    assert mock_proposal.branch in result.stdout


def test_revoke_surfaces_state_git_error(runner: CliRunner) -> None:
    """Revoke failure surfaces on stderr (hard rule #7)."""
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        mock_client.create_proposal.side_effect = StateGitError("nope")
        result = runner.invoke(plugin_app, ["revoke", "alfred.web-fetch"])
    assert result.exit_code != 0
    assert result.stderr.strip() != ""


# ---------------------------------------------------------------------------
# list / show
# ---------------------------------------------------------------------------


def test_list_returns_not_implemented_exit_code(runner: CliRunner) -> None:
    """``plugin list`` is a PR-S3-7 follow-up; until then, exit non-zero
    with an explicit not-implemented message so silent-blank output
    cannot be misread as "no plugins loaded" (devex-011)."""
    result = runner.invoke(plugin_app, ["list"])
    assert result.exit_code == 2
    assert result.stderr.strip() != ""


def test_show_returns_localised_placeholder(runner: CliRunner) -> None:
    """``plugin show`` echoes the plugin_id and a localised hint.

    Until PR-S3-7 wires the manifest projection, the show command MUST
    NOT return an empty body — that would silently mask "no such plugin"
    vs "no manifest loaded yet" cases.
    """
    result = runner.invoke(plugin_app, ["show", "alfred.web-fetch"])
    assert result.exit_code == 0, result.stderr
    assert "alfred.web-fetch" in result.stdout


# ---------------------------------------------------------------------------
# coverage-closing fixups — empty-projection default + grant usage errors
# ---------------------------------------------------------------------------


def test_list_pending_grants_default_is_empty_list() -> None:
    """The pre-PR-S3-7 ``_list_pending_grants`` stub returns ``[]``.

    The stub is the projection seam that PR-S3-7 replaces with a Postgres
    query. Until then, an empty list is the only correct value (no grants
    have been applied in a fresh deployment). Pinning the default keeps a
    future "return a placeholder row" change visible on review — the seam
    must NOT pretend grants exist when the projection hasn't been wired.
    """
    from alfred.cli.plugin import _list_pending_grants

    assert _list_pending_grants() == []


def test_grant_status_without_proposal_id_raises_usage_error(runner: CliRunner) -> None:
    """``alfred plugin grant status`` with no proposal_id exits non-zero.

    Typer cannot enforce arity here because ``grant`` swallows ``ctx.args``
    to support the shorthand ``grant <plugin> <tier> <hookpoint>`` form.
    The dispatch helper validates arity itself and emits a localised
    usage error on stderr; without this check a missing proposal_id would
    crash with an ``IndexError`` instead of a friendly hint (devex-011).
    """
    result = runner.invoke(plugin_app, ["grant", "status"])
    assert result.exit_code == 2
    assert result.stderr.strip() != ""


def test_grant_with_wrong_arity_raises_usage_error(runner: CliRunner) -> None:
    """``alfred plugin grant <plugin>`` (missing tier + hookpoint) errors.

    Same root cause as the status-arity guard: ``grant`` accepts variadic
    positional args to multiplex between the reserved subcommands and the
    shorthand grant-request form, so it must validate the shorthand arity
    itself. Missing positionals produce a localised usage error rather
    than a stack trace.
    """
    result = runner.invoke(plugin_app, ["grant", "alfred.web-fetch"])
    assert result.exit_code == 2
    assert result.stderr.strip() != ""


# ---------------------------------------------------------------------------
# sec-pr-s3-6-01 — closed-set validator wiring: BadParameter trio
# ---------------------------------------------------------------------------


def test_grant_refuses_path_traversal_in_plugin_id(runner: CliRunner) -> None:
    """``alfred plugin grant ../../etc/passwd ...`` raises BadParameter.

    sec-pr-s3-6-01: an operator-typed path-traversal string must NOT
    reach the state.git proposal payload. The :func:`validate_plugin_id`
    callback wired into the ``grant`` dispatcher refuses the input at
    parse time so the proposal-write call site never runs.
    """
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        result = runner.invoke(
            plugin_app,
            ["grant", "../../../etc/passwd", "system", "plugin.grant.requested"],
        )
    assert result.exit_code == 2
    assert "plugin_id" in result.stderr.lower() or "invalid" in result.stderr.lower()
    # The proposal write MUST NOT have been called — the parse-time
    # refusal short-circuited before the dispatch body.
    mock_client.create_proposal.assert_not_called()


def test_grant_refuses_invalid_subscriber_tier(runner: CliRunner) -> None:
    """``alfred plugin grant <id> T4 <hookpoint>`` raises BadParameter.

    sec-pr-s3-6-01: subscriber-tier is the capability axis
    (system/operator/user-plugin); a content-trust-tier string (T0..T3)
    or any out-of-set value is refused. ``T4`` is the brief's canonical
    typo example.
    """
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        result = runner.invoke(
            plugin_app,
            ["grant", "alfred.web-fetch", "T4", "plugin.grant.requested"],
        )
    assert result.exit_code == 2
    assert "subscriber_tier" in result.stderr.lower() or "invalid" in result.stderr.lower()
    mock_client.create_proposal.assert_not_called()


def test_grant_refuses_unknown_hookpoint(runner: CliRunner) -> None:
    """``alfred plugin grant <id> <tier> <bogus>`` raises BadParameter.

    sec-pr-s3-6-01: a hookpoint no publisher has declared cannot fire,
    so a grant against it would land a never-firing entry in state.git.
    The validator refuses with the closest matches surfaced from the
    closed set.
    """
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        result = runner.invoke(
            plugin_app,
            ["grant", "alfred.web-fetch", "system", "plugin.grant.requestd"],
        )
    assert result.exit_code == 2
    assert "hookpoint" in result.stderr.lower() or "invalid" in result.stderr.lower()
    mock_client.create_proposal.assert_not_called()


def test_revoke_refuses_invalid_plugin_id(runner: CliRunner) -> None:
    """``alfred plugin revoke ../etc`` raises BadParameter.

    Same path-traversal refusal as ``grant`` — the revoke surface also
    flows into a state.git proposal payload, so the closed-set check
    applies on the revoke command's plugin_id too.
    """
    with patch("alfred.cli.plugin._state_git_client") as mock_client:
        result = runner.invoke(plugin_app, ["revoke", "../../../etc/passwd"])
    assert result.exit_code == 2
    mock_client.create_proposal.assert_not_called()
