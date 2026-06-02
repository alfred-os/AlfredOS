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
        mock_client.create_proposal_from_payload.return_value = mock_add_proposal
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
        mock_client.create_proposal_from_payload.return_value = mock_add_proposal
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
        mock_client.create_proposal_from_payload.return_value = mock_add_proposal
        runner.invoke(web_app, ["allowlist", "add", "api.example.com", "--path-prefix", "/v1/"])
    # ADR-0018: typed WebAllowlistProposal replaces the dict payload.
    from alfred.state.proposal_payloads import WebAllowlistProposal

    call_kwargs = mock_client.create_proposal_from_payload.call_args.kwargs
    payload = call_kwargs["payload"]
    assert isinstance(payload, WebAllowlistProposal)
    assert payload.action == "add"
    assert payload.domain == "api.example.com"
    assert payload.path_prefix == "/v1/"


def test_web_allowlist_proposal_action_add_rejects_none_path_prefix() -> None:
    """CR-149 round-3: ``WebAllowlistProposal(action="add", path_prefix=None)`` is refused.

    The docstring already documented the invariant — ``add`` carries a
    real path-prefix; ``remove`` encodes whole-entry deletion via
    ``None``. The CLI's add path defaults ``path_prefix`` to ``"/"``
    so the bad shape never reached the model from the CLI, but any
    non-CLI producer (async writer, state.git replay tool, malformed
    test fixture) could still emit an ambiguous add proposal and
    drift from spec §11.1's add-vs-remove semantics. The
    ``@model_validator`` closes that boundary at construction.
    """
    from pydantic import ValidationError

    from alfred.state.proposal_payloads import WebAllowlistProposal

    with pytest.raises(ValidationError, match="path_prefix"):
        WebAllowlistProposal(action="add", domain="example.com", path_prefix=None)


def test_web_allowlist_proposal_action_remove_allows_none_path_prefix() -> None:
    """The ``remove`` path permits ``path_prefix=None`` (whole-entry delete).

    Pairs with the add-side rejection: the ``remove`` path's canonical
    shape is ``path_prefix=None`` (the CLI's documented choice for
    whole-entry deletion), so the validator MUST NOT block it.
    Constructing the payload succeeds.
    """
    from alfred.state.proposal_payloads import WebAllowlistProposal

    payload = WebAllowlistProposal(action="remove", domain="example.com", path_prefix=None)
    assert payload.action == "remove"
    assert payload.path_prefix is None


def test_web_allowlist_proposal_remove_default_is_none() -> None:
    """CR-149 round-6: omitting ``path_prefix`` on the remove path defaults to ``None``.

    Spec §11.1: whole-entry deletion is encoded as ``path_prefix=None``.
    The previous field default was ``"/"`` so a non-CLI producer that
    constructed ``WebAllowlistProposal(action="remove", domain=...)``
    silently emitted "remove root-prefix only" instead of "remove
    whole entry". Defaulting to ``None`` makes the spec-canonical
    shape the path-of-least-resistance, while a ``mode="before"``
    normalizer restores the historical ``"/"`` for the add path so
    the CLI's add surface keeps working.
    """
    from alfred.state.proposal_payloads import WebAllowlistProposal

    payload = WebAllowlistProposal(action="remove", domain="example.com")
    assert payload.path_prefix is None


def test_web_allowlist_proposal_add_default_normalises_to_root() -> None:
    """CR-149 round-6: omitting ``path_prefix`` on the add path normalises to ``"/"``.

    Pairs with the remove-default flip: the ``mode="before"``
    normalizer restores the historical ``"/"`` default ONLY when the
    field is omitted on ``action="add"``. An explicit
    ``path_prefix=None`` on the add path is still refused by
    ``_check_action_path_prefix_invariant`` (the existing
    round-3 boundary stays loud).
    """
    from alfred.state.proposal_payloads import WebAllowlistProposal

    payload = WebAllowlistProposal(action="add", domain="example.com")
    assert payload.path_prefix == "/"


def test_allowlist_add_default_path_prefix_is_root(
    runner: CliRunner, mock_add_proposal: ProposalResult
) -> None:
    """When --path-prefix is omitted, the payload defaults to ``/``."""
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal_from_payload.return_value = mock_add_proposal
        runner.invoke(web_app, ["allowlist", "add", "example.com"])
    call_kwargs = mock_client.create_proposal_from_payload.call_args.kwargs
    payload = call_kwargs["payload"]
    # Pydantic model exposes the field directly; the default ``/`` lands
    # when --path-prefix is omitted.
    assert payload.path_prefix == "/"


def test_allowlist_add_surfaces_state_git_error(runner: CliRunner) -> None:
    """State.git failure surfaces on stderr (CLAUDE.md hard rule #7)."""
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal_from_payload.side_effect = StateGitError("push refused")
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
        mock_client.create_proposal_from_payload.return_value = mock_remove_proposal
        result = runner.invoke(web_app, ["allowlist", "remove", "example.com"])
    assert result.exit_code == 0, result.stderr
    assert mock_remove_proposal.branch in result.stdout


def test_allowlist_remove_payload_carries_domain(
    runner: CliRunner, mock_remove_proposal: ProposalResult
) -> None:
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal_from_payload.return_value = mock_remove_proposal
        runner.invoke(web_app, ["allowlist", "remove", "example.com"])
    # ADR-0018: typed WebAllowlistProposal with action="remove".
    from alfred.state.proposal_payloads import WebAllowlistProposal

    call_kwargs = mock_client.create_proposal_from_payload.call_args.kwargs
    payload = call_kwargs["payload"]
    assert isinstance(payload, WebAllowlistProposal)
    assert payload.action == "remove"
    assert payload.domain == "example.com"
    # CR-149 round-6: spec §11.1 whole-entry delete contract — the
    # remove path materialises with ``path_prefix=None``. The previous
    # assertion only pinned ``action`` + ``domain``; an ``allowlist_remove()``
    # regression that slipped back to the historical ``"/"`` default
    # (which means "remove root-prefix only") would still pass without
    # this check.
    assert payload.path_prefix is None


def test_allowlist_add_audit_row_carries_t1_trust_tier(
    runner: CliRunner, mock_add_proposal: ProposalResult
) -> None:
    """CR-149 round-6: ``web.allowlist.requested`` row tags T1 on add.

    Same rationale as the plugin-grant regression — operator-typed
    CLI ingress declares its swimlane. The
    ``WEB_ALLOWLIST_REQUESTED_FIELDS`` constant now carries the field
    so the symmetric-keys helper would reject a drop at the emit site;
    this assertion pins the value to ``"T1"`` so a refactor that swaps
    to ``"T0"`` (or drops it entirely) surfaces here.
    """
    captured: list[dict[str, object]] = []

    def _log_info(event: str, **kwargs: object) -> None:
        if event == "web.allowlist.requested":
            captured.append(kwargs)

    with (
        patch("alfred.cli.web._state_git_client") as mock_client,
        patch("alfred.cli._state_git._log") as mock_log,
    ):
        mock_log.info = _log_info
        mock_client.create_proposal_from_payload.return_value = mock_add_proposal
        result = runner.invoke(web_app, ["allowlist", "add", "example.com"])
    assert result.exit_code == 0, result.stderr
    assert len(captured) == 1, captured
    assert captured[0]["trust_tier_of_trigger"] == "T1"


def test_allowlist_remove_audit_row_carries_t1_trust_tier(
    runner: CliRunner, mock_remove_proposal: ProposalResult
) -> None:
    """CR-149 round-6: ``web.allowlist.requested`` row tags T1 on remove."""
    captured: list[dict[str, object]] = []

    def _log_info(event: str, **kwargs: object) -> None:
        if event == "web.allowlist.requested":
            captured.append(kwargs)

    with (
        patch("alfred.cli.web._state_git_client") as mock_client,
        patch("alfred.cli._state_git._log") as mock_log,
    ):
        mock_log.info = _log_info
        mock_client.create_proposal_from_payload.return_value = mock_remove_proposal
        result = runner.invoke(web_app, ["allowlist", "remove", "example.com"])
    assert result.exit_code == 0, result.stderr
    assert len(captured) == 1, captured
    assert captured[0]["trust_tier_of_trigger"] == "T1"


def test_allowlist_remove_surfaces_state_git_error(runner: CliRunner) -> None:
    """State.git failure on the remove path surfaces too."""
    with patch("alfred.cli.web._state_git_client") as mock_client:
        mock_client.create_proposal_from_payload.side_effect = StateGitError("nope")
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


# ---------------------------------------------------------------------------
# sec-pr-s3-6-01 — closed-set domain validator wiring: BadParameter trio
# ---------------------------------------------------------------------------


def test_allowlist_add_refuses_url_with_scheme(runner: CliRunner) -> None:
    """``alfred web allowlist add https://example.com`` raises BadParameter.

    sec-pr-s3-6-01: the proposal's ``domain`` field expects the bare
    host. The :func:`validate_domain` callback surfaces a dedicated
    "drop the scheme" hint before the proposal-write call runs.
    """
    with patch("alfred.cli.web._state_git_client") as mock_client:
        result = runner.invoke(web_app, ["allowlist", "add", "https://example.com"])
    assert result.exit_code == 2
    mock_client.create_proposal_from_payload.assert_not_called()


def test_allowlist_add_refuses_path_traversal(runner: CliRunner) -> None:
    """``alfred web allowlist add ../etc`` raises BadParameter.

    Defence-in-depth on top of the regex — a ``..`` substring or any
    path separator is refused with its own localised body so the
    operator sees an explicit hint rather than a generic regex failure.
    """
    with patch("alfred.cli.web._state_git_client") as mock_client:
        result = runner.invoke(web_app, ["allowlist", "add", "../../etc/passwd"])
    assert result.exit_code == 2
    mock_client.create_proposal_from_payload.assert_not_called()


def test_allowlist_add_refuses_off_shape_domain(runner: CliRunner) -> None:
    """``alfred web allowlist add not-a-domain`` raises BadParameter.

    Anything outside the bare-domain regex (single-label, mixed-case,
    TLD too short) is refused at parse time.
    """
    with patch("alfred.cli.web._state_git_client") as mock_client:
        result = runner.invoke(web_app, ["allowlist", "add", "Example.com"])
    assert result.exit_code == 2
    mock_client.create_proposal_from_payload.assert_not_called()


def test_allowlist_remove_refuses_url_with_scheme(runner: CliRunner) -> None:
    """``alfred web allowlist remove https://...`` raises BadParameter.

    The remove path validates ``domain`` against the same rules as
    ``add`` — the proposal payload must carry a bare host either way.
    """
    with patch("alfred.cli.web._state_git_client") as mock_client:
        result = runner.invoke(web_app, ["allowlist", "remove", "http://example.com"])
    assert result.exit_code == 2
    mock_client.create_proposal_from_payload.assert_not_called()


# ---------------------------------------------------------------------------
# Stage 3 (arch-001 / cross-cutting R2): per-CLI audit-row emission
# ---------------------------------------------------------------------------


def test_allowlist_add_emits_audit_row_before_state_git_write(
    runner: CliRunner, mock_add_proposal: ProposalResult
) -> None:
    """``alfred web allowlist add`` emits ``web.allowlist.requested`` BEFORE state.git.

    Stage 3 / arch-001: ``action="add"`` distinguishes from the remove
    path so the audit-graph correlator can join the CLI emit with the
    eventual projection-merge row.
    """
    call_order: list[tuple[str, dict[str, object]]] = []

    def _log_info(event: str, **kwargs: object) -> None:
        call_order.append((f"audit:{event}", dict(kwargs)))

    with (
        patch("alfred.cli.web._state_git_client") as mock_client,
        patch("alfred.cli._state_git._log") as mock_log,
    ):
        mock_log.info = _log_info

        def _side_effect(**_: object) -> ProposalResult:
            call_order.append(("state_git", {}))
            return mock_add_proposal

        mock_client.create_proposal_from_payload.side_effect = _side_effect
        result = runner.invoke(web_app, ["allowlist", "add", "api.example.com"])
    assert result.exit_code == 0, result.stderr
    # Audit event fired exactly once before state.git.
    audit_indices = [i for i, (label, _) in enumerate(call_order) if label.startswith("audit:")]
    state_indices = [i for i, (label, _) in enumerate(call_order) if label == "state_git"]
    assert len(audit_indices) == 1, call_order
    assert audit_indices[0] < state_indices[0]
    # The audit subject carries action="add" and the domain.
    _, audit_kwargs = call_order[audit_indices[0]]
    assert audit_kwargs["action"] == "add"
    assert audit_kwargs["domain"] == "api.example.com"


def test_allowlist_remove_emits_audit_row_before_state_git_write(
    runner: CliRunner, mock_remove_proposal: ProposalResult
) -> None:
    """``alfred web allowlist remove`` emits ``web.allowlist.requested`` BEFORE state.git.

    Stage 3 / arch-001: ``action="remove"``. ``path_prefix`` is ``None``
    because remove targets an entry as a whole.
    """
    call_order: list[tuple[str, dict[str, object]]] = []

    def _log_info(event: str, **kwargs: object) -> None:
        call_order.append((f"audit:{event}", dict(kwargs)))

    with (
        patch("alfred.cli.web._state_git_client") as mock_client,
        patch("alfred.cli._state_git._log") as mock_log,
    ):
        mock_log.info = _log_info

        def _side_effect(**_: object) -> ProposalResult:
            call_order.append(("state_git", {}))
            return mock_remove_proposal

        mock_client.create_proposal_from_payload.side_effect = _side_effect
        result = runner.invoke(web_app, ["allowlist", "remove", "api.example.com"])
    assert result.exit_code == 0, result.stderr
    audit_indices = [i for i, (label, _) in enumerate(call_order) if label.startswith("audit:")]
    state_indices = [i for i, (label, _) in enumerate(call_order) if label == "state_git"]
    assert len(audit_indices) == 1, call_order
    assert audit_indices[0] < state_indices[0]
    _, audit_kwargs = call_order[audit_indices[0]]
    assert audit_kwargs["action"] == "remove"
    assert audit_kwargs["path_prefix"] is None


def test_allowlist_add_emits_no_audit_row_when_validator_refuses(runner: CliRunner) -> None:
    """A parser-time refusal must NOT emit a ``web.allowlist.requested`` row."""
    audit_events: list[str] = []

    def _log_info(event: str, **_: object) -> None:
        audit_events.append(event)

    with (
        patch("alfred.cli.web._state_git_client") as mock_client,
        patch("alfred.cli._state_git._log") as mock_log,
    ):
        mock_log.info = _log_info
        result = runner.invoke(web_app, ["allowlist", "add", "../../etc/passwd"])
    assert result.exit_code == 2
    assert "web.allowlist.requested" not in audit_events
    mock_client.create_proposal_from_payload.assert_not_called()


def test_allowlist_add_emits_audit_row_even_on_state_git_failure(runner: CliRunner) -> None:
    """A state.git failure leaves the operator-intent audit row.

    Mirrors the plugin-grant pattern: CLAUDE.md hard rule #7 forbids
    the silent-skip alternative.
    """
    audit_events: list[str] = []

    def _log_info(event: str, **_: object) -> None:
        audit_events.append(event)

    with (
        patch("alfred.cli.web._state_git_client") as mock_client,
        patch("alfred.cli._state_git._log") as mock_log,
    ):
        mock_log.info = _log_info
        mock_client.create_proposal_from_payload.side_effect = StateGitError("nope")
        result = runner.invoke(web_app, ["allowlist", "add", "api.example.com"])
    assert result.exit_code != 0
    assert "web.allowlist.requested" in audit_events
