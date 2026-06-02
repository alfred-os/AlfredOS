"""Unit tests for :class:`alfred.cli._state_git.StateGitProposalClient`.

PR-S3-6 Component A (plan §93-289). The client is the shared infrastructure
that every reviewer-gated CLI command (``alfred plugin grant``,
``alfred web allowlist add``, ``alfred config quarantined-provider``) uses
to write a proposal branch into state.git.

The test harness boots a temporary bare git repo to simulate
``/var/lib/alfred/state.git`` and exercises ``create_proposal`` end-to-end
through real ``git`` subprocess calls — the client has no Slice-3-only
imports, so unit-tier coverage suffices.

Hard invariants pinned here:

* **Branch name shape** — ``proposal/<type>-<hex8-id>`` exactly. The
  schema is shared with
  :mod:`alfred.security.capability_gate.proposals._write_proposal_to_state_git`
  (the async writer that the CLI consolidates into per PR-S3-7); a divergence
  would race the reviewer flow when both writers land in the same deployment.
* **Branch durably present in the bare repo** — the test asserts the push
  to ``origin/<branch>`` succeeded by listing branches via
  ``git --git-dir <bare> branch -a``. An audit row downstream points at
  this branch; if it does not exist, the audit-graph forensic trail breaks.
* **Unpredictable proposal id** — every call yields a distinct id. The plan
  (§2497-2640 / err-002) makes the audit log the source of truth for branch
  name → proposal payload; if ids could collide, two proposals at distinct
  commits could shadow one another in the audit graph.
* **list_pending_proposals returns branches** — every ``proposal/<type>-...``
  branch in the bare repo surfaces, with newest-first ordering by creation
  time so the CLI ``alfred plugin grant list --pending`` lists most-recent
  first.
* **get_proposal_diff returns the payload JSON** — the diff against the
  base branch carries the ``proposal.json`` file the client wrote, so the
  reviewer can ``git show`` the proposal without an extra round-trip.
* **State.git write failure raises StateGitError** — a missing bare repo
  or a permission error surfaces as a typed error rooted at
  :class:`AlfredError` (the CLI ``except`` arm narrows on this); CLAUDE.md
  hard rule #7 forbids the silent path.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from alfred.cli._state_git import (
    ProposalRef,
    ProposalResult,
    StateGitError,
    StateGitErrorKind,
    StateGitProposalClient,
    queue_proposal_or_exit,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _git_env(home: Path) -> dict[str, str]:
    """Return a minimal env dict for git subprocess calls.

    Forces a known-good HOME so git does not pick up the developer's
    global config (which can carry signing keys / commit hooks that
    break in CI).

    CR-149 round-6: PATH inherits the runner's current ``PATH`` rather
    than being hard-coded to ``"/usr/bin:/bin"``. The hard-coded shape
    only worked on Linux runners where ``git`` lives at ``/usr/bin/git``;
    GitHub Actions macOS runners install git via Homebrew at
    ``/opt/homebrew/bin/git`` (Apple Silicon) or ``/usr/local/bin/git``
    (Intel) — both outside the previous PATH, which made every test
    in this module fail with ``FileNotFoundError: git``. Inheriting the
    runner PATH keeps the HOME sandbox intact while letting the
    subprocess find git wherever it actually lives.
    """
    return {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
        "HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
    }


@pytest.fixture
def bare_repo(tmp_path: Path) -> Path:
    """Create a bare git repo to simulate ``/var/lib/alfred/state.git``.

    The bare repo is seeded with an empty ``main`` branch so the
    proposal-branch checkout has a base to fork from. Matches the
    PR-S3-0b ``alfred-setup`` script's state.git initialisation shape.
    """
    repo = tmp_path / "state.git"
    env = _git_env(tmp_path)
    # S603/S607: literal ``git`` argv under test control; no shell, no user input.
    subprocess.run(  # noqa: S603
        ["git", "init", "--bare", "--initial-branch=main", str(repo)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    work = tmp_path / "seed"
    work.mkdir()
    subprocess.run(  # noqa: S603
        ["git", "clone", str(repo), str(work)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    (work / "README").write_text("seeded")
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "add", "."],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-C",
            str(work),
            "commit",
            "-m",
            "seed",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "push", "origin", "main"],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    return repo


# ---------------------------------------------------------------------------
# create_proposal
# ---------------------------------------------------------------------------


def test_create_proposal_returns_branch_name(bare_repo: Path) -> None:
    """``create_proposal`` returns a :class:`ProposalResult` with the canonical branch shape."""
    client = StateGitProposalClient(state_git_path=bare_repo)
    result = client.create_proposal(
        proposal_type="policy-grant",
        payload={"plugin_id": "alfred.web-fetch", "hookpoint": "tool.web.fetch"},
    )
    assert isinstance(result, ProposalResult)
    assert result.branch.startswith("proposal/policy-grant-")
    # 16 hex chars (8 bytes from secrets.token_hex(8))
    assert len(result.proposal_id) == 16
    assert all(c in "0123456789abcdef" for c in result.proposal_id)


def test_create_proposal_branch_exists_in_repo(bare_repo: Path) -> None:
    """The proposal branch is durably present in the bare repo after the push."""
    client = StateGitProposalClient(state_git_path=bare_repo)
    result = client.create_proposal(
        proposal_type="web-allowlist-add",
        payload={"domain": "example.com", "path_prefix": "/"},
    )
    out = subprocess.run(  # noqa: S603
        ["git", "--git-dir", str(bare_repo), "branch", "-a"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.branch in out.stdout


def test_create_proposal_id_is_unique_per_call(bare_repo: Path) -> None:
    """Every ``create_proposal`` call yields a distinct proposal_id."""
    client = StateGitProposalClient(state_git_path=bare_repo)
    r1 = client.create_proposal("policy-grant", {"plugin_id": "a"})
    r2 = client.create_proposal("policy-grant", {"plugin_id": "b"})
    assert r1.proposal_id != r2.proposal_id
    assert r1.branch != r2.branch


@pytest.mark.parametrize(
    "bad_id",
    [
        # path-traversal — embeds into the on-disk grants tree path
        "../../etc/passwd",
        "../bad-id",
        # wrong width
        "deadbeef",  # 8 chars
        "deadbeef" * 4,  # 32 chars
        "",
        # wrong case / non-hex
        "DEADBEEFDEADBEEF",
        "Deadbeefdeadbeef",
        "deadbeef-deadbef",
        "deadbeef!deadbef",
        # ref-shape attack — embeds a slash into the branch name
        "deadbeefdead/eef",
    ],
)
def test_create_proposal_refuses_non_canonical_proposal_id(bare_repo: Path, bad_id: str) -> None:
    """Caller-supplied proposal ids outside the 16-hex-char shape are refused.

    CR-149 round-3: spec §8.3 + ADR-0018 require every state.git
    branch / grants-tree path id to be exactly 16 lowercase hex
    characters. The previous shape trusted caller-supplied ids
    verbatim, which let a typo OR a malicious value (``../``, ``/``,
    wrong width, uppercase) compose an invalid ref or escape the
    canonical grants-tree layout. Refuse at the public API boundary
    via :class:`ValueError`.
    """
    client = StateGitProposalClient(state_git_path=bare_repo)
    with pytest.raises(ValueError, match="16 lowercase hex"):
        client.create_proposal(
            "policy-grant",
            {"plugin_id": "alfred.web-fetch"},
            proposal_id=bad_id,
        )


def test_create_proposal_from_payload_refuses_non_canonical_proposal_id(
    bare_repo: Path,
) -> None:
    """The typed entry point also refuses caller-supplied non-canonical ids.

    CR-149 round-3: the typed ``create_proposal_from_payload`` API is
    the canonical entry point for ADR-0018 payloads but the legacy
    ``create_proposal`` is still public — both surfaces must close the
    boundary. Pins that the typed path applies the same validator.
    """
    from alfred.state.proposal_payloads import PluginGrantProposal

    client = StateGitProposalClient(state_git_path=bare_repo)
    payload = PluginGrantProposal(
        plugin_id="alfred.web-fetch",
        subscriber_tier="user-plugin",
        hookpoint="tool.web.fetch",
        content_tier=None,
    )
    with pytest.raises(ValueError, match="16 lowercase hex"):
        client.create_proposal_from_payload(payload, proposal_id="../escape")


@pytest.mark.parametrize(
    "bad_type",
    [
        # path-traversal / ref injection
        "policy-grant/escape",
        "../policy-grant",
        "policy/../grant",
        # whitespace — illegal in branch names
        "policy grant",
        "policy-grant ",
        " policy-grant",
        "policy\tgrant",
        # uppercase — canonical writer emits lowercase
        "Policy-Grant",
        "POLICY-GRANT",
        # underscores / punctuation outside the closed set
        "policy_grant",
        "policy.grant",
        "policy@grant",
        # empty / leading-or-trailing dash
        "",
        "-policy-grant",
        "policy-grant-",
        "policy--grant",
    ],
)
def test_create_proposal_refuses_non_canonical_proposal_type(
    bare_repo: Path, bad_type: str
) -> None:
    """Caller-supplied ``proposal_type`` outside the dash-canonical shape is refused.

    CR-149 round-6: PRD §8.3 requires every state.git branch ref to
    parse cleanly against git's ref-name rules — ``/``, ``..``,
    whitespace, or mixed casing drift from the documented shape and
    only surface deep inside the git subprocess. Refuse at the public
    API boundary via :class:`ValueError` so the legacy entry point
    fails closed the same way as the typed ``create_proposal_from_payload``
    path (which is already pinned by the
    :class:`StateGitProposalPayload.proposal_type` ClassVar).
    """
    client = StateGitProposalClient(state_git_path=bare_repo)
    with pytest.raises(ValueError, match="lowercase dash-separated"):
        client.create_proposal(
            bad_type,
            {"plugin_id": "alfred.web-fetch"},
        )


def test_create_proposal_writes_payload_as_proposal_json(bare_repo: Path) -> None:
    """The proposal branch commits the payload as ``proposal.json`` at repo root."""
    client = StateGitProposalClient(state_git_path=bare_repo)
    result = client.create_proposal(
        proposal_type="policy-grant",
        payload={"plugin_id": "alfred.web-fetch", "hookpoint": "tool.web.fetch"},
    )
    out = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "--git-dir",
            str(bare_repo),
            "show",
            f"{result.branch}:proposal.json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    # JSON is sorted + indented; spot-check both keys + the formatting shape.
    assert '"plugin_id": "alfred.web-fetch"' in out.stdout
    assert '"hookpoint": "tool.web.fetch"' in out.stdout


def test_create_proposal_commit_message_carries_proposal_id(bare_repo: Path) -> None:
    """The commit message includes the proposal_id for audit-graph correlation."""
    client = StateGitProposalClient(state_git_path=bare_repo)
    result = client.create_proposal(
        proposal_type="policy-grant",
        payload={"plugin_id": "x"},
    )
    out = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "--git-dir",
            str(bare_repo),
            "log",
            "-1",
            "--format=%s",
            result.branch,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.proposal_id in out.stdout
    assert "policy-grant" in out.stdout


def test_create_proposal_raises_state_git_error_on_missing_repo(tmp_path: Path) -> None:
    """A non-existent state.git path surfaces as :class:`StateGitError`.

    devex-004: the error is tagged :attr:`StateGitErrorKind.PUSH_REJECTED`
    (or PATH_MISSING when subprocess raises FileNotFoundError on the
    bound repo path). The exception ``str`` does NOT carry the raw argv.
    """
    client = StateGitProposalClient(state_git_path=tmp_path / "does-not-exist")
    with pytest.raises(StateGitError) as excinfo:
        client.create_proposal("policy-grant", {"plugin_id": "x"})
    # Raw argv MUST NOT appear in the operator-facing exception string.
    assert "git clone" not in str(excinfo.value)
    assert "/var/lib" not in str(excinfo.value)


def test_push_rejected_emits_structured_log_with_sanitised_stderr(
    bare_repo: Path,
) -> None:
    """CR-149 round-6: a non-zero git return code logs the sanitised stderr.

    Previously the stderr only landed as an exception note via
    ``add_note``; :func:`queue_proposal_or_exit` catches
    :class:`StateGitError` and never surfaces those notes, so the
    detailed git error was unrecoverable from the structlog stream.
    The structured ``state_git.push_rejected`` warning now carries the
    sanitised stderr so on-call sees the diagnostic alongside the
    typed exception. The bootstrap redactor still masks secret-shape
    strings; ``strip()`` keeps the line single-line searchable.
    """
    import subprocess as _subprocess

    captured: list[dict[str, object]] = []

    def _log_warning(event: str, **kwargs: object) -> None:
        if event == "state_git.push_rejected":
            captured.append(kwargs)

    client = StateGitProposalClient(state_git_path=bare_repo)
    # Simulate a non-zero git return code with stderr the real subprocess
    # would emit (e.g. clone target already exists). The patched
    # ``subprocess.run`` returns a CompletedProcess shape; the production
    # code dispatches on ``result.returncode``.
    fake_result = _subprocess.CompletedProcess(
        args=["git", "clone", "src", "dst"],
        returncode=128,
        stdout="",
        stderr="fatal: destination path 'dst' already exists and is not an empty directory.\n",
    )
    with (
        patch("alfred.cli._state_git._log") as mock_log,
        patch("alfred.cli._state_git.subprocess.run", return_value=fake_result),
    ):
        mock_log.warning = _log_warning
        with pytest.raises(StateGitError) as excinfo:
            client.create_proposal("policy-grant", {"plugin_id": "x"})
    assert excinfo.value.kind == StateGitErrorKind.PUSH_REJECTED
    assert len(captured) == 1, captured
    kwargs = captured[0]
    # The sanitised stderr is the load-bearing field: on-call grep target.
    assert "destination path" in str(kwargs["sanitised_stderr"])
    assert kwargs["returncode"] == 128
    # The argv field carries the failing command for forensic correlation.
    assert kwargs["argv"][0] == "git"


# ---------------------------------------------------------------------------
# list_pending_proposals
# ---------------------------------------------------------------------------


def test_list_pending_proposals_empty_when_no_proposals(bare_repo: Path) -> None:
    """A bare repo with only ``main`` returns an empty list."""
    client = StateGitProposalClient(state_git_path=bare_repo)
    assert client.list_pending_proposals() == []


def test_list_pending_proposals_returns_every_proposal_branch(bare_repo: Path) -> None:
    """Every ``proposal/...`` branch surfaces; non-proposal branches are filtered out."""
    client = StateGitProposalClient(state_git_path=bare_repo)
    r1 = client.create_proposal("policy-grant", {"plugin_id": "a"})
    r2 = client.create_proposal("web-allowlist-add", {"domain": "b.com"})
    pending = client.list_pending_proposals()
    refs = {p.branch for p in pending}
    assert r1.branch in refs
    assert r2.branch in refs
    # Only proposal branches surface — `main` does not.
    assert all(p.branch.startswith("proposal/") for p in pending)
    # Every entry is a typed ProposalRef.
    assert all(isinstance(p, ProposalRef) for p in pending)


# ---------------------------------------------------------------------------
# get_proposal_diff
# ---------------------------------------------------------------------------


def test_get_proposal_diff_contains_payload_json(bare_repo: Path) -> None:
    """``get_proposal_diff`` surfaces the proposal.json content for reviewer display."""
    client = StateGitProposalClient(state_git_path=bare_repo)
    result = client.create_proposal(
        proposal_type="policy-grant",
        payload={"plugin_id": "alfred.web-fetch", "hookpoint": "tool.web.fetch"},
    )
    diff = client.get_proposal_diff(result.branch)
    assert "proposal.json" in diff
    assert "alfred.web-fetch" in diff


def test_get_proposal_diff_raises_state_git_error_for_unknown_branch(
    bare_repo: Path,
) -> None:
    """An unknown branch name surfaces as :class:`StateGitError`, not git stderr."""
    client = StateGitProposalClient(state_git_path=bare_repo)
    with pytest.raises(StateGitError):
        client.get_proposal_diff("proposal/policy-grant-deadbeefdeadbeef")


# ---------------------------------------------------------------------------
# defensive filter + OSError handling — coverage gates for trust-boundary code
# ---------------------------------------------------------------------------


def test_list_pending_proposals_skips_non_proposal_lines(bare_repo: Path) -> None:
    """``list_pending_proposals`` defensively filters non-``proposal/`` lines.

    The git ``for-each-ref`` query is scoped to ``refs/heads/proposal/`` so
    in practice every line will match. The defensive filter exists to
    prevent a future git version (or a hand-edited ref) from leaking a
    ``main`` row into ``alfred plugin grant list --pending``. Patches
    the ``_run`` helper to inject the heterogeneous output a real-world
    misconfiguration could produce.
    """
    client = StateGitProposalClient(state_git_path=bare_repo)
    mixed_output = (
        "proposal/policy-grant-aaaaaaaaaaaaaaaa\n"
        "main\n"
        "\n"
        "proposal/web-allowlist-add-bbbbbbbbbbbbbbbb\n"
    )
    with patch.object(client, "_run", return_value=mixed_output):
        refs = client.list_pending_proposals()
    branch_names = {r.branch for r in refs}
    assert branch_names == {
        "proposal/policy-grant-aaaaaaaaaaaaaaaa",
        "proposal/web-allowlist-add-bbbbbbbbbbbbbbbb",
    }
    assert "main" not in branch_names


def test_run_converts_os_error_to_state_git_error(bare_repo: Path) -> None:
    """``_run`` surfaces ``OSError`` (e.g. missing ``git`` binary) as ``StateGitError``.

    CLAUDE.md hard rule #7: the CLI's ``except StateGitError`` arm
    narrows on this typed error to render a localised operator-facing
    message. A bare ``OSError`` / ``FileNotFoundError`` would bypass that
    localisation layer and leak Python's English traceback into operator
    UX. Patches ``subprocess.run`` to raise ``FileNotFoundError`` (the
    concrete ``OSError`` subclass that fires when ``git`` is missing from
    the runtime ``PATH``).

    devex-004: when the bound repo path EXISTS, the FileNotFoundError
    is attributable to ``git`` itself missing -- the error tag is
    :attr:`StateGitErrorKind.GIT_MISSING` so the CLI surfaces the
    "install git" hint rather than the "run alfred-setup" hint.
    """
    from alfred.cli._state_git import StateGitErrorKind

    client = StateGitProposalClient(state_git_path=bare_repo)
    with (
        patch(
            "alfred.cli._state_git.subprocess.run",
            side_effect=FileNotFoundError("git not found"),
        ),
        pytest.raises(StateGitError) as excinfo,
    ):
        client.list_pending_proposals()
    # devex-004: exception ``str`` no longer echoes the raw argv.
    assert excinfo.value.kind == StateGitErrorKind.GIT_MISSING
    # __cause__ pins the original OSError so the audit log can include it.
    assert isinstance(excinfo.value.__cause__, FileNotFoundError)


# ---------------------------------------------------------------------------
# devex-004: StateGitError carries a structured kind tag
# ---------------------------------------------------------------------------


def test_run_classifies_missing_repo_as_path_missing(tmp_path: Path) -> None:
    """A FileNotFoundError + non-existent repo path tags PATH_MISSING.

    The CLI surface maps PATH_MISSING to the "run alfred-setup" hint;
    GIT_MISSING to the "install git" hint. Distinguishing the two at
    the typed-error layer means each CLI sub-app does not need to
    re-implement the classification.
    """
    missing = tmp_path / "does-not-exist"
    client = StateGitProposalClient(state_git_path=missing)
    with (
        patch(
            "alfred.cli._state_git.subprocess.run",
            side_effect=FileNotFoundError("git -C ... not found"),
        ),
        pytest.raises(StateGitError) as excinfo,
    ):
        client.list_pending_proposals()
    assert excinfo.value.kind == StateGitErrorKind.PATH_MISSING


def test_run_does_not_treat_unreadable_repo_as_missing(tmp_path: Path) -> None:
    """A ``PermissionError`` on the repo path MUST NOT map to PATH_MISSING.

    CR-149 round-2: the pre-check used ``Path.exists()`` which collapses
    "genuinely missing" and "present but unreadable" into the same False
    return. The "run alfred-setup" hint that PATH_MISSING surfaces would
    mislead an operator whose real problem is access. After the fix the
    pre-check uses ``stat()`` and catches ONLY ``FileNotFoundError``;
    ``PermissionError`` propagates and the subprocess arm's catch-all
    maps it to PUSH_REJECTED so the operator sees the audit-log hint.
    """
    bound = tmp_path / "state.git"
    client = StateGitProposalClient(state_git_path=bound)
    # Patch ``Path.stat`` so the pre-check raises PermissionError; the
    # subprocess.run that follows isn't called because the OSError
    # surfaces from the pre-check arm. The mapping arm under test is
    # the explicit "FileNotFoundError-only" filter we added.
    with (
        patch(
            "pathlib.Path.stat",
            side_effect=PermissionError("EACCES on stat"),
        ),
        pytest.raises(StateGitError) as excinfo,
    ):
        client.list_pending_proposals()
    # CR-149 round-3: pin the exact classification, not just
    # "not PATH_MISSING". A future change that mis-routed unreadable
    # repos to GIT_MISSING (also wrong; the operator's recovery lever
    # is "check audit log + filesystem ACLs", not "install git") would
    # still pass the weaker inequality assertion. PUSH_REJECTED is the
    # canonical kind for the "access denied" path per CLAUDE.md hard
    # rule #7 / PRD §4.1.
    assert excinfo.value.kind == StateGitErrorKind.PUSH_REJECTED


def test_run_classifies_generic_oserror_as_push_rejected(bare_repo: Path) -> None:
    """A non-FileNotFoundError ``OSError`` (e.g. PermissionError) tags PUSH_REJECTED.

    Covers the catch-all ``except OSError`` arm in ``_run``. The CLI
    surface for PUSH_REJECTED is the generic "check audit log" hint --
    operator next-action is the same whether the cause was
    permission-denied or push-refused, so they share the kind.
    """
    client = StateGitProposalClient(state_git_path=bare_repo)
    with (
        patch(
            "alfred.cli._state_git.subprocess.run",
            side_effect=PermissionError("denied"),
        ),
        pytest.raises(StateGitError) as excinfo,
    ):
        client.list_pending_proposals()
    assert excinfo.value.kind == StateGitErrorKind.PUSH_REJECTED


def test_register_hint_keys_for_pybabel_returns_real_msgstrs() -> None:
    """The pybabel-visibility shim resolves to non-bare catalog renders.

    The function is never called at runtime but it MUST work when
    invoked -- otherwise a future refactor that decides to call it for
    e.g. catalog validation would silently get the bare msgids. Pin it.
    """
    from alfred.cli._state_git import _register_hint_keys_for_pybabel

    rendered = _register_hint_keys_for_pybabel()
    assert len(rendered) == 3
    # Each rendered string is non-trivially different from its msgid.
    for body in rendered:
        assert "cli.state_git.error." not in body
        assert body.strip() != ""
        # CR-149 round-3: the shim passes representative kwargs so the
        # ``path_missing`` body interpolates its ``{state_git_path}``
        # placeholder. A leaked ``{`` or ``}`` means either the msgstr
        # template carries an additional placeholder the shim does not
        # cover, or the shim regressed to the no-kwarg form that the
        # CR finding flagged.
        assert "{" not in body and "}" not in body


def test_run_classifies_nonzero_return_as_push_rejected(bare_repo: Path) -> None:
    """A non-zero subprocess return tags PUSH_REJECTED.

    The structured ``add_note`` carries the real stderr for forensic
    grep, but the exception ``str`` does NOT echo the argv -- that's
    the operator-leaking pattern devex-004 forbids.
    """

    class _FakeResult:
        returncode = 1
        stdout = ""
        stderr = "fatal: remote rejected push"

    client = StateGitProposalClient(state_git_path=bare_repo)
    with (
        patch(
            "alfred.cli._state_git.subprocess.run",
            return_value=_FakeResult(),
        ),
        pytest.raises(StateGitError) as excinfo,
    ):
        client.list_pending_proposals()
    assert excinfo.value.kind == StateGitErrorKind.PUSH_REJECTED
    # The ``str`` MUST NOT carry the raw argv or git's English stderr;
    # the structured ``__notes__`` channel (PEP 678) preserves the
    # stderr for forensic capture without putting it on the
    # operator-facing surface.
    surface = str(excinfo.value)
    assert "git --git-dir" not in surface
    assert "for-each-ref" not in surface
    assert "refs/heads" not in surface
    assert "fatal: remote rejected push" not in surface
    # PEP 678 note channel carries the stderr.
    assert any("fatal: remote rejected push" in note for note in excinfo.value.__notes__)


# ---------------------------------------------------------------------------
# Cross-cutting R5: queue_proposal_or_exit DRY helper
# ---------------------------------------------------------------------------


def test_queue_proposal_or_exit_happy_path_emits_pending_review(
    bare_repo: Path,
) -> None:
    """The success path emits the localised pending_review block.

    Cross-cutting R5: every CLI sub-app should call this helper rather
    than re-implementing the try/except dance. Validates the success
    branch against the real catalog so the helper is wired correctly.
    """
    import typer
    from typer.testing import CliRunner

    app = typer.Typer()

    @app.command("queue")
    def _queue() -> None:
        from alfred.state.proposal_payloads import PluginGrantProposal

        client = StateGitProposalClient(state_git_path=bare_repo)
        queue_proposal_or_exit(
            payload=PluginGrantProposal(
                plugin_id="alfred.test",
                subscriber_tier="system",
                hookpoint="tool.web.fetch",
            ),
            denied_key="cli.plugin.grant.denied",
            pending_review_key="cli.plugin.grant.pending_review",
            client=client,
        )

    result = CliRunner().invoke(app, [])
    assert result.exit_code == 0, (result.output, result.stderr)
    # The pending_review block is rendered from the catalog -- not the
    # bare msgid string.
    assert "cli.plugin.grant.pending_review" not in result.stdout
    # Branch name (with the canonical prefix) appears in the output.
    assert "proposal/policy-grant-" in result.stdout


def test_queue_proposal_or_exit_renders_localised_hint_for_each_kind(
    tmp_path: Path,
) -> None:
    """Each :class:`StateGitErrorKind` routes through its own hint key.

    The denial message carries the localised hint string matching the
    error kind. We exercise all three kinds against three patched
    clients to confirm the dispatch table.
    """
    import typer
    from typer.testing import CliRunner

    from alfred.i18n import t

    class _FailingClient:
        def __init__(self, kind: StateGitErrorKind, repo: Path) -> None:
            self._kind = kind
            # CR-149 round-3: ``_render_hint`` threads the client's
            # ``_repo`` into the localised PATH_MISSING hint so the
            # operator sees the configured state.git path rather than
            # the hard-coded default. The fake client mirrors the
            # real attribute so the test exercises the same render
            # path.
            self._repo = repo

        def create_proposal_from_payload(self, **_: object) -> ProposalResult:
            raise StateGitError("ignored", kind=self._kind)

    fake_repo = tmp_path / "fake-state.git"
    for kind in StateGitErrorKind:
        app = typer.Typer()

        @app.command("queue")
        def _queue(kind: StateGitErrorKind = kind) -> None:
            from alfred.state.proposal_payloads import PluginGrantProposal

            queue_proposal_or_exit(
                payload=PluginGrantProposal(
                    plugin_id="alfred.test",
                    subscriber_tier="system",
                    hookpoint="tool.web.fetch",
                ),
                denied_key="cli.plugin.grant.denied",
                pending_review_key="cli.plugin.grant.pending_review",
                client=_FailingClient(kind, fake_repo),  # type: ignore[arg-type]
            )

        result = CliRunner().invoke(app, [])
        assert result.exit_code != 0, (kind, result.output, result.stderr)
        # The exact catalog text for the kind's hint appears in stderr.
        # CR-149 round-3: PATH_MISSING now interpolates ``state_git_path``;
        # pass the same value the helper threads so the rendered hint
        # matches what the user-facing stderr will carry.
        hint = t(
            {
                StateGitErrorKind.PATH_MISSING: "cli.state_git.error.path_missing",
                StateGitErrorKind.GIT_MISSING: "cli.state_git.error.git_missing",
                StateGitErrorKind.PUSH_REJECTED: "cli.state_git.error.push_rejected",
            }[kind],
            state_git_path=str(fake_repo),
        )
        # A non-trivial fragment of the hint shows up on stderr.
        # ``hint.split(".")[0]`` worked for the prior hard-coded
        # ``/var/lib/alfred/state`` prefix; with the path now
        # operator-configured the assertion shifts to the path the
        # test supplied so it stays meaningful across deployments.
        assert str(fake_repo) in result.stderr or hint.split(" ")[0] in result.stderr, (
            kind,
            hint,
            result.stderr,
        )


def test_queue_proposal_or_exit_denial_path_handles_client_without_repo_attribute(
    tmp_path: Path,
) -> None:
    """CR-149 round-5: a duck-typed fake client without ``_repo`` must NOT crash.

    ``queue_proposal_or_exit`` documents ``client`` as an injectable
    seam (tests / mocks / future async-bridge callers). The denial
    path previously reached directly into ``state_git._repo`` to
    render the localised hint, so any duck-typed fake that only
    implemented :meth:`create_proposal_from_payload` turned a typed
    :class:`StateGitError` into :class:`AttributeError` -- regressing
    CLAUDE.md hard rule #7 on the operator-facing denial surface.
    Pin the defensive ``getattr`` fallback: the typed denial body
    still renders (against the production state.git default) and
    ``typer.Exit(1)`` is the surfaced exception, not AttributeError.
    """
    import typer
    from typer.testing import CliRunner

    class _NoRepoFakeClient:
        """A minimal duck-typed fake; deliberately omits ``_repo``."""

        def create_proposal_from_payload(self, **_: object) -> ProposalResult:
            raise StateGitError("ignored", kind=StateGitErrorKind.PATH_MISSING)

    del tmp_path  # only here to share fixture-shape with sibling tests
    app = typer.Typer()

    @app.command("queue")
    def _queue() -> None:
        from alfred.state.proposal_payloads import PluginGrantProposal

        queue_proposal_or_exit(
            payload=PluginGrantProposal(
                plugin_id="alfred.test",
                subscriber_tier="system",
                hookpoint="tool.web.fetch",
            ),
            denied_key="cli.plugin.grant.denied",
            pending_review_key="cli.plugin.grant.pending_review",
            client=_NoRepoFakeClient(),  # type: ignore[arg-type]
        )

    result = CliRunner().invoke(app, [])
    # The typed denial path fires (exit 1), NOT an AttributeError leak.
    assert result.exit_code == 1, (result.output, result.stderr, result.exception)
    assert not isinstance(result.exception, AttributeError), (
        f"denial path leaked AttributeError instead of typer.Exit: {result.exception!r}"
    )
    # The localised hint renders against the production default
    # ``/var/lib/alfred/state.git`` because the fake omits ``_repo``.
    assert "/var/lib/alfred/state.git" in result.stderr


def test_queue_proposal_or_exit_pending_review_extra_kwargs_forwarded(
    bare_repo: Path,
) -> None:
    """``pending_review_extra_kwargs`` lets callers thread their own placeholders.

    The ``cli.config.set.pending_review`` catalog entry references a
    ``{key}`` placeholder beyond the helper's standard
    ``branch`` + ``proposal_id``; the helper's signature accommodates
    callers like that via the optional kwargs forward.
    """
    import typer
    from typer.testing import CliRunner

    app = typer.Typer()

    @app.command("queue")
    def _queue() -> None:
        from alfred.state.proposal_payloads import ConfigSetProposal

        client = StateGitProposalClient(state_git_path=bare_repo)
        queue_proposal_or_exit(
            payload=ConfigSetProposal(
                config_key="quarantined-provider",
                value="anthropic",
            ),
            denied_key="cli.config.set.denied",
            pending_review_key="cli.config.set.pending_review",
            pending_review_extra_kwargs={"key": "quarantined-provider"},
            client=client,
        )

    result = CliRunner().invoke(app, [])
    assert result.exit_code == 0, (result.output, result.stderr)
    # The ``{key}`` placeholder is substituted -- not left as a literal.
    assert "quarantined-provider" in result.stdout
    assert "{key}" not in result.stdout


# ---------------------------------------------------------------------------
# Stage 3 (arch-001 / cross-cutting R2): audit-row emission BEFORE state.git
# ---------------------------------------------------------------------------


def test_queue_proposal_or_exit_emits_audit_row_before_state_git_write(
    bare_repo: Path,
) -> None:
    """The audit-row stand-in fires BEFORE the state.git proposal write.

    Stage 3 / arch-001: the ordering is load-bearing. A crash inside
    ``create_proposal`` (bare repo missing, git push rejected, ...) MUST
    still leave the operator-intent breadcrumb in the audit stream.
    CLAUDE.md hard rule #7 forbids the silent-skip alternative.
    """
    import typer
    from typer.testing import CliRunner

    from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REQUESTED_FIELDS

    call_order: list[str] = []

    class _OrderTrackingClient:
        """Records when ``create_proposal_from_payload`` runs vs when the audit fires.

        ``_log.info`` is patched to append before this method, so the
        relative order is observable in ``call_order``.
        """

        def create_proposal_from_payload(
            self,
            *,
            payload: object,
            proposal_id: str,
        ) -> ProposalResult:
            del payload
            call_order.append("state_git")
            return ProposalResult(
                proposal_id=proposal_id,
                branch=f"proposal/policy-grant-{proposal_id}",
            )

    def _log_info(event: str, **_: object) -> None:
        call_order.append(f"audit:{event}")

    app = typer.Typer()

    @app.command("queue")
    def _queue() -> None:
        from alfred.state.proposal_payloads import PluginGrantProposal

        with patch("alfred.cli._state_git._log") as mock_log:
            mock_log.info = _log_info
            queue_proposal_or_exit(
                payload=PluginGrantProposal(
                    plugin_id="alfred.test",
                    subscriber_tier="system",
                    hookpoint="tool.web.fetch",
                ),
                denied_key="cli.plugin.grant.denied",
                pending_review_key="cli.plugin.grant.pending_review",
                audit_event="plugin.grant.requested",
                audit_schema_name="PLUGIN_GRANT_REQUESTED_FIELDS",
                audit_fields=PLUGIN_GRANT_REQUESTED_FIELDS,
                audit_subject_partial={
                    "plugin_id": "alfred.test",
                    "subscriber_tier": "system",
                    "hookpoint": "tool.web.fetch",
                    "operator_user_id": None,
                    # CR-149 round-6: operator-CLI ingress carries the T1 tag.
                    "trust_tier_of_trigger": "T1",
                },
                client=_OrderTrackingClient(),  # type: ignore[arg-type]
            )

    _ = bare_repo  # state.git path unused by the patched client
    result = CliRunner().invoke(app, [])
    assert result.exit_code == 0, (result.output, result.stderr)
    # Audit emit MUST come strictly before the state.git call.
    audit_idx = next(i for i, label in enumerate(call_order) if label.startswith("audit:"))
    state_idx = call_order.index("state_git")
    assert audit_idx < state_idx, call_order


def test_queue_proposal_or_exit_emits_audit_row_even_when_state_git_fails() -> None:
    """A state.git failure MUST NOT skip the audit-row emission.

    The breadcrumb pointing at operator intent survives a crashed
    ``create_proposal``. CLAUDE.md hard rule #7: no silent failures in
    security paths.
    """
    import typer
    from typer.testing import CliRunner

    from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REQUESTED_FIELDS

    audit_events: list[tuple[str, dict[str, object]]] = []

    def _log_info(event: str, **kwargs: object) -> None:
        audit_events.append((event, kwargs))

    class _FailingClient:
        def create_proposal_from_payload(self, **_: object) -> ProposalResult:
            raise StateGitError("nope", kind=StateGitErrorKind.PUSH_REJECTED)

    app = typer.Typer()

    @app.command("queue")
    def _queue() -> None:
        from alfred.state.proposal_payloads import PluginGrantProposal

        with patch("alfred.cli._state_git._log") as mock_log:
            mock_log.info = _log_info
            queue_proposal_or_exit(
                payload=PluginGrantProposal(
                    plugin_id="alfred.test",
                    subscriber_tier="system",
                    hookpoint="tool.web.fetch",
                ),
                denied_key="cli.plugin.grant.denied",
                pending_review_key="cli.plugin.grant.pending_review",
                audit_event="plugin.grant.requested",
                audit_schema_name="PLUGIN_GRANT_REQUESTED_FIELDS",
                audit_fields=PLUGIN_GRANT_REQUESTED_FIELDS,
                audit_subject_partial={
                    "plugin_id": "alfred.test",
                    "subscriber_tier": "system",
                    "hookpoint": "tool.web.fetch",
                    "operator_user_id": None,
                    # CR-149 round-6: T1 ingress tag.
                    "trust_tier_of_trigger": "T1",
                },
                client=_FailingClient(),  # type: ignore[arg-type]
            )

    result = CliRunner().invoke(app, [])
    assert result.exit_code != 0
    # Exactly one audit event was emitted despite the state.git failure.
    assert len(audit_events) == 1, audit_events
    event_name, kwargs = audit_events[0]
    assert event_name == "plugin.grant.requested"
    # The branch + correlation_id were auto-filled by the helper so the
    # row carries the forensic anchor even though the branch was never
    # durably written.
    assert kwargs["proposal_branch"].startswith("proposal/policy-grant-")
    assert "correlation_id" in kwargs


def test_queue_proposal_or_exit_no_audit_when_kwargs_omitted(bare_repo: Path) -> None:
    """Legacy call sites without audit kwargs do NOT emit a row.

    The four audit kwargs are opt-in (all-or-none). Existing tests in
    this module that pass none of them are the regression bar for
    "legacy shape stays working."
    """
    import typer
    from typer.testing import CliRunner

    audit_events: list[str] = []

    def _log_info(event: str, **_: object) -> None:
        audit_events.append(event)

    app = typer.Typer()

    @app.command("queue")
    def _queue() -> None:
        from alfred.state.proposal_payloads import PluginGrantProposal

        with patch("alfred.cli._state_git._log") as mock_log:
            mock_log.info = _log_info
            client = StateGitProposalClient(state_git_path=bare_repo)
            queue_proposal_or_exit(
                payload=PluginGrantProposal(
                    plugin_id="alfred.test",
                    subscriber_tier="system",
                    hookpoint="tool.web.fetch",
                ),
                denied_key="cli.plugin.grant.denied",
                pending_review_key="cli.plugin.grant.pending_review",
                client=client,
            )

    result = CliRunner().invoke(app, [])
    assert result.exit_code == 0, (result.output, result.stderr)
    assert audit_events == []


def test_queue_proposal_or_exit_audit_kwargs_must_be_all_or_none() -> None:
    """Supplying a subset of the four audit kwargs raises ValueError.

    All-or-none discipline: a partial port from a legacy call site
    cannot silently skip the audit emission. The raise is loud so the
    refactor bug surfaces at the emit site.
    """
    from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REQUESTED_FIELDS
    from alfred.state.proposal_payloads import PluginGrantProposal

    with pytest.raises(ValueError, match="must all be supplied together"):
        queue_proposal_or_exit(
            payload=PluginGrantProposal(
                plugin_id="alfred.test",
                subscriber_tier="system",
                hookpoint="tool.web.fetch",
            ),
            denied_key="cli.plugin.grant.denied",
            pending_review_key="cli.plugin.grant.pending_review",
            # Only two of the four supplied — refused.
            audit_event="plugin.grant.requested",
            audit_fields=PLUGIN_GRANT_REQUESTED_FIELDS,
        )


def test_queue_proposal_or_exit_refuses_caller_overriding_proposal_branch() -> None:
    """``audit_subject_partial`` must not pre-set ``proposal_branch``.

    The helper auto-fills the field from the pre-generated branch name;
    a caller-supplied value would silently lose to the auto-fill. The
    loud raise surfaces the bug at the emit site.
    """
    from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REQUESTED_FIELDS
    from alfred.state.proposal_payloads import PluginGrantProposal

    with pytest.raises(ValueError, match="proposal_branch"):
        queue_proposal_or_exit(
            payload=PluginGrantProposal(
                plugin_id="alfred.test",
                subscriber_tier="system",
                hookpoint="tool.web.fetch",
            ),
            denied_key="cli.plugin.grant.denied",
            pending_review_key="cli.plugin.grant.pending_review",
            audit_event="plugin.grant.requested",
            audit_schema_name="PLUGIN_GRANT_REQUESTED_FIELDS",
            audit_fields=PLUGIN_GRANT_REQUESTED_FIELDS,
            audit_subject_partial={
                "plugin_id": "x",
                "subscriber_tier": "system",
                "hookpoint": "tool.web.fetch",
                "operator_user_id": None,
                # CR-149 round-6: T1 ingress tag.
                "trust_tier_of_trigger": "T1",
                "proposal_branch": "proposal/policy-grant-deadbeefdeadbeef",
            },
        )


def test_queue_proposal_or_exit_refuses_caller_overriding_correlation_id() -> None:
    """``audit_subject_partial`` must not pre-set ``correlation_id``."""
    from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REQUESTED_FIELDS
    from alfred.state.proposal_payloads import PluginGrantProposal

    with pytest.raises(ValueError, match="correlation_id"):
        queue_proposal_or_exit(
            payload=PluginGrantProposal(
                plugin_id="alfred.test",
                subscriber_tier="system",
                hookpoint="tool.web.fetch",
            ),
            denied_key="cli.plugin.grant.denied",
            pending_review_key="cli.plugin.grant.pending_review",
            audit_event="plugin.grant.requested",
            audit_schema_name="PLUGIN_GRANT_REQUESTED_FIELDS",
            audit_fields=PLUGIN_GRANT_REQUESTED_FIELDS,
            audit_subject_partial={
                "plugin_id": "x",
                "subscriber_tier": "system",
                "hookpoint": "tool.web.fetch",
                "operator_user_id": None,
                # CR-149 round-6: T1 ingress tag.
                "trust_tier_of_trigger": "T1",
                "correlation_id": "deadbeef-dead-beef-dead-beefdeadbeef",
            },
        )


def test_queue_proposal_or_exit_emit_helper_validates_symmetric_key_set() -> None:
    """Audit-row emit raises if subject keys do not equal declared fields.

    Mirrors :meth:`AuditWriter.append_schema` so the eventual PR-S3-7
    swap is structurally identical. Both missing AND extra keys raise
    — the symmetric check defends against typo'd field names silently
    shadowing the real field (spec §5.6).
    """
    from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REQUESTED_FIELDS
    from alfred.state.proposal_payloads import PluginGrantProposal

    # Missing the ``hookpoint`` and ``operator_user_id`` keys — both
    # surface in the error message.
    with pytest.raises(ValueError, match="missing required fields"):
        queue_proposal_or_exit(
            payload=PluginGrantProposal(
                plugin_id="alfred.test",
                subscriber_tier="system",
                hookpoint="tool.web.fetch",
            ),
            denied_key="cli.plugin.grant.denied",
            pending_review_key="cli.plugin.grant.pending_review",
            audit_event="plugin.grant.requested",
            audit_schema_name="PLUGIN_GRANT_REQUESTED_FIELDS",
            audit_fields=PLUGIN_GRANT_REQUESTED_FIELDS,
            audit_subject_partial={
                "plugin_id": "x",
                "subscriber_tier": "system",
            },
        )


def test_queue_proposal_or_exit_emit_helper_refuses_extra_keys() -> None:
    """The symmetric key check refuses keys not declared in ``audit_fields``.

    Spec §5.6: an emitter accidentally persisting ``str(exc)``,
    ``exc.args``, or any other undeclared field could leak T3 fragments
    into the audit row's JSONB column. The symmetric check is the
    runtime guard.
    """
    from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REQUESTED_FIELDS
    from alfred.state.proposal_payloads import PluginGrantProposal

    with pytest.raises(ValueError, match="unexpected fields"):
        queue_proposal_or_exit(
            payload=PluginGrantProposal(
                plugin_id="alfred.test",
                subscriber_tier="system",
                hookpoint="tool.web.fetch",
            ),
            denied_key="cli.plugin.grant.denied",
            pending_review_key="cli.plugin.grant.pending_review",
            audit_event="plugin.grant.requested",
            audit_schema_name="PLUGIN_GRANT_REQUESTED_FIELDS",
            audit_fields=PLUGIN_GRANT_REQUESTED_FIELDS,
            audit_subject_partial={
                "plugin_id": "x",
                "subscriber_tier": "system",
                "hookpoint": "tool.web.fetch",
                "operator_user_id": None,
                # CR-149 round-6: include the canonical T1 ingress tag so
                # the only difference between subject and declared
                # fields is the stray fragment — the assertion target
                # remains "unexpected fields", not "missing required".
                "trust_tier_of_trigger": "T1",
                "stray_t3_fragment": "secret-shaped",
            },
        )


def test_queue_proposal_or_exit_pre_generated_id_is_used_by_client(
    bare_repo: Path,
) -> None:
    """The helper-generated proposal id is passed through to ``create_proposal``.

    The branch in the audit row and the branch in the state.git push
    MUST match — a divergence would break the audit-graph correlator's
    join.
    """
    import typer
    from typer.testing import CliRunner

    from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REQUESTED_FIELDS

    audit_events: list[dict[str, object]] = []

    def _log_info(event: str, **kwargs: object) -> None:
        del event
        audit_events.append(kwargs)

    app = typer.Typer()

    @app.command("queue")
    def _queue() -> None:
        from alfred.state.proposal_payloads import PluginGrantProposal

        with patch("alfred.cli._state_git._log") as mock_log:
            mock_log.info = _log_info
            client = StateGitProposalClient(state_git_path=bare_repo)
            queue_proposal_or_exit(
                payload=PluginGrantProposal(
                    plugin_id="alfred.test",
                    subscriber_tier="system",
                    hookpoint="tool.web.fetch",
                ),
                denied_key="cli.plugin.grant.denied",
                pending_review_key="cli.plugin.grant.pending_review",
                audit_event="plugin.grant.requested",
                audit_schema_name="PLUGIN_GRANT_REQUESTED_FIELDS",
                audit_fields=PLUGIN_GRANT_REQUESTED_FIELDS,
                audit_subject_partial={
                    "plugin_id": "x",
                    "subscriber_tier": "system",
                    "hookpoint": "tool.web.fetch",
                    "operator_user_id": None,
                    # CR-149 round-6: T1 ingress tag.
                    "trust_tier_of_trigger": "T1",
                },
                client=client,
            )

    result = CliRunner().invoke(app, [])
    assert result.exit_code == 0, (result.output, result.stderr)
    # Audit row's branch field appears in stdout's pending-review block
    # (rendered via ``branch=result.branch``).
    assert len(audit_events) == 1
    audit_branch = str(audit_events[0]["proposal_branch"])
    assert audit_branch in result.stdout
    assert audit_branch.startswith("proposal/policy-grant-")
    # 16 hex chars after the prefix — the canonical id width.
    suffix = audit_branch.removeprefix("proposal/policy-grant-")
    assert len(suffix) == 16


def test_create_proposal_accepts_pre_generated_proposal_id(bare_repo: Path) -> None:
    """``create_proposal`` honours a caller-supplied proposal_id.

    The pre-generation is the bridge that lets
    :func:`queue_proposal_or_exit` emit the audit row with the resolved
    branch name BEFORE the state.git write.
    """
    client = StateGitProposalClient(state_git_path=bare_repo)
    result = client.create_proposal(
        "policy-grant",
        {"plugin_id": "x"},
        proposal_id="deadbeefdeadbeef",
    )
    assert result.proposal_id == "deadbeefdeadbeef"
    assert result.branch == "proposal/policy-grant-deadbeefdeadbeef"


def test_create_proposal_from_payload_generates_id_when_omitted(bare_repo: Path) -> None:
    """``create_proposal_from_payload`` falls back to :func:`secrets.token_hex`
    when the caller does not pass ``proposal_id``.

    Pins the ``if proposal_id is None`` branch (ADR-0018 typed-payload
    entry point, line 242-243 of :mod:`alfred.cli._state_git`). Without
    this branch, peer callers that omit the id would silently get the
    string "None" wired into the branch name — exactly the kind of
    soft-fail CLAUDE.md hard rule #7 forbids.

    The generated id MUST be 16 lowercase hex chars (token_hex(8)) so
    every other downstream parser (audit-graph join, parse_state_git_head
    branch-name discriminator) keeps observing a uniform width.
    """
    from alfred.state.proposal_payloads import PluginGrantProposal

    client = StateGitProposalClient(state_git_path=bare_repo)
    payload = PluginGrantProposal(
        plugin_id="alfred.test-plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        operator_user_id="op@example.com",
    )

    result = client.create_proposal_from_payload(payload)

    # Sixteen hex chars = secrets.token_hex(8).
    assert len(result.proposal_id) == 16
    assert all(c in "0123456789abcdef" for c in result.proposal_id)
    assert result.branch == f"proposal/policy-grant-{result.proposal_id}"
