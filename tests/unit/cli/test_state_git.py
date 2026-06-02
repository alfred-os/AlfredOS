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
    break in CI). PATH stays POSIX-minimal so the test does not depend
    on the user's shell rc.
    """
    return {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
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
        client = StateGitProposalClient(state_git_path=bare_repo)
        queue_proposal_or_exit(
            proposal_type="policy-grant",
            payload={"plugin_id": "alfred.test"},
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
        def __init__(self, kind: StateGitErrorKind) -> None:
            self._kind = kind

        def create_proposal(self, **_: object) -> ProposalResult:
            raise StateGitError("ignored", kind=self._kind)

    for kind in StateGitErrorKind:
        app = typer.Typer()

        @app.command("queue")
        def _queue(kind: StateGitErrorKind = kind) -> None:
            queue_proposal_or_exit(
                proposal_type="policy-grant",
                payload={"plugin_id": "x"},
                denied_key="cli.plugin.grant.denied",
                pending_review_key="cli.plugin.grant.pending_review",
                client=_FailingClient(kind),  # type: ignore[arg-type]
            )

        result = CliRunner().invoke(app, [])
        assert result.exit_code != 0, (kind, result.output, result.stderr)
        # The exact catalog text for the kind's hint appears in stderr.
        hint = t(
            {
                StateGitErrorKind.PATH_MISSING: "cli.state_git.error.path_missing",
                StateGitErrorKind.GIT_MISSING: "cli.state_git.error.git_missing",
                StateGitErrorKind.PUSH_REJECTED: "cli.state_git.error.push_rejected",
            }[kind]
        )
        # A non-trivial fragment of the hint shows up on stderr.
        assert hint.split(".")[0] in result.stderr, (kind, hint, result.stderr)


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
        client = StateGitProposalClient(state_git_path=bare_repo)
        queue_proposal_or_exit(
            proposal_type="config-quarantined-provider",
            payload={"key": "quarantined-provider", "value": "anthropic"},
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
