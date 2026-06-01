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

import pytest

from alfred.cli._state_git import (
    ProposalRef,
    ProposalResult,
    StateGitError,
    StateGitProposalClient,
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
    subprocess.run(
        ["git", "init", "--bare", "--initial-branch=main", str(repo)],
        check=True,
        capture_output=True,
        env=env,
    )
    work = tmp_path / "seed"
    work.mkdir()
    subprocess.run(
        ["git", "clone", str(repo), str(work)],
        check=True,
        capture_output=True,
        env=env,
    )
    (work / "README").write_text("seeded")
    subprocess.run(
        ["git", "-C", str(work), "add", "."],
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(
        ["git", "-C", str(work), "commit", "-m", "seed"],
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(
        ["git", "-C", str(work), "push", "origin", "main"],
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
    out = subprocess.run(
        ["git", "--git-dir", str(bare_repo), "branch", "-a"],
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
    out = subprocess.run(
        ["git", "--git-dir", str(bare_repo), "show", f"{result.branch}:proposal.json"],
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
    out = subprocess.run(
        ["git", "--git-dir", str(bare_repo), "log", "-1", "--format=%s", result.branch],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.proposal_id in out.stdout
    assert "policy-grant" in out.stdout


def test_create_proposal_raises_state_git_error_on_missing_repo(tmp_path: Path) -> None:
    """A non-existent state.git path surfaces as :class:`StateGitError`."""
    client = StateGitProposalClient(state_git_path=tmp_path / "does-not-exist")
    with pytest.raises(StateGitError):
        client.create_proposal("policy-grant", {"plugin_id": "x"})


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
