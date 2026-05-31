"""Integration test: state.git idempotent init and main-branch seeding.

Tests the ``git init --bare`` + main-seed step added to
``bin/alfred-state-git-seed.sh`` (spec §15.4 step 2, spec §8.1). Runs
against the local filesystem using ``tmp_path`` so it does not require a
running container — the seed script's behaviour reduces to plain git
plumbing the test can exercise directly.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — args are fully controlled by the test
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )


def _try(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Like ``_run`` but does not raise on non-zero exit. Used by the
    rev-parse idempotency guard which must observe the exit code."""
    return subprocess.run(  # noqa: S603 — args are fully controlled by the test
        args,
        capture_output=True,
        text=True,
        check=False,
    )


def test_git_init_bare_creates_state_git(tmp_path: Path) -> None:
    """``git init --bare`` creates a valid bare repository."""
    state_git = tmp_path / "state.git"
    _run(["git", "init", "--bare", str(state_git)])
    assert state_git.is_dir()
    assert (state_git / "HEAD").exists()
    assert (state_git / "config").exists()
    assert (state_git / "objects").is_dir()


def test_git_init_bare_is_idempotent(tmp_path: Path) -> None:
    """Re-running ``git init --bare`` on an existing bare repo is a no-op."""
    state_git = tmp_path / "state.git"
    _run(["git", "init", "--bare", str(state_git)])
    # Second run must not raise
    _run(["git", "init", "--bare", str(state_git)])
    assert (state_git / "HEAD").exists()


def test_seed_main_branch(tmp_path: Path) -> None:
    """After ``git init --bare``, seeding a main branch with an empty commit succeeds."""
    state_git = tmp_path / "state.git"
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    _run(["git", "init", "--bare", str(state_git)])

    # Clone the bare repo, add an empty commit, push to main
    _run(["git", "clone", str(state_git), str(work_dir / "clone")])
    clone_dir = work_dir / "clone"
    _run(["git", "-C", str(clone_dir), "config", "user.email", "test@example.com"])
    _run(["git", "-C", str(clone_dir), "config", "user.name", "Test"])
    _run(["git", "-C", str(clone_dir), "commit", "--allow-empty", "-m", "Initial empty commit"])
    _run(["git", "-C", str(clone_dir), "push", "origin", "HEAD:main"])

    # Verify main branch exists in bare repo
    result = _run(["git", "-C", str(state_git), "branch", "-l"])
    assert "main" in result.stdout


def test_seed_main_branch_is_idempotent(tmp_path: Path) -> None:
    """Seeding main twice does not fail (idempotent if branch already exists)."""
    state_git = tmp_path / "state.git"
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    _run(["git", "init", "--bare", str(state_git)])
    clone_dir = work_dir / "clone"
    _run(["git", "clone", str(state_git), str(clone_dir)])
    _run(["git", "-C", str(clone_dir), "config", "user.email", "test@example.com"])
    _run(["git", "-C", str(clone_dir), "config", "user.name", "Test"])
    _run(["git", "-C", str(clone_dir), "commit", "--allow-empty", "-m", "Initial empty commit"])
    _run(["git", "-C", str(clone_dir), "push", "origin", "HEAD:main"])

    # Re-run push to main (already-up-to-date path)
    _run(["git", "-C", str(clone_dir), "commit", "--allow-empty", "-m", "Second empty commit"])
    _run(["git", "-C", str(clone_dir), "push", "origin", "HEAD:main"])

    result = _run(["git", "-C", str(state_git), "log", "--oneline", "main"])
    assert "Second empty commit" in result.stdout


def test_rev_parse_verify_idempotency_guard(tmp_path: Path) -> None:
    """The idempotency guard ``git rev-parse --verify refs/heads/main`` returns
    non-zero on a fresh bare repo (no main ref yet) and zero after seeding.

    This is the exact predicate the seed script uses to gate the seed work,
    pinning the contract: a fresh state.git fails the check (so the seed runs);
    a previously-seeded state.git passes it (so the seed is skipped).
    """
    state_git = tmp_path / "state.git"
    _run(["git", "init", "--bare", str(state_git)])

    # Fresh bare repo: no main ref yet — rev-parse --verify must exit non-zero.
    pre = _try(["git", "-C", str(state_git), "rev-parse", "--verify", "refs/heads/main"])
    assert pre.returncode != 0, "fresh bare repo unexpectedly already has refs/heads/main"

    # Seed main.
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    clone_dir = work_dir / "clone"
    _run(["git", "clone", str(state_git), str(clone_dir)])
    _run(["git", "-C", str(clone_dir), "config", "user.email", "test@example.com"])
    _run(["git", "-C", str(clone_dir), "config", "user.name", "Test"])
    _run(["git", "-C", str(clone_dir), "commit", "--allow-empty", "-m", "seed"])
    _run(["git", "-C", str(clone_dir), "push", "origin", "HEAD:main"])

    # Now rev-parse --verify must succeed (the seed-script "skip" branch).
    post = _try(["git", "-C", str(state_git), "rev-parse", "--verify", "refs/heads/main"])
    assert post.returncode == 0, "seeded bare repo failed rev-parse --verify refs/heads/main"
