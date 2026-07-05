"""de-2026-018 — a layer-3 secret in a git SECONDARY WORKTREE (`.git` is a FILE)
that is NOT gitignored is refused; the gitignored case is the positive control.

#383 broadened `_walk_for_git_parent` from a `.git`-dir check to `.git`-exists
(dir OR file), so worktree/submodule secrets — previously invisible to the
ADR-0012 anti-accidental-commit refusal on every layer — are now caught. This
drives the REAL `SecretBroker` against a REAL secondary worktree, proving the
walk+#366-narrowing verdict resolves through the worktree (not a blanket allow).

A submodule has the identical `.git`-FILE → gitdir-pointer shape and resolves
through the same mechanism, so this worktree case exercises both.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Final

import pytest

from alfred.security.secrets import SecretBroker, SecretBrokerPermissionsError
from tests.adversarial.payload_schema import AdversarialPayload

_PAYLOAD_ID: Final[str] = "de-2026-018"


@pytest.fixture(autouse=True)
def _isolate_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermetic git env: `git init`/`commit`/`worktree add` and the broker's
    `git check-ignore` all inherit `os.environ`; a stray global `core.excludesFile`
    or `GIT_DIR`/`GIT_WORK_TREE` could flip the not-gitignored negative control."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.delenv("GIT_DIR", raising=False)
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)


@pytest.fixture
def worktree_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus to this wiring-smoke payload; fail loudly
    on a missing/duplicated id (the drift-guard pattern shared across the corpus)."""
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; expected at "
            "tests/adversarial/dlp_egress/secret_in_git_worktree_not_gitignored_refused.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            "expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def _git(cwd: Path, *args: str) -> None:
    """Run ``git -C <cwd> <args>`` — the S603/S607 noqa site for fixture ``git -C``
    calls (the ``git init`` below takes no ``-C`` and keeps its own noqa)."""
    subprocess.run(["git", "-C", str(cwd), *args], check=True)  # noqa: S603, S607


def _worktree_with_secret(tmp_path: Path, *, gitignored: bool) -> Path:
    """A real git SECONDARY WORKTREE (its `.git` is a FILE) holding a 0600
    secrets.toml. `worktree add` needs a commit; the inline `-c user.*` identity
    survives the devnull global config."""
    main = tmp_path / "main"
    main.mkdir(mode=0o700, parents=True)
    subprocess.run(["git", "init", "-q", str(main)], check=True)  # noqa: S603, S607
    _git(
        main,
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "commit",
        "--allow-empty",
        "-q",
        "-m",
        "init",
    )
    wt = tmp_path / "wt"
    _git(main, "worktree", "add", "-q", str(wt))
    assert (wt / ".git").is_file()  # the shape under test: .git is a FILE
    if gitignored:
        (wt / ".gitignore").write_text("secrets.toml\n")
    secret = wt / "secrets.toml"
    secret.write_text('discord_bot_token = "x"\n')
    secret.chmod(0o600)
    return secret


def test_secret_in_git_worktree_not_gitignored_refused(
    worktree_payload: AdversarialPayload,
    tmp_path: Path,
) -> None:
    """Un-gitignored secret in a real worktree is REFUSED; gitignored boots."""
    payload_fields = worktree_payload.payload
    assert isinstance(payload_fields, dict)
    assert payload_fields["layer"] == "settings_default"
    assert payload_fields["gitignored"] is False
    assert payload_fields["repo_shape"] == "git_secondary_worktree"
    assert worktree_payload.expected_outcome == "refused"

    # The defence: a layer-3 secret in a real secondary worktree, NOT gitignored,
    # is REFUSED (the vector that escaped the .git-dir-only walk before #383).
    not_ignored = _worktree_with_secret(tmp_path / "a", gitignored=False)
    with pytest.raises(SecretBrokerPermissionsError) as exc_info:
        SecretBroker(env={}, settings_default=not_ignored)
    # Pin the REASON (the .git-repo refusal), not just the exception type — a
    # mode/ownership check firing first would be a false pass. The layer-3
    # refusal names the gitignore remedy; a perms failure would not.
    assert ".gitignore" in str(exc_info.value)

    # Positive control: the SAME shape, gitignored → boots (check-ignore resolves
    # the worktree; the narrowing is a real gitignore verdict, not a blanket refusal).
    ignored = _worktree_with_secret(tmp_path / "b", gitignored=True)
    broker = SecretBroker(env={}, settings_default=ignored)
    assert broker.secrets_file_path == ignored
