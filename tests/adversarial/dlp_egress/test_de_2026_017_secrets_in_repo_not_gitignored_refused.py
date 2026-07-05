"""Adversarial wiring-smoke for the ``de-2026-017`` corpus payload.

Asserts the defence FIRED: a layer-3 (settings-default XDG) secrets file inside a
versioned repo that is NOT gitignored is REFUSED at ``SecretBroker`` construction
(``SecretBrokerPermissionsError``, ``secrets.file_in_git_repo``) — no
committable-credential boot rides the config seed. The gitignored case is the
positive control proving the #366 narrowing is a real ``git check-ignore``
verdict, not a blanket allow.

ADR-0012's ``.git``-in-parent refusal defends the accidental-commit exfiltration
vector (a secrets.toml inside a git worktree is one ``git add -A`` from being
pushed). #366 narrowed it for the layer-3 path ONLY to be gitignore-aware
(authoritative ``git check-ignore``; fail-closed on git-absent/error/timeout).
The broker is the perimeter (CLAUDE.md: the tool layer is the perimeter): it
REFUSES an un-gitignored layer-3 secret in a repo fail-closed. A pass here would
let an operator boot with a committable credential.

The test drives the REAL production :class:`alfred.security.secrets.SecretBroker`
against a real tmp ``git init`` repo — never a permissive shim (CLAUDE.md hard
rule #2). Mirrors the positive/negative-control shape of the ``cap-2026-005``
wiring-smoke.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Final

import pytest

from alfred.security.secrets import SecretBroker, SecretBrokerPermissionsError
from tests.adversarial.payload_schema import AdversarialPayload

_PAYLOAD_ID: Final[str] = "de-2026-017"


@pytest.fixture(autouse=True)
def _isolate_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermetic git env for this release-blocking adversarial test (#366, CR #384).

    Both ``git init`` here and the broker's ``git check-ignore`` inherit
    ``os.environ`` — a contributor's global ``core.excludesFile`` matching
    ``secrets.toml`` / ``*.toml`` (or a stray ``GIT_DIR`` / ``GIT_WORK_TREE``)
    could flip the not-gitignored negative control. Pin git's config to
    ``os.devnull`` and drop any repo overrides so the subprocess sees only the
    repo-local ``.gitignore``.
    """
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.delenv("GIT_DIR", raising=False)
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)


@pytest.fixture
def secrets_in_repo_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus to the wiring-smoke payload.

    Fails loudly if the payload is missing/duplicated so a future rename or
    delete surfaces here (the drift-guard pattern shared across the corpus).
    """
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; expected at "
            "tests/adversarial/dlp_egress/secrets_in_repo_not_gitignored_refused.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            "expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def _repo_with_secret(tmp_path: Path, *, gitignored: bool) -> Path:
    """A real tmp git repo containing a 0600 secrets.toml (optionally gitignored)."""
    repo = tmp_path / "dotfiles"
    repo.mkdir(mode=0o700, parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)  # noqa: S603, S607
    if gitignored:
        (repo / ".gitignore").write_text("secrets.toml\n")
    secret = repo / "secrets.toml"
    secret.write_text('discord_bot_token = "x"\n')
    secret.chmod(0o600)
    return secret


def test_secrets_in_repo_not_gitignored_refused(
    secrets_in_repo_payload: AdversarialPayload,
    tmp_path: Path,
) -> None:
    """A layer-3 un-gitignored secret in a repo is REFUSED; gitignored boots.

    Negative control (the defence) + positive control through the SAME real
    broker, proving the #366 narrowing is a gitignore verdict, not a blanket
    allow.
    """
    payload_fields = secrets_in_repo_payload.payload
    assert isinstance(payload_fields, dict)
    assert payload_fields["layer"] == "settings_default"
    assert payload_fields["gitignored"] is False
    assert secrets_in_repo_payload.expected_outcome == "refused"

    # The defence: a layer-3 secret in a versioned repo, NOT gitignored → REFUSED.
    not_ignored = _repo_with_secret(tmp_path / "a", gitignored=False)
    with pytest.raises(SecretBrokerPermissionsError):
        SecretBroker(env={}, settings_default=not_ignored)

    # Positive control: the SAME layer, gitignored → boots (the narrowing is a
    # real gitignore verdict, not a blanket refusal).
    ignored = _repo_with_secret(tmp_path / "b", gitignored=True)
    broker = SecretBroker(env={}, settings_default=ignored)
    assert broker.secrets_file_path == ignored
