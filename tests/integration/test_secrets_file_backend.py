"""End-to-end tests for the file-backed SecretBroker.

Exercises real ``os.chmod``, real ``tomllib.load``, real ``Path.stat`` — no
monkeypatch of any of those. Uses tmp_path + ``monkeypatch.setenv`` only at the
env-variable boundary. Complements the unit suite by surfacing any platform-
specific stat behaviour at CI time rather than at deploy time.

PR C delivers the broker; PRs D1 and D2 wire consumers. This integration test
exists for the broker in isolation.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from alfred.security.secrets import (
    SecretBroker,
    SecretBrokerFileMissingError,
    SecretBrokerNotAFileError,
    SecretBrokerPermissionsError,
    UnknownSecretError,
)


@pytest.fixture
def secure_file(tmp_path: Path) -> Path:
    """Create a 0600 secrets.toml under a 0700 parent (no .git in ancestors)."""
    parent = tmp_path / "alfred"
    parent.mkdir()
    parent.chmod(0o700)
    path = parent / "secrets.toml"
    path.write_text('discord_bot_token = "tok-from-file"\ndeepseek_api_key = "ds-from-file"\n')
    path.chmod(0o600)
    return path


class TestSecretsFileBackendIntegration:
    """Per spec §5 line 804 / PR-C plan task 12."""

    def test_file_value_wins_for_discord_bot_token(
        self, secure_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ALFRED_DISCORD_BOT_TOKEN", "tok-from-env")
        broker = SecretBroker(
            env=dict(os.environ),
            secrets_file=secure_file,
            allow_inside_git_worktree=True,
        )
        assert broker.get("discord_bot_token") == "tok-from-file"

    def test_env_value_wins_for_deepseek_api_key(
        self, secure_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "ds-from-env")
        broker = SecretBroker(
            env=dict(os.environ),
            secrets_file=secure_file,
            allow_inside_git_worktree=True,
        )
        assert broker.get("deepseek_api_key") == "ds-from-env"

    def test_symlinked_path_rejected(self, tmp_path: Path) -> None:
        parent = tmp_path / "alfred"
        parent.mkdir()
        parent.chmod(0o700)
        real = parent / "real.toml"
        real.write_text('discord_bot_token = "x"\n')
        real.chmod(0o600)
        link = parent / "secrets.toml"
        link.symlink_to(real)
        with pytest.raises(SecretBrokerPermissionsError):
            SecretBroker(env={}, secrets_file=link, allow_inside_git_worktree=True)

    def test_require_file_raises_when_missing(self, tmp_path: Path) -> None:
        missing = tmp_path / "absent.toml"
        with pytest.raises(SecretBrokerFileMissingError):
            SecretBroker(env={}, secrets_file=missing, require_file=True)

    def test_directory_at_path_raises_not_a_file(self, tmp_path: Path) -> None:
        parent = tmp_path / "alfred"
        parent.mkdir()
        parent.chmod(0o700)
        bad = parent / "secrets.toml"
        bad.mkdir()
        bad.chmod(0o700)
        with pytest.raises(SecretBrokerNotAFileError):
            SecretBroker(env={}, secrets_file=bad, allow_inside_git_worktree=True)

    def test_dot_git_in_parent_is_rejected_by_default(self, tmp_path: Path) -> None:
        worktree = tmp_path / "repo"
        worktree.mkdir()
        (worktree / ".git").mkdir()
        alfred = worktree / "alfred"
        alfred.mkdir()
        alfred.chmod(0o700)
        path = alfred / "secrets.toml"
        path.write_text('discord_bot_token = "x"\n')
        path.chmod(0o600)
        with pytest.raises(SecretBrokerPermissionsError) as exc_info:
            SecretBroker(env={}, secrets_file=path)
        assert exc_info.value.mode == 0  # sentinel for "location failure"

    def test_get_unknown_secret_still_raises(self, secure_file: Path) -> None:
        broker = SecretBroker(
            env={},
            secrets_file=secure_file,
            allow_inside_git_worktree=True,
        )
        with pytest.raises(UnknownSecretError):
            broker.get("nonexistent_secret")

    def test_reload_after_file_edit(self, secure_file: Path) -> None:
        broker = SecretBroker(env={}, secrets_file=secure_file, allow_inside_git_worktree=True)
        assert broker.get("discord_bot_token") == "tok-from-file"
        secure_file.write_text('discord_bot_token = "tok-v2"\n')
        secure_file.chmod(0o600)
        broker.reload()
        assert broker.get("discord_bot_token") == "tok-v2"
