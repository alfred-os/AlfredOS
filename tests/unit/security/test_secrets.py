"""Tests for the env-backed + file-backed secret broker."""

from __future__ import annotations

import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from alfred.config.settings import Settings
from alfred.errors import AlfredError
from alfred.security import secrets as secrets_module
from alfred.security.secrets import (
    _PREFER_FILE,
    MAX_REDACTOR_PATTERNS,
    SUPPORTED_SECRETS,
    SecretBroker,
    SecretBrokerConfigError,
    SecretBrokerFileMissingError,
    SecretBrokerMalformedError,
    SecretBrokerNotAFileError,
    SecretBrokerPermissionsError,
    SecretBrokerUnreadableError,
    UnknownSecretError,
    _resolve_secrets_path,
    _walk_for_git_parent,
)

# ---------------------------------------------------------------------------
# Slice-1 baseline tests (preserved verbatim)
# ---------------------------------------------------------------------------


class TestSecretBroker:
    def test_returns_secret_from_env(self) -> None:
        with patch.dict(os.environ, {"ALFRED_DEEPSEEK_API_KEY": "abc123"}):
            broker = SecretBroker()
            assert broker.get("deepseek_api_key") == "abc123"

    def test_raises_for_unknown_secret(self) -> None:
        broker = SecretBroker()
        with pytest.raises(UnknownSecretError):
            broker.get("nonexistent_secret")

    def test_known_secrets_are_listed_without_revealing_values(self) -> None:
        with patch.dict(os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x"}):
            broker = SecretBroker()
            known = broker.known()
            assert "deepseek_api_key" in known
            assert "x" not in " ".join(known)

    def test_get_raises_when_env_var_is_unset(self) -> None:
        broker = SecretBroker(env={})
        with pytest.raises(UnknownSecretError) as exc_info:
            broker.get("deepseek_api_key")
        assert "ALFRED_DEEPSEEK_API_KEY" in str(exc_info.value)

    def test_get_raises_when_env_var_is_empty_string(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": ""})
        with pytest.raises(UnknownSecretError):
            broker.get("deepseek_api_key")

    def test_has_returns_false_for_unknown_secret_name(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "x"})
        assert broker.has("nonexistent_secret") is False

    def test_has_returns_false_when_env_var_is_unset(self) -> None:
        broker = SecretBroker(env={})
        assert broker.has("deepseek_api_key") is False

    def test_has_returns_true_when_env_var_is_set(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "x"})
        assert broker.has("deepseek_api_key") is True

    def test_from_settings_constructs_broker(self, tmp_path: Path) -> None:
        # Blocker 4 (#363): a MagicMock stood in here only because the phantom
        # `getattr`+`isinstance` guard in `from_settings` swallowed anything
        # that wasn't a real Path. Now that `Settings.secrets_file` is a typed
        # `Path` field, exercise the real construction path with a Settings
        # instance built via `model_construct` (no env/secret requirements)
        # pointed at a path that provably does not exist.
        settings = Settings.model_construct(
            secrets_file=tmp_path / "does-not-exist" / "secrets.toml"
        )
        broker = SecretBroker.from_settings(settings)
        assert isinstance(broker, SecretBroker)


class TestSecretRedaction:
    def test_redact_replaces_known_secret_value(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "sk-supersecret"})
        out = broker.redact("token: sk-supersecret end")
        assert "sk-supersecret" not in out
        assert "[REDACTED:deepseek_api_key]" in out

    def test_redact_is_a_noop_when_text_contains_no_secret(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "sk-x"})
        assert broker.redact("nothing sensitive here") == "nothing sensitive here"

    def test_redact_does_not_substitute_empty_string_values(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": ""})
        assert broker.redact("hello world") == "hello world"

    def test_redact_handles_multiple_known_secrets(self) -> None:
        broker = SecretBroker(
            env={
                "ALFRED_DEEPSEEK_API_KEY": "ds-key",
                "ALFRED_ANTHROPIC_API_KEY": "an-key",
            }
        )
        out = broker.redact("ds=ds-key an=an-key")
        assert "ds-key" not in out
        assert "an-key" not in out
        assert "[REDACTED:deepseek_api_key]" in out
        assert "[REDACTED:anthropic_api_key]" in out

    def test_redact_longer_secret_before_shorter_substring(self) -> None:
        broker = SecretBroker(
            env={
                "ALFRED_DEEPSEEK_API_KEY": "sk-ant-longersecret",
                "ALFRED_ANTHROPIC_API_KEY": "sk-ant",
            }
        )
        result = broker.redact("token is sk-ant-longersecret here")
        assert "[REDACTED:deepseek_api_key]" in result
        assert "longersecret" not in result


# ---------------------------------------------------------------------------
# Task 1: SecretBrokerConfigError + subtypes
# ---------------------------------------------------------------------------


class TestConfigErrorHierarchy:
    """Pin the four-class shape of the SecretBroker config-error tree.

    CLI top-level dispatch catches ``SecretBrokerConfigError`` once and routes
    i18n on the concrete subtype — drift here is an i18n hard-rule-#1 leak."""

    def test_config_error_subtypes_inherit_from_base(self) -> None:
        assert issubclass(SecretBrokerPermissionsError, SecretBrokerConfigError)
        assert issubclass(SecretBrokerFileMissingError, SecretBrokerConfigError)
        assert issubclass(SecretBrokerNotAFileError, SecretBrokerConfigError)
        # The load-boundary typed wraps (#370 item 1) also root at the base so
        # the #368 boot/CLI handlers catch them uniformly.
        assert issubclass(SecretBrokerMalformedError, SecretBrokerConfigError)
        assert issubclass(SecretBrokerUnreadableError, SecretBrokerConfigError)
        # Base inherits from AlfredError per the conventions doc.
        assert issubclass(SecretBrokerConfigError, AlfredError)

    def test_config_error_carries_path(self) -> None:
        path = Path("/etc/alfred/secrets.toml")
        err = SecretBrokerConfigError("boom", path=path)
        assert err.path == path
        assert "boom" in str(err)

    def test_permissions_error_repr_includes_octal_mode(self) -> None:
        err = SecretBrokerPermissionsError("perms", path=Path("/x"), mode=0o644, parent=Path("/"))
        assert "0o644" in repr(err)
        assert "/x" in repr(err)
        assert err.parent == Path("/")

    def test_config_error_repr_includes_path(self) -> None:
        err = SecretBrokerConfigError("oops", path=Path("/x/y"))
        assert "/x/y" in repr(err)
        assert "SecretBrokerConfigError" in repr(err)

    def test_missing_and_not_a_file_subtypes_carry_only_path(self) -> None:
        missing = SecretBrokerFileMissingError("missing", path=Path("/m"))
        not_file = SecretBrokerNotAFileError("dir", path=Path("/d"))
        assert missing.path == Path("/m")
        assert not_file.path == Path("/d")


# ---------------------------------------------------------------------------
# Task 2: SUPPORTED_SECRETS + _PREFER_FILE invariants
# ---------------------------------------------------------------------------


class TestSupportedSecretsRegistry:
    def test_supported_secrets_contains_discord_bot_token(self) -> None:
        assert "discord_bot_token" in SUPPORTED_SECRETS

    def test_supported_secrets_preserves_slice_1_keys(self) -> None:
        assert {"deepseek_api_key", "anthropic_api_key"} <= SUPPORTED_SECRETS

    def test_prefer_file_is_strict_subset_of_supported_secrets(self) -> None:
        # Drift guard: a future PR that adds a _PREFER_FILE entry without also
        # adding it to SUPPORTED_SECRETS would silently never find the secret.
        assert _PREFER_FILE <= SUPPORTED_SECRETS
        # And the prefer-file set is non-empty (we ship at least discord_bot_token).
        assert _PREFER_FILE

    def test_prefer_file_contains_discord_bot_token(self) -> None:
        assert "discord_bot_token" in _PREFER_FILE

    def test_prefer_file_contains_quarantine_provider_api_key(self) -> None:
        # PR-S4-11c-2b: the quarantined child's provider key is file-preferred so
        # ALFRED_QUARANTINE_PROVIDER_API_KEY cannot silently override the secrets
        # file (rule #6 — secrets in the broker/file, not plugin-readable env).
        assert "quarantine_provider_api_key" in _PREFER_FILE


# ---------------------------------------------------------------------------
# Task 3: path resolution pipeline
# ---------------------------------------------------------------------------


class TestResolveSecretsPath:
    def test_constructor_override_wins(self) -> None:
        out = _resolve_secrets_path(
            constructor_arg=Path("/override"),
            env={"ALFRED_SECRETS_FILE": "/env"},
            settings_default=Path("/settings"),
        )
        assert out == Path("/override")

    def test_env_var_overrides_settings_default(self) -> None:
        out = _resolve_secrets_path(
            constructor_arg=None,
            env={"ALFRED_SECRETS_FILE": "/env"},
            settings_default=Path("/settings"),
        )
        assert out == Path("/env")

    def test_settings_default_used_when_no_override(self) -> None:
        out = _resolve_secrets_path(
            constructor_arg=None,
            env={},
            settings_default=Path("/settings"),
        )
        assert out == Path("/settings")

    def test_returns_none_when_all_layers_empty(self) -> None:
        out = _resolve_secrets_path(
            constructor_arg=None,
            env={},
            settings_default=None,
        )
        assert out is None

    def test_empty_env_value_is_treated_as_unset(self) -> None:
        # An empty string in the env is operator-error-shaped (`export VAR=`).
        # The pipeline must not treat it as a configured path.
        out = _resolve_secrets_path(
            constructor_arg=None,
            env={"ALFRED_SECRETS_FILE": ""},
            settings_default=Path("/settings"),
        )
        assert out == Path("/settings")


# ---------------------------------------------------------------------------
# Task 4 + 5: permissions check + .git walk
# ---------------------------------------------------------------------------


@pytest.fixture
def secure_secrets_file(tmp_path: Path) -> Path:
    """Create a 0600 secrets.toml under a 0700 parent. No .git in any ancestor."""
    parent = tmp_path / "alfred"
    parent.mkdir(mode=0o700)
    path = parent / "secrets.toml"
    path.write_text('discord_bot_token = "from-file"\n')
    path.chmod(0o600)
    return path


class TestLoadBoundaryTypedErrors:
    """#370 item 1: raw ``TOMLDecodeError`` / ``OSError`` at the load boundary
    become typed ``SecretBrokerConfigError`` subtypes so the #368 boot/CLI
    handlers catch them uniformly instead of surfacing a raw traceback.
    """

    def test_malformed_toml_raises_typed_malformed_error(self, tmp_path: Path) -> None:
        """A valid-perms secrets file with broken TOML → SecretBrokerMalformedError.

        Fail-closed: the broker must NOT proceed with empty/partial secrets when
        the file exists but cannot be parsed — it refuses loudly. The typed
        subtype roots at SecretBrokerConfigError so the boot/CLI dispatch catches
        it uniformly (no raw tomllib.TOMLDecodeError traceback).
        """
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text("this is = = not valid toml [\n")  # broken TOML
        path.chmod(0o600)

        with pytest.raises(SecretBrokerMalformedError) as exc_info:
            SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)

        assert isinstance(exc_info.value, SecretBrokerConfigError)
        assert exc_info.value.path == path

    def test_unreadable_file_raises_typed_unreadable_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An OSError escaping the load boundary → SecretBrokerUnreadableError.

        A permission/IO failure or a stat/lstat OSError (TOCTOU race, unreadable
        parent) that escapes the load step becomes the typed
        SecretBrokerUnreadableError rather than a raw traceback — distinct from
        the malformed-TOML case so the operator gets the right remediation (fix
        access, not fix syntax). Deterministic fault injection at the load call
        (env-independent — a real 0000 file is readable by root, so it can't
        pin this branch on a root CI lane).
        """
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "x"\n')
        path.chmod(0o600)

        def _raise_eacces(_path: Path) -> None:
            raise PermissionError(13, "Permission denied")

        # Validation passes on the real 0600 file; the load then fails with an
        # escaping OSError, exercising the __init__ except-OSError wrap.
        monkeypatch.setattr(secrets_module, "_load_toml_file", _raise_eacces)

        with pytest.raises(SecretBrokerUnreadableError) as exc_info:
            SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)

        assert isinstance(exc_info.value, SecretBrokerConfigError)
        assert exc_info.value.path == path

    def test_invalid_utf8_file_raises_typed_malformed_error(self, tmp_path: Path) -> None:
        """A valid-perms secrets file with invalid UTF-8 → SecretBrokerMalformedError.

        ``tomllib.load`` decodes the file as UTF-8 before parsing, so a corrupt /
        binary / wrong-encoding file raises ``UnicodeDecodeError`` — a ValueError
        that is NEITHER TOMLDecodeError NOR OSError. Without the wrap it would
        escape both arms as a raw traceback on the boot/CLI path this PR hardens
        (error-reviewer Medium). Invalid encoding is malformed content, so it
        maps to the same typed Malformed subtype + "fix the file" remediation.
        """
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_bytes(b'token = "\xff\xfe not utf-8"\n')  # invalid UTF-8 byte
        path.chmod(0o600)

        with pytest.raises(SecretBrokerMalformedError) as exc_info:
            SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)

        assert isinstance(exc_info.value, SecretBrokerConfigError)
        assert exc_info.value.path == path

    def test_validation_phase_oserror_raises_typed_unreadable_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An OSError from the VALIDATION step (stat/lstat) → SecretBrokerUnreadableError.

        #370 explicitly names a stat/lstat OSError as an escape route. The
        construction try encloses _validate_secrets_file_security, so a stat OSError
        maps to the same Unreadable subtype. Pinning it here (via a monkeypatch on
        the validator, mirroring the reload-TOCTOU test) guards the named property
        against a future refactor that narrows the try scope (test-eng Low).
        """
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "x"\n')
        path.chmod(0o600)

        def _raise_oserror(_path: Path) -> None:
            raise OSError(5, "Input/output error")  # e.g. stat on a failing mount

        monkeypatch.setattr(secrets_module, "_validate_secrets_file_security", _raise_oserror)

        with pytest.raises(SecretBrokerUnreadableError) as exc_info:
            SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)

        assert isinstance(exc_info.value, SecretBrokerConfigError)
        assert exc_info.value.path == path

    def test_malformed_and_unreadable_carry_only_path(self) -> None:
        """Both new subtypes carry just ``path`` (mirrors the missing/not-a-file leaves)."""
        malformed = SecretBrokerMalformedError("bad toml", path=Path("/m"))
        unreadable = SecretBrokerUnreadableError("eacces", path=Path("/u"))
        assert malformed.path == Path("/m")
        assert unreadable.path == Path("/u")


class TestSecretsFilePathAccessor:
    """#370 item 3: the read-only ``secrets_file_path`` accessor ``alfred status`` renders."""

    def test_none_for_env_only_broker(self) -> None:
        """No file layer set → None (env-only backend)."""
        assert SecretBroker(env={}).secrets_file_path is None

    def test_returns_resolved_path_for_present_file(self, tmp_path: Path) -> None:
        """A present, valid file layer → its resolved path."""
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "x"\n')
        path.chmod(0o600)
        broker = SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)
        assert broker.secrets_file_path == path

    def test_reflects_configured_but_absent_file(self, tmp_path: Path) -> None:
        """The accessor returns the resolved path even when the file is ABSENT.

        The broker falls back to env-only for a missing file (``require_file=False``)
        but keeps the resolved path (secrets.py construction returns early WITHOUT
        nulling it). ``alfred status`` relies on this to report where it looks —
        and to mark it "not found" (devex). A future refactor that nulled the path
        in the missing-file branch would silently break the status line, so pin it.
        """
        absent = tmp_path / "alfred" / "secrets.toml"  # never created
        broker = SecretBroker(env={}, secrets_file=absent, allow_inside_git_worktree=True)
        assert broker.secrets_file_path == absent


class TestPermissionsCheck:
    def test_rejects_symlink(self, tmp_path: Path) -> None:
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        real = parent / "real.toml"
        real.write_text('discord_bot_token = "x"\n')
        real.chmod(0o600)
        link = parent / "secrets.toml"
        link.symlink_to(real)
        with pytest.raises(SecretBrokerPermissionsError) as exc_info:
            SecretBroker(env={}, secrets_file=link, allow_inside_git_worktree=True)
        assert exc_info.value.path == link

    def test_rejects_world_readable_file(self, tmp_path: Path) -> None:
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "x"\n')
        path.chmod(0o644)  # group + world readable
        with pytest.raises(SecretBrokerPermissionsError) as exc_info:
            SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)
        assert exc_info.value.mode & 0o077 != 0

    def test_rejects_group_writable_parent(self, tmp_path: Path) -> None:
        parent = tmp_path / "alfred"
        parent.mkdir()
        parent.chmod(0o770)  # group writable — chmod ignores umask
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "x"\n')
        path.chmod(0o600)
        with pytest.raises(SecretBrokerPermissionsError) as exc_info:
            SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)
        assert exc_info.value.parent == parent

    def test_rejects_wrong_owner(self, secure_secrets_file: Path) -> None:
        # Patch os.getuid() to return a uid that doesn't match the file's
        # st_uid — we can't easily chown to a different user in tmp_path
        # without root, so monkey-patch the broker's view of "self".
        real_uid = secure_secrets_file.stat().st_uid
        with (
            patch("alfred.security.secrets.os.getuid", return_value=real_uid + 9999),
            pytest.raises(SecretBrokerPermissionsError),
        ):
            SecretBroker(
                env={},
                secrets_file=secure_secrets_file,
                allow_inside_git_worktree=True,
            )

    def test_rejects_directory_at_path(self, tmp_path: Path) -> None:
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        # Path exists as a directory — Docker bind-mount auto-create failure.
        dir_at_path = parent / "secrets.toml"
        dir_at_path.mkdir(mode=0o700)
        with pytest.raises(SecretBrokerNotAFileError) as exc_info:
            SecretBroker(
                env={},
                secrets_file=dir_at_path,
                allow_inside_git_worktree=True,
            )
        assert exc_info.value.path == dir_at_path


class TestGitWalk:
    def test_rejects_path_inside_worktree(self, tmp_path: Path) -> None:
        worktree = tmp_path / "repo"
        worktree.mkdir()
        (worktree / ".git").mkdir()
        alfred = worktree / "alfred"
        alfred.mkdir(mode=0o700)
        path = alfred / "secrets.toml"
        path.write_text('discord_bot_token = "x"\n')
        path.chmod(0o600)
        with pytest.raises(SecretBrokerPermissionsError) as exc_info:
            SecretBroker(env={}, secrets_file=path)
        assert exc_info.value.mode == 0
        assert exc_info.value.parent == worktree

    def test_git_walk_rejection_renders_the_location_message(self, tmp_path: Path) -> None:
        """Blocker 2 (#363): the .git-parent refusal must render the accurate
        "wrong location" remedy, NOT the misleading `chmod 600` perms-template
        text (the pre-fix defect: the message rendered `secrets.file_perms_too_open`
        with a sentinel `octal_mode="0"`, which reads as a permissions problem for
        a file that is actually in the wrong place)."""
        worktree = tmp_path / "repo"
        worktree.mkdir()
        (worktree / ".git").mkdir()
        alfred = worktree / "alfred"
        alfred.mkdir(mode=0o700)
        path = alfred / "secrets.toml"
        path.write_text('discord_bot_token = "x"\n')
        path.chmod(0o600)
        with pytest.raises(SecretBrokerPermissionsError) as exc_info:
            SecretBroker(env={}, secrets_file=path)
        message = str(exc_info.value)
        assert "inside a git repository" in message
        assert str(path) in message
        assert str(worktree) in message
        assert "chmod" not in message

    def test_allow_inside_git_worktree_bypasses(self, tmp_path: Path) -> None:
        worktree = tmp_path / "repo"
        worktree.mkdir()
        (worktree / ".git").mkdir()
        alfred = worktree / "alfred"
        alfred.mkdir(mode=0o700)
        path = alfred / "secrets.toml"
        path.write_text('discord_bot_token = "from-file"\n')
        path.chmod(0o600)
        # Must not raise.
        broker = SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)
        assert broker.get("discord_bot_token") == "from-file"

    def test_walk_for_git_parent_returns_none_when_no_git(self, tmp_path: Path) -> None:
        path = tmp_path / "alfred" / "secrets.toml"
        path.parent.mkdir(parents=True)
        path.touch()
        assert _walk_for_git_parent(path) is None

    def test_walk_for_git_parent_bounded_by_max_depth(self, tmp_path: Path) -> None:
        # If the .git directory is deeper than max_depth ancestors, the walk
        # stops without finding it. The defense is against pathological
        # symlink loops, but a shallow max_depth = 1 demonstrates the bound
        # explicitly.
        deep = tmp_path / "a" / "b" / "c" / "d" / "secrets.toml"
        deep.parent.mkdir(parents=True)
        deep.touch()
        (tmp_path / ".git").mkdir()
        assert _walk_for_git_parent(deep, max_depth=2) is None
        # Same path with adequate depth finds it.
        assert _walk_for_git_parent(deep, max_depth=12) == tmp_path


# ---------------------------------------------------------------------------
# Task 6: get() precedence + require_file semantics + load_toml
# ---------------------------------------------------------------------------


class TestGetPrecedence:
    def test_env_wins_for_slice_1_keys(self, secure_secrets_file: Path) -> None:
        # File defines discord_bot_token; we add deepseek_api_key to the file
        # to assert env still wins for slice-1 keys.
        secure_secrets_file.write_text(
            'discord_bot_token = "from-file"\ndeepseek_api_key = "ds-from-file"\n'
        )
        broker = SecretBroker(
            env={"ALFRED_DEEPSEEK_API_KEY": "ds-from-env"},
            secrets_file=secure_secrets_file,
            allow_inside_git_worktree=True,
        )
        assert broker.get("deepseek_api_key") == "ds-from-env"

    def test_file_wins_for_prefer_file_keys(self, secure_secrets_file: Path) -> None:
        broker = SecretBroker(
            env={"ALFRED_DISCORD_BOT_TOKEN": "from-env"},
            secrets_file=secure_secrets_file,
            allow_inside_git_worktree=True,
        )
        assert broker.get("discord_bot_token") == "from-file"

    def test_file_wins_for_quarantine_provider_api_key(self, tmp_path: Path) -> None:
        # PR-S4-11c-2b precedence lock: the file value wins over
        # ALFRED_QUARANTINE_PROVIDER_API_KEY (file-preferred, like discord_bot_token).
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('quarantine_provider_api_key = "from-file"\n')
        path.chmod(0o600)
        broker = SecretBroker(
            env={"ALFRED_QUARANTINE_PROVIDER_API_KEY": "from-env"},
            secrets_file=path,
            allow_inside_git_worktree=True,
        )
        assert broker.get("quarantine_provider_api_key") == "from-file"

    def test_file_falls_back_to_env_when_file_lacks_key(self, secure_secrets_file: Path) -> None:
        # File has discord_bot_token only; deepseek_api_key only in env.
        broker = SecretBroker(
            env={"ALFRED_DEEPSEEK_API_KEY": "env-only"},
            secrets_file=secure_secrets_file,
            allow_inside_git_worktree=True,
        )
        assert broker.get("deepseek_api_key") == "env-only"

    def test_prefer_file_falls_back_to_env_when_file_lacks_key(self, tmp_path: Path) -> None:
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text("# empty\n")
        path.chmod(0o600)
        broker = SecretBroker(
            env={"ALFRED_DISCORD_BOT_TOKEN": "env-fallback"},
            secrets_file=path,
            allow_inside_git_worktree=True,
        )
        assert broker.get("discord_bot_token") == "env-fallback"

    def test_require_file_raises_when_file_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "missing.toml"
        with pytest.raises(SecretBrokerFileMissingError):
            SecretBroker(env={}, secrets_file=path, require_file=True)

    def test_require_file_raises_when_no_path_resolvable(self) -> None:
        # No constructor arg, no env, no settings default — require_file=True
        # must still fail-closed.
        with pytest.raises(SecretBrokerFileMissingError):
            SecretBroker(env={}, require_file=True)

    def test_require_file_false_proceeds_when_file_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "missing.toml"
        broker = SecretBroker(
            env={"ALFRED_DEEPSEEK_API_KEY": "x"},
            secrets_file=path,
            require_file=False,
        )
        assert broker.get("deepseek_api_key") == "x"

    def test_get_with_both_missing_raises_unknown_secret(self) -> None:
        broker = SecretBroker(env={})
        with pytest.raises(UnknownSecretError):
            broker.get("discord_bot_token")

    def test_get_via_env_var_for_secrets_file_path(
        self, secure_secrets_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # ALFRED_SECRETS_FILE in the env routes through _resolve_secrets_path.
        monkeypatch.setenv("ALFRED_SECRETS_FILE", str(secure_secrets_file))
        broker = SecretBroker(env=dict(os.environ), allow_inside_git_worktree=True)
        assert broker.get("discord_bot_token") == "from-file"

    def test_load_toml_drops_non_string_values(self, tmp_path: Path) -> None:
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "ok"\njunk = 42\n[nested]\ninner = "y"\n')
        path.chmod(0o600)
        broker = SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)
        assert broker.get("discord_bot_token") == "ok"
        # `junk` (int) and `[nested]` (table) dropped by the flat-mapping policy.

    def test_has_returns_true_when_file_supplies_value(self, secure_secrets_file: Path) -> None:
        broker = SecretBroker(
            env={},
            secrets_file=secure_secrets_file,
            allow_inside_git_worktree=True,
        )
        assert broker.has("discord_bot_token") is True

    def test_known_includes_file_backed_secrets(self, secure_secrets_file: Path) -> None:
        broker = SecretBroker(
            env={},
            secrets_file=secure_secrets_file,
            allow_inside_git_worktree=True,
        )
        assert "discord_bot_token" in broker.known()


class TestFromSettings:
    def test_uses_settings_secrets_file_when_present(
        self,
        secure_secrets_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from types import SimpleNamespace

        # Strip any caller env that would otherwise mask the file backend —
        # the fixture writes ``discord_bot_token = "from-file"`` so the broker
        # MUST report that value once the settings path is honoured.
        monkeypatch.delenv("ALFRED_DISCORD_BOT_TOKEN", raising=False)
        monkeypatch.delenv("ALFRED_SECRETS_FILE", raising=False)

        broker = SecretBroker.from_settings(SimpleNamespace(secrets_file=secure_secrets_file))

        # Real behavioural assertion: the file-backend was loaded and the
        # value from the fixture is retrievable through the public API.
        assert broker.has("discord_bot_token") is True
        assert broker.get("discord_bot_token") == "from-file"

    # test_ignores_non_path_settings_attribute REMOVED (#363 blocker 4): its
    # premise — Settings.secrets_file might be a str/mock — dies once the
    # field is a typed Path. Without the isinstance guard the phantom
    # getattr()+isinstance() defence used to swallow, `from_settings` now
    # trusts the typed field directly; a str would crash on `.exists()`,
    # which is correct (a caller error, not something to paper over).


class TestReload:
    def test_reload_picks_up_new_value(self, tmp_path: Path) -> None:
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "v1"\n')
        path.chmod(0o600)
        broker = SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)
        assert broker.get("discord_bot_token") == "v1"
        path.write_text('discord_bot_token = "v2"\n')
        path.chmod(0o600)
        broker.reload()
        assert broker.get("discord_bot_token") == "v2"

    def test_reload_handles_now_missing_file(self, tmp_path: Path) -> None:
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "v1"\n')
        path.chmod(0o600)
        broker = SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)
        path.unlink()
        broker.reload()
        # No raise; subsequent get falls back to env (empty here → UnknownSecret).
        with pytest.raises(UnknownSecretError):
            broker.get("discord_bot_token")

    def test_reload_malformed_file_raises_typed_and_retains_prior(self, tmp_path: Path) -> None:
        """A now-malformed file on reload → SecretBrokerMalformedError, prior retained.

        #370 / CR #379: the reload seam mirrors __init__'s typed load boundary.
        The file exists + perms pass but the content is now broken TOML, so
        reload fails LOUD with the typed subtype (not a raw TOMLDecodeError). The
        assignment never completes → the prior secrets are retained and the
        redactor cache is not bumped (fail-closed to last-good).
        """
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "v1"\n')
        path.chmod(0o600)
        broker = SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)

        path.write_text("this is = = not valid toml [\n")
        path.chmod(0o600)
        with pytest.raises(SecretBrokerMalformedError):
            broker.reload()

        # Fail-closed to prior: the last-good value survives the failed reload.
        assert broker.get("discord_bot_token") == "v1"

    def test_reload_oserror_raises_typed_unreadable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An OSError escaping the reload load → SecretBrokerUnreadableError.

        #370 / CR #379: mirrors __init__'s except-OSError arm on the reload seam.
        FileNotFoundError is handled above (TOCTOU-as-missing); a non-FNF OSError
        (e.g. EACCES after a mode flip) fails loud with the typed subtype.
        """
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "v1"\n')
        path.chmod(0o600)
        broker = SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)

        def _raise_eacces(_path: Path) -> None:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(secrets_module, "_load_toml_file", _raise_eacces)
        with pytest.raises(SecretBrokerUnreadableError):
            broker.reload()

    def test_reload_toctou_filenotfound_fails_closed_to_empty(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """CR-142 round-3 sec-003: deterministic coverage for the TOCTOU branch.

        ``reload()`` first checks ``self._secrets_file_path.exists()``
        and then calls ``_validate_secrets_file_security`` which
        ``lstat()``s the same path. In the (rare, microsecond-window)
        case where the file disappears between those two syscalls, the
        validator raises ``FileNotFoundError``. The defensive
        ``except FileNotFoundError`` branch must fail CLOSED to the
        empty mapping — same end-state as the ``exists() == False`` arm
        — rather than propagating the race up the stack.

        The pragma previously documented why this branch was hard to
        cover from a real race; CR-142 round-3 removed the pragma in
        favour of this deterministic injection. We monkey-patch the
        validator to raise ``FileNotFoundError`` AFTER ``exists()`` has
        already returned True, simulating exactly the TOCTOU window.
        The assertion checks the same fail-closed semantics
        (empty file_secrets + cache version bump) the no-pragma branch
        guarantees.
        """
        parent = tmp_path / "alfred"
        parent.mkdir(mode=0o700)
        path = parent / "secrets.toml"
        path.write_text('discord_bot_token = "v1"\n')
        path.chmod(0o600)
        broker = SecretBroker(env={}, secrets_file=path, allow_inside_git_worktree=True)
        assert broker.get("discord_bot_token") == "v1"

        # Capture the pre-reload redactor version so we can assert the
        # cache invalidation half of the fail-closed contract.
        pre_version = broker._redactor_version

        # The file is STILL on disk — ``exists()`` returns True — but
        # the validator raises FileNotFoundError as if the file
        # vanished between the ``exists()`` probe and the ``lstat()``.
        def _raise_filenotfound(p: object) -> None:
            raise FileNotFoundError(f"simulated TOCTOU race on {p}")

        monkeypatch.setattr(
            "alfred.security.secrets._validate_secrets_file_security",
            _raise_filenotfound,
        )
        broker.reload()

        # Fail-closed: file_secrets is the empty mapping, redactor
        # cache has bumped, and ``get`` falls back to env (empty here
        # → UnknownSecret) just like the file-actually-missing arm.
        assert dict(broker._file_secrets) == {}
        assert broker._redactor_version > pre_version
        with pytest.raises(UnknownSecretError):
            broker.get("discord_bot_token")


# ---------------------------------------------------------------------------
# Task 11: redactor cache + overflow
# ---------------------------------------------------------------------------


class TestRedactorCache:
    def test_redact_uses_cache_on_second_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "sk-x"})

        compile_calls = 0
        real_compile = re.compile

        def counting_compile(*args: object, **kw: object) -> re.Pattern[str]:
            nonlocal compile_calls
            compile_calls += 1
            return real_compile(*args, **kw)  # type: ignore[arg-type]

        monkeypatch.setattr("alfred.security.secrets.re.compile", counting_compile)
        broker.redact("a sk-x b")
        first = compile_calls
        broker.redact("c sk-x d")
        # Second call must reuse the cached pattern — no extra compile.
        assert compile_calls == first

    def test_cache_invalidates_on_version_bump(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "sk-x"})
        broker.redact("a")
        cache_before = broker._redactor_cache
        broker._bump_redactor_version()
        broker.redact("a")
        # Cache tuple's version field is updated; the cache identity may
        # change (new tuple) and version differs.
        assert broker._redactor_cache is not None
        assert broker._redactor_cache[0] != (cache_before[0] if cache_before else -1)

    def test_redact_with_no_live_secrets(self) -> None:
        broker = SecretBroker(env={})
        # Should still be a safe no-op — no secrets to substitute.
        assert broker.redact("hello") == "hello"

    def test_redact_pattern_overflow_keeps_longest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "sk-deepseek"})

        # Synthesise an oversized pair list: monkeypatch _known_with_values
        # so the next redact() call sees 257 entries (cap + 1).
        long_value = "Z" * 200  # longest
        short_values = [f"short-{i}" for i in range(MAX_REDACTOR_PATTERNS)]
        oversized: list[tuple[str, str]] = [
            ("deepseek_api_key", long_value),
        ] + [(f"shortlike-{i}", v) for i, v in enumerate(short_values)]

        monkeypatch.setattr(broker, "_known_with_values", lambda: oversized)

        before = secrets_module.alfred_redactor_pattern_overflow_total
        out = broker.redact(f"x {long_value} {short_values[-1]} y")
        # Longest is kept and substituted.
        assert long_value not in out
        # Counter bumped.
        assert secrets_module.alfred_redactor_pattern_overflow_total == before + 1

    def test_overflow_warning_is_one_shot_per_broker(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        broker = SecretBroker(env={})
        big = [(f"k{i}", f"v{i}") for i in range(MAX_REDACTOR_PATTERNS + 5)]
        monkeypatch.setattr(broker, "_known_with_values", lambda: big)

        before = secrets_module.alfred_redactor_pattern_overflow_total
        # First redact: cache cold → overflow path → counter bumped once.
        broker.redact("noop")
        # Force a recompile (cache invalidated) so the overflow branch runs
        # a second time — but _overflow_warned is sticky, so the counter
        # must not bump again. This exercises the "already-warned" branch
        # explicitly.
        broker._bump_redactor_version()
        broker.redact("noop")
        broker._bump_redactor_version()
        broker.redact("noop")
        assert secrets_module.alfred_redactor_pattern_overflow_total == before + 1

    def test_redact_with_empty_pair_set_then_filled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        broker = SecretBroker(env={})
        # Initial redact: zero pairs → sentinel never-match pattern.
        assert broker.redact("hello") == "hello"
        # Now mutate: add a value via env-substitute and bump.
        broker._env = {"ALFRED_DEEPSEEK_API_KEY": "sk-x"}  # type: ignore[assignment]
        broker._bump_redactor_version()
        out = broker.redact("token sk-x")
        assert "[REDACTED:deepseek_api_key]" in out
