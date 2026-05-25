"""Tests for the env-backed secret broker."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from alfred.security.secrets import SecretBroker, UnknownSecretError


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
            # The list does not leak values
            assert "x" not in " ".join(known)

    def test_get_raises_when_env_var_is_unset(self) -> None:
        # Pass an explicit empty env so the broker can't fall back to a real
        # ALFRED_DEEPSEEK_API_KEY in the developer's shell.
        broker = SecretBroker(env={})
        with pytest.raises(UnknownSecretError) as exc_info:
            broker.get("deepseek_api_key")
        # The error message names the env var so an operator can fix it.
        assert "ALFRED_DEEPSEEK_API_KEY" in str(exc_info.value)

    def test_get_raises_when_env_var_is_empty_string(self) -> None:
        # Differs from `unset`: an empty string in the env is a common dev
        # mistake (export VAR=) and must still be treated as missing.
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": ""})
        with pytest.raises(UnknownSecretError):
            broker.get("deepseek_api_key")

    def test_has_returns_false_for_unknown_secret_name(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "x"})
        # Defends the SUPPORTED_SECRETS allowlist: an unregistered name is
        # never considered present, even if some env var of that name exists.
        assert broker.has("nonexistent_secret") is False

    def test_has_returns_false_when_env_var_is_unset(self) -> None:
        broker = SecretBroker(env={})
        assert broker.has("deepseek_api_key") is False

    def test_has_returns_true_when_env_var_is_set(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "x"})
        assert broker.has("deepseek_api_key") is True

    def test_from_settings_constructs_broker(self) -> None:
        # `_settings` is currently unused (the slice-1 backend reads os.environ
        # directly); we still anchor the construction path so the slice-3+ swap
        # to age-encrypted-file / Vault has tests to fail on if it forgets to
        # read from the passed Settings.
        from unittest.mock import MagicMock

        broker = SecretBroker.from_settings(MagicMock())
        assert isinstance(broker, SecretBroker)


class TestSecretRedaction:
    """The redactor is the structured-logging escape valve — CLAUDE.md hard
    rule #1: never log secrets. The redactor MUST replace every known secret
    value in the input string with a stable [REDACTED:<name>] marker. These
    tests pin every branch of the redact() method."""

    def test_redact_replaces_known_secret_value(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "sk-supersecret"})
        out = broker.redact("token: sk-supersecret end")
        assert "sk-supersecret" not in out
        assert "[REDACTED:deepseek_api_key]" in out

    def test_redact_is_a_noop_when_text_contains_no_secret(self) -> None:
        broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "sk-x"})
        assert broker.redact("nothing sensitive here") == "nothing sensitive here"

    def test_redact_does_not_substitute_empty_string_values(self) -> None:
        # If a secret's env var is empty, the broker treats it as unset; redact
        # must NOT replace every empty-string occurrence in the input (which
        # would corrupt every character boundary).
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
