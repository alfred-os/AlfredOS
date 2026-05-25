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
