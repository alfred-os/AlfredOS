"""Structural-satisfaction proof for the SecretBroker config Protocol (#351/#363).

The identity-return function is a COMPILE-TIME proof (never called at runtime): mypy
--strict accepts ``Settings -> SecretBrokerConfig`` iff ``Settings`` satisfies the
Protocol, so a real ``Settings`` can be passed wherever ``SecretBrokerConfig`` is
required — and a future ``Settings.secrets_file`` rename fails the type-check instead
of silently drifting. The stub tests prove the DIP win: ``SecretBroker.from_settings``
works against a trivial double, not just a full ``Settings``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from alfred.config.settings import Settings
from alfred.security._config_protocols import SecretBrokerConfig
from alfred.security.secrets import SecretBroker


def _settings_satisfies(settings: Settings) -> SecretBrokerConfig:
    # Compile-time proof only; mypy --strict type-checks the return. Needs no
    # Settings() construction (avoids env/secret requirements).
    return settings


class _StubCfg:
    """A trivial config double — NOT a Settings — supplying the one field the seam reads."""

    def __init__(self, *, secrets_file: Path) -> None:
        self.secrets_file = secrets_file


def test_plain_stub_satisfies_secret_broker_config() -> None:
    """The DIP win: a trivial stub — not a full Settings — satisfies the Protocol."""
    cfg: SecretBrokerConfig = _StubCfg(secrets_file=Path("/nonexistent/secrets.toml"))
    assert cfg.secrets_file == Path("/nonexistent/secrets.toml")


def test_from_settings_threads_the_stub_secrets_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The DIP win: from_settings threads a plain stub's secrets_file end-to-end.

    Asserts the actual OUTPUT (a secret loaded from the stub-supplied file), matching the
    egress/capability_gate proof pattern — not just construction. Clears ``ALFRED_SECRETS_FILE``
    so the ``_hermetic_secrets_path`` autouse fixture's layer-2 override does not shadow the
    stub's layer-3 path (pytest tmp_path is outside any git worktree, so the ``.git``-walk and
    perm checks pass).
    """
    monkeypatch.delenv("ALFRED_SECRETS_FILE", raising=False)
    monkeypatch.delenv("ALFRED_DISCORD_BOT_TOKEN", raising=False)
    secrets_file = tmp_path / "secrets.toml"
    secrets_file.write_text('discord_bot_token = "from-stub-file"\n', encoding="utf-8")
    secrets_file.chmod(0o600)

    broker = SecretBroker.from_settings(_StubCfg(secrets_file=secrets_file))

    assert broker.get("discord_bot_token") == "from-stub-file"
