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


def test_from_settings_accepts_a_plain_stub(tmp_path: Path) -> None:
    """from_settings consumes SecretBrokerConfig — a stub drives the seam end-to-end."""
    broker = SecretBroker.from_settings(_StubCfg(secrets_file=tmp_path / "does-not-exist.toml"))
    assert isinstance(broker, SecretBroker)
