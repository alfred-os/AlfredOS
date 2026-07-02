"""Verify Settings.secrets_file defaults + override behaviour (#363, ADR-0012).

Completes ADR-0012's layer-3 host-default field: the broker's
``settings_default`` plumbing (see ``alfred.security.secrets``) has existed
since Slice 2, but the ``Settings.secrets_file`` field it reads was never
added — this is the field these tests pin.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from alfred.config.settings import Settings


def test_secrets_file_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default is ~/.config/alfred/secrets.toml per ADR-0012 layer 3."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.delenv("ALFRED_SECRETS_FILE", raising=False)
    settings = Settings()
    assert settings.secrets_file == Path.home() / ".config/alfred/secrets.toml"
    assert settings.secrets_file.is_absolute()


def test_secrets_file_override_via_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """ALFRED_SECRETS_FILE env var overrides the default.

    Also documents Blocker 1's env-name collision (verbatim in the field's
    ``description``): with ``env_prefix="ALFRED_"``, this field auto-maps
    from the SAME ``ALFRED_SECRETS_FILE`` env var the broker reads directly
    for its layer-2 override — a conscious, documented collapse of ADR-0012
    layers 2 and 3 onto one env var.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.setenv("ALFRED_SECRETS_FILE", str(tmp_path / "alt-secrets.toml"))
    settings = Settings()
    assert settings.secrets_file == tmp_path / "alt-secrets.toml"
