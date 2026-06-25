# tests/unit/security/test_broker_discord_token_precedence.py
from pathlib import Path

from alfred.security.secrets import SecretBroker


def test_discord_token_resolves_from_env_when_no_file(tmp_path: Path) -> None:
    """Option A (#309): with no secrets file, the broker resolves discord_bot_token
    from ALFRED_DISCORD_BOT_TOKEN (the _PREFER_FILE env-fallback)."""
    broker = SecretBroker(
        env={"ALFRED_DISCORD_BOT_TOKEN": "tok-env"},
        settings_default=tmp_path / "missing.toml",
    )
    assert broker.get("discord_bot_token") == "tok-env"


def test_file_shadows_env_for_discord_token(tmp_path: Path) -> None:
    """_PREFER_FILE precedence: a secrets.toml value SHADOWS the env var. Pinned so the
    migration's 'set it in .env' guidance is honest about file-shadowing (#309)."""
    f = tmp_path / "secrets.toml"
    f.write_text('discord_bot_token = "tok-file"\n')
    f.chmod(0o600)
    broker = SecretBroker(env={"ALFRED_DISCORD_BOT_TOKEN": "tok-env"}, settings_default=f)
    assert broker.get("discord_bot_token") == "tok-file"
