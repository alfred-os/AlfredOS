"""AlfredOS configuration loading via pydantic-settings.

Loads from environment variables prefixed with ALFRED_. A `.env` file in the
working directory is read automatically. Secrets are wrapped in `SecretStr` so
they never leak into logs by accident.
"""

from __future__ import annotations

from pydantic import Field, PostgresDsn, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class SettingsError(ValueError):
    """Raised when Settings fail to load with a usable, operator-facing message.

    The CLI catches this and prints a friendly hint (`hint.copy_env_example`) instead
    of the pydantic ValidationError stack trace that would otherwise greet the first-time
    user. See `src/alfred/cli/main.py` for the catch site.
    """


class Settings(BaseSettings):
    """Top-level AlfredOS settings."""

    model_config = SettingsConfigDict(
        env_prefix="ALFRED_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Provider config
    deepseek_api_key: SecretStr
    deepseek_base_url: str = "https://api.deepseek.com/v1"
    deepseek_model: str = "deepseek-chat"
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-sonnet-4-6"
    primary_provider: str = "deepseek"
    fallback_provider: str = "anthropic"

    # Database
    database_url: PostgresDsn = Field(
        default=PostgresDsn("postgresql+asyncpg://alfred:alfred@localhost:5432/alfred")
    )

    # Budget
    daily_budget_usd: float = 1.0
    per_call_max_usd: float = 0.10

    # Operator (single-user slice 1)
    operator_name: str = "operator"
    operator_language: str = "en-US"  # BCP-47; CLAUDE.md i18n rule #2 (Task 3.5 consumer)

    def __init__(self, **kw):  # type: ignore[no-untyped-def]
        try:
            super().__init__(**kw)
        except Exception as exc:
            # Translate pydantic ValidationError into a SettingsError the CLI can render.
            raise SettingsError(str(exc)) from exc
