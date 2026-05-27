"""AlfredOS configuration loading via pydantic-settings.

Loads from environment variables prefixed with ALFRED_. A `.env` file in the
working directory is read automatically. Secrets are wrapped in `SecretStr` so
they never leak into logs by accident.
"""

from __future__ import annotations

from pydantic import Field, PostgresDsn, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The literal placeholder shipped in .env.example. Rejected in both the setup
# script (bin/alfred-setup.sh) and the Settings validator below so an operator
# who skipped editing .env hits a friendly error before any provider call.
_PLACEHOLDER_API_KEY = "sk-..."


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

    # Budget. Both must be > 0 — a zero or negative cap would make every
    # call an automatic refusal (daily_usd) or trivially-bypass-able
    # (per_call_max_usd), which contradicts the operator's intent of having
    # the gate at all. Pydantic raises ValidationError on load, which
    # ``_load_settings_or_die`` translates to a friendly t() message. The
    # complementary ``math.isfinite`` + non-negative guards inside
    # ``BudgetGuard`` cover hand-constructed sub-guards (tests, future
    # personas) that don't go through Settings.
    daily_budget_usd: float = Field(default=1.0, gt=0)
    per_call_max_usd: float = Field(default=0.10, gt=0)

    # Operator (single-user slice 1)
    operator_name: str = "operator"
    operator_language: str = "en-US"  # BCP-47; CLAUDE.md i18n rule #2 (Task 3.5 consumer)

    # PR-B Phase 5: WorkingMemoryPool cap override. ``None`` defers to the
    # pool's default policy (``max(50, active_user_count * 2)`` — see
    # ``alfred.memory.working_pool.WorkingMemoryPool._cap``). Operators can
    # pin a hard cap via ``ALFRED_WORKING_MEMORY_POOL_MAX`` when running on
    # constrained hardware; the ``ge=50`` floor stops single-user installs
    # from thrashing on the very first persona switch (CR finding — enforce
    # the docstring contract at the field level).
    working_memory_pool_max: int | None = Field(default=None, ge=50)

    @field_validator("deepseek_api_key")
    @classmethod
    def _reject_placeholder_key(cls, v: SecretStr) -> SecretStr:
        """Reject the literal placeholder shipped in .env.example.

        Belt-and-braces complement to the equivalent guard in
        ``bin/alfred-setup.sh`` (DEVEX-001 on PR #89). The setup script catches
        the typical first-run mistake; this validator catches every other path
        — direct ``docker compose run``, CI bootstrap that forgot to override
        the env, an operator who edited ``docker-compose.yaml`` directly. The
        message stays raw English here (no ``t()`` import — Settings is loaded
        too early in the boot to depend on the translator); the CLI catch site
        in ``_load_settings_or_die`` reroutes through
        ``t("error.placeholder_api_key")`` before printing.
        """
        if v.get_secret_value() == _PLACEHOLDER_API_KEY:
            raise ValueError("placeholder_api_key")
        return v

    def __init__(self, **kw):  # type: ignore[no-untyped-def]
        try:
            super().__init__(**kw)
        except Exception as exc:
            # Translate pydantic ValidationError into a SettingsError the CLI can render.
            raise SettingsError(str(exc)) from exc
