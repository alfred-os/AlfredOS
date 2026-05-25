"""Env-backed secret broker for Slice 1.

This is the minimum viable secret broker — it reads secrets from environment
variables. Slice 3+ replaces the backend with an age-encrypted file or an
external vault. The interface (`get` and `known`) stays the same; callers don't
care about the backend.

The LLM never reads env vars directly. All secret access goes through this
broker, which substitutes values at the tool-call boundary in later slices.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from alfred.config.settings import Settings

# Slice 1 supports these named secrets. Extend as new providers and integrations land.
SUPPORTED_SECRETS: frozenset[str] = frozenset(
    {
        "deepseek_api_key",
        "anthropic_api_key",
    }
)


class UnknownSecretError(KeyError):
    """Raised when a caller asks for a secret name that is not registered."""


class SecretBroker:
    """Reads secrets from environment variables prefixed with ALFRED_.

    Slice-1 stub backend. Slice-3+ replaces with age-encrypted files / Vault /
    keychain — the public API (`get`, `has`, `known`, `redact`,
    `from_settings`) stays stable so callers don't change.
    """

    def __init__(self, *, env: dict[str, str] | None = None) -> None:
        # Inject env for tests; default to os.environ so callers don't have to.
        self._env: dict[str, str] = dict(env) if env is not None else dict(os.environ)

    @classmethod
    def from_settings(cls, _settings: Settings) -> SecretBroker:
        """Build a broker primed from a Settings instance.

        Slice-1 implementation reads `os.environ` directly because Settings
        is itself populated from env vars; passing through Settings here is
        the seam slice-3+ swaps to read from age-encrypted files / Vault.
        The `_settings` argument is unused in Slice 1 but anchors the interface.
        """
        return cls()

    def get(self, name: str) -> str:
        if name not in SUPPORTED_SECRETS:
            raise UnknownSecretError(name)
        env_name = f"ALFRED_{name.upper()}"
        value = self._env.get(env_name)
        if value is None or value == "":
            raise UnknownSecretError(f"{name} (env {env_name}) is not set")
        return value

    def has(self, name: str) -> bool:
        """Return True iff `name` is a registered secret with a non-empty value.

        Used by the CLI to decide whether to wire up optional providers
        (e.g. Anthropic fallback) without forcing a try/except dance.
        """
        if name not in SUPPORTED_SECRETS:
            return False
        return bool(self._env.get(f"ALFRED_{name.upper()}"))

    def known(self) -> list[str]:
        """Return the names of registered secrets that currently have a value."""
        return [name for name in sorted(SUPPORTED_SECRETS) if self.has(name)]

    def redact(self, text: str) -> str:
        """Replace any known secret value inside `text` with `[REDACTED:<name>]`.

        Called by the structlog redactor processor so secrets never leak into
        log output. The set of known secrets is bounded by SUPPORTED_SECRETS;
        only those that currently have non-empty values are scanned.
        """
        out = text
        for name in self.known():
            value = self._env.get(f"ALFRED_{name.upper()}", "")
            if value:
                out = out.replace(value, f"[REDACTED:{name}]")
        return out
