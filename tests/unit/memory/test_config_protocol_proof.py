"""Structural-satisfaction proof for the memory config Protocol (#351).

The identity-return function is a COMPILE-TIME proof (never called at runtime): mypy
--strict accepts ``Settings -> MemoryDbConfig`` iff ``Settings`` satisfies the Protocol,
so a real ``Settings`` can be passed wherever ``MemoryDbConfig`` is required — and a
future ``Settings.database_url`` rename fails the type-check instead of silently drifting.
"""

from __future__ import annotations

from pydantic import PostgresDsn

from alfred.config.settings import Settings
from alfred.memory._config_protocols import MemoryDbConfig


def _settings_satisfies(settings: Settings) -> MemoryDbConfig:
    # Compile-time proof only; mypy --strict type-checks the return. Needs no
    # Settings() construction (avoids env/secret requirements).
    return settings


def test_plain_stub_satisfies_memory_db_config() -> None:
    """The DIP win: a trivial stub — not a full Settings — satisfies the Protocol."""

    class _StubCfg:
        database_url = PostgresDsn("postgresql+asyncpg://alfred:alfred@localhost:5432/alfred")

    cfg: MemoryDbConfig = _StubCfg()
    assert cfg.database_url.unicode_string().startswith("postgresql+asyncpg://")
