"""Alembic environment for AlfredOS migrations (async)."""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alfred.config.settings import Settings
from alfred.memory.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _settings_url() -> str:
    """Resolve the DB URL without forcing full Settings validation.

    Importing ``Settings()`` triggers validation of every required field —
    notably the provider API keys — which fails the migration step in any
    bootstrap that legitimately has DB credentials but not yet the provider
    secrets (CI matrix jobs, scripted DB-only resets, the smoke harness
    provisioning step). Read the DB URL directly from the env first so the
    migration only depends on what it actually needs; fall back to full
    Settings construction when the env doesn't expose it (operator running
    Alembic locally with `.env` already loaded into Settings via pydantic).
    """
    env_url = os.getenv("ALFRED_DATABASE_URL")
    if env_url:
        return env_url
    return Settings().database_url.unicode_string()  # type: ignore[call-arg]


def run_migrations_offline() -> None:
    context.configure(
        url=_settings_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = _settings_url()
    connectable = async_engine_from_config(cfg, prefix="sqlalchemy.", poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
