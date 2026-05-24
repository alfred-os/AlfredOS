# Slice 1 — "Hello, Alfred" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Target release:** v0.0.1 (first runnable AlfredOS slice).

**Goal:** `docker compose up && alfred chat` opens a terminal where Alfred holds a multi-turn conversation, remembers context across restarts, and logs every turn with cost. Every architectural subsystem from the PRD gets a thin vertical strand — nothing gets a full implementation, but everything is touched.

**Architecture (slice 1):** Single-process Python `alfred-core` container, plus `alfred-postgres`. DeepSeek as primary provider (cheapest), Anthropic as fallback so the multi-provider pattern is exercised from day 1. Hardcoded `Alfred` persona. Working memory (in-process buffer) + episodic log (Postgres). Trust-tier markers limited to T0/T2 (no untrusted ingestion in this slice). Minimal secret broker (env-backed). Per-day budget guard. Append-only audit table (no signing or internal git yet). `textual`-based TUI.

**Tech Stack:**
- Python 3.12+
- uv (package manager)
- Pydantic v2 + pydantic-settings (data models, config)
- SQLAlchemy 2.0 async + asyncpg (Postgres driver)
- Alembic (migrations)
- OpenAI SDK >=1.40 (used for both DeepSeek and any OpenAI-compat providers)
- anthropic SDK >=0.30 (for Anthropic fallback)
- textual (TUI)
- structlog (logging)
- pytest + pytest-cov + pytest-asyncio (tests)
- testcontainers (integration tests against real Postgres)
- mypy strict, ruff, black

**Subsystem coverage matrix (what's in this slice vs. deferred):**

| Subsystem | This slice | Deferred |
|---|---|---|
| Trust boundary | T0 + T2 markers, `tag()` only | T1, T3, dual-LLM split, capability gate, full DLP, canaries → Slice 2/3 |
| Config + secrets | pydantic-settings + env-backed broker stub | age-encrypted file backend, HashiCorp Vault, OS keychain → Slice 3+ |
| Core runtime | Plain asyncio orchestrator, no event bus | Redis-streams bus, plugin supervisor, hot reload, MCP client → Slice 3+ |
| Memory | Working (in-process) + episodic (Postgres) | Summarized, semantic, vector, graph, consolidation, auto-retrieve → Slice 4+ |
| Persona | Hardcoded Alfred | Registry, manifest, addressing modes, group sessions, inter-persona bus → Slice 5+ |
| Providers | DeepSeek (primary) + Anthropic (fallback) via shared protocol | Tiered routing, capability fallback, internal-CLI providers, 4-layer caching → Slice 2+ |
| Reviewer gate | None | Proposal flow, auto-tests, reviewer agent, internal git → Slice 6+ |
| Comms | TUI only | Discord, Telegram → Slice 2/3 |
| Identity | Single user (the operator); name from config | Multi-user, cross-platform binding, permissions, rate limits → Slice 3 |
| Deployment | docker-compose with `alfred-core` + `alfred-postgres`; basic setup script | Reviewer container, Qdrant, Redis, full self-healing supervisors → as features need them |
| Observability | `structlog` JSON to stdout; cost-per-call inline | Prometheus, OpenTelemetry, Grafana, alerts, `alfred cost report` → Slice 4+ |
| Testing | Unit + one smoke test | E2E harness, adversarial corpus, nightly suite → Slice 3+ |
| Audit + rollback | `audit_log` table; no signing | Signed append-only log, internal git repo, `alfred rollback` → Slice 5+ |

**Slice 1 Definition of Done:**
1. `bin/alfred-setup.sh && docker compose up -d` brings up `alfred-core` + `alfred-postgres` cleanly on macOS/Linux.
2. `alfred chat` opens a TUI where the operator can type and Alfred responds via DeepSeek.
3. Multi-turn context is preserved within a session.
4. Exiting and re-running `alfred chat` shows Alfred has memory of the prior conversation (context loaded from `episodes` table).
5. Per-day budget cap pauses the loop when exhausted.
6. Every turn is in the `episodes` table; every action is in `audit_log`.
7. Smoke test green in CI.
8. mypy strict + ruff + black all clean.
9. `python` job in CI passes on the PR.

---

## File Structure

```
pyproject.toml
.python-version
.env.example
docker-compose.yaml
docker/
  alfred-core.Dockerfile
config/
  alfred.toml                  # default config (committed)
bin/
  alfred-setup.sh
  alfred-setup.ps1             # stub (delegates to WSL for now)
src/
  alfred/
    __init__.py
    py.typed
    config/
      __init__.py
      settings.py              # pydantic-settings
    security/
      __init__.py
      tiers.py                 # T0, T2 markers + tag() (subset of issue #7)
      secrets.py               # env-backed secret broker
    audit/
      __init__.py
      log.py                   # append() helper + table model
    memory/
      __init__.py
      db.py                    # SQLAlchemy engine, session factory
      models.py                # ORM models (episode, audit_log)
      working.py               # in-process buffer
      episodic.py              # writer + reader
      migrations/              # alembic env + versions
        env.py
        versions/
          0001_initial.py
    providers/
      __init__.py
      base.py                  # Provider protocol + Pydantic types
      deepseek.py              # OpenAI SDK + custom base_url
      anthropic_native.py      # anthropic SDK
      router.py                # primary + fallback resolver
    personas/
      __init__.py
      alfred.py                # hardcoded persona bundle
    budget/
      __init__.py
      guard.py                 # per-day cap
    orchestrator/
      __init__.py
      core.py                  # the orchestrator (slim OODA)
    comms/
      __init__.py
      tui.py                   # textual app
    cli/
      __init__.py
      main.py                  # `alfred` CLI entry
tests/
  __init__.py
  unit/
    __init__.py
    security/
      __init__.py
      test_tiers.py
      test_secrets.py
    config/
      __init__.py
      test_settings.py
    providers/
      __init__.py
      test_router.py
    memory/
      __init__.py
      test_working.py
      test_episodic.py
    budget/
      __init__.py
      test_guard.py
    orchestrator/
      __init__.py
      test_core.py
  integration/
    __init__.py
    test_memory_postgres.py    # testcontainers Postgres
  smoke/
    __init__.py
    test_hello_alfred.py       # end-to-end via TUI driver
```

---

## Task 1 — Initialize Python project

**Files:**
- Create: `pyproject.toml`, `.python-version`
- Create: `src/alfred/__init__.py`, `src/alfred/py.typed`
- Create: all empty `__init__.py` files listed in File Structure

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "alfred"
version = "0.0.1"
description = "AlfredOS - multi-user, multi-persona, security-hardened agentic OS."
readme = "README.md"
requires-python = ">=3.12"
license = { text = "AGPL-3.0-or-later" }
authors = [{ name = "AlfredOS contributors" }]
dependencies = [
  "pydantic>=2.7,<3",
  "pydantic-settings>=2.4,<3",
  "sqlalchemy[asyncio]>=2.0,<3",
  "asyncpg>=0.29",
  "alembic>=1.13",
  "openai>=1.40",
  "anthropic>=0.34",
  "textual>=0.80",
  "structlog>=24.1",
  "typer>=0.12",
]

[dependency-groups]
dev = [
  "pytest>=8",
  "pytest-asyncio>=0.23",
  "pytest-cov>=5",
  "testcontainers[postgres]>=4.7",
  "mypy>=1.11",
  "ruff>=0.6",
  "black>=24.0",
  "types-toml",
]

[project.scripts]
alfred = "alfred.cli.main:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/alfred"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra --strict-markers --strict-config"
asyncio_mode = "auto"
markers = [
  "smoke: end-to-end smoke tests (require running stack)",
  "integration: integration tests requiring testcontainers",
]

[tool.coverage.run]
branch = true
source = ["src/alfred"]
omit = ["src/alfred/memory/migrations/*"]

[tool.coverage.report]
show_missing = true
skip_covered = false
fail_under = 75

[tool.mypy]
python_version = "3.12"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_unreachable = true
exclude = ["src/alfred/memory/migrations/.*"]

[tool.ruff]
target-version = "py312"
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "N", "S", "ARG"]
ignore = ["S101"]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101", "ARG"]
"src/alfred/memory/migrations/**/*.py" = ["N999"]

[tool.black]
line-length = 100
target-version = ["py312"]
```

- [ ] **Step 2: Write `.python-version`**

```
3.12
```

- [ ] **Step 3: Create all package and test markers**

Create empty files at every `__init__.py` and `py.typed` path listed in the File Structure section above.

- [ ] **Step 4: Sync the environment**

Run: `uv sync --dev`
Expected: `.venv/` created, `uv.lock` written, all deps installed.

- [ ] **Step 5: Verify tooling**

Run: `uv run pytest --version && uv run mypy --version && uv run ruff --version`
Expected: all three print versions cleanly.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .python-version uv.lock src/alfred tests
git commit -m "build: bootstrap Python project with uv, sqlalchemy, openai/anthropic SDKs, textual"
```

---

## Task 2 — Config and secret broker

**Files:**
- Create: `src/alfred/config/settings.py`
- Create: `src/alfred/security/secrets.py`
- Create: `tests/unit/config/test_settings.py`
- Create: `tests/unit/security/test_secrets.py`
- Create: `.env.example`, `config/alfred.toml`

- [ ] **Step 1: Write the failing settings test**

Create `tests/unit/config/test_settings.py`:

```python
"""Tests for AlfredOS configuration loading."""

from __future__ import annotations

import os
from unittest.mock import patch

from alfred.config.settings import Settings


class TestSettings:
    def test_loads_with_defaults_when_env_missing(self) -> None:
        with patch.dict(os.environ, {"ALFRED_DEEPSEEK_API_KEY": "test-key"}, clear=True):
            s = Settings()
            assert s.deepseek_api_key.get_secret_value() == "test-key"
            assert s.daily_budget_usd == 1.0  # default
            assert s.primary_provider == "deepseek"  # default
            assert s.fallback_provider == "anthropic"  # default

    def test_database_url_defaults_to_localhost_postgres(self) -> None:
        with patch.dict(os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x"}, clear=True):
            s = Settings()
            assert "postgresql" in s.database_url.unicode_string()

    def test_anthropic_api_key_is_optional(self) -> None:
        with patch.dict(os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x"}, clear=True):
            s = Settings()
            assert s.anthropic_api_key is None
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/config/test_settings.py -v`
Expected: FAIL — `alfred.config.settings` not defined.

- [ ] **Step 3: Implement `src/alfred/config/settings.py`**

```python
"""AlfredOS configuration loading via pydantic-settings.

Loads from environment variables prefixed with ALFRED_. A `.env` file in the
working directory is read automatically. Secrets are wrapped in `SecretStr` so
they never leak into logs by accident.
"""

from __future__ import annotations

from pydantic import Field, PostgresDsn, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


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
```

- [ ] **Step 4: Run the settings tests and verify they pass**

Run: `uv run pytest tests/unit/config/test_settings.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Write the failing secret-broker test**

Create `tests/unit/security/test_secrets.py`:

```python
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
```

- [ ] **Step 6: Run and verify failure**

Run: `uv run pytest tests/unit/security/test_secrets.py -v`
Expected: FAIL — `alfred.security.secrets` not defined.

- [ ] **Step 7: Implement `src/alfred/security/secrets.py`**

```python
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
    """Reads secrets from environment variables prefixed with ALFRED_."""

    def get(self, name: str) -> str:
        if name not in SUPPORTED_SECRETS:
            raise UnknownSecretError(name)
        env_name = f"ALFRED_{name.upper()}"
        value = os.environ.get(env_name)
        if value is None:
            raise UnknownSecretError(f"{name} (env {env_name}) is not set")
        return value

    def known(self) -> list[str]:
        """Return the names of registered secrets that currently have a value."""
        return [
            name
            for name in sorted(SUPPORTED_SECRETS)
            if os.environ.get(f"ALFRED_{name.upper()}")
        ]
```

- [ ] **Step 8: Run the secret-broker tests**

Run: `uv run pytest tests/unit/security/test_secrets.py -v`
Expected: 3 PASS.

- [ ] **Step 9: Write `.env.example` and `config/alfred.toml`**

`.env.example`:

```
# Copy to .env and fill in.
ALFRED_DEEPSEEK_API_KEY=sk-...
# Optional fallback. Leave blank to disable fallback in Slice 1.
ALFRED_ANTHROPIC_API_KEY=

# Postgres (defaults match docker-compose.yaml).
ALFRED_DATABASE_URL=postgresql+asyncpg://alfred:alfred@localhost:5432/alfred

# Operator identity.
ALFRED_OPERATOR_NAME=operator

# Budgets.
ALFRED_DAILY_BUDGET_USD=1.0
ALFRED_PER_CALL_MAX_USD=0.10
```

`config/alfred.toml`:

```toml
# AlfredOS default configuration. Override via environment variables prefixed
# with ALFRED_ (see .env.example).
[provider]
primary = "deepseek"
fallback = "anthropic"

[provider.deepseek]
model = "deepseek-chat"
base_url = "https://api.deepseek.com/v1"

[provider.anthropic]
model = "claude-sonnet-4-6"

[budget]
daily_usd = 1.0
per_call_max_usd = 0.10
```

- [ ] **Step 10: Commit**

```bash
git add src/alfred/config src/alfred/security tests/unit/config tests/unit/security .env.example config
git commit -m "feat(config): add pydantic-settings + env-backed secret broker"
```

---

## Task 3 — Database: SQLAlchemy 2.0 async, models, alembic

**Files:**
- Create: `src/alfred/memory/db.py`, `src/alfred/memory/models.py`
- Create: `src/alfred/memory/migrations/env.py`, `src/alfred/memory/migrations/versions/0001_initial.py`
- Create: `alembic.ini`
- Create: `tests/integration/test_memory_postgres.py`

- [ ] **Step 1: Write the SQLAlchemy models**

Create `src/alfred/memory/models.py`:

```python
"""SQLAlchemy 2.0 ORM models for Slice 1.

Two tables for the first slice: episodes (raw conversation turns) and audit_log
(every action Alfred takes). More tables land per future slices.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all AlfredOS ORM models."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class Episode(Base):
    """A single conversation turn (user input or Alfred response)."""

    __tablename__ = "episodes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    persona: Mapped[str] = mapped_column(String(64), default="alfred")
    role: Mapped[str] = mapped_column(String(16))  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text)
    trust_tier: Mapped[str] = mapped_column(String(4))  # T0..T3
    tokens_in: Mapped[int] = mapped_column(default=0)
    tokens_out: Mapped[int] = mapped_column(default=0)
    cost_usd: Mapped[float] = mapped_column(default=0.0)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class AuditEntry(Base):
    """An append-only record of an action AlfredOS took."""

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    event: Mapped[str] = mapped_column(String(64))  # e.g. "provider.call", "memory.write"
    actor_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_persona: Mapped[str] = mapped_column(String(64), default="alfred")
    subject: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    trust_tier_of_trigger: Mapped[str] = mapped_column(String(4))
    result: Mapped[str] = mapped_column(String(32))  # success | failure | refused | quarantined
    cost_estimate_usd: Mapped[float] = mapped_column(default=0.0)
```

- [ ] **Step 2: Write the async engine and session factory**

Create `src/alfred/memory/db.py`:

```python
"""SQLAlchemy 2.0 async engine + session factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.config.settings import Settings


def make_engine(settings: Settings):  # type: ignore[no-untyped-def]
    return create_async_engine(settings.database_url.unicode_string(), echo=False, future=True)


def make_session_factory(settings: Settings) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=make_engine(settings),
        expire_on_commit=False,
        class_=AsyncSession,
    )


@asynccontextmanager
async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Transactional async session scope. Commits on success; rolls back on failure."""
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
```

- [ ] **Step 3: Initialize alembic**

Create `alembic.ini`:

```ini
[alembic]
script_location = src/alfred/memory/migrations
sqlalchemy.url = postgresql+asyncpg://alfred:alfred@localhost:5432/alfred
file_template = %%(year)d_%%(month).2d_%%(day).2d_%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

Create `src/alfred/memory/migrations/env.py`:

```python
"""Alembic environment for AlfredOS migrations (async)."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from sqlalchemy import pool

from alfred.config.settings import Settings
from alfred.memory.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _settings_url() -> str:
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
```

- [ ] **Step 4: Generate the initial migration**

Run: `uv run alembic revision --autogenerate -m "initial schema"`
Expected: a file appears at `src/alfred/memory/migrations/versions/<date>-<rev>_initial_schema.py` that creates the `episodes` and `audit_log` tables. Inspect it.

Rename the generated file to `0001_initial.py` for stable referencing in tests. (The `file_template` in `alembic.ini` includes timestamps; rename to remove the timestamp prefix for slice 1 simplicity. Future migrations can keep the autogenerated naming.)

- [ ] **Step 5: Write the integration test**

Create `tests/integration/test_memory_postgres.py`:

```python
"""Integration test: schema migrates cleanly against real Postgres."""

from __future__ import annotations

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine
from testcontainers.postgres import PostgresContainer

from alfred.memory.models import Base


@pytest.mark.integration
async def test_schema_creates_episodes_and_audit_log() -> None:
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("postgresql://", "postgresql+asyncpg://")
        engine = create_async_engine(url, future=True)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            tables = await conn.run_sync(lambda c: inspect(c).get_table_names())
        await engine.dispose()
        assert "episodes" in tables
        assert "audit_log" in tables
```

- [ ] **Step 6: Run the integration test**

Run: `uv run pytest tests/integration/test_memory_postgres.py -v`
Expected: PASS. (testcontainers spins up Postgres 16 in Docker; takes 5-15 seconds.)

- [ ] **Step 7: Commit**

```bash
git add src/alfred/memory tests/integration alembic.ini
git commit -m "feat(memory): add episodes + audit_log tables with sqlalchemy 2.0 async"
```

---

## Task 4 — Trust-tier minimal: T0, T2, and `tag()`

**Files:**
- Create: `src/alfred/security/tiers.py`
- Create: `tests/unit/security/test_tiers.py`

Note: only T0 (system) and T2 (authenticated user) are needed in Slice 1 — there is no untrusted ingestion yet, so T1 and T3 are deferred to Slice 2/3. The full implementation of issue #7 is split across slices; this task delivers the part Slice 1 needs.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/security/test_tiers.py`:

```python
"""Trust-tier tests for Slice 1: T0 and T2 only."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.security.tiers import T0, T2, TaggedContent, TrustTier, tag


class TestTierMarkers:
    def test_t0_and_t2_are_distinct_trust_tier_subclasses(self) -> None:
        assert issubclass(T0, TrustTier)
        assert issubclass(T2, TrustTier)
        assert not issubclass(T0, T2)
        assert not issubclass(T2, T0)


class TestTaggedContent:
    def test_holds_content_source_metadata(self) -> None:
        c = TaggedContent[T2](content="hi", source="tui.input", metadata={"line": 1})
        assert c.content == "hi"
        assert c.source == "tui.input"
        assert c.metadata == {"line": 1}

    def test_is_frozen(self) -> None:
        c = TaggedContent[T2](content="hi", source="tui.input")
        with pytest.raises(ValidationError):
            c.content = "tampered"  # type: ignore[misc]

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TaggedContent[T2](content="x", source="s", evil="leak")  # type: ignore[call-arg]


class TestTagHelper:
    def test_tags_t0_system_content(self) -> None:
        c = tag(T0, content="persona prompt", source="persona.alfred")
        assert isinstance(c, TaggedContent)
        assert c.content == "persona prompt"

    def test_tags_t2_user_content_with_metadata(self) -> None:
        c = tag(T2, content="hi alfred", source="tui.input", line=3)
        assert c.metadata["line"] == 3
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/security/test_tiers.py -v`
Expected: FAIL — `alfred.security.tiers` not defined.

- [ ] **Step 3: Implement `src/alfred/security/tiers.py`**

```python
"""Trust-tier types for AlfredOS. Slice 1 ships T0 and T2 only.

See PRD §7.1. T1 (operator) and T3 (untrusted) markers land alongside the
dual-LLM split in Slice 2/3 when AlfredOS first ingests untrusted content.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar, overload

from pydantic import BaseModel, ConfigDict


class TrustTier:
    """Marker base for trust tiers. Used only as a type parameter."""


class T0(TrustTier):
    """System tier: AlfredOS internals (highest trust)."""


class T2(TrustTier):
    """Authenticated tier: known users."""


TierT = TypeVar("TierT", bound=TrustTier)


class TaggedContent(BaseModel, Generic[TierT]):
    """Content tagged with a trust tier.

    The tier is a type parameter, not a field. Slice 1 uses this in the
    orchestrator to keep system prompts (T0) and user input (T2) distinguishable.
    Slice 2 adds T1/T3 plus the dual-LLM split.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    content: str
    source: str
    metadata: dict[str, Any] = {}


@overload
def tag(
    tier: type[T0], *, content: str, source: str, **metadata: Any
) -> TaggedContent[T0]: ...
@overload
def tag(
    tier: type[T2], *, content: str, source: str, **metadata: Any
) -> TaggedContent[T2]: ...
def tag(
    tier: type[TrustTier], *, content: str, source: str, **metadata: Any
) -> TaggedContent[Any]:
    """Tag content with a trust tier at an ingestion boundary."""
    return TaggedContent[tier](content=content, source=source, metadata=dict(metadata))
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/security/test_tiers.py -v`
Expected: 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/security/tiers.py tests/unit/security/test_tiers.py
git commit -m "feat(security): add T0/T2 trust-tier markers and tag() for slice 1"
```

---

## Task 5 — Audit log writer

**Files:**
- Create: `src/alfred/audit/log.py`
- Modify: `tests/unit/security/` — add `test_audit.py` (use unit-level mock; integration tested through smoke later)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/audit/__init__.py` (empty) and `tests/unit/audit/test_log.py`:

```python
"""Tests for the slice 1 audit log writer."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from alfred.audit.log import AuditWriter


@pytest.mark.asyncio
class TestAuditWriter:
    async def test_append_persists_required_fields(self) -> None:
        session = AsyncMock()
        writer = AuditWriter(session=session)
        await writer.append(
            event="provider.call",
            actor_user_id="operator",
            subject={"provider": "deepseek", "model": "deepseek-chat"},
            trust_tier_of_trigger="T2",
            result="success",
            cost_estimate_usd=0.0001,
            trace_id="abc-123",
        )
        assert session.add.call_count == 1
        added = session.add.call_args[0][0]
        assert added.event == "provider.call"
        assert added.subject["provider"] == "deepseek"
        assert added.result == "success"
        assert added.trust_tier_of_trigger == "T2"
        session.flush.assert_awaited_once()

    async def test_append_raises_on_persistence_failure(self) -> None:
        session = AsyncMock()
        session.flush.side_effect = RuntimeError("db down")
        writer = AuditWriter(session=session)
        with pytest.raises(RuntimeError, match="db down"):
            await writer.append(
                event="provider.call",
                actor_user_id="operator",
                subject={},
                trust_tier_of_trigger="T2",
                result="success",
                cost_estimate_usd=0.0,
                trace_id="abc",
            )
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/audit/test_log.py -v`
Expected: FAIL — `alfred.audit.log` not defined.

- [ ] **Step 3: Implement `src/alfred/audit/log.py`**

```python
"""Slice 1 audit log writer.

Writes append-only entries to the `audit_log` table. Failed writes raise
loudly — the caller decides whether to quarantine. Future slices add signing
and integration with the internal git repo.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from alfred.memory.models import AuditEntry


class AuditWriter:
    """Append-only writer for the audit log."""

    def __init__(self, *, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self,
        *,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, Any],
        trust_tier_of_trigger: str,
        result: str,
        cost_estimate_usd: float,
        trace_id: str,
        actor_persona: str = "alfred",
    ) -> None:
        """Record a single audit entry. Raises if persistence fails."""
        entry = AuditEntry(
            trace_id=trace_id,
            event=event,
            actor_user_id=actor_user_id,
            actor_persona=actor_persona,
            subject=subject,
            trust_tier_of_trigger=trust_tier_of_trigger,
            result=result,
            cost_estimate_usd=cost_estimate_usd,
        )
        self._session.add(entry)
        await self._session.flush()
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/audit/test_log.py -v`
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/audit tests/unit/audit
git commit -m "feat(audit): add slice-1 append-only audit writer"
```

---

## Task 6 — Provider base + DeepSeek adapter

**Files:**
- Create: `src/alfred/providers/base.py`
- Create: `src/alfred/providers/deepseek.py`
- Create: `tests/unit/providers/test_deepseek.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/providers/test_deepseek.py`:

```python
"""Tests for the DeepSeek provider adapter (uses OpenAI SDK + custom base_url)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.providers.base import CompletionRequest, Message
from alfred.providers.deepseek import DeepSeekProvider


@pytest.mark.asyncio
async def test_complete_returns_assistant_text_and_token_usage() -> None:
    fake_client = MagicMock()
    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content="Hello, operator."))]
    fake_response.usage = MagicMock(prompt_tokens=10, completion_tokens=4)
    fake_client.chat.completions.create = AsyncMock(return_value=fake_response)

    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    req = CompletionRequest(
        messages=[
            Message(role="system", content="You are Alfred."),
            Message(role="user", content="hi"),
        ],
        max_tokens=512,
    )
    res = await provider.complete(req)

    assert res.content == "Hello, operator."
    assert res.tokens_in == 10
    assert res.tokens_out == 4
    assert res.cost_usd > 0
    fake_client.chat.completions.create.assert_awaited_once()


@pytest.mark.asyncio
async def test_complete_propagates_client_errors() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(side_effect=RuntimeError("rate limited"))
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    req = CompletionRequest(messages=[Message(role="user", content="hi")], max_tokens=10)
    with pytest.raises(RuntimeError, match="rate limited"):
        await provider.complete(req)
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/providers/test_deepseek.py -v`
Expected: FAIL — providers package not defined.

- [ ] **Step 3: Implement `src/alfred/providers/base.py`**

```python
"""Provider plugin contract for Slice 1.

A provider is anything that can take a sequence of messages and produce a
completion plus token usage and cost. Slice 1 has DeepSeek and Anthropic;
Slice 2 adds tiered routing across more providers.
"""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel

Role = Literal["system", "user", "assistant"]


class Message(BaseModel):
    role: Role
    content: str


class CompletionRequest(BaseModel):
    messages: list[Message]
    max_tokens: int = 1024
    temperature: float = 0.7


class CompletionResponse(BaseModel):
    content: str
    tokens_in: int
    tokens_out: int
    cost_usd: float


class Provider(Protocol):
    """The minimal slice-1 provider interface."""

    name: str

    async def complete(self, request: CompletionRequest) -> CompletionResponse: ...
```

- [ ] **Step 4: Implement `src/alfred/providers/deepseek.py`**

```python
"""DeepSeek provider adapter. Uses the OpenAI SDK with a custom base_url.

Pricing (as of 2026-05; check https://api.deepseek.com/pricing before updating):
  deepseek-chat: $0.07 / 1M input tokens, $0.27 / 1M output tokens
"""

from __future__ import annotations

from typing import Any

from openai import AsyncOpenAI

from alfred.providers.base import CompletionRequest, CompletionResponse

# Per-million-token prices in USD. Used to estimate cost_usd locally.
_DEEPSEEK_PRICING: dict[str, tuple[float, float]] = {
    "deepseek-chat": (0.07, 0.27),
    "deepseek-reasoner": (0.14, 2.19),
}


def _estimate_cost(model: str, tokens_in: int, tokens_out: int) -> float:
    in_per_m, out_per_m = _DEEPSEEK_PRICING.get(model, (0.07, 0.27))
    return (tokens_in / 1_000_000) * in_per_m + (tokens_out / 1_000_000) * out_per_m


class DeepSeekProvider:
    """OpenAI-compatible DeepSeek client wrapper."""

    name = "deepseek"

    def __init__(self, *, client: Any, model: str) -> None:
        self._client = client
        self._model = model

    @classmethod
    def from_settings(cls, api_key: str, base_url: str, model: str) -> DeepSeekProvider:
        return cls(client=AsyncOpenAI(api_key=api_key, base_url=base_url), model=model)

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[m.model_dump() for m in request.messages],
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )
        msg = response.choices[0].message
        usage = response.usage
        return CompletionResponse(
            content=msg.content or "",
            tokens_in=usage.prompt_tokens,
            tokens_out=usage.completion_tokens,
            cost_usd=_estimate_cost(self._model, usage.prompt_tokens, usage.completion_tokens),
        )
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/providers/test_deepseek.py -v`
Expected: 2 PASS.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/providers tests/unit/providers
git commit -m "feat(providers): add provider protocol and DeepSeek adapter"
```

---

## Task 7 — Anthropic adapter (fallback)

**Files:**
- Create: `src/alfred/providers/anthropic_native.py`
- Create: `tests/unit/providers/test_anthropic.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/providers/test_anthropic.py`:

```python
"""Tests for the Anthropic provider adapter (fallback)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.base import CompletionRequest, Message


@pytest.mark.asyncio
async def test_complete_returns_assistant_text_and_usage() -> None:
    fake_client = MagicMock()
    fake_response = MagicMock()
    fake_response.content = [MagicMock(text="Hi, this is Alfred.")]
    fake_response.usage = MagicMock(input_tokens=12, output_tokens=6)
    fake_client.messages.create = AsyncMock(return_value=fake_response)

    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    req = CompletionRequest(
        messages=[
            Message(role="system", content="You are Alfred."),
            Message(role="user", content="hi"),
        ],
        max_tokens=256,
    )
    res = await provider.complete(req)

    assert res.content == "Hi, this is Alfred."
    assert res.tokens_in == 12
    assert res.tokens_out == 6
    assert res.cost_usd > 0
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/providers/test_anthropic.py -v`
Expected: FAIL — `alfred.providers.anthropic_native` not defined.

- [ ] **Step 3: Implement `src/alfred/providers/anthropic_native.py`**

```python
"""Anthropic provider adapter using the native SDK. Fallback in Slice 1.

Pricing (check the Anthropic pricing page before updating):
  claude-sonnet-4-6: $3 / 1M input, $15 / 1M output
"""

from __future__ import annotations

from typing import Any

from anthropic import AsyncAnthropic

from alfred.providers.base import CompletionRequest, CompletionResponse

_ANTHROPIC_PRICING: dict[str, tuple[float, float]] = {
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-opus-4-7": (15.0, 75.0),
}


def _estimate_cost(model: str, tokens_in: int, tokens_out: int) -> float:
    in_per_m, out_per_m = _ANTHROPIC_PRICING.get(model, (3.0, 15.0))
    return (tokens_in / 1_000_000) * in_per_m + (tokens_out / 1_000_000) * out_per_m


class AnthropicProvider:
    """Native Anthropic client wrapper."""

    name = "anthropic"

    def __init__(self, *, client: Any, model: str) -> None:
        self._client = client
        self._model = model

    @classmethod
    def from_settings(cls, api_key: str, model: str) -> AnthropicProvider:
        return cls(client=AsyncAnthropic(api_key=api_key), model=model)

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        # Anthropic requires the system prompt to be separate from messages.
        system = next((m.content for m in request.messages if m.role == "system"), None)
        chat = [m.model_dump() for m in request.messages if m.role != "system"]
        response = await self._client.messages.create(
            model=self._model,
            system=system,
            messages=chat,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )
        # Anthropic's content is a list of blocks; the first text block is the response.
        text = "".join(getattr(block, "text", "") for block in response.content)
        usage = response.usage
        return CompletionResponse(
            content=text,
            tokens_in=usage.input_tokens,
            tokens_out=usage.output_tokens,
            cost_usd=_estimate_cost(self._model, usage.input_tokens, usage.output_tokens),
        )
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/providers/test_anthropic.py -v`
Expected: 1 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/providers/anthropic_native.py tests/unit/providers/test_anthropic.py
git commit -m "feat(providers): add Anthropic fallback adapter"
```

---

## Task 8 — Provider router (primary + fallback)

**Files:**
- Create: `src/alfred/providers/router.py`
- Create: `tests/unit/providers/test_router.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/providers/test_router.py`:

```python
"""Tests for the provider router."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.providers.base import CompletionRequest, CompletionResponse, Message
from alfred.providers.router import ProviderRouter


@pytest.mark.asyncio
async def test_uses_primary_when_it_succeeds() -> None:
    primary = MagicMock(name="primary")
    primary.name = "deepseek"
    primary.complete = AsyncMock(
        return_value=CompletionResponse(
            content="primary said hi", tokens_in=5, tokens_out=3, cost_usd=0.00001
        )
    )
    fallback = MagicMock(name="fallback")
    fallback.complete = AsyncMock(return_value=None)

    router = ProviderRouter(primary=primary, fallback=fallback)
    res = await router.complete(
        CompletionRequest(messages=[Message(role="user", content="hi")])
    )

    assert res.content == "primary said hi"
    primary.complete.assert_awaited_once()
    fallback.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_falls_back_when_primary_raises() -> None:
    primary = MagicMock(name="primary")
    primary.name = "deepseek"
    primary.complete = AsyncMock(side_effect=RuntimeError("upstream 503"))
    fallback = MagicMock(name="fallback")
    fallback.name = "anthropic"
    fallback.complete = AsyncMock(
        return_value=CompletionResponse(
            content="fallback responded", tokens_in=4, tokens_out=3, cost_usd=0.001
        )
    )

    router = ProviderRouter(primary=primary, fallback=fallback)
    res = await router.complete(
        CompletionRequest(messages=[Message(role="user", content="hi")])
    )

    assert res.content == "fallback responded"
    primary.complete.assert_awaited_once()
    fallback.complete.assert_awaited_once()


@pytest.mark.asyncio
async def test_no_fallback_means_primary_errors_propagate() -> None:
    primary = MagicMock(name="primary")
    primary.complete = AsyncMock(side_effect=RuntimeError("upstream"))
    router = ProviderRouter(primary=primary, fallback=None)
    with pytest.raises(RuntimeError, match="upstream"):
        await router.complete(
            CompletionRequest(messages=[Message(role="user", content="hi")])
        )
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/providers/test_router.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `src/alfred/providers/router.py`**

```python
"""Slice-1 provider router. Primary + optional fallback. No tiered routing yet."""

from __future__ import annotations

import structlog

from alfred.providers.base import CompletionRequest, CompletionResponse, Provider

_log = structlog.get_logger()


class ProviderRouter:
    """Try the primary; on exception, try the fallback (if any)."""

    def __init__(self, *, primary: Provider, fallback: Provider | None = None) -> None:
        self._primary = primary
        self._fallback = fallback

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        try:
            return await self._primary.complete(request)
        except Exception as exc:  # noqa: BLE001 - we want broad fallback in slice 1
            if self._fallback is None:
                raise
            _log.warning(
                "provider.primary.failed",
                primary=self._primary.name,
                fallback=self._fallback.name,
                error=str(exc),
            )
            return await self._fallback.complete(request)
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/providers/test_router.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/providers/router.py tests/unit/providers/test_router.py
git commit -m "feat(providers): add primary+fallback router"
```

---

## Task 9 — Working memory (in-process turn buffer)

**Files:**
- Create: `src/alfred/memory/working.py`
- Create: `tests/unit/memory/test_working.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/memory/test_working.py`:

```python
"""Tests for the working-memory turn buffer."""

from __future__ import annotations

from alfred.memory.working import WorkingMemory


class TestWorkingMemory:
    def test_appends_and_returns_turns_in_order(self) -> None:
        mem = WorkingMemory(max_turns=10)
        mem.append(role="user", content="hi")
        mem.append(role="assistant", content="hello")
        turns = mem.turns()
        assert [t.role for t in turns] == ["user", "assistant"]
        assert turns[1].content == "hello"

    def test_evicts_oldest_when_over_capacity(self) -> None:
        mem = WorkingMemory(max_turns=2)
        mem.append(role="user", content="one")
        mem.append(role="assistant", content="two")
        mem.append(role="user", content="three")
        assert [t.content for t in mem.turns()] == ["two", "three"]

    def test_clear_empties_the_buffer(self) -> None:
        mem = WorkingMemory(max_turns=4)
        mem.append(role="user", content="hi")
        mem.clear()
        assert mem.turns() == []
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/memory/test_working.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `src/alfred/memory/working.py`**

```python
"""In-process working memory for Slice 1.

A bounded FIFO buffer of the most recent N turns. Used by the orchestrator
to assemble the prompt for the next provider call. Slice 4+ adds richer
memory layers; Slice 1 keeps this dirt simple.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from alfred.providers.base import Role


@dataclass(slots=True, frozen=True)
class Turn:
    role: Role
    content: str


class WorkingMemory:
    """A bounded buffer of recent conversation turns for one (persona, user) pair."""

    def __init__(self, *, max_turns: int = 40) -> None:
        self._buf: deque[Turn] = deque(maxlen=max_turns)

    def append(self, *, role: Role, content: str) -> None:
        self._buf.append(Turn(role=role, content=content))

    def turns(self) -> list[Turn]:
        return list(self._buf)

    def clear(self) -> None:
        self._buf.clear()
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/memory/test_working.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/working.py tests/unit/memory/test_working.py
git commit -m "feat(memory): add bounded working-memory turn buffer"
```

---

## Task 10 — Episodic memory writer and continuity loader

**Files:**
- Create: `src/alfred/memory/episodic.py`
- Create: `tests/unit/memory/test_episodic.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/memory/test_episodic.py`:

```python
"""Tests for the episodic memory writer/loader."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.memory.episodic import EpisodicMemory
from alfred.memory.models import Episode


@pytest.mark.asyncio
async def test_record_writes_user_and_assistant_turns_in_order() -> None:
    session = AsyncMock()
    mem = EpisodicMemory(session=session)
    await mem.record(
        user_id="operator",
        role="user",
        content="hi",
        trust_tier="T2",
        tokens_in=0,
        tokens_out=0,
        cost_usd=0.0,
    )
    await mem.record(
        user_id="operator",
        role="assistant",
        content="hi back",
        trust_tier="T0",
        tokens_in=10,
        tokens_out=3,
        cost_usd=0.00001,
    )
    assert session.add.call_count == 2
    assert session.flush.await_count == 2


@pytest.mark.asyncio
async def test_recent_returns_last_n_turns_oldest_first() -> None:
    session = AsyncMock()
    e1 = Episode(user_id="operator", role="user", content="a", trust_tier="T2")
    e2 = Episode(user_id="operator", role="assistant", content="b", trust_tier="T0")

    result = MagicMock()
    result.scalars.return_value.all.return_value = [e2, e1]  # DB returned newest first
    session.execute = AsyncMock(return_value=result)

    mem = EpisodicMemory(session=session)
    turns = await mem.recent(user_id="operator", limit=2)
    # Caller-facing list is in chronological order (oldest first).
    assert [t.content for t in turns] == ["a", "b"]
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/memory/test_episodic.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `src/alfred/memory/episodic.py`**

```python
"""Slice-1 episodic memory: writer + recent-turns loader.

Writes every conversation turn to the `episodes` table. On startup, loads the
most recent N turns so Alfred has cross-restart continuity. Slice 4 replaces
this with the full summarization + semantic-fact consolidation pass.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.memory.models import Episode
from alfred.providers.base import Role


class EpisodicMemory:
    """Append turns to the episodes table; read the most recent for context."""

    def __init__(self, *, session: AsyncSession) -> None:
        self._session = session

    async def record(
        self,
        *,
        user_id: str,
        role: Role,
        content: str,
        trust_tier: str,
        tokens_in: int = 0,
        tokens_out: int = 0,
        cost_usd: float = 0.0,
        persona: str = "alfred",
    ) -> None:
        episode = Episode(
            user_id=user_id,
            persona=persona,
            role=role,
            content=content,
            trust_tier=trust_tier,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost_usd,
        )
        self._session.add(episode)
        await self._session.flush()

    async def recent(self, *, user_id: str, limit: int = 20) -> list[Episode]:
        """Most recent N turns for a user, in chronological order (oldest first)."""
        stmt = (
            select(Episode)
            .where(Episode.user_id == user_id)
            .order_by(Episode.created_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        rows.reverse()
        return rows
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/memory/test_episodic.py -v`
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/episodic.py tests/unit/memory/test_episodic.py
git commit -m "feat(memory): add episodic writer and recent-turns loader"
```

---

## Task 11 — Hardcoded Alfred persona

**Files:**
- Create: `src/alfred/personas/alfred.py`
- Create: `tests/unit/personas/__init__.py`, `tests/unit/personas/test_alfred.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/personas/test_alfred.py`:

```python
"""Tests for the hardcoded Alfred persona used in Slice 1."""

from __future__ import annotations

from alfred.personas.alfred import ALFRED_PERSONA, alfred_system_prompt


def test_persona_has_name_and_character() -> None:
    assert ALFRED_PERSONA.name == "alfred"
    assert "butler" in ALFRED_PERSONA.character.lower()


def test_system_prompt_mentions_operator_name() -> None:
    prompt = alfred_system_prompt(operator_name="Ian")
    assert "Ian" in prompt
    assert "Alfred" in prompt


def test_system_prompt_is_a_t0_tagged_content() -> None:
    from alfred.security.tiers import T0, TaggedContent

    prompt = alfred_system_prompt(operator_name="Ian")
    # The factory returns plain text; the orchestrator wraps it in TaggedContent[T0]
    # at the boundary. We assert the prompt-building helper is callable with a
    # string output that the orchestrator can tag.
    tagged: TaggedContent[T0] = TaggedContent[T0](content=prompt, source="persona.alfred")
    assert isinstance(tagged, TaggedContent)
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/personas/test_alfred.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `src/alfred/personas/alfred.py`**

```python
"""The default Alfred persona, hardcoded for Slice 1.

Slice 5 replaces this with the persona registry (manifest in
/var/lib/alfred/state.git/personas/alfred/). For now, Alfred is a Python
constant + a system-prompt factory.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Persona:
    name: str
    character: str  # one-paragraph description for prompt assembly


ALFRED_PERSONA = Persona(
    name="alfred",
    character=(
        "Alfred is the head butler of the household — discreet, loyal, anticipatory, "
        "multi-skilled, and unfailingly polite. He keeps confidences, prefers brevity "
        "to flourish, and prefers a useful next step to a long explanation. He addresses "
        "the operator by name."
    ),
)


def alfred_system_prompt(*, operator_name: str) -> str:
    """Build Alfred's system prompt for a given operator."""
    return (
        f"You are {ALFRED_PERSONA.name.title()}, head butler in {operator_name}'s "
        f"household. {ALFRED_PERSONA.character} "
        "Address the operator as " + operator_name + ". "
        "Keep responses tight unless asked to elaborate. "
        "If you do not know something, say so plainly; do not invent."
    )
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/personas/test_alfred.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/personas tests/unit/personas
git commit -m "feat(personas): add hardcoded Alfred persona and system-prompt factory"
```

---

## Task 12 — Budget guard

**Files:**
- Create: `src/alfred/budget/guard.py`
- Create: `tests/unit/budget/test_guard.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/budget/test_guard.py`:

```python
"""Tests for the daily / per-call budget guard."""

from __future__ import annotations

import datetime as dt

import pytest

from alfred.budget.guard import BudgetExhaustedError, BudgetGuard, PerCallCapExceededError


class TestBudgetGuard:
    def test_allows_calls_within_daily_budget(self) -> None:
        guard = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)
        guard.check_and_charge(0.05)  # ok
        guard.check_and_charge(0.05)  # still ok
        assert guard.spent_today() == 0.10

    def test_rejects_single_call_over_per_call_cap(self) -> None:
        guard = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)
        with pytest.raises(PerCallCapExceededError):
            guard.check_and_charge(0.20)

    def test_blocks_when_daily_budget_exhausted(self) -> None:
        guard = BudgetGuard(daily_usd=0.10, per_call_max_usd=0.10)
        guard.check_and_charge(0.10)
        with pytest.raises(BudgetExhaustedError):
            guard.check_and_charge(0.01)

    def test_budget_resets_on_new_day(self) -> None:
        guard = BudgetGuard(daily_usd=0.10, per_call_max_usd=0.10)
        guard.check_and_charge(0.10)
        # Simulate the day rolling over by tickling internal state.
        guard._day = dt.date.today() - dt.timedelta(days=1)
        guard._spent = 0.10
        # The next check sees a new day and resets.
        guard.check_and_charge(0.05)
        assert guard.spent_today() == 0.05
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/budget/test_guard.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `src/alfred/budget/guard.py`**

```python
"""Slice-1 budget guard.

Enforces a per-call cost cap and a per-day spend cap. The orchestrator calls
`check_and_charge(estimated_cost)` BEFORE making the provider call (using an
estimate based on prompt tokens) and `check_and_charge(actual_cost)` AFTER
(reconciling). For Slice 1 we use a single charge after the call for
simplicity; per-call upfront estimation lands in Slice 2 with the prompt cache.
"""

from __future__ import annotations

import datetime as dt


class BudgetError(RuntimeError):
    """Base for budget-related errors."""


class PerCallCapExceededError(BudgetError):
    """A single call would exceed the per-call cost cap."""


class BudgetExhaustedError(BudgetError):
    """The daily budget is exhausted."""


class BudgetGuard:
    def __init__(self, *, daily_usd: float, per_call_max_usd: float) -> None:
        self._daily_usd = daily_usd
        self._per_call_max_usd = per_call_max_usd
        self._day = dt.date.today()
        self._spent = 0.0

    def _roll_day_if_needed(self) -> None:
        today = dt.date.today()
        if today != self._day:
            self._day = today
            self._spent = 0.0

    def check_and_charge(self, cost_usd: float) -> None:
        if cost_usd > self._per_call_max_usd:
            raise PerCallCapExceededError(
                f"call cost ${cost_usd:.4f} exceeds per-call cap ${self._per_call_max_usd:.2f}"
            )
        self._roll_day_if_needed()
        if self._spent + cost_usd > self._daily_usd:
            raise BudgetExhaustedError(
                f"daily budget ${self._daily_usd:.2f} exhausted (spent ${self._spent:.4f})"
            )
        self._spent += cost_usd

    def spent_today(self) -> float:
        self._roll_day_if_needed()
        return self._spent
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/budget/test_guard.py -v`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/budget tests/unit/budget
git commit -m "feat(budget): add per-call and daily budget guard"
```

---

## Task 13 — Orchestrator (slim OODA loop)

**Files:**
- Create: `src/alfred/orchestrator/core.py`
- Create: `tests/unit/orchestrator/test_core.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/orchestrator/test_core.py`:

```python
"""Tests for the slice-1 orchestrator."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse


@pytest.mark.asyncio
async def test_handle_user_message_appends_to_working_memory_and_returns_response() -> None:
    working = MagicMock()
    working.turns.return_value = []
    episodic = MagicMock()
    episodic.record = AsyncMock()
    audit = MagicMock()
    audit.append = AsyncMock()
    router = MagicMock()
    router.complete = AsyncMock(
        return_value=CompletionResponse(
            content="Hello, operator.",
            tokens_in=12,
            tokens_out=4,
            cost_usd=0.00001,
        )
    )
    budget = MagicMock()

    orch = Orchestrator(
        operator_name="operator",
        working=working,
        episodic=episodic,
        audit=audit,
        router=router,
        budget=budget,
    )

    text = await orch.handle_user_message("hi")
    assert text == "Hello, operator."

    # User turn + assistant turn appended to working memory.
    assert working.append.call_count == 2
    # Both turns persisted to episodic.
    assert episodic.record.await_count == 2
    # Audit log records the provider call.
    audit.append.assert_awaited_once()
    # Budget guard charged the call.
    budget.check_and_charge.assert_called_once_with(0.00001)


@pytest.mark.asyncio
async def test_budget_exhausted_raises_and_no_assistant_turn_recorded() -> None:
    from alfred.budget.guard import BudgetExhaustedError

    working = MagicMock()
    working.turns.return_value = []
    episodic = MagicMock()
    episodic.record = AsyncMock()
    audit = MagicMock()
    audit.append = AsyncMock()
    router = MagicMock()
    router.complete = AsyncMock(
        return_value=CompletionResponse(
            content="...", tokens_in=10, tokens_out=2, cost_usd=10.0
        )
    )
    budget = MagicMock()
    budget.check_and_charge.side_effect = BudgetExhaustedError("over budget")

    orch = Orchestrator(
        operator_name="operator",
        working=working,
        episodic=episodic,
        audit=audit,
        router=router,
        budget=budget,
    )

    with pytest.raises(BudgetExhaustedError):
        await orch.handle_user_message("hi")

    # User turn still recorded (we want the audit even on failure), but no assistant turn.
    assert episodic.record.await_count == 1
    audit.append.assert_awaited_once()
    args = audit.append.await_args.kwargs
    assert args["result"] == "quarantined"
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/orchestrator/test_core.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `src/alfred/orchestrator/core.py`**

```python
"""Slice-1 orchestrator.

The thinnest possible OODA loop:
  1. Observe: get the user message from the comms layer.
  2. Orient: assemble the prompt — system (T0) + recent turns + new user turn (T2).
  3. Decide: call the provider router.
  4. Act: append to working + episodic memory, write audit entry, return response.

Slice 3+ adds the event bus, plugin supervisor, capability gate, secret broker
plumbing, and the dual-LLM split. This implementation does the work directly.
"""

from __future__ import annotations

import uuid

import structlog

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetError, BudgetGuard
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working import WorkingMemory
from alfred.personas.alfred import alfred_system_prompt
from alfred.providers.base import CompletionRequest, Message
from alfred.providers.router import ProviderRouter

_log = structlog.get_logger()


class Orchestrator:
    def __init__(
        self,
        *,
        operator_name: str,
        working: WorkingMemory,
        episodic: EpisodicMemory,
        audit: AuditWriter,
        router: ProviderRouter,
        budget: BudgetGuard,
    ) -> None:
        self._operator_name = operator_name
        self._working = working
        self._episodic = episodic
        self._audit = audit
        self._router = router
        self._budget = budget

    async def handle_user_message(self, content: str) -> str:
        trace_id = uuid.uuid4().hex
        # Observe.
        self._working.append(role="user", content=content)
        await self._episodic.record(
            user_id=self._operator_name,
            role="user",
            content=content,
            trust_tier="T2",
        )

        # Orient.
        system = alfred_system_prompt(operator_name=self._operator_name)
        messages: list[Message] = [Message(role="system", content=system)]
        for turn in self._working.turns():
            messages.append(Message(role=turn.role, content=turn.content))

        request = CompletionRequest(messages=messages, max_tokens=1024)

        # Decide + Act.
        try:
            response = await self._router.complete(request)
            self._budget.check_and_charge(response.cost_usd)
        except BudgetError as exc:
            await self._audit.append(
                event="provider.call",
                actor_user_id=self._operator_name,
                subject={"error": str(exc), "phase": "budget"},
                trust_tier_of_trigger="T2",
                result="quarantined",
                cost_estimate_usd=0.0,
                trace_id=trace_id,
            )
            raise

        self._working.append(role="assistant", content=response.content)
        await self._episodic.record(
            user_id=self._operator_name,
            role="assistant",
            content=response.content,
            trust_tier="T0",
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            cost_usd=response.cost_usd,
        )
        await self._audit.append(
            event="provider.call",
            actor_user_id=self._operator_name,
            subject={
                "tokens_in": response.tokens_in,
                "tokens_out": response.tokens_out,
                "model": None,
            },
            trust_tier_of_trigger="T2",
            result="success",
            cost_estimate_usd=response.cost_usd,
            trace_id=trace_id,
        )
        _log.info(
            "orchestrator.turn",
            trace_id=trace_id,
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            cost_usd=response.cost_usd,
        )
        return response.content
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/orchestrator/test_core.py -v`
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/orchestrator tests/unit/orchestrator
git commit -m "feat(orchestrator): add slice-1 slim OODA loop"
```

---

## Task 14 — Textual-based TUI

**Files:**
- Create: `src/alfred/comms/tui.py`
- Create: `tests/unit/comms/__init__.py`, `tests/unit/comms/test_tui.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/comms/test_tui.py`:

```python
"""Tests for the slice-1 textual TUI.

Driven via textual's `App.run_test()` harness so we don't actually attach a
real terminal during CI.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from alfred.comms.tui import AlfredTuiApp


@pytest.mark.asyncio
async def test_user_submission_dispatches_to_orchestrator_and_displays_response() -> None:
    orch = AsyncMock()
    orch.handle_user_message = AsyncMock(return_value="Good evening, operator.")
    app = AlfredTuiApp(orchestrator=orch)

    async with app.run_test() as pilot:
        await pilot.press("h", "i")
        await pilot.press("enter")
        await pilot.pause()
        log = app.query_one("#conversation_log")
        rendered = log.render() if hasattr(log, "render") else str(log)
        assert "Good evening" in str(rendered)
        orch.handle_user_message.assert_awaited_once_with("hi")
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/comms/test_tui.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `src/alfred/comms/tui.py`**

```python
"""Slice-1 TUI built on Textual.

The app shows a scrolling conversation log and an input box at the bottom.
Each Enter submission goes through the orchestrator and the response renders
in the log. No streaming yet — Slice 2 adds streaming UX.
"""

from __future__ import annotations

from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, RichLog


class AlfredTuiApp(App[None]):
    CSS = """
    Screen { layout: vertical; }
    #conversation_log { height: 1fr; border: solid white; padding: 1; }
    #user_input { dock: bottom; }
    """

    def __init__(self, *, orchestrator: Any) -> None:
        super().__init__()
        self._orchestrator = orchestrator

    def compose(self) -> ComposeResult:
        yield Vertical(
            RichLog(id="conversation_log", highlight=True, markup=True),
            Input(placeholder="Speak to Alfred...", id="user_input"),
        )

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        log = self.query_one("#conversation_log", RichLog)
        log.write(f"[bold cyan]you[/]: {text}")
        event.input.value = ""
        try:
            response = await self._orchestrator.handle_user_message(text)
        except Exception as exc:  # noqa: BLE001
            log.write(f"[bold red]alfred error[/]: {exc}")
            return
        log.write(f"[bold green]alfred[/]: {response}")
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/comms/test_tui.py -v`
Expected: 1 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms tests/unit/comms
git commit -m "feat(comms): add textual-based TUI for slice 1"
```

---

## Task 15 — `alfred` CLI entry

**Files:**
- Create: `src/alfred/cli/main.py`
- Create: `tests/unit/cli/__init__.py`, `tests/unit/cli/test_main.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/cli/test_main.py`:

```python
"""Tests for the Typer-based `alfred` CLI."""

from __future__ import annotations

from typer.testing import CliRunner

from alfred.cli.main import app

runner = CliRunner()


def test_alfred_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "chat" in result.stdout
    assert "status" in result.stdout


def test_alfred_status_exits_zero(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "deepseek" in result.stdout.lower()
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/cli/test_main.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `src/alfred/cli/main.py`**

```python
"""The `alfred` CLI entry point."""

from __future__ import annotations

import asyncio

import typer

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetGuard
from alfred.comms.tui import AlfredTuiApp
from alfred.config.settings import Settings
from alfred.memory.db import make_session_factory, session_scope
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working import WorkingMemory
from alfred.orchestrator.core import Orchestrator
from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.deepseek import DeepSeekProvider
from alfred.providers.router import ProviderRouter

app = typer.Typer(help="AlfredOS CLI", no_args_is_help=True)


def _build_router(settings: Settings) -> ProviderRouter:
    primary = DeepSeekProvider.from_settings(
        api_key=settings.deepseek_api_key.get_secret_value(),
        base_url=settings.deepseek_base_url,
        model=settings.deepseek_model,
    )
    fallback = None
    if settings.anthropic_api_key is not None:
        fallback = AnthropicProvider.from_settings(
            api_key=settings.anthropic_api_key.get_secret_value(),
            model=settings.anthropic_model,
        )
    return ProviderRouter(primary=primary, fallback=fallback)


@app.command()
def status() -> None:
    """Print which providers are configured and the current budget settings."""
    settings = Settings()  # type: ignore[call-arg]
    typer.echo(f"primary provider: {settings.primary_provider}")
    typer.echo(f"fallback provider: {settings.fallback_provider}")
    typer.echo(
        "anthropic fallback configured: "
        f"{'yes' if settings.anthropic_api_key else 'no'}"
    )
    typer.echo(f"daily budget USD: {settings.daily_budget_usd}")
    typer.echo(f"per-call max USD: {settings.per_call_max_usd}")


@app.command()
def chat() -> None:
    """Open the TUI chat with Alfred."""
    asyncio.run(_chat_main())


async def _chat_main() -> None:
    settings = Settings()  # type: ignore[call-arg]
    session_factory = make_session_factory(settings)
    router = _build_router(settings)
    budget = BudgetGuard(
        daily_usd=settings.daily_budget_usd,
        per_call_max_usd=settings.per_call_max_usd,
    )
    working = WorkingMemory()

    async with session_scope(session_factory) as session:
        episodic = EpisodicMemory(session=session)
        audit = AuditWriter(session=session)
        # Restore recent turns for cross-restart continuity.
        for ep in await episodic.recent(user_id=settings.operator_name, limit=20):
            working.append(role=ep.role, content=ep.content)  # type: ignore[arg-type]

        orchestrator = Orchestrator(
            operator_name=settings.operator_name,
            working=working,
            episodic=episodic,
            audit=audit,
            router=router,
            budget=budget,
        )
        tui = AlfredTuiApp(orchestrator=orchestrator)
        await tui.run_async()


if __name__ == "__main__":
    app()
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/cli/test_main.py -v`
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli tests/unit/cli
git commit -m "feat(cli): add alfred CLI with chat and status commands"
```

---

## Task 16 — Docker Compose, Dockerfile, and setup script

**Files:**
- Create: `docker-compose.yaml`
- Create: `docker/alfred-core.Dockerfile`
- Create: `bin/alfred-setup.sh`
- Modify: `bin/alfred-setup.ps1` (stub)

- [ ] **Step 1: Write `docker/alfred-core.Dockerfile`**

```dockerfile
FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv (Astral)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && cp /root/.local/bin/uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:${PATH}"

ENTRYPOINT ["alfred"]
CMD ["status"]
```

- [ ] **Step 2: Write `docker-compose.yaml`**

```yaml
services:
  alfred-postgres:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_DB: alfred
      POSTGRES_USER: alfred
      POSTGRES_PASSWORD: alfred
    ports:
      - "5432:5432"
    volumes:
      - alfred_pg_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U alfred -d alfred"]
      interval: 5s
      timeout: 5s
      retries: 10

  alfred-core:
    build:
      context: .
      dockerfile: docker/alfred-core.Dockerfile
    restart: unless-stopped
    depends_on:
      alfred-postgres:
        condition: service_healthy
    environment:
      ALFRED_DEEPSEEK_API_KEY: ${ALFRED_DEEPSEEK_API_KEY}
      ALFRED_ANTHROPIC_API_KEY: ${ALFRED_ANTHROPIC_API_KEY:-}
      ALFRED_DATABASE_URL: postgresql+asyncpg://alfred:alfred@alfred-postgres:5432/alfred
      ALFRED_OPERATOR_NAME: ${ALFRED_OPERATOR_NAME:-operator}
      ALFRED_DAILY_BUDGET_USD: ${ALFRED_DAILY_BUDGET_USD:-1.0}
      ALFRED_PER_CALL_MAX_USD: ${ALFRED_PER_CALL_MAX_USD:-0.10}
    command: ["status"]

volumes:
  alfred_pg_data:
```

- [ ] **Step 3: Write `bin/alfred-setup.sh`**

```bash
#!/usr/bin/env bash
# Idempotent setup script for AlfredOS Slice 1.
# Usage: bin/alfred-setup.sh [--dry-run]
set -euo pipefail

dry_run=false
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=true
fi

step() { printf "\n==> %s\n" "$1"; }
warn() { printf "WARNING: %s\n" "$1" >&2; }

step "Checking prerequisites"
command -v docker >/dev/null || { warn "docker not found"; exit 1; }
command -v docker compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1 \
  || { warn "docker compose not found"; exit 1; }

if $dry_run; then
  echo "DRY-RUN: prerequisites OK. Stopping."
  exit 0
fi

step "Ensuring .env exists"
if [[ ! -f .env ]]; then
  if [[ -f .env.example ]]; then
    cp .env.example .env
    echo "Created .env from .env.example. Edit it before running 'docker compose up'."
  else
    warn ".env.example not found; create .env manually."
  fi
fi

step "Validating ALFRED_DEEPSEEK_API_KEY is set"
# shellcheck disable=SC1091
[[ -f .env ]] && source .env
if [[ -z "${ALFRED_DEEPSEEK_API_KEY:-}" ]]; then
  warn "ALFRED_DEEPSEEK_API_KEY is empty. Edit .env and re-run."
  exit 1
fi

step "Building images"
docker compose build

step "Starting alfred-postgres"
docker compose up -d alfred-postgres

step "Waiting for Postgres health"
for _ in {1..30}; do
  if docker compose exec -T alfred-postgres pg_isready -U alfred -d alfred >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

step "Running migrations"
docker compose run --rm alfred-core sh -c "alembic upgrade head"

step "Setup complete"
echo "Run 'docker compose run --rm -it alfred-core chat' to open the TUI."
```

- [ ] **Step 4: Write `bin/alfred-setup.ps1`**

```powershell
# Slice-1 PowerShell stub. Delegates to WSL until native Windows support lands.
$ErrorActionPreference = "Stop"

if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Write-Error "WSL is required for AlfredOS on Windows in Slice 1. Install with 'wsl --install'."
    exit 1
}

wsl bash bin/alfred-setup.sh @args
```

- [ ] **Step 5: Make the script executable and verify dry-run**

Run: `chmod +x bin/alfred-setup.sh && bin/alfred-setup.sh --dry-run`
Expected: prerequisites OK message; exits 0.

- [ ] **Step 6: Commit**

```bash
git add docker docker-compose.yaml bin
git commit -m "build(deploy): add docker compose, alfred-core Dockerfile, setup scripts"
```

---

## Task 17 — Smoke test, CI wiring, PR

**Files:**
- Create: `tests/smoke/__init__.py`, `tests/smoke/test_hello_alfred.py`
- Modify: `.github/workflows/ci.yml` (uncomment Python job behind hashFiles guard)

- [ ] **Step 1: Write the smoke test**

Create `tests/smoke/test_hello_alfred.py`:

```python
"""End-to-end smoke test for Slice 1.

Boots a Postgres testcontainer, runs migrations, instantiates the full
orchestrator with a mocked provider, drives the TUI through one user turn, and
asserts the response renders + the audit_log table received an entry.

This is the canonical "stack is wired correctly" test. It runs in CI on every
PR; it does NOT call real LLM APIs.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from testcontainers.postgres import PostgresContainer

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetGuard
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.models import AuditEntry, Base, Episode
from alfred.memory.working import WorkingMemory
from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse


@pytest.mark.smoke
@pytest.mark.asyncio
async def test_alfred_handles_one_turn_end_to_end() -> None:
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("postgresql://", "postgresql+asyncpg://")
        engine = create_async_engine(url, future=True)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        sessionmaker = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with sessionmaker() as session:
            episodic = EpisodicMemory(session=session)
            audit = AuditWriter(session=session)
            working = WorkingMemory()
            budget = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)

            router = MagicMock()
            router.complete = AsyncMock(
                return_value=CompletionResponse(
                    content="Good evening, operator.",
                    tokens_in=12,
                    tokens_out=5,
                    cost_usd=0.00001,
                )
            )

            orch = Orchestrator(
                operator_name="operator",
                working=working,
                episodic=episodic,
                audit=audit,
                router=router,
                budget=budget,
            )

            response = await orch.handle_user_message("hi alfred")
            await session.commit()

            assert response == "Good evening, operator."

            ep_rows = (await session.execute(select(Episode))).scalars().all()
            assert len(ep_rows) == 2  # user + assistant
            assert {r.role for r in ep_rows} == {"user", "assistant"}

            audit_rows = (await session.execute(select(AuditEntry))).scalars().all()
            assert len(audit_rows) == 1
            assert audit_rows[0].result == "success"

        await engine.dispose()
```

- [ ] **Step 2: Run the smoke test locally**

Run: `uv run pytest tests/smoke -v`
Expected: PASS. (testcontainers Postgres + full orchestrator stack; ~15-30s.)

- [ ] **Step 3: Adjust `.github/workflows/ci.yml`**

The existing `python` job is guarded by `hashFiles('pyproject.toml')`. That guard now passes because `pyproject.toml` exists. Verify the job runs by pushing a branch and checking the Actions tab. If the integration job uses Postgres service, ensure the smoke test runs (it spins its own testcontainer).

No code change required if the current workflow is correct — open the PR and observe CI.

- [ ] **Step 4: Run all the slice-1 quality gates locally**

Run, in this order, and fix any issue surfaced:

```bash
uv run ruff check .
uv run black --check src/ tests/
uv run mypy src/
uv run pytest tests/unit -v
uv run pytest tests/integration -v
uv run pytest tests/smoke -v
uv run pytest --cov=src/alfred --cov-report=term-missing
```

Expected: all green. Coverage at least 75% overall and 100% on `src/alfred/security/`.

- [ ] **Step 5: Open the PR**

Push the branch and open a PR:

```bash
git push -u origin <branch-name>
gh pr create \
  --title "feat: AlfredOS Slice 1 - 'Hello, Alfred'" \
  --body "$(cat <<'EOF'
## Summary

Implements Slice 1 ("Hello, Alfred") per `docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`. A vertical cross-section of all twelve subsystems from the PRD:

- Trust tiers (T0, T2) + `tag()` helper (subset of #7)
- Config + env-backed secret broker (subset of #1 / #9)
- Postgres + SQLAlchemy 2.0 async + alembic migrations (subset of #3)
- DeepSeek primary provider + Anthropic fallback + router (subset of #5)
- Working + episodic memory (subset of #3)
- Hardcoded Alfred persona (subset of #4)
- Per-call + per-day budget guard (subset of #5)
- Slim OODA orchestrator (subset of #2)
- Textual-based TUI (subset of #7 comms)
- `alfred` CLI (`chat`, `status`)
- Docker Compose + Dockerfile + setup script (subset of #9)
- Append-only audit log (subset of #12)

## Test plan

- [x] `uv run pytest tests/unit -v` — all unit tests pass
- [x] `uv run pytest tests/integration -v` — Postgres schema migrates cleanly
- [x] `uv run pytest tests/smoke -v` — one full turn end-to-end through orchestrator
- [x] `uv run mypy src/` — strict mypy clean
- [x] `uv run ruff check . && uv run black --check src/ tests/` — clean

## Trust-boundary review

- [x] Slice 1 only ingests T2 (operator's typed input). No T3 paths land yet; those come in Slice 3 with the first real tool.
- [x] LLM never reads env vars directly; the secret broker mediates.

## Deferred to later slices

See the "Subsystem coverage matrix" in the plan for the full list of what's intentionally NOT in Slice 1 and which future slice picks it up.
EOF
)"
```

- [ ] **Step 6: Watch CI; fix failures; merge**

```bash
gh pr checks --watch
```

If checks fail, read logs (`gh run view <run-id> --log-failed`), fix, push. Repeat to green.

Once green and reviewed by CodeRabbit + `alfred-reviewer`, merge:

```bash
gh pr merge --squash --delete-branch
```

---

## Definition of Done (recap)

- [ ] `docker compose up -d` brings up `alfred-core` + `alfred-postgres` cleanly on macOS and Linux.
- [ ] `docker compose run --rm -it alfred-core chat` opens the TUI; multi-turn conversation works.
- [ ] Restart-then-rechat preserves recent context (the `episodes` table is queried at startup).
- [ ] Daily budget cap prevents runaway cost.
- [ ] Every turn is in `episodes`; every provider call is in `audit_log`.
- [ ] Smoke test green in CI.
- [ ] mypy strict + ruff + black all clean.
- [ ] Coverage at least 75% overall; 100% on `src/alfred/security/`.

---

## Slices that follow

Each subsequent slice keeps the existing surface working and adds one or two new vertical strands. Rough order (re-prioritise based on what we learn from Slice 1):

| Slice | Adds | Proves |
|---|---|---|
| **0.0.2** | Discord adapter; multi-user identity; secret broker file backend | Multi-platform + multi-user identity works; secret broker upgraded |
| **0.0.3** | First real tool (e.g. `web.fetch`); T1/T3 types; dual-LLM split; capability gate; DLP | Full security stack on one feature |
| **0.0.4** | Telegram; auto-retrieve; semantic facts; consolidation pass | Memory enrichment actually improves conversations |
| **0.0.5** | Vector layer (Qdrant); graph layer; provider prompt caching | Cost drops, recall rises |
| **0.0.6** | Second persona; addressing modes; inter-persona bus; audit graph CLI | Multi-persona system works |
| **0.0.7** | Reviewer gate; internal git repo; first agent-authored skill | Self-improvement actually self-improves |
| **0.1.0** | Adversarial suite green; everything in PRD §9 met | MVP complete |
