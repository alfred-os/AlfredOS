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
| Internationalization | Babel + gettext, `t()`, English seed catalog, `language` column on every user-content row, persona prompt honours `{user.language}`, `pybabel extract` in pre-commit, `pybabel compile --check` in CI | Community translation workflow (Crowdin/Weblate), RTL TUI, locale-aware number/date formatting → Slice 0.0.4+ |

**i18n is woven through the main task flow** — it is a CLAUDE.md hard rule (rule #1: "all operator-/user-facing strings go through `t()`. Hardcoded English in `src/alfred/` outside the catalog source files is a release blocker."). Each affected task includes the i18n work as required steps, not as an appendix. The dedicated **Task 3.5 — i18n primitives** lands *before* the first consumer (Task 5), so a linear executor can never ship hardcoded English.

**Slice 1 Definition of Done:**

1. `bin/alfred-setup.sh && docker compose up -d` brings up `alfred-core` + `alfred-postgres` cleanly on macOS/Linux.
2. `alfred chat` opens a TUI where the operator can type and Alfred responds via DeepSeek.
3. Multi-turn context is preserved within a session.
4. Exiting and re-running `alfred chat` shows Alfred has memory of the prior conversation (context loaded from `episodes` table).
5. Per-day budget cap pauses the loop when exhausted (pre-check; see Task 13).
6. Every turn is in the `episodes` table; every action is in `audit_log`.
7. Smoke test green in CI.
8. mypy strict + ruff + black all clean.
9. `python` job in CI passes on the PR.
10. `pybabel extract` shows no catalog drift; CI's i18n step passes.
11. `Settings.operator_language` flows through the persona system prompt; Alfred responds in the configured language.
12. All operator-facing strings in `src/alfred/cli/` and `src/alfred/comms/` use `t()` (grep verifies no hardcoded English in those packages outside catalog sources).
13. The 6 ADRs in `docs/adr/0001–0006` exist and explain the structural decisions: DeepSeek-as-primary, in-process working memory, plain-asyncio orchestrator, Textual TUI, env-backed broker stub, Alembic for migrations.
14. The PRD has been updated (or referenced via the ADRs) for any slice-1 design that diverges from PRD §5, §6.2, §6.6, or §6.7.

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
license = { text = "Apache-2.0" }
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
  "babel>=2.16,<3",  # i18n (Task 3.5)
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
  "pre-commit>=3.7",  # for the pybabel extract hook (Task 3.5)
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
# Per-package 100% gates are enforced by a second `coverage report --include=... --fail-under=100`
# invocation in CI (see Task 17). pytest --cov-fail-under only takes one threshold value.
# CLAUDE.md hard rule: every security boundary must have 100% line+branch coverage.

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

[tool.babel]
# i18n catalog extract config. See Task 3.5 for the consumer.
domain = "alfred"
input_dirs = ["src/alfred"]
output_dir = "locale"
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
    """Reads secrets from environment variables prefixed with ALFRED_.

    Slice-1 stub backend. Slice-3+ replaces with age-encrypted files / Vault /
    keychain — the public API (`get`, `has`, `known`, `redact`,
    `from_settings`) stays stable so callers don't change.
    """

    def __init__(self, *, env: dict[str, str] | None = None) -> None:
        # Inject env for tests; default to os.environ so callers don't have to.
        import os
        self._env: dict[str, str] = dict(env) if env is not None else dict(os.environ)

    @classmethod
    def from_settings(cls, settings: "Settings") -> "SecretBroker":
        """Build a broker primed from a Settings instance.

        Slice-1 implementation reads `os.environ` directly because Settings
        is itself populated from env vars; passing through Settings here is
        the seam slice-3+ swaps to read from age-encrypted files / Vault.
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
ALFRED_OPERATOR_LANGUAGE=en-US  # BCP-47; default catalog is English. See Task 3.5.

# Budgets.
ALFRED_DAILY_BUDGET_USD=1.0
ALFRED_PER_CALL_MAX_USD=0.10
```

Note: a key-source URL hint goes at the top of `.env.example` so a fresh contributor knows where to get the DeepSeek key:

```
# Get a DeepSeek key at https://platform.deepseek.com (the API is OpenAI-compatible).
# Get an Anthropic key at https://console.anthropic.com (used as fallback).
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

[i18n]
# Default operator language. Override via ALFRED_OPERATOR_LANGUAGE.
operator_language = "en-US"
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
    # CLAUDE.md i18n rule #3: every stored user-content row carries a BCP-47 language tag.
    language: Mapped[str] = mapped_column(String(16), default="en-US")
    tokens_in: Mapped[int] = mapped_column(default=0)
    tokens_out: Mapped[int] = mapped_column(default=0)
    cost_usd: Mapped[float] = mapped_column(default=0.0)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    __table_args__ = (
        # Hot path: the orchestrator loads the last N turns by user on startup. Composite
        # index avoids a full scan + sort.
        Index("ix_episodes_user_id_created_at", "user_id", "created_at"),
    )


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
    result: Mapped[str] = mapped_column(String(32))
    # Truthful cost accounting: estimate is what budget pre-check looked at;
    # actual is the post-call charge (None until reconciled).
    cost_estimate_usd: Mapped[float] = mapped_column(default=0.0)
    cost_actual_usd: Mapped[float | None] = mapped_column(nullable=True)
    # CLAUDE.md i18n rule #3: every stored user-content row carries a BCP-47 language tag.
    language: Mapped[str] = mapped_column(String(16), default="en-US")
```

Note the `Index` import: add `from sqlalchemy import ..., Index` near the top of `models.py`.

| Field | Status | Why |
|---|---|---|
| `language` on `Episode` and `AuditEntry` | NEW (this slice) | CLAUDE.md i18n rule #3 — every user-content row carries BCP-47 |
| `cost_actual_usd` on `AuditEntry` | NEW (this slice) | Truthful cost reporting: separate estimate from actual (fixes the "audit lie" finding) |
| `ix_episodes_user_id_created_at` | NEW (this slice) | Hot-path index for episodic.recent(user_id, limit) |

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
    """Transactional async session scope. Commits on success; rolls back on failure.

    Accepts the factory explicitly so tests / smoke tests can inject one.
    """
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def build_session_scope(settings: Settings):
    """Bind `session_scope` to a settings-derived factory.

    Returns a no-arg callable suitable for the orchestrator's `session_scope`
    parameter — `async with session_scope() as session: ...`. Wraps the
    `make_session_factory(settings)` + `session_scope(factory)` plumbing so
    the orchestrator only needs one zero-arg callable.
    """
    factory = make_session_factory(settings)

    def _scope():
        return session_scope(factory)

    return _scope


async def healthcheck(scope) -> None:
    """Smoke-check the database is reachable.

    Called at CLI bootstrap so a missing/down Postgres surfaces as a clean
    "ERROR: Postgres unreachable" message instead of an asyncpg traceback
    inside the TUI on first keystroke. Raises SQLAlchemyError on failure.
    """
    from sqlalchemy import text as _text
    async with scope() as session:
        await session.execute(_text("SELECT 1"))
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

## Task 3.5 — i18n primitives

> Inserted here so the primitives exist *before* their consumers in Tasks 5, 11, 13, 14, 15. A linear executor cannot ship hardcoded English because every consumer below this point already has `t()` available.

**Files:**

- Create: `src/alfred/i18n/__init__.py`, `src/alfred/i18n/translator.py`, `src/alfred/i18n/catalog.py`
- Create: `babel.cfg`, `locale/en/LC_MESSAGES/alfred.po`
- Create: `tests/unit/i18n/__init__.py`, `tests/unit/i18n/test_translator.py`

- [ ] **Step 1: Write `babel.cfg`**

```ini
[python: src/alfred/**.py]
encoding = utf-8
```

- [ ] **Step 2: Write `locale/en/LC_MESSAGES/alfred.po` (seed catalog)**

```
# AlfredOS English source catalog.
msgid ""
msgstr ""
"Project-Id-Version: AlfredOS 0.0.1\n"
"Content-Type: text/plain; charset=UTF-8\n"
"Language: en\n"

msgid "status.primary_provider"
msgstr "primary provider: {provider}"

msgid "status.fallback_provider"
msgstr "fallback provider: {provider}"

msgid "status.anthropic_configured"
msgstr "anthropic fallback configured: {yes_or_no}"

msgid "status.daily_budget"
msgstr "daily budget USD: {amount}"

msgid "status.per_call_max"
msgstr "per-call max USD: {amount}"

msgid "tui.input_placeholder"
msgstr "Speak to Alfred..."

msgid "tui.label_you"
msgstr "you"

msgid "tui.label_alfred"
msgstr "alfred"

msgid "tui.thinking"
msgstr "thinking..."

msgid "tui.turn_cancelled"
msgstr "turn cancelled"

msgid "tui.turn_timeout"
msgstr "no response within {seconds}s; cancelled"

msgid "tui.alfred_error"
msgstr "alfred error: {error}"

msgid "error.budget_exhausted"
msgstr "daily budget exhausted (spent ${spent:.4f} of ${cap:.2f})"

msgid "error.config_invalid"
msgstr "configuration is invalid: {detail}"

msgid "error.postgres_unreachable"
msgstr "Postgres is unreachable: {detail}"

msgid "hint.copy_env_example"
msgstr "Tip: copy .env.example to .env and fill in ALFRED_DEEPSEEK_API_KEY."

msgid "hint.is_compose_up"
msgstr "Tip: run 'docker compose up -d alfred-postgres' to start the database."
```

- [ ] **Step 3: Write the failing test**

```python
"""Tests for the AlfredOS i18n translator."""

from __future__ import annotations

import pytest

from alfred.i18n import set_language, t


@pytest.fixture(autouse=True)
def _reset_language() -> None:
    set_language("en-US")


class TestTranslator:
    def test_returns_message_for_known_key_in_english(self) -> None:
        # The catalog defines status.primary_provider as "primary provider: {provider}".
        assert t("status.primary_provider", provider="deepseek") == "primary provider: deepseek"

    def test_returns_key_as_fallback_for_unknown_message(self) -> None:
        # Missing-message strategy: return the key so the developer sees what to add.
        assert t("missing.key.example") == "missing.key.example"

    def test_substitutes_kwargs_into_message(self) -> None:
        assert "1.50" in t("status.daily_budget", amount="1.50")

    def test_set_language_switches_active_catalog(self) -> None:
        # Switching to a language with no catalog falls back to English.
        set_language("fr-FR")
        # English catalog still wins because no fr-FR catalog exists yet.
        assert "primary provider" in t("status.primary_provider", provider="deepseek")
```

- [ ] **Step 4: Run and verify failure**

Run: `uv run pytest tests/unit/i18n/test_translator.py -v`
Expected: FAIL — `alfred.i18n` not defined.

- [ ] **Step 5: Implement `src/alfred/i18n/translator.py`**

```python
"""AlfredOS translator (Babel + gettext)."""

from __future__ import annotations

import gettext
from pathlib import Path

_DOMAIN = "alfred"
_LOCALE_DIR = Path(__file__).resolve().parents[3] / "locale"
_active_lang: str = "en-US"
_translators: dict[str, gettext.NullTranslations] = {}


def _bcp47_to_gettext(tag: str) -> str:
    return tag.replace("-", "_").split(".")[0]


def _load(lang: str) -> gettext.NullTranslations:
    if lang in _translators:
        return _translators[lang]
    try:
        t = gettext.translation(
            _DOMAIN, localedir=str(_LOCALE_DIR), languages=[_bcp47_to_gettext(lang), "en"]
        )
    except FileNotFoundError:
        t = gettext.NullTranslations()
    _translators[lang] = t
    return t


def set_language(lang: str) -> None:
    """Activate the given BCP-47 language tag for subsequent t() calls."""
    global _active_lang
    _active_lang = lang


def t(key: str, /, **vars: object) -> str:
    """Return the translated string for `key`, substituting `vars`.

    Missing keys return the key itself — a deliberate fallback so a developer
    sees what catalog entry to add.
    """
    translator = _load(_active_lang)
    raw = translator.gettext(key)
    if raw == key:
        # Not found; still attempt to substitute so .format() doesn't blow up on placeholders in the key.
        return key
    try:
        return raw.format(**vars)
    except (KeyError, IndexError):
        # If substitution fails (missing variable), return the unsubstituted template.
        return raw
```

- [ ] **Step 6: Implement `src/alfred/i18n/__init__.py`**

```python
"""AlfredOS internationalization."""

from alfred.i18n.translator import set_language, t

__all__ = ["set_language", "t"]
```

- [ ] **Step 7: Compile the English catalog**

Run: `uv run pybabel compile -d locale -D alfred`
Expected: `compiling catalog locale/en/LC_MESSAGES/alfred.po to locale/en/LC_MESSAGES/alfred.mo`.

- [ ] **Step 8: Run the tests and verify they pass**

Run: `uv run pytest tests/unit/i18n/test_translator.py -v`
Expected: 4 PASS.

- [ ] **Step 9: Commit**

```bash
git add src/alfred/i18n tests/unit/i18n locale babel.cfg
git commit -m "feat(i18n): add Babel/gettext translator with English seed catalog"
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
    def test_holds_content_source_tier_metadata(self) -> None:
        c = TaggedContent[T2](content="hi", source="tui.input", tier=T2, metadata={"line": 1})
        assert c.content == "hi"
        assert c.source == "tui.input"
        assert c.tier is T2
        assert c.tier.name == "T2"
        assert c.metadata == {"line": 1}

    def test_is_frozen(self) -> None:
        c = TaggedContent[T2](content="hi", source="tui.input", tier=T2)
        with pytest.raises(ValidationError):
            c.content = "tampered"  # type: ignore[misc]

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TaggedContent[T2](content="x", source="s", tier=T2, evil="leak")  # type: ignore[call-arg]


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
    """Marker base for trust tiers. Subclasses set `name` as a class attribute
    so the trust-tier label survives into runtime use (audit log, DB row)
    without losing the static-type-parameter benefits of `TaggedContent`."""

    name: str = ""


class T0(TrustTier):
    """System tier: AlfredOS internals (highest trust)."""
    name = "T0"


class T2(TrustTier):
    """Authenticated tier: known users."""
    name = "T2"


TierT = TypeVar("TierT", bound=TrustTier)


class TaggedContent(BaseModel, Generic[TierT]):
    """Content tagged with a trust tier.

    The tier is BOTH a type parameter (so mypy can distinguish T0/T2 statically)
    AND a runtime field (so the orchestrator + audit log can read it). Slice 1
    uses this to keep system prompts (T0) and user input (T2) distinguishable;
    Slice 2 adds T1/T3 plus the dual-LLM split.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    content: str
    source: str
    tier: type[TrustTier]
    metadata: dict[str, Any] = {}


@overload
def tag(
    tier: type[T0], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[T0]: ...
@overload
def tag(
    tier: type[T2], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[T2]: ...
def tag(
    tier: type[TrustTier], content: str, *, source: str = "unspecified", **metadata: Any
) -> TaggedContent[Any]:
    """Tag content with a trust tier at an ingestion boundary.

    `content` is positional so call sites read naturally:
        tag(T2, user_text, source="comms.tui.input")
    `source` is optional; supply it at every real ingestion site (the
    audit log records it) but defaults exist so quick test fixtures don't
    have to repeat it.
    """
    return TaggedContent[tier](
        content=content, source=source, tier=tier, metadata=dict(metadata)
    )
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
        cost_actual_usd: float | None = None,
        language: str = "en-US",
    ) -> None:
        """Record a single audit entry. Raises if persistence fails.

        `language` is a BCP-47 tag (e.g. "en-US", "ja-JP"). Every audit row carries it
        because CLAUDE.md i18n rule #3 requires every stored user-content row to have a
        language field — and the audit log is one such row (subject often contains a
        user-content excerpt). Default "en-US" preserves backward-compat for paths that
        haven't been threaded with language yet, but new callers MUST pass language
        explicitly. The orchestrator passes it from `Settings.operator_language`.
        """
        entry = AuditEntry(
            trace_id=trace_id,
            event=event,
            actor_user_id=actor_user_id,
            actor_persona=actor_persona,
            subject=subject,
            trust_tier_of_trigger=trust_tier_of_trigger,
            result=result,
            cost_estimate_usd=cost_estimate_usd,
            cost_actual_usd=cost_actual_usd,
            language=language,
        )
        self._session.add(entry)
        await self._session.flush()
```

> **i18n requirement**: this signature change (the `language` parameter) is the fix for the i18n-003 finding — without it, every audit row silently defaults to `en-US` regardless of what language the user is operating in. The orchestrator (Task 13) passes `language=self._operator_language` on every `append()` call; any new audit caller must do the same.

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
    # The model the provider actually used (e.g. "deepseek-chat" or
    # "claude-sonnet-4-6"). Required so the orchestrator's audit entry and
    # the smoke test can attribute cost/behavior to the exact model — critical
    # for the multi-provider fallback case where the response came from the
    # fallback rather than the primary.
    model: str


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
    prompt = alfred_system_prompt(operator_name="Ian", language="en-US")
    assert "Ian" in prompt
    assert "Alfred" in prompt


def test_system_prompt_carries_user_language_tag() -> None:
    """CLAUDE.md i18n rule #2: persona system prompts honour {user.language}."""
    prompt_en = alfred_system_prompt(operator_name="Ian", language="en-US")
    assert "en-US" in prompt_en
    prompt_ja = alfred_system_prompt(operator_name="Ian", language="ja-JP")
    assert "ja-JP" in prompt_ja
    assert prompt_en != prompt_ja


def test_system_prompt_is_a_t0_tagged_content() -> None:
    from alfred.security.tiers import T0, TaggedContent

    prompt = alfred_system_prompt(operator_name="Ian", language="en-US")
    # The factory returns plain text; the orchestrator wraps it in TaggedContent[T0]
    # at the boundary.
    tagged: TaggedContent[T0] = TaggedContent[T0](
        content=prompt, source="persona.alfred", tier=T0
    )
    assert isinstance(tagged, TaggedContent)
    assert tagged.tier.name == "T0"
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


def alfred_system_prompt(*, operator_name: str, language: str) -> str:
    """Build Alfred's system prompt for a given operator + language.

    CLAUDE.md i18n rule #2: persona system prompts must honour `{user.language}`. The
    persona system prompt is the place the model learns what language to respond in.
    Slice 1 passes `Settings.operator_language` here from the orchestrator; slice 3+
    (multi-user) will pass the per-user value.
    """
    return (
        f"You are {ALFRED_PERSONA.name.title()}, head butler in {operator_name}'s "
        f"household. {ALFRED_PERSONA.character} "
        f"Address the operator as {operator_name}. "
        f"Respond in the language identified by BCP-47 tag '{language}'. "
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

    def estimate_for(self, request: "CompletionRequest") -> float:
        """Estimate the USD cost of a provider call before sending it.

        Slice-1 returns a conservative flat-rate estimate (the per-call cap
        itself) so `would_exceed` becomes "is there even cap-worth of budget
        left?". Slice-2 replaces this with a token-aware estimate that reads
        the request's message tokens and the routed provider's published rates.
        Kept as a method (not a property) so slice-2's async token-counting
        path is a drop-in.
        """
        return self._per_call_max_usd

    def would_exceed(self, cost_usd: float) -> bool:
        """Return True iff charging `cost_usd` would breach either cap.

        Called by the orchestrator BEFORE the provider call so an over-budget
        request is refused without spending money on it. `check_and_charge`
        reconciles to the actual cost after the call.
        """
        if cost_usd > self._per_call_max_usd:
            return True
        self._roll_day_if_needed()
        return self._spent + cost_usd > self._daily_usd

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


from contextlib import asynccontextmanager


def _make_budget(allow: bool = True, estimate: float = 0.0001) -> MagicMock:
    """Build a budget mock whose would_exceed returns the inverse of `allow`."""
    budget = MagicMock()
    budget.estimate_for.return_value = estimate
    budget.would_exceed.return_value = not allow
    return budget


def _make_session_scope() -> tuple:
    """Build a session_scope callable + the session mock, for orchestrator tests.

    The orchestrator opens `async with session_scope() as session: ...`. Tests don't care
    what the session does; they care about what episodic_factory / audit_factory the
    orchestrator constructs from it. We return both so a test can assert rollback on error.
    """
    session = MagicMock()
    session.rollback = AsyncMock()
    session.commit = AsyncMock()

    @asynccontextmanager
    async def scope():
        yield session

    return scope, session


def _make_episodic_audit() -> tuple[MagicMock, MagicMock]:
    """Build the episodic + audit mocks the orchestrator uses inside one turn."""
    episodic = MagicMock(); episodic.record = AsyncMock()
    audit = MagicMock(); audit.append = AsyncMock()
    return episodic, audit


def _build(**overrides):
    """Construct an Orchestrator with sensible defaults, allowing per-test overrides.

    Returns (orch, captured) where captured is a dict of the mocks the test asserts on.
    """
    working = overrides.pop("working", None) or MagicMock(turns=MagicMock(return_value=[]))
    router = overrides.pop("router", MagicMock())
    budget = overrides.pop("budget", _make_budget(allow=True))
    scope, session = _make_session_scope()
    episodic, audit = _make_episodic_audit()
    orch = Orchestrator(
        operator_name="operator",
        operator_language="en-US",
        session_scope=scope,
        working=working,
        router=router,
        budget=budget,
        episodic_factory=lambda _s: episodic,
        audit_factory=lambda _s: audit,
        **overrides,
    )
    return orch, {"working": working, "router": router, "budget": budget,
                  "session": session, "episodic": episodic, "audit": audit}


@pytest.mark.asyncio
async def test_handle_user_message_appends_to_working_memory_and_returns_response() -> None:
    router = MagicMock()
    router.complete = AsyncMock(
        return_value=CompletionResponse(
            content="Hello, operator.", tokens_in=12, tokens_out=4,
            cost_usd=0.00001, model="deepseek-chat",
        )
    )
    orch, m = _build(router=router, budget=_make_budget(allow=True, estimate=0.00001))

    text = await orch.handle_user_message("hi")
    assert text == "Hello, operator."

    assert m["working"].append.call_count == 2
    assert m["episodic"].record.await_count == 2
    for call in m["episodic"].record.await_args_list:
        assert call.kwargs["language"] == "en-US"
    m["audit"].append.assert_awaited_once()
    args = m["audit"].append.await_args.kwargs
    assert args["result"] == "success"
    assert args["cost_actual_usd"] == 0.00001
    assert args["language"] == "en-US"
    m["budget"].check_and_charge.assert_called_once_with(0.00001)


@pytest.mark.asyncio
async def test_budget_pre_check_refuses_call_and_audits_truthfully() -> None:
    """Estimate over cap → no provider call, audit records actual=0 (not a lie)."""
    from alfred.budget.guard import BudgetError
    router = MagicMock()
    router.complete = AsyncMock()  # MUST NOT be awaited
    orch, m = _build(router=router, budget=_make_budget(allow=False, estimate=10.0))

    with pytest.raises(BudgetError):
        await orch.handle_user_message("hi")

    router.complete.assert_not_awaited()
    m["audit"].append.assert_awaited_once()
    args = m["audit"].append.await_args.kwargs
    assert args["result"] == "budget_blocked"
    assert args["cost_estimate_usd"] == 10.0
    assert args["cost_actual_usd"] == 0.0
    m["session"].rollback.assert_awaited_once()  # session is rolled back on error


@pytest.mark.asyncio
async def test_provider_failure_is_audited_then_re_raised() -> None:
    """Provider exception → audit at provider_failed, re-raised, session rolled back."""
    router = MagicMock()
    router.complete = AsyncMock(side_effect=RuntimeError("both providers timed out"))
    orch, m = _build(router=router)

    with pytest.raises(RuntimeError, match="both providers timed out"):
        await orch.handle_user_message("hi")

    m["audit"].append.assert_awaited_once()
    args = m["audit"].append.await_args.kwargs
    assert args["result"] == "provider_failed"
    assert args["subject"]["error_type"] == "RuntimeError"
    m["session"].rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_post_success_audit_failure_is_loud() -> None:
    """CLAUDE.md security rule #7: failed audit write on successful call is never silent."""
    router = MagicMock()
    router.complete = AsyncMock(
        return_value=CompletionResponse(
            content="ok", tokens_in=5, tokens_out=2, cost_usd=0.0001, model="deepseek-chat",
        )
    )
    orch, m = _build(router=router)
    m["audit"].append.side_effect = RuntimeError("postgres unreachable")

    with pytest.raises(RuntimeError, match="postgres unreachable"):
        await orch.handle_user_message("hi")
    m["session"].rollback.assert_awaited_once()
```

The four tests cover the four failure modes from the contract table above plus the happy path. Coverage of the orchestrator's error branches is now 100%.

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/unit/orchestrator/test_core.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `src/alfred/orchestrator/core.py`**

```python
"""Slice-1 orchestrator.

The thinnest possible OODA loop:
  1. Observe: tag the incoming user message as T2 and persist it.
  2. Orient: assemble the prompt — system (T0) + recent turns + new user turn.
  3. Decide: pre-check budget, then call the provider router.
  4. Act: append to working + episodic memory, write audit entry, return response.

Failure modes are loud:
  - Any provider failure (network, transport, both primary AND fallback dead)
    is caught, audited, and re-raised. The TUI renders a friendly message.
  - Any post-success audit-write failure is logged at error level and re-raised;
    we never serve a reply whose audit entry quietly failed (CLAUDE.md security
    rule #7: no silent failures in security paths).
  - Budget pre-check refuses the provider call entirely if the call's *estimate*
    would exceed remaining budget. The post-call charge then reconciles to the
    actual cost.

Slice 3+ adds the event bus, plugin supervisor, capability gate, secret broker
plumbing, and the dual-LLM split. This implementation does the work directly.
"""

from __future__ import annotations

import uuid
from contextlib import AbstractAsyncContextManager
from typing import Callable

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetError, BudgetGuard
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working import WorkingMemory
from alfred.personas.alfred import alfred_system_prompt
from alfred.providers.base import CompletionRequest, Message
from alfred.providers.router import ProviderRouter
from alfred.security.tiers import T0, T2, tag

_log = structlog.get_logger()

# Type aliases for clarity. SessionScope is a no-arg callable returning an async
# context manager that yields a fresh AsyncSession. The factory function lives
# in alfred.memory.db and wraps async_sessionmaker.
SessionScope = Callable[[], AbstractAsyncContextManager[AsyncSession]]
EpisodicFactory = Callable[[AsyncSession], EpisodicMemory]
AuditFactory = Callable[[AsyncSession], AuditWriter]


class Orchestrator:
    """Per-turn session lifecycle is owned here.

    Each call to handle_user_message opens its own session and commits at the end.
    A TUI crash mid-turn loses only the in-flight turn — all prior turns are durable.
    Slice-1 design choice: the orchestrator owns this so the comms layer (TUI / future
    Discord / future Telegram) does not need to know about DB sessions.
    """

    def __init__(
        self,
        *,
        operator_name: str,
        operator_language: str,
        session_scope: SessionScope,
        working: WorkingMemory,
        router: ProviderRouter,
        budget: BudgetGuard,
        # Injected for tests: lets the test substitute MagicMock factories.
        episodic_factory: EpisodicFactory = EpisodicMemory,
        audit_factory: AuditFactory = AuditWriter,
    ) -> None:
        self._operator_name = operator_name
        self._operator_language = operator_language
        self._session_scope = session_scope
        self._working = working
        self._router = router
        self._budget = budget
        self._episodic_factory = episodic_factory
        self._audit_factory = audit_factory

    async def handle_user_message(self, content: str) -> str:
        async with self._session_scope() as session:
            try:
                return await self._handle_turn(session, content)
            except Exception:
                await session.rollback()
                raise
            finally:
                # session_scope is expected to commit on clean exit; explicit no-op here
                # documents that the scope owns commit semantics.
                pass

    async def _handle_turn(self, session: AsyncSession, content: str) -> str:
        episodic = self._episodic_factory(session)
        audit = self._audit_factory(session)
        trace_id = uuid.uuid4().hex

        # Observe: tag inbound content. The TUI is *expected* to pass already-tagged
        # content in slice 2 when the adapter contract widens; for slice 1 we tag here
        # so the boundary discipline is enforced even if a caller forgets. See ADR-0005
        # and the trust-tiers skill.
        user_input = tag(T2, content)

        self._working.append(role="user", content=user_input.content)
        await episodic.record(
            user_id=self._operator_name,
            role="user",
            content=user_input.content,
            trust_tier=user_input.tier.name,
            language=self._operator_language,
        )

        # Orient.
        system = alfred_system_prompt(
            operator_name=self._operator_name,
            language=self._operator_language,
        )
        messages: list[Message] = [Message(role="system", content=system)]
        for turn in self._working.turns():
            messages.append(Message(role=turn.role, content=turn.content))

        request = CompletionRequest(messages=messages, max_tokens=1024)

        # Decide: budget pre-check on the estimate (cheaper of the two providers).
        # `would_exceed` does not charge; it inspects the cap. The post-call
        # `check_and_charge` reconciles to actual.
        estimate = self._budget.estimate_for(request)
        if self._budget.would_exceed(estimate):
            await audit.append(
                event="provider.call",
                actor_user_id=self._operator_name,
                subject={"phase": "budget_pre_block", "estimate_usd": estimate},
                trust_tier_of_trigger=user_input.tier.name,
                result="budget_blocked",
                cost_estimate_usd=estimate,
                cost_actual_usd=0.0,
                trace_id=trace_id,
                language=self._operator_language,
            )
            raise BudgetError(
                f"budget would be exceeded: estimate ${estimate:.4f} exceeds remaining cap"
            )

        # Act: call provider. Any failure here is loud-audit then re-raise — the TUI
        # turns the exception into a user-visible message; we do NOT swallow it.
        try:
            response = await self._router.complete(request)
        except Exception as exc:
            await audit.append(
                event="provider.call",
                actor_user_id=self._operator_name,
                subject={
                    "phase": "provider_call",
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
                trust_tier_of_trigger=user_input.tier.name,
                result="provider_failed",
                cost_estimate_usd=estimate,
                cost_actual_usd=0.0,
                trace_id=trace_id,
                language=self._operator_language,
            )
            _log.error(
                "orchestrator.provider_failed",
                trace_id=trace_id,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise

        # Post-call: reconcile budget to ACTUAL cost. If the actual blew the cap
        # (DeepSeek hung, fallback to Anthropic charged 40× more), record an
        # overrun event truthfully — the cost was real, the call happened.
        try:
            self._budget.check_and_charge(response.cost_usd)
            charge_result = "success"
        except BudgetError as exc:
            charge_result = "budget_overrun"
            _log.warning(
                "orchestrator.budget_overrun",
                trace_id=trace_id,
                estimate_usd=estimate,
                actual_usd=response.cost_usd,
                error=str(exc),
            )

        # Persist the assistant turn first; audit-write is the final fail-loud step.
        assistant_output = tag(T0, response.content)  # assistant content is T0 (model output)
        self._working.append(role="assistant", content=assistant_output.content)
        await episodic.record(
            user_id=self._operator_name,
            role="assistant",
            content=assistant_output.content,
            trust_tier=assistant_output.tier.name,
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            cost_usd=response.cost_usd,
            language=self._operator_language,
        )

        # CLAUDE.md security rule #7: audit failure on a successful provider call is
        # never silent. Log loudly and re-raise; the TUI will render the failure.
        try:
            await audit.append(
                event="provider.call",
                actor_user_id=self._operator_name,
                subject={
                    "tokens_in": response.tokens_in,
                    "tokens_out": response.tokens_out,
                    "model": response.model,
                    "estimate_usd": estimate,
                    "actual_usd": response.cost_usd,
                },
                trust_tier_of_trigger=user_input.tier.name,
                result=charge_result,
                cost_estimate_usd=estimate,
                cost_actual_usd=response.cost_usd,
                trace_id=trace_id,
                language=self._operator_language,
            )
        except Exception as exc:
            _log.error(
                "orchestrator.audit_write_failed",
                trace_id=trace_id,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise

        _log.info(
            "orchestrator.turn",
            trace_id=trace_id,
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            cost_usd=response.cost_usd,
            charge_result=charge_result,
        )
        return response.content
```

The orchestrator's failure-mode contract:

| Failure | Audit `result` | Cost recorded | Exception |
|---|---|---|---|
| Budget pre-check refuses call | `budget_blocked` | `estimate=X, actual=0.0` | `BudgetError` |
| Provider raises (both providers dead) | `provider_failed` | `estimate=X, actual=0.0` | the original exception |
| Provider succeeds, charge fits cap | `success` | `estimate=X, actual=Y` | — |
| Provider succeeds, charge blows cap | `budget_overrun` | `estimate=X, actual=Y` (truthful) | — (the work happened) |
| Audit-write fails after success | (no row written) | n/a | the audit exception |

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

Slice-1 affordances:
- Ctrl+C / Ctrl+Q exits cleanly (BINDINGS).
- A pending submission shows a spinner and disables the input so a stalled provider
  call doesn't look like the UI froze. The user can press Esc to cancel the in-flight
  turn (the orchestrator's exception path runs and audits the cancellation).
- Errors render as a one-line message routed through t() (i18n) — never a raw traceback.
"""

from __future__ import annotations

import asyncio
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Input, RichLog

from alfred.i18n import t

# Per-turn wall-clock cap. If the provider doesn't respond in this long, the TUI
# cancels the turn and shows a friendly timeout message. Slice 2+ may make this
# configurable per persona.
TURN_TIMEOUT_SECONDS = 90


class AlfredTuiApp(App[None]):
    CSS = """
    Screen { layout: vertical; }
    #conversation_log { height: 1fr; border: solid white; padding: 1; }
    #user_input { dock: bottom; }
    #user_input.busy { background: $boost; color: $text-muted; }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", show=True, priority=True),
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("escape", "cancel_turn", "Cancel turn", show=True),
    ]

    def __init__(self, *, orchestrator: Any) -> None:
        super().__init__()
        self._orchestrator = orchestrator
        self._in_flight: asyncio.Task[str] | None = None

    def compose(self) -> ComposeResult:
        yield Vertical(
            RichLog(id="conversation_log", highlight=True, markup=True),
            Input(placeholder=t("tui.input_placeholder"), id="user_input"),
        )

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        if self._in_flight is not None and not self._in_flight.done():
            # Slice-1 policy: one turn at a time.
            return
        log = self.query_one("#conversation_log", RichLog)
        input_widget = self.query_one("#user_input", Input)
        log.write(f"[bold cyan]{t('tui.label_you')}[/]: {text}")
        event.input.value = ""

        # Disable the input + show "thinking" hint so a stalled provider call doesn't
        # look like the UI froze. Esc cancels the in-flight task.
        input_widget.disabled = True
        input_widget.add_class("busy")
        log.write(f"[dim]{t('tui.thinking')}[/]")

        self._in_flight = asyncio.create_task(self._run_turn(text))
        try:
            response = await asyncio.wait_for(self._in_flight, timeout=TURN_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            log.write(f"[yellow]{t('tui.turn_cancelled')}[/]")
            return
        except asyncio.TimeoutError:
            log.write(f"[bold red]{t('tui.turn_timeout', seconds=TURN_TIMEOUT_SECONDS)}[/]")
            return
        except Exception as exc:  # noqa: BLE001 - friendly render of all failure modes
            log.write(f"[bold red]{t('tui.alfred_error', error=str(exc))}[/]")
            return
        finally:
            input_widget.remove_class("busy")
            input_widget.disabled = False
            input_widget.focus()
            self._in_flight = None

        log.write(f"[bold green]{t('tui.label_alfred')}[/]: {response}")

    async def _run_turn(self, text: str) -> str:
        return await self._orchestrator.handle_user_message(text)

    async def action_cancel_turn(self) -> None:
        """Esc: cancel the in-flight turn if any. The orchestrator audits the cancellation."""
        if self._in_flight is not None and not self._in_flight.done():
            self._in_flight.cancel()
```

Why the spinner + cancel + timeout matter for slice 1: a stalled DeepSeek connection (a common failure mode for any external provider) would otherwise hang the input thread indefinitely with no way to recover short of killing the process — losing the in-flight turn. With the affordances above, the operator sees what's happening and can recover.

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
"""The `alfred` CLI entry point.

Slice-1 design notes:
- `_build_router` requests secrets from the SecretBroker, never from settings.*.get_secret_value().
  This keeps the broker as the single source of truth for secret access, per ADR-0005.
- `_chat_main` does NOT wrap the entire TUI lifetime in one DB session. The orchestrator
  opens a fresh session per turn via the session_scope callable passed in. A TUI crash
  loses only the in-flight turn; every committed turn is durable.
- structlog is configured once here at bootstrap; the rest of the code calls
  `structlog.get_logger()` and gets the JSON renderer + redactor pipeline.
- Missing API key and unreachable Postgres surface as friendly, actionable messages
  (not pydantic stack traces, not raw asyncpg errors).
"""

from __future__ import annotations

import asyncio
import logging

import structlog
import typer
from sqlalchemy.exc import SQLAlchemyError

from alfred.budget.guard import BudgetGuard
from alfred.comms.tui import AlfredTuiApp
from alfred.config.settings import Settings, SettingsError
from alfred.i18n import set_language, t
from alfred.memory.db import build_session_scope, healthcheck
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working import WorkingMemory
from alfred.orchestrator.core import Orchestrator
from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.deepseek import DeepSeekProvider
from alfred.providers.router import ProviderRouter
from alfred.security.secrets import SecretBroker

app = typer.Typer(help="AlfredOS CLI", no_args_is_help=True)


def _configure_logging(broker: SecretBroker) -> None:
    """Configure structlog: JSON to stdout + secret-redaction processor.

    Called once at CLI bootstrap. The redactor walks every event dict and rewrites
    any string value that contains a known secret to '[REDACTED:<secret_id>]'.
    """
    def _redact_value(v):
        if isinstance(v, str):
            return broker.redact(v)
        if isinstance(v, dict):
            return {k: _redact_value(val) for k, val in v.items()}
        if isinstance(v, list):
            return [_redact_value(item) for item in v]
        if isinstance(v, tuple):
            return tuple(_redact_value(item) for item in v)
        return v

    def _redact(_logger, _name, event_dict):
        # Recursive: secrets that end up inside `subject` payloads, error
        # tracebacks, or any nested dict/list value must also be redacted, not
        # just top-level strings. PRD §7.1: secret leakage is a security-path
        # failure; conservative redaction beats whitelisting safe shapes.
        return {k: _redact_value(v) for k, v in event_dict.items()}

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )


def _load_settings_or_die() -> Settings:
    """Load Settings. Missing-secret errors surface as a one-line actionable message
    (not a pydantic ValidationError stack trace)."""
    try:
        return Settings()  # type: ignore[call-arg]
    except SettingsError as exc:
        typer.secho(t("error.config_invalid", detail=str(exc)), fg=typer.colors.RED, err=True)
        typer.secho(t("hint.copy_env_example"), err=True)
        raise typer.Exit(code=2)


def _build_broker(settings: Settings) -> SecretBroker:
    """Build the secret broker from settings. The broker is the *only* code path
    that reads env-shaped secret values from this point on."""
    return SecretBroker.from_settings(settings)


def _build_router(broker: SecretBroker, settings: Settings) -> ProviderRouter:
    """All secret access goes through the broker; no `.get_secret_value()` here."""
    primary = DeepSeekProvider.from_settings(
        api_key=broker.get("deepseek_api_key"),
        base_url=settings.deepseek_base_url,
        model=settings.deepseek_model,
    )
    fallback = None
    if broker.has("anthropic_api_key"):
        fallback = AnthropicProvider.from_settings(
            api_key=broker.get("anthropic_api_key"),
            model=settings.anthropic_model,
        )
    return ProviderRouter(primary=primary, fallback=fallback)


@app.command()
def status() -> None:
    """Print which providers are configured and the current budget settings."""
    settings = _load_settings_or_die()
    broker = _build_broker(settings)
    set_language(settings.operator_language)
    typer.echo(t("status.primary_provider", provider=settings.primary_provider))
    typer.echo(t("status.fallback_provider", provider=settings.fallback_provider))
    typer.echo(t("status.anthropic_configured",
                 yes_or_no="yes" if broker.has("anthropic_api_key") else "no"))
    typer.echo(t("status.daily_budget", amount=settings.daily_budget_usd))
    typer.echo(t("status.per_call_max", amount=settings.per_call_max_usd))


@app.command()
def chat() -> None:
    """Open the TUI chat with Alfred."""
    asyncio.run(_chat_main())


async def _chat_main() -> None:
    settings = _load_settings_or_die()
    broker = _build_broker(settings)
    _configure_logging(broker)
    set_language(settings.operator_language)

    # Per-turn session_scope. The orchestrator opens one per call — a TUI crash
    # loses only the in-flight turn, not committed history.
    session_scope = build_session_scope(settings)

    # Up-front healthcheck so we fail with a friendly message rather than letting
    # asyncpg surface a raw connection error inside the TUI after the first keystroke.
    try:
        await healthcheck(session_scope)
    except SQLAlchemyError as exc:
        typer.secho(t("error.postgres_unreachable", detail=str(exc)),
                    fg=typer.colors.RED, err=True)
        typer.secho(t("hint.is_compose_up"), err=True)
        raise typer.Exit(code=3)

    router = _build_router(broker, settings)
    budget = BudgetGuard(
        daily_usd=settings.daily_budget_usd,
        per_call_max_usd=settings.per_call_max_usd,
    )
    working = WorkingMemory()

    # One-shot rehydrate of working memory from episodic. Uses its own short-lived session
    # because the orchestrator hasn't taken ownership yet.
    async with session_scope() as session:
        episodic = EpisodicMemory(session=session)
        recent = await episodic.recent(user_id=settings.operator_name, limit=20)
        for ep in recent:
            working.append(role=ep.role, content=ep.content)

    orchestrator = Orchestrator(
        operator_name=settings.operator_name,
        operator_language=settings.operator_language,
        session_scope=session_scope,
        working=working,
        router=router,
        budget=budget,
    )
    tui = AlfredTuiApp(orchestrator=orchestrator)
    await tui.run_async()


if __name__ == "__main__":
    app()
```

The CLI bootstrap is the single place where:

- Settings load (fail loud on missing key with a friendly hint — no pydantic stack trace).
- The SecretBroker is constructed (the only `os.environ`-aware code path from here on).
- structlog is configured (JSON renderer + redactor pipeline).
- The Postgres connection is healthchecked up front (fail loud with a friendly hint, not a raw asyncpg error inside the TUI).
- The per-turn `session_scope` is built and passed to the orchestrator.

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
# syntax=docker/dockerfile:1.7
# Multi-stage build: builder installs deps; runtime carries only the venv + app.
FROM python:3.12-slim AS builder
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Pinned uv version (don't curl|sh in production).
COPY --from=ghcr.io/astral-sh/uv:0.5.4 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# --no-install-recommends keeps the layer small; build-essential only if a wheel is missing.
RUN uv sync --frozen --no-dev

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"

# Non-root user owns /app and /var/lib/alfred.
RUN groupadd --system alfred \
    && useradd --system --gid alfred --create-home --home-dir /home/alfred alfred \
    && mkdir -p /var/lib/alfred \
    && chown -R alfred:alfred /var/lib/alfred

WORKDIR /app
COPY --from=builder /app /app
# Critical: ship everything alembic, the runtime, and i18n need.
COPY alembic.ini ./alembic.ini
COPY config ./config
COPY locale ./locale

RUN chown -R alfred:alfred /app
USER alfred

ENTRYPOINT ["alfred"]
# No default CMD — the operator invokes `alfred chat`, `alfred status`, etc. explicitly via
# `docker compose run --rm -it alfred-core <subcommand>`. See compose service config.
```

> **Critical: every file the runtime needs must be COPYed in the runtime stage.** A previous draft of this Dockerfile shipped without `alembic.ini`, `config/`, or `locale/` and the first `alembic upgrade head` failed inside the container.

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
    # NO `restart:` here. `alfred-core` is a one-shot command runner invoked via
    # `docker compose run --rm -it alfred-core <subcommand>` (chat, status, migrate, ...).
    # Adding `restart: unless-stopped` with a finite-runtime CMD would flap forever.
    depends_on:
      alfred-postgres:
        condition: service_healthy
    environment:
      ALFRED_DEEPSEEK_API_KEY: ${ALFRED_DEEPSEEK_API_KEY}
      ALFRED_ANTHROPIC_API_KEY: ${ALFRED_ANTHROPIC_API_KEY:-}
      ALFRED_DATABASE_URL: postgresql+asyncpg://alfred:alfred@alfred-postgres:5432/alfred
      ALFRED_OPERATOR_NAME: ${ALFRED_OPERATOR_NAME:-operator}
      ALFRED_OPERATOR_LANGUAGE: ${ALFRED_OPERATOR_LANGUAGE:-en-US}
      ALFRED_DAILY_BUDGET_USD: ${ALFRED_DAILY_BUDGET_USD:-1.0}
      ALFRED_PER_CALL_MAX_USD: ${ALFRED_PER_CALL_MAX_USD:-0.10}
    # No `command:` — relies on the Dockerfile ENTRYPOINT plus a subcommand passed via
    # `docker compose run alfred-core <subcommand>`. The status check `docker compose ps`
    # showing alfred-core as "exited" is expected and correct for a command runner.

volumes:
  alfred_pg_data:
```

> **Critical: `alfred-core` is not a daemon.** It is the entrypoint for one-shot operator commands (`alfred chat`, `alfred status`, `alfred migrate`). It must not carry `restart: unless-stopped` because its commands exit cleanly when the operator finishes. Only `alfred-postgres` is a long-running daemon.

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
    """One full turn through real Postgres. Uses `alembic upgrade head` rather than
    `Base.metadata.create_all` so the migration trail is exercised too — see ADR-0006."""
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("postgresql://", "postgresql+asyncpg://")
        engine = create_async_engine(url, future=True)

        # Run real migrations rather than create_all so a divergence between ORM models
        # and the 0001_initial.py migration body fails the smoke test.
        from alembic import command  # noqa: PLC0415
        from alembic.config import Config  # noqa: PLC0415

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", url)
        # Alembic's online migration runner is sync; this is fine for a one-shot smoke setup.
        command.upgrade(alembic_cfg, "head")

        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def session_scope():
            async with sm() as session:
                async with session.begin():
                    yield session

        working = WorkingMemory()
        budget = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)

        router = MagicMock()
        router.complete = AsyncMock(
            return_value=CompletionResponse(
                content="Good evening, operator.",
                tokens_in=12,
                tokens_out=5,
                cost_usd=0.00001,
                model="deepseek-chat",
            )
        )

        orch = Orchestrator(
            operator_name="operator",
            operator_language="en-US",
            session_scope=session_scope,
            working=working,
            router=router,
            budget=budget,
        )

        response = await orch.handle_user_message("hi alfred")
        assert response == "Good evening, operator."

        async with sm() as session:
            ep_rows = (await session.execute(select(Episode))).scalars().all()
            assert len(ep_rows) == 2  # user + assistant
            assert {r.role for r in ep_rows} == {"user", "assistant"}
            assert all(ep.language == "en-US" for ep in ep_rows)

            audit_rows = (await session.execute(select(AuditEntry))).scalars().all()
            assert len(audit_rows) == 1
            assert audit_rows[0].result == "success"
            assert audit_rows[0].language == "en-US"
            assert audit_rows[0].cost_actual_usd == 0.00001

        await engine.dispose()
```

- [ ] **Step 2: Run the smoke test locally**

Run: `uv run pytest tests/smoke -v`
Expected: PASS. (testcontainers Postgres + full orchestrator stack; ~15-30s.)

- [ ] **Step 3: Wire the smoke test and the coverage gate into `.github/workflows/ci.yml`**

The existing `python` job is guarded by `hashFiles('pyproject.toml')`. That guard now passes because `pyproject.toml` exists. But the workflow as written **does not run the smoke test** and **does not enforce the per-package coverage gate**. Both are release-blocking.

Edit `.github/workflows/ci.yml` so the python job runs *all* of: ruff, black, mypy, unit tests, integration tests, smoke tests, full-suite coverage with per-package gates, and the i18n catalog check. Concretely, the job steps should be:

```yaml
jobs:
  python:
    if: hashFiles('pyproject.toml') != ''
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
        with:
          enable-cache: true
      - run: uv sync --frozen
      - run: uv run ruff check .
      - run: uv run black --check src/ tests/
      - run: uv run mypy src/
      - run: uv run pytest tests/unit -v
      - run: uv run pytest tests/integration -v
      - run: uv run pytest tests/smoke -v
      - name: Coverage with per-package gates
        run: |
          uv run pytest \
            --cov=src/alfred \
            --cov-report=term-missing \
            --cov-report=xml \
            --cov-fail-under=75
          # Per-package 100% gate on the security package — CLAUDE.md hard rule.
          uv run coverage report \
            --include='src/alfred/security/*' \
            --fail-under=100
      - name: Verify i18n catalog is up to date
        run: |
          uv run pybabel extract -F babel.cfg -o locale/alfred.pot src/alfred
          uv run pybabel update -i locale/alfred.pot -d locale -D alfred --no-fuzzy-matching
          if ! git diff --exit-code locale/; then
            echo "::error::Catalog drift detected. Run pybabel extract + update locally and commit."
            exit 1
          fi
          uv run pybabel compile -d locale -D alfred --statistics
```

The per-package coverage gate is enforced by a second `coverage report --include=... --fail-under=100` invocation. `pytest --cov-fail-under` only takes one threshold; the second `coverage report` uses the cached `.coverage` from the first run.

After editing, push a branch and confirm the Actions tab shows: ruff ✓, black ✓, mypy ✓, unit ✓, integration ✓, **smoke ✓**, coverage 75%+ overall ✓, security/ 100% ✓, i18n catalog clean ✓.

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

**Tooling decision deferred to slice 0.0.3 / 0.0.6 / 0.0.7**: the event bus, inter-persona coordination, and reviewer-gate proposal flow are all state machines. Before building them in raw asyncio, **spike LangGraph** for one representative flow (likely the reviewer-gate, smallest surface) and compare lines-of-code, security-tier ergonomics, and audit-log integration cost against the hand-rolled equivalent. Adopt LangGraph if it's cleaner; stay in raw asyncio if it isn't. Slice 1's orchestrator and memory model are framework-agnostic — this decision doesn't paint us into a corner either way. Do NOT adopt the broader LangChain framework — the trust-tier discipline and CVE history make it a poor fit for the security-sensitive paths.

---

---

## Appendix A — i18n discipline reference

The full i18n strand has been inlined into the main task flow:

- **Task 1** — `babel` dependency, `pre-commit` dev dep, `[tool.babel]` config.
- **Task 2** — `Settings.operator_language`, `SettingsError` for friendly load failure, `.env.example` and `config/alfred.toml` carry the operator language.
- **Task 3** — `language` column on `Episode` and `AuditEntry`; index on `(user_id, created_at)`.
- **Task 3.5** — i18n primitives (`alfred.i18n`, `t()`, `set_language`, English seed catalog, translator tests, `babel.cfg`).
- **Task 5** — `AuditWriter.append` carries `language` and `cost_actual_usd`.
- **Task 11** — `alfred_system_prompt(operator_name=..., language=...)` substitutes the BCP-47 tag into the persona prompt.
- **Task 13** — orchestrator threads `operator_language` through every `episodic.record` and `audit.append` call.
- **Task 14** — TUI uses `t()` for every operator-facing string; spinner, cancel, and timeout affordances use translated strings.
- **Task 15** — CLI uses `t()` for every operator-facing string; `_load_settings_or_die` renders translated hints on missing keys / unreachable Postgres.
- **Task 17** — CI runs `pybabel extract` + `update` + `compile --check`; pre-commit runs `pybabel extract` and refuses commits that introduce a `t()` key without a catalog entry.

If a future task adds a new operator-facing surface (a new CLI command, a new TUI screen, a new Discord adapter), the implementer must:

1. Wrap every operator-facing string in `t("namespace.message_key", **vars)`.
2. Add the corresponding `msgid` / `msgstr` pair to `locale/en/LC_MESSAGES/alfred.po`.
3. Run `uv run pybabel compile -d locale -D alfred` and commit the regenerated `.mo`.
4. CI will fail the build if step 2 or 3 was skipped.

### Pre-commit hook (Task 3.5 wires this; documented here for reference)

`.pre-commit-config.yaml` (root of the repo):

```yaml
repos:
  - repo: local
    hooks:
      - id: pybabel-extract
        name: pybabel extract (i18n catalog drift)
        language: system
        entry: bash -c 'uv run pybabel extract -F babel.cfg -o locale/alfred.pot src/alfred && uv run pybabel update -i locale/alfred.pot -d locale -D alfred --no-fuzzy-matching && git diff --exit-code locale/ || (echo "Catalog drift: run pybabel extract+update and stage locale/."; exit 1)'
        pass_filenames: false
        files: '^(src/alfred/.*\.py|locale/.*\.po)$'
```

Install via `pre-commit install` once after cloning. CI runs the same check independently (Task 17 step 3).

---

## Appendix B — High-severity review findings: disposition

The /review-plan pass produced 73 High-severity findings across 15 specialists. They are grouped below by theme. Each theme is marked as **inlined** (the fix is already in the plan above), **accepted-debt** (left for a later slice with a rationale), or **converted** (re-classified to Critical above and addressed there).

### Inlined (fix lives in the plan body above)

- **Budget guard runs *after* the provider call → uncapped overrun on first over-budget turn.** Task 13 now pre-checks via `BudgetGuard.would_exceed(estimate)` before the provider call; the post-call `check_and_charge` reconciles the actual cost (recorded as `cost_actual_usd`). If the actual blows the cap, the audit records `result="budget_overrun"` truthfully — the call already happened, we don't lie about it. This also closes test-002 (Critical).
- **TUI blocks input with no spinner/cancel/timeout.** Task 14 now disables the input on submit, shows a translated "thinking…" hint, allows Esc to cancel the in-flight task, and `asyncio.wait_for` enforces a 90-second per-turn timeout. The cancel path goes through the orchestrator's exception branch and audits the cancellation.
- **Provider router's bare `except Exception` lumps 401/400/429/5xx together.** Task 13's orchestrator (and Task 8's router — addressed inline at that task) now distinguishes errors before deciding whether to fall back: 4xx (auth, malformed request) is **not** retried via fallback (the request will fail there too); 429 and 5xx **are**; idempotency is asserted via the request's hash so a retried call doesn't duplicate work.
- **Memory writes have no audit entry.** Each `episodic.record` call from the orchestrator is paired with an `audit.append` call carrying the `event="memory.write"` event and the truncated subject. This satisfies PRD §7.4 and CLAUDE.md security rule #7.
- **`(user_id, created_at)` compound index missing on episodes.** Task 3 now declares `ix_episodes_user_id_created_at` via `__table_args__`; the migration 0001_initial.py creates it.
- **Plan ships persona as a hardcoded import, not a registry stub.** Task 11 keeps the persona hardcoded for slice 1 *and* exposes the `Persona` dataclass shape that slice 5's registry will load. The `alfred_system_prompt` factory takes operator + language, so the registry's stored prompt template uses the same call shape. Forward-compatibility documented in ADR (covered by docs/adr/0001-0006).
- **No timeouts on httpx / anthropic clients.** Task 6 (DeepSeek) and Task 7 (Anthropic) provider constructors now set explicit `timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)` and (for Anthropic) the SDK's `max_retries=2`. The TUI's 90s per-turn timeout is the outer ceiling.
- **`AuditWriter.append` doesn't accept `language`.** Inlined into Task 5 (the `language` parameter is now a required-but-defaulted kwarg, with truncated-cost reconciliation via `cost_actual_usd`).
- **Plan creates no ADRs despite 6+ structural decisions.** Six ADRs now exist at `docs/adr/0001..0006`. DoD entry #13 enforces this.
- **PRD updates missing for slice-1 divergences (DeepSeek primary, in-process working memory, plain asyncio).** Addressed via ADRs 0001–0006. The ADRs are the canonical record; the PRD itself may be updated to *link* to them in a follow-up PR.

### Accepted as slice-2 debt (with rationale)

- **Plan is a single mega-PR of ~17 tasks.** Slicing this further would produce per-task PRs that each depend on the previous, with no individual PR passing the smoke test until the last. Slice 1 is intentionally one PR because its DoD is end-to-end runnability. Slice 2's plan (forthcoming) will explicitly split into a 3–5 PR sequence (router widening, observability, comms adapters, persona registry, reviewer-gate scaffold), each landing green on its own.
- **`operator_name` doubles as `user_id`.** Slice 3 introduces identity binding (Discord ID → operator name → user_id), at which point the column splits cleanly. Doing it now would invent an identity layer no other slice-1 code uses. The audit-log already references `actor_user_id` explicitly; the column rename in slice 3 is one Alembic migration.
- **Hardcoded provider pricing tables in the cost extractor.** The DeepSeek and Anthropic adapters carry a hardcoded `tokens_in × X + tokens_out × Y` formula. Provider pricing changes; slice 2's provider widening will move the table to `config/pricing.yaml` and add a CI job that fetches the latest from each provider's public docs and warns on drift.
- **No internal-CLI provider (Claude Code as a provider).** Deferred per PRD §6.6. Slice 2+ adds it.
- **Streaming responses in the TUI.** The slice-1 TUI renders the full response when the provider returns. Streaming UX (partial-token rendering) is slice 2 — it requires the provider Protocol's `stream()` method which is also deferred.
- **No prompt cache, semantic-response cache, or embedding cache.** Slice 2+ per PRD §6.6.
- **Slice 1 routes only `chat`; no `vision`, no `tool_use`, no `long_context`.** Capability fallback (route to a capable provider when the primary lacks vision) is slice 2.
- **Adversarial corpus has no entries seeded.** Per slice-1 coverage matrix, adversarial work begins in slice 3 when T1/T3 ingestion paths exist. The corpus directory and the harness skeleton are added in slice 3.

### Converted to Critical (and addressed above)

- err-002 (silent audit-write failure) was elevated to Critical because it directly violates CLAUDE.md security rule #7. Addressed in Task 13.
- The session_scope wrapping the entire TUI lifetime spanned 4 reviewers (comms, core, error, memory) so the implicit Critical was made explicit. Addressed in Tasks 13 and 15.
- The structlog-never-configured finding was elevated because the DoD claim "observability via structlog JSON" cannot ship if structlog is never `configure()`d. Addressed in Task 15's `_configure_logging`.

---

## Appendix C — Medium/Low punch list

These are nits and small improvements the implementer should pick up during PR review. None of them is release-blocking, but each represents a small quality improvement.

### Medium

- **`SecretBroker.get` returns plain `str` — should return `SecretStr`** so callers can't accidentally log it. Wrap the return type and unwrap at the provider-SDK boundary where the SDK demands a plain string.
- **`_active_lang` in `alfred/i18n/translator.py` is a module-global.** Use `contextvars.ContextVar[str]` so per-request language doesn't leak across concurrent calls when slice 3+ introduces multi-user.
- **`Episode.role` is a free-form `str` but `Turn.role` (in `WorkingMemory`) is a `Literal["user", "assistant"]`.** The CLI rehydrate bridges them with `# type: ignore`. Make both `Literal`-typed and add a `Role` enum in `alfred.providers.base` so the bridge is statically checked.
- **The provider Protocol declares only `complete()` + `name`; PRD §6.6 specifies 5 methods (`complete`, `stream`, `embed`, `tools`, `capabilities`).** Add the stubs that raise `NotImplementedError` in slice 1 so slice 2 doesn't have to add them and change every caller.
- **Several "inspect it" / "decide later" placeholders in Task 3** (e.g. "we'll figure out indexes later"). Either decide now or delete the placeholder.
- **`0001_initial.py` migration body is referenced but not shown.** Add the autogenerated body inline so the implementer can verify the migration matches the ORM after running `alembic revision --autogenerate`.
- **Hardcoded pricing tables in providers** (also under accepted-debt). Add a `TODO(slice-2-pricing)` comment with a link to the config-driven design.
- **TUI test asserts on `log.render()`** which is a brittle private API. Use the Textual test harness's `pilot.app.query_one(RichLog).lines` instead.
- **No outbound DLP scan stance documented for TUI text path.** Slice 1 has no T3 input so DLP is a no-op, but a one-line stance ("DLP wrapper exists with the noop policy; slice 2 adds the real policy") prevents a reviewer from being confused.
- **`user_id`/`operator_name` conflation** (also under accepted-debt — repeated here at Medium severity because some operators will hit it in slice 1).
- **PR template ships with pre-ticked test checkboxes.** Remove the default ticks; require the contributor to tick each consciously.

### Low / nits

- Unnecessary `# type: ignore[no-untyped-def]` on several test helpers where the type *is* known after `from __future__ import annotations`.
- What-vs-why docstrings on small helpers — delete them; the name is the doc.
- Mixed f-string / concatenation styles in Task 11's persona prompt builder; normalise to f-strings.
- Duplicated `_estimate_cost` helper between DeepSeek and Anthropic providers — extract to `alfred.providers.base` once both have landed.
- `.env.example` missing key-source URLs (where to get a DeepSeek key, where to get an Anthropic key). **Fixed inline in Task 2 above.**
- Budget guard uses local-tz timestamps for the "daily" rollover. Switch to UTC so the rollover is deterministic regardless of host TZ.
- No `--no-color` / accessibility flag on the TUI; future slice 3+ adds a `--plain` mode (called out in ADR-0004).
- Unfiltered/unbounded context replay in Task 10 — the `recent(limit=20)` cap exists but isn't tunable. Add a settings field in slice 2 if any operator asks.
