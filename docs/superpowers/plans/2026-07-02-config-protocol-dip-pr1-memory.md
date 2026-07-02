# Config-consumer DIP — PR1 (memory) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Narrow the `memory/db.py` config consumers from the concrete `Settings` god-object to a narrow read-only `MemoryDbConfig` Protocol, and land the project-wide convention + the structural-satisfaction mechanism-proof that the remaining batches (egress, providers, plugins, security) build on.

**Architecture:** Add `src/alfred/memory/_config_protocols.py` with a single `@property`-based read-only `Protocol` (`MemoryDbConfig`) exposing only `database_url`. Re-type `make_engine` / `make_session_factory` / `build_session_scope` to consume it. Real `Settings` satisfies the Protocol structurally (PEP 544), so every existing caller (composition root + integration tests) is unchanged and there is **zero runtime behaviour change**. A committed mypy-checked identity-return function proves `Settings` satisfies the Protocol; a stub-based unit test proves the DIP win (trivial doubles). The convention is documented in `docs/python-conventions.md`.

**Tech Stack:** Python 3.12+, Pydantic v2 (`PostgresDsn`), SQLAlchemy 2.0 async, `typing.Protocol`, pytest + pytest-asyncio, mypy `--strict`, pyright, ruff.

## Global Constraints

- **Design source of truth:** `docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md` (#351).
- **Zero runtime behaviour change.** Pure typing/DIP refactor. Existing tests pass unchanged.
- **`Settings` is not modified.** It stays a `BaseSettings`; it only *satisfies* the new Protocol.
- **Boundary:** only leaf consumers narrow; the composition root (`cli/`, `bootstrap/`, loader, `Settings` def) keeps concrete `Settings`. `memory/db.py`'s three functions are leaf consumers.
- **Read-only intent via `@property`** getters; satisfied by `Settings`' attribute and a plain stub.
- **`memory/db.py` has no config validator** on `database_url` (it is a plain `PostgresDsn` field) — so no real-`Settings` validator-retention test is required for this batch (unlike egress/security later).
- **Modern typing:** PEP 604/585/695; no `Optional[X]`/`typing.List`; `from __future__ import annotations` at file top (matches the repo).
- **Commit trailer (every commit):**

  ```
  MrReasonable <4990954+MrReasonable@users.noreply.github.com>
  Claude-Session: https://claude.ai/code/session_01LbUbRZZj1th4ubjSk7Xm5g
  ```

- **Conventional Commits** with a literal `#351` in every commit subject.
- **Branch:** `351-config-protocol-dip` (the spec is already committed here).

---

## File Structure

- `src/alfred/memory/_config_protocols.py` — **Create.** Holds `MemoryDbConfig` (the subsystem's narrow config Protocols module).
- `src/alfred/memory/db.py` — **Modify.** Re-type the 3 consumers; drop the now-unused `Settings` import.
- `tests/unit/memory/test_config_protocol_proof.py` — **Create.** The mechanism-proof (Settings satisfies) + the plain-stub DIP-win test.
- `tests/unit/memory/test_db.py` — **Modify.** Add a stub-based `make_engine` test (proves it reads only `database_url`).
- `docs/python-conventions.md` — **Modify.** Add the "Config consumers depend on narrow read-only Protocols" convention after `### Protocols over ABCs`.

---

### Task 1: `MemoryDbConfig` Protocol + the structural-satisfaction proof

**Files:**

- Create: `src/alfred/memory/_config_protocols.py`
- Create: `tests/unit/memory/test_config_protocol_proof.py`

**Interfaces:**

- Produces: `alfred.memory._config_protocols.MemoryDbConfig` — a `Protocol` with a read-only `database_url: PostgresDsn` property. Consumed by Task 2 (`db.py`) and the proof test.

- [ ] **Step 1: Write the Protocol module**

Create `src/alfred/memory/_config_protocols.py`:

```python
"""Narrow read-only config Protocols for the memory subsystem (#351).

Design: docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md. Consumers
depend on exactly the config fields they read; the real ``Settings`` satisfies these
structurally (PEP 544), so a test double is a trivial stub rather than a full
``Settings``. See docs/python-conventions.md "Config consumers depend on narrow
read-only Protocols".
"""

from __future__ import annotations

from typing import Protocol

from pydantic import PostgresDsn


class MemoryDbConfig(Protocol):
    """The config surface the memory engine / session factory reads: just the DSN.

    Producer invariant: ``Settings.database_url`` is a validated ``PostgresDsn`` with a
    default and **no** normalizer, so a stub may supply any ``PostgresDsn`` directly
    without reproducing a validator.
    """

    @property
    def database_url(self) -> PostgresDsn: ...
```

- [ ] **Step 2: Write the proof + stub test**

Create `tests/unit/memory/test_config_protocol_proof.py`:

```python
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
```

- [ ] **Step 3: Run the proof test + type-check to verify they pass**

Run: `uv run pytest tests/unit/memory/test_config_protocol_proof.py -v`
Expected: PASS (1 test: `test_plain_stub_satisfies_memory_db_config`).

Run: `uv run mypy src/alfred/memory/_config_protocols.py tests/unit/memory/test_config_protocol_proof.py`
Expected: `Success: no issues found`. (If mypy reports `Settings` does not satisfy `MemoryDbConfig`, the Protocol shape is wrong — fix the Protocol, not the proof.)

- [ ] **Step 4: Commit**

```bash
git add src/alfred/memory/_config_protocols.py tests/unit/memory/test_config_protocol_proof.py
git commit -m "feat(memory): add MemoryDbConfig read-only Protocol + satisfaction proof (#351)"
```

---

### Task 2: Narrow `db.py`'s three consumers to `MemoryDbConfig`

**Files:**

- Modify: `src/alfred/memory/db.py` (functions at lines 36, 72, 97; import at line 15)
- Modify: `tests/unit/memory/test_db.py`

**Interfaces:**

- Consumes: `MemoryDbConfig` from Task 1.
- Produces: `make_engine(config: MemoryDbConfig) -> AsyncEngine`, `make_session_factory(config: MemoryDbConfig) -> async_sessionmaker[AsyncSession]`, `build_session_scope(config: MemoryDbConfig)`. Callers passing a real `Settings` are unaffected.

- [ ] **Step 1: Write the failing stub-based test**

Add to `tests/unit/memory/test_db.py` (inside the file, e.g. after `TestEngineRegistry`):

```python
class TestConsumersAcceptNarrowConfig:
    async def test_make_engine_reads_only_database_url_from_a_stub(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """make_engine consumes MemoryDbConfig — a plain stub with just database_url."""
        from pydantic import PostgresDsn

        captured: list[str] = []

        def _fake_engine_for_url(url: str) -> object:
            captured.append(url)
            return object()

        monkeypatch.setattr(db_mod, "_engine_for_url", _fake_engine_for_url)

        class _StubCfg:
            database_url = PostgresDsn("postgresql+asyncpg://alfred:alfred@db:5432/alfred")

        db_mod.make_engine(_StubCfg())  # type-checks iff make_engine takes MemoryDbConfig
        assert captured == ["postgresql+asyncpg://alfred:alfred@db:5432/alfred"]
```

- [ ] **Step 2: Run it to confirm it passes structurally but the type-check fails**

Run: `uv run pytest tests/unit/memory/test_db.py::TestConsumersAcceptNarrowConfig -v`
Expected: PASS at runtime (Python is duck-typed).

Run: `uv run mypy src/alfred/memory/db.py tests/unit/memory/test_db.py`
Expected: FAIL — `Argument 1 to "make_engine" has incompatible type "_StubCfg"; expected "Settings"`. This is the red state: `make_engine` still demands concrete `Settings`.

- [ ] **Step 3: Narrow the three consumers + drop the unused import**

In `src/alfred/memory/db.py`:

Replace the import (line 15):

```python
# before:
from alfred.config.settings import Settings
# after:
from alfred.memory._config_protocols import MemoryDbConfig
```

Re-type `make_engine` (line 36) — signature only, body unchanged:

```python
def make_engine(config: MemoryDbConfig) -> AsyncEngine:
    """Return a cached async engine for ``config.database_url``.
    ... (keep the existing docstring body; s/settings/config/ in the prose) ...
    """
    return _engine_for_url(config.database_url.unicode_string())
```

Re-type `make_session_factory` (line 72):

```python
def make_session_factory(config: MemoryDbConfig) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=make_engine(config),
        expire_on_commit=False,
        class_=AsyncSession,
    )
```

Re-type `build_session_scope` (line 97) — keep its existing `# type: ignore[no-untyped-def]` (that ignore is about the untyped return, not config):

```python
def build_session_scope(config: MemoryDbConfig):  # type: ignore[no-untyped-def]
    """Bind `session_scope` to a config-derived factory.
    ... (keep the existing docstring body; s/settings/config/ in the prose) ...
    """
    factory = make_session_factory(config)

    def _scope():  # type: ignore[no-untyped-def]
        return session_scope(factory)

    return _scope
```

- [ ] **Step 4: Run the type-check + the memory unit suite to verify green**

Run: `uv run mypy src/alfred/memory/db.py tests/unit/memory/test_db.py tests/unit/memory/test_config_protocol_proof.py`
Expected: `Success: no issues found`.

Run: `uv run pytest tests/unit/memory/ -v`
Expected: PASS (existing registry/disposal tests + the two new tests).

Run: `uv run ruff check src/alfred/memory/db.py`
Expected: clean — confirms the dropped `Settings` import left no `F401` and nothing else references `Settings` in `db.py`.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/db.py tests/unit/memory/test_db.py
git commit -m "refactor(memory): narrow db.py consumers to MemoryDbConfig (#351)"
```

---

### Task 3: Document the convention

**Files:**

- Modify: `docs/python-conventions.md` (insert after the `### Protocols over ABCs` section, before the next `###` heading)

- [ ] **Step 1: Add the convention subsection**

Insert this immediately after the `### Protocols over ABCs` block in `docs/python-conventions.md`:

````markdown
### Config consumers depend on narrow read-only Protocols

A function that reads config depends on a narrow read-only `Protocol` of exactly the
fields it reads — never the whole `Settings` god-object (DIP; #351, design at
`docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md`). Group a subsystem's
config Protocols in `<subsystem>/_config_protocols.py`; the real `Settings` satisfies
them structurally (PEP 544), so test doubles are trivial stubs.

```python
# memory/_config_protocols.py
from typing import Protocol
from pydantic import PostgresDsn

class MemoryDbConfig(Protocol):
    @property
    def database_url(self) -> PostgresDsn: ...
```

- Use `@property` getters — read-only intent (compile-time only; `Settings` stays
  runtime-mutable), satisfied by `Settings`' attribute *and* a plain stub.
- A `from_settings(...)` that reads ≤k fields is a leaf consumer and narrows too. Only the
  composition root (`cli/`, `bootstrap/`, the loader, the `Settings` definition) keeps
  concrete `Settings`.
- If a consumer's correctness relies on a `Settings` validator/normalizer, retain ≥1
  real-`Settings` test and docstring the producer invariant on the Protocol — a plain stub
  bypasses the validator.
````

- [ ] **Step 2: Verify markdownlint is clean**

Run: `npx --yes markdownlint-cli2 "docs/python-conventions.md"`
Expected: `Summary: 0 error(s)`.

- [ ] **Step 3: Commit**

```bash
git add docs/python-conventions.md
git commit -m "docs(conventions): config consumers depend on narrow read-only Protocols (#351)"
```

---

### Task 4: Full quality gate + open the PR

**Files:** none (verification + PR).

- [ ] **Step 1: Run the full local quality bar**

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: clean.

Run: `uv run mypy src/ && uv run pyright src/`
Expected: both clean. `mypy` with `warn_unused_ignores = true` will fail if any now-redundant `# type: ignore` remains — remove any it flags (none expected in this batch; `build_session_scope`'s `no-untyped-def` ignores stay needed).

Run: `uv run pytest tests/unit/memory -q`
Expected: PASS.

- [ ] **Step 2: Run the memory integration path (zero-behaviour-change proof)**

Run: `uv run pytest tests/integration/memory -q` (boots ephemeral Postgres via testcontainers; passes a real `Settings`, proving `Settings` still satisfies the consumers end-to-end).
Expected: PASS. If testcontainers are unavailable locally, note it and rely on CI's integration lane.

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin 351-config-protocol-dip
gh pr create --base main \
  --title "refactor(memory): config-consumer DIP PR1 — MemoryDbConfig Protocol (#351)" \
  --body "$(cat <<'BODY'
## What
PR1 of the #351 config-consumer DIP pass (design:
docs/superpowers/specs/2026-07-02-config-protocol-dip-design.md). Narrows
memory/db.py's three consumers (make_engine / make_session_factory /
build_session_scope) from the concrete Settings god-object to a narrow read-only
MemoryDbConfig Protocol, and lands the convention + the structural-satisfaction
mechanism-proof the later batches build on.

## Zero behaviour change
Pure typing/DIP refactor. Settings satisfies MemoryDbConfig structurally (PEP 544),
so every caller is unchanged; the memory integration suite passes with a real Settings.

## Follow-ups (later batches, same design)
egress -> providers -> plugins/web_fetch -> security -> optional PGH capstone.

https://claude.ai/code/session_01LbUbRZZj1th4ubjSk7Xm5g
BODY
)"
```

- [ ] **Step 4: Run `/review-pr` + CodeRabbit, resolve every thread, then `gh pr merge --rebase`**

Follow the project cadence: full `/review-pr` fleet + CodeRabbit (both), resolve every thread (`required_conversation_resolution` is on), never `--admin`. Because this touches `src/alfred/memory/**`, the `alfred-memory-engineer` reviewer is auto-included.

---

## Self-Review

**Spec coverage (PR1 slice):**

- Narrow `@property` Protocol grouped in `memory/_config_protocols.py` — Task 1. ✓
- Leaf consumers narrowed; `Settings` import dropped — Task 2. ✓
- Mechanism-proof as a committed mypy-checked artifact, lint-safe home in a test module — Task 1 (`_settings_satisfies` + the stub test). ✓
- Convention doc landed with PR1 — Task 3. ✓
- `warn_unused_ignores` gate + zero-behaviour-change integration proof — Task 4. ✓
- Validator-retention rule: N/A for memory (`database_url` has no normalizer) — stated in Global Constraints, exercised in egress/security batches. ✓

**Placeholder scan:** none — every step shows the actual code/command/expected output.

**Type consistency:** `MemoryDbConfig` name + `database_url: PostgresDsn` property is identical across Task 1 (definition), Task 2 (consumers), Task 3 (doc), and the proof. `make_engine`/`make_session_factory`/`build_session_scope` signatures match between Task 2's Interfaces block and its code.
