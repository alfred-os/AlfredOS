# AlfredOS Python Conventions

This is the canonical reference for Python style, tooling, types, errors, async, testing, and security discipline in AlfredOS. The [`alfred-python-developer`](../.rulesync/subagents/alfred-python-developer.md) subagent applies these conventions without being asked. Human contributors and other AI agents should read it once and refer back.

Where CLAUDE.md hard rules and this doc disagree, CLAUDE.md wins (CLAUDE.md rules are release-blocking).

## Table of contents

1. [Tooling](#tooling)
2. [Project structure](#project-structure)
3. [Types](#types)
4. [Naming](#naming)
5. [Imports](#imports)
6. [Data modelling — Pydantic + dataclasses](#data-modelling--pydantic--dataclasses)
7. [Errors](#errors)
8. [Logging](#logging)
9. [Async](#async)
10. [SOLID applied with judgment](#solid-applied-with-judgment)
11. [Functional patterns](#functional-patterns)
12. [Testing](#testing)
13. [Security boundaries](#security-boundaries)
14. [i18n](#i18n)
15. [Commits and PRs](#commits-and-prs)

---

## Tooling

| Concern | Tool | Why |
|---|---|---|
| Package manager | **`uv`** | Fast, lock-file-first, drop-in replacement for pip + venv + pip-tools |
| Build backend | `hatchling` | Modern PEP 517 backend, simple `src/`-layout support |
| Formatter | **`ruff format`** | Black-compatible output, ~10x faster, one config |
| Linter | **`ruff check`** | Replaces flake8 + isort + pyupgrade + bandit + pylint (mostly) |
| Type checker (primary) | **`mypy --strict`** | Mature, well-known, ecosystem support |
| Type checker (secondary) | **`pyright`** | Catches what mypy misses (especially `strict` mode disagreements). Used by VS Code Pylance |
| Test framework | `pytest` + `pytest-asyncio` | Standard |
| Property tests | **`hypothesis`** | Use where the function under test has algebraic properties (parsers, redactors, serialisers) |
| Integration test infra | `testcontainers[postgres]` | Real Postgres in CI; no mocked DB for integration paths |
| Migrations | `alembic` | ADR-0006 |

**Do not** keep `black` alongside `ruff format`. They overlap; `ruff format` is the future.

### Workflow

One-time per clone:

```bash
make setup        # uv sync --dev + lefthook install (idempotent)
```

Then a two-step development cycle:

```bash
make fix          # auto-format + auto-fixable lint (mutates the tree)
make check        # verify — identical to CI (no mutations)
```

`make check` is the contract. If it passes locally, it should pass in CI. If it fails locally with mutation-recoverable issues (formatter or `--fix`able lint), run `make fix` first then re-run `make check` to verify.

By hand (no make):

```bash
uv run ruff check src tests --fix    # auto-fix lint first (its rewrites can affect formatting)
uv run ruff format src tests         # then format
uv run mypy src
uv run pyright src
uv run pytest tests/unit tests/integration -q   # matches CI; smoke + adversarial are separate
```

`pytest tests/unit tests/integration` matches what CI runs. The smoke and adversarial suites are excluded from `make check` because they require a running stack (smoke) or are nightly release-blockers (adversarial); they live behind dedicated `make test-smoke` and `make test-adversarial` targets.

Integration tests use `testcontainers`, which requires Docker. If `docker info` fails, the integration suite will fail-fast with a clear error — install Docker Desktop (macOS/Windows) or the Docker engine (Linux).

### Ruff rule set

`pyproject.toml` should enable at minimum: `["E", "F", "I", "B", "UP", "N", "S", "ARG", "RET", "SIM", "PTH", "DTZ", "FBT", "PIE", "RUF"]`. Notable selections:

- `S` — flake8-bandit (security) — catches obvious injection and crypto sins
- `RET` — return statements (avoid unnecessary `else` after return)
- `SIM` — simplifications (`if a == True` → `if a`, etc.)
- `PTH` — pathlib over `os.path`
- `DTZ` — timezone-aware datetimes only (we use `datetime.datetime.now(datetime.UTC)`, often via `import datetime as dt` → `dt.datetime.now(dt.UTC)`)
- `FBT` — bool positional args are footguns; require keyword
- `PIE` — misc anti-patterns

Suppressed per-file in `tests/**/*.py`: `S101` (assert) and `ARG` (fixture-driven unused args). The actual `pyproject.toml` ships with Slice 1 Task 1; the rule list here is the target shape it should adopt.

### Pre-push hooks

[`lefthook`](https://github.com/evilmartians/lefthook) (config in [`lefthook.yml`](../lefthook.yml)) runs a **subset** of the CI quality bar on `git push` — failures surface in your terminal before they surface on the PR. Install once per clone:

```sh
brew install lefthook   # or: npm i -g @evilmartians/lefthook
lefthook install
```

**Lefthook runs (no Docker needed):** `ruff format --check`, `ruff check`, `mypy --strict`, `pyright`, `pytest tests/unit -q`.

**CI also runs (require Docker / fuller scope):** `pytest tests/integration` against testcontainers Postgres, plus the i18n catalog freshness check once that gate lands.

So lefthook ≠ CI: lefthook catches the fast failures locally; CI is the source of truth. Don't habituate to `LEFTHOOK=0` — the local gate exists for a reason. CLAUDE.md hard rule #8 (no hook-bypass via `--no-verify`) applies in spirit here.

### CI gates

Every PR to `main` runs required status gates. See [`docs/ci/required-checks.md`](ci/required-checks.md) for the canonical list. The Python gates emitted by [`pr-validate-python.yml`](../.github/workflows/pr-validate-python.yml):

- `Ruff format` — `ruff format --check`
- `Ruff lint` — `ruff check` with the strict rule set
- `Mypy (strict)` — primary type-checker
- `Pyright` — secondary type-checker
- `Pytest` — `tests/unit tests/integration -q` (smoke and adversarial run on a separate schedule)

All five skip cleanly when there's no Python source (pre-Slice-1), then activate once code lands.

---

## Project structure

```
src/alfred/<subsystem>/__init__.py   # small public surface — re-export the API
src/alfred/<subsystem>/<module>.py    # private implementation
src/alfred/<subsystem>/_internal/    # only when truly internal helpers don't belong in a module
tests/unit/<subsystem>/test_<module>.py
tests/integration/test_<subsystem>.py
tests/smoke/test_<feature>.py
```

- Mirror tests to source. `src/alfred/security/secrets.py` ↔ `tests/unit/security/test_secrets.py`.
- Public surface is what's in `__init__.py`'s `__all__`. Everything else is private; don't import it from another subsystem.
- A file is too large when you can't see its public surface on one screen, typically around ~400 lines. Split by responsibility, not by length.

---

## Types

### Modern syntax

```python
from __future__ import annotations  # always

# PEP 604 unions
def lookup(name: str | None) -> User | None: ...

# PEP 585 built-in generics
def all_users() -> list[User]: ...
def by_id() -> dict[str, User]: ...

# PEP 695 generics (Python 3.12+)
class Cache[T]:
    def get(self, key: str) -> T | None: ...

# Type-alias statement (PEP 695)
type UserId = str
```

Never use `Optional[X]` or `Union[X, Y]` or `typing.List` in new code.

### Strictness

- `mypy --strict` is on. `disallow_untyped_defs`, `warn_return_any`, `warn_unused_ignores`, `no_implicit_optional`.
- `pyright` defaults to `strict` mode via `pyproject.toml`.
- `Any` is a code smell. If you need it, annotate `# type: ignore[<code>]  # reason: ...` or `# pyright: ignore[<code>]` with a one-line reason.

### Protocols over ABCs

When you only care about shape, use `typing.Protocol`. When you need inheritance, use ABC. Most boundary types in AlfredOS are protocols.

```python
from typing import Protocol

class Provider(Protocol):
    async def complete(self, request: CompletionRequest) -> CompletionResponse: ...
```

### Type narrowing

Use `TypeGuard` for custom narrowers. Use `assert` for invariants you can't express in the type system.

```python
def is_t2(content: TaggedContent[Any]) -> TypeGuard[TaggedContent[T2]]:
    return content.tier is T2
```

---

## Naming

- `snake_case` for functions, variables, modules.
- `PascalCase` for classes (including `Protocol`s, dataclasses, Pydantic models).
- `UPPER_SNAKE_CASE` for module-level constants.
- `_leading_underscore` for module-private and class-private.
- `__dunder__` only for Python's own protocols. Don't invent dunders.
- Test functions: `test_<noun>_<verb>_<outcome>` or `test_<does_what>` — read as a sentence.
- Pytest classes group related tests: `class TestSecretBroker:` — group by class-under-test, not by feature.

**Avoid:**
- `data`, `info`, `obj`, `tmp`, `helper`, `util` as names. They tell the reader nothing.
- Verbs in noun position: prefer `provider_router`, not `route_provider`.
- Abbreviations that aren't industry-standard. `db` and `url` are fine; `ctx` and `cfg` are fine; `prv` is not.

---

## Imports

- `from __future__ import annotations` first, on its own line.
- Then standard library, then third-party, then `alfred.*`. `ruff check --fix` handles ordering.
- Prefer top-level imports. Local imports only to break a circular dependency or to defer an optional heavy dep.
- Never `from foo import *`.

```python
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from alfred.config.settings import Settings
```

---

## Data modelling — Pydantic + dataclasses

Pick the right tool:

| Need | Use |
|---|---|
| Serialization boundary (HTTP, MCP, DB DTO, config) | **Pydantic v2** model |
| Pure-Python immutable record (internal only) | **`@dataclass(frozen=True, slots=True)`** |
| Tagged union for `match` | Pydantic with `Field(discriminator=...)`, or dataclass + `TypeGuard` |
| Mapped DB row | **SQLAlchemy 2.0** `Mapped[T]` + `mapped_column` |

### Pydantic v2 defaults

```python
from pydantic import BaseModel, ConfigDict, Field

class CompletionRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    model: str
    messages: list[Message]
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=1024, gt=0)
```

- `frozen=True` unless you have a stated reason to mutate.
- `extra="forbid"` unless the schema is genuinely open (e.g. forwarding upstream metadata).
- `Field(...)` for constraints; don't validate in `__init__`.
- Mutable defaults via `Field(default_factory=...)`, never `= {}` or `= []`.

### Dataclasses

```python
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class TurnId:
    user_id: str
    nonce: str
```

`slots=True` saves memory and prevents accidental attribute typos.

---

## Errors

### Philosophy

- **Loud at boundaries, structured inside.** Fail loudly at the trust boundary (CLI, HTTP, MCP RPC); inside the trusted core, raise typed exceptions that callers can pattern-match on.
- **One exception class per failure mode.** Not per call site.
- **Never `except Exception: pass`.** Catch what you can handle; let the rest propagate. If you must swallow, log at `ERROR` with full context and a comment explaining why — **never in `src/alfred/security/` or `src/alfred/audit/`**, where CLAUDE.md hard rule #7 forbids it outright.

### Custom exception hierarchy

```python
class AlfredError(Exception):
    """Root of the AlfredOS exception tree. Anything operator-actionable
    subclasses this so callers can decide what they handle vs. let propagate."""

class SettingsError(AlfredError, ValueError):
    """Configuration could not be loaded."""

class UnknownSecretError(AlfredError, KeyError):
    """Secret was requested but not registered."""

class BudgetExhausted(AlfredError):
    """Daily budget cap was hit; orchestrator should pause."""
```

Subclass a stdlib exception (`ValueError`, `KeyError`) when callers might legitimately catch the stdlib type.

### CLAUDE.md hard rule #7

> **No silent failures in security paths.** Failed DLP, failed capability check, canary trip → loud audit entry + alert + (where appropriate) quarantine.

Anything in `src/alfred/security/` or `src/alfred/audit/`: failures get an `await audit.append(...)` and a `structlog.bind(...).error(...)` log entry before propagating. No exceptions to this rule.

### Sum-type returns over control-flow exceptions

Use exceptions for exceptional things. For expected branching ("user not found", "cache miss"), prefer returning `Foo | None` or a small sum-type the caller can `match` on. Don't raise to control flow. AlfredOS hasn't adopted a `Result`-monad library — if we add one later, an ADR will land first.

---

## Logging

- **`structlog`** everywhere. Configure once at CLI bootstrap; rest of the code calls `structlog.get_logger(__name__)`.
- **Redaction processor is always in front.** Configured to call `SecretBroker.redact()` on every record.
- **Structured fields, not f-strings.** `log.info("provider.call", provider="deepseek", tokens=tokens)` — not `log.info(f"{provider}: {tokens}")`. Structured fields are queryable; f-string concatenation isn't.
- **Bind context once at the top of an operation:** `log = log.bind(user_id=user_id, trace_id=trace_id)` then use `log` for the rest of the function.
- **Log levels:** `debug` = developer trace, `info` = ordinary milestone, `warning` = unexpected but recoverable, `error` = failed operation, `critical` = data-loss-imminent. Default visibility is `info`.

---

## Async

- **Async-first** in `core`, `orchestrator`, `providers`, `memory`.
- **Never block the event loop.** No `time.sleep`, no `requests.get`, no synchronous file I/O over multi-MB files. Use `asyncio.sleep`, `httpx.AsyncClient`, `aiofiles`, or `asyncio.to_thread`.
- **Structured concurrency** via `asyncio.TaskGroup` (Python 3.11+). Avoid loose `asyncio.create_task` calls that no one awaits.
- **Cancellation is normal.** Handle `asyncio.CancelledError` only to clean up; re-raise.
- **Session per request.** Don't share a single `AsyncSession` across concurrent tasks. Use `async with session_scope() as session:` per logical unit of work.
- **Cache pure transformations, not coroutines.** `functools.cache` doesn't understand async; `async_lru.alru_cache` or a hand-rolled `dict`-with-`asyncio.Lock` does. Don't decorate `async def` with `@cache` and expect it to work.
- **Bound your concurrent fan-out.** `asyncio.Semaphore` for I/O-bound external calls (provider HTTP, DB) so a slow downstream doesn't queue 10 000 tasks. Pick a number, log when you hit it.

```python
async with asyncio.TaskGroup() as tg:
    a = tg.create_task(fetch_one(...))
    b = tg.create_task(fetch_two(...))
# a.result() and b.result() are available here; exceptions in either re-raise
```

---

## SOLID applied with judgment

- **Single responsibility**: one module, one reason to change. If a file describes two unrelated capabilities, split it.
- **Open/closed**: prefer composition (`compose(...)`, decorators, strategy objects) over editing the open module. Don't anticipate every extension — refactor on the second duplication, not the first.
- **Liskov**: subclasses honour their parent's contract. Overriding to no-op or raise `NotImplementedError` is a smell — prefer composition or two distinct classes.
- **Interface segregation**: prefer small `Protocol`s. A method on a `Protocol` no caller invokes is dead weight.
- **Dependency inversion**: depend on the protocol, build the implementation at the edge (CLI bootstrap, test fixture). Never reach for module globals from a function under test.

**Anti-patterns we actively avoid:**
- Premature interfaces. One implementation = no interface. Two = consider one. Three = definitely one.
- "Manager" / "Helper" / "Util" classes — they're usually a pile of unrelated functions wearing a class costume.
- Inheritance for code reuse. Compose instead.

---

## Functional patterns

Python is multi-paradigm; we use FP where it earns its keep:

- **Pure transformation functions**: take inputs, return outputs, no side effects. Trivially testable. Most of `src/alfred/` business logic should look like this.
- **Imperative shell, functional core** (Bernhardt). I/O at the edges; transformations in the middle.
- **Higher-order functions and `functools.partial`** over deep class hierarchies for behaviour parameterisation.
- **`itertools`, `functools`, `operator`** — know them and use them:
  - `itertools.pairwise`, `accumulate`, `groupby`, `chain.from_iterable`
  - `functools.cache`, `lru_cache`, `partial`, `reduce`, `singledispatch`
  - `operator.itemgetter`, `attrgetter`, `methodcaller`
- **Immutability by default**: `tuple` over `list` for fixed-shape data; `Mapping` over `dict` for read-only inputs; frozen dataclasses; Pydantic `frozen=True`.
- **Iterators and generators** for streams. Don't materialise into a list unless you need random access or len.
- **`match` statements** for tagged unions and structural matching.

```python
from functools import reduce
from itertools import pairwise

def total_cost(turns: Sequence[Turn]) -> float:
    return reduce(lambda acc, t: acc + t.cost_usd, turns, 0.0)
    # equivalent to: sum(t.cost_usd for t in turns)
```

Prefer the comprehension when it reads better; prefer the reduce when the operation is non-trivial.

---

## Testing

### Layers

| Layer | Lives in | What it tests | Speed | LLM/IO? | Schedule |
|---|---|---|---|---|---|
| Unit | `tests/unit/` | One module, no I/O | <50ms each | No (recorded fixtures only) | Every PR + pre-push |
| Integration | `tests/integration/` | Multi-module + real datastores via testcontainers | seconds | Postgres yes, LLM recorded | Every PR (Docker required) |
| Smoke | `tests/smoke/` | End-to-end happy path | tens of seconds | Real stack | Nightly + opt-in `make test-smoke` |
| Adversarial | `tests/adversarial/` | Security boundary violations | varies | Yes, with canaries | **Nightly + release-blocking** (CLAUDE.md) |

Slice 1's smoke directory is at `tests/smoke/`. (CLAUDE.md historically referenced `tests/e2e/`; that pre-dated this slice's naming decision and is being aligned.)

### Skill tests — the triad

Per CLAUDE.md, every new skill ships with all three: a happy-path test, an error-path test, and an out-of-scope refusal test. Missing any of the three is a release blocker for the skill.

### TDD when the spec specifies it

Write the failing test first, run it, see it fail with the *expected* message, then implement. Re-run, see it pass. Commit.

### Every test asserts behaviour, not structure

```python
# Bad — tests that the function called the mock
mock_db.assert_called_once_with(user_id)

# Good — tests that the function did the right thing
assert await get_user(user_id) == expected_user
```

Mocks are last-resort. Prefer real datastores via testcontainers; prefer recorded LLM fixtures; prefer in-memory test doubles you can audit.

### Property-based tests

Use `hypothesis` where the function has a property:

- "Round-trip serialisation preserves the input": `@given(model_strategy)` → serialise → deserialise → equal
- "Redaction is idempotent": `redact(redact(s)) == redact(s)`
- "Sort is stable for equal keys": `@given(st.lists(...))`

Don't use hypothesis for the sake of it. If you can name the property in one sentence, write it.

### Fixtures

- Scope fixtures appropriately. `session` for testcontainers Postgres (expensive). `function` for state-mutating fixtures.
- Use `autouse=True` sparingly — usually only for resetting global state (logging, i18n active language).
- Build fixtures via composition, not inheritance.
- **Session-scoped testcontainers + per-test rollback**: when you reuse a Postgres container across many tests, wrap each test in a savepoint that rolls back at teardown. Otherwise one test's `INSERT` becomes the next test's surprise.

```python
@pytest.fixture
async def session(pg_session_factory):  # function-scoped, depends on session-scoped factory
    async with pg_session_factory() as s:
        async with s.begin():            # outer transaction
            await s.begin_nested()       # SAVEPOINT
            yield s
            await s.rollback()           # rolls back to the SAVEPOINT, then the outer
```

### CLAUDE.md hard rule on security tests

> **Every security boundary** must have 100% line and branch coverage.

That includes `tag()`, `SecretBroker.get/has/known/redact`, capability gate (when it lands), DLP (when it lands), audit writers. Per-package 100% gates are enforced via a second `coverage report --include=... --fail-under=100` invocation in CI — wiring lands with Slice 1 Task 17; pre-Slice-1 the gate is documented here but not yet emitted as a required check.

---

## Security boundaries

CLAUDE.md is the hard-rule source. This section restates the Python-mechanics.

- **`os.environ` is allowed only in `src/alfred/config/settings.py` and `src/alfred/security/secrets.py`.** Every other module accesses secrets via `SecretBroker.get()`. A grep gate enforces this.
- **External content is `tag()`-ed at the boundary**, always. CLI input → `tag(T2, source="cli.input")`. Plugin output → `tag(T3, source="plugin.<name>")` (slice 2+).
- **The privileged orchestrator never sees raw T3 content.** Only the quarantined LLM does. (Slice 2+.)
- **DLP and capability gate are not bypassable per-call.** Pure-internal tools declare "no DLP needed" once in their manifest; the test suite verifies the claim.
- **All security-path failures are loud:** `await audit.append(...)` + `structlog.error(...)` before re-raising or quarantining.

---

## i18n

CLAUDE.md hard rule #1: **All operator-/user-facing strings go through `t()`.**

```python
from alfred.i18n import t

# Good
print(t("status.primary_provider", provider="deepseek"))

# Bad — hardcoded English
print(f"primary provider: {provider}")
```

**Adding a new string:**

1. Add the msgid to `locale/en/LC_MESSAGES/alfred.po`.
2. Run `uv run pybabel extract -F babel.cfg -o locale/alfred.pot src/alfred` to refresh the template.
3. Run `uv run pybabel compile -d locale -D alfred` to produce the runtime `.mo`.
4. Commit the `.po` (always). The `.mo` is gitignored — it's a compiled artifact rebuilt in CI / dev container / `make setup`.

**Catalog drift gate:** CI runs `pybabel compile --check` so a `.po` that no longer compiles, or any extracted-but-missing msgid, fails the build (CLAUDE.md hard rule #4). The gate lands as a follow-up to this slice; until then, `make check` includes the extract step locally.

- Persona prompts substitute `{user.language}` so Alfred responds in the operator's language.
- Every DB row that holds user content has a `language` column ([BCP-47 / RFC 5646](https://www.rfc-editor.org/rfc/rfc5646)).

Doc files (PRD, CLAUDE.md, ADRs, agent definitions, this doc) stay English-only.

---

## Commits and PRs

- **Conventional Commits**: `<type>(<scope>)!: <description> (#<issue>)`. Types: `build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test`. The `(#NN)` issue ref is required by the `Conventional commit format` gate.
- **Fixup for review fixes**: `git commit --fixup=<sha>`, then `make autosquash` before push. Never write `fix: apply CR auto-fixes`. `make autosquash` runs `scripts/autosquash.sh` which is tree-preserving (your working tree is untouched) and non-interactive (`GIT_SEQUENCE_EDITOR=true`).
- **No `--no-verify`**. If a hook fails, fix the underlying issue. Likewise, `LEFTHOOK=0` exists only as a true emergency escape — never habituate.
- **No merge commits in a PR**. Rebase onto main.
- **Branch per issue**. Branch name: `issue-NN-<kebab-case-title>`.
- **One responsibility per PR**. Reviewer should hold it in their head.

The currently-required gates are listed in [`docs/ci/required-checks.md`](ci/required-checks.md) — that file is the authoritative manifest. Don't hard-code the list here; it drifts.

---

## Further reading

- [PEP 8](https://peps.python.org/pep-0008/) — style guide (we follow with ruff overrides)
- [PEP 257](https://peps.python.org/pep-0257/) — docstring conventions
- [PEP 484](https://peps.python.org/pep-0484/) and successors — typing
- [PEP 604](https://peps.python.org/pep-0604/) — `X | Y` unions
- [PEP 695](https://peps.python.org/pep-0695/) — generic syntax
- "Functional Core, Imperative Shell" — Gary Bernhardt's talk
- Python community: [Hypothesis docs](https://hypothesis.readthedocs.io/), [SQLAlchemy 2.0 docs](https://docs.sqlalchemy.org/en/20/), [Pydantic v2 docs](https://docs.pydantic.dev/latest/), [structlog docs](https://www.structlog.org/)
