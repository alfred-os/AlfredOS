# G0 — Core Inbound Idempotency Commit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable, Postgres-backed "accept-once" commit keyed on the composite `(adapter_id, inbound_id)`, consulted at the top of the inbound trust-boundary pipeline so a replayed comms frame short-circuits before any side effect (limiter / resolve / binding / extract / audit / ingest / dispatch) re-runs.

**Architecture:** A new `inbound_idempotency` dedup ledger (Alembic migration 0018, off head 0017) + a `PostgresInboundIdempotencyStore` whose only operation is an atomic `INSERT … ON CONFLICT (adapter_id, inbound_id) DO NOTHING RETURNING inbound_id` (race-free winner/loser signal). The store is injected into `process_inbound_message` as a pre-built object (the same shape `audit_writer` uses — it owns its `session_scope`, the entrypoint never touches a raw session). `InboundMessageNotification` gains a required `inbound_id` wire field. This is the first PR of the Comms-Resume Gateway (Spec A) and is independently valuable: it makes inbound processing idempotent against adapter retries today, and is the prerequisite for gateway buffer-replay safety later.

**Composite primary key (ratified by multi-specialist consensus).** The dedup key is the COMPOSITE `(adapter_id, inbound_id)`, NOT `inbound_id` alone. `inbound_id` is a free-form plugin-minted string; a single-column primary key would put every adapter into one shared namespace, so a buggy or malicious adapter that reuses another adapter's id would silently drop a distinct real message from a different adapter (a denial-of-delivery). Scoping the key by the host-validated `adapter_id` (an `AdapterId` — already constrained to a known `adapter_kind` member at the wire boundary) isolates each adapter's id namespace.

**Trust assumption (stated, not assumed).** `inbound_id` is adapter-supplied OPAQUE metadata. In G0 it is host-validated only for shape (bounded, non-empty) — the host does NOT yet trust an individual adapter to mint globally-unique or stable ids. The composite key bounds the blast radius of a buggy id to that one adapter. The gateway (G1+) makes `inbound_id` host-trusted by deriving it from a `(leg, seq, epoch)` envelope; until then, the dedup guarantee is "exactly-once per `(adapter_id, inbound_id)` the adapter actually reproduces on retry". This assumption is documented on the `InboundId` field docstring and in the key-invariants below.

**Replay observability (signed-audit, not just a log line).** Because the commit-once guard now runs BEFORE the side effects, a replay short-circuit is a side-effecting DROP (the message is silently not processed). That MUST be observable in the SIGNED audit log, not just a structlog line. The duplicate path writes one CONTENT-FREE audit row — `adapter_id` + a PEPPERED HASH of `inbound_id` (via the existing `audit_hash` recipe; never the raw adapter string) + `observed_at`, event key `comms.inbound.idempotency.replay_observed`, `result="dropped"` (reuses an existing audit-result value, so NO audit-result migration).

**Resolved open question — distinct-id write cost.** The commit INSERT stays BEFORE the pre-resolution DoS limiter (moving it after would re-charge the coarse `(adapter_id, platform_user_id_hash)` budget on every replay and defeat G0). A consequence: a flood of DISTINCT `inbound_id`s drives ONE Postgres write per frame AHEAD of the coarse flood-cap — the ledger is correctness, not a rate-limiter, and the downstream pre-resolution limiter is what caps a per-user flood (proven by the Task 8 distinct-id-flood test + the existing pre-resolution-limiter adversarial coverage). The ledger grows unbounded without pruning, so the replay-dedup guarantee is bounded by a retention window: a **`committed_at`-based prune follow-up is tracked** (the `ix_inbound_idempotency_committed_at` index in migration 0018 exists precisely to make that prune cheap). State the bound explicitly: dedup is guaranteed only for replays within the retention window; a replay older than the prune horizon re-executes (a bounded fail-safe, same posture as the migration-0018 downgrade).

**Tech Stack:** Python 3.12+, asyncio, SQLAlchemy 2.0 (typed, async), Alembic, Pydantic v2, pytest + testcontainers (real Postgres 16), structlog. mypy --strict + pyright + ruff.

**Spec:** `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` (§2 decision 4, §7 "Core InboundIdempotencyCommit", §8 G0). Trust-boundary change → the commit-ordering placement and the dedup-before-side-effect property require an `alfred-security-engineer` review before merge (see Task 9).

---

## File structure (decomposition)

| File | Responsibility | New/Modify |
|---|---|---|
| `src/alfred/memory/migrations/versions/0018_inbound_idempotency.py` | Schema: the `inbound_idempotency` dedup ledger | **New** |
| `src/alfred/memory/models.py` | ORM model `InboundIdempotency` (mirrors the table for SQLite unit tests) | Modify |
| `src/alfred/memory/inbound_idempotency.py` | `InboundIdempotencyStore` Protocol + `PostgresInboundIdempotencyStore` (the commit-once primitive) | **New** |
| `src/alfred/comms_mcp/protocol.py` | Add required `inbound_id: InboundId` wire field to `InboundMessageNotification` | Modify |
| `src/alfred/comms_mcp/inbound.py` | `_InboundIdempotencyStoreLike` Protocol + `idempotency_store` param + commit-once guard + replay-audit row | Modify |
| `src/alfred/comms_mcp/handlers.py` | Thread `idempotency_store` through `InboundMessageHandler` | Modify |
| `src/alfred/cli/daemon/_commands.py` | Build the store in `_build_comms_boot_graph` (new `_CommsBootGraph` field) + inject in `_build_comms_adapter_wiring` | Modify |
| `plugins/alfred_discord/inbound_emitter.py`, `plugins/alfred_tui/src/alfred_tui/session.py`, `plugins/alfred_comms_test/main.py` + every inbound test fixture/factory | Stamp `inbound_id` on every emitted/constructed notification (forced by `extra="forbid"`) | Modify |
| `tests/unit/memory/test_inbound_idempotency_store.py` | Unit test the store (injected fake `session_scope`; no real engine) | **New** |
| `tests/integration/test_inbound_idempotency_postgres.py` | Integration: first-wins / replay-noop / concurrent-exactly-one / distinct-id-flood (testcontainers Postgres) | **New** |
| `tests/integration/test_migration_0018_inbound_idempotency.py` | Migration forward+backward test | **New** |

**Key invariants for the implementer:**

1. **Dedup-id stability.** The dedup key is the **wire `inbound_id`**, scoped by `adapter_id` (composite key), never the late `uuid.uuid4().hex` observability id at `inbound.py:493` (leave that line alone). Dedup requires a RETRIED frame to reproduce the SAME `inbound_id`. `uuid4().hex`-per-emit is correct ONLY for today's non-buffering single-shot emitters (Discord/TUI/reference plugin each emit a genuinely new frame per message, so a fresh id per emit is right); the gateway (G1) produces the stable id that makes buffer-replay dedup meaningful. Not a G0 blocker — documented so a future buffering emitter does not silently break dedup.
2. The commit-once guard runs **after** the two structural guards (cheap-validate, promoter-required) and **before** every per-message side effect (`set_broker`/limiter/resolve/binding/extract/audit/ingest/dispatch). The INSERT stays **before** the pre-resolution DoS limiter: moving it after would re-charge the coarse `(adapter_id, platform_user_id_hash)` budget on every replay and defeat G0's "no side effect on replay".
3. `commit_once` is a **single** `INSERT … ON CONFLICT (adapter_id, inbound_id) DO NOTHING RETURNING inbound_id` — `scalar_one_or_none() is not None` is the race-free winner signal. No read-then-write. A `SQLAlchemyError` PROPAGATES (fail-loud at the trust boundary — CLAUDE.md hard rule #7); it is never swallowed into a "won" or "replay".
4. The ledger holds **no body, no user text, no `platform_user_id`** → no `language` column (i18n hard-rule #3 satisfied by construction; the ledger never holds T3 bytes). `adapter_id` and `inbound_id` are non-user metadata.
5. The store owns its `session_scope` and is injected like `audit_writer`; `process_inbound_message` never handles a raw session.
6. **`inbound_id` is adapter-supplied OPAQUE metadata** (trust assumption above): host-validated for shape only in G0; the composite key isolates each adapter's id namespace so one adapter's reuse can never drop another adapter's distinct message.
7. **A replay short-circuit is an audited DROP.** On `won=False` the guard writes exactly one content-free `comms.inbound.idempotency.replay_observed` row carrying `adapter_id` + `audit_hash.hash_inbound_id(inbound_id)` + `observed_at` — never the raw `inbound_id` string.

---

### Task 1: Alembic migration 0018 — the dedup ledger

**Files:**

- Create: `src/alfred/memory/migrations/versions/0018_inbound_idempotency.py`
- Test: `tests/integration/test_migration_0018_inbound_idempotency.py`

- [ ] **Step 1: Confirm the current Alembic head is 0017**

Run: `uv run alembic heads`
Expected: a single head `0017 (head)`. (If it is not `0017`, set `down_revision` in Step 3 to the actual head and adjust the test.)

- [ ] **Step 2: Write the failing migration test**

Create `tests/integration/test_migration_0018_inbound_idempotency.py`:

```python
"""0018 inbound_idempotency migration — forward creates the ledger, backward drops it."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import command, config

import pytest

pytestmark = pytest.mark.integration


def _alembic_cfg(url: str) -> config.Config:
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_0018_upgrade_creates_ledger_then_downgrade_drops_it(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = _alembic_cfg(postgres_url)

    command.upgrade(cfg, "0018")
    engine = sa.create_engine(postgres_url.replace("+asyncpg", "+psycopg2"))
    insp = sa.inspect(engine)
    cols = {c["name"] for c in insp.get_columns("inbound_idempotency")}
    assert cols == {"inbound_id", "adapter_id", "committed_at"}
    pk = insp.get_pk_constraint("inbound_idempotency")
    # Composite (adapter_id, inbound_id) — each adapter's id namespace is isolated.
    assert set(pk["constrained_columns"]) == {"adapter_id", "inbound_id"}
    index_names = {ix["name"] for ix in insp.get_indexes("inbound_idempotency")}
    assert "ix_inbound_idempotency_committed_at" in index_names

    command.downgrade(cfg, "0017")
    insp = sa.inspect(sa.create_engine(postgres_url.replace("+asyncpg", "+psycopg2")))
    assert "inbound_idempotency" not in insp.get_table_names()
    engine.dispose()
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/integration/test_migration_0018_inbound_idempotency.py -v`
Expected: FAIL — `alembic.util.exc.CommandError: Can't locate revision '0018'`.

- [ ] **Step 4: Write the migration**

Create `src/alfred/memory/migrations/versions/0018_inbound_idempotency.py`:

```python
"""inbound_idempotency — durable inbound accept-once ledger (Spec A / G0).

Revision ID: 0018
Revises: 0017

The Comms-Resume Gateway (Spec A, decision 4) requires the core to commit
"this inbound was accepted exactly once" keyed on a durable wire ``inbound_id``
BEFORE any side effect (audit / extract / ingest / dispatch). A replayed frame
(gateway buffer replay after a core restart) short-circuits on the existing row
so none of the side effects re-run.

Dedup ledger, NOT a content store: holds the wire id, the originating adapter,
and a commit timestamp — and deliberately NO message body, NO user text, NO
platform_user_id. Per CLAUDE.md i18n hard-rule #3 the ``language`` column binds
rows holding user text; this row holds none, so it carries no ``language``
column (and never holds T3 bytes).

Composite ``(adapter_id, inbound_id)`` PRIMARY KEY: ``inbound_id`` is a
free-form plugin-minted opaque string, so a single-column key would put every
adapter into one shared id namespace — a buggy/malicious adapter reusing another
adapter's id would silently drop a distinct real message (denial-of-delivery).
Scoping by the host-validated ``adapter_id`` isolates each adapter's namespace.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | Sequence[str] | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

__all__ = [
    "branch_labels",
    "depends_on",
    "down_revision",
    "downgrade",
    "revision",
    "upgrade",
]


def upgrade() -> None:
    """Create the inbound_idempotency dedup ledger + retention index."""
    op.create_table(
        "inbound_idempotency",
        sa.Column("inbound_id", sa.String(255), nullable=False),
        sa.Column("adapter_id", sa.String(128), nullable=False),
        sa.Column(
            "committed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint(
            "adapter_id", "inbound_id", name="pk_inbound_idempotency"
        ),
        sa.CheckConstraint(
            "char_length(inbound_id) BETWEEN 1 AND 255",
            name="ck_inbound_idempotency_inbound_id_length",
        ),
        sa.CheckConstraint(
            "char_length(adapter_id) BETWEEN 1 AND 128",
            name="ck_inbound_idempotency_adapter_id_length",
        ),
    )
    op.create_index(
        "ix_inbound_idempotency_committed_at",
        "inbound_idempotency",
        ["committed_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the ledger; replays across the revert re-execute (bounded fail-safe)."""
    op.drop_index(
        "ix_inbound_idempotency_committed_at",
        table_name="inbound_idempotency",
        if_exists=True,
    )
    op.execute("DROP TABLE IF EXISTS inbound_idempotency")
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/integration/test_migration_0018_inbound_idempotency.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/memory/migrations/versions/0018_inbound_idempotency.py tests/integration/test_migration_0018_inbound_idempotency.py
git commit -m "feat(memory): inbound_idempotency dedup ledger migration (Spec A G0)"
```

---

### Task 2: ORM model `InboundIdempotency`

**Files:**

- Modify: `src/alfred/memory/models.py`
- Test: `tests/unit/memory/test_inbound_idempotency_model.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/memory/test_inbound_idempotency_model.py`:

```python
"""The InboundIdempotency ORM model mirrors migration 0018 for SQLite unit tests."""

from __future__ import annotations

from alfred.memory.models import Base, InboundIdempotency


def test_model_maps_inbound_idempotency_table() -> None:
    table = InboundIdempotency.__table__
    assert table.name == "inbound_idempotency"
    assert {c.name for c in table.columns} == {"inbound_id", "adapter_id", "committed_at"}
    # Composite (adapter_id, inbound_id) PK — order-independent membership check.
    assert {c.name for c in table.primary_key.columns} == {"adapter_id", "inbound_id"}
    # No user text => no language column (i18n hard-rule #3 satisfied by construction).
    assert "language" not in table.columns


def test_model_is_registered_on_base_metadata() -> None:
    assert "inbound_idempotency" in Base.metadata.tables
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/memory/test_inbound_idempotency_model.py -v`
Expected: FAIL — `ImportError: cannot import name 'InboundIdempotency'`.

- [ ] **Step 3: Add the model**

In `src/alfred/memory/models.py`, add this class alongside the other models (place it **before** the tail `import alfred.identity.models` side-effect import, which must stay last). `Mapped`, `mapped_column`, `String`, `DateTime`, `Index`, `func`, `sa`, and the `dt` datetime alias are already imported at the top of `models.py`:

```python
class InboundIdempotency(Base):
    """Durable inbound accept-once ledger (Spec A / G0).

    One row per inbound comms frame the core has committed "accepted exactly
    once", keyed on the durable wire ``inbound_id``. A replayed frame (gateway
    buffer replay after a core restart) hits the existing row and short-circuits
    BEFORE any side effect. Dedup ledger, not a content store: NO body, NO user
    text, NO ``platform_user_id`` — so no ``language`` column (i18n hard-rule #3).
    """

    __tablename__ = "inbound_idempotency"

    inbound_id: Mapped[str] = mapped_column(String(255), nullable=False)
    adapter_id: Mapped[str] = mapped_column(String(128), nullable=False)
    committed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # Composite (adapter_id, inbound_id) PK — mirrors migration 0018. Isolates
        # each adapter's id namespace so one adapter's reuse cannot drop another's
        # distinct message.
        sa.PrimaryKeyConstraint("adapter_id", "inbound_id", name="pk_inbound_idempotency"),
        # Postgres-only char_length CHECKs live in migration 0018; SQLite unit
        # tests cannot parse them (PoliciesSnapshotHistory precedent). The
        # dialect-portable named PK + retention index stay here.
        Index("ix_inbound_idempotency_committed_at", "committed_at"),
    )
```

> Verified against `models.py`: it uses `import datetime as dt`, and `String`,
> `DateTime`, `Index`, `Mapped`, `mapped_column`, `func`, and `sa` are all
> already imported there. `func.now()` (bare) and `sa.PrimaryKeyConstraint(...)`
> match the existing `ProcessedProposal` / `PoliciesSnapshotHistory` precedents,
> so the snippet above drops in without new imports.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/unit/memory/test_inbound_idempotency_model.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/models.py tests/unit/memory/test_inbound_idempotency_model.py
git commit -m "feat(memory): InboundIdempotency ORM model (Spec A G0)"
```

---

### Task 3: The store — `InboundIdempotencyStore` + Postgres impl

**Files:**

- Create: `src/alfred/memory/inbound_idempotency.py`
- Test: `tests/unit/memory/test_inbound_idempotency_store.py`

> **No `aiosqlite` in this repo.** `sqlite+aiosqlite` errors at setup — aiosqlite
> is NOT a dependency and we do NOT add it. The repo precedent for unit-testing an
> async-session-owning store is `tests/unit/identity/test_resolve_operator.py`:
> it injects a FAKE async `session_scope` (an `@asynccontextmanager` yielding a
> hand-rolled `_FakeSession` whose `execute()` returns a `_FakeResult`) — NO real
> engine, NO real DB. We follow that pattern: the unit test asserts `commit_once`
> calls `execute` with the composite-key SQL and maps the result row → `bool`,
> and that a DB error PROPAGATES. The exactly-one-winner-under-concurrency
> property is a genuine-Postgres property and lives ONLY in Task 8 (testcontainers)
> — SQLite cannot prove `ON CONFLICT` race semantics.

- [ ] **Step 1: Write the failing unit test (injected fake `session_scope` — no engine)**

Create `tests/unit/memory/test_inbound_idempotency_store.py`:

```python
"""PostgresInboundIdempotencyStore commit-once semantics (fake session_scope; no DB engine).

Mirrors the ``tests/unit/identity/test_resolve_operator.py`` precedent: the store
owns an async ``session_scope``; we inject an ``@asynccontextmanager`` yielding a
fake session so every branch (won / replay / DB-error-propagates) is exercised
hermetically. The genuine-Postgres exactly-one-winner property lives in Task 8.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from alfred.memory.inbound_idempotency import (
    InboundIdempotencyStore,
    PostgresInboundIdempotencyStore,
)


class _FakeResult:
    """Stands in for the ``Result`` of the INSERT … RETURNING."""

    def __init__(self, returned: str | None) -> None:
        self._returned = returned

    def scalar_one_or_none(self) -> str | None:
        return self._returned


class _FakeSession:
    """Records executed SQL + params; returns a configured result (or raises)."""

    def __init__(self, *, returned: str | None = None, raises: Exception | None = None) -> None:
        self._returned = returned
        self._raises = raises
        self.executed: list[tuple[Any, dict[str, Any]]] = []

    async def execute(self, statement: Any, params: dict[str, Any]) -> _FakeResult:
        self.executed.append((statement, params))
        if self._raises is not None:
            raise self._raises
        return _FakeResult(self._returned)


def _scope_for(
    session: _FakeSession,
) -> Callable[[], AbstractAsyncContextManager[_FakeSession]]:
    @asynccontextmanager
    async def _scope() -> AsyncIterator[_FakeSession]:
        yield session

    return _scope


def test_store_satisfies_protocol() -> None:
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(_FakeSession()))
    assert isinstance(store, InboundIdempotencyStore)


async def test_first_commit_wins_when_row_returned() -> None:
    # A returned inbound_id == this caller won the INSERT (the row was fresh).
    session = _FakeSession(returned="frame-1")
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(session))
    assert await store.commit_once(inbound_id="frame-1", adapter_id="tui") is True
    # The composite key is carried as bound params (never SQL-interpolated).
    _stmt, params = session.executed[0]
    assert params == {"inbound_id": "frame-1", "adapter_id": "tui"}


async def test_replay_is_noop_when_no_row_returned() -> None:
    # ON CONFLICT DO NOTHING suppressed the insert => RETURNING yields no row.
    session = _FakeSession(returned=None)
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(session))
    assert await store.commit_once(inbound_id="frame-2", adapter_id="tui") is False


async def test_db_error_propagates_fail_loud() -> None:
    # CLAUDE.md hard rule #7: a genuine DB failure is NEVER swallowed into a
    # won/replay bool — it propagates loud at the trust boundary.
    boom = OperationalError("INSERT failed", {}, Exception("db down"))
    session = _FakeSession(raises=boom)
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(session))
    with pytest.raises(OperationalError):
        await store.commit_once(inbound_id="frame-3", adapter_id="tui")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/memory/test_inbound_idempotency_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.memory.inbound_idempotency'`.

- [ ] **Step 3: Write the store**

Create `src/alfred/memory/inbound_idempotency.py`:

```python
"""Durable inbound accept-once store (Spec A / G0).

The commit-once primitive the Comms-Resume Gateway needs: the core records
"this inbound was accepted exactly once" keyed on a durable wire ``inbound_id``
BEFORE any side effect runs. A replayed frame short-circuits.

The atomicity contract is a single ``INSERT … ON CONFLICT (adapter_id,
inbound_id) DO NOTHING RETURNING inbound_id`` — Postgres returns a row IFF this
caller won the insert; an existing row yields no rows. There is NO read-then-
write window, so two concurrent commits on the same ``(adapter_id, inbound_id)``
produce exactly one winner. The key is COMPOSITE so each adapter's free-form
``inbound_id`` namespace is isolated (one adapter's id reuse cannot drop
another adapter's distinct message).

A genuine DB failure (``SQLAlchemyError``) PROPAGATES — it is never caught and
collapsed into a won/replay bool. The commit-once decision is part of the
inbound trust boundary, so a failed commit must fail LOUD (CLAUDE.md hard rule
#7), letting the caller's handler-failure path audit + surface it rather than
silently process or silently drop the message.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Protocol, runtime_checkable

import sqlalchemy as sa
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

_log = structlog.get_logger(__name__)

# Single source of truth for the commit-once SQL. ``committed_at`` is filled by
# the column ``server_default now()`` so it is never named here. ``RETURNING``
# yields a row only on a fresh insert; ON CONFLICT DO NOTHING suppresses the
# duplicate, returning zero rows — the value that tells the caller "replay".
_COMMIT_ONCE_SQL = sa.text(
    "INSERT INTO inbound_idempotency (inbound_id, adapter_id) "
    "VALUES (:inbound_id, :adapter_id) "
    "ON CONFLICT (adapter_id, inbound_id) DO NOTHING "
    "RETURNING inbound_id"
)


@runtime_checkable
class InboundIdempotencyStore(Protocol):
    """Durable accept-once commit on a wire ``inbound_id`` (Spec A decision 4)."""

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        """Atomically record ``inbound_id`` as accepted.

        The accept-once is keyed on the COMPOSITE ``(adapter_id, inbound_id)`` so
        each adapter's free-form id namespace is isolated. Returns ``True`` if
        THIS call won the insert (the inbound is new — the caller proceeds with
        side effects), ``False`` if a row already existed (a replay/retry — the
        caller short-circuits). Never raises on a duplicate; raises
        ``SQLAlchemyError`` only on a genuine DB failure (fail-loud at the
        boundary — CLAUDE.md hard rule #7; the error propagates, it is never
        swallowed into a won/replay bool).
        """
        ...


class PostgresInboundIdempotencyStore:
    """Postgres-backed :class:`InboundIdempotencyStore`.

    Owns its transactional ``session_scope`` (the daemon-built
    ``build_session_scope(settings)`` callable) — the same "pre-built durable
    writer injected from the boot graph" shape ``audit_writer`` uses, so
    ``process_inbound_message`` never handles a raw DB session.
    """

    def __init__(
        self,
        *,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_scope = session_scope

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        async with self._session_scope() as session:
            result = await session.execute(
                _COMMIT_ONCE_SQL,
                {"inbound_id": inbound_id, "adapter_id": adapter_id},
            )
            won = result.scalar_one_or_none() is not None
        if not won:
            _log.info(
                "comms.inbound.idempotency.replay_short_circuit",
                adapter_id=adapter_id,
            )
        return won
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/unit/memory/test_inbound_idempotency_store.py -v`
Expected: PASS (4 tests — protocol / won / replay / DB-error-propagates).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/inbound_idempotency.py tests/unit/memory/test_inbound_idempotency_store.py
git commit -m "feat(memory): PostgresInboundIdempotencyStore commit-once primitive (Spec A G0)"
```

---

### Task 4: Wire field — `inbound_id` on `InboundMessageNotification`

**Files:**

- Modify: `src/alfred/comms_mcp/protocol.py`
- Modify: every inbound-notification construction site (enumerated in Step 4 below — verified against the code)
- Test: `tests/unit/comms_mcp/test_protocol_inbound_id.py`

> `InboundMessageNotification` is `extra="forbid"` AND every field is required, so
> adding a **required** `inbound_id` makes every construction site that omits it
> fail validation loudly. This task adds the field AND updates ALL construction
> sites in the same commit so the suite stays green.
>
> **Two construction shapes exist — both must be found.** Some sites call the
> Pydantic constructor `InboundMessageNotification(...)`; others build a RAW
> PARAMS DICT that the host validates via `InboundMessageNotification.model_validate(raw)`
> at `src/alfred/plugins/session.py:738`. A grep for `InboundMessageNotification(`
> alone MISSES the raw-dict emitters. Grep for BOTH the constructor AND the
> params-dict builders.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/comms_mcp/test_protocol_inbound_id.py`:

```python
"""InboundMessageNotification requires a bounded, non-empty wire inbound_id."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import InboundMessageNotification


def _kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "adapter_id": "tui",
        "inbound_id": "frame-1",
        "platform_user_id": "u1",
        "body": {"content": "hi"},
        "sub_payload_refs": (),
        "received_at": datetime.now(UTC),
        "addressing_signal": "dm",
    }
    base.update(overrides)
    return base


def test_accepts_a_valid_inbound_id() -> None:
    note = InboundMessageNotification(**_kwargs())
    assert note.inbound_id == "frame-1"


def test_missing_inbound_id_is_rejected() -> None:
    kwargs = _kwargs()
    del kwargs["inbound_id"]
    with pytest.raises(ValidationError):
        InboundMessageNotification(**kwargs)


def test_empty_inbound_id_is_rejected() -> None:
    with pytest.raises(ValidationError):
        InboundMessageNotification(**_kwargs(inbound_id=""))
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_protocol_inbound_id.py -v`
Expected: FAIL — `test_accepts_a_valid_inbound_id` raises `ValidationError` (extra field `inbound_id` forbidden).

- [ ] **Step 3: Add the `InboundId` type + field**

In `src/alfred/comms_mcp/protocol.py`, add the type near `PlatformUserId` (around line 97):

```python
# The durable wire dedup key the gateway/adapter stamps on each inbound frame
# (Spec A decision 4 / G0). Bounded to match the ``inbound_idempotency.inbound_id``
# column (VARCHAR(255)); non-empty so a blank id can never collapse two frames.
#
# TRUST ASSUMPTION: ``inbound_id`` is adapter-supplied OPAQUE metadata. In G0 the
# host validates SHAPE only (bounded, non-empty) — it does NOT yet trust an
# individual adapter to mint globally-unique ids. The ``inbound_idempotency``
# ledger's COMPOSITE ``(adapter_id, inbound_id)`` key isolates each adapter's id
# namespace so one adapter's id reuse cannot drop another adapter's distinct
# message. The gateway (G1+) makes this id host-trusted by deriving it from a
# ``(leg, seq, epoch)`` envelope.
#
# STABILITY: dedup requires a RETRIED frame to reproduce the SAME id. A fresh
# ``uuid4().hex`` per emit is correct ONLY for today's non-buffering single-shot
# emitters (each emit is a genuinely new frame); a future buffering emitter MUST
# carry a stable id across its own retries or dedup is a no-op for it.
InboundId = Annotated[str, Field(min_length=1, max_length=255)]
```

Then add the field to `InboundMessageNotification` (line 264), immediately after `adapter_id`:

```python
class InboundMessageNotification(_WireModel):
    """Plugin reports a platform message inbound to the host.

    ``body`` is the raw adapter-specific blob (T3 host-side); the host's
    inbound scanner locates the body text via :data:`BODY_FIELD_BY_KIND`.
    ``inbound_id`` is the durable wire dedup key (Spec A decision 4): the host
    commits accept-once on the COMPOSITE ``(adapter_id, inbound_id)`` before any
    side effect, so a replayed frame short-circuits. ``inbound_id`` is opaque
    adapter-supplied metadata (see the :data:`InboundId` trust assumption).
    """

    adapter_id: AdapterId
    inbound_id: InboundId
    platform_user_id: PlatformUserId
    body: Mapping[str, object]
    sub_payload_refs: tuple[str, ...]
    received_at: AwareDatetime
    addressing_signal: InboundAddressingSignal
```

> The field is added immediately after `adapter_id` (the existing model is at
> `protocol.py:264`, with fields `adapter_id, platform_user_id, body,
> sub_payload_refs, received_at, addressing_signal`). Add `"InboundId"` to the
> module `__all__` list (keep it alphabetically sorted — it slots after
> `HealthReport`/before `InboundAddressingSignal`).

- [ ] **Step 4: Update EVERY construction site (both shapes) — verified list**

Find them BOTH ways (use `rg` or plain `grep` — NOT `uv run grep`, which is not a thing):

```bash
rg -n "InboundMessageNotification\(" plugins/ tests/ src/   # Pydantic constructors
rg -n 'method.*inbound|build_inbound_notification|INBOUND_PARAMS|_INBOUND_PARAMS' plugins/ tests/  # raw-dict params builders
```

The construction sites VERIFIED against the code at plan time (update each in
THIS commit; the regexes above re-confirm none drifted in):

**Real Pydantic emitters (production):**

- `plugins/alfred_discord/inbound_emitter.py` (`normalise`, the `return InboundMessageNotification(...)` at ~line 185). Stamp `inbound_id=uuid.uuid4().hex` (a Discord message has an `id`, but G0 only needs a per-emit-unique opaque value; each `normalise` call is a genuinely new frame). Import `uuid` at the top of the file.
- `plugins/alfred_tui/src/alfred_tui/session.py` (`flush_keystroke_batch`, the `note = InboundMessageNotification(...)` at ~line 128). Stamp `inbound_id=uuid.uuid4().hex` — each keystroke-batch flush is a new frame. `uuid` import.

**Raw-params-dict emitter (production reference plugin) — validated host-side via `model_validate`:**

- `plugins/alfred_comms_test/main.py` (`build_inbound_notification`, the `params: dict[str, Any] = {...}` at ~line 182). Add `"inbound_id": uuid.uuid4().hex` to the params dict (the file already imports what it needs; add `import uuid` if absent). This dict is wrapped as a JSON-RPC notification and the host validates it through `InboundMessageNotification.model_validate(raw)` — so a missing `inbound_id` would fail validation host-side, NOT at the plugin.

**Test fixtures / factories / corpora (pass a deterministic or per-call id):**

- `tests/unit/comms_mcp/_inbound_spies.py` — the shared `make_notification(...)` factory (the `return InboundMessageNotification(...)` at ~line 199). Add an `inbound_id: str = ...` keyword that defaults to a unique-per-call value, e.g. `inbound_id: str | None = None` then `inbound_id=inbound_id or uuid.uuid4().hex` in the body, so existing callers (the adversarial corpus, the comms_mcp unit tests) stay green without edits while idempotency tests can pin a fixed id. `uuid` import.
- `tests/unit/comms_mcp/_session_builders.py` — the `INBOUND_PARAMS` dict (~line 33). Add `"inbound_id": "frame-1"` (used by the session-dispatch / fan-out / breaker / handler-failure tests via `model_validate`).
- `tests/integration/test_comms_mcp_session_dispatch_real.py` — the `_INBOUND_PARAMS` dict (~line 51). Add `"inbound_id": "frame-int-1"`.
- The adversarial corpus fixture: `tests/adversarial/comms_identity_boundary/test_cib_corpus_executable.py` drives `process_inbound_message(make_notification(...))` (it uses the shared `make_notification` factory above, so the factory default covers it — re-run the corpus to confirm). Any site that hand-builds a raw inbound params dict in `tests/adversarial/` (re-grep the `prompt_injection/` corpus) must add `inbound_id` too.

> Anything the regexes surface that is NOT in this list is drift since plan time
> — add `inbound_id` there as well; a miss surfaces as a loud `ValidationError`.

- [ ] **Step 5: Run the protocol test + the full comms unit suite + adversarial to verify green**

Run: `uv run pytest tests/unit/comms_mcp/test_protocol_inbound_id.py tests/unit/comms_mcp tests/adversarial/comms_identity_boundary -q`
Expected: PASS — the protocol test passes and no construction site is left without `inbound_id` (any miss surfaces as a loud `ValidationError`).

- [ ] **Step 6: Commit (stage explicit paths — no bare `git add tests/`)**

```bash
git add src/alfred/comms_mcp/protocol.py \
  plugins/alfred_discord/inbound_emitter.py \
  plugins/alfred_tui/src/alfred_tui/session.py \
  plugins/alfred_comms_test/main.py \
  tests/unit/comms_mcp/test_protocol_inbound_id.py \
  tests/unit/comms_mcp/_inbound_spies.py \
  tests/unit/comms_mcp/_session_builders.py \
  tests/integration/test_comms_mcp_session_dispatch_real.py
git commit -m "feat(comms): add required inbound_id wire field to InboundMessageNotification (Spec A G0)"
```

---

### Task 5: Integrate the commit-once guard into `process_inbound_message`

**Files:**

- Modify: `src/alfred/comms_mcp/inbound.py`
- Test: `tests/unit/comms_mcp/test_inbound_idempotency_guard.py`

> Placement: **after** the cheap-validate (line ~382) and the M2 promoter-required guard (line ~410), and **before** `audit_hash.set_broker` / the pre-resolution limiter (line ~417). This makes the commit the first per-message side effect, so a duplicate short-circuits every downstream effect (limiter budget, binding request, extract, audit, ingest, dispatch) — including the unbound-first-contact binding branch, which is therefore idempotent on the same id by construction. Structural refusals (cheap-validate, promoter-required) stay ahead of the commit so a misconfig always fails loud and never consumes an idempotency row.

> **VERIFIED test doubles.** There is NO `tests/unit/comms_mcp/conftest.py` and
> NO `make_orchestrator`/`make_identity_resolver`/`make_burst_limiter`/
> `make_audit_writer`/`make_secret_broker` factories — those were INVENTED. The
> real doubles are `Spy*` classes in `tests/unit/comms_mcp/_inbound_spies.py`:
> `SpyOrchestrator()`, `SpyIdentityResolver(returns=...)`, `SpyBurstLimiter()`,
> `SpyAuditWriter()`, `SpySecretBroker()`, plus the `make_notification(...)`
> factory and `make_resolved(...)` helper. They expose INTEGER COUNTERS, NOT
> booleans: `resolve_calls`, `quarantined_extract_calls`, `ingest_calls`,
> `dispatch_calls`, `acquire_calls`. Assert `== 0` for the replay short-circuit
> and `>= 1`/`== 1` for the happy path. (These are the same doubles the
> adversarial corpus and the existing `test_inbound_*.py` use.)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/comms_mcp/test_inbound_idempotency_guard.py`:

```python
"""process_inbound_message commits accept-once before side effects; a replay short-circuits."""

from __future__ import annotations

import pytest

from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.inbound import process_inbound_message
from tests.unit.comms_mcp._inbound_spies import (
    SpyAuditWriter,
    SpyBurstLimiter,
    SpyIdentityResolver,
    SpyOrchestrator,
    SpySecretBroker,
    make_notification,
    make_resolved,
)

pytestmark = pytest.mark.asyncio


class _FakeStore:
    def __init__(self, *, won: bool) -> None:
        self._won = won
        self.calls: list[tuple[str, str]] = []

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        self.calls.append((inbound_id, adapter_id))
        return self._won


async def test_new_message_commits_then_proceeds_to_dispatch() -> None:
    store = _FakeStore(won=True)
    resolver = SpyIdentityResolver(returns=make_resolved())
    orch = SpyOrchestrator()
    await process_inbound_message(
        make_notification(inbound_id="frame-1", adapter_id="alfred_comms_test"),
        identity_resolver=resolver,
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
    )
    assert store.calls == [("frame-1", "alfred_comms_test")]
    # The pipeline ran end-to-end (integer counters, not booleans).
    assert resolver.resolve_calls == 1
    assert orch.quarantined_extract_calls == 1
    assert orch.dispatch_calls == 1


async def test_replay_short_circuits_before_any_side_effect() -> None:
    store = _FakeStore(won=False)
    resolver = SpyIdentityResolver(returns=make_resolved())
    orch = SpyOrchestrator()
    await process_inbound_message(
        make_notification(inbound_id="frame-1", adapter_id="alfred_comms_test"),
        identity_resolver=resolver,
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
    )
    assert store.calls == [("frame-1", "alfred_comms_test")]
    # NOTHING downstream ran — the replay was a clean DROP.
    assert resolver.resolve_calls == 0
    assert orch.quarantined_extract_calls == 0
    assert orch.dispatch_calls == 0


async def test_replay_writes_exactly_one_content_free_audit_row() -> None:
    # A replay DROP is a side effect, so it must be observable in the SIGNED
    # audit log — content-free, carrying a peppered hash of inbound_id (never
    # the raw string).
    store = _FakeStore(won=False)
    audit = SpyAuditWriter()
    broker = SpySecretBroker()
    await process_inbound_message(
        make_notification(inbound_id="frame-dup", adapter_id="alfred_comms_test"),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=broker,
        idempotency_store=store,
    )
    rows = audit.rows_with_schema("COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS")
    assert len(rows) == 1
    row = rows[0]
    # The production guard wired audit_hash to broker; recompute the digest
    # through the same authoritative helper.
    assert row["inbound_id_hash"] == audit_hash.hash_inbound_id("frame-dup")
    assert "frame-dup" not in str(row)  # raw id never on the row


async def test_none_store_preserves_legacy_behavior() -> None:
    orch = SpyOrchestrator()
    await process_inbound_message(
        make_notification(inbound_id="frame-1", adapter_id="alfred_comms_test"),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=None,
    )
    assert orch.dispatch_calls == 1  # no store => pipeline runs as before
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/comms_mcp/test_inbound_idempotency_guard.py -v`
Expected: FAIL — `process_inbound_message() got an unexpected keyword argument 'idempotency_store'`.

- [ ] **Step 3: Add the `hash_inbound_id` recipe + the replay audit field-set**

The replay-observed row must carry a PEPPERED HASH of `inbound_id`, never the
raw adapter string. Extend the authoritative comms hash recipe + add a field-set.

(a) In `src/alfred/comms_mcp/audit_hash.py`, add an `inbound_id` recipe following
the EXISTING per-field pattern (verified: the module has `_PLATFORM_USER_PREFIX`,
`_CHANNEL_PREFIX`, `_GUILD_PREFIX`, `_VERIFICATION_PHRASE_PREFIX` byte constants,
a private `_hash(prefix, raw)` HMAC helper, and per-field `hash_*` wrappers in
`__all__`):

```python
# near the other _*_PREFIX Final byte constants (line ~63):
_INBOUND_ID_PREFIX: Final = b"inbound_id:"

# near the other hash_* wrappers (line ~151), mirroring hash_platform_user_id:
def hash_inbound_id(raw: str) -> str:
    """Keyed hash of a wire ``inbound_id`` for the replay-observed audit row.

    Per-field domain separation (the ``inbound_id:`` prefix) means an
    ``inbound_id`` digest can never collide with a platform-user-id / phrase
    digest under the same comms subkey.
    """
    return _hash(_INBOUND_ID_PREFIX, raw)
```

Add `"hash_inbound_id"` to the `audit_hash.__all__` list (keep it sorted).

(b) In `src/alfred/audit/audit_row_schemas.py`, add the field-set next to
`COMMS_INBOUND_BUDGET_CAPPED_FIELDS` (line ~1016) and append its name to the
module `__all__`:

```python
COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        # The peppered hash of the wire inbound_id (never the raw string). A
        # replay DROP is content-free: NO body, NO user text, NO platform id.
        "inbound_id_hash",
        "observed_at",
    }
)
```

> No NEW `result` value is needed: the replay short-circuit reuses the EXISTING
> `result="dropped"` value (already in the `ck_audit_log_result` CHECK constraint
> from migration 0016 — verified), so this PR adds NO audit-result migration. The
> row's `trust_tier_of_trigger` is `"T3"` (plugin-triggered, like the sibling
> budget-capped / binding rows). If a schema-registry test enumerates the comms
> field-sets (mirror of `test_catalog_*`), register the new constant there too.

- [ ] **Step 4: Add the protocol, parameter, guard, and replay-audit emitter**

In `src/alfred/comms_mcp/inbound.py`:

(a) Add the structural protocol near the other `_*Like` protocols (top of the module):

```python
@runtime_checkable
class _InboundIdempotencyStoreLike(Protocol):
    """Structural type for the durable accept-once commit (Spec A / G0)."""

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool: ...
```

(b) Add the keyword-only parameter to `process_inbound_message` (defaulted `None` so existing unit callers stay valid; production always injects):

```python
    sub_payload_promoter: _SubPayloadPromoterLike | None = None,
    idempotency_store: _InboundIdempotencyStoreLike | None = None,
) -> None:
```

(c) Add the content-free replay-audit emitter alongside the other `_emit_*`
helpers in the module (it mirrors `_emit_budget_capped_pre_resolution`'s shape):

```python
async def _emit_idempotency_replay_observed(
    notification: InboundMessageNotification,
    *,
    audit_writer: _AuditWriterLike,
) -> None:
    """Emit the content-free replay-observed row when the commit-once loses.

    A replay short-circuit is a side-effecting DROP, so it must be visible in the
    SIGNED audit log — not just a structlog line. The row carries ONLY the
    adapter id, the PEPPERED HASH of the wire ``inbound_id`` (never the raw
    string — sec-010), and the observation time. ``result="dropped"`` reuses the
    existing comms drop result value (no new migration).
    """
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS,
        schema_name="COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS",
        event="comms.inbound.idempotency.replay_observed",
        actor_user_id=None,
        subject={
            "adapter_id": notification.adapter_id,
            "inbound_id_hash": audit_hash.hash_inbound_id(notification.inbound_id),
            "observed_at": datetime.now(UTC).isoformat(),
        },
        trust_tier_of_trigger="T3",
        result="dropped",
        cost_estimate_usd=0.0,
        trace_id=audit_hash.hash_inbound_id(notification.inbound_id),
    )
```

(d) Insert the guard between the M2 promoter-required guard (ends ~line 410 with
`raise PromoterRequiredError(msg)`) and the `audit_hash.set_broker(secret_broker)`
line (~417). The guard must wire the broker FIRST so `hash_inbound_id` resolves
the comms subkey (it follows the same `set_broker(secret_broker)` precondition
the rest of the hashing relies on — call it inside the duplicate branch):

```python
    # Spec A decision 4 (G0): durable accept-once commit on the COMPOSITE
    # (adapter_id, inbound_id), BEFORE any per-message side effect (limiter budget
    # / resolve / binding / extract / audit / ingest / dispatch). A replayed frame
    # (gateway buffer replay after a core restart, or an adapter retry) hits the
    # existing row and short-circuits here so NONE of the side effects re-run —
    # including the unbound-first-contact binding branch, idempotent on the same
    # id by construction. Structural refusals (cheap-validate, promoter-required)
    # stay AHEAD of this so a misconfig fails loud and never consumes an
    # idempotency row. Placed BEFORE the pre-resolution DoS limiter so a replay
    # never re-charges the coarse budget (which would defeat G0). ``None`` store =
    # pre-G0 unit callers; production always injects. A DB error in commit_once
    # PROPAGATES (the store fails loud — hard rule #7); it is not caught here.
    if idempotency_store is not None and not await idempotency_store.commit_once(
        inbound_id=notification.inbound_id,
        adapter_id=notification.adapter_id,
    ):
        # The replay DROP is a side effect → it is AUDITED (signed log), not just
        # logged. Wire the broker so hash_inbound_id can derive the comms subkey.
        audit_hash.set_broker(secret_broker)
        await _emit_idempotency_replay_observed(notification, audit_writer=audit_writer)
        _log.info(
            "comms.inbound.idempotency.replay_short_circuit",
            adapter_id=notification.adapter_id,
        )
        return
```

> Leave the existing `inbound_message_id = uuid.uuid4().hex` (line ~493) untouched — it is the post-extract observability id, not the dedup key (spec §7).
> `audit_hash`, `audit_row_schemas`, `datetime`, `UTC`, and `_log` are already imported at the top of `inbound.py` (verified).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/comms_mcp/test_inbound_idempotency_guard.py -v`
Expected: PASS (4 tests — won / replay-no-side-effect / replay-writes-audit-row / none-store).

- [ ] **Step 6: Run the full inbound unit suite + adversarial (no regressions)**

Run: `uv run pytest tests/unit/comms_mcp tests/adversarial/comms_identity_boundary -q`
Expected: PASS — existing tests pass `idempotency_store=None` implicitly and behave as before.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/comms_mcp/inbound.py \
  src/alfred/comms_mcp/audit_hash.py \
  src/alfred/audit/audit_row_schemas.py \
  tests/unit/comms_mcp/test_inbound_idempotency_guard.py
git commit -m "feat(comms): commit accept-once + audited replay before side effects in process_inbound_message (Spec A G0)"
```

---

### Task 6: Thread the store through `InboundMessageHandler`

**Files:**

- Modify: `src/alfred/comms_mcp/handlers.py`
- Test: `tests/unit/comms_mcp/test_inbound_handler_forwards_store.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/comms_mcp/test_inbound_handler_forwards_store.py`:

```python
"""InboundMessageHandler forwards its idempotency_store to process_inbound_message."""

from __future__ import annotations

import pytest

from alfred.comms_mcp.handlers import InboundMessageHandler
from tests.unit.comms_mcp._inbound_spies import (
    SpyAuditWriter,
    SpyBurstLimiter,
    SpyIdentityResolver,
    SpyOrchestrator,
    SpySecretBroker,
    make_notification,
    make_resolved,
)

pytestmark = pytest.mark.asyncio


class _FakeStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        self.calls.append((inbound_id, adapter_id))
        return True


async def test_handler_forwards_store_to_pipeline() -> None:
    store = _FakeStore()
    handler = InboundMessageHandler(
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
    )
    await handler.process(
        make_notification(inbound_id="frame-9", adapter_id="alfred_comms_test")
    )
    assert store.calls == [("frame-9", "alfred_comms_test")]
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_inbound_handler_forwards_store.py -v`
Expected: FAIL — `InboundMessageHandler.__init__() got an unexpected keyword argument 'idempotency_store'`.

- [ ] **Step 3: Thread the store through the handler**

In `src/alfred/comms_mcp/handlers.py`: import `_InboundIdempotencyStoreLike` from `alfred.comms_mcp.inbound` (alongside the other `_*Like` re-exports), add the constructor parameter (keyword-only, `None` default), store it, and forward it in `process`:

```python
    def __init__(
        self,
        *,
        identity_resolver: _IdentityResolverLike,
        orchestrator: _OrchestratorLike,
        burst_limiter: _BurstLimiterLike,
        audit_writer: _AuditWriterLike,
        secret_broker: _SecretBrokerLike,
        pre_resolution_limiter: _PreResolutionLimiter | None = None,
        sub_payload_promoter: _SubPayloadPromoterLike | None = None,
        idempotency_store: _InboundIdempotencyStoreLike | None = None,
    ) -> None:
        # ... existing assignments ...
        self._idempotency_store = idempotency_store

    async def process(self, notification: InboundMessageNotification) -> None:
        await process_inbound_message(
            notification,
            identity_resolver=self._identity_resolver,
            orchestrator=self._orchestrator,
            burst_limiter=self._burst_limiter,
            audit_writer=self._audit_writer,
            secret_broker=self._secret_broker,
            pre_resolution_limiter=self._pre_resolution_limiter,
            sub_payload_promoter=self._sub_payload_promoter,
            idempotency_store=self._idempotency_store,
        )
```

> Match the actual attribute names/structure already in `handlers.py` (read it first; the existing `process` already forwards most of these).

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_inbound_handler_forwards_store.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/handlers.py tests/unit/comms_mcp/test_inbound_handler_forwards_store.py
git commit -m "feat(comms): thread idempotency_store through InboundMessageHandler (Spec A G0)"
```

---

### Task 7: Build + inject the store in the daemon boot graph

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py`
- Modify: `tests/unit/cli/daemon/test_daemon_promoter_wiring.py` (the direct `_CommsBootGraph(...)` constructor breaks on the new field)
- Test: `tests/unit/cli/daemon/test_daemon_idempotency_store_wired.py` (new — modelled on `test_daemon_promoter_wiring.py`)

> **VERIFIED wiring topology.** `_CommsBootGraph` is `@dataclass(frozen=True,
> slots=True)` (line 384). The store is BUILT in `_build_comms_boot_graph`
> (async; line 451) — the same place the `content_store` / `quarantine_transport`
> / `resolver_bridge` are built — and added as a `_CommsBootGraph` field. It is
> INJECTED into the handler in `_build_comms_adapter_wiring` (line 573), where
> the real `InboundMessageHandler(...)` construction lives (line 652), via the
> `graph` param — NOT in `_build_comms_boot_graph` (which builds no handler). The
> whole comms graph is built ONLY when `settings.comms_enabled_adapters` is
> non-empty (the `if settings.comms_enabled_adapters:` guard at line ~1591), NOT
> "unconditionally".

- [ ] **Step 1: Read the boot wiring**

Read `src/alfred/cli/daemon/_commands.py` around the `_CommsBootGraph` dataclass (line 384), `_build_comms_boot_graph` (line 451, async), `build_boot_session_scope` (line 160), `_build_comms_adapter_wiring` (line 573) and the `InboundMessageHandler(...)` construction inside it (line 652). Confirm `build_boot_session_scope(settings)` returns the zero-arg `session_scope` callable other durable writers use (it wraps `alfred.memory.db.build_session_scope`).

- [ ] **Step 2: Write the failing test (model it on `test_daemon_promoter_wiring.py`)**

Create `tests/unit/cli/daemon/test_daemon_idempotency_store_wired.py`. Model it
EXACTLY on `test_daemon_promoter_wiring.py::test_enabled_empty_set_adapter_wires_none_promoter`:
spy `InboundMessageHandler.__init__` kwargs via `monkeypatch`, boot the daemon
through `CliRunner().invoke(daemon_app, ["start"])` with `_patch_comms_seams`,
and assert the captured `idempotency_store` kwarg is a non-None
`PostgresInboundIdempotencyStore`. Reuse the SAME fixtures
(`boot_success_env`, `quarantine_registry`, `patch_quarantine_child_spawn`) and
the `_ENABLED_ADAPTER` / `_patch_comms_seams` helpers from
`test_daemon_comms_spawn`.

```python
from alfred.cli.daemon import daemon_app
from alfred.comms_mcp.handlers import InboundMessageHandler
from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore
from .conftest import FakeAuditWriter
from .test_daemon_comms_spawn import _ENABLED_ADAPTER, _patch_comms_seams, quarantine_registry

__all__ = ["quarantine_registry"]  # re-exported fixture; silence unused-import lint


def test_enabled_adapter_wires_idempotency_store(
    monkeypatch, tmp_path, boot_success_env, quarantine_registry, patch_quarantine_child_spawn
):
    del quarantine_registry, patch_quarantine_child_spawn
    captured = []
    original_init = InboundMessageHandler.__init__

    def _spy_init(self, **kwargs):
        captured.append(kwargs.get("idempotency_store"))
        original_init(self, **kwargs)

    monkeypatch.setattr(InboundMessageHandler, "__init__", _spy_init)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert isinstance(captured[0], PostgresInboundIdempotencyStore)
```

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_idempotency_store_wired.py -v`
Expected: FAIL — the handler is built with no `idempotency_store` (the captured value is `None`/absent).

- [ ] **Step 3: Wire the store**

In `src/alfred/cli/daemon/_commands.py`:

(a) Add a CONCRETELY-typed field to the `@dataclass(frozen=True, slots=True)`
`_CommsBootGraph` (NOT `object` — that defeats `mypy --strict`). Use a
`TYPE_CHECKING` import so the module import closure stays free of the memory
package at runtime, mirroring how `content_store` is documented:

```python
# in the TYPE_CHECKING block at the top of the module:
if TYPE_CHECKING:
    from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore

# on _CommsBootGraph, alongside content_store:
    # The daemon-owned durable accept-once store (Spec A G0). Built once in
    # `_build_comms_boot_graph` and injected into every per-adapter handler. It
    # owns its `session_scope` over the SHARED cached engine — it must NOT be
    # disposed here (no `aclose` for it): `dispose_all_engines()` reaps that one
    # cached engine at process exit, and disposing it on graph teardown would
    # pull the pool out from under the rest of the daemon that shares it.
    idempotency_store: PostgresInboundIdempotencyStore
```

(b) In `_build_comms_boot_graph`, construct it (inside the post-spawn `try`,
alongside the recorder/bridge/limiter assembly so a construction failure is reaped
by the existing `except` that closes the transport + content store):

```python
    from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore

    # Owns its session_scope over the SHARED cached engine (the audit_writer
    # shape). Deliberately NO aclose: the cached engine is reaped once by
    # dispose_all_engines() at process exit; disposing it on graph teardown would
    # break every other daemon component that shares it (resolved-open-question:
    # shared-engine, must-not-dispose).
    idempotency_store = PostgresInboundIdempotencyStore(
        session_scope=build_boot_session_scope(settings),
    )
```

…and pass `idempotency_store=idempotency_store` into the `_CommsBootGraph(...)` constructor (line 536).

(c) Inject it into the handler at line 652 inside `_build_comms_adapter_wiring`
(it already receives `graph: _CommsBootGraph`):

```python
    inbound_handler = InboundMessageHandler(
        identity_resolver=graph.resolver_bridge,  # type: ignore[arg-type]
        orchestrator=graph.inbound_orchestrator,
        burst_limiter=graph.burst_limiter,  # type: ignore[arg-type]
        audit_writer=audit,  # type: ignore[arg-type]
        secret_broker=graph.secret_broker,  # type: ignore[arg-type]
        sub_payload_promoter=sub_payload_promoter,  # type: ignore[arg-type]
        idempotency_store=graph.idempotency_store,  # type: ignore[arg-type]
    )
```

- [ ] **Step 4: Fix the direct `_CommsBootGraph(...)` constructor in the existing test**

The new required frozen/slots field BREAKS the direct `_CommsBootGraph(...)`
construction in
`tests/unit/cli/daemon/test_daemon_promoter_wiring.py::test_graph_aclose_skips_close_for_non_content_store`
(it builds the dataclass positionally/by-kwarg with the old field set). Add an
`idempotency_store=object()` kwarg to that construction (the test only exercises
`aclose`, which never touches the store, so a placeholder is fine — match the
`# type: ignore[arg-type]` style the test already uses for `inbound_orchestrator`
/ `t3_nonce` / `quarantine_transport`):

```python
    graph = _CommsBootGraph(
        secret_broker=object(),
        resolver_bridge=object(),
        extractor_bridge=object(),
        burst_limiter=object(),
        inbound_orchestrator=object(),  # type: ignore[arg-type]
        t3_nonce=object(),  # type: ignore[arg-type]
        quarantine_transport=_FakeTransport(),  # type: ignore[arg-type]
        content_store=not_a_store,
        idempotency_store=object(),  # type: ignore[arg-type]  # unused by aclose
    )
```

- [ ] **Step 5: Run to verify it passes + the daemon suite is green**

Run: `uv run pytest tests/unit/cli/daemon -q`
Expected: PASS (the new wiring test + the existing promoter-wiring tests, including the patched `aclose` test).

- [ ] **Step 6: Commit (stage explicit paths)**

```bash
git add src/alfred/cli/daemon/_commands.py \
  tests/unit/cli/daemon/test_daemon_idempotency_store_wired.py \
  tests/unit/cli/daemon/test_daemon_promoter_wiring.py
git commit -m "feat(daemon): build + inject InboundIdempotencyStore into the inbound handler (Spec A G0)"
```

---

### Task 8: Integration test — real Postgres concurrency (exactly-one winner)

**Files:**

- Create: `tests/integration/test_inbound_idempotency_postgres.py`

- [ ] **Step 1: Write the test**

Create `tests/integration/test_inbound_idempotency_postgres.py`:

```python
"""InboundIdempotencyStore against real Postgres: first-wins / replay-noop / concurrent-one."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.memory.db import session_scope
from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore

pytestmark = pytest.mark.integration


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0018
    return postgres_url


@pytest.fixture
async def store(migrated_url: str) -> AsyncIterator[PostgresInboundIdempotencyStore]:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresInboundIdempotencyStore(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


async def test_first_commit_wins(store: PostgresInboundIdempotencyStore) -> None:
    assert await store.commit_once(inbound_id="frame-1", adapter_id="tui") is True


async def test_replay_is_noop_duplicate(store: PostgresInboundIdempotencyStore) -> None:
    assert await store.commit_once(inbound_id="frame-2", adapter_id="tui") is True
    assert await store.commit_once(inbound_id="frame-2", adapter_id="tui") is False


async def test_concurrent_commits_exactly_one_winner(
    store: PostgresInboundIdempotencyStore,
) -> None:
    results = await asyncio.gather(
        *(store.commit_once(inbound_id="frame-3", adapter_id="tui") for _ in range(8))
    )
    assert sum(results) == 1  # exactly one True across 8 concurrent commits


async def test_same_id_different_adapters_both_win(
    store: PostgresInboundIdempotencyStore,
) -> None:
    # The COMPOSITE key isolates each adapter's namespace: the SAME inbound_id
    # under two DIFFERENT adapters is two distinct rows — neither drops the other
    # (the denial-of-delivery the composite key exists to prevent).
    assert await store.commit_once(inbound_id="shared-id", adapter_id="tui") is True
    assert await store.commit_once(inbound_id="shared-id", adapter_id="discord") is True
    # …and each is still individually idempotent on its own adapter.
    assert await store.commit_once(inbound_id="shared-id", adapter_id="tui") is False


async def test_distinct_id_flood_writes_one_row_per_distinct_id(
    store: PostgresInboundIdempotencyStore,
) -> None:
    # A flood of DISTINCT ids drives one Postgres write per frame (resolved
    # open-question): N distinct ids => N winners (N ledger rows). G0 does NOT
    # cap this — the coarse pre-resolution DoS limiter (downstream, per
    # (adapter_id, platform_user_id_hash)) is what caps a distinct-id flood in
    # the real pipeline; the ledger's job is correctness, not rate-limiting.
    # Documented + a tracked committed_at-based prune follow-up (see plan note).
    results = [
        await store.commit_once(inbound_id=f"flood-{i}", adapter_id="tui")
        for i in range(50)
    ]
    assert all(results)  # every distinct id is a fresh winner — N rows
```

> Confirm the `postgres_url` fixture name/shape against `tests/integration/conftest.py` and `tests/integration/test_users_postgres.py`; adapt if the project's fixture is named differently.

- [ ] **Step 2: Run the integration test**

Run: `uv run pytest tests/integration/test_inbound_idempotency_postgres.py -v`
Expected: PASS (5 tests; the container boots Postgres 16 and applies migrations to head incl. 0018).

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_inbound_idempotency_postgres.py
git commit -m "test(integration): InboundIdempotencyStore exactly-one-winner under real Postgres (Spec A G0)"
```

---

### Task 9: Quality gates + security review + PR

**Files:** none (verification + review).

- [ ] **Step 1: Full local gate**

Run: `make check`
Expected: ruff check + ruff format + `mypy --strict src/` + `pyright src/` + unit suite all green. (Known-acceptable failure: `tests/integration/test_alfred_core_image_bwrap.py` `/lib64` arm64-docker OR a transient PyPI download flake — both infra, not this change.)

- [ ] **Step 2: Coverage of the new trust-boundary code**

Run: `uv run pytest tests/unit/memory tests/unit/comms_mcp --cov=alfred.memory.inbound_idempotency --cov=alfred.comms_mcp.inbound --cov=alfred.comms_mcp.audit_hash --cov-branch --cov-report=term-missing -q`
Expected: the new `commit_once` (won / duplicate / DB-error-propagates), the guard branch (won / replay-with-audit-row / None-store), and `hash_inbound_id` are all covered.

- [ ] **Step 3: Security review (REQUIRED — trust-boundary change)**

Dispatch `alfred-security-engineer` to review the committed diff against `origin/main`. Focus:
  (a) the commit-once guard sits **before** every per-message side effect and **after** the structural refusals (cheap-validate, promoter-required) — confirm a replay cannot re-charge the pre-resolution limiter, re-emit a binding request, re-run the extractor, or re-write a T3-promotion audit row;
  (b) the ledger holds **no** T3/user content (no body, no `platform_user_id`); `adapter_id`/`inbound_id` are non-user metadata, so no `language` column;
  (c) `commit_once` is genuinely race-free (the single-statement `ON CONFLICT (adapter_id, inbound_id) … RETURNING` claim) and fails loud (no `except: pass`; `SQLAlchemyError` propagates) on a DB error;
  (d) **composite key:** confirm the `(adapter_id, inbound_id)` PK actually isolates each adapter's id namespace so a buggy/malicious adapter reusing another's id cannot drop a distinct real message (the denial-of-delivery the single-column key risked) — and that `adapter_id` is the host-validated `AdapterId` (a known `adapter_kind` member), not free wire text;
  (e) **replay audit:** confirm the `comms.inbound.idempotency.replay_observed` row is content-free, carries the PEPPERED `hash_inbound_id(inbound_id)` (per-field domain-separated so it cannot collide with a user-id/phrase digest) and NEVER the raw `inbound_id`, and that the duplicate path writes EXACTLY ONE such row;
  (f) the new `inbound_id` wire field cannot collide two distinct frames (bounded, non-empty) and the stated trust assumption (opaque adapter metadata, shape-validated only in G0) is sound. Address findings before merge.

- [ ] **Step 4: Open the PR**

```bash
git push -u origin <branch>
gh pr create --title "feat(comms): core inbound idempotency commit (Spec A G0, #237)" --body "<summary: spec ref; the dedup-before-side-effect guarantee; the 0018 ledger off head 0017; the COMPOSITE (adapter_id, inbound_id) PK + its denial-of-delivery rationale; the wire inbound_id field + its opaque-metadata trust assumption; the content-free signed replay-observed audit row; the exactly-one-winner + same-id-different-adapters + distinct-id-flood integration proofs; note this is PR 1 of the Comms-Resume Gateway, prerequisite for gateway replay-safety; note the tracked committed_at-prune follow-up; note the alfred-security-engineer review outcome>"
```

- [ ] **Step 5: Run the full `/review-pr` fleet, address findings, then CodeRabbit + merge** (per the project's standing PR cadence — plain `gh pr merge --rebase --delete-branch`, never `--admin`).

---

## Self-review notes

- **Spec coverage:** §2 decision 4 (durable inbound-id + dedup-before-side-effect) → Tasks 4+5; §7 component (`InboundIdempotencyStore`, commit-before-pipeline, binding branch idempotent, NOT the late uuid4) → Tasks 3+5; §8 G0 (schema migration with memory-engineer) → Tasks 1+2; the §6/§9 release-blocking "exactly-once" property at the DB layer → Task 8 (the full restart-at-a-barrier e2e proof lives in G4, above G0). Security review (§ note, composite-PK + replay-audit additions) → Task 9.
- **Design ratifications (multi-specialist consensus):** the COMPOSITE `(adapter_id, inbound_id)` PK (against single-column denial-of-delivery) ripples through migration 0018 (Task 1), the model `__table_args__` (Task 2), and the store SQL + every `commit_once` call (Task 3) — verified consistent. The signed content-free replay-observed audit row (against a silent DROP) is wired in the guard via a new `audit_hash.hash_inbound_id` recipe + `COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS` reusing `result="dropped"` (no audit-result migration) (Task 5), with a unit test asserting exactly-one-row-with-the-hash.
- **Real (verified) test doubles — no inventions:** Task 5/6 use the EXISTING `Spy*` classes in `tests/unit/comms_mcp/_inbound_spies.py` (`SpyOrchestrator`, `SpyIdentityResolver(returns=...)`, `SpyBurstLimiter`, `SpyAuditWriter`, `SpySecretBroker`, `make_notification`, `make_resolved`) with their INTEGER counters (`resolve_calls`, `quarantined_extract_calls`, `dispatch_calls`) — there is NO `conftest.py` `make_*` factory (the originally-planned imports did not exist). Task 3's store unit test injects a FAKE `session_scope` (the `tests/unit/identity/test_resolve_operator.py` precedent) — NO `aiosqlite` (not a dep). Task 7's wiring test is modelled on `test_daemon_promoter_wiring.py` (spies `InboundMessageHandler.__init__` kwargs) and patches the direct `_CommsBootGraph(...)` constructor that the new frozen/slots field breaks.
- **Type consistency:** `commit_once(*, inbound_id: str, adapter_id: str) -> bool` is identical across the Protocol (Task 3), the `_InboundIdempotencyStoreLike` structural type (Task 5), the handler forward (Task 6), and the fakes. `InboundId`/`inbound_id` is consistent across protocol, model column (`String(255)`), and migration (`String(255)`). The `_CommsBootGraph.idempotency_store` field is typed CONCRETELY (`PostgresInboundIdempotencyStore` via `TYPE_CHECKING` import), not `object`, so `mypy --strict` holds.
- **Resource lifecycle (preserved):** the store owns its `session_scope` over the SHARED cached engine and has NO `aclose` — `dispose_all_engines()` reaps that one cached engine at process exit; disposing it on graph teardown would break every other daemon component sharing it. The comms graph is guarded by `if settings.comms_enabled_adapters` (not "built unconditionally").
