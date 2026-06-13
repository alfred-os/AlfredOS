# G0 — Core Inbound Idempotency Commit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable, Postgres-backed "accept-once" commit keyed on a wire-supplied `inbound_id`, consulted at the top of the inbound trust-boundary pipeline so a replayed comms frame short-circuits before any side effect (limiter / resolve / binding / extract / audit / ingest / dispatch) re-runs.

**Architecture:** A new `inbound_idempotency` dedup ledger (Alembic migration 0018) + a `PostgresInboundIdempotencyStore` whose only operation is an atomic `INSERT … ON CONFLICT (inbound_id) DO NOTHING RETURNING inbound_id` (race-free winner/loser signal). The store is injected into `process_inbound_message` as a pre-built object (the same shape `audit_writer` uses — it owns its `session_scope`, the entrypoint never touches a raw session). `InboundMessageNotification` gains a required `inbound_id` wire field. This is the first PR of the Comms-Resume Gateway (Spec A) and is independently valuable: it makes inbound processing idempotent against adapter retries today, and is the prerequisite for gateway buffer-replay safety later.

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
| `src/alfred/comms_mcp/inbound.py` | `_InboundIdempotencyStoreLike` Protocol + `idempotency_store` param + commit-once guard | Modify |
| `src/alfred/comms_mcp/handlers.py` | Thread `idempotency_store` through `InboundMessageHandler` | Modify |
| `src/alfred/cli/daemon/_commands.py` | Build the store on the boot graph + inject into the handler | Modify |
| `plugins/alfred_comms_test/main.py` + inbound test fixtures | Stamp `inbound_id` on emitted notifications (forced by `extra="forbid"`) | Modify |
| `tests/unit/comms/test_inbound_idempotency_store.py` | Unit test the store (SQLite in-memory) | **New** |
| `tests/integration/test_inbound_idempotency_postgres.py` | Integration: first-wins / replay-noop / concurrent-exactly-one (testcontainers Postgres) | **New** |
| `tests/integration/test_migration_0018_inbound_idempotency.py` | Migration forward+backward test | **New** |

**Key invariants for the implementer:**
1. The dedup key is the **wire `inbound_id`**, never the late `uuid.uuid4().hex` observability id at `inbound.py:493` (leave that line alone).
2. The commit-once guard runs **after** the two structural guards (cheap-validate, promoter-required) and **before** every per-message side effect (`set_broker`/limiter/resolve/binding/extract/audit/ingest/dispatch).
3. `commit_once` is a **single** `INSERT … ON CONFLICT DO NOTHING RETURNING` — `scalar_one_or_none() is not None` is the race-free winner signal. No read-then-write.
4. The ledger holds **no body, no user text, no `platform_user_id`** → no `language` column (i18n hard-rule #3 satisfied by construction; the ledger never holds T3 bytes).
5. The store owns its `session_scope` and is injected like `audit_writer`; `process_inbound_message` never handles a raw session.

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
    assert pk["constrained_columns"] == ["inbound_id"]
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
        sa.PrimaryKeyConstraint("inbound_id", name="uq_inbound_idempotency_inbound_id"),
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
    assert [c.name for c in table.primary_key.columns] == ["inbound_id"]
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
        sa.PrimaryKeyConstraint("inbound_id", name="uq_inbound_idempotency_inbound_id"),
        # Postgres-only char_length CHECKs live in migration 0018; SQLite unit
        # tests cannot parse them (PoliciesSnapshotHistory precedent). The
        # dialect-portable named PK + retention index stay here.
        Index("ix_inbound_idempotency_committed_at", "committed_at"),
    )
```

> If `dt` is not the datetime alias used in this file, match the file's existing convention (e.g. `datetime.datetime`). Verify by grepping an existing `Mapped[...]` timestamp column in `models.py`.

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
- Test: `tests/unit/comms/test_inbound_idempotency_store.py`

- [ ] **Step 1: Write the failing unit test (SQLite in-memory — `ON CONFLICT DO NOTHING` works in SQLite too)**

Create `tests/unit/comms/test_inbound_idempotency_store.py`:

```python
"""PostgresInboundIdempotencyStore commit-once semantics (SQLite-backed unit test)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.memory.db import session_scope
from alfred.memory.inbound_idempotency import (
    InboundIdempotencyStore,
    PostgresInboundIdempotencyStore,
)
from alfred.memory.models import Base


@pytest.fixture
async def store() -> AsyncIterator[PostgresInboundIdempotencyStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresInboundIdempotencyStore(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


def test_store_satisfies_protocol(store: PostgresInboundIdempotencyStore) -> None:
    assert isinstance(store, InboundIdempotencyStore)


async def test_first_commit_wins(store: PostgresInboundIdempotencyStore) -> None:
    assert await store.commit_once(inbound_id="frame-1", adapter_id="tui") is True


async def test_replay_is_noop_duplicate(store: PostgresInboundIdempotencyStore) -> None:
    assert await store.commit_once(inbound_id="frame-2", adapter_id="tui") is True
    assert await store.commit_once(inbound_id="frame-2", adapter_id="tui") is False
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/comms/test_inbound_idempotency_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.memory.inbound_idempotency'`.

- [ ] **Step 3: Write the store**

Create `src/alfred/memory/inbound_idempotency.py`:

```python
"""Durable inbound accept-once store (Spec A / G0).

The commit-once primitive the Comms-Resume Gateway needs: the core records
"this inbound was accepted exactly once" keyed on a durable wire ``inbound_id``
BEFORE any side effect runs. A replayed frame short-circuits.

The atomicity contract is a single ``INSERT … ON CONFLICT (inbound_id) DO
NOTHING RETURNING inbound_id`` — Postgres (and SQLite) return a row IFF this
caller won the insert; an existing row yields no rows. There is NO read-then-
write window, so two concurrent commits on the same id produce exactly one
winner.
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
    "ON CONFLICT (inbound_id) DO NOTHING "
    "RETURNING inbound_id"
)


@runtime_checkable
class InboundIdempotencyStore(Protocol):
    """Durable accept-once commit on a wire ``inbound_id`` (Spec A decision 4)."""

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        """Atomically record ``inbound_id`` as accepted.

        Returns ``True`` if THIS call won the insert (the inbound is new — the
        caller proceeds with side effects), ``False`` if a row already existed
        (a replay/retry — the caller short-circuits). Never raises on a
        duplicate; raises ``SQLAlchemyError`` only on a genuine DB failure
        (fail-loud at the boundary — CLAUDE.md hard rule #7).
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

Run: `uv run pytest tests/unit/comms/test_inbound_idempotency_store.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/inbound_idempotency.py tests/unit/comms/test_inbound_idempotency_store.py
git commit -m "feat(memory): PostgresInboundIdempotencyStore commit-once primitive (Spec A G0)"
```

---

### Task 4: Wire field — `inbound_id` on `InboundMessageNotification`

**Files:**
- Modify: `src/alfred/comms_mcp/protocol.py`
- Modify: `plugins/alfred_comms_test/main.py` and every inbound-notification test fixture/factory
- Test: `tests/unit/comms/test_protocol_inbound_id.py`

> `InboundMessageNotification` is `extra="forbid"`, so adding a **required** field makes every emitter that omits it fail validation loudly. This task adds the field AND updates all emitters in the same commit so the suite stays green.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/comms/test_protocol_inbound_id.py`:

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

Run: `uv run pytest tests/unit/comms/test_protocol_inbound_id.py -v`
Expected: FAIL — `test_accepts_a_valid_inbound_id` raises `ValidationError` (extra field `inbound_id` forbidden).

- [ ] **Step 3: Add the `InboundId` type + field**

In `src/alfred/comms_mcp/protocol.py`, add the type near `PlatformUserId` (around line 97):

```python
# The durable wire dedup key the gateway/adapter stamps on each inbound frame
# (Spec A decision 4 / G0). Bounded to match the ``inbound_idempotency.inbound_id``
# column (VARCHAR(255)); non-empty so a blank id can never collapse two frames.
InboundId = Annotated[str, Field(min_length=1, max_length=255)]
```

Then add the field to `InboundMessageNotification` (line 264), immediately after `adapter_id`:

```python
class InboundMessageNotification(_WireModel):
    """Plugin reports a platform message inbound to the host.

    ``body`` is the raw adapter-specific blob (T3 host-side); the host's
    inbound scanner locates the body text via :data:`BODY_FIELD_BY_KIND`.
    ``inbound_id`` is the durable wire dedup key (Spec A decision 4): the host
    commits accept-once on it before any side effect, so a replayed frame
    short-circuits.
    """

    adapter_id: AdapterId
    inbound_id: InboundId
    platform_user_id: PlatformUserId
    body: Mapping[str, object]
    sub_payload_refs: tuple[str, ...]
    received_at: AwareDatetime
    addressing_signal: InboundAddressingSignal
```

Add `"InboundId"` to the `__all__` list.

- [ ] **Step 4: Update every emitter of `InboundMessageNotification`**

Find them: `Run: uv run grep -rl "InboundMessageNotification(" plugins/ tests/ src/` (or ripgrep). For each construction site, add an `inbound_id=...` argument. The production reference plugin `plugins/alfred_comms_test/main.py` must stamp a unique id per emitted message — use a monotonic per-process counter or a `uuid4().hex` (the reference plugin has no durable id source; a `uuid4().hex` is correct there because each emit is a genuinely new frame):

```python
# plugins/alfred_comms_test/main.py — at the inbound emit site
import uuid
# ...
InboundMessageNotification(
    adapter_id=...,
    inbound_id=uuid.uuid4().hex,  # reference plugin: each emit is a new frame
    platform_user_id=...,
    ...
)
```

For test fixtures/factories, pass a deterministic id (e.g. `inbound_id="frame-1"`) so tests stay readable. A shared test factory (if one exists, e.g. a `_make_inbound_notification(...)` helper) should default `inbound_id` to a unique value per call.

- [ ] **Step 5: Run the protocol test + the full comms unit suite to verify green**

Run: `uv run pytest tests/unit/comms/test_protocol_inbound_id.py tests/unit/comms_mcp -q`
Expected: PASS — the protocol test passes and no emitter is left without `inbound_id` (any miss surfaces as a loud `ValidationError`).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/comms_mcp/protocol.py plugins/alfred_comms_test/main.py tests/
git commit -m "feat(comms): add required inbound_id wire field to InboundMessageNotification (Spec A G0)"
```

---

### Task 5: Integrate the commit-once guard into `process_inbound_message`

**Files:**
- Modify: `src/alfred/comms_mcp/inbound.py`
- Test: `tests/unit/comms_mcp/test_inbound_idempotency_guard.py`

> Placement: **after** the cheap-validate (line ~382) and the M2 promoter-required guard (line ~410), and **before** `audit_hash.set_broker` / the pre-resolution limiter (line ~417). This makes the commit the first per-message side effect, so a duplicate short-circuits every downstream effect (limiter budget, binding request, extract, audit, ingest, dispatch) — including the unbound-first-contact binding branch, which is therefore idempotent on the same id by construction. Structural refusals (cheap-validate, promoter-required) stay ahead of the commit so a misconfig always fails loud and never consumes an idempotency row.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/comms_mcp/test_inbound_idempotency_guard.py`:

```python
"""process_inbound_message commits accept-once before side effects; a replay short-circuits."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from alfred.comms_mcp.inbound import process_inbound_message
from alfred.comms_mcp.protocol import InboundMessageNotification

# Reuse the existing test doubles for resolver/orchestrator/burst/audit/broker.
# Import them from the module's existing conftest / test helpers; if a shared
# factory exists (e.g. tests/unit/comms_mcp/conftest.py), prefer it.
from tests.unit.comms_mcp.conftest import (  # type: ignore[import-not-found]
    make_audit_writer,
    make_burst_limiter,
    make_identity_resolver,
    make_orchestrator,
    make_secret_broker,
)


class _FakeStore:
    def __init__(self, *, won: bool) -> None:
        self._won = won
        self.calls: list[tuple[str, str]] = []

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        self.calls.append((inbound_id, adapter_id))
        return self._won


def _note() -> InboundMessageNotification:
    return InboundMessageNotification(
        adapter_id="tui",
        inbound_id="frame-1",
        platform_user_id="u1",
        body={"content": "hi"},
        sub_payload_refs=(),
        received_at=datetime.now(UTC),
        addressing_signal="dm",
    )


async def test_new_message_commits_then_proceeds_to_resolve() -> None:
    store = _FakeStore(won=True)
    resolver = make_identity_resolver(resolves=True)
    orchestrator = make_orchestrator()
    await process_inbound_message(
        _note(),
        identity_resolver=resolver,
        orchestrator=orchestrator,
        burst_limiter=make_burst_limiter(),
        audit_writer=make_audit_writer(),
        secret_broker=make_secret_broker(),
        idempotency_store=store,
    )
    assert store.calls == [("frame-1", "tui")]
    assert orchestrator.dispatch_called  # the pipeline ran end-to-end


async def test_replay_short_circuits_before_any_side_effect() -> None:
    store = _FakeStore(won=False)
    resolver = make_identity_resolver(resolves=True)
    orchestrator = make_orchestrator()
    await process_inbound_message(
        _note(),
        identity_resolver=resolver,
        orchestrator=orchestrator,
        burst_limiter=make_burst_limiter(),
        audit_writer=make_audit_writer(),
        secret_broker=make_secret_broker(),
        idempotency_store=store,
    )
    assert store.calls == [("frame-1", "tui")]
    assert not resolver.resolve_called      # resolve never ran
    assert not orchestrator.extract_called  # extract never ran
    assert not orchestrator.dispatch_called # dispatch never ran


async def test_none_store_preserves_legacy_behavior() -> None:
    orchestrator = make_orchestrator()
    await process_inbound_message(
        _note(),
        identity_resolver=make_identity_resolver(resolves=True),
        orchestrator=orchestrator,
        burst_limiter=make_burst_limiter(),
        audit_writer=make_audit_writer(),
        secret_broker=make_secret_broker(),
        idempotency_store=None,
    )
    assert orchestrator.dispatch_called  # no store => pipeline runs as before
```

> Adapt the imports to the module's actual test doubles. If `tests/unit/comms_mcp/conftest.py` doesn't expose these factories, read the existing `test_inbound_*.py` files and reuse whatever doubles they construct (the doubles already exist — `process_inbound_message` is heavily unit-tested). The assertions on `resolve_called`/`extract_called`/`dispatch_called` may need to match the doubles' actual attribute names.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/comms_mcp/test_inbound_idempotency_guard.py -v`
Expected: FAIL — `process_inbound_message() got an unexpected keyword argument 'idempotency_store'`.

- [ ] **Step 3: Add the protocol, parameter, and guard**

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

(c) Insert the guard between the M2 promoter-required guard (ends ~line 410 with `raise PromoterRequiredError(msg)`) and the `audit_hash.set_broker(secret_broker)` line (~417):

```python
    # Spec A decision 4 (G0): durable accept-once commit on the wire inbound-id,
    # BEFORE any per-message side effect (limiter budget / resolve / binding /
    # extract / audit / ingest / dispatch). A replayed frame (gateway buffer
    # replay after a core restart, or an adapter retry) hits the existing row and
    # short-circuits here so NONE of the side effects re-run — including the
    # unbound-first-contact binding branch, idempotent on the same id by
    # construction. Structural refusals (cheap-validate, promoter-required) stay
    # AHEAD of this so a misconfig fails loud and never consumes an idempotency
    # row. ``None`` store = pre-G0 unit callers; production always injects.
    if idempotency_store is not None and not await idempotency_store.commit_once(
        inbound_id=notification.inbound_id,
        adapter_id=notification.adapter_id,
    ):
        return
```

> Leave the existing `inbound_message_id = uuid.uuid4().hex` (line ~493) untouched — it is the post-extract observability id, not the dedup key (spec §7).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/comms_mcp/test_inbound_idempotency_guard.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full inbound unit suite (no regressions)**

Run: `uv run pytest tests/unit/comms_mcp -q`
Expected: PASS — existing tests pass `idempotency_store=None` implicitly and behave as before.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/comms_mcp/inbound.py tests/unit/comms_mcp/test_inbound_idempotency_guard.py
git commit -m "feat(comms): commit accept-once before side effects in process_inbound_message (Spec A G0)"
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

from datetime import UTC, datetime

import pytest

from alfred.comms_mcp.handlers import InboundMessageHandler
from alfred.comms_mcp.protocol import InboundMessageNotification
from tests.unit.comms_mcp.conftest import (  # type: ignore[import-not-found]
    make_audit_writer,
    make_burst_limiter,
    make_identity_resolver,
    make_orchestrator,
    make_secret_broker,
)


class _FakeStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        self.calls.append((inbound_id, adapter_id))
        return True


async def test_handler_forwards_store_to_pipeline() -> None:
    store = _FakeStore()
    handler = InboundMessageHandler(
        identity_resolver=make_identity_resolver(resolves=True),
        orchestrator=make_orchestrator(),
        burst_limiter=make_burst_limiter(),
        audit_writer=make_audit_writer(),
        secret_broker=make_secret_broker(),
        idempotency_store=store,
    )
    await handler.process(
        InboundMessageNotification(
            adapter_id="tui",
            inbound_id="frame-9",
            platform_user_id="u1",
            body={"content": "hi"},
            sub_payload_refs=(),
            received_at=datetime.now(UTC),
            addressing_signal="dm",
        )
    )
    assert store.calls == [("frame-9", "tui")]
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
- Test: extend the existing daemon-boot test that asserts the inbound handler is wired (find it under `tests/unit/cli/daemon/`).

- [ ] **Step 1: Read the boot wiring**

Read `src/alfred/cli/daemon/_commands.py` around the `_CommsBootGraph` dataclass (~line 385), `_build_comms_boot_graph`, `build_boot_session_scope` (~line 160), and the `InboundMessageHandler(...)` construction (~line 652). Confirm `build_boot_session_scope(settings)` returns the zero-arg `session_scope` callable used by other durable writers.

- [ ] **Step 2: Write/extend the failing test**

Add to the relevant daemon-boot test (or create `tests/unit/cli/daemon/test_daemon_idempotency_store_wired.py`) a test that, after building the comms boot graph (using the existing boot fixtures), the constructed `InboundMessageHandler` has a non-None `_idempotency_store`. If the existing boot tests assert handler wiring via a spy/fixture, mirror that pattern. Expected initial result: FAIL (store is `None`/absent).

- [ ] **Step 3: Wire the store**

In `src/alfred/cli/daemon/_commands.py`:

(a) Add a field to the `_CommsBootGraph` dataclass:

```python
    idempotency_store: object  # PostgresInboundIdempotencyStore (Spec A G0)
```

(b) In `_build_comms_boot_graph`, construct it (it owns only the shared engine pool, which `dispose_all_engines()` already reaps at process exit — no new `aclose()` path needed):

```python
    from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore

    idempotency_store = PostgresInboundIdempotencyStore(
        session_scope=build_boot_session_scope(settings),
    )
```

…and pass `idempotency_store=idempotency_store` into the `_CommsBootGraph(...)` constructor.

(c) Inject it into the handler (~line 652):

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

> Match the actual local names at that call site (read first).

- [ ] **Step 4: Run to verify it passes + the daemon suite is green**

Run: `uv run pytest tests/unit/cli/daemon -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/
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
```

> Confirm the `postgres_url` fixture name/shape against `tests/integration/conftest.py` and `tests/integration/test_users_postgres.py`; adapt if the project's fixture is named differently.

- [ ] **Step 2: Run the integration test**

Run: `uv run pytest tests/integration/test_inbound_idempotency_postgres.py -v`
Expected: PASS (3 tests; the container boots Postgres 16 and applies migrations to head incl. 0018).

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

Run: `uv run pytest tests/unit/comms tests/unit/comms_mcp --cov=alfred.memory.inbound_idempotency --cov=alfred.comms_mcp.inbound --cov-branch --cov-report=term-missing -q`
Expected: the new `commit_once` + the guard branch are covered (new + duplicate + None-store paths).

- [ ] **Step 3: Security review (REQUIRED — trust-boundary change)**

Dispatch `alfred-security-engineer` to review the committed diff against `origin/main`. Focus: (a) the commit-once guard sits **before** every per-message side effect and **after** the structural refusals (cheap-validate, promoter-required) — confirm a replay cannot re-charge the pre-resolution limiter, re-emit a binding request, re-run the extractor, or re-write a T3-promotion audit row; (b) the ledger holds **no** T3/user content (no body, no `platform_user_id`); (c) `commit_once` is genuinely race-free (the `ON CONFLICT … RETURNING` single-statement claim) and fails loud (no `except: pass`) on a DB error; (d) the new `inbound_id` wire field cannot be used to collide two distinct frames (bounded, non-empty). Address findings before merge.

- [ ] **Step 4: Open the PR**

```bash
git push -u origin <branch>
gh pr create --title "feat(comms): core inbound idempotency commit (Spec A G0, #237)" --body "<summary: spec ref, the dedup-before-side-effect guarantee, the 0018 ledger, the wire inbound_id field, the exactly-one-winner integration proof; note this is PR 1 of the Comms-Resume Gateway, prerequisite for gateway replay-safety; note the alfred-security-engineer review outcome>"
```

- [ ] **Step 5: Run the full `/review-pr` fleet, address findings, then CodeRabbit + merge** (per the project's standing PR cadence — plain `gh pr merge --rebase --delete-branch`, never `--admin`).

---

## Self-review notes

- **Spec coverage:** §2 decision 4 (durable inbound-id + dedup-before-side-effect) → Tasks 4+5; §7 component (`InboundIdempotencyStore`, commit-before-pipeline, binding branch idempotent, NOT the late uuid4) → Tasks 3+5; §8 G0 (schema migration with memory-engineer) → Tasks 1+2; the §6/§9 release-blocking "exactly-once" property at the DB layer → Task 8 (the full restart-at-a-barrier e2e proof lives in G4, above G0). Security review (§ note) → Task 9.
- **Placeholder scan:** every code step carries complete code; the only "match the existing names" notes are explicit read-first instructions for the test-double imports and the `_commands.py` local names, which genuinely must be read in-repo (the doubles already exist and vary by test file).
- **Type consistency:** `commit_once(*, inbound_id: str, adapter_id: str) -> bool` is identical across the Protocol (Task 3), the `_InboundIdempotencyStoreLike` structural type (Task 5), the handler forward (Task 6), and the fakes. `InboundId`/`inbound_id` is consistent across protocol, model column (`String(255)`), and migration (`String(255)`).
