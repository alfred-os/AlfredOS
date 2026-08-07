# #410 PR1 — Turn-start/turn-end idempotency ledger — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make two side-effecting call sites inside `Orchestrator._handle_turn` — the user-turn write and the assistant-turn write — idempotent per committed `(adapter_id, inbound_id)`, so a forwarded-path resume (a live-process retry after an outbound-send failure) no longer duplicates conversation context or (previously unnoticed) duplicates the live in-process `WorkingMemory` buffer. **The budget charge is deliberately left ungated** — see Architecture below.

**Architecture:** A new Postgres-backed `TurnSideEffectLedger` (composite `(adapter_id, inbound_id)` PK, two boolean columns), modeled directly on the existing `ForwardedDispatchAttemptStore` (`src/alfred/memory/forwarded_dispatch_attempts.py`) — same atomic `INSERT ... ON CONFLICT ... RETURNING` idiom, same Protocol + Postgres-impl shape, same "durable because replay happens across restarts" rationale, same composite-key precedent (a single-column `inbound_id` key would reintroduce a cross-adapter collision class the sibling table exists to prevent). `Orchestrator` gets a new optional constructor param (`side_effect_ledger: TurnSideEffectLedger | None = None`, additive, defaults preserve every existing caller byte-for-byte). Each of the two call sites is guarded by a "try to apply, tell me if I won the right to" check called BEFORE the guarded effect; on skip, the side effect does not run, but the surrounding turn logic (completion, answer text, send, **budget charge**) proceeds unchanged. **The budget charge is NOT gated by this ledger at all** — an earlier draft of this plan gated it too, but `check_and_charge` fires once per Act-loop iteration (not once per attempt), so a single boolean gate is sound only while tools are off; gating it would silently under-count real spend the instant a future PR enables multi-iteration turns, and a `/review-plan` fleet pass found this design would make the daemon fail to boot once that future PR landed (a construction-time guard against the combination would trip on every boot). Leaving it ungated restores ADR-0049's original, safe over-charge residual — a resumed turn still pays for (and is charged for) a fresh provider completion, exactly as before this PR.

**Tech Stack:** Python 3.14, SQLAlchemy 2.0 async, Alembic, pytest + pytest-asyncio, testcontainers (Postgres) for the integration tier.

## Global Constraints

- `mypy --strict` + `pyright` must pass on every new/modified file.
- No `Any` without justification; `Mapping`/frozen types for read-only inputs per `docs/python-conventions.md`.
- CLAUDE.md hard rule #7: no silent failures in security/durability paths — a genuine DB error from the ledger propagates, never collapses to a default.
- Conventional Commits on every commit (`feat(...)`, `test(...)`, `fix(...)`, `docs(...)`).
- No `--no-verify`. `make check` must pass before every push.
- This PR does **not** touch tool dispatch, the journal (PR2), or boot-graph tool wiring (PR3), and does **not** touch the budget-charge code path at all — `self._budget.check_and_charge` stays exactly as it is today, unconditional, on every iteration.

---

### Task 1: `TurnSideEffectLedger` — Protocol + Postgres implementation

**Files:**

- Create: `src/alfred/memory/turn_side_effects.py`
- Test: `tests/unit/memory/test_turn_side_effect_ledger_store.py`

**Interfaces:**

- Produces: `TurnSideEffectLedger` (runtime-checkable `Protocol`), `PostgresTurnSideEffectLedger` (impl), both exported via `__all__`. Two async methods, each `(self, *, adapter_id: str, inbound_id: str) -> bool`, returning `True` iff this call won the right to apply (proceed) and `False` iff another attempt already applied it (skip): `try_apply_user_turn`, `try_apply_assistant_turn`. **No budget-charge method** — see the implementation docstring below for why the budget charge is deliberately not gated at all (a design correction found during the `/review-plan` fleet pass).

- [ ] **Step 1: Write the failing unit tests**

Model directly on `tests/unit/memory/test_forwarded_dispatch_attempt_store.py` (fake `session_scope`, no real DB — the atomic-UPSERT property itself is proven at the integration tier in Task 3).

```python
"""PostgresTurnSideEffectLedger try-apply semantics (fake session_scope; no DB).

Mirrors tests/unit/memory/test_forwarded_dispatch_attempt_store.py: the store
owns an async session_scope; a fake session lets every branch (first-apply /
already-applied / DB-error-propagates) run hermetically. The genuine-Postgres
atomic-UPSERT property lives in the integration tier
(tests/integration/test_turn_side_effect_ledger_postgres.py).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from alfred.memory.turn_side_effects import (
    _TRY_APPLY_ASSISTANT_TURN_SQL,
    _TRY_APPLY_USER_TURN_SQL,
    PostgresTurnSideEffectLedger,
    TurnSideEffectLedger,
)


class _FakeResult:
    def __init__(self, returned: bool | None) -> None:
        self._returned = returned

    def scalar_one_or_none(self) -> bool | None:
        return self._returned


class _FakeSession:
    def __init__(self, *, returned: bool | None = None, raises: Exception | None = None) -> None:
        self._returned = returned
        self._raises = raises
        self.executed: list[tuple[Any, dict[str, Any]]] = []

    async def execute(self, statement: Any, params: dict[str, Any]) -> _FakeResult:
        self.executed.append((statement, params))
        if self._raises is not None:
            raise self._raises
        return _FakeResult(self._returned)


def _scope_for(session: _FakeSession) -> Any:
    @asynccontextmanager
    async def _scope() -> Any:
        yield session

    return _scope


def test_store_satisfies_protocol() -> None:
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(_FakeSession()))
    assert isinstance(store, TurnSideEffectLedger)


async def test_try_apply_user_turn_proceeds_on_first_apply() -> None:
    session = _FakeSession(returned=True)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    assert await store.try_apply_user_turn(adapter_id="discord", inbound_id="m1") is True
    stmt, params = session.executed[0]
    assert stmt is _TRY_APPLY_USER_TURN_SQL
    assert params == {"adapter_id": "discord", "inbound_id": "m1"}


async def test_try_apply_user_turn_skips_when_already_applied() -> None:
    # No row returned (the WHERE ...=FALSE guard didn't match) => already applied.
    session = _FakeSession(returned=None)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    assert await store.try_apply_user_turn(adapter_id="discord", inbound_id="m1") is False


async def test_try_apply_assistant_turn_proceeds_on_first_apply() -> None:
    session = _FakeSession(returned=True)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    assert await store.try_apply_assistant_turn(adapter_id="discord", inbound_id="m1") is True
    stmt, params = session.executed[0]
    assert stmt is _TRY_APPLY_ASSISTANT_TURN_SQL
    assert params == {"adapter_id": "discord", "inbound_id": "m1"}


async def test_try_apply_assistant_turn_skips_when_already_applied() -> None:
    session = _FakeSession(returned=None)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    assert await store.try_apply_assistant_turn(adapter_id="discord", inbound_id="m1") is False


async def test_adapter_id_is_part_of_the_key_not_a_free_column() -> None:
    # A different adapter_id, same inbound_id, must not be treated as the same gate.
    session = _FakeSession(returned=True)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    assert await store.try_apply_user_turn(adapter_id="tui", inbound_id="m1") is True
    _stmt, params = session.executed[0]
    assert params == {"adapter_id": "tui", "inbound_id": "m1"}


@pytest.mark.parametrize("method_name", ["try_apply_user_turn", "try_apply_assistant_turn"])
async def test_db_error_propagates_fail_loud(method_name: str) -> None:
    # CLAUDE.md hard rule #7: a genuine DB failure is NEVER swallowed into a
    # False (which would silently re-permit a side effect that should have
    # stayed blocked, or block one that should have proceeded).
    boom = OperationalError("UPSERT failed", {}, Exception("db down"))
    session = _FakeSession(raises=boom)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    method = getattr(store, method_name)
    with pytest.raises(OperationalError):
        await method(adapter_id="discord", inbound_id="m1")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/memory/test_turn_side_effect_ledger_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'alfred.memory.turn_side_effects'`

- [ ] **Step 3: Write the implementation**

```python
"""Durable turn-side-effect idempotency ledger (#410 PR1).

The forwarded dispatched-edge path
(:func:`alfred.comms_mcp.inbound.process_inbound_message` with
``commit_at_dispatch_edge=True``) leaves a failed frame NOT committed, so the
forwarding leg replays it (ADR-0039 item 4). A resumed
:meth:`alfred.orchestrator.core.Orchestrator._handle_turn` re-runs from
scratch, which — absent this ledger — re-appends the user/assistant turns to
the live in-process :class:`~alfred.memory.working.WorkingMemory` buffer and
re-writes both episodic rows (ADR-0049's accepted residual, narrowed by #410
to include the working-memory exposure ADR-0049 did not name). This ledger
makes each of those two effects apply AT MOST ONCE per committed
``(adapter_id, inbound_id)``.

**The budget charge is deliberately NOT gated by this ledger** (a #410 design
correction found during the `/review-plan` fleet pass, after an earlier draft
gated it too). ``check_and_charge`` fires once per Act-loop iteration, not
once per turn attempt — a single boolean gate is sound only while the Act
loop is guaranteed to run exactly one iteration (tools off). Gating it would
silently under-count real spend the instant a future PR enables
multi-iteration turns — the unsafe direction for a cost-control boundary.
Leaving it ungated restores ADR-0049's ORIGINAL accepted residual (bounded
over-charge, the safe direction) and composes correctly with the #410 PR2
replay journal for free: a fast-forwarded tool call never re-invokes the
provider, so only genuinely new post-resume completions are ever charged.

Durable-across-restart on purpose, same rationale as the sibling
:class:`~alfred.memory.forwarded_dispatch_attempts.ForwardedDispatchAttemptStore`:
the forwarded-edge replay happens ACROSS core restarts, so an in-memory guard
would reset exactly when it is needed.

Each ``try_apply_*`` method is a single ``INSERT ... ON CONFLICT (adapter_id,
inbound_id) DO UPDATE ... WHERE <column> = FALSE RETURNING <column>``
statement — no read-then-write window. A row is returned (mapped to
``True``, "proceed") only when this call is the one that flips the column
from FALSE to TRUE (either via the fresh INSERT or via a WHERE-qualified
UPDATE); a conflicting call that finds the column already TRUE returns no
row (mapped to ``False``, "already applied, skip"). The two columns share
ONE row per ``(adapter_id, inbound_id)`` (not two tables) since they are two
facets of the SAME turn attempt and must never be attributed to different
inbound frames.

**Composite key, not `inbound_id` alone** (a #410 design correction found
during the `/review-plan` fleet pass): ``inbound_id`` is a free-form,
per-adapter-minted opaque string (``src/alfred/comms_mcp/protocol.py``, the
same reasoning the sibling ``inbound_idempotency`` migration 0018 and
``forwarded_dispatch_attempts`` migration 0020 both document for their own
composite ``(adapter_id, inbound_id)`` keys) — a single-column key would let
two DIFFERENT adapters' turns collide on the same ``inbound_id`` string and
silently gate-skip each other's unrelated content.

**Caller contract:** call the relevant ``try_apply_*`` gate BEFORE performing
the guarded effect — the only sound order for a check-then-act idempotency
gate (a "do the effect, then mark" order would let two sequential/concurrent
attempts both pass an unmarked check and both perform the effect,
reintroducing the exact duplication this ledger exists to prevent). The one
accepted residual: a genuine process crash — SIGKILL, OOM, host reboot, NOT
the realistic "process alive, outbound-send failed" scenario ADR-0049
describes and this ledger actually targets — landing in the sub-millisecond
window between the gate's commit and the guarded write's own completion
could theoretically lose that turn's content. Accepted as a residual bounded
to that narrow crash class; see Task 4's crash-injection test for the exact
scope pinned.

A genuine DB failure (``SQLAlchemyError``) PROPAGATES — never caught and
collapsed into a boolean, which could either silently re-permit a blocked
side effect or silently block a permitted one.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

__all__ = [
    "PostgresTurnSideEffectLedger",
    "TurnSideEffectLedger",
]

# One statement per column: a fresh INSERT (no existing row) sets the named
# column TRUE and leaves the OTHER column at its column DEFAULT (FALSE); a
# conflict re-targets the SAME row and updates ONLY the named column, guarded
# by "was it FALSE" so a second attempt at the same gate returns no row.
_TRY_APPLY_USER_TURN_SQL = sa.text(
    "INSERT INTO turn_side_effect_ledger (adapter_id, inbound_id, user_turn_applied) "
    "VALUES (:adapter_id, :inbound_id, TRUE) "
    "ON CONFLICT (adapter_id, inbound_id) DO UPDATE SET user_turn_applied = TRUE "
    "WHERE turn_side_effect_ledger.user_turn_applied = FALSE "
    "RETURNING user_turn_applied"
)

_TRY_APPLY_ASSISTANT_TURN_SQL = sa.text(
    "INSERT INTO turn_side_effect_ledger (adapter_id, inbound_id, assistant_turn_applied) "
    "VALUES (:adapter_id, :inbound_id, TRUE) "
    "ON CONFLICT (adapter_id, inbound_id) DO UPDATE SET assistant_turn_applied = TRUE "
    "WHERE turn_side_effect_ledger.assistant_turn_applied = FALSE "
    "RETURNING assistant_turn_applied"
)


@runtime_checkable
class TurnSideEffectLedger(Protocol):
    """Durable per-``(adapter_id, inbound_id)`` at-most-once gate for two turn side effects."""

    async def try_apply_user_turn(self, *, adapter_id: str, inbound_id: str) -> bool:
        """Return ``True`` iff the caller should apply the user-turn write now."""
        ...

    async def try_apply_assistant_turn(self, *, adapter_id: str, inbound_id: str) -> bool:
        """Return ``True`` iff the caller should apply the assistant-turn write now."""
        ...


class PostgresTurnSideEffectLedger:
    """Postgres-backed :class:`TurnSideEffectLedger`.

    Owns its OWN ``session_scope`` — a fresh, immediately-committing
    transaction per call, INDEPENDENT of the per-turn ``session`` in
    :meth:`Orchestrator._handle_turn`. This is load-bearing: the per-turn
    session rolls back on a deadline/exception, but a live in-process
    ``WorkingMemory.append`` does NOT roll back with it. If this ledger
    shared the per-turn session, a rollback would un-mark an already-applied
    working-memory append, and the next resume would re-apply it — exactly
    the bug this ledger exists to prevent. Same shape as
    :class:`~alfred.memory.forwarded_dispatch_attempts.PostgresForwardedDispatchAttemptStore`.
    """

    def __init__(
        self,
        *,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_scope = session_scope

    async def try_apply_user_turn(self, *, adapter_id: str, inbound_id: str) -> bool:
        async with self._session_scope() as session:
            result = await session.execute(
                _TRY_APPLY_USER_TURN_SQL, {"adapter_id": adapter_id, "inbound_id": inbound_id}
            )
            return result.scalar_one_or_none() is not None

    async def try_apply_assistant_turn(self, *, adapter_id: str, inbound_id: str) -> bool:
        async with self._session_scope() as session:
            result = await session.execute(
                _TRY_APPLY_ASSISTANT_TURN_SQL,
                {"adapter_id": adapter_id, "inbound_id": inbound_id},
            )
            return result.scalar_one_or_none() is not None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/memory/test_turn_side_effect_ledger_store.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Type-check**

Run: `uv run mypy src/alfred/memory/turn_side_effects.py tests/unit/memory/test_turn_side_effect_ledger_store.py && uv run pyright src/alfred/memory/turn_side_effects.py`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add src/alfred/memory/turn_side_effects.py tests/unit/memory/test_turn_side_effect_ledger_store.py
git commit -m "feat(memory): turn-side-effect idempotency ledger store (#410 PR1)"
```

---

### Task 2: Migration — `turn_side_effect_ledger` table

**Files:**

- Create: `src/alfred/memory/migrations/versions/0025_turn_side_effect_ledger.py`
- Test: `tests/integration/test_migration_0025_turn_side_effect_ledger.py`

**Interfaces:**

- Consumes: nothing new (pure schema).
- Produces: table `turn_side_effect_ledger` — composite `(adapter_id VARCHAR(128), inbound_id VARCHAR(255))` PRIMARY KEY, `user_turn_applied BOOLEAN NOT NULL DEFAULT FALSE`, `assistant_turn_applied BOOLEAN NOT NULL DEFAULT FALSE`, `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`. No `budget_charged` column — the budget charge is deliberately not gated by this table (see Task 1).

**Known gap, accepted for this PR (found during `/review-plan`, 2026-08-07):** unlike the directly analogous `egress_idempotency` ledger (migration 0023), this table ships with no retention index or pruning story — it grows one row per turn attempt forever. Flagged as a follow-up rather than fixed here, matching the design spec §12's identical, already-accepted risk note for PR2's journal table; both should be addressed together (e.g. a shared prune-on-`commit_once` sweep) rather than solved twice independently. **Not yet filed as a tracked GitHub issue** (found during the `/review-plan` fleet's second pass, 2026-08-07) — file one covering both tables before or during PR1/PR2 execution, mirroring the pattern PR3 Task 6 establishes for the two web.fetch gaps, and cross-reference it from here and from PR2's ADR-0062 Consequences section.

- [ ] **Step 1: Write the failing migration round-trip test**

Model on `tests/integration/test_migration_0020_forwarded_dispatch_attempts.py` (read that file first for the exact upgrade/downgrade probe shape used in this repo before writing this one, since its precise fixture/assertion idiom is the project's established pattern for a migration test and must be matched, not re-invented).

```python
"""Migration 0025 upgrade/downgrade round-trip: turn_side_effect_ledger."""

from __future__ import annotations

from alembic import command, config
from sqlalchemy import create_engine, inspect, text

import pytest

pytestmark = pytest.mark.integration


def test_upgrade_creates_table_with_expected_columns(postgres_url: str) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        inspector = inspect(engine)
        columns = {c["name"] for c in inspector.get_columns("turn_side_effect_ledger")}
        assert columns == {
            "adapter_id",
            "inbound_id",
            "user_turn_applied",
            "assistant_turn_applied",
            "created_at",
        }
        pk = inspector.get_pk_constraint("turn_side_effect_ledger")
        assert set(pk["constrained_columns"]) == {"adapter_id", "inbound_id"}
    finally:
        engine.dispose()


def test_columns_default_false(postgres_url: str) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO turn_side_effect_ledger (adapter_id, inbound_id, user_turn_applied) "
                    "VALUES ('discord', 'probe-1', TRUE)"
                )
            )
            row = conn.execute(
                text(
                    "SELECT assistant_turn_applied FROM turn_side_effect_ledger "
                    "WHERE adapter_id = 'discord' AND inbound_id = 'probe-1'"
                )
            ).one()
            assert row.assistant_turn_applied is False
    finally:
        engine.dispose()


def test_composite_key_namespaces_are_isolated(postgres_url: str) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with engine.begin() as conn:
            # Two DIFFERENT adapters minting the SAME inbound_id string must not collide.
            conn.execute(
                text(
                    "INSERT INTO turn_side_effect_ledger (adapter_id, inbound_id, user_turn_applied) "
                    "VALUES ('discord', 'shared-id', TRUE), ('tui', 'shared-id', FALSE)"
                )
            )
            rows = conn.execute(
                text(
                    "SELECT adapter_id, user_turn_applied FROM turn_side_effect_ledger "
                    "WHERE inbound_id = 'shared-id' ORDER BY adapter_id"
                )
            ).all()
            assert [(r.adapter_id, r.user_turn_applied) for r in rows] == [
                ("discord", True),
                ("tui", False),
            ]
    finally:
        engine.dispose()


def test_downgrade_drops_table(postgres_url: str) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "-1")

    engine = create_engine(sync_url, future=True)
    try:
        inspector = inspect(engine)
        assert "turn_side_effect_ledger" not in inspector.get_table_names()
    finally:
        engine.dispose()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/integration/test_migration_0025_turn_side_effect_ledger.py -v`
Expected: FAIL (table does not exist / migration head is `0024`)

- [ ] **Step 3: Write the migration**

```python
"""turn_side_effect_ledger — #410 PR1 at-most-once guard for turn-start/turn-end.

Revision ID: 0025
Revises: 0024
Create Date: 2026-08-07 00:00:00.000000

#410 PR1. The forwarded dispatched-edge path
(:func:`alfred.comms_mcp.inbound.process_inbound_message` with
``commit_at_dispatch_edge=True``) leaves a failed frame NOT committed, so the
forwarding leg replays it — and, absent this table, a resumed
``Orchestrator._handle_turn`` re-applies the user-turn write and the
assistant-turn write (ADR-0049's accepted residual, widened by #410 to also
cover the previously-unnamed in-process ``WorkingMemory`` double-append).
The budget charge is deliberately NOT gated by this table — see
``src/alfred/memory/turn_side_effects.py`` for why. This migration adds the
durable per-``(adapter_id, inbound_id)`` ledger that makes the two writes
at-most-once — see that module for the atomic UPSERT contract.

Composite ``(adapter_id, inbound_id)`` PRIMARY KEY, mirroring the sibling
``inbound_idempotency`` (migration 0018) and ``forwarded_dispatch_attempts``
(migration 0020) ledgers: ``inbound_id`` is a free-form, per-adapter-minted
opaque string, so a single-column key would collapse every adapter into one
shared id namespace — scoping by the host-validated ``adapter_id`` isolates
each adapter's namespace.

Strictly additive: a new table, no existing columns touched, no cross-table
CHECK constraint. Downgrade drops the table — no destructive row deletion
needed (unlike migration 0020's ``ck_audit_log_result`` widen/narrow), so no
loud-NOTICE deletion step applies here.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | Sequence[str] | None = "0024"
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
    """Create the turn_side_effect_ledger table."""
    op.create_table(
        "turn_side_effect_ledger",
        sa.Column("adapter_id", sa.String(128), nullable=False),
        sa.Column("inbound_id", sa.String(255), nullable=False),
        sa.Column("user_turn_applied", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "assistant_turn_applied", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("adapter_id", "inbound_id", name="pk_turn_side_effect_ledger"),
        sa.CheckConstraint(
            "char_length(adapter_id) BETWEEN 1 AND 128",
            name="ck_turn_side_effect_ledger_adapter_id_length",
        ),
        sa.CheckConstraint(
            "char_length(inbound_id) BETWEEN 1 AND 255",
            name="ck_turn_side_effect_ledger_inbound_id_length",
        ),
    )


def downgrade() -> None:
    """Drop the turn_side_effect_ledger table."""
    op.execute("DROP TABLE IF EXISTS turn_side_effect_ledger")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/integration/test_migration_0025_turn_side_effect_ledger.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/migrations/versions/0025_turn_side_effect_ledger.py tests/integration/test_migration_0025_turn_side_effect_ledger.py
git commit -m "feat(memory): migration 0025 — turn_side_effect_ledger table (#410 PR1)"
```

---

### Task 3: Integration test — `PostgresTurnSideEffectLedger` against real Postgres

**Files:**

- Create: `tests/integration/test_turn_side_effect_ledger_postgres.py`

**Interfaces:**

- Consumes: `PostgresTurnSideEffectLedger` (Task 1), migration head including `0025` (Task 2).

- [ ] **Step 1: Write the test (model on `tests/integration/test_forwarded_dispatch_attempts_postgres.py`)**

```python
"""PostgresTurnSideEffectLedger against real Postgres: first-apply / already-applied / isolation / race.

The genuine "INSERT ... ON CONFLICT ... WHERE ... RETURNING" at-most-once
property can only be proven against a real Postgres — SQLite cannot express
the serialised-exactly-once-under-concurrency guarantee. Migrates to head
(incl. migration 0025) and exercises the store's full contract.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.memory.db import session_scope
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger

pytestmark = pytest.mark.integration

_ADAPTER = "discord"


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0025
    return postgres_url


@pytest.fixture
async def ledger(migrated_url: str) -> AsyncIterator[PostgresTurnSideEffectLedger]:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresTurnSideEffectLedger(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


async def test_first_apply_proceeds_each_gate(ledger: PostgresTurnSideEffectLedger) -> None:
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m1") is True
    assert await ledger.try_apply_assistant_turn(adapter_id=_ADAPTER, inbound_id="m1") is True


async def test_second_apply_skips_each_gate(ledger: PostgresTurnSideEffectLedger) -> None:
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m2") is True
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m2") is False
    assert await ledger.try_apply_assistant_turn(adapter_id=_ADAPTER, inbound_id="m2") is True
    assert await ledger.try_apply_assistant_turn(adapter_id=_ADAPTER, inbound_id="m2") is False


async def test_gates_are_independent_columns_on_one_row(
    ledger: PostgresTurnSideEffectLedger,
) -> None:
    # Applying assistant_turn does not pre-empt the OTHER gate on the same row.
    assert await ledger.try_apply_assistant_turn(adapter_id=_ADAPTER, inbound_id="m3") is True
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m3") is True


async def test_inbound_id_namespaces_are_isolated(ledger: PostgresTurnSideEffectLedger) -> None:
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m4") is True
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m5") is True  # different inbound_id, not skipped


async def test_adapter_id_namespaces_are_isolated_on_the_same_inbound_id(
    ledger: PostgresTurnSideEffectLedger,
) -> None:
    # Two DIFFERENT adapters minting the SAME inbound_id string must not collide.
    assert await ledger.try_apply_user_turn(adapter_id="discord", inbound_id="shared-id") is True
    assert await ledger.try_apply_user_turn(adapter_id="tui", inbound_id="shared-id") is True


async def test_concurrent_first_applies_settle_to_exactly_one_winner(
    ledger: PostgresTurnSideEffectLedger,
) -> None:
    # 8 concurrent try_apply_user_turn calls on ONE key: the atomic UPSERT
    # serialises, so exactly one True and seven False — never two winners.
    results = await asyncio.gather(
        *(ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="race") for _ in range(8))
    )
    assert sorted(results) == [False] * 7 + [True]
```

- [ ] **Step 2: Run to verify it passes** (requires `postgres_url` testcontainer fixture already wired repo-wide)

Run: `uv run pytest tests/integration/test_turn_side_effect_ledger_postgres.py -v`
Expected: PASS (6 tests)

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_turn_side_effect_ledger_postgres.py
git commit -m "test(memory): PostgresTurnSideEffectLedger real-Postgres contract proof (#410 PR1)"
```

---

### Task 4: Wire the ledger into `Orchestrator` — gate turn-start and turn-end

**Files:**

- Modify: `src/alfred/orchestrator/core.py:96` (import), `:258-300` (constructor), `:688-773` (move `ctx` resolution + gate turn-start), `:1009-1034` (gate turn-end)
- Test: `tests/unit/orchestrator/test_core.py`

**Interfaces:**

- Consumes: `TurnSideEffectLedger` (Task 1).
- Produces: `Orchestrator.__init__(..., side_effect_ledger: TurnSideEffectLedger | None = None)`.

This task changes production behaviour only when `side_effect_ledger` is not `None` — every existing caller (all of `tests/unit/orchestrator/test_core.py`, `test_act_loop.py`, every fixture, `alfred chat`) omits the new kwarg and gets `None`, so their behaviour is byte-for-byte unchanged. Verify this BEFORE writing new tests: the entire existing suite for this file must still pass unmodified after this task.

**The budget charge (`self._budget.check_and_charge`) is deliberately NOT touched by this task at all** — see the design correction in Task 1's module docstring for why gating it was the wrong call. `core.py`'s existing budget-charge code stays byte-for-byte as it is today; only the turn-start and turn-end writes are gated.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/orchestrator/test_core.py` (extend the existing `_build()` helper with an optional `side_effect_ledger` param, mirroring how `autocommit_audit` is already threaded):

```python
def _make_side_effect_ledger(
    *,
    user_turn: bool = True,
    assistant_turn: bool = True,
) -> MagicMock:
    ledger = MagicMock()
    ledger.try_apply_user_turn = AsyncMock(return_value=user_turn)
    ledger.try_apply_assistant_turn = AsyncMock(return_value=assistant_turn)
    return ledger
```

Add `side_effect_ledger: MagicMock | None = None` to `_build()`'s signature, thread it into `kwargs["side_effect_ledger"] = side_effect_ledger` only `if side_effect_ledger is not None` (mirroring the existing `redactor` conditional-kwarg pattern already in `_build`), and return it in the `m` dict as `"side_effect_ledger": side_effect_ledger`.

```python
class TestTurnSideEffectLedgerGating:
    """#410 PR1: the ledger, when supplied, gates turn-start and turn-end.
    The budget charge is intentionally NOT gated (Task 1) — every test below
    asserts `check_and_charge` fires unconditionally, gate or no gate."""

    async def test_no_ledger_supplied_behaves_exactly_as_before(self) -> None:
        # The regression pin: every pre-existing caller omits side_effect_ledger.
        orch, m = _build()
        await _send(orch, m, "no ledger here")
        assert m["episodic"].record.await_count == 2
        assert m["budget"].check_and_charge.call_count == 1
        assert await m["working"].turns() == [
            Turn(role="user", content="no ledger here"),
            Turn(role="assistant", content="Very good, Sir."),
        ]

    async def test_ledger_grants_both_gates_applies_normally(self) -> None:
        ledger = _make_side_effect_ledger()
        orch, m = _build(side_effect_ledger=ledger)
        await _send(orch, m, "fresh turn")
        assert m["episodic"].record.await_count == 2
        assert m["budget"].check_and_charge.call_count == 1
        assert ledger.try_apply_user_turn.await_count == 1
        assert ledger.try_apply_assistant_turn.await_count == 1

    async def test_ledger_denies_user_turn_gate_skips_working_memory_and_episodic(self) -> None:
        ledger = _make_side_effect_ledger(user_turn=False)
        orch, m = _build(side_effect_ledger=ledger)
        await _send(orch, m, "replayed turn")
        # User-turn write skipped; assistant-turn write (a separate gate) still applies.
        assert m["episodic"].record.await_count == 1
        assert m["episodic"].record.await_args_list[0].kwargs["role"] == "assistant"
        assert await m["working"].turns() == [
            Turn(role="assistant", content="Very good, Sir."),
        ]
        # Budget is charged regardless — it is never gated.
        assert m["budget"].check_and_charge.call_count == 1

    async def test_ledger_denies_assistant_turn_gate_skips_working_memory_and_episodic(
        self,
    ) -> None:
        ledger = _make_side_effect_ledger(assistant_turn=False)
        orch, m = _build(side_effect_ledger=ledger)
        reply = await _send(orch, m, "replayed turn")
        # The reply is still returned (for re-send) even though it isn't re-persisted.
        assert reply == "Very good, Sir."
        assert m["episodic"].record.await_count == 1
        assert m["episodic"].record.await_args_list[0].kwargs["role"] == "user"
        assert await m["working"].turns() == [
            Turn(role="user", content="replayed turn"),
        ]
        assert m["budget"].check_and_charge.call_count == 1

    async def test_budget_charge_always_fires_regardless_of_ledger_state(self) -> None:
        # A resumed turn with BOTH gates denied still charges budget on every
        # attempt — the ADR-0049 over-charge residual, deliberately preserved.
        ledger = _make_side_effect_ledger(user_turn=False, assistant_turn=False)
        orch, m = _build(side_effect_ledger=ledger)
        await _send(orch, m, "fully replayed turn")
        assert m["budget"].check_and_charge.call_count == 1
        assert m["episodic"].record.await_count == 0

    async def test_ledger_gates_are_keyed_on_the_resolved_egress_context_inbound_id(self) -> None:
        # Direct/fixture path: no egress_context passed => synthesized with a
        # fresh trace_id-derived inbound_id. The ledger still receives it.
        ledger = _make_side_effect_ledger()
        orch, m = _build(side_effect_ledger=ledger)
        await _send(orch, m, "check the key")
        user_turn_kwargs = ledger.try_apply_user_turn.await_args_list[0].kwargs
        assistant_kwargs = ledger.try_apply_assistant_turn.await_args_list[0].kwargs
        assert user_turn_kwargs["inbound_id"]
        assert user_turn_kwargs["adapter_id"]
        assert user_turn_kwargs["inbound_id"] == assistant_kwargs["inbound_id"]
        assert user_turn_kwargs["adapter_id"] == assistant_kwargs["adapter_id"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/orchestrator/test_core.py -v -k TurnSideEffectLedgerGating`
Expected: FAIL with `TypeError: Orchestrator.__init__() got an unexpected keyword argument 'side_effect_ledger'`

- [ ] **Step 3: Add the constructor param**

In `src/alfred/orchestrator/core.py`, add the import:

```python
from alfred.memory.turn_side_effects import TurnSideEffectLedger
```

In `Orchestrator.__init__`, immediately after the existing `outbound_dlp: OutboundDlpProtocol | None = None,` parameter:

```python
        outbound_dlp: OutboundDlpProtocol | None = None,
        # #410 PR1: the at-most-once guard for turn-start/turn-end (the
        # budget charge is deliberately NOT gated — see
        # alfred.memory.turn_side_effects's module docstring). Additive +
        # optional so every pre-#410 caller (tests, fixtures, alfred chat,
        # and every Slice-1..4 production path before this PR's Task 5)
        # keeps constructing unchanged and every guarded call site below
        # defaults to "always apply" (`side_effect_ledger is None`).
        side_effect_ledger: TurnSideEffectLedger | None = None,
    ) -> None:
```

And in the body, alongside the existing `self._outbound_dlp = outbound_dlp` line:

```python
        self._side_effect_ledger = side_effect_ledger
```

No construction-time guard is needed here: this ledger has no interaction with `self._tool_registry` at all (it never gates the budget charge, the only call site that fires per-iteration), so there is no unsafe combination to refuse.

- [ ] **Step 4: Move the `ctx` resolution earlier and gate turn-start**

The current `_handle_turn` resolves `ctx` (the `TurnEgressContext`) at what is currently lines ~766-773, AFTER the turn-start user-episodic/working-memory writes (~702-717). Move that resolution to immediately after `episodic = self._episodic_factory(session)` (currently line 688), BEFORE the turn-start writes, since the gate needs `ctx.inbound_id` before those writes run.

Replace:

```python
        episodic = self._episodic_factory(session)

        # ------------------------------------------------------------------
        # Observe — ``content`` arrives already tagged at this boundary
```

with:

```python
        episodic = self._episodic_factory(session)

        # #410 PR1: resolved here (moved up from its prior position just
        # before the Act loop) so ctx.inbound_id is available to the
        # turn-start gate immediately below. A provided egress_context, else
        # one derived from trace_id + user (both fixed for the turn) — so it
        # is resolved once, not re-derived on every dispatch.
        ctx = (
            egress_context
            if egress_context is not None
            else self._synthesize_egress_context(trace_id=trace_id, user=user)
        )

        # ------------------------------------------------------------------
        # Observe — ``content`` arrives already tagged at this boundary
```

Then delete the now-duplicate `ctx = (...)` block from its old position (immediately before `for iteration in range(loop_constants.MAX_TOOL_ITERATIONS):`), leaving the comment `# Loop-invariant — ...` deleted along with it since the block it described no longer lives there.

Replace the turn-start write block:

```python
        user_input_text = content.content
        user_input_tier = content.tier.name
        await working_memory.append(role="user", content=user_input_text)
        await episodic.record(
            user_id=user.slug,
            role="user",
            content=user_input_text,
            trust_tier=user_input_tier,
            language=user.language,
            persona=_ALFRED_PERSONA_ID,
            # Slice-2 per-row attribution: ``persona`` is the legacy text
            # column (kept for downstream analytics already reading it);
            # ``persona_id`` is the new migration-0004 column the audit
            # graph joins on. Both must be set on every write so a Slice 5+
            # multi-persona deployment doesn't end up with NULL persona_id
            # rows on its Slice-1+2 history.
            persona_id=_ALFRED_PERSONA_ID,
        )
```

with:

```python
        user_input_text = content.content
        user_input_tier = content.tier.name
        # #410 PR1: at-most-once per committed (adapter_id, inbound_id).
        # `None` (every pre-#410 caller) means "always apply" — behaviour
        # unchanged. The gate is called BEFORE the guarded write — the only
        # sound order for a check-then-act idempotency gate (see Task 1's
        # module docstring for why "effect first" was rejected).
        if self._side_effect_ledger is None or await self._side_effect_ledger.try_apply_user_turn(
            adapter_id=ctx.adapter_id, inbound_id=ctx.inbound_id
        ):
            await working_memory.append(role="user", content=user_input_text)
            await episodic.record(
                user_id=user.slug,
                role="user",
                content=user_input_text,
                trust_tier=user_input_tier,
                language=user.language,
                persona=_ALFRED_PERSONA_ID,
                # Slice-2 per-row attribution: ``persona`` is the legacy text
                # column (kept for downstream analytics already reading it);
                # ``persona_id`` is the new migration-0004 column the audit
                # graph joins on. Both must be set on every write so a Slice 5+
                # multi-persona deployment doesn't end up with NULL persona_id
                # rows on its Slice-1+2 history.
                persona_id=_ALFRED_PERSONA_ID,
            )
```

- [ ] **Step 5: Run to verify the turn-start tests pass**

Run: `uv run pytest tests/unit/orchestrator/test_core.py -v -k "TurnSideEffectLedgerGating and (no_ledger or grants_both or denies_user_turn or gates_are_keyed)"`
Expected: PASS

- [ ] **Step 6: Gate the turn-end write**

Replace:

```python
        await working_memory.append(role="assistant", content=answer)
        # A synthetic refusal (final_exit_reason set) is a local i18n string, not
        # a provider completion — its episodic row must carry ZERO provider
        # tokens/cost (the real cost already rode the provider_call:* rows).
        # Charging it `final_response`'s tokens/cost would misattribute the
        # PRIOR completion's spend to the refusal string AND double-count cost
        # already logged on a `provider_call:*` audit row.
        answer_from_provider = final_exit_reason is None
        # FIX-15: episodic.record logs the FINAL completion's cost/tokens (the
        # answer's attribution); the `completed` audit row logs the TURN total
        # (per_turn_spent_usd). For a multi-completion turn these differ BY
        # DESIGN — episodic = answer attribution, audit = turn spend.
        await episodic.record(
            user_id=user.slug,
            role="assistant",
            content=answer,
            trust_tier="T2",
            tokens_in=final_response.tokens_in if answer_from_provider else 0,
            tokens_out=final_response.tokens_out if answer_from_provider else 0,
            cost_usd=final_response.cost_usd if answer_from_provider else 0.0,
            language=user.language,
            persona=_ALFRED_PERSONA_ID,
            # See the user-turn ``episodic.record`` call above for the
            # ``persona`` vs ``persona_id`` split rationale.
            persona_id=_ALFRED_PERSONA_ID,
        )
```

with:

```python
        # #410 PR1: at-most-once per committed (adapter_id, inbound_id).
        # `answer` is still returned below regardless of this gate — a
        # resumed turn always sends SOMETHING (a fresh completion's text,
        # per ADR-0049's accepted "duplicate paid completion" residual) —
        # this gate only stops that text from ALSO being re-persisted as a
        # second assistant turn.
        if self._side_effect_ledger is None or await self._side_effect_ledger.try_apply_assistant_turn(
            adapter_id=ctx.adapter_id, inbound_id=ctx.inbound_id
        ):
            await working_memory.append(role="assistant", content=answer)
            # A synthetic refusal (final_exit_reason set) is a local i18n string, not
            # a provider completion — its episodic row must carry ZERO provider
            # tokens/cost (the real cost already rode the provider_call:* rows).
            # Charging it `final_response`'s tokens/cost would misattribute the
            # PRIOR completion's spend to the refusal string AND double-count cost
            # already logged on a `provider_call:*` audit row.
            answer_from_provider = final_exit_reason is None
            # FIX-15: episodic.record logs the FINAL completion's cost/tokens (the
            # answer's attribution); the `completed` audit row logs the TURN total
            # (per_turn_spent_usd). For a multi-completion turn these differ BY
            # DESIGN — episodic = answer attribution, audit = turn spend.
            await episodic.record(
                user_id=user.slug,
                role="assistant",
                content=answer,
                trust_tier="T2",
                tokens_in=final_response.tokens_in if answer_from_provider else 0,
                tokens_out=final_response.tokens_out if answer_from_provider else 0,
                cost_usd=final_response.cost_usd if answer_from_provider else 0.0,
                language=user.language,
                persona=_ALFRED_PERSONA_ID,
                # See the user-turn ``episodic.record`` call above for the
                # ``persona`` vs ``persona_id`` split rationale.
                persona_id=_ALFRED_PERSONA_ID,
            )
```

- [ ] **Step 7: Run to verify the turn-end tests pass**

Run: `uv run pytest tests/unit/orchestrator/test_core.py -v -k "TurnSideEffectLedgerGating and (denies_assistant_turn or budget_charge_always)"`
Expected: PASS

- [ ] **Step 8: Pin the accepted crash-injection residual window**

Task 1's module docstring names the one accepted residual precisely: a genuine process crash (not the realistic "process alive, send failed" resume) landing between a `try_apply_*` gate's commit and its guarded write's own completion could lose that turn's content. Add a unit test that pins the SCOPE of this residual — proving the gate call happens strictly before the guarded write starts, so a reader can see exactly where the (accepted, narrow) window is:

```python
    async def test_gate_is_awaited_before_the_guarded_write_starts(self) -> None:
        # Pins the accepted residual's exact scope (Task 1's module
        # docstring): the ledger call must complete BEFORE working_memory /
        # episodic are touched, so the only loss window is a genuine process
        # crash between two adjacent awaits — never a "process alive, send
        # failed" resume, which this test's ordering assertion rules out.
        call_order: list[str] = []
        ledger = _make_side_effect_ledger()

        async def _tracked_try_apply_user_turn(**_kw: object) -> bool:
            call_order.append("gate")
            return True

        ledger.try_apply_user_turn = AsyncMock(side_effect=_tracked_try_apply_user_turn)
        orch, m = _build(side_effect_ledger=ledger)
        original_append = m["working"].append

        async def _tracked_append(**kw: object) -> None:
            call_order.append("write")
            await original_append(**kw)

        m["working"].append = AsyncMock(side_effect=_tracked_append)
        await _send(orch, m, "ordering check")
        assert call_order[:2] == ["gate", "write"]
```

Add this method inside `TestTurnSideEffectLedgerGating` (same class as the rest of Task 4's new tests).

- [ ] **Step 9: Run the full gating test class and the full existing file**

Run: `uv run pytest tests/unit/orchestrator/test_core.py -v`
Expected: PASS — every pre-existing test in the file (unmodified) plus the new `TestTurnSideEffectLedgerGating` class, all green. If any pre-existing test fails, the byte-for-byte-unchanged claim in this task's header is violated — stop and fix before proceeding, do not weaken an existing assertion to make it pass.

- [ ] **Step 10: Run `test_act_loop.py` too (same `_handle_turn` body, different test file)**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py -v`
Expected: PASS, unmodified

- [ ] **Step 11: Type-check**

Run: `uv run mypy src/alfred/orchestrator/core.py tests/unit/orchestrator/test_core.py && uv run pyright src/alfred/orchestrator/core.py`
Expected: no errors

- [ ] **Step 12: Commit**

```bash
git add src/alfred/orchestrator/core.py tests/unit/orchestrator/test_core.py
git commit -m "feat(orchestrator): gate turn-start/turn-end on the side-effect ledger (#410 PR1)"
```

---

### Task 5: Wire `PostgresTurnSideEffectLedger` into the live boot graph

**Files:**

- Modify: `src/alfred/cli/_bootstrap.py:459-517` (`build_orchestrator`)
- Modify: `src/alfred/cli/daemon/_comms_boot.py:793-807` (the live construction call)
- Create: `tests/unit/cli/test_bootstrap_build_orchestrator.py` — confirmed via
  `grep -rl "build_orchestrator(" tests/unit/` (2026-08-07) that no existing
  unit test file exercises `build_orchestrator`'s injection seams directly;
  every current caller reaches it only through higher-level boot-graph tests.
  This is a new file, not an addition to an existing one.

**Interfaces:**

- Consumes: `PostgresTurnSideEffectLedger` (Task 1), `build_boot_session_scope` (existing, `src/alfred/cli/daemon/_commands.py:226`).
- Produces: `build_orchestrator(..., side_effect_ledger: TurnSideEffectLedger | None = None)`, forwarded to `Orchestrator(...)`.

- [ ] **Step 1: Write the failing test**

```python
"""build_orchestrator forwards side_effect_ledger to Orchestrator (#410 PR1)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import MagicMock

from alfred.cli._bootstrap import build_orchestrator


async def test_build_orchestrator_forwards_side_effect_ledger(
    monkeypatch: Any,
) -> None:
    # Deliberately a PLAIN MagicMock, not MagicMock(spec=Settings): pydantic
    # v2 model fields are not plain class attributes, so a spec'd mock does
    # not know about them and raises AttributeError the instant
    # build_budget_guard (called inside build_orchestrator) reads
    # settings.per_call_max_usd. This test's property is narrow (does the
    # ledger param flow through), so it doesn't need Settings' real shape —
    # only needs to not blow up on attribute access.
    settings = MagicMock()
    ledger = MagicMock()

    @asynccontextmanager
    async def _scope() -> Any:
        yield MagicMock()

    broker = MagicMock()
    router = MagicMock()
    resolver = MagicMock()
    resolver.version_counter = 1

    orch = build_orchestrator(
        settings,
        broker=broker,
        router=router,
        resolver=resolver,
        session_scope=_scope,
        side_effect_ledger=ledger,
    )
    assert orch._side_effect_ledger is ledger  # type: ignore[attr-defined]
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/cli/test_bootstrap_build_orchestrator.py -v -k side_effect_ledger`
Expected: FAIL with `TypeError: build_orchestrator() got an unexpected keyword argument 'side_effect_ledger'`

- [ ] **Step 3: Widen `build_orchestrator`**

In `src/alfred/cli/_bootstrap.py`, add the import:

```python
from alfred.memory.turn_side_effects import TurnSideEffectLedger
```

Widen the signature and forward the param:

```python
def build_orchestrator(
    settings: Settings,
    *,
    broker: SecretBroker | None = None,
    router: ProviderRouter | None = None,
    resolver: IdentityResolver | None = None,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]] | None = None,
    quarantined_extractor: QuarantinedExtractorLike | None = None,
    # #410 PR1: forwarded straight to Orchestrator. None (every caller before
    # this PR's Task 5 wiring below) preserves today's unguarded behaviour.
    side_effect_ledger: TurnSideEffectLedger | None = None,
) -> Orchestrator:
```

And in the `return Orchestrator(...)` call, add `side_effect_ledger=side_effect_ledger,` alongside the existing `quarantined_extractor=quarantined_extractor,` line.

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/cli/test_bootstrap_build_orchestrator.py -v`
Expected: PASS

- [ ] **Step 5: Wire the live construction site**

In `src/alfred/cli/daemon/_comms_boot.py`, add the import alongside the existing `PostgresForwardedDispatchAttemptStore` import:

```python
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger
```

In the `orchestrator = build_orchestrator(...)` call (currently ending `quarantined_extractor=None,`), add the new kwarg:

```python
        orchestrator = build_orchestrator(
            settings,
            # FOLD-R7: broker passed per build_orchestrator's docstring to avoid a
            # throwaway build_broker; it is UNUSED here because `router` is injected
            # (broker only feeds build_router, which is skipped). No redaction risk:
            # the log redactor is process-global (configure_logging). The ADR-0048
            # one-broker-instance invariant binds the FUTURE build_tool_registry
            # broker (tools-on), not this call.
            broker=secret_broker,
            router=router,
            resolver=resolver,
            session_scope=build_boot_session_scope(settings),
            # extraction runs at the adapter->bridge boundary, not the orchestrator funnel
            quarantined_extractor=None,
            # #410 PR1: the LIVE at-most-once guard. Same shared-DSN-cached-engine
            # session_scope shape as idempotency_store / forwarded_dispatch_attempt_store
            # below — a fresh session_scope() call is cheap (build_session_scope caches
            # the engine by DSN), never a second connection pool.
            side_effect_ledger=PostgresTurnSideEffectLedger(
                session_scope=build_boot_session_scope(settings)
            ),
        )
```

- [ ] **Step 6: Type-check**

Run: `uv run mypy src/alfred/cli/_bootstrap.py src/alfred/cli/daemon/_comms_boot.py && uv run pyright src/alfred/cli/_bootstrap.py src/alfred/cli/daemon/_comms_boot.py`
Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add src/alfred/cli/_bootstrap.py src/alfred/cli/daemon/_comms_boot.py tests/unit/cli/test_bootstrap_build_orchestrator.py
git commit -m "feat(cli): wire PostgresTurnSideEffectLedger into the live comms boot graph (#410 PR1)"
```

---

### Task 6: Flip the existing crash-injection integration test's accepted-residual assertion

**Files:**

- Modify: `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py:670-751` (`test_forwarded_crash_injection_replays_exactly_twice_with_bounded_residual`)

This is the regression-pin site: `_build_comms_boot_graph` (called by `_boot_stack`, this file's fixture) now constructs the live `PostgresTurnSideEffectLedger`-wired orchestrator via Task 5's change, so this existing test's own accepted-double-write assertions must flip from "duplicated" to "deduplicated" — that flip IS the proof this PR works end-to-end over real infra.

- [ ] **Step 1: Update the test's docstring and assertions**

Replace the docstring:

```python
    """FORWARDED path: one outbound-send failure replays the turn EXACTLY twice.

    FOLD-R6 (DECISION CLOSED): the residual is bounded by the POISON CEILING
    (5, ``inbound.py:201``) IN GENERAL — not "at most twice" — a single
    injected failure happens to produce exactly two runs, but the general
    bound this same ledger enforces is the ceiling. The in-process working-
    memory deque is NOT rolled back on the failed first attempt — asserted
    directly (the un-rolled-back double-append this fold accepts as a bounded,
    self-healing residual, not silently swept under the rug).
    """
```

with:

```python
    """FORWARDED path: one outbound-send failure replays the turn EXACTLY twice
    at the TRANSPORT level (two provider completions, two send attempts) —
    but #410 PR1's ``TurnSideEffectLedger`` makes the working-memory /
    episodic side effects apply EXACTLY ONCE despite that. The budget charge
    is a DELIBERATE exception — see below.

    FOLD-R6's original bounded-residual framing (ADR-0049) is RETIRED by
    #410 PR1 for working-memory/episodic ONLY: this test previously pinned
    the double-append as an ACCEPTED residual (``== 4``, "duplicated, not
    lost"); it now pins the FIX (``== 2``, deduplicated). The turn still
    runs twice — a second real provider completion is still paid for AND
    still separately charged (ADR-0049's "duplicate paid completion" /
    bounded-over-charge residual, which #410 PR1 deliberately does NOT
    touch — gating it would flip a safe over-charge into an unsafe
    under-charge, see Task 1) — but only the FIRST attempt's turns land in
    working memory.
    """
```

Replace the post-failure assertion block:

```python
        # The un-rolled-back residual: the FIRST (failed) turn's user+assistant
        # append already landed in the shared in-process deque — nothing
        # unwinds it when the send fails downstream of the pool release.
        pool = stack.graph.inbound_orchestrator._pool  # type: ignore[attr-defined]
        key = (_PERSONA, _ALICE_SLUG)
        wm = await pool.acquire(key)
        turns_after_failure = await wm.turns()
        await pool.release(key, wm)
        assert len(turns_after_failure) == 2  # user + assistant, NOT rolled back
        assert turns_after_failure[0].role == "user"
        assert turns_after_failure[1].role == "assistant"
```

with (unchanged — the FIRST attempt still applies both writes; the fix only prevents the SECOND from re-applying them):

```python
        # The first (failed) turn's user+assistant append still lands — the
        # ledger's job is to prevent a SECOND attempt from re-applying it,
        # not to roll back the first.
        pool = stack.graph.inbound_orchestrator._pool  # type: ignore[attr-defined]
        key = (_PERSONA, _ALICE_SLUG)
        wm = await pool.acquire(key)
        turns_after_failure = await wm.turns()
        await pool.release(key, wm)
        assert len(turns_after_failure) == 2  # user + assistant
        assert turns_after_failure[0].role == "user"
        assert turns_after_failure[1].role == "assistant"
```

Replace the final assertion:

```python
        # The residual is DOUBLE-APPEND, never cross-user: only alice's key was
        # ever touched (never crosses a user partition).
        assert set(stack.graph.inbound_orchestrator._pool._entries.keys()) == {key}  # type: ignore[attr-defined]
        wm = await pool.acquire(key)
        turns_after_replay = await wm.turns()
        await pool.release(key, wm)
        assert len(turns_after_replay) == 4  # 2 user + 2 assistant — duplicated, not lost
```

with:

```python
        # #410 PR1: the SECOND attempt's working-memory writes are gated by
        # the ledger and skipped — the buffer stays at 2, not 4. Never
        # crosses a user partition (only alice's key was ever touched). The
        # turn itself still ran twice (a fresh paid completion each time,
        # ADR-0049's separately-accepted residual, asserted a few lines
        # above this block via the pre-existing
        # `assert len(stack.captured_router.requests) == 2` — do NOT
        # duplicate that assertion here) — only the BOOKKEEPING below is
        # deduplicated, not the provider call.
        assert set(stack.graph.inbound_orchestrator._pool._entries.keys()) == {key}  # type: ignore[attr-defined]
        wm = await pool.acquire(key)
        turns_after_replay = await wm.turns()
        await pool.release(key, wm)
        assert len(turns_after_replay) == 2  # deduplicated — was 4 before #410 PR1
```

- [ ] **Step 2: Run to verify it passes**

Run: `uv run pytest tests/integration/comms_mcp/test_real_turn_inbound_boundary.py -v -k crash_injection`
Expected: PASS — both `test_forwarded_crash_injection_replays_exactly_twice_with_bounded_residual` and `test_direct_path_crash_injection_is_at_most_once` (the latter is untouched by this PR and must still pass unmodified).

- [ ] **Step 3: Run the full module**

Run: `uv run pytest tests/integration/comms_mcp/test_real_turn_inbound_boundary.py -v`
Expected: PASS, every test in the module (including the HARD#5 provenance test and the cost-model test, both untouched by this PR).

- [ ] **Step 4: Commit**

```bash
git add tests/integration/comms_mcp/test_real_turn_inbound_boundary.py
git commit -m "test(comms): flip the forwarded-replay bounded-residual pin to exactly-once (#410 PR1)"
```

---

### Task 7: Add the new working-memory-specific regression test

**Files:**

- Modify: `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py` (add new test near Task 6's edit)

Task 6 flips an EXISTING test's assertion. This task adds a NEW test that isolates the exact bug found while writing this plan (§3.4 of the design spec) — that `WorkingMemory.append`'s exposure was never named by ADR-0049 and is arguably the highest-severity part of the fix (live conversation-context corruption, not just an audit-log duplicate).

- [ ] **Step 1: Write the test**

```python
async def test_forwarded_replay_never_duplicates_the_live_conversation_context(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#410 PR1: a resumed forwarded turn must never let Alfred see its own
    prior user turn twice in the SAME live in-process WorkingMemory buffer
    that the NEXT completion reads back as history.

    This is distinct from the FOLD-R6 test above (which counts total turns
    after resume): this test proves the SPECIFIC failure mode found while
    writing #410 PR1's implementation plan — a duplicated user turn is not
    merely an audit-log oddity, it is live context the orchestrator's next
    completion (whether later in this turn, or a follow-up turn) reads back
    verbatim. ADR-0049 never named this exposure.
    """
    async with _boot_stack(postgres_url, monkeypatch) as stack:
        flaky_sender = _FlakyOnceSender(stack.sender)
        stack.graph.inbound_orchestrator.bind_outbound_sender(flaky_sender)

        idempotency_store = stack.graph.idempotency_store
        attempt_store = PostgresForwardedDispatchAttemptStore(
            session_scope=build_boot_session_scope(stack.settings)
        )
        inbound_id = f"context-dup-{uuid.uuid4().hex}"

        with pytest.raises(ConnectionError):
            await stack.send_inbound(
                body={"text": "remember this exactly once"},
                inbound_id=inbound_id,
                commit_at_dispatch_edge=True,
                idempotency_store=idempotency_store,
                attempt_store=attempt_store,
            )
        await stack.send_inbound(
            body={"text": "remember this exactly once"},
            inbound_id=inbound_id,
            commit_at_dispatch_edge=True,
            idempotency_store=idempotency_store,
            attempt_store=attempt_store,
        )

        pool = stack.graph.inbound_orchestrator._pool  # type: ignore[attr-defined]
        key = (_PERSONA, _ALICE_SLUG)
        wm = await pool.acquire(key)
        turns = await wm.turns()
        await pool.release(key, wm)

        user_turns = [t for t in turns if t.role == "user"]
        assert len(user_turns) == 1, (
            "a resumed forwarded turn duplicated the user's message into the "
            "live conversation context the next completion reads back"
        )
        assert user_turns[0].content == "remember this exactly once"
```

- [ ] **Step 2: Run to verify it passes**

Run: `uv run pytest tests/integration/comms_mcp/test_real_turn_inbound_boundary.py -v -k context_dup`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration/comms_mcp/test_real_turn_inbound_boundary.py
git commit -m "test(comms): pin that a forwarded replay never duplicates live conversation context (#410 PR1)"
```

---

### Task 8: Amend ADR-0049's residual panel

**Files:**

- Modify: `docs/adr/0049-real-privileged-turn-comms-inbound.md` (its residuals/risks section — read the file first to find the exact heading; do not guess the section title)

- [ ] **Step 1: Read the ADR's residual section**

Run: `grep -n "^##\|residual\|bounded" docs/adr/0049-real-privileged-turn-comms-inbound.md`

- [ ] **Step 2: Add a retirement note**

At the top of the residual entry describing the episodic/budget double-apply (found via Step 1), add (fill in today's actual date at implementation time, not a placeholder):

```markdown
> **Partially retired by #410 PR1.** A new `TurnSideEffectLedger`
> (`src/alfred/memory/turn_side_effects.py`) makes the user-turn write and
> the assistant-turn write at-most-once per committed `(adapter_id,
> inbound_id)`. #410 PR1 also found and fixed an identically-shaped exposure
> in `WorkingMemory.append` that this ADR did not name — see
> `docs/superpowers/specs/2026-08-07-issue-410-tools-on-design.md` §3.4.
> **The budget-charge half of this residual is DELIBERATELY NOT retired** —
> #410 PR1 found that gating it would flip this ADR's accepted (safe)
> over-charge residual into an unsafe under-charge one, so the budget charge
> stays exactly as this ADR originally described it. See design spec §3.5
> for the full reasoning. The residual below is preserved for historical
> record; only its episodic/working-memory portion no longer reflects
> production behaviour.
```

(Leave the original residual prose below the note intact — this is a retirement annotation, not a rewrite of history.)

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0049-real-privileged-turn-comms-inbound.md
git commit -m "docs(adr): partially retire ADR-0049's residual - episodic/working-memory only (#410 PR1)"
```

---

## Definition of Done

- [ ] All 8 tasks' tests pass: `uv run pytest tests/unit/memory/test_turn_side_effect_ledger_store.py tests/integration/test_migration_0025_turn_side_effect_ledger.py tests/integration/test_turn_side_effect_ledger_postgres.py tests/unit/orchestrator/test_core.py tests/unit/orchestrator/test_act_loop.py tests/unit/cli/test_bootstrap_build_orchestrator.py tests/integration/comms_mcp/test_real_turn_inbound_boundary.py -v`
- [ ] `make check` passes clean (lint, format, mypy, pyright, unit, integration).
- [ ] `uv run pytest tests/adversarial -q` still passes (this PR touches no trust-tier boundary, but `core.py` and the boot graph are release-blocking-adjacent — confirm nothing regressed).
- [ ] Three-amigos + `/review-plan` fleet already run on the design spec per the standing cadence before this plan's tasks are executed; `/review-pr` fleet + CodeRabbit `full review` run on the resulting PR before merge.
