# #410 PR2 — Deterministic-replay journal for tool dispatch — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Prerequisite: PR1 must be merged first.** This is NOT independent of PR1 (a
`/review-plan` fleet pass found and corrected an earlier "could run in
parallel" claim). Two concrete dependencies: this PR's migration `0026`
chains on PR1's `0025`; and `_fast_forward_journalled_calls` (Task 4) reads
`ctx` at a point in `_handle_turn` that only exists once PR1's Task 4 moves
`ctx`'s resolution earlier — on `main` without PR1, `ctx` is not yet assigned
at that point.

**Goal:** Make a forwarded-path resume of a tool-bearing turn replay its already-decided tool calls instead of re-consulting a fresh, possibly-divergent planner — so a resumed turn converges through the existing Spec C egress ledger's memoize-and-replay instead of risking `EgressIdIntegrityError` or, worse, silently losing accounting for egress calls that already fired for real on the crashed attempt. Ships with **no live consumer**: the fast-forward path is a no-op whenever `self._tool_registry is None` (true in production throughout this PR — PR3 wires a live registry), so it never reaches Postgres in production until PR3 lands, matching the same seam-first precedent as #339 PR1, G7-2a, and #338 PR1.

**Architecture:** A new Postgres-backed `ReplayJournal` (composite `(adapter_id, inbound_id, call_index)` → `(iteration, ToolCall)`), modeled on PR1's `TurnSideEffectLedger` and the sibling `ForwardedDispatchAttemptStore` (same composite-key precedent both use, for the same reason: `inbound_id` alone is a per-adapter-minted opaque string, not a globally unique one). The Act loop, on entry, checks for journalled entries **only when a live tool registry is wired**; if any exist, it **fast-forwards** through them — replaying each via the SAME `dispatch_tool` call the normal path uses (the existing egress ledger's memoize-and-replay handles the actual dedup, no new logic needed there — with one documented exception, see Task 4), reconstructing the ephemeral `local` transcript grouped by the journalled `iteration` — then resumes the **existing, unmodified** `for iteration in range(...)` loop from `max_journalled_iteration + 1` onward, with `tool_choice="auto"` unchanged. On the normal (non-replay) path, every tool call gets journalled immediately before its own `dispatch_tool` call. `temperature=0` for tool-bearing completions is a one-line addition to the existing `CompletionRequest(...)` construction — the field and both provider adapters' consumption of it already exist.

**Tech Stack:** Python 3.14, SQLAlchemy 2.0 async, Alembic, pytest + pytest-asyncio + hypothesis, testcontainers (Postgres).

## Global Constraints

- `mypy --strict` + `pyright` clean on every new/modified file.
- No `Any` without justification.
- CLAUDE.md hard rule #7: fail loud — a genuine DB error from the journal propagates; an invariant violation (journal entries exist but the tool seams aren't wired) raises the SAME `RuntimeError`/i18n key the normal dispatch-seams guard already uses (`core.py:976`, `orchestrator.tool.dispatch_seams_unwired`) — do not invent a second key for the identical invariant.
- Conventional Commits on every commit. No `--no-verify`. `make check` before every push.
- This PR does **not** wire `tool_registry` into `build_orchestrator`'s live call in `_comms_boot.py` — that stays PR3's job. It DOES wire the new `ReplayJournal` store itself into the boot graph (dark, unreachable — see Task 5), matching PR1's precedent for `TurnSideEffectLedger`.
- **Correction (found during `/review-plan`, 2026-08-07): PR1 no longer has a budget-charge gate or a tools-combination guard at all** — PR1 was revised to leave the budget charge permanently ungated (see PR1's plan Task 1). There is therefore no PR3 obligation regarding budget-charge iteration-awareness inherited from PR1, and nothing for this PR to defer either.
- **Design correction recorded here for anyone diffing against the original issue text:** the journal does NOT store `compute_request_descriptor` (that function is internal to web.fetch's own extraction path, `src/alfred/egress/egress_response_extract.py`, and has no meaning for `clock.now`). It stores `ToolCall` (`src/alfred/providers/base.py:110`) — the identity `dispatch_tool` already receives for any tool. See `docs/superpowers/specs/2026-08-07-issue-410-tools-on-design.md` §4 for the full correction.
- **Second design correction:** replay is NOT a single forced `tool_choice="none"` wrap-up completion. That was rejected — see the design spec §5 — because it would truncate legitimate further tool use if the original attempt crashed before the planner decided to stop. Replay fast-forwards the journalled prefix, then resumes the ordinary loop.
- **Documented, accepted gap: `InternalToolSpec` tools (e.g. `clock.now`, PR3's only live tool) have NO Spec C egress-ledger dedup protection on replay** — only `ExternalToolSpec` (web.fetch) is wired to `compute_egress_id`/the memoize-and-replay ledger. A replayed `InternalToolSpec` call re-dispatches for real with no dedup. Low blast radius today (side-effect-free by construction), but this is a convention, not a type/registry-enforced guarantee — see Task 4.

---

### Task 1: `ReplayJournal` — Protocol + Postgres implementation

**Files:**

- Create: `src/alfred/memory/replay_journal.py`
- Test: `tests/unit/memory/test_replay_journal_store.py`

**Interfaces:**

- Produces: `ReplayJournal` (Protocol), `PostgresReplayJournal` (impl), `JournalEntry` (frozen dataclass: `call_index: int`, `iteration: int`, `tool_call: ToolCall`). `async def append_batch(self, *, adapter_id: str, inbound_id: str, iteration: int, calls: Sequence[tuple[int, ToolCall]]) -> None` — durably records an ENTIRE iteration's tool-dispatch decisions (`calls` is `(call_index, ToolCall)` pairs) as ONE atomic multi-row write, before any of them is dispatched (**not** a single-call `append`, and **not** one write per call — a #410 design correction found during the `/review-plan` fleet's second pass, 2026-08-07: see Task 4 Step 6 for why per-call journalling left a silent-data-loss window on crash). `async def read(self, *, adapter_id: str, inbound_id: str) -> tuple[JournalEntry, ...]` — returns entries ordered by `call_index` ascending, `()` if none exist. **Composite `(adapter_id, inbound_id, call_index)` key** — same rationale as PR1's `TurnSideEffectLedger`: `inbound_id` is a free-form, per-adapter-minted opaque string (found during `/review-plan`, matching the sibling `inbound_idempotency`/`forwarded_dispatch_attempts` composite-key precedent).

- [ ] **Step 1: Write the failing unit tests**

```python
"""PostgresReplayJournal append/read semantics (fake session_scope; no DB).

Mirrors tests/unit/memory/test_forwarded_dispatch_attempt_store.py and
tests/unit/memory/test_turn_side_effect_ledger_store.py: the store owns an
async session_scope; a fake session lets every branch run hermetically. The
genuine-Postgres ordering/persistence property lives in the integration tier
(tests/integration/test_replay_journal_postgres.py).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from alfred.memory.replay_journal import (
    JournalEntry,
    PostgresReplayJournal,
    ReplayJournal,
)
from alfred.providers.base import ToolCall


class _FakeRow:
    def __init__(self, *, call_index: int, iteration: int, tool_call_id: str, tool_name: str, tool_arguments_json: str) -> None:
        self.call_index = call_index
        self.iteration = iteration
        self.tool_call_id = tool_call_id
        self.tool_name = tool_name
        self.tool_arguments_json = tool_arguments_json


_ADAPTER = "discord"


class _FakeResult:
    def __init__(self, rows: list[_FakeRow]) -> None:
        self._rows = rows

    def all(self) -> list[_FakeRow]:
        return self._rows


class _FakeSession:
    def __init__(self, *, rows: list[_FakeRow] | None = None, raises: Exception | None = None) -> None:
        self._rows = rows or []
        self._raises = raises
        self.executed: list[tuple[Any, dict[str, Any] | list[dict[str, Any]]]] = []

    async def execute(
        self, statement: Any, params: dict[str, Any] | list[dict[str, Any]]
    ) -> _FakeResult:
        self.executed.append((statement, params))
        if self._raises is not None:
            raise self._raises
        return _FakeResult(self._rows)


def _scope_for(session: _FakeSession) -> Any:
    @asynccontextmanager
    async def _scope() -> Any:
        yield session

    return _scope


def test_store_satisfies_protocol() -> None:
    store = PostgresReplayJournal(session_scope=_scope_for(_FakeSession()))
    assert isinstance(store, ReplayJournal)


async def test_append_batch_sends_the_expected_params() -> None:
    session = _FakeSession()
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    call = ToolCall(id="tc-1", name="web.fetch", arguments={"url": "https://example.invalid"})
    await store.append_batch(
        adapter_id=_ADAPTER, inbound_id="m1", iteration=0, calls=[(0, call)]
    )
    _stmt, params_list = session.executed[0]
    assert len(params_list) == 1
    params = params_list[0]
    assert params["adapter_id"] == _ADAPTER
    assert params["inbound_id"] == "m1"
    assert params["call_index"] == 0
    assert params["iteration"] == 0
    assert params["tool_call_id"] == "tc-1"
    assert params["tool_name"] == "web.fetch"
    assert '"url": "https://example.invalid"' in params["tool_arguments_json"]


async def test_append_batch_writes_every_call_in_one_atomic_execute() -> None:
    """The core-001 regression pin: a multi-call iteration is ONE `execute()`, not N.

    Found during the `/review-plan` fleet's second pass (2026-08-07): the
    original design journalled one row per call, inside the dispatch loop —
    a crash between two calls of the same iteration could silently drop the
    un-journalled tail. `append_batch` must send the whole iteration's calls
    in a single `session.execute()` invocation so there is no such window:
    either the transaction commits with every call recorded, or none are.
    """
    session = _FakeSession()
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    call_a = ToolCall(id="tc-1", name="clock.now", arguments={})
    call_b = ToolCall(id="tc-2", name="web.fetch", arguments={"url": "https://example.invalid"})
    await store.append_batch(
        adapter_id=_ADAPTER, inbound_id="m1", iteration=0, calls=[(0, call_a), (1, call_b)]
    )
    assert len(session.executed) == 1  # ONE execute() call, not two
    _stmt, params_list = session.executed[0]
    assert len(params_list) == 2
    assert [p["call_index"] for p in params_list] == [0, 1]
    assert [p["tool_call_id"] for p in params_list] == ["tc-1", "tc-2"]


async def test_read_returns_empty_tuple_when_absent() -> None:
    session = _FakeSession(rows=[])
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    assert await store.read(adapter_id=_ADAPTER, inbound_id="absent") == ()


async def test_read_reconstructs_tool_calls_in_call_index_order() -> None:
    session = _FakeSession(
        rows=[
            _FakeRow(
                call_index=0,
                iteration=0,
                tool_call_id="tc-1",
                tool_name="clock.now",
                tool_arguments_json="{}",
            ),
            _FakeRow(
                call_index=1,
                iteration=0,
                tool_call_id="tc-2",
                tool_name="web.fetch",
                tool_arguments_json='{"url": "https://example.invalid"}',
            ),
        ]
    )
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    entries = await store.read(adapter_id=_ADAPTER, inbound_id="m1")
    assert entries == (
        JournalEntry(
            call_index=0,
            iteration=0,
            tool_call=ToolCall(id="tc-1", name="clock.now", arguments={}),
        ),
        JournalEntry(
            call_index=1,
            iteration=0,
            tool_call=ToolCall(
                id="tc-2", name="web.fetch", arguments={"url": "https://example.invalid"}
            ),
        ),
    )


@pytest.mark.parametrize("method_name", ["append_batch", "read"])
async def test_db_error_propagates_fail_loud(method_name: str) -> None:
    boom = OperationalError("query failed", {}, Exception("db down"))
    session = _FakeSession(raises=boom)
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    with pytest.raises(OperationalError):
        if method_name == "append_batch":
            await store.append_batch(
                adapter_id=_ADAPTER,
                inbound_id="m1",
                iteration=0,
                calls=[(0, ToolCall(id="tc-1", name="clock.now", arguments={}))],
            )
        else:
            await store.read(adapter_id=_ADAPTER, inbound_id="m1")
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/memory/test_replay_journal_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.memory.replay_journal'`

- [ ] **Step 3: Write the implementation**

```python
"""Deterministic tool-call replay journal (#410 PR2).

On the forwarded dispatched-edge path, a crash between "the planner decided
to call these tools" and `commit_once` leaves the frame uncommitted, so it
replays (ADR-0039 item 4). Without this journal, a resumed
:meth:`Orchestrator._handle_turn` would ask the planner AGAIN for a fresh,
possibly non-deterministic plan — the Spec C egress ledger's body-hash
integrity check (`src/alfred/memory/egress_idempotency.py:220`) then either
catches a genuine divergence loudly (`EgressIdIntegrityError`) or, worse, if
the resumed plan happens to omit a call the original attempt already fired
for real, silently drops that already-applied side effect from the resumed
turn's accounting.

This journal records the COMMITTED ordered dispatch decision —
``(adapter_id, inbound_id, call_index) -> (iteration, ToolCall)`` — as the Act
loop makes it, in ONE atomic write per ITERATION, covering every call that
iteration's completion requested, BEFORE any of them is dispatched (never
after, and never one row per call: recording the whole iteration's decision
atomically and early is what lets a resume fast-forward through it even if
the crash happened mid-dispatch of that SAME iteration — a per-call write
would leave a crash-window where a later call in the same iteration is
dispatched for real but never durably recorded, silently vanishing from any
resumed replay; found during the `/review-plan` fleet's second pass,
2026-08-07). ``ToolCall`` (id, name, arguments,
:class:`alfred.providers.base.ToolCall`) is the identity `dispatch_tool`
already receives for ANY tool — NOT
:func:`alfred.egress.egress_id.compute_request_descriptor`, which is
internal to web.fetch's own extraction path and has no meaning for
`clock.now`. ``iteration`` is additionally stored so a replay can
reconstruct the tool-call/tool-result message grouping faithfully (a single
assistant completion can request multiple tool calls at once).

**Composite ``(adapter_id, inbound_id, call_index)`` key, not ``(inbound_id,
call_index)`` alone** (a #410 design correction found during the
`/review-plan` fleet pass, the same root cause as PR1's `TurnSideEffectLedger`
finding, independently repeated in this table's first draft): ``inbound_id``
is a free-form, per-adapter-minted opaque string
(``src/alfred/comms_mcp/protocol.py``) — a two-column key would let two
DIFFERENT adapters' turns collide on the same ``inbound_id`` string and splice
one turn's already-decided tool calls into a DIFFERENT turn's reconstructed
transcript, corrupting the privileged LLM's belief about its own conversation
history.

Durable-across-restart on purpose, same rationale as every sibling ledger in
this module (`forwarded_dispatch_attempts.py`, `turn_side_effects.py`): the
forwarded-edge replay happens ACROSS core restarts.

``tool_arguments`` is stored as an explicit JSON-serialized TEXT column, not
a native JSONB column — this codebase has no established precedent for a
raw-``sa.text()`` JSONB round-trip. ``PoliciesSnapshotHistory.policies_json``
(migration 0013, ``src/alfred/memory/models.py:656``) is the only genuinely
JSONB-typed precedent, and it too goes through the declarative ORM, not raw
SQL (``src/alfred/policies/snapshot_ref.py:224``) — ``AuditEntry.subject`` is
plain ``sa.JSON`` with no JSONB dialect variant, so it isn't a JSONB
precedent at all (corrected during the `/review-plan` fleet's second pass,
2026-08-07: an earlier draft of this docstring miscounted it as one). Either
way, asyncpg's default JSON(B) codec behavior is not something to gamble on
without a raw-SQL integration-tested precedent, which this codebase has none
of. Explicit ``json.dumps``/``json.loads``
in Python is simple, safe, and dialect-independent. The column carries a
size-cap CHECK constraint (Task 2) matching the codebase's other JSON
payload columns (e.g. migration 0013's 256 KB cap) — a tool-call argument
payload is attacker-influenced (a T3-derived planner decision), so an
unbounded column would be a real storage-exhaustion surface.

**Accepted, documented gap: this journal provides NO dedup protection for
`InternalToolSpec` tools** (found during `/review-plan`) — only
`ExternalToolSpec` (web.fetch) is wired to the Spec C
`compute_egress_id`/memoize-and-replay ledger. A replayed `InternalToolSpec`
call (e.g. `clock.now`, PR3's only live tool) re-dispatches for real on every
fast-forward, with no dedup at all. Safe today only because `clock.now` is
side-effect-free by construction — this is a convention, not a
type/registry-enforced guarantee, and a future `InternalToolSpec` with real
side effects would inherit this gap silently.

**Two concrete consequences of the gap above (found during the
`/review-plan` fleet's second pass, 2026-08-07):**

1. **Audit-log duplication.** `dispatch_tool` writes a `tool.dispatch` audit
   row on every dispatch, replay included (Task 4's fast-forward calls the
   SAME `dispatch_tool`). A turn that crashes and retries N times before a
   successful send produces N `tool.dispatch` rows for the SAME logical
   call — identical `trace_id`, `call_index`, and `tool_call_id` — each
   independently claiming a successful dispatch. Not a security or
   cost-accounting issue, but an `alfred audit graph` reader for a resumed
   turn should not be misled into seeing apparent duplicate successful
   dispatches as N distinct events. No test in this plan drives a
   multi-attempt replay to observe or pin this behaviour — a future PR
   adding a second `InternalToolSpec` tool should account for it, e.g. by
   threading a replay marker into the audit subject on the fast-forward
   path or adding a test that drives two replay attempts and asserts on the
   resulting audit-row count.
2. **Precedent risk.** Nothing in `ToolRegistry`, `InternalToolSpec`, or
   `FIRST_PARTY_LE_T2_TOOL_ALLOWLIST` (`tool_registry.py:26`) enforces "this
   tool's dispatch has no side effects" as a property distinct from "this
   tool is first-party and its `result_tier` claim is T2." A future
   `InternalToolSpec` tool with real side effects could be added to that
   allowlist and silently inherit this same no-dedup-on-replay gap — this
   time with real consequences on a forwarded-path resume-storm. This
   docstring is currently the only place the gap is written down; PR3
   Task 2a closes a DIFFERENT, related gap on the same branch (the missing
   DLP scan) — whoever adds the second `InternalToolSpec` tool should also
   relocate or duplicate this accepted-risk note onto `InternalToolSpec`'s
   own docstring in `tool_registry.py`, visible at the point that future
   decision is actually made, rather than only here.

**Invariant (disputed severity during `/review-plan` — security-engineer
rated High, comms-engineer rated Low; both agreed this pinning matters
regardless): `tool_arguments_json` NEVER contains a resolved secret value,
only an unresolved `{{secret:name}}` placeholder if one is present.** This
holds STRUCTURALLY, not by luck of call ordering: `Orchestrator._handle_turn`
(Task 4) calls `self._replay_journal.append_batch(...)` with the planner's raw
`ToolCall`s BEFORE any of that iteration's `dispatch_tool` calls run at all — broker secret substitution
happens INSIDE a tool's own dispatcher (e.g. `dispatch_web_fetch`'s Step 1c),
strictly downstream of the journal write, and writes the resolved value into
a local dict that is never round-tripped back into `call.arguments`. Task 4
pins this with a regression test. If a FUTURE refactor ever moved secret
substitution earlier (e.g. into a shared pre-dispatch step `dispatch_tool`
itself owns), this invariant would need re-verifying — it is a property of
the CURRENT call order, not an enforced type-level guarantee.

A genuine DB failure (``SQLAlchemyError``) PROPAGATES — never caught.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.providers.base import ToolCall

__all__ = [
    "JournalEntry",
    "PostgresReplayJournal",
    "ReplayJournal",
]

_APPEND_SQL = sa.text(
    "INSERT INTO tool_call_journal "
    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, tool_name, tool_arguments_json) "
    "VALUES (:adapter_id, :inbound_id, :call_index, :iteration, :tool_call_id, :tool_name, :tool_arguments_json)"
)

_READ_SQL = sa.text(
    "SELECT call_index, iteration, tool_call_id, tool_name, tool_arguments_json "
    "FROM tool_call_journal WHERE adapter_id = :adapter_id AND inbound_id = :inbound_id "
    "ORDER BY call_index ASC"
)


@dataclass(frozen=True, slots=True)
class JournalEntry:
    call_index: int
    iteration: int
    tool_call: ToolCall


@runtime_checkable
class ReplayJournal(Protocol):
    """Durable per-``(adapter_id, inbound_id)`` ordered log of committed tool-dispatch decisions."""

    async def append_batch(
        self,
        *,
        adapter_id: str,
        inbound_id: str,
        iteration: int,
        calls: Sequence[tuple[int, ToolCall]],
    ) -> None:
        """Durably record an ENTIRE iteration's tool-dispatch decisions, atomically, before any is dispatched.

        ``calls`` is the ``(call_index, ToolCall)`` pairs the planner's
        completion requested for THIS iteration, in call order. All of them
        commit in ONE transaction. Deliberately NOT a single-call primitive
        (a #410 design correction found during the `/review-plan` fleet's
        second pass, 2026-08-07): a per-call write would leave a crash
        window between journalling call N and call N+1 of the SAME
        iteration, after which a resume's fast-forward — which groups
        entries by iteration and assumes each group is COMPLETE — would
        silently believe the iteration only ever requested N calls,
        dropping the un-journalled tail forever. Journalling the whole
        iteration atomically means a crash mid-iteration either leaves it
        fully recorded or not recorded at all, so a resume correctly falls
        back to full re-planning of that iteration in the latter case
        instead of silently truncating it.
        """
        ...

    async def read(self, *, adapter_id: str, inbound_id: str) -> tuple[JournalEntry, ...]:
        """Return every journalled entry for ``(adapter_id, inbound_id)``, ordered by ``call_index``.

        Returns ``()`` if none exist (the overwhelmingly common case — every
        first-ever attempt, and every direct/fixture call with its
        always-fresh synthesized ``inbound_id``).
        """
        ...


class PostgresReplayJournal:
    """Postgres-backed :class:`ReplayJournal`.

    Owns its own ``session_scope`` — a fresh, immediately-committing
    transaction per ITERATION (not per call — see :meth:`append_batch`),
    independent of the per-turn rollback-able session, same shape as
    :class:`~alfred.memory.turn_side_effects.PostgresTurnSideEffectLedger`
    and :class:`~alfred.memory.forwarded_dispatch_attempts.PostgresForwardedDispatchAttemptStore`.
    """

    def __init__(
        self,
        *,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_scope = session_scope

    async def append_batch(
        self,
        *,
        adapter_id: str,
        inbound_id: str,
        iteration: int,
        calls: Sequence[tuple[int, ToolCall]],
    ) -> None:
        async with self._session_scope() as session:
            await session.execute(
                _APPEND_SQL,
                [
                    {
                        "adapter_id": adapter_id,
                        "inbound_id": inbound_id,
                        "call_index": call_index,
                        "iteration": iteration,
                        "tool_call_id": call.id,
                        "tool_name": call.name,
                        "tool_arguments_json": json.dumps(dict(call.arguments)),
                    }
                    for call_index, call in calls
                ],
            )

    async def read(self, *, adapter_id: str, inbound_id: str) -> tuple[JournalEntry, ...]:
        async with self._session_scope() as session:
            result = await session.execute(
                _READ_SQL, {"adapter_id": adapter_id, "inbound_id": inbound_id}
            )
            return tuple(
                JournalEntry(
                    call_index=row.call_index,
                    iteration=row.iteration,
                    tool_call=ToolCall(
                        id=row.tool_call_id,
                        name=row.tool_name,
                        arguments=json.loads(row.tool_arguments_json),
                    ),
                )
                for row in result.all()
            )
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/memory/test_replay_journal_store.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Type-check**

Run: `uv run mypy src/alfred/memory/replay_journal.py tests/unit/memory/test_replay_journal_store.py && uv run pyright src/alfred/memory/replay_journal.py`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add src/alfred/memory/replay_journal.py tests/unit/memory/test_replay_journal_store.py
git commit -m "feat(memory): deterministic tool-call replay journal store (#410 PR2)"
```

---

### Task 2: Migration — `tool_call_journal` table

**Files:**

- Create: `src/alfred/memory/migrations/versions/0026_tool_call_journal.py`
- Test: `tests/integration/test_migration_0026_tool_call_journal.py`

**Known gap, accepted for this PR** — mirroring PR1 Task 2's identical callout for `turn_side_effect_ledger` (found during `/review-plan`, and again flagged for symmetry during the fleet's second pass, 2026-08-07): this table ships with no retention index or pruning story either — it grows one row per journalled tool call forever, and stores attacker-influenced tool-call-argument JSON up to 256 KB/row (Task 1). Not yet filed as a tracked GitHub issue; both this table and PR1's ledger should be addressed together (e.g. a shared prune-on-`commit_once` sweep) rather than solved twice independently. See PR1 Task 2 for the fuller note and the follow-up issue this PR should also cross-reference once filed.

- [ ] **Step 1: Write the failing migration round-trip test**

Model directly on Task 2 of the PR1 plan (`docs/superpowers/plans/2026-08-07-issue-410-pr1-turn-side-effect-ledger.md`), adjusted for this table's composite key and column set:

```python
"""Migration 0026 upgrade/downgrade round-trip: tool_call_journal."""

from __future__ import annotations

import pytest
from alembic import command, config
from sqlalchemy import create_engine, inspect, text

pytestmark = pytest.mark.integration


_ADAPTER = "discord"


def test_upgrade_creates_table_with_expected_columns(postgres_url: str) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        inspector = inspect(engine)
        columns = {c["name"] for c in inspector.get_columns("tool_call_journal")}
        assert columns == {
            "adapter_id",
            "inbound_id",
            "call_index",
            "iteration",
            "tool_call_id",
            "tool_name",
            "tool_arguments_json",
            "created_at",
        }
        pk = inspector.get_pk_constraint("tool_call_journal")
        assert set(pk["constrained_columns"]) == {"adapter_id", "inbound_id", "call_index"}
    finally:
        engine.dispose()


def test_ordering_by_call_index_within_one_inbound_id(postgres_url: str) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tool_call_journal "
                    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, tool_name, tool_arguments_json) "
                    "VALUES ('discord', 'm1', 1, 0, 'tc-2', 'web.fetch', '{}'), "
                    "('discord', 'm1', 0, 0, 'tc-1', 'clock.now', '{}')"
                )
            )
            rows = conn.execute(
                text(
                    "SELECT call_index FROM tool_call_journal "
                    "WHERE adapter_id = 'discord' AND inbound_id = 'm1' ORDER BY call_index ASC"
                )
            ).all()
            assert [r.call_index for r in rows] == [0, 1]
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
            # Two DIFFERENT adapters, SAME inbound_id + call_index — must NOT collide.
            conn.execute(
                text(
                    "INSERT INTO tool_call_journal "
                    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, tool_name, tool_arguments_json) "
                    "VALUES ('discord', 'shared-id', 0, 0, 'tc-discord', 'clock.now', '{}'), "
                    "('tui', 'shared-id', 0, 0, 'tc-tui', 'clock.now', '{}')"
                )
            )
            rows = conn.execute(
                text(
                    "SELECT adapter_id, tool_call_id FROM tool_call_journal "
                    "WHERE inbound_id = 'shared-id' ORDER BY adapter_id"
                )
            ).all()
            assert [(r.adapter_id, r.tool_call_id) for r in rows] == [
                ("discord", "tc-discord"),
                ("tui", "tc-tui"),
            ]
    finally:
        engine.dispose()


def test_oversized_tool_arguments_json_is_rejected(postgres_url: str) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        oversized = '{"padding": "' + ("x" * 300_000) + '"}'
        with pytest.raises(Exception, match="ck_tool_call_journal_tool_arguments_json_length"):
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO tool_call_journal "
                        "(adapter_id, inbound_id, call_index, iteration, tool_call_id, tool_name, tool_arguments_json) "
                        "VALUES (:adapter_id, 'm-oversized', 0, 0, 'tc-1', 'web.fetch', :payload)"
                    ),
                    {"adapter_id": _ADAPTER, "payload": oversized},
                )
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
        assert "tool_call_journal" not in inspector.get_table_names()
    finally:
        engine.dispose()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/integration/test_migration_0026_tool_call_journal.py -v`
Expected: FAIL (table does not exist / head is `0025`)

- [ ] **Step 3: Write the migration**

```python
"""tool_call_journal — #410 PR2 deterministic tool-dispatch replay log.

Revision ID: 0026
Revises: 0025
Create Date: 2026-08-07 00:00:00.000000

#410 PR2. Records the committed ordered tool-dispatch decision — ``(adapter_id,
inbound_id, call_index) -> (iteration, tool_call)`` — BEFORE each dispatch, so
a forwarded-path resume (ADR-0039 item 4) can fast-forward through the
already-decided prefix via the SAME `dispatch_tool` call the normal path
uses, instead of asking a fresh, possibly non-deterministic planner. See
``src/alfred/memory/replay_journal.py`` for the full contract and why
``tool_arguments`` is a JSON-serialized TEXT column, not native JSONB.

Composite ``(adapter_id, inbound_id, call_index)`` PRIMARY KEY: ``call_index``
is the per-turn monotonic dispatch ordinal (already used across this
codebase as the Spec C egress-id input, `src/alfred/egress/egress_id.py:62`)
— unique only WITHIN one ``(adapter_id, inbound_id)`` pair. Mirrors the
composite-key precedent of ``forwarded_dispatch_attempts`` (migration 0020)
and ``turn_side_effect_ledger`` (migration 0025, #410 PR1): ``inbound_id``
alone is a free-form, per-adapter-minted opaque string, so a key omitting
``adapter_id`` would let two different adapters' turns collide.

``tool_arguments_json`` carries a 256 KB CHECK-constraint size cap, matching
the codebase's other JSON payload columns (migration 0013's identical cap on
``policies_json``) — the payload is attacker-influenced (a T3-derived
planner decision), so an unbounded column is a real storage-exhaustion
surface.

Strictly additive: a new table, no existing columns touched, no cross-table
CHECK constraint.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str | Sequence[str] | None = "0025"
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

# Matches migration 0013's cap on policies_json — see module docstring.
_MAX_TOOL_ARGUMENTS_JSON_BYTES = 256 * 1024


def upgrade() -> None:
    """Create the tool_call_journal table."""
    op.create_table(
        "tool_call_journal",
        sa.Column("adapter_id", sa.String(128), nullable=False),
        sa.Column("inbound_id", sa.String(255), nullable=False),
        sa.Column("call_index", sa.Integer(), nullable=False),
        sa.Column("iteration", sa.Integer(), nullable=False),
        sa.Column("tool_call_id", sa.String(255), nullable=False),
        sa.Column("tool_name", sa.String(255), nullable=False),
        sa.Column("tool_arguments_json", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint(
            "adapter_id", "inbound_id", "call_index", name="pk_tool_call_journal"
        ),
        sa.CheckConstraint(
            "char_length(adapter_id) BETWEEN 1 AND 128",
            name="ck_tool_call_journal_adapter_id_length",
        ),
        sa.CheckConstraint(
            "char_length(inbound_id) BETWEEN 1 AND 255",
            name="ck_tool_call_journal_inbound_id_length",
        ),
        sa.CheckConstraint(
            "call_index >= 0",
            name="ck_tool_call_journal_call_index_non_negative",
        ),
        sa.CheckConstraint(
            "iteration >= 0",
            name="ck_tool_call_journal_iteration_non_negative",
        ),
        sa.CheckConstraint(
            f"octet_length(tool_arguments_json) <= {_MAX_TOOL_ARGUMENTS_JSON_BYTES}",
            name="ck_tool_call_journal_tool_arguments_json_length",
        ),
    )


def downgrade() -> None:
    """Drop the tool_call_journal table."""
    op.execute("DROP TABLE IF EXISTS tool_call_journal")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/integration/test_migration_0026_tool_call_journal.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/migrations/versions/0026_tool_call_journal.py tests/integration/test_migration_0026_tool_call_journal.py
git commit -m "feat(memory): migration 0026 — tool_call_journal table (#410 PR2)"
```

---

### Task 3: Integration test — `PostgresReplayJournal` against real Postgres

**Files:**

- Create: `tests/integration/test_replay_journal_postgres.py`

- [ ] **Step 1: Write the test**

```python
"""PostgresReplayJournal against real Postgres: append/read ordering + isolation."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.memory.db import session_scope
from alfred.memory.replay_journal import JournalEntry, PostgresReplayJournal
from alfred.providers.base import ToolCall

pytestmark = pytest.mark.integration

_ADAPTER = "discord"


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0026
    return postgres_url


@pytest.fixture
async def journal(migrated_url: str) -> AsyncIterator[PostgresReplayJournal]:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresReplayJournal(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


async def test_read_empty_for_absent_inbound_id(journal: PostgresReplayJournal) -> None:
    assert await journal.read(adapter_id=_ADAPTER, inbound_id="never-seen") == ()


async def test_append_batch_then_read_round_trips(journal: PostgresReplayJournal) -> None:
    call = ToolCall(id="tc-1", name="web.fetch", arguments={"url": "https://example.invalid"})
    await journal.append_batch(adapter_id=_ADAPTER, inbound_id="m1", iteration=0, calls=[(0, call)])
    entries = await journal.read(adapter_id=_ADAPTER, inbound_id="m1")
    assert entries == (JournalEntry(call_index=0, iteration=0, tool_call=call),)


async def test_append_batch_writes_every_call_of_one_iteration_in_one_call(
    journal: PostgresReplayJournal,
) -> None:
    """The core-001 real-Postgres proof: a multi-call iteration round-trips as ONE batch write."""
    call_a = ToolCall(id="tc-a", name="clock.now", arguments={})
    call_b = ToolCall(id="tc-b", name="clock.now", arguments={})
    await journal.append_batch(
        adapter_id=_ADAPTER, inbound_id="m1b", iteration=0, calls=[(0, call_a), (1, call_b)]
    )
    entries = await journal.read(adapter_id=_ADAPTER, inbound_id="m1b")
    assert entries == (
        JournalEntry(call_index=0, iteration=0, tool_call=call_a),
        JournalEntry(call_index=1, iteration=0, tool_call=call_b),
    )


async def test_read_orders_by_call_index_regardless_of_insert_order(
    journal: PostgresReplayJournal,
) -> None:
    call_a = ToolCall(id="tc-a", name="clock.now", arguments={})
    call_b = ToolCall(id="tc-b", name="clock.now", arguments={})
    call_c = ToolCall(id="tc-c", name="clock.now", arguments={})
    # Insert out of order: iteration 1's batch first, iteration 0's second.
    await journal.append_batch(adapter_id=_ADAPTER, inbound_id="m2", iteration=1, calls=[(2, call_c)])
    await journal.append_batch(
        adapter_id=_ADAPTER, inbound_id="m2", iteration=0, calls=[(0, call_a), (1, call_b)]
    )

    entries = await journal.read(adapter_id=_ADAPTER, inbound_id="m2")
    assert [e.call_index for e in entries] == [0, 1, 2]
    assert [e.tool_call.id for e in entries] == ["tc-a", "tc-b", "tc-c"]


async def test_inbound_id_namespaces_are_isolated(journal: PostgresReplayJournal) -> None:
    call = ToolCall(id="tc-1", name="clock.now", arguments={})
    await journal.append_batch(adapter_id=_ADAPTER, inbound_id="m3", iteration=0, calls=[(0, call)])
    assert await journal.read(adapter_id=_ADAPTER, inbound_id="m4") == ()


async def test_adapter_id_namespaces_are_isolated_on_the_same_inbound_id(
    journal: PostgresReplayJournal,
) -> None:
    # Two DIFFERENT adapters minting the SAME inbound_id string must not collide.
    call_discord = ToolCall(id="tc-discord", name="clock.now", arguments={})
    call_tui = ToolCall(id="tc-tui", name="clock.now", arguments={})
    await journal.append_batch(
        adapter_id="discord", inbound_id="shared-id", iteration=0, calls=[(0, call_discord)]
    )
    await journal.append_batch(
        adapter_id="tui", inbound_id="shared-id", iteration=0, calls=[(0, call_tui)]
    )

    discord_entries = await journal.read(adapter_id="discord", inbound_id="shared-id")
    tui_entries = await journal.read(adapter_id="tui", inbound_id="shared-id")
    assert discord_entries == (JournalEntry(call_index=0, iteration=0, tool_call=call_discord),)
    assert tui_entries == (JournalEntry(call_index=0, iteration=0, tool_call=call_tui),)


async def test_arguments_round_trip_through_json_serialization(
    journal: PostgresReplayJournal,
) -> None:
    call = ToolCall(
        id="tc-1",
        name="web.fetch",
        arguments={"url": "https://example.invalid", "nested": {"a": 1, "b": [1, 2, 3]}},
    )
    await journal.append_batch(adapter_id=_ADAPTER, inbound_id="m5", iteration=0, calls=[(0, call)])
    entries = await journal.read(adapter_id=_ADAPTER, inbound_id="m5")
    assert entries[0].tool_call.arguments == call.arguments
```

- [ ] **Step 2: Run to verify it passes**

Run: `uv run pytest tests/integration/test_replay_journal_postgres.py -v`
Expected: PASS (7 tests)

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_replay_journal_postgres.py
git commit -m "test(memory): PostgresReplayJournal real-Postgres contract proof (#410 PR2)"
```

---

### Task 4: Wire the journal into the Act loop — fast-forward + write-as-you-go + `temperature=0`

**Files:**

- Modify: `src/alfred/orchestrator/core.py` — import, constructor, a new `_fast_forward_journalled_calls` private method, the `for iteration in range(...)` bound, the tool-dispatch for-loop (journal write before dispatch), the `CompletionRequest(...)` construction (`temperature`)
- Test: `tests/unit/orchestrator/test_act_loop.py` (this file already has its OWN `_build` helper with `tool_registry` support — use it, not `test_core.py`'s)

**Interfaces:**

- Consumes: `ReplayJournal` (Task 1).
- Produces: `Orchestrator.__init__(..., replay_journal: ReplayJournal | None = None)`.

This task changes production behaviour only when `replay_journal` is not `None` AND `self._tool_registry` is not `None` AND a journal actually exists for the current `inbound_id` — none of which is reachable in production until PR3 (which doesn't land in this PR). The entire existing `test_act_loop.py` suite must still pass unmodified.

- [ ] **Step 1: Add the constructor param**

In `src/alfred/orchestrator/core.py`, add the import:

```python
from alfred.memory.replay_journal import ReplayJournal
```

In `Orchestrator.__init__`, immediately after `side_effect_ledger: TurnSideEffectLedger | None = None,` (added by PR1):

```python
        side_effect_ledger: TurnSideEffectLedger | None = None,
        # #410 PR2: the deterministic tool-call replay journal. Additive +
        # optional; `None` (every caller before PR3 wires a live
        # tool_registry) preserves today's behaviour exactly — this seam has
        # NO live consumer until PR3.
        replay_journal: ReplayJournal | None = None,
    ) -> None:
```

And in the body:

```python
        self._replay_journal = replay_journal
```

- [ ] **Step 2: Write the failing fast-forward tests**

Add to `tests/unit/orchestrator/test_act_loop.py`, reusing its VERIFIED existing helpers (confirmed present in this file, 2026-08-07 — do not invent parallel ones): `_make_orchestrator(*, router=None, budget=None, **kw)`, `_drive_turn(orch, *, text=...)`, `_text_response(content=..., cost=...)`, `_tool_use_response(*calls, cost=...)`, `_fake_registry(*names)`, `_make_no_op_budget()`. `dispatch_tool` is exercised through `monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)`, mirroring `TestActLoopOrderedDispatch.test_two_tool_turn_dispatches_in_order_then_returns` (same file) exactly — do not attempt to drive the REAL `dispatch_tool` through a full registry/gate/DLP resolution chain, which is not what this test file's established pattern does.

Add the import this new test class needs — verified via `grep -n "^from alfred.memory\|^import" tests/unit/orchestrator/test_act_loop.py` (2026-08-07) that `JournalEntry` is not already imported in this file:

```python
from alfred.memory.replay_journal import JournalEntry
```

All `journal.read`/`journal.append_batch` mock calls below now also carry `adapter_id` — assert on it explicitly in at least one test so a future implementer can't silently drop the composite key (Step 2's tests below include this).

```python
class TestReplayJournalFastForward:
    """#410 PR2: a journalled prefix is replayed via dispatch_tool, not re-planned."""

    async def test_no_journal_behaves_exactly_as_today(self, monkeypatch: Any) -> None:
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        reply = await _drive_turn(orch)
        assert reply == "done"
        journal.read.assert_awaited_once()
        journal.append_batch.assert_not_called()  # no tool_use in this fixture's response

    async def test_fresh_tool_call_gets_journalled_before_dispatch(
        self, monkeypatch: Any
    ) -> None:
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        journal.append_batch = AsyncMock()
        r0 = _tool_use_response(ToolCall(id="c0", name="clock.now", arguments={}))
        r1 = _text_response("done")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch)
        journal.append_batch.assert_awaited_once()
        batch_kwargs = journal.append_batch.await_args.kwargs
        assert batch_kwargs["adapter_id"]
        assert batch_kwargs["iteration"] == 0
        assert len(batch_kwargs["calls"]) == 1
        call_index, call = batch_kwargs["calls"][0]
        assert call_index == 0
        assert call.name == "clock.now"

    async def test_journalled_prefix_fast_forwards_via_dispatch_tool_not_replanning(
        self, monkeypatch: Any
    ) -> None:
        journalled_call = ToolCall(id="tc-1", name="clock.now", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(JournalEntry(call_index=0, iteration=0, tool_call=journalled_call),)
        )
        journal.append_batch = AsyncMock()
        dispatched: list[str] = []

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            dispatched.append(call.id)
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        # The router only ever sees ONE request: the resumed loop's, starting
        # past the fast-forwarded prefix — never asked to re-plan the
        # journalled call.
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("resumed answer"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        reply = await _drive_turn(orch)
        assert reply == "resumed answer"
        assert router.complete.await_count == 1
        assert dispatched == ["tc-1"]  # the journalled call WAS dispatched, via fast-forward
        # The fast-forwarded call was NOT re-journalled (it came FROM the journal).
        journal.append_batch.assert_not_called()

    async def test_journalled_prefix_still_allows_further_tool_calls_after_resume(
        self, monkeypatch: Any
    ) -> None:
        # The regression pin for the rejected forced-wrap-up design: resume
        # must NOT force a text-only answer — the planner is free to keep
        # calling tools after the fast-forwarded prefix.
        journalled_call = ToolCall(id="tc-1", name="clock.now", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(JournalEntry(call_index=0, iteration=0, tool_call=journalled_call),)
        )
        journal.append_batch = AsyncMock()
        r0 = _tool_use_response(ToolCall(id="tc-2", name="clock.now", arguments={}))
        r1 = _text_response("second call worked too")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        reply = await _drive_turn(orch, text="what time is it, then check again")
        assert reply == "second call worked too"
        # The SECOND (fresh, post-resume) call gets journalled at call_index=1,
        # continuing the sequence the fast-forward left off at.
        journal.append_batch.assert_awaited_once()
        batch_kwargs = journal.append_batch.await_args.kwargs
        assert len(batch_kwargs["calls"]) == 1
        assert batch_kwargs["calls"][0][0] == 1

    async def test_multi_call_iteration_reconstructs_grouping_by_iteration(
        self, monkeypatch: Any
    ) -> None:
        # Two journalled calls from the SAME original iteration must land in
        # ONE reconstructed assistant tool_calls message, not two.
        call_a = ToolCall(id="tc-a", name="clock.now", arguments={})
        call_b = ToolCall(id="tc-b", name="clock.now", arguments={})
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(
                JournalEntry(call_index=0, iteration=0, tool_call=call_a),
                JournalEntry(call_index=1, iteration=0, tool_call=call_b),
            )
        )
        journal.append_batch = AsyncMock()

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch, text="two calls at once")
        # Exactly one fresh completion (the resumed iteration) — its request
        # history must contain exactly one assistant tool_calls-bearing
        # message covering BOTH replayed calls, not two separate ones.
        sent_request = router.complete.await_args_list[0].args[0]
        assistant_tool_msgs = [
            msg for msg in sent_request.messages if msg.role == "assistant" and msg.tool_calls
        ]
        assert len(assistant_tool_msgs) == 1
        assert {c.id for c in assistant_tool_msgs[0].tool_calls} == {"tc-a", "tc-b"}

    async def test_fresh_multi_call_iteration_journalled_in_one_atomic_batch(
        self, monkeypatch: Any
    ) -> None:
        """The core-001 wiring-level regression pin (found during `/review-plan` pass 2, 2026-08-07).

        A single completion that requests TWO fresh tool calls in the same
        iteration must produce exactly ONE `journal.append_batch` call
        covering both — never two separate calls, which would reopen the
        per-call crash window `append_batch` exists to close.
        """
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        journal.append_batch = AsyncMock()
        r0 = _tool_use_response(
            ToolCall(id="c0", name="clock.now", arguments={}),
            ToolCall(id="c1", name="clock.now", arguments={}),
        )
        r1 = _text_response("both done")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            return f"result-{call.id}"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch)
        journal.append_batch.assert_awaited_once()  # ONE batch write, not two
        batch_kwargs = journal.append_batch.await_args.kwargs
        assert batch_kwargs["iteration"] == 0
        assert [call_index for call_index, _call in batch_kwargs["calls"]] == [0, 1]
        assert [call.id for _call_index, call in batch_kwargs["calls"]] == ["c0", "c1"]

    async def test_no_live_consumer_never_touches_the_journal_without_a_tool_registry(
        self, monkeypatch: Any
    ) -> None:
        # #410 design correction (found during /review-plan): the "no live
        # consumer" claim depends on checking self._tool_registry FIRST,
        # before ever consulting self._replay_journal. This is the
        # regression pin for that ordering.
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(
                JournalEntry(
                    call_index=0,
                    iteration=0,
                    tool_call=ToolCall(id="tc-1", name="clock.now", arguments={}),
                ),
            )
        )
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(router=router, budget=_make_no_op_budget(), replay_journal=journal)
        reply = await _drive_turn(orch)
        assert reply == "done"
        journal.read.assert_not_called()

    async def test_seams_unwired_raises_when_journal_has_entries_but_gate_missing(
        self, monkeypatch: Any
    ) -> None:
        journal = MagicMock()
        journal.read = AsyncMock(
            return_value=(
                JournalEntry(
                    call_index=0,
                    iteration=0,
                    tool_call=ToolCall(id="tc-1", name="clock.now", arguments={}),
                ),
            )
        )
        orch = _make_orchestrator(
            router=MagicMock(),
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            # gate and outbound_dlp deliberately omitted.
            replay_journal=journal,
        )
        with pytest.raises(RuntimeError, match="dispatch_seams_unwired"):
            await _drive_turn(orch)

    async def test_temperature_is_zero_when_tools_are_advertised(self, monkeypatch: Any) -> None:
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch)
        sent_request = router.complete.await_args.args[0]
        assert sent_request.temperature == 0.0

    async def test_temperature_stays_default_when_no_tools_advertised(
        self, monkeypatch: Any
    ) -> None:
        router = MagicMock()
        router.complete = AsyncMock(return_value=_text_response("done"))
        orch = _make_orchestrator(router=router, budget=_make_no_op_budget())
        await _drive_turn(orch)
        sent_request = router.complete.await_args.args[0]
        assert sent_request.temperature == 0.7

    async def test_journal_never_receives_a_resolved_secret_value(
        self, monkeypatch: Any
    ) -> None:
        # Pins Task 1's disputed-severity invariant: the journal write
        # happens BEFORE dispatch_tool runs, so it always sees the raw
        # planner-authored arguments — a {{secret:name}} placeholder stays
        # a placeholder, never the value dispatch_tool's own broker
        # substitution would have resolved it to.
        journal = MagicMock()
        journal.read = AsyncMock(return_value=())
        journal.append_batch = AsyncMock()
        placeholder_call = ToolCall(
            id="c0", name="clock.now", arguments={"header": "{{secret:api-key}}"}
        )
        r0 = _tool_use_response(placeholder_call)
        r1 = _text_response("done")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=[r0, r1])

        async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
            # Simulates what a real tool dispatcher does INTERNALLY: resolve
            # the secret for ITS OWN use, never writing it back to `call`.
            # `call` is the SAME frozen ToolCall object journal.append_batch
            # already received (journalled before this function runs) — a
            # real dispatcher resolving into a separate local variable, as
            # web.fetch's does, can never retroactively change what was
            # already journalled.
            del call, call_index, kw
            return "used-sk-real-secret-value-never-journalled"

        monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
        orch = _make_orchestrator(
            router=router,
            budget=_make_no_op_budget(),
            tool_registry=_fake_registry("clock.now"),
            gate=MagicMock(),
            outbound_dlp=MagicMock(),
            replay_journal=journal,
        )
        await _drive_turn(orch)
        _journalled_index, journalled_call = journal.append_batch.await_args.kwargs["calls"][0]
        assert journalled_call.arguments["header"] == "{{secret:api-key}}"
```

- [ ] **Step 3: Run to verify they fail**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py -v -k ReplayJournalFastForward`
Expected: FAIL — `TypeError: Orchestrator.__init__() got an unexpected keyword argument 'replay_journal'` (or `AttributeError` once the constructor accepts it but the loop never calls `journal.read`)

- [ ] **Step 4: Add the fast-forward helper method**

In `src/alfred/orchestrator/core.py`, add a new private method (place it near `_synthesize_egress_context`, which it complements):

```python
    async def _fast_forward_journalled_calls(
        self,
        *,
        ctx: TurnEgressContext,
        user: UserLike,
        trace_id: str,
    ) -> tuple[list[Message], int, int]:
        """Replay the journalled tool-call prefix for ``ctx.inbound_id``, if any.

        Returns ``(local, call_index, start_iteration)``: the reconstructed
        ephemeral tool transcript, the next ``call_index`` a fresh dispatch
        should use, and the iteration the main Act loop should resume from.
        Returns ``([], 0, 0)`` — behaviourally identical to today — whenever
        ``self._tool_registry is None`` (checked FIRST and unconditionally:
        this is what makes the whole seam provably dark/no-live-consumer
        until PR3 — a #410 design correction, found during the
        `/review-plan` fleet pass, to an earlier draft that only checked
        ``self._replay_journal is None`` and would have done a real
        Postgres round-trip on every live comms turn the moment Task 5's
        boot-graph wiring landed, well before PR3 exists), or
        ``self._replay_journal is None``, or no journal entries exist for
        this ``inbound_id`` (the overwhelmingly common case even once tools
        are live: every direct/fixture call synthesizes a fresh,
        never-before-seen ``inbound_id``; a forwarded call only has entries
        after a PRIOR attempt reached the tool-dispatch stage).

        Each replayed call goes through the SAME ``dispatch_tool`` the
        normal path uses — the Spec C egress ledger's existing memoize-and-
        replay handles the actual dedup for ``ExternalToolSpec`` tools (e.g.
        web.fetch); this method adds no new dedup logic of its own.
        ``InternalToolSpec`` tools (e.g. `clock.now`) have NO such
        protection and re-dispatch for real on every fast-forward — an
        accepted, documented gap (Task 1's module docstring) since they are
        side-effect-free by construction. Entries are grouped by their
        journalled ``iteration`` (call_index-ascending order, which is also
        iteration-ascending by construction) so the reconstructed
        transcript's assistant-tool_calls / tool-result message SHAPE
        matches the original run — the reconstructed assistant message's
        ``content`` is always the empty string, NOT the original model's
        accompanying text (the journal does not store it — only the tool
        calls). This is a deliberate, accepted simplification: `local` is
        purely EPHEMERAL scratch space for the remainder of THIS turn's
        completions, never persisted to working memory or episodic history,
        so the wrap-up completion sees a structurally faithful tool-call/
        tool-result exchange without needing the original prose.
        """
        if self._tool_registry is None:
            return [], 0, 0
        if self._replay_journal is None:
            return [], 0, 0
        entries = await self._replay_journal.read(
            adapter_id=ctx.adapter_id, inbound_id=ctx.inbound_id
        )
        if not entries:
            return [], 0, 0
        if self._gate is None or self._outbound_dlp is None:
            # tool_registry is confirmed non-None above; gate/outbound_dlp
            # unwired alongside it is the SAME construction-time
            # misconfiguration core.py:973's guard already names.
            raise RuntimeError(t("orchestrator.tool.dispatch_seams_unwired"))
        local: list[Message] = []
        call_index = 0  # next FRESH call_index once the fast-forward is done
        max_iteration = -1
        for iteration, group in itertools.groupby(entries, key=lambda e: e.iteration):
            group_entries = list(group)
            calls = tuple(entry.tool_call for entry in group_entries)
            # content="" — see the docstring above: the journal stores tool
            # calls only, never the model's accompanying prose. `calls` is a
            # tuple (not a list) — Message.tool_calls is typed
            # tuple[ToolCall, ...] (a #410 design correction found during
            # the `/review-plan` fleet's second pass, 2026-08-07: an earlier
            # draft passed a list here, which mypy --strict rejects).
            local.append(Message(role="assistant", content="", tool_calls=calls))
            for entry in group_entries:
                # Dispatch using entry.call_index DIRECTLY, not a freshly
                # re-derived local counter (a #410 design correction found
                # during the `/review-plan` fleet's second pass, 2026-08-07):
                # call_index is the sole (with ctx) input to
                # compute_egress_id, so replay convergence must reproduce
                # the EXACT call_index the original dispatch used — reading
                # it straight from the journal makes that self-evidently
                # true rather than dependent on an unenforced contiguity
                # invariant on the write side.
                result_t2 = await dispatch_tool(
                    entry.tool_call,
                    entry.call_index,
                    ctx=ctx,
                    registry=self._tool_registry,
                    gate=self._gate,
                    dlp=self._outbound_dlp,
                    audit=self._audit,
                    user_id=user.slug,
                    correlation_id=trace_id,
                    language=user.language,
                )
                local.append(
                    Message(
                        role="tool",
                        tool_call_id=entry.tool_call.id,
                        content=_truncate_tool_result(result_t2),
                    )
                )
                call_index = entry.call_index + 1
            max_iteration = iteration
        return local, call_index, max_iteration + 1
```

Add the `itertools` import at the top of the file (alongside the existing `import asyncio` / `import time` / `import uuid` block):

```python
import itertools
```

- [ ] **Step 5: Wire the fast-forward call into `_handle_turn` and adjust the loop bound**

Replace:

```python
        tools = self._tool_registry.definitions() if self._tool_registry is not None else ()
        base_messages = messages  # system + history (built in Orient)
        local: list[Message] = []  # in-turn tool transcript (EPHEMERAL — never persisted)
        call_index = 0  # monotonic per-turn dispatch ordinal (threaded to the egress path)
        per_turn_spent_usd = 0.0
```

with:

```python
        tools = self._tool_registry.definitions() if self._tool_registry is not None else ()
        base_messages = messages  # system + history (built in Orient)
        # #410 PR2: fast-forward any journalled tool-call prefix for this
        # inbound_id BEFORE entering the loop. Returns ([], 0, 0) — today's
        # exact behaviour — whenever no journal exists (always true until
        # PR3 wires a live tool_registry; even then, true for every FIRST
        # attempt of any inbound_id).
        local, call_index, start_iteration = await self._fast_forward_journalled_calls(
            ctx=ctx, user=user, trace_id=trace_id
        )
        per_turn_spent_usd = 0.0
```

(`local` and `call_index` are no longer initialized as bare `[]` / `0` here — they now come from the fast-forward call, which returns `([], 0, ...)` in the untouched case, so every existing test's values are unchanged.)

Replace:

```python
        for iteration in range(loop_constants.MAX_TOOL_ITERATIONS):
```

with:

```python
        # #410 PR2: resume from the fast-forwarded point (0 in every case
        # reachable before PR3). The upper bound and every per-iteration
        # check below (budget, fan-out cap, max-iterations) are UNCHANGED.
        for iteration in range(start_iteration, loop_constants.MAX_TOOL_ITERATIONS):
```

- [ ] **Step 6: Journal an iteration's fresh tool calls, atomically, before dispatching any of them**

Replace:

```python
            for call in response.tool_calls:
                result_t2 = await dispatch_tool(
                    call,
                    call_index,
                    ctx=ctx,
                    registry=self._tool_registry,
                    gate=self._gate,
                    dlp=self._outbound_dlp,
                    audit=self._audit,
                    user_id=user.slug,
                    correlation_id=trace_id,
                    language=user.language,
                )
                call_index += 1
```

with:

```python
            if self._replay_journal is not None and response.tool_calls:
                # #410 PR2: journal the WHOLE iteration's decision as ONE
                # atomic write, BEFORE dispatching any call in it — so a
                # crash mid-dispatch still leaves a resume able to
                # fast-forward the entire iteration, rather than losing the
                # decision and re-asking a possibly-divergent planner.
                # Deliberately NOT one append per call inside the dispatch
                # loop below (a #410 design correction found during the
                # `/review-plan` fleet's second pass, 2026-08-07): a per-call
                # write would leave a crash window between journalling call
                # N and call N+1 of the SAME iteration — see
                # `ReplayJournal.append_batch`'s docstring (Task 1) for the
                # full failure mode this closes.
                await self._replay_journal.append_batch(
                    adapter_id=ctx.adapter_id,
                    inbound_id=ctx.inbound_id,
                    iteration=iteration,
                    calls=[
                        (call_index + offset, call)
                        for offset, call in enumerate(response.tool_calls)
                    ],
                )
            for call in response.tool_calls:
                result_t2 = await dispatch_tool(
                    call,
                    call_index,
                    ctx=ctx,
                    registry=self._tool_registry,
                    gate=self._gate,
                    dlp=self._outbound_dlp,
                    audit=self._audit,
                    user_id=user.slug,
                    correlation_id=trace_id,
                    language=user.language,
                )
                call_index += 1
```

- [ ] **Step 7: Thread `temperature=0` for tool-bearing completions**

Replace:

```python
            request = CompletionRequest(
                messages=base_messages + local,
                tools=tools,
                tool_choice="auto",
            )
```

with:

```python
            request = CompletionRequest(
                messages=base_messages + local,
                tools=tools,
                tool_choice="auto",
                # #410 PR2: temperature=0 for tool-bearing turns as
                # defence-in-depth ON TOP OF the journal (not instead of
                # it) — a resumed turn should ideally re-derive the
                # identical plan even before the fast-forward above ever
                # runs. `tools` is empty until PR3 wires a live registry,
                # so this is inert (default 0.7) in production today.
                temperature=0.0 if tools else 0.7,
            )
```

- [ ] **Step 8: Run to verify the new tests pass**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py -v -k ReplayJournalFastForward`
Expected: PASS (10 tests)

- [ ] **Step 8a: Add the hypothesis property test the design spec commits to**

Design spec §10 commits PR2 to a property test proving replay ordering holds for ANY journalled call list, not just the specific fixtures above. Add to `tests/unit/orchestrator/test_act_loop.py`:

```python
from hypothesis import given
from hypothesis import strategies as st


@given(
    call_ids=st.lists(
        st.text(alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")), min_size=1, max_size=8),
        min_size=1,
        max_size=6,
        unique=True,
    )
)
async def test_fast_forward_always_dispatches_in_journalled_call_index_order(
    call_ids: list[str], monkeypatch: Any
) -> None:
    """For ANY journalled call list, fast-forward dispatches in exactly the
    journalled call_index order — never re-ordered, never skipped."""
    entries = tuple(
        JournalEntry(
            call_index=i,
            iteration=0,
            tool_call=ToolCall(id=cid, name="clock.now", arguments={}),
        )
        for i, cid in enumerate(call_ids)
    )
    journal = MagicMock()
    journal.read = AsyncMock(return_value=entries)
    dispatched: list[str] = []

    async def _fake_dispatch(call: ToolCall, call_index: int, **kw: Any) -> str:
        dispatched.append(call.id)
        return f"result-{call.id}"

    monkeypatch.setattr("alfred.orchestrator.core.dispatch_tool", _fake_dispatch)
    router = MagicMock()
    router.complete = AsyncMock(return_value=_text_response("done"))
    orch = _make_orchestrator(
        router=router,
        budget=_make_no_op_budget(),
        tool_registry=_fake_registry("clock.now"),
        gate=MagicMock(),
        outbound_dlp=MagicMock(),
        replay_journal=journal,
    )
    await _drive_turn(orch)
    assert dispatched == call_ids
```

Add `hypothesis` to this file's imports if not already present (check first — several other test files in this repo already use it; confirm via `grep -rl "^from hypothesis" tests/unit/`).

**Mutation-testing note (design spec §10):** per project history, a new guard's first draft tends to reproduce the exact failure it exists to catch. After Step 9 below passes, run the repo's mutation-testing target (check `Makefile`/`pyproject.toml` for the exact invocation — do not guess flags) scoped to `_fast_forward_journalled_calls` and the two new call sites in `_handle_turn`, and confirm every surviving mutant is either killed by an existing test or explicitly triaged.

- [ ] **Step 9: Run the full existing suite for both files sharing `_handle_turn`**

Run: `uv run pytest tests/unit/orchestrator/test_act_loop.py tests/unit/orchestrator/test_core.py -v`
Expected: PASS — every pre-existing test unmodified, plus PR1's and this task's new classes. If anything pre-existing fails, stop and fix before proceeding; do not weaken an existing assertion.

- [ ] **Step 10: Type-check**

Run: `uv run mypy src/alfred/orchestrator/core.py tests/unit/orchestrator/test_act_loop.py && uv run pyright src/alfred/orchestrator/core.py`
Expected: no errors

- [ ] **Step 11: Commit**

```bash
git add src/alfred/orchestrator/core.py tests/unit/orchestrator/test_act_loop.py
git commit -m "feat(orchestrator): fast-forward journalled tool calls on resume, temperature=0 for tool turns (#410 PR2)"
```

---

### Task 5: Wire `PostgresReplayJournal` into the live boot graph (dark — no live consumer)

**Files:**

- Modify: `src/alfred/cli/_bootstrap.py:459-517` (`build_orchestrator`)
- Modify: `src/alfred/cli/daemon/_comms_boot.py:793-816` (the live construction call)
- Test: `tests/unit/cli/test_bootstrap_build_orchestrator.py` (created by PR1 Task 5 — add to it)
- Create: `tests/unit/cli/daemon/test_daemon_replay_journal_wired.py` (Step 5a — proves the live wiring itself, which the type-check/regression steps alone cannot)

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/cli/test_bootstrap_build_orchestrator.py`:

```python
async def test_build_orchestrator_forwards_replay_journal(monkeypatch: Any) -> None:
    # Deliberately a PLAIN MagicMock, not MagicMock(spec=Settings) — see
    # PR1's identical Task 5 fix: a spec'd mock doesn't know about pydantic
    # v2 fields and raises AttributeError inside build_budget_guard.
    settings = MagicMock()
    journal = MagicMock()

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
        replay_journal=journal,
    )
    assert orch._replay_journal is journal  # type: ignore[attr-defined]
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/cli/test_bootstrap_build_orchestrator.py -v -k replay_journal`
Expected: FAIL — `TypeError: build_orchestrator() got an unexpected keyword argument 'replay_journal'`

- [ ] **Step 3: Widen `build_orchestrator`**

In `src/alfred/cli/_bootstrap.py`, add the import:

```python
from alfred.memory.replay_journal import ReplayJournal
```

Widen the signature (alongside PR1's `side_effect_ledger` param) and forward it:

```python
        side_effect_ledger: TurnSideEffectLedger | None = None,
        # #410 PR2: forwarded straight to Orchestrator. None (every caller
        # before this PR's Task 5 wiring below) preserves today's behaviour.
        replay_journal: ReplayJournal | None = None,
    ) -> Orchestrator:
```

And in the `return Orchestrator(...)` call, add `replay_journal=replay_journal,` alongside the existing `side_effect_ledger=side_effect_ledger,` line.

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/cli/test_bootstrap_build_orchestrator.py -v`
Expected: PASS

- [ ] **Step 5: Wire the live construction site**

In `src/alfred/cli/daemon/_comms_boot.py`, add the import alongside `PostgresTurnSideEffectLedger`:

```python
from alfred.memory.replay_journal import PostgresReplayJournal
```

In the `orchestrator = build_orchestrator(...)` call (PR1 added `side_effect_ledger=...` here), add:

```python
            side_effect_ledger=PostgresTurnSideEffectLedger(
                session_scope=build_boot_session_scope(settings)
            ),
            # #410 PR2: the LIVE journal store — constructed and wired, but
            # with NO reachable consumer until PR3 wires a live
            # tool_registry (self._tool_registry stays None here, so
            # _fast_forward_journalled_calls always returns ([], 0, 0) and
            # the write-before-dispatch site inside the Act loop's
            # tool-dispatch for-loop is unreachable). Same shared-DSN-
            # cached-engine session_scope shape as every sibling store here.
            replay_journal=PostgresReplayJournal(
                session_scope=build_boot_session_scope(settings)
            ),
        )
```

(Adjust the exact insertion point to match wherever the `quarantined_extractor=None,` / `side_effect_ledger=...,` lines currently end the call, per PR1's own Task 5 edit — this is an addition to that same call, not a replacement.)

- [ ] **Step 5a: Prove the live wiring actually happened, not just that it type-checks**

**Found during `/review-plan` (2026-08-07):** because this wiring is deliberately dark, Steps 6/7 below (mypy/pyright, and "the integration suite still passes unmodified") pass IDENTICALLY whether or not the `replay_journal=` kwarg was actually added to the live `_comms_boot.py` call — neither exercises the wiring itself. PR1's Task 6 gets this proof for free via an observable behaviour change (a test assertion flips `4→2`); this PR's wiring has no such observable effect until PR3. Add an explicit wiring-proof test instead, modeled exactly on the existing `tests/unit/cli/daemon/test_daemon_idempotency_store_wired.py` pattern (spy the constructor via `monkeypatch`, boot the real daemon through `CliRunner().invoke(daemon_app, ["start"])`, assert the captured kwarg):

```python
"""#410 PR2: the daemon boot graph wires a real PostgresReplayJournal into
Orchestrator, even though nothing consumes it yet (dark).

Modelled exactly on tests/unit/cli/daemon/test_daemon_idempotency_store_wired.py
(same fixtures, same CliRunner-boot-the-real-daemon shape) — that file proves
the analogous PostgresInboundIdempotencyStore wiring; this proves PR1's
PostgresTurnSideEffectLedger and PR2's PostgresReplayJournal wiring alongside it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from alfred.cli.daemon import daemon_app
from alfred.memory.replay_journal import PostgresReplayJournal
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger
from alfred.orchestrator.core import Orchestrator
from typer.testing import CliRunner

from .conftest import FakeAuditWriter
from .test_daemon_comms_spawn import _ENABLED_ADAPTER, _patch_comms_seams, quarantine_registry

__all__ = ["quarantine_registry"]


def test_enabled_adapter_wires_replay_journal_and_side_effect_ledger(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: Any,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    del quarantine_registry, patch_quarantine_child_spawn
    captured: list[Any] = []
    original_init = Orchestrator.__init__

    def _spy_init(self: Any, **kwargs: Any) -> None:
        captured.append((kwargs.get("side_effect_ledger"), kwargs.get("replay_journal")))
        original_init(self, **kwargs)

    monkeypatch.setattr(Orchestrator, "__init__", _spy_init)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    assert len(captured) == 1
    side_effect_ledger, replay_journal = captured[0]
    assert isinstance(side_effect_ledger, PostgresTurnSideEffectLedger)
    assert isinstance(replay_journal, PostgresReplayJournal)
```

(Verify `boot_success_env`/`patch_quarantine_child_spawn`/`quarantine_registry` fixture names and the exact `_patch_comms_seams`/`_ENABLED_ADAPTER` import path against the CURRENT `test_daemon_idempotency_store_wired.py` and `test_daemon_comms_spawn.py` before writing this — they are read, not invented, and any drift in this repo's fixture names since this plan was written should be resolved by matching the real files, not this snippet.)

Place this new file at `tests/unit/cli/daemon/test_daemon_replay_journal_wired.py`.

- [ ] **Step 5b: Run the wiring-proof test**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_replay_journal_wired.py -v`
Expected: PASS — this is the ONLY step in this task that would actually fail if the `replay_journal=`/`side_effect_ledger=` kwargs were silently dropped from the live `_comms_boot.py` call.

- [ ] **Step 6: Type-check**

Run: `uv run mypy src/alfred/cli/_bootstrap.py src/alfred/cli/daemon/_comms_boot.py && uv run pyright src/alfred/cli/_bootstrap.py src/alfred/cli/daemon/_comms_boot.py`
Expected: no errors

- [ ] **Step 7: Run the full existing boot-graph integration suite (confirms the dark wiring doesn't perturb anything live)**

Run: `uv run pytest tests/integration/comms_mcp/test_real_turn_inbound_boundary.py -v`
Expected: PASS, unmodified (every assertion from PR1's Task 6/7 edits still holds — this PR adds a construction-time-only change, no behaviour visible to these tests).

- [ ] **Step 8: Commit**

```bash
git add src/alfred/cli/_bootstrap.py src/alfred/cli/daemon/_comms_boot.py tests/unit/cli/test_bootstrap_build_orchestrator.py tests/unit/cli/daemon/test_daemon_replay_journal_wired.py
git commit -m "feat(cli): wire PostgresReplayJournal into the live comms boot graph, dark (#410 PR2)"
```

---

### Task 6: ADR-0062 — the deterministic-replay journal contract

**Files:**

- Create: `docs/adr/0062-deterministic-tool-call-replay-journal.md`

- [ ] **Step 1: Read ADR-0049's structure to match this repo's ADR conventions**

Run: `sed -n '1,60p' docs/adr/0049-real-privileged-turn-comms-inbound.md` — match its header block (Status/Date/Slice/Relates-to/Supersedes), Context/Decision/Consequences section shape.

- [ ] **Step 2: Write the ADR**

```markdown
# ADR-0062 — Deterministic tool-call replay journal

- **Status**: Accepted (on #410 PR2 merge)
- **Date**: 2026-08-07
- **Slice**: 4 — #410 PR2 (`docs/superpowers/plans/2026-08-07-issue-410-pr2-replay-journal.md`)
- **Relates to**: [ADR-0039](0039-gateway-adapter-inbound-bridge.md) (the
  forwarded dispatched-edge replay this journal makes safe for tool-bearing
  turns), [ADR-0049](0049-real-privileged-turn-comms-inbound.md) (the #338
  cutover this journal was deferred from — see its Context), the Spec C
  egress-idempotency ledger (`src/alfred/egress/egress_id.py`,
  `src/alfred/memory/egress_idempotency.py`) this journal makes converge
  rather than raise, issue #410 (epic), issue #338 (predecessor)

## Context

#338 PR2 (ADR-0049) shipped a real privileged turn on the comms inbound path
with egress tools explicitly DEFERRED — the Act loop advertises an empty
tool registry, so it runs exactly one completion and writes no egress-ledger
rows. #410 turns tools on. Doing so reintroduces a hazard #338's own design
spec named but deliberately left out of scope: on the forwarded dispatched-
edge path (`commit_at_dispatch_edge=True`, ADR-0039 item 4), a crash between
"the planner decided to call these tools" and `commit_once` leaves the frame
uncommitted, so it replays. Before this journal, a resumed turn asks the
planner AGAIN — a fresh, potentially non-deterministic completion.

Verifying the existing Spec C egress-idempotency ledger against that
scenario (rather than assuming it) found it already stronger than the
original issue text implied: `compute_egress_id` is positional
(`(adapter_id, inbound_id, session_id, call_index)`), but
`compute_egress_body_hash` additionally binds the full request identity, and
`egress_idempotency.py:220` raises `EgressIdIntegrityError` on any
divergence. So a resumed turn whose planner diverges does not silently
misattribute a stale result to a new call — it fails loud, replaying until
the poison ceiling (`ForwardedDispatchAttemptStore`). That is fail-safe but
not fail-useful: a resumed tool-bearing turn could never complete if the
planner was even slightly non-deterministic between attempts.

## Decision

A new durable `tool_call_journal` table records the committed ordered
tool-dispatch decision — `(adapter_id, inbound_id, call_index) ->
(iteration, ToolCall)` — written immediately BEFORE each `dispatch_tool`
call. Composite-keyed, not `(inbound_id, call_index)` alone (a design
correction found during the `/review-plan` fleet pass): `inbound_id` is a
free-form, per-adapter-minted opaque string, so a two-column key would let
two different adapters' turns collide and splice one turn's decided tool
calls into a different turn's reconstructed transcript. On a forwarded-path
resume, the Act loop reads any journalled entries for the turn's
`(adapter_id, inbound_id)` and **fast-forwards** through them: each is
replayed via the SAME `dispatch_tool` call the normal path uses (the
existing Spec C ledger's memoize-and-replay handles the actual dedup for
`ExternalToolSpec`/web.fetch tools — this journal adds no egress-level
dedup logic of its own), reconstructing the ephemeral tool transcript
grouped by the journalled `iteration`. The loop then resumes **unmodified**,
from `max_journalled_iteration + 1` onward, with `tool_choice="auto"` — the
planner remains free to make further tool calls.

A single forced `tool_choice="none"` wrap-up completion was considered and
rejected: if the original attempt crashed BEFORE the planner decided to stop
calling tools, forcing a premature text-only answer on resume would
truncate legitimate further tool use the resumed turn should still be free
to take.

`temperature=0` threads to both provider adapters for tool-bearing
completions as defence-in-depth ON TOP OF the journal — a resumed turn
should ideally re-derive an identical plan even before the fast-forward
above ever consults history. This is not a substitute for the journal: it
only makes convergence more LIKELY, never guaranteed.

**Explicitly out of scope: dedup protection for `InternalToolSpec` tools.**
Only `ExternalToolSpec` (web.fetch) is wired to the Spec C
`compute_egress_id`/memoize-and-replay ledger. A replayed `InternalToolSpec`
call (`clock.now`, PR3's only live tool) re-dispatches for real on every
fast-forward, with no dedup at all — accepted because `clock.now` is
side-effect-free by construction; a future `InternalToolSpec` with real side
effects would need this addressed first.

**No longer in scope (retired by a PR1 design correction, found during the
same `/review-plan` pass): budget-charge iteration-awareness.** PR1's
`TurnSideEffectLedger` was originally going to gate the budget charge with a
single boolean per turn, correct only while tools were off — and PR1's own
construction-time guard against combining that gate with a live
`tool_registry` was found, during this review, to make the daemon fail to
boot the moment PR3 wired one in. The fix: PR1 leaves the budget charge
permanently ungated instead (see ADR-0049's amendment). There is therefore
no PR3 obligation regarding budget-charge granularity for this journal to
name.

## Consequences

- Positive: a resumed tool-bearing turn converges instead of poison-looping
  or losing accounting for already-real egress side effects.
- Positive: no new egress-level dedup mechanism for `ExternalToolSpec` tools
  — this journal is a pure "what to replay," the existing ledger remains the
  sole authority on "did this already happen."
- Negative: `tool_call_journal` grows without a retention/pruning story in
  this PR — a committed frame never resumes again, so pruning on
  `commit_once` is the natural follow-up, tracked but not built here.
- Negative (accepted, tracked): `InternalToolSpec` tools have no dedup
  protection on replay at all (see above) — safe only by the
  side-effect-free convention, not an enforced guarantee.

## Alternatives considered

- **Store tool RESULTS in the journal, not just the decision.** Rejected:
  result dedup is already the egress ledger's job (memoize-and-replay); a
  second copy of results here would be redundant state that could drift
  from the ledger's own.
- **Key the journal entry on `compute_request_descriptor`.** Rejected: that
  function is internal to web.fetch's own extraction path
  (`method`/`url`/`schema_id`) and has no meaning for `clock.now` or any
  future non-HTTP tool. `ToolCall` (id/name/arguments) is the identity
  `dispatch_tool` already receives generically, for any tool.
- **Key the journal on `(inbound_id, call_index)` alone.** Rejected during
  `/review-plan`: reintroduces a cross-adapter collision class the sibling
  `inbound_idempotency`/`forwarded_dispatch_attempts` ledgers already guard
  against for the identical reason.
```

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0062-deterministic-tool-call-replay-journal.md
git commit -m "docs(adr): ADR-0062 — deterministic tool-call replay journal (#410 PR2)"
```

---

## Definition of Done

- [ ] All 6 tasks' tests pass: `uv run pytest tests/unit/memory/test_replay_journal_store.py tests/integration/test_migration_0026_tool_call_journal.py tests/integration/test_replay_journal_postgres.py tests/unit/orchestrator/test_act_loop.py tests/unit/orchestrator/test_core.py tests/unit/cli/test_bootstrap_build_orchestrator.py tests/unit/cli/daemon/test_daemon_replay_journal_wired.py tests/integration/comms_mcp/test_real_turn_inbound_boundary.py -v`
- [ ] `make check` passes clean.
- [ ] `uv run pytest tests/adversarial -q` still passes.
- [ ] `/review-plan` fleet run on this plan (and PR1's) before implementation; full `/review-pr` fleet + CodeRabbit `full review` on the resulting PR before merge.
