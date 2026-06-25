# G6-7-5 — Poison ceiling / replay-bounding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound the G6-7-4 dispatched-edge replay so a deterministically-failing forwarded inbound is dead-lettered (not replayed forever, not re-charging `quarantined_extract` forever) across the *entire* post-extract region (t3-promotion-emit, ingest, dispatch), and make the forwarded-drop reasons legible to an operator — the precondition for the gateway Discord leg to graduate from TEST-ONLY (live graduation itself stays G6-7-7/-8).

**Architecture:** A new **durable** Postgres-backed per-`(adapter_id, inbound_id)` dispatch-attempt ledger (must survive core restart — replay happens *across* reconnects, so an in-memory counter would reset exactly when it matters). `process_inbound_message`'s forwarded (`commit_at_dispatch_edge=True`) path gains, gated so the direct path stays byte-for-byte: (a) a cheap attempt-count **read placed AFTER the `pre_resolution_limiter` DoS gate** — at/over ceiling **N** ⇒ a terminal `gateway.adapter.inbound.poisoned` signed dead-letter row + ack-to-drain, **before** `quarantined_extract` (the ceiling-before-extract check is the cost bound; `quarantined_extract` is not wired into `BudgetGuard`, so the ceiling is the only bound on its re-charge); (b) an **increment on entry to the post-extract region** (immediately after `quarantined_extract` returns) so the count covers every un-observed/non-draining replay path (promotion-emit, ingest, dispatch), not just dispatch. Deliberate sheds (budget-cap / burst-drop / unbound) never reach the increment (they drain single-shot before extract), so they can never poison. Plus a CLI triage pass: `alfred audit log` renders the drop reason and gains a `--reason` filter covering all reasons incl. `poisoned` (encoded as `result`/`event`) + `receive_fault` (encoded as `subject.reason`).

**Tech Stack:** Python 3.12, asyncio, SQLAlchemy 2.0 (raw `sa.text` atomic UPSERT mirroring `PostgresInboundIdempotencyStore`), Alembic (migration 0020 mirroring 0019), Pydantic v2, pytest + testcontainers (real-Postgres roundtrip), typer (CLI), structlog, i18n `t()`.

---

## Charter mapping (architect-mandated; from the G6-7-4 PR #315 memory entry)

| Charter item | Where it lands |
|---|---|
| 1. Item-4b poison ceiling: per-`(adapter_id, inbound_id)` attempt counter + `gateway.adapter.inbound.poisoned` dead-letter + ack-to-drain on >= N | Tasks 1–7 |
| 2. Replay-cost bounding tied to the counter (close PERF-309-1) | **Satisfied by item 1** — the ceiling read runs *before* `quarantined_extract`, so the (N+1)th replay short-circuits before paying extract cost (the bound is **N extracts, poison on the (N+1)th attempt** — stated honestly). A `BudgetGuard` mechanism *does* exist (`src/alfred/budget/guard.py`, `check_and_charge`) but it is wired into the act-loop provider calls (`orchestrator/core.py:787`), **NOT** into `quarantined_extract` (core.py:301-342 records latency only). So there is nothing to "charge" extract against today; the ceiling is the bound. (Today the quarantined child is a deterministic-echo loop with no provider cost — real-LLM is #230-blocked — so extract has nothing to meter until #230; wiring extract→BudgetGuard is the explicit alternative being declined.) **(resolved fork PR-1)** |
| 3. Forwarded-drop TRIAGE legibility (devex HIGH-2) | Task 8 — render the drop reason + `--reason` filter at the CLI render/filter layer (fixture-tested). `_query_audit_log` is a dead stub (raises `AuditBackendUnavailable`; backend SQL deferred to unbuilt PR-S3-7) and `audit log` renders no `subject` today, so operator value lands when PR-S3-7 wires the backend; G6-7-5 ships the triage render/filter logic ready + tested. **(resolved fork PR-2)** |
| 4. Keep deliberate sheds distinct from poison | Naturally satisfied — the ledger is touched ONLY at/after the post-extract region; sheds (budget/burst/unbound) drain single-shot *before* extract and never read or write the ledger. Task 9 adds a regression that asserts **zero ledger mutation of any kind** on every shed arm. |
| 5. Does the ceiling also cover receive_fault pre-dispatch replay? | **No for the receiver's terminal drops** (unknown_adapter/mismatch/malformed/receive_fault all drain single-shot → already bounded). **But the ceiling DOES cover the whole post-extract region** (promotion-emit + ingest + dispatch), which are the un-observed/non-draining replay paths — not "dispatch only". Documented + tested (Tasks 5, 9). **(resolved fork PR-3, scope widened per security M-3/C-2)** |

## Resolved plan-review forks (architect + security, 2026-06-22)

- **PR-1 (item 2):** ceiling-is-the-bound is the correct discharge; **but the premise "no cost-budget mechanism" was false** — `BudgetGuard` exists; restate as "`quarantined_extract` is not budget-charged" (folded into the table above + Task 10).
- **PR-2 (item 3 scope):** ship render+filter now over the stub, fixture-tested; do NOT pull PR-S3-7 in (separate trust surface). Rewrite (not append to) the existing comms.md deferred-note.
- **PR-3 (item 5 scope):** ceiling covers the whole post-extract region (promotion-emit/ingest/dispatch); receiver terminal drops are single-shot, not ceilinged.
- **PR-4 (placement):** ceiling logic in `process_inbound_message`, gated under `commit_at_dispatch_edge`, `attempt_store` an optional collaborator threaded like `idempotency_store`. **Do NOT fold `attempt_count` into `COMMS_INBOUND_DISPATCH_FAILED_FIELDS`** (architect H1) — keep that row content-identical to the replay row; the count lives only on the poisoned row; triage of the progression is via the shared `trace_id` (security M-2).
- **PR-5 (N):** `N = 5`. The real bound is **5 extracts, poison on the 6th attempt** — assert the exact count.
- **PR-6 (migration):** one additive migration 0020 (create table + extend `ck_audit_log_result` with `poisoned`); base tuple is `_BASE_RESULTS + ("dispatch_failed",)` copied verbatim from 0019; no FK on the new table; downgrade drops the table then reverts the CHECK; the downgrade DELETE of `poisoned` audit rows is a known append-only exception (flag in PR description, mirror 0019).
- **PR-7 (ledger lifecycle):** no sweeper this slice (parallel to the never-swept `inbound_idempotency`); track a TTL/sweeper follow-up note in the ADR amendment.
- **Increment ordering:** **increment-before-audit** (increment is the durable bound; it must never under-count, else a flaky audit backend could let a poison frame slip the ceiling forever). The increment's own `SQLAlchemyError` PROPAGATES as a leg-replay (NOT escalate-restart), distinct from the audit-write marker.

## Security must-haps (carry into every task; mirror G6-7-4)

- **Read placement (security C-1, CRITICAL):** the ceiling READ must run AFTER `pre_resolution_limiter.check_and_record` passes (`inbound.py:659-675`), so a flood of attacker-chosen distinct `inbound_id`s is DoS-gated before it can grow the ledger. NEVER before the limiter.
- **Whole-region bound (security C-2, CRITICAL):** the increment must bound promotion-emit (`inbound.py:762`) + ingest (`:771`) + dispatch (`:782`), not just dispatch — all three are un-observed/non-draining replay paths. Increment on entry to that region (immediately after `quarantined_extract` returns) so any downstream failure is counted. Correct the `:758-761` comment which claims "bounded by G6-7-5" (make it true).
- The `poisoned` row is **content-free**: ONLY closed-vocab `adapter_id`, the **peppered hash** of `inbound_id` (never raw — sec-010), the bounded `attempt_count`, `observed_at`. NO raw T3 body, NO `str(exc)`. Canary test asserts neither a body secret NOR the raw `inbound_id` appears in any field or structlog record.
- The poison emit is a **signed audit write** wrapped in `ForwardedInboundAuditWriteError` AT THE WRITE SITE: a write failure PROPAGATES (escalate-restart) and the frame is **left un-drained** (audit-before-drain). Drain (`observe`) only AFTER the row wrote.
- The attempt-store reads/writes raise `SQLAlchemyError` loud (never swallowed into a count); a DB error there PROPAGATES → leg replays (NOT escalate-restart).
- All ceiling logic gated under `commit_at_dispatch_edge` so the DIRECT TUI/daemon path is byte-for-byte unchanged (ship a direct-path-never-touches-the-ledger test).
- Composite-key isolation is load-bearing ONLY because upstream K4 admission + the spawn-binding-minted `adapter_id` guarantee `notification.adapter_id` is closed-vocab/un-forgeable (ADR-0039 item 4c, one-path-per-adapter_id). Assert in the store docstring + a cross-adapter isolation test.

## File Structure

- **Create** `src/alfred/memory/forwarded_dispatch_attempts.py` — `ForwardedDispatchAttemptStore` Protocol + `PostgresForwardedDispatchAttemptStore` (atomic UPSERT `increment` → new count; non-mutating `attempt_count` read). Mirrors `inbound_idempotency.py`.
- **Create** `src/alfred/memory/migrations/versions/0020_forwarded_dispatch_attempts_and_poisoned_result.py` — additive: create the ledger table + extend `ck_audit_log_result` with `poisoned`. Mirrors 0018 (table) + 0019 (CHECK).
- **Modify** `src/alfred/memory/models.py` — add `ForwardedDispatchAttempt` ORM model; add `"poisoned"` to `AuditEntry`'s `ck_audit_log_result` CHECK (models.py:173).
- **Modify** `src/alfred/audit/audit_row_schemas.py` — add `COMMS_INBOUND_POISONED_FIELDS` + roster entry. (Do NOT change `COMMS_INBOUND_DISPATCH_FAILED_FIELDS`.)
- **Modify** `src/alfred/comms_mcp/inbound.py` — `_DispatchAttemptStoreLike` Protocol + `_FORWARDED_DISPATCH_ATTEMPT_CEILING`; `_emit_poisoned`; ceiling read (after the limiter) + post-extract-entry increment; new params `attempt_store` + `dispatch_attempt_ceiling`. Dispatch except arm stays byte-identical to G6-7-4.
- **Modify** `src/alfred/comms_mcp/forwarded_inbound_receiver.py` — thread `attempt_store` + ceiling through the `self._dispatch(...)` call (new required `__init__` field). Update every existing receiver constructor in the test suite in the same commit.
- **Modify** `src/alfred/cli/daemon/_commands.py` — build the `PostgresForwardedDispatchAttemptStore` over the SAME DSN-cached boot session scope the idempotency store uses (no second engine) + inject into the receiver + add to `_CommsBootGraph`; verify it is NOT reaped in `aclose()` (mirrors the idempotency-store posture).
- **Modify** `src/alfred/cli/audit.py` — render the drop reason; add a `--reason` filter to `audit log` that matches BOTH `subject.reason` (receiver drops) AND poisoned (via `result`/`event`).
- **Modify** `locale/en/LC_MESSAGES/alfred.po` (+ compile `.mo`) — `cli.audit.log.reason_help`.
- **Create** tests: unit (model, store-with-mocked-session, ceiling logic, receiver, CLI render/filter) + integration (migration 0020 roundtrip, table, real-Postgres store) + adversarial (poison e2e, distinct-id-flood-gated, shed-no-ledger-touch, receive_fault-not-ceilinged, poison-then-receive_fault interleave, cross-adapter isolation, concurrent-replay-at-ceiling, canary incl. raw inbound_id).
- **Modify** `docs/adr/0039-gateway-adapter-inbound-bridge.md` + `docs/subsystems/comms.md`.

---

### Task 1: `ForwardedDispatchAttempt` ORM model + `poisoned` CHECK value

**Files:**

- Modify: `src/alfred/memory/models.py` (add model; add `"poisoned"` to `ck_audit_log_result` at models.py:173)
- Test: `tests/unit/memory/test_forwarded_dispatch_attempt_model.py`

- [ ] **Step 1: Write the failing test:**

```python
from alfred.memory.models import AuditEntry, ForwardedDispatchAttempt


def test_forwarded_dispatch_attempt_columns() -> None:
    cols = {c.name for c in ForwardedDispatchAttempt.__table__.columns}
    assert {"adapter_id", "inbound_id", "attempt_count", "first_failed_at", "last_failed_at"} <= cols
    pk = {c.name for c in ForwardedDispatchAttempt.__table__.primary_key.columns}
    assert pk == {"adapter_id", "inbound_id"}


def test_poisoned_is_in_audit_result_check() -> None:
    check = next(
        c for c in AuditEntry.__table__.constraints if getattr(c, "name", "") == "ck_audit_log_result"
    )
    assert "'poisoned'" in str(check.sqltext)
```

- [ ] **Step 2: Run to verify it fails** — `uv run pytest tests/unit/memory/test_forwarded_dispatch_attempt_model.py -v` → FAIL (`ImportError`).

- [ ] **Step 3: Implement** — add the model (mirror `InboundIdempotency` at models.py:687) + the CHECK value (`"poisoned"` alongside `'dispatch_failed'` at models.py:173):

```python
class ForwardedDispatchAttempt(Base):
    """Durable per-(adapter_id, inbound_id) dispatch-attempt ledger (Spec B G6-7-5, #309).

    ADR-0039 item 4b. The forwarded dispatched-edge path leaves a failed frame NOT
    committed/NOT observed so the leg replays it; this ledger BOUNDS that replay. It
    is DURABLE (Postgres) because replay happens across core restarts — an in-memory
    counter would reset exactly when the bound is needed. Composite PK isolates each
    adapter's free-form inbound_id namespace (mirrors InboundIdempotency); that
    isolation is load-bearing ONLY because upstream K4 admission mints adapter_id from
    the spawn binding (closed-vocab, un-forgeable — ADR-0039 item 4c).
    """

    __tablename__ = "forwarded_dispatch_attempts"

    adapter_id: Mapped[str] = mapped_column(sa.Text, primary_key=True)
    inbound_id: Mapped[str] = mapped_column(sa.Text, primary_key=True)
    attempt_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default=sa.text("0"))
    first_failed_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    last_failed_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
```

- [ ] **Step 4: Run to verify it passes** — PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/models.py tests/unit/memory/test_forwarded_dispatch_attempt_model.py
git commit -m "feat(memory): ForwardedDispatchAttempt ORM model + poisoned audit result value (Spec B G6-7-5, #309)"
```

---

### Task 2: Migration 0020 — ledger table + `poisoned` CHECK value + roundtrip tests

**Files:**

- Create: `src/alfred/memory/migrations/versions/0020_forwarded_dispatch_attempts_and_poisoned_result.py`
- Test: `tests/integration/test_migration_0020_forwarded_dispatch_attempts.py` (mirror `test_migration_0018_inbound_idempotency.py` for the table + `test_migration_0019_dispatch_failed_result.py` for the CHECK)

- [ ] **Step 1: Write the failing integration test** (real Postgres via the `postgres_url`/`alembic_cfg` fixtures from the 0018/0019 tests): upgrade to head; assert `forwarded_dispatch_attempts` exists with composite PK `{adapter_id, inbound_id}`; assert an `audit_log` INSERT with `result='poisoned'` succeeds; assert `result='not_a_real_value'` raises `CheckViolation`. Add the drift guard `_POISONED_RESULTS = ("poisoned",)`.

- [ ] **Step 2: Run to verify it fails** (Docker) → FAIL.

- [ ] **Step 3: Implement migration 0020** — `down_revision="0019"`. `upgrade()`: `op.create_table("forwarded_dispatch_attempts", ...)` (composite PK + the Task-1 columns; **no FK**); then drop+recreate `ck_audit_log_result` with `_BASE_RESULTS + ("dispatch_failed",) + ("poisoned",)` where `_BASE_RESULTS` is copied verbatim from 0019's `_BASE_RESULTS` (source of truth = the ORM model). `downgrade()`: loud-destruction `DELETE FROM audit_log WHERE result IN ('poisoned')` (RAISE NOTICE the count, mirror 0019:123-144) → restore the 0019 CHECK domain → `op.drop_table("forwarded_dispatch_attempts")`.

- [ ] **Step 4: Run to verify it passes** (Docker) → PASS; run the generic migration upgrade/downgrade roundtrip if present.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/migrations/versions/0020_forwarded_dispatch_attempts_and_poisoned_result.py tests/integration/test_migration_0020_forwarded_dispatch_attempts.py
git commit -m "feat(memory): migration 0020 forwarded_dispatch_attempts table + poisoned result (Spec B G6-7-5, #309)"
```

---

### Task 3: `ForwardedDispatchAttemptStore` (Protocol + Postgres impl)

**Files:**

- Create: `src/alfred/memory/forwarded_dispatch_attempts.py`
- Test: `tests/unit/memory/test_forwarded_dispatch_attempt_store.py` (mocked `session_scope`, mirror `test_inbound_idempotency_store.py`) + `tests/integration/test_forwarded_dispatch_attempts_postgres.py` (real atomic UPSERT, mirror `test_inbound_idempotency_postgres.py`)

- [ ] **Step 1: Write the failing unit tests** — with a mocked `session_scope`/`session.execute`: `increment` returns `result.scalar_one()`; `attempt_count` returns `0` when `scalar_one_or_none()` is `None`, else the value; a raised `SQLAlchemyError` from `execute` propagates (fail-loud, not swallowed).

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement** (mirror `PostgresInboundIdempotencyStore`):

```python
_INCREMENT_SQL = sa.text(
    "INSERT INTO forwarded_dispatch_attempts (adapter_id, inbound_id, attempt_count) "
    "VALUES (:adapter_id, :inbound_id, 1) "
    "ON CONFLICT (adapter_id, inbound_id) DO UPDATE SET "
    "attempt_count = forwarded_dispatch_attempts.attempt_count + 1, last_failed_at = now() "
    "RETURNING attempt_count"
)
_ATTEMPT_COUNT_SQL = sa.text(
    "SELECT attempt_count FROM forwarded_dispatch_attempts "
    "WHERE adapter_id = :adapter_id AND inbound_id = :inbound_id"
)


@runtime_checkable
class ForwardedDispatchAttemptStore(Protocol):
    async def increment(self, *, adapter_id: str, inbound_id: str) -> int: ...
    async def attempt_count(self, *, adapter_id: str, inbound_id: str) -> int: ...


class PostgresForwardedDispatchAttemptStore:
    def __init__(self, *, session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]]) -> None:
        self._session_scope = session_scope

    async def increment(self, *, adapter_id: str, inbound_id: str) -> int:
        async with self._session_scope() as session:
            result = await session.execute(
                _INCREMENT_SQL, {"adapter_id": adapter_id, "inbound_id": inbound_id}
            )
            return int(result.scalar_one())

    async def attempt_count(self, *, adapter_id: str, inbound_id: str) -> int:
        async with self._session_scope() as session:
            result = await session.execute(
                _ATTEMPT_COUNT_SQL, {"adapter_id": adapter_id, "inbound_id": inbound_id}
            )
            value = result.scalar_one_or_none()
            return int(value) if value is not None else 0
```

Module docstring: durable-across-restart rationale; fail-loud `SQLAlchemyError`; composite-key isolation depends on upstream K4 admission (un-forgeable adapter_id). No logging (pure primitive).

- [ ] **Step 4: Run to verify it passes** — unit PASS; integration (Docker) PASS: increment absent→1→2; concurrent increments on one key serialise to a monotone count via the atomic UPSERT; distinct `(adapter_id,inbound_id)` namespaces isolated (a "discord" key never moves a "tui" key).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/forwarded_dispatch_attempts.py tests/unit/memory/test_forwarded_dispatch_attempt_store.py tests/integration/test_forwarded_dispatch_attempts_postgres.py
git commit -m "feat(memory): PostgresForwardedDispatchAttemptStore atomic attempt ledger (Spec B G6-7-5, #309)"
```

---

### Task 4: `COMMS_INBOUND_POISONED_FIELDS` audit field-set

**Files:**

- Modify: `src/alfred/audit/audit_row_schemas.py` (add the field-set after `COMMS_INBOUND_DISPATCH_FAILED_FIELDS`; add to `AUDIT_FIELDSET_ROSTER`; add to `__all__`). **Do NOT modify `COMMS_INBOUND_DISPATCH_FAILED_FIELDS`.**
- Test: `tests/unit/audit/test_slice_4_audit_row_fields.py` (the roster AST walk) + an explicit field assertion.

- [ ] **Step 1: Write the failing test:**

```python
def test_poisoned_fields() -> None:
    from alfred.audit.audit_row_schemas import COMMS_INBOUND_POISONED_FIELDS
    assert COMMS_INBOUND_POISONED_FIELDS == frozenset({"adapter_id", "inbound_id_hash", "attempt_count", "observed_at"})
```

- [ ] **Step 2: Run to verify it fails** → FAIL (constant absent / roster walk red).

- [ ] **Step 3: Implement:**

```python
# Emitted by process_inbound_message on the FORWARDED dispatched edge (Spec B
# G6-7-5 / ADR-0039 item 4b) when (adapter_id, inbound_id) has failed the post-extract
# region >= the ceiling N times. Terminal DEAD-LETTER: the frame is ack-to-drained and
# never re-dispatched. Content-free: closed-vocab adapter_id, peppered inbound_id hash
# (sec-010), the bounded attempt_count (a small int, non-secret), observed_at.
# result="poisoned". subject is JSONB → adding attempt_count needs no migration.
COMMS_INBOUND_POISONED_FIELDS: Final[frozenset[str]] = frozenset(
    {"adapter_id", "inbound_id_hash", "attempt_count", "observed_at"}
)
```

Add `"COMMS_INBOUND_POISONED_FIELDS"` to `AUDIT_FIELDSET_ROSTER` + `__all__`.

- [ ] **Step 4: Run to verify it passes** — `uv run pytest tests/unit/audit/test_slice_4_audit_row_fields.py -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/audit/audit_row_schemas.py tests/unit/audit/test_slice_4_audit_row_fields.py
git commit -m "feat(audit): COMMS_INBOUND_POISONED_FIELDS dead-letter field-set (Spec B G6-7-5, #309)"
```

---

### Task 5: Poison ceiling in `process_inbound_message` (the keystone)

**Files:**

- Modify: `src/alfred/comms_mcp/inbound.py`
- Test: `tests/unit/comms/test_inbound_poison_ceiling.py` (fakes for store/audit/tracker/orchestrator)

**Insertion points (verified line numbers on origin/main @ 6c599625):**

1. Ceiling **read** — AFTER `pre_resolution_limiter.check_and_record` passes (after the `return` block at `inbound.py:675`), BEFORE the resolver call at `:678`.
2. **Increment** — immediately AFTER `quarantined_extract` returns at `:747-751` (so the count covers promotion-emit/ingest/dispatch).
3. The dispatch except arm at `:782-815` stays byte-identical to G6-7-4 (it does NOT increment — the on-entry increment already counted this attempt).

- [ ] **Step 1: Write the failing tests** (drive `process_inbound_message` with `commit_at_dispatch_edge=True`, a fake `attempt_store`, `idempotency_store.has_committed=False`, a resolver returning a bound user, a passing burst limiter, a fake `ack_tracker`):

```python
# A) EXACT cost bound (closes C1-arch off-by-one): with N=5 and a dispatch that always
#    raises, drive 6 sequential calls (simulating 6 leg replays) sharing one fake
#    attempt_store. Assert quarantined_extract was awaited EXACTLY 5 times, the 6th call
#    emits a poisoned row + observe(wire_seq) + returns (no extract, no raise).
async def test_exact_extract_count_then_poison(...) -> None: ...

# B) Under the ceiling: a post-extract failure (dispatch raises) increments the ledger
#    once and re-raises; ack_tracker.observe NOT called; the dispatch_failed row is the
#    UNCHANGED content (no attempt_count field).
async def test_post_extract_failure_increments_and_reraises(...) -> None: ...

# C) Whole-region bound (C2-sec): an INGEST failure (orchestrator.ingest raises) and a
#    PROMOTION-EMIT failure (_emit_t3_promotion's audit_writer raises) each increment the
#    ledger (the on-entry increment ran before them) and propagate → leg replays → next
#    replay at ceiling poisons. Assert increment was called for an ingest failure too.
async def test_ingest_failure_is_ceilinged(...) -> None: ...

# D) Poison emit audit-write failure PROPAGATES as ForwardedInboundAuditWriteError and
#    the frame is NOT drained (observe not called).
async def test_poison_audit_write_failure_escalates_and_does_not_drain(...) -> None: ...

# E) attempt_count DB error on the READ propagates (fail-loud), not poisoned, not drained.
async def test_attempt_count_db_error_propagates(...) -> None: ...

# E') increment DB error in the post-extract region propagates as replay, writes no
#     dispatch_failed row, does not drain.
async def test_increment_db_error_propagates_as_replay(...) -> None: ...

# F) Read placement (C1-sec): a frame the pre_resolution_limiter SHEDS (budget-capped)
#    never reads OR writes the ledger (attempt_count + increment both un-called); it drains.
async def test_shed_frame_never_touches_ledger(...) -> None: ...

# G) DIRECT path unchanged: commit_at_dispatch_edge=False + attempt_store set →
#    NEITHER attempt_count NOR increment ever called; byte-for-byte prior behaviour.
async def test_direct_path_never_touches_attempt_store(...) -> None: ...

# H) None attempt_store on the forwarded path → ceiling disabled, falls through to the
#    prior G6-7-4 dispatch-failure behaviour (re-raise, no poison, no ledger).
async def test_none_attempt_store_disables_ceiling(...) -> None: ...

# I) Poison row inbound_id is a real PEPPERED hash (the set_broker → hash_inbound_id path
#    inside the poison branch runs in isolation with no prior set_broker).
async def test_poison_row_inbound_id_is_hashed(...) -> None: ...
```

- [ ] **Step 2: Run to verify they fail** → FAIL.

- [ ] **Step 3: Implement.**

Protocol + ceiling constant (near the other `_*Like` protocols):

```python
_FORWARDED_DISPATCH_ATTEMPT_CEILING: Final[int] = 5  # ADR-0039 item 4b


@runtime_checkable
class _DispatchAttemptStoreLike(Protocol):
    async def increment(self, *, adapter_id: str, inbound_id: str) -> int: ...
    async def attempt_count(self, *, adapter_id: str, inbound_id: str) -> int: ...
```

`_emit_poisoned` (mirror `_emit_dispatch_failed`, content-free, `result="poisoned"`, carries `attempt_count`):

```python
async def _emit_poisoned(
    notification: InboundMessageNotification, *, attempt_count: int, audit_writer: _AuditWriterLike
) -> None:
    """Emit the content-free terminal poisoned dead-letter row (Spec B G6-7-5 / item 4b).

    Carries ONLY the closed-vocab adapter_id, the PEPPERED inbound_id hash (sec-010),
    the bounded attempt_count, and observed_at. Shares trace_id with this frame's
    dispatch_failed rows so triage can pivot from the dead-letter to its failure history.
    An audit-write failure PROPAGATES (the caller wraps it in ForwardedInboundAuditWriteError).
    """
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_INBOUND_POISONED_FIELDS,
        schema_name="COMMS_INBOUND_POISONED_FIELDS",
        event="comms.inbound.poisoned",
        actor_user_id=None,
        subject={
            "adapter_id": notification.adapter_id,
            "inbound_id_hash": audit_hash.hash_inbound_id(notification.inbound_id),
            "attempt_count": attempt_count,
            "observed_at": datetime.now(UTC).isoformat(),
        },
        trust_tier_of_trigger="T3",
        result="poisoned",
        cost_estimate_usd=0.0,
        trace_id=audit_hash.hash_inbound_id(notification.inbound_id),
    )
```

New params on `process_inbound_message`: `attempt_store: _DispatchAttemptStoreLike | None = None`, `dispatch_attempt_ceiling: int = _FORWARDED_DISPATCH_ATTEMPT_CEILING`.

**Ceiling read** — insert AFTER the `pre_resolution_limiter` block (after `inbound.py:675`), BEFORE the resolver at `:678`. (The `set_broker` at `:649` + `platform_user_id_hash` at `:650` already ran, so `hash_inbound_id` is safe here.):

```python
# ADR-0039 item 4b (Spec B G6-7-5): a never-committed forwarded frame that has already
# failed the post-extract region >= ceiling times is POISON — dead-letter it and drain,
# BEFORE quarantined_extract, so a deterministically-failing frame stops re-charging the
# extractor on every reconnect (closes PERF-309-1). Placed AFTER the pre-resolution DoS
# limiter (sec C-1) so a flood of distinct attacker-chosen inbound_ids is shed before it
# can grow the ledger. A DB error on the read PROPAGATES (fail-loud) → leg replays. The
# poison emit is audit-before-drain: a write failure raises ForwardedInboundAuditWriteError
# and leaves the frame UNDRAINED.
if commit_at_dispatch_edge and attempt_store is not None:
    attempts = await attempt_store.attempt_count(
        adapter_id=notification.adapter_id, inbound_id=notification.inbound_id
    )
    if attempts >= dispatch_attempt_ceiling:
        try:
            await _emit_poisoned(notification, attempt_count=attempts, audit_writer=audit_writer)
        except Exception as exc:
            raise ForwardedInboundAuditWriteError(
                "forwarded-inbound poisoned audit write failed"
            ) from exc
        _drain_forwarded_seq(ack_tracker, notification.wire_seq)
        _log.warning(
            "comms.inbound.poisoned",
            adapter_id=notification.adapter_id,
            attempt_count=attempts,
        )
        return
```

**Increment on entry to the post-extract region** — immediately after `quarantined_extract` returns at `:747-751`, before `_emit_t3_promotion`:

```python
extracted = await orchestrator.quarantined_extract(extract_body, ...)
# ADR-0039 item 4b (Spec B G6-7-5): count THIS attempt at entry to the post-extract
# region so EVERY un-observed/non-draining downstream failure (promotion-emit, ingest,
# dispatch) is ceilinged, not just dispatch (sec C-2). increment-before-audit: the
# durable bound must never under-count (a flaky audit backend must not let a poison frame
# slip the ceiling forever). The increment's own SQLAlchemyError PROPAGATES as a leg
# replay (NOT escalate-restart) — the count simply has not advanced yet. Gated under
# commit_at_dispatch_edge so the DIRECT path is byte-for-byte unchanged.
if commit_at_dispatch_edge and attempt_store is not None:
    await attempt_store.increment(
        adapter_id=notification.adapter_id, inbound_id=notification.inbound_id
    )

inbound_message_id = uuid.uuid4().hex
```

**Correct the stale comment** at `inbound.py:755-761` (the `_emit_t3_promotion` block): it currently says a promotion-emit failure replays "re-charging quarantined_extract, bounded by G6-7-5" — now TRUE; rewrite to: "the on-entry increment above counted this attempt, so a promotion-emit failure replay is bounded by the item-4b ceiling (poisoned after N attempts)."

The dispatch except arm (`:782-815`) is UNCHANGED (no increment there — the on-entry increment already counted this attempt; the dispatch_failed row stays content-identical to G6-7-4).

> **Note (happy-path write):** increment-on-entry writes one ledger row per forwarded inbound that reaches extract (success or fail), paralleling `inbound_idempotency`'s one-row-per-inbound. The read placement (post-limiter) + resolve/burst gating bound the write rate to the DoS budget. Accepted; a TTL/sweeper is a tracked follow-up (Task 10). The alternative (increment only on failure, wrapping promotion+ingest+dispatch in a forwarded-only try) avoids the happy-path write but duplicates promotion-emit/ingest across the if/else and broadens the dispatch_failed label to non-dispatch failures; rejected for higher churn in the 100%-gated trust module.

- [ ] **Step 4: Run to verify they pass** — `uv run pytest tests/unit/comms/test_inbound_poison_ceiling.py -v` → PASS; run `tests/unit/comms/test_inbound*.py` to confirm the direct path is byte-for-byte (no regressions).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/inbound.py tests/unit/comms/test_inbound_poison_ceiling.py
git commit -m "feat(comms): forwarded post-extract poison ceiling + dead-letter (Spec B G6-7-5, #309)"
```

---

### Task 6: Thread the attempt store through the receiver

**Files:**

- Modify: `src/alfred/comms_mcp/forwarded_inbound_receiver.py` (new required `__init__` field `attempt_store`; pass `attempt_store=` + `dispatch_attempt_ceiling=` into the `self._dispatch(...)` call at ~line 224-236)
- Test: `tests/unit/comms/test_forwarded_inbound_receiver.py` (extend) — **AND update every existing `GatewayForwardedInboundReceiver(...)` constructor in the test suite + boot-graph harness to pass `attempt_store=` in this same commit** (architect H3: the field is required, so the per-file 100% gate goes red on pre-existing tests otherwise).

- [ ] **Step 1: Write the failing test** — with a spy `dispatch`, assert `receive()` calls it with `attempt_store=<injected store>` and `commit_at_dispatch_edge=True`. Grep for all `GatewayForwardedInboundReceiver(` constructions: `git grep -n "GatewayForwardedInboundReceiver("`.

- [ ] **Step 2: Run to verify it fails** → FAIL.

- [ ] **Step 3: Implement** — add `attempt_store: _DispatchAttemptStoreLike` (import the Protocol from `alfred.comms_mcp.inbound`, keyword-only, required) to `__init__`; forward it + `dispatch_attempt_ceiling=` in the `self._dispatch(...)` kwargs. The admission region (K4/reparse/receive_fault) is UNTOUCHED — the ceiling is a dispatch concern, not admission (item 5: receive_fault is not ceilinged). Update all existing constructors in tests/boot-graph harness.

- [ ] **Step 4: Run to verify it passes** — `uv run pytest tests/unit/comms/test_forwarded_inbound_receiver.py -v` → PASS at 100% line+branch (per-file gate). Verify `forwarded_inbound_receiver.py` stays 100% (the new field + kwarg must be branch-covered).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/forwarded_inbound_receiver.py tests/
git commit -m "feat(comms): thread dispatch-attempt store through the forwarded-inbound receiver (Spec B G6-7-5, #309)"
```

---

### Task 7: Daemon wiring — build + inject the attempt store

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py` (build `PostgresForwardedDispatchAttemptStore` next to the idempotency store ~line 871, over the SAME `build_boot_session_scope(settings)` / DSN-cached engine — verify no second engine is opened; inject into the receiver ~line 919; add field to `_CommsBootGraph` if the graph holds it; verify it is NOT in `_CommsBootGraph.aclose()`'s reap set — mirrors the idempotency-store shared-engine posture)
- Test: `tests/unit/cli/daemon/test_comms_boot_graph*.py` (extend) — assert the receiver gets a non-None attempt_store; assert `aclose()` does NOT touch/dispose it (mirror the existing idempotency-store posture test).

- [ ] **Step 1: Write the failing tests** — (a) the built `forwarded_inbound_receiver` has a `PostgresForwardedDispatchAttemptStore`; (b) `_CommsBootGraph.aclose()` does not reap/dispose it (it shares the DSN-cached engine reaped at process exit by `dispose_all_engines()`).

- [ ] **Step 2: Run to verify they fail** → FAIL.

- [ ] **Step 3: Implement** — construct the store (mirror the idempotency-store comment about the shared DSN-cached engine / not-reaped-on-teardown) and pass `attempt_store=` into `GatewayForwardedInboundReceiver(...)`. Verify against `_commands.py` that `build_boot_session_scope` returns scopes over the cached engine (no new engine per store).

- [ ] **Step 4: Run to verify they pass** — `uv run pytest tests/unit/cli/daemon -k comms_boot -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/
git commit -m "feat(daemon): wire the forwarded dispatch-attempt store into the inbound receiver (Spec B G6-7-5, #309)"
```

---

### Task 8: `alfred audit log` triage — render the drop reason + `--reason` filter

**Files:**

- Modify: `src/alfred/cli/audit.py` (`audit_log`: add `--reason` option; render the drop reason in the row line; filter by reason — matching BOTH `subject.reason` for receiver drops AND `poisoned`/the `comms.inbound.*` discriminators which have NO `subject.reason`)
- Modify: `locale/en/LC_MESSAGES/alfred.po` (+ `pybabel compile`) — `cli.audit.log.reason_help`
- Test: `tests/unit/cli/test_audit_log_reason.py` (patch `_query_audit_log` with fixture rows; the backend stub stays untouched per PR-2)

- [ ] **Step 1: Write the failing tests** — fixture rows: `event="comms.forwarded_inbound.dropped"` with `subject.reason` in {`unknown_adapter`, `body_malformed`, `receive_fault`} + a `event="comms.inbound.poisoned"`/`result="poisoned"` row (NO `subject.reason`). Assert: (a) each rendered line includes the reason (receiver rows from `subject.reason`; the poisoned row from its `result`/event); (b) `--reason body_malformed` filters to that row only; (c) `--reason poisoned` matches the poisoned row (L-3 sec: the result/event fallback); (d) `--reason` with no match prints the localised empty message; (e) a row with no `subject`/no reason renders without crashing (empty cell).

- [ ] **Step 2: Run to verify they fail** → FAIL.

- [ ] **Step 3: Implement** — add `reason: Annotated[str | None, typer.Option("--reason", help=t("cli.audit.log.reason_help"))] = None`. Add a helper:

```python
def _row_reason(row: dict[str, object]) -> str:
    """The drop reason for triage: subject.reason (receiver drops) else the poisoned
    discriminator (poisoned rows carry no subject.reason — the reason is the result)."""
    subject = row.get("subject")
    if isinstance(subject, dict) and isinstance(subject.get("reason"), str):
        return subject["reason"]
    if row.get("result") == "poisoned":
        return "poisoned"
    return ""
```

After the `event` filter: `if reason: rows = [r for r in rows if _row_reason(r) == reason]`. Add a reason cell to the rendered line via `_row_reason(row)`. Keep the `AuditBackendUnavailable` catch unchanged (the stub still governs real invocations). Add the i18n key + recompile + re-run the drift gate (`pybabel update --check`, NEVER `--omit-header`).

- [ ] **Step 4: Run to verify they pass** — `uv run pytest tests/unit/cli/test_audit_log_reason.py tests/unit/i18n -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/audit.py tests/unit/cli/test_audit_log_reason.py locale/en/LC_MESSAGES/alfred.po locale/en/LC_MESSAGES/alfred.mo
git commit -m "feat(cli): render drop reason + --reason filter in alfred audit log (Spec B G6-7-5, #309)"
```

---

### Task 9: Adversarial companions

**Files:**

- Create: `tests/adversarial/comms/test_forwarded_inbound_poison.py`
- Modify: `.github/workflows/ci.yml` ONLY if a new per-file-100%-gated pure module was added — the attempt store is Postgres-backed (covered like `inbound_idempotency.py`, NOT per-file gated); the ceiling logic lives in `inbound.py` (comms unit suite) + `forwarded_inbound_receiver.py` (already gated). Confirm no new gate site needed.

- [ ] **Step 1: Write the failing adversarial tests:**
  - **Poison e2e:** a forwarded frame whose post-extract region fails on every attempt → after N=5 failed attempts the 6th receive is a `poisoned` dead-letter + drain; the un-observed→observed transition releases the stalled contiguous high-water so the tail can trim; NO 6th `quarantined_extract`.
  - **Distinct-id flood is DoS-gated (sec C-1):** a flood of distinct attacker-chosen `inbound_id`s under one `(adapter_id, platform_user_id_hash)` is shed by the `pre_resolution_limiter` and writes ZERO `forwarded_dispatch_attempts` rows past the budget (assert `attempt_count`/`increment` un-called once the limiter sheds).
  - **Deliberate shed is NOT poison (item 4 / sec H-1):** a budget-capped / burst-dropped / unbound-binding forwarded frame drains single-shot and the ledger is byte-for-byte untouched (NO read, NO increment); replaying it never produces a `poisoned` row.
  - **receive_fault is NOT ceilinged (item 5):** an off-vocab/unparseable envelope drains on the first occurrence (`receive_fault`) and never touches the ledger; no `poisoned` row ever.
  - **poison-then-receive_fault interleave (arch H2):** a frame that fails dispatch k<N times (ledger climbing) then on replay surfaces as a re-parse/receive_fault drop → drains single-shot, no double-count, no cross-path poison.
  - **Cross-adapter isolation (sec H4):** a frame with adapter_id "discord" can never increment the counter for adapter_id "tui" (composite-key + closed-vocab + one-path-per-adapter_id).
  - **Concurrent replay at ceiling (sec H3):** two concurrent copies of an at-ceiling frame produce >=1 `poisoned` row, advance the high-water once-effectively (idempotent `observe`), never dispatch — "at least N" semantics, no locking.
  - **Canary absence (sec H6):** a high-entropy secret in the T3 body AND a high-entropy `inbound_id` never appear (raw) in the `poisoned` row's fields or any structlog record (only the peppered hash).

- [ ] **Step 2: Run to verify they fail** → FAIL.

- [ ] **Step 3: Implement** — make them green via the Task 5–7 logic; add any missing branch. Confirm `forwarded_inbound_receiver.py` stays 100%: `uv run pytest tests/unit/comms/test_forwarded_inbound_receiver.py --cov=src/alfred/comms_mcp/forwarded_inbound_receiver.py --cov-report=term-missing --cov-fail-under=100`.

- [ ] **Step 4: Run to verify they pass** — `uv run pytest tests/adversarial/comms/test_forwarded_inbound_poison.py -v` → PASS; run the full adversarial comms suite.

- [ ] **Step 5: Commit**

```bash
git add tests/adversarial/comms/test_forwarded_inbound_poison.py .github/workflows/ci.yml
git commit -m "test(comms): adversarial poison-ceiling + DoS-gate/shed/isolation companions (Spec B G6-7-5, #309)"
```

---

### Task 10: Docs — ADR-0039 amendment + comms.md update

**Files:**

- Modify: `docs/adr/0039-gateway-adapter-inbound-bridge.md` (dated amendment)
- Modify: `docs/subsystems/comms.md` (rewrite the TEST-ONLY caveat + the deferred Triage note; add the `poisoned` reason)

- [ ] **Step 1: ADR-0039 dated amendment** (`### 2026-06-22 — G6-7-5: item-4b poison ceiling implemented; PERF-309-1 closed`). State precisely:
  - The ceiling is `N=5`; the durable ledger is `forwarded_dispatch_attempts`; the bound is **N extracts, poison on the (N+1)th attempt** (honest off-by-one).
  - The ceiling covers the WHOLE post-extract region (promotion-emit + ingest + dispatch) via the on-entry increment — not "dispatch only".
  - Receiver terminal drops (unknown_adapter/mismatch/malformed/receive_fault) are single-shot drains, NOT ceilinged (item 5).
  - **Correct the cost-budget framing:** `BudgetGuard` exists but `quarantined_extract` is not budget-charged; the ceiling is the only bound on its re-charge (declining to wire extract→BudgetGuard until the real-LLM child #230 gives it something to meter).
  - **"At least N" semantics** under concurrent replay (non-atomic read/increment; the atomic UPSERT + idempotent `observe` keep it correct without locking).
  - **Total bounded cost** is `N × extract + N × tail-reparse` (head-of-line amplification re-reads the dispatched tail behind the stalled seq; tail re-dedups via G0).
  - The downgrade DELETE of `poisoned` audit rows is a known append-only exception (mirrors 0019).
  - Follow-up: TTL/sweeper for the ledger (and the parallel never-swept `inbound_idempotency`).
- [ ] **Step 2: comms.md** — REWRITE the TEST-ONLY caveat (comms.md:640-649): replay is now bounded by the item-4b ceiling, BUT the leg is still not flag-day'd into production until G6-7-8 (gated on the G6-7-7 real-spawn proof + the `integration-privileged` lane promotion). REWRITE the "Devex deferred (G6-7-5)" note (comms.md:733-737): the render/filter logic shipped in G6-7-5 and operator-visible discrimination lands once PR-S3-7 wires the `_query_audit_log` backend. Add `poisoned` to the closed-vocab reason list in the Triage note.
- [ ] **Step 3: markdownlint** both docs (repo gate); fix.
- [ ] **Step 4: `git diff` review** both docs for accuracy against what shipped.
- [ ] **Step 5: Commit**

```bash
git add docs/adr/0039-gateway-adapter-inbound-bridge.md docs/subsystems/comms.md
git commit -m "docs(comms): ADR-0039 item-4b ceiling amendment + comms.md poison/triage update (Spec B G6-7-5, #309)"
```

---

## Self-review checklist

1. **Charter coverage:** items 1–5 all mapped (table above). ✅
2. **Plan-review fixes folded:** sec C-1 (read post-limiter), sec C-2 (whole-region increment-on-entry + comment fix), arch C-2/PR-1 (budget premise corrected), arch C-1/PR-5 (exact-count test), arch H1 (no attempt_count on dispatch_failed), sec H3 (at-least-N + concurrent test), sec H4 (cross-adapter isolation), sec H6 (canary incl. raw inbound_id), sec L-3 (--reason poisoned fallback), arch H3 (existing-constructor updates Task 6), arch M-1/M-3 (comms.md rewrite), M-1-sec/arch-gap (aclose posture Task 7), migration tuple/no-FK/downgrade (Task 2). ✅
3. **Placeholders:** none — every code step shows code; SQL/signatures concrete.
4. **Type consistency:** `attempt_store` / `ForwardedDispatchAttemptStore` / `_DispatchAttemptStoreLike` / `increment(*, adapter_id, inbound_id) -> int` / `attempt_count(*, adapter_id, inbound_id) -> int` consistent Tasks 3/5/6/7; `COMMS_INBOUND_POISONED_FIELDS` fields consistent Tasks 1/4/5; `result="poisoned"` consistent Tasks 1/2/4/5; `_FORWARDED_DISPATCH_ATTEMPT_CEILING=5` Task 5.

## Quality bar (every push)

`uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/` green; 100% line+branch on `forwarded_inbound_receiver.py` (per-file gate) + full comms/memory/adversarial suites; migration 0020 roundtrip under Docker; `pybabel update --check` clean. Commit subjects `type(scope): desc (Spec B G6-7-5, #309)` + the MrReasonable trailer. NEVER `--admin`/`--no-verify`.
