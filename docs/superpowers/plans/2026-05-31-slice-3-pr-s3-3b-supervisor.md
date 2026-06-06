# PR-S3-3b: Supervisor Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land `src/alfred/supervisor/` — the quarantined-LLM circuit breaker, MCP plugin lifecycle coordination, capability-gate fail-closed integration, per-action 30s deadline, Prometheus histogram + OTel sub-spans, and Alembic migration 0010 — so the privileged orchestrator is fault-tolerant and auditable under every plugin failure mode the spec requires. (`alfred supervisor status|reset` CLI commands are owned exclusively by PR-S3-6; rvw-002.)

**Architecture:** `Supervisor` opens an `asyncio.TaskGroup` at startup so every plugin's stdio-reader task is supervised under structured concurrency; when the group is cancelled, all readers receive graceful SIGTERM→SIGKILL shutdown. `CircuitBreaker` is a three-state machine (`CLOSED` → `OPEN` → `HALF_OPEN` → `CLOSED`) whose state, `trip_count`, and `last_trip_at` are persisted to the new `circuit_breakers` Postgres table (migration 0010); on process restart the breaker restores from Postgres and stays `OPEN` when the last trip was fewer than 1 hour ago. `deadline.py` wraps `handle_user_message` with `asyncio.timeout(30.0)` **inside** `session_scope` so the existing `CancelledError` rollback arm fires naturally; it adds a second `supervisor.action_timeout` audit row in addition to the existing `orchestrator.turn result="cancelled"` row. Observability is wired at this layer: `alfred_orchestrator_action_duration_seconds` histogram emits on every action outcome, labelled `(user_id_bucket, action_outcome, breaker_state)`; OTel sub-spans wrap `tool.web.fetch`, `security.quarantined.extract`, and `hookchain_total`.

**Tech Stack:** Python 3.12+ · asyncio (TaskGroup, timeout, CancelledError) · SQLAlchemy 2.0 typed ORM · Alembic · Pydantic v2 · structlog · Prometheus client (`prometheus_client.Histogram`) · OpenTelemetry SDK (`opentelemetry.trace`) · `alfred.hooks` (register_hookpoint + invoke) · `alfred.audit.audit_row_schemas` (from PR-S3-0a) · `alfred.i18n.t()` · pytest + testcontainers · 100% line+branch coverage gate on all trust-boundary files.

---

## §1 Goal

This PR ships `src/alfred/supervisor/` — Fork 10 of the Slice-3 spec — as a stand-alone package that every other Slice-3 subsystem depends on for fault-tolerance and observability. It resolves the following spec obligations:

- **Spec §10 entire** — supervisor module shape, quarantined-LLM circuit breaker (3 failures / 5 min → OPEN; exponential backoff restart; 1h re-arm; Postgres persistence), MCP plugin lifecycle, capability-gate fail-closed integration, per-action 30s deadline, user-facing `quarantine_unavailable` message.
- **Spec §10.5 TaskGroup ownership** — `Supervisor.start()` opens one `asyncio.TaskGroup`; all plugin stdio-reader tasks join it; on shutdown the group cascades SIGTERM→SIGKILL.
- **Spec §13 supervisor audit families** — `SUPERVISOR_BREAKER_RESET_FIELDS`, `SUPERVISOR_BREAKER_TRIPPED_FIELDS`, `SUPERVISOR_ACTION_TIMEOUT_FIELDS`, `SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS`, `SUPERVISOR_CONFIG_INSECURE_FIELDS` all consumed from `audit_row_schemas.py` (PR-S3-0a contract).
- **Spec §7a.3 observability** — `alfred_orchestrator_action_duration_seconds` histogram labelled `(user_id_bucket, action_outcome, breaker_state)`; OTel sub-spans per phase.
- **Spec §14 hookpoints** — `supervisor.breaker.tripped` (post, SYSTEM_ONLY_TIERS, fail_closed=False), `supervisor.breaker.reset` (post, SYSTEM_OPERATOR_TIERS, fail_closed=False), `supervisor.action_timeout` (error, SYSTEM_ONLY_TIERS, fail_closed=False), `plugin.lifecycle.loaded` (post, SYSTEM_ONLY), `plugin.lifecycle.crashed` (error, SYSTEM_ONLY), `plugin.lifecycle.quarantined` (post, SYSTEM_ONLY).
- **Spec §11.3 CLI (DEFERRED to PR-S3-6, rvw-002):** `alfred supervisor status` and `alfred supervisor reset <component> --confirm` are NOT shipped in this PR. The §1 sentence above is canonical — they live in PR-S3-6. Listed here only so the Slice-3 spec obligations remain traceable from this plan's §1; this PR ships the underlying `Supervisor.reset()` API + `supervisor.breaker.reset` audit row that PR-S3-6 wires the CLI on top of.
- **Spec §10.6** — Alembic migration 0010 (`circuit_breakers` table) + SQLAlchemy model.

This PR depends on PR-S3-0a (for `audit_row_schemas.py`), PR-S3-0b (for migrations 0007–0009 + i18n catalog), and PR-S3-3a (for `PluginTransport` Protocol and `AlfredPluginSession` contracts it supervises). It blocks PR-S3-4 (quarantined-LLM plugin) and PR-S3-5 (`web.fetch` plugin), which rely on `CircuitBreaker` and `Supervisor.start()`.

---

## §2 Architecture Overview

```
Orchestrator.handle_user_message(user, content, working_memory)
  │
  └─ asyncio.timeout(deadline_seconds)          # deadline.py wraps here
       │
       └─ session_scope()                        # existing DB txn context
            │
            ├─ _handle_turn(...)                 # existing OODA logic
            │    ├─ web.fetch dispatch            # → OTel sub-span
            │    ├─ quarantine.extract dispatch  # → OTel sub-span
            │    └─ hookchain_total              # → OTel sub-span
            │
            └─ on TimeoutError:
                 ├─ AuditWriter.append(supervisor.action_timeout)   # NEW
                 └─ existing CancelledError arm handles rollback


Supervisor (asyncio.TaskGroup)
  ├─ plugin stdio-reader task: quarantined-llm   # PR-S3-3a AlfredPluginSession
  ├─ plugin stdio-reader task: web-fetch         # PR-S3-5
  └─ heartbeat task: RealGate.heartbeat()        # §8.1 60s window

CircuitBreaker (per plugin_id)
  CLOSED ──(3 failures in 300s)──► OPEN
  OPEN   ──(re-arm after 3600s or operator reset)──► HALF_OPEN
  HALF_OPEN ──(probe succeeds)──► CLOSED
  HALF_OPEN ──(probe fails)──► OPEN

  State persisted to Postgres `circuit_breakers` table (migration 0010).
  On restart: load state from DB; stay OPEN if last_trip_at < 1h ago.

plugin_lifecycle.py
  start_plugin(plugin_id)
    ├─ gate.check_plugin_load(...)   # fail → plugin.lifecycle.load_refused
    └─ spawn reader task in TaskGroup

  on reader task crash:
    ├─ breaker.record_failure()
    ├─ emit plugin.lifecycle.crashed audit row
    └─ if breaker.state == OPEN → emit plugin.lifecycle.quarantined
       else schedule restart with exponential backoff

alfred_orchestrator_action_duration_seconds histogram:
  labels: user_id_bucket, action_outcome, breaker_state
  emitted on: success, timeout, cancelled
```

The `deadline.py` module adds one `asyncio.timeout` context inside the existing `session_scope` in `Orchestrator.handle_user_message`. The placement is **inside** `session_scope` so the existing `CancelledError` rollback path at `core.py:264–283` fires naturally — no new except branch is needed in `core.py` for the rollback. The supervisor's `deadline.py` adds only the `supervisor.action_timeout` audit row BEFORE re-raising `CancelledError`, complementing (not replacing) the existing `orchestrator.turn result="cancelled"` row written by `_audit_cancellation`.

---

## §3 File Structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/supervisor/__init__.py` | Create | Public exports: `Supervisor`, `BreakerState`, `CircuitBreaker`, `SupervisorError`, `BreakStateError` |
| `src/alfred/supervisor/core.py` | Create | `Supervisor` class: owns the `asyncio.TaskGroup`, plugin lifecycle map, heartbeat loop, `reset_breaker()` |
| `src/alfred/supervisor/breaker.py` | Create | `CircuitBreaker` state machine + Postgres persistence (load/save via `session_scope`) |
| `src/alfred/supervisor/plugin_lifecycle.py` | Create | `start_plugin()`, `_on_crash()`, restart scheduling with exponential backoff |
| `src/alfred/supervisor/deadline.py` | Create | `wrap_with_deadline(handle_user_message, ...)` async context decorator applying `asyncio.timeout` inside `session_scope` |
| `src/alfred/supervisor/observability.py` | Create | `alfred_orchestrator_action_duration_seconds` histogram; OTel sub-span helpers |
| `src/alfred/supervisor/errors.py` | Create | `SupervisorError(AlfredError)`, `BreakStateError(SupervisorError)`, `QuarantinedUnavailable(SupervisorError)` |
| `src/alfred/memory/models.py` | Modify | Add `CircuitBreakerState` SQLAlchemy ORM model (table `circuit_breakers`) |
| `src/alfred/memory/migrations/versions/0010_circuit_breakers.py` | Create | Alembic migration: CREATE TABLE `circuit_breakers` + downgrade |
| `src/alfred/orchestrator/core.py` | Modify | Wire `Supervisor.start()` at startup; wrap `handle_user_message` body with `deadline.wrap_with_deadline`; register `supervisor.breaker.*` hookpoints |
| `src/alfred/hooks/registry.py` | Modify | Task 20 idempotency surgery: `register_hookpoint()` becomes a no-op for an already-registered identical config; raises `HookpointConfigConflict` on mismatched re-registration. Required for the `_register_hookpoints()` call inside `Supervisor.__init__` to survive test-isolation patterns that construct multiple Supervisor instances per test process. Existing hooks-subsystem callers (Slice 2) are unaffected — current behaviour is "raise on second register"; new behaviour is "raise only on conflict, else no-op". This is a behaviour-narrowing change, not a breaking one. |
| `src/alfred/cli/supervisor.py` | (see PR-S3-6) | Supervisor CLI surface owned by PR-S3-6 (devex-001/rvw-002) |
| `tests/unit/supervisor/__init__.py` | Create | Package marker |
| `tests/unit/supervisor/test_breaker_state_machine.py` | Create | Full state-machine coverage: CLOSED→OPEN→HALF_OPEN→CLOSED transition paths, trip-count increment, 5-min window expiry |
| `tests/unit/supervisor/test_persisted_state_restore.py` | Create | Restart-from-Postgres restore: OPEN stays OPEN when `last_trip_at < 1h`; OPEN re-arms to CLOSED when `last_trip_at > 1h`; CLOSED loads as CLOSED |
| `tests/unit/supervisor/test_action_timeout_taskgroup_cancellation.py` | Create | `asyncio.timeout` fires → `supervisor.action_timeout` audit row emitted; existing `orchestrator.turn result=cancelled` row also emitted; `CancelledError` propagates |
| `tests/unit/supervisor/test_capability_gate_outage_fail_closed.py` | Create | Gate unavailable → all new dispatches denied; existing in-process subscribers denied after 60s window; `supervisor.capability_gate_unavailable` audit rows emitted on enter/exit |
| `tests/unit/supervisor/test_histograms.py` | Create | `alfred_orchestrator_action_duration_seconds` emitted on success, timeout, and cancellation with correct labels |
| `tests/integration/supervisor/test_quarantined_llm_3_failures_trip.py` | Create | 3 crashes within 300s trip the breaker to OPEN; 4th invocation raises `QuarantinedUnavailable` immediately; Postgres state reflects OPEN; reset via `Supervisor.reset_breaker()` restores CLOSED |

---

## §4 Tasks

Tasks are grouped by component. Each task follows the TDD cycle: write failing test → confirm FAIL → implement → confirm PASS → commit. All commits use `(#TBD-slice3)` as the issue reference.

---

### Component A: Errors + migration + ORM model

- [ ] **Task 1 — Error hierarchy.**
  Files: Create `src/alfred/supervisor/errors.py`.

  **Failing test** (`tests/unit/supervisor/test_errors.py`):

  ```python
  # tests/unit/supervisor/test_errors.py
  from alfred.errors import AlfredError
  from alfred.supervisor.errors import (
      BreakStateError,
      QuarantinedUnavailable,
      SupervisorError,
  )

  def test_supervisor_error_is_alfred_error() -> None:
      assert issubclass(SupervisorError, AlfredError)

  def test_break_state_error_is_supervisor_error() -> None:
      assert issubclass(BreakStateError, SupervisorError)

  def test_quarantined_unavailable_is_supervisor_error() -> None:
      assert issubclass(QuarantinedUnavailable, SupervisorError)

  def test_quarantined_unavailable_message_uses_t() -> None:
      exc = QuarantinedUnavailable()
      # Must not be a bare key — t() renders a real English string
      assert "orchestrator.quarantine_unavailable" not in str(exc)
      assert len(str(exc)) > 0
  ```

  Run: `uv run pytest tests/unit/supervisor/test_errors.py -q` → expect 4 failures (ImportError).

  **Implementation** (`src/alfred/supervisor/errors.py`):

  ```python
  """Supervisor error hierarchy.

  SupervisorError is the root; all supervisor-specific exceptions inherit from
  it. QuarantinedUnavailable is the user-facing exception raised when the
  quarantined-LLM circuit breaker is OPEN (spec §10.2, §5.5).
  """
  from alfred.errors import AlfredError
  from alfred.i18n.translator import t


  class SupervisorError(AlfredError):
      """Root for all supervisor errors."""


  class BreakStateError(SupervisorError):
      """Raised when a state transition is invalid for the current breaker state."""


  class QuarantinedUnavailable(SupervisorError):
      """Raised when the quarantined LLM's circuit breaker is OPEN.

      The orchestrator catches this and responds with the user-facing
      quarantine_unavailable message (spec §5.5, §10.2). There is no silent
      T3-self-processing fallback — this exception is always surfaced.
      """

      def __init__(self, component_id: str = "quarantined-llm") -> None:
          super().__init__(t("orchestrator.quarantine_unavailable"))
          self.component_id = component_id
  ```

  Run: `uv run pytest tests/unit/supervisor/test_errors.py -q` → 4 passed.

  Commit:

  ```
  git commit -m "feat(supervisor): error hierarchy — SupervisorError, BreakStateError, QuarantinedUnavailable (#TBD-slice3)"
  ```

---

- [ ] **Task 2 — `CircuitBreakerState` ORM model in `models.py`.**
  Files: Modify `src/alfred/memory/models.py`.

  **Failing test** (`tests/unit/supervisor/test_persisted_state_restore.py` — stub that just imports):

  ```python
  from alfred.memory.models import CircuitBreakerState  # ImportError if not present

  def test_circuit_breaker_state_model_exists() -> None:
      assert CircuitBreakerState.__tablename__ == "circuit_breakers"
  ```

  Run: `uv run pytest tests/unit/supervisor/test_persisted_state_restore.py::test_circuit_breaker_state_model_exists -q` → ImportError / AttributeError.

  **Implementation** (append to `src/alfred/memory/models.py` after `AuditEntry`):

  ```python
  class CircuitBreakerState(Base):
      """Persisted state for a named circuit breaker (spec §10.6).

      One row per supervised component_id. On process restart, the supervisor
      loads this row and stays OPEN if last_trip_at < 1h ago.

      Downgrade semantics (migration 0010): DELETE all rows then DROP TABLE.
      Breaker state is transient — the next run re-discovers failures.
      """

      __tablename__ = "circuit_breakers"

      component_id: Mapped[str] = mapped_column(
          String(128), primary_key=True
      )
      state: Mapped[str] = mapped_column(
          String(16), default="CLOSED"
      )  # "CLOSED" | "OPEN" | "HALF_OPEN"
      trip_count: Mapped[int] = mapped_column(default=0)
      last_trip_at: Mapped[dt.datetime | None] = mapped_column(
          DateTime(timezone=True), nullable=True
      )
      last_failure_type: Mapped[str | None] = mapped_column(
          String(128), nullable=True
      )  # Python exception type name; never str(exc) (T3 fragment risk, spec §5.6)
      updated_at: Mapped[dt.datetime] = mapped_column(
          DateTime(timezone=True), default=_now, onupdate=_now
      )

      __table_args__ = (
          CheckConstraint(
              "state IN ('CLOSED', 'OPEN', 'HALF_OPEN')",
              name="ck_circuit_breakers_state",
          ),
      )
  ```

  Run: `uv run pytest tests/unit/supervisor/test_persisted_state_restore.py::test_circuit_breaker_state_model_exists -q` → 1 passed.

  Commit:

  ```
  git commit -m "feat(supervisor/models): CircuitBreakerState ORM model in models.py (#TBD-slice3)"
  ```

---

- [ ] **Task 3 — Alembic migration 0010.**
  Files: Create `src/alfred/memory/migrations/versions/0010_circuit_breakers.py`.

  **Failing test** (add to `test_persisted_state_restore.py`):

  ```python
  import importlib

  def test_migration_0010_module_importable() -> None:
      mod = importlib.import_module(
          "alfred.memory.migrations.versions.0010_circuit_breakers"
      )
      assert mod.revision == "0010"
      assert mod.down_revision == "0009"
  ```

  Run: `uv run pytest tests/unit/supervisor/test_persisted_state_restore.py::test_migration_0010_module_importable -q` → ImportError.

  **Implementation** (`src/alfred/memory/migrations/versions/0010_circuit_breakers.py`):

  ```python
  """Create circuit_breakers table for supervisor breaker state (spec §10.6).

  Revision ID: 0010
  Revises: 0009
  Create Date: 2026-05-31 00:00:00.000000

  One row per supervised component_id (e.g. "quarantined-llm", "web-fetch").
  The supervisor loads this table on restart: if last_trip_at < 1h ago the
  breaker stays OPEN. Prevents flap on rolling restarts.

  Downgrade semantics: DELETE all rows then DROP TABLE. Breaker state is
  transient — the next run re-discovers failures organically. This matches
  the loud-destruction pattern in 0006/0007: operators who need the trip
  history snapshot the table BEFORE downgrading.
  """

  from __future__ import annotations

  from collections.abc import Sequence

  import sqlalchemy as sa
  from alembic import op

  revision: str = "0010"
  down_revision: str | Sequence[str] | None = "0009"
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
      """Create circuit_breakers table."""
      op.create_table(
          "circuit_breakers",
          sa.Column("component_id", sa.String(128), primary_key=True),
          sa.Column("state", sa.String(16), nullable=False, server_default="CLOSED"),
          sa.Column("trip_count", sa.Integer, nullable=False, server_default="0"),
          sa.Column(
              "last_trip_at",
              sa.DateTime(timezone=True),
              nullable=True,
          ),
          sa.Column("last_failure_type", sa.String(128), nullable=True),
          sa.Column(
              "updated_at",
              sa.DateTime(timezone=True),
              nullable=False,
              server_default=sa.text("now()"),
          ),
          sa.CheckConstraint(
              "state IN ('CLOSED', 'OPEN', 'HALF_OPEN')",
              name="ck_circuit_breakers_state",
          ),
      )


  def downgrade() -> None:
      """Drop circuit_breakers table (state is transient; safe to discard).

      Destructive: trip history is lost. Operators who care should snapshot
      the table BEFORE running this downgrade.
      """
      op.execute("DELETE FROM circuit_breakers")  # noqa: S608 (constant-controlled)
      op.drop_table("circuit_breakers")
  ```

  Run: `uv run pytest tests/unit/supervisor/test_persisted_state_restore.py::test_migration_0010_module_importable -q` → 1 passed.

  Commit:

  ```
  git commit -m "feat(supervisor/migration): 0010_circuit_breakers CREATE TABLE (#TBD-slice3)"
  ```

---

### Component B: CircuitBreaker state machine

- [ ] **Task 4 — `BreakerState` enum + `CircuitBreaker` skeleton.**
  Files: Create `src/alfred/supervisor/breaker.py`.

  **Failing test** (`tests/unit/supervisor/test_breaker_state_machine.py`):

  ```python
  from alfred.supervisor.breaker import BreakerState, CircuitBreaker

  def test_initial_state_is_closed() -> None:
      cb = CircuitBreaker(component_id="test-plugin", session_scope=None)
      assert cb.state == BreakerState.CLOSED

  def test_breaker_state_enum_values() -> None:
      assert {s.value for s in BreakerState} == {"CLOSED", "OPEN", "HALF_OPEN"}
  ```

  Run: `uv run pytest tests/unit/supervisor/test_breaker_state_machine.py -q` → ImportError.

  **Implementation** (`src/alfred/supervisor/breaker.py` — skeleton):

  ```python
  """CircuitBreaker — three-state fault isolation for supervised plugins.

  State machine (spec §10.2):
      CLOSED ──(3 failures in 300s)──► OPEN
      OPEN   ──(re-arm: 1h elapsed or operator reset)──► HALF_OPEN
      HALF_OPEN ──(probe succeeds)──► CLOSED
      HALF_OPEN ──(probe fails)──► OPEN

  State is persisted to Postgres (circuit_breakers table, migration 0010).
  Exponential backoff for HALF_OPEN probes: 5s initial, ×2 multiplier, 5min max.
  """

  from __future__ import annotations

  import asyncio
  import datetime as dt
  from collections.abc import Callable
  from contextlib import AbstractAsyncContextManager
  from enum import Enum
  from typing import TYPE_CHECKING

  import structlog

  from alfred.audit.audit_row_schemas import (
      SUPERVISOR_BREAKER_RESET_FIELDS,
      SUPERVISOR_BREAKER_TRIPPED_FIELDS,
  )
  from alfred.supervisor.errors import BreakStateError, QuarantinedUnavailable

  if TYPE_CHECKING:
      from sqlalchemy.ext.asyncio import AsyncSession

  _log = structlog.get_logger(__name__)

  _FAILURE_WINDOW_SECONDS: float = 300.0   # 5 minutes (spec §10.2)
  _FAILURE_THRESHOLD: int = 3              # trips after 3 failures in window
  _RE_ARM_SECONDS: float = 3600.0          # 1 hour re-arm (spec §10.6)
  _BACKOFF_INITIAL_SECONDS: float = 5.0   # exponential backoff start
  _BACKOFF_MULTIPLIER: float = 2.0
  _BACKOFF_MAX_SECONDS: float = 300.0     # 5 minutes cap


  class BreakerState(str, Enum):
      CLOSED = "CLOSED"
      OPEN = "OPEN"
      HALF_OPEN = "HALF_OPEN"


  class CircuitBreaker:
      """Three-state circuit breaker with Postgres persistence.

      Construct with a component_id and a session_scope factory (the same
      factory injected into the orchestrator). The supervisor passes its own
      session_scope so breaker writes share the same DB pool.
      """

      def __init__(
          self,
          component_id: str,
          session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]] | None,
          *,
          failure_threshold: int = _FAILURE_THRESHOLD,
          failure_window_seconds: float = _FAILURE_WINDOW_SECONDS,
          re_arm_seconds: float = _RE_ARM_SECONDS,
      ) -> None:
          self.component_id = component_id
          self._session_scope = session_scope
          self._failure_threshold = failure_threshold
          self._failure_window_seconds = failure_window_seconds
          self._re_arm_seconds = re_arm_seconds

          self.state: BreakerState = BreakerState.CLOSED
          self.trip_count: int = 0
          self.last_trip_at: dt.datetime | None = None
          self._recent_failures: list[dt.datetime] = []
          self._backoff_seconds: float = _BACKOFF_INITIAL_SECONDS
          self._save_lock: asyncio.Lock = asyncio.Lock()  # rvw-pre-flight: lost-update safety for concurrent save_to_db (Task 8).
  ```

  Run: `uv run pytest tests/unit/supervisor/test_breaker_state_machine.py -q` → 2 passed (skeleton enough for initial tests).

---

- [ ] **Task 5 — `record_failure()` → CLOSED→OPEN transition.**
  Files: Modify `src/alfred/supervisor/breaker.py`.

  **Failing test** (add to `test_breaker_state_machine.py`):

  ```python
  import datetime as dt
  from unittest.mock import AsyncMock

  def _make_cb(**kwargs) -> CircuitBreaker:
      return CircuitBreaker(component_id="test-plugin", session_scope=AsyncMock(), **kwargs)

  def test_single_failure_stays_closed() -> None:
      cb = _make_cb()
      cb.record_failure("SubprocessExitedError", now=dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC))
      assert cb.state == BreakerState.CLOSED
      assert cb.trip_count == 0

  def test_three_failures_in_window_opens_breaker() -> None:
      cb = _make_cb()
      base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
      for i in range(3):
          cb.record_failure("SubprocessExitedError", now=base + dt.timedelta(seconds=i * 60))
      assert cb.state == BreakerState.OPEN
      assert cb.trip_count == 1

  def test_failures_outside_window_do_not_trip() -> None:
      cb = _make_cb()
      base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
      cb.record_failure("SubprocessExitedError", now=base)
      cb.record_failure("SubprocessExitedError", now=base + dt.timedelta(seconds=400))  # outside 5min
      cb.record_failure("SubprocessExitedError", now=base + dt.timedelta(seconds=800))
      assert cb.state == BreakerState.CLOSED  # window expired between each

  def test_open_state_raises_quarantined_unavailable() -> None:
      cb = _make_cb()
      cb.state = BreakerState.OPEN
      import pytest
      from alfred.supervisor.errors import QuarantinedUnavailable
      with pytest.raises(QuarantinedUnavailable):
          cb.assert_available()
  ```

  Run: `uv run pytest tests/unit/supervisor/test_breaker_state_machine.py -q` → failures on new tests.

  **Implementation** (add methods to `CircuitBreaker`):

  ```python
  def record_failure(
      self,
      exception_type: str,
      *,
      now: dt.datetime | None = None,
  ) -> None:
      """Record a plugin failure. Trips to OPEN after threshold in window.

      exception_type: Python type name only — never str(exc) or exc.args
      (spec §5.6: subprocess crash rows must not carry T3 fragment risk).
      """
      if self.state == BreakerState.OPEN:
          return  # already tripped; ignore additional failures

      _now = now or dt.datetime.now(dt.UTC)
      cutoff = _now - dt.timedelta(seconds=self._failure_window_seconds)
      self._recent_failures = [f for f in self._recent_failures if f > cutoff]
      self._recent_failures.append(_now)

      if len(self._recent_failures) >= self._failure_threshold:
          self._trip(exception_type=exception_type, now=_now)

  def _trip(self, *, exception_type: str, now: dt.datetime) -> None:
      self.state = BreakerState.OPEN
      self.trip_count += 1
      self.last_trip_at = now
      self._recent_failures.clear()
      _log.warning(
          "supervisor.breaker.tripped",
          component_id=self.component_id,
          trip_count=self.trip_count,
          last_failure_type=exception_type,
      )

  def assert_available(self) -> None:
      """Raise QuarantinedUnavailable if breaker is OPEN.

      Called by plugin_lifecycle before dispatching to a supervised plugin.
      """
      if self.state == BreakerState.OPEN:
          raise QuarantinedUnavailable(self.component_id)
  ```

  Run: `uv run pytest tests/unit/supervisor/test_breaker_state_machine.py -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor/breaker): record_failure CLOSED→OPEN transition, assert_available (#TBD-slice3)"
  ```

---

- [ ] **Task 6 — OPEN → HALF_OPEN re-arm logic.**
  Files: Modify `src/alfred/supervisor/breaker.py`.

  **Failing test** (add to `test_breaker_state_machine.py`):

  ```python
  def test_open_re_arms_after_1h() -> None:
      cb = _make_cb()
      base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
      cb.state = BreakerState.OPEN
      cb.last_trip_at = base - dt.timedelta(seconds=3601)  # > 1h ago
      cb.maybe_rearm(now=base)
      assert cb.state == BreakerState.HALF_OPEN

  def test_open_does_not_rearm_before_1h() -> None:
      cb = _make_cb()
      base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
      cb.state = BreakerState.OPEN
      cb.last_trip_at = base - dt.timedelta(seconds=1800)  # 30min ago
      cb.maybe_rearm(now=base)
      assert cb.state == BreakerState.OPEN

  def test_half_open_probe_success_closes() -> None:
      cb = _make_cb()
      cb.state = BreakerState.HALF_OPEN
      cb.record_probe_success()
      assert cb.state == BreakerState.CLOSED
      assert cb._backoff_seconds == _BACKOFF_INITIAL_SECONDS  # reset

  def test_half_open_probe_failure_reopens() -> None:
      cb = _make_cb()
      cb.state = BreakerState.HALF_OPEN
      cb.record_probe_failure("SubprocessExitedError")
      assert cb.state == BreakerState.OPEN
      # backoff doubles
      assert cb._backoff_seconds == _BACKOFF_INITIAL_SECONDS * _BACKOFF_MULTIPLIER
  ```

  Import `_BACKOFF_INITIAL_SECONDS`, `_BACKOFF_MULTIPLIER` in the test file.

  Run → failures.

  **Implementation** (add to `CircuitBreaker`):

  ```python
  def maybe_rearm(self, *, now: dt.datetime | None = None) -> None:
      """Transition OPEN → HALF_OPEN when the re-arm window has elapsed.

      Called by the supervisor's restart scheduler to check if a probe
      should be attempted. No-op for CLOSED or HALF_OPEN states.
      """
      if self.state != BreakerState.OPEN:
          return
      _now = now or dt.datetime.now(dt.UTC)
      if self.last_trip_at is None:
          return
      elapsed = (_now - self.last_trip_at).total_seconds()
      if elapsed >= self._re_arm_seconds:
          self.state = BreakerState.HALF_OPEN
          _log.info(
              "supervisor.breaker.half_open",
              component_id=self.component_id,
              elapsed_seconds=elapsed,
          )

  def record_probe_success(self) -> None:
      """HALF_OPEN probe succeeded — close the breaker and reset backoff."""
      if self.state != BreakerState.HALF_OPEN:
          raise BreakStateError(
              f"record_probe_success called in state {self.state!r} (expected HALF_OPEN)"
          )
      self.state = BreakerState.CLOSED
      self._recent_failures.clear()
      self._backoff_seconds = _BACKOFF_INITIAL_SECONDS
      _log.info("supervisor.breaker.closed", component_id=self.component_id)

  def record_probe_failure(self, exception_type: str) -> None:
      """HALF_OPEN probe failed — reopen the breaker with doubled backoff."""
      if self.state != BreakerState.HALF_OPEN:
          raise BreakStateError(
              f"record_probe_failure called in state {self.state!r} (expected HALF_OPEN)"
          )
      self._backoff_seconds = min(
          self._backoff_seconds * _BACKOFF_MULTIPLIER, _BACKOFF_MAX_SECONDS
      )
      self._trip(exception_type=exception_type, now=dt.datetime.now(dt.UTC))
  ```

  Run: `uv run pytest tests/unit/supervisor/test_breaker_state_machine.py -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor/breaker): OPEN→HALF_OPEN re-arm, probe success/failure, backoff (#TBD-slice3)"
  ```

---

- [ ] **Task 7 — `reset()` operator-triggered and full state-machine coverage.**
  Files: Modify `src/alfred/supervisor/breaker.py`.

  **Failing test** (add to `test_breaker_state_machine.py`):

  ```python
  def test_operator_reset_from_open_to_closed() -> None:
      cb = _make_cb()
      cb.state = BreakerState.OPEN
      cb.trip_count = 5
      cb.reset()
      assert cb.state == BreakerState.CLOSED
      assert cb.trip_count == 5  # trip_count NOT reset; audit trail preserved

  def test_reset_from_closed_is_noop() -> None:
      cb = _make_cb()
      cb.reset()  # no raise
      assert cb.state == BreakerState.CLOSED

  def test_reset_from_half_open_closes() -> None:
      cb = _make_cb()
      cb.state = BreakerState.HALF_OPEN
      cb.reset()
      assert cb.state == BreakerState.CLOSED
  ```

  Run → failures.

  **Implementation**:

  ```python
  def reset(self) -> None:
      """Operator-triggered reset: transition any state → CLOSED.

      trip_count is NOT reset — it is a cumulative audit counter.
      Called by Supervisor.reset_breaker() after auditing supervisor.breaker.reset.
      """
      self.state = BreakerState.CLOSED
      self._recent_failures.clear()
      self._backoff_seconds = _BACKOFF_INITIAL_SECONDS
      _log.info("supervisor.breaker.reset", component_id=self.component_id)
  ```

  Run: `uv run pytest tests/unit/supervisor/test_breaker_state_machine.py -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor/breaker): reset(), full state-machine coverage (#TBD-slice3)"
  ```

---

### Component C: Breaker Postgres persistence

- [ ] **Task 8 — `load_from_db()` and `save_to_db()` on `CircuitBreaker`.**
  Files: Modify `src/alfred/supervisor/breaker.py`.

  **Failing test** (`tests/unit/supervisor/test_persisted_state_restore.py` — complete):

  ```python
  """Tests for CircuitBreaker Postgres persistence (spec §10.6)."""

  from __future__ import annotations

  import datetime as dt
  import uuid
  from unittest.mock import AsyncMock, MagicMock

  import pytest

  from alfred.supervisor.breaker import BreakerState, CircuitBreaker


  def _make_db_row(
      *,
      state: str = "CLOSED",
      trip_count: int = 0,
      last_trip_at: dt.datetime | None = None,
      last_failure_type: str | None = None,
  ) -> MagicMock:
      row = MagicMock()
      row.state = state
      row.trip_count = trip_count
      row.last_trip_at = last_trip_at
      row.last_failure_type = last_failure_type
      return row


  @pytest.mark.asyncio
  async def test_load_closed_from_db() -> None:
      session = AsyncMock()
      session.get = AsyncMock(return_value=_make_db_row(state="CLOSED", trip_count=2))
      cb = CircuitBreaker(component_id="plugin", session_scope=None)
      await cb.load_from_db(session)
      assert cb.state == BreakerState.CLOSED
      assert cb.trip_count == 2


  @pytest.mark.asyncio
  async def test_load_open_stays_open_when_last_trip_recent() -> None:
      base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
      recent_trip = base - dt.timedelta(minutes=30)  # < 1h ago
      session = AsyncMock()
      session.get = AsyncMock(
          return_value=_make_db_row(state="OPEN", trip_count=3, last_trip_at=recent_trip)
      )
      cb = CircuitBreaker(component_id="plugin", session_scope=None)
      await cb.load_from_db(session, now=base)
      assert cb.state == BreakerState.OPEN  # spec §10.6: stays OPEN


  @pytest.mark.asyncio
  async def test_load_open_rearms_when_last_trip_over_1h() -> None:
      base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
      old_trip = base - dt.timedelta(hours=2)  # > 1h ago
      session = AsyncMock()
      session.get = AsyncMock(
          return_value=_make_db_row(state="OPEN", trip_count=1, last_trip_at=old_trip)
      )
      cb = CircuitBreaker(component_id="plugin", session_scope=None)
      await cb.load_from_db(session, now=base)
      assert cb.state == BreakerState.HALF_OPEN  # re-armed on load


  @pytest.mark.asyncio
  async def test_load_no_row_starts_closed() -> None:
      session = AsyncMock()
      session.get = AsyncMock(return_value=None)  # no row in DB
      cb = CircuitBreaker(component_id="plugin", session_scope=None)
      await cb.load_from_db(session)
      assert cb.state == BreakerState.CLOSED
      assert cb.trip_count == 0


  @pytest.mark.asyncio
  async def test_save_to_db_upserts_row() -> None:
      session = AsyncMock()
      session.merge = AsyncMock()
      cb = CircuitBreaker(component_id="plugin", session_scope=None)
      cb.state = BreakerState.OPEN
      cb.trip_count = 3
      await cb.save_to_db(session)
      session.merge.assert_called_once()
      call_args = session.merge.call_args[0][0]
      assert call_args.component_id == "plugin"
      assert call_args.state == "OPEN"
      assert call_args.trip_count == 3
  ```

  Run: `uv run pytest tests/unit/supervisor/test_persisted_state_restore.py -q` → failures (methods missing).

  **Implementation** (add to `CircuitBreaker`):

  ```python
  async def load_from_db(
      self,
      session: AsyncSession,
      *,
      now: dt.datetime | None = None,
  ) -> None:
      """Load persisted state from Postgres. Call at supervisor startup.

      If last_trip_at < 1h ago, stays OPEN (spec §10.6: prevents flap on
      rolling restarts). If last_trip_at > 1h ago, transitions to HALF_OPEN.
      No row → starts CLOSED with zero trip_count.
      """
      from alfred.memory.models import CircuitBreakerState as _Model  # local import avoids circular
      row: _Model | None = await session.get(_Model, self.component_id)
      if row is None:
          return  # new breaker; defaults already CLOSED
      self.trip_count = row.trip_count
      self.last_trip_at = row.last_trip_at
      match row.state:
          case "CLOSED":
              self.state = BreakerState.CLOSED
          case "OPEN":
              self.state = BreakerState.OPEN
              # Apply re-arm check using wall-clock time at load (spec §10.6)
              self.maybe_rearm(now=now)
          case "HALF_OPEN":
              self.state = BreakerState.HALF_OPEN

  async def save_to_db(self, session: AsyncSession) -> None:
      """Persist current state to Postgres. Call after every state transition.

      Uses session.merge for upsert semantics (INSERT OR UPDATE by primary key).
      last_failure_type carries the Python exception type name only — never
      str(exc) (spec §5.6: no T3 fragment risk in crash rows).

      **Lost-update safety (rvw-pre-flight fix):** Two coroutines calling
      ``save_to_db`` for the same ``component_id`` concurrently — e.g. a crash
      handler and a manual reset — can interleave their read-modify-write and
      lose a trip count increment. The breaker holds an ``asyncio.Lock`` per
      instance; because ``CircuitBreaker`` is a singleton per ``component_id``
      (``Supervisor.get_or_create_breaker``, Task 19), the per-instance lock
      serialises all writes for a given component within the same event loop.
      """
      from alfred.memory.models import CircuitBreakerState as _Model
      import datetime as dt

      async with self._save_lock:
          row = _Model(
              component_id=self.component_id,
              state=self.state.value,
              trip_count=self.trip_count,
              last_trip_at=self.last_trip_at,
              updated_at=dt.datetime.now(dt.UTC),
          )
          await session.merge(row)
  ```

  > **Required field (declared in Task 4 `__init__`):**
  > ``self._save_lock: asyncio.Lock = asyncio.Lock()`` is already initialized
  > in ``CircuitBreaker.__init__`` (Task 4). The singleton-per-component
  > invariant (``Supervisor.get_or_create_breaker``) is asserted in
  > ``Supervisor.__init__`` so the lock provides correctness inside the single
  > event loop AlfredOS runs on. If a future ADR introduces multi-process
  > supervisors, escalate to ``SELECT … FOR UPDATE`` on the row — out of scope
  > for Slice 3.

  Run: `uv run pytest tests/unit/supervisor/test_persisted_state_restore.py -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor/breaker): load_from_db + save_to_db Postgres persistence (#TBD-slice3)"
  ```

---

- [ ] **Task 9 — Breaker hookpoint invocation helper.**
  Files: Modify `src/alfred/supervisor/breaker.py`.

  **Motivation (err-001 / core-004):** hookpoint invocation must NOT be fire-and-forget. `asyncio.get_event_loop().create_task(...)` escapes the Supervisor's TaskGroup, loses exceptions silently, and uses a deprecated API on Python 3.12+. The fix: `_trip()` does NOT invoke hookpoints itself. Instead `PluginLifecycle.on_crash()` and `Supervisor.reset_breaker()` — both already `async` — call `await _invoke_hookpoint(...)` after recording the state change. Hookpoint registration belongs in `Supervisor.__init__` (Task 20), not at module-import time (core-010). Additionally: `invoke(...)` positional arg is `name`, not `hookpoint=` keyword (core-004).

  **Failing test** (add to `test_breaker_state_machine.py`):

  ```python
  import pytest
  from unittest.mock import AsyncMock, patch

  @pytest.mark.asyncio
  async def test_trip_does_not_fire_and_forget_hookpoint() -> None:
      """_trip() must NOT spawn a fire-and-forget task (err-001/core-004).
      Hookpoint invocation is the caller's (PluginLifecycle/Supervisor) responsibility.
      """
      cb = _make_cb()
      base = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)

      with patch("asyncio.get_running_loop") as mock_loop:
          for i in range(3):
              cb.record_failure("SubprocessExitedError", now=base + dt.timedelta(seconds=i))
      # create_task must NOT have been called on the loop — hookpoint is not scheduled here
      mock_loop.return_value.create_task.assert_not_called()
      assert cb.state == BreakerState.OPEN
  ```

  Run → failure if old fire-and-forget code is present.

  **Implementation** — remove the `asyncio.get_event_loop().create_task(...)` block from `_trip()`. Add the standalone `_invoke_hookpoint` helper for callers:

  ```python
  # breaker.py — module-level helper (no import-time registration)
  import uuid as _uuid
  from alfred.hooks.context import HookContext


  async def invoke_breaker_tripped_hookpoint(
      component_id: str,
      trip_count: int,
      last_failure_type: str,
  ) -> None:
      """Invoke supervisor.breaker.tripped hookpoint. Called by PluginLifecycle.on_crash().

      Separated from _trip() so the call stays inside the Supervisor's TaskGroup
      (err-001: no fire-and-forget; core-004: positional name arg to invoke()).
      """
      from alfred.hooks.invoke import invoke  # noqa: PLC0415 (deferred to break circular)
      ctx: HookContext[dict[str, object]] = HookContext(
          action_id="supervisor.breaker.tripped",
          hookpoint="supervisor.breaker.tripped",
          input={
              "component_id": component_id,
              "trip_count": trip_count,
              "last_failure_type": last_failure_type,
              "breaker_state": "OPEN",
              "correlation_id": str(_uuid.uuid4()),
          },
          correlation_id=str(_uuid.uuid4()),
          kind="post",
      )
      await invoke("supervisor.breaker.tripped", ctx, kind="post", fail_closed=False)
  ```

  Run: `uv run pytest tests/unit/supervisor/test_breaker_state_machine.py -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor/breaker): hookpoint helper — no fire-and-forget, TaskGroup-safe (#TBD-slice3)"
  ```

---

### Component D: Plugin lifecycle

- [ ] **Task 10 — `plugin_lifecycle.py` — `start_plugin()` + crash handler.**
  Files: Create `src/alfred/supervisor/plugin_lifecycle.py`.

  **Failing test** (`tests/unit/supervisor/test_action_timeout_taskgroup_cancellation.py` — plugin lifecycle portion):

  ```python
  """Plugin lifecycle: load_refused emitted when gate denies, crash increments breaker."""

  from __future__ import annotations

  import asyncio
  from unittest.mock import AsyncMock, MagicMock

  import pytest

  from alfred.supervisor.breaker import BreakerState, CircuitBreaker
  from alfred.supervisor.plugin_lifecycle import PluginLifecycle


  @pytest.fixture
  def mock_gate() -> MagicMock:
      gate = MagicMock()
      gate.check_plugin_load = MagicMock(return_value=True)
      return gate


  @pytest.fixture
  def mock_audit() -> AsyncMock:
      return AsyncMock()


  @pytest.mark.asyncio
  async def test_start_plugin_gate_refused_emits_load_refused(
      mock_gate: MagicMock, mock_audit: AsyncMock
  ) -> None:
      mock_gate.check_plugin_load.return_value = False
      pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
      cb = CircuitBreaker(component_id="test-plugin", session_scope=None)
      result = await pl.start_plugin("test-plugin", manifest_tier="system", breaker=cb)
      assert result == "load_refused"
      mock_audit.append.assert_awaited_once()
      call_kwargs = mock_audit.append.call_args.kwargs
      assert call_kwargs["event"] == "plugin.lifecycle.load_refused"


  @pytest.mark.asyncio
  async def test_crash_increments_breaker(mock_gate: MagicMock, mock_audit: AsyncMock) -> None:
      pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
      cb = CircuitBreaker(component_id="test-plugin", session_scope=None)
      import datetime as dt
      base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
      for i in range(3):
          await pl.on_crash(
              "test-plugin",
              exception_type="SubprocessExitedError",
              exit_code=1,
              signal=None,
              restart_count=i,
              breaker=cb,
              now=base + dt.timedelta(seconds=i * 60),
          )
      assert cb.state == BreakerState.OPEN
  ```

  Run → ImportError.

  **Implementation** (`src/alfred/supervisor/plugin_lifecycle.py`):

  ```python
  """Plugin lifecycle coordination for the supervisor.

  Owns start_plugin() (gate check + audit on load_refused) and on_crash()
  (breaker.record_failure + audit row). The Supervisor class drives both
  from its asyncio.TaskGroup restart loop.
  """

  from __future__ import annotations

  import datetime as dt
  from typing import Literal

  import structlog

  from alfred.audit.audit_row_schemas import (
      PLUGIN_LIFECYCLE_CRASHED_FIELDS,
      PLUGIN_LIFECYCLE_FIELDS,
      PLUGIN_LIFECYCLE_QUARANTINED_FIELDS,
  )
  from alfred.supervisor.breaker import BreakerState, CircuitBreaker

  _log = structlog.get_logger(__name__)


  class PluginLifecycle:
      """Coordinates gate check, audit rows, and breaker updates for plugin lifecycle events."""

      def __init__(self, *, gate: object, audit: object) -> None:
          self._gate = gate
          self._audit = audit

      async def start_plugin(
          self,
          plugin_id: str,
          manifest_tier: str,
          breaker: CircuitBreaker,
      ) -> Literal["loaded", "load_refused"]:
          """Check the capability gate and emit the appropriate lifecycle audit row.

          Returns "load_refused" if the gate denies the plugin; returns "loaded"
          if the gate permits. Does NOT spawn the subprocess — that is the
          Supervisor's TaskGroup responsibility.
          """
          if not self._gate.check_plugin_load(  # type: ignore[attr-defined]
              plugin_id=plugin_id, manifest_tier=manifest_tier
          ):
              # CR round-2 fix: use append_schema with the typed PLUGIN_LIFECYCLE_FIELDS
              # constant + schema_name kwarg (PR-S3-0a cceafbd hardening) so the
              # symmetric missing/extra-field guard fires on subject drift.
              await self._audit.append_schema(  # type: ignore[attr-defined]
                  fields=PLUGIN_LIFECYCLE_FIELDS,
                  schema_name="PLUGIN_LIFECYCLE_FIELDS",
                  event="plugin.lifecycle.load_refused",
                  actor_user_id="system",
                  actor_persona="supervisor",
                  subject={
                      "plugin_id": plugin_id,
                      "manifest_subscriber_tier": manifest_tier,
                      "manifest_version": 1,
                      "sandbox_profile": "unknown",
                      "exit_code": None,
                      "signal": None,
                      "restart_count": 0,
                      "breaker_state": breaker.state.value,
                      "correlation_id": None,
                  },
                  trust_tier_of_trigger="T0",
                  result="load_refused",
                  cost_estimate_usd=0.0,
                  cost_actual_usd=0.0,
              )
              return "load_refused"

          # CR round-2 fix: typed emit via append_schema + schema_name (cceafbd contract).
          await self._audit.append_schema(  # type: ignore[attr-defined]
              fields=PLUGIN_LIFECYCLE_FIELDS,
              schema_name="PLUGIN_LIFECYCLE_FIELDS",
              event="plugin.lifecycle.loaded",
              actor_user_id="system",
              actor_persona="supervisor",
              subject={
                  "plugin_id": plugin_id,
                  "manifest_subscriber_tier": manifest_tier,
                  "manifest_version": 1,
                  "sandbox_profile": "unknown",
                  "exit_code": None,
                  "signal": None,
                  "restart_count": 0,
                  "breaker_state": breaker.state.value,
                  "correlation_id": None,
              },
              trust_tier_of_trigger="T0",
              result="success",
              cost_estimate_usd=0.0,
              cost_actual_usd=0.0,
          )
          return "loaded"

      async def on_crash(
          self,
          plugin_id: str,
          *,
          exception_type: str,
          exit_code: int | None,
          signal: int | None,
          restart_count: int,
          breaker: CircuitBreaker,
          now: dt.datetime | None = None,
      ) -> None:
          """Record a plugin crash: update the breaker and emit audit rows.

          exception_type: Python type name only — never str(exc) or exc.args
          (spec §5.6: no T3 fragment risk in crash audit rows).
          """
          breaker.record_failure(exception_type, now=now)
          audit_event = (
              "plugin.lifecycle.quarantined"
              if breaker.state == BreakerState.OPEN
              else "plugin.lifecycle.crashed"
          )
          base_subject: dict[str, object] = {
              "plugin_id": plugin_id,
              "manifest_subscriber_tier": "system",
              "manifest_version": 1,
              "sandbox_profile": "unknown",
              "exit_code": exit_code,
              "signal": signal,
              "restart_count": restart_count,
              "breaker_state": breaker.state.value,
              "correlation_id": None,
          }
          # CR round-2 fix: append_schema (not append) per cross-PR Cluster-4 contract
          # + PR-S3-0a cceafbd (schema_name kwarg, symmetric missing/extra-field guard).
          # PLUGIN_LIFECYCLE_QUARANTINED_FIELDS covers the OPEN-breaker quarantine row
          # (adds kill_succeeded / quarantine_reason / trip_count per PR-S3-0a schema);
          # PLUGIN_LIFECYCLE_CRASHED_FIELDS covers the still-CLOSED-breaker crash row
          # (adds exception_type per spec §5.6 — Python type name only, never str(exc)).
          if breaker.state == BreakerState.OPEN:
              await self._audit.append_schema(  # type: ignore[attr-defined]
                  fields=PLUGIN_LIFECYCLE_QUARANTINED_FIELDS,
                  schema_name="PLUGIN_LIFECYCLE_QUARANTINED_FIELDS",
                  event=audit_event,
                  actor_user_id="system",
                  actor_persona="supervisor",
                  subject=base_subject | {
                      "kill_succeeded": True,
                      "quarantine_reason": "circuit_breaker_open",
                      "trip_count": breaker.trip_count,
                  },
                  trust_tier_of_trigger="T0",
                  result="quarantined",
                  cost_estimate_usd=0.0,
                  cost_actual_usd=0.0,
              )
          else:
              await self._audit.append_schema(  # type: ignore[attr-defined]
                  fields=PLUGIN_LIFECYCLE_CRASHED_FIELDS,
                  schema_name="PLUGIN_LIFECYCLE_CRASHED_FIELDS",
                  event=audit_event,
                  actor_user_id="system",
                  actor_persona="supervisor",
                  subject=base_subject | {"exception_type": exception_type},
                  trust_tier_of_trigger="T0",
                  result="crashed",
                  cost_estimate_usd=0.0,
                  cost_actual_usd=0.0,
              )
  ```

  Run: `uv run pytest tests/unit/supervisor/test_action_timeout_taskgroup_cancellation.py -q` → plugin lifecycle tests pass.

  Commit:

  ```
  git commit -m "feat(supervisor): PluginLifecycle — start_plugin + on_crash with audit rows (#TBD-slice3)"
  ```

---

### Component E: Deadline + orchestrator wiring

- [ ] **Task 11 — `deadline.py` — `asyncio.timeout` wrapper.**
  Files: Create `src/alfred/supervisor/deadline.py`.

  **Key design decisions (core-002, core-003, core-005, err-006):**

  - **Catch only `asyncio.TimeoutError`** (core-002). Python 3.11+ `asyncio.timeout()` converts its internal cancel into `TimeoutError` before raising out of the `async with` block. `CancelledError` from an operator/system cancel must propagate untouched so the orchestrator's existing `except CancelledError` arm handles it. No wall-clock heuristic.
  - **Emit the audit row OUTSIDE `session_scope`** (core-003). Task 12 wires `DeadlineWrapper.run` inside `session_scope`. On timeout the session is rolled back immediately; the `supervisor.action_timeout` row must go to an **autocommit** audit writer injected separately from the session-scoped writer, or be emitted after re-raising `TimeoutError` (the orchestrator catches `TimeoutError` in a new arm that writes the row outside the rolled-back session). See Task 12 for the orchestrator-side wiring.
  - **Do NOT forward `_user_id`/`_correlation_id` to `fn`** (core-005). These are keyword-only parameters consumed by `DeadlineWrapper.run` and explicitly excluded from `**kwargs` forwarded to `fn`. See the `_user_id`/`_correlation_id` naming convention below.
  - **Re-raise `TimeoutError`, not `CancelledError`** — the orchestrator's new `except asyncio.TimeoutError` arm (Task 12) emits the audit row and then re-raises `CancelledError` to trigger rollback. This keeps the roles clean: `DeadlineWrapper` is a pure timing wrapper; the orchestrator handles audit.
  - **Audit write failure is NOT swallowed** (err-006). `_emit_timeout_row` does not have a bare `except Exception: log.error(...)` fallback. Either the write succeeds or the exception propagates to the orchestrator, which already has a structured error-handling arm.

  **Failing test** (`tests/unit/supervisor/test_action_timeout_taskgroup_cancellation.py` — deadline portion):

  ```python
  """deadline.py: asyncio.timeout wrapper re-raises TimeoutError, never misclassifies cancel."""

  from __future__ import annotations

  import asyncio
  from unittest.mock import AsyncMock

  import pytest


  @pytest.mark.asyncio
  async def test_deadline_fires_raises_timeout_error() -> None:
      """asyncio.timeout fires → DeadlineWrapper re-raises asyncio.TimeoutError (not CancelledError)."""
      from alfred.supervisor.deadline import DeadlineWrapper

      wrapper = DeadlineWrapper(deadline_seconds=0.001)

      async def slow_fn() -> str:
          await asyncio.sleep(10)
          return "done"

      with pytest.raises(asyncio.TimeoutError):
          await wrapper.run(slow_fn, _user_id="user-1", _correlation_id="corr-1")


  @pytest.mark.asyncio
  async def test_operator_cancel_propagates_cancelled_error_not_timeout() -> None:
      """Operator-initiated CancelledError passes through DeadlineWrapper unchanged (core-002)."""
      from alfred.supervisor.deadline import DeadlineWrapper

      wrapper = DeadlineWrapper(deadline_seconds=30.0)

      async def cancellable_fn() -> str:
          raise asyncio.CancelledError()

      with pytest.raises(asyncio.CancelledError):
          await wrapper.run(cancellable_fn, _user_id="u", _correlation_id="c")


  @pytest.mark.asyncio
  async def test_deadline_user_id_not_forwarded_to_fn() -> None:
      """_user_id/_correlation_id kwargs are consumed by wrapper, not forwarded to fn (core-005)."""
      from alfred.supervisor.deadline import DeadlineWrapper

      received_kwargs: dict = {}

      async def recorder(**kw: object) -> str:
          received_kwargs.update(kw)
          return "ok"

      wrapper = DeadlineWrapper(deadline_seconds=5.0)
      await wrapper.run(recorder, x=1, _user_id="u", _correlation_id="c")
      assert "_user_id" not in received_kwargs
      assert "_correlation_id" not in received_kwargs
      assert received_kwargs == {"x": 1}


  @pytest.mark.asyncio
  async def test_deadline_success_returns_result() -> None:
      from alfred.supervisor.deadline import DeadlineWrapper

      wrapper = DeadlineWrapper(deadline_seconds=5.0)

      async def fast_fn() -> str:
          return "done"

      result = await wrapper.run(fast_fn, _user_id="u", _correlation_id="c")
      assert result == "done"
  ```

  Run → ImportError.

  **Implementation** (`src/alfred/supervisor/deadline.py`):

  ```python
  """Per-orchestrator-action deadline enforcement (spec §10.5).

  DeadlineWrapper wraps a callable with asyncio.timeout(deadline_seconds).
  When the deadline fires it re-raises asyncio.TimeoutError — NOT CancelledError.
  The orchestrator's new `except asyncio.TimeoutError` arm (Orchestrator.handle_user_message
  Task 12) emits the supervisor.action_timeout audit row OUTSIDE session_scope (core-003)
  and then re-raises CancelledError to trigger the existing rollback arm.

  Operator/system-initiated CancelledError passes through DeadlineWrapper unchanged
  so the orchestrator's existing `except CancelledError` path handles it with no
  spurious supervisor.action_timeout row (core-002).
  """

  from __future__ import annotations

  import asyncio
  import time
  from collections.abc import Awaitable, Callable
  from typing import Any, TypeVar

  _R = TypeVar("_R")


  class DeadlineWrapper:
      """Wraps an async callable with a per-action deadline.

      _user_id and _correlation_id are required keyword arguments consumed by
      the wrapper for future observability wiring. They are stripped from **kwargs
      before calling fn so fn does not receive them (core-005).

      On asyncio.TimeoutError the wrapper re-raises it. The orchestrator catches
      TimeoutError, emits the supervisor.action_timeout audit row with an
      autocommit writer (outside the rolled-back session), then re-raises
      CancelledError. This keeps audit-write safety and rollback semantics clean (core-003).
      """

      def __init__(self, *, deadline_seconds: float = 30.0) -> None:
          self._deadline_seconds = deadline_seconds

      async def run(
          self,
          fn: Callable[..., Awaitable[_R]],
          /,
          *args: Any,
          _user_id: str,
          _correlation_id: str,
          **kwargs: Any,
      ) -> _R:
          """Call fn(*args, **kwargs) under a deadline.

          _user_id and _correlation_id are consumed here; fn receives only *args/**kwargs.
          Raises asyncio.TimeoutError on deadline expiry (core-002: never misclassifies
          operator-cancel as timeout). Lets CancelledError propagate untouched.
          """
          async with asyncio.timeout(self._deadline_seconds):
              return await fn(*args, **kwargs)
  ```

  The audit-row emission is the orchestrator's responsibility (Task 12).

  Run: `uv run pytest tests/unit/supervisor/test_action_timeout_taskgroup_cancellation.py -q` → deadline tests pass.

  Commit:

  ```
  git commit -m "feat(supervisor/deadline): DeadlineWrapper — TimeoutError-only, no audit side-effect (#TBD-slice3)"
  ```

---

- [ ] **Task 12 — Wire deadline into `Orchestrator.handle_user_message`.**
  Files: Modify `src/alfred/orchestrator/core.py`.

  **Design note (core-002, core-003):** `asyncio.timeout` sits **inside** `session_scope` per spec §10.5 so the existing `CancelledError` rollback arm fires. But the `supervisor.action_timeout` audit row must land **outside** the rolled-back transaction. The fix: a new `except asyncio.TimeoutError` arm catches the `TimeoutError` re-raised by `DeadlineWrapper.run`, writes the audit row with a separate **autocommit** writer (not the session-scoped writer), then re-raises `CancelledError` to trigger the existing rollback arm. The two rows — `supervisor.action_timeout` and `orchestrator.turn result=cancelled` — are independent writes.

  **Failing test** (add to `test_action_timeout_taskgroup_cancellation.py`):

  ```python
  @pytest.mark.asyncio
  async def test_orchestrator_timeout_emits_both_audit_rows() -> None:
      """Timeout fires: supervisor.action_timeout row (autocommit) + orchestrator.turn result=cancelled row.

      Implements test-001: replaces the placeholder with a real assertion.
      """
      from alfred.orchestrator.core import Orchestrator

      audit_calls: list[str] = []

      class SpyAudit:
          async def append(self, **kwargs: object) -> None:
              audit_calls.append(str(kwargs.get("event")))

      class FakeSessionScope:
          """Simulates a session_scope that always triggers CancelledError rollback."""
          async def __aenter__(self):
              return self
          async def __aexit__(self, exc_type, exc, tb):
              return False  # do not suppress exceptions
          async def rollback(self): ...
          async def commit(self): ...

      # Construct minimal orchestrator with near-zero deadline and spy audit
      orc = Orchestrator.__new__(Orchestrator)
      orc._deadline_wrapper = __import__("alfred.supervisor.deadline", fromlist=["DeadlineWrapper"]).DeadlineWrapper(deadline_seconds=0.001)
      orc._audit = SpyAudit()
      orc._autocommit_audit = SpyAudit()  # separate writer for the timeout row
      orc._session_scope = FakeSessionScope

      async def slow_turn(**_kw: object) -> str:
          await asyncio.sleep(10)
          return "done"

      orc._handle_turn = slow_turn  # type: ignore[assignment]
      orc._audit_cancellation = AsyncMock()

      with pytest.raises(asyncio.CancelledError):
          await orc.handle_user_message.__wrapped__(orc, user=MagicMock(slug="u1"), content=MagicMock(), working_memory=MagicMock())

      assert "supervisor.action_timeout" in audit_calls
      orc._audit_cancellation.assert_awaited_once()
  ```

  Run → failure (orchestrator not yet wired).

  **Implementation** (modify `src/alfred/orchestrator/core.py`):

  Add `deadline_seconds: float = 30.0` to `Orchestrator.__init__` signature. Add a second audit writer (`self._autocommit_audit`) constructed from a separate autocommit session factory for timeout rows. Wire:

  ```python
  from alfred.supervisor.deadline import DeadlineWrapper

  # In __init__:
  self._deadline_wrapper = DeadlineWrapper(deadline_seconds=deadline_seconds)
  # self._autocommit_audit = AuditWriter(autocommit_session_scope) — wired in the same init

  async def handle_user_message(
      self,
      user: UserLike,
      content: TaggedContent[T2],
      working_memory: WorkingMemory,
  ) -> str:
      trace_id = str(uuid.uuid4())
      async with self._session_scope() as session:
          try:
              return await self._deadline_wrapper.run(
                  self._handle_turn,
                  session,
                  user=user,
                  content=content,
                  working_memory=working_memory,
                  trace_id=trace_id,
                  _user_id=user.slug,          # consumed by DeadlineWrapper, not forwarded
                  _correlation_id=trace_id,    # consumed by DeadlineWrapper, not forwarded
              )
          except asyncio.TimeoutError:
              # Emit supervisor.action_timeout row OUTSIDE the rolled-back session (core-003)
              await self._emit_supervisor_timeout_row(
                  user_id=user.slug,
                  correlation_id=trace_id,
                  deadline_seconds=self._deadline_wrapper._deadline_seconds,
              )
              await session.rollback()
              # CR-round-4 sec-001 fix: emit cancellation row via the AUTOCOMMIT writer,
              # not the session-bound `_audit_cancellation()`. The session-bound writer
              # opens a NEW transaction; the `except BaseException` rollback at L1458
              # would then destroy the orchestrator.turn row before commit. The
              # autocommit writer flushes the row in its own session that the outer
              # rollback can't reach. core-003 invariant preserved.
              await self._emit_orchestrator_turn_cancelled_row(
                  user_id=user.slug,
                  trace_id=trace_id,
                  phase="turn_timeout",
              )
              raise asyncio.CancelledError("deadline expired") from None
          except asyncio.CancelledError:
              # External cancellation (not timeout-derived). Session is alive; the
              # session-bound _audit_cancellation flushes inside the active txn
              # which we then roll back — the row is intentionally tied to the
              # rolled-back work and is lost on rollback. That's the correct
              # semantic for "user cancelled mid-turn; nothing committed."
              await self._audit_cancellation(user=user, trace_id=trace_id, phase="turn_cancelled")
              await session.rollback()
              raise
          except BaseException:
              await session.rollback()
              raise

  async def _emit_supervisor_timeout_row(
      self,
      *,
      user_id: str,
      correlation_id: str,
      deadline_seconds: float,
  ) -> None:
      """Write supervisor.action_timeout audit row via autocommit writer (core-003)."""
      await self._autocommit_audit.append(
          event="supervisor.action_timeout",
          actor_user_id=user_id,
          actor_persona="supervisor",
          subject={
              "user_id": user_id,
              "deadline_seconds": deadline_seconds,
              "phase_at_timeout": "unknown",  # Slice 4+: resolve from OTel span
              "correlation_id": correlation_id,
          },
          trust_tier_of_trigger="T0",
          result="cancelled",
          cost_estimate_usd=0.0,
          cost_actual_usd=0.0,
      )
  ```

  Run: `uv run pytest tests/unit/supervisor/ -q && uv run pytest tests/unit/orchestrator/ -q` → all pass.

  Commit:

  ```
  git commit -m "feat(orchestrator): wire DeadlineWrapper — timeout row via autocommit writer outside session (#TBD-slice3)"
  ```

---

### Component F: Observability

- [ ] **Task 13 — `observability.py` — Prometheus histogram.**
  Files: Create `src/alfred/supervisor/observability.py`.

  **Failing test** (`tests/unit/supervisor/test_histograms.py`):

  ```python
  """alfred_orchestrator_action_duration_seconds histogram emitted on every outcome."""

  from __future__ import annotations

  import pytest


  def test_histogram_registered() -> None:
      from alfred.supervisor.observability import ACTION_DURATION_HISTOGRAM
      assert ACTION_DURATION_HISTOGRAM._name == "alfred_orchestrator_action_duration_seconds"


  def test_histogram_labels() -> None:
      from alfred.supervisor.observability import ACTION_DURATION_HISTOGRAM
      label_names = ACTION_DURATION_HISTOGRAM._labelnames
      assert set(label_names) == {"user_id_bucket", "action_outcome", "breaker_state"}


  def test_record_duration_success() -> None:
      from alfred.supervisor.observability import record_action_duration
      # Should not raise; just verify it calls through without error
      record_action_duration(
          duration_seconds=0.5,
          user_id_bucket="user-a",
          action_outcome="success",
          breaker_state="CLOSED",
      )


  def test_record_duration_timeout() -> None:
      from alfred.supervisor.observability import record_action_duration
      record_action_duration(
          duration_seconds=30.0,
          user_id_bucket="user-b",
          action_outcome="timeout",
          breaker_state="OPEN",
      )
  ```

  Run → ImportError.

  **Implementation** (`src/alfred/supervisor/observability.py`):

  ```python
  """Prometheus histogram + OpenTelemetry sub-spans for per-action observability.

  alfred_orchestrator_action_duration_seconds (spec §7a.3):
    Labels: user_id_bucket, action_outcome, breaker_state
    Emitted on: success, timeout, cancelled

  OTel sub-spans:
    tool.web.fetch, security.quarantined.extract, hookchain_total
    These wrap the respective dispatch calls in the orchestrator turn.
  """

  from __future__ import annotations

  from prometheus_client import Histogram
  from opentelemetry import trace

  _tracer = trace.get_tracer("alfred.supervisor")

  # perf-013: use ms-resolution buckets so p50/p90 estimates have < 5ms error
  # at typical action durations (200–800ms). Start from 5ms and cover the 30s deadline.
  ACTION_DURATION_HISTOGRAM = Histogram(
      "alfred_orchestrator_action_duration_seconds",
      "Duration of a single orchestrator action (one handle_user_message call).",
      labelnames=["user_id_bucket", "action_outcome", "breaker_state"],
      buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, float("inf")],
  )


  def record_action_duration(
      *,
      duration_seconds: float,
      user_id_bucket: str,
      action_outcome: str,
      breaker_state: str,
  ) -> None:
      """Observe duration on the histogram.

      Emitted for every action outcome: success, timeout, cancelled.
      Callers: DeadlineWrapper._emit_timeout_row and Orchestrator.handle_user_message
      success path.
      """
      ACTION_DURATION_HISTOGRAM.labels(
          user_id_bucket=user_id_bucket,
          action_outcome=action_outcome,
          breaker_state=breaker_state,
      ).observe(duration_seconds)


  def span_web_fetch() -> trace.Span:
      """OTel sub-span for tool.web.fetch dispatch (spec §7a.3)."""
      return _tracer.start_as_current_span("tool.web.fetch")


  def span_quarantine_extract() -> trace.Span:
      """OTel sub-span for security.quarantined.extract dispatch (spec §7a.3)."""
      return _tracer.start_as_current_span("security.quarantined.extract")


  def span_hookchain() -> trace.Span:
      """OTel sub-span for hook-chain total (spec §7a.3)."""
      return _tracer.start_as_current_span("hookchain_total")
  ```

  Run: `uv run pytest tests/unit/supervisor/test_histograms.py -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor/observability): Prometheus histogram + OTel sub-spans (#TBD-slice3)"
  ```

---

- [ ] **Task 14 — Wire histogram into orchestrator action path (bucketed user_id).**
  Files: Modify `src/alfred/supervisor/observability.py`; modify `src/alfred/orchestrator/core.py`.

  **Design note (perf-001):** The histogram label is named `user_id_bucket` precisely to avoid per-user cardinality explosion in Prometheus. The orchestrator must call `bucket_user_id(user_id)` before passing the label. Add `bucket_user_id()` to `observability.py`:

  ```python
  # In observability.py:
  import hashlib

  _BUCKET_COUNT: int = 256  # bounded label cardinality; documented in spec §7a.3

  def bucket_user_id(user_id: str) -> str:
      """Map a raw user_id to one of _BUCKET_COUNT stable hex buckets (perf-001).

      SHA-256(user_id) mod 256 → 2-hex-digit string. Cardinality is bounded at
      256 regardless of the number of users, preventing Prometheus OOM.
      """
      digest = hashlib.sha256(user_id.encode()).digest()
      bucket = digest[0] % _BUCKET_COUNT  # first byte mod 256
      return f"{bucket:02x}"
  ```

  The histogram is emitted by the orchestrator's `handle_user_message` success path and by `_emit_supervisor_timeout_row` (Task 12). DeadlineWrapper itself does NOT call the histogram — it is a pure timing wrapper (core-002: no audit/observability side-effects inside the wrapper).

  **Failing test** (add to `test_histograms.py`):

  ```python
  def test_bucket_user_id_bounded_cardinality() -> None:
      """bucket_user_id returns a value in [0, 255] for any user_id (perf-001)."""
      from alfred.supervisor.observability import bucket_user_id, _BUCKET_COUNT
      import hashlib

      # 1000 random-ish user_ids must produce ≤ _BUCKET_COUNT distinct buckets
      user_ids = [f"user-{i}" for i in range(1000)]
      buckets = {bucket_user_id(uid) for uid in user_ids}
      assert len(buckets) <= _BUCKET_COUNT
      # Each bucket value is a 2-hex-digit string
      for b in buckets:
          assert len(b) == 2
          int(b, 16)  # must be valid hex


  def test_record_duration_uses_bucket() -> None:
      from alfred.supervisor.observability import record_action_duration
      from unittest.mock import patch

      observed: list[str] = []

      def mock_observe(v):
          pass

      with patch("alfred.supervisor.observability.ACTION_DURATION_HISTOGRAM") as mock_hist:
          mock_hist.labels.return_value.observe = mock_observe
          record_action_duration(
              duration_seconds=0.3,
              user_id="user-12345",
              action_outcome="success",
              breaker_state="CLOSED",
          )
          call_kwargs = mock_hist.labels.call_args.kwargs
          # user_id_bucket must be bucketed, not the raw user_id
          assert call_kwargs["user_id_bucket"] != "user-12345"
          assert len(call_kwargs["user_id_bucket"]) == 2  # 2-hex-digit bucket
  ```

  Run → failure (`bucket_user_id` not present yet).

  **Implementation** (update `observability.py` `record_action_duration` to call `bucket_user_id`):

  ```python
  def record_action_duration(
      *,
      duration_seconds: float,
      user_id: str,            # raw user_id — bucketed internally (perf-001)
      action_outcome: str,
      breaker_state: str,
  ) -> None:
      """Observe duration on the histogram with a bounded user_id label."""
      ACTION_DURATION_HISTOGRAM.labels(
          user_id_bucket=bucket_user_id(user_id),
          action_outcome=action_outcome,
          breaker_state=breaker_state,
      ).observe(duration_seconds)
  ```

  Wire `record_action_duration(user_id=user.slug, ...)` into the orchestrator's success path and `_emit_supervisor_timeout_row`. Use the actual breaker state from `Supervisor.get_or_create_breaker(...)` where it is available; default to `"UNKNOWN"` when the supervisor is not wired (guards against import cycles before PR-S3-3b merge).

  Run: `uv run pytest tests/unit/supervisor/test_histograms.py -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor/observability): bucket_user_id, wire histogram with bounded cardinality (#TBD-slice3)"
  ```

---

### Component G: Capability-gate fail-closed

- [ ] **Task 15 — `test_capability_gate_outage_fail_closed.py`.**
  Files: Create `tests/unit/supervisor/test_capability_gate_outage_fail_closed.py`.

  **Test** (TDD — this drives spec §10.4, §8.1):

  ```python
  """Gate unavailable → fail-closed; supervisor.capability_gate_unavailable rows emitted."""

  from __future__ import annotations

  import asyncio
  import datetime as dt
  from unittest.mock import AsyncMock, MagicMock

  import pytest

  from alfred.supervisor.capability_monitor import CapabilityGateMonitor


  @pytest.fixture
  def mock_gate() -> MagicMock:
      gate = MagicMock()
      gate.check = MagicMock(return_value=True)
      gate.is_backing_store_available = MagicMock(return_value=True)
      return gate


  @pytest.fixture
  def audit() -> AsyncMock:
      return AsyncMock()


  @pytest.mark.asyncio
  async def test_gate_unavailable_emits_entering_fail_closed(
      mock_gate: MagicMock, audit: AsyncMock
  ) -> None:
      mock_gate.is_backing_store_available.return_value = False
      monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit, heartbeat_interval=0.01)
      await monitor.run_one_heartbeat()
      audit.append.assert_awaited()
      events = [c.kwargs["event"] for c in audit.append.call_args_list]
      assert "supervisor.capability_gate_unavailable" in events
      call = next(c for c in audit.append.call_args_list if c.kwargs["event"] == "supervisor.capability_gate_unavailable")
      assert call.kwargs["subject"]["state_transition"] == "entering_fail_closed"


  @pytest.mark.asyncio
  async def test_gate_recovery_emits_exiting_fail_closed(
      mock_gate: MagicMock, audit: AsyncMock
  ) -> None:
      monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit, heartbeat_interval=0.01)
      # First: simulate unavailable
      mock_gate.is_backing_store_available.return_value = False
      await monitor.run_one_heartbeat()
      # Then: recover
      mock_gate.is_backing_store_available.return_value = True
      await monitor.run_one_heartbeat()
      events = [c.kwargs["event"] for c in audit.append.call_args_list]
      exit_events = [e for e in events if e == "supervisor.capability_gate_unavailable"]
      # Two rows: entering + exiting
      assert len(exit_events) == 2
      subjects = [c.kwargs["subject"] for c in audit.append.call_args_list if c.kwargs["event"] == "supervisor.capability_gate_unavailable"]
      transitions = [s["state_transition"] for s in subjects]
      assert "entering_fail_closed" in transitions
      assert "exiting_fail_closed" in transitions


  @pytest.mark.asyncio
  async def test_entering_and_exiting_rows_share_correlation_id(
      mock_gate: MagicMock, audit: AsyncMock
  ) -> None:
      """entering_fail_closed and exiting_fail_closed rows must share correlation_id (err-014)."""
      monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit, heartbeat_interval=0.01)
      mock_gate.is_backing_store_available.return_value = False
      await monitor.run_one_heartbeat()
      mock_gate.is_backing_store_available.return_value = True
      await monitor.run_one_heartbeat()
      subjects = [c.kwargs["subject"] for c in audit.append.call_args_list if c.kwargs["event"] == "supervisor.capability_gate_unavailable"]
      assert len(subjects) == 2
      # Both rows carry a non-empty correlation_id that is the same UUID
      assert subjects[0]["correlation_id"] != ""
      assert subjects[0]["correlation_id"] == subjects[1]["correlation_id"]


  @pytest.mark.asyncio
  async def test_denied_dispatch_count_rolled_into_exiting_row(
      mock_gate: MagicMock, audit: AsyncMock
  ) -> None:
      """denied_dispatch_count in the exiting row matches actual denials (err-015).

      Spec §10.4 requires per-dispatch denied rows AND a rollup in the exiting row.
      """
      monitor = CapabilityGateMonitor(gate=mock_gate, audit=audit, heartbeat_interval=0.01)
      mock_gate.is_backing_store_available.return_value = False
      await monitor.run_one_heartbeat()

      # Simulate 3 denied dispatches during fail-closed
      for _ in range(3):
          monitor.record_denied_dispatch()

      mock_gate.is_backing_store_available.return_value = True
      await monitor.run_one_heartbeat()

      exiting_subject = next(
          c.kwargs["subject"]
          for c in audit.append.call_args_list
          if c.kwargs["event"] == "supervisor.capability_gate_unavailable"
          and c.kwargs["subject"]["state_transition"] == "exiting_fail_closed"
      )
      assert exiting_subject["denied_dispatch_count"] == 3
  ```

  Run → ImportError (CapabilityGateMonitor not created yet).

  Commit: do NOT commit yet — add to next task.

---

- [ ] **Task 16 — `capability_monitor.py` implementation.**
  Files: Create `src/alfred/supervisor/capability_monitor.py`.

  **Implementation**:

  ```python
  """CapabilityGateMonitor — heartbeat loop for RealGate backing-store health.

  Emits one supervisor.capability_gate_unavailable row per state-transition
  (entering fail-closed AND exiting fail-closed). Per-dispatch denied rows
  are rate-limited at 1/sec/plugin_id in the RealGate itself (spec §8.1).

  In OPEN state (backing store unavailable), all new dispatches are denied
  immediately. In-process subscribers are also denied after 60s window (spec §8.1).
  """

  from __future__ import annotations

  import asyncio
  import datetime as dt

  import structlog

  from alfred.audit.audit_row_schemas import SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS
  from alfred.i18n.translator import t

  _log = structlog.get_logger(__name__)

  _FAIL_CLOSED_WINDOW_SECONDS: float = 60.0  # deny in-process after this window (spec §8.1)


  class CapabilityGateMonitor:
      """Monitors the capability gate's backing store and emits state-transition audit rows."""

      def __init__(
          self,
          *,
          gate: object,
          audit: object,
          heartbeat_interval: float = 5.0,
      ) -> None:
          self._gate = gate
          self._audit = audit
          self._heartbeat_interval = heartbeat_interval
          self._in_fail_closed: bool = False
          self._fail_closed_since: dt.datetime | None = None
          self._denied_dispatch_count: int = 0

      def record_denied_dispatch(self) -> None:
          """Increment denied_dispatch_count. Call from RealGate.check() when fail-closed denies."""
          if self._in_fail_closed:
              self._denied_dispatch_count += 1

      async def run_one_heartbeat(self) -> None:
          """Run a single heartbeat check. Called by Supervisor's heartbeat task."""
          available: bool = self._gate.is_backing_store_available()  # type: ignore[attr-defined]
          if not available and not self._in_fail_closed:
              self._in_fail_closed = True
              self._fail_closed_since = dt.datetime.now(dt.UTC)
              self._denied_dispatch_count = 0
              self._fail_closed_correlation_id: str | None = None  # set in _emit_transition
              await self._emit_transition("entering_fail_closed", backing_store_error_type="unavailable")
          elif available and self._in_fail_closed:
              self._in_fail_closed = False
              denied = self._denied_dispatch_count
              self._denied_dispatch_count = 0
              await self._emit_transition("exiting_fail_closed", denied_count=denied)

      async def _emit_transition(
          self,
          transition: str,
          *,
          backing_store_error_type: str = "",
          denied_count: int = 0,
      ) -> None:
          # err-014: generate a correlation_id per emission; entering/exiting rows
          # for the same outage share _fail_closed_correlation_id.
          import uuid as _uuid
          if transition == "entering_fail_closed":
              self._fail_closed_correlation_id = str(_uuid.uuid4())
          correlation_id = getattr(self, "_fail_closed_correlation_id", None) or str(_uuid.uuid4())
          subject: dict[str, object] = {
              "state_transition": transition,
              "denied_dispatch_count": denied_count,
              "backing_store_error_type": backing_store_error_type,
              "correlation_id": correlation_id,
          }
          await self._audit.append(  # type: ignore[attr-defined]
              event="supervisor.capability_gate_unavailable",
              actor_user_id="system",
              actor_persona="supervisor",
              subject=subject,
              trust_tier_of_trigger="T0",
              result="fault",
              cost_estimate_usd=0.0,
              cost_actual_usd=0.0,
          )
  ```

  Run: `uv run pytest tests/unit/supervisor/test_capability_gate_outage_fail_closed.py -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor): CapabilityGateMonitor — fail-closed state-transition audit rows (#TBD-slice3)"
  ```

---

### Component H: Supervisor core

- [ ] **Task 17 — `Supervisor` class + `__init__.py`.**
  Files: Create `src/alfred/supervisor/core.py`; create `src/alfred/supervisor/__init__.py`.

  **Failing test** (add to existing test files — just import check):

  ```python
  def test_supervisor_importable() -> None:
      from alfred.supervisor import Supervisor, BreakerState, CircuitBreaker
      assert Supervisor is not None
  ```

  **Implementation** (`src/alfred/supervisor/core.py`):

  ```python
  """Supervisor — top-level coordinator for plugin lifecycle and circuit breakers.

  Supervisor.start() opens an asyncio.TaskGroup. Each supervised plugin's
  stdio-reader task joins that group. On shutdown, cancelling the group
  cascade-cancels all reader tasks, which SIGTERM each subprocess with a
  bounded grace period (5s) then SIGKILL (spec §10.5).
  """

  from __future__ import annotations

  import asyncio
  import datetime as dt
  import uuid
  from collections.abc import Callable, Coroutine
  from contextlib import AbstractAsyncContextManager
  from typing import TYPE_CHECKING, Any

  import structlog

  from alfred.audit.audit_row_schemas import SUPERVISOR_BREAKER_RESET_FIELDS
  from alfred.supervisor.breaker import BreakerState, CircuitBreaker
  from alfred.supervisor.capability_monitor import CapabilityGateMonitor
  from alfred.supervisor.errors import BreakStateError, QuarantinedUnavailable
  from alfred.supervisor.plugin_lifecycle import PluginLifecycle

  if TYPE_CHECKING:
      from sqlalchemy.ext.asyncio import AsyncSession

  _log = structlog.get_logger(__name__)


  class Supervisor:
      """Owns all plugin circuit breakers and the supervision TaskGroup.

      Construct with a session_scope factory (same pool as the orchestrator),
      a capability gate, and an audit writer. Call start() at bootstrap to
      open the TaskGroup; call stop() at shutdown to cancel all tasks.
      """

      def __init__(
          self,
          *,
          session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
          gate: object,
          audit: object,
      ) -> None:
          self._session_scope = session_scope
          self._gate = gate
          self._audit = audit
          self._breakers: dict[str, CircuitBreaker] = {}
          self._lifecycle = PluginLifecycle(gate=gate, audit=audit)
          self._capability_monitor = CapabilityGateMonitor(gate=gate, audit=audit)
          self._task_group: asyncio.TaskGroup | None = None
          # start/stop lifecycle state (core-001)
          self._run_task: asyncio.Task[None] | None = None
          self._shutdown_event: asyncio.Event = asyncio.Event()
          self._started_event: asyncio.Event = asyncio.Event()
          self._register_hookpoints()

      async def start(self) -> None:
          """Open the asyncio.TaskGroup and begin supervising. Call once at bootstrap.

          Spawns an internal `_run()` task that holds the TaskGroup open until
          `_shutdown_event` is set. Plugin tasks are added via `register_plugin_task()`
          which calls `self._task_group.create_task(coro)` while the group is active.

          Design (core-001): `asyncio.TaskGroup()` must be entered with `async with`
          before any `create_task()` calls. A long-lived runner coroutine holds the
          group open until stop() sets the shutdown event.
          """
          if self._run_task is not None:
              raise RuntimeError("Supervisor.start() called twice")
          self._shutdown_event = asyncio.Event()
          self._run_task = asyncio.get_running_loop().create_task(self._run())
          # Wait until _run() has entered the TaskGroup and set _task_group
          await self._started_event.wait()
          _log.info("supervisor.started")

      async def _run(self) -> None:
          """Hold the TaskGroup open until _shutdown_event is set."""
          async with asyncio.TaskGroup() as tg:
              self._task_group = tg
              self._started_event.set()
              await self._shutdown_event.wait()

      async def stop(self) -> None:
          """Set the shutdown event; wait for all supervised tasks to finish (err-019).

          After the TaskGroup drains, persist all breaker states and emit the
          supervisor.lifecycle.stopped audit row.
          """
          if self._run_task is None:
              return
          _log.info("supervisor.stopping")
          self._shutdown_event.set()
          try:
              await asyncio.wait_for(self._run_task, timeout=10.0)
          except asyncio.TimeoutError:
              self._run_task.cancel()
              _log.warning("supervisor.stop_timeout_force_cancel")
          # Persist breaker states to Postgres
          async with self._session_scope() as session:
              for breaker in self._breakers.values():
                  await breaker.save_to_db(session)
              await session.commit()
          await self._audit.append(  # type: ignore[attr-defined]
              event="supervisor.lifecycle.stopped",
              actor_user_id="system",
              actor_persona="supervisor",
              subject={"component_count": len(self._breakers)},
              trust_tier_of_trigger="T0",
              result="success",
              cost_estimate_usd=0.0,
              cost_actual_usd=0.0,
          )
          self._run_task = None
          self._task_group = None

      def register_plugin_task(
          self,
          coro: Coroutine[Any, Any, None],
      ) -> asyncio.Task[None]:
          """Spawn a plugin task inside the active TaskGroup (core-001).

          Must be called after start() has set self._task_group. Raises RuntimeError
          if called before start() or after stop(). The TaskGroup owns the task's
          lifetime — on shutdown the group cancels all tasks in it.
          """
          if self._task_group is None:
              raise RuntimeError("register_plugin_task() called before Supervisor.start()")
          return self._task_group.create_task(coro)

      def get_or_create_breaker(self, component_id: str) -> CircuitBreaker:
          """Return the breaker for component_id, creating it if absent."""
          if component_id not in self._breakers:
              self._breakers[component_id] = CircuitBreaker(
                  component_id=component_id,
                  session_scope=self._session_scope,
              )
          return self._breakers[component_id]

      async def reset_breaker(
          self,
          component_id: str,
          *,
          operator_user_id: str,
      ) -> None:
          """Operator-triggered breaker reset (spec §10.8).

          Emits supervisor.breaker.reset audit row with operator attribution.
          Persists new CLOSED state to Postgres.
          """
          breaker = self._breakers.get(component_id)
          if breaker is None:
              from alfred.supervisor.errors import SupervisorError
              raise SupervisorError(f"No supervised component with id={component_id!r}")

          old_state = breaker.state.value
          breaker.reset()

          correlation_id = str(uuid.uuid4())
          await self._audit.append(  # type: ignore[attr-defined]
              event="supervisor.breaker.reset",
              actor_user_id=operator_user_id,
              actor_persona="supervisor",
              subject={
                  "component_id": component_id,
                  "old_state": old_state,
                  "new_state": "CLOSED",
                  "trip_count": breaker.trip_count,
                  "operator_user_id": operator_user_id,
                  "correlation_id": correlation_id,
              },
              trust_tier_of_trigger="T1",  # operator-tier T1 command (spec §3.6)
              result="success",
              cost_estimate_usd=0.0,
              cost_actual_usd=0.0,
          )

          async with self._session_scope() as session:
              await breaker.save_to_db(session)
              await session.commit()

      async def load_all_breakers(self) -> None:
          """Load all circuit breaker states from Postgres at supervisor startup."""
          async with self._session_scope() as session:
              for component_id, breaker in self._breakers.items():
                  await breaker.load_from_db(session)
  ```

  **`src/alfred/supervisor/__init__.py`**:

  ```python
  """Supervisor subsystem — circuit breakers, plugin lifecycle, per-action deadlines.

  Public surface:
    Supervisor       — top-level coordinator (start / stop / reset_breaker)
    CircuitBreaker   — three-state breaker (CLOSED / OPEN / HALF_OPEN)
    BreakerState     — enum of breaker states
    SupervisorError  — root exception
    BreakStateError  — invalid state-transition exception
    QuarantinedUnavailable — raised when quarantined-LLM breaker is OPEN

  Dependencies: PR-S3-0a (audit_row_schemas), PR-S3-0b (migrations + i18n),
  PR-S3-3a (AlfredPluginSession contract). See plan:
  docs/superpowers/plans/2026-05-31-slice-3-pr-s3-3b-supervisor.md
  """

  from alfred.supervisor.breaker import BreakerState, CircuitBreaker
  from alfred.supervisor.core import Supervisor
  from alfred.supervisor.errors import BreakStateError, QuarantinedUnavailable, SupervisorError

  __all__ = [
      "BreakerState",
      "BreakStateError",
      "CircuitBreaker",
      "QuarantinedUnavailable",
      "Supervisor",
      "SupervisorError",
  ]
  ```

  Run: `uv run pytest tests/unit/supervisor/ -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor): Supervisor core class + __init__.py public surface (#TBD-slice3)"
  ```

---

### ~~Component I: CLI commands~~ — DELETED (devex-001 / rvw-002)

**Task 18 deleted.** `alfred supervisor status` and `alfred supervisor reset` CLI commands are exclusively owned by PR-S3-6, which is the canonical Typer-based CLI PR for all Slice-3 surface area. PR-S3-3b ships only the `Supervisor` class and its `reset_breaker()` method; the CLI wires against it. Shipping a Click-based duplicate here would silently overwrite the Typer-based PR-S3-6 commands on whichever merges second (devex-001). The hardcoded `operator_user_id = "operator"` placeholder in the deleted CLI would also have shipped wrong audit attribution (rvw-006).

**File table update:** `src/alfred/cli/supervisor.py` is PR-S3-6-owned; remove from this PR's creation list (already updated in §3).

---

- [ ] **Task 19 — `supervisor.action_timeout` hookpoint — registered in `Supervisor.__init__`.**
  Files: Modify `src/alfred/supervisor/core.py` (`_register_hookpoints`).

  **Design note (core-010):** All supervisor hookpoints — including `supervisor.action_timeout` — are registered once in `Supervisor._register_hookpoints()` called from `Supervisor.__init__`. Import-time side-effects (`_register_deadline_hookpoints()` at module level in `deadline.py`) are an anti-pattern that breaks test isolation and contradicts the Slice-2.5 hooks contract. `deadline.py` has no hookpoint-registration calls; the Supervisor owns the full registration table.

  Move `supervisor.action_timeout` from a module-level call to the `_register_hookpoints` block in Task 20. Remove any import-time registration from `deadline.py`.

  **Failing test** (add to `test_action_timeout_taskgroup_cancellation.py`):

  ```python
  def test_supervisor_action_timeout_hookpoint_registered_by_supervisor_init() -> None:
      """supervisor.action_timeout hookpoint must be registered by Supervisor.__init__,
      NOT at module-import time (core-010).
      """
      from alfred.hooks.registry import get_registry
      from unittest.mock import MagicMock
      from alfred.supervisor.core import Supervisor

      registry = get_registry()
      # Before Supervisor is instantiated, verify importing deadline.py alone does NOT register
      import alfred.supervisor.deadline  # noqa: F401
      # (If deadline.py has import-time registration this assertion would fail)

      # Instantiate Supervisor — this triggers _register_hookpoints()
      Supervisor(session_scope=MagicMock(), gate=MagicMock(), audit=MagicMock())
      meta = getattr(registry, "_hookpoint_meta", {})
      # CR round-2 fix: strict assertion — `... or True` is tautological and cannot detect
      # missing registration. The contract is "Supervisor.__init__ registers this hookpoint";
      # the test verifies the contract holds.
      assert "supervisor.action_timeout" in meta, (
          "Supervisor.__init__ must register supervisor.action_timeout hookpoint (core-010)"
      )
  ```

  Run: `uv run pytest tests/unit/supervisor/test_action_timeout_taskgroup_cancellation.py -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor): move supervisor.action_timeout hookpoint registration into Supervisor.__init__ (#TBD-slice3)"
  ```

---

- [ ] **Task 20 — Register remaining supervisor hookpoints in `core.py`.**
  Files: Modify `src/alfred/supervisor/core.py`.

  Register at `Supervisor.__init__` time (spec §14 full table for supervisor hookpoints):

  ```python
  def _register_hookpoints(self) -> None:
      """Register all supervisor hookpoints. Called once at Supervisor.__init__ (core-010).

      All hookpoints — including supervisor.action_timeout — are registered here,
      not at module-import time in individual modules. This matches the Slice-2.5
      hooks contract and keeps test isolation clean.
      """
      from alfred.hooks.registry import get_registry, SYSTEM_ONLY_TIERS, SYSTEM_OPERATOR_TIERS
      registry = get_registry()
      hookpoints = [
          ("supervisor.breaker.tripped", SYSTEM_ONLY_TIERS, False),
          ("supervisor.breaker.reset", SYSTEM_OPERATOR_TIERS, False),
          ("supervisor.action_timeout", SYSTEM_ONLY_TIERS, False),   # added: core-010
          ("plugin.lifecycle.loaded", SYSTEM_ONLY_TIERS, False),
          ("plugin.lifecycle.crashed", SYSTEM_ONLY_TIERS, False),
          ("plugin.lifecycle.quarantined", SYSTEM_ONLY_TIERS, False),
      ]
      for name, tiers, fail_closed in hookpoints:
          registry.register_hookpoint(
              name=name,
              subscribable_tiers=tiers,
              refusable_tiers=frozenset(),
              fail_closed=fail_closed,
          )
  ```

  Call `self._register_hookpoints()` at the end of `Supervisor.__init__`.

  **Test** (add to test suite):

  ```python
  def test_supervisor_registers_lifecycle_hookpoints() -> None:
      from alfred.hooks.registry import get_registry
      from unittest.mock import AsyncMock, MagicMock
      from alfred.supervisor.core import Supervisor
      registry = get_registry()
      Supervisor(session_scope=MagicMock(), gate=MagicMock(), audit=MagicMock())
      meta = getattr(registry, "_hookpoint_meta", {})
      # CR round-2 fix: strict assertions — `... or True` is tautological. Spec §14 requires
      # every supervisor hookpoint be registered in __init__; this test enforces it.
      expected_hookpoints = (
          "supervisor.breaker.tripped",
          "supervisor.breaker.reset",
          "supervisor.action_timeout",
          "plugin.lifecycle.loaded",
          "plugin.lifecycle.crashed",
          "plugin.lifecycle.quarantined",
      )
      for hp in expected_hookpoints:
          assert hp in meta, (
              f"Supervisor.__init__ must register hookpoint {hp!r} (spec §14, core-010)"
          )
  ```

  **Idempotency contract (rvw-pre-flight fix):** `_register_hookpoints()` runs once per
  `Supervisor.__init__`. Tests routinely instantiate multiple `Supervisor`s per process
  (one per test case), so `registry.register_hookpoint()` must be **idempotent for
  identical configs and only raise on conflict**. Update
  `src/alfred/hooks/registry.py::register_hookpoint`:

  ```python
  def register_hookpoint(
      self,
      *,
      name: str,
      subscribable_tiers: frozenset[TrustTier],
      refusable_tiers: frozenset[TrustTier],
      fail_closed: bool,
  ) -> None:
      """Register a hookpoint.

      Idempotent for identical (subscribable_tiers, refusable_tiers, fail_closed).
      Raises ``HookpointConfigConflict`` if a hookpoint with the same name was
      previously registered with a different configuration — this catches genuine
      drift (e.g. one module registers system-only, another registers operator) while
      letting tests reinstantiate Supervisor freely.
      """
      existing = self._hookpoints.get(name)
      if existing is not None:
          if (
              existing.subscribable_tiers == subscribable_tiers
              and existing.refusable_tiers == refusable_tiers
              and existing.fail_closed == fail_closed
          ):
              return  # identical config — no-op
          raise HookpointConfigConflict(
              f"Hookpoint {name!r} already registered with different config "
              f"(existing={existing!r}, requested=(subscribable={subscribable_tiers}, "
              f"refusable={refusable_tiers}, fail_closed={fail_closed}))"
          )
      self._hookpoints[name] = _HookpointMeta(
          subscribable_tiers=subscribable_tiers,
          refusable_tiers=refusable_tiers,
          fail_closed=fail_closed,
      )
  ```

  Cover both branches in `tests/unit/hooks/test_registry.py`:

  ```python
  def test_register_hookpoint_is_idempotent_for_same_config(registry):
      registry.register_hookpoint(
          name="supervisor.breaker.tripped",
          subscribable_tiers=SYSTEM_ONLY_TIERS,
          refusable_tiers=frozenset(),
          fail_closed=False,
      )
      # Second call with identical config: no-op, no raise.
      registry.register_hookpoint(
          name="supervisor.breaker.tripped",
          subscribable_tiers=SYSTEM_ONLY_TIERS,
          refusable_tiers=frozenset(),
          fail_closed=False,
      )

  def test_register_hookpoint_raises_on_config_conflict(registry):
      registry.register_hookpoint(
          name="supervisor.breaker.tripped",
          subscribable_tiers=SYSTEM_ONLY_TIERS,
          refusable_tiers=frozenset(),
          fail_closed=False,
      )
      with pytest.raises(HookpointConfigConflict):
          registry.register_hookpoint(
              name="supervisor.breaker.tripped",
              subscribable_tiers=SYSTEM_OPERATOR_TIERS,  # different tier set
              refusable_tiers=frozenset(),
              fail_closed=False,
          )
  ```

  Run: `uv run pytest tests/unit/supervisor/ -q` → all pass.

  Commit:

  ```
  git commit -m "feat(supervisor/core): register plugin.lifecycle.* and supervisor.breaker.* hookpoints (#TBD-slice3)"
  ```

---

### Component J: Integration test

- [ ] **Task 21 — Integration test: 3 failures trip the breaker.**
  Files: Create `tests/integration/supervisor/__init__.py`; create `tests/integration/supervisor/test_quarantined_llm_3_failures_trip.py`.

  **Implementation**:

  ```python
  """Integration test: 3 quarantined-LLM crashes within 5 min trip the breaker to OPEN.

  Uses testcontainers for real Postgres. Exercises the full stack:
  CircuitBreaker.record_failure → trip → save_to_db → load_from_db on restart.

  Spec §10.2, §10.6.
  """

  from __future__ import annotations

  import asyncio
  import datetime as dt

  import pytest
  import pytest_asyncio
  from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
  from sqlalchemy.orm import sessionmaker
  from testcontainers.postgres import PostgresContainer

  from alfred.memory.models import Base, CircuitBreakerState
  from alfred.supervisor.breaker import BreakerState, CircuitBreaker
  from alfred.supervisor.errors import QuarantinedUnavailable


  @pytest.fixture(scope="module")
  def pg_container():
      with PostgresContainer("postgres:16") as pg:
          yield pg


  @pytest_asyncio.fixture
  async def async_session(pg_container: PostgresContainer) -> AsyncSession:
      url = pg_container.get_connection_url().replace("psycopg2", "asyncpg")
      engine = create_async_engine(url, echo=False)
      async with engine.begin() as conn:
          await conn.run_sync(Base.metadata.create_all)
      factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
      async with factory() as session:
          yield session
          await session.rollback()
      await engine.dispose()


  @pytest.mark.asyncio
  async def test_three_failures_trip_and_persist(async_session: AsyncSession) -> None:
      cb = CircuitBreaker(component_id="quarantined-llm", session_scope=None)
      base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
      for i in range(3):
          cb.record_failure("SubprocessExitedError", now=base + dt.timedelta(seconds=i * 60))
      assert cb.state == BreakerState.OPEN
      assert cb.trip_count == 1

      # Persist to DB
      await cb.save_to_db(async_session)
      await async_session.commit()

      # Simulate restart: load from DB
      cb2 = CircuitBreaker(component_id="quarantined-llm", session_scope=None)
      # Recent trip (< 1h ago)
      await cb2.load_from_db(async_session, now=base + dt.timedelta(minutes=30))
      assert cb2.state == BreakerState.OPEN  # stays OPEN

      # Fourth call raises QuarantinedUnavailable immediately
      with pytest.raises(QuarantinedUnavailable):
          cb2.assert_available()


  @pytest.mark.asyncio
  async def test_restart_after_1h_rearms_breaker(async_session: AsyncSession) -> None:
      cb = CircuitBreaker(component_id="quarantined-llm-b", session_scope=None)
      base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
      for i in range(3):
          cb.record_failure("SubprocessExitedError", now=base + dt.timedelta(seconds=i * 60))
      await cb.save_to_db(async_session)
      await async_session.commit()

      cb2 = CircuitBreaker(component_id="quarantined-llm-b", session_scope=None)
      # Load 2 hours after trip
      await cb2.load_from_db(async_session, now=base + dt.timedelta(hours=2))
      assert cb2.state == BreakerState.HALF_OPEN  # re-armed


  @pytest.mark.asyncio
  async def test_supervisor_reset_via_db(async_session: AsyncSession) -> None:
      cb = CircuitBreaker(component_id="quarantined-llm-c", session_scope=None)
      cb.state = BreakerState.OPEN
      cb.trip_count = 2
      await cb.save_to_db(async_session)
      await async_session.commit()

      cb.reset()
      await cb.save_to_db(async_session)
      await async_session.commit()

      cb2 = CircuitBreaker(component_id="quarantined-llm-c", session_scope=None)
      await cb2.load_from_db(async_session)
      assert cb2.state == BreakerState.CLOSED
      assert cb2.trip_count == 2  # trip_count preserved across reset
  ```

  Run: `uv run pytest tests/integration/supervisor/ -q` → all pass with testcontainer.

  Commit:

  ```
  git commit -m "test(supervisor): integration test — 3 failures trip breaker, persisted state restore (#TBD-slice3)"
  ```

---

### Component K: Coverage gate + quality

- [ ] **Task 22 — 100% coverage gate for trust-boundary files.**
  Files: Modify `pyproject.toml`.

  The supervisor module is NOT itself a trust-boundary file (the trust boundary lives in `src/alfred/security/`). However, `deadline.py` and `breaker.py` are security-adjacent (they gate when supervisor.action_timeout fires and when plugins are quarantined).

  **Design note (core-009):** `[tool.coverage.supervisor]` is not a recognised coverage.py TOML section — coverage.py only reads `[tool.coverage.run]`, `[tool.coverage.report]`, etc. The bogus section is silently ignored, making the `fail_under = 100` claim non-binding. Drive the 100% gate through the Makefile invocation only.

  Add to `Makefile` (or `make check` target):

  ```
  uv run pytest tests/unit/supervisor/ \
    --cov=src/alfred/supervisor/breaker \
    --cov=src/alfred/supervisor/deadline \
    --cov-branch --cov-fail-under=100
  ```

  Do NOT add a `[tool.coverage.supervisor]` stanza to `pyproject.toml`.

  Run: `make check` → green.

  Commit:

  ```
  git commit -m "chore(supervisor): 100% coverage gate for breaker.py and deadline.py — Makefile only (#TBD-slice3)"
  ```

---

- [ ] **Task 23 — Full `make check` pass.**

  ```bash
  cd <repo-root>
  make check
  ```

  Expected output:

  ```
  ruff check . ✓
  ruff format --check . ✓
  mypy src/ ✓
  pyright src/ ✓
  pytest tests/unit/supervisor/ tests/unit/cli/test_supervisor_cli.py -q  [all pass]
  ```

  Fix any mypy/pyright failures (common: missing `TYPE_CHECKING` guards on SQLAlchemy imports, missing `asyncio.get_event_loop()` deprecation for Python 3.12+).

  **Python 3.12+ asyncio note:** Replace `asyncio.get_event_loop().create_task(...)` with `asyncio.get_running_loop().create_task(...)` where needed. Replace `asyncio.get_event_loop().run_until_complete(...)` in CLI with a dedicated runner.

  Commit:

  ```
  git commit -m "chore(supervisor): make check passes — mypy strict + pyright clean (#TBD-slice3)"
  ```

---

- [ ] **Task 24 — `make docs-check` pass.**

  ```bash
  cd <repo-root>
  make docs-check
  ```

  Fix any broken cross-links introduced by this PR. The plan file itself does not introduce new deep-docs; those land in PR-S3-7 per spec §17.

  Commit:

  ```
  git commit -m "chore(supervisor): make docs-check passes (#TBD-slice3)"
  ```

---

## §5 Spec Coverage Map

> **Note (devex-001/rvw-002):** `alfred supervisor status` and `alfred supervisor reset` CLI commands were deleted from this PR. They are owned by PR-S3-6.

| Spec section / sub-section | Task(s) | Finding(s) applied |
|---|---|---|
| §10.1 — `src/alfred/supervisor/` module shape | Tasks 1, 10, 11, 17 | core-001 |
| §10.2 — CircuitBreaker: 3 failures/5min → OPEN | Tasks 4, 5, 6, 7 | — |
| §10.2 — Exponential backoff restart (5s, ×2, 5min max) | Task 6 | — |
| §10.2 — HALF_OPEN probe success/failure | Task 6 | — |
| §10.3 — MCP plugin lifecycle: `start_plugin()`, `on_crash()` | Task 10 | err-001, core-004 |
| §10.3 — `plugin.lifecycle.*` audit family wiring | Tasks 10, 20 | core-010 |
| §10.4 — Capability-gate fail-closed on backing-store outage | Tasks 15, 16 | err-014, err-015 |
| §10.4 — `supervisor.capability_gate_unavailable` audit rows (per state-transition) | Task 16 | err-014 |
| §10.4 — Per-dispatch denial count rolled into exiting row | Task 15 (test), Task 16 (impl) | err-015 |
| §10.5 — `asyncio.timeout(30.0)` inside `session_scope` | Task 11 | core-002 |
| §10.5 — `supervisor.action_timeout` row outside rolled-back session | Task 12 | core-003 |
| §10.5 — `asyncio.TaskGroup` for plugin stdio reader tasks + `register_plugin_task()` | Task 17 | core-001 |
| §10.5 — SIGTERM→SIGKILL on supervisor shutdown | Task 17 | err-019 |
| §10.5 — `supervisor.lifecycle.stopped` audit row on clean shutdown | Task 17 | err-019 |
| §10.6 — `circuit_breakers` Postgres table (migration 0010) | Tasks 2, 3 | — |
| §10.6 — Load state on restart; stay OPEN if `last_trip_at < 1h` | Task 8 | — |
| §10.7 — `t("orchestrator.quarantine_unavailable")` user-facing message | Task 1 | — |
| §10.8 — `alfred supervisor reset <component> --confirm` | (PR-S3-6) | devex-001, rvw-002 |
| §10.8 — `supervisor.breaker.reset` audit row with operator attribution | Task 17 | rvw-006 |
| §11.3 — `alfred supervisor status` CLI command | (PR-S3-6) | devex-001, rvw-002 |
| §11.3 — `alfred supervisor reset <component> --confirm` CLI | (PR-S3-6) | devex-001, rvw-002 |
| §13 — `SUPERVISOR_BREAKER_RESET_FIELDS` consumed from `audit_row_schemas.py` | Tasks 9, 17 | — |
| §13 — `SUPERVISOR_BREAKER_TRIPPED_FIELDS` | Task 9 | err-001 |
| §13 — `SUPERVISOR_ACTION_TIMEOUT_FIELDS` | Task 12 | core-003 |
| §13 — `SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS` | Task 16 | err-014 |
| §13 — `SUPERVISOR_CONFIG_INSECURE_FIELDS` | Task 10 (partial; full in PR-S3-3a launcher) | — |
| §14 — `supervisor.breaker.tripped` hookpoint | Tasks 9, 20 | err-001, core-004, core-010 |
| §14 — `supervisor.breaker.reset` hookpoint | Task 20 | core-010 |
| §14 — `supervisor.action_timeout` hookpoint | Tasks 19, 20 | core-010 |
| §14 — `plugin.lifecycle.loaded` hookpoint | Task 20 | core-010 |
| §14 — `plugin.lifecycle.crashed` hookpoint | Task 20 | core-010 |
| §14 — `plugin.lifecycle.quarantined` hookpoint | Task 20 | core-010 |
| §7a.3 — `alfred_orchestrator_action_duration_seconds` histogram (bounded cardinality) | Tasks 13, 14 | perf-001, perf-013 |
| §7a.3 — `bucket_user_id()` — bounded Prometheus label cardinality | Task 14 | perf-001 |
| §7a.3 — OTel sub-spans: `tool.web.fetch`, `security.quarantined.extract`, `hookchain_total` | Task 13 | — |
| §5.5 — `QuarantinedUnavailable` distinct exception | Task 1 | — |
| §5.6 — Audit fields: exception_type (type name only, never str(exc)) | Task 10 | — |
| §15.4 — `alfred supervisor status` step in upgrade runbook | (PR-S3-6 CLI implements it) | devex-001 |
| Integration: 3 failures trip breaker + persist | Task 21 | — |
| Integration: restart from Postgres restores OPEN/HALF_OPEN correctly | Task 21 | — |
| Unit: both audit rows on timeout (test-001 replacement) | Task 12 | test-001 |
| Unit: denied dispatch count in fail-closed exiting row | Task 15 | err-015 |
| Unit: correlation_id shared by entering/exiting rows | Task 15 | err-014 |

---

## §6 Quality Gates

Run these before opening the PR:

```bash
# From worktree root:
make check
# Includes: ruff check + ruff format --check + mypy src/ + pyright src/ + pytest

make docs-check
# Verifies no broken cross-links

uv run pytest tests/unit/supervisor/ -q --tb=short
uv run pytest tests/unit/cli/test_supervisor_cli.py -q --tb=short
uv run pytest tests/integration/supervisor/ -q --tb=short
# integration requires docker compose up (testcontainers)

# Trust-boundary coverage gate:
uv run coverage run -m pytest tests/unit/supervisor/ \
  --cov=src/alfred/supervisor/breaker \
  --cov=src/alfred/supervisor/deadline \
  --cov-branch --cov-fail-under=100

# Adversarial suite (touches supervisor.errors — QuarantinedUnavailable path):
uv run pytest tests/adversarial -q --tb=short

# Verify no VERIFY markers leaked:
grep -r '\[VERIFY:' docs/ && echo "LEAKED VERIFY MARKERS" && exit 1 || echo "Clean"
```

---

## §7 References

- **Spec:** [`docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`](../specs/2026-05-30-slice-3-trust-tier-completion-design.md) — §10 entire, §5.5, §5.6, §13 (supervisor audit families), §14 (hookpoint table), §7a.3, §11.3, §15.4.
- **ADR-0017** (co-merged in PR-S3-0a) — Slice-3 trust-tier completion + supervisor commitment; see `docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md`.
- **PRD §6.7** (line 324) — circuit breaker spec: 3/5min numbers.
- **PRD §7.3** — supervisor plugin lifecycle (self-healing).
- **Predecessor plans this PR depends on:**
  - [PR-S3-0a plan](2026-05-31-slice-3-index.md) — `audit_row_schemas.py` constants this plan imports.
  - [PR-S3-0b plan](2026-05-31-slice-3-index.md) — migrations 0007–0009 (0010 lands here), i18n catalog, Docker UID setup.
  - [PR-S3-3a plan](../specs/2026-05-30-slice-3-trust-tier-completion-design.md) — `AlfredPluginSession` and `PluginTransport` contracts this supervisor wraps.
- **Migration precedent:** [`src/alfred/memory/migrations/versions/0006_audit_result_hooks_values.py`](../../src/alfred/memory/migrations/versions/0006_audit_result_hooks_values.py) — downgrade pattern for destructive migrations.
- **Orchestrator contract:** [`src/alfred/orchestrator/core.py`](../../src/alfred/orchestrator/core.py) — `session_scope`, `handle_user_message`, `_audit_cancellation` — the surfaces this PR wraps without breaking.
- **Hooks contract:** [`src/alfred/hooks/registry.py`](../../src/alfred/hooks/registry.py) — `SYSTEM_ONLY_TIERS`, `SYSTEM_OPERATOR_TIERS`, `register_hookpoint`.
