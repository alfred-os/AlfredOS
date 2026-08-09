# #410 PR1 — Pool-Deadlock Fix: Three-Phase Turn + Role-Scoped Connection Pools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the orchestrator turn into three phases (Observe / Orient+Act / Persist) so no Postgres connection is ever held across the LLM provider call, with the `TurnSideEffectLedger` folded into each phase's own short-lived transaction and all Postgres pools role-scoped and budget-validated.

**Architecture:** `Orchestrator.handle_user_message` stops opening one session for the whole turn; instead Phase A (ledger user-gate + episodic user row, one sub-ms transaction), Phase B (prompt build + provider call + Act loop + all audit writes, ZERO connections held), and Phase C (ledger assistant-gate + episodic assistant row, one sub-ms transaction) each own their own `session_scope()`. `src/alfred/memory/db.py` grows a closed `ConnectionRole` enum (`TURN`/`SIDE_EFFECT`/`CONTROL`) with per-role cached engines, per-role pool parameters, a tight `idle_in_transaction_session_timeout`, and a contextvar nesting guard where `SIDE_EFFECT` is the only role permitted while `TURN` is held (the audit-durability exception, CLAUDE.md hard rule #7). `session_scope` rolls back EXPLICITLY on `BaseException` — `asyncio.CancelledError` is a `BaseException`, and a cancellation delivered mid-Phase-A/C must provably un-mark the ledger gate rather than lean on `AsyncSession.close()`'s implicit-rollback folklore; the property is proven at three tiers (Task 1 unit, Task 4 real-`task.cancel()` against Postgres, Task 6 orchestrator-level). A phase-commit failure is recorded three ways (histogram outcome, structlog error, audit row — Task 6), any failure between Phase A's commit and Phase C's commit counts the orphaned user row on its own metric (Tasks 5/6), and the three previously-unconfigured `alfred supervisor` CLI engines join the explicit CONTROL pool shape (Task 7) so no unconfigured pool remains anywhere. This supersedes §3.1 of `docs/superpowers/specs/2026-08-08-issue-410-pr1-ledger-transactional-fix-design.md` (whose one-transaction-spanning-the-provider-call mechanism was empirically shown to deadlock the pool: 16 concurrent turns, 0 succeeded); §3.2/§3.3/§3.4 of that design carry forward in the conditional/deferred forms specified below.

**Tech Stack:** Python 3.14, SQLAlchemy 2.0 async + asyncpg, Pydantic v2 / pydantic-settings, pytest + testcontainers (Postgres 18), prometheus_client, structlog.

## Global Constraints

- Work in the existing worktree `/Users/iandominey/projects/AlfredOS/.claude/worktrees/410-pr1-turn-side-effect-ledger`, branch `worktree-410-pr1-turn-side-effect-ledger`. All paths below are relative to that worktree root. Do NOT create a new worktree.
- This is a REVISION to already-committed PR1 work, not greenfield. Already landed on this branch: migration 0025 (`74991f1b`), the ledger store (`8f03df7d`), its Postgres contract test (`e660e37c`), the orchestrator gating wiring (`0a75f1ba`..`fa13d3e8`), and the design doc (`4e2c54c6`, `4a73b4ac`). Each task below states whether it modifies committed code or is net-new.
- CLAUDE.md hard rule #7 is untouched: `AuditWriter.append()` keeps opening its own independent session per call so audit rows survive caller rollback. Only WHICH pool it draws from changes (`SIDE_EFFECT` role).
- No changes to `src/alfred/security/` anywhere in this plan (the capability-gate BACKEND construction site changed is `src/alfred/cli/daemon/_gate_boot.py`, which lives in `cli/`). If any task drifts into `src/alfred/security/`, stop and run the full adversarial suite.
- `mypy --strict` + `pyright` clean on `src/`; PEP 604 unions (`X | Y`), PEP 585 builtin generics, PEP 695 generic syntax; frozen dataclasses; no `Any` without a stated reason; structlog for new log lines (event-key style, redactor already process-global — never log raw user content or secrets).
- New exception messages follow the `PostgresBackend` precedent (plain English programmer-facing invariant messages, not `t()`). The daemon Settings boundary (`_load_settings_or_die` → `_bootstrap_settings_message`) renders curated `t()` messages and deliberately NEVER interpolates raw error text (DLP) — Task 2 works WITH that contract via an error-type slug, not around it. No new operator-facing CLI strings are added by this plan (Task 2 reuses the existing `daemon.boot.settings_invalid_field` key), so no i18n catalog changes.
- Conventional Commits; every commit subject carries a literal `#410` AFTER the colon (repo CI gate). NEVER use the words `fix`/`fixes`/`closes` adjacent to `#410` anywhere in a commit message — GitHub's closing-keyword scan reads the whole message and would auto-close the epic.
- Per task: run the named tests, then `uv run ruff check <touched paths> && uv run ruff format <touched paths>` and `uv run mypy src/ && uv run pyright src/` before the commit step. Full `make check` runs once, in Task 10's final step.
- New `docs/` markdown must pass markdownlint (MD004 dash bullets, MD031/MD032 blank lines around fences/lists) — it is a required CI check.
- Integration tests need Docker running (testcontainers, `postgres:18`).

## Coverage Matrix

Primary subsystem and owning specialist per task (the implementing session
dispatches the matching engineer subagent; reviewers use this to route
findings), plus — pass-2 finding test2-2 — the key property each task's
tests exist to prove and the specific test function(s) that pin it
(property→test traceability; test paths are stated once per row, in the
first cell that names them):

| Task | Scope | Primary subsystem | Owner | Key property/invariant | Pinning test(s) |
| --- | --- | --- | --- | --- | --- |
| 1 | `memory/db.py` role registry + nesting guard + `BaseException` rollback | Memory | alfred-memory-engineer | One cached engine+pool per `(dsn, role)` with role-shaped params; only SIDE_EFFECT may nest inside a held TURN scope (per-task isolated); `session_scope` rolls back EXPLICITLY on `BaseException` incl. `CancelledError` | `test_same_url_different_roles_get_distinct_engines`, `test_turn_and_side_effect_pool_parameters_reach_create_async_engine`, `test_control_scope_inside_turn_raises`, `test_cancelled_error_rolls_back_explicitly_and_resets_the_flag`, `test_turn_scope_is_isolated_per_task_not_process_global` (tests/unit/memory/test_db.py) |
| 2 | Settings pool fields + budget validator + DLP-safe refusal surfacing | Config + CLI boundary | alfred-python-developer (validator) / alfred-devex-reviewer (refusal UX) | An over-budget pool combination is refused AT BOOT; the refusal surfaces a value-free category slug at the daemon boundary (never an operator-configured number) | `test_over_budget_combination_is_refused_at_boot` (tests/unit/config/test_settings_db_pools.py), `test_settings_error_field_name_surfaces_a_custom_slug_at_empty_loc` (tests/unit/cli/daemon/test_probe_environment_not_set.py) |
| 3 | `TurnSideEffectLedger` caller-transaction rewrite | Memory | alfred-memory-engineer | The ledger's ONLY session interaction is `execute()` on the CALLER's session — it never commits/rolls back; a genuine DB error propagates, never collapses to a boolean | `test_the_ledger_never_commits_or_rolls_back_the_callers_session`, `test_db_error_propagates_fail_loud` (tests/unit/memory/test_turn_side_effect_ledger_store.py) |
| 4 | Real-Postgres ledger contract (rollback / cancel / lock properties) | Memory + Tests | alfred-memory-engineer + alfred-test-engineer | On real Postgres the gate travels with the caller's transaction: rollback AND a real `task.cancel()` both un-mark it; concurrent transactions settle to exactly one winner; an orphaned lock is reclaimed within the idle-in-transaction timeout | `test_rollback_after_gate_leaves_gate_unset`, `test_cancellation_mid_transaction_rolls_the_gate_back`, `test_concurrent_first_transactions_settle_to_exactly_one_winner`, `test_loser_blocked_on_the_row_lock_wins_after_the_winner_rolls_back`, `test_orphaned_transaction_lock_is_reclaimed_by_the_idle_timeout` (tests/integration/test_turn_side_effect_ledger_postgres.py) |
| 5 | `commit_failed` outcome + orphaned-user-turn counter | Observability | alfred-core-engineer | `commit_failed` is in-domain (never silently rewritten to `unknown`); the orphaned-user-turn counter increments under the caller's bucket | `test_commit_failed_is_recorded_verbatim_not_rewritten_to_unknown`, `test_orphaned_user_turn_counter_increments_under_the_callers_bucket` (tests/unit/supervisor/test_histograms.py) |
| 6 | Three-phase `Orchestrator` restructure | Core runtime | alfred-core-engineer | ZERO turn-session scopes open while the provider call runs; per-phase gate→write→commit→append order; a phase-commit failure is recorded three ways and never masquerades as success; ANY failure between Phase A's and Phase C's commits counts the orphaned user row; cancellation AND deadline expiry inside a phase transaction roll back explicitly | `test_no_turn_scope_is_open_while_the_provider_call_runs`, `test_gate_write_commit_append_order_is_pinned_per_phase`, `test_phase_commit_failure_records_commit_failed_and_appends_nothing`, `test_phase_b_failure_increments_the_orphaned_user_turn_counter`, `test_phase_c_failure_increments_the_orphaned_user_turn_counter`, `test_cancellation_inside_phase_a_rolls_back_and_appends_nothing`, `test_deadline_expiry_inside_phase_a_rolls_back_and_audits_timeout` (tests/unit/orchestrator/test_core.py) |
| 7 | Boot wiring, CONTROL routing (gate backend, identity resolver, supervisor CLI) | CLI / boot graph | alfred-core-engineer (+ alfred-security-engineer sign-off on the gate-backend seam) | The production boot path arms the ledger and role-scopes BOTH scopes (TURN + SIDE_EFFECT, injected scopes used verbatim); no unconfigured `create_engine` remains in `supervisor.py`; the armed ledger closes the crash-replay double-append residual | `test_default_scopes_are_role_scoped_and_the_ledger_is_armed`, `test_injected_scopes_are_used_verbatim_no_default_builds` (tests/unit/cli/test_build_orchestrator_wiring.py), `test_no_bare_create_engine_call_sites_remain` (tests/unit/cli/test_supervisor_control_engine.py), `test_forwarded_crash_injection_replays_exactly_twice_with_bounded_residual` (tests/integration/comms_mcp/test_real_turn_inbound_boundary.py, flipped) |
| 8 | Pool-starved integration tier | Tests | alfred-test-engineer | Integration engines are pool-starved BY DEFAULT so any reintroduced hold-and-wait fails loud within `pool_timeout`; the fixture override is the documented opt-out and genuinely reaches the engine | `test_default_integration_pool_is_the_starvation_shape`, `test_third_concurrent_hold_fails_loud_within_pool_timeout`, `TestOptOut::test_override_reaches_the_engine` (tests/integration/memory/test_pool_starvation_default.py) |
| 9 | Deterministic no-hold-across-provider proof | Tests + Core | alfred-test-engineer | With all four concurrent REAL turns parked inside `complete()`, the TURN pool's checked-out count is exactly 0 on real Postgres; the companion proves the 2-connection pool genuinely starves a held-across-the-park design (oracle independence) | `test_no_connection_is_held_while_all_turns_sit_in_the_provider_call`, `test_hold_and_wait_on_this_pool_really_starves` (tests/integration/orchestrator/test_turn_pool_no_hold_across_provider.py) |
| 10 | ADR-0062, ADR-0049 amendment, design-doc supersession | Docs / ADR | alfred-architect (reviewed by alfred-reviewer) | Decision record matches the shipped mechanism and names every accepted residual; docs lint clean | No runtime property — verified by markdownlint + the full `make check` gate (Task 10 Step 5) |

---

### Task 1: `ConnectionRole` + role-scoped engine registry + turn-scope nesting guard

**Files:**

- Modify: `src/alfred/memory/db.py` (full-file rewrite below; currently 124 lines)
- Modify: `src/alfred/memory/_config_protocols.py` (append one Protocol)
- Test: `tests/unit/memory/test_db.py` (update 2 existing tests, add 2 new classes)

This task modifies pre-existing main-branch code (`db.py` predates PR1), not PR1-committed code.

**Interfaces:**

- Consumes: `alfred.errors.AlfredError`, `alfred.memory._config_protocols.MemoryDbConfig` (existing).
- Produces (later tasks rely on these exact names):
  - `class ConnectionRole(enum.Enum)` with members `TURN`, `SIDE_EFFECT`, `CONTROL` (values `"turn"`, `"side_effect"`, `"control"`).
  - `@dataclass(frozen=True, slots=True) class DbPoolTuning` with fields `turn_pool_max_connections: int = 32`, `side_pool_max_connections: int = 16`, `checkout_timeout_seconds: float = 10.0`, `idle_in_transaction_timeout_seconds: float = 5.0`.
  - `class NestedTurnConnectionError(AlfredError)`.
  - `make_engine(config: MemoryDbConfig, *, role: ConnectionRole = ConnectionRole.SIDE_EFFECT, tuning: DbPoolTuning | None = None) -> AsyncEngine`
  - `make_session_factory(config: MemoryDbConfig, *, role: ConnectionRole = ConnectionRole.SIDE_EFFECT, tuning: DbPoolTuning | None = None) -> async_sessionmaker[AsyncSession]`
  - `session_scope(factory: async_sessionmaker[AsyncSession], *, role: ConnectionRole = ConnectionRole.SIDE_EFFECT)` (async context manager yielding `AsyncSession`)
  - `build_session_scope(config: MemoryDbConfig, *, role: ConnectionRole = ConnectionRole.SIDE_EFFECT, tuning: DbPoolTuning | None = None) -> Callable[[], AbstractAsyncContextManager[AsyncSession]]` (now fully typed — the old `# type: ignore[no-untyped-def]` comments are gone)
  - `dispose_all_engines() -> None` (unchanged signature, now iterates the composite-key registry)
  - `MemoryDbTuningConfig` runtime-checkable Protocol in `_config_protocols.py` (property names `db_turn_pool_max_connections: int`, `db_side_pool_max_connections: int`, `db_pool_checkout_timeout_seconds: float`, `db_idle_in_transaction_timeout_seconds: float`).
  - Prometheus counter `alfred_db_side_effect_scope_inside_turn_total`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/memory/test_db.py` (keep the existing `_isolated_registry` / `fake_engine_factory` fixtures — they are updated in Step 3):

```python
class TestRoleScopedEngines:
    """#410 PR1: one cached engine per (dsn, role), each with role-shaped pool params."""

    async def test_same_url_different_roles_get_distinct_engines(
        self, fake_engine_factory: MagicMock
    ) -> None:
        url = "postgresql+asyncpg://x:y@localhost/test"
        turn = db_mod._engine_for_url(url, role=db_mod.ConnectionRole.TURN)
        side = db_mod._engine_for_url(url, role=db_mod.ConnectionRole.SIDE_EFFECT)
        assert turn is not side
        assert fake_engine_factory.call_count == 2
        # Same (url, role) still deduplicates.
        assert db_mod._engine_for_url(url, role=db_mod.ConnectionRole.TURN) is turn
        assert fake_engine_factory.call_count == 2

    async def test_turn_and_side_effect_pool_parameters_reach_create_async_engine(
        self, fake_engine_factory: MagicMock
    ) -> None:
        url = "postgresql+asyncpg://x:y@localhost/test"
        tuning = db_mod.DbPoolTuning(
            turn_pool_max_connections=7,
            side_pool_max_connections=3,
            checkout_timeout_seconds=2.5,
            idle_in_transaction_timeout_seconds=1.0,
        )
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.TURN, tuning=tuning)
        kwargs = fake_engine_factory.call_args.kwargs
        assert kwargs["pool_size"] == 7
        assert kwargs["max_overflow"] == 0
        assert kwargs["pool_timeout"] == 2.5
        assert kwargs["pool_pre_ping"] is True
        assert kwargs["pool_recycle"] == 1800
        assert kwargs["connect_args"] == {
            "server_settings": {"idle_in_transaction_session_timeout": "1000"}
        }
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.SIDE_EFFECT, tuning=tuning)
        kwargs = fake_engine_factory.call_args.kwargs
        assert kwargs["pool_size"] == 3
        assert kwargs["max_overflow"] == 0
        # Pass-2 finding: pool_recycle is pinned on BOTH runtime roles, not
        # just TURN — the SIDE_EFFECT engine is equally long-lived.
        assert kwargs["pool_recycle"] == 1800

    async def test_control_role_gets_stock_pool_and_no_idle_timeout(
        self, fake_engine_factory: MagicMock
    ) -> None:
        # CONTROL (CLI / Alembic / gate backend / identity resolver) does
        # human-scale multi-statement work — a tight idle-in-transaction bound
        # would kill a paused operator psql-style session mid-migration.
        url = "postgresql+asyncpg://x:y@localhost/test"
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.CONTROL)
        kwargs = fake_engine_factory.call_args.kwargs
        assert kwargs["pool_size"] == 5
        assert kwargs["max_overflow"] == 10
        assert kwargs["pool_pre_ping"] is True
        assert kwargs["pool_recycle"] == 1800
        assert "connect_args" not in kwargs

    async def test_tuning_is_auto_derived_from_a_settings_shaped_config(
        self, fake_engine_factory: MagicMock
    ) -> None:
        """A config carrying the four db_* tuning fields (i.e. the real Settings)
        is picked up structurally — no call site has to thread tuning= by hand,
        so operator env overrides can never be lost to call-site ordering."""
        from pydantic import PostgresDsn

        class _TunedCfg:
            database_url = PostgresDsn("postgresql+asyncpg://a:b@db:5432/x")
            db_turn_pool_max_connections = 9
            db_side_pool_max_connections = 4
            db_pool_checkout_timeout_seconds = 1.5
            db_idle_in_transaction_timeout_seconds = 2.0

        db_mod.make_engine(_TunedCfg(), role=db_mod.ConnectionRole.TURN)
        kwargs = fake_engine_factory.call_args.kwargs
        assert kwargs["pool_size"] == 9
        assert kwargs["pool_timeout"] == 1.5
        assert (
            kwargs["connect_args"]["server_settings"]["idle_in_transaction_session_timeout"]
            == "2000"
        )

    async def test_dispose_all_engines_covers_every_role(
        self, fake_engine_factory: MagicMock
    ) -> None:
        url = "postgresql+asyncpg://x:y@localhost/test"
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.TURN)
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.SIDE_EFFECT)
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.CONTROL)
        assert len(db_mod._ENGINES) == 3
        await db_mod.dispose_all_engines()
        assert db_mod._ENGINES == {}


def _fake_session_factory() -> tuple[Any, MagicMock]:
    """A factory() whose product is an async-CM yielding a commit/rollback-capable
    session mock — the minimal shape session_scope drives."""
    from contextlib import asynccontextmanager

    session = MagicMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()

    @asynccontextmanager
    async def _open() -> AsyncGenerator[MagicMock, None]:
        yield session

    return _open, session


class TestSessionScopeRoleGuard:
    """#410 PR1 / ADR-0062: closed acquisition hierarchy. While a TURN scope is
    held in this task/context, SIDE_EFFECT is the ONLY role that may open a
    second scope (the AuditWriter durability path, hard rule #7). A second TURN
    or a CONTROL scope is a hold-and-wait deadlock seed and fails loud."""

    async def test_nested_turn_scope_raises(self) -> None:
        factory, _session = _fake_session_factory()
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
            with pytest.raises(db_mod.NestedTurnConnectionError):
                async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
                    pass  # pragma: no cover — the guard raises at __aenter__

    async def test_control_scope_inside_turn_raises(self) -> None:
        factory, _session = _fake_session_factory()
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
            with pytest.raises(db_mod.NestedTurnConnectionError):
                async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.CONTROL):
                    pass  # pragma: no cover — the guard raises at __aenter__

    async def test_side_effect_scope_inside_turn_is_allowed_and_counted(self) -> None:
        from prometheus_client import REGISTRY

        factory, _session = _fake_session_factory()
        before = (
            REGISTRY.get_sample_value("alfred_db_side_effect_scope_inside_turn_total") or 0.0
        )
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
            async with db_mod.session_scope(
                factory, role=db_mod.ConnectionRole.SIDE_EFFECT
            ) as inner:
                assert inner is _session
        after = REGISTRY.get_sample_value("alfred_db_side_effect_scope_inside_turn_total")
        assert after == before + 1.0

    async def test_side_effect_scope_outside_turn_is_not_counted(self) -> None:
        from prometheus_client import REGISTRY

        factory, _session = _fake_session_factory()
        before = (
            REGISTRY.get_sample_value("alfred_db_side_effect_scope_inside_turn_total") or 0.0
        )
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.SIDE_EFFECT):
            pass
        after = (
            REGISTRY.get_sample_value("alfred_db_side_effect_scope_inside_turn_total") or 0.0
        )
        assert after == before

    async def test_turn_flag_resets_even_when_the_scope_body_raises(self) -> None:
        factory, _session = _fake_session_factory()
        with pytest.raises(RuntimeError, match="boom"):
            async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
                raise RuntimeError("boom")
        _session.rollback.assert_awaited()
        # The contextvar must have been reset — a fresh TURN scope opens cleanly.
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
            pass

    async def test_cancelled_error_rolls_back_explicitly_and_resets_the_flag(self) -> None:
        """#410 PR1 fleet finding H-1: asyncio.CancelledError is a BaseException,
        NOT an Exception. An `except Exception:` scope would let a cancellation
        mid-Phase-A/C skip the rollback call entirely and lean on
        AsyncSession.close()'s IMPLICIT rollback — driver behaviour this
        codebase would then be assuming, not proving. The scope must roll back
        EXPLICITLY on BaseException; the real-driver twin of this test is
        tests/integration/test_turn_side_effect_ledger_postgres.py::
        test_cancellation_mid_transaction_rolls_the_gate_back (Task 4)."""
        factory, _session = _fake_session_factory()
        with pytest.raises(asyncio.CancelledError):
            async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
                raise asyncio.CancelledError()
        _session.rollback.assert_awaited()
        _session.commit.assert_not_awaited()
        # The contextvar reset survives the BaseException path too.
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
            pass

    async def test_turn_scope_is_isolated_per_task_not_process_global(self) -> None:
        """#410 PR1 fleet finding H-6: the documented reason the guard is a
        ContextVar and not a module flag is per-TASK isolation — task B must be
        able to open TURN (or CONTROL) scopes while task A holds a TURN scope.
        A regression to module-level state makes task B raise
        NestedTurnConnectionError here (the TaskGroup then fails the test)."""
        factory, _session = _fake_session_factory()
        a_holding = asyncio.Event()
        release_a = asyncio.Event()

        async def task_a() -> None:
            async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
                a_holding.set()
                await release_a.wait()

        async def task_b() -> None:
            await a_holding.wait()
            # Task A holds its TURN scope RIGHT NOW (released only after this
            # body completes) — an unrelated task must be unaffected.
            async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
                pass
            async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.CONTROL):
                pass
            release_a.set()

        async with asyncio.timeout(5):
            async with asyncio.TaskGroup() as tg:
                tg.create_task(task_a())
                tg.create_task(task_b())
```

Also add `AsyncGenerator` to the existing `from collections.abc import AsyncGenerator` import at the top of the file (it is already imported), `Any` to a `from typing import Any` import (add it — the file does not currently import `typing`), and `import asyncio` (the file does not currently import it; the two new guard tests above use it).

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/memory/test_db.py -x -q`
Expected: FAIL with `AttributeError: module 'alfred.memory.db' has no attribute 'ConnectionRole'`

- [ ] **Step 3: Write the implementation**

Append to `src/alfred/memory/_config_protocols.py` (and extend its `from typing import Protocol` import to `from typing import Protocol, runtime_checkable`):

```python
@runtime_checkable
class MemoryDbTuningConfig(Protocol):
    """Optional pool-tuning surface a db config MAY carry (#410 PR1 / ADR-0062).

    The real ``Settings`` satisfies this structurally (Task 2 adds the four
    fields); narrow test stubs that only carry ``database_url`` simply don't
    match, and ``make_engine`` falls back to ``DbPoolTuning()`` defaults —
    which are the same values as the Settings field defaults, so the two
    sources can never disagree silently.
    """

    @property
    def db_turn_pool_max_connections(self) -> int: ...

    @property
    def db_side_pool_max_connections(self) -> int: ...

    @property
    def db_pool_checkout_timeout_seconds(self) -> float: ...

    @property
    def db_idle_in_transaction_timeout_seconds(self) -> float: ...
```

Replace `src/alfred/memory/db.py` in full with:

```python
"""SQLAlchemy 2.0 async engine + session factory, role-scoped (#410 PR1 / ADR-0062).

Every Postgres connection in the core is acquired under one of three closed
:class:`ConnectionRole`\\ s, each with its own cached engine + pool per DSN:

- ``TURN`` — the orchestrator's per-phase transactions (Phase A / Phase C of
  the three-phase turn). Sub-millisecond hold times by design: the ONLY
  in-transaction work is the ledger UPSERT + one episodic write (bounded by
  the episodic before-write hook chain, ``HOOK_CHAIN_DEADLINE_SECONDS`` =
  0.25 s x 2 hookpoints ~= 0.5 s worst case), so the tight
  ``idle_in_transaction_session_timeout`` below (default 5 s = 10x that
  bound) is safe — under the pre-#410 single-turn-transaction design it was
  NOT (a healthy turn idled in-transaction for the whole provider call).
- ``SIDE_EFFECT`` — durability-guaranteed writes that must survive a caller's
  rollback: the audit writers (CLAUDE.md hard rule #7), idempotency stores,
  working-pool rehydrate. The default role, so pre-#410 call sites keep
  their behaviour without edits.
- ``CONTROL`` — CLI / Alembic / gate-backend / identity-resolver traffic:
  human-scale, multi-statement, deliberately NOT idle-bounded.

Acquisition hierarchy (enforced by :func:`session_scope`'s contextvar guard):
while a ``TURN`` scope is held in the current task, ``SIDE_EFFECT`` is the
ONLY role permitted to open a second scope — that is the audit-durability
exception, and it is counted on
``alfred_db_side_effect_scope_inside_turn_total`` so the load-bearing
exception stays visible. A second ``TURN`` (or a ``CONTROL``) scope raises
:class:`NestedTurnConnectionError`: two-connections-per-task on a bounded
pool is the hold-and-wait shape that deadlocked 16/16 concurrent turns in
the #410 PR1 investigation.

Registry lifecycle: engines are cached per ``(dsn, role)``. The FIRST
construction for a key wins its pool parameters (same first-wins contract the
previous DSN-only registry had); production always derives tuning from the
one ``Settings`` instance (structurally, via :class:`MemoryDbTuningConfig`),
so all call sites agree. ``dispose_all_engines()`` is the test/shutdown
reaper — ``functools.cache.cache_clear()`` was insufficient because it only
dropped Python references and leaked the pools' sockets.
"""

from __future__ import annotations

import enum
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Final

from prometheus_client import Counter
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from alfred.errors import AlfredError
from alfred.memory._config_protocols import MemoryDbConfig, MemoryDbTuningConfig


class ConnectionRole(enum.Enum):
    """Closed vocabulary of Postgres-connection acquisition roles (ADR-0062)."""

    TURN = "turn"
    SIDE_EFFECT = "side_effect"
    CONTROL = "control"


@dataclass(frozen=True, slots=True)
class DbPoolTuning:
    """Per-role pool parameters.

    Defaults MIRROR the ``Settings`` field defaults (Task 2 of the #410 PR1
    plan) so a config object without the tuning fields (narrow test stubs)
    behaves identically to an un-overridden production Settings.
    """

    turn_pool_max_connections: int = 32
    side_pool_max_connections: int = 16
    checkout_timeout_seconds: float = 10.0
    idle_in_transaction_timeout_seconds: float = 5.0


class NestedTurnConnectionError(AlfredError):
    """A TURN or CONTROL scope was opened while a TURN scope was already held.

    Holding one pooled connection while acquiring a second (non-SIDE_EFFECT)
    one in the same task is the hold-and-wait deadlock seed #410 PR1 exists
    to eliminate — fail loud at the acquisition site, never wait it out.
    """


# Composite-key registry: one engine (and pool) per (dsn, role).
_ENGINES: dict[tuple[str, ConnectionRole], AsyncEngine] = {}

# Per-task flag: is a TURN-role scope currently open? A ContextVar, not a
# module flag — the core is async and a flag would leak the "held" state
# across concurrently-running tasks (same reasoning as
# alfred.security.tiers._T3_CONSTRUCTION_AUTHORIZED and
# alfred.hooks.registry._reentry).
_TURN_SCOPE_ACTIVE: ContextVar[bool] = ContextVar(
    "alfred_db_turn_scope_active", default=False
)

_SIDE_EFFECT_INSIDE_TURN: Final[Counter] = Counter(
    "alfred_db_side_effect_scope_inside_turn_total",
    "SIDE_EFFECT-role session scopes opened while a TURN-role scope was held "
    "(the audit-durability exception to the no-nesting rule, CLAUDE.md hard "
    "rule #7 — counted so the load-bearing exception stays visible).",
)

# CONTROL keeps SQLAlchemy's stock QueuePool shape — made EXPLICIT here (and
# named in Settings' DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET arithmetic)
# rather than left as the silent library default the #410 investigation
# started from.
_CONTROL_POOL_SIZE: Final[int] = 5
_CONTROL_MAX_OVERFLOW: Final[int] = 10
# Recycle connections older than 30 minutes — long-lived daemon processes
# otherwise accumulate server-side-stale connections across Postgres restarts
# that pool_pre_ping alone detects one checkout too late.
_POOL_RECYCLE_SECONDS: Final[int] = 1800


def _tuning_for(config: MemoryDbConfig, tuning: DbPoolTuning | None) -> DbPoolTuning:
    """Resolve tuning: explicit arg > config's own fields > defaults."""
    if tuning is not None:
        return tuning
    if isinstance(config, MemoryDbTuningConfig):
        return DbPoolTuning(
            turn_pool_max_connections=config.db_turn_pool_max_connections,
            side_pool_max_connections=config.db_side_pool_max_connections,
            checkout_timeout_seconds=config.db_pool_checkout_timeout_seconds,
            idle_in_transaction_timeout_seconds=config.db_idle_in_transaction_timeout_seconds,
        )
    return DbPoolTuning()


def _engine_kwargs(role: ConnectionRole, tuning: DbPoolTuning) -> dict[str, Any]:
    # dict[str, Any] (not object) is required to **-unpack into
    # create_async_engine's typed signature — the values are heterogeneous
    # engine kwargs, which is exactly what Any is for here.
    if role is ConnectionRole.CONTROL:
        return {
            "pool_size": _CONTROL_POOL_SIZE,
            "max_overflow": _CONTROL_MAX_OVERFLOW,
            "pool_pre_ping": True,
            "pool_recycle": _POOL_RECYCLE_SECONDS,
        }
    pool_size = (
        tuning.turn_pool_max_connections
        if role is ConnectionRole.TURN
        else tuning.side_pool_max_connections
    )
    # asyncpg forwards server_settings in the startup packet; the GUC's unit
    # is milliseconds, sent as a bare-integer string.
    idle_ms = str(int(tuning.idle_in_transaction_timeout_seconds * 1000))
    return {
        "pool_size": pool_size,
        # max_overflow=0: the pool size IS the cap. Overflow connections would
        # make the Settings-level connection-budget validator a fiction.
        "max_overflow": 0,
        "pool_timeout": tuning.checkout_timeout_seconds,
        "pool_pre_ping": True,
        "pool_recycle": _POOL_RECYCLE_SECONDS,
        "connect_args": {
            "server_settings": {"idle_in_transaction_session_timeout": idle_ms}
        },
    }


def _engine_for_url(
    url: str,
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
    tuning: DbPoolTuning | None = None,
) -> AsyncEngine:
    """Return the cached engine for ``(url, role)``, creating it on first use."""
    key = (url, role)
    engine = _ENGINES.get(key)
    if engine is None:
        engine = create_async_engine(
            url,
            echo=False,
            future=True,
            **_engine_kwargs(role, tuning if tuning is not None else DbPoolTuning()),
        )
        _ENGINES[key] = engine
    return engine


def make_engine(
    config: MemoryDbConfig,
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
    tuning: DbPoolTuning | None = None,
) -> AsyncEngine:
    """Return a cached async engine for ``(config.database_url, role)``.

    First construction for a given key wins its pool parameters (see module
    docstring). ``tuning=None`` auto-derives from ``config`` when it carries
    the :class:`MemoryDbTuningConfig` fields (the real ``Settings`` does),
    else falls back to :class:`DbPoolTuning` defaults.
    """
    return _engine_for_url(
        config.database_url.unicode_string(),
        role=role,
        tuning=_tuning_for(config, tuning),
    )


async def dispose_all_engines() -> None:
    """Dispose every cached engine (all roles) and clear the registry.

    Tests, fixtures, and any controlled shutdown path call this so the
    SQLAlchemy connection pools actually close their sockets.
    """
    # Snapshot first: `engine.dispose()` yields control to the event loop and
    # we don't want a concurrent `_engine_for_url` to repopulate the dict
    # while we're iterating it.
    engines = list(_ENGINES.values())
    _ENGINES.clear()
    for engine in engines:
        await engine.dispose()


def make_session_factory(
    config: MemoryDbConfig,
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
    tuning: DbPoolTuning | None = None,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=make_engine(config, role=role, tuning=tuning),
        expire_on_commit=False,
        class_=AsyncSession,
    )


@asynccontextmanager
async def session_scope(
    factory: async_sessionmaker[AsyncSession],
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
) -> AsyncIterator[AsyncSession]:
    """Transactional async session scope. Commits on success; rolls back on failure.

    Enforces the ADR-0062 acquisition hierarchy: while a TURN scope is held
    in the current task/context, only SIDE_EFFECT may nest (counted); TURN
    and CONTROL raise :class:`NestedTurnConnectionError` — see the class
    docstring for why waiting instead of raising is the deadlock.

    Rollback fires on ``BaseException``, not ``Exception`` — deliberately.
    ``asyncio.CancelledError`` (and ``KeyboardInterrupt``/``SystemExit``) are
    ``BaseException``\\ s, and a cancellation delivered mid-transaction must
    un-do the transaction's writes (for the orchestrator's Phase A/C, that
    means un-marking the ledger gate) as EXPLICITLY as any other failure.
    Relying on ``AsyncSession.close()``'s implicit rollback-on-close would
    make the plan's headline safety property an unverified driver assumption;
    the explicit call is proven against real asyncpg by
    ``tests/integration/test_turn_side_effect_ledger_postgres.py``'s
    ``task.cancel()`` test.

    Two narrow-window cancellation residuals are ACCEPTED here, not solved
    — both named in ADR-0062's residual list (#410 PR1 pass-2 findings
    sec-101 / mem-p2-001; they are DISTINCT windows — closing one does not
    close the other):

    1. a SECOND cancellation landing while this explicit ``rollback()``'s
       own await is in flight re-raises out of the rollback; connection
       teardown then falls to ``AsyncSession.close()`` (via ``async with
       factory()``) — behaviour this codebase relies on for that window
       but does not independently prove;
    2. a cancellation delivered during the ORIGINAL statement's in-flight
       asyncpg network I/O can leave the connection protocol-wedged such
       that even an ordinary, uninterrupted ``rollback()`` call itself
       raises ``asyncpg.InterfaceError`` — a real, still-open upstream
       driver/ORM interaction (sqlalchemy/sqlalchemy#6592, #8145, #11125,
       #12099; MagicStack/asyncpg#863, #258, #1310; read against the
       installed sqlalchemy 2.0.51 / asyncpg 0.31.0).

    Neither window can strand the ledger gate: in both, the transaction
    never commits, so the server aborts it (at the latest when
    ``idle_in_transaction_session_timeout`` reaps the backend) and a replay
    correctly sees "not applied". The residual exposure is one
    possibly-unclean pooled connection, bounded by
    ``pool_pre_ping``/``pool_recycle`` — and the at-risk window is Phase
    A/C's sub-millisecond transactions, not the pre-#410 design's
    whole-provider-call span.
    """
    if _TURN_SCOPE_ACTIVE.get():
        if role is not ConnectionRole.SIDE_EFFECT:
            raise NestedTurnConnectionError(
                f"a {role.value!r}-role session scope was opened while a TURN-role "
                "scope is already held in this task; only SIDE_EFFECT may nest "
                "inside TURN (ADR-0062 acquisition hierarchy)"
            )
        _SIDE_EFFECT_INSIDE_TURN.inc()
    token = _TURN_SCOPE_ACTIVE.set(True) if role is ConnectionRole.TURN else None
    try:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                # BaseException on purpose (see docstring). Safe to await here:
                # @asynccontextmanager delivers body exceptions via athrow() at
                # the yield point, so the handler runs as normal coroutine code
                # — this is not a GeneratorExit-during-close path.
                await session.rollback()
                raise
    finally:
        if token is not None:
            _TURN_SCOPE_ACTIVE.reset(token)


def build_session_scope(
    config: MemoryDbConfig,
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
    tuning: DbPoolTuning | None = None,
) -> Callable[[], AbstractAsyncContextManager[AsyncSession]]:
    """Bind `session_scope` to a config-derived, role-scoped factory.

    Returns a no-arg callable suitable for the orchestrator's `session_scope`
    parameter — `async with session_scope() as session: ...`.
    """
    factory = make_session_factory(config, role=role, tuning=tuning)

    def _scope() -> AbstractAsyncContextManager[AsyncSession]:
        return session_scope(factory, role=role)

    return _scope


async def healthcheck(scope) -> None:  # type: ignore[no-untyped-def]
    """Smoke-check the database is reachable.

    Called at CLI bootstrap so a missing/down Postgres surfaces as a clean
    "ERROR: Postgres unreachable" message instead of an asyncpg traceback
    inside the TUI on first keystroke. Raises SQLAlchemyError on failure.
    """
    from sqlalchemy import text as _text

    async with scope() as session:
        await session.execute(_text("SELECT 1"))
```

Then update the two now-broken pieces of `tests/unit/memory/test_db.py`:

Replace the `_isolated_registry` fixture's dict line:

```python
    fresh: dict[str, object] = {}
```

with:

```python
    fresh: dict[tuple[str, db_mod.ConnectionRole], object] = {}
```

Replace `_fake_engine_for_url` inside `test_make_engine_reads_only_database_url_from_a_stub`:

```python
        def _fake_engine_for_url(url: str) -> object:
            captured.append(url)
            return object()
```

with:

```python
        captured_tuning: list[db_mod.DbPoolTuning | None] = []

        def _fake_engine_for_url(
            url: str,
            *,
            role: db_mod.ConnectionRole = db_mod.ConnectionRole.SIDE_EFFECT,
            tuning: db_mod.DbPoolTuning | None = None,
        ) -> object:
            captured.append(url)
            captured_tuning.append(tuning)
            return object()
```

and, in the same test, replace the final assertion line

```python
        assert captured == ["postgresql+asyncpg://alfred:alfred@db:5432/alfred"]
```

with:

```python
        assert captured == ["postgresql+asyncpg://alfred:alfred@db:5432/alfred"]
        # Fleet finding M-12: the "structural fallback to defaults" guarantee
        # is ASSERTED, not just exercised — a stub without the tuning fields
        # must resolve to the DOCUMENTED DbPoolTuning defaults (which Task 2
        # pins as equal to the Settings field defaults), never to "some
        # tuning" or None.
        assert captured_tuning == [db_mod.DbPoolTuning()]
        assert captured_tuning[0] == db_mod.DbPoolTuning(
            turn_pool_max_connections=32,
            side_pool_max_connections=16,
            checkout_timeout_seconds=10.0,
            idle_in_transaction_timeout_seconds=5.0,
        )
```

(The `test_dispose_all_engines_invokes_dispose_on_each` test injects string keys directly into `_ENGINES`; the dict accepts them at runtime and `dispose_all_engines` iterates `.values()`, so it needs no edit.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/memory/test_db.py -q`
Expected: all PASS.

- [ ] **Step 5: Verify no existing consumer broke, then quality gates**

Run: `uv run pytest tests/unit/memory tests/unit/cli -q` (every `build_session_scope` / `make_session_factory` caller defaults to `SIDE_EFFECT`, so nothing should need edits yet)
Run: `uv run ruff check src/alfred/memory/ tests/unit/memory/ && uv run ruff format src/alfred/memory/ tests/unit/memory/ && uv run mypy src/ && uv run pyright src/`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/memory/db.py src/alfred/memory/_config_protocols.py tests/unit/memory/test_db.py
git commit -m "refactor(memory): role-scoped engine registry + turn-scope nesting guard (#410 PR1)"
```

---

### Task 2: Settings pool fields + connection-budget validator

**Files:**

- Modify: `src/alfred/config/settings.py` (add one module constant, four fields, one validator; add `Final` to the `typing` import; add `from pydantic_core import PydanticCustomError`)
- Modify: `src/alfred/cli/daemon/_commands.py` (`_settings_error_field_name` — surface a model-level refusal's category slug instead of swallowing it; fleet finding H-3)
- Test: `tests/unit/config/test_settings_db_pools.py` (create)
- Test: `tests/unit/cli/daemon/test_probe_environment_not_set.py` (one new test beside the existing `_settings_error_field_name` pair)

This task modifies pre-existing main-branch code, not PR1-committed code.

**How the refusal reaches the operator (fleet finding H-3 — read before implementing).** `Settings.__init__` translates EVERY construction failure into `SettingsError(str(exc)) from exc` (settings.py:539-544), so callers never see a raw `ValidationError`. The interactive CLI path (`alfred.cli._bootstrap.load_settings_or_die`) echoes `str(exc)` — the full message, numbers included — so it needs nothing from this task. The DAEMON path is the swallow: `_load_settings_or_die` → `_bootstrap_settings_message` → `_settings_error_field_name`, which reads `exc.__cause__.errors()[0]["loc"]` and returns `None` for a `loc=()` model-validator error (its own test, `test_settings_error_field_name_none_when_loc_is_empty`, documents this exact future-model-validator case) — degrading to the fully generic `daemon.boot.settings_invalid` message. That boundary deliberately never interpolates `str(exc)` (DLP: a DSN failure can echo a password), so the fix must NOT widen what it prints. The existing M2 precedent is exactly the right shape: surface a value-free IDENTIFIER (there, the field's dotted `loc` path; here, a category slug). Mechanism: the validator raises `PydanticCustomError` with the deliberately-authored type slug `db_pool_connection_budget_exceeded`; `_settings_error_field_name` gains a fallback — when `loc` is empty AND the error `type` is not one of pydantic's two generic wrappers for bare raises (`value_error` / `assertion_error`, which carry no category information), return the slug. It renders through the EXISTING `daemon.boot.settings_invalid_field` catalog key (no new i18n strings), naming WHICH constraint failed as a category — never the operator's configured numbers.

**Interfaces:**

- Consumes: nothing from earlier tasks (the field names must match Task 1's `MemoryDbTuningConfig` property names exactly — that is the structural link).
- Produces: `Settings.db_turn_pool_max_connections: int`, `Settings.db_side_pool_max_connections: int`, `Settings.db_pool_checkout_timeout_seconds: float`, `Settings.db_idle_in_transaction_timeout_seconds: float`, module constant `DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET: Final[int] = 60`, error-type slug `db_pool_connection_budget_exceeded` (the daemon boundary's DLP-safe refusal category). Env overrides: `ALFRED_DB_TURN_POOL_MAX_CONNECTIONS`, `ALFRED_DB_SIDE_POOL_MAX_CONNECTIONS`, `ALFRED_DB_POOL_CHECKOUT_TIMEOUT_SECONDS`, `ALFRED_DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/config/test_settings_db_pools.py`:

```python
"""#410 PR1: role-scoped Postgres pool sizing + the connection-budget validator.

The unconfigured pre-#410 pool ("15", never justified anywhere) is replaced by
named, budget-validated fields. The budget constant's arithmetic lives in its
own docstring in settings.py; these tests pin the enforcement, the defaults,
and the field bounds.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.config.settings import (
    DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET,
    Settings,
    SettingsError,
)


def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    for var in (
        "ALFRED_DB_TURN_POOL_MAX_CONNECTIONS",
        "ALFRED_DB_SIDE_POOL_MAX_CONNECTIONS",
        "ALFRED_DB_POOL_CHECKOUT_TIMEOUT_SECONDS",
        "ALFRED_DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)


def test_defaults_match_db_pool_tuning_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    # The DbPoolTuning dataclass in alfred.memory.db mirrors these values so a
    # stub config without the fields behaves like un-overridden Settings.
    from alfred.memory.db import DbPoolTuning

    _base_env(monkeypatch)
    s = Settings()
    tuning = DbPoolTuning()
    assert s.db_turn_pool_max_connections == tuning.turn_pool_max_connections == 32
    assert s.db_side_pool_max_connections == tuning.side_pool_max_connections == 16
    assert s.db_pool_checkout_timeout_seconds == tuning.checkout_timeout_seconds == 10.0
    assert (
        s.db_idle_in_transaction_timeout_seconds
        == tuning.idle_in_transaction_timeout_seconds
        == 5.0
    )


def test_defaults_fit_inside_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    s = Settings()
    assert (
        s.db_turn_pool_max_connections + s.db_side_pool_max_connections
        <= DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET
    )


def test_over_budget_combination_is_refused_at_boot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Settings.__init__ translates every ValidationError into SettingsError
    # (settings.py:539-544) — callers never see a raw ValidationError, so the
    # refusal is pinned on SettingsError with the ValidationError as __cause__.
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DB_TURN_POOL_MAX_CONNECTIONS", "64")
    monkeypatch.setenv("ALFRED_DB_SIDE_POOL_MAX_CONNECTIONS", "64")  # 128 > 60
    with pytest.raises(SettingsError, match="connection budget") as excinfo:
        Settings()
    # Fleet finding H-3: the refusal carries the deliberately-authored
    # PydanticCustomError slug so the daemon boundary
    # (_settings_error_field_name) can name WHICH constraint failed without
    # interpolating any operator-configured value. `str(exc)` (with the
    # numbers) still reaches the INTERACTIVE path via load_settings_or_die.
    cause = excinfo.value.__cause__
    assert isinstance(cause, ValidationError)
    assert cause.errors()[0]["type"] == "db_pool_connection_budget_exceeded"
    assert cause.errors()[0]["loc"] == ()


def test_exactly_at_budget_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DB_TURN_POOL_MAX_CONNECTIONS", "44")
    monkeypatch.setenv("ALFRED_DB_SIDE_POOL_MAX_CONNECTIONS", "16")  # 60 == budget
    s = Settings()
    assert s.db_turn_pool_max_connections == 44


def test_turn_pool_floor_is_two(monkeypatch: pytest.MonkeyPatch) -> None:
    # A 1-connection TURN pool would serialize Phase A/C across ALL users.
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DB_TURN_POOL_MAX_CONNECTIONS", "1")
    with pytest.raises(SettingsError):
        Settings()


def test_idle_timeout_floor_is_one_second(monkeypatch: pytest.MonkeyPatch) -> None:
    # Below ~2x the worst-case in-transaction hook-chain time (0.5 s) the
    # timeout would reap HEALTHY Phase A/C transactions; ge=1.0 enforces it.
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS", "0.5")
    with pytest.raises(SettingsError):
        Settings()
```

Also append to `tests/unit/cli/daemon/test_probe_environment_not_set.py`, directly after the existing `test_settings_error_field_name_none_when_loc_is_empty` (all names it uses — `InitErrorDetails`, `PydanticCustomError`, `ValidationError`, `SettingsError`, `_settings_error_field_name` — are already imported in that file):

```python
def test_settings_error_field_name_surfaces_a_custom_slug_at_empty_loc() -> None:
    """#410 PR1 (fleet finding H-3): a model-level (``loc=()``) refusal raised
    as a deliberately-slugged ``PydanticCustomError`` surfaces its slug — the
    DLP-safe category naming WHICH constraint failed — instead of degrading to
    the fully generic message. The sibling test above still holds: a BARE
    ``ValueError`` raise arrives as pydantic's generic ``value_error`` wrapper
    type, which names nothing and stays swallowed. Slugs are authored string
    literals in settings.py — never interpolated from a value — so this is
    the same value-free contract as the M2 field-name variant."""
    line_errors: list[InitErrorDetails] = [
        InitErrorDetails(
            type=PydanticCustomError("db_pool_connection_budget_exceeded", "over budget"),
            loc=(),
            input="irrelevant",
        )
    ]
    cause = ValidationError.from_exception_data("Settings", line_errors)
    try:
        raise SettingsError("settings blew up") from cause
    except SettingsError as exc:
        assert _settings_error_field_name(exc) == "db_pool_connection_budget_exceeded"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/config/test_settings_db_pools.py -x -q`
Expected: FAIL with `ImportError: cannot import name 'DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET'`

Run: `uv run pytest tests/unit/cli/daemon/test_probe_environment_not_set.py::test_settings_error_field_name_surfaces_a_custom_slug_at_empty_loc -x -q`
Expected: FAIL with `AssertionError: assert None == 'db_pool_connection_budget_exceeded'` (the current boundary swallows every empty-`loc` error).

- [ ] **Step 3: Write the implementation**

In `src/alfred/config/settings.py`: change `from typing import Annotated, Any, Literal` to `from typing import Annotated, Any, Final, Literal`, and add `from pydantic_core import PydanticCustomError` below the existing `pydantic` import block (pydantic-core is pydantic v2's own core — already a direct transitive dependency, not a new fourth-party dep). Add the module constant directly below the `_COMMS_ADAPTER_ID_RE` constant:

```python
# #410 PR1 / ADR-0062: hard ceiling on the two runtime pools' combined size.
DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET: Final[int] = 60
"""Ceiling on ``db_turn_pool_max_connections + db_side_pool_max_connections``.

Derivation — every number named, none bare (the pre-#410 "15" was an
unconfigured SQLAlchemy default that was never justified anywhere; this
constant exists so that mistake is not repeated):

- 100 : postgres:18 default ``max_connections`` (docker-compose.yaml ships no
  override)
- -3 : postgres default ``superuser_reserved_connections`` — never available
  to alfred's non-superuser role
- -15 : capability-gate backend CONTROL pool (stock QueuePool: pool_size 5 +
  max_overflow 10 — ``alfred.memory.db._CONTROL_POOL_SIZE`` /
  ``_CONTROL_MAX_OVERFLOW``, wired in ``_gate_boot.py``)
- -15 : sync IdentityResolver CONTROL engine (same explicit stock shape —
  ``_bootstrap.install_identity_factories_for_settings``)
- -7 : CLI / Alembic / emergency-operator headroom (``alfred user ...``,
  migrations, and a rescue psql session must never be locked out by a
  saturated runtime)

100 - 3 - 15 - 15 - 7 = 60.
"""
```

Add the four fields inside `class Settings`, directly after the `working_memory_pool_max` field (around line 251):

```python
    # #410 PR1 / ADR-0062: role-scoped Postgres pools. TURN carries the
    # orchestrator's sub-millisecond Phase A/C transactions; SIDE_EFFECT
    # carries the durability-guaranteed audit/idempotency writes that must
    # acquire a SECOND connection while a TURN one is held (hard rule #7) —
    # which is exactly why the two pools are separate: a saturated TURN pool
    # must never starve the audit path. Their SUM is validated against
    # DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET below. ge=2 on each: a
    # 1-connection pool serializes every concurrent user through one socket.
    db_turn_pool_max_connections: int = Field(default=32, ge=2, le=200)
    db_side_pool_max_connections: int = Field(default=16, ge=2, le=200)
    # Pool checkout wait bound. A checkout that waits longer than this raises
    # instead of joining a silent convoy; le=30 keeps it under the 30 s action
    # deadline so starvation surfaces as a distinct loud error, not a timeout.
    db_pool_checkout_timeout_seconds: float = Field(default=10.0, gt=0.0, le=30.0)
    # Postgres-side idle_in_transaction_session_timeout for TURN/SIDE_EFFECT
    # connections. Safe to keep TIGHT only because of the three-phase split:
    # the only in-transaction work is Phase A/C (ledger UPSERT + one episodic
    # write, bounded by the before-write hook chain —
    # HOOK_CHAIN_DEADLINE_SECONDS 0.25 s x 2 hookpoints ~= 0.5 s worst case).
    # Default 5 s = 10x that bound; ge=1.0 stops an operator configuring a
    # value that would reap HEALTHY transactions. An orphaned crash-abandoned
    # transaction's row locks are reclaimed within this window instead of OS
    # TCP-keepalive timescales (hours).
    db_idle_in_transaction_timeout_seconds: float = Field(default=5.0, ge=1.0, le=30.0)
```

Add the validator inside `class Settings`, next to the existing `@model_validator(mode="wrap")` (keep it a separate method):

```python
    @model_validator(mode="after")
    def _refuse_over_budget_db_pools(self) -> Settings:
        """#410 PR1: refuse a pool combination Postgres cannot actually serve.

        Without this, an operator override could configure more pooled
        connections than ``max_connections`` minus reserves — which fails at
        the WORST time (peak load, checkout storm) instead of at boot.

        Raised as :class:`PydanticCustomError` (a ``ValueError`` subclass),
        NOT a bare ``ValueError`` — deliberately. A model-level validator
        reports ``loc=()``, and the daemon boundary
        (``alfred.cli.daemon._commands._settings_error_field_name``) refuses
        to interpolate ``str(exc)`` for DLP reasons, so a bare raise would be
        swallowed into the fully generic ``daemon.boot.settings_invalid``
        message. The custom error TYPE slug
        (``db_pool_connection_budget_exceeded``) is the value-free category
        that boundary surfaces instead — the operator learns WHICH constraint
        refused the boot without any configured number reaching a log sink.
        The full message (numbers included) still reaches the interactive
        path via ``load_settings_or_die``'s ``str(exc)`` echo.
        """
        total = self.db_turn_pool_max_connections + self.db_side_pool_max_connections
        if total > DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET:
            raise PydanticCustomError(
                "db_pool_connection_budget_exceeded",
                "db_turn_pool_max_connections ({turn}) + "
                "db_side_pool_max_connections ({side}) = {total}, which exceeds "
                "the connection budget of {budget} (postgres:18 default "
                "max_connections 100 minus superuser reserve, the two "
                "CONTROL-role pools, and CLI/ops headroom — see "
                "DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET's docstring). Lower "
                "the pool fields, or raise Postgres max_connections and this "
                "budget together, deliberately.",
                {
                    "turn": self.db_turn_pool_max_connections,
                    "side": self.db_side_pool_max_connections,
                    "total": total,
                    "budget": DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET,
                },
            )
        return self
```

Then, in `src/alfred/cli/daemon/_commands.py`, replace `_settings_error_field_name`'s empty-`loc` arm. Change:

```python
    loc = errors[0]["loc"]
    if not loc:
        return None
    return ".".join(str(part) for part in loc)
```

to:

```python
    loc = errors[0]["loc"]
    if not loc:
        # #410 PR1 (fleet finding H-3): a model-level validator reports
        # loc=(). A DELIBERATELY-SLUGGED PydanticCustomError (e.g. the
        # db-pool budget validator's "db_pool_connection_budget_exceeded")
        # carries its category in the error TYPE — a value-free identifier
        # authored as a string literal in settings.py, safe to surface under
        # the same never-a-value contract as the field path below. Pydantic's
        # own wrappers for bare `raise ValueError/AssertionError` arrive as
        # the generic "value_error"/"assertion_error" types, which name
        # nothing — those (and only those) still degrade to the generic
        # message.
        error_type = errors[0]["type"]
        if error_type not in {"value_error", "assertion_error"}:
            return error_type
        return None
    return ".".join(str(part) for part in loc)
```

and extend the function's docstring final sentence from "the caller falls back to the fully generic message rather than guess." to: "the caller falls back to the fully generic message rather than guess — except for a model-level (`loc=()`) error whose TYPE is a deliberately-authored `PydanticCustomError` slug, which is returned as the DLP-safe category (#410 PR1)."

Finally, amend the now-half-stale docstring of the pre-existing `test_settings_error_field_name_none_when_loc_is_empty` (its body needs no change — a generic `value_error` wrapper still returns `None`): replace its sentence "but the guard exists precisely so a FUTURE model-level validator on ``Settings`` degrades to the generic ``daemon.boot.settings_invalid`` message rather than rendering an empty field name." with "but the guard exists so a model-level validator raised as a BARE ``ValueError`` degrades to the generic ``daemon.boot.settings_invalid`` message rather than rendering an empty field name — a deliberately-slugged ``PydanticCustomError`` instead surfaces its category slug (#410 PR1; see the sibling test below)."

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/config/test_settings_db_pools.py tests/unit/config tests/unit/cli/daemon/test_probe_environment_not_set.py -q`
Expected: all PASS — including the pre-existing `test_settings_error_field_name_none_when_loc_is_empty`, which pins the OTHER half of the new fallback (a generic `value_error` wrapper at `loc=()` still returns `None`); it needs no edit because the slug fallback deliberately excludes pydantic's generic wrapper types.

- [ ] **Step 5: Quality gates**

Run: `uv run ruff check src/alfred/config/ src/alfred/cli/daemon/_commands.py tests/unit/config/ tests/unit/cli/daemon/test_probe_environment_not_set.py && uv run ruff format src/alfred/config/ src/alfred/cli/daemon/_commands.py tests/unit/config/ tests/unit/cli/daemon/test_probe_environment_not_set.py && uv run mypy src/ && uv run pyright src/`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/config/settings.py src/alfred/cli/daemon/_commands.py tests/unit/config/test_settings_db_pools.py tests/unit/cli/daemon/test_probe_environment_not_set.py
git commit -m "feat(config): role-scoped db pool sizing with a connection-budget validator (#410 PR1)"
```

---

### Task 3: `TurnSideEffectLedger` joins the caller's transaction (session-per-call)

**Files:**

- Modify: `src/alfred/memory/turn_side_effects.py` (full-file rewrite below; the docstrings currently assert the OPPOSITE of the new design and are the direct cause of the bug — rewrite, don't amend)
- Test: `tests/unit/memory/test_turn_side_effect_ledger_store.py` (all 7 tests currently construct via the removed `session_scope=` kwarg and fail at construction — every one is rewritten below)

This task REVISES committed PR1 code (`8f03df7d`).

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces (Tasks 4, 6, 7, 9 rely on these exact signatures):
  - `TurnSideEffectLedger` Protocol: `async def try_apply_user_turn(self, session: AsyncSession, *, adapter_id: str, inbound_id: str) -> bool` and `async def try_apply_assistant_turn(self, session: AsyncSession, *, adapter_id: str, inbound_id: str) -> bool` — the session is now the FIRST POSITIONAL parameter on each call.
  - `PostgresTurnSideEffectLedger()` — zero-argument constructor (stateless; every call operates inside the caller's transaction).

Design decision recorded here (the design doc §3.1 left the mechanism open): session-per-call-method rather than a `ledger_factory: Callable[[AsyncSession], ...]`, because a stateless object whose methods demand the caller's session makes the "operates in the caller's transaction" contract impossible to misuse — there is no constructor seam through which an independent scope could ever be re-introduced — and the boot wiring collapses to `PostgresTurnSideEffectLedger()`.

- [ ] **Step 1: Rewrite the unit tests (failing first)**

Replace `tests/unit/memory/test_turn_side_effect_ledger_store.py` in full with:

```python
"""PostgresTurnSideEffectLedger try-apply semantics (fake session; no DB).

#410 PR1 transactional revision: the ledger no longer owns any session or
scope — each ``try_apply_*`` call executes its single UPSERT statement on the
CALLER's ``AsyncSession``, inside the caller's transaction, so the gate and
the write it guards commit or roll back together. A fake session lets every
branch (first-apply / already-applied / DB-error-propagates) run hermetically.
The genuine-Postgres atomic-UPSERT and rollback-coupling properties live in
the integration tier (tests/integration/test_turn_side_effect_ledger_postgres.py).
"""

from __future__ import annotations

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
    def __init__(self, *, returned: bool | None) -> None:
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
        return _FakeResult(returned=self._returned)


def test_store_satisfies_protocol() -> None:
    assert isinstance(PostgresTurnSideEffectLedger(), TurnSideEffectLedger)


async def test_try_apply_user_turn_proceeds_on_first_apply() -> None:
    session = _FakeSession(returned=True)
    store = PostgresTurnSideEffectLedger()
    assert (
        await store.try_apply_user_turn(session, adapter_id="discord", inbound_id="m1") is True
    )
    stmt, params = session.executed[0]
    assert stmt is _TRY_APPLY_USER_TURN_SQL
    assert params == {"adapter_id": "discord", "inbound_id": "m1"}


async def test_try_apply_user_turn_skips_when_already_applied() -> None:
    # No row returned (the WHERE ...=FALSE guard didn't match) => already applied.
    session = _FakeSession(returned=None)
    store = PostgresTurnSideEffectLedger()
    assert (
        await store.try_apply_user_turn(session, adapter_id="discord", inbound_id="m1") is False
    )


async def test_try_apply_assistant_turn_proceeds_on_first_apply() -> None:
    session = _FakeSession(returned=True)
    store = PostgresTurnSideEffectLedger()
    assert (
        await store.try_apply_assistant_turn(session, adapter_id="discord", inbound_id="m1")
        is True
    )
    stmt, params = session.executed[0]
    assert stmt is _TRY_APPLY_ASSISTANT_TURN_SQL
    assert params == {"adapter_id": "discord", "inbound_id": "m1"}


async def test_try_apply_assistant_turn_skips_when_already_applied() -> None:
    session = _FakeSession(returned=None)
    store = PostgresTurnSideEffectLedger()
    assert (
        await store.try_apply_assistant_turn(session, adapter_id="discord", inbound_id="m1")
        is False
    )


async def test_adapter_id_is_part_of_the_key_not_a_free_column() -> None:
    # A different adapter_id, same inbound_id, must not be treated as the same gate.
    session = _FakeSession(returned=True)
    store = PostgresTurnSideEffectLedger()
    assert await store.try_apply_user_turn(session, adapter_id="tui", inbound_id="m1") is True
    _stmt, params = session.executed[0]
    assert params == {"adapter_id": "tui", "inbound_id": "m1"}


async def test_the_ledger_never_commits_or_rolls_back_the_callers_session() -> None:
    # The transactional contract in one assertion: the ledger's ONLY session
    # interaction is execute(). Commit/rollback belong to the caller's
    # session_scope — a ledger that committed would re-create the exact
    # independent-commit bug this revision removes.
    session = _FakeSession(returned=True)
    store = PostgresTurnSideEffectLedger()
    await store.try_apply_user_turn(session, adapter_id="discord", inbound_id="m1")
    await store.try_apply_assistant_turn(session, adapter_id="discord", inbound_id="m1")
    assert not hasattr(store, "_session_scope")
    assert len(session.executed) == 2  # two execute() calls and nothing else


@pytest.mark.parametrize("method_name", ["try_apply_user_turn", "try_apply_assistant_turn"])
async def test_db_error_propagates_fail_loud(method_name: str) -> None:
    # CLAUDE.md hard rule #7: a genuine DB failure is NEVER swallowed into a
    # False (which would silently re-permit a side effect that should have
    # stayed blocked, or block one that should have proceeded).
    boom = OperationalError("UPSERT failed", {}, Exception("db down"))
    session = _FakeSession(raises=boom)
    store = PostgresTurnSideEffectLedger()
    method = getattr(store, method_name)
    with pytest.raises(OperationalError):
        await method(session, adapter_id="discord", inbound_id="m1")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/memory/test_turn_side_effect_ledger_store.py -x -q`
Expected: FAIL — `TypeError: PostgresTurnSideEffectLedger.__init__() ... 'session_scope'` shape errors (the current class requires the kwarg the tests no longer pass, and the methods reject the positional session).

- [ ] **Step 3: Rewrite the implementation**

Replace `src/alfred/memory/turn_side_effects.py` in full with:

```python
"""Durable turn-side-effect idempotency ledger (#410 PR1, transactional revision).

The forwarded dispatched-edge path
(:func:`alfred.comms_mcp.inbound.process_inbound_message` with
``commit_at_dispatch_edge=True``) leaves a failed frame NOT committed, so the
forwarding leg replays it (ADR-0039 item 4). A resumed turn re-runs from
scratch, which — absent this ledger — re-appends the user/assistant turns to
the live in-process :class:`~alfred.memory.working.WorkingMemory` buffer and
re-writes both episodic rows. This ledger makes each of those two effects
apply AT MOST ONCE per committed ``(adapter_id, inbound_id)``.

**Transactional contract (ADR-0062 — this INVERTS the original PR1 design):**
each ``try_apply_*`` call executes on the CALLER's :class:`AsyncSession`,
inside the caller's transaction. The gate and the guarded episodic write
commit or roll back TOGETHER: a mid-phase rollback un-marks the gate in
lockstep with the write it guards, so a replay after any failure correctly
sees "not yet applied" and retries — never "applied but missing" (the
data-loss bug the original independent-session design had). The ledger never
calls ``commit()``/``rollback()`` itself and holds no session of its own.

The caller is :meth:`alfred.orchestrator.core.Orchestrator`'s Phase A/C —
each a SHORT-LIVED transaction (ledger UPSERT + one episodic write) that
closes before any provider call, so the row lock a losing concurrent attempt
waits on is held for milliseconds, and an orphaned (crashed-caller) lock is
reclaimed by the TURN pool's ``idle_in_transaction_session_timeout``.

**Deliberate divergence from the sibling**
:class:`~alfred.memory.forwarded_dispatch_attempts.ForwardedDispatchAttemptStore`:
that store's own-independent-session design is CORRECT for what IT guards (a
retry counter, not a durability claim about another write). This ledger's
original copy of that pattern was a mis-transfer, not a second instance of a
shared design — recorded in ADR-0062 so the deviation reads as deliberate.

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

Durable-across-restart on purpose: the forwarded-edge replay happens ACROSS
core restarts, so an in-memory guard would reset exactly when it is needed.

Each ``try_apply_*`` method is a single ``INSERT ... ON CONFLICT (adapter_id,
inbound_id) DO UPDATE ... WHERE <column> = FALSE RETURNING <column>``
statement — no read-then-write window. A row is returned (mapped to
``True``, "proceed") only when this call is the one that flips the column
from FALSE to TRUE (either via the fresh INSERT or via a WHERE-qualified
UPDATE); a conflicting call that finds the column already TRUE returns no
row (mapped to ``False``, "already applied, skip"). Under READ COMMITTED a
concurrent second transaction on the same key blocks on the row lock until
the first resolves: first committed => the ``WHERE ... = FALSE`` guard denies
the second; first rolled back => the second's insert wins. The two columns
share ONE row per ``(adapter_id, inbound_id)`` (not two tables) since they
are two facets of the SAME turn attempt and must never be attributed to
different inbound frames.

**Composite key, not `inbound_id` alone** (a #410 design correction found
during the `/review-plan` fleet pass): ``inbound_id`` is a free-form,
per-adapter-minted opaque string (``src/alfred/comms_mcp/protocol.py``, the
same reasoning the sibling ``inbound_idempotency`` migration 0018 and
``forwarded_dispatch_attempts`` migration 0020 both document for their own
composite ``(adapter_id, inbound_id)`` keys) — a single-column key would let
two DIFFERENT adapters' turns collide on the same ``inbound_id`` string and
silently gate-skip each other's unrelated content.

**Caller contract:** call the relevant ``try_apply_*`` gate at the START of
the same transaction that performs the guarded episodic write, and defer any
NON-transactional twin effect (the in-process working-memory append) until
AFTER that transaction commits. The residual this leaves is an orphaned USER
episodic row when Phase B fails after Phase A committed — accepted (ADR-0062)
as strictly better than the alternative (losing the user's message entirely):
replay re-denies the user gate, allows the assistant gate, and converges.

A genuine DB failure (``SQLAlchemyError``) PROPAGATES — never caught and
collapsed into a boolean, which could either silently re-permit a blocked
side effect or silently block a permitted one.
"""

from __future__ import annotations

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
    """Durable per-``(adapter_id, inbound_id)`` at-most-once gate, caller-transactional."""

    async def try_apply_user_turn(
        self, session: AsyncSession, *, adapter_id: str, inbound_id: str
    ) -> bool:
        """Return ``True`` iff the caller should apply the user-turn write now.

        Executes inside ``session``'s transaction; commit/rollback are the
        caller's, so the gate travels with the guarded write.
        """
        ...

    async def try_apply_assistant_turn(
        self, session: AsyncSession, *, adapter_id: str, inbound_id: str
    ) -> bool:
        """Return ``True`` iff the caller should apply the assistant-turn write now."""
        ...


class PostgresTurnSideEffectLedger:
    """Postgres-backed :class:`TurnSideEffectLedger`.

    Stateless on purpose: every call runs its single atomic UPSERT on the
    caller's session, inside the caller's transaction. There is no
    constructor seam through which an independent session/scope could be
    re-introduced — the shape of the class IS the transactional contract.
    """

    async def try_apply_user_turn(
        self, session: AsyncSession, *, adapter_id: str, inbound_id: str
    ) -> bool:
        result = await session.execute(
            _TRY_APPLY_USER_TURN_SQL, {"adapter_id": adapter_id, "inbound_id": inbound_id}
        )
        return result.scalar_one_or_none() is not None

    async def try_apply_assistant_turn(
        self, session: AsyncSession, *, adapter_id: str, inbound_id: str
    ) -> bool:
        result = await session.execute(
            _TRY_APPLY_ASSISTANT_TURN_SQL,
            {"adapter_id": adapter_id, "inbound_id": inbound_id},
        )
        return result.scalar_one_or_none() is not None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/memory/test_turn_side_effect_ledger_store.py -q`
Expected: all PASS.

NOTE: `tests/unit/orchestrator/test_core.py` and `tests/integration/test_turn_side_effect_ledger_postgres.py` are now BROKEN against the new signature — that is expected and correct at this point in the sequence; Task 4 fixes the integration file, Task 6 fixes the orchestrator (which also must change its call sites to pass the session). Do not run the full suite green-gate here; run only the file above plus:

Run: `uv run ruff check src/alfred/memory/turn_side_effects.py tests/unit/memory/test_turn_side_effect_ledger_store.py && uv run ruff format src/alfred/memory/turn_side_effects.py tests/unit/memory/test_turn_side_effect_ledger_store.py`

`mypy src/` will fail on `src/alfred/orchestrator/core.py` (call-site signature mismatch) until Task 6 — that failure is the sequencing signal, not a defect. Record it and move on.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/memory/turn_side_effects.py tests/unit/memory/test_turn_side_effect_ledger_store.py
git commit -m "refactor(memory): TurnSideEffectLedger executes in the caller's transaction (#410 PR1)"
```

---

### Task 4: Real-Postgres transactional ledger contract

**Files:**

- Modify: `tests/integration/test_turn_side_effect_ledger_postgres.py` (full-file rewrite below — the fixture and every test body construct/pass the removed session-scope callable)

This task REVISES committed PR1 code (`e660e37c`).

**Interfaces:**

- Consumes: `PostgresTurnSideEffectLedger()` + `try_apply_*(session, *, adapter_id, inbound_id)` from Task 3; `ConnectionRole`, `make_engine`, `make_session_factory`, `dispose_all_engines`, `session_scope` from Task 1.
- Produces: nothing (test-only), but pins the three properties the ADR (Task 10) cites: rollback-unsets-gate, bounded orphaned-lock wait, one-winner-under-concurrent-transactions.

- [ ] **Step 1: Rewrite the test file (failing first)**

Replace `tests/integration/test_turn_side_effect_ledger_postgres.py` in full with:

```python
"""Real-Postgres integration tests for the TRANSACTIONAL PostgresTurnSideEffectLedger.

#410 PR1 revision: the ledger executes inside the caller's transaction, so the
properties proven here move from "8 independent immediately-committing
sessions" to "N independent transactions that commit or roll back the gate
together with the write it guards" — the same one-winner shape, not a weaker
one — PLUS the three new properties the transactional design introduces:

1. a rollback after the gate leaves the gate UNSET (the direct regression
   test for the data-loss bug the revision fixes);
2. an ORPHANED transaction's row lock (crashed caller, connection never
   closed) is reclaimed within the TURN pool's
   idle_in_transaction_session_timeout — not OS TCP-keepalive timescales;
3. a loser blocked on the row lock resolves promptly once the winner's
   transaction concludes, and wins when the winner ROLLED BACK;
4. a REAL asyncio cancellation (task.cancel(), a BaseException — not an
   Exception subclass) delivered mid-transaction also leaves the gate UNSET,
   proven against the real asyncpg driver rather than assumed from
   AsyncSession.close() behaviour.

SQLite cannot express any of this; real Postgres only.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest
import sqlalchemy as sa
from alembic import command, config
from pydantic import PostgresDsn
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.memory.db import (
    ConnectionRole,
    dispose_all_engines,
    make_engine,
    make_session_factory,
    session_scope,
)
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger

pytestmark = pytest.mark.integration

_ADAPTER = "discord"


@dataclass(frozen=True)
class _LedgerEnv:
    ledger: PostgresTurnSideEffectLedger
    factory: async_sessionmaker[AsyncSession]


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0025
    return postgres_url


@pytest.fixture
async def ledger_env(migrated_url: str) -> AsyncIterator[_LedgerEnv]:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield _LedgerEnv(ledger=PostgresTurnSideEffectLedger(), factory=factory)
    finally:
        await engine.dispose()


async def _apply_user(env: _LedgerEnv, inbound_id: str, *, adapter_id: str = _ADAPTER) -> bool:
    """One gate call in its OWN committed transaction — the Phase-A shape."""
    async with session_scope(env.factory) as session:
        return await env.ledger.try_apply_user_turn(
            session, adapter_id=adapter_id, inbound_id=inbound_id
        )


async def _apply_assistant(
    env: _LedgerEnv, inbound_id: str, *, adapter_id: str = _ADAPTER
) -> bool:
    """One gate call in its OWN committed transaction — the Phase-C shape."""
    async with session_scope(env.factory) as session:
        return await env.ledger.try_apply_assistant_turn(
            session, adapter_id=adapter_id, inbound_id=inbound_id
        )


async def test_first_apply_proceeds_each_gate(ledger_env: _LedgerEnv) -> None:
    assert await _apply_user(ledger_env, "m1") is True
    assert await _apply_assistant(ledger_env, "m1") is True


async def test_second_apply_skips_each_gate(ledger_env: _LedgerEnv) -> None:
    assert await _apply_user(ledger_env, "m2") is True
    assert await _apply_user(ledger_env, "m2") is False
    assert await _apply_assistant(ledger_env, "m2") is True
    assert await _apply_assistant(ledger_env, "m2") is False


async def test_gates_are_independent_columns_on_one_row(ledger_env: _LedgerEnv) -> None:
    # Applying assistant_turn does not pre-empt the OTHER gate on the same row.
    assert await _apply_assistant(ledger_env, "m3") is True
    assert await _apply_user(ledger_env, "m3") is True


async def test_inbound_id_namespaces_are_isolated(ledger_env: _LedgerEnv) -> None:
    assert await _apply_user(ledger_env, "m4") is True
    assert await _apply_user(ledger_env, "m5") is True  # different inbound_id


async def test_adapter_id_namespaces_are_isolated_on_the_same_inbound_id(
    ledger_env: _LedgerEnv,
) -> None:
    # Two DIFFERENT adapters minting the SAME inbound_id string must not collide.
    assert await _apply_user(ledger_env, "shared-id", adapter_id="discord") is True
    assert await _apply_user(ledger_env, "shared-id", adapter_id="tui") is True


async def test_rollback_after_gate_leaves_gate_unset(ledger_env: _LedgerEnv) -> None:
    """THE regression test for the #410 PR1 bug: the gate must travel with the
    transaction. Pre-revision, the gate committed independently and a caller
    rollback stranded it TRUE with the guarded write missing forever."""

    class _MidPhaseFailure(Exception):
        pass

    with pytest.raises(_MidPhaseFailure):
        async with session_scope(ledger_env.factory) as session:
            assert (
                await ledger_env.ledger.try_apply_user_turn(
                    session, adapter_id=_ADAPTER, inbound_id="rb1"
                )
                is True
            )
            raise _MidPhaseFailure()  # the phase fails after the gate said "proceed"

    # The rollback un-marked the gate: a replay gets to (re)apply the write.
    assert await _apply_user(ledger_env, "rb1") is True


async def test_cancellation_mid_transaction_rolls_the_gate_back(
    ledger_env: _LedgerEnv,
) -> None:
    """Fleet finding H-1's real-driver proof: asyncio.CancelledError is a
    BaseException, so an `except Exception:` scope would never roll it back
    explicitly — the whole safety property would silently rest on
    AsyncSession.close()'s implicit rollback, an asyncpg behaviour this suite
    would then be assuming rather than proving. This test delivers a REAL
    task.cancel() (not a manually-raised exception) while the coroutine is
    parked inside the transaction AFTER the gate said "proceed", and proves
    the gate is unset afterward — session_scope's explicit BaseException
    rollback, verified end-to-end against real Postgres."""
    gate_taken = asyncio.Event()

    async def cancelled_phase() -> None:
        async with session_scope(ledger_env.factory) as session:
            assert (
                await ledger_env.ledger.try_apply_user_turn(
                    session, adapter_id=_ADAPTER, inbound_id="cx1"
                )
                is True
            )
            gate_taken.set()
            # Park mid-transaction on a never-set Event; the ONLY exit from
            # this await is the CancelledError the test injects below.
            await asyncio.Event().wait()

    task = asyncio.create_task(cancelled_phase())
    async with asyncio.timeout(10):
        await gate_taken.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The BaseException rollback un-marked the gate: a replay re-applies.
    assert await _apply_user(ledger_env, "cx1") is True


async def test_concurrent_first_transactions_settle_to_exactly_one_winner(
    ledger_env: _LedgerEnv,
) -> None:
    # 8 concurrent TRANSACTIONS (not bare statements) on ONE key: the atomic
    # UPSERT + row lock serialise, so exactly one True and seven False.
    async def attempt() -> bool:
        async with session_scope(ledger_env.factory) as session:
            return await ledger_env.ledger.try_apply_user_turn(
                session, adapter_id=_ADAPTER, inbound_id="race"
            )

    results = await asyncio.gather(*(attempt() for _ in range(8)))
    assert sorted(results) == [False] * 7 + [True]


async def test_loser_blocked_on_the_row_lock_wins_after_the_winner_rolls_back(
    ledger_env: _LedgerEnv,
) -> None:
    """The concurrent-attempt-plus-rollback intersection: a loser blocked on the
    winner's row lock must (a) resolve promptly once the winner concludes and
    (b) WIN when the winner rolled back — the lock-footprint property the
    single-statement inspection argument does not cover."""

    gate_taken = asyncio.Event()
    release_winner = asyncio.Event()
    # Backend PIDs of the two connections under test, captured via
    # SELECT pg_backend_pid() right after each session opens (pass-2 finding
    # test2-1) — the probe below scopes its pg_locks poll to the loser's PID
    # so it can never be satisfied by an unrelated lock elsewhere in the
    # instance.
    winner_pid: list[int] = []
    loser_pid: list[int] = []

    class _WinnerAborts(Exception):
        pass

    async def winner() -> None:
        with pytest.raises(_WinnerAborts):
            async with session_scope(ledger_env.factory) as session:
                winner_pid.append(
                    (await session.execute(sa.text("SELECT pg_backend_pid()"))).scalar_one()
                )
                assert (
                    await ledger_env.ledger.try_apply_user_turn(
                        session, adapter_id=_ADAPTER, inbound_id="cr1"
                    )
                    is True
                )
                gate_taken.set()
                await release_winner.wait()
                raise _WinnerAborts()  # -> rollback releases the row lock

    async def loser() -> tuple[bool, float]:
        await gate_taken.wait()
        started = time.monotonic()
        async with session_scope(ledger_env.factory) as session:
            # PID captured BEFORE the gate call blocks, so the probe below
            # can scope its pg_locks poll to exactly this backend's wait.
            loser_pid.append(
                (await session.execute(sa.text("SELECT pg_backend_pid()"))).scalar_one()
            )
            result = await ledger_env.ledger.try_apply_user_turn(
                session, adapter_id=_ADAPTER, inbound_id="cr1"
            )  # blocks on the winner's in-flight transaction
        return result, time.monotonic() - started

    async def _loser_is_parked_on_a_transactionid_wait() -> bool:
        # What the loser waits on here is NOT a relation-level lock: a
        # blocked INSERT ... ON CONFLICT ... DO UPDATE ... WHERE ...
        # RETURNING on a contended key parks on the WINNER'S TRANSACTION ID
        # — pg_locks reports locktype='transactionid', mode='ShareLock',
        # granted=false against the loser's backend (verified against real
        # Postgres 18 during the #410 investigation). Filtering on the
        # loser's OWN backend pid AND locktype='transactionid' means this
        # probe is true ONLY when the specific loser under test is genuinely
        # blocked on that transaction-id wait — an unscoped
        # `WHERE NOT granted` count could be satisfied by any unrelated
        # not-granted lock anywhere in the Postgres instance, releasing the
        # winner early and letting the assertions pass without ever
        # exercising real contention. Observed over a THIRD connection (the
        # factory pool default of 5 accommodates winner + loser + this
        # probe).
        if not loser_pid:
            return False  # the loser has not opened its session yet
        async with session_scope(ledger_env.factory) as session:
            result = await session.execute(
                sa.text(
                    "SELECT 1 FROM pg_locks "
                    "WHERE NOT granted AND pid = :loser_pid "
                    "AND locktype = 'transactionid'"
                ),
                {"loser_pid": loser_pid[0]},
            )
            return result.scalar_one_or_none() is not None

    async with asyncio.timeout(30), asyncio.TaskGroup() as tg:
        tg.create_task(winner())
        loser_task = tg.create_task(loser())
        await gate_taken.wait()
        # Deterministic contention barrier (fleet finding H-5 — no bare
        # sleep-based synchronization): release the winner only once Postgres
        # ITSELF reports the loser's OWN backend blocked on a transactionid
        # wait, i.e. the specific loser under test is provably parked on the
        # winner's transaction. The 50 ms interval below is poll pacing, not
        # the synchronization mechanism — the release condition is the
        # server-side fact, and the enclosing asyncio.timeout(30) bounds the
        # poll.
        while not await _loser_is_parked_on_a_transactionid_wait():
            await asyncio.sleep(0.05)
        release_winner.set()

    won, waited = loser_task.result()
    assert won is True  # the winner rolled back, so the loser's insert succeeds
    assert waited < 10.0  # resolved promptly after the winner concluded, not a hang
    assert winner_pid and loser_pid and winner_pid[0] != loser_pid[0], (
        "winner and loser must be DISTINCT backends — same-backend reuse would "
        "make the contention this test exists to exercise impossible"
    )


async def test_orphaned_transaction_lock_is_reclaimed_by_the_idle_timeout(
    migrated_url: str,
) -> None:
    """A crashed process leaves a transaction holding the ledger row lock with
    nothing to roll it back. The TURN-role engine's
    idle_in_transaction_session_timeout must bound the replay's wait — NOT
    OS-level TCP keepalive defaults (hours). Uses the REAL role-scoped engine
    construction path so the setting is proven to reach the server."""

    class _TurnTunedCfg:
        database_url = PostgresDsn(migrated_url)
        db_turn_pool_max_connections = 4
        db_side_pool_max_connections = 2
        db_pool_checkout_timeout_seconds = 5.0
        db_idle_in_transaction_timeout_seconds = 1.0  # tight, to keep the test fast

    cfg = _TurnTunedCfg()
    engine = make_engine(cfg, role=ConnectionRole.TURN)
    factory = make_session_factory(cfg, role=ConnectionRole.TURN)
    ledger = PostgresTurnSideEffectLedger()
    holder = factory()  # the "crashed" caller's session — never committed, never closed
    try:
        assert (
            await ledger.try_apply_user_turn(
                holder, adapter_id=_ADAPTER, inbound_id="orphan"
            )
            is True
        )
        # holder now idles in-transaction holding the row lock. Postgres kills
        # that backend after 1s; the blocked replay below then proceeds AND
        # wins (the orphan's un-committed insert died with its backend).
        started = time.monotonic()
        async with asyncio.timeout(20):
            async with session_scope(factory, role=ConnectionRole.TURN) as session:
                assert (
                    await ledger.try_apply_user_turn(
                        session, adapter_id=_ADAPTER, inbound_id="orphan"
                    )
                    is True
                )
        elapsed = time.monotonic() - started
        assert elapsed < 5.0, (
            f"replay waited {elapsed:.1f}s — the idle_in_transaction timeout did not "
            "bound the orphaned lock"
        )
        # engine.pool sanity: the TURN pool really carries the configured size.
        assert engine.pool.size() == 4
    finally:
        # The server already terminated the holder's backend (that IS the
        # property under test); close() then raises the terminated-connection
        # error by design — suppress ONLY here, in teardown of a deliberately
        # killed connection, never in the assertion path above.
        with contextlib.suppress(Exception):
            await holder.close()
        await dispose_all_engines()
```

- [ ] **Step 2: Run tests to verify current state**

Run: `uv run pytest tests/integration/test_turn_side_effect_ledger_postgres.py -x -q` (Docker required)
Expected: all PASS on first run — Task 3 already landed the implementation these tests target. Verify the two gate-travels-with-the-transaction tests genuinely bite by mutation (`git stash` is not needed — edit, run, revert):

In `src/alfred/memory/turn_side_effects.py`, temporarily append `await session.commit()` as the line before `return result.scalar_one_or_none() is not None` in `try_apply_user_turn`, run `uv run pytest tests/integration/test_turn_side_effect_ledger_postgres.py::test_rollback_after_gate_leaves_gate_unset tests/integration/test_turn_side_effect_ledger_postgres.py::test_cancellation_mid_transaction_rolls_the_gate_back -q`, confirm BOTH FAIL (the premature commit strands the gate TRUE on the rollback path and on the cancellation path alike — the same mutation kills both, which is the point: they pin one property from two exception classes), then restore the file with `git restore src/alfred/memory/turn_side_effects.py` (restore, not `checkout --` — a staged mutant survives `checkout --`).

- [ ] **Step 3: Quality gates**

Run: `uv run ruff check tests/integration/test_turn_side_effect_ledger_postgres.py && uv run ruff format tests/integration/test_turn_side_effect_ledger_postgres.py`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_turn_side_effect_ledger_postgres.py
git commit -m "test(memory): transactional ledger contract on real Postgres (#410 PR1)"
```

---

### Task 5: Admit `commit_failed` into the action-outcome domain + orphaned-user-turn counter

**Files:**

- Modify: `src/alfred/supervisor/observability.py:110` (`_ACTION_OUTCOME_DOMAIN`), the `record_action_duration` docstring outcome list, and (fleet finding M-14) a new `ORPHANED_USER_TURN_COUNTER` + `record_orphaned_user_turn` beside the existing histogram/recorder pair
- Modify: `docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md` (§7a.3 outcome enumeration — pass-2 finding arch-1: the domain pin's docstring names THREE lockstep obligations, and this doc is the third)
- Test: `tests/unit/supervisor/test_histograms.py:199-201` (the existing exact-domain pin) plus two new tests in the same file

This task modifies pre-existing main-branch code. It MUST land before Task 6 (which emits the new outcome value and fires the new counter) — without it, `record_action_duration` silently rewrites `"commit_failed"` to `"unknown"` and the counter doesn't exist to fire.

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: `"commit_failed"` as a valid `action_outcome` label value on `alfred_orchestrator_action_duration_seconds` (Task 6 emits it); `record_orphaned_user_turn(*, user_id: str)` observing `alfred_orchestrator_orphaned_user_turn_total{user_id_bucket}` (Task 6 fires it whenever a turn fails after Phase A committed and before Phase C committed — Phase-B failures AND Phase-C body/commit failures alike, per pass-2 finding core-004 — the plan's own accepted behavior change, which without this metric would have zero production observability).

- [ ] **Step 1: Write the failing test**

In `tests/unit/supervisor/test_histograms.py`, update the existing exact pin at line 201 from:

```python
    assert frozenset({"success", "timeout", "cancelled"}) == _ACTION_OUTCOME_DOMAIN
```

to:

```python
    assert (
        frozenset({"success", "timeout", "cancelled", "commit_failed"})
        == _ACTION_OUTCOME_DOMAIN
    )
```

and add, alongside it:

```python
def test_commit_failed_is_recorded_verbatim_not_rewritten_to_unknown() -> None:
    """#410 PR1: a commit failure at a phase boundary records its OWN outcome.

    The domain normaliser rewrites out-of-domain values to "unknown" — if
    "commit_failed" were missing from the domain, the new telemetry Task 6
    emits would silently vanish into the unknown bucket.
    """
    from prometheus_client import REGISTRY

    from alfred.supervisor.observability import bucket_user_id, record_action_duration

    bucket = bucket_user_id("commit-failed-probe-user")
    labels = {
        "user_id_bucket": bucket,
        "action_outcome": "commit_failed",
        "breaker_state": "UNKNOWN",
    }
    before = (
        REGISTRY.get_sample_value(
            "alfred_orchestrator_action_duration_seconds_count", labels
        )
        or 0.0
    )
    record_action_duration(
        duration_seconds=0.01,
        user_id="commit-failed-probe-user",
        action_outcome="commit_failed",
        breaker_state="UNKNOWN",
    )
    after = REGISTRY.get_sample_value(
        "alfred_orchestrator_action_duration_seconds_count", labels
    )
    assert after == before + 1.0


def test_orphaned_user_turn_counter_increments_under_the_callers_bucket() -> None:
    """#410 PR1 (fleet finding M-14, widened by pass-2 finding core-004): the
    accepted orphan trade-off — a committed user episodic row with no paired
    assistant row — is a DELIBERATE behavior change, and a deliberate
    degradation with no metric is invisible in production. One counter,
    bucketed like every other per-user family (perf-001), fired by the
    orchestrator whenever a turn fails after Phase A committed and before
    Phase C committed (Task 6)."""
    from prometheus_client import REGISTRY

    from alfred.supervisor.observability import bucket_user_id, record_orphaned_user_turn

    labels = {"user_id_bucket": bucket_user_id("orphan-probe-user")}
    before = (
        REGISTRY.get_sample_value("alfred_orchestrator_orphaned_user_turn_total", labels)
        or 0.0
    )
    record_orphaned_user_turn(user_id="orphan-probe-user")
    after = REGISTRY.get_sample_value(
        "alfred_orchestrator_orphaned_user_turn_total", labels
    )
    assert after == before + 1.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/supervisor/test_histograms.py -x -q`
Expected: FAIL — the domain-equality assertion fails (no `commit_failed` member), the commit-failed test finds the observation in the `unknown` bucket instead, and the orphan-counter test fails at import (`ImportError: cannot import name 'record_orphaned_user_turn'`).

- [ ] **Step 3: Write the implementation**

In `src/alfred/supervisor/observability.py`, change line 110 from:

```python
_ACTION_OUTCOME_DOMAIN: Final[frozenset[str]] = frozenset({"success", "timeout", "cancelled"})
```

to:

```python
_ACTION_OUTCOME_DOMAIN: Final[frozenset[str]] = frozenset(
    {"success", "timeout", "cancelled", "commit_failed"}
)
```

and add this bullet to the `record_action_duration` docstring's outcome list (after the `cancelled` bullet):

```python
    * ``commit_failed`` — a phase transaction's COMMIT raised after its body
      completed (#410 PR1 three-phase turn). Distinct from ``success`` so a
      commit failure can never masquerade as a completed turn, and distinct
      from the exception-free rollback paths, which record nothing.
```

Then (pass-2 finding arch-1) satisfy the THIRD lockstep obligation the domain pin's own docstring declares ("this assertion, the histogram label docs, and the PRD §7a.3 entry in lockstep"): in `docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md` §7a.3 (line ~673), change the sentence

```text
The supervisor's `deadline.py` emits duration on **every** action (success, timeout, and cancelled), not only on timeout.
```

to

```text
The supervisor's `deadline.py` emits duration on **every** action (success, timeout, and cancelled), not only on timeout; since #410 PR1 the orchestrator additionally records `commit_failed` when a phase transaction's COMMIT raises after its body completed (the closed outcome vocabulary is pinned in `_ACTION_OUTCOME_DOMAIN`).
```

Then (fleet finding M-14) change `from prometheus_client import Histogram` to `from prometheus_client import Counter, Histogram`, and add below the `ACTION_DURATION_HISTOGRAM` block:

```python
# #410 PR1 / ADR-0062 accepted trade-off, made observable: ANY failure
# between Phase A's commit and Phase C's commit (provider error, budget
# refusal, cancellation, deadline, a Phase-C write or commit failure —
# pass-2 finding core-004 widened this beyond Phase-B-only) leaves a user
# episodic row with no paired assistant row — the "orphan user row" the
# three-phase split deliberately accepts as strictly better than losing the
# user's message. Deliberate degradations still need a rate: a spike here
# means the turn pipeline is failing often enough that WorkingMemoryPool
# rehydration is regularly prefilling double-user-turn context, which is
# the signal to investigate the underlying failures.
# Bucketed like every per-user family (perf-001).
ORPHANED_USER_TURN_COUNTER: Final[Counter] = Counter(
    "alfred_orchestrator_orphaned_user_turn_total",
    "Turns that failed after Phase A committed the user episodic row but "
    "before Phase C committed the assistant row (#410 PR1 three-phase "
    "turn) — the accepted orphan-user-row trade-off, counted so its "
    "production rate is visible.",
    labelnames=["user_id_bucket"],
)


def record_orphaned_user_turn(*, user_id: str) -> None:
    """Count one orphaned-user-turn occurrence (#410 PR1 / ADR-0062).

    Fired by the orchestrator when anything raises after Phase A's
    transaction committed and before Phase C's committed — a Phase-B
    failure of any class OR a Phase-C body/commit failure (core-004).
    ``user_id`` is the RAW id — bucketed here via
    :func:`bucket_user_id`, same contract as :func:`record_action_duration`.
    """
    ORPHANED_USER_TURN_COUNTER.labels(user_id_bucket=bucket_user_id(user_id)).inc()
```

and add `"ORPHANED_USER_TURN_COUNTER"` and `"record_orphaned_user_turn"` to the module's `__all__`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/supervisor/test_histograms.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/supervisor/observability.py tests/unit/supervisor/test_histograms.py docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md
git commit -m "feat(supervisor): commit_failed outcome + orphaned-user-turn counter (#410 PR1)"
```

---

### Task 6: Three-phase `Orchestrator` — no connection held across the provider call

**Files:**

- Modify: `src/alfred/orchestrator/core.py` (module docstring lines 38-49; `Orchestrator.__init__` at 258-344; replace `handle_user_message` at 389-546 and `_handle_turn` at 684-1111 with the phase methods below; `_audit_cancellation`, `_emit_supervisor_timeout_row`, `_emit_orchestrator_turn_cancelled_row_autocommit`, `_audit_unknown_budget_user`, `_synthesize_egress_context` are all UNCHANGED)
- Modify: `tests/unit/orchestrator/test_core.py` (double upgrade + assertion flips + one replacement + eleven new tests, all specified below)
- Modify: `tests/unit/orchestrator/test_act_loop.py:88-97` (stale comment in `_make_orchestrator`'s scope double)

This task REVISES committed PR1 code (`0a75f1ba`) AND pre-existing main-branch orchestrator code. It is the core of the plan; every step is mechanical, but there are many.

**Where the old `except BaseException:` arm went (fleet finding M-15 — record, don't leave implicit).** Pre-#410 `handle_user_message` carried three exception arms around the held turn session: `TimeoutError` (audit + rollback), `asyncio.CancelledError` (audit + rollback), and a final `except BaseException:` (`core.py:540-546`) whose ONLY job was `await session.rollback()` on `KeyboardInterrupt`/`SystemExit` before re-raising. The restructure removes that arm IN ITS ENTIRETY, and that is safe because its one responsibility moved into `session_scope` itself (Task 1): the scope's `except BaseException:` arm now rolls back EVERY abnormal exit of a phase transaction — CancelledError, KeyboardInterrupt, SystemExit alike — at the only moments a transaction is open (Phase A/C), and outside those phases there is no session to roll back. The audit halves of the old arms (timeout row, cancellation row) stay in `handle_user_message`'s `TimeoutError`/`CancelledError` arms exactly as before; nothing audited `KeyboardInterrupt`/`SystemExit` pre-#410 and nothing does now. Any reviewer diffing "the old arm vanished" should be pointed here.

**Interfaces:**

- Consumes: `try_apply_user_turn(session, *, adapter_id, inbound_id)` / `try_apply_assistant_turn(session, *, adapter_id, inbound_id)` (Task 3); `record_action_duration(action_outcome="commit_failed")` being domain-valid and `record_orphaned_user_turn` existing (Task 5); `session_scope`'s explicit-`BaseException`-rollback contract (Task 1).
- Produces (Tasks 7 and 9 rely on these):
  - `Orchestrator.__init__` gains keyword-only `audit_session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]] | None = None` (placed after `side_effect_ledger`; `None` falls back to `session_scope`, so every existing caller/test constructs byte-for-byte unchanged).
  - `handle_user_message` signature unchanged.
  - Internal (named so reviewers/tests can reference them): `_TurnOutcome` frozen dataclass; `_run_turn_phases`, `_run_committed_phase`, `_observe_user_turn`, `_orient_and_act`, `_persist_assistant_turn`, `_emit_turn_completed_row`. `_handle_turn` is DELETED.

- [ ] **Step 1: Write the failing driver test**

Add to `tests/unit/orchestrator/test_core.py` (new class at the end of the file):

```python
class TestThreePhaseConnectionDiscipline:
    """#410 PR1 / ADR-0062: the provider call must run with ZERO turn-session
    scopes open. This is the unit-level twin of the integration barrier proof
    (tests/integration/orchestrator/test_turn_pool_no_hold_across_provider.py)."""

    async def test_no_turn_scope_is_open_while_the_provider_call_runs(self) -> None:
        open_scopes = 0
        observed_during_complete: list[int] = []
        session = MagicMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()

        @asynccontextmanager
        async def counting_scope() -> AsyncIterator[MagicMock]:
            nonlocal open_scopes
            open_scopes += 1
            try:
                yield session
                await session.commit()
            finally:
                open_scopes -= 1

        router = MagicMock()

        async def _observing_complete(*_args: Any, **_kwargs: Any) -> CompletionResponse:
            observed_during_complete.append(open_scopes)
            return CompletionResponse(
                content="Very good, Sir.",
                tokens_in=1,
                tokens_out=1,
                cost_usd=0.0001,
                model="m",
            )

        router.complete = AsyncMock(side_effect=_observing_complete)
        resolver = MagicMock()
        resolver.get_operator = MagicMock(return_value=_default_operator())
        audit = MagicMock()
        audit.append = AsyncMock()
        audit.append_schema = AsyncMock()
        episodic = MagicMock()
        episodic.record = AsyncMock()
        orch = Orchestrator(
            identity_resolver=resolver,
            session_scope=counting_scope,
            router=router,
            budget=_make_budget(),
            episodic_factory=lambda _s: episodic,
            audit_factory=lambda _f: audit,
            autocommit_audit_factory=lambda _f: audit,
        )
        buffer: list[Turn] = []
        working = MagicMock(
            turns=AsyncMock(side_effect=lambda: list(buffer)),
            append=AsyncMock(
                side_effect=lambda *, role, content: buffer.append(
                    Turn(role=role, content=content)  # type: ignore[arg-type]
                )
            ),
            clear=AsyncMock(),
        )
        reply = await orch.handle_user_message(
            user=_default_user(), content=_tag_t2("hold check"), working_memory=working
        )
        assert reply == "Very good, Sir."
        # THE invariant: zero scopes open at the moment the provider ran.
        assert observed_during_complete == [0]
        # And the turn still committed both phases.
        assert session.commit.await_count == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/orchestrator/test_core.py::TestThreePhaseConnectionDiscipline -x -q`
Expected: FAIL with `assert [1] == [0]` — the current code holds the per-turn scope across `router.complete`.

- [ ] **Step 3: Restructure `core.py`**

3a. Replace the module docstring's "Session lifecycle" paragraph (lines 38-49, beginning `Session lifecycle: a per-turn ``session_scope``...` and ending `...(no silent failures in security paths).`) with:

```text
Session lifecycle (#410 PR1 / ADR-0062 — the three-phase turn): NO database
connection is ever held across external I/O. Phase A (Observe) opens one
short-lived ``session_scope``, runs the ledger user-gate + the episodic user
write in ONE transaction, and commits; the working-memory append is deferred
until after that commit. Phase B (Orient + Act) — prompt construction, the
provider call, the whole tool loop, and every audit write — runs with ZERO
connections held. Phase C (Persist) opens a second short-lived scope for the
ledger assistant-gate + the episodic assistant write, commits, then performs
the deferred assistant append and the terminal audit row. Rollback of a
phase is the scope's own job — there are no manual ``session.rollback()``
calls in this module any more.

**Audit writes live OUTSIDE those transactions.** ``AuditWriter`` takes its
own ``session_factory`` (the SIDE_EFFECT-role scope in production) and opens
a fresh session per ``.append()`` — CLAUDE.md hard rule #7: audit rows
survive any caller rollback. That second-connection acquisition is exactly
why the SIDE_EFFECT pool is separate from the TURN pool: under the pre-#410
single-turn-transaction design, N in-flight turns each holding a TURN
connection while demanding a SIDE_EFFECT one deadlocked the unconfigured
shared pool (verified: 16 concurrent turns, 0 succeeded).
```

3b. In `Orchestrator.__init__`, add the new parameter after `side_effect_ledger` (keep every existing parameter and comment as-is):

```python
        # #410 PR1: the scope the two AuditWriters draw their per-append
        # sessions from. In production this is the SIDE_EFFECT-role scope —
        # audit writes are the ONE acquisition permitted while a TURN-role
        # phase transaction is open (hard rule #7; ADR-0062 hierarchy).
        # ``None`` falls back to ``session_scope`` so every existing caller
        # and test constructs byte-for-byte unchanged.
        audit_session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]]
        | None = None,
```

and change the body's audit-writer construction (currently `self._audit = self._audit_factory(self._session_scope)` and `self._autocommit_audit = self._autocommit_audit_factory(self._session_scope)`) to:

```python
        if audit_session_scope is None:
            # #410 PR1 (fleet finding M-10): the fallback is legitimate for
            # unit tests and pre-#410 construction paths, but a PRODUCTION
            # boot site omitting audit_session_scope silently points the
            # AuditWriters at the TURN pool — quietly re-coupling the two
            # pools this plan separates. Both real boot sites pass it
            # explicitly today; this once-at-construction warning makes any
            # future omission a visible decision, never a silent default.
            _log.warning("orchestrator.audit_session_scope_fallback")
        self._audit_session_scope = (
            audit_session_scope if audit_session_scope is not None else session_scope
        )
        self._audit = self._audit_factory(self._audit_session_scope)
        self._autocommit_audit = self._autocommit_audit_factory(self._audit_session_scope)
```

3c. Add the outcome dataclass at module level (below `_truncate_tool_result`, above `class Orchestrator`), and extend the `collections.abc` import line to `from collections.abc import Awaitable, Callable, Mapping`:

```python
@dataclass(frozen=True, slots=True)
class _TurnOutcome:
    """Everything Phase B decides that Phases C + the terminal row consume.

    Frozen: Phase B's result is a fact by the time Phase C runs — nothing
    downstream may edit it.
    """

    answer: str
    final_response: CompletionResponse
    final_result_token: str
    final_exit_reason: str | None
    answer_from_provider: bool
    estimate: float
    per_turn_spent_usd: float
    pending_completion_cost: float
```

(add `from dataclasses import dataclass` to the imports.)

3d. Replace `handle_user_message` (lines 389-546) in full with:

```python
    async def handle_user_message(
        self,
        *,
        user: UserLike,
        content: TaggedContent[T1] | TaggedContent[T2],
        working_memory: WorkingMemory,
        egress_context: TurnEgressContext | None = None,
    ) -> str:
        """Process one user turn end-to-end and return the assistant reply.

        ``user`` is the per-turn requester (may be the operator or any other
        authorized household user). ``content`` arrives already tagged at the
        orchestrator boundary — the host-side comms-MCP ingress path owns the
        tagging post-PR-S4-10;
        :func:`alfred.identity._ingest._ingest_tier` encodes the
        role-x-adapter rule but is currently unwired (reserved; see issue
        #237). The orchestrator reads ``content.content`` and
        ``content.tier.name`` but does not re-tag. The accepted tiers are T1
        (operator via TUI) and T2 (all other authenticated ingress); T3 NEVER
        reaches this method directly — T3 bytes live behind opaque
        ContentHandle references in the plugin host's content store (spec
        §3.1, §7.3). ``working_memory`` is the pool-acquired buffer for this
        (persona, user.slug) pair; the adapter owns its lifecycle (acquire
        before, release in finally). ``egress_context`` is the per-turn
        :class:`TurnEgressContext` the live comms inbound path passes so the
        egress ledger anchors to the real ``(adapter_id, inbound_id,
        session_id)`` identity; ``None`` (the default) synthesizes it from
        the ``trace_id`` for the ``alfred chat``/fixture path (#338).

        #410 PR1: the deadline wrapper now encloses the WHOLE three-phase
        sequence (Phase A observe-txn, Phase B provider/tools with no
        connection held, Phase C persist-txn + deferred appends + terminal
        row) instead of a single-session turn body. If the deadline or an
        external cancel fires during Phase B, no connection is held, so the
        autocommit audit writes below always acquire cleanly; if it fires
        during Phase A/C, that phase's own ``async with`` unwinds (rolling
        the transaction back) BEFORE either arm runs — the pre-#410
        recovery-ordering hazard (audit write needing a fresh connection
        BEFORE the held one was rolled back) is gone structurally, which is
        why the explicit ``session.rollback()`` calls that used to live in
        these arms no longer exist.

        Raises:
            BudgetError: pre-check refusal — or, for the 7th audit branch,
                ``UnknownBudgetUserError`` (defense-in-depth on a slug the
                resolver should have caught upstream). Phase A has committed
                by then: the orphan user episodic row is the ADR-0062
                accepted trade-off (replay re-denies the user gate and
                converges).
            Exception: re-raises the provider's exception if both providers
                in the router fail, and re-raises a phase-commit failure
                after recording ``action_outcome="commit_failed"``, writing
                the ``orchestrator.turn`` ``phase_commit:*`` audit row, and
                logging ``orchestrator.phase_commit_failed`` (see
                ``_run_committed_phase``).
            asyncio.CancelledError: re-raised after auditing on user cancel.
            Exception: re-raises the audit writer's exception if persistence
                breaks after a successful provider call (CLAUDE.md hard
                rule #7).
        """
        trace_id = str(uuid.uuid4())
        # PR-S3-3b Task 14: stamp the start of the action for the per-turn
        # Prometheus histogram. ``time.monotonic`` is the right clock here —
        # immune to NTP step adjustments and never goes backwards across a
        # suspended laptop or a leap second.
        action_start = time.monotonic()
        try:
            reply = await self._deadline_wrapper.run(
                self._run_turn_phases,
                user=user,
                content=content,
                working_memory=working_memory,
                trace_id=trace_id,
                egress_context=egress_context,
                action_start=action_start,
                _user_id=user.slug,
                _correlation_id=trace_id,
            )
        except TimeoutError:
            # PR-S3-3b Task 12 — the deadline fired. Two audit rows land on
            # the AUTOCOMMIT writer (its own SIDE_EFFECT-role sessions):
            #   1. ``supervisor.action_timeout`` — operator-facing row.
            #   2. ``orchestrator.turn`` ``result=cancelled`` — the turn's
            #      own cancellation row.
            # #410 PR1: no session is held here (see the method docstring),
            # so these writes always acquire a fresh connection cleanly.
            await self._emit_supervisor_timeout_row(
                user_id=user.slug,
                correlation_id=trace_id,
                action_duration_seconds=time.monotonic() - action_start,
            )
            await self._emit_orchestrator_turn_cancelled_row_autocommit(
                user=user,
                trace_id=trace_id,
                phase="turn_timeout",
            )
            record_action_duration(
                duration_seconds=time.monotonic() - action_start,
                user_id=user.slug,
                action_outcome="timeout",
                breaker_state="UNKNOWN",
            )
            raise asyncio.CancelledError("deadline expired") from None
        except asyncio.CancelledError:
            # External cancellation (NOT timeout-derived). CLAUDE.md hard
            # rule #7: cancellation at ANY awaited step in the turn MUST
            # write a ``cancelled`` audit row. ``_audit_cancellation`` opens
            # its own session (audit_session_scope), so the row COMMITS and
            # survives — the pre-#410 comment claiming this row was
            # "intentionally lost on rollback" described a wiring that never
            # matched the writer's own fresh-session-per-append contract and
            # is gone with the held session itself.
            await self._audit_cancellation(user=user, trace_id=trace_id, phase="turn_cancelled")
            record_action_duration(
                duration_seconds=time.monotonic() - action_start,
                user_id=user.slug,
                action_outcome="cancelled",
                breaker_state="UNKNOWN",
            )
            raise
        # Success telemetry fires only after the whole sequence (both commits,
        # deferred appends, terminal audit row) returned — same post-return
        # position as pre-#410, so a terminal-audit failure still records
        # nothing rather than a spurious "success" (§3.4 requirement 1's
        # commit-ordering half is carried by _run_committed_phase).
        record_action_duration(
            duration_seconds=time.monotonic() - action_start,
            user_id=user.slug,
            action_outcome="success",
            breaker_state="UNKNOWN",
        )
        return reply
```

3e. Replace `_handle_turn` (lines 684-1111) in full with the following six methods (everything from the old body is preserved verbatim where not explicitly changed — the Observe block moves into `_observe_user_turn`, the Orient+Act blocks into `_orient_and_act`, the assistant-persist block into `_persist_assistant_turn`, the terminal row into `_emit_turn_completed_row`):

```python
    async def _run_turn_phases(
        self,
        *,
        user: UserLike,
        content: TaggedContent[T1] | TaggedContent[T2],
        working_memory: WorkingMemory,
        trace_id: str,
        egress_context: TurnEgressContext | None,
        action_start: float,
    ) -> str:
        # ``trace_id`` is supplied by ``handle_user_message`` so the top-level
        # cancellation-audit row and the per-phase audit rows share the same
        # trace identifier. ctx is resolved once — both ledger gates and every
        # dispatch must key on the SAME (adapter_id, inbound_id).
        ctx = (
            egress_context
            if egress_context is not None
            else self._synthesize_egress_context(trace_id=trace_id, user=user)
        )
        user_input_text = content.content
        user_input_tier = content.tier.name

        # ── Phase A — Observe: ledger user-gate + episodic user row, ONE
        # short-lived transaction (ADR-0062). The gate travels with the write.
        user_turn_applied = await self._run_committed_phase(
            lambda session: self._observe_user_turn(
                session,
                user=user,
                user_input_text=user_input_text,
                user_input_tier=user_input_tier,
                ctx=ctx,
            ),
            user=user,
            trace_id=trace_id,
            trigger_tier=user_input_tier,
            phase="observe_user_turn",
            action_start=action_start,
        )
        # ONE orphan-counting arm spans everything BETWEEN Phase A's commit
        # and Phase C's commit (fleet finding M-14, widened by pass-2 finding
        # core-004): ANY failure in that span — the deferred user append,
        # a provider error, budget refusal, cancellation, deadline (both are
        # BaseExceptions), escalation, a Phase-C body exception, or Phase C's
        # own commit failure — leaves the IDENTICAL accepted
        # orphan-user-episodic-row state (ADR-0062). Count it on the way out
        # so the deliberate degradation has a production rate; the exception
        # itself propagates untouched to the existing arms. The post-commit
        # steps (deferred assistant append, terminal audit row) sit OUTSIDE
        # the arm: once Phase C committed, the assistant row exists and the
        # user row is no longer orphaned.
        try:
            if user_turn_applied:
                # Deferred until AFTER Phase A's commit: an append before
                # commit could survive a rollback the durable gate did not
                # (§3.3 of the 2026-08-08 design doc, carried into the phase
                # split).
                await working_memory.append(role="user", content=user_input_text)

            # ── Phase B — Orient + Act: NO database connection held. The
            # provider call, the tool loop, and every audit write happen
            # here; audit writers open their own SIDE_EFFECT-role sessions
            # per append.
            outcome = await self._orient_and_act(
                user=user,
                working_memory=working_memory,
                trace_id=trace_id,
                ctx=ctx,
                user_input_text=user_input_text,
                user_input_tier=user_input_tier,
                # §3.2, now CONDITIONAL under the phase split: on the happy path
                # Phase A already committed AND appended the user turn, so the
                # history read below ends on it — re-threading would duplicate
                # it. Only a denied user gate (a replay) needs the explicit
                # thread so the prompt never ends on an assistant turn (the
                # prefill-continuation bug). Keyed on the GATE RESULT — never on
                # content comparison.
                thread_current_user_message=not user_turn_applied,
            )

            # ── Phase C — Persist: ledger assistant-gate + episodic assistant
            # row, ONE short-lived transaction.
            assistant_turn_applied = await self._run_committed_phase(
                lambda session: self._persist_assistant_turn(
                    session, user=user, outcome=outcome, ctx=ctx
                ),
                user=user,
                trace_id=trace_id,
                trigger_tier=user_input_tier,
                phase="persist_assistant_turn",
                action_start=action_start,
            )
        except BaseException:
            if user_turn_applied:
                record_orphaned_user_turn(user_id=user.slug)
            raise

        if assistant_turn_applied:
            # Deferred post-commit append. Uncancelled-tail safety argument:
            # ``RealTurnOrchestratorAdapter._turn_locks``
            # (src/alfred/comms_mcp/real_turn_adapter.py:193-203) serialises
            # the whole turn per (persona, user_id), so this append's lock is
            # uncontended and returns without awaiting. Whoever removes or
            # bypasses that mutex inherits the obligation to re-derive this
            # safety argument (design doc §3.3; ADR-0062).
            await working_memory.append(role="assistant", content=outcome.answer)

        # Terminal ``completed`` audit row AFTER Phase C's scope has closed —
        # never nested inside it (its own fresh SIDE_EFFECT session must not
        # be an in-TURN acquisition when it doesn't have to be).
        await self._emit_turn_completed_row(
            user=user, trace_id=trace_id, outcome=outcome, user_input_tier=user_input_tier
        )
        _log.info(
            "orchestrator.turn",
            trace_id=trace_id,
            tokens_in=outcome.final_response.tokens_in,
            tokens_out=outcome.final_response.tokens_out,
            cost_usd=outcome.per_turn_spent_usd,
            charge_result=outcome.final_result_token,
        )
        return outcome.answer

    async def _run_committed_phase[R](
        self,
        body: Callable[[AsyncSession], Awaitable[R]],
        *,
        user: UserLike,
        trace_id: str,
        trigger_tier: str,
        phase: str,
        action_start: float,
    ) -> R:
        """Run ``body`` in ONE short-lived turn transaction; label commit failure.

        ``body_completed`` is the deterministic discriminator (§3.4): once the
        body returned, the only raiser left inside the ``async with`` is the
        scope's own ``session.commit()`` — so an ``Exception`` with
        ``body_completed=True`` IS a commit failure. Fleet finding H-2: every
        sibling failure arm in this turn (provider failure, budget refusal,
        terminal-row failure) writes an audit row, and a lost phase commit is
        at least as operator-significant — so a commit failure is recorded
        THREE ways before re-raising, never a spurious "success", never a
        metric-only whisper:

        * ``action_outcome="commit_failed"`` on the duration histogram;
        * a loud ``orchestrator.phase_commit_failed`` structlog error;
        * an ``orchestrator.turn`` audit row. ``result="failed"`` — an
          in-domain ``ck_audit_log_result`` value, reused across writers the
          same way the spawn-grant refusal row reuses ``'refused'``
          (models.py documents that precedent); the ``phase_commit:<phase>``
          ``subject.phase`` is the discriminator. The audit writer opens its
          OWN ``audit_session_scope`` session, so the row commits even though
          the phase's session is broken. If the audit write itself fails, it
          is logged loudly and the ORIGINAL commit exception still propagates
          — the same non-masking contract as ``_audit_cancellation``.

        The catch is deliberately ``Exception``, not ``BaseException``: a
        ``CancelledError`` landing during the commit await is a CANCELLATION
        (the scope's own ``BaseException`` arm already rolled the phase back;
        the caller's timeout/cancel arms own its audit + telemetry) — not a
        commit failure to double-report. Body failures likewise record
        nothing here; the caller's arms handle them exactly as before.
        """
        body_completed = False
        try:
            async with self._session_scope() as session:
                result = await body(session)
                body_completed = True
        except Exception as exc:
            if body_completed:
                record_action_duration(
                    duration_seconds=time.monotonic() - action_start,
                    user_id=user.slug,
                    action_outcome="commit_failed",
                    breaker_state="UNKNOWN",
                )
                _log.error(
                    "orchestrator.phase_commit_failed",
                    trace_id=trace_id,
                    phase=phase,
                    error=self._redactor(str(exc)),
                    error_type=type(exc).__name__,
                )
                try:
                    await self._audit.append(
                        event="orchestrator.turn",
                        actor_user_id=user.slug,
                        actor_persona=_ALFRED_PERSONA_ID,
                        subject=_sanitize_subject(
                            {
                                "phase": f"phase_commit:{phase}",
                                "error_type": type(exc).__name__,
                                "error": str(exc),
                            },
                            self._redactor,
                        ),
                        trust_tier_of_trigger=trigger_tier,
                        result="failed",
                        cost_estimate_usd=0.0,
                        cost_actual_usd=0.0,
                        trace_id=trace_id,
                        language=user.language,
                        persona_id=_ALFRED_PERSONA_ID,
                    )
                except Exception as audit_exc:
                    _log.error(
                        "orchestrator.commit_failed_audit_write_failed",
                        trace_id=trace_id,
                        phase=phase,
                        error=self._redactor(str(audit_exc)),
                        error_type=type(audit_exc).__name__,
                    )
            raise
        return result

    async def _observe_user_turn(
        self,
        session: AsyncSession,
        *,
        user: UserLike,
        user_input_text: str,
        user_input_tier: str,
        ctx: TurnEgressContext,
    ) -> bool:
        """Phase A body: user-gate + episodic user row in the caller's txn.

        ``content`` arrives already tagged at this boundary (host-side
        comms-MCP ingress owns tagging post-PR-S4-10; ``alfred.identity.
        _ingest._ingest_tier`` is reserved/unwired, see issue #237); T3 never
        reaches this method — T3 bytes are held in ContentHandle references
        only (spec §3.1). ``None`` ledger (every pre-#410 caller) means
        "always apply" — behaviour unchanged.
        """
        applied = (
            True
            if self._side_effect_ledger is None
            else await self._side_effect_ledger.try_apply_user_turn(
                session, adapter_id=ctx.adapter_id, inbound_id=ctx.inbound_id
            )
        )
        if not applied:
            return False
        episodic = self._episodic_factory(session)
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
        return True

    async def _orient_and_act(
        self,
        *,
        user: UserLike,
        working_memory: WorkingMemory,
        trace_id: str,
        ctx: TurnEgressContext,
        user_input_text: str,
        user_input_tier: str,
        thread_current_user_message: bool,
    ) -> _TurnOutcome:
        # ------------------------------------------------------------------
        # Orient — operator_name is the household OWNER (cached at
        # construction); addressed_user_name is the per-turn requester.
        # Mixing them up is the entire reason PR-B introduced two fields.
        # ------------------------------------------------------------------
        system_prompt = render_persona_prompt(
            persona=ALFRED_PERSONA,
            operator_name=self._operator.display_name,
            requesting_user_name=user.display_name,
            language=user.language,
        )
        history = await working_memory.turns()
        messages: list[Message] = [Message(role="system", content=system_prompt)]
        messages.extend(Message(role=turn.role, content=turn.content) for turn in history)
        if thread_current_user_message:
            # Replay path (user gate denied): the history already holds the
            # prior committed [user, assistant] pair and would otherwise END
            # on the assistant turn — which providers treat as a prefill to
            # continue, not a question to answer (§3.2). Redundant-but-
            # correct context; the prompt always ends on a fresh user turn.
            messages.append(Message(role="user", content=user_input_text))
        # ------------------------------------------------------------------
        # Act — the agentic tool-calling loop (#339 PR3, spec §6/§7/§9).
        #
        # The per-action DEADLINE (DeadlineWrapper in handle_user_message)
        # bounds the WHOLE loop; loop_constants.MAX_TOOL_ITERATIONS is the
        # cost/round-trip backstop under it (core-004). asyncio.CancelledError
        # from the deadline is NOT caught here — it propagates to the top-level
        # timeout/cancel arm (hard rule #7). dispatch_tool escalations (Task 3)
        # likewise propagate to halt the turn. With no registry the loop runs
        # exactly one iteration and reduces to the pre-#339 single-completion
        # turn (empty tools -> stop_reason "end_turn" on iteration 0).
        # ------------------------------------------------------------------
        tools = self._tool_registry.definitions() if self._tool_registry is not None else ()
        base_messages = messages  # system + history (built in Orient)
        local: list[Message] = []  # in-turn tool transcript (EPHEMERAL — never persisted)
        call_index = 0  # monotonic per-turn dispatch ordinal (threaded to the egress path)
        per_turn_spent_usd = 0.0
        pending_completion_cost = 0.0  # this completion's cost until a provider_call row logs it
        # Pyright can't prove the loop body below runs at least once (it only
        # sees MAX_TOOL_ITERATIONS as `Final[int]`, not a literal), so it
        # can't see that `estimate` is always assigned before the `completed`
        # audit row reads it. Runtime-safe either way — the constant is 8, so
        # the loop always executes — but the 0.0 here is never the value
        # actually persisted; it only satisfies the static analyzer.
        estimate: float = 0.0
        final_content: str | None = None
        final_response: CompletionResponse | None = None
        # "token" here means a closed-vocabulary audit result label
        # (ck_audit_log_result), not a credential — bandit's S105 pattern-
        # matches the variable name, not the value; suppressed below.
        final_result_token = "success"  # noqa: S105
        final_exit_reason: str | None = None  # set only on a non-normal exit

        for iteration in range(loop_constants.MAX_TOOL_ITERATIONS):
            request = CompletionRequest(
                messages=base_messages + local,
                tools=tools,
                tool_choice="auto",
            )

            # --- per-iteration budget pre-check (spec §7) ---
            try:
                estimate = self._budget.estimate_for(user.slug, request)
                would_exceed = self._budget.would_exceed(user.slug, estimate)
            except BudgetError as exc:
                if isinstance(exc, UnknownBudgetUserError):
                    await self._audit_unknown_budget_user(
                        user=user,
                        trace_id=trace_id,
                        phase="budget_pre_check",
                        trigger_tier=user_input_tier,
                    )
                raise
            if would_exceed:
                if iteration == 0:
                    # No spend yet — preserve the pre-#339 pre-check contract
                    # (a budget_pre_check row + a raised BudgetError). Existing
                    # test_pre_check_refusal_audits_and_raises depends on this.
                    await self._audit.append(
                        event="orchestrator.turn",
                        actor_user_id=user.slug,
                        actor_persona=_ALFRED_PERSONA_ID,
                        subject=_sanitize_subject(
                            {"phase": "budget_pre_check", "estimate_usd": estimate},
                            self._redactor,
                        ),
                        trust_tier_of_trigger=user_input_tier,
                        result="budget_blocked",
                        cost_estimate_usd=estimate,
                        cost_actual_usd=0.0,
                        trace_id=trace_id,
                        language=user.language,
                        persona_id=_ALFRED_PERSONA_ID,
                    )
                    raise BudgetError(
                        f"pre-check refused: estimate ${estimate:.4f} would breach budget"
                    )
                # Mid-turn (iteration >= 1): end gracefully; the terminal
                # `completed` row records it (FIX-6 — no separate row).
                final_content = t("orchestrator.tool.budget_exhausted_mid_turn")
                final_result_token = "budget_blocked"  # noqa: S105
                final_exit_reason = "budget_exhausted_mid_turn"
                break

            # --- completion (NEVER gather) ---
            try:
                response = await self._router.complete(request)
            except Exception as exc:
                _log.error(
                    "orchestrator.provider_failed",
                    trace_id=trace_id,
                    iteration=iteration,
                    error=self._redactor(str(exc)),
                    error_type=type(exc).__name__,
                )
                await self._audit.append(
                    event="orchestrator.turn",
                    actor_user_id=user.slug,
                    actor_persona=_ALFRED_PERSONA_ID,
                    subject=_sanitize_subject(
                        {
                            "phase": f"provider_call:{iteration}",
                            "error_type": type(exc).__name__,
                            "error": str(exc),
                        },
                        self._redactor,
                    ),
                    trust_tier_of_trigger=user_input_tier,
                    result="provider_failed",
                    cost_estimate_usd=estimate,
                    cost_actual_usd=0.0,
                    trace_id=trace_id,
                    language=user.language,
                    persona_id=_ALFRED_PERSONA_ID,
                )
                raise
            final_response = response

            # --- charge; force-record on overrun (spec §7, mem-002) ---
            charge_result = "success"
            try:
                self._budget.check_and_charge(user.slug, response.cost_usd)
            except BudgetError as exc:
                if isinstance(exc, UnknownBudgetUserError):
                    await self._audit_unknown_budget_user(
                        user=user,
                        trace_id=trace_id,
                        phase="budget_post_charge",
                        trigger_tier=user_input_tier,
                    )
                    raise
                charge_result = "budget_overrun"
                _log.warning(
                    "orchestrator.budget_overrun",
                    trace_id=trace_id,
                    iteration=iteration,
                    estimate_usd=estimate,
                    actual_usd=response.cost_usd,
                    error=self._redactor(str(exc)),
                )
            per_turn_spent_usd += response.cost_usd
            pending_completion_cost = response.cost_usd  # not yet logged to any row

            # --- terminal? (no tool request -> final answer). FIX-3: the
            #     terminal completion is audited SOLELY by the `completed` row
            #     — NO provider_call row here. This keeps the no-tools happy
            #     path at audit.append.await_count == 1 (byte-for-byte). ---
            if response.stop_reason != "tool_use" or not response.tool_calls:
                final_content = response.content
                final_result_token = charge_result  # "success" | "budget_overrun"
                break

            # --- non-terminal completion: audit it as provider_call:{iteration}
            #     (FIX-3 — only continuing completions get their own row). ---
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject(
                    {
                        "phase": f"provider_call:{iteration}",
                        "model": response.model,
                        "tokens_in": response.tokens_in,
                        "tokens_out": response.tokens_out,
                        "charge_result": charge_result,
                    },
                    self._redactor,
                ),
                trust_tier_of_trigger=user_input_tier,
                result=charge_result if charge_result == "budget_overrun" else "success",
                cost_estimate_usd=estimate,
                cost_actual_usd=response.cost_usd,
                trace_id=trace_id,
                language=user.language,
                persona_id=_ALFRED_PERSONA_ID,
            )
            pending_completion_cost = 0.0  # logged to the provider_call row above

            if charge_result == "budget_overrun":
                # Over cap AND the model wants more tools — stop before more egress.
                final_content = t("orchestrator.tool.budget_overrun_mid_turn")
                final_result_token = "budget_overrun"  # noqa: S105
                final_exit_reason = "budget_overrun_mid_turn"
                break

            # --- fan-out cap (spec §7, mem-003). FIX-6: fold into the terminal
            #     `completed` row below — no separate audit row. A single
            #     completion requesting more tools than the cap allows is
            #     refused outright rather than partially honoured (a partial
            #     dispatch would silently drop the model's remaining
            #     requests without telling it). ---
            if len(response.tool_calls) > loop_constants.MAX_TOOL_CALLS_PER_ITERATION:
                final_content = t("orchestrator.tool.too_many_tool_calls")
                final_result_token = "refused"  # noqa: S105
                final_exit_reason = "too_many_tool_calls"
                break

            # --- FINAL iteration: a further tool request cannot be fed back
            #     (there is no next completion to consume the results), so
            #     dispatching here would incur real egress + spend + a
            #     consumed call_index for results we would then have to
            #     discard. Stop now instead (spec §9 max-iterations bound). ---
            if iteration == loop_constants.MAX_TOOL_ITERATIONS - 1:
                final_content = t("orchestrator.tool.max_iterations_reached")
                final_result_token = "refused"  # noqa: S105 -- FIX-1: in-domain (NOT "max_iterations_reached")
                final_exit_reason = "max_iterations_reached"
                break

            # --- echo the assistant's tool-request turn into the EPHEMERAL
            #     local transcript (discarded after the turn; never persisted
            #     to working memory or episodic — only the final answer is). ---
            local.append(
                Message(role="assistant", content=response.content, tool_calls=response.tool_calls)
            )

            # --- deterministic ordered dispatch (NEVER gather; call_index
            #     monotonic across the whole turn, not per-iteration) ---
            # Not a behavioural guard, a construction-time invariant check:
            # reaching this branch means `response.tool_calls` is non-empty,
            # which is only possible when `tools` (built in Orient) was
            # non-empty, which is only possible when
            # `self._tool_registry is not None`. Production (#338) wires
            # registry/gate/dlp together as a trio, so a registry set without a
            # gate/dlp is a construction-time misconfiguration. An `assert`
            # here would be stripped under `python -O`, degrading this to an
            # opaque `AttributeError` inside `dispatch_tool` — an explicit
            # raise fails loud (hard rule #7) regardless of optimization flags,
            # and narrows all three for the `dispatch_tool` call below.
            if self._tool_registry is None or self._gate is None or self._outbound_dlp is None:
                # t()'d for consistency with the sibling quarantined_extract
                # wiring guards above (source_tier_must_be_t3 / no_extractor_wired).
                raise RuntimeError(t("orchestrator.tool.dispatch_seams_unwired"))
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
                local.append(
                    Message(
                        role="tool",
                        tool_call_id=call.id,
                        content=_truncate_tool_result(result_t2),
                    )
                )

        # final_response is None ONLY on the iteration-0 pre-check raise / provider
        # failure paths, which do not reach here (they raise). So it is populated
        # on every path that reaches this point.
        assert final_response is not None
        answer = final_content if final_content is not None else final_response.content
        return _TurnOutcome(
            answer=answer,
            final_response=final_response,
            final_result_token=final_result_token,
            final_exit_reason=final_exit_reason,
            # A synthetic refusal (final_exit_reason set) is a local i18n
            # string, not a provider completion — its episodic row must carry
            # ZERO provider tokens/cost (the real cost already rode the
            # provider_call:* rows).
            answer_from_provider=final_exit_reason is None,
            estimate=estimate,
            per_turn_spent_usd=per_turn_spent_usd,
            pending_completion_cost=pending_completion_cost,
        )

    async def _persist_assistant_turn(
        self,
        session: AsyncSession,
        *,
        user: UserLike,
        outcome: _TurnOutcome,
        ctx: TurnEgressContext,
    ) -> bool:
        """Phase C body: assistant-gate + episodic assistant row in the caller's txn.

        ADR-0008: assistant output is T2 in Slice 1+2 (at-most-as-trusted as
        the T2 input that triggered it). ``outcome.answer`` is still returned
        by the caller regardless of this gate — a resumed turn always sends
        SOMETHING (a fresh completion's text, per ADR-0049's accepted
        "duplicate paid completion" residual) — this gate only stops that
        text from ALSO being re-persisted as a second assistant turn.
        """
        applied = (
            True
            if self._side_effect_ledger is None
            else await self._side_effect_ledger.try_apply_assistant_turn(
                session, adapter_id=ctx.adapter_id, inbound_id=ctx.inbound_id
            )
        )
        if not applied:
            return False
        episodic = self._episodic_factory(session)
        # FIX-15: episodic.record logs the FINAL completion's cost/tokens (the
        # answer's attribution); the `completed` audit row logs the TURN total
        # (per_turn_spent_usd). For a multi-completion turn these differ BY
        # DESIGN — episodic = answer attribution, audit = turn spend.
        await episodic.record(
            user_id=user.slug,
            role="assistant",
            content=outcome.answer,
            trust_tier="T2",
            tokens_in=outcome.final_response.tokens_in if outcome.answer_from_provider else 0,
            tokens_out=outcome.final_response.tokens_out if outcome.answer_from_provider else 0,
            cost_usd=outcome.final_response.cost_usd if outcome.answer_from_provider else 0.0,
            language=user.language,
            persona=_ALFRED_PERSONA_ID,
            # See _observe_user_turn for the persona vs persona_id rationale.
            persona_id=_ALFRED_PERSONA_ID,
        )
        return True

    async def _emit_turn_completed_row(
        self,
        *,
        user: UserLike,
        trace_id: str,
        outcome: _TurnOutcome,
        user_input_tier: str,
    ) -> None:
        completed_subject: dict[str, object] = {
            "phase": "completed",
            "model": outcome.final_response.model,
            "tokens_in": outcome.final_response.tokens_in,
            "tokens_out": outcome.final_response.tokens_out,
            "charge_result": outcome.final_result_token,
            "turn_cost_usd": outcome.per_turn_spent_usd,
        }
        if outcome.final_exit_reason is not None:
            completed_subject["exit_reason"] = outcome.final_exit_reason
        try:
            await self._audit.append(
                event="orchestrator.turn",
                actor_user_id=user.slug,
                actor_persona=_ALFRED_PERSONA_ID,
                subject=_sanitize_subject(completed_subject, self._redactor),
                trust_tier_of_trigger=user_input_tier,
                result=outcome.final_result_token,
                cost_estimate_usd=outcome.estimate,  # MINOR-A: terminal estimate
                cost_actual_usd=outcome.pending_completion_cost,  # FIX-3: terminal cost only
                trace_id=trace_id,
                language=user.language,
                persona_id=_ALFRED_PERSONA_ID,
            )
        except Exception as exc:
            # CLAUDE.md hard rule #7: audit-path failures are loud.
            _log.error(
                "orchestrator.audit_write_failed",
                trace_id=trace_id,
                error=self._redactor(str(exc)),
                error_type=type(exc).__name__,
            )
            raise
```

3f. Extend the existing `from alfred.supervisor.observability import record_action_duration` import in `core.py` to `from alfred.supervisor.observability import record_action_duration, record_orphaned_user_turn` (the Phase-B orphan counter in `_run_turn_phases` above).

- [ ] **Step 4: Upgrade the session-scope test double to MODEL the real scope**

In `tests/unit/orchestrator/test_core.py`, replace `_make_session_scope` (lines 89-99) with:

```python
def _make_session_scope() -> tuple[Any, MagicMock]:
    """Return (scope_callable, session_mock).

    The scope MODELS the real alfred.memory.db.session_scope — commit on
    clean exit, rollback + re-raise on BaseException. The BaseException arm
    is load-bearing (fleet finding H-1): the real scope rolls back
    EXPLICITLY on asyncio.CancelledError too, and a double that only rolled
    back on Exception would hide exactly the cancellation-mid-phase class
    the real scope exists to handle. A test double must model the real
    object: the old always-just-yield double could not distinguish "phase
    committed" from "phase rolled back", which is the entire property
    #410 PR1 turns on.
    """
    session = MagicMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()

    @asynccontextmanager
    async def scope() -> AsyncIterator[MagicMock]:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise

    return scope, session
```

- [ ] **Step 5: Flip the assertions the phase split legitimately changes**

Each flip below pins the NEW, deliberate behavior (the Phase-B-failure orphan-user-row trade-off). Apply exactly:

1. Line ~313-314 (`test_records_episode_calls_provider_and_audits`), replace:

```python
        # Session was not rolled back.
        m["session"].rollback.assert_not_awaited()
```

with:

```python
        # Both phase transactions committed; nothing rolled back.
        assert m["session"].commit.await_count == 2
        m["session"].rollback.assert_not_awaited()
```

2. Line ~349-350 (`test_pre_check_refusal_audits_and_raises`), replace:

```python
        # Session rolled back because we raised out of the scope.
        m["session"].rollback.assert_awaited()
```

with:

```python
        # #410 PR1: the refusal fires in Phase B, AFTER Phase A committed the
        # user episode — the accepted orphan-user-row trade-off (ADR-0062).
        # Nothing is rolled back because no transaction is open in Phase B.
        assert m["session"].commit.await_count == 1
        m["session"].rollback.assert_not_awaited()
```

3. Line ~373-374 (`test_provider_exception_is_audited_and_re_raised`), replace:

```python
        # Rollback fired on the way out.
        m["session"].rollback.assert_awaited()
```

with:

```python
        # #410 PR1: the provider failed in Phase B — Phase A's commit stands
        # (orphan user row, ADR-0062); no transaction was open to roll back.
        assert m["session"].commit.await_count == 1
        m["session"].rollback.assert_not_awaited()
```

4. Line ~388-389 (`test_post_success_audit_failure_propagates`), replace:

```python
        # Rollback fired because we propagated out of the session scope.
        m["session"].rollback.assert_awaited()
```

with:

```python
        # #410 PR1: the terminal audit row fires AFTER Phase C committed —
        # both phase commits stand; the audit failure propagates loudly with
        # no transaction left open to roll back.
        assert m["session"].commit.await_count == 2
        m["session"].rollback.assert_not_awaited()
```

5. Line ~559-560 (`test_user_cancellation_inside_provider_call_is_audited`), replace:

```python
        # User-content txn rolled back as part of the outer BaseException arm.
        m["session"].rollback.assert_awaited()
```

with:

```python
        # #410 PR1: the cancel landed in Phase B — Phase A's commit stands.
        assert m["session"].commit.await_count == 1
        m["session"].rollback.assert_not_awaited()
```

6. Line ~581 (`test_cancellation_before_provider_call_is_still_audited`) — the cancel now lands in the DEFERRED post-commit append, replace:

```python
        m["session"].rollback.assert_awaited()
```

with:

```python
        # #410 PR1: working_memory.append is the deferred post-commit step —
        # the cancel lands AFTER Phase A committed, outside any transaction.
        assert m["session"].commit.await_count == 1
        m["session"].rollback.assert_not_awaited()
```

7. Line ~615 (`test_cancellation_after_provider_call_is_still_audited`) — the cancel lands inside Phase C's scope; CancelledError (a BaseException) hits the scope's explicit `except BaseException:` rollback arm (fleet finding H-1) before propagating, replace:

```python
        m["session"].rollback.assert_awaited()
```

with:

```python
        # #410 PR1: the cancel landed inside Phase C's scope — Phase A
        # committed, Phase C did not. The scope's BaseException arm rolled
        # Phase C back EXPLICITLY (never the implicit-close fallback), so the
        # rollback assertion is KEPT, now joined by the phase-commit count.
        assert m["session"].commit.await_count == 1
        m["session"].rollback.assert_awaited()
```

8. Lines ~652 and ~678 (`test_unknown_budget_user_on_pre_check_audits_and_reraises`, `test_unknown_budget_user_on_post_charge_audits_and_reraises`) — both raise in Phase B; in EACH, replace:

```python
        # Session rolled back on the way out.
        m["session"].rollback.assert_awaited()
```

with:

```python
        # #410 PR1: raised in Phase B — Phase A's commit stands (orphan user
        # row, ADR-0062); nothing to roll back.
        assert m["session"].commit.await_count == 1
        m["session"].rollback.assert_not_awaited()
```

9. Lines ~860-874: rename `test_timeout_rolls_back_user_content_session` and flip its body:

```python
    async def test_timeout_leaves_no_transaction_open(self) -> None:
        """#410 PR1: the deadline fires during Phase B (the slow provider),
        where NO transaction is open — Phase A's sub-ms commit already stood.
        The pre-#410 assertion (an explicit outer session.rollback()) pinned
        machinery that no longer exists; the property that replaced it is
        "Phase A committed, nothing held, nothing to roll back"."""
        router = MagicMock()

        async def _slow_complete(*_args: Any, **_kwargs: Any) -> Any:
            await asyncio.sleep(10)
            return None  # pragma: no cover — deadline fires first

        router.complete = AsyncMock(side_effect=_slow_complete)
        orch, m = _build(router=router, deadline_seconds=0.001)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "deadline-fires")

        assert m["session"].commit.await_count == 1
        m["session"].rollback.assert_not_awaited()
```

10. Update the two now-stale prose blocks: in `TestOrchestratorActionDeadline`'s class docstring (lines ~724-733) replace the final two bullets (`* The orchestrator ALSO emits ... would lose the row to the rollback that follows.` and `* The session is rolled back and ...`) with:

```text
    * The orchestrator ALSO emits an ``orchestrator.turn`` ``result=cancelled``
      row via the autocommit writer.
    * #410 PR1: no session is held when the deadline fires mid-Phase-B (and a
      deadline inside Phase A/C unwinds that phase's own scope first), so
      there is no rollback step in the arm any more — ``CancelledError`` is
      re-raised so higher-level cancellation handling stays unchanged.
```

and in `tests/unit/orchestrator/test_act_loop.py` (lines ~88-95) replace the comment inside `_make_orchestrator`'s `_scope`:

```python
        # ``rollback`` must be an AsyncMock (mirrors test_core.py's ``_build``):
        # the top-level ``except BaseException`` arm in ``handle_user_message``
        # awaits ``session.rollback()`` on ANY propagating exception — including
        # the Task 3 escalation-propagation tests' faked ``dispatch_tool``
        # raises. A plain ``MagicMock`` attribute is a sync callable and would
        # raise ``TypeError: 'MagicMock' object can't be awaited`` there,
        # masking the escalation the test means to observe.
```

with:

```python
        # #410 PR1: handle_user_message no longer calls session.rollback()
        # itself (each phase's scope owns rollback), but the double keeps
        # commit/rollback as AsyncMocks so it stays shaped like a real
        # AsyncSession for any scope double that models the real session_scope.
```

and add `session.commit = AsyncMock()` beside the existing `session.rollback = AsyncMock()` line there.

- [ ] **Step 6: Replace the silently-stale ordering test and add the new coverage**

In `tests/unit/orchestrator/test_core.py`, DELETE `test_gate_is_awaited_before_the_guarded_write_starts` (lines 1173-1196) and add these to `TestTurnSideEffectLedgerGating`:

```python
    async def test_gate_write_commit_append_order_is_pinned_per_phase(self) -> None:
        """Replaces test_gate_is_awaited_before_the_guarded_write_starts, whose
        call_order[:2] == ["gate","write"] assertion kept passing no matter how
        much code ran between the two labels (silently stale under the phase
        split). The property that matters now, per phase: gate -> episodic
        write (same txn) -> COMMIT -> deferred working-memory append. An
        append that ever precedes its phase's commit is the §3.3 regression."""
        call_order: list[str] = []
        ledger = _make_side_effect_ledger()

        # NOTE: every tracking side_effect below is an ASYNC def — AsyncMock
        # only awaits an async side_effect; a sync lambda returning a
        # coroutine hands the un-awaited coroutine back as the call's result
        # (truthy, so the gate would "pass" without ever recording its label).
        # The real gate takes (session, *, adapter_id, inbound_id); *_args
        # absorbs the positional session.
        async def _gate_user(*_args: object, **_kw: object) -> bool:
            call_order.append("gate:user")
            return True

        async def _gate_assistant(*_args: object, **_kw: object) -> bool:
            call_order.append("gate:assistant")
            return True

        ledger.try_apply_user_turn = AsyncMock(side_effect=_gate_user)
        ledger.try_apply_assistant_turn = AsyncMock(side_effect=_gate_assistant)
        orch, m = _build(side_effect_ledger=ledger)

        async def _tracked_record(**kw: object) -> None:
            call_order.append(f"episodic:{kw['role']}")

        m["episodic"].record = AsyncMock(side_effect=_tracked_record)

        async def _tracked_commit() -> None:
            call_order.append("commit")

        m["session"].commit = AsyncMock(side_effect=_tracked_commit)
        original_append = m["working"].append

        async def _tracked_append(**kw: object) -> None:
            call_order.append(f"append:{kw['role']}")
            await original_append(**kw)

        m["working"].append = AsyncMock(side_effect=_tracked_append)
        await _send(orch, m, "ordering")
        assert call_order == [
            "gate:user",
            "episodic:user",
            "commit",
            "append:user",
            "gate:assistant",
            "episodic:assistant",
            "commit",
            "append:assistant",
        ]

    async def test_replayed_turn_with_denied_user_gate_still_ends_prompt_on_user(
        self,
    ) -> None:
        """§3.2 precise prefill pin: the request's LAST message must be a USER
        turn carrying the current text — not an assistant tail, which
        providers treat as a prefill continuation to extend rather than a
        question to answer. Turn counts alone cannot catch this class."""
        ledger = _make_side_effect_ledger(user_turn=False)
        orch, m = _build(side_effect_ledger=ledger)
        # Prefill the buffer with the PRIOR committed attempt's exchange —
        # what WorkingMemoryPool rehydration yields on a send-failed retry.
        await m["working"].append(role="user", content="original question")
        await m["working"].append(role="assistant", content="original answer")
        reply = await _send(orch, m, "original question")
        assert reply == "Very good, Sir."
        req = m["router"].complete.await_args.args[0]
        assert req.messages[-1].role == "user"
        assert req.messages[-1].content == "original question"
        # Redundant-but-correct: the committed pair appears exactly once.
        assert [msg.role for msg in req.messages] == ["system", "user", "assistant", "user"]

    async def test_happy_path_does_not_double_thread_the_current_user_message(
        self,
    ) -> None:
        """§3.2's conditionality: an APPLIED user gate means the post-commit
        append already put the current turn in history — unconditional
        threading would duplicate it. Keyed on the gate result, never content
        comparison."""
        ledger = _make_side_effect_ledger()
        orch, m = _build(side_effect_ledger=ledger)
        await _send(orch, m, "fresh question")
        req = m["router"].complete.await_args.args[0]
        assert req.messages[-1].role == "user"
        assert req.messages[-1].content == "fresh question"
        occurrences = [
            msg
            for msg in req.messages
            if msg.role == "user" and msg.content == "fresh question"
        ]
        assert len(occurrences) == 1

    async def test_phase_b_failure_appends_user_but_never_assistant(self) -> None:
        """Assertion-contract note (design doc §5 "Task 4" — this plan's
        Task 6 per the design doc's status-block numbering key): exception
        propagation alone passes on both buggy and fixed code — this test
        spies the REAL WorkingMemory and pins WHICH appends happened. Under
        the phase split a Phase-B failure legitimately leaves the user append
        (Phase A committed first — the ADR-0062 orphan trade-off); the
        assistant append must NEVER have run."""
        from alfred.memory.working import WorkingMemory as RealWorkingMemory

        real_wm = RealWorkingMemory()
        append_roles: list[str] = []
        original_append = real_wm.append

        async def _spy_append(*, role: str, content: str) -> None:
            append_roles.append(role)
            await original_append(role=role, content=content)  # type: ignore[arg-type]

        real_wm.append = _spy_append  # type: ignore[method-assign]
        router = MagicMock()
        router.complete = AsyncMock(side_effect=RuntimeError("upstream 503"))
        orch, m = _build(working=real_wm, router=router)  # type: ignore[arg-type]

        with pytest.raises(RuntimeError, match="upstream 503"):
            await _send(orch, m, "will fail in phase B")

        assert append_roles == ["user"]
        assert [turn.role for turn in await real_wm.turns()] == ["user"]

    async def test_phase_commit_failure_records_commit_failed_and_appends_nothing(
        self, monkeypatch: Any
    ) -> None:
        """§3.3/§3.4 + fleet finding H-2: a commit failure records its OWN
        outcome AND its own audit row AND a loud structlog line (never a
        spurious success, never a metric-only whisper — every sibling failure
        arm in the same method audits), the exception propagates, and the
        deferred append NEVER ran — fail-closed by construction."""
        from structlog.testing import capture_logs

        recorder = MagicMock()
        monkeypatch.setattr("alfred.orchestrator.core.record_action_duration", recorder)
        orch, m = _build()
        m["session"].commit = AsyncMock(side_effect=RuntimeError("commit refused"))

        with capture_logs() as cap_logs:
            with pytest.raises(RuntimeError, match="commit refused"):
                await _send(orch, m, "hi")

        outcomes = [c.kwargs["action_outcome"] for c in recorder.call_args_list]
        assert outcomes == ["commit_failed"]  # exactly one observation, no "success"
        m["working"].append.assert_not_awaited()
        m["session"].rollback.assert_awaited()  # the modeled scope rolled the phase back
        # Fleet finding H-2: the failure is a loud audit row, not only a metric.
        # The audit writer has its own session, so the row survives the broken
        # phase session. (This fails in Phase A: subject.phase names it.)
        commit_rows = [
            c
            for c in m["audit"].append.await_args_list
            if str(c.kwargs["subject"].get("phase", "")).startswith("phase_commit:")
        ]
        assert len(commit_rows) == 1
        assert commit_rows[0].kwargs["result"] == "failed"
        assert commit_rows[0].kwargs["subject"]["phase"] == "phase_commit:observe_user_turn"
        assert commit_rows[0].kwargs["subject"]["error_type"] == "RuntimeError"
        # structlog does NOT land in caplog — capture_logs() is the harness.
        assert any(e["event"] == "orchestrator.phase_commit_failed" for e in cap_logs)

    async def test_cancellation_inside_phase_a_rolls_back_and_appends_nothing(
        self,
    ) -> None:
        """Fleet finding H-1's orchestrator-level twin (unit tier, no
        Postgres): a REAL task.cancel() delivered while Phase A's transaction
        is open (episodic.record parks until cancelled) must hit the scope's
        explicit BaseException rollback — un-marking the gate with it — and
        the deferred post-commit append must never run. Mirrors the
        real-driver proof in tests/integration/
        test_turn_side_effect_ledger_postgres.py; here the modeled scope
        (Step 4's double) stands in for session_scope, and the REAL
        WorkingMemory proves no append leaked."""
        from alfred.memory.working import WorkingMemory as RealWorkingMemory

        real_wm = RealWorkingMemory()
        record_started = asyncio.Event()

        async def _parked_record(**_kw: object) -> None:
            record_started.set()
            # The ONLY exit from this await is the injected CancelledError.
            await asyncio.Event().wait()

        orch, m = _build(working=real_wm)  # type: ignore[arg-type]
        m["episodic"].record = AsyncMock(side_effect=_parked_record)

        task = asyncio.create_task(_send(orch, m, "cancel mid phase A"))
        async with asyncio.timeout(5):
            await record_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # The modeled scope's BaseException arm rolled Phase A back...
        m["session"].rollback.assert_awaited()
        m["session"].commit.assert_not_awaited()
        # ...the deferred post-commit append never ran...
        assert await real_wm.turns() == []
        # ...and the cancellation was still audited (hard rule #7).
        cancel_rows = [
            c
            for c in m["audit"].append.await_args_list
            if c.kwargs.get("result") == "cancelled"
        ]
        assert len(cancel_rows) == 1

    async def test_phase_b_failure_increments_the_orphaned_user_turn_counter(
        self,
    ) -> None:
        """Fleet finding M-14: the accepted orphan-user-row trade-off gets a
        production rate. A Phase-B provider failure after Phase A committed
        increments alfred_orchestrator_orphaned_user_turn_total under the
        requester's bucket; the exception still propagates untouched."""
        from prometheus_client import REGISTRY

        from alfred.supervisor.observability import bucket_user_id

        labels = {"user_id_bucket": bucket_user_id(_default_user().slug)}
        before = (
            REGISTRY.get_sample_value(
                "alfred_orchestrator_orphaned_user_turn_total", labels
            )
            or 0.0
        )
        router = MagicMock()
        router.complete = AsyncMock(side_effect=RuntimeError("upstream 503"))
        orch, m = _build(router=router)

        with pytest.raises(RuntimeError, match="upstream 503"):
            await _send(orch, m, "will orphan the user row")

        after = REGISTRY.get_sample_value(
            "alfred_orchestrator_orphaned_user_turn_total", labels
        )
        assert after == before + 1.0

    async def test_phase_c_failure_increments_the_orphaned_user_turn_counter(
        self,
    ) -> None:
        """Pass-2 finding core-004 (cross-check widening of M-14): an ORDINARY
        Phase-C body exception — not just a deadline/cancellation — leaves the
        IDENTICAL committed-user-row-with-no-assistant-row state and must be
        counted on the same metric. Here the episodic ASSISTANT write raises
        inside Phase C's transaction; Phase A's commit stands, Phase C rolls
        back, and the orphan is counted on the way out."""
        from prometheus_client import REGISTRY

        from alfred.supervisor.observability import bucket_user_id

        labels = {"user_id_bucket": bucket_user_id(_default_user().slug)}
        before = (
            REGISTRY.get_sample_value(
                "alfred_orchestrator_orphaned_user_turn_total", labels
            )
            or 0.0
        )
        orch, m = _build()

        async def _fail_assistant_record(**kw: object) -> None:
            if kw["role"] == "assistant":
                raise RuntimeError("phase C write refused")

        m["episodic"].record = AsyncMock(side_effect=_fail_assistant_record)

        with pytest.raises(RuntimeError, match="phase C write refused"):
            await _send(orch, m, "will orphan via phase C")

        after = REGISTRY.get_sample_value(
            "alfred_orchestrator_orphaned_user_turn_total", labels
        )
        assert after == before + 1.0
        # Phase A committed; Phase C rolled back — the orphan state is real,
        # not an artifact of the counting arm.
        assert m["session"].commit.await_count == 1
        m["session"].rollback.assert_awaited()
```

And add to `TestThreePhaseConnectionDiscipline` (from Step 1) the audit-scope constructor tests:

```python
    async def test_audit_factories_receive_the_audit_session_scope_when_provided(
        self,
    ) -> None:
        seen: list[object] = []

        def _capturing_factory(f: Any) -> MagicMock:
            seen.append(f)
            writer = MagicMock()
            writer.append = AsyncMock()
            writer.append_schema = AsyncMock()
            return writer

        turn_scope, _s1 = _make_session_scope()
        audit_scope, _s2 = _make_session_scope()
        resolver = MagicMock()
        resolver.get_operator = MagicMock(return_value=_default_operator())
        Orchestrator(
            identity_resolver=resolver,
            session_scope=turn_scope,
            router=MagicMock(),
            budget=_make_budget(),
            audit_factory=_capturing_factory,
            autocommit_audit_factory=_capturing_factory,
            audit_session_scope=audit_scope,
        )
        assert seen == [audit_scope, audit_scope]

    async def test_audit_factories_fall_back_to_session_scope_when_omitted(self) -> None:
        """Fleet finding M-10: the fallback is pinned EXPLICITLY (a future
        change to this default must break a test, not slip through), and it
        warns once at construction — a production boot site omitting
        audit_session_scope would silently re-couple the two pools."""
        from structlog.testing import capture_logs

        seen: list[object] = []

        def _capturing_factory(f: Any) -> MagicMock:
            seen.append(f)
            writer = MagicMock()
            writer.append = AsyncMock()
            writer.append_schema = AsyncMock()
            return writer

        turn_scope, _s1 = _make_session_scope()
        resolver = MagicMock()
        resolver.get_operator = MagicMock(return_value=_default_operator())
        with capture_logs() as cap_logs:
            Orchestrator(
                identity_resolver=resolver,
                session_scope=turn_scope,
                router=MagicMock(),
                budget=_make_budget(),
                audit_factory=_capturing_factory,
                autocommit_audit_factory=_capturing_factory,
            )
        # Backward-compat: omitted audit_session_scope == the turn scope, so
        # every pre-#410 caller/test constructs byte-for-byte unchanged.
        assert seen == [turn_scope, turn_scope]
        # The fallback is visible, never silent (structlog does not land in
        # caplog — capture_logs() is the harness).
        assert any(
            e["event"] == "orchestrator.audit_session_scope_fallback" for e in cap_logs
        )
```

And add to `TestOrchestratorActionDeadline` (directly after the renamed `test_timeout_leaves_no_transaction_open` from Step 5 item 9 — pass-2 finding core-005: until now only an external `task.cancel()` proxy and a Phase-B-only deadline test existed; no test exercised a REAL `DeadlineWrapper` expiry landing inside Phase A/C's open transaction):

```python
    async def test_deadline_expiry_inside_phase_a_rolls_back_and_audits_timeout(
        self, monkeypatch: Any
    ) -> None:
        """Pass-2 finding core-005: the external task.cancel() test
        (test_cancellation_inside_phase_a_rolls_back_and_appends_nothing)
        proves the rollback path for a DELIVERED cancellation; this one
        proves the same behavior when the cancellation source is the turn's
        OWN DeadlineWrapper expiring while Phase A's transaction is open —
        episodic.record parks past the deadline (the same deterministic
        short-deadline pattern as test_timeout_leaves_no_transaction_open;
        the difference is WHERE the deadline lands: inside a phase
        transaction, not Phase B)."""
        recorder = MagicMock()
        monkeypatch.setattr("alfred.orchestrator.core.record_action_duration", recorder)

        async def _parked_record(**_kw: object) -> None:
            # The ONLY exit from this await is the deadline's CancelledError.
            await asyncio.Event().wait()

        orch, m = _build(deadline_seconds=0.001)
        m["episodic"].record = AsyncMock(side_effect=_parked_record)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "deadline lands in phase A")

        # The scope's explicit BaseException arm rolled Phase A back — a
        # deadline-driven cancellation un-marks the gate exactly like an
        # external one; nothing committed.
        m["session"].rollback.assert_awaited()
        m["session"].commit.assert_not_awaited()
        # The deferred post-commit append never ran.
        m["working"].append.assert_not_awaited()
        # The timeout arm's audit + telemetry contract holds unchanged for a
        # deadline landing inside a phase transaction: the turn-cancelled row
        # rides the AUTOCOMMIT writer's append(), the
        # supervisor.action_timeout row its append_schema(), and the
        # histogram outcome is "timeout" — never "commit_failed" (the scope
        # rolled back; no commit was attempted after the body).
        cancel_rows = [
            c
            for c in m["autocommit_audit"].append.await_args_list
            if c.kwargs.get("result") == "cancelled"
        ]
        assert len(cancel_rows) == 1
        assert m["autocommit_audit"].append_schema.await_count == 1
        outcomes = [c.kwargs["action_outcome"] for c in recorder.call_args_list]
        assert outcomes == ["timeout"]
```

- [ ] **Step 7: Run the orchestrator unit suites**

Run: `uv run pytest tests/unit/orchestrator -q`
Expected: all PASS (including every flip and every new test; `test_act_loop.py` and the burst/dispatch files pass untouched apart from the comment edit).

- [ ] **Step 8: Prove each new test bites (fail-first / mutation evidence — fleet finding H-4)**

Task 4 sets the bar (reintroduce the bug, confirm the test fails for the right reason, revert); the same bar applies to every new test this task adds — two of these tests' own docstrings quote the project's vacuous-test warning, so shipping them unverified would be the documented failure mode. The Step-1 driver (`test_no_turn_scope_is_open_while_the_provider_call_runs`) already has its evidence: Step 2 ran it against the pre-restructure code and it failed `assert [1] == [0]`. For each remaining new test: apply the ONE mutation named below to the fresh post-Step-3 code, run ONLY that test, confirm it FAILS for the stated reason, then `git restore` the mutated file before the next mutation (restore, not `checkout --`). All mutations are in `src/alfred/orchestrator/core.py` unless stated.

1. `test_gate_write_commit_append_order_is_pinned_per_phase` — in `_run_turn_phases`, insert `await working_memory.append(role="user", content=user_input_text)` directly ABOVE the Phase-A `user_turn_applied = await self._run_committed_phase(` statement and delete the conditional append from inside the shared try below. Expect FAIL: `call_order` starts `["append:user", "gate:user", ...]` (append preceded its phase's commit — the §3.3 regression).
2. `test_replayed_turn_with_denied_user_gate_still_ends_prompt_on_user` — change `thread_current_user_message=not user_turn_applied` to `thread_current_user_message=False`. Expect FAIL: the request's last message is the assistant tail.
3. `test_happy_path_does_not_double_thread_the_current_user_message` — change the same line to `thread_current_user_message=True`. Expect FAIL: two occurrences of the fresh user message. (2 and 3 pin OPPOSITE arms of one conditional — together they kill both constant-mutants of the gate-keyed threading.)
4. `test_phase_b_failure_appends_user_but_never_assistant` — in `_run_turn_phases`'s shared Phase-B/C `except BaseException:` arm, insert `await working_memory.append(role="assistant", content="mutant")` before `raise`. Expect FAIL: `append_roles == ["user", "assistant"]`.
5. `test_phase_commit_failure_records_commit_failed_and_appends_nothing` — TWO mutations, run separately: (a) in `_run_committed_phase`, change `action_outcome="commit_failed"` to `action_outcome="success"` — expect FAIL on the outcomes list; (b) delete the `await self._audit.append(...)` block from the commit-failure arm — expect FAIL on `len(commit_rows) == 1`.
6. `test_cancellation_inside_phase_a_rolls_back_and_appends_nothing` AND `test_deadline_expiry_inside_phase_a_rolls_back_and_audits_timeout` — in `tests/unit/orchestrator/test_core.py`'s `_make_session_scope` double, narrow `except BaseException:` back to `except Exception:`. Expect BOTH to FAIL: `rollback.assert_awaited()` (this is precisely the double-hides-the-cancellation-class bug the BaseException arm exists to model, for the external-cancel and deadline-driven cancellation sources alike; the REAL scope's equivalents are Task 1's unit test and Task 4's `task.cancel()` integration test).
7. `test_phase_b_failure_increments_the_orphaned_user_turn_counter` AND `test_phase_c_failure_increments_the_orphaned_user_turn_counter` — invert the shared orphan arm's guard to `if not user_turn_applied:`. Expect BOTH to FAIL: counter unchanged.
8. `test_phase_c_failure_increments_the_orphaned_user_turn_counter` — move the Phase-C `assistant_turn_applied = await self._run_committed_phase(...)` statement OUT of the shared try, to directly below the `except BaseException:` arm. Expect FAIL: counter unchanged — while `test_phase_b_failure_increments_the_orphaned_user_turn_counter` still PASSES, proving this mutation reproduces exactly the Phase-B-only coverage gap pass-2 finding core-004 closed.
9. `test_audit_factories_receive_the_audit_session_scope_when_provided` AND `test_audit_factories_fall_back_to_session_scope_when_omitted` — in `Orchestrator.__init__`, invert the fallback conditional to `audit_session_scope if audit_session_scope is None else session_scope`. Expect BOTH to FAIL (one mutation, two kills — the pair pins both arms).

After the final revert, re-run `uv run pytest tests/unit/orchestrator -q` and confirm all PASS again (no mutant left staged or unsaved).

- [ ] **Step 9: Quality gates**

Run: `uv run pytest tests/unit -q` (full unit tier — catches any orchestrator consumer this plan missed)
Run: `uv run ruff check src/alfred/orchestrator/ tests/unit/orchestrator/ && uv run ruff format src/alfred/orchestrator/ tests/unit/orchestrator/ && uv run mypy src/ && uv run pyright src/`
Expected: clean — the Task-3 mypy failure on `core.py` resolves here.

- [ ] **Step 10: Commit**

```bash
git add src/alfred/orchestrator/core.py tests/unit/orchestrator/test_core.py tests/unit/orchestrator/test_act_loop.py
git commit -m "refactor(orchestrator): three-phase turn holds no connection across the provider call (#410 PR1)"
```

---

### Task 7: Boot wiring — arm the ledger, role the pools, route CONTROL traffic

**Files:**

- Modify: `src/alfred/cli/_bootstrap.py:44` (import), `:229-234` (sync identity engine), `:459-517` (`build_orchestrator`)
- Modify: `src/alfred/cli/daemon/_commands.py:226-233` (`build_boot_session_scope`)
- Modify: `src/alfred/cli/daemon/_comms_boot.py:793-807` (orchestrator assembly)
- Modify: `src/alfred/cli/daemon/_gate_boot.py:132` (gate backend construction)
- Modify: `src/alfred/cli/supervisor.py:407,791,829` (fleet finding M-9 — the last three unconfigured `create_engine` sites in the codebase join the explicit CONTROL pool shape via one shared helper)
- Modify: `tests/unit/cli/daemon/conftest.py:254-257` (the `build_boot_session_scope` monkeypatch fake)
- Modify: `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py:670-751` (crash-injection flip — the armed ledger changes its asserted behavior)
- Test: `tests/unit/cli/test_build_orchestrator_wiring.py` (create)
- Test: `tests/unit/cli/test_supervisor_control_engine.py` (create)

This task supersedes the original PR1 "Task 5 (boot wiring)" that was never implemented (`build_orchestrator` does not currently accept or construct a ledger — verified against `_bootstrap.py:459-517`). The crash-injection edit REVISES a committed Spec-A-era test whose assertions the design doc §5 explicitly names as flipping the moment the ledger is armed.

**Interfaces:**

- Consumes: `PostgresTurnSideEffectLedger()` (Task 3), `ConnectionRole` / `build_session_scope(config, *, role, tuning)` / `make_session_factory(config, *, role, tuning)` (Task 1), `Orchestrator(audit_session_scope=..., side_effect_ledger=...)` (Task 6), Settings tuning fields (Task 2, picked up structurally).
- Produces: `build_orchestrator(settings, *, broker=None, router=None, resolver=None, session_scope=None, audit_session_scope=None, quarantined_extractor=None) -> Orchestrator` (one new kwarg); `build_boot_session_scope(settings, *, role: ConnectionRole = ConnectionRole.SIDE_EFFECT)`.

- [ ] **Step 1: Write the failing wiring test**

Create `tests/unit/cli/test_build_orchestrator_wiring.py`:

```python
"""#410 PR1: build_orchestrator arms the ledger and role-scopes its pools.

No DB is touched — build_session_scope and build_budget_guard are monkeypatched
at the _bootstrap module namespace; engine construction is lazy anyway.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

import pytest

from alfred.cli import _bootstrap
from alfred.config.settings import Settings
from alfred.memory.db import ConnectionRole
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger


@dataclass(frozen=True)
class _StubUser:
    slug: str
    display_name: str
    language: str


def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")


def _fake_scope() -> Any:
    @asynccontextmanager
    async def _scope() -> AsyncIterator[MagicMock]:
        yield MagicMock()

    return _scope


def _stub_resolver() -> MagicMock:
    resolver = MagicMock()
    resolver.get_operator = MagicMock(
        return_value=_StubUser(slug="op", display_name="Op", language="en-US")
    )
    return resolver


def test_default_scopes_are_role_scoped_and_the_ledger_is_armed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _base_env(monkeypatch)
    settings = Settings()
    recorded_roles: list[ConnectionRole] = []

    def _fake_build_session_scope(
        _config: Any,
        *,
        role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
        tuning: Any = None,
    ) -> Any:
        recorded_roles.append(role)
        return _fake_scope()

    monkeypatch.setattr(_bootstrap, "build_session_scope", _fake_build_session_scope)
    monkeypatch.setattr(_bootstrap, "build_budget_guard", lambda _r, _s: MagicMock())

    orch = _bootstrap.build_orchestrator(
        settings, broker=MagicMock(), router=MagicMock(), resolver=_stub_resolver()
    )
    # The at-most-once gate is ARMED on the production construction path.
    assert isinstance(orch._side_effect_ledger, PostgresTurnSideEffectLedger)
    # Turn scope first, audit (SIDE_EFFECT) scope second — and nothing else.
    assert recorded_roles == [ConnectionRole.TURN, ConnectionRole.SIDE_EFFECT]


def test_injected_scopes_are_used_verbatim_no_default_builds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _base_env(monkeypatch)
    settings = Settings()
    recorded_roles: list[ConnectionRole] = []

    def _fake_build_session_scope(
        _config: Any,
        *,
        role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
        tuning: Any = None,
    ) -> Any:
        recorded_roles.append(role)
        return _fake_scope()

    monkeypatch.setattr(_bootstrap, "build_session_scope", _fake_build_session_scope)
    monkeypatch.setattr(_bootstrap, "build_budget_guard", lambda _r, _s: MagicMock())

    orch = _bootstrap.build_orchestrator(
        settings,
        broker=MagicMock(),
        router=MagicMock(),
        resolver=_stub_resolver(),
        session_scope=_fake_scope(),
        audit_session_scope=_fake_scope(),
    )
    assert isinstance(orch._side_effect_ledger, PostgresTurnSideEffectLedger)
    # The comms boot graph injects both scopes — the builder must not build
    # shadow ones (a shadow TURN engine would double the budgeted pool).
    assert recorded_roles == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/test_build_orchestrator_wiring.py -x -q`
Expected: FAIL with `TypeError: build_orchestrator() got an unexpected keyword argument 'audit_session_scope'`

Run: `uv run pytest tests/unit/cli/test_supervisor_control_engine.py -q`
Expected: FAIL — `AttributeError: module 'alfred.cli.supervisor' has no attribute '_control_engine'`, and the AST scan reports the three bare `create_engine` sites (407, 791, 829).

- [ ] **Step 3: Write the wiring**

3a. `src/alfred/cli/_bootstrap.py` — change line 44 from `from alfred.memory.db import build_session_scope` to:

```python
from alfred.memory.db import ConnectionRole, build_session_scope
```

and add below the other `alfred.memory` imports:

```python
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger
```

3b. In `install_identity_factories_for_settings`, replace `sync_engine = create_engine(sync_db_url(settings))` (line 231) with:

```python
    # #410 PR1 / ADR-0062: pin the sync resolver engine's pool EXPLICITLY to
    # the stock CONTROL-tier shape (pool_size 5 + max_overflow 10) so its
    # budget usage is a NAMED number in settings.py's
    # DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET arithmetic, not an
    # unconfigured default-by-accident (the exact mistake #410 started from).
    # pool_recycle mirrors alfred.memory.db._POOL_RECYCLE_SECONDS and is
    # REQUIRED here, not optional (pass-2 finding mem-p2-002): this engine
    # lives for the whole daemon process, and — per db.py's own rationale —
    # a long-lived process otherwise accumulates server-side-stale
    # connections across Postgres restarts that pool_pre_ping alone detects
    # one checkout too late.
    sync_engine = create_engine(
        sync_db_url(settings),
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=1800,
    )
```

3c. Replace `build_orchestrator`'s signature and the wiring lines (keep the full docstring, adding the paragraph below to its end; keep the `broker`/`router`/`resolver` resolution lines exactly as they are):

```python
def build_orchestrator(
    settings: Settings,
    *,
    broker: SecretBroker | None = None,
    router: ProviderRouter | None = None,
    resolver: IdentityResolver | None = None,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]] | None = None,
    audit_session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]]
    | None = None,
    quarantined_extractor: QuarantinedExtractorLike | None = None,
) -> Orchestrator:
```

New docstring paragraph (append after the existing `quarantined_extractor` paragraph):

```text
    #410 PR1 / ADR-0062: ``session_scope`` defaults to the TURN-role scope
    (the orchestrator's sub-ms Phase A/C transactions) and
    ``audit_session_scope`` to the SIDE_EFFECT-role scope (the AuditWriters'
    per-append durability sessions — the one acquisition permitted while a
    TURN scope is held). Callers injecting one should inject both, from the
    same role-scoped builders, or the budgeted pool split is bypassed. The
    ``PostgresTurnSideEffectLedger`` is armed unconditionally: it is
    stateless, keys on the per-turn egress context, and the fixture/chat
    path's synthesized per-turn ``(adapter_id, inbound_id)`` makes each gate
    trivially first-apply there.
```

Body wiring (replace the current `session_scope = session_scope if session_scope is not None else build_session_scope(settings)` line and the trailing `return Orchestrator(...)`):

```python
    session_scope = (
        session_scope
        if session_scope is not None
        else build_session_scope(settings, role=ConnectionRole.TURN)
    )
    audit_session_scope = (
        audit_session_scope
        if audit_session_scope is not None
        else build_session_scope(settings, role=ConnectionRole.SIDE_EFFECT)
    )
    budget = build_budget_guard(resolver, settings)  # type: ignore[arg-type]  # reason: resolver.version_counter is the dynamically-promoted PR-B Phase 1 attribute; Phase 5 lifts it to a typed property
    return Orchestrator(
        identity_resolver=resolver,
        session_scope=session_scope,
        audit_session_scope=audit_session_scope,
        router=router,
        budget=budget,
        episodic_factory=_episodic_factory,
        quarantined_extractor=quarantined_extractor,
        side_effect_ledger=PostgresTurnSideEffectLedger(),
    )
```

3d. `src/alfred/cli/daemon/_commands.py` — replace `build_boot_session_scope` (lines 226-233) with:

```python
def build_boot_session_scope(  # pragma: no cover - real-infra glue; unit tests monkeypatch
    settings: Settings,
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
) -> Callable[[], AbstractAsyncContextManager[AsyncSession]]:
    """Build a role-scoped async session scope for the daemon boot graph.

    Default SIDE_EFFECT keeps every existing caller (Supervisor, audit
    writer, idempotency stores, working-pool rehydrate) on the durability
    pool; the orchestrator assembly passes ``role=ConnectionRole.TURN``
    explicitly (#410 PR1 / ADR-0062).
    """
    from alfred.memory.db import build_session_scope

    return build_session_scope(settings, role=role)
```

(add `from alfred.memory.db import ConnectionRole` to `_commands.py`'s module-level imports; the old `# type: ignore[no-any-return]` goes away because `build_session_scope` is now fully typed.)

3e. `src/alfred/cli/daemon/_comms_boot.py` — replace the `orchestrator = build_orchestrator(...)` call (lines 793-807) with (keep the FOLD-R7 comment block above it verbatim; add `from alfred.memory.db import ConnectionRole` to the module imports):

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
            # #410 PR1 / ADR-0062: TURN-role scope for the sub-ms Phase A/C
            # transactions; SIDE_EFFECT-role scope for the AuditWriters so the
            # in-turn audit acquisition draws from the durability pool, never
            # a second TURN connection.
            session_scope=build_boot_session_scope(settings, role=ConnectionRole.TURN),
            audit_session_scope=build_boot_session_scope(settings),
            # extraction runs at the adapter->bridge boundary, not the orchestrator funnel
            quarantined_extractor=None,
        )
```

3f. `src/alfred/cli/daemon/_gate_boot.py` — replace line 132 (`backend = PostgresBackend(dsn=settings.database_url.unicode_string())`) with:

```python
    from alfred.memory.db import ConnectionRole, make_session_factory

    # #410 PR1 / ADR-0062: route the gate backend through the CACHED
    # CONTROL-role engine (the pre-existing session_factory= injection seam,
    # backend.py:283-296) instead of a private dsn=-built engine that
    # bypassed the registry — and dispose_all_engines() — entirely. CONTROL
    # is the named 15-connection reserve in settings.py's
    # DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET arithmetic.
    backend = PostgresBackend(
        session_factory=make_session_factory(settings, role=ConnectionRole.CONTROL)
    )
```

3g. `tests/unit/cli/daemon/conftest.py` — replace the monkeypatch fake (lines 254-257):

```python
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_session_scope",
        lambda _settings: lambda: None,
    )
```

with:

```python
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_session_scope",
        # #410 PR1: accept-and-ignore the new role kwarg so callers with or
        # without an explicit role hit the same inert double.
        lambda _settings, *, role=None: lambda: None,
    )
```

3h. `src/alfred/cli/supervisor.py` (fleet finding M-9) — the three sync CLI read helpers (`_list_breaker_states` line 407, `_list_proposals` line 791, `_recent_dispatch_counts` line 829) each build `create_engine(_resolve_database_url(), pool_pre_ping=True)` — the exact unconfigured-pool anti-pattern this PR eliminates everywhere else, and a direct contradiction of ADR-0062's "cannot recur silently" claim. They are sync engines (the CLI bundle ships psycopg, not asyncpg — CR-156), so they cannot route through the async `make_engine`; instead they get the same explicit CONTROL shape `_bootstrap.py` 3b gives the sync identity-resolver engine, via ONE shared helper (three copies would drift silently — the #422 lesson). Add `from sqlalchemy.engine import Engine` to the module imports, add above `_list_breaker_states`:

```python
def _control_engine() -> Engine:
    """One CLI-invocation-lifetime sync engine, explicit CONTROL pool shape.

    #410 PR1 / ADR-0062: pins pool_size 5 + max_overflow 10 — the same
    named numbers as ``alfred.memory.db._CONTROL_POOL_SIZE`` /
    ``_CONTROL_MAX_OVERFLOW`` and the ``_bootstrap`` sync identity-resolver
    engine — so no engine anywhere in the codebase carries an
    unconfigured-default pool (the mistake #410 started from). Short-lived
    by contract: every caller disposes in a ``finally``; the explicit shape
    is about the budget arithmetic staying honest, not throughput. No
    idle-in-transaction bound, per the CONTROL role's human-scale semantics.
    """
    return create_engine(
        _resolve_database_url(),
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
    )
```

and replace each of the three `engine = create_engine(_resolve_database_url(), pool_pre_ping=True)` lines with `engine = _control_engine()`.

Create `tests/unit/cli/test_supervisor_control_engine.py`:

```python
"""#410 PR1 (fleet finding M-9): supervisor CLI engines carry the explicit CONTROL shape.

The three sync read helpers used to build create_engine(url, pool_pre_ping=True)
— an unconfigured default pool, the exact anti-pattern ADR-0062 claims cannot
recur. One helper, one pinned shape, one test.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from alfred.cli import supervisor as supervisor_mod


def test_control_engine_pins_the_explicit_control_pool_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = MagicMock(return_value=MagicMock(name="engine"))
    monkeypatch.setattr(supervisor_mod, "create_engine", captured)
    monkeypatch.setattr(
        supervisor_mod, "_resolve_database_url", lambda: "postgresql+psycopg2://x:y@h/db"
    )
    supervisor_mod._control_engine()
    kwargs = captured.call_args.kwargs
    assert kwargs["pool_size"] == 5
    assert kwargs["max_overflow"] == 10
    assert kwargs["pool_pre_ping"] is True


def test_no_bare_create_engine_call_sites_remain() -> None:
    """Default-deny the CLASS, not the three known sites: any supervisor.py
    call reaching create_engine without an explicit pool_size is a
    regression to the unconfigured-pool shape. Source-level scan — the
    lexical rule CAN decide this (a keyword argument's presence is a
    lexical fact), unlike runtime pool behaviour, which the kwargs test
    above covers."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(supervisor_mod))
    bare_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "create_engine"
        and "pool_size" not in {kw.arg for kw in node.keywords}
    ]
    assert bare_calls == [], (
        f"unconfigured create_engine call(s) at supervisor.py line(s) {bare_calls} — "
        "route through _control_engine() (ADR-0062)"
    )
```

**Idle-in-transaction consumer audit (fleet finding M-13 — the result is recorded here so the 5 s SIDE_EFFECT default is a checked claim, not a hope).** The memory-subsystem consumers were cleared by the memory-engineer's cross-check pass. The three non-memory consumers of default-role scopes were each read end-to-end for this plan revision; their longest single in-transaction idle gap:

- `src/alfred/state/dispatch_loop.py` — five `async with session_scope()` bodies (`_read_sentinel` 524, `_bump_sentinel` 543, the `_dispatch_one` PK lookup 612, `_record_applied`'s ledger insert 791, `_record_failure`'s ledger+audit insert pair 1037). Every body is a back-to-back DB statement sequence; the git blob read (`_read_blob`, subprocess) and the handler invocation both run OUTSIDE any scope. Worst idle gap: inter-statement Python time, microseconds — well under 5 s.
- `src/alfred/cli/operator_session.py` — scopes feed `DefaultOperatorSessionResolver` and the CLI user-picker: single-statement bodies (`_warm_connection`'s `SELECT 1`, itself inside an `asyncio.timeout`; `_lookup_row`'s one SELECT at `_resolver.py:365`; `_list_users`' one SELECT). The whole resolution pipeline is bounded by err-008's 250 ms budget — two orders of magnitude under the timeout.
- `src/alfred/cli/supervisor.py` — after 3h these helpers ride CONTROL-shaped engines (no idle bound at all, per the role's semantics); even so, each body is a single SELECT.

No consumer needs re-routing; the audit lands as one sentence in ADR-0062 (Task 10) so the next SIDE_EFFECT consumer knows the bound is load-bearing.

- [ ] **Step 4: Flip the crash-injection integration test**

In `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py`, in `test_forwarded_crash_injection_replays_exactly_twice_with_bounded_residual`:

Replace the docstring's final sentence (`The in-process working-` through `swept under the rug).`) with:

```text
    #410 PR1: the armed TurnSideEffectLedger now CLOSES the double-append
    residual this test previously accepted — the replay's fresh completion is
    still paid for (ADR-0049's duplicate-paid-completion residual stands),
    but the deque ends with exactly one user + one assistant turn, asserted
    directly below.
```

Replace the final assertion:

```python
        assert len(turns_after_replay) == 4  # 2 user + 2 assistant — duplicated, not lost
```

with:

```python
        # #410 PR1: the ledger denies BOTH gates on the replay (the first
        # attempt's Phase A/C transactions committed before the send failed),
        # so the replay re-runs the completion but re-appends NOTHING.
        assert len(turns_after_replay) == 2
        assert [t.role for t in turns_after_replay] == ["user", "assistant"]
```

(The earlier `assert len(turns_after_failure) == 2` and both `stack.captured_router.requests` / `flaky_sender.call_count == 2` assertions stay — the first attempt's appends and the replay's fresh paid completion are unchanged behavior.)

- [ ] **Step 5: Run the affected suites**

Run: `uv run pytest tests/unit/cli tests/unit/orchestrator -q`
Expected: PASS (the daemon conftest fake and all daemon unit boot tests keep working).

Run: `uv run pytest tests/integration/comms_mcp/test_real_turn_inbound_boundary.py tests/integration/test_orchestrator_bootstrap.py -q` (Docker required)
Expected: PASS. Contingency for `test_orchestrator_bootstrap.py` ONLY: if it fails with `UndefinedTableError: turn_side_effect_ledger`, its DB fixture creates schema without running migration 0025 — add the same migration step the ledger integration test uses, inside that file's engine/DB fixture, immediately after the container URL is available:

```python
    from alembic import command, config as alembic_config

    cfg = alembic_config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")
```

- [ ] **Step 6: Quality gates**

Run: `uv run ruff check src/alfred/cli/ tests/unit/cli/ tests/integration/comms_mcp/test_real_turn_inbound_boundary.py && uv run ruff format src/alfred/cli/ tests/unit/cli/ tests/integration/comms_mcp/test_real_turn_inbound_boundary.py && uv run mypy src/ && uv run pyright src/`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/alfred/cli/_bootstrap.py src/alfred/cli/daemon/_commands.py src/alfred/cli/daemon/_comms_boot.py src/alfred/cli/daemon/_gate_boot.py src/alfred/cli/supervisor.py tests/unit/cli/test_build_orchestrator_wiring.py tests/unit/cli/test_supervisor_control_engine.py tests/unit/cli/daemon/conftest.py tests/integration/comms_mcp/test_real_turn_inbound_boundary.py
git commit -m "feat(cli): arm the side-effect ledger + role-scoped pools at boot (#410 PR1)"
```

---

### Task 8: Integration tier is pool-starved by default

**Files:**

- Modify: `tests/integration/conftest.py` (add the `integration_pool_kwargs` fixture; thread it into `postgres_engine`)
- Modify: `tests/integration/memory/conftest.py` (thread it into `pg_engine`)
- Test: `tests/integration/memory/test_pool_starvation_default.py` (create)

Net-new test infrastructure; modifies pre-existing conftest files.

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: fixture `integration_pool_kwargs() -> dict[str, Any]` (default `{"pool_size": 2, "max_overflow": 0, "pool_timeout": 5}`), overridable at any narrower fixture scope as the opt-out.

- [ ] **Step 1: Write the failing tests**

Create `tests/integration/memory/test_pool_starvation_default.py`:

```python
"""#410 PR1: integration engines are pool-starved BY DEFAULT.

With pool_size=2 / max_overflow=0 / pool_timeout=5 on every shared
integration engine, any test that reintroduces hold-and-wait (holding one
connection while demanding another beyond the pool) fails LOUDLY with a
SQLAlchemy TimeoutError within seconds — every boot-graph integration test
becomes an incidental deadlock detector. The opt-out is a standard pytest
fixture override at a narrower scope, demonstrated below.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import TimeoutError as SaTimeoutError
from sqlalchemy.ext.asyncio import AsyncEngine

pytestmark = pytest.mark.integration


async def test_default_integration_pool_is_the_starvation_shape(
    pg_engine: AsyncEngine,
) -> None:
    assert pg_engine.pool.size() == 2


async def test_third_concurrent_hold_fails_loud_within_pool_timeout(
    pg_engine: AsyncEngine,
) -> None:
    conn_a = await pg_engine.connect()
    conn_b = await pg_engine.connect()
    try:
        await conn_a.execute(text("SELECT 1"))
        await conn_b.execute(text("SELECT 1"))
        with pytest.raises(SaTimeoutError):
            async with asyncio.timeout(30):  # the pool_timeout (5s) fires well inside
                conn_c = await pg_engine.connect()
                await conn_c.close()  # pragma: no cover — checkout must have raised
    finally:
        await conn_a.close()
        await conn_b.close()


class TestOptOut:
    """The documented opt-out: override the fixture at a narrower scope."""

    @pytest.fixture
    def integration_pool_kwargs(self) -> dict[str, Any]:
        return {"pool_size": 5, "max_overflow": 0, "pool_timeout": 10}

    async def test_override_reaches_the_engine(self, pg_engine: AsyncEngine) -> None:
        assert pg_engine.pool.size() == 5
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/integration/memory/test_pool_starvation_default.py -x -q` (Docker required)
Expected: FAIL — `fixture 'integration_pool_kwargs' not found` (and `pg_engine.pool.size()` would be SQLAlchemy's default 5, not 2).

- [ ] **Step 3: Write the fixtures**

In `tests/integration/conftest.py`, add `from typing import Any` to the imports and add below the `postgres_url` fixture:

```python
@pytest.fixture
def integration_pool_kwargs() -> dict[str, Any]:
    """Starvation-by-default engine kwargs for the integration tier (#410 PR1).

    Deliberately SMALL: with pool_size=2 and no overflow, any code path that
    holds one connection while demanding another beyond the pool fails with a
    loud SQLAlchemy TimeoutError within pool_timeout seconds — so every
    integration test exercising the real boot graph doubles as an incidental
    hold-and-wait detector (ADR-0062). Opt out by overriding this fixture at
    a narrower conftest/module/class scope; never by inflating this default.
    An INTERMITTENT failure under these kwargs is not automatically flake:
    timing-dependent hold-and-wait bites only under contention, so rule out
    a genuine pool-starvation regression (TimeoutError on checkout, stalled
    connection acquisition) before dismissing one.
    """
    return {"pool_size": 2, "max_overflow": 0, "pool_timeout": 5}
```

and change `postgres_engine` to consume it:

```python
@pytest.fixture
def postgres_engine(
    postgres_url: str, integration_pool_kwargs: dict[str, Any]
) -> Iterator[Engine]:
    """Yield a sync SQLAlchemy Engine bound to the per-test Postgres container.

    Rewrites the asyncpg URL back to psycopg2 for the sync engine — the
    migration env consumes ``postgres_url`` (asyncpg), the tests use this
    sync engine for inspecting / inserting rows around the migration calls.
    Pool-starved by default via ``integration_pool_kwargs`` (#410 PR1).
    """
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = create_engine(sync_url, future=True, **integration_pool_kwargs)
    try:
        yield engine
    finally:
        engine.dispose()
```

In `tests/integration/memory/conftest.py`, add `from typing import Any` to the imports and change `pg_engine`'s signature/engine line:

```python
@pytest.fixture
async def pg_engine(
    integration_pool_kwargs: dict[str, Any],
) -> AsyncIterator[AsyncEngine]:
```

and inside it:

```python
        engine = create_async_engine(url, **integration_pool_kwargs)
```

(keep the rest of the fixture body — container, `create_all`, dispose — exactly as-is; keep its docstring and append one line: `Pool-starved by default via ``integration_pool_kwargs`` (#410 PR1).`)

- [ ] **Step 4: Run tests to verify they pass, and sweep the WHOLE tier for false trips**

Run: `uv run pytest tests/integration/memory tests/integration/test_turn_side_effect_ledger_postgres.py -q` (Docker required) — the fast local loop first.

Then (fleet finding M-11 — the starved default reaches EVERY consumer of the shared conftest engines, roughly ten files, not just the three memory ones): run the FULL integration tier before declaring the change safe:

Run: `uv run pytest tests/integration -q` (Docker required)

Expected: all PASS in both runs. A pre-existing test failing with `SaTimeoutError` anywhere in the tier is a REAL hold-and-wait finding, not a false positive of this task — investigate it as a bug (fix what you find), or, only if the test's concurrency is legitimate and bounded, give that module the documented fixture override with a comment stating its concurrent-connection budget. Record in the commit message body which (if any) modules needed the override and why. The same discipline applies to INTERMITTENT failures (pass-2 finding mem-p2-003): a timing-dependent hold-and-wait bug can pass most runs under these kwargs and bite only under contention — never dismiss an intermittent integration failure introduced by this change as "just flake" without first ruling out a genuine pool-starvation regression (look for `SaTimeoutError` / pool-checkout stalls in the failure output). If the macOS integration lane flakes under load, re-run the failing file alone before concluding anything.

- [ ] **Step 5: Quality gates + commit**

Run: `uv run ruff check tests/integration/ && uv run ruff format tests/integration/conftest.py tests/integration/memory/conftest.py tests/integration/memory/test_pool_starvation_default.py`

```bash
git add tests/integration/conftest.py tests/integration/memory/conftest.py tests/integration/memory/test_pool_starvation_default.py
git commit -m "test(integration): pool-starvation-by-default integration engines (#410 PR1)"
```

---

### Task 9: Deterministic proof — no connection held during the provider call

**Files:**

- Test: `tests/integration/orchestrator/test_turn_pool_no_hold_across_provider.py` (create)

Net-new. This is the headline regression lock for the whole plan: real Postgres, the real role-scoped TURN engine pinned to `pool_size=2`, four concurrent REAL turns (real ledger, real episodic writes), and a gate router that parks every turn inside `complete()` until all four have arrived — deterministic, not sleep/timing-based.

**Interfaces:**

- Consumes: `ConnectionRole`, `make_engine`, `make_session_factory`, `build_session_scope`, `dispose_all_engines` (Task 1); `PostgresTurnSideEffectLedger()` (Task 3); the three-phase `Orchestrator` (Task 6). The `postgres_url` fixture from `tests/integration/conftest.py`.
- Produces: nothing (test-only).

- [ ] **Step 1: Write the test file**

Create `tests/integration/orchestrator/test_turn_pool_no_hold_across_provider.py`:

```python
"""#410 PR1 headline proof: NO Postgres connection is held during the provider call.

Deterministic, not timing-based: a gate router parks ALL four concurrent
turns inside complete(); once every turn has arrived (arrival counter + one
release Event — nothing is mid-Phase-A/C at the measurement point), the test
reads the TURN pool's checked-out count while all four are parked and
asserts ZERO. Under the pre-#410 single-turn-transaction design this test
cannot even reach the measurement point: four turns each holding one of two
pooled connections across complete() is hold-and-wait — the last two turns
starve at Phase-A checkout until the 3s pool_timeout raises, failing the
TaskGroup loudly. The companion test proves the pool really is that small
(oracle independence: the detector is demonstrated to bite, not assumed to).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import sqlalchemy as sa
from alembic import command, config
from pydantic import PostgresDsn

from alfred.memory.db import (
    ConnectionRole,
    build_session_scope,
    dispose_all_engines,
    make_engine,
    make_session_factory,
)
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger
from alfred.memory.working import WorkingMemory
from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse
from alfred.security.tiers import T2, tag

pytestmark = pytest.mark.integration

_PARTIES = 4


@dataclass(frozen=True)
class _StubUser:
    slug: str
    display_name: str
    language: str


class _SmallTurnPoolCfg:
    """TURN pool of 2 — SMALLER than the concurrency (4) — so any design that
    holds a connection across complete() starves instead of passing."""

    def __init__(self, url: str) -> None:
        self.database_url = PostgresDsn(url)

    db_turn_pool_max_connections = 2
    db_side_pool_max_connections = 4
    db_pool_checkout_timeout_seconds = 3.0
    db_idle_in_transaction_timeout_seconds = 5.0


class _GateRouter:
    """complete() parks every caller until the test releases them together."""

    def __init__(self, parties: int) -> None:
        self._parties = parties
        self._arrivals = 0
        self.all_arrived = asyncio.Event()
        self.release = asyncio.Event()

    async def complete(self, _request: Any) -> CompletionResponse:
        self._arrivals += 1
        if self._arrivals == self._parties:
            self.all_arrived.set()
        await self.release.wait()
        return CompletionResponse(
            content="Very good, Sir.",
            tokens_in=3,
            tokens_out=2,
            cost_usd=0.0001,
            model="gate-router",
        )


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0025 (turn_side_effect_ledger)
    return postgres_url


def _make_budget() -> MagicMock:
    budget = MagicMock()
    budget.estimate_for = MagicMock(return_value=0.001)
    budget.would_exceed = MagicMock(return_value=False)
    budget.check_and_charge = MagicMock(return_value=None)
    return budget


async def test_no_connection_is_held_while_all_turns_sit_in_the_provider_call(
    migrated_url: str,
) -> None:
    cfg = _SmallTurnPoolCfg(migrated_url)
    engine = make_engine(cfg, role=ConnectionRole.TURN)
    turn_scope = build_session_scope(cfg, role=ConnectionRole.TURN)
    router = _GateRouter(_PARTIES)
    audit = MagicMock()
    audit.append = AsyncMock()
    audit.append_schema = AsyncMock()
    resolver = MagicMock()
    resolver.get_operator = MagicMock(
        return_value=_StubUser(slug="bruce", display_name="Bruce", language="en-US")
    )
    orch = Orchestrator(
        identity_resolver=resolver,
        session_scope=turn_scope,
        router=router,  # type: ignore[arg-type]  # reason: duck-typed gate router; only .complete is consumed
        budget=_make_budget(),
        episodic_factory=lambda s: EpisodicMemory(session=s),
        audit_factory=lambda _f: audit,
        autocommit_audit_factory=lambda _f: audit,
        side_effect_ledger=PostgresTurnSideEffectLedger(),
    )
    user = _StubUser(slug="bruce", display_name="Bruce", language="en-US")

    async def one_turn(i: int) -> str:
        # Fresh WorkingMemory per turn: the pool/adapter owns per-user buffers
        # in production; here each turn is an independent conversation.
        return await orch.handle_user_message(
            user=user,
            content=tag(T2, f"barrier turn {i}", source="test.adapter"),
            working_memory=WorkingMemory(),
        )

    try:
        async with asyncio.timeout(60):
            async with asyncio.TaskGroup() as tg:
                tasks = [tg.create_task(one_turn(i)) for i in range(_PARTIES)]
                await router.all_arrived.wait()
                # All four turns are parked inside complete(); none is in
                # Phase A or C. THE deterministic invariant of ADR-0062:
                assert engine.pool.checkedout() == 0
                router.release.set()
        assert [task.result() for task in tasks] == ["Very good, Sir."] * _PARTIES
    finally:
        await dispose_all_engines()


async def test_hold_and_wait_on_this_pool_really_starves(migrated_url: str) -> None:
    """Oracle-independence companion: the barrier test's pass is only meaningful
    if this pool genuinely cannot serve held-across-the-park connections. Two
    held TURN sessions + a third checkout = SQLAlchemy TimeoutError within the
    3s checkout timeout — the failure the barrier test would produce under the
    pre-#410 design."""
    from sqlalchemy.exc import TimeoutError as SaTimeoutError

    cfg = _SmallTurnPoolCfg(migrated_url)
    factory = make_session_factory(cfg, role=ConnectionRole.TURN)
    try:
        async with factory() as held_a, factory() as held_b:
            await held_a.execute(sa.text("SELECT 1"))  # checkout + hold (in txn)
            await held_b.execute(sa.text("SELECT 1"))
            with pytest.raises(SaTimeoutError):
                async with asyncio.timeout(30):
                    async with factory() as starved:
                        await starved.execute(sa.text("SELECT 1"))
    finally:
        await dispose_all_engines()
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/integration/orchestrator/test_turn_pool_no_hold_across_provider.py -q` (Docker required)
Expected: both PASS. (The barrier test is a regression lock for work already landed in Task 6 — its failing-first evidence is Task 6 Step 2's unit twin, which failed with `assert [1] == [0]` against the pre-restructure code; the starvation companion proves the detector's teeth independently of the orchestrator.)

- [ ] **Step 3: Quality gates + commit**

Run: `uv run ruff check tests/integration/orchestrator/test_turn_pool_no_hold_across_provider.py && uv run ruff format tests/integration/orchestrator/test_turn_pool_no_hold_across_provider.py`

```bash
git add tests/integration/orchestrator/test_turn_pool_no_hold_across_provider.py
git commit -m "test(integration): deterministic proof no connection is held during the LLM call (#410 PR1)"
```

---

### Task 10: ADR-0062 + ADR-0049 amendment + design-doc supersession note

**Files:**

- Create: `docs/adr/0062-three-phase-turn-and-role-scoped-connection-pools.md`
- Modify: `docs/adr/0049-real-privileged-turn-comms-inbound.md` (Consequences → Negative, the "Forwarded-path bounded double-apply residual" entry)
- Modify: `docs/superpowers/specs/2026-08-08-issue-410-pr1-ledger-transactional-fix-design.md:3-10` (status block)

**Interfaces:**

- Consumes: the shipped mechanism from Tasks 1-9 (the ADR records decisions, it does not introduce names).
- Produces: ADR-0062 as the citable decision record; later PRs (#410 PR2 replay journal, PR3 tools-on) MUST cite its "future work defaults to SIDE_EFFECT" rule.

- [ ] **Step 1: Verify the ADR number at write time**

Run: `ls docs/adr/ | sort | tail -3`
Expected: `0061-declared-python-floor-diverges-from-enforced-floor.md` is the highest. If a `0062-*.md` has appeared since this plan was written, use the next free number instead and substitute it throughout this task.

- [ ] **Step 2: Write ADR-0062**

Create `docs/adr/0062-three-phase-turn-and-role-scoped-connection-pools.md`:

```markdown
# ADR-0062 — Three-phase turn and role-scoped connection pools

- **Status**: Accepted
- **Date**: 2026-08-08
- **Slice**: #410 PR1 (tools-on prerequisite work)
- **Relates to**: [ADR-0049](0049-real-privileged-turn-comms-inbound.md) (whose
  double-apply residual the turn-side-effect ledger narrows, and whose residual
  panel this ADR amends), issue #410, the design addendum
  `docs/superpowers/specs/2026-08-08-issue-410-pr1-ledger-transactional-fix-design.md`
  (whose §3.1 single-transaction mechanism this ADR supersedes)

## Context

`TurnSideEffectLedger` (the at-most-once gate for the turn's episodic /
working-memory side effects) originally committed its gate on an independent
session, separate from the per-turn transaction that performed the guarded
write — so a mid-turn rollback could strand the gate "applied" with the write
missing forever (permanent user-message loss on replay). The first fix design
(§3.1 of the 2026-08-08 addendum) folded the ledger into ONE per-turn
transaction spanning the whole turn — including the multi-second LLM provider
call. That mechanism is empirically wrong: the (previously unconfigured,
never-justified 15-connection) pool served every turn ONE held connection for
its full duration, while `AuditWriter.append()` demanded a SECOND independent
connection mid-turn for its durability guarantee (CLAUDE.md hard rule #7,
deliberately unchanged). N in-flight turns each holding one connection while
demanding another is hold-and-wait: verified with 16 concurrent turns — 0
succeeded, all timed out at 30 s. The real anti-pattern was never the shared
transaction per se; it was holding a database connection across slow external
I/O.

## Decision

- **The three-phase turn is a standing invariant: no database connection is
  ever held across external I/O.** `Orchestrator` runs Phase A (Observe:
  ledger user-gate + episodic user row, one sub-millisecond transaction),
  Phase B (Orient + Act: prompt construction, the provider call, the tool
  loop, every audit write — ZERO connections held), and Phase C (Persist:
  ledger assistant-gate + episodic assistant row, one sub-millisecond
  transaction). In-process working-memory appends are deferred until after
  their phase's commit; the terminal audit row fires after Phase C's scope
  has closed. The deadline wrapper encloses the whole sequence.
- **The ledger executes in its caller's transaction.** `try_apply_*` methods
  take the phase's `AsyncSession`; the gate and the guarded write commit or
  roll back together. The sibling `ForwardedDispatchAttemptStore` keeps its
  independent-commit design deliberately — it guards a retry counter, not a
  durability claim; the ledger's original copy of that pattern was a
  mis-transfer, not a second instance of a shared design.
- **Connections are acquired under a closed role vocabulary** (`TURN`,
  `SIDE_EFFECT`, `CONTROL`), one cached engine + pool per `(dsn, role)`,
  sized by budget-validated Settings fields
  (`DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET` documents the arithmetic
  against postgres:18's default `max_connections=100`). The acquisition
  hierarchy is enforced for **session-scope-mediated access** — every
  acquisition that flows through `alfred.memory.db.session_scope`, which is
  all TURN and SIDE_EFFECT traffic: while a `TURN` scope is held,
  `SIDE_EFFECT` is the ONLY role permitted to open a nested scope — and only
  because of hard rule #7 (audit durability); it is counted on
  `alfred_db_side_effect_scope_inside_turn_total`. A nested `TURN` or
  `CONTROL` scope raises `NestedTurnConnectionError` (fail loud, never
  wait). **Named exception:** the capability-gate `PostgresBackend` receives
  a CONTROL-role `session_factory` and opens sessions directly, without
  `session_scope` — the guard never sees those acquisitions. This is a
  known, currently-safe gap, not closure: the gate backend is the only
  CONTROL-role consumer reachable from turn handling, gate checks run in
  Phase B (which holds zero TURN connections), and nothing dispatches tools
  from inside Phase A/C. Any change that invokes the gate while a TURN scope
  is held must first route the backend through `session_scope` (or extend
  the guard) — the pool-starved integration tier is the behavioral backstop
  in the meantime. `alfred_db_side_effect_scope_inside_turn_total` is
  expected to read a constant ZERO in this PR: every in-turn audit write
  happens in Phase B (no TURN scope open) or after Phase C's scope closes.
  It is forward provisioning for the #410 PR2 replay journal and PR3
  tools-on writes that WILL acquire SIDE_EFFECT inside a TURN scope — a
  flat zero until those land is correct behavior, not broken
  instrumentation.
- **`idle_in_transaction_session_timeout` is set TIGHT (default 5 s) on the
  TURN and SIDE_EFFECT pools.** Safe only because of the phase split: the
  sole in-transaction work is Phase A/C, bounded by the episodic before-write
  hook chain (`HOOK_CHAIN_DEADLINE_SECONDS` 0.25 s x 2 hookpoints ~= 0.5 s
  worst case; 5 s = 10x). An orphaned crash-abandoned transaction's row locks
  are reclaimed in that window instead of OS TCP-keepalive timescales.
  CONTROL pools carry no idle bound (human-scale CLI/Alembic work). Every
  default-role consumer was audited against the bound at decision time
  (memory subsystem cleared by the memory-engineer cross-check;
  `state/dispatch_loop.py`, `cli/operator_session.py`, and
  `cli/supervisor.py` audited in the #410 PR1 plan revision — all
  back-to-back statement sequences with external I/O outside every scope,
  worst idle gap orders of magnitude under 5 s). The bound is load-bearing:
  a NEW consumer whose transaction can idle near it belongs on `CONTROL`,
  with the move recorded against this ADR.
- **Future DB consumers default to `SIDE_EFFECT`.** The #410 PR2 replay
  journal and any tool-dispatch fan-out state acquire under `SIDE_EFFECT`
  unless an ADR argues otherwise — `TURN` is reserved for the orchestrator's
  two phase transactions, and nothing new may nest inside them.

## Consequences

### Positive

- The 16-turn concurrency deadlock is structurally impossible: no turn holds
  a connection while waiting on the provider, and the audit path draws from
  its own pool.
- The §3.1 design's accepted "lock-hold-duration up to the full turn"
  residual is AVOIDED, not accepted: a losing concurrent attempt's row-lock
  wait is bounded by Phase A/C's sub-millisecond footprint, and an orphaned
  lock by the 5 s idle timeout (both proven by integration tests in
  `tests/integration/test_turn_side_effect_ledger_postgres.py`).
- Every pool size is a named, budget-checked number; the unconfigured "15"
  that caused the deadlock cannot recur silently. This claim was made TRUE
  before being written down: the last three unconfigured `create_engine`
  sites in the codebase (the `alfred supervisor` sync CLI readers) were
  routed onto the explicit CONTROL shape in the same PR, and an AST-level
  guard test (`tests/unit/cli/test_supervisor_control_engine.py`)
  default-denies any future bare `create_engine` call in that module.

### Negative

- **Accepted trade-off: any failure after Phase A's commit and before Phase
  C's commit — a Phase-B failure of any class, or a Phase-C write/commit
  failure — leaves an orphan user episodic row** (no paired assistant row)
  where the pre-split design rolled both back together. Strictly better
  than the alternative this fix exists to prevent (losing the user's
  message entirely): on replay the user gate correctly re-denies, the
  assistant gate allows, and the turn converges. Counted on
  `alfred_orchestrator_orphaned_user_turn_total` so the deliberate
  degradation has a production rate. The one degradation:
  `WorkingMemoryPool` rehydration may prefill ending on a USER turn, giving
  the next turn's prompt two consecutive user messages — degraded context,
  not incorrect, and NOT the prefill-continuation bug (that requires ending
  on an ASSISTANT turn, which the conditional current-message threading
  prevents).
- Two short transactions per turn instead of one — two commits' WAL flushes.
  Negligible against a multi-second provider call.
- **Accepted residuals: two distinct narrow cancellation windows inside
  `session_scope` itself** (pass-2 findings sec-101 / mem-p2-001 — separate
  windows; closing one does not close the other). (1) A second
  `task.cancel()` landing while the scope's own explicit
  `await session.rollback()` is in flight re-raises before the rollback
  completes, leaving connection teardown to `AsyncSession.close()` —
  relied on for that window, not independently proven. (2) A cancellation
  delivered during the ORIGINAL statement's in-flight asyncpg network I/O
  can wedge the connection protocol such that even an ordinary,
  uninterrupted `rollback()` itself raises `asyncpg.InterfaceError` — a
  real, still-open upstream driver/ORM interaction
  (sqlalchemy/sqlalchemy#6592, #8145, #11125, #12099;
  MagicStack/asyncpg#863, #258, #1310; read against the installed
  sqlalchemy 2.0.51 / asyncpg 0.31.0). Neither can strand the ledger gate
  — the transaction never commits, so the server aborts it (at the latest
  when the idle-in-transaction timeout reaps the backend) and a replay
  sees "not applied"; the worst case is one unclean pooled connection,
  bounded by `pool_pre_ping`/`pool_recycle`. Accepted WITHOUT new
  fault-injection infrastructure because the phase split shrinks the
  at-risk window to Phase A/C's sub-millisecond transactions — the
  pre-#410 design exposed the whole multi-second provider call to the
  same class of window.
- The nesting guard is per-task (`contextvars`); code that smuggles a scope
  across tasks defeats it. The pool-starved integration tier
  (`integration_pool_kwargs`) is the behavioral backstop.

## Alternatives considered

- **Keep the single per-turn transaction, grow the pool.** Rejected: sizing
  cannot fix hold-and-wait, only move the deadlock threshold; connections
  held across multi-second external I/O also pin server resources per
  in-flight turn.
- **Weaken `AuditWriter` to reuse the turn connection.** Rejected without
  discussion: CLAUDE.md hard rule #7 — audit rows must survive caller
  rollback.
- **Option C (idempotent episodic write, retiring the ledger).** Still
  deferred, unchanged from the design addendum §4.

## References

- Design addendum: `docs/superpowers/specs/2026-08-08-issue-410-pr1-ledger-transactional-fix-design.md`
  (§3.1 superseded by this ADR; §3.2 carried forward as gate-keyed
  conditional threading; §3.3/§3.4 carried forward as per-phase deferred
  appends + `commit_failed` telemetry)
- Plan: `docs/superpowers/plans/2026-08-08-issue-410-pr1-pool-deadlock-fix.md`
- Proof tests:
  `tests/integration/orchestrator/test_turn_pool_no_hold_across_provider.py`,
  `tests/integration/test_turn_side_effect_ledger_postgres.py`
```

- [ ] **Step 3: Amend ADR-0049's residual entry**

In `docs/adr/0049-real-privileged-turn-comms-inbound.md`, append to the END of the `- **Forwarded-path bounded double-apply residual (accepted).**` bullet (after `...deliberately not implemented here.`):

```markdown
  **Amended 2026-08-08 (#410 PR1 / [ADR-0062](0062-three-phase-turn-and-role-scoped-connection-pools.md)):**
  the episodic-transcript double-write and the working-memory double-append
  halves of this residual are now CLOSED by the `turn_side_effect_ledger`
  at-most-once gate; the duplicate paid completion and the in-process budget
  double-charge remain accepted (bounded over-charge is the safe direction
  for a cost control). The transactional-coupling design's contemplated
  "row-lock held up to the full turn duration" residual was AVOIDED — never
  shipped — by ADR-0062's three-phase split; it is recorded there as
  avoided, not here as accepted.
```

- [ ] **Step 4: Mark the design doc's superseded mechanism**

In `docs/superpowers/specs/2026-08-08-issue-410-pr1-ledger-transactional-fix-design.md`, replace the status block (lines 3-10, `> **Status:** approved by requester...` through `...not a scope change to the #410 epic).`) with the same block plus one appended sentence, so it reads:

```markdown
> **Status:** approved by requester, 2026-08-08. Supersedes the session-ownership
> design in `TurnSideEffectLedger`'s Task 1 implementation and Task 4's wiring as
> already committed on the `410-pr1-turn-side-effect-ledger` worktree branch
> (commits through `fa13d3e8`). This is an addendum discovered during Task 4's
> code review, not a revision to the original
> `2026-08-07-issue-410-tools-on-design.md` spec (that document is unaffected —
> this fix is internal to PR1's own implementation, not a scope change to the
> #410 epic).
> **2026-08-08, later:** §3.1's one-transaction-spanning-the-provider-call
> mechanism is itself superseded by
> [ADR-0062](../../adr/0062-three-phase-turn-and-role-scoped-connection-pools.md)
> (empirically verified pool deadlock: 16 concurrent turns, 0 succeeded);
> §3.2 carries forward as gate-keyed conditional threading and §3.3/§3.4 as
> per-phase deferred appends + `commit_failed` telemetry, per
> `docs/superpowers/plans/2026-08-08-issue-410-pr1-pool-deadlock-fix.md`.
> Task-number key: §1/§5 below cite the ORIGINAL
> `2026-08-07-issue-410-pr1-turn-side-effect-ledger.md` plan's numbering.
> In the superseding pool-deadlock plan those land as — original Task 1
> (`turn_side_effects.py` rewrite) → its Task 3; original Task 3 (Postgres
> integration contract) → its Task 4; original Task 4 (orchestrator
> wiring) → its Task 6; original Task 5 (boot wiring / arming) → its
> Task 7; original Task 6 (crash-injection flip) → folded into its Task 7
> Step 4; original Task 7 (working-memory append tests) → its Task 6
> Step 6. Read §5's per-task impact notes through that mapping.
```

- [ ] **Step 5: Lint the docs and run the full gate**

Run: `npx markdownlint-cli2 "docs/adr/0062-three-phase-turn-and-role-scoped-connection-pools.md" "docs/adr/0049-real-privileged-turn-comms-inbound.md"` (or the repo's configured markdownlint invocation if `make check` covers it)
Run: `make check`
Expected: everything green — this is the plan's final verification gate. If the macOS integration lane flakes under load, re-run the failing file alone before concluding anything (`make ...|tail` masks exit codes — check `$?` directly).

- [ ] **Step 6: Commit**

```bash
git add docs/adr/0062-three-phase-turn-and-role-scoped-connection-pools.md docs/adr/0049-real-privileged-turn-comms-inbound.md docs/superpowers/specs/2026-08-08-issue-410-pr1-ledger-transactional-fix-design.md
git commit -m "docs(adr): record the three-phase turn + role-scoped pools decision (#410 PR1)"
```

---

## Execution order and dependencies

Tasks 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10, strictly in order. Task 3 deliberately leaves `mypy src/` red on `core.py` until Task 6 lands (the ledger signature change precedes its consumer's restructure); Tasks 4, 7, 8, 9 need Docker. Nothing in this plan touches `src/alfred/security/`, `personas/`, `skills/`, or state.git.
