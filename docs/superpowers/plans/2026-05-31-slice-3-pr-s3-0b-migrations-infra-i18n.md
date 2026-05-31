# PR-S3-0b: Migrations, Infrastructure, and i18n Catalog — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the executable infrastructure that all Slice-3 implementation PRs depend on — Alembic migrations 0007/0008/0009, their SQLAlchemy 2.0 typed models, the complete Slice-3 i18n catalog additions, Docker/Redis/state.git infrastructure changes, and config schema additions for the `[quarantine]` block and `config/policies.yaml` low-blast knobs.

**Architecture:** Three Alembic migrations extend the Postgres schema (adding result values, two projection tables) without touching business logic. The i18n catalog ships all `t()` keys for every subsequent Slice-3 PR as a prerequisite gate — any implementation PR that calls `t("some.new.key")` before this PR merges fails `pybabel compile --check` in CI. Infrastructure changes are additive: the Dockerfile adds two new layers (git package + alfred-quarantine system user), docker-compose.yaml adds one service (alfred-redis) and one named volume (alfred_state_git), bin/alfred-setup.sh adds an idempotent `git init --bare` step, and the config files add schema stubs that downstream PRs read. Everything is independently revertable.

**Tech Stack:** Python 3.12+ / SQLAlchemy 2.0 declarative ORM / Alembic / Docker multi-stage build / Docker Compose v2 / Redis 7 / Babel pybabel / pytest + testcontainers / structlog

---

## §1 Goal

PR-S3-0b delivers the executable substrate for all Slice-3 implementation PRs. It gates on PR-S3-0a (which establishes `audit_row_schemas.py` constants and `payload_schema.py` Literal additions as the Slice-3 schema truth). Without this PR, no downstream PR can migrate the database, assume Redis is available, or call any new `t()` key without failing CI.

Spec anchors: spec §13 (migration table, SQLAlchemy models), spec §11.5 (i18n keys, full list), spec §17 PR-S3-0b scope, spec §7.7 (Redis key-pattern registry and `volatile-lru` policy), spec §8.1 (state.git idempotent init), spec §5.2 (alfred-quarantine UID), spec §11.1/§11.2 (config schema for high-blast and low-blast operator knobs).

**Depends on:** PR-S3-0a (merged — `audit_row_schemas.py` constants module that docs the migration table; `payload_schema.py` Literals; ADR-0017 as the load-bearing Slice-3 ADR).

**Blocks:** PR-S3-1, PR-S3-2, PR-S3-3a, PR-S3-3b, PR-S3-4, PR-S3-5, PR-S3-6.

---

## §2 Architecture overview

### Migration chain

The existing migration chain ends at `0006` (Slice-2.5 hook-trace dispositions). This PR adds three migrations in sequence:

```
0006 (Slice-2.5) → 0007 (Slice-3 result values) → 0008 (plugin_grants) → 0009 (capability_gate_sync)
```

Migration `0007` extends the `ck_audit_log_result` CHECK constraint additively — drop old, create new with 13 extra values. No data migration needed (additive). Downgrade: revert CHECK to 0006 domain and delete any rows that use the Slice-3-only values.

Migration `0008` creates `plugin_grants` — a Postgres projection of state.git-approved grants. Built from state.git on startup if the commit-hash cache says it is stale. Downgrade: DROP TABLE (rebuildable).

Migration `0009` creates `capability_gate_sync` — holds `(commit_hash, synced_at)` for the `RealGate` staleness check. Singleton row (INTEGER PK, id=1 enforced). One upsert on each sync. Downgrade: DROP TABLE. (mem-002: column is `commit_hash`; mem-004: singleton enforced by schema.)

### Infrastructure additions

```
docker/alfred-core.Dockerfile
  builder stage  ──────────────────── (unchanged)
  runtime stage
    + apt-get install -y git          # state.git operations
    + useradd --system alfred-quarantine  # UID for subprocess isolation (spec §5.2)
    + COPY bin/ into /app/bin         # launcher stub (PR-S3-3a writes content)

docker-compose.yaml
  + alfred-redis service (Redis 7, internal-only, volatile-lru, AOF, healthcheck)
  + alfred_state_git named volume at /var/lib/alfred (shared across alfred-core)
  alfred-core service:
    + depends_on: alfred-redis (condition: service_healthy)
    + ALFRED_REDIS_URL env var
    + cap_add: [SETUID]               # for alfred-plugin-launcher setuid bit (spec §5.2)

bin/alfred-setup.sh
  + state.git idempotent init step    # git init --bare + seed main branch

config/routing.yaml
  + [quarantine] block (provider, model, secret_id fields)  # spec §5.4

config/policies.yaml  (new file)
  + low-blast knob schema             # spec §11.2
```

### i18n catalog additions

All new `t()` keys ship in `locale/en/LC_MESSAGES/alfred.po` in this PR. The implementation PRs (S3-1 through S3-6) call these keys — they will find them in the compiled `.mo` and pass `pybabel compile --check` without needing to add entries themselves. The catalog-additions PR ships the keys with canonical English copy; copy editorial review is deferred to the implementing PR.

---

## §3 File structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/memory/migrations/versions/0007_audit_result_slice3_values.py` | Create | Extends `ck_audit_log_result` CHECK with 13 new Slice-3 result values |
| `src/alfred/memory/migrations/versions/0008_plugin_grants.py` | Create | Creates `plugin_grants` table (Postgres projection of state.git grants) |
| `src/alfred/memory/migrations/versions/0009_capability_gate_sync.py` | Create | Creates `capability_gate_sync` table (commit-hash cache for RealGate) |
| `src/alfred/memory/models.py` | Modify | Adds `PluginGrant`, `CapabilityGateSync` SQLAlchemy 2.0 typed models |
| `locale/en/LC_MESSAGES/alfred.po` | Modify | All new Slice-3 `t()` keys per spec §11.5 |
| `docker/alfred-core.Dockerfile` | Modify | Adds `git` package, `alfred-quarantine` system user, copies `bin/` |
| `docker-compose.yaml` | Modify | Adds `alfred-redis` service, `alfred_state_git` volume, updates `alfred-core` |
| `bin/alfred-setup.sh` | Modify | Adds idempotent `git init --bare /var/lib/alfred/state.git` + seed step |
| `config/routing.yaml` | Create | New config file: `[quarantine]` block (provider, model, secret_id) |
| `config/policies.yaml` | Create | New config file: low-blast operator knobs per spec §11.2 |
| `tests/integration/test_migrations_0007_0009.py` | Create | Migration round-trip: upgrade + downgrade for migrations 0007/0008/0009 |
| `tests/integration/test_state_git_init.py` | Create | Asserts idempotent `git init --bare` + `main` branch seeding |
| `tests/integration/test_capability_gate_seed.py` | Create | Asserts `capability_gate_sync` seeding on fresh DB |
| `tests/integration/test_redis_compose_service.py` | Create | Healthcheck + key-pattern smoke for `alfred-redis` |
| `tests/unit/test_catalog_slice3_keys.py` | Create | Every new Slice-3 `t()` key resolves without returning bare key; placeholder-integrity assertions (Cluster 6 / i18n-007) |
| `tests/unit/test_compose_invariants.py` | Create | Compose SETUID / volume invariant assertions (devops-010) |
| `bin/alfred-state-git-seed.sh` | Create | Dedicated seed script for state.git init; bypasses 'alfred' ENTRYPOINT (devops-001 / devops-009) |

---

## §4 Tasks

### Component A: Migration 0007 — `ck_audit_log_result` extension

- [ ] **Task 1 — Write failing migration round-trip test for 0007.**

  Files: Create `tests/integration/test_migrations_0007_0009.py`.

  Step 1 — Write the test (migration 0007 section only):

  ```python
  # tests/integration/test_migrations_0007_0009.py
  """Round-trip tests for Slice-3 migrations 0007–0009.

  Uses testcontainers to spin up a real Postgres instance so CHECK constraint
  violations are caught at the DB layer, not just in Python.
  """
  from __future__ import annotations

  import uuid
  import datetime as dt

  import pytest
  import sqlalchemy as sa
  from alembic import command as alembic_command
  from alembic.config import Config as AlembicConfig
  from testcontainers.postgres import PostgresContainer

  ALEMBIC_INI_PATH = "alembic.ini"

  SLICE_2_5_RESULTS = (
      "success", "budget_blocked", "budget_overrun", "provider_failed",
      "cancelled", "refused", "refused_unknown_user", "rate_limited",
      "dlp_failed", "split_failed", "send_failed", "recovery_send_failed",
      "login_failed", "gateway_unhealthy", "unknown_budget_user",
      "fault", "bypass",
  )
  SLICE_3_ONLY_RESULTS = (
      "extracted", "malformed_exhausted", "load_refused", "crashed",
      "quarantined", "reloaded", "requested", "approved", "denied",
      "revoked", "tripped", "reset", "content_expired",
  )


  # mem-005: module-scoped fixtures mean tests depend on ordering.
  # We pin ordering with pytest-ordering markers (pytestmark below).
  # This is safe because the entire test_migrations_0007_0009.py module uses a
  # single shared container — the tests form a deliberate migration chain.
  # Alternative: function-scoped fixtures for full isolation (slower).
  pytestmark = pytest.mark.run(order=1)  # ensure migration tests run in file order


  @pytest.fixture(scope="module")
  def pg_url() -> str:
      with PostgresContainer("postgres:16") as pg:
          # mem-005: .replace("psycopg2", "psycopg2") is a no-op; removed.
          # If the project uses asyncpg for async paths, swap here.
          # The migration tests use sync SQLAlchemy (alembic requires sync).
          yield pg.get_connection_url()


  @pytest.fixture(scope="module")
  def alembic_cfg(pg_url: str) -> AlembicConfig:
      cfg = AlembicConfig(ALEMBIC_INI_PATH)
      cfg.set_main_option("sqlalchemy.url", pg_url)
      return cfg


  @pytest.fixture(scope="module")
  def engine_at_0006(alembic_cfg: AlembicConfig, pg_url: str) -> sa.Engine:
      """Apply migrations up to 0006 (Slice-2.5 baseline)."""
      alembic_command.upgrade(alembic_cfg, "0006")
      return sa.create_engine(pg_url)


  def test_0007_upgrade_accepts_slice3_results(
      alembic_cfg: AlembicConfig,
      engine_at_0006: sa.Engine,
  ) -> None:
      """After upgrade to 0007, Slice-3 result values are accepted."""
      alembic_command.upgrade(alembic_cfg, "0007")
      with engine_at_0006.begin() as conn:
          # Insert a row with a Slice-3 result value — must not raise
          for result_val in SLICE_3_ONLY_RESULTS:
              conn.execute(
                  sa.text(
                      "INSERT INTO audit_log "
                      "(id, created_at, trace_id, event, trust_tier_of_trigger, result, language)"
                      " VALUES (:id, :ts, :trace, :event, :tier, :result, :lang)"
                  ),
                  {
                      "id": str(uuid.uuid4()),
                      "ts": dt.datetime.now(dt.UTC),
                      "trace": "test-trace-id",
                      "event": "test.event",
                      "tier": "T2",
                      "result": result_val,
                      "lang": "en-US",
                  },
              )


  def test_0007_upgrade_still_accepts_slice25_results(
      alembic_cfg: AlembicConfig,
      engine_at_0006: sa.Engine,
  ) -> None:
      """After upgrade to 0007, legacy result values are still accepted."""
      with engine_at_0006.begin() as conn:
          conn.execute(
              sa.text(
                  "INSERT INTO audit_log "
                  "(id, created_at, trace_id, event, trust_tier_of_trigger, result, language)"
                  " VALUES (:id, :ts, :trace, :event, :tier, :result, :lang)"
              ),
              {
                  "id": str(uuid.uuid4()),
                  "ts": dt.datetime.now(dt.UTC),
                  "trace": "test-trace-id",
                  "event": "test.event",
                  "tier": "T2",
                  "result": "success",
                  "lang": "en-US",
              },
          )


  def test_0007_upgrade_rejects_unknown_result(
      engine_at_0006: sa.Engine,
  ) -> None:
      """After upgrade to 0007, unknown result values raise IntegrityError."""
      with pytest.raises(sa.exc.IntegrityError):
          with engine_at_0006.begin() as conn:
              conn.execute(
                  sa.text(
                      "INSERT INTO audit_log "
                      "(id, created_at, trace_id, event, trust_tier_of_trigger, result, language)"
                      " VALUES (:id, :ts, :trace, :event, :tier, :result, :lang)"
                  ),
                  {
                      "id": str(uuid.uuid4()),
                      "ts": dt.datetime.now(dt.UTC),
                      "trace": "test-trace-id",
                      "event": "test.event",
                      "tier": "T2",
                      "result": "not_a_real_result",
                      "lang": "en-US",
                  },
              )


  def test_0007_downgrade_removes_slice3_results(
      alembic_cfg: AlembicConfig,
      engine_at_0006: sa.Engine,
  ) -> None:
      """Downgrade to 0006 removes Slice-3 result rows and reverts CHECK."""
      alembic_command.downgrade(alembic_cfg, "0006")
      with pytest.raises(sa.exc.IntegrityError):
          with engine_at_0006.begin() as conn:
              conn.execute(
                  sa.text(
                      "INSERT INTO audit_log "
                      "(id, created_at, trace_id, event, trust_tier_of_trigger, result, language)"
                      " VALUES (:id, :ts, :trace, :event, :tier, :result, :lang)"
                  ),
                  {
                      "id": str(uuid.uuid4()),
                      "ts": dt.datetime.now(dt.UTC),
                      "trace": "test-trace-id",
                      "event": "test.event",
                      "tier": "T2",
                      "result": "extracted",
                      "lang": "en-US",
                  },
              )
  ```

  Step 2 — Run and confirm FAIL (migration 0007 does not exist yet):

  ```bash
  cd <repo-root>
  uv run pytest tests/integration/test_migrations_0007_0009.py::test_0007_upgrade_accepts_slice3_results -x -q 2>&1 | tail -5
  # Expected: ERROR — alembic can't find revision 0007
  ```

- [ ] **Task 2 — Implement migration 0007.**

  Files: Create `src/alfred/memory/migrations/versions/0007_audit_result_slice3_values.py`.

  ```python
  # src/alfred/memory/migrations/versions/0007_audit_result_slice3_values.py
  """Extend audit_log.result CHECK constraint with Slice-3 result values.

  Revision ID: 0007
  Revises: 0006
  Create Date: 2026-05-31 00:00:00.000000

  Slice 3 introduces five new emitter subsystems (plugins/, supervisor/,
  security/, orchestrator/, identity/) that write audit rows with result
  values outside the Slice-2.5 domain. This migration extends ck_audit_log_result
  to accept the 13 new values. It is strictly additive — no rows are modified.

  New result values (from spec §13 migration table):
  - extracted           — quarantine.extract: structured data extracted
  - malformed_exhausted — quarantine.extract: retries exhausted on malformed output
  - load_refused        — plugin.lifecycle: load refused at handshake
  - crashed             — plugin.lifecycle: subprocess exited unexpectedly
  - quarantined         — plugin.lifecycle: circuit breaker tripped / protocol violation
  - reloaded            — plugin.lifecycle: successful restart after crash
  - requested           — plugin.grant: grant proposal submitted
  - approved            — plugin.grant: grant proposal approved
  - denied              — plugin.grant: grant proposal denied
  - revoked             — plugin.grant: grant revoked
  - tripped             — supervisor.breaker: circuit breaker opened
  - reset               — supervisor.breaker: breaker reset by operator
  - content_expired     — web.fetch / quarantine.extract: ContentHandle TTL expired

  Downgrade: revert CHECK to the 0006 domain. Rows whose ``result`` is in
  the Slice-3-only set are deleted before the constraint is restored (same
  loud-destruction pattern as 0005/0006 downgrades — operators should
  snapshot before downgrading).
  """
  from collections.abc import Sequence

  from alembic import op

  revision: str = "0007"
  down_revision: str | Sequence[str] | None = "0006"
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

  # 0006 base domain — Slice-1 through Slice-2.5 values. Kept intact.
  _BASE_RESULTS: tuple[str, ...] = (
      # Slice-1 (0003)
      "success",
      "budget_blocked",
      "budget_overrun",
      "provider_failed",
      "cancelled",
      # Slice-2 (0005) — comms-adapter outcomes
      "refused",
      "refused_unknown_user",
      "rate_limited",
      "dlp_failed",
      "split_failed",
      "send_failed",
      "recovery_send_failed",
      "login_failed",
      "gateway_unhealthy",
      "unknown_budget_user",
      # Slice-2.5 (0006) — hook-trace dispositions
      "fault",
      "bypass",
  )

  # Slice-3 additions (spec §13).
  _SLICE_3_ADDITIONS: tuple[str, ...] = (
      "extracted",
      "malformed_exhausted",
      "load_refused",
      "crashed",
      "quarantined",
      "reloaded",
      "requested",
      "approved",
      "denied",
      "revoked",
      "tripped",
      "reset",
      "content_expired",
  )


  def _result_in_clause(values: tuple[str, ...]) -> str:
      quoted = ", ".join(f"'{v}'" for v in values)
      return f"result IN ({quoted})"


  def upgrade() -> None:
      """Replace ck_audit_log_result with the Slice-3 extended domain."""
      op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
      op.create_check_constraint(
          "ck_audit_log_result",
          "audit_log",
          _result_in_clause(_BASE_RESULTS + _SLICE_3_ADDITIONS),
      )


  def downgrade() -> None:
      """Restore the 0006 domain.

      Destructive: deletes rows whose ``result`` is in the Slice-3-only set.
      Operators who care about Slice-3 audit history must snapshot the table
      BEFORE downgrading. Same pattern as 0005/0006 downgrades.
      """
      quoted = ", ".join(f"'{v}'" for v in _SLICE_3_ADDITIONS)
      op.execute(f"DELETE FROM audit_log WHERE result IN ({quoted})")  # noqa: S608
      op.drop_constraint("ck_audit_log_result", "audit_log", type_="check")
      op.create_check_constraint(
          "ck_audit_log_result",
          "audit_log",
          _result_in_clause(_BASE_RESULTS),
      )
  ```

  Step 3 — Run and confirm PASS:

  ```bash
  uv run pytest tests/integration/test_migrations_0007_0009.py -k "0007" -q 2>&1 | tail -5
  # Expected: 4 passed
  ```

  Step 4 — Commit:

  ```bash
  git add src/alfred/memory/migrations/versions/0007_audit_result_slice3_values.py \
          tests/integration/test_migrations_0007_0009.py
  git commit -m "feat(migrations): extend ck_audit_log_result with Slice-3 result values (#TBD-slice3)"
  ```

### Component B: Migration 0008 — `plugin_grants` table

- [ ] **Task 3 — Write failing migration round-trip test for 0008.**

  Files: Modify `tests/integration/test_migrations_0007_0009.py` (append 0008 tests).

  Append to `test_migrations_0007_0009.py`:

  ```python
  def test_0008_upgrade_creates_plugin_grants_table(
      alembic_cfg: AlembicConfig,
      pg_url: str,
  ) -> None:
      """After upgrade to 0008, plugin_grants table exists with correct columns."""
      alembic_command.upgrade(alembic_cfg, "0008")
      engine = sa.create_engine(pg_url)
      insp = sa.inspect(engine)
      assert "plugin_grants" in insp.get_table_names()
      cols = {c["name"] for c in insp.get_columns("plugin_grants")}
      assert cols >= {
          "id", "created_at", "plugin_id", "subscriber_tier",
          "hookpoint", "content_tier", "operator_user_id", "proposal_branch",
          "correlation_id", "state", "state_git_commit_hash",
      }
      # mem-003: verify unique constraint exists (matches PR-S3-2 ON CONFLICT target)
      unique_constraints = {
          uc["name"] for uc in insp.get_unique_constraints("plugin_grants")
      }
      assert "uq_plugin_grants_plugin_hook_tier" in unique_constraints


  def test_0008_plugin_grants_accepts_valid_row(
      pg_url: str,
  ) -> None:
      """plugin_grants accepts a row with all required fields including content_tier."""
      engine = sa.create_engine(pg_url)
      with engine.begin() as conn:
          conn.execute(
              sa.text(
                  "INSERT INTO plugin_grants "
                  "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                  " content_tier, operator_user_id, proposal_branch, correlation_id, "
                  " state, state_git_commit_hash) "
                  "VALUES (:id, :ts, :pid, :tier, :hp, :ctier, :uid, :branch, :cid, :state, :hash)"
              ),
              {
                  "id": str(uuid.uuid4()),
                  "ts": dt.datetime.now(dt.UTC),
                  "pid": "alfred.quarantined-llm",
                  "tier": "system",
                  "hp": "security.quarantined.extract",
                  "ctier": "T3",  # mem-001: content_tier column
                  "uid": "operator-001",
                  "branch": "proposal/policy-grant-abc123",
                  "cid": str(uuid.uuid4()),
                  "state": "approved",
                  "hash": "abc123def456",
              },
          )
      # Also verify NULL content_tier is accepted (no content-tier restriction)
      with engine.begin() as conn:
          conn.execute(
              sa.text(
                  "INSERT INTO plugin_grants "
                  "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                  " content_tier, operator_user_id, proposal_branch, correlation_id, "
                  " state, state_git_commit_hash) "
                  "VALUES (:id, :ts, :pid, :tier, :hp, NULL, :uid, :branch, :cid, :state, :hash)"
              ),
              {
                  "id": str(uuid.uuid4()),
                  "ts": dt.datetime.now(dt.UTC),
                  "pid": "alfred.web-fetch",
                  "tier": "operator",
                  "hp": "tool.web.fetch",
                  "uid": "operator-001",
                  "branch": "proposal/policy-grant-def456",
                  "cid": str(uuid.uuid4()),
                  "state": "approved",
                  "hash": "abc123def456",
              },
          )


  def test_0008_plugin_grants_rejects_invalid_state(
      pg_url: str,
  ) -> None:
      """plugin_grants rejects an unrecognised state value."""
      engine = sa.create_engine(pg_url)
      with pytest.raises(sa.exc.IntegrityError):
          with engine.begin() as conn:
              conn.execute(
                  sa.text(
                      "INSERT INTO plugin_grants "
                      "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                      " content_tier, operator_user_id, proposal_branch, correlation_id, "
                      " state, state_git_commit_hash) "
                      "VALUES (:id, :ts, :pid, :tier, :hp, NULL, :uid, :branch, :cid, :state, :hash)"
                  ),
                  {
                      "id": str(uuid.uuid4()),
                      "ts": dt.datetime.now(dt.UTC),
                      "pid": "alfred.quarantined-llm",
                      "tier": "system",
                      "hp": "security.quarantined.extract",
                      "uid": "operator-001",
                      "branch": "proposal/policy-grant-abc123",
                      "cid": str(uuid.uuid4()),
                      "state": "totally_made_up",
                      "hash": "abc123def456",
                  },
              )


  def test_0008_plugin_grants_rejects_invalid_content_tier(
      pg_url: str,
  ) -> None:
      """plugin_grants rejects a content_tier value outside T0/T1/T2/T3."""
      engine = sa.create_engine(pg_url)
      with pytest.raises(sa.exc.IntegrityError):
          with engine.begin() as conn:
              conn.execute(
                  sa.text(
                      "INSERT INTO plugin_grants "
                      "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                      " content_tier, operator_user_id, proposal_branch, correlation_id, "
                      " state, state_git_commit_hash) "
                      "VALUES (:id, :ts, :pid, :tier, :hp, :ctier, :uid, :branch, :cid, :state, :hash)"
                  ),
                  {
                      "id": str(uuid.uuid4()),
                      "ts": dt.datetime.now(dt.UTC),
                      "pid": "alfred.quarantined-llm",
                      "tier": "system",
                      "hp": "security.quarantined.extract",
                      "ctier": "T99",  # invalid — must reject
                      "uid": "operator-001",
                      "branch": "proposal/policy-grant-xyz",
                      "cid": str(uuid.uuid4()),
                      "state": "approved",
                      "hash": "abc123def456",
                  },
              )


  def test_0008_plugin_grants_unique_constraint_on_conflict_target(
      pg_url: str,
  ) -> None:
      """upsert on (plugin_id, hookpoint, subscriber_tier) leaves exactly one row.

      Verifies the ON CONFLICT target used by PR-S3-2 PostgresBackend.upsert_grant.
      Without the unique constraint, every upsert raises InvalidColumnReference.
      """
      engine = sa.create_engine(pg_url)
      plugin_id = "alfred.test-upsert"
      hookpoint = "test.upsert.hook"
      tier = "operator"
      row_base = {
          "ts": dt.datetime.now(dt.UTC),
          "pid": plugin_id,
          "tier": tier,
          "hp": hookpoint,
          "uid": "operator-001",
          "branch": "proposal/upsert-test",
          "hash": "abc123",
      }
      with engine.begin() as conn:
          conn.execute(
              sa.text(
                  "INSERT INTO plugin_grants "
                  "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                  " content_tier, operator_user_id, proposal_branch, correlation_id, "
                  " state, state_git_commit_hash) "
                  "VALUES (gen_random_uuid(), :ts, :pid, :tier, :hp, NULL, :uid, :branch, "
                  "        gen_random_uuid()::text, 'requested', :hash)"
              ),
              row_base,
          )
          # ON CONFLICT upsert — same triple, different state
          conn.execute(
              sa.text(
                  "INSERT INTO plugin_grants "
                  "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                  " content_tier, operator_user_id, proposal_branch, correlation_id, "
                  " state, state_git_commit_hash) "
                  "VALUES (gen_random_uuid(), :ts, :pid, :tier, :hp, NULL, :uid, :branch, "
                  "        gen_random_uuid()::text, 'approved', :hash) "
                  "ON CONFLICT (plugin_id, hookpoint, subscriber_tier) "
                  "DO UPDATE SET state = EXCLUDED.state"
              ),
              row_base,
          )
          count = conn.execute(
              sa.text(
                  "SELECT COUNT(*) FROM plugin_grants "
                  "WHERE plugin_id = :pid AND hookpoint = :hp AND subscriber_tier = :tier"
              ),
              {"pid": plugin_id, "hp": hookpoint, "tier": tier},
          ).scalar()
          assert count == 1, f"Expected 1 row after upsert, got {count}"


  def test_0008_downgrade_drops_plugin_grants(
      alembic_cfg: AlembicConfig,
      pg_url: str,
  ) -> None:
      """Downgrade from 0008 drops plugin_grants table."""
      alembic_command.downgrade(alembic_cfg, "0007")
      engine = sa.create_engine(pg_url)
      insp = sa.inspect(engine)
      assert "plugin_grants" not in insp.get_table_names()
  ```

  Run and confirm FAIL (table does not exist):

  ```bash
  uv run pytest tests/integration/test_migrations_0007_0009.py -k "0008" -x -q 2>&1 | tail -5
  # Expected: ERROR — alembic can't find revision 0008
  ```

- [ ] **Task 4 — Implement migration 0008 + `PluginGrant` SQLAlchemy model.**

  Files:
  - Create `src/alfred/memory/migrations/versions/0008_plugin_grants.py`
  - Modify `src/alfred/memory/models.py`

  Migration file:

  ```python
  # src/alfred/memory/migrations/versions/0008_plugin_grants.py
  """Create plugin_grants table — Postgres projection of state.git grants.

  Revision ID: 0008
  Revises: 0007
  Create Date: 2026-05-31 00:00:00.000000

  plugin_grants is the Postgres runtime cache for the state.git capability
  grant tree. RealGate (PR-S3-2) reads from this table for millisecond-latency
  hot-path checks; the table is rebuilt from state.git when the commit hash
  stored in capability_gate_sync (migration 0009) differs from the current
  HEAD (spec §8.1).

  Columns:
  - id: UUID primary key
  - created_at: timestamp with tz
  - plugin_id: the MCP plugin identifier (e.g. "alfred.quarantined-llm")
  - subscriber_tier: "system" | "operator" | "user-plugin" (spec §4.3 naming rule,
    subscriber_tier axis — NOT a content trust tier)
  - hookpoint: dotted action name (e.g. "security.quarantined.extract")
  - content_tier: content trust tier the grant allows the plugin to handle (T0/T1/T2/T3),
    NULL means no content-tier restriction. See spec §4.3 two-axis naming rule.
  - operator_user_id: canonical_user_id of the operator who created the grant
  - proposal_branch: state.git proposal branch name (e.g. "proposal/policy-grant-abc")
  - correlation_id: UUID for audit trail linkage
  - state: "requested" | "approved" | "denied" | "revoked" — closed domain
  - state_git_commit_hash: HEAD at the time this row was written

  UNIQUE constraint on (plugin_id, hookpoint, subscriber_tier) matches the
  PR-S3-2 PostgresBackend ON CONFLICT target. See mem-003.

  Downgrade: DROP TABLE — table is fully rebuildable from state.git (spec §13).
  """
  from collections.abc import Sequence

  import sqlalchemy as sa
  from alembic import op

  revision: str = "0008"
  down_revision: str | Sequence[str] | None = "0007"
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

  _GRANT_STATES = ("requested", "approved", "denied", "revoked")


  def upgrade() -> None:
      """Create plugin_grants table."""
      op.create_table(
          "plugin_grants",
          sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
          sa.Column(
              "created_at",
              sa.DateTime(timezone=True),
              nullable=False,
          ),
          sa.Column("plugin_id", sa.String(128), nullable=False),
          sa.Column("subscriber_tier", sa.String(32), nullable=False),
          sa.Column("hookpoint", sa.String(128), nullable=False),
          # mem-001: content_tier column added — PR-S3-2 PostgresBackend reads/writes this.
          # NULL = no content-tier restriction on the grant (spec §4.3 two-axis rule).
          # When set, values are T0/T1/T2/T3 matching the trust-tier domain.
          sa.Column("content_tier", sa.String(8), nullable=True),
          sa.Column("operator_user_id", sa.String(64), nullable=True),
          sa.Column("proposal_branch", sa.String(256), nullable=True),
          sa.Column("correlation_id", sa.String(64), nullable=False),
          sa.Column("state", sa.String(32), nullable=False),
          sa.Column("state_git_commit_hash", sa.String(64), nullable=True),
          sa.CheckConstraint(
              "state IN ('requested', 'approved', 'denied', 'revoked')",
              name="ck_plugin_grants_state",
          ),
          sa.CheckConstraint(
              "subscriber_tier IN ('system', 'operator', 'user-plugin')",
              name="ck_plugin_grants_subscriber_tier",
          ),
          sa.CheckConstraint(
              "content_tier IS NULL OR content_tier IN ('T0', 'T1', 'T2', 'T3')",
              name="ck_plugin_grants_content_tier",
          ),
          # mem-003: UNIQUE constraint must match PR-S3-2's ON CONFLICT target.
          # PostgresBackend.upsert_grant issues:
          #   INSERT ... ON CONFLICT (plugin_id, hookpoint, subscriber_tier) DO UPDATE
          # Without this, every upsert raises InvalidColumnReference.
          sa.UniqueConstraint(
              "plugin_id",
              "hookpoint",
              "subscriber_tier",
              name="uq_plugin_grants_plugin_hook_tier",
          ),
      )
      op.create_index(
          "ix_plugin_grants_plugin_id_state",
          "plugin_grants",
          ["plugin_id", "state"],
      )
      op.create_index(
          "ix_plugin_grants_hookpoint",
          "plugin_grants",
          ["hookpoint"],
      )


  def downgrade() -> None:
      """Drop plugin_grants table. Rebuildable from state.git."""
      op.drop_table("plugin_grants")
  ```

  Add model to `src/alfred/memory/models.py` — append after `AuditEntry`:

  ```python
  class PluginGrant(Base):
      """Postgres projection of a state.git capability grant.

      RealGate (PR-S3-2) reads this table for millisecond-latency hot-path
      capability checks. Built from state.git when commit hash drifts from
      capability_gate_sync. See spec §8.1 and migration 0008.

      Two grant axes per spec §4.3:
      - subscriber_tier (system / operator / user-plugin): which tier of hook-
        subscribers the plugin is permitted to serve.
      - content_tier (T0-T3, nullable): which content trust tier the plugin may
        handle. NULL = no content-tier restriction.
      """

      __tablename__ = "plugin_grants"

      id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
      created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
      plugin_id: Mapped[str] = mapped_column(String(128))
      # spec §4.3 naming rule: subscriber_tier is the hook-subscription axis
      # (system / operator / user-plugin). NOT a content trust tier (T0-T3).
      subscriber_tier: Mapped[str] = mapped_column(String(32))
      hookpoint: Mapped[str] = mapped_column(String(128))
      # mem-001: content_tier column — PR-S3-2 PostgresBackend reads/writes this.
      # NULL = no content-tier restriction. When set, must be T0/T1/T2/T3.
      content_tier: Mapped[str | None] = mapped_column(String(8), nullable=True)
      operator_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
      proposal_branch: Mapped[str | None] = mapped_column(String(256), nullable=True)
      correlation_id: Mapped[str] = mapped_column(String(64))
      # state follows the plugin.grant.* audit family (spec §8.5, audit_row_schemas.py)
      state: Mapped[str] = mapped_column(String(32))
      state_git_commit_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

      __table_args__ = (
          CheckConstraint(
              "state IN ('requested', 'approved', 'denied', 'revoked')",
              name="ck_plugin_grants_state",
          ),
          CheckConstraint(
              "subscriber_tier IN ('system', 'operator', 'user-plugin')",
              name="ck_plugin_grants_subscriber_tier",
          ),
          CheckConstraint(
              "content_tier IS NULL OR content_tier IN ('T0', 'T1', 'T2', 'T3')",
              name="ck_plugin_grants_content_tier",
          ),
          # mem-003: UNIQUE on (plugin_id, hookpoint, subscriber_tier) matches
          # PR-S3-2 PostgresBackend.upsert_grant ON CONFLICT target.
          UniqueConstraint(
              "plugin_id",
              "hookpoint",
              "subscriber_tier",
              name="uq_plugin_grants_plugin_hook_tier",
          ),
          Index("ix_plugin_grants_plugin_id_state", "plugin_id", "state"),
          Index("ix_plugin_grants_hookpoint", "hookpoint"),
      )
  ```

  Step 3 — Run and confirm PASS:

  ```bash
  uv run pytest tests/integration/test_migrations_0007_0009.py -k "0008" -q 2>&1 | tail -5
  # Expected: 4 passed
  ```

  Step 4 — Type check:

  ```bash
  uv run mypy src/alfred/memory/models.py --strict 2>&1 | tail -5
  # Expected: Success: no issues found
  ```

  Step 5 — Commit:

  ```bash
  git add src/alfred/memory/migrations/versions/0008_plugin_grants.py \
          src/alfred/memory/models.py \
          tests/integration/test_migrations_0007_0009.py
  git commit -m "feat(migrations): add plugin_grants table + PluginGrant ORM model (#TBD-slice3)"
  ```

### Component C: Migration 0009 — `capability_gate_sync` table

- [ ] **Task 5 — Write failing migration round-trip test for 0009.**

  Files: Modify `tests/integration/test_migrations_0007_0009.py` (append 0009 tests).
  Also: Create `tests/integration/test_capability_gate_seed.py`.

  Append to `test_migrations_0007_0009.py`:

  ```python
  def test_0009_upgrade_creates_capability_gate_sync(
      alembic_cfg: AlembicConfig,
      pg_url: str,
  ) -> None:
      """After upgrade to 0009, capability_gate_sync table exists with correct schema.

      mem-002: column is 'commit_hash' (not 'state_git_commit_hash') — matches
      PR-S3-2 PostgresBackend SQL.
      mem-004: PK is INTEGER with CHECK (id = 1) — enforces singleton row.
      """
      alembic_command.upgrade(alembic_cfg, "0009")
      engine = sa.create_engine(pg_url)
      insp = sa.inspect(engine)
      assert "capability_gate_sync" in insp.get_table_names()
      cols = {c["name"] for c in insp.get_columns("capability_gate_sync")}
      # mem-002: column must be 'commit_hash', NOT 'state_git_commit_hash'
      assert "commit_hash" in cols
      assert "state_git_commit_hash" not in cols
      assert cols >= {"id", "commit_hash", "synced_at"}


  def test_0009_capability_gate_sync_singleton_upsert(
      pg_url: str,
  ) -> None:
      """capability_gate_sync enforces exactly one row (singleton pattern).

      mem-004: the singleton row semantics require a fixed PK (id=1) with a
      CHECK constraint, not a UUID PK. After N upserts there must be exactly
      one row. PR-S3-2 PostgresBackend.set_sync_hash uses:
        INSERT (id, commit_hash) VALUES (1, :h)
        ON CONFLICT (id) DO UPDATE SET commit_hash = EXCLUDED.commit_hash
      """
      engine = sa.create_engine(pg_url)
      with engine.begin() as conn:
          # First upsert seeds the singleton row
          conn.execute(
              sa.text(
                  "INSERT INTO capability_gate_sync "
                  "(id, commit_hash, synced_at) "
                  "VALUES (1, :hash, :ts) "
                  "ON CONFLICT (id) DO UPDATE "
                  "SET commit_hash = EXCLUDED.commit_hash, synced_at = EXCLUDED.synced_at"
              ),
              {"hash": "abc123", "ts": dt.datetime.now(dt.UTC)},
          )
          # Second upsert updates the same row
          conn.execute(
              sa.text(
                  "INSERT INTO capability_gate_sync "
                  "(id, commit_hash, synced_at) "
                  "VALUES (1, :hash, :ts) "
                  "ON CONFLICT (id) DO UPDATE "
                  "SET commit_hash = EXCLUDED.commit_hash, synced_at = EXCLUDED.synced_at"
              ),
              {"hash": "def456", "ts": dt.datetime.now(dt.UTC)},
          )
          count = conn.execute(
              sa.text("SELECT COUNT(*) FROM capability_gate_sync")
          ).scalar()
          assert count == 1, f"Expected singleton row, got {count}"
          hash_val = conn.execute(
              sa.text("SELECT commit_hash FROM capability_gate_sync")
          ).scalar()
          assert hash_val == "def456"


  def test_0009_capability_gate_sync_rejects_second_id(
      pg_url: str,
  ) -> None:
      """capability_gate_sync rejects a second row (id != 1)."""
      engine = sa.create_engine(pg_url)
      with pytest.raises(sa.exc.IntegrityError):
          with engine.begin() as conn:
              conn.execute(
                  sa.text(
                      "INSERT INTO capability_gate_sync "
                      "(id, commit_hash, synced_at) "
                      "VALUES (2, :hash, :ts)"
                  ),
                  {"hash": "xyz", "ts": dt.datetime.now(dt.UTC)},
              )


  def test_0009_downgrade_drops_capability_gate_sync(
      alembic_cfg: AlembicConfig,
      pg_url: str,
  ) -> None:
      """Downgrade from 0009 drops capability_gate_sync table."""
      alembic_command.downgrade(alembic_cfg, "0008")
      engine = sa.create_engine(pg_url)
      insp = sa.inspect(engine)
      assert "capability_gate_sync" not in insp.get_table_names()
  ```

  Create `tests/integration/test_capability_gate_seed.py`:

  ```python
  # tests/integration/test_capability_gate_seed.py
  """Integration test: capability_gate_sync seeding on fresh database.

  Asserts that after migrations 0007-0009 are applied to a fresh DB, the
  capability_gate_sync table exists and can accept the initial seed row
  written by 'alfred plugin grant init' (per spec §15.4 step 2).

  mem-002: column is 'commit_hash' (not 'state_git_commit_hash').
  mem-004: id is INTEGER 1 (singleton PK), not UUID.
  """
  from __future__ import annotations

  import datetime as dt

  import sqlalchemy as sa
  from alembic import command as alembic_command
  from alembic.config import Config as AlembicConfig
  from testcontainers.postgres import PostgresContainer

  ALEMBIC_INI_PATH = "alembic.ini"


  @pytest.fixture(scope="module")
  def pg_url_fresh() -> str:
      with PostgresContainer("postgres:16") as pg:
          yield pg.get_connection_url()  # mem-005: .replace("psycopg2","psycopg2") was a no-op


  @pytest.fixture(scope="module")
  def engine_at_head(pg_url_fresh: str) -> sa.Engine:
      cfg = AlembicConfig(ALEMBIC_INI_PATH)
      cfg.set_main_option("sqlalchemy.url", pg_url_fresh)
      alembic_command.upgrade(cfg, "head")
      return sa.create_engine(pg_url_fresh)


  def test_capability_gate_sync_table_present_after_head(
      engine_at_head: sa.Engine,
  ) -> None:
      """After applying all migrations, capability_gate_sync exists."""
      insp = sa.inspect(engine_at_head)
      assert "capability_gate_sync" in insp.get_table_names()


  def test_capability_gate_sync_seed_row_can_be_written(
      engine_at_head: sa.Engine,
  ) -> None:
      """A seed row (written by 'alfred plugin grant init') is accepted.

      mem-002: column is 'commit_hash'; mem-004: id must be 1 (singleton PK).
      """
      with engine_at_head.begin() as conn:
          conn.execute(
              sa.text(
                  "INSERT INTO capability_gate_sync "
                  "(id, commit_hash, synced_at) "
                  "VALUES (1, :hash, :ts) "
                  "ON CONFLICT (id) DO UPDATE "
                  "SET commit_hash = EXCLUDED.commit_hash, synced_at = EXCLUDED.synced_at"
              ),
              {
                  # Empty commit hash for a freshly seeded state.git (spec §15.4 step 2)
                  "hash": "0000000000000000000000000000000000000000",
                  "ts": dt.datetime.now(dt.UTC),
              },
          )


  def test_capability_gate_sync_allows_null_hash(
      engine_at_head: sa.Engine,
  ) -> None:
      """commit_hash may be NULL (before first sync — before alfred plugin grant init)."""
      with engine_at_head.begin() as conn:
          # id=1 is already written by the previous test (module scope); this upsert sets NULL
          conn.execute(
              sa.text(
                  "INSERT INTO capability_gate_sync "
                  "(id, commit_hash, synced_at) "
                  "VALUES (1, NULL, :ts) "
                  "ON CONFLICT (id) DO UPDATE "
                  "SET commit_hash = NULL, synced_at = EXCLUDED.synced_at"
              ),
              {"ts": dt.datetime.now(dt.UTC)},
          )
  ```

  Run and confirm FAIL:

  ```bash
  uv run pytest tests/integration/test_migrations_0007_0009.py -k "0009" -x -q 2>&1 | tail -5
  # Expected: ERROR — alembic can't find revision 0009
  ```

- [ ] **Task 6 — Implement migration 0009 + `CapabilityGateSync` SQLAlchemy model.**

  Files:
  - Create `src/alfred/memory/migrations/versions/0009_capability_gate_sync.py`
  - Modify `src/alfred/memory/models.py`

  Migration file:

  ```python
  # src/alfred/memory/migrations/versions/0009_capability_gate_sync.py
  """Create capability_gate_sync table — commit-hash cache for RealGate.

  Revision ID: 0009
  Revises: 0008
  Create Date: 2026-05-31 00:00:00.000000

  capability_gate_sync holds a SINGLETON row tracking the state.git HEAD
  commit hash at the last time RealGate (PR-S3-2) rebuilt plugin_grants from
  state.git. On AlfredOS startup, RealGate checks whether the stored hash
  differs from state.git HEAD; if so, it rebuilds plugin_grants (spec §8.1).

  Singleton enforcement (mem-004):
  - id is INTEGER PRIMARY KEY with CHECK (id = 1), not UUID.
  - Each RealGate sync uses an ON CONFLICT (id) DO UPDATE upsert with id=1.
  - This guarantees exactly one row at all times without application-layer
    coordination. UUID PKs allow multiple rows when id is omitted (each INSERT
    gets a new UUID), making staleness checks non-deterministic.

  Column naming (mem-002):
  - Column is 'commit_hash' (not 'state_git_commit_hash') to match the
    PR-S3-2 PostgresBackend SQL exactly:
      SELECT commit_hash FROM capability_gate_sync
      INSERT (id, commit_hash) VALUES (1, :h) ON CONFLICT (id) DO UPDATE ...

  Columns:
  - id: INTEGER PRIMARY KEY CHECK (id = 1) — singleton sentinel
  - commit_hash: 40-char SHA or NULL before first sync (spec §15.4 step 2)
  - synced_at: timestamp with tz of last successful sync

  Downgrade: DROP TABLE — re-derived from state.git on next startup (spec §13).
  """
  from collections.abc import Sequence

  import sqlalchemy as sa
  from alembic import op

  revision: str = "0009"
  down_revision: str | Sequence[str] | None = "0008"
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
      """Create capability_gate_sync singleton table."""
      op.create_table(
          "capability_gate_sync",
          # mem-004: INTEGER PK with CHECK enforces the singleton row contract.
          # UUID PK with default=uuid4 would create a new row on every INSERT
          # that omits the id — RealGate's staleness check would be non-deterministic.
          sa.Column("id", sa.Integer(), primary_key=True),
          sa.CheckConstraint("id = 1", name="ck_capability_gate_sync_singleton"),
          # mem-002: column named 'commit_hash' to match PR-S3-2 PostgresBackend SQL.
          sa.Column("commit_hash", sa.String(64), nullable=True),
          sa.Column(
              "synced_at",
              sa.DateTime(timezone=True),
              nullable=False,
          ),
      )


  def downgrade() -> None:
      """Drop capability_gate_sync. Re-derived from state.git on next startup."""
      op.drop_table("capability_gate_sync")
  ```

  Add model to `src/alfred/memory/models.py` (append after `PluginGrant`):

  ```python
  class CapabilityGateSync(Base):
      """Commit-hash cache for RealGate (spec §8.1).

      Singleton row (id=1 enforced by CHECK constraint). Upserted by RealGate
      on each successful state.git sync. RealGate reads this at startup to
      decide whether to rebuild plugin_grants. See migration 0009.

      mem-002: column is 'commit_hash' (not 'state_git_commit_hash') — matches
      PR-S3-2 PostgresBackend SQL exactly.

      mem-004: id is INTEGER with CHECK (id = 1), not UUID. UUID PK with
      default=uuid4 creates a new row on every INSERT, making the staleness
      check non-deterministic. The singleton sentinel guarantees one row always.
      """

      __tablename__ = "capability_gate_sync"

      # Singleton sentinel: id is always 1. No UUID.
      id: Mapped[int] = mapped_column(Integer(), primary_key=True, default=1)
      # NULL before first sync (before 'alfred plugin grant init' is run).
      # spec §15.4 step 2 seeds this with the empty-commit hash on init.
      commit_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
      synced_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

      __table_args__ = (
          CheckConstraint("id = 1", name="ck_capability_gate_sync_singleton"),
      )
  ```

  Run and confirm PASS:

  ```bash
  uv run pytest tests/integration/test_migrations_0007_0009.py tests/integration/test_capability_gate_seed.py -q 2>&1 | tail -5
  # Expected: all passed
  ```

  Type check:

  ```bash
  uv run mypy src/alfred/memory/models.py --strict 2>&1 | tail -5
  # Expected: Success: no issues found
  ```

  Commit:

  ```bash
  git add src/alfred/memory/migrations/versions/0009_capability_gate_sync.py \
          src/alfred/memory/models.py \
          tests/integration/test_migrations_0007_0009.py \
          tests/integration/test_capability_gate_seed.py
  git commit -m "feat(migrations): add capability_gate_sync table + CapabilityGateSync model (#TBD-slice3)"
  ```

- [ ] **Task 7 — Verify migration chain is contiguous (head = 0009).**

  ```bash
  uv run alembic history --verbose 2>&1 | grep -E "^[0-9]" | head -10
  # Expected: 0009 -> (head), 0008 -> 0009, 0007 -> 0008, 0006 -> 0007, ...

  uv run alembic check 2>&1 | tail -5
  # Expected: "No new upgrade operations detected." (confirming models match migrations)
  ```

  If any drift: fix models to match migration DDL. Commit the fix with `git commit --fixup=<previous-task-sha>`.

### Component D: Docker infrastructure

- [ ] **Task 8 — Write failing test for alfred-redis service healthcheck.**

  Files: Create `tests/integration/test_redis_compose_service.py`.

  ```python
  # tests/integration/test_redis_compose_service.py
  """Smoke test: alfred-redis service is reachable and honours key patterns.

  Runs against a Redis instance started via testcontainers (not the full
  docker-compose stack) to keep CI fast. Tests key patterns from spec §7.7
  (alfred:rate:*, alfred:fetch_budget:*, alfred:content:*, alfred:robots:*)
  and the volatile-lru maxmemory-policy setting.
  """
  from __future__ import annotations

  import datetime as dt
  import uuid

  import pytest
  import redis.asyncio as aioredis
  from testcontainers.redis import RedisContainer


  @pytest.fixture(scope="module")
  def redis_url() -> str:
      with RedisContainer("redis:7") as r:
          yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


  @pytest.fixture(scope="module")
  async def redis_client(redis_url: str) -> aioredis.Redis:
      client = aioredis.from_url(redis_url)
      yield client
      await client.aclose()


  @pytest.mark.asyncio
  async def test_redis_ping(redis_client: aioredis.Redis) -> None:
      """Redis responds to PING."""
      result = await redis_client.ping()
      assert result is True


  @pytest.mark.asyncio
  async def test_rate_key_pattern(redis_client: aioredis.Redis) -> None:
      """alfred:rate:{domain} keys can be set and expire."""
      key = "alfred:rate:example.com"
      await redis_client.set(key, 5, ex=60)
      val = await redis_client.get(key)
      assert int(val) == 5
      ttl = await redis_client.ttl(key)
      assert 0 < ttl <= 60


  @pytest.mark.asyncio
  async def test_rate_user_key_pattern(redis_client: aioredis.Redis) -> None:
      """alfred:rate:user:{user_id} keys can be set and expire."""
      key = "alfred:rate:user:user-abc-123"
      await redis_client.set(key, 3, ex=60)
      val = await redis_client.get(key)
      assert int(val) == 3


  @pytest.mark.asyncio
  async def test_fetch_budget_key_pattern(redis_client: aioredis.Redis) -> None:
      """alfred:fetch_budget:{user_id}:{YYYY-MM-DD} keys with TTL=48h."""
      today = dt.date.today().isoformat()
      key = f"alfred:fetch_budget:user-abc-123:{today}"
      await redis_client.set(key, 42, ex=172800)  # 48h
      val = await redis_client.get(key)
      assert int(val) == 42
      ttl = await redis_client.ttl(key)
      assert 0 < ttl <= 172800


  @pytest.mark.asyncio
  async def test_content_handle_key_pattern(redis_client: aioredis.Redis) -> None:
      """alfred:content:{handle_id} keys hold T3 content with bounded TTL."""
      handle_id = str(uuid.uuid4())
      key = f"alfred:content:{handle_id}"
      await redis_client.set(key, b"<html>test content</html>", ex=80)
      val = await redis_client.get(key)
      assert val == b"<html>test content</html>"
      ttl = await redis_client.ttl(key)
      assert 0 < ttl <= 80


  @pytest.mark.asyncio
  async def test_robots_key_pattern(redis_client: aioredis.Redis) -> None:
      """alfred:robots:{domain} keys with TTL=24h."""
      key = "alfred:robots:example.com"
      await redis_client.set(key, "User-agent: *\nDisallow: /admin/", ex=86400)
      ttl = await redis_client.ttl(key)
      assert 0 < ttl <= 86400


  @pytest.mark.asyncio
  async def test_content_handle_single_use_delete(
      redis_client: aioredis.Redis,
  ) -> None:
      """GETDEL on a content handle key enforces the single-extract invariant.

      devops-005: the single-extract-per-handle invariant (spec §7.2) requires
      ATOMIC get + delete. A pipeline batches round-trips but is NOT atomic
      (another client can read between GET and DEL). Use GETDEL (Redis 6.2+)
      which is truly atomic. PR-S3-5 ContentStore.pop() must use GETDEL.
      This test pins the production primitive so PR-S3-5 cannot drift to
      a pipeline-based approach.
      """
      handle_id = str(uuid.uuid4())
      key = f"alfred:content:{handle_id}"
      await redis_client.set(key, b"test body", ex=80)
      # GETDEL atomically fetches and deletes the key (spec §7.2)
      body = await redis_client.getdel(key)
      assert body == b"test body"
      # Second GETDEL returns None — single-use invariant enforced
      second = await redis_client.getdel(key)
      assert second is None


  # perf-006: ContentStore lifecycle documentation for PR-S3-5.
  # ContentStore must be constructed ONCE at plugin startup with a shared
  # aioredis.ConnectionPool (decode_responses=False), not rebuilt per-request.
  # Per-request construction opens a new TCP+Redis handshake (1-3ms localhost;
  # 10-30ms network) and exhausts the pool under concurrency. The pool is
  # shared with the RateLimiter (one Redis client per plugin process).
  # PR-S3-5 must implement:
  #   pool = aioredis.ConnectionPool.from_url(redis_url, decode_responses=False)
  #   store = ContentStore(pool=pool)  # long-lived singleton
  # The test below documents this requirement:

  @pytest.mark.asyncio
  async def test_content_store_connection_pool_reuse(
      redis_url: str,
  ) -> None:
      """A shared connection pool supports N sequential operations without new connections.

      perf-006: verifies the ConnectionPool lifecycle contract. 10 sequential
      operations on a shared pool must succeed and must not open more than 1
      connection (asserted via INFO clients).
      """
      pool = aioredis.ConnectionPool.from_url(redis_url, decode_responses=False)
      client = aioredis.Redis(connection_pool=pool)
      try:
          for i in range(10):
              key = f"alfred:content:pool-test-{i}"
              await client.set(key, b"body", ex=5)
              body = await client.getdel(key)
              assert body == b"body"
          # Pool should have at most 1 connection open (sequential ops)
          info = await client.info("clients")
          assert info["connected_clients"] <= 2  # pool + info query
      finally:
          await client.aclose()
          await pool.disconnect()
  ```

  Run and confirm it FAILS (no redis dep yet or test structure):

  ```bash
  uv run pytest tests/integration/test_redis_compose_service.py -x -q 2>&1 | tail -5
  # May fail on import (no redis[asyncio] dep) or on container start — record error shape
  ```

- [ ] **Task 9 — Add redis asyncio dependency and update Dockerfile.**

  Files: Modify `docker/alfred-core.Dockerfile`, check `pyproject.toml` for `redis` dep.

  Check existing deps:

  ```bash
  grep -i redis <repo-root>/pyproject.toml
  # If not present, add redis[asyncio]>=5 to dependencies
  ```

  If redis is not listed, add it:

  ```bash
  cd <repo-root>
  uv add "redis[asyncio]>=5"
  ```

  Modify `docker/alfred-core.Dockerfile` runtime stage — add git + alfred-quarantine user + copy bin/:

  The modified runtime stage (replace the existing `RUN groupadd --system alfred` block and everything below it through `USER alfred`):

  ```dockerfile
  FROM python:3.12-slim AS runtime
  ENV PYTHONUNBUFFERED=1 \
      PATH="/app/.venv/bin:${PATH}"

  # Install git + util-linux.
  # git: required for state.git operations (spec §8.1, §11.1).
  # util-linux: provides 'runuser' — required by alfred-plugin-launcher for
  # UID-drop to alfred-quarantine at subprocess spawn (spec §5.2, sec-003).
  # Without runuser, the launcher cannot drop privileges and the isolation
  # guarantee collapses.
  RUN apt-get update -qq \
      && apt-get install -y --no-install-recommends git util-linux \
      && rm -rf /var/lib/apt/lists/*

  # Non-root runtime user. /var/lib/alfred is owned by alfred:alfred.
  # alfred-quarantine is the dedicated UID for quarantined-LLM subprocess
  # isolation (spec §5.2). It has no home dir and cannot read alfred's
  # secrets file (OS-level enforcement of the secrets boundary).
  # devops-008: --user-group creates a dedicated GID for alfred-quarantine
  # (separate from any default group) so the OS-level secret-file ownership
  # boundary is enforceable: alfred's secret files owned alfred:alfred are
  # not readable by the alfred-quarantine GID.
  RUN groupadd --system alfred \
      && useradd --system --gid alfred --create-home --home-dir /home/alfred alfred \
      && useradd --system --no-create-home --user-group alfred-quarantine \
      && mkdir -p /var/lib/alfred \
      && chown -R alfred:alfred /var/lib/alfred

  WORKDIR /app
  COPY --from=builder /app /app
  COPY alembic.ini ./alembic.ini
  COPY config ./config
  COPY locale ./locale
  # bin/ contains alfred-plugin-launcher (stub shipped in PR-S3-3a) and
  # alfred-setup scripts. Copied here so the launcher is on $PATH inside
  # the container.
  COPY bin ./bin

  RUN chown -R alfred:alfred /app
  USER alfred
  ```

  Run the Dockerfile syntax check:

  ```bash
  docker build --no-cache -f docker/alfred-core.Dockerfile . -t alfred-test-0b 2>&1 | tail -10
  # Expected: Successfully built <hash>
  # If git install or useradd fails, fix and retry.
  ```

  Confirm alfred-quarantine user exists in image:

  ```bash
  docker run --rm alfred-test-0b id alfred-quarantine 2>&1 | head -3
  # Expected: uid=NNN(alfred-quarantine) gid=NNN ...
  # (runs as alfred user by default; use --user root to check)
  docker run --rm --user root alfred-test-0b id alfred-quarantine 2>&1 | head -3
  ```

  Run redis tests:

  ```bash
  uv run pytest tests/integration/test_redis_compose_service.py -q 2>&1 | tail -5
  # Expected: 7 passed
  ```

  Commit:

  ```bash
  git add docker/alfred-core.Dockerfile pyproject.toml uv.lock \
          tests/integration/test_redis_compose_service.py
  git commit -m "feat(docker): add git + alfred-quarantine UID to alfred-core image (#TBD-slice3)"
  ```

- [ ] **Task 10 — Update docker-compose.yaml: alfred-redis service + alfred_state_git volume.**

  Files: Modify `docker-compose.yaml`.

  Write the complete updated `docker-compose.yaml`. Key additions:
  - `alfred-redis` service (Redis 7, internal-only, `volatile-lru`, AOF persistence, healthcheck)
  - `alfred_state_git` named volume mounted at `/var/lib/alfred` on `alfred-core`
  - `alfred-core` gains `depends_on: alfred-redis`, `ALFRED_REDIS_URL` env var, `cap_add: [SETUID]`
  - `alfred-discord` must NOT have `cap_add: SETUID` (would allow UID-drop attacks in that service)

  Read the current `docker-compose.yaml` to preserve exact existing content, then add:

  Add to `services:` section (before `volumes:`):

  ```yaml
    # alfred-redis — rate-limit counters, ContentHandle store, robots cache.
    # Internal-only: no host port exposed (spec §7.7). volatile-lru evicts
    # TTL-bearing keys under memory pressure when maxmemory is reached.
    # devops-002: maxmemory MUST be set — without it, volatile-lru never triggers
    # (eviction only kicks in at the memory ceiling). Default 256 MB; override
    # with ALFRED_REDIS_MAXMEMORY env var for larger deployments.
    # devops-007: appendfsync everysec means up to 1s of budget-counter data can
    # be lost on crash. This is the accepted trade-off for AlfredOS's low write
    # rate — budget bypass from a 1s gap is an acceptable risk vs. the performance
    # cost of appendfsync always. Document this in the operator runbook.
    alfred-redis:
      image: redis:7
      restart: unless-stopped
      command: >
        redis-server
        --maxmemory ${ALFRED_REDIS_MAXMEMORY:-256mb}
        --maxmemory-policy volatile-lru
        --appendonly yes
        --appendfsync everysec
      healthcheck:
        test: ["CMD", "redis-cli", "ping"]
        interval: 5s
        timeout: 5s
        retries: 10
      volumes:
        - alfred_redis_data:/data
  ```

  Update `alfred-core` service to add (merging into existing block):

  ```yaml
    alfred-core:
      # ... existing fields preserved ...
      depends_on:
        alfred-postgres:
          condition: service_healthy
        alfred-redis:
          condition: service_healthy
      cap_add:
        - SETUID  # required for alfred-plugin-launcher setuid bit (spec §5.2)
      environment:
        # ... existing env vars preserved ...
        ALFRED_REDIS_URL: ${ALFRED_REDIS_URL:-redis://alfred-redis:6379/0}
      volumes:
        - alfred_state_git:/var/lib/alfred
  ```

  Update `volumes:` block:

  ```yaml
  volumes:
    alfred_pg_data:
    alfred_redis_data:
    alfred_state_git:
  ```

  Note: `alfred-discord` service must NOT get `cap_add: SETUID` or the `alfred_state_git` volume. It does not run the plugin host.

  Verify compose file is valid:

  ```bash
  docker compose config --quiet 2>&1 | tail -5
  # Expected: no output (clean validation) or "x services" line
  ```

  Commit:

  ```bash
  git add docker-compose.yaml
  git commit -m "feat(compose): add alfred-redis service + alfred_state_git volume (#TBD-slice3)"
  ```

- [ ] **Task 10a — Add compose invariant unit test (devops-010).**

  Files: Create `tests/unit/test_compose_invariants.py`.

  This test pins two load-bearing compose invariants the plan introduces, so
  that a future edit cannot accidentally grant `SETUID` to `alfred-discord`
  or give it access to the state.git volume. `docker compose config --quiet`
  only checks YAML validity — it does not assert these security properties.

  ```python
  # tests/unit/test_compose_invariants.py
  """Invariant assertions for docker-compose.yaml security properties.

  devops-010: pins that alfred-discord never gets SETUID or alfred_state_git,
  and that alfred-core always has both. These invariants are load-bearing:
  - SETUID in alfred-discord would allow the Discord adapter to impersonate
    alfred-quarantine, bypassing the process-boundary isolation (spec §5.2).
  - alfred_state_git in alfred-discord would expose state.git grant files to
    the comms adapter, widening the trust surface.
  """
  from __future__ import annotations

  from pathlib import Path

  import pytest
  import yaml


  COMPOSE_PATH = Path(__file__).parent.parent.parent / "docker-compose.yaml"


  @pytest.fixture(scope="module")
  def compose() -> dict:
      return yaml.safe_load(COMPOSE_PATH.read_text())


  def test_alfred_discord_has_no_setuid(compose: dict) -> None:
      """alfred-discord must NOT have cap_add: SETUID (spec §5.2)."""
      discord = compose.get("services", {}).get("alfred-discord", {})
      cap_add = discord.get("cap_add", []) or []
      assert "SETUID" not in cap_add, (
          "alfred-discord must not have SETUID capability — "
          "this would allow it to impersonate alfred-quarantine."
      )


  def test_alfred_discord_has_no_state_git_volume(compose: dict) -> None:
      """alfred-discord must NOT have alfred_state_git volume mounted."""
      discord = compose.get("services", {}).get("alfred-discord", {})
      volumes = discord.get("volumes", []) or []
      volume_strings = [v if isinstance(v, str) else v.get("source", "") for v in volumes]
      assert not any("alfred_state_git" in v for v in volume_strings), (
          "alfred-discord must not have the alfred_state_git volume — "
          "this would expose state.git grant files to the comms adapter."
      )


  def test_alfred_core_has_setuid(compose: dict) -> None:
      """alfred-core must have cap_add: SETUID for plugin-launcher setuid bit (spec §5.2)."""
      core = compose.get("services", {}).get("alfred-core", {})
      cap_add = core.get("cap_add", []) or []
      assert "SETUID" in cap_add, (
          "alfred-core requires SETUID capability for alfred-plugin-launcher "
          "to perform UID-drop to alfred-quarantine (spec §5.2)."
      )


  def test_alfred_core_has_state_git_volume(compose: dict) -> None:
      """alfred-core must have alfred_state_git volume mounted at /var/lib/alfred."""
      core = compose.get("services", {}).get("alfred-core", {})
      volumes = core.get("volumes", []) or []
      volume_strings = [v if isinstance(v, str) else f"{v.get('source', '')}:{v.get('target', '')}" for v in volumes]
      assert any("alfred_state_git" in v for v in volume_strings), (
          "alfred-core requires the alfred_state_git volume for state.git operations."
      )


  def test_alfred_redis_has_maxmemory(compose: dict) -> None:
      """alfred-redis command must include --maxmemory (devops-002).

      Without maxmemory, volatile-lru eviction never triggers — Redis grows
      unbounded and OOMs under load.
      """
      redis_svc = compose.get("services", {}).get("alfred-redis", {})
      command = redis_svc.get("command", "") or ""
      assert "--maxmemory" in command, (
          "alfred-redis must have --maxmemory set for volatile-lru eviction "
          "to trigger. Without it, Redis grows unbounded (devops-002)."
      )
  ```

  Run and confirm PASS (the compose file must have been edited in Task 10 first):

  ```bash
  uv run pytest tests/unit/test_compose_invariants.py -q 2>&1 | tail -5
  # Expected: 5 passed
  ```

  Commit:

  ```bash
  git add tests/unit/test_compose_invariants.py
  git commit -m "test(compose): add invariant assertions for SETUID/volume/maxmemory properties (#TBD-slice3)"
  ```

### Component E: state.git infra + alfred-setup.sh

- [ ] **Task 11 — Write failing test for state.git init.**

  Files: Create `tests/integration/test_state_git_init.py`.

  ```python
  # tests/integration/test_state_git_init.py
  """Integration test: state.git idempotent init and main-branch seeding.

  Tests the 'git init --bare' step added to bin/alfred-setup.sh (spec §15.4
  step 2, spec §8.1). Runs against the local filesystem using a tmp_path
  so it does not require a running container.
  """
  from __future__ import annotations

  import subprocess
  from pathlib import Path


  def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
      return subprocess.run(
          args,
          cwd=cwd,
          capture_output=True,
          text=True,
          check=True,
      )


  def test_git_init_bare_creates_state_git(tmp_path: Path) -> None:
      """git init --bare creates a valid bare repository."""
      state_git = tmp_path / "state.git"
      _run(["git", "init", "--bare", str(state_git)])
      assert state_git.is_dir()
      assert (state_git / "HEAD").exists()
      assert (state_git / "config").exists()
      assert (state_git / "objects").is_dir()


  def test_git_init_bare_is_idempotent(tmp_path: Path) -> None:
      """Re-running git init --bare on an existing bare repo is a no-op."""
      state_git = tmp_path / "state.git"
      _run(["git", "init", "--bare", str(state_git)])
      # Second run must not raise
      _run(["git", "init", "--bare", str(state_git)])
      assert (state_git / "HEAD").exists()


  def test_seed_main_branch(tmp_path: Path) -> None:
      """After git init --bare, seeding a main branch with an empty commit succeeds."""
      state_git = tmp_path / "state.git"
      work_dir = tmp_path / "work"
      work_dir.mkdir()

      _run(["git", "init", "--bare", str(state_git)])

      # Clone the bare repo, add an empty commit, push to main
      _run(["git", "clone", str(state_git), str(work_dir / "clone")])
      clone_dir = work_dir / "clone"
      _run(["git", "-C", str(clone_dir), "config", "user.email", "test@example.com"])
      _run(["git", "-C", str(clone_dir), "config", "user.name", "Test"])
      _run(["git", "-C", str(clone_dir), "commit", "--allow-empty", "-m", "Initial empty commit"])
      _run(["git", "-C", str(clone_dir), "push", "origin", "HEAD:main"])

      # Verify main branch exists in bare repo
      result = _run(["git", "-C", str(state_git), "branch", "-l"])
      assert "main" in result.stdout


  def test_seed_main_branch_is_idempotent(tmp_path: Path) -> None:
      """Seeding main twice does not fail (idempotent if branch already exists)."""
      state_git = tmp_path / "state.git"
      work_dir = tmp_path / "work"
      work_dir.mkdir()

      _run(["git", "init", "--bare", str(state_git)])
      clone_dir = work_dir / "clone"
      _run(["git", "clone", str(state_git), str(clone_dir)])
      _run(["git", "-C", str(clone_dir), "config", "user.email", "test@example.com"])
      _run(["git", "-C", str(clone_dir), "config", "user.name", "Test"])
      _run(["git", "-C", str(clone_dir), "commit", "--allow-empty", "-m", "Initial empty commit"])
      _run(["git", "-C", str(clone_dir), "push", "origin", "HEAD:main"])

      # Re-run push to main (already-up-to-date path)
      _run(["git", "-C", str(clone_dir), "commit", "--allow-empty", "-m", "Second empty commit"])
      _run(["git", "-C", str(clone_dir), "push", "origin", "HEAD:main"])

      result = _run(["git", "-C", str(state_git), "log", "--oneline", "main"])
      assert "Second empty commit" in result.stdout
  ```

  Run and confirm tests PASS (they test git behaviour, not the setup script yet):

  ```bash
  uv run pytest tests/integration/test_state_git_init.py -q 2>&1 | tail -5
  # Expected: 4 passed (pure git subprocess tests, no script dependency)
  ```

- [ ] **Task 12 — Add state.git seed script + update bin/alfred-setup.sh.**

  Files:
  - Create `bin/alfred-state-git-seed.sh` (dedicated script — devops-009)
  - Modify `bin/alfred-setup.sh`

  **devops-001**: `alfred-core` declares `ENTRYPOINT ["alfred"]`, so
  `docker compose run --rm alfred-core sh -c "..."` becomes `alfred sh -c "..."` —
  an invalid alfred subcommand. Fix: pass `--entrypoint /bin/sh` and invoke the
  dedicated seed script. Using a separate script file (devops-009) also eliminates
  the fragile triple-nested escaping.

  Create `bin/alfred-state-git-seed.sh`:

  ```bash
  #!/usr/bin/env sh
  # bin/alfred-state-git-seed.sh — idempotent state.git init + main-branch seeding.
  #
  # Called by bin/alfred-setup.sh via:
  #   docker compose run --rm --entrypoint /bin/sh alfred-core /app/bin/alfred-state-git-seed.sh
  #
  # devops-001: invoked with --entrypoint /bin/sh to bypass the 'alfred' ENTRYPOINT.
  # devops-009: separate script avoids triple-nested shell escaping in setup.sh.
  #
  # alfred plugin grant init requires state.git to exist and have a seeded
  # main branch. Without this, every plugin load fails with the message
  # returned by t("bootstrap.capability_gate_unseeded") (spec §15.4 step 2).
  # Safe to re-run: git init --bare is a no-op on an existing bare repo.
  set -euo pipefail

  STATE_GIT_PATH="${STATE_GIT_PATH:-/var/lib/alfred/state.git}"

  if [ ! -d "${STATE_GIT_PATH}" ]; then
    git init --bare "${STATE_GIT_PATH}"
    echo "Initialised bare state.git at ${STATE_GIT_PATH}."
  else
    echo "state.git already exists; skipping init."
  fi

  # Seed main branch if not present
  if ! git -C "${STATE_GIT_PATH}" rev-parse --verify refs/heads/main >/dev/null 2>&1; then
    WORK=$(mktemp -d)
    git clone "${STATE_GIT_PATH}" "${WORK}/clone"
    git -C "${WORK}/clone" config user.email 'alfred-setup@localhost'
    git -C "${WORK}/clone" config user.name 'alfred-setup'
    git -C "${WORK}/clone" commit --allow-empty -m 'Initial empty commit (alfred-setup)'
    git -C "${WORK}/clone" push origin HEAD:main
    rm -rf "${WORK}"
    echo "Seeded main branch in state.git."
  else
    echo "main branch already exists in state.git; skipping seed."
  fi
  ```

  Make it executable:

  ```bash
  chmod +x bin/alfred-state-git-seed.sh
  ```

  Insert the following step in `bin/alfred-setup.sh` after the "Running migrations" block and before "Priming secrets bind-mount":

  ```bash
  step "Seeding state.git (idempotent)"
  # devops-001: --entrypoint /bin/sh bypasses 'alfred' ENTRYPOINT so we can
  # run the seed script directly. 'alfred sh -c "..."' is not a valid alfred
  # subcommand.
  docker compose run --rm --entrypoint /bin/sh alfred-core /app/bin/alfred-state-git-seed.sh
  ```

  Validate both scripts are valid bash/sh:

  ```bash
  bash -n bin/alfred-setup.sh && echo "setup.sh: Syntax OK"
  sh -n bin/alfred-state-git-seed.sh && echo "state-git-seed.sh: Syntax OK"
  ```

  Commit:

  ```bash
  git add bin/alfred-setup.sh bin/alfred-state-git-seed.sh \
          tests/integration/test_state_git_init.py
  git commit -m "feat(infra): add idempotent state.git seed script + alfred-setup.sh step (#TBD-slice3)"
  ```

### Component F: Config schema additions

- [ ] **Task 13 — Create config/routing.yaml with [quarantine] block.**

  Files: Create `config/routing.yaml`.

  ```yaml
  # config/routing.yaml — AlfredOS provider routing configuration.
  #
  # This file configures the privileged and quarantined LLM providers.
  # The [quarantine] block is gated: changes to 'provider' and 'secret_id'
  # go through the state.git reviewer-gate (high-blast, spec §11.1).
  # Use 'alfred config quarantined-provider <provider>' to propose a change.
  #
  # Downstream consumer: QuarantinedExtractor (PR-S3-4) reads
  # routing.yaml[quarantine] at construction; the manifest's declared
  # provider must match or the plugin receives plugin.load_refused at handshake
  # (spec §5.4, index plan §3 cross-PR contract).

  # Primary (privileged) provider — governed by config/alfred.toml [provider].
  # Repeated here for documentation; alfred.toml is the authoritative source.
  # primary_provider: "deepseek"  # informational only; set in alfred.toml

  quarantine:
    # Provider for the quarantined LLM — MUST differ from the privileged
    # provider by default (defence-in-depth, spec §5.4, PRD §6.4).
    # If privileged uses deepseek, quarantined uses anthropic (and vice versa).
    # Changing this field requires 'alfred config quarantined-provider <provider>'
    # + state.git reviewer-gate approval (spec §11.1).
    provider: "anthropic"

    # Model identifier for the quarantined LLM.
    # Haiku is the default: fast, cheap, adequate for structured extraction.
    model: "claude-haiku-3-5"

    # Secret broker ID for the quarantined provider API key.
    # The SecretBroker resolves this before subprocess spawn via fd-3 handshake
    # (spec §5.3). The literal API key never appears here.
    secret_id: "quarantine_provider_api_key"
  ```

  Verify the YAML is well-formed:

  ```bash
  python3 -c "import yaml; yaml.safe_load(open('config/routing.yaml'))" && echo "YAML OK"
  # Expected: YAML OK
  ```

  Commit:

  ```bash
  git add config/routing.yaml
  git commit -m "feat(config): add config/routing.yaml with [quarantine] block schema (#TBD-slice3)"
  ```

- [ ] **Task 14 — Create config/policies.yaml with low-blast knobs.**

  Files: Create `config/policies.yaml`.

  Per spec §11.2, the low-blast knobs do not require reviewer-gate approval. This file is hot-reloaded (file-mtime invalidation, spec §7.7).

  ```yaml
  # config/policies.yaml — AlfredOS low-blast operator policy knobs.
  #
  # Changes here take effect on the next hot-reload (file-mtime polling,
  # 1s interval). No restart required. These knobs narrow or tune within
  # the existing trust surface — they cannot widen it. Widening actions
  # (domain allowlist additions, plugin grants, quarantined-provider changes)
  # require state.git reviewer-gate approval (spec §11.1).

  web_fetch:
    # User-Agent header sent with every web.fetch request (spec §16 Fork 4).
    # Default: AlfredOS/<version> — operators may customise but should
    # retain an identifiable UA string.
    user_agent: "AlfredOS/dev"

    # Per-domain rate-limit overrides. Keys are domain names; values are
    # requests/minute (int). Omitting a domain uses the system default (10/min).
    # Example: rate_limits: {api.example.com: 60}
    rate_limits: {}

    # Per-user daily fetch budget. "user" tier = non-operator users.
    # Operator-tier default: unlimited (null). Override per-user with
    # 'alfred config web-fetch-budget <user> <n>' (writes to this file).
    user_daily_budget: 100
    operator_daily_budget: null  # unlimited

    # Per-user concurrent ContentHandle cap (spec §7.7).
    # A sixth web.fetch call from the same user while 5 handles are live
    # receives WebFetchRateLimited.
    max_concurrent_handles_per_user: 5

    # Maximum response body size in bytes (spec §16 Fork 4). Default: 5MB.
    max_response_body_bytes: 5242880

    # TLS verification — ONLY honoured when ALFRED_ENV=development.
    # Production deployments with skip_tls_verify=true emit a loud startup
    # warning + supervisor.config_insecure audit row (spec §7.11).
    skip_tls_verify: false

  quarantine:
    # Maximum retries for prompt-embedded fallback extraction (spec §6.3).
    # After this many failures, QuarantinedExtractor returns TypedRefusal.
    extraction_max_retries: 2

  orchestrator:
    # Per-action deadline in seconds (spec §10.5).
    # asyncio.timeout wraps the entire handle_user_message turn.
    # Configurable here; default 30s matches spec §10.5.
    action_deadline_seconds: 30
  ```

  Verify the YAML is well-formed:

  ```bash
  python3 -c "import yaml; yaml.safe_load(open('config/policies.yaml'))" && echo "YAML OK"
  # Expected: YAML OK
  ```

  Commit:

  ```bash
  git add config/policies.yaml
  git commit -m "feat(config): add config/policies.yaml with low-blast operator knobs (#TBD-slice3)"
  ```

### Component G: i18n catalog additions

- [ ] **Task 15 — Write failing test asserting all Slice-3 keys resolve.**

  Files: Create `tests/unit/test_catalog_slice3_keys.py`.

  ```python
  # tests/unit/test_catalog_slice3_keys.py
  """Assert every new Slice-3 t() key resolves and its placeholders are renderable.

  Two-part test (Cluster 6 / i18n-007):

  1. test_slice3_key_resolves: every key returns a non-empty non-bare string.
     A bare key signals a missing catalog entry. Gates the catalog PR.

  2. test_slice3_key_placeholder_integrity: every key with declared placeholders
     can be rendered with its expected kwargs without raising KeyError. Catches
     catalog/call-site kwarg mismatches (i18n-001 / i18n-002 / devex-004) at
     PR-S3-0b CI rather than at runtime in PR-S3-6.

  i18n-003 note: the test list and the catalog msgid count must agree.
  Current total: 86 keys (82 original + 3 new: plugin.transport.dlp_outbound_refused,
  cli.supervisor.reset.rerun_hint, cli.audit.graph.since_invalid).
  """
  from __future__ import annotations

  import pytest

  from alfred.i18n.translator import t


  # Full list from spec §11.5 + fixup additions.
  # i18n-003: count must match msgid count in Task 16's .po block.
  _SLICE_3_KEYS: list[str] = [
      # CLI navigation / help keys (used as Typer group docstrings)
      "cli.plugin.help",
      "cli.plugin.grant.help",
      "cli.plugin.grant.usage",
      "cli.plugin.grant.follow_up_command",
      "cli.plugin.grant.success",
      "cli.web.help",
      "cli.web.allowlist.help",
      "cli.web.allowlist.add.usage",
      "cli.web.allowlist.add.denied",
      "cli.web.allowlist.remove.denied",
      "cli.config.help",
      "cli.config.set.key_help",
      "cli.config.set.value_help",
      "cli.config.set.denied",
      "cli.config.set.unknown_key",
      "cli.config.get.unknown_key",
      "cli.config.get.not_set",
      "cli.config.list.empty",
      "cli.supervisor.help",
      "cli.supervisor.reset.usage",
      "cli.audit.help",
      "cli.audit.graph.tier_help",
      "cli.audit.graph.since_help",
      "cli.audit.graph.empty",
      "cli.audit.graph.tier_header",
      "cli.audit.graph.header",
      # CLI action keys
      "cli.plugin.grant.pending_review",
      "cli.plugin.grant.denied",
      "cli.plugin.grant.confirm_prompt",
      "cli.plugin.grant.status.pending",
      "cli.plugin.grant.status.approved",
      "cli.plugin.grant.status.denied",
      "cli.plugin.grant.status.expired",
      "cli.web.allowlist.pending_review",
      "cli.web.allowlist.added",
      "cli.web.allowlist.removed",
      "cli.config.quarantined_provider_pending_review",
      "cli.config.web_fetch_budget_set",
      "cli.supervisor.reset.confirm_prompt",
      "cli.supervisor.reset.success",
      "cli.supervisor.reset.component_not_found",
      # devex-004 / i18n-004: rerun hint key (hardcoded English in PR-S3-6 Task N)
      "cli.supervisor.reset.rerun_hint",
      # devex-016: bad --since value error key
      "cli.audit.graph.since_invalid",
      # List/table column keys
      "cli.plugin.list.column.plugin_id",
      "cli.plugin.list.column.subscriber_tier",
      "cli.plugin.list.column.status",
      "cli.plugin.list.column.manifest_version",
      "cli.plugin.list.empty_hint",
      "cli.plugin.show.field.plugin_id",
      "cli.plugin.show.field.manifest_version",
      "cli.plugin.show.field.sandbox_profile",
      "cli.plugin.show.field.hookpoints",
      "cli.plugin.show.field.grants",
      "cli.plugin.show.field.last_lifecycle_event",
      "cli.web.allowlist.list.column.domain",
      "cli.web.allowlist.list.column.path_prefix",
      "cli.web.allowlist.list.column.granted_by",
      "cli.web.allowlist.list.column.granted_at",
      "cli.web.allowlist.list_empty",
      "cli.supervisor.status.column.component",
      "cli.supervisor.status.column.state",
      "cli.supervisor.status.column.trip_count",
      "cli.supervisor.status.column.last_trip_at",
      "cli.supervisor.status.empty_hint",
      "cli.supervisor.status.breaker_state.open",
      "cli.supervisor.status.breaker_state.closed",
      "cli.supervisor.status.breaker_state.half_open",
      # WebFetchError message keys
      "web.fetch.error.domain_not_allowed",
      "web.fetch.error.tls_failure",
      "web.fetch.error.rate_limited",
      "web.fetch.error.mime_type_not_allowed",
      "web.fetch.error.size_limit_exceeded",
      # System / bootstrap keys
      "bootstrap.quarantined_provider_same_as_privileged",
      "orchestrator.quarantine_unavailable",
      "orchestrator.action_timeout",
      "security.tag_t3_unauthorized",  # i18n-003: was missing from original list
      "security.tier_mismatch",
      "security.canary_tripped",
      "capability_gate.unavailable",
      "plugin.manifest_version_mismatch",
      "plugin.launcher_no_sandbox_policy",
      "plugin.grant_prompt",
      # Cluster 1: DLP outbound refused key (PR-S3-3a StdioTransport rewrite)
      "plugin.transport.dlp_outbound_refused",
      "quarantine.schema_version_missing",
      "bootstrap.capability_gate_unseeded",
  ]

  # Cluster 6 / i18n-007: placeholder-integrity mapping.
  # Keys that have placeholders declare the minimum required kwargs here.
  # test_slice3_key_placeholder_integrity renders t(key, **kwargs) and asserts:
  # (a) no KeyError raised, (b) rendered string differs from msgstr-without-subs.
  # Kwargs are drawn from the call-sites planned in S3-1 .. S3-6.
  # i18n-001: cli.config.web_fetch_budget_set uses {user} + {n} (not {key}/{value})
  # i18n-002: cli.plugin.grant.pending_review uses {branch} + {proposal_id}
  # devex-004: cli.supervisor.reset.confirm_prompt uses {component},{trip_count},{last_trip_at}
  _KEY_REQUIRED_PLACEHOLDERS: dict[str, dict[str, object]] = {
      "cli.plugin.grant.follow_up_command": {"proposal_id": "prop-abc123"},
      "cli.plugin.grant.success": {"plugin_id": "alfred.web-fetch", "hookpoint": "tool.web.fetch"},
      "cli.web.allowlist.add.denied": {"reason": "quota exceeded"},
      "cli.web.allowlist.remove.denied": {"reason": "quota exceeded"},
      "cli.config.set.denied": {"reason": "high-blast change requires reviewer gate"},
      "cli.config.set.unknown_key": {"key": "web_fetch.unknown_field"},
      "cli.config.get.unknown_key": {"key": "web_fetch.unknown_field"},
      "cli.config.get.not_set": {"key": "web_fetch.user_agent"},
      "cli.audit.graph.empty": {"tier": "T3", "since": "24h"},
      "cli.audit.graph.tier_header": {"tier": "T3"},
      # i18n-002: caller sends branch= + proposal_id=
      "cli.plugin.grant.pending_review": {"branch": "proposal/abc123", "proposal_id": "prop-xyz"},
      "cli.plugin.grant.denied": {"plugin_id": "alfred.web-fetch", "hookpoint": "tool.web.fetch", "reason": "not approved"},
      "cli.plugin.grant.confirm_prompt": {
          "plugin_id": "alfred.web-fetch",
          "hookpoint": "tool.web.fetch",
          "tier": "operator",
          "blast_radius": "read-only web access",
      },
      # i18n-002: caller sends proposal_id=
      "cli.plugin.grant.status.pending": {"proposal_id": "prop-abc123"},
      "cli.plugin.grant.status.approved": {"commit_hash": "abc123def"},
      "cli.plugin.grant.status.denied": {"reason": "policy violation"},
      "cli.web.allowlist.pending_review": {"proposal_branch": "proposal/allow-abc", "proposal_id": "prop-xyz"},
      "cli.web.allowlist.added": {"domain": "example.com"},
      "cli.web.allowlist.removed": {"domain": "example.com"},
      "cli.config.quarantined_provider_pending_review": {"provider": "deepseek", "proposal_branch": "proposal/qprov-abc"},
      # i18n-001: caller sends user= + n= (not key=/value=)
      "cli.config.web_fetch_budget_set": {"user": "alice", "n": 50},
      # devex-004: caller sends component= + trip_count= + last_trip_at=
      "cli.supervisor.reset.confirm_prompt": {"component": "quarantined-llm", "trip_count": 3, "last_trip_at": "2026-05-31T00:00:00Z"},
      "cli.supervisor.reset.success": {"component": "quarantined-llm"},
      "cli.supervisor.reset.component_not_found": {"component": "quarantined-llm"},
      # devex-004 / i18n-004
      "cli.supervisor.reset.rerun_hint": {"component": "quarantined-llm"},
      # devex-016
      "cli.audit.graph.since_invalid": {"value": "7day", "example": "24h, 7d, or 90m"},
      "web.fetch.error.domain_not_allowed": {"domain": "blocked.example.com"},
      "web.fetch.error.tls_failure": {"url": "https://example.com"},
      "web.fetch.error.rate_limited": {"limit": "10/min", "scope": "domain", "retry_after": 30},
      "web.fetch.error.mime_type_not_allowed": {"mime_type": "application/pdf"},
      "web.fetch.error.size_limit_exceeded": {"size": 6291456, "limit": 5242880},
      "security.tag_t3_unauthorized": {"caller_id": "rogue-module"},
      "security.tier_mismatch": {"wire_tier": "T2", "expected_tier": "T3Content"},
      "security.canary_tripped": {"url": "https://attacker.example.com"},
      "plugin.manifest_version_mismatch": {"got": 2, "expected": 1},
      "plugin.launcher_no_sandbox_policy": {"plugin_id": "alfred.custom-plugin"},
      "plugin.grant_prompt": {"plugin_id": "alfred.web-fetch", "tier": "operator", "hookpoint": "tool.web.fetch", "blast_radius": "read-only web"},
      # Cluster 1: DLP outbound refused
      "plugin.transport.dlp_outbound_refused": {"plugin_id": "alfred.web-fetch"},
      "quarantine.schema_version_missing": {"schema_name": "MyExtractionSchema"},
      "bootstrap.capability_gate_unseeded": {},
      "bootstrap.quarantined_provider_same_as_privileged": {},
  }


  @pytest.mark.parametrize("key", _SLICE_3_KEYS)
  def test_slice3_key_resolves(key: str) -> None:
      """t(key) returns a non-empty string that is not the bare key."""
      result = t(key)
      assert isinstance(result, str), f"t({key!r}) did not return str"
      assert result, f"t({key!r}) returned empty string"
      assert result != key, (
          f"t({key!r}) returned the bare key — "
          f"entry is missing from locale/en/LC_MESSAGES/alfred.po. "
          f"Add the entry and run pybabel extract + compile."
      )


  @pytest.mark.parametrize(
      "key,kwargs",
      [
          (key, kwargs)
          for key, kwargs in _KEY_REQUIRED_PLACEHOLDERS.items()
      ],
  )
  def test_slice3_key_placeholder_integrity(key: str, kwargs: dict) -> None:
      """t(key, **kwargs) renders without KeyError and substitutes placeholder values.

      Cluster 6 / i18n-007: catches catalog/call-site kwarg mismatches at CI
      rather than at PR-S3-6 runtime. i18n-001 (cli.config.web_fetch_budget_set
      {user}/{n}), i18n-002 (cli.plugin.grant.pending_review {branch}), devex-004
      (cli.supervisor.reset.confirm_prompt {component}/{trip_count}/{last_trip_at})
      would all raise KeyError without this test.
      """
      try:
          rendered = t(key, **kwargs)
      except KeyError as exc:
          raise AssertionError(
              f"t({key!r}, **{kwargs!r}) raised KeyError({exc}) — "
              f"placeholder mismatch between catalog msgstr and expected kwargs. "
              f"Check locale/en/LC_MESSAGES/alfred.po entry for {key!r}."
          ) from exc
      assert rendered != key, f"t({key!r}) with kwargs still returned bare key"
      # Verify at least one kwarg value appears in the rendered string
      if kwargs:
          any_substituted = any(str(v) in rendered for v in kwargs.values() if v != "")
          assert any_substituted, (
              f"t({key!r}, **{kwargs!r}) = {rendered!r} — "
              f"none of the kwarg values appear in the output. "
              f"Check that the msgstr contains the expected placeholder names."
          )
  ```

  Run and confirm FAIL (keys are not yet in the catalog):

  ```bash
  uv run pytest tests/unit/test_catalog_slice3_keys.py -x -q 2>&1 | tail -10
  # Expected: FAILED — t("cli.plugin.grant.pending_review") returns bare key
  ```

- [ ] **Task 16 — Add all Slice-3 keys to locale/en/LC_MESSAGES/alfred.po.**

  Files: Modify `locale/en/LC_MESSAGES/alfred.po`.

  Append the following block to `alfred.po`. Each entry uses the format established by existing entries — `msgid` is the dotted key, `msgstr` is the canonical English copy. Translators comments are added where placeholder names are ambiguous.

  ```po
  # === Slice 3: CLI navigation / help strings ===
  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.help"
  msgstr "Manage AlfredOS plugins — list, show, and grant capabilities."

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.grant.help"
  msgstr "Manage plugin capability grants."

  #: src/alfred/cli/plugin_cmd.py
  # Translators: CLI argument help text; {plugin_id} is the plugin identifier.
  msgid "cli.plugin.grant.usage"
  msgstr "Plugin identifier (e.g. alfred.web-fetch)"

  #: src/alfred/cli/plugin_cmd.py
  # Translators: {proposal_id} is the proposal ID shown after queuing.
  msgid "cli.plugin.grant.follow_up_command"
  msgstr "Run 'alfred plugin grant status {proposal_id}' to track approval."

  #: src/alfred/cli/plugin_cmd.py
  # Reserved for the reviewer-approved path — not shown when queuing the proposal.
  msgid "cli.plugin.grant.success"
  msgstr "Plugin grant for {plugin_id} on {hookpoint} is now active."

  #: src/alfred/cli/web_cmd.py
  msgid "cli.web.help"
  msgstr "Manage web-fetch settings — allowlist and rate limits."

  #: src/alfred/cli/web_cmd.py
  msgid "cli.web.allowlist.help"
  msgstr "Manage the web-fetch domain allowlist."

  #: src/alfred/cli/web_cmd.py
  # Translators: CLI argument help text.
  msgid "cli.web.allowlist.add.usage"
  msgstr "Domain to add to the allowlist (e.g. example.com)"

  #: src/alfred/cli/web_cmd.py
  # Translators: {reason} is the denial reason.
  msgid "cli.web.allowlist.add.denied"
  msgstr "Allowlist addition denied: {reason}"

  #: src/alfred/cli/web_cmd.py
  # Translators: {reason} is the denial reason.
  msgid "cli.web.allowlist.remove.denied"
  msgstr "Allowlist removal denied: {reason}"

  #: src/alfred/cli/config_cmd.py
  msgid "cli.config.help"
  msgstr "Manage AlfredOS operator configuration."

  #: src/alfred/cli/config_cmd.py
  msgid "cli.config.set.key_help"
  msgstr "Configuration key to set (dotted path, e.g. web_fetch.user_agent)"

  #: src/alfred/cli/config_cmd.py
  msgid "cli.config.set.value_help"
  msgstr "New value for the configuration key"

  #: src/alfred/cli/config_cmd.py
  # Translators: {reason} is the denial reason.
  msgid "cli.config.set.denied"
  msgstr "Configuration change denied: {reason}"

  #: src/alfred/cli/config_cmd.py
  # Translators: {key} is the configuration key.
  msgid "cli.config.set.unknown_key"
  msgstr "Unknown configuration key: {key}. Run 'alfred config list' to see available keys."

  #: src/alfred/cli/config_cmd.py
  # Translators: {key} is the configuration key.
  msgid "cli.config.get.unknown_key"
  msgstr "Unknown configuration key: {key}."

  #: src/alfred/cli/config_cmd.py
  # Translators: {key} is the configuration key.
  msgid "cli.config.get.not_set"
  msgstr "{key} is not set (using default)."

  #: src/alfred/cli/config_cmd.py
  msgid "cli.config.list.empty"
  msgstr "No configuration keys have been overridden. All values are at their defaults."

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.help"
  msgstr "Manage the AlfredOS supervisor — circuit breakers and component status."

  #: src/alfred/cli/supervisor_cmd.py
  # Translators: CLI argument help text; {component} is the supervisor component ID.
  msgid "cli.supervisor.reset.usage"
  msgstr "Supervisor component ID (e.g. quarantined-llm)"

  #: src/alfred/cli/audit_cmd.py
  msgid "cli.audit.help"
  msgstr "Query the AlfredOS audit log."

  #: src/alfred/cli/audit_cmd.py
  # Translators: {tier} is the trust tier filter (T1 or T3).
  msgid "cli.audit.graph.tier_help"
  msgstr "Filter by trust tier (T1 or T3)"

  #: src/alfred/cli/audit_cmd.py
  # Translators: accepts a duration string, e.g. "24h", "7d".
  msgid "cli.audit.graph.since_help"
  msgstr "Show events since this duration ago (e.g. 24h, 7d)"

  #: src/alfred/cli/audit_cmd.py
  # Translators: {tier} is the trust tier; {since} is the duration.
  msgid "cli.audit.graph.empty"
  msgstr "No audit events found for tier {tier} in the last {since}."

  #: src/alfred/cli/audit_cmd.py
  # Translators: {tier} is the trust tier string.
  msgid "cli.audit.graph.tier_header"
  msgstr "Audit graph — tier {tier}"

  #: src/alfred/cli/audit_cmd.py
  msgid "cli.audit.graph.header"
  msgstr "Audit graph"

  # === Slice 3: CLI plugin management ===
  #: src/alfred/cli/plugin_cmd.py
  # Translators: {branch} is the state.git proposal branch; {proposal_id} is the short ID.
  # i18n-002: caller passes branch= (not proposal_branch=) + proposal_id= — match those names.
  msgid "cli.plugin.grant.pending_review"
  msgstr ""
  "Plugin grant proposal queued at {branch}. "
  "Run 'alfred plugin grant status {proposal_id}' to track approval."

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.grant.denied"
  msgstr "Plugin grant denied for {plugin_id} on {hookpoint}: {reason}"

  #: src/alfred/cli/plugin_cmd.py
  # Translators: shown before the operator confirms a grant. {blast_radius} is
  # a human-readable description of what the grant allows.
  msgid "cli.plugin.grant.confirm_prompt"
  msgstr ""
  "Grant {plugin_id} access to {hookpoint} at {tier} tier. "
  "Blast radius: {blast_radius}. Proceed? [y/N]"

  #: src/alfred/cli/plugin_cmd.py
  # Translators: {proposal_id} is the proposal short ID (not branch name).
  # i18n-002: caller passes proposal_id= (not proposal_branch=) — match that name.
  msgid "cli.plugin.grant.status.pending"
  msgstr "Pending review (proposal: {proposal_id})"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.grant.status.approved"
  msgstr "Approved (commit {commit_hash})"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.grant.status.denied"
  msgstr "Denied: {reason}"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.grant.status.expired"
  msgstr "Expired: proposal branch deleted or not merged within TTL"

  # === Slice 3: CLI web allowlist ===
  #: src/alfred/cli/web_cmd.py
  msgid "cli.web.allowlist.pending_review"
  msgstr ""
  "Web allowlist addition queued at {proposal_branch}. "
  "Run 'alfred web allowlist list' to confirm when approved."

  #: src/alfred/cli/web_cmd.py
  msgid "cli.web.allowlist.added"
  msgstr "Domain {domain} added to web fetch allowlist."

  #: src/alfred/cli/web_cmd.py
  msgid "cli.web.allowlist.removed"
  msgstr "Domain {domain} removed from web fetch allowlist."

  # === Slice 3: CLI config ===
  #: src/alfred/cli/config_cmd.py
  msgid "cli.config.quarantined_provider_pending_review"
  msgstr ""
  "Quarantined-provider change to {provider} queued at {proposal_branch}. "
  "Run 'alfred plugin grant status' to track approval."

  #: src/alfred/cli/config_cmd.py
  # Translators: {user} is the canonical user slug; {n} is the new daily limit.
  msgid "cli.config.web_fetch_budget_set"
  msgstr "Daily web-fetch budget for {user} set to {n} fetches/day."

  # === Slice 3: CLI supervisor ===
  #: src/alfred/cli/supervisor_cmd.py
  # Translators: {component} is a supervisor component ID (e.g. "quarantined-llm").
  msgid "cli.supervisor.reset.confirm_prompt"
  msgstr ""
  "Reset circuit breaker for {component}? "
  "({trip_count} trips; last trip at {last_trip_at}) [y/N]"

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.reset.success"
  msgstr "Circuit breaker for {component} reset. Current state: CLOSED."

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.reset.component_not_found"
  msgstr "Component {component} not found. Run 'alfred supervisor status' to list components."

  #: src/alfred/cli/supervisor_cmd.py
  # Translators: {component} is the supervisor component ID. This hint is shown
  # when reset is invoked without --confirm; devex-004 / i18n-004.
  msgid "cli.supervisor.reset.rerun_hint"
  msgstr "Re-run with: alfred supervisor reset {component} --confirm"

  #: src/alfred/cli/audit_cmd.py
  # Translators: {value} is the bad --since value the user typed;
  # {example} gives accepted examples. devex-016.
  msgid "cli.audit.graph.since_invalid"
  msgstr "Invalid --since value: '{value}'. Use a number with a unit, e.g. {example}."

  # === Slice 3: CLI list/table column labels ===
  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.list.column.plugin_id"
  msgstr "Plugin ID"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.list.column.subscriber_tier"
  msgstr "Subscriber Tier"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.list.column.status"
  msgstr "Status"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.list.column.manifest_version"
  msgstr "Manifest Version"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.list.empty_hint"
  msgstr "No plugins loaded. Run 'alfred plugin grant init' to initialise the capability gate."

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.show.field.plugin_id"
  msgstr "Plugin ID"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.show.field.manifest_version"
  msgstr "Manifest Version"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.show.field.sandbox_profile"
  msgstr "Sandbox Profile"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.show.field.hookpoints"
  msgstr "Registered Hookpoints"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.show.field.grants"
  msgstr "Active Grants"

  #: src/alfred/cli/plugin_cmd.py
  msgid "cli.plugin.show.field.last_lifecycle_event"
  msgstr "Last Lifecycle Event"

  #: src/alfred/cli/web_cmd.py
  msgid "cli.web.allowlist.list.column.domain"
  msgstr "Domain"

  #: src/alfred/cli/web_cmd.py
  msgid "cli.web.allowlist.list.column.path_prefix"
  msgstr "Path Prefix"

  #: src/alfred/cli/web_cmd.py
  msgid "cli.web.allowlist.list.column.granted_by"
  msgstr "Granted By"

  #: src/alfred/cli/web_cmd.py
  msgid "cli.web.allowlist.list.column.granted_at"
  msgstr "Granted At"

  #: src/alfred/cli/web_cmd.py
  msgid "cli.web.allowlist.list_empty"
  msgstr "No domains in allowlist. Use 'alfred web allowlist add <domain>' to add one."

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.status.column.component"
  msgstr "Component"

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.status.column.state"
  msgstr "State"

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.status.column.trip_count"
  msgstr "Trip Count"

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.status.column.last_trip_at"
  msgstr "Last Trip At"

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.status.empty_hint"
  msgstr "No supervisor-managed components found."

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.status.breaker_state.open"
  msgstr "OPEN"

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.status.breaker_state.closed"
  msgstr "CLOSED"

  #: src/alfred/cli/supervisor_cmd.py
  msgid "cli.supervisor.status.breaker_state.half_open"
  msgstr "HALF_OPEN"

  # === Slice 3: WebFetchError messages ===
  #: src/alfred/plugins/errors.py
  # Translators: {url} is the URL that was blocked; {domain} is the domain.
  msgid "web.fetch.error.domain_not_allowed"
  msgstr "Domain {domain} is not in the web-fetch allowlist. Ask your operator to add it."

  #: src/alfred/plugins/errors.py
  msgid "web.fetch.error.tls_failure"
  msgstr "TLS verification failed for {url}. The connection cannot be trusted."

  #: src/alfred/plugins/errors.py
  # Translators: {limit} is the rate limit (e.g. "10/min"); {scope} is "domain" or "user".
  msgid "web.fetch.error.rate_limited"
  msgstr "Rate limit exceeded ({limit} per {scope}). Retry in {retry_after}s."

  #: src/alfred/plugins/errors.py
  # Translators: {mime_type} is the MIME type that was refused.
  msgid "web.fetch.error.mime_type_not_allowed"
  msgstr "MIME type {mime_type} is not in the allowed list for web fetch."

  #: src/alfred/plugins/errors.py
  # Translators: {size} is the response body size in bytes; {limit} is the limit.
  msgid "web.fetch.error.size_limit_exceeded"
  msgstr "Response body size {size} bytes exceeds the {limit}-byte limit."

  # === Slice 3: System / bootstrap keys ===
  #: src/alfred/bootstrap/gate_factory.py
  msgid "bootstrap.quarantined_provider_same_as_privileged"
  msgstr ""
  "Quarantined and privileged LLMs are configured to use the same provider. "
  "This weakens defence-in-depth. Run 'alfred config quarantined-provider <provider>' "
  "to set a different provider, or obtain reviewer-gate approval to proceed with "
  "the same provider."

  #: src/alfred/orchestrator/core.py
  msgid "orchestrator.quarantine_unavailable"
  msgstr "I can't process external content right now; please retry in a few minutes."

  #: src/alfred/orchestrator/core.py
  msgid "orchestrator.action_timeout"
  msgstr "This action is taking too long. Please retry — if the problem persists, contact your operator."

  #: src/alfred/security/tiers.py
  # Translators: {caller_id} is the identifier of the caller attempting the tag.
  msgid "security.tag_t3_unauthorized"
  msgstr "Unauthorized attempt to tag content as T3 by {caller_id}."

  #: src/alfred/security/tiers.py
  # Translators: {wire_tier} is the tier string on the wire; {expected_tier} is the expected Python type.
  msgid "security.tier_mismatch"
  msgstr "Trust tier mismatch: wire says {wire_tier} but object is typed as {expected_tier}."

  #: src/alfred/security/
  # Translators: {url} is the URL where the canary token was detected.
  msgid "security.canary_tripped"
  msgstr "Canary token detected in content from {url}. This is a security event."

  #: src/alfred/hooks/capability.py
  msgid "capability_gate.unavailable"
  msgstr "I can't verify your permissions right now. Please retry in a few minutes."

  #: src/alfred/plugins/
  # Translators: {got} is the version presented; {expected} is 1.
  msgid "plugin.manifest_version_mismatch"
  msgstr "Plugin manifest version {got} is not supported (expected {expected}). Update the plugin."

  #: src/alfred/plugins/
  # Translators: {plugin_id} is the plugin identifier.
  msgid "plugin.launcher_no_sandbox_policy"
  msgstr ""
  "No sandbox policy configured for plugin {plugin_id}. "
  "Set ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1 for development, "
  "or provide a sandbox policy file."

  #: src/alfred/cli/plugin_cmd.py
  # Translators: {plugin_id} is the plugin; {tier} is the subscription tier;
  # {hookpoint} is the hookpoint name; {blast_radius} describes the access granted.
  msgid "plugin.grant_prompt"
  msgstr ""
  "Grant plugin {plugin_id} access at {tier} tier on hookpoint {hookpoint}. "
  "Blast radius: {blast_radius}."

  #: src/alfred/plugins/quarantine_extractor.py
  # Translators: {schema_name} is the Pydantic model class name.
  msgid "quarantine.schema_version_missing"
  msgstr ""
  "Extraction schema {schema_name} is missing schema_version: Literal[1]. "
  "Add 'schema_version: Literal[1] = 1' as a class attribute."

  #: src/alfred/bootstrap/gate_factory.py
  msgid "bootstrap.capability_gate_unseeded"
  msgstr ""
  "Capability gate backing store is not seeded. "
  "Run 'alfred plugin grant init' to initialise state.git, "
  "then 'uv run alembic upgrade head' to apply migrations."

  # === Cluster 1 / PR-S3-3a: StdioTransport DLP outbound refused ===
  #: src/alfred/plugins/transport.py
  # Translators: {plugin_id} is the plugin identifier. Raised when OutboundDlp.scan
  # refuses to let the outbound payload leave for the subprocess (arch-006 / sec-006).
  msgid "plugin.transport.dlp_outbound_refused"
  msgstr ""
  "Outbound DLP blocked dispatch to plugin {plugin_id}. "
  "The payload contains content that cannot be sent to an external subprocess."
  ```

  After appending, compile the catalog:

  ```bash
  cd <repo-root>
  # i18n-009: pybabel extract is NOT run here. The Slice-3 t() call-sites land in
  # PR-S3-1 through PR-S3-6, not in this PR. Running extract now would flag all
  # 86 new entries as obsolete (#~ msgid) because no call-sites exist in src/ yet.
  # The catalog entries are the source of truth for this PR; call-sites validate
  # against them via test_catalog_slice3_keys.py (placeholder-integrity test).
  #
  # The pre-commit hook runs pybabel compile (not extract) and will catch .po/.mo
  # drift. Run compile directly:
  uv run pybabel compile -d locale 2>&1 | tail -5
  # Expected: "compiling catalog locale/en/LC_MESSAGES/alfred.po to locale/en/LC_MESSAGES/alfred.mo"
  ```

  Run catalog check:

  ```bash
  uv run pybabel compile --check -d locale 2>&1 | tail -5
  # Expected: clean (no drift)
  ```

  Run the failing test again — must now PASS:

  ```bash
  uv run pytest tests/unit/test_catalog_slice3_keys.py -q 2>&1 | tail -5
  # Expected: 86 passed (test_slice3_key_resolves) + N placeholder-integrity passed
  # i18n-003: total msgid count in the .po block must match _SLICE_3_KEYS length (86).
  # If the counts diverge, update both _SLICE_3_KEYS and the .po block together.
  ```

  Commit:

  ```bash
  git add locale/en/LC_MESSAGES/alfred.po locale/en/LC_MESSAGES/alfred.mo \
          tests/unit/test_catalog_slice3_keys.py
  git commit -m "feat(i18n): add all Slice-3 t() catalog keys per spec §11.5 + placeholder-integrity test (#TBD-slice3)"
  ```

### Component H: Quality gates

- [ ] **Task 17 — Run full quality bar and fix any issues.**

  ```bash
  cd <repo-root>
  make check 2>&1 | tail -20
  # Expected: all green (lint + format + type + tests)
  # Fix any ruff / mypy / pyright issues before proceeding.
  ```

  Common fixes:
  - If `mypy` reports `Any` in models.py: replace `dict[str, Any]` with typed alternatives where possible; if `JSON` fields must stay `Any`, add `# type: ignore[assignment]` with a comment.
  - If `ruff` flags `S608` on the migration f-strings: add `# noqa: S608` with comment (values are module-level constants, not user-controlled — same pattern as 0005/0006 migrations).
  - If `ruff` flags unused imports in migrations: ensure `__all__` is present.

  ```bash
  uv run pytest tests/integration/ -q --tb=short 2>&1 | tail -10
  # Expected: all integration tests pass
  ```

  ```bash
  make docs-check 2>&1 | tail -3
  # Expected: no broken cross-links
  ```

  ```bash
  uv run pybabel compile --check -d locale 2>&1 | tail -3
  # Expected: clean
  ```

  Commit any fixes:

  ```bash
  git add -p  # stage only the fix hunks
  git commit -m "fix(s3-0b): address make check findings (#TBD-slice3)"
  ```

---

## §5 Spec Coverage Map

| Spec § / Sub-section | What it requires | Task(s) |
|---|---|---|
| §13 — migration 0007 | Extend `ck_audit_log_result` with 13 Slice-3 values | Tasks 1, 2 |
| §13 — migration 0008 | Create `plugin_grants` table with `content_tier`, unique constraint on (plugin_id, hookpoint, subscriber_tier) | Tasks 3, 4 |
| §13 — migration 0009 | Create `capability_gate_sync` table as singleton (INTEGER PK, `commit_hash` column) | Tasks 5, 6 |
| §13 — SQLAlchemy models | `PluginGrant` (+ content_tier, UniqueConstraint), `CapabilityGateSync` (INTEGER PK, commit_hash) | Tasks 4, 6 |
| §13 — migration chain | 0006→0007→0008→0009 contiguous, `alembic check` clean | Task 7 |
| §7.7 — Redis key patterns | Rate, budget, content, robots key namespaces + TTLs | Tasks 8, 9 |
| §7.7 — volatile-lru policy | Redis started with `--maxmemory <N>mb --maxmemory-policy volatile-lru` | Task 10 |
| §7.7 — single-extract invariant | `GETDEL` on content handle key is atomic (devops-005) | Task 8 |
| §5.2 — alfred-quarantine UID | `useradd --system --no-create-home --user-group alfred-quarantine` in Dockerfile | Task 9 |
| §5.2 — git + util-linux packages | `apt-get install -y git util-linux` in Dockerfile runtime stage (devops-003) | Task 9 |
| §8.1 — state.git init | Idempotent `git init --bare /var/lib/alfred/state.git` via dedicated seed script (devops-001 / devops-009) | Tasks 11, 12 |
| §8.1 — main branch seed | Empty initial commit pushed to `main` in state.git | Tasks 11, 12 |
| §15.4 — operator migration runbook step 2 | `alfred plugin grant init` seeds state.git | Tasks 11, 12 |
| §5.4 / index §3 — routing.yaml `[quarantine]` block | `provider`, `model`, `secret_id` fields | Task 13 |
| §11.2 — low-blast `config/policies.yaml` knobs | All six low-blast knob categories | Task 14 |
| §11.5 — i18n catalog: CLI action keys | `cli.plugin.grant.*`, `cli.web.allowlist.*`, `cli.config.*`, `cli.supervisor.reset.*` + rerun_hint + since_invalid (i18n-004 / devex-016) | Tasks 15, 16 |
| §11.5 — i18n catalog: list/table column keys | `cli.plugin.list.*`, `cli.plugin.show.*`, `cli.web.allowlist.list.*`, `cli.supervisor.status.*` | Tasks 15, 16 |
| §11.5 — i18n catalog: WebFetchError keys | `web.fetch.error.*` (5 keys) | Tasks 15, 16 |
| §11.5 — i18n catalog: system/bootstrap + new Cluster 1 key | `bootstrap.*`, `orchestrator.*`, `security.*`, `capability_gate.*`, `plugin.*`, `quarantine.*`, `plugin.transport.dlp_outbound_refused` | Tasks 15, 16 |
| §7.7 — Redis AOF persistence | `appendonly yes` + `appendfsync everysec` in docker-compose | Task 10 |
| §7.7 — maxmemory bound | `--maxmemory ${ALFRED_REDIS_MAXMEMORY:-256mb}` required for volatile-lru to trigger (devops-002) | Task 10 |
| §5.2 — cap_add SETUID | `alfred-core` service gets `cap_add: [SETUID]`; `alfred-discord` does not; invariants tested (devops-010) | Tasks 10, 10a |
| perf-006 — ContentStore pool | `ContentStore` lifecycle + `GETDEL` primitive documented via test | Task 8 |
| CLAUDE.md i18n rule #1 | Every new `t()` key in catalog (86 total); placeholder integrity tested (Cluster 6 / i18n-007) | Tasks 15, 16 |
| CLAUDE.md i18n rule #4 | `pybabel compile --check` passes; extract not run (call-sites in S3-1..S3-7, i18n-009) | Tasks 16, 17 |
| CLAUDE.md i18n rule #3 | Models carry `language` field (inherited from existing patterns) | Tasks 4, 6 |
| mem-001 | `plugin_grants.content_tier` column added; test asserts T0/T1/T2/T3/NULL valid; T99 rejected | Tasks 3, 4 |
| mem-002 | `capability_gate_sync.commit_hash` (not `state_git_commit_hash`); test asserts column name | Tasks 5, 6 | **Deviation from fixup contract**: the fixup directive said "pick `state_git_commit_hash` everywhere"; implementers chose the shorter `commit_hash` for the sync table and applied it consistently across S3-0b + S3-2. The `state_git_commit_hash` column name correctly belongs only on the `plugin_grants` table, where it records the state.git commit that authorised each row. The sync table's column records the current cache HEAD, making `commit_hash` the accurate name. This deviation is intentional and internally consistent. |
| mem-003 | `uq_plugin_grants_plugin_hook_tier` UNIQUE constraint; upsert ON CONFLICT test | Tasks 3, 4 |
| mem-004 | `capability_gate_sync` id=INTEGER CHECK(id=1) singleton; second-row rejected test | Tasks 5, 6 |
| mem-005 | Migration test ordering pinned with `pytestmark`; no-op `.replace` removed | Tasks 1, 3, 5 |
| devops-001 | `--entrypoint /bin/sh` added to compose-run invocation | Task 12 |
| devops-002 | `--maxmemory` bound added to alfred-redis | Task 10 |
| devops-003 | `util-linux` package added for `runuser`; `--user-group` on alfred-quarantine | Task 9 |
| devops-008 | `--user-group` flag creates dedicated GID for alfred-quarantine | Task 9 |
| devops-009 | Seed logic in dedicated `bin/alfred-state-git-seed.sh` | Task 12 |
| devops-010 | Compose invariant unit test | Task 10a |

---

## §6 Quality gates

Run these in order before opening the PR for review:

```bash
# 1. Lint + format + type + unit
make check

# 2. Integration tests (requires testcontainers / Docker daemon)
uv run pytest tests/integration/ -q

# 3. Catalog drift check (CLAUDE.md i18n rule #4)
uv run pybabel compile --check -d locale

# 4. All Slice-3 keys resolve
uv run pytest tests/unit/test_catalog_slice3_keys.py -q

# 5. Migration chain integrity
uv run alembic history --verbose | head -10
uv run alembic check

# 6. Docs-check (no broken cross-links)
make docs-check

# 7. Adversarial suite (no new adversarial files in this PR, but confirm no regression)
uv run pytest tests/adversarial -q

# 8. Dockerfile build
docker build --no-cache -f docker/alfred-core.Dockerfile . -t alfred-s3-0b-check
docker run --rm --user root alfred-s3-0b-check id alfred-quarantine
docker run --rm --user root alfred-s3-0b-check git --version

# 9. Compose config validation
docker compose config --quiet
```

All of the above must be clean before the PR is opened. CI enforces items 1–6 automatically; 7–9 are verified locally.

---

## §7 References

- **Spec:** [docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md](../specs/2026-05-30-slice-3-trust-tier-completion-design.md) — §7.7 (Redis), §8.1 (state.git), §11.1–§11.5 (config + i18n), §13 (migrations, SQLAlchemy models), §15.4 (operator runbook), §17 PR-S3-0b scope.
- **Index plan:** [2026-05-31-slice-3-index.md](./2026-05-31-slice-3-index.md) — §3 cross-PR contracts, §7 PR-S3-0 split rationale.
- **PR-S3-0a plan (predecessor):** [2026-05-31-slice-3-pr-s3-0a-docs-adrs-foundations.md](./2026-05-31-slice-3-pr-s3-0a-docs-adrs-foundations.md) — defines `audit_row_schemas.py` (the migration table source of truth) and `payload_schema.py` Literal additions.
- **ADR-0017:** [docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — load-bearing Slice-3 ADR; co-merged with PR-S3-0a.
- **Migration precedent:** [src/alfred/memory/migrations/versions/0006_audit_result_hooks_values.py](../../../src/alfred/memory/migrations/versions/0006_audit_result_hooks_values.py) — pattern for additive CHECK constraint extension.
- **PRD §5.2:** process boundary isolation; `alfred-quarantine` UID requirement.
- **PRD §6.4:** reviewer-gate flow for high-blast grants; state.git proposal flow.
- **PRD §7.1:** trust tiers, dual-LLM split, secret broker.
- **CLAUDE.md hard rules:** security #1 (never log secrets), #6 (secrets in broker), #7 (no silent failures); i18n #1 (every `t()` key in catalog), #3 (language field on stored rows), #4 (`pybabel compile --check` in CI), #5 (doc files stay English-only).
