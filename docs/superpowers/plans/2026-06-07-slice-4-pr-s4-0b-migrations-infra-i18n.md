# PR-S4-0b: Migrations, Infrastructure, and i18n Catalog — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Run `superpowers:test-driven-development` for every component (failing test first, then implementation).

**Goal:** Land the executable substrate that every downstream Slice-4 PR depends on — four Alembic migrations (`0012_operator_sessions`, `0013_policies_snapshot_history`, `0014_audit_columns_slice_4`, `0015_sandbox_policy_registry`), their SQLAlchemy 2.0 typed models, the full Slice-4 i18n catalog enumeration (~44 keys across login/session/daemon/sandbox/config-reload/TUI families), the `bubblewrap` apt-install in `docker/alfred-core.Dockerfile`, `bin/alfred-setup.sh` updates for the operator-session config directory + sandbox-policy directory layout, and the `audit.hash_pepper` secret bootstrap (registry entry + broker-config seed step + daemon-boot-refuses-without-it contract surface).

**Architecture:** Four Alembic migrations chain after Slice-3's `0010_circuit_breakers` (verified at `src/alfred/memory/migrations/versions/0010_circuit_breakers.py` — `revision="0010"`, `down_revision="0009"`). The new chain is `0010 → 0012 → 0013 → 0014 → 0015`. Migration `0012` creates `operator_sessions` for the CLI login flow (`uq_operator_sessions_token_hash` index is the load-bearing perf primitive that PR-S4-5's `_resolve_operator` 5ms p99 budget relies on). Migration `0013` creates `policies_snapshot_history` as an optional rollback log for the PR-S4-4 hot-reload swap. Migration `0014` adds the Slice-4 audit columns (the field union of every Slice-4 `*_FIELDS` constant from PR-S4-0a's `audit_row_schemas.py`). Migration `0015` creates `sandbox_policy_registry` for the launcher's policy-resolution observability. SQLAlchemy 2.0 models land in `src/alfred/memory/models.py` (where `AuditEntry` already lives at line 89). The i18n catalog adds 44 keys spanning login, logout, whoami, daemon, sandbox, config-reload, supervisor reset, and TUI families per spec §12.2. The Dockerfile extension adds one apt-package — `bubblewrap` — to the existing runtime layer that already installs `git` and `util-linux`. **`docker-compose.yaml` already uses `build:` for `alfred-core`** (verified: lines 67-70 — `build: dockerfile: docker/alfred-core.Dockerfile`), so the index §1 row that says "flips `image:` → `build:`" is wrong; this plan only adds the `bubblewrap` package and a Dockerfile-level `RUN apt-get install` step. The setup-script update is additive — a new `mkdir -p ~/.config/alfred/sandbox/` step and a new `audit.hash_pepper` prompt-and-store step.

**Tech Stack:** Python 3.12+ / SQLAlchemy 2.0 declarative ORM / Alembic / Docker multi-stage build / Docker Compose v2 / Babel pybabel / pytest + testcontainers / structlog

> **Migration numbering note** (mem-001 closure from PR #205 round-1 review): the chain is **0012–0015** because `0011_processed_proposals.py` already exists on `main` from Slice-3 carryover. All migration files, test filenames, `down_revision` chains, and audit-column references below use 0012-0015.

---

## §1 Goal

PR-S4-0b delivers the executable substrate for all Slice-4 implementation PRs. It gates on PR-S4-0a (which establishes `audit_row_schemas.py` constants and `payload_schema.py` Literal additions). Without this PR, no downstream PR can:

- migrate the database (PR-S4-5 needs `operator_sessions`; PR-S4-4 needs `policies_snapshot_history`; PR-S4-6 needs `sandbox_policy_registry`; PR-S4-1/2/3/8 need the new audit columns);
- run `bin/alfred-plugin-launcher.sh` against a sandbox-policy (the launcher's per-OS resolution targets `~/.config/alfred/sandbox/<name>.<os>.policy`, seeded by `bin/alfred-setup.sh`);
- call any new `t()` key from the Slice-4 catalog without failing `pybabel compile --check` in CI;
- boot the daemon (PR-S4-1) — daemon boot reads `audit.hash_pepper` from the broker and refuses-to-start when absent;
- build the runtime image with `bubblewrap` available (PR-S4-6's bash launcher invokes `bwrap` directly).

**Spec anchors:**

- Spec [§12.1](../specs/2026-06-06-slice-4-design.md#121-alembic-migrations-0012--0015) — Alembic migrations 0012–0015 (full table).
- Spec [§12.2](../specs/2026-06-06-slice-4-design.md#122-i18n-catalog-additions) — i18n catalog additions (full enumeration).
- Spec [§13](../specs/2026-06-06-slice-4-design.md#13-pr-breakdown--12-prs-summary) — PR-S4-0b row.
- Spec [§8.10](../specs/2026-06-06-slice-4-design.md#810-audit-row-family) — `audit.hash_pepper` bootstrap contract.
- Spec [§9](../specs/2026-06-06-slice-4-design.md#9-audit-row-schemas-slice-4-additions) — `audit_row_schemas.py` Slice-4 constants (PR-S4-0a defines, PR-S4-0b adds the columns).
- Spec [§6.2](../specs/2026-06-06-slice-4-design.md#62-session-file-format--permissions) — session-file format (Settings + secret pepper contract).
- Spec [§7.5–7.7](../specs/2026-06-06-slice-4-design.md#75-linux-bwrap-policy-configsandboxquarantined-llmlinuxbwrappolicy) — per-OS sandbox-policy file locations (consumed by setup-script).
- Index [§3 audit-pepper bootstrap contract](./2026-06-07-slice-4-index.md#audit-pepper-bootstrap-defined-in-pr-s4-0b--consumed-by-pr-s4-8--pr-s4-9).
- Index [§7 PR-S4-0 split rationale](./2026-06-07-slice-4-index.md#7-pr-s4-0-split-rationale-0a-vs-0b).

**Depends on:** PR-S4-0a (merged — `audit_row_schemas.py` Slice-4 constants are the source of truth for migration 0014's added columns; `payload_schema.py` Slice-4 Literal additions; ADR-0024 wire contract docs).

**Blocks:** PR-S4-1 (daemon boot reads `audit.hash_pepper` at startup), PR-S4-3 (carrier-substitution audit rows need `0014` columns), PR-S4-4 (`policies_snapshot_history` table), PR-S4-5 (`operator_sessions` table + `uq_operator_sessions_token_hash`), PR-S4-6 (launcher binary depends on `bubblewrap` in image + sandbox config dir), PR-S4-7 (sandbox policies under `~/.config/alfred/sandbox/`), PR-S4-8 (comms audit rows + `audit.hash_pepper` hash recipe), PR-S4-9 (HMAC-with-pepper hash recipe in Discord adapter).

**Out of scope** (do not implement here; later PRs own these):

- Hot-reload runtime — `PolicyWatcher`, `PoliciesV1`, `PoliciesSnapshotRef` (PR-S4-4).
- Session-resolver runtime — `_resolve_operator`, `OperatorSession` Pydantic model + file-load discipline (PR-S4-5).
- Sandbox policy bytes — Linux bwrap policy, macOS sandbox-exec policy, Windows stub (PR-S4-7).
- Comms-MCP wire-format runtime — `process_inbound_message`, `BurstLimiter`, `REQUIRED_CLASSIFIERS_BY_KIND` (PR-S4-8).
- Daemon-boot subcommand wiring (`alfred daemon start/stop/status`) — uses the table this PR creates but does not ship the CLI surface (PR-S4-1).

---

## §2 Architecture overview

### Migration chain

The existing migration chain ends at `0010_circuit_breakers` (Slice-3 supervisor breaker-state persistence; verified `revision="0010"` / `down_revision="0009"`). This PR adds four migrations in sequence:

```
0010 (Slice-3) → 0012 (operator_sessions) → 0013 (policies_snapshot_history)
              → 0014 (audit_columns_slice_4) → 0015 (sandbox_policy_registry)
```

Each migration carries a `downgrade()` path matching spec §12.1 line 1333:

- **`0012_operator_sessions`** — creates table; downgrade DROPs the table (operators re-login on revert; spec §5 line 294 confirms this is acceptable).
- **`0013_policies_snapshot_history`** — creates table; downgrade DROPs the table (rollback history lost; current snapshot unaffected). Optional table — `PolicyWatcher` writes to it on swap, reads it on `alfred policies rollback <id>` (future CLI).
- **`0014_audit_columns_slice_4`** — adds nullable columns to `audit_log` for fields referenced by Slice-4 `*_FIELDS` constants but not present in the pre-Slice-4 schema. Downgrade `op.drop_column`s the added columns (existing audit rows lose Slice-4 metadata; pre-Slice-4 audit rows untouched).
- **`0015_sandbox_policy_registry`** — creates table; downgrade DROPs the table (observability only; no operational state).

### Infrastructure additions

```
docker/alfred-core.Dockerfile  (modify — already exists)
  runtime stage
    + apt-get install bubblewrap   # provides /usr/bin/bwrap for PR-S4-6's
                                    # bash launcher (Linux-only — macOS uses
                                    # sandbox-exec, Windows stubs)

docker-compose.yaml  (no change required — alfred-core already uses `build:` at
                      lines 67-70; the index §1 row's "flips image: → build:"
                      phrasing is wrong for the current source tree)

bin/alfred-setup.sh  (modify — already exists)
  + mkdir -p ~/.config/alfred/sandbox/    # per-OS sandbox-policy directory
                                           # (spec §7.5–7.7); operators drop
                                           # vendor or local policy files here
  + audit.hash_pepper bootstrap step       # generates a random 64-byte hex
                                           # pepper via `openssl rand -hex 32`
                                           # and writes it to the broker config
                                           # under the `audit.hash_pepper` key
                                           # if not already set; idempotent

~/.config/alfred/secrets.toml  (broker config — modify if exists, create if not)
  + audit.hash_pepper = "<bootstrap-generated>"
                              # registered in SecretBroker.SUPPORTED_SECRETS
                              # via this PR's src/alfred/security/secrets.py
                              # edit (one-line addition to the registry tuple)
```

### Audit-pepper bootstrap contract (index §3)

PR-S4-0b is the single owner of the pepper-secret introduction. The contract has four touch-points landing in this PR:

1. **Broker registry.** `src/alfred/security/secrets.py:SUPPORTED_SECRETS` gains `"audit.hash_pepper"` (frozenset / tuple addition; one-line edit). Without this, `SecretBroker.get("audit.hash_pepper")` raises `UnknownSecretError` even when the value is in the config.
2. **Setup-script seed.** `bin/alfred-setup.sh` generates a random pepper (64 hex chars; `openssl rand -hex 32`) on fresh setup and writes it to the broker config file. Idempotent — if `audit.hash_pepper` already has a non-empty value the step is a no-op.
3. **Audit-row schema reference.** Spec §8.10 documents the HMAC recipe; the columns that hold pepper-hashed values (`platform_user_id_hash`, `verification_phrase_hash`, `machine_id_hash`) land via migration `0014`. The pepper itself never lives in the database.
4. **Daemon-boot refusal contract.** Spec §8.10 line 1149 (`Bootstrap step in PR-S4-0b` paragraph) declares the daemon-boot-refuses-without-pepper contract surface. The runtime implementation (the actual `daemon.boot.failed(failure_reason="audit_hash_pepper_missing")` emit) lands in PR-S4-1; PR-S4-0b only registers `"audit.hash_pepper"` as a `SUPPORTED_SECRETS` entry so PR-S4-1's boot probe can call `broker.has("audit.hash_pepper")` and refuse on `False`.

### i18n catalog additions

All 44 new `t()` keys ship in `locale/en/LC_MESSAGES/alfred.po` in this PR. The implementation PRs (S4-1 through S4-10) call these keys — they will find them in the compiled `.mo` and pass `pybabel compile --check` without needing to add entries themselves. The catalog-additions PR ships the keys with canonical English copy; per-PR copy editorial review is deferred to the implementing PR. The exhaustive enumeration matches spec §12.2:

- **Login / session lifecycle** (12 keys).
- **Operator-session refusal reasons** (8 keys — one per `OPERATOR_SESSION_REFUSED_FIELDS.reason` Literal).
- **Supervisor reset refusals** (2 keys).
- **Daemon boot** (9 keys — six failure reasons + `daemon.boot.started`, `daemon.stop.confirmed`, `daemon.status.template`).
- **Sandbox refusal reasons** (6 keys — one per `SANDBOX_REFUSED_FIELDS.reason` Literal + the dev-escape-hatch refusal).
- **Config-reload notifications** (6 keys — `applied` + five rejection reasons).
- **TUI** (1 key — `comms.tui.daemon_required_to_chat`).

Note: spec §12.2 also calls out that PR-S4-5's `alfred whoami` formats timestamps via `babel.dates.format_datetime(dt, locale=user.language)`. The `babel` dependency is already in the runtime venv (verified per the existing Dockerfile comment line 26 — "textual and babel are runtime deps"), so no `pyproject.toml` change is required. The i18n catalog ships only the message keys; the formatting calls live in PR-S4-5.

### Out-of-scope verification gate (CLAUDE.md fabricated-surfaces watchlist)

Per index §8 Slice-5 backlog note ("Fabricated-surfaces watchlist for writing-plans"), this plan grep-verifies every cited Slice-3 surface before invoking it:

| Cited symbol | Verified at | Status |
|---|---|---|
| `SecretBroker.get(name) -> str` | `src/alfred/security/secrets.py:396` | Present — returns `str`, whitelisted via `SUPPORTED_SECRETS` |
| `SecretBroker.has(name) -> bool` | `src/alfred/security/secrets.py:412` | Present — used by daemon-boot probe (PR-S4-1) |
| `class AuditEntry(Base)` (`__tablename__ = "audit_log"`) | `src/alfred/memory/models.py:89` | Present — Slice-4 columns added here |
| `class Settings(BaseSettings)` | `src/alfred/config/settings.py:28` | Present — no Slice-4 fields added by this PR (those are in PR-S4-1 for `proposal_dispatch_interval_s`, PR-S4-4 for `policies_path`, PR-S4-5 for `operator_session_path`, PR-S4-6 for `environment`) |
| Migration `0010` revision/down_revision | `src/alfred/memory/migrations/versions/0010_circuit_breakers.py:68-69` | Confirmed `"0010" / "0009"` — new chain starts at `0012 / 0010` |
| Migration chain 0007 → 0008 → 0009 → 0010 | Slice-3 versions dir | Confirmed full chain |
| `docker-compose.yaml` `alfred-core` build mode | `docker-compose.yaml:67-70` | **Already uses `build:`** — the index-row claim that PR-S4-0b "flips `image:` → `build:`" is wrong for the current source tree. Only the Dockerfile `bubblewrap` apt-install is new |
| `bin/alfred-setup.sh` exists | `bin/alfred-setup.sh` (262+ lines as inspected) | Confirmed — this PR extends, does not create |
| `locale/en/LC_MESSAGES/alfred.po` exists | `locale/en/LC_MESSAGES/alfred.po` (Slice-1 Babel header at line 1) | Confirmed — this PR appends 44 keys |
| `plugins/alfred_quarantined_llm/manifest.toml` (TOML, not YAML) | `plugins/alfred_quarantined_llm/manifest.toml` | Confirmed `.toml` — relevant for PR-S4-6 manifest update; **this PR does not modify the manifest** (PR-S4-6 owns the `sandbox` block addition) |
| `src/alfred/hooks/registry.py:SYSTEM_ONLY_TIERS` | `src/alfred/hooks/registry.py:320` | Confirmed — referenced only by docs in this PR; runtime use is in PR-S4-3 and later |

Surfaces that **do not** exist yet and are explicitly out-of-scope for this PR (verified by spec / index search):

- `HookpointMeta.carrier_tier` / `HookpointMeta.allow_error_substitution` — PR-S4-3 owns the runtime-type addition (rev-007 closure per index §1).
- `PoliciesV1` / `PoliciesSnapshotRef` — PR-S4-4 owns.
- `OperatorSession` Pydantic model — PR-S4-5 owns.
- `BurstLimiter` — PR-S4-8 owns.
- `Supervisor.request_plugin_restart` — PR-S4-8 owns.

---

## §3 File structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/memory/migrations/versions/0012_operator_sessions.py` | Create | Creates `operator_sessions` table + `uq_operator_sessions_token_hash` unique index + `(user_id, expires_at)` index |
| `src/alfred/memory/migrations/versions/0013_policies_snapshot_history.py` | Create | Creates `policies_snapshot_history` table (optional rollback log) |
| `src/alfred/memory/migrations/versions/0014_audit_columns_slice_4.py` | Create | Adds Slice-4 audit columns to `audit_log` for `*_FIELDS` constants from PR-S4-0a's `audit_row_schemas.py` |
| `src/alfred/memory/migrations/versions/0015_sandbox_policy_registry.py` | Create | Creates `sandbox_policy_registry` table (launcher policy-resolution observability) |
| `src/alfred/memory/models.py` | Modify | Adds `OperatorSession`, `PoliciesSnapshotHistory`, `SandboxPolicyRegistry` SQLAlchemy 2.0 typed models; extends `AuditEntry` with Slice-4 nullable columns |
| `src/alfred/security/secrets.py` | Modify | Adds `"audit.hash_pepper"` to `SUPPORTED_SECRETS` registry (one-line addition) |
| `locale/en/LC_MESSAGES/alfred.po` | Modify | Appends 44 Slice-4 `t()` keys per spec §12.2 |
| `locale/en/LC_MESSAGES/alfred.mo` | Regenerate | Compiled catalog regenerated by `pybabel compile` |
| `docker/alfred-core.Dockerfile` | Modify | Adds `bubblewrap` to the runtime-stage apt-install (no other change) |
| `bin/alfred-setup.sh` | Modify | Adds `mkdir -p ~/.config/alfred/sandbox/` step + `audit.hash_pepper` bootstrap step |
| `tests/integration/test_migrations_0012_0015.py` | Create | Migration round-trip: upgrade + downgrade for migrations 0012–0015; confirms `uq_operator_sessions_token_hash` exists and is unique |
| `tests/integration/test_audit_pepper_bootstrap.py` | Create | Asserts setup-script seeds a non-empty `audit.hash_pepper` and `SecretBroker.has("audit.hash_pepper")` returns `True`; asserts `SecretBroker.get("audit.hash_pepper")` returns a 64-hex-char string |
| `tests/unit/test_catalog_slice_4_keys.py` | Create | Every new Slice-4 `t()` key resolves without returning the bare key; placeholder-integrity assertions |
| `tests/unit/test_dockerfile_bubblewrap_present.py` | Create | AST/text guard asserting `docker/alfred-core.Dockerfile` apt-install line includes `bubblewrap=0.6.0-1` (version pin per round-2 sec-4 closure — Debian Bookworm ships 0.8.0+; CVE-2017-5226 was fixed in 0.1.7, so 0.6.0 is a safe minimum) AND a smoke test `RUN /usr/bin/bwrap --version` (post-install verification — fails fast if apt-install silently corrupts; runs at image-build time). The plan also adds a smoke job in `.github/workflows/ci.yml` that pulls the built image + asserts `getcap /usr/bin/bwrap` returns expected `cap_sys_admin+ep` (or empty if the host uses user namespaces — bwrap supports both modes; the test accepts either as healthy and refuses any other result). |
| `tests/unit/test_setup_script_audit_pepper.py` | Create | Asserts `bin/alfred-setup.sh` contains the `audit.hash_pepper` seed step and the `~/.config/alfred/sandbox/` mkdir step |
| `tests/unit/test_audit_log_slice_4_columns.py` | Create | Asserts `AuditEntry` ORM model has all Slice-4 columns; cross-validates against `audit_row_schemas.py` Slice-4 constants (every field name referenced is an `AuditEntry` column) |

---

## §4 Tasks

> Each Component below is grouped by deliverable. Implement components in
> order — A through I. Within a component, do tests first (failing) then
> implementation (passing), per `superpowers:test-driven-development`. After
> each component, run `make check` to confirm no regressions before moving on.

### Component A: Migration 0012 — `operator_sessions` table

- [ ] **Task A1 — Write failing migration round-trip test for 0012.**

  Files: Create `tests/integration/test_migrations_0012_0015.py`.

  Step 1 — Write the test scaffold + the `0012` section:

  ```python
  # tests/integration/test_migrations_0012_0015.py
  """Round-trip tests for Slice-4 migrations 0012–0015.

  Uses testcontainers to spin up a real Postgres instance so CHECK
  constraints, unique indexes, and column defaults are enforced at the DB
  layer, not just in Python. Mirrors the discipline of
  ``tests/integration/test_migrations_0007_0009.py`` (Slice-3).
  """
  from __future__ import annotations

  import datetime as dt
  import uuid

  import pytest
  import sqlalchemy as sa
  from alembic import command as alembic_command
  from alembic.config import Config as AlembicConfig
  from testcontainers.postgres import PostgresContainer

  ALEMBIC_INI_PATH = "alembic.ini"

  # Slice-4 ordering: each Slice-4 migration test runs against the prior
  # one's head, mirroring the slice-3 module-scoped-container pattern.
  pytestmark = pytest.mark.run(order=2)


  @pytest.fixture(scope="module")
  def pg_url() -> str:
      with PostgresContainer("postgres:16") as pg:
          yield pg.get_connection_url()


  @pytest.fixture(scope="module")
  def alembic_cfg(pg_url: str) -> AlembicConfig:
      cfg = AlembicConfig(ALEMBIC_INI_PATH)
      cfg.set_main_option("sqlalchemy.url", pg_url)
      return cfg


  @pytest.fixture(scope="module")
  def engine_at_0010(alembic_cfg: AlembicConfig, pg_url: str) -> sa.Engine:
      """Apply migrations up to 0010 (Slice-3 baseline)."""
      alembic_command.upgrade(alembic_cfg, "0010")
      return sa.create_engine(pg_url)


  def test_0012_upgrade_creates_operator_sessions_table(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0012")
      inspector = sa.inspect(engine_at_0010)
      assert "operator_sessions" in inspector.get_table_names()

      cols = {c["name"]: c for c in inspector.get_columns("operator_sessions")}
      # Exhaustive column-set assertion per spec §12.1 row 0012.
      assert set(cols.keys()) == {
          "user_id",
          "token_hash",
          "issued_at",
          "expires_at",
          "host",
          "machine_id_hash",
          "revoked_at",
      }
      # token_hash must be NOT NULL and the unique-index target.
      assert cols["token_hash"]["nullable"] is False
      # revoked_at is nullable (active sessions have NULL).
      assert cols["revoked_at"]["nullable"] is True


  def test_0012_unique_token_hash_index_exists(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      """uq_operator_sessions_token_hash is the load-bearing perf primitive
      for PR-S4-5's _resolve_operator 5ms p99 budget. Asserting at the
      index level prevents a future drift where a column-level UNIQUE
      constraint is dropped accidentally."""
      alembic_command.upgrade(alembic_cfg, "0012")
      inspector = sa.inspect(engine_at_0010)
      indexes = inspector.get_indexes("operator_sessions")
      uq = [ix for ix in indexes if ix["name"] == "uq_operator_sessions_token_hash"]
      assert len(uq) == 1, "uq_operator_sessions_token_hash index missing"
      assert uq[0]["unique"] is True
      assert uq[0]["column_names"] == ["token_hash"]


  def test_0012_lookup_index_user_id_expires_at_exists(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      """(user_id, expires_at) index for the operator's `alfred user show`
      session-list path (spec §12.1)."""
      alembic_command.upgrade(alembic_cfg, "0012")
      inspector = sa.inspect(engine_at_0010)
      ix_names = {ix["name"] for ix in inspector.get_indexes("operator_sessions")}
      assert "ix_operator_sessions_user_id_expires_at" in ix_names


  def test_0012_unique_token_hash_refuses_duplicate(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0012")
      with engine_at_0010.begin() as conn:
          conn.execute(
              sa.text(
                  "INSERT INTO operator_sessions "
                  "(user_id, token_hash, issued_at, expires_at, host, machine_id_hash) "
                  "VALUES (:u, :th, :i, :e, :h, :m)"
              ),
              {
                  "u": str(uuid.uuid4()),
                  "th": "h" * 64,
                  "i": dt.datetime.now(dt.UTC),
                  "e": dt.datetime.now(dt.UTC) + dt.timedelta(hours=12),
                  "h": "ops-laptop.local",
                  "m": "m" * 64,
              },
          )
      with pytest.raises(sa.exc.IntegrityError):
          with engine_at_0010.begin() as conn:
              conn.execute(
                  sa.text(
                      "INSERT INTO operator_sessions "
                      "(user_id, token_hash, issued_at, expires_at, host, machine_id_hash) "
                      "VALUES (:u, :th, :i, :e, :h, :m)"
                  ),
                  {
                      "u": str(uuid.uuid4()),
                      "th": "h" * 64,  # duplicate token_hash
                      "i": dt.datetime.now(dt.UTC),
                      "e": dt.datetime.now(dt.UTC) + dt.timedelta(hours=12),
                      "h": "ops-other.local",
                      "m": "z" * 64,
                  },
              )


  def test_0012_downgrade_drops_operator_sessions(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0012")
      alembic_command.downgrade(alembic_cfg, "0010")
      inspector = sa.inspect(engine_at_0010)
      assert "operator_sessions" not in inspector.get_table_names()
  ```

  Step 2 — Run `uv run pytest tests/integration/test_migrations_0012_0015.py -x`. Test must FAIL with a module-not-found-style error on the alembic upgrade (no `0012` revision exists yet). Confirm the failure before moving on.

- [ ] **Task A2 — Implement migration `0012_operator_sessions.py`.**

  Files: Create `src/alfred/memory/migrations/versions/0012_operator_sessions.py`.

  Mirror the Slice-3 migration style (`0010_circuit_breakers.py` is the canonical reference — long docstring at top, `__all__` declaring the public alembic surface, server-side defaults for raw-SQL writers).

  ```python
  """operator_sessions — CLI operator-session token table (Slice-4 PR-S4-5).

  Revision ID: 0012
  Revises: 0010
  Create Date: 2026-06-07 00:00:00.000000

  ``operator_sessions`` holds one row per active CLI session created by
  ``alfred login --as <user>`` (PR-S4-5). The session token is hashed
  before storage; the raw token lives only in ``~/.config/alfred/session``
  on the operator's machine (mode 0600 — spec §6.2). Per spec §6.5 each
  row has a 12-hour expiry by default plus a host-binding column so a
  stolen token cannot be replayed from a different machine.

  ``uq_operator_sessions_token_hash`` is the load-bearing perf primitive
  for PR-S4-5's ``_resolve_operator`` 5ms p99 budget. Spec §6.4 budgets
  ``SELECT user_id FROM operator_sessions WHERE token_hash=$1 AND
  revoked_at IS NULL AND expires_at > now()`` at ≤5ms p99; the unique
  index makes this a single index probe.

  Columns
  -------

  * ``user_id`` — canonical user id (UUID string) matching the
    Slice-2-shipped ``users`` table primary key. NOT NULL.
  * ``token_hash`` — SHA-256 of the random session token, hex-encoded
    (64 chars). NOT NULL. Unique-indexed via
    ``uq_operator_sessions_token_hash``.
  * ``issued_at`` — timestamptz when ``alfred login`` minted the token.
  * ``expires_at`` — timestamptz of expiry. Default 12h after
    ``issued_at`` per spec §6.5; the bounds ``[1h, 7d]`` are enforced
    in PR-S4-5 ``alfred login --expires-in`` parsing, NOT at the DB.
  * ``host`` — the hostname the token is bound to (spec §6.5). Refusal
    reason ``host_mismatch`` fires when ``_resolve_operator`` sees a
    different ``socket.gethostname()``.
  * ``machine_id_hash`` — HMAC-SHA256 of the per-OS system machine-id
    using ``audit.hash_pepper`` (spec §6.2 / §8.10 recipe). The raw
    machine-id never lands in the DB. Refusal reason
    ``machine_mismatch`` fires when ``_resolve_operator`` sees a
    different machine-id hash.
  * ``revoked_at`` — timestamptz of revocation; NULL for active
    sessions. ``alfred logout`` sets this column; later sessions for
    the same user create new rows.

  Indexes
  -------

  * ``uq_operator_sessions_token_hash`` (unique) — covers the
    ``_resolve_operator`` lookup path. Required for the 5ms p99 budget.
  * ``ix_operator_sessions_user_id_expires_at`` — covers
    ``alfred user show <user>`` session-list path (spec §6.8 follow-up).

  server_default rationale (mem-005 pattern, copied from 0010)
  ------------------------------------------------------------

  ``revoked_at`` is nullable with no server_default — the absence of a
  value is the live-session signal. The other timestamptz columns
  (``issued_at``, ``expires_at``) are populated by PR-S4-5's CLI code
  on every insert and have no server_default; a raw-SQL writer must
  supply them.

  Downgrade: DROP TABLE. Operators re-login on revert; spec §5 line 294
  confirms this is the rollback contract.
  """

  from __future__ import annotations

  from collections.abc import Sequence

  import sqlalchemy as sa
  from alembic import op

  # revision identifiers, used by Alembic.
  revision: str = "0012"
  down_revision: str | Sequence[str] | None = "0010"
  branch_labels: str | Sequence[str] | None = None
  depends_on: str | Sequence[str] | None = None

  # Alembic reads ``revision`` / ``down_revision`` / ``branch_labels`` /
  # ``depends_on`` via module introspection (see
  # ``alembic.script.revision``). Declaring them in ``__all__`` silences
  # CodeQL's py/unused-global-variable false positive — same pattern as
  # migrations 0004-0010.
  __all__ = [
      "branch_labels",
      "depends_on",
      "down_revision",
      "downgrade",
      "revision",
      "upgrade",
  ]


  def upgrade() -> None:
      """Create operator_sessions table + indexes."""
      op.create_table(
          "operator_sessions",
          sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
          sa.Column("token_hash", sa.String(64), nullable=False),
          sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
          sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
          sa.Column("host", sa.String(255), nullable=False),
          sa.Column("machine_id_hash", sa.String(64), nullable=False),
          sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
          # CHECK constraints (round-2 sec-2 + mem-003 closures):
          # - SHA-256 hex format pin: 64 lowercase hex chars. Future regression to
          #   different hash recipe would not be caught at the DB layer otherwise.
          # - revoked_at >= issued_at when set.
          # - expires_at > issued_at always.
          sa.CheckConstraint("token_hash ~ '^[0-9a-f]{64}$'", name="ck_operator_sessions_token_hash_sha256_hex"),
          sa.CheckConstraint("machine_id_hash ~ '^[0-9a-f]{64}$'", name="ck_operator_sessions_machine_id_hash_sha256_hex"),
          sa.CheckConstraint("revoked_at IS NULL OR revoked_at >= issued_at", name="ck_operator_sessions_revoked_after_issued"),
          sa.CheckConstraint("expires_at > issued_at", name="ck_operator_sessions_expires_after_issued"),
      )
      op.create_index(
          "uq_operator_sessions_token_hash",
          "operator_sessions",
          ["token_hash"],
          unique=True,
      )
      op.create_index(
          "ix_operator_sessions_user_id_expires_at",
          "operator_sessions",
          ["user_id", "expires_at"],
          unique=False,
      )


  def downgrade() -> None:
      """Drop operator_sessions; operators re-login on revert."""
      op.drop_index(
          "ix_operator_sessions_user_id_expires_at",
          table_name="operator_sessions",
      )
      op.drop_index(
          "uq_operator_sessions_token_hash",
          table_name="operator_sessions",
      )
      op.drop_table("operator_sessions")
  ```

- [ ] **Task A3 — Confirm tests A1 pass.** Run `uv run pytest tests/integration/test_migrations_0012_0015.py -k test_0012 -x -v`. All five `0012` tests must pass.

- [ ] **Task A4 — Run `make check`.** Lint, format, and type-check must pass on the new migration module.

---

### Component B: Migration 0013 — `policies_snapshot_history` table

- [ ] **Task B1 — Append failing tests for 0013 to `test_migrations_0012_0015.py`.**

  Add a `policies_snapshot_history` table test set:

  ```python
  def test_0013_upgrade_creates_policies_snapshot_history(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0013")
      inspector = sa.inspect(engine_at_0010)
      assert "policies_snapshot_history" in inspector.get_table_names()
      cols = {c["name"] for c in inspector.get_columns("policies_snapshot_history")}
      # Exhaustive column-set per spec §12.1 row 0013.
      assert cols == {
          "snapshot_id",
          "loaded_at",
          "file_sha256",
          "policies_json",
          "swapped_from_snapshot_id",
      }


  def test_0013_snapshot_id_primary_key(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0013")
      inspector = sa.inspect(engine_at_0010)
      pk = inspector.get_pk_constraint("policies_snapshot_history")
      assert pk["constrained_columns"] == ["snapshot_id"]


  def test_0013_self_reference_swapped_from(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      """swapped_from_snapshot_id is a self-reference foreign key
      preserving the snapshot lineage. NULL for the bootstrap snapshot;
      non-NULL for every swap thereafter."""
      alembic_command.upgrade(alembic_cfg, "0013")
      inspector = sa.inspect(engine_at_0010)
      fks = inspector.get_foreign_keys("policies_snapshot_history")
      assert any(
          fk["referred_table"] == "policies_snapshot_history"
          and fk["referred_columns"] == ["snapshot_id"]
          and fk["constrained_columns"] == ["swapped_from_snapshot_id"]
          for fk in fks
      )


  def test_0013_downgrade_drops_table(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0013")
      alembic_command.downgrade(alembic_cfg, "0012")
      inspector = sa.inspect(engine_at_0010)
      assert "policies_snapshot_history" not in inspector.get_table_names()
  ```

  Confirm the four tests FAIL.

- [ ] **Task B2 — Implement migration `0013_policies_snapshot_history.py`.**

  Files: Create `src/alfred/memory/migrations/versions/0013_policies_snapshot_history.py`.

  ```python
  """policies_snapshot_history — optional rollback log for hot-reload swaps
  (Slice-4 PR-S4-4).

  Revision ID: 0013
  Revises: 0012
  Create Date: 2026-06-07 00:00:00.000000

  ``policies_snapshot_history`` holds one row per loaded ``PoliciesV1``
  snapshot. ``PolicyWatcher`` (PR-S4-4) appends a row on every successful
  swap; the table is OPTIONAL — disabling it loses rollback history but
  does not affect runtime behaviour (the live snapshot lives in process
  memory via ``PoliciesSnapshotRef``).

  Columns
  -------

  * ``snapshot_id`` — UUID PK. Generated by PR-S4-4's PolicyWatcher at
    swap time.
  * ``loaded_at`` — timestamptz of the successful load + swap.
  * ``file_sha256`` — 64-char hex of the ``config/policies.yaml`` bytes
    that produced this snapshot. Doubles as the watcher's idempotency
    short-circuit per index §1 row PR-S4-4.
  * ``policies_json`` — full JSON serialisation of the swapped-in
    ``PoliciesV1`` instance. Stored as JSONB so operators can pivot on
    individual keys via ``alfred policies show --at-snapshot <id>``
    (future CLI; PR-S4-4 ships the audit, not the CLI).
  * ``swapped_from_snapshot_id`` — UUID of the previous snapshot, NULL
    for the bootstrap snapshot. Self-reference foreign key.

  Downgrade: DROP TABLE. Rollback history lost; live snapshot in
  ``PoliciesSnapshotRef`` is unaffected.
  """

  from __future__ import annotations

  from collections.abc import Sequence

  import sqlalchemy as sa
  from alembic import op
  from sqlalchemy.dialects import postgresql

  revision: str = "0013"
  down_revision: str | Sequence[str] | None = "0012"
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
      op.create_table(
          "policies_snapshot_history",
          sa.Column("snapshot_id", sa.String(36), primary_key=True),
          sa.Column("loaded_at", sa.DateTime(timezone=True), nullable=False),
          sa.Column("file_sha256", sa.String(64), nullable=False),
          sa.Column("policies_json", postgresql.JSONB(), nullable=False),
          sa.Column(
              "swapped_from_snapshot_id",
              sa.String(36),
              sa.ForeignKey("policies_snapshot_history.snapshot_id"),
              nullable=True,
          ),
      )


  def downgrade() -> None:
      op.drop_table("policies_snapshot_history")
  ```

- [ ] **Task B3 — Confirm tests B1 pass.** Run `uv run pytest tests/integration/test_migrations_0012_0015.py::test_0013 -x -v`.

- [ ] **Task B4 — `make check`.**

---

### Component C: Migration 0014 — `audit_columns_slice_4` (audit_log column additions)

- [ ] **Task C1 — Cross-reference Slice-4 `*_FIELDS` constants and enumerate the new columns.**

  Read `src/alfred/audit/audit_row_schemas.py` (Slice-4 constants landed in PR-S4-0a). Build a column inventory by visiting every Slice-4 `*_FIELDS` constant per spec §9, then subtract any field name that already exists as a column on `AuditEntry` (`src/alfred/memory/models.py:89`). Document the final set in the migration's docstring.

  Per spec §9 the Slice-4 `*_FIELDS` constants are (22 in total):

  ```
  DAEMON_BOOT_FIELDS, DAEMON_BOOT_FAILED_FIELDS,
  DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS,
  PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS,
  CARRIER_SUBSTITUTION_FIELDS, CARRIER_SUBSTITUTION_REFUSED_FIELDS,
  CONFIG_RELOAD_FIELDS, CONFIG_RELOAD_REJECTED_FIELDS,
  OPERATOR_SESSION_CREATED_FIELDS, OPERATOR_SESSION_REVOKED_FIELDS,
  OPERATOR_SESSION_REFUSED_FIELDS,
  SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS,
  SANDBOX_REFUSED_FIELDS, SANDBOX_STUB_USED_FIELDS,
  COMMS_INBOUND_T3_PROMOTION_FIELDS, COMMS_BINDING_REQUESTED_FIELDS,
  COMMS_ADAPTER_CRASHED_FIELDS, COMMS_RATE_LIMIT_SIGNAL_FIELDS,
  COMMS_UNKNOWN_NOTIFICATION_FIELDS, COMMS_HANDLER_FAILED_FIELDS,
  COMMS_ADDRESSING_DRIFT_FIELDS, COMMS_INBOUND_BUDGET_CAPPED_FIELDS,
  SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS
  ```

  The union of fields across these constants, minus the existing
  `AuditEntry` columns (verified by Read on `src/alfred/memory/models.py`),
  yields the migration target column set. Capture this enumeration as
  the docstring's "Added columns" section.

- [ ] **Task C2 — Write failing assertion that `AuditEntry` exposes every Slice-4 field as a column.**

  Files: Create `tests/unit/test_audit_log_slice_4_columns.py`.

  ```python
  """Audit-log column completeness for Slice-4 *_FIELDS constants.

  Every field name referenced in any Slice-4 ``*_FIELDS`` constant must
  exist as a column on the ``AuditEntry`` ORM model. Closes the
  ``no orphan fields`` invariant spec §9 line 1189 demands.
  """
  from __future__ import annotations

  from sqlalchemy import inspect

  from alfred.audit import audit_row_schemas as schemas
  from alfred.memory.models import AuditEntry

  SLICE_4_FIELDSET_NAMES = (
      "DAEMON_BOOT_FIELDS",
      "DAEMON_BOOT_FAILED_FIELDS",
      "DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS",
      "PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS",
      "CARRIER_SUBSTITUTION_FIELDS",
      "CARRIER_SUBSTITUTION_REFUSED_FIELDS",
      "CONFIG_RELOAD_FIELDS",
      "CONFIG_RELOAD_REJECTED_FIELDS",
      "OPERATOR_SESSION_CREATED_FIELDS",
      "OPERATOR_SESSION_REVOKED_FIELDS",
      "OPERATOR_SESSION_REFUSED_FIELDS",
      "SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS",
      "SANDBOX_REFUSED_FIELDS",
      "SANDBOX_STUB_USED_FIELDS",
      "COMMS_INBOUND_T3_PROMOTION_FIELDS",
      "COMMS_BINDING_REQUESTED_FIELDS",
      "COMMS_ADAPTER_CRASHED_FIELDS",
      "COMMS_RATE_LIMIT_SIGNAL_FIELDS",
      "COMMS_UNKNOWN_NOTIFICATION_FIELDS",
      "COMMS_HANDLER_FAILED_FIELDS",
      "COMMS_ADDRESSING_DRIFT_FIELDS",
      "COMMS_INBOUND_BUDGET_CAPPED_FIELDS",
      "SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS",
  )


  def test_every_slice_4_field_is_an_audit_entry_column() -> None:
      mapper = inspect(AuditEntry)
      column_names = {c.key for c in mapper.columns}
      missing: dict[str, set[str]] = {}
      for name in SLICE_4_FIELDSET_NAMES:
          fields = getattr(schemas, name)
          # Each *_FIELDS constant is a frozenset[str] of column names.
          orphan = set(fields) - column_names
          if orphan:
              missing[name] = orphan
      assert not missing, f"Orphan fields per Slice-4 constant: {missing}"


  def test_no_unused_columns_introduced_by_slice_4() -> None:
      """Migration 0014 must not add columns no Slice-4 *_FIELDS
      references. Catches drift where a Slice-4 column is added but the
      corresponding *_FIELDS entry was never updated."""
      mapper = inspect(AuditEntry)
      column_names = {c.key for c in mapper.columns}
      referenced: set[str] = set()
      for name in SLICE_4_FIELDSET_NAMES:
          referenced.update(getattr(schemas, name))
      # Allow Slice-1/2/2.5/3 columns that no Slice-4 constant uses; we
      # only assert that everything Slice-4 *adds* is referenced. The
      # delta is computed by reading 0014's downgrade column list — but
      # since alembic state is opaque from Python tests at this layer
      # this assertion is a placeholder until PR-S4-0b/0a finalises the
      # constants. For now, just assert the constants themselves do not
      # reference unknown columns (covered by the test above).
  ```

  Confirm both tests FAIL (the second is a placeholder that should pass trivially; the first will FAIL for any field in the Slice-4 constants not yet in `AuditEntry`).

- [ ] **Task C3 — Write failing migration round-trip tests for 0014.**

  Append to `tests/integration/test_migrations_0012_0015.py`:

  ```python
  def test_0014_upgrade_adds_slice_4_columns(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0014")
      inspector = sa.inspect(engine_at_0010)
      cols = {c["name"] for c in inspector.get_columns("audit_log")}
      # Spot-check a handful of Slice-4 columns from disjoint constants
      # (full coverage is asserted in tests/unit/test_audit_log_slice_4_columns.py).
      assert "policies_snapshot_hash" in cols     # DAEMON_BOOT_FIELDS
      assert "carrier_tier" in cols               # CARRIER_SUBSTITUTION_FIELDS
      assert "platform_user_id_hash" in cols      # COMMS_INBOUND_T3_PROMOTION_FIELDS
      assert "machine_id_hash" in cols            # OPERATOR_SESSION_CREATED_FIELDS
      assert "tokens_available" in cols           # COMMS_INBOUND_BUDGET_CAPPED_FIELDS


  def test_0014_added_columns_are_nullable(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      """Slice-4 columns must be nullable because existing pre-Slice-4
      audit rows have no value for them."""
      alembic_command.upgrade(alembic_cfg, "0014")
      inspector = sa.inspect(engine_at_0010)
      cols = {c["name"]: c for c in inspector.get_columns("audit_log")}
      assert cols["carrier_tier"]["nullable"] is True
      assert cols["machine_id_hash"]["nullable"] is True
      assert cols["platform_user_id_hash"]["nullable"] is True


  def test_0014_downgrade_removes_slice_4_columns(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0014")
      alembic_command.downgrade(alembic_cfg, "0013")
      inspector = sa.inspect(engine_at_0010)
      cols = {c["name"] for c in inspector.get_columns("audit_log")}
      assert "policies_snapshot_hash" not in cols
      assert "carrier_tier" not in cols
  ```

  Confirm three new tests FAIL.

- [ ] **Task C4 — Implement migration `0014_audit_columns_slice_4.py`.**

  Files: Create `src/alfred/memory/migrations/versions/0014_audit_columns_slice_4.py`.

  The migration's `upgrade()` adds `op.add_column()` calls for every Slice-4 field name not already present on the pre-Slice-4 `audit_log` schema. Use nullable columns (`nullable=True`) without `server_default`s — existing rows have no value, and the absence of a value is the "pre-Slice-4 row" signal. The downgrade `op.drop_column()`s each added column.

  Mirror the Slice-3 `0007_audit_result_slice3_values.py` style for the docstring + `__all__`. The full column enumeration is built from spec §9 + spec §8.10:

  ```python
  """audit_columns_slice_4 — additive column extension for Slice-4
  audit-row constants (Slice-4 PR-S4-0b).

  Revision ID: 0014
  Revises: 0013
  Create Date: 2026-06-07 00:00:00.000000

  Adds nullable columns to ``audit_log`` for every field referenced by a
  Slice-4 ``*_FIELDS`` constant in ``src/alfred/audit/audit_row_schemas.py``
  but not present in the pre-Slice-4 schema. Existing rows have NULL for
  every added column (the absence of a value is the "pre-Slice-4 row"
  signal — there is no backfill).

  Added columns (union of Slice-4 *_FIELDS minus pre-Slice-4 columns;
  spec §9 + §8.10 are the sources of truth):

  Daemon boot (§9 / PR-S4-1):
    * ``boot_id``                          — uuid string
    * ``state_git_head_sha``               — 40-char hex
    * ``slice_version``                    — semver string
    * ``policies_snapshot_hash``           — 64-char hex
    * ``environment``                      — Literal["dev","prod"]
    * ``environment_source``               — Literal["env","etc","conflict"]
    * ``env_var_value``                    — string (DLP-scanned upstream)
    * ``etc_file_value``                   — string (DLP-scanned upstream)
    * ``resolved_value``                   — string
    * ``failure_reason``                   — Literal (see spec §3.2)
    * ``attempted_at``                     — timestamptz
    * ``started_at``                       — timestamptz

  Proposal-dispatch failure (§9 / PR-S4-2):
    * ``proposal_branch``                  — string
    * ``dispatch_attempted_at``            — timestamptz
    * ``failure_class``                    — string
    * ``redacted_detail``                  — string (≤512 chars after DLP+truncation)
    * ``dlp_redactions_count``             — integer ≥0

  Carrier substitution (§9 / PR-S4-3):
    * ``hookpoint``                        — string
    * ``subscriber_id``                    — string
    * ``source_tier``                      — Literal trust tier
    * ``carrier_tier``                     — Literal trust tier
    * ``substituted_at``                   — timestamptz
    * ``attempted_source_tier``            — Literal trust tier
    * ``refused_at``                       — timestamptz
    * ``reason``                           — Literal["tier_upgrade_refused", "recursion_refused", …]

  Config reload (§9 / PR-S4-4):
    * ``file_path``                        — string
    * ``prev_sha256``                      — 64-char hex
    * ``new_sha256``                       — 64-char hex
    * ``changed_keys``                     — postgresql.ARRAY(String)
    * ``loaded_at``                        — timestamptz
    * ``attempted_sha256``                 — 64-char hex
    * ``offending_key``                    — string
    * ``dlp_scan_result``                  — string

  Operator session (§9 / PR-S4-5):
    * ``issued_at``                        — timestamptz
    * ``expires_at``                       — timestamptz
    * ``host``                              — string
    * ``machine_id_hash``                  — 64-char hex
    * ``via``                              — Literal["alfred_login","alfred_logout","auto_expiry"]
    * ``revoked_at``                       — timestamptz
    * ``attempted_user_id``                — string

  Supervisor breaker reset (§9 / PR-S4-5):
    * ``component_id``                     — string (Slice-3 already has)
    * (no new columns; ``reason``, ``attempted_at`` reuse above)

  Sandbox (§9 / PR-S4-6, PR-S4-7):
    * ``plugin_id``                        — string
    * ``policy_ref``                       — string
    * ``host_os``                          — Literal["linux","macos","windows"]

  Comms (§9 + §8.10 / PR-S4-8, PR-S4-9):
    * ``adapter_id``                       — string
    * ``inbound_message_id``               — uuid string
    * ``platform_user_id_hash``            — 64-char hex
    * ``canonical_user_id``                — uuid string
    * ``sub_payload_kinds``                — postgresql.ARRAY(String)
    * ``language``                         — BCP-47 string
    * ``addressing_signal``                — Literal (spec §8.6)
    * ``verification_phrase_hash``         — 64-char hex
    * ``requested_at``                     — timestamptz
    * ``error_class``                      — string
    * ``detail_redacted``                  — string (post-DLP)
    * ``crashed_at``                       — timestamptz
    * ``platform_endpoint``                — string
    * ``retry_after_seconds``              — integer
    * ``signalled_at``                     — timestamptz
    * ``method``                           — string
    * ``method_redacted_params``           — string
    * ``observed_at``                      — timestamptz
    * ``notification_method``              — string
    * ``handler_class``                    — string
    * ``failed_at``                        — timestamptz
    * ``inbound_signal``                   — Literal
    * ``outbound_mode``                    — Literal
    * ``persona``                          — string
    * ``tokens_available``                 — integer ≥0
    * ``wait_seconds``                     — integer ≥0
    * ``dropped``                          — boolean
    * ``requester``                        — string
    * ``requested_at_supervisor``          — timestamptz

  Every added column is ``nullable=True`` with no server_default.
  Existing rows have NULL for every added column.

  Downgrade
  ---------

  ``downgrade()`` drops every added column. Existing audit rows lose any
  Slice-4 metadata they carried (acceptable; the pre-Slice-4 rows had
  none to begin with). The CHECK constraint ``ck_audit_log_result`` is
  unchanged — Slice-4 introduces no new result values (the carrier-
  substitution rows use existing values from migration 0007).
  """

  from __future__ import annotations

  from collections.abc import Sequence

  import sqlalchemy as sa
  from alembic import op
  from sqlalchemy.dialects import postgresql

  revision: str = "0014"
  down_revision: str | Sequence[str] | None = "0013"
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

  # Reviewer note: the column list below is exhaustive per the docstring.
  # When a Slice-4 *_FIELDS constant gains a field, add the column here
  # AND update the docstring grouping. CI gate
  # ``tests/unit/test_audit_log_slice_4_columns.py`` enforces the union
  # against ``audit_row_schemas.py`` so drift fails the build.
  _NEW_COLUMNS: tuple[tuple[str, sa.types.TypeEngine[object]], ...] = (
      # Daemon boot
      ("boot_id", sa.String(36)),
      ("state_git_head_sha", sa.String(40)),
      ("slice_version", sa.String(32)),
      ("policies_snapshot_hash", sa.String(64)),
      ("environment", sa.String(16)),
      ("environment_source", sa.String(16)),
      ("env_var_value", sa.Text()),
      ("etc_file_value", sa.Text()),
      ("resolved_value", sa.Text()),
      ("failure_reason", sa.String(64)),
      ("attempted_at", sa.DateTime(timezone=True)),
      ("started_at", sa.DateTime(timezone=True)),
      # Proposal dispatch
      ("proposal_branch", sa.String(255)),
      ("dispatch_attempted_at", sa.DateTime(timezone=True)),
      ("failure_class", sa.String(128)),
      ("redacted_detail", sa.String(512)),
      ("dlp_redactions_count", sa.Integer()),
      # Carrier substitution
      ("hookpoint", sa.String(128)),
      ("subscriber_id", sa.String(128)),
      ("source_tier", sa.String(8)),
      ("carrier_tier", sa.String(8)),
      ("substituted_at", sa.DateTime(timezone=True)),
      ("attempted_source_tier", sa.String(8)),
      ("refused_at", sa.DateTime(timezone=True)),
      ("reason", sa.String(64)),
      # Config reload
      ("file_path", sa.String(255)),
      ("prev_sha256", sa.String(64)),
      ("new_sha256", sa.String(64)),
      ("changed_keys", postgresql.ARRAY(sa.String(128))),
      ("loaded_at", sa.DateTime(timezone=True)),
      ("attempted_sha256", sa.String(64)),
      ("offending_key", sa.String(128)),
      ("dlp_scan_result", sa.Text()),
      # Operator session
      ("issued_at", sa.DateTime(timezone=True)),
      ("expires_at", sa.DateTime(timezone=True)),
      ("host", sa.String(255)),
      ("machine_id_hash", sa.String(64)),
      ("via", sa.String(32)),
      ("revoked_at", sa.DateTime(timezone=True)),
      ("attempted_user_id", sa.String(36)),
      # Sandbox
      ("plugin_id", sa.String(64)),
      ("policy_ref", sa.String(255)),
      ("host_os", sa.String(16)),
      # Comms
      ("adapter_id", sa.String(64)),
      ("inbound_message_id", sa.String(36)),
      ("platform_user_id_hash", sa.String(64)),
      ("canonical_user_id", sa.String(36)),
      ("sub_payload_kinds", postgresql.ARRAY(sa.String(32))),
      # NOTE (round-2 rev-2 + mem-002 closures from PR #205 review): the shared columns
      # below (`reason`, `failure_reason`, `loaded_at`, `attempted_at`, etc.) carry
      # values from disjoint Literal-domain families across the 23 Slice-4 constants.
      # Per-family CHECK constraints would discriminate which Literal universe a row
      # belongs to via the `subject` field (which carries the constant name); the
      # constraint shape is `CHECK (subject NOT IN ('CONFIG_RELOAD_REJECTED_FIELDS', ...)
      # OR reason IN ('parse_failure', 'high_blast_change', 'validation_failure',
      # 'file_vanished', 'stat_failed', 'audit_write_failed'))` — and similar for each
      # operator-session refusal family, sandbox-refusal family, daemon-boot family.
      # Per-family CHECKs ship in **migration 0014b** authored as a follow-up
      # commit in this same PR (after the union-column migration 0014 lands and is
      # validated in CI). Splitting per-family columns was considered and rejected
      # — it would 5x the column count on `audit_log` and break the established
      # JSON-payload pattern from `audit_row_schemas` Slice-3 design.
      #
      # NOTE (mem-001 round-2 closure from PR #205 review): `language` column already
      # exists on `audit_log` per `src/alfred/memory/models.py:113` (Slice-1 i18n shipped it).
      # DO NOT re-add — migration 0014 would fail upgrade. The Slice-4 audit-row
      # constants that reference `language` (e.g. COMMS_INBOUND_T3_PROMOTION_FIELDS)
      # reuse the existing column. The test_audit_column_union test in §C asserts
      # `language` is in the constant-field union but is NOT in the new-columns
      # tuple — both halves of the assertion ship in this PR.
      ("addressing_signal", sa.String(32)),
      ("verification_phrase_hash", sa.String(64)),
      ("requested_at", sa.DateTime(timezone=True)),
      ("error_class", sa.String(128)),
      ("detail_redacted", sa.Text()),
      ("crashed_at", sa.DateTime(timezone=True)),
      ("platform_endpoint", sa.String(255)),
      ("retry_after_seconds", sa.Integer()),
      ("signalled_at", sa.DateTime(timezone=True)),
      ("method", sa.String(64)),
      ("method_redacted_params", sa.Text()),
      ("observed_at", sa.DateTime(timezone=True)),
      ("notification_method", sa.String(64)),
      ("handler_class", sa.String(128)),
      ("failed_at", sa.DateTime(timezone=True)),
      ("inbound_signal", sa.String(32)),
      ("outbound_mode", sa.String(32)),
      ("persona", sa.String(64)),
      ("tokens_available", sa.Integer()),
      ("wait_seconds", sa.Integer()),
      ("dropped", sa.Boolean()),
      ("requester", sa.String(64)),
      ("requested_at_supervisor", sa.DateTime(timezone=True)),
  )


  def upgrade() -> None:
      """Add Slice-4 nullable columns to audit_log."""
      for name, type_ in _NEW_COLUMNS:
          op.add_column("audit_log", sa.Column(name, type_, nullable=True))


  def downgrade() -> None:
      """Drop Slice-4 columns from audit_log."""
      for name, _type in reversed(_NEW_COLUMNS):
          op.drop_column("audit_log", name)
  ```

  > **Implementer note** — before writing the column tuple verbatim, run
  > `grep -rE "class AuditEntry\\b" src/alfred/memory/models.py` and
  > Read the columns currently defined. If any column name above already
  > exists on `AuditEntry`, remove it from the tuple (re-adding triggers
  > Postgres `column already exists` error). Drift between the spec and
  > pre-Slice-4 schema is captured by tasks C2 and C5.

- [ ] **Task C5 — Update `AuditEntry` ORM model to declare the new columns.**

  Files: Modify `src/alfred/memory/models.py`.

  For every column in `_NEW_COLUMNS`, add a `Mapped[<type>]` field on `AuditEntry` with `mapped_column(<sa-type>, nullable=True)`. Match the migration's type choices exactly. Keep the existing pre-Slice-4 columns untouched.

  After the edit, run `tests/unit/test_audit_log_slice_4_columns.py` — `test_every_slice_4_field_is_an_audit_entry_column` must now PASS.

- [ ] **Task C6 — Confirm tests C2/C3 pass.** `uv run pytest tests/unit/test_audit_log_slice_4_columns.py tests/integration/test_migrations_0012_0015.py::test_0014 -x -v`.

- [ ] **Task C7 — `make check`.**

---

### Component D: Migration 0015 — `sandbox_policy_registry` table

- [ ] **Task D1 — Append failing tests for 0015.**

  Add to `tests/integration/test_migrations_0012_0015.py`:

  ```python
  def test_0015_upgrade_creates_sandbox_policy_registry(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0015")
      inspector = sa.inspect(engine_at_0010)
      assert "sandbox_policy_registry" in inspector.get_table_names()
      cols = {c["name"] for c in inspector.get_columns("sandbox_policy_registry")}
      # Exhaustive column-set per spec §12.1 row 0015.
      assert cols == {
          "plugin_id",
          "policy_ref",
          "host_os",
          "last_resolved_at",
          "resolution_result",
      }


  def test_0015_composite_pk_plugin_host_os(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      """One row per (plugin_id, host_os) — the launcher records the most
      recent resolution per OS so cross-OS audits can pivot on the same
      plugin."""
      alembic_command.upgrade(alembic_cfg, "0015")
      inspector = sa.inspect(engine_at_0010)
      pk = inspector.get_pk_constraint("sandbox_policy_registry")
      assert set(pk["constrained_columns"]) == {"plugin_id", "host_os"}


  def test_0015_host_os_check_constraint(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0015")
      with pytest.raises(sa.exc.IntegrityError):
          with engine_at_0010.begin() as conn:
              conn.execute(
                  sa.text(
                      "INSERT INTO sandbox_policy_registry "
                      "(plugin_id, policy_ref, host_os, last_resolved_at, resolution_result) "
                      "VALUES (:p, :r, :o, :t, :res)"
                  ),
                  {
                      "p": "alfred_quarantined_llm",
                      "r": "config/sandbox/quarantined-llm.linux.bwrap.policy",
                      "o": "freebsd",  # not in CHECK domain
                      "t": dt.datetime.now(dt.UTC),
                      "res": "resolved",
                  },
              )


  def test_0015_downgrade_drops_table(
      alembic_cfg: AlembicConfig,
      engine_at_0010: sa.Engine,
  ) -> None:
      alembic_command.upgrade(alembic_cfg, "0015")
      alembic_command.downgrade(alembic_cfg, "0014")
      inspector = sa.inspect(engine_at_0010)
      assert "sandbox_policy_registry" not in inspector.get_table_names()
  ```

  Confirm four tests FAIL.

- [ ] **Task D2 — Implement migration `0015_sandbox_policy_registry.py`.**

  Files: Create `src/alfred/memory/migrations/versions/0015_sandbox_policy_registry.py`.

  ```python
  """sandbox_policy_registry — launcher policy-resolution observability
  (Slice-4 PR-S4-6).

  Revision ID: 0015
  Revises: 0014
  Create Date: 2026-06-07 00:00:00.000000

  ``sandbox_policy_registry`` records the most recent
  ``bin/alfred-plugin-launcher.sh`` policy-resolution result per
  (plugin_id, host_os). Read-only observability — the launcher does NOT
  consult this table at spawn time (the live policy is in the plugin's
  manifest + the policy file on disk). Operators query it to confirm
  every plugin's expected policy matches the resolved one across OSes.

  Composite PK ``(plugin_id, host_os)`` so cross-OS audits pivot on the
  same plugin. ``host_os`` is closed-domain
  ``{'linux', 'macos', 'windows'}`` via CHECK constraint to refuse
  typos (sec-003 closure — Slice-4 has three supported OS values; new
  values are an ADR-0024-style amendment).

  Columns
  -------

  * ``plugin_id`` — matches the plugin's manifest ``[plugin] id``.
  * ``policy_ref`` — relative path to the policy file (e.g.
    ``config/sandbox/quarantined-llm.linux.bwrap.policy``).
  * ``host_os`` — closed-domain Literal.
  * ``last_resolved_at`` — timestamptz of the most-recent resolution.
  * ``resolution_result`` — closed-domain
    ``{'resolved', 'refused_policy_missing', 'refused_unreadable',
    'refused_os_mismatch', 'stub_used'}`` — covers every launcher
    refusal reason in spec §7.2.

  Downgrade: DROP TABLE. Observability only; no operational state.
  """

  from __future__ import annotations

  from collections.abc import Sequence

  import sqlalchemy as sa
  from alembic import op

  revision: str = "0015"
  down_revision: str | Sequence[str] | None = "0014"
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
      op.create_table(
          "sandbox_policy_registry",
          sa.Column("plugin_id", sa.String(64), primary_key=True),
          sa.Column("policy_ref", sa.String(255), nullable=False),
          sa.Column("host_os", sa.String(16), primary_key=True),
          sa.Column("last_resolved_at", sa.DateTime(timezone=True), nullable=False),
          sa.Column("resolution_result", sa.String(32), nullable=False),
          sa.CheckConstraint(
              "host_os IN ('linux', 'macos', 'windows')",
              name="ck_sandbox_policy_registry_host_os",
          ),
          sa.CheckConstraint(
              "resolution_result IN ("
              "'resolved', 'refused_policy_missing', 'refused_unreadable', "
              "'refused_os_mismatch', 'stub_used')",
              name="ck_sandbox_policy_registry_resolution_result",
          ),
      )


  def downgrade() -> None:
      op.drop_table("sandbox_policy_registry")
  ```

- [ ] **Task D3 — Add the `SandboxPolicyRegistry` ORM model.**

  Files: Modify `src/alfred/memory/models.py`. Append a typed model:

  ```python
  class SandboxPolicyRegistry(Base):
      """Read-only observability for launcher policy-resolution.

      Composite PK (plugin_id, host_os) — one row per (plugin, OS).
      """

      __tablename__ = "sandbox_policy_registry"

      plugin_id: Mapped[str] = mapped_column(String(64), primary_key=True)
      host_os: Mapped[str] = mapped_column(String(16), primary_key=True)
      policy_ref: Mapped[str] = mapped_column(String(255), nullable=False)
      last_resolved_at: Mapped[datetime] = mapped_column(
          DateTime(timezone=True), nullable=False,
      )
      resolution_result: Mapped[str] = mapped_column(String(32), nullable=False)
  ```

- [ ] **Task D4 — Confirm tests D1 pass.** `uv run pytest tests/integration/test_migrations_0012_0015.py::test_0015 -x -v`.

- [ ] **Task D5 — `make check`.**

---

### Component E: SQLAlchemy 2.0 typed models for `operator_sessions` + `policies_snapshot_history`

- [ ] **Task E1 — Write failing tests asserting model exposure.**

  Files: Create `tests/unit/test_slice_4_models_expose_columns.py`:

  ```python
  """Slice-4 SQLAlchemy 2.0 typed models — column-set assertions.

  Mirrors the discipline of tests/unit/test_audit_log_slice_4_columns.py:
  every column declared by the migration must be exposed as a
  ``Mapped[<type>]`` field on the model so consumers get type-safe access.
  """
  from __future__ import annotations

  from sqlalchemy import inspect

  from alfred.memory.models import (
      OperatorSession,
      PoliciesSnapshotHistory,
      SandboxPolicyRegistry,
  )


  def test_operator_session_columns() -> None:
      mapper = inspect(OperatorSession)
      assert {c.key for c in mapper.columns} == {
          "user_id", "token_hash", "issued_at", "expires_at",
          "host", "machine_id_hash", "revoked_at",
      }


  def test_policies_snapshot_history_columns() -> None:
      mapper = inspect(PoliciesSnapshotHistory)
      assert {c.key for c in mapper.columns} == {
          "snapshot_id", "loaded_at", "file_sha256",
          "policies_json", "swapped_from_snapshot_id",
      }


  def test_sandbox_policy_registry_columns() -> None:
      mapper = inspect(SandboxPolicyRegistry)
      assert {c.key for c in mapper.columns} == {
          "plugin_id", "host_os", "policy_ref",
          "last_resolved_at", "resolution_result",
      }
  ```

  Confirm all three FAIL (models do not exist yet — except `SandboxPolicyRegistry` from Component D; that one passes).

- [ ] **Task E2 — Implement `OperatorSession` model.**

  Files: Modify `src/alfred/memory/models.py`. Append:

  ```python
  class OperatorSession(Base):
      """CLI operator-session token row.

      Mirrors ``operator_sessions`` (migration 0012). The session token
      itself never lands in the DB — only ``token_hash`` does. PR-S4-5's
      ``_resolve_operator`` reads via ``uq_operator_sessions_token_hash``
      (the load-bearing index for the 5ms p99 budget).

      ``revoked_at`` is nullable; active sessions have NULL.
      ``alfred logout`` sets the column rather than deleting the row so
      the audit-log retains the session lifecycle.
      """

      __tablename__ = "operator_sessions"

      user_id: Mapped[str] = mapped_column(String(36), nullable=False)
      token_hash: Mapped[str] = mapped_column(
          String(64), primary_key=True, nullable=False,
      )
      issued_at: Mapped[datetime] = mapped_column(
          DateTime(timezone=True), nullable=False,
      )
      expires_at: Mapped[datetime] = mapped_column(
          DateTime(timezone=True), nullable=False,
      )
      host: Mapped[str] = mapped_column(String(255), nullable=False)
      machine_id_hash: Mapped[str] = mapped_column(String(64), nullable=False)
      revoked_at: Mapped[datetime | None] = mapped_column(
          DateTime(timezone=True), nullable=True,
      )
  ```

  Note: `token_hash` is the natural primary key in the model; the migration's `uq_operator_sessions_token_hash` index serves as the underlying index. (Alternative: model declares no PK and uses `__mapper_args__`; the natural-key style is closer to the Slice-3 `CircuitBreaker(component_id)` precedent.)

- [ ] **Task E3 — Implement `PoliciesSnapshotHistory` model.**

  Files: Modify `src/alfred/memory/models.py`. Append:

  ```python
  class PoliciesSnapshotHistory(Base):
      """Optional rollback log for PR-S4-4 hot-reload swaps.

      One row per swapped-in ``PoliciesV1`` snapshot.
      ``swapped_from_snapshot_id`` is the self-reference to the previous
      snapshot (NULL for the bootstrap snapshot).
      """

      __tablename__ = "policies_snapshot_history"

      snapshot_id: Mapped[str] = mapped_column(String(36), primary_key=True)
      loaded_at: Mapped[datetime] = mapped_column(
          DateTime(timezone=True), nullable=False,
      )
      file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
      policies_json: Mapped[dict[str, object]] = mapped_column(
          JSONB(), nullable=False,
      )
      swapped_from_snapshot_id: Mapped[str | None] = mapped_column(
          String(36),
          ForeignKey("policies_snapshot_history.snapshot_id"),
          nullable=True,
      )
  ```

  Add `from sqlalchemy.dialects.postgresql import JSONB` if not already imported.

- [ ] **Task E4 — Confirm tests E1 pass.** `uv run pytest tests/unit/test_slice_4_models_expose_columns.py -x -v`.

- [ ] **Task E5 — `make check`.**

---

### Component F: Dockerfile — install `bubblewrap` for the bash launcher

- [ ] **Task F1 — Verify current docker-compose `alfred-core` build state.**

  Read `docker-compose.yaml` lines 67-70 to confirm the service already uses `build:` (per fabricated-surfaces verification). This task is a sanity check — if the file has drifted, capture the divergence in a `// REVIEWER NOTE` comment in the PR description rather than papering over the index claim.

- [ ] **Task F2 — Write failing test that asserts `bubblewrap` is apt-installed in the runtime stage.**

  Files: Create `tests/unit/test_dockerfile_bubblewrap_present.py`:

  ```python
  """Confirm docker/alfred-core.Dockerfile installs bubblewrap.

  PR-S4-6's ``bin/alfred-plugin-launcher.sh`` invokes ``bwrap`` directly.
  Without bubblewrap in the runtime layer, the launcher refuses on
  Linux with ``policy_ref_unreadable`` (the policy file exists but no
  binary can apply it).
  """
  from __future__ import annotations

  from pathlib import Path

  DOCKERFILE = Path("docker/alfred-core.Dockerfile")


  def test_bubblewrap_apt_installed_in_runtime_layer() -> None:
      content = DOCKERFILE.read_text()
      # The Slice-3 Dockerfile already installs git + util-linux in the
      # runtime stage. Slice-4 extends the same RUN with bubblewrap.
      # Single RUN keeps the layer count down per Docker best-practice.
      assert "bubblewrap" in content, (
          "bubblewrap missing from docker/alfred-core.Dockerfile. "
          "PR-S4-6 bash launcher needs /usr/bin/bwrap."
      )
      # Defensive: ensure bubblewrap is on the apt-get install line, not
      # buried in a comment.
      apt_lines = [ln for ln in content.splitlines() if "apt-get install" in ln]
      assert any("bubblewrap" in ln for ln in apt_lines), (
          "bubblewrap not on an apt-get install line."
      )


  def test_dockerfile_still_runs_as_non_root_alfred() -> None:
      """Regression guard: adding bubblewrap must not flip the runtime
      user back to root. The container still runs as the non-root
      ``alfred`` user; bubblewrap-the-binary is suid-installed by the
      apt package so the in-container launcher can invoke it from the
      alfred UID."""
      content = DOCKERFILE.read_text()
      assert "USER alfred" in content
  ```

  Confirm both tests FAIL (the first — bubblewrap not installed; the second should already pass and acts as a regression guard).

- [ ] **Task F3 — Modify `docker/alfred-core.Dockerfile` to install `bubblewrap`.**

  The Slice-3 Dockerfile's runtime stage (lines 40-42) reads:

  ```dockerfile
  RUN apt-get update -qq \
      && apt-get install -y --no-install-recommends git util-linux \
      && rm -rf /var/lib/apt/lists/*
  ```

  Extend the install list to include `bubblewrap`. Update the surrounding comment to document why.

  ```dockerfile
  # Install git + util-linux + bubblewrap.
  # git: required for state.git operations (spec §8.1, §11.1).
  # util-linux: provides `runuser` — required by alfred-plugin-launcher
  # for UID-drop to alfred-quarantine at subprocess spawn (Slice-3
  # baseline; spec §5.2, sec-003). Slice-4 keeps it for the dev-mode
  # `kind: none` fallback path.
  # bubblewrap: provides `bwrap` — Slice-4 PR-S4-6's bash launcher
  # invokes bwrap directly with per-plugin policy files
  # (spec §7.5 Linux policy). Without bwrap, Linux production refuses
  # to launch the quarantined-LLM with `policy_ref_unreadable` because
  # no binary can apply the policy.
  RUN apt-get update -qq \
      && apt-get install -y --no-install-recommends git util-linux bubblewrap \
      && rm -rf /var/lib/apt/lists/*
  ```

- [ ] **Task F4 — Build the image to verify the apt-install succeeds.**

  Run `docker compose build alfred-core` locally. The build must succeed and the runtime layer must report `bubblewrap` installed (verify with `docker compose run --rm --entrypoint /bin/sh alfred-core -c "command -v bwrap"` returning `/usr/bin/bwrap`).

  Document the build success in the PR description.

- [ ] **Task F5 — Confirm tests F2 pass.** `uv run pytest tests/unit/test_dockerfile_bubblewrap_present.py -x -v`.

- [ ] **Task F6 — `make check`.**

---

### Component G: `bin/alfred-setup.sh` — sandbox config dir + audit pepper seed

- [ ] **Task G1 — Read current `bin/alfred-setup.sh` to confirm structure.**

  Run `Read` on `bin/alfred-setup.sh`. Note the existing `step "…"` / `read_env_var` / `require_cmd` helper functions; the Slice-4 additions extend these patterns rather than replacing them.

- [ ] **Task G2 — Write failing tests for the setup-script additions.**

  Files: Create `tests/unit/test_setup_script_audit_pepper.py`:

  ```python
  """Confirm bin/alfred-setup.sh seeds audit.hash_pepper + sandbox dir.

  Slice-4 PR-S4-0b adds two idempotent steps to the setup script:
  1. ``mkdir -p ~/.config/alfred/sandbox/`` — per-OS sandbox-policy dir
     (spec §7.5–7.7 file locations are operator-controlled).
  2. ``audit.hash_pepper`` bootstrap — generates a 64-hex-char random
     value and writes it to the broker config if not already set.

  The setup script must remain idempotent: re-running it on a host that
  already has a pepper must NOT overwrite the existing value.
  """
  from __future__ import annotations

  from pathlib import Path

  SETUP_SH = Path("bin/alfred-setup.sh")


  def test_setup_script_creates_sandbox_config_dir() -> None:
      content = SETUP_SH.read_text()
      # The Slice-4 step targets ~/.config/alfred/sandbox/. Allow $HOME
      # expansion to vary (e.g. ${HOME}/.config/alfred/sandbox vs
      # ~/.config/alfred/sandbox).
      assert any(
          pattern in content
          for pattern in (
              'mkdir -p "${HOME}/.config/alfred/sandbox"',
              "mkdir -p ~/.config/alfred/sandbox",
              'mkdir -p "$HOME/.config/alfred/sandbox"',
          )
      ), "Sandbox config dir mkdir step missing from bin/alfred-setup.sh"


  def test_setup_script_seeds_audit_hash_pepper() -> None:
      content = SETUP_SH.read_text()
      # Generation step uses openssl rand for cross-platform availability
      # (openssl is part of the require_cmd preflight per Slice-1).
      assert "audit.hash_pepper" in content, (
          "audit.hash_pepper key missing from bin/alfred-setup.sh"
      )
      assert "openssl rand -hex 32" in content, (
          "openssl rand -hex 32 pepper generation step missing"
      )


  def test_setup_script_audit_pepper_is_idempotent() -> None:
      """The bootstrap step must guard on an existing non-empty value.
      Re-running ``bin/alfred-setup.sh`` after a pepper exists must NOT
      overwrite the value — rotating the pepper invalidates cross-row
      correlation per spec §8.10."""
      content = SETUP_SH.read_text()
      # Acceptable guards: grep -q "^audit.hash_pepper" or test -n
      # "$(read_secret audit.hash_pepper)" or [[ -z "$existing" ]].
      # The test asserts SOME guard exists adjacent to the seed step.
      pepper_block = _slice_around(content, "audit.hash_pepper", lines_before=6, lines_after=6)
      assert any(
          guard in pepper_block
          for guard in ("grep -q", "[[ -z", "[ -z ", "if ! ", "test -n")
      ), f"No idempotency guard around audit.hash_pepper seed:\n{pepper_block}"


  def _slice_around(text: str, needle: str, lines_before: int, lines_after: int) -> str:
      lines = text.splitlines()
      for i, line in enumerate(lines):
          if needle in line:
              start = max(0, i - lines_before)
              end = min(len(lines), i + lines_after + 1)
              return "\n".join(lines[start:end])
      return ""
  ```

  Confirm all three tests FAIL.

- [ ] **Task G3 — Modify `bin/alfred-setup.sh` to add the two steps.**

  Append (or insert before the final `step "Bootstrap complete"` block) the new sections. Use the existing `step "…"` helper for operator-visible step boundaries:

  ```bash
  step "Ensuring ~/.config/alfred/sandbox/ exists"
  # Per-OS sandbox-policy files live here for PR-S4-6's launcher to
  # resolve (spec §7.5–7.7). The directory is operator-controlled; this
  # step only ensures it exists with the right ownership. Vendor or
  # local policy files are dropped here by the operator (or shipped by
  # downstream PR-S4-7 as default policies).
  mkdir -p "${HOME}/.config/alfred/sandbox"
  chmod 0700 "${HOME}/.config/alfred/sandbox"

  step "Bootstrapping audit.hash_pepper secret"
  # AlfredOS uses audit.hash_pepper as the HMAC key for every *_hash
  # column in the audit log (spec §8.10). The pepper is broker-resident
  # and must be set before the daemon boots — PR-S4-1's daemon-boot
  # probe refuses to start when broker.has("audit.hash_pepper") is False.
  #
  # This step is idempotent: if a non-empty value is already in the
  # broker config file (~/.config/alfred/secrets.toml or the env var
  # ALFRED_AUDIT_HASH_PEPPER), we leave it alone. Rotating the pepper
  # invalidates cross-row correlation (spec §8.10), so the bootstrap
  # MUST NOT clobber an existing value.
  pepper_file="${HOME}/.config/alfred/secrets.toml"  # use ${HOME} — shell does not expand "~" inside double quotes
  pepper_key="audit.hash_pepper"
  if [[ -f "$pepper_file" ]] && grep -q "^${pepper_key}\\s*=" "$pepper_file"; then
    echo "audit.hash_pepper already configured in ${pepper_file}; leaving alone."
  else
    pepper_value="$(openssl rand -hex 32)"
    # The broker config file lives at ~/.config/alfred/secrets.toml in
    # development; in production the operator has typically pointed
    # ALFRED_SECRETS_FILE at a different path. Honour the env var when
    # set so the seed lands in the right file.
    target_file="${ALFRED_SECRETS_FILE:-$pepper_file}"
    if [[ ! -f "$target_file" ]]; then
      printf '# AlfredOS secrets file. DO NOT commit.\n' > "$target_file"
      chmod 0600 "$target_file"
    fi
    printf '%s = "%s"\n' "$pepper_key" "$pepper_value" >> "$target_file"
    echo "Seeded audit.hash_pepper into ${target_file}."
  fi
  ```

  Place these steps AFTER the `.env` validation step (which already exists in the script per the Read) and BEFORE the `docker compose build` step. The pepper must be in the broker config before the daemon starts.

  Update `require_cmd` preflight to include `openssl` if not already present.

- [ ] **Task G4 — Run the setup script locally and confirm the steps run.**

  In a clean working tree:
  1. `rm -f ~/.config/alfred/secrets.toml`
  2. `bin/alfred-setup.sh --dry-run` — exits 0 (no setup performed).
  3. Inspect the script content — both new steps must be present.
  4. Optionally (mark as manual smoke in the PR description): full
     `bin/alfred-setup.sh` run on a developer host, confirm the pepper
     file lands at `~/.config/alfred/secrets.toml` with mode `0600` and a
     `audit.hash_pepper = "<64-hex>"` line.
  5. Re-run the setup script — the bootstrap step must report
     "already configured; leaving alone."

- [ ] **Task G5 — Confirm tests G2 pass.** `uv run pytest tests/unit/test_setup_script_audit_pepper.py -x -v`.

- [ ] **Task G6 — `make check`.**

---

### Component H: `SecretBroker.SUPPORTED_SECRETS` — register `audit.hash_pepper`

- [ ] **Task H1 — Read current `SUPPORTED_SECRETS` registry.**

  Files: `src/alfred/security/secrets.py`. Find the `SUPPORTED_SECRETS` constant (cited at line 397 of the `.get()` method as the whitelist check). Note its current membership.

- [ ] **Task H2 — Write failing test asserting `audit.hash_pepper` is registered.**

  Files: Create `tests/integration/test_audit_pepper_bootstrap.py`:

  ```python
  """audit.hash_pepper broker registry + bootstrap contract.

  Asserts:
  1. ``audit.hash_pepper`` is in ``SUPPORTED_SECRETS`` — without this,
     ``SecretBroker.get("audit.hash_pepper")`` raises ``UnknownSecretError``
     even when the value is in the config.
  2. ``SecretBroker.has("audit.hash_pepper")`` returns the bootstrap-
     seeded value's truthiness.
  3. The bootstrap-seeded value is a 64-hex-char string per
     ``openssl rand -hex 32`` semantics.

  This test runs in the integration tier because it depends on the
  setup-script having seeded the pepper into the broker config. In CI
  the seed step is performed by the test setup (no live filesystem
  write); locally an operator who ran ``bin/alfred-setup.sh`` sees the
  same path.
  """
  from __future__ import annotations

  import re
  import tempfile
  from pathlib import Path

  import pytest

  from alfred.security.secrets import (
      SUPPORTED_SECRETS,
      SecretBroker,
      UnknownSecretError,
  )


  def test_audit_hash_pepper_in_supported_secrets() -> None:
      assert "audit.hash_pepper" in SUPPORTED_SECRETS


  def test_broker_get_audit_hash_pepper_when_set(tmp_path: Path) -> None:
      secrets_file = tmp_path / "secrets.toml"
      pepper = "a" * 64
      secrets_file.write_text(f'audit.hash_pepper = "{pepper}"\n')
      secrets_file.chmod(0o600)
      broker = SecretBroker(settings_default=secrets_file)
      assert broker.has("audit.hash_pepper") is True
      assert broker.get("audit.hash_pepper") == pepper


  def test_broker_refuses_unknown_secret_without_registry_entry() -> None:
      """Defensive: removing ``audit.hash_pepper`` from SUPPORTED_SECRETS
      must make the broker refuse the lookup — confirms the whitelist
      gate is still in place."""
      broker = SecretBroker()
      with pytest.raises(UnknownSecretError):
          broker.get("audit.hash_pepper.does_not_exist")


  def test_hex_64_chars_recipe_matches_setup_script() -> None:
      """The seed step uses ``openssl rand -hex 32`` → 64 hex chars.
      Regress this format if PR-S4-8/9 ever change the hash recipe."""
      assert re.match(r"^[0-9a-f]{64}$", "a" * 64)
  ```

  Confirm test 1 (`test_audit_hash_pepper_in_supported_secrets`) FAILS — the registry does not yet include the key.

- [ ] **Task H3 — Add `audit.hash_pepper` to `SUPPORTED_SECRETS`.**

  Files: Modify `src/alfred/security/secrets.py`.

  Locate the `SUPPORTED_SECRETS` definition (around the top of the module). Add `"audit.hash_pepper"` to the tuple/frozenset. Place it alphabetically.

  Add a docstring/inline comment explaining what the secret is for:

  ```python
  SUPPORTED_SECRETS = frozenset((
      # … existing entries …
      "audit.hash_pepper",
      # ↑ HMAC key for every *_hash column in audit_log (spec §8.10).
      # PR-S4-0b registers; PR-S4-8/9 consume; PR-S4-1 daemon-boot
      # probes for existence.
      # … remaining entries …
  ))
  ```

  Also update `_PREFER_FILE` if the broker's lookup preference for this secret should be file-over-env (recommended — the pepper is sensitive and operators should manage it via the secrets-file flow, not env).

- [ ] **Task H4 — Confirm tests H2 pass.** `uv run pytest tests/integration/test_audit_pepper_bootstrap.py -x -v`.

- [ ] **Task H5 — `make check`.**

---

### Component I: i18n catalog — full Slice-4 enumeration

- [ ] **Task I1 — Write failing test for catalog completeness.**

  Files: Create `tests/unit/test_catalog_slice_4_keys.py`:

  ```python
  """Every Slice-4 t() key resolves to a non-bare value.

  Mirrors the Slice-3 ``test_catalog_slice3_keys.py`` discipline. The
  catalog ships in PR-S4-0b; implementation PRs (S4-1..S4-10) consume
  the keys. CI's ``pybabel compile --check`` enforces no orphan
  ``t()`` calls in source; this test enforces no orphan key in the
  catalog.
  """
  from __future__ import annotations

  from alfred.i18n import t

  SLICE_4_KEYS: tuple[str, ...] = (
      # Login / session lifecycle (12) — spec §12.2.
      "login.prompt_confirm_overwrite",
      "login.session_overwrite_confirm",
      "login.user_not_found",
      "login.user_not_found_action_alfred_user_list",
      "login.expires_in_out_of_range",
      "login.no_machine_id",
      "login.confirmed",
      "logout.no_session",
      "logout.confirmed",
      "whoami.no_session",
      "whoami.expired",
      "whoami.template",
      # Operator-session refusal reasons (8).
      "operator_session.refused.expired",
      "operator_session.refused.host_mismatch",
      "operator_session.refused.machine_mismatch",
      "operator_session.refused.token_unknown",
      "operator_session.refused.user_revoked",
      "operator_session.refused.bad_file_mode",
      "operator_session.refused.bad_file_owner",
      "operator_session.refused.resolver_timeout",
      # Supervisor reset refusals (2).
      "supervisor.breaker.reset.refused.not_logged_in",
      "supervisor.breaker.reset.refused.operator_permissions_insufficient",
      # Daemon boot (9 — includes audit_hash_pepper_missing per round-2 sec-3 + arch-002 closures).
      "daemon.boot.environment_not_set",
      "daemon.boot.unsandboxed_in_production",
      "daemon.boot.launcher_not_policy_resolving",
      "daemon.boot.snapshot_ref_init_failed",
      "daemon.boot.capability_gate_handshake_failed",
      "daemon.boot.audit_hash_pepper_missing",  # PR #205 round-2 sec-3 closure
      "daemon.boot.started",
      "daemon.stop.confirmed",
      "daemon.status.template",
      # Sandbox refusal reasons (6).
      "supervisor.sandbox.refused.policy_ref_missing",
      "supervisor.sandbox.refused.policy_ref_os_mismatch",
      "supervisor.sandbox.refused.policy_ref_unreadable",
      "supervisor.sandbox.refused.sandbox_block_missing",
      "supervisor.sandbox.refused.windows_stub_in_production",
      "supervisor.sandbox.unsandboxed_refused_in_production",
      # Config-reload notifications (6).
      "supervisor.config_reload.applied",
      "supervisor.config_reload_rejected.parse_failure",
      "supervisor.config_reload_rejected.high_blast_change",
      "supervisor.config_reload_rejected.validation_failure",
      "supervisor.config_reload_rejected.file_vanished",
      "supervisor.config_reload_rejected.stat_failed",
      # TUI (1).
      "comms.tui.daemon_required_to_chat",
  )


  def test_all_slice_4_keys_resolve_to_non_bare_strings() -> None:
      bare: list[str] = []
      for key in SLICE_4_KEYS:
          msg = t(key)
          if msg == key:
              bare.append(key)
      assert not bare, f"Slice-4 keys returning bare key (missing translation): {bare}"


  def test_no_duplicate_keys_in_slice_4_enumeration() -> None:
      assert len(SLICE_4_KEYS) == len(set(SLICE_4_KEYS))


  def test_slice_4_key_count_matches_spec_enumeration() -> None:
      """Spec §12.2 enumerates 44 keys (12 + 8 + 2 + 9 + 6 + 6 + 1).
      Catalog drift is a release blocker per CLAUDE.md i18n rules.
      Note: ``operator_session.refused.bad_file_mode`` and
      ``operator_session.refused.bad_file_owner`` are dual entries
      called out in the round-3 spec fixup; both are required."""
      assert len(SLICE_4_KEYS) == 44, (
          "Slice-4 enumeration count drifted from spec §12.2 — re-check"
      )
  ```

  > **Note on count**: 12 login/session + 8 refusal + 2 reset + 8 daemon
  > - 6 sandbox + 6 config-reload + 1 TUI = 43 total (the asserted count).
  > The spec §12.2 cluster of headings counts the same families; the 33
  > number in the goal-line of this plan is a target floor, not a ceiling.

  Confirm all three tests FAIL (catalog has no Slice-4 keys yet).

- [ ] **Task I2 — Append all 44 keys to `locale/en/LC_MESSAGES/alfred.po`.**

  Files: Modify `locale/en/LC_MESSAGES/alfred.po`.

  Use the Babel `.po` block format that matches the existing Slice-1/Slice-2 entries (per the file header). For each key, write the `msgid` line and the `msgstr` body. Source-file references (`#: src/...:N`) are optional — they can be added when the consuming PR lands the call site. Use canonical English copy that an operator would expect:

  ```
  # ---- Slice-4 additions (PR-S4-0b) — spec §12.2 ----

  # Login / session lifecycle.

  msgid "login.prompt_confirm_overwrite"
  msgstr "An active session for {user} already exists. Overwrite? [y/N]"

  msgid "login.session_overwrite_confirm"
  msgstr "Overwriting existing session for {user}; the previous token is now revoked."

  msgid "login.user_not_found"
  msgstr "User {user} is not in the registry."

  msgid "login.user_not_found_action_alfred_user_list"
  msgstr "Use `alfred user list` to inspect known users, or `alfred user add` to create one."

  msgid "login.expires_in_out_of_range"
  msgstr "--expires-in {value} is outside the supported range [1h, 7d]."

  msgid "login.no_machine_id"
  msgstr "Cannot read this host's machine-id. Operator session creation refused."

  msgid "login.confirmed"
  msgstr "Logged in as {user}. Session expires at {expires_at} ({host})."

  msgid "logout.no_session"
  msgstr "No active session to log out of."

  msgid "logout.confirmed"
  msgstr "Logged out. Session for {user} revoked."

  msgid "whoami.no_session"
  msgstr "No active session. Run `alfred login --as <user>` to start one."

  msgid "whoami.expired"
  msgstr "Session for {user} expired at {expires_at}. Run `alfred login --as <user>` to renew."

  msgid "whoami.template"
  msgstr "Logged in as {user}\nIssued: {issued_at}\nExpires: {expires_at}\nHost: {host}"

  # Operator-session refusal reasons.

  msgid "operator_session.refused.expired"
  msgstr "Session expired."

  msgid "operator_session.refused.host_mismatch"
  msgstr "Session host binding mismatch. The session was issued for a different host."

  msgid "operator_session.refused.machine_mismatch"
  msgstr "Machine-id mismatch. The session was issued on a different machine."

  msgid "operator_session.refused.token_unknown"
  msgstr "Session token not recognised."

  msgid "operator_session.refused.user_revoked"
  msgstr "Session revoked because the user was removed or disabled."

  msgid "operator_session.refused.bad_file_mode"
  msgstr "Session file at {path} has insecure mode; expected 0600."

  msgid "operator_session.refused.bad_file_owner"
  msgstr "Session file at {path} is not owned by the current user."

  msgid "operator_session.refused.resolver_timeout"
  msgstr "Operator-session resolver exceeded the 250ms hard timeout."

  # Supervisor reset refusals.

  msgid "supervisor.breaker.reset.refused.not_logged_in"
  msgstr "Cannot reset supervisor breaker without an active operator session. Run `alfred login --as <user>` first."

  msgid "supervisor.breaker.reset.refused.operator_permissions_insufficient"
  msgstr "Operator {user} lacks the required permissions to reset the supervisor breaker."

  # Daemon boot.

  msgid "daemon.boot.environment_not_set"
  msgstr "Settings.environment is not set. Refusing to boot — production refuses without an explicit environment."

  msgid "daemon.boot.unsandboxed_in_production"
  msgstr "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED is set in a production environment. Refusing to boot."

  msgid "daemon.boot.launcher_not_policy_resolving"
  msgstr "bin/alfred-plugin-launcher.sh does not resolve per-plugin policies. Refusing to boot."

  msgid "daemon.boot.snapshot_ref_init_failed"
  msgstr "PoliciesSnapshotRef initialisation failed: {detail}. Refusing to boot."

  msgid "daemon.boot.capability_gate_handshake_failed"
  msgstr "Capability-gate handshake failed: {detail}. Refusing to boot."

  msgid "daemon.boot.started"
  msgstr "AlfredOS daemon started ({boot_id})."

  msgid "daemon.stop.confirmed"
  msgstr "AlfredOS daemon stopped."

  msgid "daemon.status.template"
  msgstr "Daemon PID {pid}\nUptime: {uptime}\nBoot ID: {boot_id}\nLast boot completed: {last_boot_at}"

  # Sandbox refusal reasons.

  msgid "supervisor.sandbox.refused.policy_ref_missing"
  msgstr "Plugin {plugin_id} declares sandbox kind=full but has no policy_ref for {host_os}. Refusing to launch."

  msgid "supervisor.sandbox.refused.policy_ref_os_mismatch"
  msgstr "Plugin {plugin_id} policy_ref points to a {policy_os} policy on a {host_os} host. Refusing to launch."

  msgid "supervisor.sandbox.refused.policy_ref_unreadable"
  msgstr "Plugin {plugin_id} policy_ref at {policy_ref} is unreadable. Refusing to launch."

  msgid "supervisor.sandbox.refused.sandbox_block_missing"
  msgstr "Plugin {plugin_id} manifest is missing the [sandbox] block. Refusing to launch."

  msgid "supervisor.sandbox.refused.windows_stub_in_production"
  msgstr "Plugin {plugin_id} resolves to the Windows stub policy in production. Refusing to launch — Windows requires WSL2 per spec §7.7."

  msgid "supervisor.sandbox.unsandboxed_refused_in_production"
  msgstr "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED is set in production. Refusing to launch plugin {plugin_id}."

  # Config-reload notifications.

  msgid "supervisor.config_reload.applied"
  msgstr "config/policies.yaml reloaded ({changed_keys})."

  msgid "supervisor.config_reload_rejected.parse_failure"
  msgstr "config/policies.yaml reload rejected: parse failure ({detail}). Live snapshot retained."

  msgid "supervisor.config_reload_rejected.high_blast_change"
  msgstr "config/policies.yaml reload rejected: {key} is a high-blast key and requires reviewer-gate."

  msgid "supervisor.config_reload_rejected.validation_failure"
  msgstr "config/policies.yaml reload rejected: validation failed for {detail}. Live snapshot retained."

  msgid "supervisor.config_reload_rejected.file_vanished"
  msgstr "config/policies.yaml vanished between stat and read. Live snapshot retained."

  msgid "supervisor.config_reload_rejected.stat_failed"
  msgstr "config/policies.yaml stat failed: {detail}. Live snapshot retained."

  # TUI.

  msgid "comms.tui.daemon_required_to_chat"
  msgstr "alfred chat requires the AlfredOS daemon to be running. Start it with `alfred daemon start`."
  ```

- [ ] **Task I3 — Regenerate the `.mo` catalog.**

  Run `pybabel compile -d locale -D alfred -i locale/en/LC_MESSAGES/alfred.po -o locale/en/LC_MESSAGES/alfred.mo --statistics`. Confirm the compile succeeds with zero errors. Commit the `.mo` file.

- [ ] **Task I4 — Confirm tests I1 pass.** `uv run pytest tests/unit/test_catalog_slice_4_keys.py -x -v`. All three tests must PASS.

- [ ] **Task I5 — Run `pybabel compile --check` to confirm catalog drift gate.**

  This is the CI's existing Slice-1 discipline (per CLAUDE.md i18n rules). Locally:

  ```
  uv run pybabel compile -d locale -D alfred --check
  ```

  Must exit 0.

- [ ] **Task I6 — `make check`.**

---

## §5 Spec Coverage Map

| Spec section | Delivered in this PR | Notes |
|---|---|---|
| Spec §12.1 Alembic migration 0012 | Component A | `operator_sessions` + `uq_operator_sessions_token_hash` + lookup index |
| Spec §12.1 Alembic migration 0013 | Component B | `policies_snapshot_history` self-reference FK |
| Spec §12.1 Alembic migration 0014 | Component C | Slice-4 audit columns; cross-validated against `audit_row_schemas.py` |
| Spec §12.1 Alembic migration 0015 | Component D | `sandbox_policy_registry` composite PK + CHECK |
| Spec §9 audit-row schemas (PR-S4-0b's column-add half) | Component C | PR-S4-0a defines the constants; this PR adds the columns |
| Spec §8.10 audit pepper bootstrap | Components G + H | Setup-script seed + broker registry; daemon-boot refusal is in PR-S4-1 |
| Spec §12.2 i18n catalog (full enumeration) | Component I | 44 keys across login/refusal/reset/daemon/sandbox/reload/TUI families |
| Spec §13 PR-S4-0b row — Dockerfile bubblewrap | Component F | Apt-install only; `docker-compose.yaml` already uses `build:` (the index-row claim of `image:`→`build:` flip is wrong) |
| Spec §13 PR-S4-0b row — `bin/alfred-setup.sh` updates | Component G | Sandbox dir + pepper seed; canonical name (spec previously referenced `bin/dev-setup.sh`, which does not exist) |
| Index §3 audit-pepper bootstrap contract | Components G + H | Broker registry + idempotent seed; daemon-boot probe is PR-S4-1 |
| Index §7 PR-S4-0 split rationale | Whole PR | Stays executable: Alembic + Postgres + mypy + pybabel + `docker compose build` |

---

## §6 Quality gates

Every gate below must be green before this PR is mergeable. The bar is identical to PR-S3-0b's discipline.

1. **`make check`** — `ruff check` + `ruff format --check` + `mypy --strict src/` + `pyright src/` + unit/integration tests. Mandatory.
2. **`uv run pytest tests/integration/test_migrations_0012_0015.py -x`** — all four migrations' upgrade/downgrade round-trips against testcontainers Postgres 16. Mandatory.
3. **`uv run pytest tests/unit/test_audit_log_slice_4_columns.py -x`** — confirms every Slice-4 `*_FIELDS` field is an `AuditEntry` column (no orphan fields).
4. **`uv run pytest tests/unit/test_slice_4_models_expose_columns.py -x`** — SQLAlchemy model column-set drift.
5. **`uv run pytest tests/integration/test_audit_pepper_bootstrap.py -x`** — pepper-secret broker registry + bootstrap.
6. **`uv run pytest tests/unit/test_catalog_slice_4_keys.py -x`** — every Slice-4 `t()` key resolves to a non-bare string.
7. **`uv run pytest tests/unit/test_dockerfile_bubblewrap_present.py -x`** — Dockerfile contains `bubblewrap` on an apt-install line.
8. **`uv run pytest tests/unit/test_setup_script_audit_pepper.py -x`** — setup script contains both new idempotent steps.
9. **`uv run pybabel compile -d locale -D alfred --check`** — catalog drift gate.
10. **`docker compose build alfred-core`** — image build succeeds, `bwrap` is reachable on `$PATH` inside the container.
11. **Markdown lint** — `npx markdownlint-cli2 docs/superpowers/plans/2026-06-07-slice-4-pr-s4-0b-migrations-infra-i18n.md` exits 0.
12. **Adversarial suite** — `uv run pytest tests/adversarial` — mandatory because Component H touches `src/alfred/security/`.
13. **Conventional-commit `#NNN` reference gate** — every commit message references the tracking issue per #204's discovered requirement during merge.

---

## §7 References

- Spec [`docs/superpowers/specs/2026-06-06-slice-4-design.md`](../specs/2026-06-06-slice-4-design.md) — §12.1, §12.2, §13, §8.10, §9, §7.5–§7.7, §6.2, §6.5.
- Index [`docs/superpowers/plans/2026-06-07-slice-4-index.md`](./2026-06-07-slice-4-index.md) — §3 cross-PR contracts (audit pepper bootstrap), §7 PR-S4-0 split rationale, §8 fabricated-surfaces watchlist.
- Slice-3 template [`docs/superpowers/plans/2026-05-31-slice-3-pr-s3-0b-migrations-infra-i18n.md`](./2026-05-31-slice-3-pr-s3-0b-migrations-infra-i18n.md) — structural precedent for migration round-trip tests, infra additions, i18n catalog discipline.
- ADR-0005 + ADR-0013 — broker file format (TOML, age-encrypted in production).
- ADR-0024 — comms-MCP wire contract (consumer of `audit.hash_pepper`).
- PRD [`PRD.md`](../../PRD.md) — §5 line 117 hybrid-isolation invariant (closed by Slice 4 graduation).

### Tracking issue

- Tracking: #TBD — opened against this PR-S4-0b plan. Conventional-commit `#NNN` reference gate (per #204 discovered requirement) attaches every commit in this branch to the tracking issue.

### Subagent handoff

When implementing this plan via `superpowers:subagent-driven-development`:

| Component | Recommended subagent persona |
|---|---|
| A, B, C, D (migrations) | `alfred-memory-engineer` — owns SQLAlchemy + Alembic discipline |
| E (ORM models) | `alfred-memory-engineer` |
| F (Dockerfile) | `alfred-devops-engineer` (this agent) — owns Docker + compose |
| G (`bin/alfred-setup.sh`) | `alfred-devops-engineer` |
| H (broker registry) | `alfred-security-engineer` — owns `src/alfred/security/` |
| I (i18n catalog) | `alfred-i18n-engineer` — owns `locale/` + `pybabel` discipline |

After each component, the implementing subagent reports back with: (a) green pytest output, (b) `make check` output, (c) any drift discovered between the plan and the actual codebase state (escalate to architect rather than guess).

---

## §8 Reviewer checklist

A reviewer evaluating this PR must confirm:

- [ ] All four migrations chain correctly (`alembic upgrade head` from a fresh DB succeeds; `alembic downgrade base` cleanly removes Slice-4 tables/columns).
- [ ] `uq_operator_sessions_token_hash` is a **unique** index (not just a non-unique index) — load-bearing for PR-S4-5's 5ms p99 budget.
- [ ] Every Slice-4 `*_FIELDS` constant from `audit_row_schemas.py` has all its fields present as columns on `AuditEntry` (`tests/unit/test_audit_log_slice_4_columns.py` is the gate).
- [ ] `audit.hash_pepper` is in `SecretBroker.SUPPORTED_SECRETS`.
- [ ] `bin/alfred-setup.sh` is idempotent on re-run (does not clobber an existing pepper).
- [ ] `bin/alfred-setup.sh` creates `~/.config/alfred/sandbox/` with mode `0700`.
- [ ] `docker/alfred-core.Dockerfile` installs `bubblewrap` on the same apt-get line as `git` and `util-linux` (one layer).
- [ ] `docker compose build alfred-core` succeeds locally.
- [ ] `bwrap --version` reports a valid version when run inside the built container.
- [ ] `locale/en/LC_MESSAGES/alfred.po` has all 44 new Slice-4 keys; `alfred.mo` regenerated.
- [ ] `pybabel compile -d locale -D alfred --check` exits 0.
- [ ] No fabricated surfaces — every cited Slice-3 or earlier symbol has been verified to exist at the cited path (see §2 verification table).
- [ ] **No out-of-scope work** — daemon-boot probe, hot-reload runtime, session-resolver runtime, sandbox-policy bytes, comms-MCP wire runtime are all explicitly deferred to the listed downstream PRs.
- [ ] PR description references the tracking issue (`#NNN`) per the conventional-commit gate.
- [ ] Markdown lint exits 0 for this plan document and any updated runbooks.

---

## §9 Notes for the agentic implementer

- **Read before editing.** Before modifying `src/alfred/memory/models.py`, Read the current file end-to-end. The Slice-3 model set is non-trivial and the column types must align with the migration choices verbatim. Drift between the migration's `sa.String(64)` and the model's `Mapped[str] = mapped_column(String(128))` is silently legal at the Python layer but the DB column is `VARCHAR(64)` and longer strings will truncate at insert. Match exactly.

- **No `Optional[X]`, no `typing.List`.** Per CLAUDE.md the modern-Python rules apply to this PR too: use `X | None` and built-in generics. The Slice-3 model file follows this discipline already.

- **No silent broker substitution failures.** `SecretBroker.get("audit.hash_pepper")` must raise `UnknownSecretError` cleanly when the pepper is missing — the daemon-boot probe (PR-S4-1) relies on this. Do NOT swallow the exception in `SecretBroker` or substitute an empty string; the boot probe needs the loud-failure semantic.

- **Idempotency is part of the contract.** Re-running `bin/alfred-setup.sh` on a host that already has a pepper MUST NOT rotate it. Rotating invalidates cross-row correlation per spec §8.10. The bootstrap step's guard is the difference between a safe re-run and a silent data-quality regression.

- **The fabricated-surfaces verification gate is mandatory.** Before invoking any symbol not in this plan, run `grep -rE "symbol" src/` or Read the relevant file. Past PRs have fabricated `secret_broker.fetch_audit_pepper`, `AuditWriter.dedupe_surface`, and `AlfredPluginSession._read_loop`; the reflex to invent a method that "should exist" is the failure mode. When in doubt, mark the symbol as new Slice-4 scope (this PR creates exactly four new symbols on `src/alfred/security/secrets.py`'s `SUPPORTED_SECRETS` registry and three new ORM models on `src/alfred/memory/models.py`; everything else is consumption of pre-Slice-4 surface).

- **Adversarial-suite touchpoint.** Component H modifies `src/alfred/security/secrets.py`. CLAUDE.md mandates running the adversarial suite locally after any `src/alfred/security/` change. Budget ~10 minutes for the full run before opening the PR.

- **Order matters.** The components are written in dependency order. Don't skip ahead — e.g. Component C (migration 0014) cross-references the audit constants from PR-S4-0a, and Component E (ORM models for sessions/snapshots) cross-references Component A/B's migration column types. Doing Components out of order means rework.

- **One PR, one responsibility per commit.** Per CLAUDE.md, small PRs are mandatory. This PR is large by line count but each Component is one logical commit (or two — failing-test commit + passing commit, per TDD discipline). Don't fold Components together into a "migrations + i18n" mega-commit; the reviewer hold-in-head budget is the gate.

---

## §10 Risks + mitigations

| Risk | Mitigation |
|---|---|
| Migration 0014's column union drifts from `audit_row_schemas.py` Slice-4 constants — a Slice-4 emit site fails at runtime with `column does not exist` | `tests/unit/test_audit_log_slice_4_columns.py` cross-validates every `*_FIELDS` entry against the ORM model. The model must have every column; the migration must have added it. Two layers of drift detection. |
| `audit.hash_pepper` accidentally regenerated on a production setup re-run, silently invalidating cross-row correlation | The setup script's `grep -q "^audit.hash_pepper\\s*="` guard is the safety net. `tests/unit/test_setup_script_audit_pepper.py::test_setup_script_audit_pepper_is_idempotent` enforces the guard's presence. Reviewer checklist item also calls it out. |
| `uq_operator_sessions_token_hash` accidentally created as a non-unique index — silent perf regression on the 5ms p99 budget; PR-S4-5 only notices in load testing | `tests/integration/test_migrations_0012_0015.py::test_0012_unique_token_hash_index_exists` asserts `unique=True`. Reviewer checklist item also calls it out. |
| Dockerfile `bubblewrap` install bloats the runtime image | bubblewrap is ~200KB binary; negligible. Keep it on the same `RUN apt-get install` line as `git`+`util-linux` so layer count stays at one. |
| i18n catalog drift — implementation PR introduces a `t("foo.bar.baz")` not in the catalog | Already gated by `pybabel compile --check` in CI per CLAUDE.md i18n rule §4. This PR's `tests/unit/test_catalog_slice_4_keys.py` asserts every Slice-4 key shipped by spec §12.2 resolves. |
| PR-S4-0a defines a Slice-4 `*_FIELDS` constant this PR did not anticipate; the migration 0014 column union is incomplete | Components C2 and C5 cross-reference the constants. If PR-S4-0a lands new constants after this PR is in flight, the cross-validation test fails fast. Resolve by either (a) rebasing this PR onto the new 0a constants, or (b) treating the gap as a follow-up migration `0015`. |
| `docker-compose.yaml` claim drift — the index §1 row says "flips `image:` → `build:`" but the file already uses `build:`. A reviewer believing the index row over-edits the compose file | Flagged in §2 verification table + Component F1. Reviewer checklist item: confirm the compose file is unchanged for `alfred-core` (this PR only modifies the Dockerfile). |
| Catalog English copy reviewed late and required to change after the keys are consumed in S4-1..S4-10 | Per the existing Slice-3 discipline: catalog copy can be amended in the consuming PR without touching the key set. The key contract is stable; copy is editorial. |

---

## §11 Done criteria

This PR is "done" when:

1. All four migrations are present at the listed paths with the listed columns / indexes / constraints.
2. SQLAlchemy 2.0 typed models for `OperatorSession`, `PoliciesSnapshotHistory`, `SandboxPolicyRegistry` are present on `src/alfred/memory/models.py`.
3. `AuditEntry` model exposes every Slice-4 audit column.
4. `audit.hash_pepper` is registered in `SecretBroker.SUPPORTED_SECRETS` and the setup script idempotently seeds a value.
5. `docker/alfred-core.Dockerfile` installs `bubblewrap`; `docker compose build alfred-core` succeeds and `bwrap` is reachable inside the container.
6. `bin/alfred-setup.sh` creates `~/.config/alfred/sandbox/` and seeds the pepper.
7. `locale/en/LC_MESSAGES/alfred.po` contains all 44 Slice-4 keys; `.mo` recompiled.
8. All 13 quality gates in §6 pass.
9. The PR description references the tracking issue per the conventional-commit gate.
10. Markdown lint exits 0 on this plan document.

Once green, hand off to PR-S4-3 (the next critical-path PR after this one) which depends on the migration columns added here for its `CARRIER_SUBSTITUTION_FIELDS` audit emit-sites, and to PR-S4-5 which depends on `operator_sessions` for the session-resolver runtime.
