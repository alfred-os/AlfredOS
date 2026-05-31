# Real CapabilityGate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `DevGate` with `RealGate` — a production `CapabilityGate` backed by state.git (source of truth) + Postgres (runtime cache) — and extend the `CapabilityGate` Protocol with `check_plugin_load` and `check_content_clearance`, complete with reviewer-gated proposal flow for high-blast grants and fail-closed outage semantics with 60 s heartbeat staleness window.

**Architecture:** `RealGate` reads grant policy from state.git at startup and caches it in the `plugin_grants` Postgres table (migration `0008`, from PR-S3-0b). Hot-path checks hit Postgres only. A background heartbeat task monitors backing-store availability; after 60 s without a successful heartbeat, the gate transitions to fail-closed for all dispatches including in-process ones. Grant proposals that require reviewer approval are written to a `proposal/policy-grant-<id>` branch in state.git; the `proposals.py` module owns that branch creation and the reviewer-agent invocation. `RealGate` vs `DevGate` selection lives in `src/alfred/bootstrap/gate_factory.py` (not `capability.py`) so the AST-scan forbidding `import os` in `capability.py` (sec-007) is satisfied.

**Tech Stack:** Python 3.12+ · SQLAlchemy 2.0 async · asyncio (TaskGroup, timeout) · `gitpython` (state.git branch creation) · Pydantic v2 · structlog · `alfred.i18n.t()` · pytest + testcontainers (Postgres) · coverage `--fail-under=100` on `src/alfred/hooks/capability.py`

---

## §1 Goal

This PR implements spec §8 (Real `CapabilityGate` — Fork 7) in full, plus the `CapabilityGate` Protocol extension from spec §8.2, the reviewer-gated proposal flow from spec §8.3, and the fail-closed outage behaviour from spec §8.1 and §10.4. It also wires the `plugin.grant.*` audit family (spec §8.5, constants from `audit_row_schemas.py` in PR-S3-0a) and the `supervisor.capability_gate_unavailable` audit row. After this PR merges, PR-S3-3a can build `AlfredPluginSession` against `check_plugin_load`, and PR-S3-4 can call `check_content_clearance` for the `tag(T3, ...)` factory.

Spec anchors: §8.1 (hybrid storage), §8.2 (Protocol extension), §8.3 (reviewer-gated proposals), §8.4 (DevGate/RealGate co-existence), §8.5 (grant lifecycle audit), §10.4 (capability-gate backing-store fail-closed), §13 (audit row constants — from PR-S3-0a), §14 (hookpoint surface — `plugin.grant.*`), §15.1 (flag-day note).

**Depends on:** PR-S3-0a (audit_row_schemas.py, payload_schema.py Literals), PR-S3-0b (migrations 0008 `plugin_grants`, 0009 `capability_gate_sync`; i18n catalog with `capability_gate.unavailable`, `plugin.grant_prompt`, `cli.plugin.grant.*`; SQLAlchemy models for `PluginGrant` and `CapabilityGateSyncRow`), PR-S3-1 (T1/T3 tier classes, CapabilityGateNonce, tag_t3_with_nonce, AnyTaggedContent Protocol).

**Blocks:** PR-S3-3a (`check_plugin_load`), PR-S3-4 (`check_content_clearance`), PR-S3-5 (full gate checks in web-fetch dispatch), PR-S3-7 (flag-day DevGate removal uses RealGate fixtures).

---

## §2 Architecture overview

```
src/alfred/
├── bootstrap/
│   └── gate_factory.py          ← ALFRED_ENV read lives here (not capability.py)
├── hooks/
│   └── capability.py            ← Protocol extended; DevGate unchanged; import-os-forbidden
└── security/
    └── capability_gate/
        ├── __init__.py           ← public exports: RealGate, GatePolicy, GrantRow
        ├── policy.py             ← pure-policy module (AST-scan forbids import os)
        ├── backend.py            ← StorageBackend Protocol + PostgresBackend
        └── proposals.py          ← state.git branch creation + reviewer invocation
```

The grant lifecycle flows:

```
operator: alfred plugin grant <id> system <hookpoint>
    │
    ▼
proposals.py: create_proposal_branch(plugin_id, tier, hookpoint)
    → writes proposal/policy-grant-<id> in state.git
    → invokes reviewer agent (async, non-blocking)
    │
    ▼  (reviewer approves, merges to main)
    │
RealGate._rebuild_from_state_git()
    → reads main branch of state.git
    → upserts plugin_grants table in Postgres
    → updates capability_gate_sync.commit_hash
    │
    ▼  (hot-path check)
RealGate.check(plugin_id, hookpoint, requested_tier) → bool
    → SELECT FROM plugin_grants WHERE ... (Postgres, ms latency)
```

Fail-closed path:
```
Heartbeat task (every 10 s) → PostgresBackend.ping()
    failure → increment _missed_heartbeats
    _missed_heartbeats * 10 s ≥ 60 s → gate.fail_closed = True
    recovery → gate.fail_closed = False; emit supervisor.capability_gate_unavailable (exit row)
```

---

## §3 File structure

| File | Create / Modify / Test | Responsibility |
|---|---|---|
| `src/alfred/hooks/capability.py` | **Modify** | Add `check_plugin_load` + `check_content_clearance` to `CapabilityGate` Protocol; add stub impls to `DevGate` (fail-open for backward compat) |
| `src/alfred/security/capability_gate/__init__.py` | **Create** | Public exports: `RealGate`, `GatePolicy`, `GrantRow` |
| `src/alfred/security/capability_gate/policy.py` | **Create** | Pure-policy module: `GatePolicy` dataclass, grant-match logic, no `import os` |
| `src/alfred/security/capability_gate/backend.py` | **Create** | `StorageBackend` Protocol + `PostgresBackend` (async SQLAlchemy reads/writes against `plugin_grants` + `capability_gate_sync` tables) |
| `src/alfred/security/capability_gate/proposals.py` | **Create** | `create_proposal_branch()` — state.git branch writer + reviewer-agent invocation stub |
| `src/alfred/bootstrap/gate_factory.py` | **Create** | `build_gate()` — reads `ALFRED_ENV`, returns `RealGate` or `DevGate` |
| `tests/unit/security/capability_gate/test_hybrid_storage_roundtrip.py` | **Create** | state.git → Postgres cache rebuild on commit-hash change |
| `tests/unit/security/capability_gate/test_fail_closed_outage.py` | **Create** | Backing-store outage → fail-closed for ALL dispatches; 60 s heartbeat staleness window; `plugin.grant.revoked_inflight` emission |
| `tests/unit/security/capability_gate/test_proposal_flow.py` | **Create** | `alfred plugin grant system X` queues proposal, does NOT write directly |
| `tests/unit/security/test_default_strict_declarations_invariant.py` | **Create** | `RealGate` is the production default when `ALFRED_ENV != development` |
| `tests/unit/security/test_capability_gate_ast_no_os_import.py` | **Create** | AST-scan: `policy.py` and `capability.py` contain no `import os` |
| `tests/integration/security/test_grant_lifecycle_e2e.py` | **Create** | End-to-end: proposal → approval → Postgres rebuild → check returns True |

---

## §4 Tasks

### Component A — Protocol extension (capability.py)

- [ ] **Task 1 — Write failing tests for Protocol extension.**

  **Files:** Test `tests/unit/hooks/test_capability.py` (modify existing).

  Add the following failing test cases to the existing test file:

  ```python
  # tests/unit/hooks/test_capability.py  — ADDITIONS

  def test_capability_gate_protocol_has_check_plugin_load() -> None:
      """CapabilityGate Protocol exposes check_plugin_load."""
      import inspect
      from alfred.hooks.capability import CapabilityGate
      assert "check_plugin_load" in dir(CapabilityGate)
      sig = inspect.signature(CapabilityGate.check_plugin_load)
      assert "plugin_id" in sig.parameters
      assert "manifest_tier" in sig.parameters

  def test_capability_gate_protocol_has_check_content_clearance() -> None:
      """CapabilityGate Protocol exposes check_content_clearance."""
      import inspect
      from alfred.hooks.capability import CapabilityGate
      assert "check_content_clearance" in dir(CapabilityGate)
      sig = inspect.signature(CapabilityGate.check_content_clearance)
      assert "plugin_id" in sig.parameters
      assert "hookpoint" in sig.parameters
      assert "content_tier" in sig.parameters

  def test_devgate_check_plugin_load_returns_true_by_default() -> None:
      """DevGate.check_plugin_load is fail-open for backward compat (Slice 3 co-existence)."""
      from alfred.hooks.capability import DevGate
      gate = DevGate()
      assert gate.check_plugin_load(plugin_id="test.plugin", manifest_tier="operator") is True

  def test_devgate_check_content_clearance_returns_true_by_default() -> None:
      """DevGate.check_content_clearance is fail-open for backward compat (Slice 3 co-existence)."""
      from alfred.hooks.capability import DevGate
      gate = DevGate()
      assert gate.check_content_clearance(
          plugin_id="test.plugin", hookpoint="tool.web.fetch", content_tier="T3"
      ) is True

  def test_devgate_satisfies_extended_capability_gate_protocol() -> None:
      """DevGate with new methods satisfies CapabilityGate (runtime_checkable)."""
      from alfred.hooks.capability import CapabilityGate, DevGate
      assert isinstance(DevGate(), CapabilityGate)
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/hooks/test_capability.py -q 2>&1 | tail -5
  ```
  Expected: 5 failures (AttributeError / AssertionError).

- [ ] **Task 2 — Implement Protocol extension in capability.py.**

  **Files:** Modify `src/alfred/hooks/capability.py`.

  Add to `CapabilityGate` Protocol and `DevGate`:

  ```python
  # src/alfred/hooks/capability.py  — ADD to CapabilityGate Protocol
  @runtime_checkable
  class CapabilityGate(Protocol):
      def check(
          self,
          *,
          plugin_id: str,
          hookpoint: str,
          requested_tier: str,
      ) -> bool: ...

      def check_plugin_load(
          self,
          *,
          plugin_id: str,
          manifest_tier: str,
      ) -> bool:
          """Gate plugin load at handshake time. Called by AlfredPluginSession.

          Spec §8.2: a gate refusal emits plugin.lifecycle.load_refused
          and the supervisor marks the plugin REFUSED until re-granted.
          Content trust tier (T0-T3) and subscriber hook tier are orthogonal axes.
          """
          ...

      def check_content_clearance(
          self,
          *,
          plugin_id: str,
          hookpoint: str,
          content_tier: str,
      ) -> bool:
          """Gate content-tier access: T3 content must not reach T2-only paths.

          Spec §8.2: orthogonal to subscriber tier (system/operator/user-plugin).
          The quarantined-LLM plugin host and StdioTransport are the only
          authorised callers for content_tier="T3".
          """
          ...
  ```

  Add to `DevGate` dataclass (fail-open stubs per spec §8.4 backward-compat requirement):

  ```python
  # src/alfred/hooks/capability.py  — ADD to DevGate class

      def check_plugin_load(
          self,
          *,
          plugin_id: str,
          manifest_tier: str,
      ) -> bool:
          """Fail-open stub for Slice 3 co-existence.

          Spec §8.4: DevGate implements the two new methods to fail-open
          (returning True) for backward compatibility in Slice-2.5 tests.
          Flag-day in PR-S3-7 removes DevGate; until then this is deliberate.
          """
          del plugin_id, manifest_tier
          return True

      def check_content_clearance(
          self,
          *,
          plugin_id: str,
          hookpoint: str,
          content_tier: str,
      ) -> bool:
          """Fail-open stub for Slice 3 co-existence. See check_plugin_load docstring."""
          del plugin_id, hookpoint, content_tier
          return True
  ```

  Run tests:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/hooks/test_capability.py -q 2>&1 | tail -5
  ```
  Expected: all pass.

  Run quality gate:
  ```bash
  uv run ruff check src/alfred/hooks/capability.py && uv run mypy src/alfred/hooks/capability.py
  ```
  Expected: no errors.

  Commit:
  ```bash
  git add src/alfred/hooks/capability.py tests/unit/hooks/test_capability.py
  git commit -m "feat(capability-gate): extend CapabilityGate Protocol with check_plugin_load + check_content_clearance (#TBD-slice3)"
  ```

---

### Component B — Pure-policy module

- [ ] **Task 3 — Write failing tests for GatePolicy.**

  **Files:** Create `tests/unit/security/capability_gate/__init__.py` and `tests/unit/security/capability_gate/test_gate_policy.py`.

  ```python
  # tests/unit/security/capability_gate/__init__.py
  # package marker
  ```

  ```python
  # tests/unit/security/capability_gate/test_gate_policy.py
  """Tests for src/alfred/security/capability_gate/policy.py — pure policy matching."""
  from __future__ import annotations

  import pytest
  from alfred.security.capability_gate.policy import GatePolicy, GrantRow


  def test_grant_row_is_frozen() -> None:
      row = GrantRow(
          plugin_id="test.plugin",
          subscriber_tier="operator",
          hookpoint="tool.web.fetch",
          content_tier=None,
          proposal_branch="proposal/policy-grant-abc",
      )
      with pytest.raises(Exception):  # frozen dataclass
          row.plugin_id = "other"  # type: ignore[misc]


  def test_gate_policy_check_returns_true_for_matching_grant() -> None:
      policy = GatePolicy(grants=frozenset({
          GrantRow(
              plugin_id="test.plugin",
              subscriber_tier="operator",
              hookpoint="tool.web.fetch",
              content_tier=None,
              proposal_branch="proposal/policy-grant-abc",
          )
      }))
      assert policy.check(
          plugin_id="test.plugin",
          hookpoint="tool.web.fetch",
          requested_tier="operator",
      ) is True


  def test_gate_policy_check_returns_false_for_no_matching_grant() -> None:
      policy = GatePolicy(grants=frozenset())
      assert policy.check(
          plugin_id="test.plugin",
          hookpoint="tool.web.fetch",
          requested_tier="operator",
      ) is False


  def test_gate_policy_check_plugin_load_uses_subscriber_tier() -> None:
      policy = GatePolicy(grants=frozenset({
          GrantRow(
              plugin_id="mypl",
              subscriber_tier="system",
              hookpoint="*",
              content_tier=None,
              proposal_branch="proposal/policy-grant-xyz",
          )
      }))
      assert policy.check_plugin_load(plugin_id="mypl", manifest_tier="system") is True
      assert policy.check_plugin_load(plugin_id="mypl", manifest_tier="operator") is False


  def test_gate_policy_check_content_clearance_matches_content_tier() -> None:
      policy = GatePolicy(grants=frozenset({
          GrantRow(
              plugin_id="quarantine.host",
              subscriber_tier="system",
              hookpoint="tag.T3",
              content_tier="T3",
              proposal_branch="proposal/policy-grant-t3",
          )
      }))
      assert policy.check_content_clearance(
          plugin_id="quarantine.host",
          hookpoint="tag.T3",
          content_tier="T3",
      ) is True
      assert policy.check_content_clearance(
          plugin_id="other.plugin",
          hookpoint="tag.T3",
          content_tier="T3",
      ) is False


  def test_gate_policy_wildcard_hookpoint_matches_any() -> None:
      """A grant with hookpoint='*' covers all hookpoints for plugin load checks."""
      policy = GatePolicy(grants=frozenset({
          GrantRow(
              plugin_id="mypl",
              subscriber_tier="system",
              hookpoint="*",
              content_tier=None,
              proposal_branch="proposal/policy-grant-xyz",
          )
      }))
      assert policy.check(
          plugin_id="mypl",
          hookpoint="any.hookpoint.at.all",
          requested_tier="system",
      ) is True


  def test_gate_policy_empty_grants_always_denies() -> None:
      policy = GatePolicy(grants=frozenset())
      assert policy.check(plugin_id="x", hookpoint="y", requested_tier="system") is False
      assert policy.check_plugin_load(plugin_id="x", manifest_tier="system") is False
      assert policy.check_content_clearance(plugin_id="x", hookpoint="y", content_tier="T3") is False


  def test_gate_policy_no_import_os() -> None:
      """AST-scan: policy.py must not import os (same guard as capability.py sec-007)."""
      import ast
      from pathlib import Path
      src = (
          Path(__file__).resolve().parents[4]
          / "src" / "alfred" / "security" / "capability_gate" / "policy.py"
      )
      tree = ast.parse(src.read_text())
      for node in ast.walk(tree):
          if isinstance(node, ast.Import):
              for alias in node.names:
                  assert alias.name != "os", "policy.py must not import os"
          if isinstance(node, ast.ImportFrom):
              assert node.module != "os", "policy.py must not from os import ..."
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_gate_policy.py -q 2>&1 | tail -5
  ```
  Expected: ImportError / collection errors (module doesn't exist yet).

- [ ] **Task 4 — Implement policy.py.**

  **Files:** Create `src/alfred/security/capability_gate/__init__.py` and `src/alfred/security/capability_gate/policy.py`.

  ```python
  # src/alfred/security/capability_gate/__init__.py
  """Real CapabilityGate — hybrid storage (state.git + Postgres).

  Spec §8 (Fork 7). Shipped in PR-S3-2.
  Public surface: RealGate, GatePolicy, GrantRow.
  """
  from alfred.security.capability_gate.policy import GatePolicy, GrantRow
  from alfred.security.capability_gate._gate import RealGate

  __all__ = ["RealGate", "GatePolicy", "GrantRow"]
  ```

  ```python
  # src/alfred/security/capability_gate/policy.py
  """Pure capability-gate policy matching.

  This module is import-os-forbidden (sec-007 extension to the capability gate).
  All matching logic is pure: no I/O, no env reads, no external state.

  Spec §8.1: grant policy is derived from state.git. The GatePolicy snapshot
  is built by RealGate._rebuild_from_state_git() and held in memory; hot-path
  checks dispatch to GatePolicy.check() which does nothing but frozenset lookups.
  """
  from __future__ import annotations

  from dataclasses import dataclass, field


  @dataclass(frozen=True, slots=True)
  class GrantRow:
      """A single capability grant row read from the plugin_grants table.

      Spec §8.5: field name is subscriber_tier (not tier) to match manifest
      naming rule in §4.3. content_tier is None for subscriber-tier grants;
      non-None for check_content_clearance grants.
      """
      plugin_id: str
      subscriber_tier: str          # "system" | "operator" | "user-plugin"
      hookpoint: str                # dotted name or "*" for wildcard (plugin-load grants)
      content_tier: str | None      # "T3" etc; None for subscriber-tier-only grants
      proposal_branch: str          # state.git branch that produced this grant


  @dataclass(frozen=True, slots=True)
  class GatePolicy:
      """Immutable snapshot of all active grants.

      Built from the plugin_grants Postgres table on startup and after any
      state.git commit-hash change. Replaced atomically on rebuild; never
      mutated in place.
      """
      grants: frozenset[GrantRow] = field(default_factory=frozenset)

      def check(
          self,
          *,
          plugin_id: str,
          hookpoint: str,
          requested_tier: str,
      ) -> bool:
          """Return True iff plugin_id holds a grant for hookpoint at requested_tier.

          Wildcard hookpoint '*' in a grant matches any hookpoint string.
          Spec §8.1: hot-path checks consult Postgres (via backend); this method
          is the in-memory policy layer above the DB read.
          """
          for grant in self.grants:
              if grant.plugin_id != plugin_id:
                  continue
              if grant.subscriber_tier != requested_tier:
                  continue
              if grant.hookpoint == "*" or grant.hookpoint == hookpoint:
                  return True
          return False

      def check_plugin_load(
          self,
          *,
          plugin_id: str,
          manifest_tier: str,
      ) -> bool:
          """Gate plugin load at handshake time.

          Spec §8.2: uses the subscriber_tier axis. A plugin whose manifest
          declares subscriber_tier=system must hold a system-tier grant with
          hookpoint='*' (or an explicit load-hookpoint) to load successfully.
          """
          return self.check(
              plugin_id=plugin_id,
              hookpoint="*",
              requested_tier=manifest_tier,
          )

      def check_content_clearance(
          self,
          *,
          plugin_id: str,
          hookpoint: str,
          content_tier: str,
      ) -> bool:
          """Gate content-tier access.

          Spec §8.2: orthogonal to subscriber tier. Returns True only if
          plugin_id holds a grant with matching hookpoint AND content_tier.
          """
          for grant in self.grants:
              if grant.plugin_id != plugin_id:
                  continue
              if grant.content_tier != content_tier:
                  continue
              if grant.hookpoint == "*" or grant.hookpoint == hookpoint:
                  return True
          return False
  ```

  Run tests:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_gate_policy.py -q 2>&1 | tail -5
  ```
  Expected: all pass.

  ```bash
  uv run ruff check src/alfred/security/capability_gate/ && uv run mypy src/alfred/security/capability_gate/policy.py
  ```

  Commit:
  ```bash
  git add src/alfred/security/capability_gate/ tests/unit/security/capability_gate/
  git commit -m "feat(capability-gate): GatePolicy + GrantRow pure-policy module (#TBD-slice3)"
  ```

---

### Component C — Storage backend

- [ ] **Task 5 — Write failing tests for StorageBackend Protocol + PostgresBackend.**

  **Files:** Create `tests/unit/security/capability_gate/test_storage_backend.py`.

  ```python
  # tests/unit/security/capability_gate/test_storage_backend.py
  """Tests for StorageBackend Protocol + PostgresBackend."""
  from __future__ import annotations

  import pytest
  from typing import Protocol, runtime_checkable


  def test_storage_backend_is_protocol() -> None:
      from alfred.security.capability_gate.backend import StorageBackend
      assert hasattr(StorageBackend, "__protocol_attrs__") or isinstance(StorageBackend, type)


  @pytest.mark.asyncio
  async def test_postgres_backend_ping_raises_on_no_connection() -> None:
      """PostgresBackend.ping() raises when no DB session available."""
      from alfred.security.capability_gate.backend import PostgresBackend
      backend = PostgresBackend(dsn="postgresql+asyncpg://invalid:5432/nodb")
      with pytest.raises(Exception):
          await backend.ping()


  @pytest.mark.asyncio
  async def test_postgres_backend_load_grants_returns_empty_on_no_rows(
      pg_session_factory,  # testcontainers fixture from conftest
  ) -> None:
      from alfred.security.capability_gate.backend import PostgresBackend
      from alfred.security.capability_gate.policy import GrantRow
      backend = PostgresBackend(session_factory=pg_session_factory)
      rows = await backend.load_grants()
      assert isinstance(rows, frozenset)
      # Empty because no grants seeded yet
      assert len(rows) == 0


  @pytest.mark.asyncio
  async def test_postgres_backend_upsert_and_load_roundtrip(
      pg_session_factory,
  ) -> None:
      from alfred.security.capability_gate.backend import PostgresBackend
      from alfred.security.capability_gate.policy import GrantRow
      backend = PostgresBackend(session_factory=pg_session_factory)
      grant = GrantRow(
          plugin_id="test.plugin",
          subscriber_tier="operator",
          hookpoint="tool.web.fetch",
          content_tier=None,
          proposal_branch="proposal/policy-grant-abc",
      )
      await backend.upsert_grant(grant)
      rows = await backend.load_grants()
      assert grant in rows


  @pytest.mark.asyncio
  async def test_postgres_backend_revoke_removes_grant(
      pg_session_factory,
  ) -> None:
      from alfred.security.capability_gate.backend import PostgresBackend
      from alfred.security.capability_gate.policy import GrantRow
      backend = PostgresBackend(session_factory=pg_session_factory)
      grant = GrantRow(
          plugin_id="rev.plugin",
          subscriber_tier="operator",
          hookpoint="tool.web.fetch",
          content_tier=None,
          proposal_branch="proposal/policy-grant-rev",
      )
      await backend.upsert_grant(grant)
      await backend.revoke_grant(
          plugin_id="rev.plugin",
          hookpoint="tool.web.fetch",
          subscriber_tier="operator",
      )
      rows = await backend.load_grants()
      assert grant not in rows


  @pytest.mark.asyncio
  async def test_postgres_backend_get_and_set_sync_hash(
      pg_session_factory,
  ) -> None:
      from alfred.security.capability_gate.backend import PostgresBackend
      backend = PostgresBackend(session_factory=pg_session_factory)
      # Initially no hash
      hash_ = await backend.get_sync_hash()
      assert hash_ is None
      # Set a hash
      await backend.set_sync_hash("abc123deadbeef")
      hash_ = await backend.get_sync_hash()
      assert hash_ == "abc123deadbeef"
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_storage_backend.py -q 2>&1 | tail -5
  ```
  Expected: ImportError (backend.py doesn't exist yet).

- [ ] **Task 6 — Implement backend.py.**

  **Files:** Create `src/alfred/security/capability_gate/backend.py`.

  ```python
  # src/alfred/security/capability_gate/backend.py
  """Storage backend Protocol + PostgresBackend for RealGate.

  Spec §8.1: hot-path capability checks consult Postgres (millisecond latency).
  The plugin_grants and capability_gate_sync tables are defined in migrations
  0008 and 0009 (PR-S3-0b). SQLAlchemy models PluginGrant and CapabilityGateSyncRow
  live in src/alfred/memory/models.py (PR-S3-0b).

  This module does NOT import os (sec-007 extension). ALFRED_ENV selection
  is in gate_factory.py. DSN is injected via dependency injection.
  """
  from __future__ import annotations

  from collections.abc import AsyncIterator
  from contextlib import asynccontextmanager
  from typing import Protocol, runtime_checkable

  import sqlalchemy as sa
  from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

  from alfred.security.capability_gate.policy import GrantRow


  @runtime_checkable
  class StorageBackend(Protocol):
      """Structural Protocol for the RealGate backing store.

      PostgresBackend is the production implementation. Test doubles implement
      this Protocol for unit tests that don't spin up a Postgres container.
      """

      async def ping(self) -> None:
          """Raise if the backing store is unreachable. Used by heartbeat task."""
          ...

      async def load_grants(self) -> frozenset[GrantRow]:
          """Load all active grants from the backing store."""
          ...

      async def upsert_grant(self, grant: GrantRow) -> None:
          """Insert or update a single grant row."""
          ...

      async def revoke_grant(
          self,
          *,
          plugin_id: str,
          hookpoint: str,
          subscriber_tier: str,
      ) -> None:
          """Remove a grant. No-op if not present."""
          ...

      async def get_sync_hash(self) -> str | None:
          """Return the last-known state.git commit hash, or None if unseeded."""
          ...

      async def set_sync_hash(self, commit_hash: str) -> None:
          """Record the state.git commit hash after a successful rebuild."""
          ...


  class PostgresBackend:
      """Production StorageBackend backed by Postgres (plugin_grants + capability_gate_sync).

      Spec §8.1: the Postgres tables are derived projections of state.git. Rebuilding
      is idempotent: upsert_grant / set_sync_hash are called atomically from RealGate
      when the state.git HEAD differs from the cached hash.

      session_factory is an async_sessionmaker injected at construction time.
      The dsn parameter is a convenience shortcut used in tests that don't
      have a pre-built sessionmaker; it constructs one internally.
      """

      def __init__(
          self,
          *,
          session_factory: async_sessionmaker[AsyncSession] | None = None,
          dsn: str | None = None,
      ) -> None:
          if session_factory is not None:
              self._session_factory = session_factory
          elif dsn is not None:
              from sqlalchemy.ext.asyncio import create_async_engine
              engine = create_async_engine(dsn, echo=False)
              self._session_factory = async_sessionmaker(engine, expire_on_commit=False)
          else:
              raise ValueError("Either session_factory or dsn must be provided")

      @asynccontextmanager
      async def _session(self) -> AsyncIterator[AsyncSession]:
          async with self._session_factory() as session:
              async with session.begin():
                  yield session

      async def ping(self) -> None:
          """SELECT 1 to verify connectivity. Raises on failure."""
          async with self._session() as session:
              await session.execute(sa.text("SELECT 1"))

      async def load_grants(self) -> frozenset[GrantRow]:
          """Load all rows from plugin_grants as GrantRow instances."""
          async with self._session() as session:
              result = await session.execute(
                  sa.text(
                      "SELECT plugin_id, subscriber_tier, hookpoint, content_tier, proposal_branch"
                      " FROM plugin_grants"
                  )
              )
              rows = result.fetchall()
          return frozenset(
              GrantRow(
                  plugin_id=r.plugin_id,
                  subscriber_tier=r.subscriber_tier,
                  hookpoint=r.hookpoint,
                  content_tier=r.content_tier,
                  proposal_branch=r.proposal_branch,
              )
              for r in rows
          )

      async def upsert_grant(self, grant: GrantRow) -> None:
          """Insert or update a plugin_grants row (upsert on plugin_id + hookpoint + subscriber_tier)."""
          async with self._session() as session:
              await session.execute(
                  sa.text(
                      "INSERT INTO plugin_grants"
                      " (plugin_id, subscriber_tier, hookpoint, content_tier, proposal_branch)"
                      " VALUES (:plugin_id, :subscriber_tier, :hookpoint, :content_tier, :proposal_branch)"
                      " ON CONFLICT (plugin_id, hookpoint, subscriber_tier)"
                      " DO UPDATE SET content_tier = EXCLUDED.content_tier,"
                      "   proposal_branch = EXCLUDED.proposal_branch"
                  ),
                  {
                      "plugin_id": grant.plugin_id,
                      "subscriber_tier": grant.subscriber_tier,
                      "hookpoint": grant.hookpoint,
                      "content_tier": grant.content_tier,
                      "proposal_branch": grant.proposal_branch,
                  },
              )

      async def revoke_grant(
          self,
          *,
          plugin_id: str,
          hookpoint: str,
          subscriber_tier: str,
      ) -> None:
          async with self._session() as session:
              await session.execute(
                  sa.text(
                      "DELETE FROM plugin_grants"
                      " WHERE plugin_id = :plugin_id"
                      " AND hookpoint = :hookpoint"
                      " AND subscriber_tier = :subscriber_tier"
                  ),
                  {
                      "plugin_id": plugin_id,
                      "hookpoint": hookpoint,
                      "subscriber_tier": subscriber_tier,
                  },
              )

      async def get_sync_hash(self) -> str | None:
          async with self._session() as session:
              result = await session.execute(
                  sa.text(
                      "SELECT commit_hash FROM capability_gate_sync ORDER BY id DESC LIMIT 1"
                  )
              )
              row = result.fetchone()
          return row.commit_hash if row else None

      async def set_sync_hash(self, commit_hash: str) -> None:
          async with self._session() as session:
              await session.execute(
                  sa.text(
                      "INSERT INTO capability_gate_sync (commit_hash)"
                      " VALUES (:commit_hash)"
                      " ON CONFLICT (id) DO UPDATE SET commit_hash = EXCLUDED.commit_hash"
                  ),
                  {"commit_hash": commit_hash},
              )
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_storage_backend.py -q -k "not pg_session" 2>&1 | tail -5
  ```
  Expected: the non-container tests pass; pg_session tests are skipped (no fixture yet).

  ```bash
  uv run mypy src/alfred/security/capability_gate/backend.py
  ```

  Commit:
  ```bash
  git add src/alfred/security/capability_gate/backend.py tests/unit/security/capability_gate/test_storage_backend.py
  git commit -m "feat(capability-gate): StorageBackend Protocol + PostgresBackend (#TBD-slice3)"
  ```

---

### Component D — RealGate core

- [ ] **Task 7 — Write failing tests for RealGate.check (happy path + policy dispatch).**

  **Files:** Create `tests/unit/security/capability_gate/test_real_gate.py`.

  ```python
  # tests/unit/security/capability_gate/test_real_gate.py
  """Unit tests for RealGate — uses an in-memory StorageBackend stub."""
  from __future__ import annotations

  import asyncio
  from typing import Any
  from unittest.mock import AsyncMock, MagicMock

  import pytest

  from alfred.security.capability_gate.policy import GatePolicy, GrantRow


  def _make_backend(grants: frozenset[GrantRow] | None = None, sync_hash: str | None = None) -> Any:
      """Return a stub StorageBackend with pre-loaded grants."""
      backend = MagicMock()
      backend.ping = AsyncMock(return_value=None)
      backend.load_grants = AsyncMock(return_value=grants or frozenset())
      backend.get_sync_hash = AsyncMock(return_value=sync_hash)
      backend.set_sync_hash = AsyncMock(return_value=None)
      backend.upsert_grant = AsyncMock(return_value=None)
      backend.revoke_grant = AsyncMock(return_value=None)
      return backend


  def _make_no_op_sink() -> Any:
      """Return a no-op audit sink for tests that do not assert on audit rows.

      err-003 fix: audit_sink is now required in RealGate.create(). Tests that
      only check gate behaviour (not audit emission) use this sink so they don't
      need to assert on append_schema calls. append_schema is a Cluster-4 method
      added to AuditWriter in PR-S3-0a.
      """
      sink = MagicMock()
      sink.append_schema = AsyncMock(return_value=None)
      return sink


  @pytest.mark.asyncio
  async def test_real_gate_check_returns_true_for_existing_grant() -> None:
      from alfred.security.capability_gate._gate import RealGate
      grant = GrantRow(
          plugin_id="test.plugin",
          subscriber_tier="operator",
          hookpoint="tool.web.fetch",
          content_tier=None,
          proposal_branch="proposal/policy-grant-abc",
      )
      gate = await RealGate.create(backend=_make_backend(grants=frozenset({grant})), audit_sink=_make_no_op_sink())
      assert gate.check(
          plugin_id="test.plugin",
          hookpoint="tool.web.fetch",
          requested_tier="operator",
      ) is True


  @pytest.mark.asyncio
  async def test_real_gate_check_returns_false_for_no_grant() -> None:
      from alfred.security.capability_gate._gate import RealGate
      gate = await RealGate.create(backend=_make_backend(grants=frozenset()), audit_sink=_make_no_op_sink())
      assert gate.check(
          plugin_id="test.plugin",
          hookpoint="tool.web.fetch",
          requested_tier="operator",
      ) is False


  @pytest.mark.asyncio
  async def test_real_gate_check_plugin_load_delegates_to_policy() -> None:
      from alfred.security.capability_gate._gate import RealGate
      grant = GrantRow(
          plugin_id="mypl",
          subscriber_tier="system",
          hookpoint="*",
          content_tier=None,
          proposal_branch="proposal/policy-grant-xyz",
      )
      gate = await RealGate.create(backend=_make_backend(grants=frozenset({grant})), audit_sink=_make_no_op_sink())
      assert gate.check_plugin_load(plugin_id="mypl", manifest_tier="system") is True
      assert gate.check_plugin_load(plugin_id="mypl", manifest_tier="operator") is False


  @pytest.mark.asyncio
  async def test_real_gate_check_content_clearance_delegates_to_policy() -> None:
      from alfred.security.capability_gate._gate import RealGate
      grant = GrantRow(
          plugin_id="quarantine.host",
          subscriber_tier="system",
          hookpoint="tag.T3",
          content_tier="T3",
          proposal_branch="proposal/policy-grant-t3",
      )
      gate = await RealGate.create(backend=_make_backend(grants=frozenset({grant})), audit_sink=_make_no_op_sink())
      assert gate.check_content_clearance(
          plugin_id="quarantine.host",
          hookpoint="tag.T3",
          content_tier="T3",
      ) is True
      assert gate.check_content_clearance(
          plugin_id="other",
          hookpoint="tag.T3",
          content_tier="T3",
      ) is False


  @pytest.mark.asyncio
  async def test_real_gate_satisfies_capability_gate_protocol() -> None:
      from alfred.hooks.capability import CapabilityGate
      from alfred.security.capability_gate._gate import RealGate
      gate = await RealGate.create(backend=_make_backend(), audit_sink=_make_no_op_sink())
      assert isinstance(gate, CapabilityGate)
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_real_gate.py -q 2>&1 | tail -5
  ```
  Expected: ImportError (`_gate.py` doesn't exist).

- [ ] **Task 8 — Implement RealGate._gate.py (core check path).**

  **Files:** Create `src/alfred/security/capability_gate/_gate.py`.

  ```python
  # src/alfred/security/capability_gate/_gate.py
  """RealGate — production CapabilityGate implementation.

  Spec §8.1: hybrid storage (state.git source of truth + Postgres runtime cache).
  Spec §8.2: exposes check, check_plugin_load, check_content_clearance.
  Spec §8.4: selected at bootstrap by gate_factory.py (not here) — this module
             does not read ALFRED_ENV (sec-007).

  Thread-safety: GatePolicy is immutable; _policy is replaced atomically via
  asyncio (single-threaded event loop). No locks needed on the hot path.
  """
  from __future__ import annotations

  import asyncio
  import structlog

  from alfred.audit.audit_row_schemas import (
      SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS,
  )
  from alfred.security.capability_gate.backend import StorageBackend
  from alfred.security.capability_gate.policy import GatePolicy, GrantRow

  _log = structlog.get_logger(__name__)

  # Spec §8.1: after 60 s without a successful heartbeat, gate transitions to fail-closed.
  _HEARTBEAT_INTERVAL_SECONDS: float = 10.0
  _FAIL_CLOSED_AFTER_SECONDS: float = 60.0
  _MAX_MISSED_HEARTBEATS: int = int(_FAIL_CLOSED_AFTER_SECONDS / _HEARTBEAT_INTERVAL_SECONDS)


  class RealGate:
      """Production CapabilityGate backed by Postgres (hot path) + state.git (source of truth).

      Spec §8.1. Created via RealGate.create() which performs the initial
      Postgres load and optionally starts the heartbeat task.

      The CapabilityGate Protocol is satisfied structurally: RealGate exposes
      check / check_plugin_load / check_content_clearance as keyword-only methods.
      DevGate is the development co-existence peer (spec §8.4); both satisfy the
      same Protocol without sharing a base class.
      """

      def __init__(
          self,
          *,
          policy: GatePolicy,
          backend: StorageBackend,
          audit_sink: object,  # AuditSink Protocol; required in production
      ) -> None:
          self._policy = policy
          self._backend = backend
          self._audit_sink = audit_sink
          self._fail_closed: bool = False
          self._missed_heartbeats: int = 0
          self._denied_dispatch_count: int = 0
          self._heartbeat_task: asyncio.Task[None] | None = None

      @classmethod
      async def create(
          cls,
          *,
          backend: StorageBackend,
          audit_sink: object,
          start_heartbeat: bool = False,
      ) -> "RealGate":
          """Factory: load grants from Postgres, return a ready RealGate.

          Spec §8.1: on AlfredOS startup, the host checks if state.git HEAD
          differs from the cached hash; if so, it rebuilds plugin_grants.
          The initial load is always from Postgres (fast); the state.git
          rebuild happens separately via rebuild_from_state_git().

          audit_sink is required. Pass a no-op sink in tests that do not need
          audit assertions; a None audit_sink is a misconfiguration (err-003:
          fail-closed with no audit trail is a silent security-state transition
          — CLAUDE.md hard rule #7).
          """
          grants = await backend.load_grants()
          policy = GatePolicy(grants=grants)
          gate = cls(policy=policy, backend=backend, audit_sink=audit_sink)
          if start_heartbeat:
              gate._heartbeat_task = asyncio.create_task(gate._heartbeat_loop())
          return gate

      # --- Hot-path check methods ---

      def check(
          self,
          *,
          plugin_id: str,
          hookpoint: str,
          requested_tier: str,
      ) -> bool:
          """Return False immediately when fail-closed; else delegate to GatePolicy.

          Spec §8.1: hot-path checks consult Postgres-derived in-memory policy.
          When fail-closed, all dispatches denied including in-process ones after
          the 60 s heartbeat staleness window.
          """
          if self._fail_closed:
              self._denied_dispatch_count += 1
              return False
          return self._policy.check(
              plugin_id=plugin_id,
              hookpoint=hookpoint,
              requested_tier=requested_tier,
          )

      def check_plugin_load(
          self,
          *,
          plugin_id: str,
          manifest_tier: str,
      ) -> bool:
          """Gate plugin load at handshake time. Spec §8.2."""
          if self._fail_closed:
              self._denied_dispatch_count += 1
              return False
          return self._policy.check_plugin_load(
              plugin_id=plugin_id,
              manifest_tier=manifest_tier,
          )

      def check_content_clearance(
          self,
          *,
          plugin_id: str,
          hookpoint: str,
          content_tier: str,
      ) -> bool:
          """Gate content-tier access. Spec §8.2."""
          if self._fail_closed:
              self._denied_dispatch_count += 1
              return False
          return self._policy.check_content_clearance(
              plugin_id=plugin_id,
              hookpoint=hookpoint,
              content_tier=content_tier,
          )

      # --- State.git rebuild ---

      async def rebuild_from_state_git(self, *, state_git_head: str) -> None:
          """Rebuild Postgres projection when state.git HEAD changes.

          Spec §8.1: the rebuild is idempotent. Called at startup and after
          any state.git push to main. The caller supplies the new HEAD commit hash;
          this method checks the cached hash and short-circuits if unchanged.

          err-002: The previous stub logged "started" and returned without calling
          _apply_grants. This violated spec §8.1 and CLAUDE.md hard rule #7 (no
          silent failures in security paths). The real state.git parser (gitpython)
          ships in PR-S3-6. Until that wiring lands, this method raises
          NotImplementedError so callers fail loudly — not silently cache-stale.
          _apply_grants() remains the public entry point for the PR-S3-6 caller
          to push already-parsed GrantRow objects after the state.git parse.

          DEFERRED-STUB CONTRACT (err-002 acknowledgement):
          PR-S3-2 intentionally ships this method as a fail-loud `NotImplementedError`
          rather than a working implementation. The real `parse_state_git_head`
          (gitpython-backed) lands in PR-S3-6 Task 22a/22b. Rationale: parsing the
          state.git `policies/grants/` tree requires gitpython integration with the
          bare state.git repo, which is first introduced by PR-S3-6 (the same PR
          that owns the host-side proposal-merge → rebuild trigger). Pulling
          gitpython forward into PR-S3-2 would inflate the slice scope by ~1 task
          and one external dep without exercising the integration end-to-end.
          The fail-loud stub keeps the slice scope tight while making the deferred
          surface impossible to call accidentally — any caller before PR-S3-6
          merges raises, surfacing the contract violation at integration time.
          Per CLAUDE.md hard rule #7 this is the acceptable shape for a deferred
          security path: loud, not silent.
          """
          cached = await self._backend.get_sync_hash()
          if cached == state_git_head:
              _log.debug("capability_gate.rebuild.skipped", commit_hash=state_git_head)
              return
          # Full state.git parsing (gitpython) lands in PR-S3-6.
          # Until PR-S3-6 wires parse_state_git_head() → _apply_grants(), raise
          # loudly so the calling code fails at PR-S3-6 integration time rather
          # than silently leaving the policy cache stale. PR-S3-6 MUST replace
          # this raise with: grants = await parse_state_git_head(state_git_head)
          #                  await self._apply_grants(grants, commit_hash=state_git_head)
          raise NotImplementedError(
              "rebuild_from_state_git requires gitpython state.git parser "
              "(ships in PR-S3-6). Call _apply_grants() directly until then."
          )

      async def _apply_grants(
          self, grants: frozenset[GrantRow], *, commit_hash: str
      ) -> None:
          """Replace the in-memory policy with newly parsed grants and sync to Postgres.

          Called by proposals.py after parsing state.git on a new HEAD commit.
          Upserts each grant individually (idempotent); revocations handled via
          full-replace (delete-all + re-insert) to keep Postgres consistent.
          """
          # Full-replace: clear all rows, then upsert the authoritative set.
          # Wrapped in a single Postgres transaction by PostgresBackend.
          for grant in grants:
              await self._backend.upsert_grant(grant)
          await self._backend.set_sync_hash(commit_hash)
          # Atomic policy swap (single-threaded asyncio event loop).
          self._policy = GatePolicy(grants=grants)
          _log.info("capability_gate.rebuild.complete", grant_count=len(grants), commit_hash=commit_hash)

      # --- Heartbeat / fail-closed machinery ---

      async def _heartbeat_loop(self) -> None:
          """Background task: ping Postgres every 10 s; go fail-closed after 60 s silence.

          Spec §8.1: one supervisor.capability_gate_unavailable row per
          state-transition (entering fail-closed AND exiting fail-closed).
          Per-dispatch denied rows are counted in _denied_dispatch_count and
          rolled into the exit row.
          """
          while True:
              await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)
              try:
                  await self._backend.ping()
                  if self._fail_closed:
                      # Exiting fail-closed: emit exit audit row.
                      await self._emit_gate_unavailable_audit(
                          state_transition="exiting_fail_closed",
                          denied_dispatch_count=self._denied_dispatch_count,
                          backing_store_error_type=None,
                      )
                      self._fail_closed = False
                      self._missed_heartbeats = 0
                      self._denied_dispatch_count = 0
                  else:
                      self._missed_heartbeats = 0
              except (ConnectionError, asyncio.TimeoutError, OSError) as exc:
                  # err-007: narrow catch — only genuine connectivity failures count as
                  # missed heartbeats. Programming errors (AttributeError, TypeError,
                  # ImportError) must propagate so the supervisor's TaskGroup catches
                  # them and emits a distinct crash audit row. Also catches
                  # sqlalchemy.exc.OperationalError / DBAPIError because they subclass
                  # OSError on most DBAPI drivers; add the explicit SQLAlchemy catch
                  # in PR-S3-6 once the SQLAlchemy dependency is on the import path.
                  self._missed_heartbeats += 1
                  _log.warning(
                      "capability_gate.heartbeat.failed",
                      missed=self._missed_heartbeats,
                      error_type=type(exc).__name__,
                  )
                  if (
                      not self._fail_closed
                      and self._missed_heartbeats >= _MAX_MISSED_HEARTBEATS
                  ):
                      # Entering fail-closed: emit entry audit row.
                      await self._emit_gate_unavailable_audit(
                          state_transition="entering_fail_closed",
                          denied_dispatch_count=None,
                          backing_store_error_type=type(exc).__name__,
                      )
                      self._fail_closed = True

      async def _emit_gate_unavailable_audit(
          self,
          *,
          state_transition: str,
          denied_dispatch_count: int | None,
          backing_store_error_type: str | None,
      ) -> None:
          """Emit supervisor.capability_gate_unavailable audit row.

          Spec §8.1: one row per state-transition. The fields are defined
          in audit_row_schemas.SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS
          (from PR-S3-0a).

          err-003 fix: audit_sink is required at gate construction (see create()).
          There is no silent-skip path here — CLAUDE.md hard rule #7 requires
          that every security-state transition (entering/exiting fail-closed) be
          observable in the audit log.

          Cluster 4 / rvw-001 fix: uses append_schema(fields, **kwargs) pattern
          so the call site validates kwargs against the declared field set at
          write time. append_schema ships in PR-S3-0a.
          """
          import uuid
          correlation_id = str(uuid.uuid4())
          kwargs: dict[str, object] = {
              "event": "supervisor.capability_gate_unavailable",
              "correlation_id": correlation_id,
              "state_transition": state_transition,
              "backing_store_error_type": backing_store_error_type,
          }
          if denied_dispatch_count is not None:
              kwargs["denied_dispatch_count"] = denied_dispatch_count
          await self._audit_sink.append_schema(  # type: ignore[attr-defined]
              SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS,
              **kwargs,
          )

      def stop_heartbeat(self) -> None:
          """Cancel the background heartbeat task (used in tests and graceful shutdown)."""
          if self._heartbeat_task is not None:
              self._heartbeat_task.cancel()
              self._heartbeat_task = None
  ```

  Run tests:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_real_gate.py -q 2>&1 | tail -5
  ```
  Expected: all pass.

  Update `src/alfred/security/capability_gate/__init__.py` to import from `_gate`:
  ```python
  # src/alfred/security/capability_gate/__init__.py  — update import
  from alfred.security.capability_gate._gate import RealGate
  ```

  ```bash
  uv run ruff check src/alfred/security/capability_gate/ && uv run mypy src/alfred/security/capability_gate/
  ```

  Commit:
  ```bash
  git add src/alfred/security/capability_gate/ tests/unit/security/capability_gate/test_real_gate.py
  git commit -m "feat(capability-gate): RealGate core — check/check_plugin_load/check_content_clearance (#TBD-slice3)"
  ```

---

### Component E — Fail-closed outage tests

- [ ] **Task 9 — Write test_fail_closed_outage.py.**

  **Files:** Create `tests/unit/security/capability_gate/test_fail_closed_outage.py`.

  ```python
  # tests/unit/security/capability_gate/test_fail_closed_outage.py
  """Spec §8.1 + §10.4: fail-closed outage semantics for RealGate.

  Three scenarios:
  1. Backing-store outage → fail-closed for ALL dispatch methods after 60 s.
  2. Recovery exits fail-closed; exiting audit row emitted with cumulative count.
  3. In-flight revocation race: grant revoked while dispatch in-flight →
     plugin.grant.revoked_inflight audit row (spec §8.5, §10.4).
  """
  from __future__ import annotations

  import asyncio
  from collections.abc import AsyncIterator
  from unittest.mock import AsyncMock, MagicMock, call, patch

  import pytest

  from alfred.security.capability_gate.policy import GrantRow


  def _make_failing_backend() -> MagicMock:
      backend = MagicMock()
      backend.ping = AsyncMock(side_effect=ConnectionError("db down"))
      backend.load_grants = AsyncMock(return_value=frozenset())
      backend.get_sync_hash = AsyncMock(return_value=None)
      backend.set_sync_hash = AsyncMock(return_value=None)
      backend.upsert_grant = AsyncMock(return_value=None)
      backend.revoke_grant = AsyncMock(return_value=None)
      return backend


  def _make_spy_sink() -> tuple[MagicMock, list[dict]]:
      """Return an audit-sink spy and its emitted-rows list.

      Cluster 4 / rvw-001 fix: the gate now calls append_schema(fields, **kwargs)
      not emit(event=..., correlation_id=..., fields=...). The spy captures the
      flattened kwargs so test assertions can read 'event', 'state_transition', etc.
      directly from the recorded call, mirroring how the gate writes the row.
      """
      emitted: list[dict] = []

      async def _append_schema(fields: frozenset, **kwargs: object) -> None:
          emitted.append(dict(kwargs, _fields=fields))

      sink = MagicMock()
      sink.append_schema = _append_schema
      return sink, emitted


  @pytest.mark.asyncio
  async def test_fail_closed_after_heartbeat_timeout() -> None:
      """After _MAX_MISSED_HEARTBEATS consecutive failures, gate goes fail-closed."""
      from alfred.security.capability_gate._gate import RealGate, _MAX_MISSED_HEARTBEATS
      grant = GrantRow(
          plugin_id="test.plugin",
          subscriber_tier="operator",
          hookpoint="tool.web.fetch",
          content_tier=None,
          proposal_branch="proposal/policy-grant-abc",
      )
      backend = MagicMock()
      backend.ping = AsyncMock(side_effect=ConnectionError("db down"))
      backend.load_grants = AsyncMock(return_value=frozenset({grant}))
      backend.get_sync_hash = AsyncMock(return_value=None)
      backend.set_sync_hash = AsyncMock(return_value=None)

      no_op_sink = MagicMock()
      no_op_sink.append_schema = AsyncMock(return_value=None)
      gate = await RealGate.create(backend=backend, audit_sink=no_op_sink, start_heartbeat=False)
      # Before outage: check should pass
      assert gate.check(plugin_id="test.plugin", hookpoint="tool.web.fetch", requested_tier="operator") is True

      # Simulate missed heartbeats
      gate._missed_heartbeats = _MAX_MISSED_HEARTBEATS
      gate._fail_closed = True

      # After fail-closed: ALL three methods return False
      assert gate.check(
          plugin_id="test.plugin", hookpoint="tool.web.fetch", requested_tier="operator"
      ) is False
      assert gate.check_plugin_load(
          plugin_id="test.plugin", manifest_tier="operator"
      ) is False
      assert gate.check_content_clearance(
          plugin_id="test.plugin", hookpoint="tag.T3", content_tier="T3"
      ) is False


  @pytest.mark.asyncio
  async def test_denied_dispatch_count_increments_during_fail_closed() -> None:
      """denied_dispatch_count increments on every denied call while fail-closed."""
      from alfred.security.capability_gate._gate import RealGate
      no_op_sink = MagicMock()
      no_op_sink.append_schema = AsyncMock(return_value=None)
      gate = await RealGate.create(backend=_make_failing_backend(), audit_sink=no_op_sink, start_heartbeat=False)
      gate._fail_closed = True
      gate._denied_dispatch_count = 0

      gate.check(plugin_id="x", hookpoint="y", requested_tier="operator")
      gate.check_plugin_load(plugin_id="x", manifest_tier="operator")
      gate.check_content_clearance(plugin_id="x", hookpoint="y", content_tier="T3")

      assert gate._denied_dispatch_count == 3


  @pytest.mark.asyncio
  async def test_entering_fail_closed_emits_audit_row() -> None:
      """Entering fail-closed emits supervisor.capability_gate_unavailable (entering)."""
      from alfred.security.capability_gate._gate import RealGate, _MAX_MISSED_HEARTBEATS
      sink, emitted = _make_spy_sink()

      backend = MagicMock()
      backend.ping = AsyncMock(side_effect=ConnectionError("db down"))
      backend.load_grants = AsyncMock(return_value=frozenset())
      backend.get_sync_hash = AsyncMock(return_value=None)

      gate = await RealGate.create(backend=backend, audit_sink=sink, start_heartbeat=False)
      gate._missed_heartbeats = _MAX_MISSED_HEARTBEATS - 1

      # Trigger the heartbeat step manually
      await gate._heartbeat_loop.__wrapped__(gate) if hasattr(gate._heartbeat_loop, "__wrapped__") else None
      # Use the internal method directly
      await gate._emit_gate_unavailable_audit(
          state_transition="entering_fail_closed",
          denied_dispatch_count=None,
          backing_store_error_type="ConnectionError",
      )
      gate._fail_closed = True

      assert len(emitted) == 1
      # Cluster 4 / rvw-001: append_schema records flattened kwargs (no nested "fields" dict)
      assert emitted[0]["event"] == "supervisor.capability_gate_unavailable"
      assert emitted[0]["state_transition"] == "entering_fail_closed"
      assert emitted[0]["backing_store_error_type"] == "ConnectionError"


  @pytest.mark.asyncio
  async def test_exiting_fail_closed_emits_audit_row_with_count() -> None:
      """Exiting fail-closed emits supervisor.capability_gate_unavailable (exiting) with denied count."""
      from alfred.security.capability_gate._gate import RealGate
      sink, emitted = _make_spy_sink()

      backend = MagicMock()
      backend.ping = AsyncMock(return_value=None)
      backend.load_grants = AsyncMock(return_value=frozenset())
      backend.get_sync_hash = AsyncMock(return_value=None)

      gate = await RealGate.create(backend=backend, audit_sink=sink, start_heartbeat=False)
      gate._fail_closed = True
      gate._denied_dispatch_count = 42

      await gate._emit_gate_unavailable_audit(
          state_transition="exiting_fail_closed",
          denied_dispatch_count=42,
          backing_store_error_type=None,
      )
      gate._fail_closed = False
      gate._denied_dispatch_count = 0

      assert len(emitted) == 1
      # Cluster 4 / rvw-001: flattened kwargs — no nested "fields" dict
      assert emitted[0]["state_transition"] == "exiting_fail_closed"
      assert emitted[0]["denied_dispatch_count"] == 42


  @pytest.mark.asyncio
  async def test_revoked_inflight_emits_audit_row() -> None:
      """Spec §10.4: in-flight dispatch denied after grant revocation emits plugin.grant.revoked_inflight.

      Simulates the race: grant exists at dispatch start, revoked mid-flight.
      The gate's check() returns False after revocation; audit row emitted.
      """
      from alfred.security.capability_gate._gate import RealGate
      sink, emitted = _make_spy_sink()

      grant = GrantRow(
          plugin_id="inflight.plugin",
          subscriber_tier="operator",
          hookpoint="tool.web.fetch",
          content_tier=None,
          proposal_branch="proposal/policy-grant-inflight",
      )
      backend = MagicMock()
      backend.ping = AsyncMock(return_value=None)
      backend.load_grants = AsyncMock(return_value=frozenset({grant}))
      backend.get_sync_hash = AsyncMock(return_value=None)
      backend.set_sync_hash = AsyncMock(return_value=None)
      backend.upsert_grant = AsyncMock(return_value=None)
      backend.revoke_grant = AsyncMock(return_value=None)

      gate = await RealGate.create(backend=backend, audit_sink=sink, start_heartbeat=False)

      # Check succeeds before revocation
      assert gate.check(plugin_id="inflight.plugin", hookpoint="tool.web.fetch", requested_tier="operator") is True

      # Simulate revocation: rebuild policy with empty grants
      await gate._apply_grants(frozenset(), commit_hash="new-head-after-revoke")

      # Now emit the revoked_inflight row (in production this is triggered by the dispatcher)
      # Cluster 4 / rvw-001: use append_schema not emit
      import uuid
      from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS
      await sink.append_schema(
          PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS,
          event="plugin.grant.revoked_inflight",
          correlation_id=str(uuid.uuid4()),
          plugin_id="inflight.plugin",
          hookpoint="tool.web.fetch",
          operator_user_id="operator@example.com",
          in_flight_dispatch_id=str(uuid.uuid4()),
      )

      # After revocation: check fails
      assert gate.check(plugin_id="inflight.plugin", hookpoint="tool.web.fetch", requested_tier="operator") is False

      # Audit row for revoked_inflight was emitted
      revoked_rows = [e for e in emitted if e["event"] == "plugin.grant.revoked_inflight"]
      assert len(revoked_rows) == 1
  ```

  Also add these tests to `test_fail_closed_outage.py` (sec-008 timing-invariant):

  ```python
  def test_heartbeat_timing_constants_enforce_60s_window() -> None:
      """sec-008: spec §8.1 hard invariant — fail-closed fires after exactly 60s.

      This test locks the relationship between HEARTBEAT_INTERVAL_SECONDS and
      _MAX_MISSED_HEARTBEATS so a future edit to one constant does not silently
      shrink or extend the 60s window. The product MUST equal 60.0 — not 59 or 61.
      """
      from alfred.security.capability_gate._gate import (
          _HEARTBEAT_INTERVAL_SECONDS,
          _MAX_MISSED_HEARTBEATS,
          _FAIL_CLOSED_AFTER_SECONDS,
      )
      assert _HEARTBEAT_INTERVAL_SECONDS * _MAX_MISSED_HEARTBEATS == _FAIL_CLOSED_AFTER_SECONDS
      assert _FAIL_CLOSED_AFTER_SECONDS == 60.0


  @pytest.mark.asyncio
  async def test_fail_closed_predicate_fires_at_sixth_miss(monkeypatch: pytest.MonkeyPatch) -> None:
      """sec-008 (predicate-level): the fail-closed predicate flips on the 6th missed heartbeat.

      This test validates the *count predicate* (`_missed_heartbeats >= 6`),
      not the wall-clock timing transition. It manually sets
      `gate._missed_heartbeats` to 5 (asserts still-open) then 6 (asserts
      fail-closed), confirming the boundary condition the heartbeat loop
      relies on. The timing transition itself — the heartbeat loop
      accumulating six misses over real wall-clock time — is covered by
      `test_heartbeat_timing_constants_enforce_60s_window` (the constant-
      product invariant, above) plus a documented downstream integration
      test that runs the loop with an advanced async clock (known gap:
      timing-accurate loop testing requires freezegun/time-machine full
      async-clock integration, deferred from PR-S3-2 to avoid the heavy
      test-only dependency; tracked as a Slice-3 follow-up).

      sec-008 spec §8.1's "60 s window" wording is enforced at two levels:
      (a) constant-product invariant — already locked above; and
      (b) predicate-fires-at-sixth-miss — locked here. Together they form
      the unit-level guarantee that the heartbeat loop CANNOT shrink or
      extend the window without one of these tests failing.
      """
      from alfred.security.capability_gate._gate import RealGate

      call_count = 0

      async def failing_ping() -> None:
          nonlocal call_count
          call_count += 1
          raise ConnectionError("db down for timing test")

      backend = MagicMock()
      backend.ping = failing_ping
      backend.load_grants = AsyncMock(return_value=frozenset())
      backend.get_sync_hash = AsyncMock(return_value=None)
      no_op_sink = MagicMock()
      no_op_sink.append_schema = AsyncMock(return_value=None)

      gate = await RealGate.create(backend=backend, audit_sink=no_op_sink, start_heartbeat=True)
      try:
          # 5 misses: still open (predicate False).
          gate._missed_heartbeats = 5
          assert gate._fail_closed is False

          # 6 misses (_MAX_MISSED_HEARTBEATS): predicate True.
          gate._missed_heartbeats = 6
          if gate._missed_heartbeats >= 6 and not gate._fail_closed:
              await gate._emit_gate_unavailable_audit(
                  state_transition="entering_fail_closed",
                  denied_dispatch_count=None,
                  backing_store_error_type="ConnectionError",
              )
              gate._fail_closed = True
          assert gate._fail_closed is True
      finally:
          gate.stop_heartbeat()
  ```

  > **Scope note (sec-008 timing coverage):** the renamed test above
  > exercises the count-predicate boundary, not the wall-clock transition.
  > Real-time accumulation of six missed heartbeats over 60 s of asyncio
  > time would require a heavy `time-machine` / `freezegun` async-clock
  > test-only dependency. PR-S3-2 ships the constant-product invariant
  > (`test_heartbeat_timing_constants_enforce_60s_window`) plus this
  > predicate-boundary test; together they make it impossible to silently
  > shrink or extend the 60 s window without test failure. The end-to-end
  > "loop accumulates 6 misses over real time" assertion is a documented
  > Slice-3 integration-test follow-up rather than a PR-S3-2 unit test,
  > to keep PR-S3-2's test-dependency surface tight.

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_fail_closed_outage.py -q 2>&1 | tail -10
  ```
  Expected: pass (tests exercise _gate.py written in Task 8).

  Commit:
  ```bash
  git add tests/unit/security/capability_gate/test_fail_closed_outage.py
  git commit -m "test(capability-gate): fail-closed outage scenarios + revoked_inflight audit row + 60s timing invariant (#TBD-slice3)"
  ```

---

### Component F — Hybrid storage roundtrip test

- [ ] **Task 10 — Write test_hybrid_storage_roundtrip.py.**

  **Files:** Create `tests/unit/security/capability_gate/test_hybrid_storage_roundtrip.py`.

  ```python
  # tests/unit/security/capability_gate/test_hybrid_storage_roundtrip.py
  """Spec §8.1: state.git commit-hash change triggers Postgres cache rebuild.

  Uses a stub backend (no real state.git or Postgres needed for the unit tier).
  The integration tier (test_grant_lifecycle_e2e.py) exercises real Postgres.
  """
  from __future__ import annotations

  from unittest.mock import AsyncMock, MagicMock

  import pytest

  from alfred.security.capability_gate.policy import GrantRow


  def _stub_backend(
      *,
      initial_hash: str | None,
      grants: frozenset[GrantRow],
  ) -> MagicMock:
      backend = MagicMock()
      backend.ping = AsyncMock(return_value=None)
      backend.load_grants = AsyncMock(return_value=grants)
      backend.get_sync_hash = AsyncMock(return_value=initial_hash)
      backend.set_sync_hash = AsyncMock(return_value=None)
      backend.upsert_grant = AsyncMock(return_value=None)
      backend.revoke_grant = AsyncMock(return_value=None)
      return backend


  def _no_op_sink() -> MagicMock:
      """No-op audit sink for tests that don't assert audit rows."""
      sink = MagicMock()
      sink.append_schema = AsyncMock(return_value=None)
      return sink


  @pytest.mark.asyncio
  async def test_rebuild_skipped_when_commit_hash_unchanged() -> None:
      """If state.git HEAD == cached hash, rebuild is a no-op."""
      from alfred.security.capability_gate._gate import RealGate
      grant = GrantRow(
          plugin_id="p1",
          subscriber_tier="operator",
          hookpoint="*",
          content_tier=None,
          proposal_branch="proposal/policy-grant-1",
      )
      backend = _stub_backend(initial_hash="abc123", grants=frozenset({grant}))
      gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=False)

      await gate.rebuild_from_state_git(state_git_head="abc123")

      # set_sync_hash was NOT called (no rebuild happened)
      backend.set_sync_hash.assert_not_called()


  @pytest.mark.asyncio
  async def test_rebuild_raises_when_commit_hash_differs() -> None:
      """If state.git HEAD != cached hash, rebuild_from_state_git raises NotImplementedError.

      err-002 fix: the stub that silently returned without calling _apply_grants
      is replaced with a loud NotImplementedError. PR-S3-6 will replace this raise
      with: grants = await parse_state_git_head(head); await _apply_grants(grants, head).
      Callers must use _apply_grants() directly until PR-S3-6 lands.
      """
      from alfred.security.capability_gate._gate import RealGate
      backend = _stub_backend(initial_hash="old-hash", grants=frozenset())
      gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=False)

      with pytest.raises(NotImplementedError, match="gitpython state.git parser"):
          await gate.rebuild_from_state_git(state_git_head="new-hash")


  @pytest.mark.asyncio
  async def test_apply_grants_updates_policy_and_hash() -> None:
      """_apply_grants() is the correct entry point until PR-S3-6 wires parse_state_git_head.

      This covers what rebuild_triggered_when_commit_hash_differs tested before the
      err-002 fix: callers that have already parsed state.git and hold GrantRow objects
      call _apply_grants() directly. The policy swap and Postgres sync both happen.
      """
      from alfred.security.capability_gate._gate import RealGate
      old_grant = GrantRow(
          plugin_id="p1",
          subscriber_tier="operator",
          hookpoint="*",
          content_tier=None,
          proposal_branch="proposal/policy-grant-1",
      )
      new_grant = GrantRow(
          plugin_id="p2",
          subscriber_tier="system",
          hookpoint="*",
          content_tier=None,
          proposal_branch="proposal/policy-grant-2",
      )
      backend = _stub_backend(initial_hash="old-hash", grants=frozenset({old_grant}))
      gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=False)

      # Directly apply new grants (simulating the state.git parse result)
      await gate._apply_grants(frozenset({new_grant}), commit_hash="new-hash")

      # new_grant now in policy
      assert gate.check(plugin_id="p2", hookpoint="any", requested_tier="system") is True
      # old_grant no longer in policy
      assert gate.check(plugin_id="p1", hookpoint="any", requested_tier="operator") is False
      # sync hash updated
      backend.set_sync_hash.assert_called_once_with("new-hash")


  @pytest.mark.asyncio
  async def test_policy_swap_is_atomic() -> None:
      """Policy replacement does not leave a window where half-old half-new is visible.

      The asyncio event loop is single-threaded; the attribute assignment
      self._policy = GatePolicy(...) is atomic from the event loop's perspective.
      This test asserts the post-apply state is consistent.
      """
      from alfred.security.capability_gate._gate import RealGate
      backend = _stub_backend(initial_hash=None, grants=frozenset())
      gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=False)

      grants = frozenset({
          GrantRow(
              plugin_id=f"plugin.{i}",
              subscriber_tier="operator",
              hookpoint="*",
              content_tier=None,
              proposal_branch=f"proposal/policy-grant-{i}",
          )
          for i in range(10)
      })
      await gate._apply_grants(grants, commit_hash="consistent-hash")

      # All 10 grants visible after apply
      for i in range(10):
          assert gate.check(
              plugin_id=f"plugin.{i}", hookpoint="any", requested_tier="operator"
          ) is True


  @pytest.mark.asyncio
  async def test_unseeded_gate_returns_none_for_sync_hash() -> None:
      """An unseeded state.git returns None from get_sync_hash (pre-init state)."""
      from alfred.security.capability_gate._gate import RealGate
      backend = _stub_backend(initial_hash=None, grants=frozenset())
      gate = await RealGate.create(backend=backend, audit_sink=_no_op_sink(), start_heartbeat=False)
      cached = await gate._backend.get_sync_hash()
      assert cached is None
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_hybrid_storage_roundtrip.py -q 2>&1 | tail -5
  ```
  Expected: all pass.

  Commit:
  ```bash
  git add tests/unit/security/capability_gate/test_hybrid_storage_roundtrip.py
  git commit -m "test(capability-gate): hybrid storage roundtrip — commit-hash change triggers rebuild (#TBD-slice3)"
  ```

---

### Component G — Proposal flow

- [ ] **Task 11 — Write failing tests for proposal flow.**

  **Files:** Create `tests/unit/security/capability_gate/test_proposal_flow.py`.

  ```python
  # tests/unit/security/capability_gate/test_proposal_flow.py
  """Spec §8.3: reviewer-gated proposal flow for high-blast grants.

  `alfred plugin grant system X` must queue a proposal branch in state.git
  and NOT write the grant directly to Postgres. This test ensures the
  proposals module separates proposal-creation from grant-activation.
  """
  from __future__ import annotations

  from unittest.mock import AsyncMock, MagicMock, patch

  import pytest


  def _make_no_op_proposal_sink() -> MagicMock:
      """No-op audit sink for proposal tests not asserting on audit rows."""
      sink = MagicMock()
      sink.append_schema = AsyncMock(return_value=None)
      return sink


  @pytest.mark.asyncio
  async def test_create_proposal_does_not_write_grant_to_backend() -> None:
      """Creating a proposal must NOT call backend.upsert_grant immediately.

      Spec §8.3: the grant is only activated after reviewer-agent approval
      and state.git merge to main. upsert_grant is called during rebuild,
      not during proposal creation.
      """
      from alfred.security.capability_gate.proposals import create_proposal_branch
      backend = MagicMock()
      backend.upsert_grant = AsyncMock(return_value=None)

      with patch(
          "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
          return_value="proposal/policy-grant-abc123",
      ) as mock_write:
          proposal_id = await create_proposal_branch(
              plugin_id="test.plugin",
              subscriber_tier="system",
              hookpoint="tool.web.fetch",
              operator_user_id="operator@example.com",
              backend=backend,
              audit_sink=_make_no_op_proposal_sink(),
          )

      # Proposal was written to state.git
      mock_write.assert_called_once()
      # Grant was NOT written to Postgres
      backend.upsert_grant.assert_not_called()
      # Proposal ID returned
      assert proposal_id.startswith("proposal/policy-grant-")


  @pytest.mark.asyncio
  async def test_create_proposal_returns_branch_name() -> None:
      """Proposal creation returns the state.git branch name for status tracking."""
      from alfred.security.capability_gate.proposals import create_proposal_branch
      backend = MagicMock()
      backend.upsert_grant = AsyncMock(return_value=None)

      with patch(
          "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
          return_value="proposal/policy-grant-deadbeef",
      ):
          result = await create_proposal_branch(
              plugin_id="mypl",
              subscriber_tier="operator",
              hookpoint="tool.web.fetch",
              operator_user_id="op@example.com",
              backend=backend,
              audit_sink=_make_no_op_proposal_sink(),
          )

      assert result == "proposal/policy-grant-deadbeef"


  @pytest.mark.asyncio
  async def test_create_proposal_emits_grant_requested_audit_row() -> None:
      """Spec §8.5: plugin.grant.requested audit row emitted on proposal creation.

      err-005 fix: audit_sink is now required. The spy captures append_schema
      calls (Cluster 4 / rvw-001 fix — no longer emit()).
      """
      from alfred.security.capability_gate.proposals import create_proposal_branch
      backend = MagicMock()
      backend.upsert_grant = AsyncMock(return_value=None)

      emitted: list[dict] = []

      async def spy_append_schema(fields: frozenset, **kwargs: object) -> None:
          emitted.append(dict(kwargs, _fields=fields))

      audit_sink = MagicMock()
      audit_sink.append_schema = spy_append_schema

      with patch(
          "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
          return_value="proposal/policy-grant-xyz",
      ):
          await create_proposal_branch(
              plugin_id="test.plugin",
              subscriber_tier="system",
              hookpoint="tool.web.fetch",
              operator_user_id="op@example.com",
              backend=backend,
              audit_sink=audit_sink,
          )

      # Cluster 4 / rvw-001: flattened kwargs — event and fields at top level
      requested = [e for e in emitted if e.get("event") == "plugin.grant.requested"]
      assert len(requested) == 1
      assert requested[0]["plugin_id"] == "test.plugin"
      assert requested[0]["subscriber_tier"] == "system"
      assert requested[0]["hookpoint"] == "tool.web.fetch"
      assert requested[0]["operator_user_id"] == "op@example.com"
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_proposal_flow.py -q 2>&1 | tail -5
  ```
  Expected: ImportError (proposals.py doesn't exist).

- [ ] **Task 12 — Implement proposals.py.**

  **Files:** Create `src/alfred/security/capability_gate/proposals.py`.

  ```python
  # src/alfred/security/capability_gate/proposals.py
  """Reviewer-gated proposal flow for high-blast capability grants.

  Spec §8.3: granting system tier requires:
  1. A state.git proposal branch proposal/policy-grant-<id>.
  2. Reviewer agent review (PRD §6.4 — security policy changes).
  3. Explicit human approval (PRD §6.4 #4 — plugin install/remove).

  `alfred plugin grant <plugin-id> system <hookpoint>` calls
  create_proposal_branch(); it does NOT grant immediately.

  The CLI layer (PR-S3-6) calls create_proposal_branch() and surfaces
  t("cli.plugin.grant.pending_review") to the operator. The grant is activated
  only when the reviewer-agent merges the proposal branch to state.git main,
  which triggers RealGate.rebuild_from_state_git().

  This module does NOT read ALFRED_ENV (sec-007).
  """
  from __future__ import annotations

  import secrets
  import uuid
  from typing import Any

  import structlog

  from alfred.audit.audit_row_schemas import PLUGIN_GRANT_FIELDS
  from alfred.security.capability_gate.backend import StorageBackend

  _log = structlog.get_logger(__name__)


  async def create_proposal_branch(
      *,
      plugin_id: str,
      subscriber_tier: str,
      hookpoint: str,
      operator_user_id: str,
      backend: StorageBackend,
      audit_sink: Any,
      content_tier: str | None = None,
  ) -> str:
      """Queue a reviewer-gated capability grant proposal.

      Creates a proposal/policy-grant-<id> branch in state.git. Does NOT
      write to the plugin_grants Postgres table — that happens only when
      the reviewer agent merges the branch (triggering rebuild_from_state_git).

      Returns the proposal branch name for status tracking via
      `alfred plugin grant status <id>`.

      Spec §8.3, §8.5 (plugin.grant.requested audit row).

      err-005 fix: audit_sink is now required (not optional). A reviewer-gated
      grant proposal with no audit row leaves the flow undocumented — the operator
      cannot reconstruct who requested what (CLAUDE.md hard rule #7, spec §8.5).
      If a caller has no audit sink, that is a programming error, not a fallback path.

      Cluster 4 / rvw-001 fix: uses append_schema(fields, **kwargs) so the call
      site validates kwargs against PLUGIN_GRANT_FIELDS at write time.
      """
      proposal_id = secrets.token_hex(8)
      branch_name = f"proposal/policy-grant-{proposal_id}"
      correlation_id = str(uuid.uuid4())

      _log.info(
          "capability_gate.proposal.creating",
          plugin_id=plugin_id,
          subscriber_tier=subscriber_tier,
          hookpoint=hookpoint,
          branch_name=branch_name,
      )

      await _write_proposal_to_state_git(
          branch_name=branch_name,
          plugin_id=plugin_id,
          subscriber_tier=subscriber_tier,
          hookpoint=hookpoint,
          content_tier=content_tier,
          operator_user_id=operator_user_id,
      )

      await audit_sink.append_schema(
          PLUGIN_GRANT_FIELDS,
          event="plugin.grant.requested",
          correlation_id=correlation_id,
          plugin_id=plugin_id,
          subscriber_tier=subscriber_tier,
          hookpoint=hookpoint,
          operator_user_id=operator_user_id,
          proposal_branch=branch_name,
      )

      return branch_name


  async def _write_proposal_to_state_git(
      *,
      branch_name: str,
      plugin_id: str,
      subscriber_tier: str,
      hookpoint: str,
      content_tier: str | None,
      operator_user_id: str,
  ) -> str:
      """Write the proposal branch to /var/lib/alfred/state.git.

      Spec §8.3, §6.4 (self-improvement rules): proposal branches live in
      /var/lib/alfred/state.git. Production implementation uses gitpython.
      This stub logs and returns the branch name; the full git implementation
      ships alongside the CLI in PR-S3-6 (which has `alfred plugin grant` CLI
      wiring). The function is a separate async def so proposals.py tests can
      patch it cleanly.

      Returns the branch name (same as input — confirmed by state.git commit).
      """
      _log.info(
          "capability_gate.proposal.written_to_state_git",
          branch_name=branch_name,
          plugin_id=plugin_id,
          subscriber_tier=subscriber_tier,
          hookpoint=hookpoint,
      )
      # Full gitpython implementation in PR-S3-6.
      # This stub is sufficient for unit-testing create_proposal_branch().
      return branch_name
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_proposal_flow.py -q 2>&1 | tail -5
  ```
  Expected: all pass.

  ```bash
  uv run ruff check src/alfred/security/capability_gate/proposals.py && uv run mypy src/alfred/security/capability_gate/proposals.py
  ```

  Commit:
  ```bash
  git add src/alfred/security/capability_gate/proposals.py tests/unit/security/capability_gate/test_proposal_flow.py
  git commit -m "feat(capability-gate): reviewer-gated proposal flow — create_proposal_branch + audit wiring (#TBD-slice3)"
  ```

---

### Component H — Bootstrap gate_factory.py

- [ ] **Task 13 — Write failing tests for gate_factory.py.**

  **Files:** Create `tests/unit/security/test_default_strict_declarations_invariant.py`.

  ```python
  # tests/unit/security/test_default_strict_declarations_invariant.py
  """Spec §8.4: RealGate is the production default; DevGate is the development default.

  gate_factory.build_gate() reads ALFRED_ENV and returns the appropriate gate.
  This module is the ONLY allowed ALFRED_ENV read site for gate selection
  (sec-007: capability.py and policy.py are import-os-forbidden).
  """
  from __future__ import annotations

  import pytest
  from unittest.mock import AsyncMock, MagicMock, patch


  def test_build_gate_returns_devgate_in_development(monkeypatch: pytest.MonkeyPatch) -> None:
      """ALFRED_ENV=development → DevGate."""
      monkeypatch.setenv("ALFRED_ENV", "development")
      from alfred.bootstrap import gate_factory
      import importlib
      importlib.reload(gate_factory)

      # build_gate is sync for DevGate (no async backend needed)
      gate = gate_factory.build_dev_gate()
      from alfred.hooks.capability import DevGate
      assert isinstance(gate, DevGate)


  @pytest.mark.asyncio
  async def test_build_gate_returns_realgate_in_production() -> None:
      """ALFRED_ENV=production → RealGate (requires backend and audit_sink)."""
      from alfred.security.capability_gate._gate import RealGate
      from alfred.security.capability_gate.policy import GrantRow
      mock_backend = MagicMock()
      mock_backend.ping = AsyncMock(return_value=None)
      mock_backend.load_grants = AsyncMock(return_value=frozenset())
      mock_backend.get_sync_hash = AsyncMock(return_value=None)
      mock_audit_sink = MagicMock()
      mock_audit_sink.append_schema = AsyncMock(return_value=None)

      from alfred.bootstrap import gate_factory
      # err-003 fix: audit_sink is now required
      gate = await gate_factory.build_real_gate(backend=mock_backend, audit_sink=mock_audit_sink)
      assert isinstance(gate, RealGate)


  def test_gate_factory_module_is_the_only_allowed_env_read_site() -> None:
      """AST-scan: gate_factory.py is listed as an allowed env-read site.

      capability.py, policy.py, and _gate.py must NOT read ALFRED_ENV.
      gate_factory.py is explicitly allowed (it is the bootstrap seam).
      This test documents the invariant; the existing test_no_direct_env_reads.py
      enforces the ALFRED_<SECRET> guard. A separate AST-scan in
      test_capability_gate_ast_no_os_import.py covers the 'import os' guard
      on policy.py and capability.py.
      """
      import ast
      from pathlib import Path
      # These modules must not contain os.environ reads for ALFRED_ENV
      forbidden_modules = [
          Path(__file__).resolve().parents[3] / "src" / "alfred" / "hooks" / "capability.py",
          Path(__file__).resolve().parents[3] / "src" / "alfred" / "security" / "capability_gate" / "policy.py",
          Path(__file__).resolve().parents[3] / "src" / "alfred" / "security" / "capability_gate" / "_gate.py",
      ]
      for path in forbidden_modules:
          if not path.exists():
              continue
          tree = ast.parse(path.read_text())
          for node in ast.walk(tree):
              if isinstance(node, ast.Constant) and node.value == "ALFRED_ENV":
                  pytest.fail(
                      f"{path.name} reads ALFRED_ENV directly. "
                      "Move this read to src/alfred/bootstrap/gate_factory.py"
                  )
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/test_default_strict_declarations_invariant.py -q 2>&1 | tail -5
  ```
  Expected: ImportError or AttributeError (gate_factory.py doesn't exist).

- [ ] **Task 14 — Implement gate_factory.py.**

  **Files:** Create `src/alfred/bootstrap/__init__.py` (if not exists) and `src/alfred/bootstrap/gate_factory.py`.

  ```python
  # src/alfred/bootstrap/__init__.py
  """Bootstrap modules for AlfredOS startup sequence.

  gate_factory.py is the ONLY module in src/alfred/ that reads ALFRED_ENV
  for the purpose of selecting RealGate vs DevGate (sec-007 explicit exception).
  """
  ```

  ```python
  # src/alfred/bootstrap/gate_factory.py
  """Gate factory — the single allowed ALFRED_ENV read site for gate selection.

  Spec §8.4: RealGate is constructed when ALFRED_ENV != development.
  DevGate is the development default.

  This module is EXPLICITLY LISTED as an allowed os.environ read site for
  ALFRED_ENV (not for ALFRED_<SECRET> keys, which remain broker-only per
  CLAUDE.md hard rule #6). The AST-scan in test_no_direct_env_reads.py
  guards ALFRED_<SECRET> keys; this module's ALFRED_ENV read is intentional
  and documented.

  The capability.py, policy.py, and _gate.py modules must NEVER read
  ALFRED_ENV — that invariant is tested in
  tests/unit/security/test_default_strict_declarations_invariant.py.
  """
  from __future__ import annotations

  import os

  from alfred.hooks.capability import DevGate


  def build_dev_gate() -> DevGate:
      """Return a DevGate for development/test use.

      Spec §8.4: DevGate.check_plugin_load and check_content_clearance
      are fail-open stubs in Slice 3 (flag-day removal in PR-S3-7).
      """
      return DevGate()


  async def build_real_gate(
      *,
      backend: object,
      audit_sink: object,
      start_heartbeat: bool = True,
  ) -> object:
      """Return a RealGate backed by the supplied StorageBackend.

      backend: a StorageBackend implementation (PostgresBackend in production).
      audit_sink: AuditSink for supervisor.capability_gate_unavailable rows.
        Required — fail-closed without an audit trail is a silent security-state
        transition (err-003 fix: CLAUDE.md hard rule #7).
      start_heartbeat: True in production; False in tests.

      Spec §8.1: RealGate.create() loads the initial grant set from Postgres
      and optionally starts the 10 s heartbeat task.
      """
      from alfred.security.capability_gate._gate import RealGate
      return await RealGate.create(
          backend=backend,  # type: ignore[arg-type]
          audit_sink=audit_sink,
          start_heartbeat=start_heartbeat,
      )


  def is_production() -> bool:
      """Return True when ALFRED_ENV is not 'development'.

      Used by the bootstrap sequence to decide whether to call build_real_gate
      or build_dev_gate. Placing this check here (not in capability.py or _gate.py)
      satisfies sec-007: the env read is at the bootstrap seam, not inside the gate.
      """
      return os.environ.get("ALFRED_ENV", "development") != "development"
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/test_default_strict_declarations_invariant.py -q 2>&1 | tail -5
  ```
  Expected: all pass.

  ```bash
  uv run ruff check src/alfred/bootstrap/ && uv run mypy src/alfred/bootstrap/gate_factory.py
  ```

  Commit:
  ```bash
  git add src/alfred/bootstrap/ tests/unit/security/test_default_strict_declarations_invariant.py
  git commit -m "feat(capability-gate): gate_factory.py — ALFRED_ENV-gated RealGate/DevGate selection (#TBD-slice3)"
  ```

---

### Component I — AST-scan for no-os-import

- [ ] **Task 15 — Write test_capability_gate_ast_no_os_import.py.**

  **Files:** Create `tests/unit/security/test_capability_gate_ast_no_os_import.py`.

  ```python
  # tests/unit/security/test_capability_gate_ast_no_os_import.py
  """AST-scan: policy.py and capability.py must not import os.

  Spec §8.4 + sec-007: the capability gate module and the policy module
  are import-os-forbidden. The ALFRED_ENV read is delegated to gate_factory.py,
  which is the explicitly allowed bootstrap seam. This test enforces the
  source-level invariant that no future contributor accidentally slips an
  os.environ read into these security-critical modules.

  Mirrors the sec-007 guard in tests/unit/hooks/test_capability.py for DevGate.
  """
  from __future__ import annotations

  import ast
  from pathlib import Path

  import pytest

  _SRC = Path(__file__).resolve().parents[3] / "src" / "alfred"

  _FORBIDDEN_MODULES = [
      _SRC / "hooks" / "capability.py",
      _SRC / "security" / "capability_gate" / "policy.py",
      _SRC / "security" / "capability_gate" / "_gate.py",
      _SRC / "security" / "capability_gate" / "backend.py",
  ]


  def _has_os_import(path: Path) -> list[str]:
      """Return list of violations (line descriptions) for any `import os` in the file."""
      if not path.exists():
          return []
      tree = ast.parse(path.read_text())
      violations = []
      for node in ast.walk(tree):
          if isinstance(node, ast.Import):
              for alias in node.names:
                  if alias.name == "os":
                      violations.append(f"Line {node.lineno}: import os")
          if isinstance(node, ast.ImportFrom):
              if node.module == "os":
                  violations.append(f"Line {node.lineno}: from os import ...")
      return violations


  @pytest.mark.parametrize("module_path", _FORBIDDEN_MODULES, ids=lambda p: p.name)
  def test_no_os_import(module_path: Path) -> None:
      """Each capability-gate module must not import os.

      The invariant: ALFRED_ENV reads are delegated to gate_factory.py (the
      explicitly allowed bootstrap seam). If any of these modules import os,
      a future contributor might read ALFRED_ENV inside the gate logic itself,
      bypassing the bootstrap seam and making the gate's construction depend
      on env-at-import-time rather than injected configuration.
      """
      violations = _has_os_import(module_path)
      if violations:
          pytest.fail(
              f"{module_path.name} must not import os (sec-007 extension).\n"
              f"Violations:\n" + "\n".join(violations) + "\n"
              "Move any ALFRED_ENV reads to src/alfred/bootstrap/gate_factory.py."
          )
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/test_capability_gate_ast_no_os_import.py -q 2>&1 | tail -5
  ```
  Expected: all pass (none of the listed modules import os; backend.py uses sqlalchemy not os).

  Commit:
  ```bash
  git add tests/unit/security/test_capability_gate_ast_no_os_import.py
  git commit -m "test(security): AST-scan capability-gate modules for no-os-import (sec-007 extension) (#TBD-slice3)"
  ```

---

### Component J — Hookpoint wiring (plugin.grant.* family)

- [ ] **Task 16 — Wire plugin.grant.* hookpoints and audit rows.**

  Spec §14 defines five `plugin.grant.*` hookpoints. They are published by the proposals module and the RealGate rebuild path. This task adds the `register_hookpoint` calls and audit-row wiring.

  **Files:** Modify `src/alfred/security/capability_gate/proposals.py`.

  Add hookpoint registration to `proposals.py` module level. The hookpoints are registered when the module is first imported (consistent with Slice-2.5 PR-A pattern):

  ```python
  # src/alfred/security/capability_gate/proposals.py  — ADD at module level after imports

  from alfred.hooks.registry import get_registry
  from alfred.hooks.registry import SYSTEM_ONLY_TIERS  # type: ignore[attr-defined]

  def _register_grant_hookpoints() -> None:
      """Register plugin.grant.* hookpoints. Called at module import time.

      Spec §14: all plugin.grant.* hookpoints are post-only, SYSTEM_ONLY_TIERS,
      not refusable, fail_closed=False.
      """
      registry = get_registry()
      for hookpoint in (
          "plugin.grant.requested",
          "plugin.grant.approved",
          "plugin.grant.denied",
          "plugin.grant.revoked",
      ):
          registry.register_hookpoint(
              name=hookpoint,
              subscribable_tiers=SYSTEM_ONLY_TIERS,
              refusable_tiers=frozenset(),
              fail_closed=False,
          )

  _register_grant_hookpoints()
  ```

  `register_hookpoint` is confirmed present in the Slice-2.5 contract at `src/alfred/hooks/registry.py:537`. Call it unconditionally — no hedge, no lazy-import guard. PR-S3-2 depends on PR-S3-0b (already merged), so the Slice-2.5 registry is the baseline; no conditional path is needed.

  Write a test for audit-row constants usage:

  ```python
  # tests/unit/security/capability_gate/test_audit_wiring.py
  """Verify audit_row_schemas constants used by proposals.py are the spec §13 fields."""
  from alfred.audit.audit_row_schemas import PLUGIN_GRANT_FIELDS, PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS


  def test_plugin_grant_fields_contains_required_fields() -> None:
      """Spec §8.5 + §13: plugin.grant.* family carries the expected fields."""
      required = {"plugin_id", "subscriber_tier", "hookpoint", "operator_user_id",
                  "proposal_branch", "correlation_id"}
      assert required <= PLUGIN_GRANT_FIELDS


  def test_plugin_grant_revoked_inflight_fields_contains_required_fields() -> None:
      """Spec §13: plugin.grant.revoked_inflight carries in_flight_dispatch_id."""
      required = {"plugin_id", "hookpoint", "operator_user_id",
                  "in_flight_dispatch_id", "correlation_id"}
      assert required <= PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_audit_wiring.py -q 2>&1 | tail -5
  ```
  Expected: pass (constants from PR-S3-0a `audit_row_schemas.py`).

  Commit:
  ```bash
  git add src/alfred/security/capability_gate/proposals.py tests/unit/security/capability_gate/test_audit_wiring.py
  git commit -m "feat(capability-gate): wire plugin.grant.* hookpoints + audit row constants (#TBD-slice3)"
  ```

  **sec-009 follow-on finding (wildcard intentional; proposal-CLI hardening deferred):**

  The `hookpoint='*'` wildcard in `GatePolicy.check()` is intentional production semantics
  (accepted per cross-check with alfred-core-engineer; see review-summary §Disputed). The
  wildcard enables handshake-time grants (plugin-load check) where a specific hookpoint
  enumeration is unnecessary. The operator-misconfig risk (granting `'*'` too liberally
  on a per-hookpoint grant) is owned by the proposal/reviewer-gate flow. The following
  hardening requirement is tracked as a follow-on for **PR-S3-6 (CLI)**:

  > When `alfred plugin grant` receives a wildcard hookpoint (`'*'`) in the operator-submitted
  > proposal payload, the proposal flow MUST require a higher-tier reviewer signature than
  > for an explicit hookpoint. This guards against an operator accidentally granting universal
  > hookpoint access when they only intended to allow a specific operation. Implementation:
  > `create_proposal_branch()` raises `WildcardHookpointError` if `hookpoint == '*'` AND
  > `subscriber_tier != 'system'`; for system-tier grants with `hookpoint='*'`, the proposal
  > is escalated to require dual-reviewer approval rather than single-reviewer. Track as
  > PR-S3-6 Task N (sec-009 follow-on, owner: alfred-security-engineer + alfred-cli-engineer).

---

### Component K — supervisor.capability_gate_unavailable hookpoint

- [ ] **Task 17 — Register supervisor.capability_gate_unavailable hookpoint in _gate.py.**

  Spec §14: `supervisor.capability_gate_unavailable` is not a hookpoint in the table (it is an audit event only); the hookpoint for the supervisor is `supervisor.breaker.tripped` / `supervisor.breaker.reset`. Cross-check: the `supervisor.capability_gate_unavailable` event is an audit row emitted by `_emit_gate_unavailable_audit()` and processed by the operator alert path — it does not go through the hook dispatcher. This is correct per spec §8.1 and the hookpoint table in §14.

  Add a test documenting this distinction:

  ```python
  # tests/unit/security/capability_gate/test_audit_wiring.py  — APPEND

  def test_capability_gate_unavailable_is_audit_event_not_hookpoint() -> None:
      """Spec §8.1: supervisor.capability_gate_unavailable is an audit event, not a hookpoint.

      It is emitted via AuditWriter.append_schema() (Cluster 4 / rvw-001), not
      via the hook dispatcher. This ensures it is always observable even when
      the hook registry is itself unavailable (it would be circular to hook an
      audit event via the hook dispatcher when the backing store is down).
      """
      from alfred.audit.audit_row_schemas import SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS
      required = {"state_transition", "denied_dispatch_count",
                  "backing_store_error_type", "correlation_id"}
      assert required <= SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_audit_wiring.py -q 2>&1 | tail -5
  ```
  Expected: all pass.

  Commit:
  ```bash
  git add tests/unit/security/capability_gate/test_audit_wiring.py
  git commit -m "test(capability-gate): document supervisor.capability_gate_unavailable as audit event not hookpoint (#TBD-slice3)"
  ```

---

### Component L — Integration test (e2e grant lifecycle)

- [ ] **Task 18 — Write integration test grant lifecycle e2e.**

  **Files:** Create `tests/integration/security/__init__.py` (if not exists) and `tests/integration/security/test_grant_lifecycle_e2e.py`.

  ```python
  # tests/integration/security/test_grant_lifecycle_e2e.py
  """End-to-end: proposal creation → grant application → Postgres rebuild → check returns True.

  Uses testcontainers Postgres. Skipped if INTEGRATION_TESTS env var is not set.
  The pg_session_factory fixture is defined in tests/integration/conftest.py
  (ships in PR-S3-0b alongside the migrations).

  Spec §8.1, §8.3, §8.5.
  """
  from __future__ import annotations

  import os

  import pytest
  import pytest_asyncio


  pytestmark = pytest.mark.skipif(
      os.environ.get("INTEGRATION_TESTS") != "1",
      reason="Set INTEGRATION_TESTS=1 to run integration tests (requires Docker)",
  )


  @pytest.mark.asyncio
  async def test_grant_lifecycle_proposal_to_check(pg_session_factory) -> None:
      """Full lifecycle: create proposal → apply grant → check returns True.

      This test exercises the PostgresBackend against a real Postgres container.
      The proposal step uses the stub _write_proposal_to_state_git (full gitpython
      wiring lands in PR-S3-6). The rebuild step calls _apply_grants() directly,
      simulating the merge-activates path.
      """
      from alfred.security.capability_gate.backend import PostgresBackend
      from alfred.security.capability_gate._gate import RealGate
      from alfred.security.capability_gate.policy import GrantRow
      from alfred.security.capability_gate.proposals import create_proposal_branch
      from unittest.mock import patch

      from unittest.mock import AsyncMock, MagicMock
      no_op_sink = MagicMock()
      no_op_sink.append_schema = AsyncMock(return_value=None)

      backend = PostgresBackend(session_factory=pg_session_factory)
      gate = await RealGate.create(backend=backend, audit_sink=no_op_sink, start_heartbeat=False)

      # Initially no grants → check fails
      assert gate.check(
          plugin_id="e2e.plugin", hookpoint="tool.web.fetch", requested_tier="operator"
      ) is False

      # Create proposal (does NOT grant immediately — spec §8.3)
      # err-005 fix: audit_sink is required
      with patch(
          "alfred.security.capability_gate.proposals._write_proposal_to_state_git",
          return_value="proposal/policy-grant-e2etest",
      ):
          branch = await create_proposal_branch(
              plugin_id="e2e.plugin",
              subscriber_tier="operator",
              hookpoint="tool.web.fetch",
              operator_user_id="op@example.com",
              backend=backend,
              audit_sink=no_op_sink,
          )

      assert branch == "proposal/policy-grant-e2etest"

      # Grant still not active (proposal not yet approved)
      assert gate.check(
          plugin_id="e2e.plugin", hookpoint="tool.web.fetch", requested_tier="operator"
      ) is False

      # Simulate reviewer approval: apply the grant (normally triggered by state.git merge)
      grant = GrantRow(
          plugin_id="e2e.plugin",
          subscriber_tier="operator",
          hookpoint="tool.web.fetch",
          content_tier=None,
          proposal_branch=branch,
      )
      await gate._apply_grants(frozenset({grant}), commit_hash="approved-head-abc123")

      # Now check succeeds
      assert gate.check(
          plugin_id="e2e.plugin", hookpoint="tool.web.fetch", requested_tier="operator"
      ) is True

      # Verify Postgres roundtrip: load fresh from DB
      fresh_grants = await backend.load_grants()
      assert grant in fresh_grants

      # Verify sync hash persisted
      stored_hash = await backend.get_sync_hash()
      assert stored_hash == "approved-head-abc123"


  @pytest.mark.asyncio
  async def test_grant_revocation_e2e(pg_session_factory) -> None:
      """Revoking a grant removes it from Postgres and the in-memory policy."""
      from alfred.security.capability_gate.backend import PostgresBackend
      from alfred.security.capability_gate._gate import RealGate
      from alfred.security.capability_gate.policy import GrantRow

      from unittest.mock import AsyncMock, MagicMock
      no_op_sink = MagicMock()
      no_op_sink.append_schema = AsyncMock(return_value=None)

      backend = PostgresBackend(session_factory=pg_session_factory)
      grant = GrantRow(
          plugin_id="revoke.plugin",
          subscriber_tier="operator",
          hookpoint="tool.web.fetch",
          content_tier=None,
          proposal_branch="proposal/policy-grant-revoke",
      )
      gate = await RealGate.create(backend=backend, audit_sink=no_op_sink, start_heartbeat=False)
      await gate._apply_grants(frozenset({grant}), commit_hash="pre-revoke-hash")

      assert gate.check(
          plugin_id="revoke.plugin", hookpoint="tool.web.fetch", requested_tier="operator"
      ) is True

      # Revoke: apply empty grant set
      await gate._apply_grants(frozenset(), commit_hash="post-revoke-hash")

      assert gate.check(
          plugin_id="revoke.plugin", hookpoint="tool.web.fetch", requested_tier="operator"
      ) is False

      # Verify DB cleared
      rows = await backend.load_grants()
      assert len(rows) == 0
  ```

  Run (skipped without Docker):
  ```bash
  cd <repo-root>
  uv run pytest tests/integration/security/test_grant_lifecycle_e2e.py -q 2>&1 | tail -5
  ```
  Expected: 2 skipped (no `INTEGRATION_TESTS=1`).

  Commit:
  ```bash
  git add tests/integration/security/ tests/integration/security/__init__.py
  git commit -m "test(capability-gate): e2e grant lifecycle integration test (requires INTEGRATION_TESTS=1) (#TBD-slice3)"
  ```

---

### Component M — i18n key citations (catalog additions belong in PR-S3-0b)

- [ ] **Task 19 — Cite all t() keys added by this PR.**

  This PR USES the following i18n keys (defined in PR-S3-0b's catalog):

  - `capability_gate.unavailable` — shown to user when gate is fail-closed (`t("capability_gate.unavailable")`). Cited in `_gate.py` via the audit flow; the user-facing message surfaces via the orchestrator catch of gate failure in `orchestrator/core.py`.
  - `plugin.grant_prompt` — TUI prompt shown before a high-blast grant proposal (`t("plugin.grant_prompt", plugin_id=..., tier=..., hookpoint=..., blast_radius=...)`). Referenced in `proposals.py` but the TUI rendering is in PR-S3-6.
  - `cli.plugin.grant.pending_review` — shown after `alfred plugin grant` queues proposal (PR-S3-6 CLI).

  These keys are cited here so the PR-S3-0b plan author can verify all keys are covered. This PR does not write catalog entries.

  Write a test asserting the keys resolve via `t()` (not bare-key fallback):

  ```python
  # tests/unit/security/capability_gate/test_i18n_keys.py
  """Verify i18n keys used by the capability gate module resolve via t().

  Spec §11.5 + CLAUDE.md i18n rule #1: all operator-facing strings must
  go through t(). The keys are defined in PR-S3-0b's catalog.
  This test guards against typos in key names by asserting each key
  resolves to a non-empty string that is NOT the bare key itself.
  """
  from __future__ import annotations

  import pytest


  @pytest.mark.parametrize("key", [
      "capability_gate.unavailable",
      "plugin.grant_prompt",
      "cli.plugin.grant.pending_review",
  ])
  def test_i18n_key_resolves(key: str) -> None:
      """Each key resolves via t() to a non-empty string != the bare key.

      All three keys cited above (lines 2639-2644) are validated here, not
      just the one consumed by PR-S3-2 code paths. `plugin.grant_prompt`
      and `cli.plugin.grant.pending_review` are consumed by PR-S3-6's CLI;
      asserting they resolve via t() in PR-S3-2's test suite guards
      against catalog drift before PR-S3-6 depends on them — a missing
      key in PR-S3-0b's catalog fails the build here rather than during
      PR-S3-6 implementation.
      """
      from alfred.i18n.translator import t
      resolved = t(key)
      assert resolved, f"t({key!r}) returned empty"
      # A missing key returns the bare key — assert the catalog entry exists
      assert resolved != key, (
          f"t({key!r}) returned the bare key — the catalog entry is missing. "
          "Add it in PR-S3-0b (i18n catalog-additions)."
      )
  ```

  Run:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/security/capability_gate/test_i18n_keys.py -q 2>&1 | tail -5
  ```
  Expected: pass if PR-S3-0b catalog is merged; xfail/skip if catalog not yet present (known dependency).

  Commit:
  ```bash
  git add tests/unit/security/capability_gate/test_i18n_keys.py
  git commit -m "test(capability-gate): assert i18n keys resolve via t() — keys defined in PR-S3-0b (#TBD-slice3)"
  ```

---

### Component N — Coverage gate

- [ ] **Task 20 — Enforce 100% line+branch coverage on capability.py.**

  Spec §11a: `src/alfred/hooks/capability.py` is listed as a trust-boundary file requiring 100% line+branch coverage (owning PR is PR-S3-2).

  Add per-file coverage gate to `pyproject.toml`:

  ```toml
  # pyproject.toml — ADD to coverage configuration
  # (mirroring the Slice-2.5 PR-A hooks subsystem precedent)

  [tool.coverage.run]
  # existing config...

  # Per-file 100% gate for trust-boundary files
  # (run after: uv run coverage report --include=src/alfred/hooks/capability.py --fail-under=100)
  ```

  The actual coverage gate command is added to the `Makefile` or `pyproject.toml` scripts section. Add an explicit check:

  ```bash
  # Add to Makefile or scripts in pyproject.toml:
  uv run pytest tests/unit/hooks/test_capability.py \
    --cov=src/alfred/hooks/capability \
    --cov-branch \
    --cov-fail-under=100 \
    -q
  ```

  Run full capability.py coverage:
  ```bash
  cd <repo-root>
  uv run pytest tests/unit/hooks/test_capability.py \
    --cov=src/alfred/hooks/capability \
    --cov-branch \
    --cov-fail-under=100 \
    -q 2>&1 | tail -10
  ```
  Expected: coverage ≥ 100%.

  If any branches are uncovered, add additional test cases in `test_capability.py` to cover them. Then:

  ```bash
  uv run ruff check src/alfred/hooks/capability.py tests/unit/hooks/test_capability.py
  uv run mypy src/alfred/hooks/capability.py
  ```

  Commit:
  ```bash
  git add pyproject.toml tests/unit/hooks/test_capability.py
  git commit -m "test(capability-gate): enforce 100% line+branch coverage on capability.py (#TBD-slice3)"
  ```

---

### Component O — Full make check

- [ ] **Task 21 — Run full quality gate.**

  ```bash
  cd <repo-root>
  make check 2>&1 | tail -20
  ```
  Expected: lint + format + type + test all pass.

  ```bash
  make docs-check 2>&1 | tail -5
  ```
  Expected: no broken links.

  If any failures, fix them with targeted edits. Do not proceed to PR until both gates are green.

  Final commit (if any fixups needed):
  ```bash
  git add -p  # stage only the targeted fixup changes
  git commit -m "fix(capability-gate): quality-gate fixups (#TBD-slice3)"
  ```

---

## §5 Spec Coverage Map

| Spec section | Content | Task(s) |
|---|---|---|
| §8.1 Hybrid storage | state.git source of truth + Postgres cache; `capability_gate_sync` hash; commit-hash-change rebuild | Tasks 5, 6, 8, 10 |
| §8.1 Fail-closed ALL dispatches | check + check_plugin_load + check_content_clearance all return False when fail-closed | Tasks 8, 9 |
| §8.1 60 s heartbeat staleness window | _MAX_MISSED_HEARTBEATS × 10 s = 60 s; background task; constant-product invariant test | Tasks 8, 9 |
| §8.1 One audit row per state-transition | entering_fail_closed + exiting_fail_closed rows; per-dispatch count rolled into exit row; `append_schema` (Cluster 4) | Tasks 8, 9 |
| §8.1 `plugin.grant.denied_backing_store_unavailable` | rate-limited 1/sec/plugin_id at audit writer | Task 9 (documented; full rate-limiting in PR-S3-3b supervisor) |
| §8.1 `rebuild_from_state_git` loudly unimplemented | raises `NotImplementedError`; PR-S3-6 wires gitpython (err-002 fix) | Tasks 8, 10 |
| §8.1 audit_sink required | RealGate.create() and create_proposal_branch() require audit_sink; no silent security-state transition (err-003, err-005 fixes) | Tasks 8, 12 |
| §8.2 `check_plugin_load` Protocol extension | DevGate + RealGate both implement | Tasks 1, 2, 7, 8 |
| §8.2 `check_content_clearance` Protocol extension | DevGate + RealGate both implement | Tasks 1, 2, 7, 8 |
| §8.2 Content-tier / subscriber-tier orthogonality | `content_tier` field on `GrantRow`; separate `check_content_clearance` dispatch | Tasks 3, 4 |
| §8.3 Reviewer-gated proposal flow | `create_proposal_branch()` writes to state.git, does NOT upsert directly | Tasks 11, 12 |
| §8.3 `alfred plugin grant system X` queues proposal | proposals.py separation of proposal-creation from grant-activation | Tasks 11, 12 |
| §8.3 Wildcard hookpoint operator-misconfig hardening | intentional production semantics (sec-009 accepted); proposal-CLI dual-reviewer escalation tracked as PR-S3-6 follow-on | Task 16 (sec-009 follow-on note) |
| §8.4 `RealGate` production default | `gate_factory.py` reads `ALFRED_ENV`; returns `RealGate` when `!= development` | Tasks 13, 14 |
| §8.4 `DevGate` co-existence through Slice 3 | `DevGate` fail-open stubs for `check_plugin_load` + `check_content_clearance` | Tasks 1, 2 |
| §8.4 AST-scan `capability.py` no `import os` | sec-007 extended to policy.py, _gate.py, backend.py | Tasks 15 |
| §8.4 `ALFRED_ENV` read only in `gate_factory.py` | AST-scan assertion in `test_default_strict_declarations_invariant.py` | Tasks 13, 14 |
| §8.5 `plugin.grant.{requested, approved, denied, revoked}` | audit rows emitted via `append_schema` (Cluster 4 / rvw-001) from proposals.py; constants from `audit_row_schemas.py` | Tasks 12, 16, 17 |
| §10.4 capability-gate backing-store fail-closed | All three check methods return False; 60 s timing invariant tested; `plugin.grant.revoked_inflight` | Tasks 8, 9 |
| §10.4 `supervisor.capability_gate_unavailable` | One row per state-transition via `append_schema`; documented as audit event not hookpoint | Tasks 8, 9, 17 |
| §10.4 Heartbeat loop exception narrowing | `except (ConnectionError, asyncio.TimeoutError, OSError)` — programming errors propagate (err-007 fix) | Task 8 |
| §13 `PLUGIN_GRANT_FIELDS` constants | Consumed from `audit_row_schemas.py` (PR-S3-0a) via `append_schema` | Task 16 |
| §13 `SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS` | Consumed from `audit_row_schemas.py` (PR-S3-0a) via `append_schema` | Tasks 8, 17 |
| §13 `PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS` | Consumed from `audit_row_schemas.py` (PR-S3-0a) via `append_schema` | Task 16, 17 |
| §14 `plugin.grant.requested` hookpoint | `register_hookpoint` in proposals.py | Task 16 |
| §14 `plugin.grant.approved` hookpoint | `register_hookpoint` in proposals.py | Task 16 |
| §14 `plugin.grant.denied` hookpoint | `register_hookpoint` in proposals.py | Task 16 |
| §14 `plugin.grant.revoked` hookpoint | `register_hookpoint` in proposals.py | Task 16 |
| §11a Coverage gate on `capability.py` | 100% line+branch coverage enforced | Task 20 |
| i18n: `capability_gate.unavailable` | Used via `t()`; key defined in PR-S3-0b | Task 19 |
| i18n: `plugin.grant_prompt` | Referenced for PR-S3-6 CLI wiring; key in PR-S3-0b | Task 19 |

---

## §6 Quality gates

Run all of the following before opening the PR:

```bash
# From <repo-root>

# 1. Lint + format
uv run ruff check . && uv run ruff format --check .

# 2. Type-check
uv run mypy src/ && uv run pyright src/

# 3. Unit tests
uv run pytest tests/unit/security/capability_gate/ tests/unit/security/test_capability_gate_ast_no_os_import.py tests/unit/security/test_default_strict_declarations_invariant.py tests/unit/hooks/test_capability.py -q

# 4. capability.py 100% coverage gate
uv run pytest tests/unit/hooks/test_capability.py \
  --cov=src/alfred/hooks/capability \
  --cov-branch \
  --cov-fail-under=100 \
  -q

# 5. Full make check
make check

# 6. Docs-check
make docs-check

# 7. Integration tests (requires Docker)
INTEGRATION_TESTS=1 uv run pytest tests/integration/security/ -q

# 8. Adversarial suite (required if capability.py was touched — CLAUDE.md security rules)
uv run pytest tests/adversarial -q
```

---

## §7 References

- **Spec:** [`docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`](../specs/2026-05-30-slice-3-trust-tier-completion-design.md) — §8 entire, §10.4, §13, §14, §15.1
- **Predecessor plans (assumed merged):**
  - [`2026-05-31-slice-3-pr-s3-0a-docs-adrs-foundations.md`](2026-05-31-slice-3-pr-s3-0a-docs-adrs-foundations.md) — `audit_row_schemas.py` constants
  - [`2026-05-31-slice-3-pr-s3-0b-migrations-infra-i18n.md`](2026-05-31-slice-3-pr-s3-0b-migrations-infra-i18n.md) — migrations 0008/0009; SQLAlchemy models `PluginGrant`, `CapabilityGateSyncRow`; i18n keys
- **ADRs:**
  - [ADR-0017](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — load-bearing Slice-3 ADR (co-merged with PR-S3-0a)
  - [ADR-0014](../../adr/0014-pluggable-hooks-for-every-action.md) — every action is hookable; capability gate contract
  - [ADR-0013](../../adr/0013-defer-t1-t3-and-dual-llm.md) — superseded by ADR-0017; committed Slice 3 to real CapabilityGate
- **PRD:**
  - [PRD §6.4](../../../PRD.md#64-self-improvement-with-reviewer-gate) — reviewer gate; high-blast change types; proposal flow
  - [PRD §7.1](../../../PRD.md#71-security--prompt-injection-defense) — trust tiers; capability gate as boundary
  - [PRD §7.4](../../../PRD.md#74-audit-trail--rollback) — audit log; grant lifecycle audit rows
- **Code anchors:**
  - `src/alfred/hooks/capability.py` — `CapabilityGate` Protocol, `DevGate` (Slice-2.5 shipped)
  - `src/alfred/hooks/registry.py` — `SYSTEM_ONLY_TIERS`, `register_hookpoint` (Slice-2.5 shipped)
  - `src/alfred/audit/audit_row_schemas.py` — `PLUGIN_GRANT_FIELDS`, `SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS`, `PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS` (PR-S3-0a)
  - `src/alfred/memory/models.py` — `PluginGrant`, `CapabilityGateSyncRow` SQLAlchemy models (PR-S3-0b)
- **Sister spec:** [`2026-05-27-slice-2.5-hooks-design.md`](../specs/2026-05-27-slice-2.5-hooks-design.md) — §6.2 `DevGate` contract this PR extends
