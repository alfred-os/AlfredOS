# Hookpoint canonical declaration registry — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a canonical hookpoint declaration registry independent of import-order side effects, so `validate_hookpoint()` works on cold CLI start (without lazy-import bootstrap firing each subsystem's `declare_hookpoints()`). Closes #151.

**Architecture:** New thin manifest module `src/alfred/hooks/_known_hookpoints.py` with a static `Mapping[subsystem, tuple[hookpoint_name, ...]]`. CLI validator consults it. Sync test asserts manifest matches what subsystems actually register at runtime. Subprocess test pins cold-start behaviour.

**Tech Stack:** Python 3.14.5 • `collections.abc.Mapping` + `typing.Final` • pytest + `subprocess` for cold-start test • existing CLI validator test fixtures.

**Spec anchor:** [`docs/superpowers/specs/2026-06-04-hookpoint-canonical-registry-design.md`](../specs/2026-06-04-hookpoint-canonical-registry-design.md) — committed on this branch alongside this plan.

**Depends on:** Nothing in flight.
**Blocks:** Nothing in flight. (Slice-4 new publishers benefit but don't block this fix.)

---

## §1 Goal

After this PR merges:

1. `src/alfred/hooks/_known_hookpoints.py` exists with the canonical static manifest listing all 18 current hookpoint names grouped by 5 declaring subsystems.
2. `validate_hookpoint()` succeeds for every name in the manifest on a cold-Python-process CLI invocation (no chat-graph imports forced).
3. Sync test asserts the runtime registry, after a full subsystem-import sweep, equals the manifest's flat set.
4. A subsystem adding a new hookpoint without updating the manifest fails the sync test loud — drift cannot happen silently.

100% line + branch coverage on `_known_hookpoints.py` and the modified `_validators.py` block.

---

## §2 File structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/hooks/_known_hookpoints.py` | Create | Static manifest + `all_known_hookpoints()` helper |
| `src/alfred/cli/_validators.py` | Modify | `_default_known_hookpoints_provider` consults the manifest |
| `tests/unit/hooks/test_known_hookpoints_sync.py` | Create | Imports every declarer module + asserts runtime registry equals manifest |
| `tests/unit/cli/test_validate_hookpoint_cold_start.py` | Create | Subprocess test pinning validator works on cold CLI start (no lazy-import bootstrap) |
| `tests/unit/cli/test_validators.py` | Modify | Update existing hookpoint tests to patch the new seam (if needed) |

---

## §3 Definition of Done

- [ ] `uv run pytest tests/unit/hooks/test_known_hookpoints_sync.py tests/unit/cli/test_validate_hookpoint_cold_start.py tests/unit/cli/test_validators.py -v` → green.
- [ ] `uv run ruff check . && uv run ruff format --check .` → clean.
- [ ] `uv run mypy src/ && uv run pyright src/` → clean.
- [ ] `make check` → green.
- [ ] Conventional Commits + `#151` in every subject + no `fixup!` markers post-autosquash.
- [ ] User check-in before opening the PR.

---

## §4 Tasks

### Task 1 — Create the canonical manifest module

**Files**:

- Create: `src/alfred/hooks/_known_hookpoints.py`

- [ ] **Step 1: Write the failing tests.**

  Create `tests/unit/hooks/test_known_hookpoints_basic.py`:

  ```python
  """Unit tests for the canonical hookpoint manifest module (issue #151)."""

  from __future__ import annotations

  from alfred.hooks._known_hookpoints import KNOWN_HOOKPOINTS, all_known_hookpoints


  def test_manifest_is_non_empty() -> None:
      assert len(KNOWN_HOOKPOINTS) > 0
      for subsystem, names in KNOWN_HOOKPOINTS.items():
          assert isinstance(subsystem, str)
          assert len(names) > 0, f"subsystem {subsystem!r} has empty hookpoint tuple"
          for name in names:
              assert isinstance(name, str)


  def test_all_known_hookpoints_returns_flat_tuple() -> None:
      flat = all_known_hookpoints()
      assert isinstance(flat, tuple)
      expected_count = sum(len(names) for names in KNOWN_HOOKPOINTS.values())
      assert len(flat) == expected_count


  def test_no_duplicate_hookpoint_names_across_subsystems() -> None:
      flat = all_known_hookpoints()
      assert len(flat) == len(set(flat)), (
          f"duplicate hookpoint names across subsystems: "
          f"{[name for name in flat if flat.count(name) > 1]}"
      )


  def test_grant_hookpoints_present() -> None:
      """Slice-3's plugin.grant.* family — the #149 CR-1 use case."""
      flat = all_known_hookpoints()
      for name in ("plugin.grant.requested", "plugin.grant.approved",
                   "plugin.grant.denied", "plugin.grant.revoked"):
          assert name in flat, f"{name} missing from manifest"


  def test_web_fetch_hookpoint_present() -> None:
      assert "tool.web.fetch" in all_known_hookpoints()


  def test_identity_hookpoints_present() -> None:
      flat = all_known_hookpoints()
      assert "identity.t1_ingress" in flat
      assert "identity.t1_downgrade" in flat


  def test_supervisor_lifecycle_hookpoints_present() -> None:
      flat = all_known_hookpoints()
      for name in ("plugin.lifecycle.loaded", "plugin.lifecycle.crashed",
                   "plugin.lifecycle.quarantined"):
          assert name in flat
  ```

  Also need `tests/unit/hooks/__init__.py` if it doesn't already exist (check first; likely it does).

- [ ] **Step 2: Run; confirm ImportError.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  uv run pytest tests/unit/hooks/test_known_hookpoints_basic.py -v
  ```

  Expected: `ImportError: cannot import name 'KNOWN_HOOKPOINTS'`.

- [ ] **Step 3: Implement the manifest.**

  Create `src/alfred/hooks/_known_hookpoints.py`:

  ```python
  """Canonical declaration registry of every AlfredOS hookpoint name.

  Imported eagerly by the CLI validator (issue #151). Independent of
  which subsystems happen to be imported by the running process — a
  property the runtime registry's ``_hookpoints`` dict does NOT have
  (#149 CR-1).

  Sync invariant: every name listed here MUST be registered by exactly
  one subsystem's ``declare_hookpoints()`` (or equivalent eager-init
  call) at runtime. Pinned by
  ``tests/unit/hooks/test_known_hookpoints_sync.py``: any drift between
  the manifest and the runtime registry after a full subsystem-import
  sweep fails the test.

  Grouping: by declaring module so a future addition lands in one
  place. The grouping is documentation-only; the validator uses the
  flat set returned by :func:`all_known_hookpoints`.
  """

  from __future__ import annotations

  from collections.abc import Mapping
  from typing import Final

  KNOWN_HOOKPOINTS: Final[Mapping[str, tuple[str, ...]]] = {
      "alfred.memory.episodic": (
          "before_validate",
          "before_db_write",
          "after_flush",
          "write_failed",
          "cancelled",
      ),
      "alfred.identity._ingest": (
          "identity.t1_ingress",
          "identity.t1_downgrade",
      ),
      "alfred.security.capability_gate.proposals": (
          "plugin.grant.requested",
          "plugin.grant.approved",
          "plugin.grant.denied",
          "plugin.grant.revoked",
      ),
      "alfred.plugins.web_fetch": (
          "tool.web.fetch",
      ),
      "alfred.supervisor.core": (
          "supervisor.breaker.tripped",
          "supervisor.breaker.reset",
          "supervisor.action_timeout",
          "plugin.lifecycle.loaded",
          "plugin.lifecycle.crashed",
          "plugin.lifecycle.quarantined",
      ),
  }


  def all_known_hookpoints() -> tuple[str, ...]:
      """Return every declared hookpoint name as a flat tuple.

      Order matches the manifest's grouping (subsystem -> names).
      The CLI validator consults this on every call.
      """
      return tuple(
          name for names in KNOWN_HOOKPOINTS.values() for name in names
      )


  __all__ = ["KNOWN_HOOKPOINTS", "all_known_hookpoints"]
  ```

- [ ] **Step 4: Run; confirm green.**

- [ ] **Step 5: Lint/format/type-check.**

- [ ] **Step 6: Commit.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  git add src/alfred/hooks/_known_hookpoints.py tests/unit/hooks/test_known_hookpoints_basic.py
  git commit -m "feat(hooks): canonical hookpoint manifest module (#151)

  New thin manifest at src/alfred/hooks/_known_hookpoints.py listing
  every declared hookpoint name grouped by declaring subsystem.
  Imported eagerly by the CLI validator (Task 2) so validation works
  independent of which subsystems happen to be imported by the running
  process.

  Refs: #151

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 2 — Update CLI validator to consult the manifest

**Files**:

- Modify: `src/alfred/cli/_validators.py`
- Modify: `tests/unit/cli/test_validators.py` (update existing patching pattern if needed)

- [ ] **Step 1: Inspect existing validator tests to understand patching pattern.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  grep -nE 'validate_hookpoint|_known_hookpoints_provider|_hookpoints' tests/unit/cli/test_validators.py | head -20
  ```

  Verify that existing tests patch `_known_hookpoints_provider` (the test seam at module level). If they patch `get_registry()._hookpoints` directly, they need updating too.

- [ ] **Step 2: Update the validator.**

  In `src/alfred/cli/_validators.py`, replace `_default_known_hookpoints_provider`:

  ```python
  from alfred.hooks._known_hookpoints import all_known_hookpoints

  def _default_known_hookpoints_provider() -> Iterable[str]:
      """Return the names of every canonically-declared hookpoint.

      Sources from the static manifest at
      :mod:`alfred.hooks._known_hookpoints` (issue #151) — independent of
      which subsystems happen to be imported by the running process. The
      runtime registry's ``_hookpoints`` dict is populated by each
      subsystem's ``declare_hookpoints()`` at module-import time; the
      validator MUST work even when those imports have not fired (CLI
      lazy-import discipline per PR-S3-6 perf-001 + #151).

      Read-only iteration only. Test seams replace this function
      wholesale rather than patching the manifest.
      """
      return all_known_hookpoints()
  ```

  Remove the now-unused `get_registry` import if it's no longer used elsewhere in the file (search for other usages first).

- [ ] **Step 3: Update existing validator tests if they relied on registry state.**

  If `tests/unit/cli/test_validators.py` patches `get_registry()._hookpoints` directly, switch to patching `alfred.cli._validators._known_hookpoints_provider` to return a closed iterable. This is the same test seam pattern documented in the validator's module docstring.

- [ ] **Step 4: Run; confirm green.**

  ```bash
  uv run pytest tests/unit/cli/test_validators.py -v -k hookpoint
  ```

- [ ] **Step 5: Lint/format/type-check.**

- [ ] **Step 6: Commit.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  git add src/alfred/cli/_validators.py tests/unit/cli/test_validators.py
  git commit -m "fix(cli): validator consults canonical hookpoint manifest (#151)

  _default_known_hookpoints_provider now sources from the new manifest
  module instead of get_registry()._hookpoints. Removes the import-
  order dependency that made the validator reject valid hookpoints
  when their declaring subsystem hadn't been imported yet (#149 CR-1).

  Refs: #151

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 3 — Sync test (manifest vs runtime registry)

**Files**:

- Create: `tests/unit/hooks/test_known_hookpoints_sync.py`

- [ ] **Step 1: Write the test.**

  Create `tests/unit/hooks/test_known_hookpoints_sync.py`:

  ```python
  """Drift detector: the canonical manifest MUST match runtime reality.

  Imports every module listed in :data:`KNOWN_HOOKPOINTS`, forcing each
  subsystem's ``declare_hookpoints()`` to run, then asserts the
  resulting runtime registry equals the manifest's flat set. Any drift
  (subsystem adds a hookpoint without updating the manifest, or vice
  versa) fails loud.

  This test is the load-bearing invariant for issue #151's hand-
  maintained manifest. Without it, the manifest could silently rot —
  defeating the cold-start guarantee the validator now relies on.
  """

  from __future__ import annotations

  import importlib

  from alfred.hooks import get_registry
  from alfred.hooks._known_hookpoints import KNOWN_HOOKPOINTS, all_known_hookpoints


  def test_manifest_matches_runtime_registry_after_full_import_sweep() -> None:
      """After importing every declarer module, the runtime registry MUST
      list exactly the set the manifest declares."""
      # Force every declarer module to run its module-init declare_hookpoints().
      for subsystem in KNOWN_HOOKPOINTS:
          importlib.import_module(subsystem)

      # Two subsystems use explicit-bootstrap (not declare_hookpoints-at-
      # import-bottom) — invoke them so their hookpoints land too.
      import alfred.plugins.web_fetch
      alfred.plugins.web_fetch.register_hookpoints(get_registry())
      from alfred.supervisor.core import Supervisor
      Supervisor._register_hookpoints(object())  # type: ignore[arg-type]

      # Read the resulting runtime set.
      runtime_names = set(get_registry()._hookpoints.keys())
      manifest_names = set(all_known_hookpoints())

      # Missing from manifest (subsystem registered, manifest didn't list).
      missing_in_manifest = runtime_names - manifest_names
      assert not missing_in_manifest, (
          f"runtime registry declares hookpoints the manifest doesn't list: "
          f"{sorted(missing_in_manifest)}. Add them to "
          f"src/alfred/hooks/_known_hookpoints.py under the correct subsystem."
      )

      # In manifest but not registered (manifest lists a name no subsystem registers).
      missing_at_runtime = manifest_names - runtime_names
      assert not missing_at_runtime, (
          f"manifest lists hookpoints no subsystem actually registers at "
          f"runtime: {sorted(missing_at_runtime)}. Either remove them from "
          f"src/alfred/hooks/_known_hookpoints.py or wire a subsystem's "
          f"declare_hookpoints() to register them."
      )
  ```

  **Two subsystems need explicit bootstrap beyond `importlib.import_module`** —
  the test must invoke them directly because their hookpoints do NOT
  register at import time:

  - `alfred.plugins.web_fetch` ships
    `register_hookpoints(registry)` as a one-shot bootstrap call rather
    than firing at import. The test calls
    `alfred.plugins.web_fetch.register_hookpoints(get_registry())`
    explicitly so `tool.web.fetch` lands in the registry for the drift
    check.
  - `alfred.supervisor.core.Supervisor._register_hookpoints` is an
    instance method that an instance calls from `__init__`
    (plan-review decision core-010 keeps registration off the
    module-import path for test isolation). The method body dispatches
    to the registry singleton without reading instance state, so the
    test calls `Supervisor._register_hookpoints(object())` on a bare
    object to land the six supervisor hookpoints in the registry.

  Without these two explicit calls the dynamic sync check would fail
  "missing at runtime" on every supervisor + web-fetch name even
  though those subsystems do register them in production.

- [ ] **Step 2: Run; confirm green.**

  ```bash
  uv run pytest tests/unit/hooks/test_known_hookpoints_sync.py -v
  ```

- [ ] **Step 3: Commit.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  git add tests/unit/hooks/test_known_hookpoints_sync.py
  git commit -m "test(hooks): drift detector — manifest must match runtime registry (#151)

  Imports every declarer module listed in KNOWN_HOOKPOINTS, then
  asserts the runtime registry's _hookpoints set equals the manifest's
  flat set. Catches drift in either direction — subsystem adding a
  hookpoint without updating the manifest, or vice versa.

  Refs: #151

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 4 — Cold-start subprocess test (validator works without lazy-import bootstrap)

**Files**:

- Create: `tests/unit/cli/test_validate_hookpoint_cold_start.py`

- [ ] **Step 1: Write the test.**

  Create `tests/unit/cli/test_validate_hookpoint_cold_start.py`:

  ```python
  """Validator works on cold CLI start — issue #151 acceptance.

  Boots a fresh Python interpreter (no shared sys.modules pollution
  from other test modules) and verifies validate_hookpoint succeeds
  against the manifest without forcing any subsystem's
  declare_hookpoints() to run first.

  Mirrors the pattern at tests/unit/cli/test_main_lazy_imports.py:
  subprocess.run(sys.executable, "-c", ...) so other tests' import side
  effects can't leak.
  """

  from __future__ import annotations

  import subprocess
  import sys
  import textwrap


  def _run_in_fresh_python(script: str) -> subprocess.CompletedProcess[str]:
      return subprocess.run(
          [sys.executable, "-c", textwrap.dedent(script)],
          capture_output=True,
          text=True,
          check=False,
      )


  def test_validate_hookpoint_succeeds_on_cold_start_for_grant_requested() -> None:
      """The #149 CR-1 use case: alfred plugin grant on a freshly-spawned
      Python process. validate_hookpoint("plugin.grant.requested") must
      succeed without first importing alfred.security.capability_gate.proposals."""
      result = _run_in_fresh_python("""
          from alfred.cli._validators import validate_hookpoint
          out = validate_hookpoint("plugin.grant.requested")
          print(f"OK:{out}")
      """)
      assert result.returncode == 0, (
          f"validator failed on cold start. stderr={result.stderr!r}"
      )
      assert result.stdout.strip() == "OK:plugin.grant.requested"


  def test_validate_hookpoint_succeeds_on_cold_start_for_web_fetch() -> None:
      """Cross-subsystem cold-start check: tool.web.fetch lives in
      alfred.plugins.web_fetch which the CLI doesn't necessarily import."""
      result = _run_in_fresh_python("""
          from alfred.cli._validators import validate_hookpoint
          out = validate_hookpoint("tool.web.fetch")
          print(f"OK:{out}")
      """)
      assert result.returncode == 0, (
          f"validator failed on cold start. stderr={result.stderr!r}"
      )
      assert result.stdout.strip() == "OK:tool.web.fetch"


  def test_validate_hookpoint_rejects_unknown_on_cold_start() -> None:
      """An unknown hookpoint name MUST be rejected at parse time even on
      cold start — the validator's defensive contract is import-order-
      independent."""
      result = _run_in_fresh_python("""
          import typer
          from alfred.cli._validators import validate_hookpoint
          try:
              validate_hookpoint("nonexistent.event")
              print("WRONG: validator accepted unknown hookpoint")
          except typer.BadParameter as exc:
              print(f"REJECTED:{type(exc).__name__}")
      """)
      assert result.returncode == 0, f"subprocess crashed: {result.stderr!r}"
      assert "REJECTED:BadParameter" in result.stdout, result.stdout


  def test_validate_hookpoint_does_not_force_subsystem_imports() -> None:
      """The validator MUST NOT import the heavy chain transitively.

      Cold-start invocation should NOT load alfred.security.capability_gate.proposals,
      alfred.memory.episodic, alfred.supervisor.core, or any other declarer
      subsystem. Otherwise the perf-001 lazy-import discipline is silently
      defeated.
      """
      # Derive the forbidden tuple from the manifest so a future 6th
      # subsystem is automatically covered.
      from alfred.hooks._known_hookpoints import KNOWN_HOOKPOINTS
      forbidden_repr = repr(tuple(KNOWN_HOOKPOINTS.keys()))
      script_template = """
          import sys
          from alfred.cli._validators import validate_hookpoint
          validate_hookpoint("plugin.grant.requested")
          # After validation, NONE of the heavy declarer modules should be loaded.
          forbidden = __FORBIDDEN__
          for mod in forbidden:
              assert mod not in sys.modules, f"validator leaked import of {mod}"
          print("OK")
      """
      result = _run_in_fresh_python(
          script_template.replace("__FORBIDDEN__", forbidden_repr)
      )
      assert result.returncode == 0, (
          f"validator forced subsystem imports on cold start. "
          f"stderr={result.stderr!r}, stdout={result.stdout!r}"
      )
      assert result.stdout.strip() == "OK"
  ```

- [ ] **Step 2: Run; confirm green.**

  ```bash
  uv run pytest tests/unit/cli/test_validate_hookpoint_cold_start.py -v
  ```

- [ ] **Step 3: Commit.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  git add tests/unit/cli/test_validate_hookpoint_cold_start.py
  git commit -m "test(cli): subprocess test pinning validator works on cold CLI start (#151)

  Boots a fresh Python interpreter (no sys.modules pollution from
  other tests) and verifies validate_hookpoint succeeds against the
  manifest WITHOUT forcing any subsystem's declare_hookpoints() to run
  first. Also pins that the validator doesn't leak subsystem imports —
  preserves the PR-S3-6 perf-001 lazy-import discipline.

  Refs: #151

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

---

### Task 5 — Final QA + push + STOP

**Files**: none — gates only.

- [ ] **Step 1: Full quality bar.**

  ```bash
  cd "$(git rev-parse --show-toplevel)"
  uv run ruff check . && uv run ruff format --check .
  uv run mypy src/ && uv run pyright src/
  uv run pytest tests/unit/hooks/ tests/unit/cli/test_validators.py tests/unit/cli/test_validate_hookpoint_cold_start.py -v
  make check
  ```

  Expected: all green. Pre-existing ruff S603/S607 in `scripts/check_strict_declarations.py` — ignore.

- [ ] **Step 2: Commit log audit.**

  ```bash
  git log --oneline main..HEAD
  ```

  Verify every commit is Conventional Commits, contains `#151`, no `fixup!` prefixes.

- [ ] **Step 3: Push.**

  ```bash
  git push -u origin issue-151-hookpoint-registry
  ```

- [ ] **Step 4: STOP for user check-in.**

  Report: branch pushed, commit list, gate status. Do NOT open the PR autonomously.

---

## §5 Post-PR follow-ups (not in this PR's scope)

- entry_points-based discovery (future-proof; not warranted at AlfredOS's current scale).
- Auto-AST-scan of `register_hookpoint` calls (extra build step; sync test is sufficient).
- A `subsystem` field on the manifest entries for richer audit-log attribution (manifest is hand-grouped today; this would let the validator surface a "registered by" hint).
