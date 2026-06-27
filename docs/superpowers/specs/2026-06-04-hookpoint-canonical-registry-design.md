# Hookpoint canonical declaration registry — design

**Date:** 2026-06-04
**Author:** Claude Code (on behalf of Ian Dominey)
**Scope:** Issue [#151](https://github.com/alfred-os/AlfredOS/issues/151) — CR-149 round-1 deferral on PR #149
**Anchors:** PR #149 CR thread (comment id 3338373911); `src/alfred/cli/_validators.py` `_default_known_hookpoints_provider`; CLI lazy-import discipline at `tests/unit/cli/test_main_lazy_imports.py`; spec §11.3 `alfred plugin grant` path

---

## 1. What this is for

`validate_hookpoint()` in `src/alfred/cli/_validators.py` rejects unknown hookpoint names so a typo on `alfred plugin grant <hookpoint>` doesn't land a never-firing entry in `state.git`. Today the validator reads from `get_registry()._hookpoints` — the set of publishers that have **already been imported** into this process.

That works in Slice 3 by coincidence: `alfred plugin grant ...` transitively imports `alfred.security.capability_gate.proposals` via the module-level `_state_git_client`, which declares the four `plugin.grant.*` hookpoints at import time. But:

- **PR-S3-6 (perf-001)** deliberately added lazy imports for CLI startup. The set of `_hookpoints` keys at validator-call time depends on which imports have fired.
- **Slice-4+** will add publishers (e.g. memory-subsystem hookpoints) that the CLI does NOT transitively import. Valid hookpoint names will get rejected at parse time.

This PR adds a canonical declaration registry independent of import-order side effects. The validator consults the canonical source; `declare_hookpoints()` calls in each subsystem still run at module-import time to populate the runtime registry (unchanged); a sync test asserts the canonical source lists exactly what gets registered.

## 2. Architecture

**New module:** `src/alfred/hooks/_known_hookpoints.py` — a single read-only `Mapping` from subsystem name to tuple of hookpoint names. Imported eagerly by the CLI validator (no heavy dependencies; just a static dict literal).

**Updated module:** `src/alfred/cli/_validators.py` — `_default_known_hookpoints_provider` calls `all_known_hookpoints()` from the manifest instead of `get_registry()._hookpoints`.

**Unchanged:** every subsystem's `declare_hookpoints()` continues to run at module-import time. The runtime registry still populates the same way for invoke/dispatch — only the CLI validator's source of truth changes.

### 2.1 Manifest shape

```python
# src/alfred/hooks/_known_hookpoints.py
"""Canonical declaration registry of every AlfredOS hookpoint name.

Imported eagerly by the CLI validator (issue #151). Independent of which
subsystems happen to be imported by the running process — a property the
runtime registry's ``_hookpoints`` dict does NOT have (#149 CR-1).

Sync invariant: every name listed here MUST be registered by exactly one
subsystem's ``declare_hookpoints()`` at runtime. Pinned by
``tests/unit/hooks/test_known_hookpoints_sync.py``: any drift between the
manifest and the runtime registry after a full subsystem-import sweep
fails the test.
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

    Order matches the manifest's grouping (subsystem → names).
    The CLI validator consults this on every call.
    """
    return tuple(name for names in KNOWN_HOOKPOINTS.values() for name in names)


__all__ = ["KNOWN_HOOKPOINTS", "all_known_hookpoints"]
```

### 2.2 Validator integration

In `src/alfred/cli/_validators.py`:

```python
from alfred.hooks._known_hookpoints import all_known_hookpoints

def _default_known_hookpoints_provider() -> tuple[str, ...]:
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

### 2.3 Sync invariant

The manifest is hand-maintained. To prevent drift, `tests/unit/hooks/test_known_hookpoints_sync.py`:

1. Imports every module listed in `KNOWN_HOOKPOINTS` (forcing their `declare_hookpoints()` to run).
2. Calls `alfred.plugins.web_fetch.register_hookpoints(get_registry())` directly — the `web_fetch` plugin exposes its registration as an explicit bootstrap function rather than firing it at import time, so `importlib.import_module` alone leaves `tool.web.fetch` unregistered.
3. Invokes `Supervisor._register_hookpoints(object())` on a bare instance — the supervisor's six hookpoints are registered inside an instance method (core-010 deliberately keeps them off the module-import path for test isolation); the method dispatches to the registry singleton without reading instance state, so a bare-object dispatch produces the same six registrations a real `Supervisor.__init__` would.
4. Reads the resulting `get_registry()._hookpoints` set.
5. Asserts the runtime set equals `set(all_known_hookpoints())`.

Any drift (subsystem adds a hookpoint without updating the manifest, or vice versa) fails the test loud.

### 2.4 Cold-start subprocess test

`tests/unit/cli/test_validate_hookpoint_cold_start.py`:

1. Boots a fresh Python interpreter via `subprocess.run([sys.executable, "-c", ...])`.
2. Imports only `alfred.cli._validators` (no chat-graph imports).
3. Calls `validate_hookpoint("plugin.grant.requested")` — succeeds.
4. Calls `validate_hookpoint("nonexistent.event")` — raises `typer.BadParameter`.

Pattern mirrors `tests/unit/cli/test_main_lazy_imports.py`. Pins that the validator works on cold CLI start without lazy-import bootstrap.

## 3. Why this shape (vs alternatives)

The issue lists three options: pyproject.toml entry_points, generated table, explicit eager registration.

| Option | Pros | Cons | Chosen? |
| --- | --- | --- | --- |
| pyproject.toml entry_points | Aligns with packaging, plugin-friendly | Slow to enumerate on cold start; machinery; entry_points scanning depends on the install state of every package | No |
| Codegen at build time | Never drifts | Build step; extra machinery; harder to grep | No |
| **Hand-maintained thin manifest module** | Simple, fast, greppable, sync test catches drift | Requires hand-maintenance (one-line per hookpoint) — addressed by sync test | **Yes** |

The manifest is ~30 lines of static data. The sync test makes drift a CI fail. The validator import is a pure-Python module-level read (microsecond cost). Best fit for AlfredOS conventions.

## 4. Files affected

| File | Status | Responsibility |
| --- | --- | --- |
| `src/alfred/hooks/_known_hookpoints.py` | Create | Static manifest of every declared hookpoint, grouped by declaring subsystem |
| `src/alfred/cli/_validators.py` | Modify | `_default_known_hookpoints_provider` consults the manifest |
| `tests/unit/hooks/test_known_hookpoints_sync.py` | Create | Imports every declarer module + asserts runtime registry == manifest |
| `tests/unit/cli/test_validate_hookpoint_cold_start.py` | Create | Subprocess test pinning validator works on cold CLI start |
| `tests/unit/cli/test_validators.py` | Modify | Update existing hookpoint tests to use the manifest (replace `monkeypatch.setattr(get_registry, "_hookpoints", ...)` patterns with `monkeypatch.setattr("alfred.cli._validators._known_hookpoints_provider", lambda: ...)`) |

## 5. Out of scope

- Migrating to entry_points-based plugin discovery (future-proof but out of scope here; AlfredOS doesn't have a third-party plugin story today).
- Auto-generating the manifest from AST scan (extra build step; the sync test is sufficient).
- Subsystem reorganization (the manifest groups by declaring module today; if subsystems consolidate, the grouping follows).

## 6. References

- Issue #151 — CR-149 round-1 deferral.
- PR #149 — `alfred plugin grant` CLI surface where the validator lives.
- `tests/unit/cli/test_main_lazy_imports.py` — the subprocess-test precedent.
- `src/alfred/cli/_validators.py` — current `_default_known_hookpoints_provider`.
- CLAUDE.md hard rule #7 — fail-loud at trust boundaries (the sync test makes drift loud, not silent).
