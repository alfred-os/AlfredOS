# #568 — restore Dependabot's Python coverage

**Date:** 2026-08-04
**Issue:** [#568](https://github.com/alfred-os/AlfredOS/issues/568)
**Status:** design approved, pending implementation plan

## Problem

`pyproject.toml` declares `requires-python = ">=3.14.6"`. Dependabot resolves Python at
*series* granularity (`3.10.*` … `3.14.*`) and cannot resolve a patch-level specifier, so it
aborts with `tool_version_not_supported` before doing any work.

The consequence is larger than the issue as filed. Three of that issue's claims are wrong, and
each correction makes the problem worse.

### Correction 1 — Python *was* covered; this is a regression, not an absence

The issue states Python "has never been covered". Dependabot opened Python PRs from
2026-05-31 to 2026-06-19, including a security bump (`aiohttp 3.13.5 → 3.14.1`, 2026-06-04).
They stop dead at `c2711da1` (2026-06-20, the 3.14.6 pin). Every Dependabot PR after that date
is the `actions` group.

### Correction 2 — the weekly `pip` updater died too, not just the graph submission

Both the `update_graph` job and the `pip` ecosystem in `.github/dependabot.yml` read
`requires-python`. Both stopped on the same day, from the same cause. This is one broken
channel, not two independent ones.

### Correction 3 — 45 days dead, not "10+"

Last successful run 2026-06-19; first failure 2026-06-21T08:26:31Z; failing on every run since.

### Evidence

`requires-python` value history against Dependency Graph outcomes:

| `requires-python` | commit | date | Dependency Graph |
| --- | --- | --- | --- |
| `>=3.12` | `7c3a81e8` | 2026-05-25 | 1 success, 0 failures |
| `>=3.14` | `f30a8942` | 2026-05-27 | **20 successes, 0 failures** |
| `>=3.14.6` | `c2711da1` | 2026-06-20 | **0 successes, 20 failures** |

The split is total and falls exactly on the pin commit — a clean natural experiment, not a
correlation.

`.python-version` was `3.14.5` — an exact patch — from 2026-06-03 to 2026-06-17, and Dependabot
kept working throughout. **`.python-version` is not the blocker; `requires-python` alone is.**

The submitted graph is frozen at its last good snapshot, which is why all 27 open alerts are
already remediated in `uv.lock`:

| package | dependency graph | `uv.lock` on `main` |
| --- | --- | --- |
| `aiohttp` | 3.13.5 | 3.14.3 |
| `gitpython` | 3.1.50 | 3.1.57 |
| `pydantic-settings` | 2.14.1 | 2.14.2 |

### The floor note is off by one patch

`pyproject.toml:6-11` claims CPython 3.14.0–3.14.5 carry the gh-135228 frozen+slots regression
and that 3.14.6 fixes it. Measured across uv-managed `python-build-standalone` builds:

| version | unknown-attr assignment on `@dataclass(frozen=True, slots=True)` |
| --- | --- |
| 3.14.0 | `TypeError: super(type, obj)…` — regression present |
| 3.14.4 | `TypeError: super(type, obj)…` — regression present |
| **3.14.5** | `FrozenInstanceError` — **already fixed** |
| 3.14.6 | `FrozenInstanceError` |

Confirmed at source level by diffing `Lib/dataclasses.py` between 3.14.4 and 3.14.5:
`_frozen_get_del_attr` → `_frozen_set_del_attr`, switching the generated `__setattr__`/
`__delattr__` closure from `cls` to `__class__` so the closure-cell update actually applies.
This is a pure `Lib/dataclasses.py` source change, so unlike the `ast` recursion-limit case it
is **build-independent**.

The same off-by-one is repeated in `tests/unit/test_frozen_slots_dataclass_regression_guard.py`
(module docstring) and `PRD.md:618`.

## Decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Fix approach | Relax `requires-python` to `>=3.14`, add an import-time floor guard | Only option that restores **both** the graph and the weekly `pip` PRs; proven by the repo's own history |
| Enforced floor | `(3, 14, 6)` — hold current | Avoids creating a 3.14.5 band that is "supported" but that no CI lane exercises. Supported == tested |
| `.python-version` | unchanged at `3.14.6` | Evidenced safe: an exact patch coexisted with a working Dependabot |
| i18n on the guard message | English-only, documented exemption | Fires at `import alfred`, before any catalog can load, on an interpreter already refused; `t()` lives under `src/alfred/` so calling it is circular |
| Freshness failure routing | Open/update a tracking issue | Visible without anyone watching the Actions tab — the honest answer to "route its failure to wherever failures are actually read" |

## Design

### Part 1 — the fix

| File | Change |
| --- | --- |
| `pyproject.toml` | `requires-python = ">=3.14"`; rewrite the note with the corrected patch range and state *why* the specifier is series-level |
| `.python-version` | unchanged (`3.14.6`) |
| `src/alfred/_python_floor.py` *(new)* | `FLOOR = (3, 14, 6)` and a pure `enforce(version: tuple[int, int, int]) -> None` |
| `src/alfred/__init__.py` | calls `enforce(sys.version_info[:3])`; currently empty, so every `import alfred.*` runs it |

`enforce` is pure and takes the version as a parameter rather than reading `sys.version_info`
directly. That is the whole point of the seam: it lets the **negative case execute** in a test
(`enforce((3, 14, 4))` must raise) instead of a guard that can only ever be observed passing.

The trade this accepts, stated plainly: `pyproject.toml` no longer refuses a sub-floor
interpreter at *install* time. A `pip install` on 3.14.0 now succeeds and fails loudly at first
import instead. In exchange, Dependabot's Python coverage returns.

### Part 2a — PR gate (static, rides an existing required check)

`tests/unit/meta/test_requires_python_is_dependabot_resolvable.py` asserts `requires-python`
carries no patch component. This is the detector for the exact root cause: it would have blocked
`c2711da1` on 2026-06-20 and saved all 45 days.

It rides the **existing required** `Python (lint, types, unit)` check. No new status context, no
branch-protection change, and therefore no promotion deadlock. `tests/unit/meta/` already holds
this genre (`test_gate_surfaces_are_pinned.py`, `test_scripts_coverage_census.py`).

### Part 2b — freshness monitor

A freshness check **cannot** be a PR required check. The Dependency Graph workflow has only ever
run on `main` (verified across all 41 runs), so it never reflects a PR branch. A "last main run
must be green" gate would additionally **deadlock its own fix**: red until the fix merges, and
unblocking it would require an `--admin` merge, which is ruled out.

So the monitor runs on `push: main` and on a daily `schedule`:

- `scripts/check_dependency_graph_freshness.py` — pure parse/compare functions plus a thin
  `main`. Reads a fetched SBOM JSON file and `uv.lock`; emits the drift list.
- Comparison is **version equality over the name-intersection** of the SBOM's `pkg:pypi`
  packages and `uv.lock`. Intersection, not set-equality: `uv.lock` carries dev/optional groups
  the runtime SBOM legitimately omits.
- The workflow fetches the SBOM with `gh api`, runs the script, and on drift opens or updates a
  labelled tracking issue, closing it when the graph resyncs.

**Trap, recorded so it is not reintroduced:** the SBOM's `created` timestamp is useless as a
freshness signal. It read `2026-08-04T17:20Z` while serving June data. Freshness must be measured
by **content**. A timestamp-based check here would be a paper gate.

Because the check fails *today* (aiohttp 3.13.5 vs 3.14.3) and must flip green after the fix
lands, it has an executable negative case before a line of it is trusted.

`scripts/` files are governed by `tests/unit/meta/test_scripts_coverage_census.py` (#423): a new
script must be either gated at 100% or explicitly allow-listed. This one is gate-enforcing code,
so it carries a **100% line+branch gate** in `ci.yml`'s `python` job alongside `check_tag_t3.py`
and `check_strict_declarations.py` — not an omit entry.

Workflow constraints, since `Zizmor (workflow security)` is a required check:

- least-privilege `permissions:` — `contents: read` plus `issues: write` only on the job that
  needs it
- all untrusted data passed via `env:`, never interpolated into `run:` bodies
- actions pinned by commit SHA, matching the existing workflows

### Part 3 — doc corrections

The off-by-one patch claim is corrected in all three places it appears:

- `pyproject.toml:6-11`
- `tests/unit/test_frozen_slots_dataclass_regression_guard.py` (module docstring)
- `PRD.md:618`

`PRD.md` edits are **human-gated**. That change is prepared as a proposed diff for review, not
committed unilaterally.

## Testing

| Test | Asserts | Non-vacuity |
| --- | --- | --- |
| `enforce` rejects below floor | `enforce((3, 14, 4))` raises; message names both required and found versions | Negative case executes — the defect is reintroduced deliberately |
| `enforce` accepts at/above floor | `enforce((3, 14, 6))` and `(3, 15, 0)` return | Boundary is exercised on both sides |
| `requires-python` is series-level | parsed specifier has no patch component | Mutation-verified: restoring `>=3.14.6` must turn it red |
| freshness comparison | drift detected on mismatched versions; clean on match; intersection semantics hold | Run against the real stale SBOM, which must fail today |
| frozen+slots guard | unchanged behaviour, corrected docstring | Already present |

Every guard added here is mutation-verified before the PR opens. Reading a guard does not
establish that it can fail — only reintroducing the defect does.

## Verification

- `make check` green (read the exit status, not the tail of the log)
- After merge: re-run the Dependency Graph workflow and confirm it **succeeds**
- Confirm the submitted graph reports `aiohttp 3.14.3` / `gitpython 3.1.57` /
  `pydantic-settings 2.14.2`
- Confirm the 27 open alerts auto-close; any that do not get dismissed with a reason so the queue
  is trustworthy
- Confirm the freshness monitor flips from red to green on the same event
- Watch for the first Dependabot `pip` PR to reappear on the weekly schedule

## Out of scope

- Promoting the freshness monitor to a required check. Deferred deliberately: steady-state it
  would mean an unrelated Dependabot outage blocks every PR. Revisit once the monitor has a
  track record.
- Any change to `.python-version` or to the CI `3.14` pins.
- The remaining open follow-ups (#565, #564, #560).
