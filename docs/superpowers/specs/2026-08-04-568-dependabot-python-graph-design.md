# #568 — restore Dependabot's Python coverage

**Date:** 2026-08-04
**Issue:** [#568](https://github.com/alfred-os/AlfredOS/issues/568)
**Status:** implementation complete; under review on PR [#569](https://github.com/alfred-os/AlfredOS/pull/569)

## Revision note

The first draft of this spec was reviewed by eight specialists and a coordinator. It carried
**2 Critical defects** and **six factual claims that failed to reproduce**. Every correction below
was established by execution, not argument. The most instructive failure: an unverified claim in
the first draft ("calling `t()` would be circular") propagated into three of eight reviewers
before being refuted. An unexecuted premise in a design doc contaminates the review meant to
catch it.

## Problem

`pyproject.toml` **and `uv.lock`** both declare `requires-python = ">=3.14.6"`. Dependabot
resolves Python at *series* granularity (`3.10.*` … `3.14.*`) and cannot resolve a patch-level
specifier, so it aborts with `tool_version_not_supported` during file fetching.

### Three dead channels, not one

All three read `requires-python` and first failed on 2026-06-21, but not in one window. The
dependency-graph and security-update channels failed 79 seconds apart. The weekly `pip` channel's
first failure was hours later, at `10:21:52Z` — it did not fail inside that 79-second window at
all.

| Channel | Workflow / job | First failure | State |
| --- | --- | --- | --- |
| Dependency-graph submission | `Dependency Graph` / `update-uv-graph` | `2026-06-21T08:26:31Z` | 20 consecutive failures |
| Dependabot **security** updates | workflow `282449388`, `"command":"security"` | `2026-06-21T08:27:47Z` | 22 failures |
| Dependabot weekly `pip` updates | `.github/dependabot.yml` `pip` ecosystem | `2026-06-21T10:21:52Z` | last success `2026-06-14` |

The **security-update** channel is the one that should have opened a PR for the aiohttp and
GitPython CVEs. Its absence — not the weekly updater's — is why Trivy was the only thing that
caught them.

### Corrections to the issue as filed

- **Python was covered, then regressed.** Dependabot opened Python PRs 2026-05-31 → 2026-06-19,
  including `aiohttp 3.13.5 → 3.14.1` (PR #161, 2026-06-04). Every later Dependabot PR is the
  `actions` group.
- **44 days dead**, not "10+". `c2711da1` landed on `main` at `2026-06-21T08:26:25Z` (its *author*
  date is 2026-06-20T23:08 — the discrepancy that produced two wrong figures in draft 1).
- **The exposure is not the 27 alerts.** All 27 are genuinely remediated in `uv.lock`
  (independently enumerated). The real exposure is **~35 of 100 packages frozen at
  pre-2026-06-19 versions** — `anthropic 0.104.1` (current 0.116.0), `openai`, `certifi`,
  `cachetools`.

### Evidence

| `requires-python` | commit | successes | failures |
| --- | --- | --- | --- |
| `>=3.12` | `7c3a81e8` | 4 | 0 |
| `>=3.14` | `f30a8942` | 17 | 0 |
| `>=3.14.6` | `c2711da1` | 0 | **20** |

Totals reconcile at 21/20 across 41 runs, **all on `main`**. The boundary falls exactly on
`c2711da1` with zero anomalies. Draft 1 reported `1 / 20 / 20`; that was an artefact of keying on
commit *date* and then on a timezone-naive string comparison.

The submitted graph is frozen at its last good snapshot:

| package | dependency graph | `uv.lock` on `main` |
| --- | --- | --- |
| `aiohttp` | 3.13.5 | 3.14.3 |
| `gitpython` | 3.1.50 | 3.1.57 |
| `pydantic-settings` | 2.14.1 | 2.14.2 |

`.python-version` was `3.14.5` — an exact patch — from 2026-06-04 to 2026-06-17 while Dependabot
worked (commit dates, not author dates — the same author-vs-commit-date confusion this document
criticises above for the "44 days dead" figure, recurring here). **`requires-python` is the
blocker; `.python-version` is not.**

### The floor note is off by one patch

Measured on uv-managed `python-build-standalone`: **3.14.0 and 3.14.4** raise the spurious
`TypeError: super(type, obj)…` on unknown-attribute assignment to a `@dataclass(frozen=True,
slots=True)`; **3.14.5 and 3.14.6** raise `FrozenInstanceError`. 3.14.1–3.14.3 were not measured,
so the affected range is stated as "3.14.0–3.14.4" on the strength of the source diff, not of
four probes.

Confirmed at source level: `_frozen_get_del_attr` → `_frozen_set_del_attr`, switching the
generated `__setattr__`/`__delattr__` closure from `cls` to `__class__` so the closure-cell update
applies. A pure `Lib/dataclasses.py` change, therefore build-independent.

### The floor is a diagnostics floor, not a trust-boundary control

Established by execution during review, and it makes the trade clearly correct: on 3.14.4,
assigning or deleting a **declared** field on a frozen+slots dataclass still raises
`FrozenInstanceError`. Only **unknown**-attribute assignment misbehaves. **Zero production sites
catch `FrozenInstanceError`.** Nothing security-relevant is surrendered by relaxing the declared
specifier.

## Decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Fix approach | Relax **both** `pyproject.toml` and `uv.lock` to `>=3.14`; enforce the real floor at import | The only option restoring all three channels |
| Enforced floor | `(3, 14, 6)` | Supported == tested; no untested 3.14.5 band |
| Exception type | `UnsupportedPythonError(AlfredError, RuntimeError)` | Measured `sys.modules` delta for `import alfred.errors` is `['alfred', 'alfred._python_floor', 'alfred.errors', 'typing']` (plus stdlib `__future__`/`_typing`) — not the bare `['alfred','alfred.errors']` first claimed; `alfred._python_floor` and `typing` were omitted from the original count. Zero forbidden hits against the ADR-0030 closure bound either way. `alfred/errors.py` itself is 13 lines, only `__future__` import. Not circular, not sub-floor-fragile. Three reviewers who claimed otherwise were overruled on measured evidence |
| i18n on the guard | English-only, exemption documented | **Not** circularity (refuted). Real grounds: `t()` silently drops kwargs on a missing msgid, and the versions *are* the payload; plus 29.7 ms added to every `import alfred.*`, inside the ADR-0030-bounded quarantine-child closure |
| Monitor signal | **Liveness primary, content secondary** | Content-only is lagging and noisy — see below |
| Monitor trigger | `schedule:` + `workflow_dispatch:`; **no `push: main`** | Measured race: graph run created +6 s after push, completing in 34–98 s (measured range across 41 runs), plus ingest lag |
| PR shape | One PR, four conditions | Split is not forced; see "PR shape" below |
| ADR | **ADR-0061** | Declared floor and enforced floor deliberately diverge — a structural invariant |

### Why content comparison cannot be the primary signal

Replaying the frozen graph at every post-freeze commit: the content monitor's apparent day-1
redness is **100 % noise** — phantom version-less records. De-noised, it is **green and blind for
16 days**, reddening only via an unrelated bulk upgrade. Draft 1's claim that "it fails today,
therefore it is non-vacuous" was itself vacuous.

Liveness is one API call (0.55 s) and a perfect step function: 21 success / 20 failure splitting
exactly at `2026-06-21T08:26:31Z`. It would have gone red at hour 0 instead of day 44.

## Design

### Part 1 — the fix

| File | Change |
| --- | --- |
| `pyproject.toml` | `requires-python = ">=3.14"`; note rewritten with the corrected patch range and the reason the specifier is series-level |
| **`uv.lock:3`** | same relaxation via `uv lock` (4-line diff, **zero** resolution churn) |
| `.python-version` | unchanged (`3.14.6`) |
| `src/alfred/_python_floor.py` *(new)* | `FLOOR = (3, 14, 6)`, `UnsupportedPythonError`, pure `enforce(version) -> None` |
| `src/alfred/__init__.py` | calls `enforce(sys.version_info[:3])` |

`_python_floor.py` at package root follows the existing `_repo_root.py` / `_stdio_logging.py`
precedent. `sys.version_info[:3]` reveals as `tuple[int, int, int]` under both `mypy --strict` and
pyright — no cast, no ignore.

**`uv lock --check` gate (new).** `uv sync --frozen` returns 0 on a pyproject/lock mismatch, all
11 `ci.yml` sync sites use `--frozen`, and nothing anywhere runs `--check`. Without this gate the
lockfile can silently drift back out of sync and re-kill all three channels.

### Part 2a — static detector (PR-gating)

A unit test in `tests/unit/meta/` asserting **both** `pyproject.toml` and `uv.lock` carry a
series-level `requires-python`. Draft 1 checked only `pyproject.toml` — it would have reported
green on a repo where the fix did not work.

Its oracle must not reuse the implementation's parsing predicate. It rides the existing required
`Python (lint, types, unit)` check, so no new status context and no promotion deadlock.

### Part 2b — the monitor

`scripts/check_dependency_graph_freshness.py`, pure functions + thin `main`, argparse, stdlib-only
(`tomllib`), consuming a fetched SBOM file.

Signals, in order:

1. **Liveness (primary, per-channel).** Latest run conclusion for exactly **two** keys,
   `dependency-graph` and `dependabot-updates` — not three. Dependabot's security-update and
   weekly-`pip` channels are separate commands inside one workflow (282449388), so the runs API
   gives them a single shared conclusion; splitting them needs per-job inspection, which does not
   exist yet. This is a named limitation, not an oversight: claiming three independent signals
   would overstate what is actually measured.
2. **Coverage floor.** A measured minimum `pkg:pypi` count. Defeats the empty-SBOM, no-pypi and
   error-body degeneracies.
3. **Two-directional containment.** Both directions, each independently fail-closed:
   - `missing_from_sbom` — `set(uv.lock) − set(SBOM)` must be empty (measured empty at 100/100
     today). Defeats the silently-dropped-package case.
   - `unexpected_in_sbom` — `set(SBOM) − set(uv.lock)` must be empty once
     `_GRAPH_ONLY_ALLOWLIST = {click, hatchling}` is subtracted too: names the graph can
     legitimately carry with no lock entry (`hatchling` is the PEP 517 build backend; `click` is a
     stale leftover from a since-dropped transitive dependency, confirmed against the frozen
     fixture). Anything else present in the graph but absent from the lock is unexplained and
     fails closed. Defeats the silently-kept-stale-package case draft 2 could not see — draft 2
     only ever checked the first direction.
4. **Conflicting versions.** A package whose purls carry more than one distinct version in the
   SBOM (`conflicting_versions`) fails closed on its own terms, independent of whether either
   version matches `uv.lock`: two versions of one package in the graph is itself evidence of
   staleness.
5. **Content comparison (secondary).** Version equality, keyed off the **purl**, excluding
   `alfred`. The live SBOM contains duplicate `textual` and `alfred` entries — one version-less,
   one carrying a real version — with `versionInfo: null` on the version-less half of each pair; a
   naive `{name: version}` map yields permanent false drift and a monitor that can never go green.
   The frozen SBOM also carries a third version-less record, `hatchling`, which is **not** a
   duplicate: it appears exactly once, with no versioned twin. It is invisible to this signal
   (excluded by the same version-less filter) but IS counted by the coverage floor's package-name
   set — the distinction the coverage floor got wrong (see the `--min-packages` note in the
   monitor workflow).
6. **Versioned-record proof.** A lock package whose SBOM presence is *entirely* version-less
   (`unversioned_in_sbom`) fails closed, even though it already clears containment (signal 3) and
   is invisible to signal 5's comparison — `sbom_names()` counts a version-less purl as present,
   and `sbom_versions()` excludes version-less records from comparison entirely, so without this
   signal a graph in which every lock package appears only as a version-less purl would pass
   everything else cleanly. A version-less record stays legitimate when a **versioned** record for
   the same name also exists elsewhere in the document: the live graph really does carry
   version-less `textual` and `alfred` duplicates alongside versioned ones (signal 5's
   phantom-record pair), and `alfred` itself is excluded from every signal via `_SELF_PACKAGE`
   because it is the repo's own published package, not a lockfile dependency. The rejection is
   narrow — a lock package with no versioned record anywhere, not a package that merely has a
   version-less duplicate.
7. **Fail-closed fetch.** A failed or malformed `gh api` response is a failure, never "no drift".

Draft 1's algorithm passed on four of five degenerate inputs, including one that *is* #568
recurring — and would have closed its own tracking issue while doing so.

**Alerting.** One **permanently-open** tracking issue whose body is rewritten each run. Draft 1's
"open on drift, close on resync" made silence the healthy state, so a broken monitor was
indistinguishable from a healthy repo — #568's own failure class inside its remedy.

**Injection.** This would be the repo's first `issues: write` workflow. `check_tag_t3.py:622`
pins scan roots to `('src/alfred','plugins')`, so the repo's existing tag discipline cannot be
inherited here. Package names and versions reaching the issue body must be sanitised, passed via
`env:`, never interpolated into `run:`. Actions pinned by SHA; `persist-credentials: false`.

**Negative case.** A **committed stale-SBOM fixture**, not the live API. The live signal
evaporates on merge and would leave the guard permanently unfalsifiable.

### Part 3 — launcher reason vocabulary

`bin/alfred-plugin-launcher.sh:241` runs `python3 -m alfred.plugins.manifest_reader`, which imports
`alfred` and therefore fires the new guard pre-exec. Its fallback classifies any unrecognised
capture as `daemon.boot.environment_not_set`, and **that reason is persisted to the signed,
append-only audit log**. A confidently wrong reason there violates CLAUDE.md hard rule 7.

Fix: mirror the exemplar at `:434`, whose `*)` arm already treats an unrecognised capture as
"a drift/crash ALARM, not a routine refusal — say so rather than guessing a specific reason".
Add an `interpreter_below_floor` token to `SANDBOX_REFUSED_REASONS`
(`src/alfred/audit/audit_row_schemas.py:1225`).

### Part 4 — ADR-0030 import-closure gate

The gate is a denylist and is **structurally blind to `src/alfred/__init__.py`**: `to_clear` never
clears `alfred`, so `__init__.py` never re-runs inside the measurement window. Proven by mutation
— adding `import alfred.audit` to the guard module leaves the gate at *2 passed, mutant survived*,
while `alfred.audit` genuinely enters the bwrapped quarantine child's reachable surface.

It is inert today only because `__init__.py` is 0 bytes. **This change is what populates it.**

Measured during implementation: the blindness is **unconditional under pytest**, not
order-dependent as first thought. `tests/unit/conftest.py:39` imports `alfred.audit.log` at module
scope (since 2026-05-27, #95), so `alfred` is resident during collection for every invocation —
including running the gate's own file alone.

Fix: clear the entire `alfred` tree from `sys.modules` and re-import `_CHILD_ENTRY` **in the same
pytest process**, restoring the original module objects in a `finally` afterward — not a fresh
subprocess. (`test_main_lazy_imports.py`'s subprocess pattern was the plan; what shipped in
`test_quarantine_child_import_closure.py`'s `_alfred_modules_to_clear()` +
`test_quarantine_child_import_closure_touches_no_privileged_module()` is the cheaper in-process
eviction-and-re-import instead — verified working and mutation-proven, so left as shipped.) Plus a
mutation case pinning it, and an explicit statement of the child's closure bound.

### Part 5 — doc corrections

| Site | Correction |
| --- | --- |
| `pyproject.toml:6-11` | patch range + series-level rationale |
| `tests/unit/test_frozen_slots_dataclass_regression_guard.py` | lines **6 and 26** both carry the claim |
| `.rulesync/rules/CLAUDE.md:74` | canonical source; root `CLAUDE.md` is a gitignored rulesync **output** (`.gitignore:85`) — regenerate with `rulesync generate -t '*' -f '*'` (CONTRIBUTING.md:35), never edit directly |
| `PRD.md:618` (DEC-001) | states the floor, not a patch range; needs the floor update only. **Human-gated** — prepared as a proposed diff, not committed |

New **ADR-0061** records the deliberate divergence between declared and enforced floor.

## PR shape

One PR, on four conditions established during review:

1. The monitor's negative case is a **committed fixture** (its verification does not depend on
   merge order).
2. `PRD.md` is explicitly out-of-PR, so it cannot gate the merge.
3. The guard is exercised across **real import surfaces**, not just the pure function.
4. Issue-body sanitisation is specified before the workflow is written.

The split into fix-then-monitor was considered and rejected: it is self-defeating, because the
monitor's first run would be green and its live red would never execute. The five-surface
coverage-gate lockstep fails loud at collection time (`zip(..., strict=True)`), so worst case is
red-CI iteration, not a silent gap. If a cut is ever needed, cut the `__init__.py` wiring, not the
monitor.

## Testing

| Test | Asserts | Non-vacuity |
| --- | --- | --- |
| `enforce` below/at/above floor | raises / returns; message names required and found | Negative case executes |
| **guard wiring** | `monkeypatch.setattr(sys,"version_info",(3,14,4,"final",0))` + `importlib.reload(alfred)` raises | Kills the mutant that **deletes** `enforce(...)` — draft 1's tests all survived it |
| series-level, **both files** | no patch component in `pyproject.toml` *and* `uv.lock` | Mutation: restoring `>=3.14.6` in either must go red |
| monitor degeneracies | empty SBOM, no-pypi SBOM, API error body, dropped package, null `versionInfo` | Each must FAIL; all five passed in draft 1 |
| liveness | red on a failing channel conclusion | Replay against the real 20-failure history |
| ADR-0030 gate | `import alfred.audit` in `_python_floor.py` must fail the gate | Currently survives — the mutation is the proof |
| launcher reason | sub-floor interpreter → `interpreter_below_floor`, never `environment_not_set` | Assert the audit row's reason field |

Every guard is mutation-verified before the PR opens. `scripts/` is neither ruff-linted nor
type-checked today (py-006); the coverage census (#423) still requires the new script to be gated
at 100 % or allow-listed, which is a six-file lockstep edit (rev-005), not a one-line addition.

## Verification

- `make check` green — read the exit status directly, never `| tail`
- `uv lock --check` clean
- After merge: **all three channels** confirmed alive — graph run succeeds, security-update run
  succeeds, weekly `pip` PR reappears. Liveness is the fast signal; the weekly PR is the slowest
  and must not be the only one watched
- Graph reports `aiohttp 3.14.3` / `gitpython 3.1.57` / `pydantic-settings 2.14.2`
- The ~35 stale packages begin resolving; the 27 alerts auto-close or are dismissed with a reason
- **Commit subjects use `fix: #568` only on the commit that should close the issue.** `fix: #568`
  auto-closes on merge, which would close #568 *before* post-merge verification runs

## Out of scope

- Promoting the monitor to a required check — revisit once it has a track record.
- `.python-version` and the CI `3.14` pins.
- Extending `check_tag_t3.py`'s scan roots to `scripts/`.
- #565, #564, #560.
