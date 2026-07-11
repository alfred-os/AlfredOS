# Windows unit-test CI leg → blocking — #246 Phase B, Part 1 (design)

**Status:** Ratified (mechanism + scope confirmed with the requester 2026-07-11).
Branch `246-windows-unit-blocking` off main `44e95b08` (#246 Phase A merged, PR #417).

This is Phase B of the cross-platform unit-CI work whose Phase A design record is
[`2026-07-11-macos-unit-crossplatform-ci-design.md`](2026-07-11-macos-unit-crossplatform-ci-design.md)
(and whose authoritative Phase A contract is the
[Phase A plan](../plans/2026-07-11-crossos-unit-ci-phase-a.md)). Phase A landed the macOS unit leg
**blocking** and the Windows unit leg **informational** (`continue-on-error`). Phase B guards the
win32 failure surface that informational leg reveals and promotes Windows to **blocking**.

## 1. Goal

Make the `Python cross-OS (windows-latest)` unit step green on real CI, then drop its
`continue-on-error` so the leg **blocks** merge like macOS — and close **#246 Part 1**. This gives
Windows contributors a portability-clean unit suite and turns the existing informational signal into
an enforced gate.

Non-goal for this PR: **#246 Part 2** (macOS-native `sandbox-exec`, blocked on PR-S4-7) stays open.
Orthogonal and **not bundled**: the deterministic-type-check trim (running mypy/pyright once on
ubuntu instead of duplicating across arm64/macOS/Windows).

## 2. Current state — the win32 failure surface

Phase A's informational Windows leg runs `uv run pytest tests/unit -q`. Its step `conclusion` reads
"success" only because `continue-on-error` masks the real `outcome: failure` (GitHub distinguishes
`outcome` from `conclusion` — the informational contract working as intended). The actual result
(from the Phase A PR run, `Python cross-OS (windows-latest)` job):

> **`Interrupted: 3 errors during collection`** — pytest never ran the suite.

Because pytest reports **every** import failure in one collection pass, these 3 are the **complete
current collection-error set**. The 3 offending modules and their import-time causes:

1. `tests/unit/supervisor/test_process_posture.py` — `ModuleNotFoundError: No module named 'resource'`.
   The POSIX-only `resource` stdlib module is imported both by the test (line 13) **and by the
   production module it imports**: `src/alfred/supervisor/process_posture.py` does `import resource`
   at its top (for `RLIMIT_CORE`). So `from alfred.supervisor.process_posture import …` crashes on
   Windows inside the **production** import.
2. `tests/unit/plugins/test_plugin_launcher_stub.py` — `AttributeError: module 'os' has no attribute
   'uname'`. A module-level constant evaluates `os.uname().sysname` at import
   (`_LAUNCHER_REQUIRES_ROOT`, line 58). The module's own imports are otherwise Windows-safe, but its
   tests `exec` the bash launcher, `runuser`, and `/bin/echo` — POSIX-runtime regardless.
3. `tests/unit/identity/test_operator_session_file_load.py` — `AttributeError: module 'os' has no
   attribute 'getuid'`. Two `@pytest.mark.skipif(os.getuid() == 0, …)` decorators (lines 203, 218)
   evaluate `os.getuid()` at **decoration** (import) time. The module is **already** whole-module
   `pytestmark = skipif(sys.platform == "win32", …)` — but that skip is applied by pytest *after* the
   module imports, so it never fires; the import crashes first. The production module
   (`operator_session.py`) is Windows-import-safe (it guards with `hasattr(os, "geteuid")`).

### Why a module-level `skipif` cannot fix these

`pytestmark`/`skipif` are evaluated **after** the module is imported. All three failures happen
**during** import (a top-level `import resource`, a module-const `os.uname()`, a decorator-expression
`os.getuid()`). You cannot skip a module that crashes before pytest gets to apply the skip. File 1 is
the sharpest case: even a flawless in-place guard in the test file cannot prevent the crash, because
the crash is in the **production** module's `import resource`, triggered by the test's `from … import`.

## 3. Design decision — centralized collection-ignore (Approach A)

All three modules are **genuinely POSIX-runtime** (POSIX `resource`/`RLIMIT_CORE`; a bash/`runuser`
launcher; POSIX file mode/owner semantics). None can run meaningfully on Windows. The chosen mechanism
is a **win32-gated `collect_ignore_glob`** in the top-most `tests/conftest.py` — pytest reads this
**before importing** the listed modules, so the crash never happens.

Rejected alternatives:

- **Per-file in-place guards (`pytestmark` + fix the eager `os.getuid()`/`os.uname()` evaluation).**
  Cannot solve File 1 without a production change (making `resource` a lazy import — scope creep;
  `resource` is legitimately needed at module scope for `RLIMIT_CORE`). Also still imports the module
  on Windows (slower, more fragile). Rejected as the sole mechanism.
- **Hybrid (in-place for Files 2 & 3, ignore only File 1).** Two mechanisms and an inconsistent
  "where do I look?" policy for the same class of problem. Rejected in favour of one uniform mechanism.

This mirrors the Phase-A discipline: collection-level control in the top-most conftest (Phase A added
a `pytest_collection_modifyitems` docker auto-skip hook there; this adds `collect_ignore_glob` — the
sibling mechanism for **import-time** rather than **fixture-time** skips).

## 4. Mechanism

The win32 branch never executes on the Darwin dev box, so the list is extracted into a **pure,
testable function** in a small helper module (mirroring Phase A's `tests/_docker_probe.py`), and the
conftest merely wires it. This keeps the branch verifiable locally.

```python
# tests/_posix_only_tests.py
from pathlib import Path
from typing import Final

# Unit modules that cannot be COLLECTED on Windows because they import POSIX-only
# facilities at import time. Each entry is a path relative to the tests/ root.
# Because the failure is at import (not fixture) time, a module-level skipif
# cannot help — pytest must be told to ignore the file before importing it.
POSIX_ONLY_TEST_FILES: Final[tuple[str, ...]] = (
    # `import resource` (RLIMIT_CORE) in BOTH the test and the production module
    # src/alfred/supervisor/process_posture.py it imports — crashes on Windows.
    "unit/supervisor/test_process_posture.py",
    # os.uname() in a module-level const + bash/runuser/`/bin/echo` exec.
    "unit/plugins/test_plugin_launcher_stub.py",
    # os.getuid() in a skipif decorator evaluated at import; POSIX mode/owner
    # semantics (module is already whole-module skipif win32 for non-Windows).
    "unit/identity/test_operator_session_file_load.py",
)


def collect_ignore_for(platform: str, tests_root: Path) -> list[str]:
    """Absolute paths pytest must ignore on `platform`; empty off Windows."""
    if platform != "win32":
        return []
    return [str(tests_root / rel) for rel in POSIX_ONLY_TEST_FILES]
```

```python
# tests/conftest.py (added near the existing collection hook)
import sys
from tests._posix_only_tests import collect_ignore_for

collect_ignore_glob = collect_ignore_for(sys.platform, Path(__file__).parent)
```

Design notes:

- **Absolute paths**, built from `Path(__file__).parent`, so matching is independent of pytest's
  invocation cwd.
- **Zero edits to the 3 test files.** Collection-ignore prevents the import entirely — the correct
  and minimal change. We deliberately do **not** also "fix" the eager `os.getuid()`/`os.uname()`
  evaluations as defence-in-depth: YAGNI, and touching unrelated security-test files widens the blast
  radius for no benefit (if a future maintainer removes a file from the list, the blocking leg catches
  the regression immediately — see §6).
- **No production code change.** `resource` stays eagerly imported in `process_posture.py`.

## 5. Iteration decision rule (the runtime failures that surface next)

Once collection is clean, the suite actually **runs** on Windows for the first time and will likely
surface a fresh layer of **runtime** failures (path separators, text encoding, subprocess quoting,
`/bin/sh`, `signal.SIGKILL`, `subprocess(..., pass_fds=…)`). These cannot be pre-validated on Darwin
(the dev box is macOS), so Phase B is **discover-then-guard against real Windows CI**, iterating with
this rule:

- **Import-time crash** (a new collection error) → add the file to `POSIX_ONLY_TEST_FILES`. You cannot
  skip what will not import.
- **Runtime failure, import succeeds** → in-place `@pytest.mark.skipif(sys.platform == "win32",
  reason=…)` on the specific test or module (or make the test portable). Once import works, `skipif`
  is the correct, most-local tool.

Each iteration: push → read the Windows unit step's `outcome` (readable even while the step is still
`continue-on-error`) → apply the rule → repeat until the step is green.

## 6. Testing

- **Pure-function unit test** (`tests/unit/meta/…`, mirroring Phase A's meta guard):
  - `collect_ignore_for("win32", base)` returns the 3 absolute paths; `collect_ignore_for("linux",
    base)` returns `[]` — pins the list and verifies the win32 gating branch locally (the branch real
    Windows exercises, otherwise untested on Darwin).
  - **Anti-orphan assertion:** every path in `POSIX_ONLY_TEST_FILES` resolves to an existing file, so a
    rename/deletion that orphans an entry fails loudly rather than silently no-op'ing the glob.
- **pytester end-to-end** (optional; uses the already-enabled `pytest_plugins=["pytester"]`): a
  sub-`pytest` run with `collect_ignore_glob` set to the target paths asserts those items are not
  collected — proves pytest honours the mechanism, on Darwin.
- **No "forgot to add a file" anti-rot guard is needed.** Once Windows is blocking, a new POSIX-only
  file that crashes collection fails CI loudly — the blocking leg *is* that guard. The only silent
  failure mode is an orphaned entry, covered by the anti-orphan assertion above.

## 7. Promotion (once the Windows unit step is green on real CI)

- `.github/workflows/ci.yml`: **delete** the single line
  `continue-on-error: ${{ matrix.os == 'windows-latest' }}` on the collapsed `Unit tests (no coverage
  gate)` step (ci.yml:872) so the step blocks on both matrix legs. Update the now-stale
  "informational / Phase B lands the guards" comments in the `python-cross-os` job (the per-OS reality
  block ~763–772, the job-level note ~785–790, and the step comment ~851–870) to past-tense/blocking.
- `docs/ci/required-checks.md`:
  - **Windows required-check row** (≈ line 53): "unit suite INFORMATIONALLY … promote it to blocking
    in #246 Phase B" → runs the unit suite **blocking** (#246 Phase B), collection-ignoring the
    POSIX-only modules.
  - **Reality table** (≈ line 97): the Windows `Unit suite` cell `informational (continue-on-error;
    #246)` → `✓ blocking (Docker + POSIX-only tests skip; #246)`.
  - **Windows prose bullet** (≈ line 114) and surrounding prose (≈ 101–108): reflect blocking.
  - **Deferred item 2** (≈ line 121): mark **DONE (#246 Phase B)** like item 1.
- Close **#246 Part 1**.

## 8. Risks & contingency

- **Unknown runtime-failure depth.** We cannot pre-validate on Darwin. Per the requester's decision,
  the plan drives to green + blocking in this one PR, iterating (§5) against real Windows CI.
  **Contingency (documented, not expected):** if the runtime surface proves unexpectedly deep, we do
  **not** ship a red blocking leg — we keep Windows informational and split promotion to a follow-up.
  This spec's §4 collection guard has standalone value (clean collection) regardless.
- **Glob matching.** Absolute paths from `Path(__file__).parent` remove cwd ambiguity; the pytester
  test confirms pytest honours them.
- **Orphaned ignore entry** (a listed file renamed/deleted): caught by the §6 anti-orphan assertion.

## 9. Acceptance criteria

1. `tests/conftest.py` collection-ignores the 3 POSIX-only modules on win32 only, via a testable pure
   function; the meta test (gating + anti-orphan) passes on Darwin.
2. On the PR's own CI, the `Python cross-OS (windows-latest)` **Unit tests** step reports
   `outcome: success` (green) — collection clean and every executed test passing.
3. `continue-on-error` is removed from the unit step; the Windows unit leg **blocks** merge.
4. `docs/ci/required-checks.md` reflects the Windows unit leg as blocking (row, reality table, prose,
   Deferred item 2 marked done).
5. #246 Part 1 closed; Part 2 (macOS-native `sandbox-exec`) remains open.
6. macOS unit leg stays blocking (no Phase A regression); Linux `python`/`python-arm64` unchanged.
