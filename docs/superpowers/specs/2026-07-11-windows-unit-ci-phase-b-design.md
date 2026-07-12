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
   (`_LAUNCHER_REQUIRES_ROOT`, line 58). This module is **mixed**, not purely POSIX-runtime: roughly
   half its tests `exec` the bash launcher / `runuser` / `/bin/echo` (POSIX-runtime), but ~6 are
   **portable** static-contract tests that only `_LAUNCHER.read_text()` the launcher script and grep
   its bytes (e.g. `test_launcher_invokes_runuser_for_uid_drop`). Whole-file collection-ignore drops
   those portable tests on Windows too. That loss is **accepted** (see §4): they read tracked repo
   bytes, so they produce byte-identical results on every OS — the Linux and macOS legs already run
   them, and Windows adds **zero unique signal**. The alternative (reclassify as a runtime-failure file
   by fixing the one-line `os.uname()` const to `platform.system()` and per-test `skipif`-ing only the
   exec tests) was weighed and declined in favour of the uniform mechanism.
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

All three modules are **POSIX-runtime** on the whole (POSIX `resource`/`RLIMIT_CORE`; a bash/`runuser`
launcher; POSIX file mode/owner semantics), and none can run its *substantive* tests on Windows —
File 2 additionally carries some portable static-grep tests whose Windows loss is accepted (§2 item 2,
§4). The chosen mechanism is a **win32-gated `collect_ignore_glob`** in the top-most `tests/conftest.py`
— pytest reads this **before importing** the listed modules, so the crash never happens.

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

collect_ignore_glob = collect_ignore_for(sys.platform, Path(__file__).resolve().parent)
```

Design notes:

- **Resolved absolute paths**, built from `Path(__file__).resolve().parent` (matching the repo's
  existing `_REPO_ROOT = Path(__file__).resolve().parents[1]` convention and the meta test's resolved
  root), so matching is independent of pytest's invocation cwd **and** canonicalises symlinks — pytest
  compares against resolved collection-node paths, so an unresolved entry could fail to match under a
  symlinked `tests/` tree.
- **Exact paths, not globs.** The helper emits exact absolute paths with no fnmatch metacharacters
  (`* ? [ ]`); `collect_ignore_glob` is used for parity with the sibling docker mechanism and is
  proven by the pytester test, but entries must stay literal — do not add wildcard entries expecting
  glob semantics. (`collect_ignore` — exact-path equality — is the semantically-precise alternative;
  kept as `collect_ignore_glob` per this design, and the metacharacter-free repo path makes the two
  equivalent in practice.)
- **`collect_ignore_glob` is NOT merged across conftests.** pytest takes the value from the *deepest*
  conftest that defines the name. There are intermediate conftests under `tests/unit` (none define it
  today); a future one that assigns `collect_ignore`/`collect_ignore_glob` would silently shadow this
  win32 guard for its subtree. §6 adds a static meta assertion forbidding that.
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

- **A NEW import-time crash** (a collection error in a file not already listed) → add the file to
  `POSIX_ONLY_TEST_FILES`. You cannot skip what will not import. **Precondition (fix-don't-dismiss):**
  first confirm the crash comes from a genuinely POSIX-only facility (in the test, or a legitimately
  POSIX production module) — **not** an unguarded `os.getuid()`/`os.uname()`/POSIX syscall newly
  introduced into `src/alfred/` that should instead be made Windows-import-safe. Any rule-(a) addition
  of a `src/alfred/security/`- or `supervisor`-adjacent test goes through **security review** (the
  helper only ignores on win32, so Linux coverage is structurally intact regardless — but the review
  guards against suppressing a symptom instead of fixing a regression).
- **The SAME already-listed modules still error at collection** → this is a **collect-ignore mechanism
  failure** (the win32 glob did not match — e.g. a path-separator / resolution mismatch that the
  Darwin pytester test cannot exercise), **not** a new rule-(a) file. Re-adding an already-listed file
  is a no-op; instead inspect the Windows collection-node paths vs the resolved ignore entries.
- **Runtime failure, import succeeds** → in-place `@pytest.mark.skipif(sys.platform == "win32",
  reason=…)` on the specific test or module (or make the test portable). Once import works, `skipif`
  is the correct, most-local tool.

Each iteration: push → read the Windows unit step's result **from the step LOG** (the pytest summary
line) — the step `conclusion` shows "success" while `continue-on-error` is on, and the true `outcome`
is not surfaced by `gh run view`, only the masked `conclusion` is → apply the rule → repeat until the
step is green **and runs a substantial passed count** (§6's assert-RAN floor), not merely free of
FAILED/ERROR.

## 6. Testing

- **Pure-function unit test** (`tests/unit/meta/…`, mirroring Phase A's meta guard):
  - `collect_ignore_for("win32", base)` returns the 3 absolute paths; `collect_ignore_for("linux",
    base)` returns `[]` — pins the list and verifies the win32 gating branch locally (the branch real
    Windows exercises, otherwise untested on Darwin).
  - **Content-pinning canary:** assert the ignored set is exactly the three known basenames (not just a
    `len == 3` count) so a *same-count swap* of which modules are ignored also trips the review gate.
  - **Anti-orphan assertion:** every path in `POSIX_ONLY_TEST_FILES` resolves to an existing file, so a
    rename/deletion that orphans an entry fails loudly rather than silently no-op'ing the glob.
- **Real-wiring assertion** (mirrors Phase A's `test_docker_autoskip_hook.py` importing the real
  conftest): `from tests import conftest; assert conftest.collect_ignore_glob ==
  collect_ignore_for(sys.platform, Path(conftest.__file__).resolve().parent)`. On Darwin/Linux this is
  `== []` but it still proves the conftest attribute **exists, is spelled correctly, and is wired to
  the helper with the right resolved `tests_root`** — catching a `collect_ignore_globs` typo or a wrong
  base locally, instead of only on a re-crashed real Windows CI run.
- **No-shadow static guard:** assert no `conftest.py` under `tests/unit` defines
  `collect_ignore`/`collect_ignore_glob` (they are not merged across conftests; the deepest definer
  wins, which would silently shadow the top-most win32 guard). Mirrors the existing docker-conftest
  anti-rot guard.
- **pytester end-to-end** (uses the already-enabled `pytest_plugins=["pytester"]`): a sub-`pytest` run
  whose `collect_ignore_glob` is built by `collect_ignore_for("win32", …)` asserts the target file is
  not collected — proves pytest honours the helper-built list, on Darwin.
- **Assert-RAN floor (hollow-gate guard).** The blocking Windows leg must **run a substantial passed
  count**, not merely be free of FAILED/ERROR — otherwise progressive accumulation of ignore-list
  entries + `skipif`s could hollow the gate into the repo's #245 "green while gating nothing" shape.
  The Task-4 exit criterion parses `N passed` from the Windows summary and asserts `N >= 3000` (a floor
  far below today's ~5900 that only trips on a runaway ignore list; the suite only grows) with
  `skipped` a small fraction of `passed`.
- **No "forgot to add a file" anti-rot guard is needed** for *additions*: once Windows is blocking, a
  new POSIX-only file that crashes collection fails CI loudly — the blocking leg *is* that guard. The
  silent failure modes (orphaned entry, same-count swap, an intermediate conftest shadowing the guard,
  a runaway ignore list) are covered by the assertions above.

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
  **Contingency (documented, not expected):** if the runtime surface proves unexpectedly deep (or the
  assert-RAN floor cannot be met without a hollow gate), we do **not** ship a red or hollow blocking
  leg — we keep Windows informational and split promotion to a follow-up. If that fires, the PR
  title/body must be reworded to describe only the collection guard, and the "#246 Part 1 complete"
  close-out comment is **not** posted (Part 1 stays open). This spec's §4 collection guard has
  standalone value (clean collection) regardless.
- **Glob matching.** Resolved absolute paths from `Path(__file__).resolve().parent` remove cwd +
  symlink ambiguity; the pytester test confirms pytest honours the helper-built list.
- **Orphaned ignore entry** (a listed file renamed/deleted): caught by the §6 anti-orphan assertion.
- **Hollow gate via accumulated skips:** caught by the §6 assert-RAN floor + the security-review
  invariant on security-adjacent ignore additions.

## 9. Acceptance criteria

1. `tests/conftest.py` collection-ignores the 3 POSIX-only modules on win32 only, via a testable pure
   function; the meta test (gating + content-pinning canary + anti-orphan + real-wiring + no-shadow)
   passes on Darwin.
2. On the PR's own CI, the `Python cross-OS (windows-latest)` **Unit tests** step's LOG shows a clean
   pytest summary — collection clean, every executed test passing, and a substantial passed count
   (assert-RAN floor `N >= 3000`), read from the log (not a `gh … outcome` field, which does not
   exist).
3. `continue-on-error` is removed from the unit step; the Windows unit leg **blocks** merge. A rollback
   lever is documented: on a Windows-unit flake, re-add the one `continue-on-error` line — do **not**
   de-require the check (that would also drop the static lint/type gate).
4. `docs/ci/required-checks.md` reflects the Windows unit leg as blocking (row, reality table, prose,
   Deferred item 2 marked done).
5. #246 Part 1 closed; Part 2 (macOS-native `sandbox-exec`) remains open.
6. macOS unit leg stays blocking (no Phase A regression); Linux `python`/`python-arm64` unchanged.
