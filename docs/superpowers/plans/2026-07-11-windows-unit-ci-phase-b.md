# Windows unit-test CI leg → blocking (#246 Phase B, Part 1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `Python cross-OS (windows-latest)` unit step green on real CI, then drop its `continue-on-error` so the Windows unit leg blocks merge, and mark #246 Part 1 done.

**Architecture:** A win32-gated `collect_ignore_glob` in the top-most `tests/conftest.py`, backed by a pure/testable helper (`tests/_posix_only_tests.py`), stops pytest from importing the 3 POSIX-only modules that crash at collection on Windows. With collection clean, the suite runs on Windows for the first time; remaining runtime failures are guarded discover-then-guard against real CI (import-crash → the ignore list; runtime failure → in-place `skipif(win32)`). Once green, one line of `ci.yml` and a docs pass promote the leg to blocking.

**Tech Stack:** Python 3.14+, pytest (`collect_ignore_glob`, `pytester`), GitHub Actions, `uv`, `ruff`, `markdownlint-cli2`, `gh` CLI.

## Global Constraints

- **Python 3.14+**; modern idioms (PEP 604/585/695), `from __future__ import annotations` at file top (matches the repo).
- **No production code change.** `resource` stays eagerly imported in `src/alfred/supervisor/process_posture.py` — it is legitimately needed for `RLIMIT_CORE`.
- **Zero edits to the 3 collection-erroring test files** in the guard step — collection-ignore prevents their import entirely.
- **Spec is authoritative:** `docs/superpowers/specs/2026-07-11-windows-unit-ci-phase-b-design.md`.
- **Not bundled** (orthogonal): the deterministic-type-check trim (mypy/pyright once on ubuntu). Do not touch it here.
- **#246 stays OPEN** after this PR — Part 2 (macOS-native `sandbox-exec`) remains, blocked on PR-S4-7. PR body says `Part of #246 (Phase B / Part 1)` with **no** closing keyword.
- **Commits:** conventional-commit format with a literal `#246` **after the colon** in every subject; end every commit body with the `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` trailer; never `--no-verify`; stage named paths only (never `git add -A`); never `--admin` merge.
- **`make check` (or the relevant `uv run` gates) before every push.**
- **Assert-RAN floor.** Before promoting, the Windows unit leg must run a substantial passed count (`>= 3000`, floor far below today's ~5900), not merely be FAILED/ERROR-free — a hollow-gate guard (#245 discipline).
- **Rollback = revert one line, not de-require.** On a Windows-unit flake post-merge, re-add the step-level `continue-on-error`; never de-require `Python cross-OS (windows-latest)` (that would also drop the static lint/type gate).
- **Local markdownlint is pinned** to the CI version (`markdownlint-cli2@0.22.1`) so local matches CI.

---

### Task 1: The testable ignore-list helper + meta unit tests

Pure function + its unit tests. Fully local (TDD) — the win32 branch never runs on the Darwin/Linux legs otherwise, so these tests are how it gets exercised before real Windows CI.

**Files:**

- Create: `tests/_posix_only_tests.py`
- Create: `tests/unit/meta/test_posix_only_collect_ignore.py`

**Interfaces:**

- Consumes: nothing (leaf helper).
- Produces:
  - `POSIX_ONLY_TEST_FILES: Final[tuple[str, ...]]` — the 3 tests/-relative paths.
  - `collect_ignore_for(platform: str, tests_root: Path) -> list[str]` — absolute paths to ignore when `platform == "win32"`, else `[]`.

- [ ] **Step 1: Write the failing meta test**

Create `tests/unit/meta/test_posix_only_collect_ignore.py`:

```python
"""#246 Phase B — the win32 collection-ignore list is correct and non-rotting.

The win32 branch of ``collect_ignore_for`` never runs on the macOS/Linux dev box
or the Linux CI legs, so these tests pin it directly: the platform gating (win32
→ the 3 modules, else empty), that the produced paths resolve to existing files
(anti-orphan), and — via ``pytester`` — that pytest actually honours a
``collect_ignore_glob`` built from the helper.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests import conftest as root_conftest
from tests._posix_only_tests import POSIX_ONLY_TEST_FILES, collect_ignore_for

_TESTS_ROOT = Path(__file__).resolve().parents[2]  # tests/


def test_non_win32_ignores_nothing() -> None:
    assert collect_ignore_for("linux", _TESTS_ROOT) == []
    assert collect_ignore_for("darwin", _TESTS_ROOT) == []


def test_win32_ignores_the_known_posix_only_modules() -> None:
    ignored = collect_ignore_for("win32", _TESTS_ROOT)
    assert ignored == [str(_TESTS_ROOT / rel) for rel in POSIX_ONLY_TEST_FILES]
    # Content-pinning canary: the exact known basenames — so a SAME-COUNT swap
    # of which modules are ignored also trips this reviewed gate, not just an
    # add/remove. Bump this set (a reviewed diff) when the list legitimately
    # changes (Task 4 rule a).
    assert {Path(rel).name for rel in POSIX_ONLY_TEST_FILES} == {
        "test_process_posture.py",
        "test_plugin_launcher_stub.py",
        "test_operator_session_file_load.py",
    }


def test_every_listed_module_exists() -> None:
    """Anti-orphan: a rename/deletion that orphans an entry fails loudly here."""
    for rel in POSIX_ONLY_TEST_FILES:
        assert (_TESTS_ROOT / rel).is_file(), f"orphaned collect-ignore entry: {rel}"


def test_pytest_honours_collect_ignore_from_helper(pytester: pytest.Pytester) -> None:
    """End-to-end: a ``collect_ignore_glob`` built by the helper hides the file.

    Recreates one POSIX-only path under the pytester root plus a portable
    sibling, feeds ``collect_ignore_for("win32", ...)`` into a temp conftest, and
    asserts only the portable test is collected — proving the conftest wiring
    (Task 2) actually prevents collection, the link the pure-function tests above
    do not exercise.
    """
    target_rel = POSIX_ONLY_TEST_FILES[0]
    target = pytester.path / target_rel
    target.parent.mkdir(parents=True)
    target.write_text("def test_would_crash() -> None:\n    assert True\n")
    (pytester.path / "test_portable.py").write_text(
        "def test_runs() -> None:\n    assert True\n"
    )

    ignore = collect_ignore_for("win32", pytester.path)
    pytester.makeconftest(f"collect_ignore_glob = {ignore!r}\n")

    result = pytester.runpytest("-q")
    result.assert_outcomes(passed=1)  # POSIX-only file ignored; only portable ran


def test_conftest_wiring_is_pinned() -> None:
    """The REAL conftest attribute is wired to the helper on every platform.

    On Darwin/Linux this is `== []`, but it still proves the attribute EXISTS,
    is spelled correctly (not `collect_ignore_globs`), and is derived from the
    helper with the right resolved tests_root — catching a typo/wrong-base
    locally instead of only on a re-crashed real Windows CI run. Mirrors the
    docker meta test's `from tests import conftest` pattern.
    """
    assert root_conftest.collect_ignore_glob == collect_ignore_for(
        sys.platform, Path(root_conftest.__file__).resolve().parent
    )


def test_no_intermediate_conftest_shadows_the_guard() -> None:
    """No conftest under tests/unit may define collect_ignore[_glob].

    pytest does NOT merge collect_ignore/collect_ignore_glob across the conftest
    chain — the DEEPEST definer wins. An intermediate conftest assigning either
    name would silently shadow the top-most win32 guard for its subtree and
    re-break Windows collection. This static guard forbids that (mirrors the
    docker-conftest anti-rot guard).
    """
    offenders = [
        cf
        for cf in (_TESTS_ROOT / "unit").rglob("conftest.py")
        if "collect_ignore" in cf.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        f"collect_ignore[_glob] is not merged across conftests; the win32 guard "
        f"lives only in the top-most tests/conftest.py. Offenders: {offenders}"
    )
```

- [ ] **Step 2: Run the meta test to verify it fails**

Run: `uv run pytest tests/unit/meta/test_posix_only_collect_ignore.py -q`
Expected: FAIL at import — `ModuleNotFoundError: No module named 'tests._posix_only_tests'`.

- [ ] **Step 3: Write the helper**

Create `tests/_posix_only_tests.py`:

```python
"""POSIX-only unit modules pytest must not COLLECT on Windows (#246 Phase B).

Three unit modules import POSIX-only facilities at import time, so they crash
during collection on Windows — before pytest can apply any module-level
``skipif`` (which is evaluated only after the module imports). The docker
auto-skip hook cannot help either: it runs in ``pytest_collection_modifyitems``,
also after import. ``tests/conftest.py`` feeds this list to pytest's
``collect_ignore_glob`` so the modules are never imported on Windows.

Kept as a pure function so the win32 branch — which never executes on a
non-Windows dev box or the Linux CI legs — is unit-testable locally (see
``tests/unit/meta/test_posix_only_collect_ignore.py``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

# Paths relative to the tests/ root. Each is POSIX-runtime and crashes Windows
# collection at import time:
POSIX_ONLY_TEST_FILES: Final[tuple[str, ...]] = (
    # `import resource` (RLIMIT_CORE) at module top in BOTH the test and the
    # production module it imports (src/alfred/supervisor/process_posture.py).
    # `resource` is POSIX-only → ModuleNotFoundError at import on Windows.
    "unit/supervisor/test_process_posture.py",
    # `os.uname().sysname` in a module-level constant → AttributeError on
    # Windows. Mixed file: most tests exec the bash launcher/runuser/`/bin/echo`
    # (POSIX); its ~6 portable read_text()+grep tests are lost on Windows too, an
    # accepted no-op (they read tracked bytes → identical on every OS; spec §2).
    "unit/plugins/test_plugin_launcher_stub.py",
    # `os.getuid()` inside two skipif decorators evaluated at import →
    # AttributeError on Windows; POSIX file mode/owner semantics (the module is
    # already whole-module skipif win32 for the non-Windows platforms).
    "unit/identity/test_operator_session_file_load.py",
)


def collect_ignore_for(platform: str, tests_root: Path) -> list[str]:
    """Absolute paths pytest must ignore when collecting on ``platform``.

    Returns the POSIX-only modules as absolute paths under ``tests_root`` when
    ``platform`` is ``"win32"``, else an empty list. ``platform`` is normally
    ``sys.platform``; passing it explicitly keeps the win32 branch testable off
    Windows.
    """
    if platform != "win32":
        return []
    return [str(tests_root / rel) for rel in POSIX_ONLY_TEST_FILES]
```

- [ ] **Step 4: Run the meta test to verify it passes**

Run: `uv run pytest tests/unit/meta/test_posix_only_collect_ignore.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Lint/format/type the two new files**

Run: `uv run ruff check tests/_posix_only_tests.py tests/unit/meta/test_posix_only_collect_ignore.py && uv run ruff format --check tests/_posix_only_tests.py tests/unit/meta/test_posix_only_collect_ignore.py && uv run mypy tests/_posix_only_tests.py`
Expected: all clean. (If ruff reports I001 import-order, run `uv run ruff check --fix <files>` and re-verify.)

- [ ] **Step 6: Commit**

```bash
git add tests/_posix_only_tests.py tests/unit/meta/test_posix_only_collect_ignore.py
git commit -m "test(ci): #246 add win32 collect-ignore helper + meta tests

$(printf 'Pure, testable collect_ignore_for(platform, tests_root) listing the 3\nPOSIX-only unit modules that crash Windows collection at import time, plus\nmeta tests pinning the win32 gating, an anti-orphan existence check, and a\npytester end-to-end proof that pytest honours the produced list.\n\nMrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

---

### Task 2: Wire the helper into the top-most conftest

Feed the helper into pytest's `collect_ignore_glob`. On non-Windows this is a no-op (`[]`), so the whole `tests/unit` suite must be byte-for-byte unchanged on Darwin.

**Files:**

- Modify: `tests/conftest.py` (imports block ~15-26; add the assignment near `_REPO_ROOT` ~33)

**Interfaces:**

- Consumes: `collect_ignore_for` from `tests/_posix_only_tests.py` (Task 1).
- Produces: module-level `collect_ignore_glob` read by pytest at collection time.

- [ ] **Step 1: Add the two imports**

In `tests/conftest.py`, add `import sys` to the stdlib import group (after `import subprocess`) and `from tests._posix_only_tests import collect_ignore_for` to the first-party `from tests.` group (alphabetically between `_docker_probe` and `support.discord_mocks`). Result:

```python
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests._docker_probe import docker_available, docker_unavailable_reason
from tests._posix_only_tests import collect_ignore_for
from tests.support.discord_mocks import DiscordMockFactory
```

- [ ] **Step 2: Add the `collect_ignore_glob` assignment**

Immediately after the `pytest_plugins = ["pytester"]` line and the `_REPO_ROOT = ...` line (near the top, module scope), add:

```python
# Modules pytest must NOT collect on Windows: they import POSIX-only facilities
# (`resource`, `os.uname`, `os.getuid`) at import time, before any module-level
# skipif can fire. Empty off Windows → a no-op on the Linux/macOS legs. The list
# is a testable pure function (tests/_posix_only_tests.py). #246 Phase B.
collect_ignore_glob = collect_ignore_for(sys.platform, Path(__file__).resolve().parent)
```

`Path(__file__).resolve().parent` is the `tests/` directory (conftest lives at `tests/conftest.py`). Use `.resolve()` for parity with the meta test's resolved root, consistency with the existing `_REPO_ROOT = Path(__file__).resolve().parents[1]` convention, and to honour spec §4's absolute-path guarantee under a symlinked tree (pytest compares against resolved collection-node paths).

- [ ] **Step 3: Verify the suite is unchanged on Darwin (no-op branch)**

Run: `uv run pytest tests/unit -q 2>&1 | tail -5`
Expected: the same pass/skip totals as before this branch (collection unaffected — `collect_ignore_for("darwin", …) == []`). No new errors, no newly-skipped files.

- [ ] **Step 4: Confirm the 3 target files are STILL collected on Darwin**

Run: `uv run pytest tests/unit/supervisor/test_process_posture.py tests/unit/plugins/test_plugin_launcher_stub.py tests/unit/identity/test_operator_session_file_load.py -q 2>&1 | tail -5`
Expected: they collect and run/skip normally on Darwin (the ignore list is empty off Windows — we did not accidentally hide them everywhere).

- [ ] **Step 5: Run the meta test + ruff on conftest**

Run: `uv run pytest tests/unit/meta/test_posix_only_collect_ignore.py -q && uv run ruff check tests/conftest.py && uv run ruff format --check tests/conftest.py`
Expected: PASS + clean. (If ruff reports I001, `uv run ruff check --fix tests/conftest.py` and re-verify.)

- [ ] **Step 6: Commit**

```bash
git add tests/conftest.py
git commit -m "test(ci): #246 wire win32 collect-ignore into the top-most conftest

$(printf 'collect_ignore_glob = collect_ignore_for(sys.platform, tests/) — a no-op\noff Windows; on Windows it stops pytest importing the 3 POSIX-only modules\nthat crash at collection. Suite unchanged on Darwin (empty-list branch).\n\nMrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

---

### Task 3: Run full local gates, push, open the PR, confirm Windows collection is clean

The collection guard is now complete and locally verified. This task takes it to real Windows CI for the first time. **Push/PR is outward-facing — HOLD here for the user's explicit "go" before pushing.**

**Files:** none (operational).

- [ ] **Step 1: Full local quality gates**

Run: `make check`
Expected: green. (If `make check|tail` is used, check `$?` — a tail masks the exit code.) Also run markdownlint on the committed spec + this plan, **pinned to the CI version** (`@0.22.1` per required-checks.md, so local matches CI): `npx --yes markdownlint-cli2@0.22.1 "docs/superpowers/specs/2026-07-11-windows-unit-ci-phase-b-design.md" "docs/superpowers/plans/2026-07-11-windows-unit-ci-phase-b.md"` → `0 error(s)`.

- [ ] **Step 2: Optional pre-push review (per CLAUDE.md cadence)**

Where practical, run the `/review-pr` fleet + CodeRabbit CLI (`--base origin/main`) on the local branch and fold findings before the first push (dismiss_stale_reviews discipline). The substantive review target is the guard mechanism (Tasks 1-2) + the spec.

- [ ] **Step 3: HOLD — get the user's "go", then push and open the PR**

```bash
git push -u origin 246-windows-unit-blocking
gh pr create --title "ci: #246 Phase B — Windows unit leg blocking (win32 collect-ignore)" \
  --body "Part of #246 (Phase B / Part 1). Promotes the Windows unit CI leg from informational to blocking. Adds a win32-gated collect_ignore_glob for the 3 POSIX-only modules that crash at collection, then guards the runtime failures the leg surfaces. Spec: docs/superpowers/specs/2026-07-11-windows-unit-ci-phase-b-design.md. #246 stays open for Part 2 (macOS sandbox-exec, blocked on PR-S4-7)."
```

No closing keyword — #246 stays open for Part 2.

- [ ] **Step 4: Confirm Windows collection is now clean**

Read the Unit-tests step's real result from the step **LOG** — the step `conclusion` shows "success" because `continue-on-error` masks it, and the true `outcome` is NOT surfaced by `gh run view` (only the masked `conclusion` is), so this log-read supersedes spec §5's `outcome` phrasing. **Gate on job completion first** (do not `2>/dev/null` the log read — an in-progress `gh run view --log` errors, and swallowing that would misread empty output as a clean collection):

```bash
RUN=$(gh run list --branch 246-windows-unit-blocking --workflow ci.yml --limit 1 --json databaseId -q '.[0].databaseId')
STATUS=$(gh run view "$RUN" --json jobs -q '.jobs[] | select(.name|test("windows-latest")) | .status')
[ "$STATUS" = "completed" ] || { echo "windows job still $STATUS — wait"; exit 0; }
WINJOB=$(gh run view "$RUN" --json jobs -q '.jobs[] | select(.name|test("windows-latest")) | .databaseId')
gh run view --job "$WINJOB" --log | grep -iE "error during collection|errors during collection| passed| failed|== .* ==" | tail -20
```

Expected: **no "errors during collection"** — the guard worked — and a non-empty summary line reporting `passed`/`failed`/`skipped` counts (the suite RAN; empty output means the read was premature, not clean). If a NOT-already-listed file errors at collection → Task 4 rule (a). If the SAME 3 listed files still error → it is a glob-matching/mechanism failure, not a new file (Task 4 decision rule, third bullet).

---

### Task 4: Iterate to a green Windows unit step (discover-then-guard)

With collection clean, the suite runs on Windows and will likely surface **runtime** failures (path separators, encoding, subprocess quoting, `/bin/sh`, `signal.SIGKILL`, `subprocess(..., pass_fds=…)`). These cannot be pre-validated on Darwin — iterate against real CI. This task is a **loop**; its exact edits are CI-discovered, so it gives the decision rule and two concrete fix templates rather than fabricated failures.

**Files:** discovered per iteration — either `tests/_posix_only_tests.py` (rule a) or the specific failing test module (rule b).

**Decision rule (from spec §5):**

- **A NEW import-time crash** (collection error in a file NOT already listed) → **rule (a)**: add the file to `POSIX_ONLY_TEST_FILES`. You cannot skip what will not import. **Precondition (fix-don't-dismiss):** first confirm the crash is a genuinely POSIX-only facility (in the test, or a legitimately-POSIX production module) — NOT an unguarded `os.getuid()`/`os.uname()`/POSIX syscall newly added to `src/alfred/` that should instead be made Windows-import-safe. Any rule-(a) addition of a `src/alfred/security/`- or `supervisor`-adjacent test goes through **security review** (see the review's sec-001).
- **The SAME already-listed files still error at collection** → this is a **collect-ignore mechanism failure** (the win32 glob did not match — a path-separator / resolution mismatch the Darwin pytester test cannot exercise), NOT a new rule-(a) file. Re-adding a listed file is a no-op; instead inspect the Windows collection-node paths vs the resolved ignore entries.
- **Runtime failure, import succeeds** → **rule (b)**: in-place `@pytest.mark.skipif(sys.platform == "win32", reason=…)` on the specific test or module (or make the test portable). Once import works, `skipif` is the correct, most-local tool.

- [ ] **Step 1: Read the current Windows failures**

```bash
RUN=$(gh run list --branch 246-windows-unit-blocking --workflow ci.yml --limit 1 --json databaseId -q '.[0].databaseId')
STATUS=$(gh run view "$RUN" --json jobs -q '.jobs[] | select(.name|test("windows-latest")) | .status')
[ "$STATUS" = "completed" ] || { echo "windows job still $STATUS — wait"; exit 0; }
WINJOB=$(gh run view "$RUN" --json jobs -q '.jobs[] | select(.name|test("windows-latest")) | .databaseId')
gh run view --job "$WINJOB" --log | grep -iE "FAILED|ERROR|error during collection|== .* ==" | tail -40
```

If the summary is all-passed (e.g. `N passed, M skipped`), go to Step 6 (the assert-RAN floor) then Task 5. Otherwise, classify each failure with the decision rule and apply the matching template below. (Gate on `status == completed` and do not `2>/dev/null` the log read — empty output from a premature read is not the same as a clean run.)

- [ ] **Step 2 (rule a): a new import-time crash → extend the ignore list**

Add the offending tests/-relative path to `POSIX_ONLY_TEST_FILES` in `tests/_posix_only_tests.py`, with a one-line rationale comment naming the POSIX facility (after satisfying the rule-(a) precondition above). Then update the meta test's **content-pinning canary** — add the new basename to the expected set in `test_win32_ignores_the_known_posix_only_modules`. Verify locally:

Run: `uv run pytest tests/unit/meta/test_posix_only_collect_ignore.py -q`
Expected: PASS (the anti-orphan check confirms the new path exists; the content-pinning canary confirms the new set is exactly the reviewed list).

- [ ] **Step 3 (rule b): a runtime failure → in-place skipif**

In the failing test module, ensure `import sys` is present, then guard the specific failing test (or the module) with the win32 skip. Per-test example:

```python
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: <name the syscall/behaviour, e.g. signal.SIGKILL / pass_fds / /bin/sh>.",
)
def test_the_failing_one() -> None:
    ...
```

Module-wide example (when every test in the file is POSIX-runtime but the module still *imports* fine on Windows — so it is a rule-b file, not a rule-a file):

```python
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: <one-line reason>.",
)
```

Prefer making a test portable (e.g. `Path`/`os.path.join` instead of hard-coded `/`, `tmp_path` instead of `/tmp`) when the logic is genuinely cross-platform; use `skipif` only when the behaviour is inherently POSIX.

- [ ] **Step 4: Local gate + commit the iteration**

Run: `uv run ruff check <changed files> && uv run ruff format --check <changed files> && uv run pytest tests/unit -q 2>&1 | tail -5`
Expected: clean + Darwin suite still green (skipif is a no-op on Darwin; a rule-a addition is a no-op on Darwin). Commit with a `#246`-after-colon subject and the standard trailer, e.g.:

```bash
git add <changed files>
git commit -m "test(ci): #246 guard <file> for win32 (<rule a: import / rule b: runtime>)

$(printf '<one-line what+why>\n\nMrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

(The trailer is mandatory on every commit including these loop iterations — Global Constraints.)

- [ ] **Step 5: Push and re-read Windows CI; repeat until green**

```bash
git push
```

Re-run Step 1. Loop Steps 1-5 until the Windows Unit-tests step log shows an all-passed summary (`N passed[, M skipped]`, no FAILED/ERROR), then apply the Step 6 floor. **Contingency (spec §8):** if the runtime surface proves unexpectedly deep and green (or the Step 6 floor) is not reachable in reasonable iterations, do **not** ship a red or hollow blocking leg — stop, leave Windows informational, and split promotion (Task 5) into a follow-up; escalate to the user. **If the contingency fires, also reword the PR title/body to describe only the collection guard, and do NOT post the Task 6 Step 4 "#246 Part 1 complete" comment (Part 1 stays open).** Per the ratified scope, the target is green + blocking in this PR.

- [ ] **Step 6: Assert-RAN floor (hollow-gate guard) before promoting**

Confirm the Windows leg is not merely FAILED/ERROR-free but actually RAN a substantial suite — otherwise accumulated ignore-list entries + `skipif`s could hollow the gate (the repo's #245 "green while gating nothing" shape). From the summary line captured in Step 1:

```bash
# PASSED must be well above the floor (today the suite is ~5900; the floor is far
# below and only trips on a runaway ignore list — the suite only grows).
# e.g. summary "5873 passed, 128 skipped in 240s" → PASSED=5873, SKIPPED=128.
```

Expected: `PASSED >= 3000` and `SKIPPED` a small fraction of `PASSED`. If the floor is not met, treat it as the contingency (Step 5) — do not promote a hollow gate.

---

### Task 5: Promote the Windows unit leg to blocking

Only once the Windows Unit-tests step is green (Task 4 exit). Deterministic edits.

**Files:**

- Modify: `.github/workflows/ci.yml` (the `python-cross-os` job — the collapsed `Unit tests (no coverage gate)` step ~858-874 and its stale comments ~763-772, ~785-790, ~851-870)
- Modify: `docs/ci/required-checks.md` (windows required-check row ~53; reality table ~97; windows prose bullet ~114; surrounding prose ~101-108; Deferred item 2 ~121)

- [ ] **Step 1: Drop the `continue-on-error` line in ci.yml**

Delete this single line from the `Unit tests (no coverage gate)` step (the step now blocks on both matrix legs):

```yaml
        continue-on-error: ${{ matrix.os == 'windows-latest' }}
```

- [ ] **Step 2: Update the now-stale ci.yml comments**

In the `python-cross-os` job, change the comments that describe the Windows unit leg as informational / "Phase B lands the guards" to past-tense/blocking. Specifically:

- The per-OS reality block (~763-772): the `windows-latest` bullet should say the unit suite now runs **blocking**; the 3 POSIX-only modules are collect-ignored on win32 (`tests/_posix_only_tests.py`), other POSIX-only tests carry `skipif(win32)`.
- The job-level note (~785-790) and the step comment (~851-870): drop the "INFORMATIONAL on windows-latest … #246 Phase B removes that" phrasing; state both legs' unit step is blocking (macOS proven green; Windows guarded via collect-ignore + win32 skips, #246 Phase B).

- [ ] **Step 3: Update docs/ci/required-checks.md**

- Windows required-check row (~53): replace "Runs the unit suite INFORMATIONALLY (step-level `continue-on-error`; #246 Phase A) — Docker files auto-skip, POSIX-only tests still error; win32 skip-guards promote it to blocking in #246 Phase B." with a blocking description: the unit suite runs **blocking** (#246 Phase B); the 3 POSIX-only modules are collect-ignored on win32 and remaining POSIX-only tests carry `skipif(win32)`.
- Reality table (~97): the `Unit suite` × `windows-latest` cell `informational (`continue-on-error`; #246)` → `✓ blocking (Docker + POSIX-only tests skip; #246)`.
- Windows prose bullet (~114) and surrounding prose (~101-108): reword "informational until #246 Phase B" to blocking.
- **#321 Phase 3 rollup bullet (~64):** that line reads "`Python cross-OS (windows-latest)` — continue-on-error removed …; the leg now blocks" but refers to the job-level STATIC-layer removal. Qualify it (or add a one-clause note) so a reader does not read "the leg now blocks" as having always covered the unit step too — the unit step became blocking in #246 Phase B.
- **Rollback lever** — add to the Windows required-check row (~53): on a Windows-unit flake, restore `continue-on-error: ${{ matrix.os == 'windows-latest' }}` on the unit step (a one-line code revert). Do **NOT** de-require the whole `Python cross-OS (windows-latest)` check — that would also drop enforcement of the already-required static lint/format/type layer on the same job. This is a code-revert rollback, not a `gh api .../contexts` branch-protection rollback (unlike the other flake-prone required checks).
- Deferred item 2 (~121): mark **DONE (#246 Phase B)** mirroring item 1's "DONE (#246 Phase A)" style, one line summarising the mechanism (collect-ignore for import-time crashes + `skipif(win32)` for runtime).

Branch-protection contexts are **unchanged**: `Python cross-OS (windows-latest)` is already a required check, so dropping the step-level `continue-on-error` only tightens that already-required job's internal step — no new context is emitted and **no `gh api .../contexts` call is needed** (only the required-checks.md rationale text is updated).

- [ ] **Step 4: Validate the workflow + docs locally**

Run: `uv run python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')" && npx --yes markdownlint-cli2@0.22.1 "docs/ci/required-checks.md"`
Expected: `yaml ok` + `0 error(s)`. Also grep-assert the flip landed — **use `grep -F` (fixed string), NOT plain `grep`**: the `$` in `${{` is a regex end-anchor, so a plain `grep -c` returns `0` whether or not the line was deleted (a vacuous, false-confidence check — verified against the live tree):

Run: `grep -cF "continue-on-error: \${{ matrix.os == 'windows-latest' }}" .github/workflows/ci.yml`
Expected: `0` AFTER deletion (confirm it returns `1` BEFORE deleting, so you know the assert is live). The expression is unique to the one step, so a `1→0` transition proves the flip.

- [ ] **Step 5: Commit and push**

```bash
git add .github/workflows/ci.yml docs/ci/required-checks.md
git commit -m "ci: #246 promote Windows unit leg to blocking (drop continue-on-error)

$(printf 'Windows unit step is green (collect-ignore + win32 skips); remove the\nstep-level continue-on-error so the leg blocks merge like macOS. Docs:\nrequired-checks row, reality table, prose, Deferred item 2 marked done.\n\nMrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
git push
```

- [ ] **Step 6: Confirm the Windows unit step now BLOCKS (real conclusion, not masked)**

Re-read the Windows job (with `continue-on-error` gone, the step `conclusion` is now the real outcome):

```bash
RUN=$(gh run list --branch 246-windows-unit-blocking --workflow ci.yml --limit 1 --json databaseId -q '.[0].databaseId')
gh run view "$RUN" --json jobs -q '.jobs[] | select(.name|test("windows-latest")) | {name, conclusion, steps: [.steps[] | select(.name|test("Unit tests")) | {name, conclusion}]}'
```

Expected: the `Unit tests (no coverage gate)` step `conclusion: "success"` (a real pass, no longer masked). The macOS leg must stay green (no Phase A regression).

---

### Task 6: Review, merge, and close out #246 Part 1

Standing CLAUDE.md cadence — not fabricated content; follow the repo process.

- [ ] **Step 1: Full `/review-pr` fleet + BOTH CodeRabbit (CLI `--base origin/main` + cloud)**

Run the full fleet (security ALWAYS; devops/test/docs lanes most relevant here). Parse CR CLI findings AND CR-cloud inline threads + review-body (they are disjoint; CR-cloud also reviews the committed spec/plan docs). Fold actionable findings.

- [ ] **Step 2: Resolve every review thread**

Verify each fix is in HEAD before resolving; with `required_conversation_resolution` on, fixed-but-unresolved threads still block merge. A reasoned decline = reply-with-rationale + resolve.

- [ ] **Step 3: Confirm all gates green, then non-admin merge**

Poll `reviewDecision` + `mergeStateStatus` until CLEAN + APPROVED (CR-cloud is the approving review). Then:

```bash
gh pr merge --rebase --delete-branch
```

Never `--admin`. If merge is blocked with everything green, check `required_conversation_resolution` + the approving-review requirement (separate state machines).

- [ ] **Step 4: Close out #246 Part 1 (keep the issue open for Part 2)**

Comment on #246 that Part 1 (Windows unit leg → blocking) is complete as of this PR, and Part 2 (macOS-native `sandbox-exec`) remains open, blocked on PR-S4-7. Do **not** close #246.

```bash
gh issue comment 246 --body "Part 1 (Windows unit leg → blocking) complete — PR merged. Part 2 (macOS-native sandbox-exec) remains open, blocked on PR-S4-7."
```

---

## Self-Review

**Spec coverage** (against `docs/superpowers/specs/2026-07-11-windows-unit-ci-phase-b-design.md`):

- §3/§4 centralized win32 `collect_ignore_glob` + testable helper → Tasks 1-2. ✓
- §4 resolved absolute paths (`.resolve().parent`), exact-not-glob note, no-shadow note, zero test-file edits, no production change → Task 1 helper + Task 2 Step 2 (resolved) + Steps 3-4 + Global Constraints. ✓
- §5 iteration decision rule (new-import-crash → list, with fix-don't-dismiss precondition; same-files-error → mechanism failure; runtime → skipif) → Task 4 decision rule (3 bullets) + templates. ✓
- §6 meta test (gating + content-pinning canary + anti-orphan + real-wiring + no-shadow) + pytester end-to-end + assert-RAN floor → Task 1 Step 1 (6 tests) + Task 4 Step 6. ✓
- §7 promotion (drop `continue-on-error` + ci.yml comments + required-checks.md rows + #321 bullet + rollback + branch-protection-unchanged + close Part 1) → Task 5 + Task 6 Step 4. ✓
- §8 contingency (deep runtime surface OR hollow floor → keep informational, split; reword PR + skip Part-1 comment) → Task 4 Step 5. ✓
- §9 acceptance criteria 1-6 → Tasks 1-2 (crit 1), Task 3-4 + Task 4 Step 6 floor (crit 2), Task 5 (crit 3-4), Task 6 (crit 5), Task 5 Step 6 (crit 6). ✓

**Placeholder scan:** the only non-verbatim content is Task 4's CI-discovered edits (deliberately templated rule a/b with complete code — the exact runtime failures are unknown until real Windows CI) and the Task 5 Step 2 ci.yml-comment reflow (described, since exact line positions shift as edits land; the required-checks.md prose is given verbatim). All local (Task 1-2, 5) steps carry exact code/paths/commands.

**Type consistency:** `POSIX_ONLY_TEST_FILES: Final[tuple[str, ...]]` and `collect_ignore_for(platform: str, tests_root: Path) -> list[str]` are used identically in the helper (Task 1 Step 3), the meta test (Task 1 Step 1), and the conftest wiring (Task 2 Step 2). The renamed canary `test_win32_ignores_the_known_posix_only_modules` (count-neutral) is referenced consistently in Task 4 Step 2. Both the conftest wiring and the meta test's real-wiring assertion derive `tests_root` as `Path(__file__).resolve().parent` / `Path(root_conftest.__file__).resolve().parent` (the `tests/` dir), and `_TESTS_ROOT = Path(__file__).resolve().parents[2]` — all resolved, all the same directory. Consistent.
