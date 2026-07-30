# check_tag_t3 Gate Integrity Implementation Plan (#537)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close five executed ways to defeat `scripts/check_tag_t3.py` entirely — bypasses that make the gate never see a file, or see it wrong — so that the rules added in #538 and #539 rest on a gate that cannot be walked around.

**Architecture:** Four changes to `scripts/check_tag_t3.py`, plus a scan-root widening and two toolchain gates. The load-bearing insight: three separate bypasses (symlinked package directory, vendored `.venv` noise, and the `.py`-enumeration question) collapse into one fix — derive the directory scan from `git ls-files` instead of `Path.rglob`. That is default-deny by construction: a file that is not tracked cannot land in a PR, and gitignored trees disappear for free. Measured: `git ls-files` yields exactly **293** `.py` files under `src/alfred` (identical to today's `rglob`, so zero regression) and **39** under `plugins/` (vs 895 by `rglob`, because `plugins/alfred_tui/.venv` is gitignored). The repo has **zero** tracked symlinks today.

**Tech Stack:** Python 3.14+, stdlib only (`ast`, `re`, `pathlib`, `subprocess`, `sys`). No new dependencies. pytest for tests. `mypy --strict` + `pyright` + `coverage` for the toolchain gates.

## Global Constraints

- **This PR touches no file under `src/alfred/`.** If it does, scope has slipped — the sole-layer rules are #538 and the seven shapes are #539. (Docstring path corrections in `src/alfred/security/tiers.py` belong to #538.)
- **No new violation rule lands here.** This step changes *what the gate sees* and *how it reports*, never *what counts as a violation shape*.
- The script stays **stdlib-only** — CI invokes it without `uv sync` (`pr-validate-python.yml:352`), and the "Check for Python source files" guard at `pr-validate-python.yml:319` exists precisely so no provisioning is needed.
- Python 3.14+, PEP 604 unions (`X | Y`), PEP 585 built-in generics. Never `Optional[X]` or `typing.List`.
- **Commit subjects must NOT read `fix: #536`.** The repo's conventional-commit gate mandates `#NNN` after the colon, and GitHub parses `fix: #NNN` as a closing reference — that is how #518 closed twice with its work undone. Use `fix: #537 …`; reference the epic as `Refs #536` in the body only.
- `make check` before every push. Check `$?` directly — `make … | tail` masks the exit code.
- Every operator-facing string in `src/alfred/` goes through `t()`. **This script is exempt**: `scripts/` is outside `[tool.babel] input_dirs` and the script imports no i18n. Do not add `t()` calls here.

---

## File Structure

| File | Responsibility | Change |
| --- | --- | --- |
| `scripts/check_tag_t3.py` | The detector. Gains a `_scan_text` seam, fail-closed error handling, resolved-path exemptions, git-derived collection, and an assert-RAN census. | Modify |
| `tests/unit/security/test_check_tag_t3_gate_integrity.py` | The new in-process suite for all five bypasses. Imports the script via `spec_from_file_location` against the **real** path. | Create |
| `tests/unit/security/test_tag_t3_capability_gate.py` | Existing subprocess suite. Two tests pin exemption behaviour this plan changes; both must keep passing unchanged. | Verify only |
| `Makefile` | `tag-t3-check` target — widen the scan root to `plugins/`. | Modify (`:231-236`) |
| `.github/workflows/pr-validate-python.yml` | `tag-t3-grep` job — widen the scan root to `plugins/`. | Modify (`:344-352`) |
| `.github/workflows/ci.yml` | Add the 100% coverage gate step. `scripts/run_coverage_gates.py` derives its gate list from this file, so `make check` picks it up automatically. | Modify |
| `pyproject.toml` | `exclude_lines` for the `__main__` guard; `[tool.pyright] include`; mypy target. | Modify |

**Why a new test file rather than extending `test_tag_t3_capability_gate.py`:** that file is 700+ lines of `subprocess.run` tests which record **zero** coverage (measured: `--cov` reports "No data was collected" against them). The new suite is in-process against `_scan_text`, which is what makes the 100% gate achievable. Mixing the two styles in one file would obscure which tests count toward the gate.

---

## Reference: the five bypasses, as measured

Each was executed against the real script. Keep this table beside you — every task closes a numbered row.

| # | Bypass | Evidence |
| --- | --- | --- |
| 1 | **PEP-263 non-UTF-8 source.** `_scan_file` reads `encoding="utf-8"` and swallows `UnicodeDecodeError` (`:312-316`). Python honours `# -*- coding: latin-1 -*-`. | detector `rc=0`; the module **imports and executes**, constructing `TaggedContent[T3]`. Defeats every rule in one header line. |
| 2 | **`tests/../src/alfred/...` traversal.** `_is_exempt` runs the `(^\|/)tests/` regex on the **raw string** (`:127-130`) *before* `path.resolve()` (`:139`). | direct path `rc=1`; via `tests/../` `rc=0`. A **directory** argument poisons everything under it. Works with **relative** paths — reachable from the production invocation. #428's `/lib64/../etc` class. |
| 3 | **Symlinked package directory.** `Path.rglob` does not recurse symlinked dirs. | scanner enumerated `['src/alfred/__init__.py']` instead of the tree; `rc=0`. |
| 4 | **In-repo `test_*.py` symlinked out of repo.** `_is_exempt` requires `not resolved.is_relative_to(_REPO_ROOT)` (`:151`), so `path.name` reads the link while `resolved` reads the target. | scanner *enumerates* the file, then exempts it. Control (`notatest.py` → same target) `rc=1`. |
| 5 | **Argument-less run from the wrong cwd.** `_collect_paths([])` is `Path("src/alfred").rglob(...)` relative to CWD (`:356`). | 0 files scanned, `rc=0`, no diagnostic. The #514 paper-gate shape. |

Two more silent-pass surfaces in the same family, closed by the same work: a nonexistent path argument → `rc=0`; a file carrying a real violation **plus** a `SyntaxError` → `rc=0` (swallowed at `:322`).

---

## Task 1: The `_scan_text` seam and the in-process harness

Everything else depends on this. A `tmp_path` **copy** of the script recomputes `_REPO_ROOT` from `__file__` and silently **inverts every exemption** (measured), so tests must import the real script and feed it text.

**Files:**
- Modify: `scripts/check_tag_t3.py:295-350` (split `_scan_file`)
- Create: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `_scan_text(text: str, path: Path) -> list[str]` — pure; runs the AST and line passes over `text`, attributing violations to `path`. Does **not** consult `_is_exempt` and does **not** read the filesystem.
  - `_scan_file(path: Path) -> list[str]` — unchanged public behaviour: exemption check, read, delegate to `_scan_text`.

- [ ] **Step 1: Write the failing test**

```python
"""In-process gate-integrity suite for ``scripts/check_tag_t3.py`` (#537).

Imports the REAL script via ``spec_from_file_location``. A ``tmp_path`` copy
would recompute ``_REPO_ROOT`` from ``__file__`` and invert every exemption,
so the module identity assertion below is load-bearing, not decorative.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_SCRIPT: Path = _REPO_ROOT / "scripts" / "check_tag_t3.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_tag_t3_under_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_tag_t3: ModuleType = _load_script()

# If this fires, every exemption assertion below is measuring a different tree.
assert check_tag_t3._REPO_ROOT == _REPO_ROOT, (
    f"loaded script computed _REPO_ROOT={check_tag_t3._REPO_ROOT!r}, "
    f"expected {_REPO_ROOT!r} — exemption tests would be inverted"
)


def test_scan_text_reports_a_violation_without_touching_the_filesystem() -> None:
    """``_scan_text`` is pure: it takes text + a path label, reads no file."""
    text = "from alfred.security.tiers import tag, T3\nx = tag(T3, 'payload')\n"
    nonexistent = _REPO_ROOT / "src" / "alfred" / "does_not_exist_on_disk.py"

    violations = check_tag_t3._scan_text(text, nonexistent)

    assert len(violations) == 2, violations
    assert violations[0] == f"{nonexistent}:2: {check_tag_t3._TAG_T3_MESSAGE}"
    assert violations[1] == "  x = tag(T3, 'payload')"


def test_scan_text_returns_empty_for_clean_text() -> None:
    """Negative floor. Paired with the positive above, so neither is vacuous."""
    text = "from alfred.security.tiers import tag, T2\nx = tag(T2, 'fine')\n"
    label = _REPO_ROOT / "src" / "alfred" / "clean.py"

    assert check_tag_t3._scan_text(text, label) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -q`
Expected: FAIL with `AttributeError: module 'check_tag_t3_under_test' has no attribute '_scan_text'`

- [ ] **Step 3: Write minimal implementation**

Replace the body of `_scan_file` (`scripts/check_tag_t3.py:295-350`) with a read-and-delegate, and move the scanning logic into `_scan_text`. The AST and line passes move verbatim; only the `text` acquisition leaves.

```python
def _scan_text(text: str, path: Path) -> list[str]:
    """Return violation messages for ``text``, attributed to ``path``.

    Pure: performs no filesystem access and applies no exemption. Split out of
    :func:`_scan_file` so tests can feed mutated real source under its REAL
    path — a ``tmp_path`` copy of this script would recompute ``_REPO_ROOT``
    and invert every exemption — and so the suite can run the scanner
    in-process, which is what makes the 100% coverage gate achievable
    (a subprocess records nothing without ``COVERAGE_PROCESS_START``).
    """
    violations: list[str] = []
    lines = text.splitlines()

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        tree = None

    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            lineno = node.lineno
            snippet = lines[lineno - 1].rstrip() if 0 <= lineno - 1 < len(lines) else ""
            if _is_tag_t3_call(node):
                violations.append(f"{path}:{lineno}: {_TAG_T3_MESSAGE}")
                violations.append(f"  {snippet}")
            if _is_cast_tagged_content_call(node):
                violations.append(f"{path}:{lineno}: {_CAST_TAGGED_CONTENT_MESSAGE}")
                violations.append(f"  {snippet}")
            if _is_tagged_content_t3_subscript_call(node):
                violations.append(f"{path}:{lineno}: {_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE}")
                violations.append(f"  {snippet}")

    for lineno, line in enumerate(lines, 1):
        if _TYPE_IGNORE_PATTERN.search(line):
            violations.append(f"{path}:{lineno}: {_TYPE_IGNORE_MESSAGE}")
            violations.append(f"  {line.rstrip()}")

    return violations


def _scan_file(path: Path) -> list[str]:
    """Return a list of violation messages for ``path``. Empty list = clean."""
    if _is_exempt(path):
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    return _scan_text(text, path)
```

> The `SyntaxError`/`OSError` swallowing is preserved **verbatim** here on purpose — Task 2 changes it under its own test, so this task's diff is a pure refactor with no behaviour change.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py tests/unit/security/test_tag_t3_capability_gate.py tests/unit/security/test_check_tag_t3_subscript.py -q`
Expected: PASS — the two new tests plus every pre-existing test, unchanged. A pure refactor must not move any existing test.

- [ ] **Step 5: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "refactor: #537 split a pure _scan_text seam out of _scan_file

The seam lets tests feed mutated real source under its REAL path. A tmp_path
copy of the script recomputes _REPO_ROOT from __file__ and silently inverts
every exemption, so a copy-based test measures the wrong tree.

It is also what makes an in-process test suite possible, and therefore the
100% coverage gate: subprocess runs record nothing without
COVERAGE_PROCESS_START, and the existing suite is entirely subprocess-based
(measured: 0% coverage, 120/120 statements missed).

Pure refactor — the SyntaxError/OSError swallowing is preserved verbatim and
changes under its own test in the next commit.

Refs #536

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: Unreadable and unparseable files become violations (bypass 1)

`_scan_file` returns clean on `SyntaxError`, `OSError` and `UnicodeDecodeError`. A `# -*- coding: latin-1 -*-` header makes the file unreadable as UTF-8 while Python imports and runs it perfectly — the gate is blind to a file that executes.

Measured false-positive cost across the scan root: **0 unparseable, 0 unreadable files.**

**Files:**
- Modify: `scripts/check_tag_t3.py` (`_scan_file`, plus three new message constants)
- Modify: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**
- Consumes: `_scan_text`, `_scan_file` from Task 1.
- Produces: `_UNPARSEABLE_MESSAGE`, `_UNREADABLE_MESSAGE`, `_UNDECODABLE_MESSAGE` — three **distinct** strings, so a test for one cannot be satisfied by another firing.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/security/test_check_tag_t3_gate_integrity.py`:

```python
def test_latin1_source_is_a_violation_not_a_silent_pass(tmp_path: Path) -> None:
    """Bypass 1: a PEP-263 non-UTF-8 file imports and runs, but read_text raises.

    Measured on the real script: rc=0 while ``python -c 'import ...'`` executed
    the module and constructed TaggedContent[T3]. Swallowing UnicodeDecodeError
    means one header line defeats every rule in the gate.
    """
    hidden = tmp_path / "launder.py"
    # 0xe9 is a valid latin-1 'e-acute' and an invalid UTF-8 start byte.
    hidden.write_bytes(
        b"# -*- coding: latin-1 -*-\n"
        b"# comment with a latin-1 byte: \xe9\n"
        b"from alfred.security.tiers import tag, T3\n"
        b"x = tag(T3, 'laundered')\n"
    )

    violations = check_tag_t3._scan_file(hidden)

    assert violations, "a file the gate cannot decode must not scan clean"
    assert check_tag_t3._UNDECODABLE_MESSAGE in violations[0]


def test_unparseable_source_is_a_violation(tmp_path: Path) -> None:
    """A file carrying a real violation AND a SyntaxError must not scan clean."""
    broken = tmp_path / "broken.py"
    broken.write_text(
        "from alfred.security.tiers import tag, T3\n"
        "x = tag(T3, 'payload')\n"
        "def (\n"  # unparseable
    )

    violations = check_tag_t3._scan_file(broken)

    assert violations, "an unparseable file must not scan clean"
    assert check_tag_t3._UNPARSEABLE_MESSAGE in violations[0]


def test_a_real_utf8_file_still_scans_normally(tmp_path: Path) -> None:
    """Positive twin: the same text as valid UTF-8 trips the ORDINARY rule.

    Without this, the two tests above would pass on a detector that flagged
    every file for every reason.
    """
    ok = tmp_path / "ordinary.py"
    ok.write_text(
        "# comment with a real unicode char: é\n"
        "from alfred.security.tiers import tag, T3\n"
        "x = tag(T3, 'payload')\n"
    )

    violations = check_tag_t3._scan_file(ok)

    assert any(check_tag_t3._TAG_T3_MESSAGE in v for v in violations)
    assert not any(check_tag_t3._UNDECODABLE_MESSAGE in v for v in violations)
    assert not any(check_tag_t3._UNPARSEABLE_MESSAGE in v for v in violations)


def test_the_real_scan_root_has_no_unreadable_or_unparseable_files() -> None:
    """Non-vacuity floor: this change must cost zero false positives.

    Measured at plan time: 0 unparseable, 0 unreadable across 293 files. The
    census assertion makes the floor non-vacuous — a floor that scanned nothing
    would otherwise pass.
    """
    paths = check_tag_t3._collect_paths(["src/alfred"])
    assert len(paths) >= 250, f"scanned implausibly few files: {len(paths)}"

    noisy = [
        v
        for p in paths
        for v in check_tag_t3._scan_file(p)
        if check_tag_t3._UNPARSEABLE_MESSAGE in v
        or check_tag_t3._UNREADABLE_MESSAGE in v
        or check_tag_t3._UNDECODABLE_MESSAGE in v
    ]
    assert noisy == [], noisy
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -q`
Expected: FAIL — `AttributeError: ... has no attribute '_UNDECODABLE_MESSAGE'`

- [ ] **Step 3: Write minimal implementation**

Add the constants beside the existing message constants (`scripts/check_tag_t3.py:67-74`):

```python
# Collection- and read-surface failures. These are VIOLATIONS, not silent
# passes: a file the gate cannot read is a file the gate is not gating, and
# Python's import machinery is far more permissive than this reader. A
# ``# -*- coding: latin-1 -*-`` header makes ``read_text(encoding="utf-8")``
# raise while the module imports and executes normally — measured: rc=0 on a
# file that constructed TaggedContent[T3]. Fail closed.
_UNDECODABLE_MESSAGE: str = (
    "file is not valid UTF-8 — the gate cannot read it but Python can execute "
    "it (PEP 263 coding declaration). Re-encode as UTF-8."
)
_UNPARSEABLE_MESSAGE: str = (
    "file does not parse — the gate cannot scan it. Fix the syntax error."
)
_UNREADABLE_MESSAGE: str = "file could not be read — the gate cannot scan it."
```

Replace `_scan_file`'s error handling:

```python
def _scan_file(path: Path) -> list[str]:
    """Return a list of violation messages for ``path``. Empty list = clean."""
    if _is_exempt(path):
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{path}:1: {_UNDECODABLE_MESSAGE}", "  <undecodable>"]
    except OSError as exc:
        return [f"{path}:1: {_UNREADABLE_MESSAGE}", f"  {exc.strerror or exc}"]
    return _scan_text(text, path)
```

And in `_scan_text`, turn the swallowed `SyntaxError` into a violation:

```python
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        return [f"{path}:{exc.lineno or 1}: {_UNPARSEABLE_MESSAGE}", f"  {exc.msg}"]
```

> Returning early on `SyntaxError` means the line-based suppression pass does not run on a file that does not parse. That is correct: a half-scanned view of a broken file is exactly the "silently accepting a syntactically broken file" the original docstring warned against — the difference is that we now report it instead of passing it.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/security/ -q`
Expected: PASS — including every pre-existing test in `test_tag_t3_capability_gate.py`.

- [ ] **Step 5: Verify the real tree is still clean end-to-end**

Run: `python3 scripts/check_tag_t3.py src/alfred; echo "rc=$?"`
Expected: `rc=0`. If this reds, a real file in the tree is unreadable or unparseable — investigate rather than loosening the rule.

- [ ] **Step 6: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "fix: #537 an unreadable or unparseable file is a violation, not a pass

A '# -*- coding: latin-1 -*-' header makes read_text(encoding='utf-8') raise
while Python imports and executes the module perfectly. Measured: the gate
returned rc=0 for a file that constructed TaggedContent[T3]. One header line
defeated every rule in the detector, current and proposed.

The same swallow hid a file carrying a real violation alongside a SyntaxError,
and made every 'must PASS' floor in the suite vacuously green on text that was
never parsed.

Three distinct messages so a test for one cannot be satisfied by another.
Measured false-positive cost across the scan root: 0 unparseable, 0 unreadable.

Refs #536

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: Exemptions resolve before they match (bypasses 2 and 4)

`_is_exempt` runs `(^|/)tests/` against the **raw** path string at `:127-130`, then resolves at `:139`. So `tests/../src/alfred/security/foo.py` is exempt while `src/alfred/security/foo.py` is not — the same file. A **directory** argument poisons everything beneath it, and it needs no absolute path, so it is reachable from the production invocation.

Separately, `path.name` (`:149`) reads the **link** while `resolved.is_relative_to` (`:151`) reads the **target**, so an in-repo `test_*.py` symlinked to an out-of-repo file is exempt.

**Files:**
- Modify: `scripts/check_tag_t3.py:105-155` (`_TEST_PATTERNS`, `_is_exempt`)
- Modify: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**
- Consumes: `_scan_file` from Task 2.
- Produces: `_is_exempt(path: Path) -> bool` — same signature, resolved-first semantics. `_TEST_PATTERNS` is **deleted** and replaced by component matching.

- [ ] **Step 1: Write the failing test**

```python
def test_dotdot_traversal_cannot_launder_a_src_file_into_exemption() -> None:
    """Bypass 2: the exemption regex ran on the RAW string, before resolve().

    ``tests/../src/alfred/...`` and ``src/alfred/...`` are the same file. One
    was exempt and one was not. Works with RELATIVE paths, so it is reachable
    from the production invocation (`Makefile` and CI both pass `src/alfred`).
    This is #428's `/lib64/../etc` traversal class on the exemption axis.
    """
    direct = Path("src/alfred/security/tiers.py")
    laundered = Path("tests/../src/alfred/security/tiers.py")

    assert direct.resolve() == laundered.resolve(), "precondition: same file"
    assert check_tag_t3._is_exempt(direct) == check_tag_t3._is_exempt(laundered)


def test_dotdot_traversal_on_a_non_exempt_file_stays_non_exempt() -> None:
    """The positive control for the test above.

    ``tiers.py`` is exempt by _APPROVED_PATHS, so equality alone could be
    satisfied by 'both exempt'. This asserts a file that must NOT be exempt
    stays non-exempt through the same traversal.
    """
    direct = Path("src/alfred/orchestrator/core.py")
    laundered = Path("tests/../src/alfred/orchestrator/core.py")

    assert check_tag_t3._is_exempt(direct) is False
    assert check_tag_t3._is_exempt(laundered) is False


def test_an_in_repo_symlink_named_test_py_is_not_exempt(tmp_path: Path) -> None:
    """Bypass 4: ``path.name`` read the LINK, ``resolved`` read the TARGET.

    The live direction is an IN-repo link pointing OUT of the repo, because
    _is_exempt requires ``not resolved.is_relative_to(_REPO_ROOT)``. Round 1
    recorded this backwards; getting the direction wrong makes the regression
    test pass vacuously.
    """
    target = tmp_path / "payload.py"
    target.write_text("from alfred.security.tiers import tag, T3\nx = tag(T3, 'p')\n")

    link_dir = _REPO_ROOT / "build" / "synthetic-537-symlink"
    link_dir.mkdir(parents=True, exist_ok=True)
    link = link_dir / "test_bypass.py"
    try:
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(target)

        assert check_tag_t3._is_exempt(link) is False, (
            "an in-repo file named test_*.py is exempt only under tests/; a "
            "symlink must not buy exemption by pointing out of the repo"
        )
        assert check_tag_t3._scan_file(link), "the link's content must be scanned"
    finally:
        if link.is_symlink() or link.exists():
            link.unlink()
        try:
            link_dir.rmdir()
            link_dir.parent.rmdir()
        except OSError:
            pass


def test_a_directory_literally_named_tests_is_still_exempt() -> None:
    """Negative floor: the legitimate exemption must survive the hardening."""
    assert check_tag_t3._is_exempt(Path("tests/unit/security/test_tag_t3_capability_gate.py"))


def test_a_path_segment_merely_containing_tests_is_not_exempt() -> None:
    """Component matching, not substring: 'contests/' must not be exempt.

    The old regex was ``(^|/)tests/`` which is already anchored, so this is a
    forward guard against a re-widening to a bare substring check.
    """
    assert check_tag_t3._is_exempt(Path("src/alfred/contests/foo.py")) is False
    assert check_tag_t3._is_exempt(Path("src/alfred/tests_helpers/foo.py")) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -q -k "traversal or symlink"`
Expected: FAIL — `test_dotdot_traversal_cannot_launder_a_src_file_into_exemption` asserts `True == False`, and the symlink test asserts `True is False`.

- [ ] **Step 3: Write minimal implementation**

Delete `_TEST_PATTERNS` (`scripts/check_tag_t3.py:105`) and rewrite `_is_exempt`:

```python
# Test trees are exempt: tests assert the patterns the gate forbids.
# Matched as a resolved PATH COMPONENT, never as a substring of the raw
# string. Two bugs lived in the old substring-on-raw-string form:
#   * `tests/../src/alfred/foo.py` was exempt while `src/alfred/foo.py` was
#     not — the same file. A directory argument poisoned everything under it,
#     and it needed no absolute path, so it was reachable from the production
#     invocation (#428's `/lib64/../etc` class on the exemption axis).
#   * a checkout under any ancestor directory named `tests` made the whole
#     gate vacuous for absolute-path invocations.
# Resolving first fixes both: the component check runs on the real location.
_TEST_DIR_NAME: str = "tests"


def _is_exempt(path: Path) -> bool:
    """Return True if ``path`` is allowed to contain the disallowed patterns.

    **Resolve first, then match.** Every exemption decision is made against the
    resolved absolute path, so `..` traversal and symlinks cannot present one
    identity to the matcher and another to the reader.

    Exempt set:
      * any path under this repo's ``tests/`` tree — matched by resolved path
        components relative to the repo root, not by substring,
      * any ``test_*.py`` whose **resolved** path is outside this repo — the
        ``tmp_path`` fixtures the unit suite plants. Keyed on ``resolved.name``,
        not ``path.name``: an in-repo symlink named ``test_bypass.py`` pointing
        at an out-of-repo file previously satisfied the basename check with the
        LINK and the location check with the TARGET.
      * the explicit authorised homes in ``_APPROVED_PATHS``, by resolved
        absolute-path equality.
    """
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError):
        # A path we cannot resolve is not one of the known-good homes.
        return False

    if resolved in _APPROVED_PATHS:
        return True

    if resolved.is_relative_to(_REPO_ROOT):
        # In-repo: exempt only by living under the repo's own tests/ tree.
        return _TEST_DIR_NAME in resolved.relative_to(_REPO_ROOT).parts

    # Out-of-repo: the tmp_path fixture exemption. Keyed on the RESOLVED name
    # so a symlink cannot borrow a test_* basename it does not own.
    return resolved.name.startswith("test_") and resolved.suffix == ".py"
```

> **Behaviour change to note in review:** an out-of-repo path under a directory named `tests/` is no longer exempt unless it is also named `test_*.py`. That is deliberate — the old rule exempted any out-of-repo path containing a `tests` segment, which is how a checkout under `/home/me/tests/AlfredOS` made the gate vacuous.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/security/ -q`
Expected: PASS. **`test_check_tag_t3_script_exempts_out_of_repo_tmp_path_test_file` and `test_check_tag_t3_script_rejects_in_repo_test_prefix_attack` (`test_tag_t3_capability_gate.py:613,664`) must pass unchanged** — they pin the two directions this rewrite preserves. If either needs editing, the rewrite has changed a behaviour it should not have.

- [ ] **Step 5: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "fix: #537 exemptions resolve before they match

_is_exempt ran the tests/ regex on the RAW path string and only resolved
afterwards, so 'tests/../src/alfred/foo.py' was exempt while
'src/alfred/foo.py' was not — the same file. A directory argument poisoned
every file beneath it, and it needs no absolute path, so it was reachable from
the production invocation. This is the /lib64/../etc traversal class from #428
recurring on the exemption axis.

Separately path.name read the LINK while resolved.is_relative_to read the
TARGET, so an in-repo test_*.py symlinked out of the repo was exempt. Keying
the basename check on resolved.name closes it. The live direction is in-repo
link -> out-of-repo target; the opposite direction was never exempt.

Matching is now on resolved path COMPONENTS relative to the repo root, never a
substring, so a checkout under an ancestor named 'tests' no longer makes the
gate vacuous.

Refs #536, #428

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Collection is derived from git, not filesystem traversal (bypass 3)

`Path.rglob` does not recurse symlinked directories, so a symlinked package under `src/alfred` hides its whole subtree — measured: the scanner enumerated one file instead of the tree, `rc=0`.

The fix that closes this **also** solves the `plugins/` widening problem and replaces an enumeration with a default-deny. Deriving the file list from `git ls-files` means: a file that is not tracked cannot land in a PR, so it is not part of the codebase this gate polices; and gitignored trees (the vendored `plugins/alfred_tui/.venv`) vanish without an exclusion list that someone has to remember to extend.

**Measured:**

| Scan root | `git ls-files` `.py` | `rglob` `.py` |
| --- | --- | --- |
| `src/alfred` | **293** | 293 (identical — zero regression) |
| `plugins` | **39** | 895 (856 under the gitignored `.venv`) |

Tracked symlinks in the repo today: **zero**.

**Files:**
- Modify: `scripts/check_tag_t3.py:353-364` (`_collect_paths`)
- Modify: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**
- Consumes: `_is_exempt` from Task 3.
- Produces: `_collect_paths(argv: list[str]) -> list[Path]` — same signature. Directory arguments **inside the repo** expand via `git ls-files`; directory arguments **outside** the repo expand via `rglob` (test fixtures); explicit file arguments are returned as-is, unconditionally.

- [ ] **Step 1: Write the failing test**

```python
def test_a_symlinked_package_directory_does_not_hide_its_subtree(tmp_path: Path) -> None:
    """Bypass 3: Path.rglob does not recurse symlinked directories.

    Measured on the real script: a symlinked package under src/alfred made the
    scanner enumerate ['src/alfred/__init__.py'] instead of the tree, rc=0.
    Deriving from git ls-files removes the traversal entirely — the target
    files are tracked under their own real paths, so they are listed.
    """
    real_pkg = tmp_path / "realpkg"
    real_pkg.mkdir()
    (real_pkg / "launder.py").write_text(
        "from alfred.security.tiers import tag, T3\nx = tag(T3, 'p')\n"
    )

    link = tmp_path / "linked"
    link.symlink_to(real_pkg, target_is_directory=True)

    collected = check_tag_t3._collect_paths([str(link)])

    assert any(p.name == "launder.py" for p in collected), (
        f"the symlinked directory hid its subtree: {collected}"
    )


def test_collect_paths_uses_git_for_an_in_repo_directory() -> None:
    """The scan root matches git's view, so gitignored trees are excluded."""
    collected = check_tag_t3._collect_paths(["src/alfred"])

    assert len(collected) == 293, (
        f"expected the 293 tracked .py files under src/alfred, got {len(collected)}"
    )
    assert all(p.suffix == ".py" for p in collected)


def test_collect_paths_excludes_the_vendored_venv_under_plugins() -> None:
    """plugins/ holds 39 first-party files and 856 under a gitignored .venv.

    An exclusion LIST would have to enumerate '.venv', 'site-packages', and
    whatever the next vendored tree is called. git ls-files is default-deny.
    """
    collected = check_tag_t3._collect_paths(["plugins"])

    assert len(collected) == 39, f"expected 39 tracked .py files, got {len(collected)}"
    assert not any(".venv" in p.parts for p in collected)


def test_an_explicit_file_argument_is_scanned_even_if_untracked(tmp_path: Path) -> None:
    """Positive control: file args bypass the git derivation entirely.

    The unit suite plants untracked fixtures and passes them by path; if the
    git derivation swallowed those, every subprocess test would go vacuous.
    """
    planted = tmp_path / "planted.py"
    planted.write_text("from alfred.security.tiers import tag, T3\nx = tag(T3, 'p')\n")

    assert check_tag_t3._collect_paths([str(planted)]) == [planted]
    assert check_tag_t3._scan_file(planted)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -q -k "symlinked_package or collect_paths or venv"`
Expected: FAIL — the symlink test finds no `launder.py`; the `plugins` test collects 895.

- [ ] **Step 3: Write minimal implementation**

```python
def _git_tracked_python_files(directory: Path) -> list[Path] | None:
    """Return the tracked ``.py`` files under ``directory``, or None if unavailable.

    ``git ls-files`` is DEFAULT-DENY where an exclusion list is enumerate-and-hope:
    a file that is not tracked cannot land in a PR, and gitignored trees (the
    vendored ``plugins/alfred_tui/.venv`` — 856 of that tree's 895 ``.py`` files)
    disappear without anyone maintaining a list of directory names to skip.

    It also removes the filesystem traversal that made a symlinked package
    directory hide its whole subtree: ``Path.rglob`` does not recurse symlinked
    dirs, so the scanner enumerated one file instead of the tree. Tracked files
    are listed under their own real paths regardless of what links point at them.

    Returns None when git cannot answer (not a checkout, git absent), so the
    caller can fall back rather than silently scanning nothing.
    """
    try:
        proc = subprocess.run(  # noqa: S603 — literal argv, no shell, no user input
            ["git", "ls-files", "-z", "--", str(directory)],
            capture_output=True,
            check=False,
            cwd=_REPO_ROOT,
        )
    except (OSError, ValueError):
        return None
    if proc.returncode != 0:
        return None
    names = proc.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    return [_REPO_ROOT / n for n in names if n.endswith(".py")]


def _collect_paths(argv: list[str]) -> list[Path]:
    """Expand the CLI arg list into a flat list of ``.py`` paths to scan.

    Explicit FILE arguments are returned unconditionally — the unit suite plants
    untracked fixtures in ``tmp_path`` and passes them by path, and swallowing
    those would make every one of those tests vacuous.
    """
    if not argv:
        argv = ["src/alfred"]
    paths: list[Path] = []
    for arg in argv:
        candidate = Path(arg)
        if not candidate.is_dir():
            paths.append(candidate)
            continue
        resolved = candidate.resolve(strict=False)
        if resolved.is_relative_to(_REPO_ROOT):
            tracked = _git_tracked_python_files(candidate)
            if tracked is not None:
                paths.extend(tracked)
                continue
        # Out-of-repo directory (test fixtures), or git unavailable. rglob with
        # symlink recursion ON, since the git default-deny is not in play here.
        paths.extend(candidate.rglob("*.py", recurse_symlinks=True))
    return paths
```

Add `import subprocess` to the import block.

> `recurse_symlinks=True` is the Python 3.13+ `rglob` parameter. It is safe on the fallback path because that path only runs for out-of-repo fixture directories — inside the repo, git is authoritative and no traversal happens at all.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/security/ -q`
Expected: PASS, all tests including the pre-existing suite.

- [ ] **Step 5: Verify against the real tree**

```bash
python3 scripts/check_tag_t3.py src/alfred; echo "src rc=$?"
python3 scripts/check_tag_t3.py plugins; echo "plugins rc=$?"
```
Expected: `src rc=0` and `plugins rc=0`. `plugins` was measured clean under today's rules at plan time; if it reds, read the violation — it is a real finding, not a reason to narrow the scan root.

- [ ] **Step 6: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "fix: #537 derive the scan set from git, not filesystem traversal

Path.rglob does not recurse symlinked directories, so a symlinked package
under src/alfred hid its whole subtree — measured: the scanner enumerated
['src/alfred/__init__.py'] instead of the tree and exited 0.

git ls-files removes the traversal entirely and is default-deny where an
exclusion list is enumerate-and-hope: an untracked file cannot land in a PR,
and gitignored trees vanish without a list of directory names someone has to
remember to extend. That matters immediately — plugins/ holds 895 .py files,
856 of them under a vendored .venv.

Measured: git ls-files yields exactly 293 .py under src/alfred, identical to
today's rglob, so the scan set does not regress; and 39 under plugins/.

Explicit file arguments still bypass the derivation, or the unit suite's
tmp_path fixtures would all go vacuous.

Refs #536

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: The script asserts it actually ran (bypass 5)

`_collect_paths([])` resolves `src/alfred` relative to CWD. Run from anywhere but the repo root it scans **0 files, exits 0, prints nothing** — a required check that is green while gating nothing. This is the #514 paper-gate shape, and #245 is the standing rule that a gate must assert it ran.

A test-side census is not sufficient: the failure mode is a *caller*, and the caller is what the census must be inside.

**Files:**
- Modify: `scripts/check_tag_t3.py` (`main`)
- Modify: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**
- Consumes: `_collect_paths` from Task 4.
- Produces: `main(argv: list[str]) -> int` — now returns `2` (distinct from `1` = violations found) when the scan set is implausibly small. `_MIN_SCANNED_FILES: int = 250`.

- [ ] **Step 1: Write the failing test**

```python
def test_main_fails_loudly_when_it_scans_nothing(tmp_path: Path, capsys) -> None:
    """Bypass 5: 0 files scanned, rc=0, no diagnostic — a green no-op.

    Exit code 2 is distinct from 1 (violations found) so a caller can tell
    'the gate failed' from 'the gate could not run'.
    """
    empty = tmp_path / "empty"
    empty.mkdir()

    rc = check_tag_t3.main([str(empty)])

    assert rc == 2, "scanning zero files must not report success"
    assert "scanned 0" in capsys.readouterr().err


def test_main_returns_zero_on_the_real_tree() -> None:
    """Positive twin: the census must not red the real invocation."""
    assert check_tag_t3.main(["src/alfred"]) == 0


def test_main_still_returns_one_for_a_real_violation(tmp_path: Path) -> None:
    """A single planted file is below the census floor but must still red as 1.

    The census applies to the DEFAULT scan root, not to explicit file args —
    otherwise every fixture-based test in the suite would start returning 2.
    """
    bad = tmp_path / "bad.py"
    bad.write_text("from alfred.security.tiers import tag, T3\nx = tag(T3, 'p')\n")

    assert check_tag_t3.main([str(bad)]) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -q -k "main_"`
Expected: FAIL — `assert 0 == 2` on the empty-directory case.

- [ ] **Step 3: Write minimal implementation**

Add beside the other module constants:

```python
# Assert-RAN floor (#245, #514). `_collect_paths([])` resolves `src/alfred`
# relative to CWD, so an argument-less run from the wrong directory scanned 0
# files, exited 0 and printed nothing — a required check reporting green while
# gating nothing. 293 tracked .py files live under src/alfred today; 250 leaves
# headroom for deletions without leaving room for the gate to go vacuous.
_MIN_SCANNED_FILES: int = 250
```

Rewrite `main`:

```python
def main(argv: list[str]) -> int:
    paths = sorted(_collect_paths(argv))

    # The census applies to DIRECTORY scans only. Explicit file arguments are
    # how the unit suite plants fixtures — holding those to a 250-file floor
    # would red every one of them.
    scanned_a_directory = not argv or any(Path(a).is_dir() for a in argv)
    if scanned_a_directory and len(paths) < _MIN_SCANNED_FILES:
        print(
            f"check_tag_t3: scanned {len(paths)} files, expected at least "
            f"{_MIN_SCANNED_FILES}. The gate is not reaching the source tree "
            f"(wrong working directory, or the scan root moved) — refusing to "
            f"report success while gating nothing.",
            file=sys.stderr,
        )
        return 2

    all_violations: list[str] = []
    for path in paths:
        all_violations.extend(_scan_file(path))

    if all_violations:
        print("check_tag_t3: violations found:", file=sys.stderr)
        for line in all_violations:
            print(line, file=sys.stderr)
        return 1
    return 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/security/ -q`
Expected: PASS.

- [ ] **Step 5: Verify the census fires from the wrong directory**

```bash
cd /tmp && python3 "$OLDPWD/scripts/check_tag_t3.py"; echo "rc=$?"; cd -
```
Expected: `rc=2` with the diagnostic on stderr. Before this task the same command printed nothing and returned 0.

- [ ] **Step 6: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "fix: #537 the gate refuses to report success while gating nothing

_collect_paths([]) resolves src/alfred relative to CWD, so an argument-less run
from any other directory scanned 0 files, exited 0 and printed nothing. Nothing
invokes it that way today, which is precisely why it would have gone unnoticed
— it is a green-reporting no-op waiting for a caller, the same shape as the
#514 paper gate.

A test-side census cannot catch this: the failure mode IS the caller, so the
census belongs inside main().

Exit 2 is distinct from 1 so a caller can tell 'the gate failed' from 'the gate
could not run'. The floor applies to directory scans only — holding explicit
file arguments to it would red every fixture-based test in the suite.

Refs #536, #245, #514

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: Widen the scan root to `plugins/`

25 first-party plugin files import `alfred`, including `plugins/alfred_discord/inbound_emitter.py` — a real ingestion boundary currently outside the gate. Task 4 already made this safe: `git ls-files` yields 39 tracked `.py` files, not the 895 `rglob` would walk.

**Files:**
- Modify: `Makefile:231-236`
- Modify: `.github/workflows/pr-validate-python.yml:344-352`

**Interfaces:**
- Consumes: `_collect_paths` from Task 4, `main` from Task 5.
- Produces: nothing new.

- [ ] **Step 1: Verify the widened root is clean before wiring it**

```bash
python3 scripts/check_tag_t3.py src/alfred plugins; echo "rc=$?"
```
Expected: `rc=0`. If it reds, stop and read the violation — a real first-party finding, not a reason to skip this task.

- [ ] **Step 2: Update the Makefile target**

Replace `Makefile:231-236`:

```makefile
tag-t3-check: ## Slice-3 spec §3.7-3.8: reject unauthorised tag(T3 + cast(TaggedContent[ uses.
	@if [ -d src/alfred ]; then \
		python3 scripts/check_tag_t3.py src/alfred plugins; \
	else \
		echo "::error::no src/alfred/ — the gate cannot run"; \
		exit 1; \
	fi
```

> The `else` branch flips from a `::notice::` + silent pass to a hard failure. `src/alfred` is permanent; "not there" now means the invocation is broken, not that there is nothing to check — the same fail-closed reasoning `pr-validate-python.yml:337` already applies in CI.

- [ ] **Step 3: Update the CI job**

Replace the `run:` at `.github/workflows/pr-validate-python.yml:352`:

```yaml
        run: python3 scripts/check_tag_t3.py src/alfred plugins
```

And extend the step's `name` at `:344`:

```yaml
      - name: Run check_tag_t3.py against src/alfred and plugins
```

- [ ] **Step 4: Verify both invocations**

```bash
make tag-t3-check; echo "make rc=$?"
python3 -c "import yaml,pathlib; yaml.safe_load(pathlib.Path('.github/workflows/pr-validate-python.yml').read_text())" && echo "workflow parses"
```
Expected: `make rc=0` and `workflow parses`.

- [ ] **Step 5: Commit**

```bash
git add Makefile .github/workflows/pr-validate-python.yml
git commit -m "fix: #537 gate first-party plugins/, not just src/alfred

25 first-party plugin files import alfred, including
plugins/alfred_discord/inbound_emitter.py — a real ingestion boundary that has
been outside the gate. The tree is clean today, so this costs zero exemptions.

Safe only because collection now derives from git ls-files: rglob would walk
895 .py files under plugins/, 856 of them in a vendored .venv.

The Makefile's missing-src branch also flips from a notice-and-pass to a hard
failure, matching the fail-closed guard CI already applies: src/alfred is
permanent, so 'not there' means the invocation is broken.

Refs #536

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 7: Toolchain gates — coverage, mypy, pyright

`scripts/check_tag_t3.py` is under **no** coverage gate and **no** type-checker. Measured today: **0%** coverage (120/120 statements, 66 branches missed) because the entire existing suite is `subprocess.run`, which records nothing without `COVERAGE_PROCESS_START`. `mypy --strict` and `pyright` both scope to `src` (`Makefile:83`, `[tool.pyright] include = ["src"]`) and both pass on the script today.

**Verified mechanics** (these were measured, not assumed):
- `--cov=scripts/check_tag_t3.py` **does not work** — coverage treats it as a module name and warns `Module scripts/check_tag_t3.py was never imported`, collecting nothing.
- `--cov=scripts` (directory form) **does** work — it traced the script to 69% from just the 4 in-process adversarial tests.
- `scripts/run_coverage_gates.py` derives its gate list from `.github/workflows/ci.yml` by regex (`coverage report … --include='…' --fail-under=N`) and runs `coverage report` against whatever `.coverage` already exists. So adding the step to `ci.yml` wires it into `make check` automatically — no second source of truth.
- There is **no** `exclude_lines` config in `pyproject.toml`, so `if __name__ == "__main__":` is unreachable in-process and `--fail-under=100` reds without one.

**Files:**
- Modify: `pyproject.toml` (`[tool.coverage.report] exclude_lines`, `[tool.pyright] include`)
- Modify: `.github/workflows/ci.yml` (the gate step)
- Modify: `Makefile:81-83` (typecheck target)

**Interfaces:**
- Consumes: the in-process suite from Tasks 1-5.
- Produces: nothing new in the script.

- [ ] **Step 1: Measure the current in-process coverage**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -q \
  --cov=scripts --cov-report=term-missing --cov-fail-under=0 2>&1 | grep check_tag_t3
```
Record the percentage and the missing-line list. Every uncovered line must gain a test in Step 2 — do not lower the threshold to fit the tests.

- [ ] **Step 2: Add tests for the uncovered lines**

Write one test per uncovered branch reported in Step 1, in `test_check_tag_t3_gate_integrity.py`. The branches this plan's changes introduce and which are easy to miss:

```python
def test_is_exempt_returns_false_for_an_unresolvable_path() -> None:
    """The OSError/RuntimeError arm of _is_exempt's resolve()."""
    # A path with a NUL byte cannot be resolved on any supported platform.
    assert check_tag_t3._is_exempt(Path("bad\x00path.py")) is False


def test_git_derivation_falls_back_when_git_is_unavailable(monkeypatch, tmp_path: Path) -> None:
    """The `tracked is None` arm — git absent or not a checkout."""
    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError("git not found")

    monkeypatch.setattr(check_tag_t3.subprocess, "run", _boom)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "mod.py").write_text("x = 1\n")

    # tmp_path is out-of-repo so it takes the rglob arm regardless; this asserts
    # the in-repo arm degrades to rglob rather than raising.
    assert check_tag_t3._git_tracked_python_files(Path("src/alfred")) is None


def test_unreadable_file_is_a_violation(tmp_path: Path) -> None:
    """The OSError arm of _scan_file — a directory read as a file."""
    a_directory = tmp_path / "not_a_file.py"
    a_directory.mkdir()

    violations = check_tag_t3._scan_file(a_directory)

    assert violations
    assert check_tag_t3._UNREADABLE_MESSAGE in violations[0]
```

- [ ] **Step 3: Add the `exclude_lines` config**

In `pyproject.toml` under `[tool.coverage.report]`:

```toml
exclude_lines = [
    # The CLI entry point cannot execute under an in-process test run. Excluded
    # rather than pragma'd so the exclusion is auditable in one place; there is
    # no other unreachable-by-construction code in the gated set.
    'if __name__ == .__main__.:',
]
```

- [ ] **Step 4: Verify 100% is reached**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -q \
  --cov=scripts --cov-report=term-missing --cov-fail-under=0 2>&1 | grep check_tag_t3
uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100; echo "gate rc=$?"
```
Expected: `100%` and `gate rc=0`. If short, return to Step 2 — **do not** lower the threshold.

- [ ] **Step 5: Wire the gate into `ci.yml`**

Add a step to the `python` job, immediately after the existing security-glob gate (`ci.yml:161`). It needs the script in the coverage data, so the pytest invocation in that job's step gains `--cov=scripts`:

```yaml
      - name: check_tag_t3 detector 100% line+branch coverage
        # #537: the gate that enforces CLAUDE.md security rule #3 was itself
        # under NO coverage gate and NO type-checker — measured 0%, because the
        # whole suite was subprocess-based and subprocess records nothing
        # without COVERAGE_PROCESS_START. The in-process _scan_text seam is what
        # makes this gate possible. `--include` is a single file, so the six
        # other scripts in the data do not affect this threshold.
        if: steps.check.outputs.has_py == 'true'
        run: |
          uv run coverage report \
            --include='scripts/check_tag_t3.py' \
            --fail-under=100
```

> **Note for the implementer:** the `--cov-fail-under=75` whole-tree floor in the same job is computed over *all* collected data, so adding `--cov=scripts` pulls in six other scripts at 0%. Step 6 measures whether that stays above the floor; if it does not, scope the pytest `--cov` to keep the floor honest rather than lowering it.

- [ ] **Step 6: Confirm the whole-tree floor survives**

```bash
uv run pytest tests/unit -q --cov=src/alfred --cov=scripts --cov-report=term --cov-fail-under=0 2>&1 | tail -3
```

**Measured at plan time: `TOTAL 18341 stmts, 94%`** across 6974 passing tests — against a `fail_under = 75` floor. The six ungated scripts contribute 593 uncovered statements; even attributing all of them to the total lands ~91%. There is no dilution problem and **no `omit` entries are needed**.

Expected: TOTAL above 75%. If a future change ever brings it close, do **not** lower `fail_under` — add `omit` entries in `[tool.coverage.run]` for the six scripts that are not gated (`check_strict_declarations.py`, `docs_check.py`, `gen_alfred_seccomp.py`, `quarantine_spawn_probe.py`, `run_coverage_gates.py`, `validate_devin_wiki.py`) and note that a NEW script then joins the floor at 0% until it is either gated or omitted.

- [ ] **Step 7: Add the script to both type-checkers**

`Makefile:83`:

```makefile
		uv run mypy --strict src scripts/check_tag_t3.py && uv run pyright src scripts/check_tag_t3.py; \
```

`pyproject.toml`:

```toml
[tool.pyright]
include = ["src", "scripts/check_tag_t3.py"]
```

- [ ] **Step 8: Verify both type-checkers pass**

```bash
uv run mypy --strict src scripts/check_tag_t3.py
uv run pyright src scripts/check_tag_t3.py
```
Expected: `Success: no issues found` and `0 errors, 0 warnings`.

- [ ] **Step 9: Verify the gate runner picks it up**

```bash
uv run python scripts/run_coverage_gates.py --job python --min-gates 1 2>&1 | grep -i check_tag_t3
```
Expected: the new gate appears in the runner's list. If it does not, the `run:` block's shape does not match `_GATE_RE` — fix the YAML, not the runner.

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml .github/workflows/ci.yml Makefile tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "fix: #537 put the detector under a coverage gate and both type-checkers

The script that enforces CLAUDE.md security rule #3 was itself under no
coverage gate and no type-checker. Measured: 0% — 120/120 statements and 66
branches missed — because the entire existing suite is subprocess-based and
subprocess records nothing without COVERAGE_PROCESS_START.

--cov=scripts/check_tag_t3.py does not work (coverage reads it as a module name
and collects nothing); the directory form does. The gate itself uses a
single-file --include, so the other scripts in the data do not affect it.

run_coverage_gates.py derives its list from ci.yml, so this lands in make check
automatically rather than as a second source of truth that drifts.

Both type-checkers were already green on this file; only the scoping was
missing.

Refs #536, #474

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 8: Full verification

**Files:** none modified — this task proves the branch.

- [ ] **Step 1: Confirm the #536 tripwire still passes**

```bash
uv run pytest tests/adversarial/tier_laundering/test_tier_laundering_copy_seams.py -q
```
Expected: PASS, all 4 tests.

`test_tl_2026_013_is_currently_undefended_at_the_authoring_layer_too` asserts the detector scans the `tl-2026-013` residual spellings **clean**. This step adds no rule that catches them, so it *should* still pass — but it changes exemption handling, error handling and collection, so **confirm rather than assume**. If it now fails, something in this PR became a rule, which is out of scope: find it and move it to #538.

- [ ] **Step 2: Confirm the whole security suite**

```bash
uv run pytest tests/unit/security tests/adversarial -q
```
Expected: PASS. The adversarial suite is release-blocking and several of its tests invoke this script by subprocess.

- [ ] **Step 3: Run the full quality bar**

```bash
make check; echo "make check rc=$?"
```
Expected: `rc=0`. Check `$?` directly — piping through `tail` masks it.

- [ ] **Step 4: Mutation sweep — prove each fix is load-bearing**

For each of the five bypasses, revert the fix in the working tree, confirm the matching test **reds**, then restore. A fix whose test still passes when reverted is decorative.

| Revert | Must red |
| --- | --- |
| `_UNDECODABLE_MESSAGE` arm → `return []` | `test_latin1_source_is_a_violation_not_a_silent_pass` |
| `_is_exempt` → match before resolve | `test_dotdot_traversal_cannot_launder_a_src_file_into_exemption` |
| `resolved.name` → `path.name` | `test_an_in_repo_symlink_named_test_py_is_not_exempt` |
| `_git_tracked_python_files` → always `None` | `test_collect_paths_excludes_the_vendored_venv_under_plugins` |
| `_MIN_SCANNED_FILES` → `0` | `test_main_fails_loudly_when_it_scans_nothing` |

Then mutate in the **widening** direction: set `_MIN_SCANNED_FILES = 100000` and confirm `test_main_returns_zero_on_the_real_tree` reds. A floor that only ever fires one way is half a gate.

- [ ] **Step 5: Push and open the PR**

```bash
git push -u origin 537-check-tag-t3-gate-integrity
gh pr create --title "fix: #537 close five ways to defeat the check_tag_t3 gate entirely" --body-file <(cat <<'EOF'
Closes #537. Step 1 of 3 under #536.

Five executed bypasses that make the gate never see a file, or see it wrong.
Every rule in #538 and #539 rests on this landing first.

See the plan: `docs/superpowers/plans/2026-07-30-537-check-tag-t3-gate-integrity.md`

Refs #536, #428, #514, #245
EOF
)
```

---

## Self-Review

**Spec coverage.** Every numbered item in #537's scope maps to a task: resolve-before-match → Task 3; symlinked dirs → Task 4; `SyntaxError`/`OSError`/`UnicodeDecodeError` → Task 2; assert-RAN census → Task 5; `_scan_text` seam → Task 1; `plugins/` widening → Tasks 4+6; coverage gate → Task 7; mypy/pyright → Task 7. The definition-of-done items (regression test per bypass, `spec_from_file_location` against the real path, `_plant`-style compile check, mutation sweep, tripwire verification) map to Tasks 1-5 and Task 8.

**Deviation from the issue, flagged for review.** #537 lists the `.venv` exclusion and the symlinked-directory fix as separate items and describes the `plugins/` widening as needing "a site-packages exclusion". This plan replaces all three with the `git ls-files` derivation, because an exclusion list is an enumeration of the trees someone thought of, and this repo's `domain_enumerate_vs_default_deny` lesson says that closes what you thought of rather than the class. Measured to be a strict improvement: identical 293-file scan set for `src/alfred`, 39 instead of 895 for `plugins/`. The fallback arm keeps out-of-repo fixture directories working.

**Placeholder scan.** No "TBD", no "add appropriate error handling", no "similar to Task N". Every code step carries the actual code; every verification step carries the actual command and its expected output. Task 7 Step 6 is a genuine measurement with a stated decision rule for either outcome, not a deferred decision.

**Type consistency.** `_scan_text(text: str, path: Path) -> list[str]` is defined in Task 1 and consumed by Tasks 2 and 7 under that exact signature. `_is_exempt(path: Path) -> bool` keeps its signature through Task 3. `_collect_paths(argv: list[str]) -> list[Path]` keeps its signature through Task 4 and is consumed by Task 5. `_git_tracked_python_files(directory: Path) -> list[Path] | None` is defined and consumed in Task 4 and tested in Task 7. Message constants `_UNDECODABLE_MESSAGE` / `_UNPARSEABLE_MESSAGE` / `_UNREADABLE_MESSAGE` are defined in Task 2 and referenced in Tasks 2 and 7. `main(argv: list[str]) -> int` gains return code `2` in Task 5 and nothing later assumes it returns only 0 or 1.

**Known gap the reviewer should press on.** Task 5's census uses `any(Path(a).is_dir() for a in argv)`, so a mixed invocation (one directory plus one file) is held to the directory floor. No caller does this today — the Makefile and CI both pass directories only, and the test suite passes files only — but the rule is worth challenging.
