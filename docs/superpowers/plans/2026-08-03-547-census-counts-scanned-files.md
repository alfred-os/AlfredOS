# #547 — Census Counts SCANNED Files Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Revision 2 — 2026-08-03, after the `/review-plan` fleet.** Five reviewers plus the
> coordinator returned 48 findings (4 Critical, 15 High after reconciliation, 0 retractions).
> Revision 1's design was sound and its **test specification was not**: three of its tests
> could not distinguish fixed from broken, and its sentinel polarity was measured fail-open.
> Findings that changed the shape of the work are marked inline with their id.

**Goal:** Make `scripts/check_tag_t3.py`'s aggregate census assert the number of files the
gate actually read and parsed, not the number traversal collected, so the gate cannot report
success — or report "violations found" — while having gated nothing.

**Architecture:** A `_ScannedOk(list[str])` subclass marks the ONE path meaning "this file was
completely read, parsed and gated". Every other return — every arm today and every arm added
later — is a failure by construction. `main` classifies with `isinstance`, skips exempt files
on both sides of the ratio, prints everything it collected, then asserts
`scanned_ok >= _MIN_SCANNED_FILES`.

**Tech Stack:** Python 3.14+, pytest, `coverage.py` (branch mode), `mypy --strict`,
`pyright`, `ruff`.

**Design doc:** [`docs/superpowers/specs/2026-08-03-547-census-counts-scanned-files-design.md`](../specs/2026-08-03-547-census-counts-scanned-files-design.md)

## Global Constraints

- `scripts/check_tag_t3.py` is under a **REQUIRED 100% line + branch** coverage gate.
  **No pragmas.** Do not touch `exclude_also` in `pyproject.toml`.
- Never launder a dead branch into a ternary — `coverage.py` does not branch on a
  conditional expression (#538). If an arc proves unreachable, use `assert` on the precedent
  at `scripts/check_tag_t3.py:902` and `:2291`, and **measure** unreachability first.
- `mypy --strict` runs with `warn_unreachable = true`; `scripts/check_tag_t3.py` is
  explicitly type-checked by both mypy and pyright (`Makefile:88`).
- Coverage: a bare `coverage run` measures **nothing**, because
  `[tool.coverage.run] source = ["src/alfred"]`. Run
  `uv run pytest tests/unit --cov=src/alfred --cov=scripts` first, then
  `uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100`.
- **Never assert on `expected at least`** in a census test — that substring matches BOTH
  censuses, so it cannot tell you which one fired (`test-003`).
- Commit subjects: Conventional Commits with a literal `#547` **after** the colon. Do not use
  the `fix:` type in any commit — `fix: #547 …` auto-closes the issue on merge, and the
  closing reference belongs on the PR (Task 4).
- No `--no-verify`. No `git add -A` — add named paths only.
- Ergonomic cost stays at zero: no existing test may be edited to keep it passing. Measured
  under the built variant at 1335/1335 passing with 324 existing gate tests unedited.

## Subsystem coverage matrix

| Subsystem | Touched | Owner agent |
| --- | --- | --- |
| `src/alfred/security/` (trust boundary) | **No** — authoring-layer gate only, no runtime code | `alfred-security-engineer` (review) |
| `scripts/` (release-blocking gate) | **Yes** — `check_tag_t3.py` | `alfred-test-engineer` |
| `tests/unit/security/` | **Yes** — gate integrity tests | `alfred-test-engineer` |
| `docs/adr/` | **Yes** — ADR-0060 | `alfred-docs-author` |
| CI workflows / Makefile | **No** — `tag(T3) grep gate` verified REQUIRED (branch protection + `docs/ci/required-checks.md:52`), no job-level `if:`, nothing repo-wide distinguishes exit 1 from exit 2 | `alfred-devops-engineer` (verified) |
| Memory / personas / providers / comms / core | **No** | — |

**Plan-level owner agent:** `alfred-test-engineer`, with `alfred-security-engineer` as
mandatory reviewer because the artifact is a release-blocking security gate.

## Definition of Done

1. `scanned_ok` is the census quantity; exempt files count on neither side.
2. Probe A (non-exempt unparseable tree above the floor) exits **2**, not 1.
3. Probe C (all-exempt tree above the floor) exits **2**, not 0, with a message saying
   *exempt* rather than *could not read*.
4. Production unchanged: `scanned_ok == 331` exactly, pinned by floor bisection, verified
   with **bare `python3`** (both call sites and CI use `python3`, not `uv run` — `ops-002`).
5. A single genuine syntax error in-tree still exits **1**, not 2.
6. A file that trips a real rule on a line whose source quotes a collection-failure message
   counts as **scanned**, proved with ZERO slack.
7. A sixth `except` arm reusing an existing `_*_MESSAGE` scores `scanned_ok == 0` — the
   fail-closed proof.
8. The census prints every collected violation before refusing.
9. `scripts/check_tag_t3.py` at **100% line + branch**, no pragmas.
10. `make check` green; `mypy --strict` + `pyright` clean; `ruff` clean; markdownlint clean.
11. No existing test edited to keep it passing.

---

### Task 1: `_ScannedOk` and the derived outcome guard

Marks the success path so unknown failure arms fail CLOSED. Revision 1 marked the five
FAILURE sites; two reviewers built both variants and measured that one fail-OPEN on a sixth
arm reusing an existing message (`sec-004`) — it default-denied the message axis while
enumerating the producing-site axis, the #518 mistake on a second axis.

**Files:**

- Modify: `scripts/check_tag_t3.py` — new class near the message constants (~`:543`); an
  early `return` in `_scan_text`'s broad-except arm; the shared return at `:2579`
- Test: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: `check_tag_t3._ScannedOk`, a `list[str]` subclass with `__slots__ = ()`. Task 2
  consumes it via `isinstance(result, _ScannedOk)`.

- [ ] **Step 1: Write the failing derived outcome guard**

Add next to `test_every_collection_failure_message_is_enumerated` (~`:120`). This guard
asserts on the RESULT TYPE, not on `result[0]` — the `_UNSCANNABLE_MESSAGE` site appends
after any real violations the walk already found, so a position-keyed guard would be
order-dependent (`arch-011`).

```python
def _trigger_unparseable(tmp: Path) -> Path:
    p = tmp / "unparseable.py"
    p.write_text("def (:\n", encoding="utf-8")
    return p


def _trigger_undecodable(tmp: Path) -> Path:
    p = tmp / "undecodable.py"
    p.write_bytes(b"# -*- coding: latin-1 -*-\nx = '\xff\xfe'\n")
    return p


def _trigger_unreadable(tmp: Path) -> Path:
    p = tmp / "a_directory.py"
    p.mkdir()
    return p


def _trigger_unscannable(tmp: Path) -> Path:
    # REUSE `_ALWAYS_UNSCANNABLE` (`:1540`) — do NOT hand-roll a nesting depth.
    # It is derived from `_PATHOLOGICAL_SOURCES["unary-not-chain"]` and is the
    # one shape documented as behaving identically on EVERY build measured.
    # `ast.parse` raises RecursionError on the uv/proto standalone build and
    # parses clean on Homebrew at the same CPython version.
    p = tmp / "unscannable.py"
    p.write_text(_ALWAYS_UNSCANNABLE, encoding="utf-8")
    return p


def _trigger_unscannable_path(tmp: Path) -> Path:
    return tmp / "embedded\x00nul.py"


_FAILURE_TRIGGERS: dict[str, Callable[[Path], Path]] = {
    check_tag_t3._UNPARSEABLE_MESSAGE: _trigger_unparseable,
    check_tag_t3._UNDECODABLE_MESSAGE: _trigger_undecodable,
    check_tag_t3._UNREADABLE_MESSAGE: _trigger_unreadable,
    check_tag_t3._UNSCANNABLE_MESSAGE: _trigger_unscannable,
    check_tag_t3._UNSCANNABLE_PATH_MESSAGE: _trigger_unscannable_path,
}


def test_only_a_completed_scan_returns_the_scanned_ok_marker(tmp_path: Path) -> None:
    """DEFAULT-DENY the outcome axis.

    `main` counts a file toward the census only when `_scan_file` returns a
    `_ScannedOk`. Marking the FAILURES instead would enumerate them, and this
    file already carries two shapes enumeration misses: the `S_ISREG` refusal
    reuses `_UNREADABLE_MESSAGE`, and `_NOT_A_REGULAR_FILE_REASON` is a
    collection failure whose name carries no `_MESSAGE` suffix.

    Derived from the module's own constants, so a sixth message reds here.
    """
    assert set(_FAILURE_TRIGGERS) == set(_COLLECTION_FAILURE_MESSAGES), (
        "a collection-failure message has no trigger — add one, or the census "
        "can silently count its files as successfully scanned"
    )

    for index, (message, build) in enumerate(_FAILURE_TRIGGERS.items()):
        directory = tmp_path / f"case{index}"
        directory.mkdir()
        result = check_tag_t3._scan_file(build(directory))

        assert result, f"{message!r}: expected a collection failure, got a clean scan"
        assert any(message in line for line in result), f"expected {message!r} in {result!r}"
        assert not isinstance(result, check_tag_t3._ScannedOk), (
            f"{message!r}: marked as a completed scan, so `main` will count "
            f"this unreadable file toward the census — the fail-open direction"
        )


def test_a_clean_file_returns_the_scanned_ok_marker(tmp_path: Path) -> None:
    """The other side. Without this, the guard above passes on a build that
    never marks anything and the census would count zero files forever."""
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1\n", encoding="utf-8")

    result = check_tag_t3._scan_file(clean)

    assert result == []
    assert isinstance(result, check_tag_t3._ScannedOk)


def test_a_file_with_a_real_finding_still_counts_as_scanned(tmp_path: Path) -> None:
    """A finding is not a collection failure. The gate READ this file fine."""
    bad = tmp_path / "bad.py"
    bad.write_text(
        "from alfred.security.tiers import tag, T3\nv = tag(T3, 'x')\n", encoding="utf-8"
    )

    result = check_tag_t3._scan_file(bad)

    assert result, "expected the tag(T3, ...) finding"
    assert isinstance(result, check_tag_t3._ScannedOk)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -k scanned_ok_marker -v`

Expected: FAIL — `AttributeError: module 'check_tag_t3_under_test' has no attribute '_ScannedOk'`.

- [ ] **Step 3: Add the marker type**

In `scripts/check_tag_t3.py`, after `_UNSCANNABLE_PATH_MESSAGE` (~`:543`):

```python
class _ScannedOk(list[str]):
    """Violations from a scan that RAN TO COMPLETION. Empty list = clean.

    DEFAULT-DENY on the outcome axis (#547). `main`'s census counts a file only
    when its result is one of these, so a return path nobody has thought of yet
    — a new `except` arm, an early return, a future refactor — counts as a
    failure rather than as a clean scan.

    MARKING THE FAILURES INSTEAD WAS MEASURED FAIL-OPEN. That variant
    default-denied the MESSAGE axis (deriving from `_*_MESSAGE`) while
    ENUMERATING the producing-site axis, and this file already carries two
    shapes that enumeration misses: the `S_ISREG` refusal reuses
    `_UNREADABLE_MESSAGE` rather than adding a message, and
    `_NOT_A_REGULAR_FILE_REASON` is a collection failure whose name carries no
    `_MESSAGE` suffix. A sixth `except` arm reusing an existing message left
    the guard GREEN while its files scored as clean scans.

    A `list` subclass rather than a richer return type because `==` against a
    plain list is transparent, so every existing assertion holds unchanged.
    Rebuilding the list (`+`, a comprehension, `sorted()`, `list(...)`) drops
    the marker — and that direction is FAIL-CLOSED, which is the whole reason
    the polarity is this way round.
    """

    __slots__ = ()
```

- [ ] **Step 4: Convert the fall-through into an early return**

In `_scan_text`'s broad-except arm, after the two `violations.append(...)` calls at `:2576`:

```python
        violations.append(f"{path}:1: {_UNSCANNABLE_MESSAGE}")
        violations.append(f"  {type(exc).__name__}: {exc}")
        # NOT a fall-through to the marked return below (#547). The walk was
        # abandoned part-way, so this file's clean lines prove nothing and it
        # must not count toward the census.
        return violations

    return _ScannedOk(violations)
```

No completion flag is needed: the fall-through becomes an early return, which adds no branch
that real inputs cannot reach. `_scan_file` needs **no edit** — its three failure arms already
return plain lists, and `return _scan_text(text, path, resolved)` propagates the delegate's.

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -k scanned_ok_marker -v`

Expected: PASS (3 tests).

- [ ] **Step 6: Verify no existing test regressed**

Run: `uv run pytest tests/unit/security/ tests/unit/meta/ -q`

Expected: all pass, **zero edits to existing tests**. If an existing assertion broke, the
`list` subclass is not transparent and the design assumption is wrong — stop and report.

- [ ] **Step 7: Commit — BEFORE any mutation testing**

The mutation step MUST follow this commit. Revision 1 put it before, and `git checkout` then
destroyed the uncommitted implementation on iteration 1 while iterations 2-5 failed on the
missing attribute and were scored "killed" — four false kills over zero mutations
(`rev-001`, `arch-003`, `sec-005`, `test-004`, corroborated x4).

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "test: #547 mark the completed-scan path, not the failure paths

The census must tell a file the gate could not read from a file it read and
found clean. Marking the five failure sites enumerates them, and this file
already carries two shapes enumeration misses: the S_ISREG refusal reuses
_UNREADABLE_MESSAGE, and _NOT_A_REGULAR_FILE_REASON carries no _MESSAGE
suffix. A sixth except arm reusing an existing message was measured leaving
the guard green while its files scored as clean scans.

Marking the single completion path instead means every other return - known
or not - counts as a failure by construction. _scan_text's broad arm gains an
early return so a part-way walk cannot reach the marked return.

_ScannedOk is a list subclass, so equality against a plain list stays
transparent and no existing assertion changes."
```

- [ ] **Step 8: MUTATION-TEST the guard — now that the work is safe**

A guard that cannot see the bug it exists for is itself a paper gate. Two hazards, both found
in review:

1. `git checkout -- <path>` restores from the **INDEX, not HEAD**. A staged mutation survives
   the "revert" silently, and this plan runs `git add` on that path. Use
   `git restore --source=HEAD --staged --worktree` to reset both.
2. A mutant that never applied reports as SURVIVED. Verify each edit landed before concluding.

Apply these two mutations one at a time, by hand:

- drop the early `return violations` so an abandoned walk falls through to the marked return;
- change `return _ScannedOk(violations)` back to `return violations`.

For each one:

```bash
git diff --stat scripts/check_tag_t3.py    # MUST be non-empty, or the mutant never applied
uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -k scanned_ok_marker -q \
  && echo "SURVIVED — THE GUARD IS VACUOUS" || echo "killed (correct)"
git restore --source=HEAD --staged --worktree scripts/check_tag_t3.py
git status --porcelain scripts/check_tag_t3.py    # MUST print nothing
```

Expected: `killed (correct)` both times. Any `SURVIVED` means the guard does not cover that
path — fix the guard before continuing.

---

### Task 2: The census asserts `scanned_ok`

**Files:**

- Modify: `scripts/check_tag_t3.py` — `main`'s census block and scan loop (~`:2988-3010`),
  `main`'s docstring (`:2965-2979`), the `_MIN_SCANNED_FILES` rationale comment (`:560-622`)
- Test: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**

- Consumes: `_ScannedOk` from Task 1.
- Produces: `_build_flat_tree(root: Path, count: int, body: str, prefix: str = "mod") -> Path`,
  consumed by Task 3.

- [ ] **Step 1: Write the failing census tests**

Fixtures are monkeypatched-floor-small except one realistic case — revision 1 planted 530+
files across four tests, which runs on the macOS, Windows and WSL2 legs (`arch-012`). Every
test asserts on discriminating substrings, never on `expected at least` (`test-003`).

```python
def _build_flat_tree(root: Path, count: int, body: str, prefix: str = "mod") -> Path:
    """`count` files of identical content in one out-of-repo directory."""
    root.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        (root / f"{prefix}_{index:04d}.py").write_text(body, encoding="utf-8")
    return root


def test_a_tree_the_gate_cannot_read_exits_2_not_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Probe A. Measured on 7095dbbc as rc=1 with 521 stderr lines.

    Exit 1 is "violations found", and `main`'s docstring promises "every listed
    line is a finding in a file, not a fault in the gate". Files the gate could
    not parse are not findings in files.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)
    tree = _build_flat_tree(tmp_path / "unreadable", 4, "def (:\n")

    assert check_tag_t3.main([str(tree)]) == 2
    err = capsys.readouterr().err
    assert "0 scanned" in err and "4 unreadable" in err
    assert "not reaching the source tree" not in err, (
        "the PRE-SCAN floor fired, not the post-scan census — this tree does "
        "not clear the collection floor and the test proves nothing (rev-003)"
    )
    assert check_tag_t3._UNPARSEABLE_MESSAGE in err, (
        "the census refused without printing what it collected (arch-001)"
    )


def test_a_tree_of_only_exempt_files_exits_2_and_says_exempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Probe C — the genuinely SILENT shape. Measured as rc=0, zero output.

    The message must say EXEMPT, not "could not read it": every file here was
    read perfectly and simply was not gated.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)
    tree = _build_flat_tree(tmp_path / "allexempt", 4, "x = 1\n", prefix="test_x")
    assert all(check_tag_t3._is_exempt(p) for p in tree.glob("*.py")), (
        "the fixture is not exempt — this test would pass for the wrong reason"
    )

    assert check_tag_t3.main([str(tree)]) == 2
    err = capsys.readouterr().err
    assert "4 exempt" in err and "0 scanned" in err
    assert "not reaching the source tree" not in err


def test_the_census_passes_at_the_floor_and_fails_one_below(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Both sides of the new comparison.

    The failing half must be decided by the POST-SCAN census, not the pre-scan
    collection floor (`rev-003`, `test-002`): revision 1 planted 3 files with
    the floor at 4, so the pre-scan floor refused it and the test passed on
    unmodified code. Here the tree always CLEARS the collection floor and only
    the scanned tally varies.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)

    at_floor = _build_flat_tree(tmp_path / "at", 4, "x = 1\n")
    assert check_tag_t3.main([str(at_floor)]) == 0

    one_below = _build_flat_tree(tmp_path / "below", 3, "x = 1\n")
    (one_below / "broken.py").write_text("def (:\n", encoding="utf-8")
    assert check_tag_t3.main([str(one_below)]) == 2
    err = capsys.readouterr().err
    assert "3 scanned" in err and "1 unreadable" in err
    assert "not reaching the source tree" not in err, (
        "the pre-scan floor decided this — 4 files were collected, so it must not"
    )


def test_one_unparseable_file_among_many_still_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proportionality: only a MASS read failure flips the exit code."""
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)
    tree = _build_flat_tree(tmp_path / "mostly_fine", 5, "x = 1\n")
    (tree / "broken.py").write_text("def (:\n", encoding="utf-8")

    assert check_tag_t3.main([str(tree)]) == 1


def test_the_production_tree_scans_exactly_331_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DoD #4. `scanned_ok` is a local printed only on failure, so it cannot be
    asserted directly (`arch-004`). Bisect the floor against the real tree
    instead: 331 must pass and 332 must refuse, pinning it exactly while adding
    no new surface to the gate.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 331)
    assert check_tag_t3.main([]) != 2

    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 332)
    assert check_tag_t3.main([]) == 2


def test_a_realistic_mass_failure_above_the_real_floor_exits_2(tmp_path: Path) -> None:
    """The one full-size case, at the SHIPPED floor with no monkeypatch —
    the decoy-fixture precedent at `:1920`. Everything else runs small."""
    tree = _build_flat_tree(tmp_path / "big", 260, "def (:\n")
    assert 260 > check_tag_t3._MIN_SCANNED_FILES

    assert check_tag_t3.main([str(tree)]) == 2
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -k "exits_2 or census_passes or still_exits_1 or exactly_331" -v`

Expected: FAIL.

- [ ] **Step 3: Extract the shared printer**

Two call sites now print violations, so factor it once (#422 — a shared helper fails LOUD, N
copies drift SILENTLY):

```python
def _print_violations(violations: list[str]) -> None:
    """Print collected violation lines to stderr. Shared by the census refusal
    and the exit-1 path so the two cannot drift apart."""
    if violations:
        print("check_tag_t3: violations found:", file=sys.stderr)
        for line in violations:
            print(line, file=sys.stderr)
```

- [ ] **Step 4: Replace the census and the scan loop**

```python
    # The PRE-SCAN floor. Fast-fails a wrong-checkout scan before reading 332
    # files, and diagnoses a DIFFERENT fault from the post-scan census below:
    # "traversal did not reach the source tree" rather than "it reached it and
    # could not read it". Explicit file arguments are how the unit suite plants
    # fixtures, so they are exempt.
    #
    # #547: this message said "scanned" and meant "collected". That conflation
    # IS the defect this census had.
    scanned_a_directory = not argv or any(Path(a).is_dir() for a in argv)
    if scanned_a_directory and len(paths) < _MIN_SCANNED_FILES:
        print(
            f"check_tag_t3: collected {len(paths)} files, expected at least "
            f"{_MIN_SCANNED_FILES}. The gate is not reaching the source tree "
            f"(wrong working directory, or the scan root moved) — refusing to "
            f"report success while gating nothing.",
            file=sys.stderr,
        )
        return 2

    all_violations: list[str] = []
    exempt = 0
    scanned_ok = 0
    try:
        for path in paths:
            # EXEMPT FILES COUNT ON NEITHER SIDE. An exemption is a decision not
            # to gate, so counting one as a successful scan counts a non-event —
            # and with `_APPROVED_PATHS` at size one, a production run always has
            # one, which is what made the withdrawn draft's all-or-nothing test
            # unreachable in production (#547, ADR-0058).
            #
            # `_scan_file` checks this again. One redundant CALL to one
            # implementation, not a second implementation — #422's drift trap is
            # copy-pasted logic, and there is none here.
            if _is_exempt(path):
                exempt += 1
                continue
            violations = _scan_file(path)
            all_violations.extend(violations)
            # DEFAULT-DENY: only a completed scan carries the marker, so any
            # other return path — including one added later — is a failure.
            if isinstance(violations, _ScannedOk):
                scanned_ok += 1
    except GateInternalError as exc:
        print(f"check_tag_t3: {exc}", file=sys.stderr)
        return 2

    # The POST-SCAN census (#547). `len(paths)` counted files COLLECTED during
    # traversal — `git ls-files` plus a `stat`, which proves nothing was read,
    # parsed or gated. Two measured shapes cleared it: a tree the gate could not
    # read exited 1 ("violations found") against an exit contract that reserves 2
    # for "the gate could not run", and a tree of exempt files exited 0 in
    # silence having scanned nothing at all.
    #
    # ONE self-diagnosing message rather than two arms: reporting the full tally
    # distinguishes "all exempt" from "could not read" without a second branch
    # to cover under this file's 100% gate.
    if scanned_a_directory and scanned_ok < _MIN_SCANNED_FILES:
        # PRINT WHAT WE FOUND BEFORE REFUSING. Returning above this discarded
        # every violation collected so far — a real tag(T3, ...) finding
        # alongside read failures vanished entirely, and a change that fixes a
        # diagnostic defect must not introduce a worse one.
        _print_violations(all_violations)
        print(
            f"check_tag_t3: collected {len(paths)} files: {exempt} exempt, "
            f"{scanned_ok} scanned, {len(paths) - exempt - scanned_ok} "
            f"unreadable — expected at least {_MIN_SCANNED_FILES} scanned. "
            f"Refusing to report success while gating nothing.",
            file=sys.stderr,
        )
        return 2

    if all_violations:
        _print_violations(all_violations)
        return 1
    return 0
```

- [ ] **Step 5: Run to verify they pass**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -k "exits_2 or census_passes or still_exits_1 or exactly_331" -v`

Expected: PASS (6 tests).

- [ ] **Step 6: Update `main`'s docstring and the floor rationale**

`main`'s docstring at `:2965-2979` enumerates "THREE routes to exit 2" with "the aggregate
census below" as one. There are now two censuses, and a whole input class moves from 1 to 2
(`arch-005`). Update it, and the module docstring's "Exits 0 if clean; exits 1 with violation
messages" contract.

`_MIN_SCANNED_FILES`'s rationale comment at `:560-622` is written entirely for the *collected*
quantity ("332 tracked .py files ... 250 leaves headroom"). It now governs two populations —
collected (includes exempt) and `scanned_ok` (excludes them). State both, and that production
is 332 collected / 331 scanned (`arch-006`).

- [ ] **Step 7: Verify production is unchanged, on the build CI uses**

```bash
python3 scripts/check_tag_t3.py || { status=$?; echo "FAILED rc=$status"; exit "$status"; }
```

Bare `python3`, not `uv run` — both call sites and CI use `python3` (`ops-002`). Expected:
rc=0, no census message.

- [ ] **Step 8: Full gate suite**

Run: `uv run pytest tests/unit/security/ tests/unit/meta/ -q`

Expected: all pass, zero existing-test edits.

- [ ] **Step 9: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "test: #547 census counts files SCANNED, not files collected

len(paths) counted what traversal found. Collection is git ls-files plus a
stat: it proves nothing was read, parsed or gated. Two shapes cleared the
floor — a tree the gate could not read exited 1 against a contract reserving
2 for 'the gate could not run', and a tree of exempt files exited 0 in
silence having scanned nothing.

Exempt files now count on neither side. An exemption is a decision not to
gate, and with _APPROVED_PATHS at size one a production run always has one,
which is what made the withdrawn draft unreachable in production.

The census prints what it collected before refusing: returning above the
print block discarded a real finding collected alongside read failures. One
self-diagnosing message reports the full tally, so the all-exempt shape is
not misdescribed as 'could not read it'."
```

---

### Task 3: The discriminator, the fail-closed proof, coverage and ADR-0060

**Files:**

- Create: `docs/adr/0060-the-census-counts-scanned-files.md`
- Test: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**

- Consumes: `_ScannedOk` (Task 1); the census and `_build_flat_tree` (Task 2).
- Produces: nothing consumed downstream.

- [ ] **Step 1: Write the discriminator test — with ZERO slack**

Revision 1's version was vacuous: it planted floor-many clean files PLUS the quoter, so losing
the quoter left `scanned_ok` exactly at the floor and both implementations returned rc=1.
Found by three reviewers and measured by the test-engineer against three built variants.

```python
def test_a_file_quoting_a_failure_message_still_counts_as_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The NON-SUBSTRING requirement, stated as a test with no slack.

    A substring implementation keys the census on file CONTENT, because
    `_record` appends a source snippet under every finding. This file is read
    and parsed perfectly and trips a REAL rule on a line quoting a
    collection-failure message, so its snippet carries that text.

    ZERO SLACK IS LOAD-BEARING (`sec-001`, `rev-002`, `test-001`). Plant exactly
    `_MIN_SCANNED_FILES` files of which ONE is the quoter. `==` is the unique
    solution: collected >= floor or the pre-scan floor decides the test instead,
    and collected <= floor or a misclassified quoter still clears the census and
    the mutant survives.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 2)
    tree = _build_flat_tree(tmp_path / "quoter", 1, "x = 1\n")
    (tree / "quoter.py").write_text(
        "from alfred.security.tiers import tag, T3\n"
        f'v = tag(T3, "{check_tag_t3._UNPARSEABLE_MESSAGE}")\n',
        encoding="utf-8",
    )

    planted = sorted(tree.glob("*.py"))
    assert len(planted) == check_tag_t3._MIN_SCANNED_FILES, (
        "zero slack is the point: one more file and the substring mutant "
        "survives; one fewer and the pre-scan floor decides the test"
    )
    assert not any(check_tag_t3._is_exempt(p) for p in planted)

    rc = check_tag_t3.main([str(tree)])

    assert rc == 1, (
        "expected the real tag(T3, ...) finding under exit 1; exit 2 means the "
        "census classified a perfectly-scannable file as a read failure "
        "because its SOURCE quoted a message constant"
    )
```

- [ ] **Step 2: Mutation-test the discriminator**

The implementation is committed (Task 2 Step 9), so a mutation is safely revertible.

Replace the `isinstance(violations, _ScannedOk)` check with the substring form:

```python
            if not any(
                m in line for line in violations for m in (
                    _UNPARSEABLE_MESSAGE, _UNREADABLE_MESSAGE, _UNDECODABLE_MESSAGE,
                    _UNSCANNABLE_MESSAGE, _UNSCANNABLE_PATH_MESSAGE,
                )
            ):
```

Verify the edit landed (`git diff --stat scripts/check_tag_t3.py` non-empty), run the test,
expect **FAIL** with the exit-2 assertion message, then:

```bash
git restore --source=HEAD --staged --worktree scripts/check_tag_t3.py
git status --porcelain scripts/check_tag_t3.py   # must print nothing
```

- [ ] **Step 3: Write the fail-closed proof test**

This is the test that justifies the polarity, and the one revision 1 could not pass.

```python
def test_an_unknown_failure_arm_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DoD #7. A future `except` arm reusing an EXISTING message must not count
    as a clean scan.

    This is the shape that made the failure-marking variant fail open: it
    derived its guard from the `_*_MESSAGE` constants, so an arm reusing one was
    invisible. Both shapes already exist here — the `S_ISREG` refusal reuses
    `_UNREADABLE_MESSAGE`, and `_NOT_A_REGULAR_FILE_REASON` carries no `_MESSAGE`
    suffix at all.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)

    def _new_arm(text: str, path: Path, resolved: Path) -> list[str]:
        # A hypothetical sixth arm: returns a plain list reusing an existing
        # message, exactly as a real `except PermissionError` would.
        return [f"{path}:1: {check_tag_t3._UNREADABLE_MESSAGE}", "  simulated"]

    monkeypatch.setattr(check_tag_t3, "_scan_text", _new_arm)
    tree = _build_flat_tree(tmp_path / "newarm", 4, "x = 1\n")

    assert check_tag_t3.main([str(tree)]) == 2, (
        "an unrecognised failure arm was counted as a clean scan — the census "
        "enumerates outcomes instead of default-denying them"
    )
```

- [ ] **Step 4: Run the required coverage gate**

```bash
uv run pytest tests/unit --cov=src/alfred --cov=scripts -q
uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100
```

Expected: `100%`, exit 0. Reference from the built variant: 674 statements, 362 branches, 0
miss, 0 partial. No pragma, no `exclude_also` edit, no ternary laundering.

- [ ] **Step 5: Verify the gate-surface pin rather than grepping**

The repo already ships the derived pin — use it instead of a hand-written grep that can only
confirm the call sites it already assumed (`ops-004`, enumerate-vs-default-deny):

```bash
uv run pytest tests/unit/meta/test_gate_surfaces_are_pinned.py -q
```

- [ ] **Step 6: Write ADR-0060**

Create `docs/adr/0060-the-census-counts-scanned-files.md` with the ADR-0058 section set,
including **Alternatives considered** and **References**, which revision 1 dropped
(`arch-007`).

Required content:

- **Context**: the measured baseline (`collected=332, floor=250, exempt=1`) and the three
  probes (A: rc=1/521 lines; C: rc=0/silent; D: rc=1/violation named).
- **Decision 1**: the census asserts `scanned_ok`.
- **Decision 2**: the SUCCESS path is marked, so unknown failure arms fail closed — with the
  measured fail-open result for the alternative.
- **Decision 3**: the exit-code reclassification. Revision 1 buried this; it is the
  widest-blast-radius change and needs to be a Decision of its own (`arch-007`).
- **Alternatives considered**: failure-site marking (measured fail-open); an explicit
  `(outcome, violations)` tuple (rejected on churn); `attempted` instead of `scanned_ok`
  (leaves probe A at exit 1).
- **Consequences → Negative**: the marker is lost by list rebuilding (fail-closed direction);
  partial-scan-then-fault counts as failed; explicit FILE arguments stay census-exempt; the
  `_is_exempt` double-call TOCTOU (`sec-006`); the census proves read+parsed, not gated
  (`sec-007`); and the `scanned_ok` build-sensitivity with its measured headroom (`ops-002`).
- **Relates to**: must name ADR-0058, whose Consequences carry the live instruction "Do not
  implement #547 against its body as written". ADR-0060 supersedes that instruction — the
  body was rewritten 2026-08-03 and this ADR records what was implemented instead
  (`arch-008`).

- [ ] **Step 7: Lint the ADR**

Run: `npx --yes markdownlint-cli2 "docs/adr/0060-the-census-counts-scanned-files.md"`

Expected: `0 issues`. Watch MD004 / MD031 / MD032, and MD018 — a line starting with `#547`
parses as a heading, so reflow it.

- [ ] **Step 8: Full quality bar**

```bash
make check || { status=$?; echo "make check FAILED with $status"; exit "$status"; }
```

Never `make check; echo $?` — the compound exits with `echo`'s status and discards the real
one. `make check` requires Docker via `coverage-gates`, and it does include `tag-t3-check`
(`Makefile:252`), so this genuinely exercises the 1→2 change. Read the output rather than
trusting the status.

- [ ] **Step 9: Commit**

```bash
git add docs/adr/0060-the-census-counts-scanned-files.md \
        tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "docs: #547 ADR-0060, the discriminator and the fail-closed proof

The discriminator test is the one a substring implementation fails: a file
read and parsed perfectly, tripping a real rule on a line whose source quotes
a collection-failure message. Zero slack is load-bearing — plant exactly
_MIN_SCANNED_FILES files of which one is the quoter, or the mutant survives.

The fail-closed proof simulates a sixth except arm reusing an existing
message. That is the shape that made failure-site marking fail open.

ADR-0060 records the measured baseline, the three probes, the alternatives
considered, and the residuals — marker loss on list rebuilding, the
_is_exempt TOCTOU, read-and-parsed not gated, and the build sensitivity.
It supersedes ADR-0058's 'do not implement #547 as written'."
```

---

### Task 4: PR, review fleet, and merge

Revision 1 sequenced a content-free `fix:` commit after CodeRabbit approval, which would have
meant fabricating an empty commit or amending a reviewed one — and a force-push rewriting a
reviewed commit dismisses the approval (`arch-009`, `rev-005`). The closing reference goes on
the PR instead.

- [ ] **Step 1: Push and open the PR with the closing keyword in the BODY**

```bash
git push -u origin 547-census-counts-scanned-files
gh pr create --base main \
  --title "fix: #547 the census counts SCANNED files, not collected ones" \
  --body "Closes #547. <summary>"
```

The title carries the `fix: #547` shape the repo's commit gate wants on the squashed subject;
`Closes #547` in the body does the closing. No empty commit, no amend after review.

- [ ] **Step 2: Run the full review fleet**

`/review-pr` with the security specialist **always** included. #539 was defence-in-depth on
this same file and drew 35 Critical/High findings across three review layers; this plan drew
48 at plan stage. Budget accordingly.

- [ ] **Step 3: Run CodeRabbit**

Run BOTH the internal fleet and CodeRabbit — they catch disjoint bugs. CLI needs
`--base origin/main`. If the cloud review goes quiet, `@coderabbitai full review` (not
`review`), once. Resolve every thread; verify each fix is in HEAD before resolving, and never
claim a fix before pushing it.

- [ ] **Step 4: Merge**

```bash
gh pr merge --rebase
```

Never `--admin`. If blocked, resolve the real blocker. Afterwards confirm #547 actually
closed — verify issue state rather than assuming the keyword fired.

---

## Notes for the implementer

- **Do not "fix" the exemption short-circuit in `_scan_file`.** `if _is_exempt(path): return []`
  stays. `main` skipping exempt files is what excludes them from the ratio.
- **`GateInternalError` is not a collection failure.** It says the gate is broken, not the
  file, and travels to exit 2 on its own path. It must not enter `_COLLECTION_FAILURE_MESSAGES`.
- **Three derived guards red in both directions.** A new `_*_MESSAGE` must be classified in
  `test_every_collection_failure_message_is_enumerated` and mirrored in
  `test_the_corpus_record_matches_the_shipped_rule_set`. `_ScannedOk` is a type, not a keyed
  identifier, so `test_every_keyed_identifier_is_alias_resolved` should not apply — confirm by
  running it rather than assuming (`arch-010`).
- **Do not raise `_MIN_SCANNED_FILES`.** Rejected in #541: at 300 it sits 7 files above the
  `src/alfred` count against a tree growing ~19 files per 23 days.
