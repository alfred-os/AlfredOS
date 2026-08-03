# #547 — Census Counts SCANNED Files Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Revision 3 — 2026-08-03, after a SECOND `/review-plan` fleet.** Round 1 returned 48
> findings; round 2 returned 40 more against revision 2, including three Criticals revision 2
> introduced itself. The pattern across both rounds: the design direction held every time and
> the mechanism and tests did not. Revision 2's inversion marked the `try` fall-through rather
> than a completion event, which is enumeration wearing default-deny's clothes — measured
> fail-open, byte-identical to revision 1. Findings that changed the work are marked inline
> with their id.

**Goal:** Make `scripts/check_tag_t3.py`'s aggregate census assert the number of files the
gate actually read and parsed, not the number traversal collected, so the gate cannot report
success — or report "violations found" — while having gated nothing.

**Architecture:** A `_ScannedOk(list[str])` subclass is returned only on a COMPLETION EVENT —
a `completed = True` as the last statement of `_scan_text`'s `try` body — so no arm can reach
it by falling through. A name census pins the marker to two construction sites. `main` counts
DISTINCT resolved files. `main` classifies with `isinstance`, skips exempt files
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
4. Production gated as a PROPERTY over constants — zero unreadable, at least the shipped
   floor of distinct non-exempt files — never a hard-coded count. Verified with bare
   `python3`, the invocation form both call sites use (`ops-002`).
5. A single genuine syntax error in-tree still exits **1**, not 2.
6. A file that trips a real rule on a line whose source quotes a collection-failure message
   counts as **scanned**, proved with ZERO slack.
7. A naive new `except MemoryError` arm — append, no `return`, reusing an existing message —
   inserted into REAL source scores `scanned_ok == 0`. Proved by a source-mutation harness,
   not a monkeypatch: revision 2's stub replaced `_scan_text` and so never entered its `try`,
   and measured PASS against the fail-open build.
8. The census prints every collected violation before refusing.
9. `scripts/check_tag_t3.py` at **100% line + branch**, no pragmas.
10. `make check` green; `mypy --strict` + `pyright` clean; `ruff` clean; markdownlint clean.
11. 260 symlinks to one file do NOT clear the census — it counts distinct resolved files,
    not scan events (NEW-1, measured rc=0 and silent on the shipped gate).
12. `_ScannedOk` is referenced in exactly two places in the source, enforced by a name census.
13. No existing test edited to keep it passing.

---

### Task 1: `_ScannedOk` and the derived outcome guard

Marks the success path so unknown failure arms fail CLOSED. Revision 1 marked the five
FAILURE sites; two reviewers built both variants and measured that one fail-OPEN on a sixth
arm reusing an existing message (`sec-004`) — it default-denied the message axis while
enumerating the producing-site axis, the #518 mistake on a second axis.

**Files:**

- Modify: `scripts/check_tag_t3.py` — new class near the message constants (~`:543`); a
  `completed` flag in `_scan_text`; the shared return at `:2579`
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
    # The RecursionError/Homebrew divergence belongs to
    # `binop-chain`, NOT to this shape — `unary-not-chain` is pinned to
    # MemoryError at test file `:1550`. Name the fixture, not a remembered
    # mechanism.
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

- [ ] **Step 4: Mark on a COMPLETION EVENT, not on the fall-through**

> **Revision 3 correction.** Revision 2 added an early `return` to the broad-except arm and
> claimed no completion flag was needed. That was wrong, and measured wrong three times:
> `_ScannedOk` then marked the `try` statement's **fall-through**, so a new `except` arm
> written the ordinary way — append, no `return` — falls straight through to the marked
> return. Security built an `except MemoryError` arm reusing `_UNSCANNABLE_MESSAGE` and
> measured `scanned_ok == 4/4`, rc=1: **byte-identical to revision 1's fail-open.** Revision 2
> replaced "enumerate the five messages" with "enumerate the five returns" and called it
> default-deny. Only a positive completion event actually inverts the polarity.

```python
    completed = False
    try:
        ...                      # existing walk, unchanged
        # THE COMPLETION EVENT. Last statement of the try body, so it is
        # reached only when every preceding step ran. An `except` arm added
        # later cannot set it, and cannot reach the marked return by falling
        # through — which is what revision 2 got wrong.
        completed = True
    except Exception as exc:
        violations.append(f"{path}:1: {_UNSCANNABLE_MESSAGE}")
        violations.append(f"  {type(exc).__name__}: {exc}")

    # NOT a ternary: `coverage.py` does not branch on a conditional expression,
    # so a ternary would hide an arm from this file's REQUIRED 100% branch gate
    # (#538). Both arcs are driven by real inputs — the True arc by any clean
    # file, the False arc by the suite's own `_ALWAYS_UNSCANNABLE` fixture.
    if completed:
        return _ScannedOk(violations)
    return violations
```

Measured on the flag variant: **683 statements / 366 branches / 0 partial / 100%**, no
pragma. Revision 2's coverage objection to this flag was backwards.

`_scan_file` needs **no edit** — its three failure arms already return plain lists, and
`return _scan_text(text, path, resolved)` propagates the delegate's.

- [ ] **Step 4b: Pin the marker to exactly two construction sites**

The flag closes fall-through. It does **not** stop anyone constructing a marker directly:
`_ScannedOk([... _UNREADABLE_MESSAGE ...])` fails open through every other guard, and neither
mypy nor pyright can see the invariant (`arch-002`).

**Do NOT write this as an `ast.Call`-whose-func-is-a-`Name` pin.** The architect proposed
that, executed it, and **retracted it**: it reports GREEN against `_Alias = _ScannedOk`, a
subclass, `functools.partial(_ScannedOk)` and `globals()["_ScannedOk"]` — all fail-open at
4/4. That is this repo's alias-resolution lesson for the third time in one issue.

Ship a default-deny **name census** instead — every `ast.Name` node referencing `_ScannedOk`
anywhere in the source, with exactly two positions allowed (the `class` statement and the one
`return`). Any third reference, in any syntactic role, reds.

**Name its blind spot rather than claiming closure:** `type(x)(...)` and `copy.copy(x)`
reproduce the class without ever spelling the name, so no source-level instrument sees them.
That residual goes in ADR-0060 (`sec-007` family), or is closed later by a runtime
construction invariant on the #518/#520 pattern.

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

- Modify: `scripts/check_tag_t3.py` — `main`'s census block and scan loop (~`:2987-3019`),
  `main`'s docstring (`:2963-2980`), the `_MIN_SCANNED_FILES` rationale comment (`:579-621`)
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
    # ALL THREE terms. Asserting only two let a mutant dropping `- exempt`
    # from the unreadable arithmetic survive every test in the suite.
    assert "0 exempt" in err and "0 scanned" in err and "4 unreadable" in err
    assert "not reaching the source tree" not in err, (
        "the PRE-SCAN floor fired, not the post-scan census — this tree does "
        "not clear the collection floor and the test proves nothing (rev-003)"
    )
    assert check_tag_t3._UNPARSEABLE_MESSAGE in err, (
        "the census refused without printing what it collected (arch-001)"
    )
    assert check_tag_t3._PARTIAL_HEADER in err, "wrong header on a refusal"
    assert check_tag_t3._FINDINGS_HEADER not in err, (
        "520 read failures announced as 'violations found' (arch-004)"
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
    # THE THIRD TERM IS LOAD-BEARING. A mutant computing `unreadable` as
    # `len(distinct) - scanned_ok` (dropping `- exempt`) reports "4 exempt,
    # 0 scanned, 4 unreadable" here and survived all 91 tests, because this was
    # the only test reaching the census with exempt > 0 and it checked two of
    # the three terms.
    assert "4 exempt" in err and "0 scanned" in err and "0 unreadable" in err
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


def test_the_production_tree_is_gated_as_a_property(monkeypatch: pytest.MonkeyPatch) -> None:
    """DoD #4, as a PROPERTY over constants — never a count.

    Revision 2 bisected the floor around 331 and four reviewers rejected it: the
    production tree grows ~25 `.py` files per 30 days, `tests/unit` runs in four
    required checks, and the next unrelated merge would red it within ~2 days.
    The plan's own Notes reject count-keyed guards for exactly that reason, and
    revision 2 then wrote one three sections later.

    An stderr-reading variant is no better: the post-scan census is reachable on
    the real tree at exactly ONE floor value, so any such test is structurally
    count-pinned. The test-engineer withdrew its own stderr suggestion on that
    evidence.

    Every assertion here is against a CONSTANT or a relation, so nothing drifts
    with the tree. Oracle independence comes from pairing this with
    `test_only_a_completed_scan_returns_the_scanned_ok_marker`, which pins the
    marker itself without reference to any count.
    """
    paths = check_tag_t3._collect_paths([])
    distinct = {p.resolve(strict=False) for p in paths}
    exempt = {p for p in distinct if check_tag_t3._is_exempt(p)}
    unreadable = [
        p
        for p in distinct - exempt
        if not isinstance(check_tag_t3._scan_file(p), check_tag_t3._ScannedOk)
    ]

    assert not unreadable, f"the gate cannot read its own tree: {unreadable}"
    assert len(distinct - exempt) >= check_tag_t3._MIN_SCANNED_FILES
    assert len(exempt) <= len(check_tag_t3._APPROVED_PATHS)
    assert check_tag_t3.main([]) != 2


def test_a_realistic_mass_failure_above_the_real_floor_exits_2(tmp_path: Path) -> None:
    """The one full-size case, at the SHIPPED floor with no monkeypatch —
    the decoy-fixture precedent at `:1920`. Everything else runs small."""
    tree = _build_flat_tree(tmp_path / "big", 260, "def (:\n")
    # `<` not `>`: ruff SIM300 reds a Yoda condition.
    assert check_tag_t3._MIN_SCANNED_FILES < 260

    assert check_tag_t3.main([str(tree)]) == 2


def test_symlink_copies_of_one_file_do_not_clear_the_census(tmp_path: Path) -> None:
    """NEW-1. `_collect_paths` never deduped, so the census counted scan EVENTS
    rather than distinct files.

    MEASURED ON THE SHIPPED GATE, no monkeypatch: 260 symlinks to a single
    `x = 1` file exited 0 with empty stderr, having gated one distinct file.
    That falsifies this plan's goal sentence on the live gate, and the census as
    specified in revisions 1 and 2 passes it too — all 260 scan perfectly.
    """
    tree = tmp_path / "links"
    tree.mkdir()
    (tree / "real.py").write_text("x = 1\n", encoding="utf-8")
    for index in range(260):
        (tree / f"link_{index:04d}.py").symlink_to(tree / "real.py")

    assert check_tag_t3.main([str(tree)]) == 2
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -k "exits_2 or census_passes or still_exits_1 or exactly_331" -v`

Expected: FAIL.

- [ ] **Step 3: Extract the shared printer**

Two call sites now print violations, so factor it once (#422 — a shared helper fails LOUD, N
copies drift SILENTLY):

```python
def _print_violations(violations: list[str], header: str) -> None:
    """Print collected violation lines to stderr under ``header``.

    The HEADER is a parameter, not a constant (#547, `arch-004`). Sharing the
    printer must not share the headline: exit 1 means "every listed line is a
    finding in a file", and printing that over 520 read failures tells the
    operator the opposite of the truth.
    """
    if violations:
        print(header, file=sys.stderr)
        for line in violations:
            print(line, file=sys.stderr)


_FINDINGS_HEADER: str = "check_tag_t3: violations found:"
_PARTIAL_HEADER: str = (
    "check_tag_t3: partial results from a scan that did NOT complete — these "
    "are what the gate managed to collect before refusing, NOT a clean bill of "
    "health for anything absent from this list:"
)
```

The `if violations:` guard needs its own pin, not merely coverage: the test-engineer's sweep
showed dropping it survives all tests while both arcs report covered. Coverage-covered is not
the same as pinned.

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

    # DEDUPE BY RESOLVED PATH (#547, NEW-1). `_collect_paths` returns what
    # traversal found, and nothing deduped it — so the census counted scan
    # EVENTS, not distinct files. Measured on the SHIPPED gate with no
    # monkeypatch: 260 symlinks to one `x = 1` file exited 0 with empty stderr,
    # having gated exactly one distinct file. Every one of them scans perfectly,
    # so `scanned_ok` alone cannot see it.
    #
    # Deduping HERE and not in `_collect_paths` is deliberate: that function's
    # per-directory floor and decoy defence are specified over what traversal
    # found, and `recurse_symlinks=True` is load-bearing there (#541). Narrowing
    # its return would change three guards to fix one.
    distinct = sorted({path.resolve(strict=False): path for path in paths}.values())

    all_violations: list[str] = []
    exempt = 0
    scanned_ok = 0
    try:
        for path in distinct:
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
        # diagnostic defect must not introduce a worse one. Under its OWN
        # header: these are partial results, not a findings list.
        _print_violations(all_violations, _PARTIAL_HEADER)
        print(
            f"check_tag_t3: collected {len(paths)} files ({len(distinct)} "
            f"distinct): {exempt} exempt, {scanned_ok} scanned, "
            f"{len(distinct) - exempt - scanned_ok} unreadable — expected at "
            f"least {_MIN_SCANNED_FILES} scanned. Refusing to report success "
            f"while gating nothing.",
            file=sys.stderr,
        )
        return 2

    if all_violations:
        _print_violations(all_violations, _FINDINGS_HEADER)
        return 1
    return 0
```

Note `len(distinct)`, not `len(paths)`, in the unreadable term — with dedup they differ, and
the tally must describe what was actually scanned.

- [ ] **Step 5: Run to verify they pass**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -k "exits_2 or census_passes or still_exits_1 or exactly_331" -v`

Expected: PASS (6 tests).

- [ ] **Step 6: Update `main`'s docstring and the floor rationale**

`main`'s docstring at `:2963-2980` enumerates "THREE routes to exit 2" with "the aggregate
census below" as one. There are now two censuses, and a whole input class moves from 1 to 2
(`arch-005`). Update it, and the module docstring's "Exits 0 if clean; exits 1 with violation
messages" contract.

`_MIN_SCANNED_FILES`'s rationale comment at `:579-621` is written entirely for the *collected*
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

- [ ] **Step 1b: Run the new tests GREEN before mutating anything**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -k "quoting_a_failure_message or naive_new_except_arm" -v`

Expected: **PASS**. Revision 2 went straight from writing a test to mutating and expecting
FAIL, with no green baseline — so a failure could not be told from a test that never worked.
That is revision 1's false-kill shape one task later, and it must not recur: a mutation result
means nothing until the test has been observed passing on unmutated code.

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

> **Revision 3 correction — this test was vacuous and is rewritten.** Revision 2
> monkeypatched `_scan_text` wholesale, so it never entered the real `try` at all and
> **measured PASS against the fail-open variant**. It was the flagship test for the whole
> polarity decision and it could not see the bug it existed to prove absent. A stub that
> replaces the function cannot test the function's control flow; the arm has to be added to
> the real source.

```python
_NAIVE_ARM = '''
    except MemoryError as exc:
        violations.append(f"{path}:1: {_UNSCANNABLE_MESSAGE}")
        violations.append(f"  {type(exc).__name__}: {exc}")
'''


def test_a_naive_new_except_arm_fails_closed(tmp_path: Path) -> None:
    """DoD #7, against a REAL new arm in REAL source.

    The shape that broke both earlier designs: an `except` arm written the
    ordinary way — append messages, no `return` — reusing an EXISTING message so
    no `_*_MESSAGE`-derived guard can see it. Revision 1 scored these files as
    clean scans; so did revision 2, because its marker sat on the try
    statement's fall-through rather than on a completion event.

    A source-mutation harness rather than a monkeypatch, because the property
    under test IS `_scan_text`'s control flow. Replacing the function cannot
    exercise it — that is exactly how revision 2's version passed against a
    fail-open build.
    """
    source = Path(check_tag_t3.__file__).read_text(encoding="utf-8")
    anchor = "    except Exception as exc:\n"
    assert source.count(anchor) == 1, "anchor drifted — the mutation would not apply"
    mutated = source.replace(anchor, _NAIVE_ARM.lstrip("\n") + anchor, 1)
    assert mutated != source, "MUTANT NEVER APPLIED — a green result would be meaningless"

    script = tmp_path / "mutated_gate.py"
    script.write_text(mutated, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("mutated_gate", script)
    assert spec is not None and spec.loader is not None
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)

    gate._MIN_SCANNED_FILES = 4
    tree = _build_flat_tree(tmp_path / "newarm", 4, _ALWAYS_UNSCANNABLE)

    assert gate.main([str(tree)]) == 2, (
        "a naive new except arm was counted as a clean scan — the marker is on "
        "the try fall-through, not on a completion event"
    )
```

`_ALWAYS_UNSCANNABLE` is the fixture that reaches the broad arm; the inserted `MemoryError`
arm sits **above** `except Exception` so it wins for that shape. The test file already
imports `importlib.util`.

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

Verified via `gh api`: the repo is **rebase-only** (`allow_squash_merge: false`), so the PR
title never becomes a commit subject. The commit gate reads `git log BASE..HEAD`, and the
`test:`/`docs:` subjects below each carry a literal `#547`, so it passes on those.
A `Closes #547` line in the PR BODY closes the issue under a rebase merge. No empty commit, no amend after
review.

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
