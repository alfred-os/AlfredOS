# #547 — Census Counts SCANNED Files Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `scripts/check_tag_t3.py`'s aggregate census assert the number of files the
gate actually read and parsed, not the number traversal collected, so the gate cannot report
success — or report "violations found" — while having gated nothing.

**Architecture:** A `_CollectionFailure(str)` sentinel subclass marks the first line at each
of the five collection-failure producing sites, at the exact point the decision is made.
`main` classifies each file by `isinstance` (never by substring, which would key on
author-controlled file content), skips exempt files on both sides of the ratio, and asserts
`scanned_ok >= _MIN_SCANNED_FILES`. A derived guard over the module's own `_*_MESSAGE`
constants protects the sentinel's fail-open edge.

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
- Coverage gate command — a bare `coverage run` measures **nothing**, because
  `[tool.coverage.run] source = ["src/alfred"]`. Run
  `uv run pytest tests/unit --cov=src/alfred --cov=scripts` first, then
  `uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100`.
- Commit subjects: Conventional Commits with a literal `#547` **after** the colon. Never use
  the `fix:` type until the final task — `fix: #547 …` auto-closes the issue on merge.
- No `--no-verify`. No `git add -A` — add named paths only.
- Ergonomic cost must stay at zero: no existing test may need editing to keep passing.

## Subsystem coverage matrix

| Subsystem | Touched | Owner agent |
| --- | --- | --- |
| `src/alfred/security/` (trust boundary) | **No** — authoring-layer gate only, no runtime code | `alfred-security-engineer` (review) |
| `scripts/` (release-blocking gate) | **Yes** — `check_tag_t3.py` | `alfred-test-engineer` |
| `tests/unit/security/` | **Yes** — gate integrity tests | `alfred-test-engineer` |
| `docs/adr/` | **Yes** — ADR-0060 | `alfred-docs-author` |
| CI workflows / Makefile | **No** — verified unchanged, both call sites run the script bare | `alfred-devops-engineer` (verify) |
| Memory / personas / providers / comms / core | **No** | — |

**Plan-level owner agent:** `alfred-test-engineer` (the deliverable is gate + test
behaviour), with `alfred-security-engineer` as mandatory reviewer because the artifact is a
release-blocking security gate.

## Definition of Done

1. `scanned_ok` is the census quantity; exempt files count on neither side.
2. Probe A (≥250 non-exempt unparseable files) exits **2**, not 1.
3. Probe C (≥250 exempt files) exits **2**, not 0.
4. The production argument-less run is **unchanged** (`scanned_ok == 331` on the `7095dbbc`
   tree; rc unchanged).
5. A single genuine syntax error in-tree still exits **1**, not 2.
6. A file that trips a real rule on a line whose source quotes a collection-failure message
   counts as **scanned**.
7. Every `_*_MESSAGE` collection failure produces an `isinstance(_CollectionFailure)` line,
   enforced by a derived guard that reds on a sixth message.
8. `scripts/check_tag_t3.py` at **100% line + branch**, no pragmas.
9. `make check` green; `mypy --strict` + `pyright` clean; `ruff check` + `ruff format --check`
   clean; markdownlint clean on new docs.
10. No existing test edited to keep it passing.

---

### Task 1: The `_CollectionFailure` sentinel and its derived guard

Establishes the marker and proves every producing site sets it. The guard is written FIRST
because the fail-open direction (a dropped marker inflates `scanned_ok`) is the dangerous
one, and a guard that cannot see a dropped marker is a paper gate.

**Files:**

- Modify: `scripts/check_tag_t3.py` — new class near the message constants (~`:530`); mark
  lines at `:2399`, `:2576`, `:2649`, `:2651`, `:2666`
- Test: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: `check_tag_t3._CollectionFailure`, a `str` subclass with `__slots__ = ()`. Task 2
  consumes it via `isinstance(line, _CollectionFailure)`.

- [ ] **Step 1: Write the failing derived guard**

Add to `tests/unit/security/test_check_tag_t3_gate_integrity.py`, next to
`test_every_collection_failure_message_is_enumerated` (~`:120`):

```python
# Each collection-failure MESSAGE mapped to a real input that triggers it. Keyed
# by the message CONSTANT, not by name, so a rename cannot silently orphan a row.
# `_scan_file` is driven end-to-end rather than the arm being called directly:
# the marker must survive the real return path, which is where an f-string would
# drop it.
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
    # It is derived from `_PATHOLOGICAL_SOURCES["unary-not-chain"]` and is
    # documented as the one shape that behaved identically on EVERY build
    # measured. `ast.parse` raises RecursionError on the uv/proto standalone
    # build and parses clean on Homebrew at the same CPython version, so a
    # locally-tuned depth is a test that passes on one build and vacuously
    # green on the other.
    p = tmp / "unscannable.py"
    p.write_text(_ALWAYS_UNSCANNABLE, encoding="utf-8")
    return p


def _trigger_unscannable_path(tmp: Path) -> Path:
    return tmp / "embedded\x00nul.py"


_MARKER_TRIGGERS: dict[str, Callable[[Path], Path]] = {
    check_tag_t3._UNPARSEABLE_MESSAGE: _trigger_unparseable,
    check_tag_t3._UNDECODABLE_MESSAGE: _trigger_undecodable,
    check_tag_t3._UNREADABLE_MESSAGE: _trigger_unreadable,
    check_tag_t3._UNSCANNABLE_MESSAGE: _trigger_unscannable,
    check_tag_t3._UNSCANNABLE_PATH_MESSAGE: _trigger_unscannable_path,
}


def test_every_collection_failure_line_carries_the_sentinel(tmp_path: Path) -> None:
    """DEFAULT-DENY the marker, the same way the message set is default-denied.

    The census counts a file as scanned when NO returned line is a
    `_CollectionFailure`. So a producing site that loses the marker — an
    f-string rebuild, a reformat, a sixth message added without one — makes a
    file the gate could not read count as a clean scan. That direction fails
    OPEN, which is why this is derived from the module's own constants rather
    than from a hand-written list of the five sites we know about today.
    """
    expected = set(_COLLECTION_FAILURE_MESSAGES)
    assert set(_MARKER_TRIGGERS) == expected, (
        "a collection-failure message has no marker trigger — add one, or the "
        "census can silently count its files as successfully scanned"
    )

    for index, (message, build) in enumerate(_MARKER_TRIGGERS.items()):
        directory = tmp_path / f"case{index}"
        directory.mkdir()
        target = build(directory)
        result = check_tag_t3._scan_file(target)

        assert result, f"{message!r}: expected a collection failure, got a clean scan"
        assert message in result[0], f"expected {message!r}, got {result[0]!r}"
        assert isinstance(result[0], check_tag_t3._CollectionFailure), (
            f"{message!r}: the line is not marked, so `main` will count this "
            f"unreadable file as a successful scan — the fail-open direction"
        )
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py::test_every_collection_failure_line_carries_the_sentinel -v`

Expected: FAIL with `AttributeError: module 'check_tag_t3_under_test' has no attribute '_CollectionFailure'`.

- [ ] **Step 3: Add the sentinel type**

In `scripts/check_tag_t3.py`, immediately after `_UNSCANNABLE_PATH_MESSAGE` (~`:543`):

```python
class _CollectionFailure(str):
    """A violation line saying the gate could NOT read a file.

    NEVER a finding IN a file. `main`'s census counts a file as successfully
    scanned when none of its lines is one of these, and it must decide that
    from the CONTROL FLOW that produced the line, not from its text: findings
    carry a source SNIPPET (see :func:`_record`), so a file whose source merely
    quotes one of the `_*_MESSAGE` constants would be misclassified by any
    substring test. Those strings already appear verbatim outside the constants
    that define them.

    A `str` subclass rather than a richer return type because `==`, `hash`, set
    and dict membership and list equality are all transparent, so the returned
    value is still exactly `list[str]` and every existing assertion holds.

    THE FAIL-OPEN EDGE: `f"{line}"` and `line + ""` return a plain `str`. A
    producing site that rebuilds its line loses the marker, and an unreadable
    file then counts as a clean scan. Wrap at construction, never re-wrap, and
    see `test_every_collection_failure_line_carries_the_sentinel`, which
    derives its expectations from the `_*_MESSAGE` constants so a sixth message
    reds on the day it lands.
    """

    __slots__ = ()
```

- [ ] **Step 4: Mark all five producing sites**

`scripts/check_tag_t3.py:2399` (in `_scan_text`, the SyntaxError arm):

```python
            return [
                _CollectionFailure(f"{path}:{exc.lineno or 1}: {_UNPARSEABLE_MESSAGE}"),
                f"  {exc.msg}",
            ]
```

`:2576` (in `_scan_text`, the broad arm — APPEND, so only the message line is marked):

```python
        violations.append(_CollectionFailure(f"{path}:1: {_UNSCANNABLE_MESSAGE}"))
        violations.append(f"  {type(exc).__name__}: {exc}")
```

`:2649`, `:2651`, `:2666` (in `_scan_file`):

```python
    except UnicodeDecodeError:
        return [_CollectionFailure(f"{path}:1: {_UNDECODABLE_MESSAGE}"), "  <undecodable>"]
    except OSError as exc:
        return [
            _CollectionFailure(f"{path}:1: {_UNREADABLE_MESSAGE}"),
            f"  {exc.strerror or exc}",
        ]
```

```python
        return [
            _CollectionFailure(f"{path}:1: {_UNSCANNABLE_PATH_MESSAGE}"),
            f"  {type(exc).__name__}: {exc}",
        ]
```

Only the **first** line of each pair is marked. The reason line is data and stays plain.

- [ ] **Step 5: Run the guard to verify it passes**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py::test_every_collection_failure_line_carries_the_sentinel -v`

Expected: PASS.

- [ ] **Step 6: MUTATION-TEST the guard**

A guard that cannot see the bug it exists for is itself a paper gate. Revert **one** site at
a time to a plain f-string and confirm the guard REDS each time:

```bash
for site in 2399 2576 2649 2651 2666; do
  echo "=== reverting site $site ==="
  # unwrap _CollectionFailure(...) at that line by hand, then:
  uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py::test_every_collection_failure_line_carries_the_sentinel -q \
    && echo "SURVIVED — THE GUARD IS VACUOUS AT $site" || echo "killed (correct)"
  git checkout scripts/check_tag_t3.py
done
```

Expected: `killed (correct)` five times. Any `SURVIVED` means the guard does not cover that
site — fix the guard before continuing.

- [ ] **Step 7: Verify no existing test regressed**

Run: `uv run pytest tests/unit/security/ -q`

Expected: all pass, **zero edits to existing tests**. If any existing assertion broke, the
sentinel is not transparent and the design assumption is wrong — stop and report.

- [ ] **Step 8: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "test: #547 mark collection-failure lines with a control-flow sentinel

The census must tell a file the gate could not read from a file it read and
found clean. Deciding that by substring would key on author-controlled file
content: findings carry a source snippet, and the message strings already
appear verbatim outside the constants that define them.

_CollectionFailure is a str subclass, so equality, hash, set/dict membership
and list equality stay transparent and no existing assertion changes.

The guard is derived from the _*_MESSAGE constants rather than from the five
sites known today, because a dropped marker fails OPEN — an unreadable file
would count as a clean scan. Mutation-tested against all five sites."
```

---

### Task 2: The census asserts `scanned_ok`

**Files:**

- Modify: `scripts/check_tag_t3.py:2988-3010` (the census block and the scan loop in `main`)
- Test: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**

- Consumes: `_CollectionFailure` from Task 1.
- Produces: no new public names. `main`'s exit contract is unchanged in wording; a mass read
  failure now reaches exit 2 instead of exit 1.

- [ ] **Step 1: Write the failing boundary + shape tests**

```python
def _build_flat_tree(root: Path, count: int, body: str, prefix: str = "mod") -> Path:
    """`count` files of identical content in one out-of-repo directory."""
    root.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        (root / f"{prefix}_{index:04d}.py").write_text(body, encoding="utf-8")
    return root


def test_a_tree_the_gate_cannot_read_exits_2_not_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Probe A. Measured on 7095dbbc as rc=1 with 521 stderr lines.

    Exit 1 is the code for "violations found", and `main`'s own docstring
    promises "every listed line is a finding in a file, not a fault in the
    gate". 260 files the gate could not parse are not findings in files.
    """
    tree = _build_flat_tree(tmp_path / "unreadable", 260, "def (:\n")
    assert 260 > check_tag_t3._MIN_SCANNED_FILES, (
        "the tree must CLEAR the collection floor, or the old census fires "
        "and the test passes without the check it exists for"
    )

    assert check_tag_t3.main([str(tree)]) == 2
    assert "scanned 0 files" in capsys.readouterr().err


def test_a_tree_of_only_exempt_files_exits_2_not_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Probe C — the genuinely SILENT shape. Measured as rc=0, zero output.

    `_scan_file` short-circuits on `_is_exempt` BEFORE any read, so an exempt
    file is indistinguishable from a scanned-clean one in the aggregate. 260
    collected, 0 read, "clean".
    """
    tree = _build_flat_tree(tmp_path / "allexempt", 260, "x = 1\n", prefix="test_x")
    assert all(check_tag_t3._is_exempt(p) for p in tree.glob("*.py")), (
        "the fixture is not exempt — this test would pass for the wrong reason"
    )

    assert check_tag_t3.main([str(tree)]) == 2
    assert "scanned 0 files" in capsys.readouterr().err


def test_the_census_boundary_passes_at_the_floor_and_fails_one_below(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both sides of the new comparison, at the exact boundary.

    Monkeypatching the floor (precedent: `:819`) keeps this cheap; the
    realistic ≥250 shape is covered by the two probes above.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)

    at_floor = _build_flat_tree(tmp_path / "at", 4, "x = 1\n")
    assert check_tag_t3.main([str(at_floor)]) == 0

    below = _build_flat_tree(tmp_path / "below", 3, "x = 1\n")
    assert check_tag_t3.main([str(below)]) == 2


def test_one_unparseable_file_among_many_still_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proportionality: only a MASS read failure flips the exit code.

    Without this, a fix that returns 2 whenever ANY file fails to parse would
    pass every other test in this file while making one developer typo
    indistinguishable from a broken gate.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)
    tree = _build_flat_tree(tmp_path / "mostly_fine", 5, "x = 1\n")
    (tree / "broken.py").write_text("def (:\n", encoding="utf-8")

    assert check_tag_t3.main([str(tree)]) == 1
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -k "exits_2_not_1 or exits_2_not_0 or census_boundary or still_exits_1" -v`

Expected: FAIL. The first two return 1 and 0 respectively; the boundary test's `below` case
returns 0.

- [ ] **Step 3: Replace the census and the scan loop**

In `scripts/check_tag_t3.py:main`, replace the pre-scan census and the scan loop:

```python
    # The PRE-SCAN floor. Fast-fails a wrong-checkout scan before reading 332
    # files, and diagnoses a DIFFERENT fault from the post-scan census below:
    # "traversal did not reach the source tree" rather than "it reached it and
    # could not read it". Explicit file arguments are how the unit suite plants
    # fixtures, so they are exempt — holding those to a 250-file floor would red
    # every one of them.
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
    scanned_ok = 0
    try:
        for path in paths:
            # EXEMPT FILES COUNT ON NEITHER SIDE. An exemption is a decision not
            # to gate, so counting one as a successful scan counts a non-event —
            # and with `_APPROVED_PATHS` at size one, a production run always has
            # one, which is exactly what made the withdrawn draft's all-or-nothing
            # test unreachable in production (#547, ADR-0058).
            #
            # `_scan_file` checks this again. That is one redundant CALL to one
            # implementation, not a second implementation — #422's drift trap is
            # copy-pasted logic, and there is none here.
            if _is_exempt(path):
                continue
            violations = _scan_file(path)
            all_violations.extend(violations)
            if not any(isinstance(line, _CollectionFailure) for line in violations):
                scanned_ok += 1
    except GateInternalError as exc:
        # NOT exit 1. Whatever was collected before the fault is discarded on
        # purpose: a faulting detector means no file's verdict is trustworthy,
        # including the ones that came back clean. Exit 2 says exactly that.
        print(f"check_tag_t3: {exc}", file=sys.stderr)
        return 2

    # The POST-SCAN census (#547). `len(paths)` counted files COLLECTED during
    # traversal — `git ls-files` plus a `stat`, which proves nothing was read,
    # parsed or gated. Two measured shapes cleared it: a tree the gate could not
    # read exited 1 ("violations found") against an exit contract that reserves 2
    # for "the gate could not run", and a tree of exempt files exited 0 in
    # silence having scanned nothing at all.
    #
    # `scanned_ok <= len(paths)` always, so this is strictly stronger than the
    # pre-scan floor; the pre-scan floor stays for its speed and its different
    # diagnosis.
    if scanned_a_directory and scanned_ok < _MIN_SCANNED_FILES:
        print(
            f"check_tag_t3: collected {len(paths)} files but scanned "
            f"{scanned_ok}, expected at least {_MIN_SCANNED_FILES}. The gate "
            f"reached the tree and could not read it — refusing to report "
            f"success while gating nothing.",
            file=sys.stderr,
        )
        return 2

    if all_violations:
```

Note the ordering: the census runs **after** the loop but **before** the
`if all_violations` return, so a tree that is both unreadable and violation-bearing exits 2.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py -k "exits_2_not_1 or exits_2_not_0 or census_boundary or still_exits_1" -v`

Expected: PASS (4 tests).

- [ ] **Step 5: Verify production is unchanged**

```bash
uv run python scripts/check_tag_t3.py; echo "rc=$?"
```

Expected: `rc=0` and no census message. `scanned_ok` is 331 (332 collected − 1 exempt).

- [ ] **Step 6: Run the whole gate suite**

Run: `uv run pytest tests/unit/security/ tests/unit/meta/ -q`

Expected: all pass, zero existing-test edits.

- [ ] **Step 7: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "test: #547 census counts files SCANNED, not files collected

len(paths) counted what traversal found. Collection is git ls-files plus a
stat: it proves nothing was read, parsed or gated. Two shapes cleared the
floor — a tree the gate could not read exited 1 against a contract reserving
2 for 'the gate could not run', and a tree of exempt files exited 0 in
silence having scanned nothing.

Exempt files now count on neither side of the ratio. An exemption is a
decision not to gate, and with _APPROVED_PATHS at size one a production run
always has one, which is what made the withdrawn draft unreachable in
production.

The pre-scan floor stays: it fast-fails a wrong checkout and diagnoses a
different fault. Its message said 'scanned' and meant 'collected' — the
conflation this census was built on."
```

---

### Task 3: The discriminator test, coverage, ADR, and the full gate run

**Files:**

- Create: `docs/adr/0060-the-census-counts-scanned-files.md`
- Test: `tests/unit/security/test_check_tag_t3_gate_integrity.py`

**Interfaces:**

- Consumes: `_CollectionFailure` (Task 1); the census and the
  `_build_flat_tree(root: Path, count: int, body: str, prefix: str = "mod") -> Path`
  test helper (Task 2).
- Produces: nothing consumed downstream.

- [ ] **Step 1: Write the discriminator test**

This is the test that proves the classification is control-flow-derived. It is the reason the
sentinel exists, and a substring implementation passes every other test in this plan.

```python
def test_a_file_quoting_a_failure_message_still_counts_as_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The NON-SUBSTRING requirement, stated as a test.

    A substring implementation — `any(m in line for m in _COLLECTION_FAILURE_MESSAGES)`
    — keys the census on file CONTENT, because `_record` appends a source
    snippet under every finding. This file is read and parsed perfectly and
    trips a REAL rule on a line that happens to quote a collection-failure
    message, so the snippet carries that text. It must count as scanned.

    With a substring implementation this file counts as a read failure, the
    scanned tally drops below the floor, and the gate exits 2 instead of
    reporting the violation it genuinely found.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 2)
    tree = _build_flat_tree(tmp_path / "quoter", 2, "x = 1\n")
    (tree / "quoter.py").write_text(
        "from alfred.security.tiers import tag, T3\n"
        f'v = tag(T3, "{check_tag_t3._UNPARSEABLE_MESSAGE}")\n',
        encoding="utf-8",
    )

    rc = check_tag_t3.main([str(tree)])

    assert rc == 1, (
        "expected the real tag(T3, ...) finding under exit 1; exit 2 means the "
        "census classified a perfectly-scannable file as a read failure "
        "because its SOURCE quoted a message constant"
    )
```

- [ ] **Step 2: Run it — and mutation-test it**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_gate_integrity.py::test_a_file_quoting_a_failure_message_still_counts_as_scanned -v`

Expected: PASS.

Then prove it is not vacuous — temporarily replace the `isinstance` check in `main` with the
substring form and confirm this test REDS:

```python
            if not any(
                m in line for line in violations for m in (
                    _UNPARSEABLE_MESSAGE, _UNREADABLE_MESSAGE, _UNDECODABLE_MESSAGE,
                    _UNSCANNABLE_MESSAGE, _UNSCANNABLE_PATH_MESSAGE,
                )
            ):
```

Expected: FAIL with the exit-2 assertion message. Then `git checkout scripts/check_tag_t3.py`
is **wrong** here (it would discard Task 2) — revert the single hunk by hand.

- [ ] **Step 3: Run the required coverage gate**

```bash
uv run pytest tests/unit --cov=src/alfred --cov=scripts -q
uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100
```

Expected: `100%`, and the command exits 0. If an arc is uncovered, drive it with a real
input. Do **not** add a pragma, touch `exclude_also`, or rewrite the branch as a ternary. If
an arc is provably unreachable, measure it first, then use `assert` per `:902` / `:2291`.

- [ ] **Step 4: Verify the CI contract did not shift**

Both call sites run the script bare, so any non-zero exit fails the job — the 1→2 change is
CI-safe. Confirm rather than assume:

```bash
grep -n "check_tag_t3.py" Makefile .github/workflows/pr-validate-python.yml | grep -v mypy | grep -v pyright
```

Expected: `Makefile:241` and `pr-validate-python.yml:359`, both bare invocations with no
exit-code branching.

- [ ] **Step 5: Write ADR-0060**

Create `docs/adr/0060-the-census-counts-scanned-files.md` following the ADR-0058 shape:
Status / Date / Slice / Relates-to header, Context (with the three measured probes and the
`collected=332, floor=250, exempt=1` baseline), Decision (the three decisions from the
spec), Consequences split Positive / Negative / Neutral. The Negative section must carry:
the sentinel's fail-open edge and what guards it; that partial-scan-then-fault counts as
failed; and that explicit FILE arguments remain census-exempt.

- [ ] **Step 6: Lint the ADR**

Run: `npx --yes markdownlint-cli2 "docs/adr/0060-the-census-counts-scanned-files.md"`

Expected: `0 issues`. Watch MD004 / MD031 / MD032, and MD018 — a line starting with `#547`
is parsed as a heading, so reflow it.

- [ ] **Step 7: Full quality bar**

```bash
make check || { status=$?; echo "make check FAILED with $status"; exit "$status"; }
```

Never `make check; echo $?` — the compound exits with `echo`'s status and discards the real
one. After it returns, read the log:

```bash
grep -ciE '^(FAILED|ERROR)|\*\*\*|\[fail\]' <log>
```

- [ ] **Step 8: Commit**

```bash
git add docs/adr/0060-the-census-counts-scanned-files.md \
        tests/unit/security/test_check_tag_t3_gate_integrity.py
git commit -m "docs: #547 ADR-0060 and the non-substring discriminator test

The discriminator test is the one a substring implementation fails: a file
read and parsed perfectly, tripping a real rule on a line whose source quotes
a collection-failure message. _record appends a source snippet under every
finding, so a substring census keys on file content and refuses a file it
scanned successfully.

ADR-0060 records the measured baseline, the three probes, and the residuals —
the sentinel's fail-open edge, partial-scan-then-fault counting as failed,
and explicit file arguments staying census-exempt."
```

---

### Task 4: PR, review fleet, and merge

- [ ] **Step 1: Push and open the PR**

```bash
git push -u origin 547-census-counts-scanned-files
gh pr create --fill --base main
```

- [ ] **Step 2: Run the full review fleet**

`/review-pr` with the security specialist **always** included — the artifact is a
release-blocking security gate. #539 was defence-in-depth on this same file and drew 35
Critical/High findings across three review layers; budget for that.

- [ ] **Step 3: Run CodeRabbit**

Run BOTH the internal fleet and CodeRabbit — they catch disjoint bugs. CLI needs
`--base origin/main`. If the cloud review goes quiet, `@coderabbitai full review` (not
`review`). Resolve every thread; verify each fix is in HEAD before resolving.

- [ ] **Step 4: Final commit uses `fix:` to close the issue**

Only now. The repo's conventional-commit gate mandates `#NNN` after the colon, and
`fix: #547 …` auto-closes the issue on merge.

- [ ] **Step 5: Merge**

```bash
gh pr merge --rebase
```

Never `--admin`. If it is blocked, resolve the real blocker.

---

## Notes for the implementer

- **Do not "fix" the exemption short-circuit in `_scan_file`.** `if _is_exempt(path): return []`
  stays. `main` skipping exempt files is what excludes them from the ratio; changing
  `_scan_file` would break its many direct-call tests for no gain.
- **`GateInternalError` is not a collection failure.** It says the gate is broken, not the
  file, and travels to exit 2 on its own path. It must not be marked with the sentinel and
  must not enter `_COLLECTION_FAILURE_MESSAGES`.
- **The two derived guards red in both directions.** A new `_*_MESSAGE` constant must be
  classified in `test_every_collection_failure_message_is_enumerated` and mirrored in
  `test_the_corpus_record_matches_the_shipped_rule_set`. Naming a constant `_REASON` to dodge
  the first defeats it silently, which is why `_NOT_A_REGULAR_FILE_REASON` is documented as a
  deliberate exclusion rather than an accident.
- **Do not raise `_MIN_SCANNED_FILES`.** Considered and rejected in #541: at 300 it sits 7
  files above the `src/alfred` count against a tree growing ~19 files per 23 days.
