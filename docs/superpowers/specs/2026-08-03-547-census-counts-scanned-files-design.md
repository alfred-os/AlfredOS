# #547 — the `check_tag_t3` census must count files SCANNED, not files COLLECTED

- **Date**: 2026-08-03
- **Issue**: [#547](https://github.com/alfred-os/AlfredOS/issues/547) (body rewritten
  2026-08-03; the original must not be implemented as written — see
  [ADR-0058](../../adr/0058-single-approved-t3-authoring-home.md))
- **Baseline**: `main` @ `7095dbbc`
- **Family**: the last open member of #536. Siblings #537, #538, #539, #541, #542, #543,
  #546 all shipped against this same file.

## The defect

`scripts/check_tag_t3.py:2993` — the aggregate census in `main`:

```python
scanned_a_directory = not argv or any(Path(a).is_dir() for a in argv)
if scanned_a_directory and len(paths) < _MIN_SCANNED_FILES:
    ...
    return 2
```

`len(paths)` counts files **collected during traversal**. Collection is `git ls-files` (or
an `rglob` fallback) plus a `stat`; it does not prove a single file was read, parsed or
gated. The census verifies that traversal *found* enough paths — while its operator message
says `scanned {len(paths)} files` and its stated purpose is "refusing to report success
while gating nothing".

## Measured, not reasoned

Every number below was executed on `7095dbbc`. Probes are out-of-repo directories of 260
`.py` files (above the 250 floor) passed as one directory argument.

```
collected = 332      floor = 250
_APPROVED_PATHS = ['tiers.py']       # size 1 since #538
exempt within the default scan = 1   # ['tiers.py']
```

| Probe | Tree | Today | Why it matters |
| --- | --- | --- | --- |
| **A** | 260 non-exempt, all unparseable | `rc=1`, 521 stderr lines | Loud, but the **wrong exit code** |
| **C** | 260 out-of-repo `test_*.py` (exempt), all unparseable | **`rc=0`, zero output** | Census cleared; **zero files scanned**; reported clean |
| **D** | 259 exempt + 1 real `tag(T3, ...)` | `rc=1`, violation named | The gate is not blind — the census measures the wrong quantity |

Probe A is an **exit-contract** defect. `main`'s docstring promises "exit 1 therefore means
what it says: every listed line is a finding in a file, not a fault in the gate." 260
files the gate could not read are reported under exit 1, when the gate defines exit 2 as
"the gate could not run".

Probe C is the genuine "success while gating nothing": `_scan_file` short-circuits
`if _is_exempt(path): return []` *before any read*, so an exempt file is indistinguishable
from a successfully-scanned clean one in the aggregate.

**Ergonomic cost is measured at zero.** Not one existing test scans an out-of-repo
directory through to the census: every directory-shaped `main()` call in the suite either
fails earlier (`EmptyScanRootError`, `PartialScanRootError`, the decoy defence) or is the
real argument-less repo scan. Explicit FILE arguments are census-exempt and stay that way.

## Decision 1 — the census asserts `scanned_ok`

```
attempted  = collected - exempt
scanned_ok = attempted - read/parse failures
```

`scanned_ok` catches both measured shapes; `attempted` alone would leave probe A at exit 1.

| Scenario | collected | scanned_ok | rc today | rc after |
| --- | --- | --- | --- | --- |
| Production argument-less run | 332 | 331 | 0 or 1 | **unchanged** |
| One genuine syntax error in-tree | 332 | 330 | 1 | **1 (unchanged)** |
| Probe A | 260 | 0 | 1 | **2** |
| Probe C | 260 | 0 | 0 | **2** |

Only a *mass* read failure flips the exit code. A single unparseable file still reports as
a violation under exit 1, which is the existing and correct behaviour.

## Decision 2 — the outcome travels as a sentinel type, not a substring

The discriminator must come from the control flow that produced the result, never from
matching its text: `_scan_file` returns a flat `list[str]` and `_record` appends a source
SNIPPET line under every finding, so an `in`-based test would key on author-controlled file
content. Those message strings already appear verbatim outside the constant that defines
them (`docs/superpowers/plans/2026-07-30-537-check-tag-t3-gate-integrity.md:349`).

```python
class _CollectionFailure(str):
    """A line saying the gate could NOT read the file — never a finding IN it."""
    __slots__ = ()
```

Applied at each of the five producing sites — three return arms in `_scan_file`
(`_UNDECODABLE_MESSAGE`, `_UNREADABLE_MESSAGE`, `_UNSCANNABLE_PATH_MESSAGE`) and two in
`_scan_text` (the `_UNPARSEABLE_MESSAGE` early return, and the `_UNSCANNABLE_MESSAGE`
append). The `S_ISREG` refusal is deliberately **not** a sixth site: it raises into the
existing `OSError` arm, which #546 documented as a single funnel that keeps both sides of
that branch covered.

### Why a `str` subclass rather than a signature change

Verified by execution:

| Property | Result |
| --- | --- |
| `==` both directions, `hash`, set/dict membership, list equality | transparent |
| `list.extend`, `sorted` | preserve the subclass |
| A snippet quoting the message text | stays plain `str` → correctly counted as scanned |
| `mypy --strict`, `pyright`, `ruff` (both check this file explicitly) | clean |

So the existing assertions pass untouched — `_record`'s docstring notes that tests assert
the returned list "by equality rather than by substring search", and the 324 tests across
the five `test_check_tag_t3_*` files are the ones that must stay green — and `list[str]`
stays true. The alternative — threading `(outcome, violations)` tuples
through `_scan_file` and `_scan_text` behind list-returning wrappers — adds an enum, two
wrappers and new branches to a file under a REQUIRED 100% line+branch gate, for a signal
the sentinel carries at the exact point the decision is made.

### The hazard, and why it needs a derived guard

`f"{line}"` and `line + ""` **drop** the subclass (executed: both return plain `str`).
Losing the marker fails **open** — a collection failure would count as a clean scan and
inflate `scanned_ok`. A comment is not sufficient protection for a fail-open edge.

The guard: derive the collection-failure message set from the module's own `_*_MESSAGE`
suffix — reusing the derivation `test_every_collection_failure_message_is_enumerated`
already performs — and require each message to have a registered real-input trigger whose
produced line satisfies `isinstance(..., _CollectionFailure)`. A sixth message, or a
producing site that reformats its line, reds on the day it lands. Default-deny the class,
not the five sites we thought of (#518).

## Decision 3 — both floors stay; the old message is corrected

`scanned_ok <= collected` always, so the post-scan check is strictly stronger. The
pre-scan collection floor stays anyway:

- it short-circuits a wrong-checkout scan before reading 332 files;
- it diagnoses a **different** fault — "not reaching the source tree" vs "reached it and
  could not read it" — and #543 (dx-001, dx-003) established that this gate owes the
  operator the remedy, not just the diagnosis.

Its message currently reads `scanned {len(paths)} files`, which is the very conflation this
issue is about. It becomes `collected`, and the new post-scan message says `scanned`.

## Structure

`main` classifies; it does not re-implement anything:

```python
scanned_ok = 0
for path in paths:
    if _is_exempt(path):
        continue                      # a decision NOT to gate — counts on neither side
    result = _scan_file(path)
    all_violations.extend(result)
    if not any(isinstance(line, _CollectionFailure) for line in result):
        scanned_ok += 1
```

`_is_exempt` is pure and is called again inside `_scan_file`, so non-exempt files pay one
redundant call (two `resolve()`s each, ~660 on the real tree — measured negligible). This
is deliberately a second CALL to one implementation, not a second implementation: #422's
drift trap is copy-pasted logic, and there is none here.

`GateInternalError` handling is untouched. It still aborts the loop and returns 2, and is
still not a collection-failure message — it says the gate is broken, not the file.

## Testing

| Test | Shape | Asserts |
| --- | --- | --- |
| Boundary pass | `scanned_ok == floor`, floor monkeypatched low (precedent at `:819`) | `rc != 2` |
| Boundary fail | `scanned_ok == floor - 1` | `rc == 2` |
| Realistic mass failure | ≥250-file unparseable tree (decoy-fixture precedent, `:1920`) | `rc == 2`, not 1 |
| All-exempt | probe C shape | `rc == 2`, not 0 |
| **Discriminator** | a file tripping a REAL rule on a line whose source quotes a collection-failure message | counted as **scanned**, not failed |
| **Derived marker guard** | every `_*_MESSAGE` collection failure | its produced line is `isinstance(_CollectionFailure)` |
| Production unchanged | argument-less run | `scanned_ok == 331`, rc unchanged |

Coverage: the new arm's false side is already covered by the existing `main([])` tests; the
true side by the boundary-fail and all-exempt tests. The 100% line+branch gate on this file
is REQUIRED and takes **no pragmas** — do not touch `exclude_also`, and never launder a
dead branch into a ternary, because `coverage.py` does not branch on a conditional
expression (#538). If an arc proves unreachable, follow the `assert` precedent at `:902`
and `:2291` — but measure unreachability first. Note `mypy` runs with `warn_unreachable = true`, so it is
a second signal on the same question.

Gate command — a bare `coverage run` measures nothing, because
`[tool.coverage.run] source = ["src/alfred"]`:

```bash
uv run pytest tests/unit --cov=src/alfred --cov=scripts
uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100
```

## Derived guards this change must satisfy

- `test_every_collection_failure_message_is_enumerated` — any new `_*_MESSAGE` must be
  classified finding vs collection failure. Naming one `_REASON` to dodge it defeats it
  silently.
- `test_the_corpus_record_matches_the_shipped_rule_set` — checks the adversarial corpus
  record against the gate's constants in both directions.
- `test_every_keyed_identifier_is_alias_resolved` — any new keyed identifier needs a row or
  an entry in `_DECLARED_ALIAS_RESIDUALS`. Reds in **both** directions.

## Residuals — stated, not closed

- A file partially scanned before a fault (`_scan_text`'s append arm) counts as **failed**.
  Conservative and fail-closed: it under-counts successes, so it can only make the census
  stricter.
- The sentinel is lost by any reformatting of a producing line. The derived guard catches a
  dropped marker at the five known sites and at any sixth message; it cannot catch a caller
  that copies a line out and back through an f-string. No such caller exists today.
- Explicit FILE arguments remain exempt from the census, unchanged. The call-site pin in
  `tests/unit/meta/test_gate_surfaces_are_pinned.py` is what stops that becoming an
  enumeration bypass.
- **Production reachability of the silent shape stays nil.** The realistic operator
  mistakes are already refused by the per-directory floor, the `_DEFAULT_SCAN_ROOTS`
  runtime invariant and the decoy defence. This is defence-in-depth, and its ergonomic cost
  is measured at zero — like #539's.

## Out of scope

Raising `_MIN_SCANNED_FILES` (considered and rejected in #541: at 300 it sits 7 files above
the `src/alfred` count and the tree grows ~19 files/23 days, so the guard would stop working
within a week). Any change to what `_DEFAULT_SCAN_ROOTS` covers. Any change to the
`tests/unit/security/**` half of the exempt set.
