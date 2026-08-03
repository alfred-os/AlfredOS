# ADR-0060 — The census counts files SCANNED, not files collected

- **Status**: Accepted
- **Date**: 2026-08-03
- **Slice**: #547 (`check_tag_t3` aggregate census — the last open member of the #536 family)
- **Relates to**: [ADR-0058](0058-single-approved-t3-authoring-home.md) (whose Consequences
  carry the instruction "Do not implement #547 against its body as written" — **this ADR
  supersedes that instruction**; the issue body was rewritten 2026-08-03 and this records what
  was implemented instead), [ADR-0059](0059-default-deny-on-unresolvable-tier-slices.md)
  (default-deny on an unreadable operand — same principle, different axis), issue
  [#547](https://github.com/alfred-os/AlfredOS/issues/547)

## Context

`scripts/check_tag_t3.py` is a release-blocking required check (`tag(T3) grep gate` in
`.github/workflows/pr-validate-python.yml`). Its aggregate census existed to stop the gate
"reporting success while gating nothing". It compared `len(paths)` — files **collected during
traversal** — against `_MIN_SCANNED_FILES`.

Collection is `git ls-files` (or an `rglob` fallback) plus a `stat`. It proves no file was
read, parsed or gated. The census therefore verified that traversal *found* enough paths,
while its own operator message said `scanned {len(paths)} files`.

### What was measured

Baseline on `7095dbbc`: `collected=332`, `floor=250`, `exempt=1` (`tiers.py`).
`_APPROVED_PATHS` has been size one since #538 — `quarantine.py` still exists, is no longer
exempt, and is genuinely scanned and genuinely clean.

Three probes, each an out-of-repo directory passed as one argument:

| Probe | Tree | Result | Why it matters |
| --- | --- | --- | --- |
| A | 260 non-exempt, all unparseable | `rc=1`, 521 stderr lines | Loud, but the **wrong exit code** |
| C | 260 out-of-repo exempt `test_*.py` | **`rc=0`, zero output** | Census cleared; **zero files scanned** |
| D | 259 exempt + 1 real `tag(T3, ...)` | `rc=1`, violation named | The gate is not blind; the census counts the wrong thing |

A fourth shape was found during review and reproduced on the shipped gate: **260 symlinks to
one `x = 1` file exited 0 with empty stderr**, having gated exactly one distinct file. Every
one of them scans perfectly, so a census over successful scans alone does not see it either.

Probe A is an exit-contract defect. `main`'s docstring promised "exit 1 therefore means what
it says: every listed line is a finding in a file, not a fault in the gate" — and 260 files
the gate could not read were reported under it.

Probe C is the genuine "success while gating nothing": `_scan_file` short-circuits
`if _is_exempt(path): return []` before any read, so an exempt file was indistinguishable
from a successfully-scanned clean one.

## Decision

### 1. The census asserts `scanned_ok` over DISTINCT files

`scanned_ok = distinct − exempt − read/parse failures`, where `distinct` deduplicates by
resolved path. Exempt files count on neither side: an exemption is a decision *not* to gate,
so counting one as a successful scan counts a non-event — and with `_APPROVED_PATHS` at size
one, a production run always has one, which is what made an all-or-nothing test over the
collected set unreachable in production.

Deduplication happens in `main`, not in `_collect_paths`. That function's per-directory floor
and decoy defence are specified over what traversal *found*, and `recurse_symlinks=True` is
load-bearing there (#541); narrowing its return would change three guards to fix one.

Production is unchanged: 332 collected, 1 exempt, 331 scanned, rc unchanged. A single genuine
syntax error still exits 1. Only a *mass* read failure flips the code.

### 2. The COMPLETION PATH is marked, so unknown failures fail closed

`_scan_text` sets `completed = True` as the last statement of its `try` body and returns
`_ScannedOk(violations)` only when that flag is set. `main` counts a file only on
`isinstance(violations, _ScannedOk)`.

Marking the **failure** sites instead was measured fail-open: it default-denies the *message*
axis (deriving from `_*_MESSAGE`) while **enumerating** the producing-site axis, and this file
already carries two shapes enumeration misses — the `S_ISREG` refusal reuses
`_UNREADABLE_MESSAGE` rather than adding a message, and `_NOT_A_REGULAR_FILE_REASON` carries
no `_MESSAGE` suffix at all.

Marking the try statement's **fall-through** was also measured fail-open, and this is the
subtler of the two: an `except` arm written the ordinary way — append messages, no `return` —
falls straight into a fall-through return. A real `except MemoryError` arm reusing
`_UNSCANNABLE_MESSAGE` scored 4 files of 4 as clean scans under that design. Only a positive
completion event distinguishes "the walk finished" from "the walk stopped somewhere".

`_ScannedOk` is pinned to two locations by a **name census** over every `ast.Name` reference —
not by matching a call shape. A call-shape pin was proposed, executed and retracted during
review: it reports green against `_Alias = _ScannedOk`, a subclass, `functools.partial` and
`globals()[...]`.

### 3. A mass read failure exits 2, and still prints what it collected

The exit contract is unchanged in wording; an input class moves to match it. A refusal prints
every collected violation under `_PARTIAL_HEADER` rather than `_FINDINGS_HEADER`: discarding a
real `tag(T3, ...)` finding because the same run also hit read failures would trade one
diagnostic defect for a worse one, and announcing read failures as "violations found" would be
a second lie.

## Alternatives considered

- **Mark the five failure sites** with a `str` subclass. Measured fail-open on a sixth arm
  reusing an existing message. Rejected.
- **Mark the try fall-through** (an early `return` in the broad-except arm, no flag). Measured
  fail-open on a naive new arm, byte-identical to the above. Rejected. The coverage objection
  originally used to reject the flag was backwards: the flag variant reaches 100% at 366
  branches with both arcs driven by real inputs.
- **An explicit `(outcome, violations)` tuple** threaded through `_scan_file`/`_scan_text`
  behind list-returning wrappers. Rejected on surface cost: an enum, two wrappers and new
  branches on a file under a REQUIRED 100% no-pragma gate, for a signal a subclass carries at
  the point the decision is made. Coverage is not the discriminator between the designs —
  every variant reaches 100%. Failure DIRECTION is.
- **Assert `attempted` rather than `scanned_ok`** (exclude exempt, ignore read failures).
  Leaves probe A at exit 1. Rejected.
- **Raise `_MIN_SCANNED_FILES`.** Rejected in #541 and again here: at 300 it sits 7 files above
  the `src/alfred` count against a tree that grew ~25 `.py` files in 30 days.

## Consequences

### Positive

- The census measures what its message claims, and what the gate exists to guarantee.
- Three previously-clearing shapes now refuse: mass-unreadable, all-exempt, and symlink
  inflation.
- A failure arm added years from now counts as a failure without anyone remembering to
  register it.
- Ergonomic cost is zero: 7375 tests pass with no existing test edited.

### Negative

- **The marker is lost by rebuilding the list** (`+`, a comprehension, `sorted()`,
  `list(...)`). Nothing between `_scan_text`'s return and `main`'s check does that today, and
  the direction of loss is fail-closed.
- **The name census cannot see `type(x)(...)` or `copy.copy(x)`** — both reproduce the class
  without spelling the name. No source-level instrument closes that; a runtime construction
  invariant on the #518/#520 pattern would.
- **A file partially scanned before a fault counts as failed.** Conservative and fail-closed.
- **`_is_exempt` is called twice per non-exempt file**, so the two calls could disagree if the
  filesystem changes mid-scan. Same shape as the accepted `stat`/`open` TOCTOU residual #546
  documented: it needs write access to the tree the gate is reading.
- **The census proves files were read and parsed, not that they were GATED.** 250 distinct
  files of `x = 1` clear it. Closing that needs an assertion about detector coverage, not
  about file counts.
- **`scanned_ok` inherits the build-sensitivity of the RecursionError→unscannable arm.**
  Measured identical at 331 across three CPython 3.14.6 builds, with 81 files of headroom, and
  any divergence makes the census stricter.
- **A real `tag(T3, ...)` finding alongside a mass read failure now exits 2, not 1.** The
  finding is still printed, under a header saying the scan did not complete.
- Explicit FILE arguments remain exempt from the census, unchanged. The call-site pin in
  `tests/unit/meta/test_gate_surfaces_are_pinned.py` is what stops that becoming a bypass.

### Neutral

- No runtime behaviour changes; this is an authoring-layer gate.
- Both invocation sites consume the exit code bare, so 1→2 changes no CI outcome. Verified
  repo-wide: nothing distinguishes exit 1 from exit 2.
- `_MIN_SCANNED_FILES` now governs two populations — collected (332) and distinct scanned
  (331). Both are stated at the constant.

## References

- [#547](https://github.com/alfred-os/AlfredOS/issues/547) — the issue, body rewritten
  2026-08-03 after ADR-0058 invalidated its original premise
- `docs/superpowers/specs/2026-08-03-547-census-counts-scanned-files-design.md`
- `docs/superpowers/plans/2026-08-03-547-census-counts-scanned-files.md`
- #518 / #520 — enumerate-vs-default-deny, and the runtime invariant that beat a static
  detector
- #538 — the sole-layer rules; #541 — scan-root ownership; #543 — the exit contract;
  #546 — the non-regular-file refusal
