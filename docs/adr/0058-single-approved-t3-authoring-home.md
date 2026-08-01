# ADR-0058 — One approved T3-authoring home, not two

- **Status**: Accepted
- **Date**: 2026-08-01
- **Slice**: #538 (`check_tag_t3` sole-layer rules — the raw-state-write vehicles and
  the authorisation-bypass names), Task 5
- **Relates to**: [ADR-0028](0028-boot-time-authorized-t3-nonce-registration.md) (the
  nonce gate this exempt set exists to protect), issue
  [#538](https://github.com/alfred-os/AlfredOS/issues/538) (the sole-layer rules whose
  measured baseline made the second exemption provably dead), issue
  [#547](https://github.com/alfred-os/AlfredOS/issues/547) (whose stated premise this
  decision invalidates — see Consequences)

## Context

`scripts/check_tag_t3.py` is a release-blocking required check
(`.github/workflows/pr-validate-python.yml`, job `tag-t3-grep`). It refuses
`tag(T3, ...)`, `TaggedContent[T3](...)` and `cast(TaggedContent[...])` anywhere in
`src/alfred/**` and `plugins/**` except inside a closed set of exempt files. That set has
two halves: an explicit frozenset of absolute paths, plus the repo's own
`tests/unit/security/**` tree (tests must be able to spell what the gate forbids).

The frozenset half was written in PR-S3-1 with two entries. Its second entry was
`src/alfred/security/quarantine.py`, carved out for `downgrade_to_orchestrator` — the
boundary that bridges `T3` to `T3DerivedData`. That justification stopped describing the
file at some point between PR-S3-1 and now, and nothing noticed, because an exemption
that is never exercised leaves no trace.

### What was measured

Issue #538 added nine new AST rules to the same gate — the raw-state-write vehicles
(`__dict__`, `__setstate__`, `__reduce__`, `__class__` in store context, `vars()`,
`X.__setattr__` receiver-blind, the vehicle name as a folded string, the carrier-by-
reference primitives) and the `alfred.security.tiers` private surface. Running that full
rule set over the file with its exemption removed:

| Property | Measured |
| --- | --- |
| Violations across 1634 lines | **0** |
| `tag(` calls | **0** |
| `TaggedContent[` constructions | **0** |
| New exemptions required elsewhere to keep the tree at rc=0 | **0** |

The exemption was not merely unnecessary. Its stated reason was already false: the file
it names does not construct T3 at all, by any spelling the gate models.

### Why an unexercised exemption is worse than no exemption

`security/quarantine.py` is 1634 lines in the highest-care subsystem, and it is where
untrusted extraction output is handled. An exemption there means the gate is structurally
incapable of reporting a T3-authoring line added to it — by anyone, in any future PR, for
any reason. The cost of that blind spot is paid continuously; the benefit was zero, and
had been zero for long enough that nobody could say when it stopped being non-zero.

Three artefacts still asserted the two-entry set as a live security invariant, one of them
inside the workflow that runs the gate, and one inside a unit test that stayed green while
saying it (its body only ever exercised `tiers.py`). A stale claim that a file may author
T3 is not a documentation defect; it is a reader being told the wrong thing about the
trust boundary by the gate's own contract.

## Decision

**`_APPROVED_PATHS` becomes a single-entry frozenset containing
`src/alfred/security/tiers.py`.** The authorised set for authoring T3 is now:

```text
src/alfred/security/tiers.py   — the tag() overload bodies, the home of the factory
tests/unit/security/**         — tests assert the gate's behaviour using the patterns
```

The exemption is **deleted, not narrowed**. Narrowing it — to a function, a line range, a
pattern — would leave a live soft-landing zone in the one module that had just been
measured not to need one, and every narrowed form still answers "yes" to some input. A
narrowed exemption is also the shape that decays quietly: it keeps passing while the
reason for it evaporates, which is exactly how the two-entry set survived this long.

Three tests pin the decision in
`tests/unit/security/test_check_tag_t3_sole_layer_rules.py`:

- `test_quarantine_is_no_longer_an_approved_path` asserts set equality against a literal
  pinned in the test file, so a re-added entry fails on the set, not on a membership
  probe that a second addition would slip past.
- `test_quarantine_scans_clean_without_its_exemption` runs `_scan_file` over the **real**
  file at its **real** path under the **full** rule set, and asserts `not _is_exempt(...)`
  in the same test body. Without that second assertion the pin passes on `main` for the
  opposite reason it exists — the exemption arm returns `[]` before anything is scanned.
- `test_tiers_still_needs_its_whole_file_exemption` is the anti-vacuity twin, and it
  discriminates on a **#538** message rather than on `assert violations`. The pre-existing
  `tag(T3` rule satisfies a bare truthiness assert, so the bare form would pass with every
  #538 rule deleted and could not tell a working detector from an empty diff.

A fourth test, `test_no_stale_claim_that_quarantine_is_an_authorised_home_survives`,
sweeps every tracked file paragraph-by-paragraph for a surviving claim. It is
paragraph-scoped rather than line-scoped because all three claims inside
`check_tag_t3.py` — the primary edit sites — wrap the qualifier onto a different physical
line from the filename, and a `git grep` sweep reports them clean.

The day a line in that module genuinely needs to author T3, the build fails loudly and
somebody records the decision. That is the point: re-adding the entry becomes a named,
reviewed act rather than an inheritance.

## Consequences

### Positive

- The gate now covers 1634 lines of the highest-care subsystem that it previously could
  not see. Zero new violations, so the coverage is free.
- The gate's own docstring, the release-blocking workflow's two contract comments, one
  unit-test name and docstring, one subscript-test name and one adversarial-test docstring
  all stop asserting an invariant that is not true.
- Deleting rather than narrowing means the exempt set is a one-line frozenset. There is no
  scope, no predicate and no second condition for a future reader to mis-evaluate.
- `_APPROVED_PATHS` at size one makes the remaining entry legible as what it is: the file
  that *defines* `tag()`, which cannot be gated by a rule about calling `tag()`.

### Negative

- **Issue [#547](https://github.com/alfred-os/AlfredOS/issues/547) is now designed against
  a false premise and must be re-measured before it is implemented.** Its body states that
  "`_scan_file` returns `[]` for the two `_APPROVED_PATHS` entries", and reasons from
  there that a fix to the `_MIN_SCANNED_FILES` census "could never fire in production" and
  that a correct fix must skip exempt paths in both numerator and denominator. There is
  one such entry now, and the second file is genuinely scanned and genuinely clean, so it
  counts as a real scan on both sides of that ratio. The premise also predates PR #549's
  `S_ISREG` change. Do not implement #547 against its body as written.
- The same stale premise is transcribed into
  `docs/superpowers/plans/2026-07-30-541-542-543-gate-hardening.md` at `:1458` and
  `:2757`. Those are dated records and are deliberately left alone; this ADR is the
  correction of record.
- A future legitimate need for a T3-authoring line outside `tiers.py` now costs a PR that
  argues for it, rather than a line in an already-exempt file. That is the intended cost,
  but it is a cost.
- The invariant is now asymmetric in an easy-to-misread way: `security/` is not exempt,
  one file inside it is. A reader who generalises "security code may author T3" is wrong,
  and the gate is the only thing that tells them so.

### Neutral

- No runtime behaviour changes. `downgrade_to_orchestrator` is untouched; this is an
  authoring-layer gate, and the module never used what the exemption permitted.
- The `tests/unit/security/**` half of the exempt set is unchanged and is not in scope
  here. It is matched by resolved path components, not by `_APPROVED_PATHS`.

## Alternatives considered

### Option A — narrow the exemption to `downgrade_to_orchestrator`

Rejected. The `(path, function)` exemption form already exists in this gate (it is how
`src/alfred/bootstrap/nonce_factory.py` is handled), so this was cheap to build. It was
rejected because the function it would scope to does not author T3 either — the narrowing
would have been a live exemption with no live user, which is the same defect in a smaller
box. It also reads as a considered decision to a future reviewer, when in fact nothing
would have been considered.

### Option B — leave the exemption, fix only the stale prose

Rejected. This was the minimum change that makes every document true, and it was the
tempting one: the exemption is dormant, so it costs nothing today. It fails on the same
argument that produced #538 in the first place — the gate's blind spot is the thing that
matters, and the prose is downstream of it. Fixing the prose while keeping the hole
documents the hole accurately, which is worse than useless: it converts an accident into
a design.

### Option C — write no ADR

The docs reviewer read the same evidence and concluded no ADR was required, on the
grounds that nothing in this change goes stale — the code and its tests are
self-describing, and an ADR is one more artefact to keep true. That reading is
defensible and is recorded here rather than dropped.

It was not taken because the exempt set is a structural invariant of a release-blocking
gate, CLAUDE.md requires an ADR whenever one of those changes, and no existing ADR names
`_APPROVED_PATHS` at all. Before this record, the gate's own module docstring was the sole
source of truth for the exempt set — and that docstring was, at the moment this was
written, false. A single source of truth that has already been observed to drift is the
argument for the second one.

## References

- `scripts/check_tag_t3.py` — `_APPROVED_PATHS`, `_is_exempt`, `_view_is_exempt`
- `tests/unit/security/test_check_tag_t3_sole_layer_rules.py` — the four pins above
- `.github/workflows/pr-validate-python.yml` — job `tag-t3-grep`, the release-blocking
  invocation
- [ADR-0028](0028-boot-time-authorized-t3-nonce-registration.md) — the per-process nonce that
  makes `tag_t3_with_nonce` the only runtime path to a `TaggedContent[T3]`
- `docs/superpowers/plans/2026-08-01-538-check-tag-t3-sole-layer-rules.md` — the measured
  baseline this decision rests on
