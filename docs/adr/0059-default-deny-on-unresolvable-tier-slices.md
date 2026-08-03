# ADR-0059 — Default-deny on a tier slice the authoring gate cannot read

- **Status**: Accepted
- **Date**: 2026-08-03
- **Slice**: #539 (`check_tag_t3` — the seven T3-construction shapes, the tier alias
  environment and the suppression widening), the last step of epic #536
- **Relates to**: [ADR-0058](0058-single-approved-t3-authoring-home.md) (the exempt set
  this decision leans on and does not change),
  [ADR-0028](0028-boot-time-authorized-t3-nonce-registration.md) (the nonce gate both
  layers exist to protect), issue
  [#539](https://github.com/alfred-os/AlfredOS/issues/539), issue
  [#536](https://github.com/alfred-os/AlfredOS/issues/536)

## Context

`scripts/check_tag_t3.py` is a release-blocking required check. Until #539 its
subscript rule asked one question — *is this generic argument the identifier `T3`?* —
and answered **no** for every shape that was not a bare `Name` or the string `"T3"`.

That is a two-valued verdict over a three-valued question, and the missing value is
"I could not read this". A rule with nowhere to put that answer has to fold it into one
of the other two, and it folded it into **clean**:

| slice | before #539 | reaches a real T3 construction |
| --- | --- | --- |
| `TaggedContent["T" + "3"]` | clean | yes |
| `TaggedContent[globals()["T3"]]` | clean | yes |
| `TaggedContent[TIERS["T3"]]` | clean | yes |
| `TaggedContent[T3 if x else T2]` | clean | yes |
| `TaggedContent[(T3,)]` | clean | yes |

None of these is a live hole: the runtime invariant shipped by #534/#535 refuses every
one of them, and the security review re-verified that independently (19/19 green, each
refusal carrying a `security.t3_boundary.refused` audit row). But the authoring layer
fires when a line is **written** and the runtime fires when it **executes**, and an
unexercised branch in `src/` ships unrefused until it runs. A detector that models one
spelling of eight does not enforce hard rule #3.

The same shape recurred **inside the fix**. The first revision of the alias environment
classified derived bindings with a two-way ternary over the three-valued verdict:

```python
bucket = t3_seeds if _slice_verdict(...) is T3 else benign_seeds
```

Every `UNRESOLVED` went to the benign side, so all five rows above scanned clean again
once bound to a name (`X = TaggedContent["T" + "3"]`; `X(content=ATTACKER)`) while the
identical inline slice correctly red. Being a conditional *expression*, it was also
invisible to the file's required 100% branch gate — `coverage.py` does not branch on a
ternary. Four independent reviewers found it; it was confirmed by execution.

## Decision

**A tier slice the gate cannot resolve is REFUSED, and the verdict that says so is a
first-class value carried end to end.**

1. `_slice_verdict` is **total** over `ast.expr` and returns one of three verdicts —
   `T3`, `BENIGN`, `UNRESOLVED` — written as an allow-list over the two shapes the gate
   can read, with everything else falling through to `UNRESOLVED`.
2. Parameterised bindings travel as a **verdict map** (`Mapping[str, _SliceVerdict]`),
   never as one set per verdict. A set-per-verdict has no home for the verdict that has
   no set, which is what forces the collapse above.
3. Where two bindings disagree, the **stricter** verdict wins
   (`T3 > UNRESOLVED > BENIGN`), so a name cannot be walked back down to benign by a
   second assignment.
4. A name bound both bare and parameterised is **ambiguous**, and is raised to at least
   `UNRESOLVED`.
5. `UNRESOLVED` reports its own distinct message, so a shape test can never be satisfied
   by the wrong rule firing.

**The relief valve is the benign tier sets, and it is what makes this affordable.**
`T0`/`T1`/`T2` are alias-resolved, and in-file generic tier parameters (PEP-695
`type TierT = TrustTier` and `TypeVar(..., bound=TrustTier)`) are seeded as benign.

## Consequences

### Positive

- The five shapes above are refused as a **class** rather than one spelling at a time.
  Round-2 probes could not bypass the rule.
- Measured ergonomic cost across the 332 tracked files under both scan roots: **zero**.
  The only non-`T0..T3` slices in the tree are `TaggedContent[TierT]` ×3, `[Any]` ×1 and
  `[tier]` ×1, and all five are inside the whole-file-exempt `security/tiers.py`.

### Negative — the ergonomic contract, stated so it is not discovered

- **The first generic tier helper written OUTSIDE `security/tiers.py` reds unless its
  type parameter is bound to `TrustTier`.** That is the intended cost of the relief
  valve being narrow, but it is a cost, and it will be paid by whoever writes that helper
  rather than by whoever chose this posture.
- **A plain parameter is not rescued by anything lexical.** `security/tiers.py:949` is
  `TaggedContent[tier](...)` where `tier` is a function parameter. No name-keyed set can
  decide what a caller passed, and the same applies to
  `def f(T2): TaggedContent[T2](...)` where the caller passes `T3` — the gate reads `T2`
  as benign. Masked by the runtime guard, which is what makes it a residual rather than
  a hole.
- **A `# ruff: noqa` or `# mypy: ignore-errors` anywhere in a module that mentions
  `TaggedContent` now reds.** File-wide suppressors are scoped to the file, because that
  is what they do. `docs/python-conventions.md` gains a carve-out saying so.

### The escape hatch, and it is the only one

A legitimate future need to construct `T3` outside the approved home belongs behind a
**named helper inside the already-exempt `security/tiers.py`**, not behind a loosened
rule here. This is ADR-0058's escape hatch, restated because #539 widens what "loosened"
would cost: a rule relaxed to admit one caller admits every caller that can spell the
same shape, and the relaxation is invisible at every site that later depends on it.

### Neutral

- No runtime behaviour changes. This is entirely an authoring-layer decision.
- The exempt set is untouched — ADR-0058 remains the record of what it is and why.
- `scripts/check_tag_t3.py` stays at 100% line+branch with no pragmas. One guard whose
  branch measurement proved unreachable (a `NEWLINE` token arriving with no logical-line
  span open — zero occurrences across 15 edge-case spellings and all 332 tracked files)
  became an `assert`, on the precedent `_enclosing_functions` already set in that file.

## Alternatives considered

- **Keep the two-valued verdict and enumerate the bad slice shapes.** Rejected: an
  enumeration closes what it names and silently widens the day the grammar grows a shape.
  `ast.TypeAlias` already did exactly that to the binding scan during this work.
- **Scope annotation immunity with an ancestor blacklist** instead of the one-position
  `Call.func` whitelist. Rejected on the stronger ground rather than the obvious one: a
  correctly scoped `.annotation`-subtree blacklist regresses nothing today, but it must
  ENUMERATE annotation-bearing positions, and the whitelist cannot go stale. It protects
  22 annotation sites across 5 files, 13 of them outside any exempt file.
- **Make the construction-seam rule tier-agnostic** (the original plan's position).
  Rejected by measurement twice over: the wire-round-trip argument for it is false at
  **0** sites, and a tier-agnostic form fires on
  `test_model_construct_still_works_for_a_lower_tier` — a floor this repo explicitly
  named "still works". A naked, non-receiver-scoped form is worse still, at 34 false
  positives.
