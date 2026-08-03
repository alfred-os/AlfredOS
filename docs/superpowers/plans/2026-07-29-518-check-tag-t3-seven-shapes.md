# #518 — teach `check_tag_t3.py` the seven T3-construction shapes

**Issue:** #518 (REOPENED — PR #534 closed only the runtime root cause)
**Depends on:** PR #534 (merged, `bcad7103`) — the runtime invariant
**Scope:** `scripts/check_tag_t3.py` + its unit suite. No `src/` change expected.

## Why this exists when the runtime invariant already refuses all seven

PR #534 made a `T3` object unconstructable off the nonce path, so **none of the
seven shapes can reach production**. This work is not defence-in-depth theatre —
the two layers fail at different times and catch different things:

| | Runtime invariant (#534) | CI detector (this PR) |
| --- | --- | --- |
| Fires when | the line **executes** | the line is **written** |
| Blind spot | an unexercised branch in `src/` ships unrefused until it runs | only shapes it was *taught* |
| Fails | a running system | the author's build |

Hard rule #3 ("every function that ingests external content tags it `T3` at the
boundary") is written against the authoring layer. A detector that models one of
eight shapes does not enforce it.

## Design

### The alias environment (what makes shapes 6 and 7 tractable)

Two of the seven exist *because* names are not statically resolvable. A
per-file, fixed-point alias environment closes the resolvable subset:

- `tagged_names` — seeded `{"TaggedContent"}`, extended by
  `from … import TaggedContent as X` and `X = TaggedContent`.
- `t3_names` — seeded `{"T3"}`, extended the same way.

Fixed-point iteration (not a single source-ordered pass) so a chain
`B = A; A = TaggedContent` resolves regardless of textual order.

### Rules

Additive — the three existing rules (`tag(T3, …)`, `cast(TaggedContent[…]`,
suppression comment) keep their current messages.

**R1 — unparameterised construction.** A `Call` whose `func` is a bare
`Name`/`Attribute` resolving into `tagged_names` (i.e. **not** a `Subscript`).

Covers shape 1 (`TaggedContent(tier=T3, …)`) without resolving the tier at all,
and therefore also covers `tier=_ALIAS` and `**payload`. Justified beyond shape
1: `tiers.py:236` short-circuits the cross-tier guard when the generic args are
empty, so an unparameterised construction bypasses the tier/generic cross-check
for *every* tier, not just T3.

**R2 — unvalidated / deserialising seams.** `Attribute` call with
`attr ∈ {model_construct, model_validate, model_validate_json}` whose receiver is
TaggedContent-ish (bare name in `tagged_names`, or a `Subscript` over one).

Covers shapes 2–4. Deliberately **tier-agnostic**: at these seams the tier is
*data* (`model_validate(payload)`), not a static token, so the detector cannot
know what tier is being minted. Refusing the whole seam is the only fail-closed
answer. `super().model_construct(…)` (the receiver in `tiers.py`'s own
overrides) does not resolve to a name and is unaffected.

**R3 — tier-mutating copy.** `attr == "model_copy"` with **either** a
TaggedContent-ish receiver **or** a `update={…}` literal containing a `"tier"`
key — the value is not inspected, because it is usually a variable.

Covers shape 5 on an *instance* receiver (`lower.model_copy(update=…)`), where
receiver-scoping is impossible by construction.

**R4 — subscript slice widening.** Extend the existing subscript rule:
`value` resolves via `tagged_names` (shape 6), and the slice trips when it
resolves via `t3_names` (shape 7), is `Constant("T3")` (existing), **or is a
name not in the known-benign tier set `{T0, T1, T2}` + their aliases**
(fail-closed on an unresolvable slice).

**R5 — widen the suppression regex.** `# type: ignore` → also
`# pyright: ignore` and `# noqa`, each with or without a bracketed/colon code
list.

**R6 — narrow the `quarantine.py` exemption** from whole-file to
`downgrade_to_orchestrator` only, via a parent map + enclosing-function walk.
`tiers.py` stays whole-file (it *is* the factory's home).

### Named limitations — what this guard CANNOT do

Stated in the module docstring, per the lexical-vs-runtime rule. Each is closed
by the runtime invariant, and the docstring says so:

- cross-module aliasing (`from mymod import TC` where `mymod` re-exports),
- `getattr(tiers, "TaggedContent")`, dict-of-classes, factory returns,
- a `tier` arriving through `**kwargs`,
- `model_copy(update=<variable>)` on a non-TaggedContent receiver — flagging
  every such call across the core is an ergonomics tax the runtime gate makes
  unnecessary.

## Non-vacuity floors (a "flag everything" detector must fail the suite)

1. The real `src/alfred/` tree passes clean — includes the **34** legitimate
   pydantic-seam sites outside the exempt `tiers.py` (`model_validate` 26,
   `model_validate_json` 6, `model_copy` 2) and the 2 legitimate `model_copy(update=…)`
   sites. The "26 + 2" written here was wrong and the scan root has since widened to
   include `plugins/` (re-measured 2026-08-03 across all 332 tracked files). **ZERO** of
   those 34 has a `TaggedContent`-shaped receiver, which is what makes receiver-scoping
   false-positive-free — and what refutes the wire-round-trip argument for a
   tier-agnostic seam rule.
2. `TaggedContent[T2](…)`, `schema.model_validate(…)`,
   `notification.model_copy(update={"wire_seq": …})` each pass explicitly.
3. The real `tiers.py` and `quarantine.py` pass.
4. A `# noqa` on a **non**-`TaggedContent` line passes.

## Testability seam for R6

The `quarantine.py` exemption is keyed on resolved-absolute-path equality, so a
`tmp_path` copy is not exempt and cannot exercise function-scoping. Split
`_scan_file` into read + `_scan_text(text, path)`; the test imports the script
and feeds *mutated real `quarantine.py` text* under the *real* path:

- violation planted at module scope → trips,
- the same violation planted inside `downgrade_to_orchestrator` → exempt,
- unmutated real text → clean.

## Mutation-test protocol (non-negotiable per #245)

For each of the 7 shapes plus R5 and R6: plant the violation, confirm the
detector **reds**; remove it, confirm **green**. Then invert — disable each new
rule in turn and confirm at least one test fails. A surviving mutant means the
rule is decorative.

## Steps

1. Alias environment + parent map helpers.
2. R4 (extends existing rule) — 7 tests inc. benign-tier floors.
3. R1, R2, R3 — per-shape tests, one named test per shape.
4. R5 suppression widening + non-`TaggedContent`-line floor.
5. R6 function-scoped exemption via `_scan_text` seam.
6. Repo-wide non-vacuity floor test; run detector over real `src/alfred`.
7. Mutation-test sweep (all rules, both directions).
8. Docstring limitations + `docs/` touch-ups if the rule list is documented
   elsewhere.
9. `make check`; i18n catalog regeneration **only if** a `t()`-bearing file was
   touched (not expected — this is a stdlib-only script).
