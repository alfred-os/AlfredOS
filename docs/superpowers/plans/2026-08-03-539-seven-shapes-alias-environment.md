# #539 — the seven T3-construction shapes, alias environment and suppression widening

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.

**Issue:** #539 (step 3 of 3 under epic #536; steps 1 #537 and 2 #538 are MERGED)

**Base:** `main` @ `054c13f7`

**Goal:** Teach `scripts/check_tag_t3.py` the seven T3-construction shapes at the AUTHORING
layer, resolved through a per-file tier alias environment, with the subscript slice decided
by a TOTAL default-deny function and the suppression rule widened to `# pyright: ignore` /
`# noqa` and friends via `tokenize`.

**Architecture:** A per-file `TierAliasEnv` built entirely from the EXISTING seed-parameterised
`_alias_names` — no second resolver (#422). Parameterised bindings are carried as a **verdict
MAP**, not as one set per verdict, because a set-per-verdict silently drops the verdict that
has no set. `_slice_verdict` is a total function over `ast.expr` returning one of three
verdicts and default-denying on SHAPE. Suppression detection moves off a line regex onto
`tokenize`, anchored at the start of a real COMMENT token and scoped to the enclosing LOGICAL
line.

**Tech Stack:** stdlib only (`ast`, `enum`, `io`, `re`, `tokenize`). The gate runs under bare
`python3` from the Makefile with no venv, so it may import nothing outside the standard
library and must do no filesystem I/O at import time. Its own interpreter floor is **3.12**,
not the repo's 3.14 — `ast.TypeAlias` and PEP-695 `type X = …` parsing are what set it — and
that distinction matters precisely because the interpreter here is whatever `python3` resolves
to on the contributor's machine rather than the pinned venv.

---

## Priority framing — read before writing a line

**All seven shapes are ALREADY REFUSED AT RUNTIME.** Round-2 probes ran 32 spellings against
the live runtime; every one of S01–S08 is refused. The security review re-verified this
independently: the runtime oracle is **19/19 green**, and every bypass listed in the review
disposition below is still refused by `tiers.py` with a `security.t3_boundary.refused` audit
row. **None of them is a live T3 mint.**

This step is therefore **defence-in-depth**, deliberately sequenced last. The issue explicitly
refutes the older plan's R1 justification:

> The old plan claimed `tiers.py`'s empty-generic short-circuit means unparameterised
> construction "bypasses the tier/generic cross-check for *every* tier". True for the
> cross-check, **irrelevant for T3** — `_refuse_unauthorized_t3` fires regardless of
> parameterisation.

The layers still differ usefully: one fires when the line **executes**, the other when the
line is **written**, and an unexercised branch in `src/` ships unrefused until it runs. But
**the ergonomic cost must stay at ZERO**, and no rule may be justified by a claim that does
not survive measurement.

## Global constraints

- **`scripts/check_tag_t3.py` is under a REQUIRED 100% line+branch coverage gate, no pragmas.**
  Do not touch `exclude_also`; `exclude_lines` REPLACES `DEFAULT_EXCLUDE`.
- **Never launder a dead branch into a ternary.** `coverage.py` branch analysis works on the
  statement graph, so neither arm of a conditional *expression* is tracked. Precedents in the
  file: `assert X is not None`, or an explicit `if`/`else` with `# noqa: SIM108`.
- **`mypy --strict` and `pyright` both run over this file.** Use `getattr(node, "lineno", 1)`
  where the static type is `ast.AST`. Declare `frozenset[str]` parameters and pass
  `frozenset`, never `set` — see finding py-001.
- **Every keyed identifier must be alias-resolved** and must gain a row in
  `test_every_keyed_identifier_is_alias_resolved` (which DERIVES its identifier set from the
  gate's own AST) or an entry in `_DECLARED_ALIAS_RESIDUALS` with a stated reason. The guard
  reds in BOTH directions: an unexcused identifier fails, and a residual the derivation never
  produces also fails.
- **Per-rule DISTINCT messages**, and every negative floor needs a positive twin.
- **Mutation-test every guard, both directions.** Each mutant must red a **named** floor.
- **Commit subjects must contain `#539` somewhere after the colon.** The gate's regex is
  `^[a-z]+(\([^)]+\))?(!)?: .*#[0-9]+.*$` — read it rather than trusting a summary of it;
  an earlier draft here (and a project-memory note) claimed the reference had to come
  IMMEDIATELY after the colon, which the regex does not require. `refactor: … (#539)`
  passes just as `fix: #539 …` does.
- **AUTO-CLOSING is a separate mechanism from the gate.** GitHub closes an issue when the
  subject reads as a closing keyword plus a reference — `fix: #539 …` parses as `fix #539`.
  `refactor:`/`test:`/`docs:` with `(#539)` satisfy the gate and close nothing, which is why
  the intermediate commits use them and exactly one commit carries the closing form. #518
  closed twice with work undone (finding arch-003).
- **i18n:** stdlib-only script, no `t()`. No catalog regeneration expected.

### The real verification commands

Finding ops-001 / rev-003 / py-00x: `[tool.coverage.run] source = ["src/alfred"]`, so a bare
`coverage run -m pytest` never measures `scripts/`. The plan's original command printed
`No data to report.` CI populates the dataset in a PRIOR step and then reports on it:

```bash
uv run pytest tests/unit -q --cov=src/alfred --cov=scripts --cov-report= \
  && uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100 -m
```

Note it runs the WHOLE `tests/unit` tree, not just `tests/unit/security/` — which also closes
finding ops-008 (`tests/unit/meta/` was never in the per-task commands).

Markdown lint is a required check that globs `**/*.md` and does **not** exclude
`docs/superpowers/plans/` (finding ops-010). `make docs-check` DOES exclude it, so a green
`make check` is not evidence for that gate. Run it directly:

```bash
npx --yes markdownlint-cli2 "docs/superpowers/plans/2026-08-03-539-seven-shapes-alias-environment.md"
```

---

## Review disposition

Eight specialist reviewers ran against the first draft of this plan. The design survived; the
written artifact did not. Every finding below was reproduced by execution before being
accepted, and the corrected design was re-validated the same way.

### Critical — accepted and closed in the design

| ID | Finding | Closure |
| --- | --- | --- |
| arch-001 = err-001 = sec-001 | `bucket = t3_seeds if verdict is T3 else benign_seeds` routes **UNRESOLVED into the benign bucket**. Default-deny rows go clean once bound to a name (the shipped suite parametrises seven such shapes). Executed: `X = TaggedContent["T"+"3"]` then `X(...)` scans clean while the inline slice reds. | A verdict **MAP** replaces the two sets. A map cannot lose a verdict. The ternary — which is also what hid the arm from the branch gate — is gone. |
| sec-002 | `tc_bare ∩ tc_param` unchecked: `Cool = TaggedContent[T2]; Cool = TaggedContent; Cool(tier=T3)` returns BENIGN and silences R1. | A name bound BOTH bare and parameterised is ambiguous, so its verdict is raised to at least UNRESOLVED. |
| sec-003 | `_TRUST_TIER_NAME` was a bare literal on the **admitting** side: `TrustTier = T3; type TierT = TrustTier` admits T3. The proposed residual ("rebinding makes the gate STRICTER") was false in every direction. | `TrustTier` is alias-resolved, and a bound whose name resolves into `t3` is refused. Both legitimate TypeVar spellings stay clean. |
| sec-004 | `_slice_verdict`'s string arm matched the raw seed tuple while its Name arm was alias-resolved, so `T2 = T3; TaggedContent["T2"](...)` was clean while `TaggedContent[T2](...)` red. | A quoted generic is a forward-referenced NAME: the string arm now resolves through the SAME sets. |
| arch-007 = err-007 = sec-005 | The binding scan enumerated `ast.Assign` only, so `X: TypeAlias = TaggedContent[T3]`, PEP-695 `type X = …` and the walrus escaped. | Default-deny over BINDING SHAPES (`Assign`, `AnnAssign`, `TypeAlias`, `NamedExpr`). |
| sec-006 | R3's `ast.Dict` key missed `dict(tier=T3)` and `{**{"tier": T3}}`. | `_mapping_mentions_tier` is total over the mapping shapes a copy seam accepts, and default-denies an unreadable `**`. |
| arch-002 = doc-001 | The four new `_*_MESSAGE` constants red `test_the_corpus_record_matches_the_shipped_rule_set`, which derives its vocabulary from `vars(check_tag_t3)` in BOTH directions. The plan named neither corpus file. | Task 7 updates `tl_base_dispatch_and_raw_state_write.yaml` and the `tl-2026-013` README row. |
| doc-002 | The plan edited `2026-07-30-541-542-543-gate-hardening.md:1458,2757` — the exact pair **ADR-0058 decided to leave alone**: *"Those are dated records and are deliberately left alone; this ADR is the correction of record."* | **Those edits are dropped.** ADR-0058 outranks the session's suggestion. ADR-0058 also says *"Do not implement #547 against its body as written"*, so #547 needs a body rewrite, not a count patch — out of scope here. |
| rev-002 | Task 3 appended in-process tests to `test_check_tag_t3_subscript.py`, which is entirely **subprocess-based** and binds neither `check_tag_t3` nor `_messages`. All eight would `NameError`, and subprocess suites record 0% coverage. | R4's tests go in the new in-process suite. |
| rev-001 | `_messages()` returns `"{path}:{lineno}: {message}"`, so every `MESSAGE in _messages(...)` assertion fails and every `not in` assertion is **vacuously true**. | All assertions use the established forms: `_messages(src) == [f"{_PROBE}:1: {MSG}"]` or `any(MSG in m for m in _messages(src))`. |
| py-003 | Deleting `_is_tagged_content_t3_subscript_call` and `_TYPE_IGNORE_PATTERN` breaks `test_check_tag_t3_gate_integrity.py` — a file the plan never listed. One reference errors; the other goes **silently vacuous** (an `_Exploding` fault-injection stand-in duck-typing `.search()`). | Task 6 updates that suite explicitly, and asserts the fault-injection stand-in still injects. |

### High — accepted

| ID | Finding | Closure |
| --- | --- | --- |
| arch-003 = ops-006 = doc-008 | "ONE PR" was declared, then three branches were pushed and three PRs merged — and `feat: #539` on the first would auto-close the issue with two thirds unbuilt. **This is the #518 failure #536 exists to correct.** | One branch, one push, one PR, one merge. Only the final commit carries the auto-closing subject. |
| ops-004 = py-002 = sec-008 = rev | The totality test cannot run: `expr_type()` builds field-less nodes and `ast.Constant().value` raises `AttributeError` on 3.14.6 — on exactly the three node types `_slice_verdict` reads. | Totality is asserted over REAL parsed slices plus a structural check that the function has no `raise` and ends in a `return`. |
| arch-011 = ops-005 = err-003 = sec-007 = py-007 | `test_an_untokenizable_file_is_reported_not_swallowed` is a paper gate: `"x = (\n"` fails `ast.parse` first, so tokenize never runs and mutation row 7 survives its own floor. py-007 searched and found **no input that parses but fails to tokenize**. | **No separate arm.** The tokenize pass sits inside the existing `try`, so a `TokenError` is reported by the existing `_UNSCANNABLE` arm. No unreachable branch, no paper gate, mutation row 7 deleted. |
| sec-010 | The named prose floor `# noqa is the wrong tool…` **starts with** `noqa`, so it is a real bare-noqa directive and the anchored pattern correctly trips — while the floor asserted clean. The plan contradicted itself. | Prose fixture replaced with one that does not begin with the anchor. |
| sec-011 | `# ruff: noqa`, `# flake8: noqa` and `# mypy: ignore-errors` — the STRONGEST suppressors — were invisible. | Anchor widened to cover all of them. |
| ops-002 = py-008 | `"bound"` (from `k.arg == "bound"`) reaches the derived identifier set and is excused nowhere. | Residual entry added. |
| ops-003 | Residuals for `type`/`pyright`/`ignore`/`noqa` are **dead** — the derivation never produces them — tripping the guard's no-dead-residuals assertion. | Only identifiers the derivation actually produces get residuals; verified by running `_identifiers_the_gate_keys_on` against the final source. |
| err-004 | `_slice_verdict` straddles the `GateInternalError` fence: exit 2 via `_detect`, exit 1 via `_tier_alias_env`. The #543 err-001 shape reintroduced. | The function is provably total with no raise path, and the docstring records which side of the fence each caller sits on. |
| py-004 | 7 lines / 11 branch arcs uncovered, worst being `_trust_tier_type_aliases`'s `TypeVar(..., bound=…)` arm — **the test was named for that arm but its fixture exercised the other one.** A vacuity. | Both spellings get their own fixture. |
| arch-005 | `test_the_benign_tier_seeds_match_the_real_module` was named but never written, and its cited precedent was misread. | Written, against the real `tiers.py`. |
| doc-003 | The corpus payload's residual "`TaggedContent.model_construct(...)` is refused at RUNTIME only" is exactly what R2 closes; #536's DoD required rewriting it. | Task 7. |
| doc-004 | The third wrong count lives in `2026-07-29-518-check-tag-t3-seven-shapes.md:96-97`, not the constraints doc. | Task 7 targets the right file. |
| arch-008 = rev | `_TAGGED_SEAM_ATTRS ∪ _COPY_SEAM_ATTRS` is a third copy of `_BASEMODEL_SEAM_ATTRS` (#422). | The two new sets are DERIVED from the existing one by partition, with the partition asserted. |
| rev | The oracle's `split(":", 2)` breaks on the required `windows-latest` leg (drive letters). | Parse from the right with `rsplit`, or match on the known path prefix. |
| ops-007 = sec-009 = py-009 | The derived-seed `_alias_names` loops pass the meta-guard only by loop-variable **name collision** (`seed`); a rename hard-reds it. | Kept as `seed` deliberately, with a comment saying why, and a test that pins it. |
| err-002 | The `env_overflow` → `_ALIAS_BUDGET_MESSAGE` wiring was prose-only, with no test and no mutant. | Wired, tested, and mutated. |
| ops-010 | Markdown lint globs `**/*.md` without excluding plans; this doc alone had 30 errors and would red a required check. | This rewrite is markdownlint-clean; verified in Task 8. |
| err-005 | The 97-FP floor passed only because standalone comments emit `NL`, not `NEWLINE` — and the plan's own degenerate-span fix would have broken it. | The span lookup falls back to the comment's own line, and both shapes are tested. |

### Accepted with a stated position, not silently dropped

- **arch-006 vs doc: does #539 need an ADR?** Disputed. The architect says the fail-closed
  slice posture plus the escape-hatch policy is a structural decision of the kind #538 recorded
  in ADR-0058; the docs reviewer says #539 adds rules to a gate, not an invariant, and ADR-0058
  already records the exempt set #539 does not touch. **Resolved toward the architect**: the
  posture has an ergonomic contract (the first generic helper written outside `tiers.py` reds
  unless its TypeVar is bound to `TrustTier`), and a future author who hits that red deserves a
  record. Task 7 writes a short ADR-0059.
- **arch-010: split R5 into its own PR.** Declined for this delivery — one PR was the explicit
  instruction. The architect's reasoning is sound (R5 shares no alias set, rule or `_detect`
  signature) and is recorded here for the next reader.
- **doc-006:** `docs/python-conventions.md:171` recommends `# pyright: ignore`, which R5 bans on
  `TaggedContent` lines. Cost is zero today, but the guidance is now narrower than the rule.
  Task 7 adds the one-line carve-out.
- **doc-009:** the position partition sums 2 + 22 = 24 of 25 subscripts. The 25th is
  `tiers.py:660` (`vars(TaggedContent[T0])`, a Call **argument**). Exempt and harmless, but
  Task 3's annotation-immunity argument turns on `Call.func` being the only position read, so
  the argument is stated precisely rather than as a partition.
- **doc-005:** two further stale `_APPROVED_PATHS` sites at `:2791`/`:2829`. Same ADR-0058
  disposition as doc-002 — dated records, left alone.
- **err-006:** two incompatible placements for the tokenize pass. Resolved: the pass runs where
  the old line loop ran (after the AST walk), so findings already collected are APPENDED to,
  never discarded. Distinguishing fixture `"tag(T3, x)\n\r\r"` is in the suite.
- **err-008:** the oracle's clean half gains an assert-RAN control and stops `continue`-ing
  silently on unparsed lines.

### What the reviewers verified as sound

- **All 62 behavioural cases pass** against a spliced prototype, and the real tree scans
  **clean at 332 files / 0 violations** with R1–R4 wired in (python reviewer, executed).
- **Every measurement in this plan reproduces exactly** — independently re-derived by the docs
  reviewer, zero stale numbers.
- **The independent oracle passes as specified**: 7/7 trip, 4/4 clean (security reviewer).
- **No prompt-injection** in the plan text; the `REQUIRED SUB-SKILL` preamble is the repo's
  standard template, present in 132 of 142 plan docs.
- CRLF-safe on the Windows leg; no workflow edited so no gate job can skip; the two new suite
  files are genuinely gated by four required checks; `pybabel` never reads `scripts/`.

---

## Measurements

Taken 2026-08-03 against `main` @ `054c13f7`, and independently reproduced by the docs
reviewer. **The false-positive cost of every rule is ZERO outside the whole-file-exempt
`src/alfred/security/tiers.py`.**

| Quantity | Measured |
| --- | --- |
| Files collected by `_collect_paths([])` | 332 |
| Exempt files in that set | 1 (`security/tiers.py`; `quarantine.py` deleted by #538) |
| Bare `TaggedContent(...)` calls (R1 surface) | 0, anywhere |
| Copy seams with a `"tier"` key (R3 surface) | 0 |
| Seam calls with a TaggedContent-shaped receiver (R2 surface) | 0 |
| Seam calls outside `tiers.py` (a NAKED tier-agnostic R2's cost) | 34 (`model_validate` 26, `model_validate_json` 6, `model_copy` 2) |
| `TaggedContent[...]` subscripts | 25 (T3 11, T2 4, T1 3, TierT 3, T0 2, Any 1, tier 1) |
| …in `ast.Call.func` position | 2 |
| …in annotation position | 22 across 5 files |
| …the 25th | `tiers.py:660`, a Call **argument** (doc-009) |
| Non-`T0..T3` slices | 5, all inside exempt `tiers.py` |
| Naive top-level-alternation suppression regex | 98 hits vs 1 correctly grouped → **97 pure FPs** |
| `tokenize`-anchored real suppressors | `noqa` 92, `type: ignore` 76, `pyright: ignore` 0 |
| Corrected R3 on the real tree | **0 hits** |
| Corrected R5 on the real tree | **1 hit**, in exempt `tiers.py` — same as today |
| Oracle file under a synthetic non-exempt path | 0 violations |

The five annotation-bearing files are `plugins/content_store_base.py` (5),
`orchestrator/core.py` (4), `security/quarantine_transport.py` (3),
`comms_mcp/real_turn_adapter.py` (1) and exempt `security/tiers.py` (9).
**`orchestrator/core.py` and `comms_mcp/real_turn_adapter.py` are NOT exempt and the
constraints doc never lists them** — they are why annotation immunity is load-bearing.

## The independent oracle

`tests/unit/security/test_t3_construction_requires_the_nonce_path.py` states all seven shapes
as executable source and scores 0 violations today.

**Must each yield ≥1 violation** (7), as LITERALS:

- `test_bare_keyword_construction_is_refused`
- `test_model_construct_is_refused`
- `test_model_validate_is_refused`
- `test_model_validate_json_is_refused`
- `test_model_copy_update_to_t3_is_refused`
- `test_renamed_import_subscript_is_refused`
- `test_non_literal_generic_argument_is_refused`

**Must each yield ZERO violations** (4). Note this set is larger than a `*_still_works` suffix
glob finds — `test_model_construct_still_works_for_a_lower_tier` does not END with it:

- `test_the_authorised_path_still_works`
- `test_a_lower_tier_is_unaffected`
- `test_model_construct_still_works_for_a_lower_tier`
- `test_model_copy_still_works_when_not_touching_the_tier`

`test_model_construct_still_works_for_a_lower_tier` is `TaggedContent[T2].model_construct(...)`.
**It is the whole argument for R2 being slice-discriminating**: a receiver-scoped but
tier-AGNOSTIC R2 fires on a floor the repo explicitly named "still works". Discrimination costs
nothing and saves a named benign floor. The wire-round-trip argument the old plan gave for
tier-agnosticism is measurably false: 0 TaggedContent-receiver seam sites.

## File structure

- **Modify `scripts/check_tag_t3.py`** — the whole mechanism plus the docstring residual block.
- **Create `tests/unit/security/test_check_tag_t3_seven_shapes.py`** — the alias environment,
  `_slice_verdict`, R1–R4, the independent oracle. A new in-process file, because
  `test_check_tag_t3_subscript.py` is subprocess-based (rev-002).
- **Create `tests/unit/security/test_check_tag_t3_suppression.py`** — R5's cases.
- **Modify `tests/unit/security/test_check_tag_t3_sole_layer_rules.py`** — move `TaggedContent`
  and `T3` from `_DECLARED_ALIAS_RESIDUALS` into `_KEYED_IDENTIFIER_SPELLINGS`, add the new
  residuals, narrow the tripwire test.
- **Modify `tests/unit/security/test_check_tag_t3_gate_integrity.py`** — py-003.
- **Modify `tests/adversarial/tier_laundering/tl_base_dispatch_and_raw_state_write.yaml`** and
  **`tests/adversarial/tier_laundering/README.md`** — the derived corpus record (arch-002).
- **Modify `docs/superpowers/plans/2026-07-29-518-detector-review-constraints.md`** and
  **`docs/superpowers/plans/2026-07-29-518-check-tag-t3-seven-shapes.md`** — the three counts.
- **Create `docs/adr/0059-default-deny-on-unresolvable-tier-slices.md`** — arch-006.

## PR shape

**ONE branch, ONE PR, ONE merge**: `539-seven-shapes-alias-environment`. Work is committed in
eight tasks so a reviewer can read it in units, but nothing is pushed as a separate PR and
**only the final commit carries a `#539` auto-closing subject** (arch-003).

Intermediate commits use `refactor:`/`test:`/`docs:` with `(#539)` **in the SUBJECT** — the
gate requires the reference there, so putting it in the body fails the required check. Those
types are not closing keywords, so they satisfy the gate and close nothing.

---

## Task 1: The tier alias environment

**Files:** modify `scripts/check_tag_t3.py`; create
`tests/unit/security/test_check_tag_t3_seven_shapes.py`.

**Produces:** `_SliceVerdict`, `_slice_verdict`, `TierAliasEnv`, `_tier_alias_env`,
`_trust_tier_type_aliases`, `_parameterised_bindings`, `_stricter`.

`_slice_verdict` is defined FIRST because `_tier_alias_env` calls it (arch-004: the original
task order inverted this and still claimed PASS).

The test file's preamble is copied verbatim from `test_check_tag_t3_sole_layer_rules.py:15-40`
— `spec_from_file_location` against the REAL script path, the `_REPO_ROOT` assertion, `_PROBE`,
and the `_messages` helper that filters snippet lines.

- [ ] **Step 1: Write the failing tests**

Cover, at minimum: `tc_bare` rebind + import-alias; the reverse-order fixed point; the six
UNRESOLVED shapes; `T3 as Wire` vs `T2 as Broadcast`; both TypeVar spellings; the sec-002,
sec-003 and sec-004 bypasses; `AnnAssign` / PEP-695 / walrus bindings; the conflicting-rebind
strictness rule; and budget overflow.

Every assertion uses `_messages(src) == [f"{_PROBE}:1: {MSG}"]` or
`any(MSG in m for m in _messages(src))` — never `MSG in _messages(src)` (rev-001).

- [ ] **Step 2: Run to verify they fail**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_seven_shapes.py -q
```

- [ ] **Step 3: Implement**

The validated implementation is in the prototype at
`scratchpad/fixed_v2.py`; port it with real docstrings. The load-bearing points:

1. `_slice_verdict` treats a quoted generic as a forward-referenced NAME and resolves it
   through the SAME sets as the bare form (sec-004).
2. `_parameterised_bindings` default-denies over binding SHAPES (sec-005).
3. `_trust_tier_type_aliases` alias-resolves `TrustTier` and refuses a bound that resolves
   into `t3` (sec-003).
4. Parameterised bindings are a `Mapping[str, _SliceVerdict]`, merged with `_stricter`
   (arch-001).
5. A name in both `tc_bare` and the map is raised to at least UNRESOLVED (sec-002).
6. No ternary anywhere in the classification path (arch-009, py-005).
7. All seven `_alias_names` overflow flags are OR-ed and returned (err-002).

- [ ] **Step 4: Run to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_seven_shapes.py
git commit -m "refactor: #539 tier alias environment and a total slice verdict"
```

## Task 2: R4 — wire the environment into the subscript rule

**Files:** modify `scripts/check_tag_t3.py`, `tests/unit/security/test_check_tag_t3_seven_shapes.py`.

**Produces:** `_tagged_subscript_verdict`, `_TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE`.
`_detect` gains an `env: TierAliasEnv` parameter appended after `private_names`; `_scan_text`
builds it alongside the other per-file maps and ORs its overflow into the existing
`_ALIAS_BUDGET_MESSAGE` condition.

**Annotation immunity is STRUCTURAL.** `ast.Call.func` is the only position read — a
**one-position whitelist**, never an ancestor blacklist. The argument is not "a blacklist
regresses shapes" (a correctly scoped `.annotation`-subtree blacklist regresses zero); it is
that a blacklist must **ENUMERATE** annotation-bearing positions and silently widens when a new
one appears — `ast.TypeAlias` already did. It protects 22 annotation sites across 5 files, 13
of them outside any exempt file.

Two call shapes reach the same construction and both must be read: `TaggedContent[T3](...)`
where the subscript is in `Call.func`, and `Hot(...)` where `Hot = TaggedContent[T3]` and there
is **no subscript at the call site at all**.

- [ ] **Step 1–5:** failing tests, verify fail, implement, verify pass, commit.

Include the assert-RAN real-tree floor in the SAME invocation as the clean assertion.

```bash
git commit -m "refactor: #539 R4 alias-resolved subscript value and default-denied slice"
```

## Task 3: R1, R2, R3

**Files:** modify `scripts/check_tag_t3.py`, `tests/unit/security/test_check_tag_t3_seven_shapes.py`.

**Produces:** `_UNPARAMETERISED_CONSTRUCTION_MESSAGE`, `_TAGGED_SEAM_MESSAGE`,
`_TIER_MUTATING_COPY_MESSAGE`, `_mapping_mentions_tier`.

`_TAGGED_SEAM_ATTRS` and `_COPY_SEAM_ATTRS` are derived from `_BASEMODEL_SEAM_ATTRS` as a
partition, with the partition asserted in the suite (arch-008).

**R2's safety is BORROWED from the runtime guard**, and the docstring must say so:
`TaggedContent[T2].model_construct(tier=T3, …)` slips the lexical rule entirely and is caught
only by `_enforce_tier_admissible` / `model_post_init`.

**R3 is receiver-blind by necessity** — the oracle's case is `lower.model_copy(update={"tier": T3})`
on an INSTANCE. `_mapping_mentions_tier` is total over the mapping shapes a copy seam accepts
and default-denies an unreadable `**` (sec-006). Validated at 10/10 with 0 real-tree hits.

- [ ] **Step 1–5:** failing tests, verify fail, implement, verify pass, commit.

```bash
git commit -m "refactor: #539 R1 R2 R3 construction seam and tier-mutating copy rules"
```

## Task 4: R5 — tokenize-anchored suppression

**Files:** modify `scripts/check_tag_t3.py`; create
`tests/unit/security/test_check_tag_t3_suppression.py`.

Three things force `tokenize`:

1. The naive top-level alternation is the likely wrong implementation and costs **97 pure
   false positives** (measured 98 vs 1).
2. A "token regex" is WORSE than the naive regex on prose-in-a-comment. Only `tokenize`
   anchoring gets all the cases right.
3. Today's rule needs the suppressor and `TaggedContent` on the SAME PHYSICAL LINE, so moving
   the suppressor to a closing paren makes it blind.

The anchor covers `type: ignore`, `pyright: ignore`, `mypy: ignore`, `mypy: ignore-errors`,
`ruff: noqa`, `flake8: noqa` and bare `noqa` (sec-011). The span lookup falls back to the
comment's own line, because a standalone comment emits `NL`, not `NEWLINE` (err-005).

The pass runs where the old line loop ran — AFTER the AST walk — so findings already collected
are appended to, never discarded (err-006). It sits inside the existing `try`, so a `TokenError`
is reported by the existing `_UNSCANNABLE` arm: **no new arm, no unreachable branch, no paper
gate** (arch-011 and four corroborations).

`_TYPE_IGNORE_PATTERN` is REPLACED, not deleted outright — see Task 6 for its other consumer.

- [ ] **Step 1–5:** failing tests, verify fail, implement, verify pass, commit.

```bash
git commit -m "refactor: #539 R5 tokenize-anchored suppression over the logical line"
```

## Task 5: The independent oracle

**Files:** modify `tests/unit/security/test_check_tag_t3_seven_shapes.py`.

Feed the nonce-path suite's text through `_scan_text` under a synthetic non-exempt path and
assert per-function verdicts, with the two function-name sets as LITERALS. Line attribution
must `rsplit` rather than `split(":", 2)` — a Windows drive letter breaks the left-to-right
form on a required leg. The clean half needs an assert-RAN control and must not `continue`
silently on an unparsed line (err-008).

- [ ] **Step 1–3:** write, run, commit.

```bash
git commit -m "test: #539 independent oracle over the nonce-path suite's own source"
```

## Task 6: The meta-guard, the tripwire, and the gate-integrity suite

**Files:** modify `tests/unit/security/test_check_tag_t3_sole_layer_rules.py`,
`tests/unit/security/test_check_tag_t3_gate_integrity.py`.

`test_the_pre_existing_call_rules_are_still_the_declared_residual` is designed to red on the
day this issue closes these rules, and its own failure message says so. Deleting the residual
is the correct response.

1. Move `TaggedContent` and `T3` out of `_DECLARED_ALIAS_RESIDUALS` and into
   `_KEYED_IDENTIFIER_SPELLINGS` as behavioural rows. The real shape is
   `dict[str, dict[str, str]]` with `"DIRECT"` / `"REBOUND"` / `"IMPORT-ALIASED"` keys — NOT a
   `_Row` NamedTuple — and row values must not carry trailing newlines.
2. Keep `tag` and `cast` residual, preserving the existing hand-written two-role `cast` entry
   verbatim. **Verify by execution** that `_c = cast; _c(TaggedContent[T2], x)` still scans
   clean after R4.
3. Add residuals only for identifiers the derivation ACTUALLY produces — including `bound`
   (ops-002) — and add none it does not (ops-003). Verify by running
   `_identifiers_the_gate_keys_on` against the final gate source.
4. Update `test_check_tag_t3_gate_integrity.py` for the renamed predicate and the replaced
   pattern, and **assert the `_Exploding` fault-injection stand-in still injects** — it
   duck-types `.search()` and would otherwise go silently vacuous (py-003).
5. Write `test_the_benign_tier_seeds_match_the_real_module` against the real `tiers.py`
   (arch-005).

- [ ] **Step 1–3:** run to see the designed failure, fix, verify, commit.

```bash
git commit -m "test: #539 TaggedContent and T3 leave the alias residual set for behavioural rows"
```

## Task 7: Corpus record, docs and the ADR

**Files:** modify `tests/adversarial/tier_laundering/tl_base_dispatch_and_raw_state_write.yaml`,
`tests/adversarial/tier_laundering/README.md`,
`docs/superpowers/plans/2026-07-29-518-detector-review-constraints.md`,
`docs/superpowers/plans/2026-07-29-518-check-tag-t3-seven-shapes.md`,
`docs/python-conventions.md`, `scripts/check_tag_t3.py` (docstring); create
`docs/adr/0059-default-deny-on-unresolvable-tier-slices.md`.

1. Add the new message stems to the corpus yaml and the `tl-2026-013` README row — the oracle
   derives its vocabulary from the gate's constants in BOTH directions (arch-002, doc-001).
2. Rewrite the payload's residual (5): `TaggedContent.model_construct(...)` is no longer
   runtime-only (doc-003).
3. Correct the three counts, each date-stamped `measured 2026-08-03`:
   - constraints doc `~26`: "Six legitimate uses" → **3** (`plugins/web_fetch/allowlist.py:139`,
     `plugins/web_fetch/fetch_dispatcher.py:219`, `hooks/context.py:106`)
   - constraints doc `~71`: "~15 legitimate annotations" → **22 across 5 files**, naming the
     three it omits, two of which are not exempt
   - seven-shapes plan `96-97`: "26 pydantic-seam sites and 2 `model_copy(update=…)`" → **34
     seam calls outside `tiers.py`**, 0 with a TaggedContent-shaped receiver (doc-004)
4. Add the `docs/python-conventions.md:171` carve-out (doc-006).
5. Write ADR-0059 recording the default-deny-on-unresolvable-slice posture, its ergonomic
   contract, and the named escape hatch (arch-006).
6. Extend the module docstring's residual block: cross-module re-export aliasing;
   `getattr(x, var)` and `REGISTRY[k](…)`; a tier through `**kwargs`; `exec`/`eval` (ruff
   `S102`/`S307` are the defence); R2's borrowed safety; R3's literal-at-the-call-site
   requirement; and the benign-NAME binding — `def f(T2): TaggedContent[T2](...)` with a caller
   passing `T3` scans clean, because a name-keyed set cannot decide a runtime binding.

**Do NOT edit `2026-07-30-541-542-543-gate-hardening.md`** at `:1458`, `:2757`, `:2791` or
`:2829`. ADR-0058 deliberately left those dated records alone (doc-002, doc-005).

- [ ] **Step 1–2:** edit, verify the corpus oracle passes, commit.

```bash
git commit -m "docs: #539 corpus record, three measured counts and ADR-0059"
```

## Task 8: Close-out

- [ ] **Step 1: Coverage, with the command that actually measures**

```bash
uv run pytest tests/unit -q --cov=src/alfred --cov=scripts --cov-report= \
  && uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100 -m
```

If an arc is uncovered, write an input that reaches it or delete the arm. No pragma, no
`exclude_also` edit, no ternary.

- [ ] **Step 2: Mutation sweep, both directions**

Each mutant must red a NAMED floor. Record the floor per mutant.

| # | Mutant | Must red |
| --- | --- | --- |
| 1 | `_alias_names` loop → single pass | the reverse-order test, which asserts the EXACT rule |
| 2 | `_slice_verdict` default → BENIGN | every `_UNRESOLVED_SHAPES` case (7 parametrised) |
| 3 | benign arm deleted (widening) | benign floors + real-tree floor |
| 4 | `benign_tier` → empty (widening) | the `T2 as Broadcast` floor |
| 5 | `_trust_tier_type_aliases` → empty (widening) | both TypeVar-spelling tests |
| 6 | verdict map → two sets | the six arch-001 laundering cases |
| 7 | drop the `tc_bare ∩ map` raise | the sec-002 case |
| 8 | `TrustTier` matched as a literal | the sec-003 case |
| 9 | quoted arm → raw seed tuple | the sec-004 case |
| 10 | binding scan → `ast.Assign` only | AnnAssign / PEP-695 / walrus cases |
| 11 | `_tagged_subscript_verdict` reads any position (widening) | the annotation-immunity test |
| 12 | R2 made tier-agnostic | the benign-receiver floor AND the oracle's `still_works` |
| 13 | R2 made receiver-blind (widening) | real-tree floor — 34 sites |
| 14 | `_mapping_mentions_tier` → literal Dict only | `dict(tier=)` and `**` cases |
| 15 | R3 `**` default-deny removed | the opaque-`**` case |
| 16 | R5 anchor drops the non-capturing group | the prose floor AND the real-tree floor |
| 17 | `re.match` → `re.search` | the prose floor |
| 18 | logical span → physical line | the multiline closing-paren case |
| 19 | drop `ruff`/`flake8`/`mypy` from the anchor | their three tests |

Mutation testing only kills regressions you thought to write. It is a floor, not a proof.

- [ ] **Step 3: Markdown lint — a required check `make check` does not cover**

```bash
npx --yes markdownlint-cli2 "docs/**/*.md"
```

- [ ] **Step 4: `make check`**

```bash
make check || { status=$?; echo "make check FAILED with $status"; exit "$status"; }
```

**Do not write `make check; echo "EXIT=$?"`.** It prints the status and then throws it away —
the compound command exits with `echo`'s success, so a caller (or a harness) sees 0 for a
failed build. That is not hypothetical: during this work `make check` reported exit 0 while
its log ended `make: *** [coverage-gates] Error 1`. Piping through `tail` masks it the same
way. Read the log as well as the code.

If the macOS integration lane fails, re-run the suspect in ISOLATION before concluding
anything.

- [ ] **Step 5: Final commit, push, PR**

Only this commit carries a CLOSING subject — and `feat:` is not one. The closing keywords
are the `fix`/`close`/`resolve` families, so `feat: #539 …` satisfies the gate and closes
nothing; it must be either `fix: #539 …` or an explicit `(closes #539)`.

```bash
git commit -m "fix: #539 detect the seven T3-construction shapes at the authoring layer"
git push -u origin 539-seven-shapes-alias-environment
```

Then the standing cadence: full `/review-pr` fleet (security ALWAYS), CodeRabbit, resolve every
thread, plain `gh pr merge --rebase`. Never `--admin`.

- [ ] **Step 6: Verify the epic survived**

```bash
gh issue view 539   # CLOSED, auto-closed by the final subject
gh issue view 536   # MUST still be OPEN unless every step is genuinely done
gh issue view 547   # still OPEN — untouched here, see ADR-0058
```

`fix:`/`feat:` with `#NNN` in the subject auto-closes issue NNN, and the conventional-commit
gate MANDATES that shape. **#518 closed twice with work undone.** Check every time.

## Out of scope, stated rather than silently dropped

- **#547.** ADR-0058 says *"Do not implement #547 against its body as written"* — it needs a
  body rewrite, not a count patch. Re-measured here: the premise's count is wrong (1 exempt
  file, not 2) but its conclusion survives, because one exempt file still makes the failure
  condition unreachable.
- **`tag` and `cast` alias resolution.** Pre-existing, deliberately not widened by #538, still
  declared residual after Task 6.
- **Splitting R5 into its own PR** (arch-010) — declined for this delivery, reasoning recorded.
- **Stale local branches** (10, including the now-empty `518-detector-seven-shapes`).
