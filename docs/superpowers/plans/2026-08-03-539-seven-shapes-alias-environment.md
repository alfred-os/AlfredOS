# #539 — the seven T3-construction shapes, alias environment and suppression widening

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.

**Issue:** #539 (step 3 of 3 under epic #536; steps 1 #537 and 2 #538 are MERGED)
**Base:** `main` @ `054c13f7`
**Goal:** Teach `scripts/check_tag_t3.py` the seven T3-construction shapes at the
AUTHORING layer, resolved through a five-set alias environment, with the subscript
slice decided by a TOTAL default-deny function and the suppression rule widened to
`# pyright: ignore` / `# noqa` via `tokenize`.

**Architecture:** Five alias sets, every one produced by the EXISTING
seed-parameterised `_alias_names` — no second resolver (#422). Two of the five
(`tc_t3`, `tc_benign`) are derived by seeding `_alias_names` from subscript-binding
targets discovered against the first three, so the fixed point is still `_alias_names`'s.
The subscript slice becomes a total function over `ast.expr` returning one of three
verdicts, default-denying on SHAPE. Suppression detection moves off a line regex onto
`tokenize`, anchored at the start of a real COMMENT token and applied over the
enclosing LOGICAL line.

**Tech Stack:** Python 3.14 stdlib only (`ast`, `re`, `tokenize`, `io`). The gate runs
under bare `python3` from the Makefile with no venv, so it may import nothing outside
the standard library.

---

## Priority framing — read this before writing a line

**All seven shapes are ALREADY REFUSED AT RUNTIME.** Round-2 probes ran 32 spellings
against the live runtime; every one of S01–S08 is refused. This step is
**defence-in-depth**, deliberately sequenced last, and the issue explicitly refutes the
older plan's R1 justification:

> The old plan claimed `tiers.py`'s empty-generic short-circuit means unparameterised
> construction "bypasses the tier/generic cross-check for *every* tier". True for the
> cross-check, **irrelevant for T3** — `_refuse_unauthorized_t3` fires regardless of
> parameterisation.

The layers still differ usefully — one fires when the line **executes**, the other when
the line is **written**, and an unexercised branch in `src/` ships unrefused until it
runs — but **the ergonomic cost of this work must stay at ZERO**, and no rule may be
justified by a claim that does not survive measurement.

## Global Constraints

- **`scripts/check_tag_t3.py` is under a REQUIRED 100% line+branch coverage gate, with
  NO pragmas allowed.** Do not touch `exclude_also`; `exclude_lines` REPLACES
  `DEFAULT_EXCLUDE` and would un-exclude 66 pragma + 63 `TYPE_CHECKING` blocks.
- **Never launder a dead branch into a ternary.** `coverage.py` branch analysis works on
  the statement graph, so neither arm of a conditional *expression* is tracked and an
  unreachable arm reports as covered. Precedents in the file: `assert X is not None`
  (`_enclosing_functions`), or an explicit `if`/`else` with `# noqa: SIM108` (`_record`).
- **`mypy --strict` and `pyright` both run over `scripts/check_tag_t3.py`.** Use
  `getattr(node, "lineno", 1)` rather than `node.lineno` when the static type is
  `ast.AST` — both type-checkers error on the attribute form.
- **Every keyed identifier must be alias-resolved**, and must gain a row in
  `test_every_keyed_identifier_is_alias_resolved` (which DERIVES its identifier set from
  the gate's own AST) or an entry in `_DECLARED_ALIAS_RESIDUALS` with a stated reason.
  A rule keying on a new identifier with neither reds the meta-guard by design.
- **Per-rule DISTINCT messages.** A shape test satisfied by a different rule firing on
  the same line is a vacuous test.
- **Every negative floor needs a positive twin** built from the same text with one token
  swapped, asserted to TRIP — otherwise nothing proves the text reached the rule.
- **Mutation-test every guard, in BOTH directions**, including the widening direction.
  Each mutant must red a **named** floor.
- **Commit subjects must carry a literal `#539` AFTER the colon** (`fix: #539 …`) —
  the conventional-commit required check mandates it. Note this AUTO-CLOSES #539 on
  merge; verify #536 survives after every merge.
- **i18n:** this is a stdlib-only script with no `t()` calls. No catalog regeneration
  expected — but any line-count change to a `t()`-bearing file requires `make i18n-fix`.

## Measurements this plan is built on (taken 2026-08-03 against `main` @ `054c13f7`)

Every number below was produced by executing against the real 332-file scan set, not
inferred. **The false-positive cost of every rule in this plan is ZERO outside the
whole-file-exempt `src/alfred/security/tiers.py`.**

| Quantity | Measured |
| --- | --- |
| Files collected by `_collect_paths([])` | 332 |
| Exempt files in that set | **1** (`src/alfred/security/tiers.py` — `quarantine.py` deleted by #538) |
| Bare `TaggedContent(...)` calls (R1 surface) | **0**, anywhere |
| `copy`/`model_copy` calls with a `"tier"` key in a `Dict` arg (R3 surface) | **0** |
| `Dict` literals with a `"tier"` key, anywhere | 2, both in exempt `tiers.py` |
| Seam calls with a TaggedContent-shaped receiver (R2 surface) | **0** |
| Seam calls outside `tiers.py` (a NAKED tier-agnostic R2's FP cost) | **34** (`model_validate` 26, `model_validate_json` 6, `model_copy` 2) |
| `TaggedContent[...]` subscripts, total | 25 (`T3` 11, `T2` 4, `T1` 3, `TierT` 3, `T0` 2, `Any` 1, `tier` 1) |
| …in `ast.Call.func` position | 2 |
| …in annotation position | **22 across 5 files** |
| Non-`T0..T3` slices | 5, **all inside exempt `tiers.py`** (`TierT` ×3, `Any` ×1, `tier` ×1) |
| Naive top-level-alternation suppression regex hits | **98** vs **1** correctly grouped → **97 pure FPs** |
| `tokenize`-anchored real suppressors | `noqa` 92, `type: ignore` 76, `pyright: ignore` 0 |
| `tokenize` + logical-line R5 hits on the real tree | **1**, in exempt `tiers.py` (same as today) |
| Oracle file under a synthetic non-exempt path, today | **0 violations** |

The five annotation-bearing files are `plugins/content_store_base.py` (5),
`orchestrator/core.py` (4), `security/quarantine_transport.py` (3),
`comms_mcp/real_turn_adapter.py` (1) and the exempt `security/tiers.py` (9).
**`orchestrator/core.py` and `comms_mcp/real_turn_adapter.py` are NOT exempt and the
constraints doc never lists them** — they are why annotation immunity is load-bearing.

## The independent oracle

`tests/unit/security/test_t3_construction_requires_the_nonce_path.py` states all seven
shapes as executable source and scores **0 violations** today. Its function sets, as
LITERALS:

**Must each yield ≥1 violation** (7):
`test_bare_keyword_construction_is_refused`, `test_model_construct_is_refused`,
`test_model_validate_is_refused`, `test_model_validate_json_is_refused`,
`test_model_copy_update_to_t3_is_refused`, `test_renamed_import_subscript_is_refused`,
`test_non_literal_generic_argument_is_refused`.

**Must each yield ZERO violations** (4 — note this set is larger than a `*_still_works`
suffix glob finds; `test_model_construct_still_works_for_a_lower_tier` does not END with
it):
`test_the_authorised_path_still_works`, `test_a_lower_tier_is_unaffected`,
`test_model_construct_still_works_for_a_lower_tier`,
`test_model_copy_still_works_when_not_touching_the_tier`.

`test_model_construct_still_works_for_a_lower_tier` is `TaggedContent[T2].model_construct(...)`.
**It is the whole argument for R2 being slice-discriminating**: a receiver-scoped but
tier-AGNOSTIC R2 fires on a floor the repo explicitly named "still works". Discrimination
costs nothing and saves a named benign floor. (The wire-round-trip argument the old plan
gave for tier-agnosticism is measurably false: **0** TaggedContent-receiver seam sites.)

## File structure

- **Modify `scripts/check_tag_t3.py`** — the whole mechanism. Five alias-set builders
  (all delegating to `_alias_names`), `_slice_verdict`, four rules, the `tokenize`
  suppression pass, and the module-docstring residual block.
- **Modify `tests/unit/security/test_check_tag_t3_subscript.py`** — R4's home (it already
  owns the subscript rule's tests).
- **Create `tests/unit/security/test_check_tag_t3_seven_shapes.py`** — the alias
  environment, `_slice_verdict`, R1/R2/R3, the independent oracle, and the mutation
  sweep. A new file rather than a sixth section of the 2800-line sole-layer suite:
  different rules, different floors, and the sole-layer file is already at the size where
  a reviewer cannot hold it.
- **Create `tests/unit/security/test_check_tag_t3_suppression.py`** — R5's six cases.
- **Modify `tests/unit/security/test_check_tag_t3_sole_layer_rules.py`** — delete the
  `TaggedContent`/`T3` entries from `_DECLARED_ALIAS_RESIDUALS`, add their behavioural
  rows, and narrow `test_the_pre_existing_call_rules_are_still_the_declared_residual` to
  the two identifiers that remain residual (`tag`, `cast`).
- **Modify `docs/superpowers/plans/2026-07-29-518-detector-review-constraints.md`** —
  correct the three wrong counts in place.
- **Modify `docs/superpowers/plans/2026-07-30-541-542-543-gate-hardening.md:1458,2757`** —
  correct the stale "the two `_APPROVED_PATHS` files" premise (#538 left ONE).

## PR shape — ONE PR, three review-sized stages

**ONE PR** on branch `539-seven-shapes-alias-environment`, built and committed in three
stages so a reviewer can read it as three coherent units without three merge cycles.

The parts interlock and a split would ship a half-mechanism: all four rules decide on the
SAME five alias sets, `_slice_verdict` is shared by R2 and R4, and the
`_DECLARED_ALIAS_RESIDUALS` tripwire only flips once R4 lands — so a PR-A that stops
before R1/R2/R3 leaves the epic's titular deliverable half-refused, and a PR-B in flight
against a moving `_detect` signature is a rebase hazard for no review gain.

Precedent: #538 shipped ten rules on this same file in one PR.

| Stage | Responsibility | Tasks |
| --- | --- | --- |
| **1** | The alias environment + `_slice_verdict` + R4 (widening an EXISTING rule). Flips the `_DECLARED_ALIAS_RESIDUALS` tripwire. | 1–5 |
| **2** | R1, R2, R3 — the three NEW rules, riding on stage 1's alias sets. Independent oracle. | 6–10 |
| **3** | R5 — the `tokenize` suppression widening. Comments, not AST. | 11–12 |

Each stage ends at a commit with the full suite green, `make check` clean, and
`check_tag_t3.py` at 100% line+branch — so a mid-stage stop is still a coherent tree.
Where a task below says "open PR", that means "finish the stage"; the PR opens once after
Task 12, and the close-out steps (coverage, mutation sweep, `make check`) run per stage
AND once more before pushing.

Doc corrections land in the stage that makes each true: the `541` premise in stage 1, the
constraints-doc counts in stage 2.

---

# PR A — the alias environment, `_slice_verdict`, and R4

### Task 1: Five alias sets, all through `_alias_names`

**Files:**
- Modify: `scripts/check_tag_t3.py` (new helper after `_alias_names`, ~line 869)
- Test: `tests/unit/security/test_check_tag_t3_seven_shapes.py` (create)

**Interfaces:**
- Consumes: `_alias_names(tree: ast.AST, seed: str) -> tuple[frozenset[str], bool]` —
  the existing seed-parameterised fixed-point resolver. It handles
  `from m import X as Y` and plain `B = X` rebinds, chains included.
- Produces: `_tier_alias_env(tree: ast.AST) -> tuple[TierAliasEnv, bool]` where
  `TierAliasEnv` is a frozen `NamedTuple` with fields
  `tc_bare: frozenset[str]`, `tc_t3: frozenset[str]`, `tc_benign: frozenset[str]`,
  `t3: frozenset[str]`, `benign_tier: frozenset[str]`. The `bool` is `overflowed`,
  OR-ed into `_scan_text`'s existing `_ALIAS_BUDGET_MESSAGE` condition.

**Why five and not two.** `tc_t3`/`tc_benign` must be distinct because
`X = TaggedContent[T3]` and `X = TaggedContent[T2]` are **opposite verdicts under the
same binding form**. `t3`/`benign_tier` must be distinct because `T3 as Wire` must trip
while `T2 as Broadcast` must pass. The two benign sets are the false-positive relief
valve for the default-deny in Task 2 — **take both or neither**.

**Why the derivation order is a DAG, not an outer fixed point.** `tc_bare`, `t3` and
`benign_tier` are direct `_alias_names` seeds. `tc_t3`/`tc_benign` are derived by
scanning for `Assign(target=Name, value=Subscript(value=<in tc_bare>, slice=…))`,
classifying the slice, and then fanning `_alias_names` out over each discovered TARGET
name — so the chain `B = A; A = TaggedContent[T3]` resolves through `_alias_names`'s own
fixed point, and `A = X[T3]; X = TaggedContent` resolves because `tc_bare` is complete
before the scan runs.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/security/test_check_tag_t3_seven_shapes.py`. Import the gate the same
way the existing suites do — via `spec_from_file_location` against the REAL path, and
assert `_REPO_ROOT` is the real repo (a `tmp_path` copy recomputes `_REPO_ROOT` from
`__file__` and silently inverts every exemption). Copy the import preamble verbatim from
`tests/unit/security/test_check_tag_t3_sole_layer_rules.py`.

```python
def _env(source: str) -> tuple[object, bool]:
    return check_tag_t3._tier_alias_env(ast.parse(source))


def test_tc_bare_resolves_rebind_and_import_alias() -> None:
    env, overflowed = _env(
        "from alfred.security.tiers import TaggedContent as _Imported\n"
        "_Rebound = TaggedContent\n"
    )
    assert env.tc_bare == frozenset({"TaggedContent", "_Imported", "_Rebound"})
    assert not overflowed


def test_tc_bare_reaches_a_fixed_point_against_source_order() -> None:
    """`B = A` written BEFORE `A = TaggedContent`. A single pass misses `B`."""
    env, _ = _env("B = A\nA = TaggedContent\n")

    assert env.tc_bare == frozenset({"TaggedContent", "A", "B"})


def test_tc_t3_and_tc_benign_are_opposite_verdicts_on_the_same_binding_form() -> None:
    env, _ = _env("Hot = TaggedContent[T3]\nCool = TaggedContent[T2]\n")

    assert env.tc_t3 == frozenset({"Hot"})
    assert env.tc_benign == frozenset({"Cool"})


def test_tc_t3_chains_through_alias_names_fixed_point() -> None:
    """`B = A` before `A = TaggedContent[T3]` — the derived sets get the fixed point too."""
    env, _ = _env("B = A\nA = TaggedContent[T3]\n")

    assert env.tc_t3 == frozenset({"A", "B"})


def test_a_parameterised_binding_over_an_aliased_base_resolves() -> None:
    env, _ = _env("X = TaggedContent\nHot = X[T3]\n")

    assert env.tc_t3 == frozenset({"Hot"})


def test_t3_and_benign_tier_are_distinct_sets() -> None:
    env, _ = _env(
        "from alfred.security.tiers import T3 as Wire\n"
        "from alfred.security.tiers import T2 as Broadcast\n"
    )

    assert "Wire" in env.t3
    assert "Wire" not in env.benign_tier
    assert "Broadcast" in env.benign_tier
    assert "Broadcast" not in env.t3


def test_benign_tier_seeds_in_file_pep695_typevars_bound_to_trust_tier() -> None:
    env, _ = _env("type TierT = TrustTier\n")

    assert "TierT" in env.benign_tier


def test_an_alias_chain_past_the_budget_overflows() -> None:
    chain = "".join(f"_n{i} = _n{i - 1}\n" for i in range(1, 40))
    env, overflowed = _env(f"_n0 = TaggedContent\n{chain}")

    assert overflowed
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_seven_shapes.py -q`
Expected: FAIL — `AttributeError: module 'check_tag_t3' has no attribute '_tier_alias_env'`.

- [ ] **Step 3: Implement `_tier_alias_env`**

Add after `_alias_names`. Note the `NamedTuple` import goes at module top with the other
stdlib imports.

```python
class TierAliasEnv(NamedTuple):
    """The five per-file name sets every tier rule decides on.

    FIVE, not two, and the pairs cannot be merged. `tc_t3`/`tc_benign` are OPPOSITE
    verdicts reached through the identical binding form (`X = TaggedContent[T3]` vs
    `X = TaggedContent[T2]`), and `t3`/`benign_tier` likewise (`T3 as Wire` must trip
    while `T2 as Broadcast` must pass). The two benign sets are the false-positive
    relief valve for `_slice_verdict`'s default-deny: take both or neither.

    Every set is produced by `_alias_names`, the ONE seed-parameterised resolver this
    gate owns. A second resolver would be the #422 shape — a shared helper fails LOUD,
    N copies drift SILENTLY — and on this axis the drift is a bypass.
    """

    tc_bare: frozenset[str]
    tc_t3: frozenset[str]
    tc_benign: frozenset[str]
    t3: frozenset[str]
    benign_tier: frozenset[str]


# The tier identifiers that are NOT T3. Named rather than derived: the gate cannot
# import `alfred.security.tiers` (it runs under bare `python3` with no venv), and
# `_APPROVED_TIERS` is already hard-coded on the same terms. The drift guard is
# `test_the_benign_tier_seeds_match_the_real_module`.
_BENIGN_TIER_SEEDS: tuple[str, ...] = ("T0", "T1", "T2")

# The annotation a PEP-695 type alias must carry to count as a benign tier. Seeding
# these is what stops the FIRST generic helper written outside `tiers.py` redding for a
# benign reason — `TaggedContent[TierT]` is ×3 in `tiers.py` today.
_TRUST_TIER_NAME: str = "TrustTier"


def _tier_alias_env(tree: ast.AST) -> tuple[TierAliasEnv, bool]:
    """The five tier name sets for ONE file, plus whether any chain overflowed.

    DERIVATION ORDER IS A DAG, NOT AN OUTER FIXED POINT. `tc_bare`, `t3` and
    `benign_tier` are direct `_alias_names` seeds. `tc_t3`/`tc_benign` are then derived
    from `X = <tc_bare>[<slice>]` bindings and each discovered TARGET is fanned back
    through `_alias_names`, so `B = A` written before `A = TaggedContent[T3]` still
    resolves `B` — the fixed point is `_alias_names`'s, not a second one written here.

    RESIDUAL, inherited from `_alias_names` and restated because it bites harder on
    this axis: the alias sets are PER-FILE. A `TaggedContent` re-exported through
    another module and imported under its new spelling is not resolved.

    RESIDUAL, and it cannot be closed by a name-keyed set: `benign_tier` holds bare
    NAMES, so a parameter or local named `T2` is treated as benign —
    `def f(T2): TaggedContent[T2](...)` where the caller passes `T3` scans clean. A
    name-keyed set cannot decide a runtime binding. It is masked by the runtime guard
    (`_refuse_unauthorized_t3` fires regardless of parameterisation), which is what
    makes it an acceptable residual rather than a hole.
    """
    overflowed = False
    tc_bare, grew = _alias_names(tree, "TaggedContent")
    overflowed = overflowed or grew
    t3, grew = _alias_names(tree, "T3")
    overflowed = overflowed or grew

    benign: set[str] = set()
    for seed in _BENIGN_TIER_SEEDS:
        resolved, grew = _alias_names(tree, seed)
        benign |= resolved
        overflowed = overflowed or grew
    benign |= _trust_tier_type_aliases(tree)

    t3_seeds: set[str] = set()
    benign_seeds: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Subscript)):
            continue
        if _arg_name(node.value.value) not in tc_bare:
            continue
        bucket = t3_seeds if _slice_verdict(node.value.slice, t3, benign) is _SliceVerdict.T3 else benign_seeds
        for target in node.targets:
            if isinstance(target, ast.Name):
                bucket.add(target.id)

    tc_t3: set[str] = set()
    for seed in sorted(t3_seeds):
        resolved, grew = _alias_names(tree, seed)
        tc_t3 |= resolved
        overflowed = overflowed or grew
    tc_benign: set[str] = set()
    for seed in sorted(benign_seeds):
        resolved, grew = _alias_names(tree, seed)
        tc_benign |= resolved
        overflowed = overflowed or grew

    return (
        TierAliasEnv(
            tc_bare=tc_bare,
            tc_t3=frozenset(tc_t3),
            tc_benign=frozenset(tc_benign),
            t3=t3,
            benign_tier=frozenset(benign),
        ),
        overflowed,
    )


def _trust_tier_type_aliases(tree: ast.AST) -> frozenset[str]:
    """In-file PEP-695 type aliases and TypeVars bound to ``TrustTier``.

    WITHOUT THIS, the first generic helper written OUTSIDE `tiers.py` reds for a benign
    reason: `TaggedContent[TierT]` is a legitimate shape and `TierT` is in no tier set.
    `tiers.py` carries three such sites today and is whole-file exempt, so this seeding
    buys nothing on the current tree — it is what keeps the default-deny in
    `_slice_verdict` affordable for the NEXT such helper.

    IT DOES NOT RESCUE A PLAIN PARAMETER. `tiers.py:949` is `TaggedContent[tier](...)`
    where `tier` is a function parameter, and no lexical set can decide what a caller
    passed. Stated here so the next reader does not expect it to.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.TypeAlias) and _arg_name(node.value) == _TRUST_TIER_NAME:
            names.add(node.name.id)
        # `TierT = TypeVar("TierT", bound=TrustTier)` — the pre-PEP-695 spelling, still
        # legal and still the shape a `typing.TypeVar` import produces.
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            bound = next((k.value for k in node.value.keywords if k.arg == "bound"), None)
            if bound is not None and _arg_name(bound) == _TRUST_TIER_NAME:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
    return frozenset(names)
```

`_slice_verdict` and `_SliceVerdict` land in Task 2 — write Task 2 FIRST if executing
strictly, or accept a red import for one step. The plan orders them this way because the
alias env is the thing `_slice_verdict` is defined against.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_seven_shapes.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_seven_shapes.py
git commit -m "feat: #539 five-set tier alias environment over the one _alias_names resolver"
```

---

### Task 2: `_slice_verdict` — a TOTAL function over `ast.expr`, default-deny on SHAPE

**Files:**
- Modify: `scripts/check_tag_t3.py`
- Test: `tests/unit/security/test_check_tag_t3_seven_shapes.py`

**Interfaces:**
- Consumes: `TierAliasEnv` from Task 1.
- Produces: `_SliceVerdict` (an `enum.Enum` with members `T3`, `BENIGN`, `UNRESOLVED`)
  and `_slice_verdict(node: ast.expr, t3: frozenset[str], benign: frozenset[str]) -> _SliceVerdict`.

**This is the strongest rule in the epic and round-2 could not bypass it.** Today's
detector is fail-**OPEN** on every non-`Name` slice. The table, from the issue and
re-verified against the current code:

| slice shape | today | with the rule |
| --- | --- | --- |
| `TaggedContent["T"+"3"]` (BinOp) | clean | FLAG |
| `TaggedContent[globals()["T3"]]` (Call) | clean | FLAG |
| `TaggedContent[TIERS["T3"]]` (Subscript) | clean | FLAG |
| `TaggedContent[T3 if 1 else T2]` (IfExp) | clean | FLAG |
| `TaggedContent[(T3,)]` (Tuple) | clean | FLAG |
| `TaggedContent[T2]` (benign floor) | clean | clean |
| `T2 as Broadcast` (benign alias floor) | clean | clean |
| `T3 as Wire` | clean | FLAG |

**Measured false-positive cost: 5 non-`T0..T3` slices exist and ALL FIVE are inside the
whole-file-exempt `tiers.py`.**

- [ ] **Step 1: Write the failing tests**

```python
_UNRESOLVED_SHAPES = {
    "binop": 'TaggedContent["T" + "3"](x)',
    "call": 'TaggedContent[globals()["T3"]](x)',
    "subscript": 'TaggedContent[TIERS["T3"]](x)',
    "ifexp": "TaggedContent[T3 if flag else T2](x)",
    "tuple": "TaggedContent[(T3,)](x)",
    "unknown_name": "TaggedContent[Mystery](x)",
}


@pytest.mark.parametrize("label", sorted(_UNRESOLVED_SHAPES))
def test_every_non_name_slice_shape_is_default_denied(label: str) -> None:
    messages = _messages(f"{_UNRESOLVED_SHAPES[label]}\n")

    assert check_tag_t3._TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE in messages, label


def test_the_t3_slice_reports_the_t3_rule_not_the_unresolved_one() -> None:
    """DISTINCT messages: an unresolved-shape hit must not satisfy a T3 shape test."""
    messages = _messages("TaggedContent[T3](x)\n")

    assert check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in messages
    assert check_tag_t3._TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE not in messages


@pytest.mark.parametrize("tier", ["T0", "T1", "T2"])
def test_a_benign_tier_slice_is_clean(tier: str) -> None:
    assert _messages(f"TaggedContent[{tier}](x)\n") == []


def test_a_benign_tier_alias_slice_is_clean_and_its_t3_twin_trips() -> None:
    """The positive twin proves the text reached the rule at all."""
    benign = (
        "from alfred.security.tiers import T2 as Broadcast\nTaggedContent[Broadcast](x)\n"
    )
    hot = "from alfred.security.tiers import T3 as Wire\nTaggedContent[Wire](x)\n"

    assert _messages(benign) == []
    assert check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in _messages(hot)


def test_a_pep695_trust_tier_alias_slice_is_clean() -> None:
    assert _messages("type TierT = TrustTier\nTaggedContent[TierT](x)\n") == []


def test_a_quoted_benign_tier_is_clean_and_the_quoted_t3_trips() -> None:
    assert _messages('TaggedContent["T2"](x)\n') == []
    assert check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in _messages('TaggedContent["T3"](x)\n')


def test_slice_verdict_is_total_over_every_expression_node_type() -> None:
    """DEFAULT-DENY ON SHAPE, asserted as a property rather than a list of shapes.

    Every `ast.expr` subclass the parser can produce in slice position must return a
    verdict rather than raise. An enumeration of shapes closes what it names; this
    closes the axis.
    """
    for expr_type in _every_expr_subclass():
        node = _minimal_instance(expr_type)
        verdict = check_tag_t3._slice_verdict(node, frozenset({"T3"}), frozenset({"T2"}))
        assert verdict in set(check_tag_t3._SliceVerdict), expr_type.__name__
```

`_every_expr_subclass()` / `_minimal_instance()` are module-level helpers in the test
file: walk `ast.expr.__subclasses__()` recursively, and build each with
`expr_type()` (hand-built nodes need no fields for an `isinstance` cascade). Skip
`ast.expr` itself.

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_seven_shapes.py -q -k slice`
Expected: FAIL — `_slice_verdict` and `_TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE` undefined.

- [ ] **Step 3: Implement**

```python
_TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE: str = (
    "TaggedContent[...] whose generic argument is not a tier this gate can read — "
    "a computed, quoted-non-tier or otherwise non-identifier slice. The gate cannot "
    "tell T3 from T2 here, so it refuses. Write the tier literally, or go through "
    "tag_t3_with_nonce()."
)


class _SliceVerdict(enum.Enum):
    """What a `TaggedContent[...]` generic argument resolves to. THREE, not two.

    `UNRESOLVED` is the whole point. Today's rule asks "is this slice the name T3?" and
    answers "no" for `"T"+"3"`, `globals()["T3"]`, `TIERS["T3"]`, `T3 if x else T2` and
    `(T3,)` alike — fail-OPEN on every non-`Name` shape. A two-valued verdict cannot
    express "I could not read this", so it has to guess, and the safe guess and the
    quiet guess are different guesses.
    """

    T3 = "t3"
    BENIGN = "benign"
    UNRESOLVED = "unresolved"


def _slice_verdict(
    node: ast.expr, t3_names: frozenset[str], benign_names: frozenset[str]
) -> _SliceVerdict:
    """TOTAL over `ast.expr`. Every shape gets a verdict; the default is DENY.

    Written as an allow-list over the two shapes this gate can READ — a bare/qualified
    identifier, and a string-quoted tier — with everything else falling through to
    `UNRESOLVED`. An enumeration of BAD shapes closes what it names and silently widens
    the day the grammar grows one; this closes the axis
    (see `domain_enumerate_vs_default_deny`).

    The benign sets are what make that affordable. Measured across both scan roots: the
    only non-`T0..T3` slices are `TaggedContent[TierT]` x3, `[Any]` x1 and `[tier]` x1,
    and ALL FIVE are inside the whole-file-exempt `tiers.py`. The first generic helper
    written OUTSIDE it reds unless its TypeVar is bound to `TrustTier` — which
    `_trust_tier_type_aliases` seeds — and a plain PARAMETER (`tiers.py:949`) is not
    rescued by anything lexical.
    """
    name = _arg_name(node)
    if name is not None:
        if name in t3_names:
            return _SliceVerdict.T3
        if name in benign_names:
            return _SliceVerdict.BENIGN
        return _SliceVerdict.UNRESOLVED
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value == "T3":
            return _SliceVerdict.T3
        if node.value in _BENIGN_TIER_SEEDS:
            return _SliceVerdict.BENIGN
    return _SliceVerdict.UNRESOLVED
```

Add `import enum` to the module imports, in alphabetical position.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_seven_shapes.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_seven_shapes.py
git commit -m "feat: #539 _slice_verdict as a total default-deny function over ast.expr"
```

---

### Task 3: R4 — wire the alias env and `_slice_verdict` into the subscript rule

**Files:**
- Modify: `scripts/check_tag_t3.py` (`_is_tagged_content_t3_subscript_call`, `_detect`, `_scan_text`)
- Test: `tests/unit/security/test_check_tag_t3_subscript.py`

**Interfaces:**
- Consumes: `TierAliasEnv`, `_slice_verdict`, `_SliceVerdict`.
- Produces: `_tagged_subscript_verdict(node: ast.Call, env: TierAliasEnv) -> _SliceVerdict | None`
  — `None` when the call is not a `TaggedContent`-ish subscript construction at all.
  `_detect` gains an `env: TierAliasEnv` parameter; `_scan_text` builds it once per file
  alongside the other per-file maps and OR-s its overflow into the existing
  `_ALIAS_BUDGET_MESSAGE` condition.

**Annotation immunity is STRUCTURAL, not a new check.** `ast.Call.func` is the ONLY
position this rule reads, and that is a **one-position whitelist** — never an ancestor
blacklist. Argue it on the right ground: a naive ancestor blacklist regresses exactly
three shapes (annotated-assignment RHS, parameter default, class-body annotated
assignment), but a *correctly scoped* `.annotation`-subtree blacklist regresses zero — so
the real argument is that a blacklist must **ENUMERATE** annotation-bearing positions and
silently widens the day a new one appears (`ast.TypeAlias`, PEP-695 `type X = …`). The
whitelist cannot. The FP surface it protects is **22 annotation sites across 5 files**,
including `orchestrator/core.py` (×4) and `comms_mcp/real_turn_adapter.py` (×1), **neither
of which is exempt and neither of which the constraints doc lists**.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/security/test_check_tag_t3_subscript.py`:

```python
def test_a_renamed_import_subscript_trips() -> None:
    source = (
        "from alfred.security.tiers import TaggedContent as _Renamed\n"
        "_Renamed[T3](content='x', source='s', tier=T3, metadata={})\n"
    )

    assert check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in _messages(source)


def test_a_rebound_taggedcontent_subscript_trips() -> None:
    assert check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in _messages(
        "_TC = TaggedContent\n_TC[T3](x)\n"
    )


def test_a_non_literal_generic_argument_trips() -> None:
    source = "_TIER = T3\nTaggedContent[_TIER](content='x', tier=_TIER)\n"

    assert check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in _messages(source)


def test_the_reverse_order_alias_trips_under_the_T3_RULE_not_the_unresolved_one() -> None:
    """THE FIXED-POINT MUTANT KILLER, and it must assert the exact rule.

    `B = A` before `A = T3`. A single-pass resolver leaves `B` out of `t3`, so the
    slice falls through to UNRESOLVED and the line STILL TRIPS — under the wrong rule.
    A "does it trip" assertion lets that mutant survive; this one does not.
    """
    source = "B = A\nA = T3\nTaggedContent[B](x)\n"
    messages = _messages(source)

    assert check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in messages
    assert check_tag_t3._TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE not in messages


def test_annotation_position_is_immune_and_the_call_twin_trips() -> None:
    """22 annotation sites across 5 files depend on this; 13 are outside exempt files."""
    annotations = (
        "def f(x: TaggedContent[T3]) -> TaggedContent[T3]: ...\n"
        "y: TaggedContent[T3]\n"
        "class C:\n    z: TaggedContent[T3]\n"
        "def g(a: int = 0, *, b: TaggedContent[T3] | None = None) -> None: ...\n"
        "type Alias = TaggedContent[T3]\n"
    )

    assert _messages(annotations) == []
    assert check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in _messages(
        "y: TaggedContent[T3] = TaggedContent[T3](x)\n"
    )


def test_a_parameterised_alias_call_trips_without_a_subscript_at_the_call_site() -> None:
    """`Hot = TaggedContent[T3]` then `Hot(...)` — no Subscript in Call.func at all."""
    assert check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in _messages(
        "Hot = TaggedContent[T3]\nHot(content='x', tier=T3)\n"
    )


def test_a_benign_parameterised_alias_call_is_clean() -> None:
    assert _messages("Cool = TaggedContent[T2]\nCool(content='x', tier=T2)\n") == []


def test_the_real_tree_still_scans_clean_with_an_assert_ran_census() -> None:
    """ASSERT-RAN, in the SAME invocation. 'real tree clean' is a tautology otherwise."""
    paths = check_tag_t3._collect_paths([])

    assert len(paths) >= check_tag_t3._MIN_SCANNED_FILES
    assert [v for p in paths for v in check_tag_t3._scan_file(p)] == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_subscript.py -q`
Expected: FAIL on the alias, non-literal, reverse-order and parameterised-alias cases.
Expected: the annotation and real-tree tests PASS already (they are the floors).

- [ ] **Step 3: Implement**

Replace `_is_tagged_content_t3_subscript_call` with a verdict-returning form, keeping the
existing message for the T3 case so no downstream text changes:

```python
def _tagged_subscript_verdict(node: ast.Call, env: TierAliasEnv) -> _SliceVerdict | None:
    """The tier a `TaggedContent`-ish construction CALL mints, or `None` if it is not one.

    TWO call shapes reach the same construction and both must be read here:

    * `TaggedContent[T3](...)` — the subscript sits in `Call.func`;
    * `Hot(...)` where `Hot = TaggedContent[T3]` — there is NO subscript at the call
      site at all, so a rule that keyed on `ast.Subscript` is blind to it by
      construction.

    ONE-POSITION WHITELIST, and it is why the 22 annotation sites across 5 files do not
    red: `Call.func` is the only position read. Never an ancestor blacklist — a
    blacklist must ENUMERATE annotation-bearing positions and silently widens the day
    the grammar grows one (`ast.TypeAlias` already did).
    """
    func = node.func
    if isinstance(func, ast.Subscript):
        if _arg_name(func.value) not in env.tc_bare:
            return None
        return _slice_verdict(func.slice, env.t3, env.benign_tier)
    name = _arg_name(func)
    if name in env.tc_t3:
        return _SliceVerdict.T3
    if name in env.tc_benign:
        return _SliceVerdict.BENIGN
    return None
```

In `_detect`, inside the `isinstance(node, ast.Call)` arm, replace the old subscript
branch:

```python
        verdict = _tagged_subscript_verdict(node, env)
        if verdict is _SliceVerdict.T3:
            messages.append(_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE)
        elif verdict is _SliceVerdict.UNRESOLVED:
            messages.append(_TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE)
```

`_SliceVerdict.BENIGN` and `None` both fall through with no message — written as an
`if`/`elif` with no `else`, so `coverage.py` tracks both arcs.

In `_scan_text`, alongside the other per-file maps:

```python
        env, env_overflow = _tier_alias_env(tree)
```

and extend the overflow condition to include `env_overflow`, and the `_detect(...)` call
to pass `env`.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/security/ -q`
Expected: PASS, except `test_the_pre_existing_call_rules_are_still_the_declared_residual`
in the sole-layer suite, which now REDS on `TaggedContent rebound` and `T3 rebound`.
**That is the designed signal, not a regression** — Task 4 handles it.

- [ ] **Step 5: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_subscript.py
git commit -m "feat: #539 R4 — alias-resolved subscript value and default-denied slice"
```

---

### Task 4: Flip the `_DECLARED_ALIAS_RESIDUALS` tripwire

**Files:**
- Modify: `tests/unit/security/test_check_tag_t3_sole_layer_rules.py`
  (`_DECLARED_ALIAS_RESIDUALS` ~line 2422, `_KEYED_IDENTIFIER_SPELLINGS`,
  `test_the_pre_existing_call_rules_are_still_the_declared_residual` ~line 2469)

**Interfaces:**
- Consumes: nothing new.
- Produces: `TaggedContent` and `T3` move OUT of `_DECLARED_ALIAS_RESIDUALS` and INTO
  `_KEYED_IDENTIFIER_SPELLINGS` as behavioural rows. `tag` and `cast` STAY residual.

`test_the_pre_existing_call_rules_are_still_the_declared_residual` is designed to red the
day #539 closes these rules, and its own failure message says so. **Deleting the residual
is the correct response; suppressing the test is not.** The meta-guard forbids an
identifier being in both sets, so this is a move, not a copy.

`tag` and `cast` remain out of scope — #539 does not widen them — so the test must keep
measuring those two in both directions rather than being deleted wholesale.

- [ ] **Step 1: Run the suite to see the designed failure**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -q -k declared_residual`
Expected: FAIL, with the message "the TaggedContent rebound spelling now REDS … Give the
identifier a row in `_KEYED_IDENTIFIER_SPELLINGS` and delete the residual."

- [ ] **Step 2: Add the behavioural rows**

Add to `_KEYED_IDENTIFIER_SPELLINGS`, matching the existing row shape (direct / rebound /
import-aliased, with the direct form as the positive control):

```python
    "TaggedContent": _Row(
        direct="TaggedContent[T3](content='x', tier=T3)\n",
        rebound="_TC = TaggedContent\n_TC[T3](content='x', tier=T3)\n",
        import_aliased=(
            "from alfred.security.tiers import TaggedContent as _TC\n"
            "_TC[T3](content='x', tier=T3)\n"
        ),
    ),
    "T3": _Row(
        direct="TaggedContent[T3](content='x', tier=T3)\n",
        rebound="_T = T3\nTaggedContent[_T](content='x', tier=_T)\n",
        import_aliased=(
            "from alfred.security.tiers import T3 as _T\nTaggedContent[_T](content='x', tier=_T)\n"
        ),
    ),
```

Read the real `_Row`/spelling shape in the file before writing — copy it exactly rather
than inventing field names.

- [ ] **Step 3: Narrow the residual to the two identifiers that remain**

```python
_DECLARED_ALIAS_RESIDUALS: dict[str, str] = {
    # `TaggedContent` and `T3` LEFT this set when #539 landed — both now carry
    # behavioural rows in `_KEYED_IDENTIFIER_SPELLINGS`, which is the stronger of the
    # two: a row MEASURES the closure instead of asserting it. `tag` and `cast` stay,
    # because #539 widened the SUBSCRIPT and CONSTRUCTION rules and left those two
    # call rules exactly as they were.
    **dict.fromkeys(("tag", "cast"), _PRE_EXISTING_RESIDUAL),
    ...
}
```

Note `cast` already has a hand-written two-role entry lower in the dict; keep that one
and drop `cast` from the `fromkeys` if the merge order would clobber it — **read the
current file and preserve the existing "TWO ROLES" text verbatim.**

- [ ] **Step 4: Narrow the tripwire test**

```python
def test_the_pre_existing_call_rules_are_still_the_declared_residual() -> None:
    """#539 CLOSED `TaggedContent` and `T3`; `tag` and `cast` are what is left.

    The residual is asserted in BOTH directions for the two that remain: the direct
    spelling must red (the rules are live), and the rebound and import-aliased
    spellings must NOT (the residual is real). It still REDS the day a future PR closes
    either one — that is the point, and the message says so.
    """
    for label, source in {
        "tag": "tag(T3, payload)\n",
        "cast": "cast(TaggedContent[T2], x)\n",
    }.items():
        assert _messages(source), f"the pre-existing {label} rule is not live at all"

    for label, source in {
        "tag rebound": "_t = tag\n_t(T3, payload)\n",
        "tag import-aliased": "from alfred.security.tiers import tag as _t\n_t(T3, payload)\n",
        "cast rebound": "_c = cast\n_c(TaggedContent[T2], x)\n",
    }.items():
        assert check_tag_t3._scan_text(source, _PROBE) == [], (
            f"the {label} spelling now REDS. That is a widening of a pre-existing rule "
            f"— good news, but _DECLARED_ALIAS_RESIDUALS still claims it is out of "
            f"scope. Give the identifier a row in _KEYED_IDENTIFIER_SPELLINGS and "
            f"delete the residual."
        )
```

**Verify by execution, do not assume:** `_c = cast; _c(TaggedContent[T2], x)` must still
scan clean AFTER R4 lands. `cast`'s first argument is `TaggedContent[T2]` in
NON-`Call.func` position, so `_tagged_subscript_verdict` never sees it — but check, do
not reason.

- [ ] **Step 5: Add residual entries for the new literals R4 introduced**

The meta-guard DERIVES its identifier set from the gate's AST, so `"T0"`, `"T1"`, `"T2"`
and `"TrustTier"` now reach it. Add:

```python
_BENIGN_TIER_RESIDUAL: str = (
    "a BENIGN-tier seed, keyed in the ADMISSIBILITY direction: rebinding `T2` makes the "
    "gate STRICTER (the slice falls through to UNRESOLVED and reds), never weaker. "
    "Alias-resolved anyway by `_tier_alias_env`, and pinned by "
    "`test_a_benign_tier_alias_slice_is_clean_and_its_t3_twin_trips`."
)
```

…keyed over `_BENIGN_TIER_SEEDS` and `_TRUST_TIER_NAME`. **Do not hand-transcribe the
member list** — derive it from the gate's own constants the way the existing
`_EXPECTED_*` sets do, or the residual set drifts from the gate the next time a seed is
added.

- [ ] **Step 6: Run the full security suite**

Run: `uv run pytest tests/unit/security/ -q`
Expected: PASS, 0 failures.

- [ ] **Step 7: Commit**

```bash
git add tests/unit/security/test_check_tag_t3_sole_layer_rules.py
git commit -m "test: #539 TaggedContent and T3 leave the alias residual set for behavioural rows"
```

---

### Task 5: PR-A close-out — coverage, mutation sweep, docs, `make check`

**Files:**
- Modify: `scripts/check_tag_t3.py` (module docstring residual block)
- Modify: `docs/superpowers/plans/2026-07-30-541-542-543-gate-hardening.md:1458,2757`

- [ ] **Step 1: Prove the 100% line+branch gate still holds**

Run:
```bash
uv run coverage run -m pytest tests/unit/security/ -q \
  && uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100 -m
```
Expected: 100%. If an arc is uncovered, **write an input that reaches it or delete the
arm** — do not add a pragma, do not touch `exclude_also`, and do not rewrite it as a
ternary (`coverage.py` cannot see a ternary branch, so that HIDES the arm rather than
covering it).

- [ ] **Step 2: Mutation sweep, both directions**

For each mutant, confirm a **named** floor reds. Record the floor name per mutant.

| # | Mutant | Must red |
| --- | --- | --- |
| 1 | `_alias_names` loop → single pass | `test_the_reverse_order_alias_trips_under_the_T3_RULE_not_the_unresolved_one` (asserts the exact rule — a "does it trip" assertion would survive this) |
| 2 | `_slice_verdict` final `return UNRESOLVED` → `BENIGN` | every `_UNRESOLVED_SHAPES` case |
| 3 | `_slice_verdict` benign arm deleted (widening) | `test_a_benign_tier_slice_is_clean`, `test_the_real_tree_still_scans_clean_with_an_assert_ran_census` |
| 4 | `_tier_alias_env` `benign_tier` → `frozenset()` (widening) | `test_a_benign_tier_alias_slice_is_clean_and_its_t3_twin_trips` |
| 5 | `_trust_tier_type_aliases` → `frozenset()` (widening) | `test_a_pep695_trust_tier_alias_slice_is_clean` |
| 6 | `tc_t3`/`tc_benign` merged into one set | `test_a_benign_parameterised_alias_call_is_clean` |
| 7 | `_tagged_subscript_verdict` non-Subscript arm deleted | `test_a_parameterised_alias_call_trips_without_a_subscript_at_the_call_site` |
| 8 | `_tagged_subscript_verdict` reads any position, not just `Call.func` (widening) | `test_annotation_position_is_immune_and_the_call_twin_trips` |

Mutation testing only kills regressions you thought to write — it is a floor, not a
proof. Do not quote "N/N killed" as test adequacy.

- [ ] **Step 3: Write the module-docstring residual block**

Extend the existing "WHAT THE #538 RULES CANNOT DO" block with #539's, stating what the
guard CANNOT do rather than implying closure:

- cross-module re-export aliasing (the alias sets are per-file — inherited, restated
  because it bites harder on this axis);
- `getattr(x, var)` and `REGISTRY[k](…)` — the class reaches the constructor with no
  identifier in code position;
- a tier arriving through `**kwargs`;
- `exec`/`eval` (ruff `S102`/`S307` are the defence, not this gate);
- **the benign-NAME binding**: `benign_tier` holds bare names, so
  `def f(T2): TaggedContent[T2](...)` with a caller passing `T3` scans clean. A
  name-keyed set cannot decide a runtime binding; masked by the runtime guard.

Close with the named escape hatch, in the file's existing voice: **a future legitimate
benign wire round-trip belongs behind a NAMED helper inside the already-exempt
`security/tiers.py`, not behind a loosened rule here.**

- [ ] **Step 4: Correct the stale #547 premise in the 541 plan doc**

Both `:1458` and `:2757` say the failure condition is unreachable because **"the two
`_APPROVED_PATHS` files"** (`tiers.py` and `quarantine.py`) always return `[]`. **#538
deleted `quarantine.py` from that set, so there is now ONE.** Measured 2026-08-03: 332
files collected, exactly 1 exempt.

The CONCLUSION survives — one exempt file in the collected set still makes
`unscannable == len(paths)` unreachable — so #547 stays open and valid. Correct the
count and name the property rather than the number, so the next reader is not
calibrating off a figure that moves every time an exemption does.

- [ ] **Step 5: `make check` and push**

Run: `make check; echo "EXIT=$?"`
**Check `$?` explicitly** — piping `make` through `tail` MASKS the exit code.
Expected: `EXIT=0`.

If the macOS integration lane fails, re-run the suspect in ISOLATION before concluding
anything — that lane is flaky under load, and a 2× same-commit failure is a real
regression, not flake.

- [ ] **Step 6: Commit and open PR A**

```bash
git add scripts/check_tag_t3.py docs/superpowers/plans/2026-07-30-541-542-543-gate-hardening.md
git commit -m "docs: #539 record the R4 residuals and correct the stale one-exempt-file premise"
git push -u origin 539-alias-environment-and-slice-verdict
```

Then the standing cadence: full `/review-pr` fleet (**security ALWAYS**), CodeRabbit CLI
with `--base origin/main`, resolve every thread, plain `gh pr merge --rebase`.
**Never `--admin`.** Verify #536 and #539 states after merge (`fix:`/`feat:` with
`#539` in the subject auto-closes the issue).

---

# PR B — R1, R2, R3 and the independent oracle

### Task 6: R1 — unparameterised construction

**Files:**
- Modify: `scripts/check_tag_t3.py`
- Test: `tests/unit/security/test_check_tag_t3_seven_shapes.py`

**Interfaces:**
- Consumes: `TierAliasEnv.tc_bare` from Task 1, `_tagged_subscript_verdict` from Task 3.
- Produces: `_UNPARAMETERISED_CONSTRUCTION_MESSAGE`; a branch in `_detect`.

**Justified on the honest ground only.** The issue explicitly refutes the old plan's
claim that `tiers.py`'s empty-generic short-circuit makes this a T3 bypass:
`_refuse_unauthorized_t3` fires regardless of parameterisation. R1 exists because the
authoring layer fires when the line is WRITTEN and an unexercised branch in `src/` ships
unrefused until it runs — not because the runtime misses it. **Measured FP cost: 0 bare
`TaggedContent(...)` calls exist anywhere in the tree.**

- [ ] **Step 1: Write the failing tests**

```python
def test_bare_keyword_construction_trips() -> None:
    source = "TaggedContent(content='untrusted', source='t', tier=T3, metadata={})\n"

    assert check_tag_t3._UNPARAMETERISED_CONSTRUCTION_MESSAGE in _messages(source)


def test_unparameterised_construction_trips_regardless_of_the_tier_argument() -> None:
    """R1 does not read the tier: `tier=_ALIAS` and `**payload` reach the same write."""
    for source in (
        "TaggedContent(content='x', tier=_ALIAS)\n",
        "TaggedContent(**payload)\n",
    ):
        assert check_tag_t3._UNPARAMETERISED_CONSTRUCTION_MESSAGE in _messages(source)


def test_a_rebound_bare_construction_trips() -> None:
    assert check_tag_t3._UNPARAMETERISED_CONSTRUCTION_MESSAGE in _messages(
        "_TC = TaggedContent\n_TC(content='x', tier=T3)\n"
    )


def test_a_parameterised_construction_does_not_report_the_unparameterised_rule() -> None:
    """DISTINCT messages: R1 must not satisfy an R4 shape test, or vice versa."""
    messages = _messages("TaggedContent[T2](content='x', tier=T2)\n")

    assert check_tag_t3._UNPARAMETERISED_CONSTRUCTION_MESSAGE not in messages
    assert messages == []


def test_an_annotation_naming_bare_taggedcontent_is_clean() -> None:
    assert _messages("def f(x: TaggedContent) -> TaggedContent: ...\n") == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_seven_shapes.py -q -k unparameterised`
Expected: FAIL — `_UNPARAMETERISED_CONSTRUCTION_MESSAGE` undefined.

- [ ] **Step 3: Implement**

```python
_UNPARAMETERISED_CONSTRUCTION_MESSAGE: str = (
    "TaggedContent(...) built with no generic argument — the tier arrives as data the "
    "gate cannot read, so it cannot tell a T3 construction from a T0 one. Parameterise "
    "the construction, or use tag_t3_with_nonce()."
)
```

In `_detect`'s `ast.Call` arm, after the `_tagged_subscript_verdict` branch:

```python
        if verdict is None and _arg_name(node.func) in env.tc_bare:
            messages.append(_UNPARAMETERISED_CONSTRUCTION_MESSAGE)
```

`verdict is None` is what keeps R1 and R4 disjoint: a name in `tc_t3`/`tc_benign` already
returned a verdict, and a `Subscript` func never reaches here.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_seven_shapes.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_seven_shapes.py
git commit -m "feat: #539 R1 — unparameterised TaggedContent construction"
```

---

### Task 7: R2 — the deserialisation/construction seam, receiver-scoped AND slice-discriminating

**Files:**
- Modify: `scripts/check_tag_t3.py`
- Test: `tests/unit/security/test_check_tag_t3_seven_shapes.py`

**Interfaces:**
- Consumes: `TierAliasEnv`, `_slice_verdict`.
- Produces: `_TAGGED_SEAM_MESSAGE`, `_TAGGED_SEAM_ATTRS: frozenset[str]`, a branch in `_detect`.

**Settled against the old plan's "deliberately tier-agnostic".** Not on the
wire-round-trip argument, which is measurably false at **0** TaggedContent-receiver sites
— but on the repo's own mandated independent oracle: a tier-agnostic receiver-scoped R2
fires on `test_model_construct_still_works_for_a_lower_tier`
(`TaggedContent[T2].model_construct(...)`), failing a floor the repo explicitly named
"still works". **Discrimination costs nothing and saves a named benign floor.**

A NAKED (non-receiver-scoped) tier-agnostic rule is far worse: **34 false positives**
across legitimate sites (`model_validate` 26, `model_validate_json` 6, `model_copy` 2).
*(The issue said 23; re-measured 2026-08-03 at 34 — the direction of the argument is
unchanged and stronger.)*

**R2's safety is BORROWED from the runtime guard**, and the docstring must say so:
`TaggedContent[T2].model_construct(tier=T3, …)` slips this lexical rule entirely and is
caught only by `_enforce_tier_admissible` / `model_post_init`.

- [ ] **Step 1: Write the failing tests**

```python
_SEAMS = ("model_construct", "model_validate", "model_validate_json")


@pytest.mark.parametrize("seam", _SEAMS)
def test_a_t3_receiver_seam_call_trips(seam: str) -> None:
    assert check_tag_t3._TAGGED_SEAM_MESSAGE in _messages(f"TaggedContent[T3].{seam}(payload)\n")


@pytest.mark.parametrize("seam", _SEAMS)
def test_a_benign_receiver_seam_call_is_clean(seam: str) -> None:
    """THE NAMED FLOOR. `test_model_construct_still_works_for_a_lower_tier` is real."""
    assert _messages(f"TaggedContent[T2].{seam}(payload)\n") == []


@pytest.mark.parametrize("seam", _SEAMS)
def test_a_foreign_receiver_seam_call_is_clean(seam: str) -> None:
    """34 legitimate seam sites live outside tiers.py; none may red."""
    assert _messages(f"Schema.{seam}(payload)\nnotification.{seam}(payload)\n") == []


def test_an_unparameterised_receiver_seam_call_trips() -> None:
    """Default-deny: a bare `TaggedContent` receiver names no tier the gate can read."""
    assert check_tag_t3._TAGGED_SEAM_MESSAGE in _messages("TaggedContent.model_construct(p)\n")


def test_an_unresolved_slice_receiver_seam_call_trips() -> None:
    assert check_tag_t3._TAGGED_SEAM_MESSAGE in _messages(
        'TaggedContent["T" + "3"].model_validate(p)\n'
    )


def test_an_aliased_t3_receiver_seam_call_trips() -> None:
    assert check_tag_t3._TAGGED_SEAM_MESSAGE in _messages(
        "Hot = TaggedContent[T3]\nHot.model_validate(p)\n"
    )
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_seven_shapes.py -q -k seam`
Expected: FAIL — `_TAGGED_SEAM_MESSAGE` undefined.

- [ ] **Step 3: Implement**

```python
# The seams that BUILD a model from data. `copy`/`model_copy` are deliberately absent —
# they mutate an EXISTING object and R3 decides them on the update mapping, receiver-
# blind, because the receiver there is an instance and receiver-scoping is impossible by
# construction.
_TAGGED_SEAM_ATTRS: frozenset[str] = frozenset(
    {"model_construct", "model_validate", "model_validate_json"}
)

_TAGGED_SEAM_MESSAGE: str = (
    "a TaggedContent construction seam (model_construct / model_validate*) that does "
    "not name a benign tier — these build field state from DATA, so the tier is not a "
    "token this gate can read. Use tag_t3_with_nonce()."
)
```

In `_detect`'s `ast.Call` arm:

```python
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _TAGGED_SEAM_ATTRS:
            receiver = func.value
            if isinstance(receiver, ast.Subscript) and _arg_name(receiver.value) in env.tc_bare:
                if _slice_verdict(receiver.slice, env.t3, env.benign_tier) is not _SliceVerdict.BENIGN:
                    messages.append(_TAGGED_SEAM_MESSAGE)
            elif _arg_name(receiver) in env.tc_t3 or _arg_name(receiver) in env.tc_bare:
                messages.append(_TAGGED_SEAM_MESSAGE)
```

`tc_benign` receivers fall through with no message — that is the named floor. Note
`func` is already bound in the surrounding scope by the existing code; reuse it rather
than shadowing.

- [ ] **Step 4: Run to verify they pass, and that the real tree is still clean**

Run: `uv run pytest tests/unit/security/ -q`
Expected: PASS, including `test_the_real_tree_still_scans_clean_with_an_assert_ran_census`.

- [ ] **Step 5: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_seven_shapes.py
git commit -m "feat: #539 R2 — receiver-scoped, slice-discriminating construction seams"
```

---

### Task 8: R3 — tier-mutating copy, receiver-blind

**Files:**
- Modify: `scripts/check_tag_t3.py`
- Test: `tests/unit/security/test_check_tag_t3_seven_shapes.py`

**Interfaces:**
- Consumes: `_fold_str`.
- Produces: `_TIER_MUTATING_COPY_MESSAGE`, `_COPY_SEAM_ATTRS: frozenset[str]`, a branch in `_detect`.

**Receiver-blind by necessity.** The oracle's case is `lower.model_copy(update={"tier": T3})`
— an INSTANCE receiver, so receiver-scoping is impossible by construction. The rule keys
on a `"tier"` key in an `ast.Dict` argument instead, and must accept that Dict in **kw or
positional** position (`BaseModel.copy(obj, {…})` — pydantic v1's positional signature).
Reading ANY `Dict` argument rather than a signature-derived index is default-deny on
shape: it does not have to know pydantic's parameter order, and it does not silently
widen when that order changes.

**Measured FP cost: 0.** The two live `model_copy(update={…})` sites outside `tiers.py`
carry `wire_seq`, not `tier`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_tier_mutating_model_copy_trips() -> None:
    assert check_tag_t3._TIER_MUTATING_COPY_MESSAGE in _messages(
        "lower.model_copy(update={'tier': T3})\n"
    )


def test_a_tier_mutating_copy_in_positional_position_trips() -> None:
    """`BaseModel.copy(obj, {...})` — pydantic v1's positional `update`."""
    assert check_tag_t3._TIER_MUTATING_COPY_MESSAGE in _messages(
        "BaseModel.copy(obj, None, None, {'tier': T3})\n"
    )


def test_a_folded_tier_key_trips() -> None:
    assert check_tag_t3._TIER_MUTATING_COPY_MESSAGE in _messages(
        "lower.model_copy(update={'ti' + 'er': T3})\n"
    )


def test_a_copy_not_touching_the_tier_is_clean_and_its_tier_twin_trips() -> None:
    """The live floors: two `model_copy(update={'wire_seq': ...})` sites must not red."""
    assert _messages("notification.model_copy(update={'wire_seq': wire_seq})\n") == []
    assert _messages("original.model_copy()\n") == []
    assert check_tag_t3._TIER_MUTATING_COPY_MESSAGE in _messages(
        "notification.model_copy(update={'tier': wire_seq})\n"
    )


def test_a_tier_dict_not_passed_to_a_copy_seam_is_clean() -> None:
    """R3 is scoped to the copy seams — a bare dict with a tier key is ordinary data."""
    assert _messages("payload = {'tier': T3}\nlog.info('x', extra={'tier': T3})\n") == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_seven_shapes.py -q -k copy`
Expected: FAIL — `_TIER_MUTATING_COPY_MESSAGE` undefined.

- [ ] **Step 3: Implement**

```python
# pydantic v1's `copy` and v2's `model_copy`. Both merge an `update` mapping into the
# copied field state, and v1's does NOT route through v2's (`copy_internals` merges it
# itself), so both spellings need naming.
_COPY_SEAM_ATTRS: frozenset[str] = frozenset({"copy", "model_copy"})

_TIER_MUTATING_COPY_MESSAGE: str = (
    "a copy seam whose update mapping carries a 'tier' key — relabelling a tier on an "
    "existing object never passes the capability gate. Build the object you want with "
    "tag_t3_with_nonce()."
)


def _mutates_tier_in_a_copy(node: ast.Call) -> bool:
    """True when a `copy`/`model_copy` call carries a `"tier"` key in ANY Dict argument.

    RECEIVER-BLIND, and it has to be: the shape this exists for is
    `lower.model_copy(update={"tier": T3})` on an INSTANCE, where there is no class
    identifier to scope against. That is the most plausible accident of the seven — an
    author copies an object and edits the tier, never touching a guarded function.

    EVERY argument is read, positional and keyword alike, rather than the index
    pydantic v1 happens to give `update` today. A signature-derived index closes the
    spelling it was written against and silently widens when the signature moves; a
    shape rule does not. Measured cost of the wider form across both scan roots: ZERO —
    the two live `model_copy(update=...)` sites outside `tiers.py` carry `wire_seq`.

    RESIDUAL: an update mapping built anywhere but at the call site
    (`payload = {"tier": T3}; obj.model_copy(update=payload)`) carries no `ast.Dict`
    here. Refused at RUNTIME by `_coerce_and_guard_update`; not closable lexically
    without flagging every `model_copy` in the tree, which costs 2 named floors.
    """
    if not (isinstance(node.func, ast.Attribute) and node.func.attr in _COPY_SEAM_ATTRS):
        return False
    supplied = list(node.args) + [keyword.value for keyword in node.keywords]
    return any(
        isinstance(argument, ast.Dict)
        and any(key is not None and _fold_str(key) == "tier" for key in argument.keys)
        for argument in supplied
    )
```

In `_detect`'s `ast.Call` arm:

```python
        if _mutates_tier_in_a_copy(node):
            messages.append(_TIER_MUTATING_COPY_MESSAGE)
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/security/ -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_seven_shapes.py
git commit -m "feat: #539 R3 — receiver-blind tier-mutating copy detection"
```

---

### Task 9: The independent oracle

**Files:**
- Test: `tests/unit/security/test_check_tag_t3_seven_shapes.py`

**The repo's mandated independent oracle.** Feed
`tests/unit/security/test_t3_construction_requires_the_nonce_path.py`'s text through
`_scan_text` under a SYNTHETIC non-exempt path, and assert per-function verdicts. **The
expected function-name sets are LITERALS** — a set derived from the same predicate the
implementation uses is a tautological oracle, and this repo has shipped two.

That file scores **0 violations** today, so this test is the strongest single measure
that the seven rules actually reach real source rather than only the fixtures they were
written against.

- [ ] **Step 1: Write the test**

```python
_ORACLE = _REPO_ROOT / "tests/unit/security/test_t3_construction_requires_the_nonce_path.py"

# LITERALS, not a glob. `test_model_construct_still_works_for_a_lower_tier` does NOT end
# with `_still_works`, so a suffix pattern silently drops the floor that matters most.
_MUST_TRIP = frozenset({
    "test_bare_keyword_construction_is_refused",
    "test_model_construct_is_refused",
    "test_model_validate_is_refused",
    "test_model_validate_json_is_refused",
    "test_model_copy_update_to_t3_is_refused",
    "test_renamed_import_subscript_is_refused",
    "test_non_literal_generic_argument_is_refused",
})
_MUST_BE_CLEAN = frozenset({
    "test_the_authorised_path_still_works",
    "test_a_lower_tier_is_unaffected",
    "test_model_construct_still_works_for_a_lower_tier",
    "test_model_copy_still_works_when_not_touching_the_tier",
})


def _violations_by_function(text: str, path: Path) -> dict[str, int]:
    tree = ast.parse(text)
    spans = {
        node.name: range(node.lineno, (node.end_lineno or node.lineno) + 1)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    counts = dict.fromkeys(spans, 0)
    for line in check_tag_t3._scan_text(text, path):
        head = line.split(":", 2)
        if len(head) < 3 or not head[1].isdigit():
            continue
        lineno = int(head[1])
        for name, span in spans.items():
            if lineno in span:
                counts[name] += 1
    return counts


def test_the_independent_oracle_trips_on_every_refused_shape() -> None:
    text = _ORACLE.read_text(encoding="utf-8")
    synthetic = _REPO_ROOT / "src" / "alfred" / "_synthetic_oracle_probe.py"
    counts = _violations_by_function(text, synthetic)

    assert _MUST_TRIP <= set(counts), "the oracle file's function set moved"
    assert {name for name in _MUST_TRIP if counts[name] == 0} == set()


def test_the_independent_oracle_leaves_every_named_floor_clean() -> None:
    text = _ORACLE.read_text(encoding="utf-8")
    synthetic = _REPO_ROOT / "src" / "alfred" / "_synthetic_oracle_probe.py"
    counts = _violations_by_function(text, synthetic)

    assert _MUST_BE_CLEAN <= set(counts), "the oracle file's floor set moved"
    assert {name: counts[name] for name in _MUST_BE_CLEAN if counts[name]} == {}
```

- [ ] **Step 2: Run it**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_seven_shapes.py -q -k oracle`
Expected: PASS. If a `_MUST_TRIP` entry is 0, the rule does not reach real source —
fix the RULE, never the literal. If a `_MUST_BE_CLEAN` entry is non-zero, the rule has
an ergonomic cost the issue forbids.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/security/test_check_tag_t3_seven_shapes.py
git commit -m "test: #539 independent oracle over the nonce-path suite's own source"
```

---

### Task 10: PR-B close-out — mutation sweep, constraints-doc counts, `make check`

**Files:**
- Modify: `scripts/check_tag_t3.py` (docstring)
- Modify: `docs/superpowers/plans/2026-07-29-518-detector-review-constraints.md`

- [ ] **Step 1: Coverage**

Run:
```bash
uv run coverage run -m pytest tests/unit/security/ -q \
  && uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100 -m
```
Expected: 100%. Same no-pragma, no-ternary rule as Task 5.

- [ ] **Step 2: Mutation sweep, both directions**

| # | Mutant | Must red |
| --- | --- | --- |
| 1 | R1 branch deleted | `test_bare_keyword_construction_trips`, oracle `_MUST_TRIP` |
| 2 | R1 made receiver-blind on every Call (widening) | `test_a_foreign_receiver_seam_call_is_clean`, real-tree floor |
| 3 | R2 made tier-AGNOSTIC (drop the `_slice_verdict` check) | `test_a_benign_receiver_seam_call_is_clean` **and** oracle `test_model_construct_still_works_for_a_lower_tier` |
| 4 | R2 made receiver-BLIND (widening) | real-tree floor — 34 sites |
| 5 | R2 `_TAGGED_SEAM_ATTRS` → `_BASEMODEL_SEAM_ATTRS` (adds `copy`/`model_copy`) | `test_a_copy_not_touching_the_tier_is_clean_and_its_tier_twin_trips` |
| 6 | R3 reads only `keywords`, not `args` | `test_a_tier_mutating_copy_in_positional_position_trips` |
| 7 | R3 key match `==` → truthy/containment (widening) | `test_a_copy_not_touching_the_tier_is_clean_and_its_tier_twin_trips` |
| 8 | R3 scope widened to every Call (widening) | `test_a_tier_dict_not_passed_to_a_copy_seam_is_clean` |
| 9 | R3 `_fold_str` → raw `ast.Constant` | `test_a_folded_tier_key_trips` |

- [ ] **Step 3: Correct the three wrong counts in the constraints doc, in place**

Measured 2026-08-03 against `main` @ `054c13f7`, 332 files:

| Line | Says | Measured |
| --- | --- | --- |
| ~26 | "Six legitimate uses exist under the scan root" (`object.__setattr__`) | **3** — `plugins/web_fetch/allowlist.py:139`, `plugins/web_fetch/fetch_dispatcher.py:219`, `hooks/context.py:106` |
| ~71 | "~15 legitimate annotations (`content_store_base.py`, `quarantine_transport.py`)" | **22 across 5 files** — and it names 2 of the 5. The unlisted three are `orchestrator/core.py` (×4), `comms_mcp/real_turn_adapter.py` (×1) and exempt `tiers.py` (×9). **The first two are NOT exempt** |
| ~96 (plan doc) | "the 26 legitimate pydantic-seam sites and the 2 legitimate `model_copy(update=…)` sites" | **34 seam calls** outside `tiers.py` (`model_validate` 26, `model_validate_json` 6, `model_copy` 2), **0** with a TaggedContent-shaped receiver |

Date-stamp each correction (`measured 2026-08-03`) — a bare number rots, and #538's own
docstrings say so repeatedly. Where a count is only a proxy for a property, state the
property too.

- [ ] **Step 4: Extend the module docstring with R1/R2/R3's residuals**

Add, in the file's existing voice:

- **R2's safety is BORROWED from the runtime guard.**
  `TaggedContent[T2].model_construct(tier=T3, …)` slips the lexical rule entirely and is
  caught only by `_enforce_tier_admissible` / `model_post_init`. Say it plainly — a rule
  whose stated basis does not survive measurement is what this epic exists to stop.
- **R3's update mapping must be a literal at the call site.**
  `payload = {"tier": T3}; obj.model_copy(update=payload)` carries no `ast.Dict`.
- **R1 reads no tier at all**, deliberately: `tier=_ALIAS` and `**payload` reach the same
  write, so an unparameterised construction is refused on shape.

- [ ] **Step 5: `make check` and push**

Run: `make check; echo "EXIT=$?"` — check `$?`, do not pipe through `tail`.

- [ ] **Step 6: Commit and open PR B**

```bash
git add scripts/check_tag_t3.py docs/superpowers/plans/2026-07-29-518-detector-review-constraints.md
git commit -m "docs: #539 correct three measured counts the FP budget was calibrated off"
git push -u origin 539-construction-seam-and-copy-rules
```

Full `/review-pr` fleet + CodeRabbit, resolve every thread, `gh pr merge --rebase`.

---

# PR C — the `tokenize` suppression widening

### Task 11: R5 — `tokenize`-anchored suppression over the logical line

**Files:**
- Modify: `scripts/check_tag_t3.py` (`_TYPE_IGNORE_PATTERN` → a `tokenize` pass in `_scan_text`)
- Test: `tests/unit/security/test_check_tag_t3_suppression.py` (create)

**Interfaces:**
- Produces: `_SUPPRESSOR_PATTERN: re.Pattern[str]`, `_suppressed_lines(text: str) -> list[int]`.
  `_TYPE_IGNORE_MESSAGE` keeps its current text — the rule widens, the message does not
  need to.

**Three things force `tokenize`, and only `tokenize` gets all six cases right.**

1. **The naive top-level alternation is the likely wrong implementation.**
   `TaggedContent.*#\s*(?:type|pyright):\s*ignore|noqa` makes the `|noqa` arm match ANY
   line containing "noqa". **Measured: 98 hits vs 1 correctly grouped — 97 pure false
   positives.** A mutant that drops the non-capturing group must red a floor.
2. **A "token regex" is WORSE than the naive regex on one case**: it regresses
   prose-in-a-comment. Only `tokenize`-anchored extraction gets all six right
   (real suppressor / real `noqa` / real `pyright` / prose-in-a-comment / prose-in-a-string
   / docstring prose).
3. **`tokenize` closes a blind spot nobody raised.** Today's rule needs the suppressor
   and the word `TaggedContent` on the SAME PHYSICAL LINE, so reformatting a call across
   lines and putting `# type: ignore` on the closing paren makes it blind. Scoping to the
   enclosing LOGICAL line closes that.

**Measured cost: 1 hit on the real tree, inside the whole-file-exempt `tiers.py` —
identical to today.**

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/security/test_check_tag_t3_suppression.py` with the same
`spec_from_file_location` preamble.

```python
def test_a_real_type_ignore_on_a_taggedcontent_line_trips() -> None:
    assert check_tag_t3._TYPE_IGNORE_MESSAGE in _messages(
        "x = TaggedContent[T2](y)  # type: ignore[arg-type]\n"
    )


def test_a_real_pyright_ignore_trips() -> None:
    assert check_tag_t3._TYPE_IGNORE_MESSAGE in _messages(
        "x = TaggedContent[T2](y)  # pyright: ignore[reportGeneralTypeIssues]\n"
    )


def test_a_real_noqa_trips() -> None:
    assert check_tag_t3._TYPE_IGNORE_MESSAGE in _messages(
        "x = TaggedContent[T2](y)  # noqa: E501\n"
    )


def test_a_bare_noqa_trips() -> None:
    assert check_tag_t3._TYPE_IGNORE_MESSAGE in _messages("x = TaggedContent[T2](y)  # noqa\n")


def test_prose_in_a_comment_mentioning_noqa_is_clean() -> None:
    """THE 97-FALSE-POSITIVE CASE. A naive top-level alternation reds all of these."""
    assert _messages("x = TaggedContent[T2](y)  # we do not noqa TaggedContent here\n") == []
    assert _messages("# noqa is the wrong tool for TaggedContent problems\n") == []


def test_prose_in_a_string_is_clean() -> None:
    assert _messages('MSG = "TaggedContent  # type: ignore is banned"\n') == []


def test_docstring_prose_is_clean() -> None:
    assert _messages('"""Never write TaggedContent  # noqa in this repo."""\n') == []


def test_a_suppressor_on_a_line_with_no_taggedcontent_is_clean() -> None:
    assert _messages("x = plain_call(y)  # type: ignore[arg-type]\n") == []


def test_a_suppressor_on_the_closing_paren_of_a_multiline_call_trips() -> None:
    """TODAY'S BLIND SPOT. The suppressor and `TaggedContent` are on different lines."""
    source = "x = TaggedContent[T2](\n    content='a',\n    source='b',\n)  # type: ignore\n"

    assert check_tag_t3._TYPE_IGNORE_MESSAGE in _messages(source)


def test_the_naive_alternation_false_positive_count_is_zero_on_the_real_tree() -> None:
    """MEASURED FLOOR: 97 pure FPs if the non-capturing group is dropped."""
    paths = check_tag_t3._collect_paths([])

    assert len(paths) >= check_tag_t3._MIN_SCANNED_FILES
    assert [v for p in paths for v in check_tag_t3._scan_file(p)] == []


def test_an_untokenizable_file_is_reported_not_swallowed() -> None:
    """A file the tokenizer cannot read is a file the gate is not gating (#537)."""
    messages = _messages("x = (\n")

    assert messages, "an unterminated construct must not scan clean"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_suppression.py -q`
Expected: FAIL on `pyright`, `noqa`, and the multiline case.

- [ ] **Step 3: Implement**

```python
# ANCHORED AT THE START of a real COMMENT token's body. `re.match`, never `re.search`:
# a comment reading "we do not noqa TaggedContent here" is PROSE, and the 97 measured
# false positives of the naive form are exactly that shape.
#
# THE NON-CAPTURING GROUP IS LOAD-BEARING. Written as
# `#\s*(?:type|pyright):\s*ignore|noqa` the alternation binds at the TOP level, so the
# `noqa` arm matches any line containing the word — measured 98 hits against 1. A mutant
# that drops the group must red `test_prose_in_a_comment_mentioning_noqa_is_clean`.
_SUPPRESSOR_PATTERN: re.Pattern[str] = re.compile(r"(?:(?:type|pyright):\s*ignore|noqa)\b")


def _suppressed_lines(text: str) -> list[int]:
    """Line numbers of LOGICAL lines carrying a real suppressor comment.

    `tokenize`, not a line regex, for three measured reasons:

    * a regex over raw lines cannot tell a COMMENT from the same characters inside a
      string or a docstring — and a "token regex" is WORSE on one case than the naive
      form, because it readmits prose inside a real comment;
    * the suppressor and the thing it suppresses need not share a PHYSICAL line. Today's
      rule requires it, so reformatting a call across lines and putting `# type: ignore`
      on the closing paren makes the gate blind. The LOGICAL line is the right scope;
    * anchoring at the start of the comment body is what makes `noqa` safe to add at all.

    Raises `tokenize.TokenError` / `SyntaxError` on text the tokenizer cannot read; the
    caller reports that as a violation rather than swallowing it (#537 — a file the gate
    cannot read is a file the gate is not gating).
    """
    starts: list[int] = []
    comments: list[int] = []
    line_start = 1
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type == tokenize.COMMENT and _SUPPRESSOR_PATTERN.match(
            token.string.lstrip("#").strip()
        ):
            comments.append(token.start[0])
        if token.type == tokenize.NEWLINE:
            starts.append(line_start)
            for comment_line in comments:
                if line_start <= comment_line <= token.end[0]:
                    starts.append(-comment_line)
            line_start = token.end[0] + 1
    return starts
```

**Design the exact return shape during implementation** — the sketch above is the
mechanism, not the final signature. What the caller needs is: for each suppressor
comment, the `(first_line, last_line)` span of its enclosing logical line, so
`_scan_text` can test `"TaggedContent" in "\n".join(lines[first - 1:last])` and record
at the COMMENT's own line number. A comment before any `NEWLINE` (module-level, on its
own line) has a degenerate span of itself — cover that arm with a real input, not a
pragma.

In `_scan_text`, replace the `_TYPE_IGNORE_PATTERN` loop. The `tokenize` call is
INPUT-DRIVEN, so it belongs **outside** the `GateInternalError` fence, alongside
`ast.parse` — a `TokenError` is a property of the file, not a broken predicate. It is
already inside the outer `except Exception` arm that reports `_UNSCANNABLE_MESSAGE`.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/security/ -q`
Expected: PASS.

- [ ] **Step 5: Delete `_TYPE_IGNORE_PATTERN` and its now-stale docstring paragraph**

The module docstring's "The `# type: ignore` suppression sits in comment text that the
parser discards, so it stays on a line-based regex" is now FALSE. Rewrite it: the
suppression still sits in text the parser discards, which is why it needs `tokenize`
rather than `ast` — and why it is scoped to the LOGICAL line rather than the physical one.

- [ ] **Step 6: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_suppression.py
git commit -m "feat: #539 R5 — tokenize-anchored suppression over the logical line"
```

---

### Task 12: PR-C close-out

- [ ] **Step 1: Coverage at 100%**

Run:
```bash
uv run coverage run -m pytest tests/unit/security/ -q \
  && uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100 -m
```

- [ ] **Step 2: Mutation sweep**

| # | Mutant | Must red |
| --- | --- | --- |
| 1 | Drop the non-capturing group (top-level alternation) | `test_prose_in_a_comment_mentioning_noqa_is_clean` **and** the real-tree floor (97 FPs) |
| 2 | `re.match` → `re.search` | `test_prose_in_a_comment_mentioning_noqa_is_clean` |
| 3 | Logical-line span → physical line | `test_a_suppressor_on_the_closing_paren_of_a_multiline_call_trips` |
| 4 | `tokenize` → raw line iteration | `test_prose_in_a_string_is_clean`, `test_docstring_prose_is_clean` |
| 5 | Drop `pyright` from the alternation | `test_a_real_pyright_ignore_trips` |
| 6 | Drop `noqa` from the alternation | `test_a_real_noqa_trips`, `test_a_bare_noqa_trips` |
| 7 | Swallow `TokenError` and return `[]` | `test_an_untokenizable_file_is_reported_not_swallowed` |

- [ ] **Step 3: Update `_DECLARED_ALIAS_RESIDUALS` for the new literals**

`"type"`, `"pyright"`, `"ignore"` and `"noqa"` now reach the derived identifier set.
They are COMMENT TEXT, not identifiers — nothing in a source file can rebind them, and
a file that renames them renames nothing. Give them one shared residual saying exactly
that, pinned by `test_prose_in_a_comment_mentioning_noqa_is_clean`.

- [ ] **Step 4: `make check`, push, review, merge**

Run: `make check; echo "EXIT=$?"`

```bash
git push -u origin 539-tokenize-suppression-widening
```

Full `/review-pr` fleet + CodeRabbit, resolve every thread, `gh pr merge --rebase`.

- [ ] **Step 5: Verify the epic survived**

```bash
gh issue view 539   # expect CLOSED (auto-closed by the `feat: #539` subject)
gh issue view 536   # MUST still be OPEN unless every step is genuinely done
gh issue view 547   # still OPEN — its premise is corrected, not resolved
```

`fix:`/`feat:` with `#NNN` in the subject auto-closes issue NNN on merge, and the repo's
conventional-commit gate MANDATES that shape. **#518 closed twice with work undone.**
Check, every time.

---

## Self-review against the issue

| Issue scope item | Task |
| --- | --- |
| 1. Alias environment — five sets, fixed point, reverse-order test asserting the EXACT rule | 1, 3 (Step 1 test), 5 (mutant 1) |
| 2. `_slice_verdict` TOTAL, default-deny on SHAPE, benign seeds from PEP-695 TypeVars | 2 |
| 3. R1 / R2 / R3 / R4 | 6 / 7 / 8 / 3 |
| 4. Annotation immunity via a one-position whitelist, argued on the enumeration ground | 3 |
| 5. Suppression widening, `tokenize`-anchored | 11 |
| Known limitation (benign-NAME binding) named in the module docstring | 1 (docstring), 5 Step 3 |
| DoD: independent oracle, literal function sets, negative twin | 9 |
| DoD: mutation sweep both directions, each redding a NAMED floor | 5, 10, 12 |
| DoD: assert-RAN census in the same invocation as every real-tree floor | 3 Step 1, 11 Step 1 |
| DoD: module docstring states what the guard cannot do + the escape hatch | 5 Step 3, 10 Step 4 |
| DoD: correct the three wrong counts in the constraints doc in place | 10 Step 3 |
| Open thread: five alias sets must call `_alias_names`, not a second resolver | 1 |
| Open thread: `tag`/`cast`/`TaggedContent`/`T3` residual — the tripwire reds by design | 4 |
| Open thread: new keyed identifiers need meta-guard rows | 4 Step 5, 12 Step 3 |
| Open thread: 100% line+branch, no pragmas, no ternary laundering | 5 Step 1, 10 Step 1, 12 Step 1 |
| Open thread: #547 premise re-measured (2 exempt files → 1; conclusion survives) | 5 Step 4 |

## Out of scope, stated rather than silently dropped

- **#547 itself.** Re-measured: the premise's COUNT is wrong (1 exempt file, not 2) but
  its CONCLUSION survives — the failure condition is still unreachable while any exempt
  file is collected. This plan corrects the count in both doc sites and leaves the issue
  open.
- **`tag` and `cast` alias resolution.** Pre-existing, deliberately not widened by #538,
  and still declared residual after Task 4.
- **Stale local branches** (10, including the now-empty `518-detector-seven-shapes`).
  A `clean_gone` pass, not this work.
