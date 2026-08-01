# PR-B detector spec — additions forced by the PR-A review

Fold these into `docs/superpowers/plans/2026-07-29-518-check-tag-t3-seven-shapes.md`
(which lives on branch `518-check-tag-t3-seven-shapes`).

## Premise correction (the plan's opening claim was wrong)

The plan said the runtime layer was complete so the detector was pure
defence-in-depth. Disproved. Five more seams were verified admitted; PR-A closed
four. **Two are not closable at runtime at all**, so for those the detector is the
ONLY enforcement layer:

- unbound base dispatch — `BaseModel.copy(obj, update={"tier": T3})`,
  `BaseModel.model_construct.__func__(TaggedContent[T3], ...)`
- raw state writes — `object.__setattr__(obj, "tier", T3)`, `__new__` + `__setstate__`

## Definition of done additions

1. **A PR-A tripwire must be flipped.**
   `tests/adversarial/tier_laundering/test_tier_laundering_copy_seams.py::test_tl_2026_013_is_currently_undefended_at_the_authoring_layer_too`
   asserts the detector scans the residual spellings CLEAN, with a positive control.
   It is designed to FAIL when these rules land. Flip its assertion and rewrite
   `tl_base_dispatch_and_raw_state_write.yaml`'s `out_of_scope_rationale`.
2. **`object.__setattr__` must NOT be refused outright.** Six legitimate uses exist
   under the scan root: `src/alfred/plugins/web_fetch/allowlist.py`,
   `src/alfred/plugins/web_fetch/fetch_dispatcher.py`, `src/alfred/hooks/context.py`. The rule must key on
   the written attribute being `"tier"`, not on the call.
3. **New rules for the two runtime-unclosable shapes** (these are the highest-value
   rules in the PR, because nothing else can catch them):
   - `BaseModel`-receiver dispatch of any seam attr (`copy`, `model_copy`,
     `model_construct`, `model_validate*`).
   - `object.__setattr__(x, "tier", ...)`, `x.__dict__["tier"] = ...`,
     `__setstate__` with a tier key.
4. **`type(name, bases, ns)` three-arg subclassing of TaggedContent**, plus a
   namespace literal containing `"__module__": "alfred.security.tiers"` or
   `"_TaggedContent__enforce_tier_invariant"` — the two residuals PR-A documents.

## Test-design constraints (from the reviewers, all verified)

- **`assert returncode != 0` is vacuous** — an unhandled exception in the new
  alias/parent-map code also exits 1. Assert stderr starts with
  `check_tag_t3: violations found:` AND `"Traceback" not in stderr` AND exact
  message + count. Better: move rule tests onto a `_scan_text` seam and assert the
  returned list by EQUALITY (message line + snippet + lineno).
- **Every "must PASS" floor is green on unparseable text** — `_scan_file` swallows
  `SyntaxError` (tree=None, AST pass skipped) and `OSError` (returns clean). Use a
  shared `_plant()` helper that `compile()`s before writing and asserts the file
  round-trips.
- **Every negative floor needs a positive twin** built from the same text with one
  token swapped (`T2`→`T3`), asserted to TRIP — otherwise nothing proves the text
  reached the rule.
- **`downgrade_to_orchestrator` is `async def`** (`quarantine.py:1493`). An
  enclosing-function walk checking only `ast.FunctionDef` silently never matches,
  and NOTHING in the repo fails, because the real function body contains zero
  detectable violations. Test both `def` and `async def`.
- **R6 must key on (path, function)**, not function name alone — else
  `src/alfred/anything.py` with `async def downgrade_to_orchestrator` is exempt.
  This is CR-138 finding #11 recurring on a third axis.
- **Floor "real src/alfred passes clean" is a tautology** on a no-op detector: R1,
  R2, R3, R5 have zero live sites. Needs (a) an assert-RAN census (glob
  `src/alfred/**/*.py`, assert >= 250; 293 today) and (b) a positive control in the
  SAME invocation.
- **Per-rule DISTINCT messages**, else a shape test is satisfied by a different rule
  firing on the same line.
- **R4's fail-closed is fail-OPEN on non-`Name` slices** — `BinOp`
  (`TaggedContent["T" + "3"]`), `Call` (`TaggedContent[globals()["T3"]]`),
  `Subscript` (`TaggedContent[TIERS["T3"]]`). Restate as default-deny on SHAPE.
- **Define `benign_tier_names`** with alias resolution: `T2 as Broadcast` must PASS,
  `T3 as Wire` must TRIP. Add in-file PEP-695 TypeVars bound to `TrustTier` to the
  benign set or the first generic helper reds for a benign reason.
- **R4 must skip ANNOTATION position** — `TaggedContent[T3]` appears in ~15
  legitimate annotations (`content_store_base.py:83,91,157,159,162`,
  `quarantine_transport.py:217,219,223`). Only `ast.Call` func position counts.
- **Bind `X = TaggedContent[...]` into `tagged_names`**, not just bare
  `X = TaggedContent`.
- **Import the script via `spec_from_file_location` against the REAL path** — a
  tmp_path copy recomputes `_REPO_ROOT`/`_APPROVED_PATHS` and silently inverts every
  exemption. Assert `module._REPO_ROOT == <real repo>`.
- **The fixed-point alias loop needs a reverse-order test** (`B = A` before
  `A = TaggedContent`) or a single-pass implementation survives as a mutant.
- **Mutate in the WIDENING direction too** — `benign_tier_names = set()`, "flag every
  model_validate" — each must red a NAMED benign floor.
- **`scripts/check_tag_t3.py` is under NO coverage gate and NO mypy/pyright.**
  `pyproject.toml:210` scopes coverage to `src/alfred`; type-checkers run on `src`
  only. Add `coverage report --include='scripts/check_tag_t3.py' --fail-under=100`,
  which requires in-process tests (subprocess records nothing without
  `COVERAGE_PROCESS_START`) — an independent reason for the `_scan_text` seam.
- **Independent oracle available:**
  `tests/unit/security/test_t3_construction_requires_the_nonce_path.py` states all
  seven shapes as executable source and currently scores rc=0 / zero violations
  against the detector. Feed its text through `_scan_text` under a synthetic
  non-exempt path and assert every `test_*_is_refused` function body contains >= 1
  violation, with the expected function-name set as a LITERAL.

## Open decisions

- **quarantine.py exemption: narrow vs delete.** User asked to narrow to
  `downgrade_to_orchestrator`. Security reviewer argues DELETE is strictly better:
  the function constructs no TaggedContent and calls no `tag()`, a non-exempt copy
  scans clean, so the exemption is already dead and the docstring's justification is
  already false. Narrowing keeps a live soft-landing zone in the one function that
  provably does not need one, and forces the `_scan_text` + parent-map machinery
  whose only consumer is testing an exemption nobody uses. Implement the narrowing as
  asked; surface the deletion argument.
- **Scan root excludes `plugins/`** (`Makefile:171`, `pr-validate-python.yml:352`
  pass only `src/alfred`). 39 first-party plugin files, 10 import `alfred`, including
  `plugins/alfred_discord/inbound_emitter.py` — a real ingestion boundary. Widening
  is ~1 line and the tree is clean. Also `docs/` claims about approved homes appear in
  `glossary.md`, `python-conventions.md`, `subsystems/quarantine.md`,
  `ci/required-checks.md`, the slice-3 spec, plus Makefile/workflow comments.
