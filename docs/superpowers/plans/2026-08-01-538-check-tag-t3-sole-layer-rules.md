# #538 — `check_tag_t3` sole-layer rules: raw-state writes and the authorisation bypasses

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `scripts/check_tag_t3.py` refuse the raw-state-write vehicles and the
authorisation-bypass names — the two classes for which the authoring layer is the ONLY
enforcement layer that can exist — and delete the now-dead `quarantine.py` exemption.

**Architecture:** Seven new AST rules on the existing `_scan_text` seam, plus four shared
per-file maps. Every rule is **default-deny on the VEHICLE or the SHAPE**, never an
enumeration of spellings. No `src/alfred/**` behaviour changes; the only `src/` edits are
docstring text.

**Tech Stack:** Python 3.14+, `ast`, pytest. No new dependencies.

## THE RECURRING FAILURE — read this before writing any rule

Two review rounds produced **seven Critical bypasses, every one of the same shape**: a rule
keyed on a **bare identifier that Python lets you rebind**. An eighth was then found by
self-audit. The list, in order of discovery:

| Round | Rule keyed on | Bypass |
| --- | --- | --- |
| 1 | identifier `object` | `builtins.object.__setattr__`, `_o = object`, `from builtins import object as _o`, `type(obj).__mro__[-1].__setattr__` |
| 1 | field name `"tier"` only | `object.__setattr__(low, "content", ATTACKER)` |
| 1 | five dunder names | `gc.get_referents(obj)` names none of them |
| 1 | `ast.Constant` only | `"_set_authorized" + "_t3_nonce"` |
| 1 | hand-rolled receiver `isinstance` | `pydantic.BaseModel.model_copy(...)` |
| 2 | `_RAW_STATE_VEHICLE_ATTRS` as the only string set | `getattr(object, "__setattr__")(low, "tier", T3)` — **no `ast.Attribute` node at all** |
| 2 | `args[0]` must be named `self` | `def _apply(self, v): object.__setattr__(self, "content", v)` — no subclass needed |
| 2 | identifier `gc` / `ctypes` | `import gc as _g`, `from gc import get_referents` |
| self-audit | identifier `vars` | `_v = vars; _v(obj)["tier"] = T3` |

**The rule this produces, and it is binding on every rule in this plan:**

> **Every bare identifier a rule keys on MUST be resolved through `_alias_names`, and a
> meta-test must enumerate them.** An identifier is a *name*, and Python lets any name be
> rebound. Matching one spelling of a name closes one spelling.

Task 4 ships `test_every_keyed_identifier_is_alias_resolved` to enforce this, because the
first seven of the nine rows above were each "fix the spelling" and each produced the next
row. That test is the only thing in this plan that closes the CLASS.

## Revision history — this is v2

v1 of this plan went through a six-reviewer fleet (security, test, architect, cross-cutting,
devops, docs) which returned **57 findings, 7 Critical**. Five reviewers transcribed the plan
onto the real gate and executed it. What they found is folded in below; the headline items
are recorded here because each one is a trap the next author would otherwise re-walk.

- **Four executed security bypasses.** The security reviewer minted genuine
  `TaggedContent[T3]` objects with attacker content against v1's rules, and downgraded a real
  `tag_t3_with_nonce` T3 to T2 — raw untrusted text onto the privileged plane.
- **Ten of v1's ~37 tests passed against the UNMODIFIED script.** Including the two v1 called
  "THE SILENT TRAP" and "the ANTI-VACUITY TWIN".
- **v1's required 100% coverage gate was unsatisfiable.** Two reviewers independently proved
  a branch structurally unreachable (exhaustive: 0 of 406,901 and 0 of 16,276 inputs).
- **v1 broke `_scan_text`'s documented, test-pinned purity** while copying the now-false
  purity claim into a new docstring.
- **v1's doc scope missed 7 live stale claims**, including both copies inside the workflow
  that runs the gate.

## Global Constraints

- **`scripts/check_tag_t3.py` is at 100% line + branch coverage under a REQUIRED CI check**
  (`.github/workflows/ci.yml:162`). Baseline verified genuinely 100% at `3fcba193`. Every new
  branch needs a covering test. **No `# pragma: no cover`; do not touch
  `[tool.coverage.report] exclude_also`.** A branch that cannot be reached is a DESIGN fault —
  restructure it, do not exempt it.
- **Coverage runs are NOT concurrency-safe in a shared directory.** Isolated clone only.
- `mypy --strict` and `pyright` run over this script at **12** required sites
  (`ci.yml:139/893/1022`, `:142/896/1031`, `pr-validate-python.yml:221/279`, `Makefile:88`,
  `lefthook.yml:56/61`). The lefthook ones fire **before the branch can be pushed**.
- The gate runs under **bare `python3`** from the Makefile — no venv, no `alfred` importable.
  Import nothing beyond the stdlib already imported.
- **Touch no `src/alfred/**` behaviour.** Docstring text only.
- **`fix: #NNN` in a commit SUBJECT auto-closes NNN**, and the conventional-commit gate
  mandates a literal `#NNN` after the colon. Exactly one `fix: #538`. **Never `#536`, `#539`
  or `#518` in any subject — and never `Closes #536` in the PR BODY either**, which closes the
  epic on merge regardless of merge method.
- Per-rule **DISTINCT** messages; **no message a substring of another**
  (`test_every_collection_failure_message_is_enumerated` matches by containment).
- **Every new `_*_MESSAGE` must be added to the `findings` set** at
  `tests/unit/security/test_check_tag_t3_gate_integrity.py:143`.
- **Every negative floor carries a positive twin IN THE SAME TEST** — same text, one token
  swapped, asserted to TRIP. v1 shipped ten floors without one and all ten were vacuous.
- Assert returned lists by **equality**. `assert returncode != 0` is vacuous.
- **i18n does NOT apply** — `scripts/` is outside the catalog roots and outside CLAUDE.md hard
  rule #1's `src/alfred/` scope; 10 existing plain-English `_*_MESSAGE` constants are the
  precedent. (Verified by two reviewers.)
- **Markdown lint is a required check** and lints `docs/**`. Blank line around every fenced
  block and every list. v1 shipped 19 MD031/MD032 errors in this very file.

---

## Measured baseline — re-measured after the fleet, do not re-derive

Executed against the 332 tracked `.py` files under `_DEFAULT_SCAN_ROOTS` (`src/alfred` 293 +
`plugins` 39). Reference implementation:
`scratchpad/probe_538_v2.py`.

| Property | Measured |
| --- | --- |
| FULL rule set, all 332 files | **0 violations** |
| New exemptions required | **0** |
| `quarantine.py` non-exempt, full rule set | **0 violations** (1634 lines) |
| Attack corpus (incl. all 4 fleet bypasses) | **18/18 flagged** |
| Benign floors | **12/12 clean** |
| `tiers.py` private surface | **21 names**, derived == hard-coded |

### The rules, and why each is shaped that way

1. **Vehicle attributes** — `__dict__`, `__setstate__`, `__getstate__`, `__reduce__`,
   `__reduce_ex__`, `__new__`, `__mro__`, `__bases__`. Cost 1 (`tiers.py:508`, exempt).
2. **`__class__` in STORE/DEL context only.** A class swap is a laundering vehicle; a
   `.__class__.__name__` read is not. Context discriminates at zero cost — `invoke.py:1265`
   stays clean.
3. **`vars()`, receiver ALIAS-RESOLVED.** Cost 3 (all `tiers.py`). `_v = vars` and
   `from builtins import vars as _v` both scanned clean until the self-audit; `vars` was the
   last identifier in the file still matched as a literal.
4. **`X.__setattr__` — RECEIVER-BLIND, one-position whitelist.** Any reference outside
   `Call.func` position is denied. **v1 matched only the bare identifier `object`**, so
   `builtins.object.__setattr__`, `_o = object`, `from builtins import object as _o` and
   `type(obj).__mro__[-1].__setattr__` all scanned clean and were executed to mint T3.
5. **`__setattr__` call SHAPE** — admissible only when `args[0]` is the bare `Name` `self`
   AND `args[1]` folds to a plain non-dunder string literal that is **not in
   `_TAGGED_STATE_FIELDS = {"tier", "content", "source"}`**. v1 denied only `"tier"`, so
   `object.__setattr__(low, "content", ATTACKER)` was admitted — attacker text inside a T2
   object the orchestrator may read (hard rule #1 breach) — and `"source"` forged audit
   provenance. Round 2 then showed the `self` requirement alone is **not** a type guarantee:
   `def _apply(self, v): object.__setattr__(self, "content", v)` needs no subclass, just a
   parameter named `self`. Both conditions are kept (they compose), but the field ban is what
   actually holds. Cost 0 — no live site writes any of the three.
6. **Carrier-by-reference PRIMITIVES, module name ALIAS-RESOLVED** — `gc.get_referents`,
   `gc.get_objects`, `ctypes.py_object`, `ctypes.cast`, `copyreg._reconstructor`,
   `copyreg.__newobj__`, plus the `from gc import get_referents` direct-binding form.
   `gc.get_referents(obj)` hands back the instance mapping naming no vehicle. **Scoped to
   primitives, not modules**: a module ban costs 2 legitimate sites (`ctypes.CDLL` for libc in
   `supervisor/process_posture.py`, `gc.collect()` in `fd3_key_delivery.py`); the primitive
   ban costs **0**. Keying on the literal `gc` left `import gc as _g` clean.
7. **Vehicle name as a FOLDED string in code position**, over
   `_RAW_STATE_VEHICLE_NAMES = _RAW_STATE_VEHICLE_ATTRS | {"__setattr__", "__delattr__",
   "__class__"}`. **The string set is deliberately WIDER than the attribute set.**
   `getattr(object, "__setattr__")(low, "tier", T3)` produces **no `ast.Attribute` node at
   all**, so every attribute-keyed rule is blind to it; executed, it turned a
   `TaggedContent[T2]` into T3. `__setattr__` must NOT be added to the attribute set — the
   three live benign `object.__setattr__(...)` call sites all carry that attribute node, and
   the dedicated receiver-blind rules already cover it. `ast` folds *implicit* concatenation
   but not `+`, so `"_set_authorized" + "_t3_nonce"` escaped v1 and forged the nonce
   end-to-end. Fold `BinOp(Add)` chains and literal-only `JoinedStr`.
8. **Unbound `BaseModel` seam dispatch**, receiver collapsed by identifier. **v1 hand-rolled
   `isinstance` checks and missed `pydantic.BaseModel.model_copy(...)`** — the CR-138 round-2
   #2 class that `_arg_name` exists to close. Cost 0.
9. **`alfred.security.tiers` private surface** (21 names) in code position. Cost 0.

### Three findings that SUPERSEDE the issue body

1. **Do NOT scope the vehicle ban to "files that mention `TaggedContent`"** as the issue
   proposes. Unscoped costs the same (zero) and the scoped form has a live bypass — a file
   that receives a `TaggedContent` as a parameter and never spells the name. Confirmed by the
   architect independently.
2. **The prose exclusion is "bare string EXPRESSION STATEMENT", not `ast.get_docstring`.**
   `src/alfred/hooks/invoke.py:466` is a PEP-258 attribute docstring; `get_docstring` misses
   it and the rule reds. Measured: 1 false positive with `get_docstring`, **0** with the
   bare-`ast.Expr` form.
3. **`nonce_factory.py` needs (path, function) AND a module-level-alias-only arm.** Line 40 is
   a module-level import outside the exempt function. The second arm must additionally require
   `enclosing.get(lineno) is None`, or a function-local aliased import buys the exemption too.

### Accepted residuals — state them, do not claim they are closed

- **Cross-module re-export aliasing.** Both alias sets are per-file.
- **A name assembled from non-literal parts** (`"".join`, a variable, `exec`/`eval`).
- **Carrier-by-reference beyond the six named primitives.** The vehicle set is now a class ban
  plus a named primitive list, not a proof of completeness.
- **A name-keyed collision** — another module defining its own `_log_t3` reds benignly.
  Measured: zero today.
- **`TaggedContent.model_construct(...)`** is refused at RUNTIME only; the seam rule is
  receiver-scoped to `BaseModel` aliases.
- **`object.__setattr__(self, "metadata", …)` on a `TaggedContent`.** `metadata` is
  deliberately NOT in `_TAGGED_STATE_FIELDS`: `hooks/context.py:106` writes it on a
  `HookContext`, an unrelated frozen dataclass that happens to share the field name. Banning
  it would red a legitimate site for a name collision. The residual cannot change `tier`,
  `content` or `source`, so it cannot mint or relabel T3 — it can only alter auxiliary
  metadata. Named rather than silently accepted.
- **`self` is a NAMING convention, not a type guarantee.** Round 2 proved a plain function
  whose first parameter is called `self` reaches the admissible branch. `_TAGGED_STATE_FIELDS`
  is what actually holds; the `self` check narrows the surface but proves nothing on its own,
  and the code comment must not claim otherwise.

---

## Round-2 findings — binding requirements, verify each by execution

The round-2 fleet's three security Criticals are already folded into the rules above and
re-measured (0 violations / 332 files, 19/19 corpus, 0 false positives). What follows are the
remaining round-2 findings. **Each is a requirement on the implementer, not a suggestion**,
and each was produced by execution against a full Tasks 1-5 implementation.

### Determinate defects — the plan as written cannot be implemented until these are settled

- **R2-A (test2-002). `test_import_exemption_is_module_level_only` is unsatisfiable as
  written.** It expects messages at `:2` AND `:3`, but `_reg` is not a member of
  `_TIERS_PRIVATE_SURFACE`, so only `:2` can fire — and it directly contradicts
  `test_import_aliased_nonce_setter_is_refused`, which asserts the identical `_reg(...)` call
  does NOT red. No implementation satisfies both.
  **RESOLUTION: an aliased private import POISONS the asname.** Resolve private-surface names
  through the same per-file alias environment every other rule now uses — this is the meta-guard
  principle applied to the private-surface rule, and A16's whole point is that `_reg(mine)` is
  the laundering CALL, not the import. Update
  `test_import_aliased_nonce_setter_is_refused` to expect two messages (the binding and the
  use), and add the row to `test_every_keyed_identifier_is_alias_resolved`.
- **R2-B (test2-008 / sec2-006). `ruff check` FAILS on the plan's own snippet** —
  `ARG001 Unused function argument: object_names`. Making `__setattr__` receiver-blind left
  the `object` alias set vestigial. Delete `_alias_names(tree, "object")` and the `object_names`
  parameter, and stop crediting `_alias_names` with closing sec-001 — receiver-blindness is what
  closed it. `ruff check` is a required gate.
- **R2-C (test2-011). Task 2 Step 4 lists the Task 3 and Task 4 rules inside `_detect`.** Read
  literally that implements Tasks 3 and 4 in Task 2's commit, so their "run to verify failure"
  steps cannot fail and their messages land before their `findings`-set registration. `_detect`
  gains one rule per task; each task adds its own.
- **R2-D (test2-013). `_scan_text`'s new signature is never specified**, yet 20+ tests call it
  with two arguments and depend on path-keyed exemptions. Specify it:
  `_scan_text(text: str, path: Path, resolved: Path | None = None)`, where `resolved is None`
  means "use `path` as given". State that the default arm is what
  `test_scan_text_verdict_does_not_depend_on_the_working_directory` exercises, and TEST it.

### Test-adequacy defects — the mutation tables do not yet hold

Run every mutation. **8 of the 35 rows in v2 survived their named test**, five of them rows
this plan marks `[fleet]` and claims to have closed.

- **R2-E (test2-005). `test_every_declared_seam_attribute_is_enforced` is a TAUTOLOGICAL
  ORACLE** — it loops over `_BASEMODEL_SEAM_ATTRS`, the constant under test, so removing
  `model_validate` removes it from the oracle too. This reproduces the project's own recorded
  rule that an oracle must not reuse the implementation predicate, in the very test written to
  close that mutation. **Pin every set as a separate literal in the TEST file, assert equality
  with the module constant FIRST, then loop over the pinned literal.** Apply to
  `_BASEMODEL_SEAM_ATTRS`, `_RAW_STATE_VEHICLE_ATTRS`, `_RAW_STATE_VEHICLE_NAMES`,
  `_RAW_STATE_CARRIERS` and `_TAGGED_STATE_FIELDS`.
- **R2-F (test2-006). The prose floor cannot kill its mutant.** The STR rule matches by
  EQUALITY, and the fixture's docstring folds to a whole sentence, so the prose exclusion is
  never consulted. Use a bare docstring whose entire value IS a set member:
  `_scan_text('"""__dict__"""\n', _PROBE) == []`. That fixture is also the oracle for the
  equality-to-containment widening in R2-H.
- **R2-G (test2-004). Two rows are attributed to tests that cannot discriminate.** Every
  non-benign `__setattr__` fixture targets `obj`/`low`, so the `self` check short-circuits and
  the `name != tier` and dunder arms are never reached. Add self-target fixtures:
  `object.__setattr__(self, "__dict__", v)` and `object.__setattr__(self, computed, v)`.
- **R2-H (test2-010). 14 unlisted mutations survive the whole suite AND the real-tree scan.**
  Untested: 3 of 8 `_RAW_STATE_VEHICLE_ATTRS` members; 4 of 6 `_RAW_STATE_CARRIERS`
  (`ctypes.py_object` appears only as an argument in its fixture, never as `Call.func`);
  `del obj.__class__`; `_fold_str`'s `JoinedStr` arm; three arms of the private-surface
  derivation. **And a real WIDENING: changing the STR rule from equality to containment reds
  nothing and keeps rc=0.** Loop-over-the-pinned-set tests close most of this.
- **R2-I (test2-001). Vacuity is 4, and the DoD requires 0.**
  `test_qualified_receiver_does_not_widen_to_ordinary_modules` and
  `test_the_real_nonce_factory_file_scans_clean` are bare floors with no twin — a direct breach
  of this plan's own Global Constraint. `test_quarantine_scans_clean_without_its_exemption`
  passes on `main` for the OPPOSITE reason it exists (the file is still exempt there): move
  `assert not _is_exempt(_QUARANTINE)` INTO it so it cannot pass via the exemption.
- **R2-J (test2-003). Coverage is 98%, not 100%.** The named budget genuinely fixes v1's
  unreachable arc inside `_alias_names`, but a NEW uncovered arc appears at the `_scan_text`
  call site: nothing drives a >32-deep chain through the scanner, so `_ALIAS_BUDGET_MESSAGE` is
  never emitted. Also uncovered: both `self`-target arms of `_is_benign_setattr_target`, and
  the `asname` arm of the private-surface rule.
- **R2-K (test2-012). Three assertions cannot discriminate**, and two of them are dead branches
  reproduced as TERNARIES — which `coverage.py` does not branch on, so the required 100% gate is
  structurally blind to them. That exempts by construction exactly what the Global Constraints
  forbid exempting. Replace `fold('f"...")' is None or ... == "__dict__"` with the measured
  outcome; drop `_enclosing_functions`' `end_lineno` ternary (`end_lineno` is never `None` for a
  parsed `FunctionDef`) and `_record`'s `else ""` arm, or write inputs that reach them.

### Design corrections

- **R2-L (sec2-004). `_fold_str`'s recursion is input-driven but runs inside the `_detect`
  fence**, so a ~2000-operand `+` chain raises `GateInternalError`; `main` then discards every
  violation collected so far and exits 2, suppressing a real laundering finding in an earlier
  file. Merge is still blocked, so this hides the DIAGNOSIS rather than the gate. Either bound
  `_fold_str`'s depth explicitly and return `None` past the bound, or move it outside the fence
  alongside `ast.parse`. Bounding is preferred — it keeps the fence meaning "gate defect".
- **R2-M (sec2-005). The cardinality pin is defeated by swapping only the ARGUMENT** of the
  single `_set_authorized_t3_nonce` call: `(hits, aliases)` stays `(3, 1)`, it sits inside the
  `(path, function)` exemption, and it installs an attacker-held object as the authorised
  nonce (executed). Strengthen the pin to compare the exempt call's ARGUMENT against the
  expected `CapabilityGateNonce()` construction, or state plainly that the exemption trusts
  `nonce_factory.py`'s body and that this is the residual.
- **R2-N (test2-009). `_derive_tiers_private_surface` is documented DEFAULT-DENY but is an
  enumeration of six statement kinds.** Measured module-level misses: `from m import y as _z`,
  `import _mod`, `for` targets, `with ... as`, `except ... as`, walrus, match captures, and —
  inside the shape the oracle claims to cover — `_h, *_rest = ...` misses `_rest`. **Use an
  `ast.Name(ctx=Store)` walk per module-level statement**, which covers every shape and passes
  the same oracle. Extend the oracle fixture so it DISCRIMINATES between the two designs.
  (Good news, verified: the deeper walk still yields exactly 21 on the real `tiers.py`, so the
  hard-coded constant is not broken on day one, and `ast.TypeAlias` behaves as assumed.)
- **R2-O (test2-007). The Task 5 invariant sweep is blind to all three stale claims inside
  `check_tag_t3.py`** — the plan's own primary edit sites — because the qualifier word is
  line-wrapped and `git grep` is line-scoped. It also flags
  `docs/runbooks/slice-3-operator-migration.md:651` ("wait for reviewer approval"), an unrelated
  row, and is tripped by this plan's own prescribed replacement wording. Use a paragraph-scoped
  search (`git grep -A2` or a small Python pass over the file text) and exclude the runbook by
  path with a stated reason.
- **R2-P (sec2-007). The `_fold_str` residual is understated.** `"_set_authorized%s" %
  "_t3_nonce"`, `"_set_authorized{}".format("_t3_nonce")` and `"".join([...])` are assembled
  ENTIRELY from literals and all scan clean. State the residual as "a name assembled by any
  operation other than `+` or implicit concatenation", not "from non-literal parts".

## File structure

| File | Change |
| --- | --- |
| `scripts/check_tag_t3.py` | Modify (~+300 lines) |
| `tests/unit/security/test_check_tag_t3_sole_layer_rules.py` | Create |
| `tests/unit/security/test_check_tag_t3_gate_integrity.py` | Modify (`findings` set) |
| `tests/unit/security/test_tag_t3_capability_gate.py` | Modify (stale docstring + name) |
| `tests/unit/security/test_check_tag_t3_subscript.py` | Modify (plural test name) |
| `tests/adversarial/tier_laundering/test_tier_laundering_copy_seams.py` | Modify (tripwire) |
| `tests/adversarial/tier_laundering/tl_base_dispatch_and_raw_state_write.yaml` | Modify |
| `tests/adversarial/tier_laundering/README.md` | Modify (row 56) |
| `.github/workflows/pr-validate-python.yml` | Modify (comments at :299, :348) |
| `src/alfred/security/tiers.py` | Modify (docstring text only) |
| `docs/adr/0058-single-approved-t3-authoring-home.md` | Create |

The gate stays ONE file. Not for v1's stated reasons (coverage `--include` takes globs and
comma lists; `ci.yml:2548` already uses a 14-entry list, and mypy/pyright take directories)
but for the real ones: the bare-`python3` invocation and a pinned call-site string.

---

## Task 0: Fix the two gates this plan currently fails

Do this FIRST — `lefthook` blocks the push otherwise, and the Markdown gate is required.

- [ ] **Step 1: Confirm both failures**

```bash
cd /Users/iandominey/projects/AlfredOS
npx --yes markdownlint-cli2@0.22.1 "docs/**/*.md"; echo "rc=$?"
```

Expected: 19 MD031/MD032 errors, all in this plan file. (This v2 file is already compliant —
if the count is 0, this step is satisfied; record that and move on.)

- [ ] **Step 2: Verify no other doc regressed**

```bash
npx --yes markdownlint-cli2@0.22.1 "docs/**/*.md" 2>&1 | tail -3
```

Expected: `Summary: 0 error(s)`.

- [ ] **Step 3: Commit if anything changed**

```bash
git add docs/superpowers/plans/2026-08-01-538-check-tag-t3-sole-layer-rules.md
git commit -m "docs: #538 revise the sole-layer plan after the review fleet

Refs #538"
```

---

## Task 1: Shared per-file maps

Four maps every later rule needs. Each carries a trap that fails SILENTLY.

**Files:**

- Modify: `scripts/check_tag_t3.py` (helpers after `_arg_name`, ~line 355)
- Test: `tests/unit/security/test_check_tag_t3_sole_layer_rules.py` (create)

**Interfaces produced:**

- `_prose_string_ids(tree: ast.AST) -> frozenset[int]`
- `_enclosing_functions(tree: ast.AST) -> dict[int, str]`
- `_fold_str(node: ast.expr) -> str | None`
- `_alias_names(tree: ast.AST, seed: str) -> tuple[frozenset[str], bool]`
- `_ALIAS_RESOLUTION_BUDGET: int`

- [ ] **Step 1: Write the failing tests**

```python
"""Unit tests for the #538 sole-layer rules in ``scripts/check_tag_t3.py``.

Loaded via ``spec_from_file_location`` against the REAL script path: a ``tmp_path``
copy would recompute ``_REPO_ROOT`` from ``__file__`` and silently invert every
exemption, so a copy-based test measures the wrong tree while still passing.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "check_tag_t3.py"

_spec = importlib.util.spec_from_file_location("check_tag_t3_sole_layer", _SCRIPT)
assert _spec is not None and _spec.loader is not None
check_tag_t3 = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = check_tag_t3
_spec.loader.exec_module(check_tag_t3)

assert check_tag_t3._REPO_ROOT == _REPO_ROOT, (
    f"loaded the wrong script: {check_tag_t3._REPO_ROOT} != {_REPO_ROOT}"
)

_PROBE = Path("/nonexistent/probe.py")
_NONCE_FACTORY = _REPO_ROOT / "src" / "alfred" / "bootstrap" / "nonce_factory.py"
_QUARANTINE = _REPO_ROOT / "src" / "alfred" / "security" / "quarantine.py"
_TIERS = _REPO_ROOT / "src" / "alfred" / "security" / "tiers.py"


def _messages(source: str, path: Path = _PROBE) -> list[str]:
    """Violation MESSAGE lines only — odd-indexed entries are code snippets."""
    return [v for v in check_tag_t3._scan_text(source, path) if not v.startswith("  ")]


def test_prose_string_ids_covers_all_four_docstring_shapes() -> None:
    """Module, class, function AND PEP-258 attribute docstrings are prose.

    ``ast.get_docstring`` sees only the first three. ``src/alfred/hooks/invoke.py:466``
    is the fourth shape and is a MEASURED false positive without it.
    """
    source = '''\
"""module docstring"""
X = 1
"""attribute docstring — PEP 258, NOT an ast docstring"""


class C:
    """class docstring"""


async def f() -> None:
    """async function docstring"""
'''
    tree = ast.parse(source)
    prose = check_tag_t3._prose_string_ids(tree)
    found = {
        n.value.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Constant)
        and isinstance(n.value.value, str)
        and id(n.value) in prose
    }
    assert found == {
        "module docstring",
        "attribute docstring — PEP 258, NOT an ast docstring",
        "class docstring",
        "async function docstring",
    }


def test_prose_string_ids_excludes_strings_in_code_position() -> None:
    """A string ARGUMENT is code, not prose — this is what catches A17.

    ``getattr(_t, "_set_authorized_t3_nonce")`` hides the name in a string. If the
    prose exclusion swallowed every string constant, A17 would walk straight through.
    POSITIVE TWIN included so this cannot pass on an empty prose set.
    """
    tree = ast.parse('getattr(_t, "_set_authorized_t3_nonce")\nx = "not prose"\n"""prose"""\n')
    prose = check_tag_t3._prose_string_ids(tree)
    strings = {
        n.value: id(n) in prose
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    }
    assert strings["_set_authorized_t3_nonce"] is False
    assert strings["not prose"] is False
    assert strings["prose"] is True, "positive twin: a bare string statement IS prose"


def test_enclosing_functions_matches_async_def_as_well_as_def() -> None:
    """THE SILENT TRAP: a ``FunctionDef``-only walk matches nothing for ``async def``.

    Nothing in the repo fails when that mutation is applied — the one real
    (path, function) exemption is a plain ``def``.
    """
    fmap = check_tag_t3._enclosing_functions(
        ast.parse("def sync_one():\n    a = 1\n\n\nasync def async_one():\n    b = 2\n")
    )
    assert fmap[2] == "sync_one"
    assert fmap[6] == "async_one", "async def unmapped — the walk matches ast.FunctionDef only"


def test_enclosing_functions_reports_the_innermost_function() -> None:
    """A nested def must shadow its parent, or an exemption leaks outward."""
    fmap = check_tag_t3._enclosing_functions(
        ast.parse("def outer():\n    def inner():\n        x = 1\n    y = 2\n")
    )
    assert fmap[3] == "inner"
    assert fmap[4] == "outer"


def test_enclosing_functions_leaves_module_scope_unmapped() -> None:
    """Module-level lines have no enclosing function.

    Load-bearing: the module-level import exemption keys on this being ``None``.
    """
    fmap = check_tag_t3._enclosing_functions(ast.parse("import os\n\n\ndef f():\n    x = 1\n"))
    assert 1 not in fmap
    assert fmap[5] == "f"


def test_fold_str_folds_binop_and_fstring_but_not_computed_values() -> None:
    """``ast`` folds IMPLICIT concatenation but not ``+``.

    ``"_set_authorized" + "_t3_nonce"`` escaped the v1 rule and was executed to forge
    the nonce and mint a legitimate T3 for attacker content through the front door.
    """

    def fold(src: str) -> str | None:
        return check_tag_t3._fold_str(ast.parse(src, mode="eval").body)

    assert fold('"_set_authorized" + "_t3_nonce"') == "_set_authorized_t3_nonce"
    assert fold('"a" "b"') == "ab"
    assert fold('"__di" + "ct" + "__"') == "__dict__"
    assert fold('f"__di{""}ct__"') is None or fold('f"__di{""}ct__"') == "__dict__"
    assert fold("name") is None, "a bare name is not a literal"
    assert fold('"".join(parts)') is None, "a computed value must not fold"
    assert fold("1 + 2") is None, "non-str BinOp must not fold"


def test_alias_names_reaches_a_fixed_point_in_reverse_order() -> None:
    """``C = B`` written BEFORE ``B = BaseModel``.

    PROVEN REQUIRED by mutation: a single pass yields ``{BaseModel, B}`` and MISSES
    ``C``. Asserted on membership, not on "trips", because the single-pass mutant
    still trips under a different rule.
    """
    names, overflow = check_tag_t3._alias_names(
        ast.parse("from pydantic import BaseModel\nC = B\nB = BaseModel\n"), "BaseModel"
    )
    assert names == frozenset({"BaseModel", "B", "C"})
    assert overflow is False


def test_alias_names_reports_budget_exhaustion_instead_of_looping() -> None:
    """The budget is a NAMED CONSTANT, so exhaustion is REACHABLE — and testable.

    v1 bounded the loop by ``len(assignments) + 1``, which makes the loop-exhaustion
    arc unreachable BY CONSTRUCTION: two reviewers proved it independently (0 of
    406,901 and 0 of 16,276 exhaustive inputs reach it). Under the repo's no-pragma
    rule that made the required 100% branch gate unsatisfiable. An input-INDEPENDENT
    budget makes the arc a real, reachable, fail-closed outcome.
    """
    depth = check_tag_t3._ALIAS_RESOLUTION_BUDGET + 5
    chain = "from pydantic import BaseModel\n"
    chain += "".join(f"a{i} = a{i - 1}\n" for i in range(depth, 0, -1))
    chain += "a0 = BaseModel\n"
    _, overflow = check_tag_t3._alias_names(ast.parse(chain), "BaseModel")
    assert overflow is True

    _, shallow = check_tag_t3._alias_names(
        ast.parse("from pydantic import BaseModel\nB = BaseModel\n"), "BaseModel"
    )
    assert shallow is False, "positive twin: an ordinary file must NOT report overflow"
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -v
```

Expected: FAIL — `AttributeError: … has no attribute '_prose_string_ids'`

- [ ] **Step 3: Implement the four maps**

Insert into `scripts/check_tag_t3.py` after `_arg_name`:

```python
# Bounded, and deliberately INPUT-INDEPENDENT. A bound of `len(assignments) + 1`
# makes the loop-exhaustion arc unreachable BY CONSTRUCTION — the fixed point always
# converges first — and this file is under a REQUIRED 100% branch gate with no
# pragmas allowed, so an unreachable arc is an unsatisfiable gate, not a safe
# default. A fixed budget makes exhaustion a real outcome a test can reach, and the
# honest disposition for it is a reported violation: the input is pathological, not
# the gate (contrast `GateInternalError`, which means the gate itself is broken).
_ALIAS_RESOLUTION_BUDGET: int = 32


def _prose_string_ids(tree: ast.AST) -> frozenset[int]:
    """``id()`` of every string constant that is PROSE rather than code.

    Prose is a **bare string expression statement**: a module, class or function
    docstring, or a PEP-258 attribute docstring (a bare string after an assignment).
    ``ast.get_docstring`` covers only the first three; ``src/alfred/hooks/invoke.py:466``
    is the fourth shape and is a MEASURED false positive without it.

    WHY NOT exclude every string constant: ``getattr(_t, "_set_authorized_t3_nonce")``
    hides the name in a string ARGUMENT. Excluding all strings would admit it. The
    discriminator is POSITION — a string that is a whole statement documents; a string
    anywhere else is data the program uses.

    WHAT THIS CANNOT DO: a ``#`` comment is invisible to the parser, so a private name
    there is neither prose-excluded nor flagged. Correct (a comment cannot launder) but
    a different mechanism from this one.
    """
    return frozenset(
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    """Map every line to its INNERMOST enclosing function name.

    Module-scope lines are ABSENT from the map, which is load-bearing: the
    module-level import exemption keys on ``.get(lineno) is None``.

    **Both ``def`` and ``async def``**, in ONE ``isinstance`` over the tuple. A walk
    matching only ``ast.FunctionDef`` silently maps nothing for ``async def`` and no
    test in this repo fails — the sole real (path, function) exemption is a plain
    ``def``. One tuple check also means the 332-file real-tree scan exercises both
    node types, so the branch cannot rot behind a fixture.

    ``ast.walk`` is breadth-first, so a nested function is visited AFTER the function
    containing it and correctly overwrites its parent's lines.
    """
    mapping: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = node.end_lineno if node.end_lineno is not None else node.lineno
            for line in range(node.lineno, end + 1):
                mapping[line] = node.name
    return mapping


def _fold_str(node: ast.expr) -> str | None:
    """Constant-fold a string expression, or ``None`` if it is not a literal.

    ``ast.parse`` folds IMPLICIT concatenation (``"a" "b"``) into one ``Constant`` but
    leaves ``"a" + "b"`` as a ``BinOp``. Matching raw ``Constant`` nodes therefore
    missed ``"_set_authorized" + "_t3_nonce"``, which the review fleet executed
    end-to-end: it registered an attacker nonce and minted a fully legitimate
    ``TaggedContent[T3]`` for attacker content through ``tag_t3_with_nonce``.

    Recursion is bounded by the expression's own depth, and ``_scan_text``'s broad
    ``except Exception`` arm already reports a ``RecursionError`` as an unscannable
    file rather than letting it abort the run (#542).

    Deliberately NOT ``ast.literal_eval``: that evaluates tuples, dicts and numbers
    too, so it would answer a different question and raise on the common case.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_str(node.left)
        right = _fold_str(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            folded = _fold_str(value)
            if folded is None:
                return None
            parts.append(folded)
        return "".join(parts)
    return None


def _alias_names(tree: ast.AST, seed: str) -> tuple[frozenset[str], bool]:
    """Local names bound to ``seed``, to a fixed point. Returns (names, overflowed).

    Two binding forms: ``from m import X as Y`` and a plain ``B = X`` rebind, including
    chains. THE FIXED POINT IS PROVEN REQUIRED: with ``C = B`` written BEFORE
    ``B = BaseModel``, a single pass yields ``{BaseModel, B}`` and misses ``C``. Source
    order is the author's to choose, so a resolver that depends on it is one an attacker
    controls.

    Parameterised by ``seed`` because BOTH ``BaseModel`` and ``object`` need it. v1
    built this for ``BaseModel`` only and matched ``object`` as a bare identifier, so
    ``builtins.object.__setattr__``, ``_o = object`` and
    ``from builtins import object as _o`` all scanned clean — executed, they minted
    genuine T3 objects with attacker content.
    """
    names = {seed}
    assignments: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.alias) and node.name == seed and node.asname is not None:
            names.add(node.asname)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.append((target.id, node.value.id))
    for _ in range(_ALIAS_RESOLUTION_BUDGET):
        grown = {t for t, source in assignments if source in names} - names
        if not grown:
            return frozenset(names), False
        names |= grown
    return frozenset(names), True
```

- [ ] **Step 4: Run to verify pass**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -v
```

Expected: 8 passed.

- [ ] **Step 5: Mutation-test the traps**

Each script MUST carry `assert new != s` — a mutation that silently stops matching
turns "the mutant survived" into a false conclusion (that false alarm cost a session
on #552).

> **STAGE BEFORE YOU MUTATE.** At this point the implementation is still uncommitted,
> so a bare `git checkout scripts/check_tag_t3.py` restores **HEAD** and destroys the
> work you are testing. Run `git add scripts/check_tag_t3.py` FIRST, so `git checkout`
> restores from the index, and verify with `sha256sum` after each trap. Found during
> Task 1 implementation; applies to every mutation step in this plan.

```bash
cd /Users/iandominey/projects/AlfredOS

# Trap A — FunctionDef-only walk.
python3 - <<'PY'
import pathlib
p = pathlib.Path("scripts/check_tag_t3.py"); s = p.read_text()
new = s.replace("isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))",
                "isinstance(node, ast.FunctionDef)")
assert new != s, "MUTATION DID NOT APPLY"
p.write_text(new)
PY
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -q; echo "rc=$? (MUST be non-zero)"
git checkout scripts/check_tag_t3.py

# Trap B — prose set widened to EVERY string constant (v1's mutant crashed instead
# of widening, so the suite red for the wrong reason).
python3 - <<'PY'
import pathlib
p = pathlib.Path("scripts/check_tag_t3.py"); s = p.read_text()
old = """        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)"""
new_body = """        id(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)"""
assert old in s, "MUTATION DID NOT APPLY"
p.write_text(s.replace(old, new_body))
PY
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -q; echo "rc=$? (MUST be non-zero)"
git checkout scripts/check_tag_t3.py

# Trap C — single-pass alias resolution.
python3 - <<'PY'
import pathlib
p = pathlib.Path("scripts/check_tag_t3.py"); s = p.read_text()
new = s.replace("for _ in range(_ALIAS_RESOLUTION_BUDGET):", "for _ in range(1):")
assert new != s, "MUTATION DID NOT APPLY"
p.write_text(new)
PY
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -q; echo "rc=$? (MUST be non-zero)"
git checkout scripts/check_tag_t3.py

# Trap D — drop the BinOp arm from _fold_str.
python3 - <<'PY'
import pathlib
p = pathlib.Path("scripts/check_tag_t3.py"); s = p.read_text()
new = s.replace("    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):",
                "    if False:")
assert new != s, "MUTATION DID NOT APPLY"
p.write_text(new)
PY
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -q; echo "rc=$? (MUST be non-zero)"
git checkout scripts/check_tag_t3.py
```

- [ ] **Step 6: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_sole_layer_rules.py
git commit -m "test: #538 per-file maps for the sole-layer rules

Refs #538"
```

---

## Task 2: The raw-state-write vehicle ban, and the tripwire flip

**Files:**

- Modify: `scripts/check_tag_t3.py`
- Modify: `tests/unit/security/test_check_tag_t3_gate_integrity.py:143`
- Modify: `tests/adversarial/tier_laundering/test_tier_laundering_copy_seams.py`
- Test: append to `tests/unit/security/test_check_tag_t3_sole_layer_rules.py`

**Interfaces produced:** `_RAW_VEHICLE_ATTR_MESSAGE`, `_RAW_VEHICLE_VARS_MESSAGE`,
`_RAW_VEHICLE_STR_MESSAGE`, `_RAW_SETATTR_SHAPE_MESSAGE`, `_RAW_SETATTR_ALIASED_MESSAGE`,
`_RAW_CLASS_SWAP_MESSAGE`, `_RAW_CARRIER_MESSAGE`, `_RAW_STATE_VEHICLE_ATTRS`,
`_RAW_STATE_CARRIERS`, `_record`, `_is_benign_setattr_target`.

- [ ] **Step 1: Write the failing tests**

Every negative floor below carries its positive twin **in the same test**. v1 shipped
ten bare floors and all ten passed against the unmodified script.

```python
def test_a01_object_setattr_writing_dunder_dict_is_refused() -> None:
    """A01 — the decisive spelling; round-2 minted a real TaggedContent[T3] with it.

    A01 defeats the "key on the written ``tier`` attribute" rule BY CONSTRUCTION: the
    attribute written is ``__dict__``. That is why the VEHICLE is banned, not the spelling.
    """
    source = 'object.__setattr__(obj, "__dict__", {"tier": T3})\n'
    assert check_tag_t3._scan_text(source, _PROBE) == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}",
        '  object.__setattr__(obj, "__dict__", {"tier": T3})',
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}",
        '  object.__setattr__(obj, "__dict__", {"tier": T3})',
    ]


def test_setattr_receiver_is_matched_by_alias_not_by_the_bare_name_object() -> None:
    """FLEET FINDING sec-001 — v1 matched only the identifier ``object``.

    All four spellings below scanned CLEAN under v1 and were EXECUTED to mint genuine
    TaggedContent[T3] objects with attacker-controlled content; one downgraded a real
    tag_t3_with_nonce T3 to T2, putting raw untrusted text on the privileged plane.
    """
    for label, source in {
        "builtins": 'import builtins\nbuiltins.object.__setattr__(low, "tier", T3)\n',
        "rebind": '_o = object\n_o.__setattr__(low, "tier", T3)\n',
        "import-alias": 'from builtins import object as _o\n_o.__setattr__(low, "tier", T3)\n',
        "mro": 'type(low).__mro__[-1].__setattr__(low, "tier", T3)\n',
    }.items():
        assert any(
            check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE in m for m in _messages(source)
        ), f"{label} spelling was admitted"


def test_setattr_shape_denies_every_tagged_content_field_target() -> None:
    """FLEET FINDING sec-002 — v1 denied only ``"tier"``.

    ``object.__setattr__(low, "content", ATTACKER)`` was EXECUTED to place raw
    attacker-controlled text inside a T2-tagged object the privileged orchestrator is
    entitled to read — a hard-rule-#1 breach. ``"source"`` forged audit provenance.

    The discriminator is the TARGET: every live benign site writes ``self``.
    """
    assert _messages('object.__setattr__(low, "content", ATTACKER)\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]
    assert _messages('object.__setattr__(low, "source", "forged")\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]
    assert _messages('object.__setattr__(low, "tier", T3)\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]


def test_frozen_dataclass_post_init_idiom_stays_clean_with_a_positive_twin() -> None:
    """NEGATIVE FLOOR + POSITIVE TWIN in one invocation.

    Three live sites depend on the clean half: ``hooks/context.py:106``,
    ``plugins/web_fetch/allowlist.py:139``,
    ``plugins/web_fetch/fetch_dispatcher.py:219``. Refusing ``object.__setattr__``
    outright reds all three.

    The twin swaps ONE token (``self`` -> ``low``) and must trip, which is what proves
    the clean text reached the rule at all rather than the rule being absent.
    """
    benign = 'object.__setattr__(self, "metadata", dict(self.metadata))\n'
    assert check_tag_t3._scan_text(benign, _PROBE) == []
    twin = 'object.__setattr__(low, "metadata", dict(self.metadata))\n'
    assert _messages(twin) == [f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"]


def test_setattr_outside_call_position_is_refused() -> None:
    """A05 — aliasing the callable defeats every rule keyed on the CALL.

    The one-position whitelist closes it: ``Call.func`` is the only admissible position.
    Never an ancestor blacklist — that must ENUMERATE the bad positions and silently
    widens the day a new one appears.
    """
    for source in (
        "_osa = object.__setattr__\n",
        "apply(object.__setattr__, obj, 'tier', T3)\n",
        "def get():\n    return object.__setattr__\n",
    ):
        assert any(
            check_tag_t3._RAW_SETATTR_ALIASED_MESSAGE in m for m in _messages(source)
        ), f"admitted: {source!r}"


def test_vehicle_attributes_are_refused() -> None:
    """A02, A07 and the rest of the raw-state class, banned as VEHICLES."""
    for source in (
        'obj.__dict__.update({"tier": T3})\n',
        'd = obj.__dict__\nd["tier"] = T3\n',
        'obj.__setstate__({"tier": T3})\n',
        "o = TaggedContent.__new__(TaggedContent[T3])\n",
        "f, args = obj.__reduce__()\n",
        "base = type(low).__mro__[-1]\n",
    ):
        assert any(
            check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE in m for m in _messages(source)
        ), f"admitted: {source!r}"


def test_class_swap_is_refused_but_a_class_read_is_not() -> None:
    """``__class__`` discriminated by CONTEXT, not by name.

    A class swap is a laundering vehicle; ``exc.__class__.__name__`` (live at
    ``hooks/invoke.py:1265``) is an ordinary read. Banning the name costs a false
    positive; banning the STORE context costs zero.
    """
    assert _messages("low.__class__ = Evil\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_CLASS_SWAP_MESSAGE}"
    ]
    assert check_tag_t3._scan_text('t = {"x": exc.__class__.__name__}\n', _PROBE) == []


def test_vars_is_refused_and_ordinary_getattr_is_not() -> None:
    """A03 — ``vars(obj)`` returns the mapping ``__dict__`` does.

    Twin floor: ``getattr(prev, field)`` is four live sites in
    ``policies/snapshot_ref.py``. Banning non-literal ``getattr`` outright costs 7
    false positives (measured); this rule does not do that.
    """
    assert _messages('vars(obj)["tier"] = T3\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_VARS_MESSAGE}"
    ]
    assert check_tag_t3._scan_text("prev_val = getattr(prev, field)\n", _PROBE) == []


def test_vehicle_dunder_named_as_a_folded_string_is_refused() -> None:
    """A06 — ``getattr(obj, "__dict__")`` produces no ``ast.Attribute``.

    The folded form is the fleet's sec-004 shape: ``ast`` folds implicit concatenation
    but not ``+``.
    """
    for source in (
        'getattr(obj, "__dict__")["tier"] = T3\n',
        '_A = "__dict__"\n',
        'getattr(obj, "__di" + "ct__")["tier"] = T3\n',
    ):
        assert any(
            check_tag_t3._RAW_VEHICLE_STR_MESSAGE in m for m in _messages(source)
        ), f"admitted: {source!r}"


def test_a_raw_state_dunder_in_prose_stays_clean_with_a_positive_twin() -> None:
    """WIDENING GUARD for the string rule (fleet finding arch-004/test-003 M1).

    The real tree contains ZERO prose-position vehicle strings, so neither the
    real-tree scan nor any other floor can kill a mutant that drops the prose
    exclusion here. This test is the only thing that can.
    """
    assert check_tag_t3._scan_text('"""Explains ``obj.__dict__`` handling."""\n', _PROBE) == []
    assert _messages('x = "__dict__"\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"
    ]


def test_carrier_by_reference_primitives_are_refused() -> None:
    """FLEET FINDING sec-003 — ``gc.get_referents(obj)`` names no vehicle at all.

    Scoped to the reaching PRIMITIVES, not to the modules: a module-scoped ban costs
    two legitimate sites (``ctypes.CDLL`` for libc in ``supervisor/process_posture.py``,
    ``gc.collect()`` in ``fd3_key_delivery.py``); the primitive ban costs ZERO.
    Both live benign uses are the twin here.
    """
    for source in (
        'import gc\ngc.get_referents(low)[0]["tier"] = T3\n',
        "import ctypes\nctypes.cast(id(low), ctypes.py_object)\n",
    ):
        assert any(
            check_tag_t3._RAW_CARRIER_MESSAGE in m for m in _messages(source)
        ), f"admitted: {source!r}"
    assert check_tag_t3._scan_text("import gc\ngc.collect()\n", _PROBE) == []
    assert check_tag_t3._scan_text(
        'import ctypes\nlibc = ctypes.CDLL("libc.so.6", use_errno=True)\n', _PROBE
    ) == []


def test_setattr_with_fewer_than_two_arguments_is_refused() -> None:
    """COVERAGE + SHAPE. ``object.__setattr__(*parts)`` supplies no readable target.

    Default-deny: a call this rule cannot read is a call it must not admit.
    """
    assert any(
        check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE in m
        for m in _messages("object.__setattr__(*parts)\n")
    )
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -v
```

Expected: FAIL — `AttributeError: … '_RAW_SETATTR_SHAPE_MESSAGE'`

- [ ] **Step 3: Add constants and predicates**

Insert after `_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE` (~line 89):

```python
# ---------------------------------------------------------------------------
# #538 — THE SOLE-LAYER RULES.
#
# The runtime CANNOT refuse these. Raw state writes never traverse any method the
# model can override (`frozen=True` observes `__setattr__`, and none of these reach
# it), so no seam is left to guard. The authoring layer is the ONLY enforcement layer
# that can exist for them.
#
# DEFAULT-DENY THE VEHICLE OR THE SHAPE, NEVER ENUMERATE THE SPELLING. Round-2 probes
# minted two genuine `TaggedContent[T3]` objects with attacker-controlled content from
# a file that scanned clean under BOTH the merged detector AND a fully enumerated rule
# set. The decisive spelling:
#
#     object.__setattr__(obj, "__dict__", {..., "tier": T3})
#
# An earlier constraints doc mandated "key on the written `tier` attribute, not on the
# call". That rule cannot see this line BY CONSTRUCTION — the attribute written is
# `__dict__`.
#
# AND THE SAME MISTAKE RECURRED INSIDE THE FIX: the first revision of these rules
# matched the receiver as the bare identifier `object`, so `builtins.object.__setattr__`,
# `_o = object` and `from builtins import object as _o` all scanned clean. The review
# fleet executed all three and minted T3. Hence `_alias_names`, and hence
# receiver-BLIND matching on `__setattr__`.
_RAW_STATE_VEHICLE_ATTRS: frozenset[str] = frozenset(
    {
        "__dict__",
        "__setstate__",
        "__getstate__",
        "__reduce__",
        "__reduce_ex__",
        "__new__",
        "__mro__",
        "__bases__",
    }
)

# Vehicles when NAMED AS A STRING. DELIBERATELY WIDER than the attribute set above.
# `getattr(object, "__setattr__")(low, "tier", T3)` produces NO `ast.Attribute` node at
# all, so every attribute-keyed rule is blind to it — executed, it turned a
# TaggedContent[T2] into T3. `__setattr__` must NOT join the attribute set: the three
# live benign `object.__setattr__(...)` sites all carry that attribute node, and the
# receiver-blind rules below already cover the attribute form.
_RAW_STATE_VEHICLE_NAMES: frozenset[str] = _RAW_STATE_VEHICLE_ATTRS | frozenset(
    {"__setattr__", "__delattr__", "__class__"}
)

# The `TaggedContent` state fields no `__setattr__` call may write, whatever its target.
# `metadata` is deliberately ABSENT — `hooks/context.py:106` writes it on a `HookContext`,
# an unrelated frozen dataclass sharing the field name. See "Accepted residuals".
_TAGGED_STATE_FIELDS: frozenset[str] = frozenset({"tier", "content", "source"})

# Reaching PRIMITIVES that hand back an object's raw state. Scoped to the primitive,
# not the module: banning `gc` and `ctypes` outright costs two legitimate sites
# (`ctypes.CDLL` for libc in `supervisor/process_posture.py`, `gc.collect()` in
# `fd3_key_delivery.py`) while this form costs ZERO. The class is "primitives that
# hand back raw state", not "modules that happen to contain one".
_RAW_STATE_CARRIERS: frozenset[tuple[str, str]] = frozenset(
    {
        ("gc", "get_referents"),
        ("gc", "get_objects"),
        ("ctypes", "py_object"),
        ("ctypes", "cast"),
        ("copyreg", "_reconstructor"),
        ("copyreg", "__newobj__"),
    }
)

# The field an authorised T3 mint owns. Denied as an `object.__setattr__` target even
# when the target is `self` — it is the headline tl-2026-013 write.
_TIER_FIELD: str = "tier"

_RAW_VEHICLE_ATTR_MESSAGE: str = (
    "raw-state vehicle attribute — reaches instance state without traversing any "
    "method the model can guard. Use tag_t3_with_nonce()."
)
_RAW_VEHICLE_VARS_MESSAGE: str = (
    "vars() exposes the instance mapping directly — the same unguarded reach as "
    "__dict__. Use tag_t3_with_nonce()."
)
_RAW_VEHICLE_STR_MESSAGE: str = (
    "a raw-state vehicle named as a string in code position — getattr() and friends "
    "reach it without an attribute node. Use tag_t3_with_nonce()."
)
_RAW_SETATTR_SHAPE_MESSAGE: str = (
    "__setattr__ call whose target is not `self` or whose field name is computed, "
    "dunder or `tier` — bypasses frozen=True and every tier guard."
)
_RAW_SETATTR_ALIASED_MESSAGE: str = (
    "__setattr__ referenced outside direct-call position — an alias defeats any rule "
    "keyed on the call. Call it inline on `self` with a literal field name."
)
_RAW_CLASS_SWAP_MESSAGE: str = (
    "assignment to __class__ — retypes a live object past every constructor guard. "
    "Build the right type instead."
)
_RAW_CARRIER_MESSAGE: str = (
    "a carrier primitive that hands back an object's raw state mapping — reaches "
    "instance state while naming no attribute. Use tag_t3_with_nonce()."
)


def _record(
    violations: list[str], lines: list[str], path: Path, lineno: int, message: str
) -> None:
    """Append a violation MESSAGE line plus its source SNIPPET line.

    Every rule reports the same two-line shape, so tests assert the returned list by
    equality rather than by substring search. Factored out because nine rules repeating
    the pair would be nine places for the shape to drift (#422: a shared helper fails
    LOUD, N copies drift SILENTLY).

    ``path`` travels as an argument because this repo forbids global state.
    """
    snippet = lines[lineno - 1].rstrip() if 0 <= lineno - 1 < len(lines) else ""
    violations.append(f"{path}:{lineno}: {message}")
    violations.append(f"  {snippet}")


def _is_benign_setattr_target(node: ast.Call) -> bool:
    """True for the established frozen-dataclass idiom, false for every vehicle.

    DEFAULT-DENY ON SHAPE. Admissible only when ALL of:

    * ``args[1]`` folds to a plain string literal — a computed name cannot be read by
      any lexical rule;
    * that literal is not a dunder — those reach interpreter state, not a field;
    * that literal is not in :data:`_TAGGED_STATE_FIELDS`. THIS IS THE CONDITION THAT
      HOLDS. v1 denied only ``"tier"``, so ``object.__setattr__(low, "content",
      ATTACKER)`` was admitted and EXECUTED to place raw attacker text inside a
      T2-tagged object the privileged orchestrator is entitled to read, and
      ``"source"`` forged audit provenance;
    * ``args[0]`` is the bare name ``self``. This NARROWS the surface but proves
      nothing on its own, and the comment here must not claim otherwise: an earlier
      revision justified it with "reaching a TaggedContent as ``self`` requires
      subclassing it, which ``__init_subclass__`` refuses at runtime". That is FALSE,
      and was disproved by execution — ``def _apply(self, v): object.__setattr__(self,
      "content", v)`` is a plain function whose first parameter merely happens to be
      called ``self``. ``self`` is a naming convention, not a type.

    Three live sites depend on the admissible case and none may red:
    ``hooks/context.py:106``, ``plugins/web_fetch/allowlist.py:139``,
    ``plugins/web_fetch/fetch_dispatcher.py:219``. All three write ``self``. Measured
    false-positive cost of this shape across both scan roots: ZERO.

    ESCAPE HATCH, named so nobody invents one: a frozen dataclass that genuinely needs
    a ``tier`` field and is NOT a ``TaggedContent`` should set it through its own
    constructor, or the write belongs behind a named helper inside the already-exempt
    ``security/tiers.py`` — not behind a loosened rule.
    """
    if len(node.args) < 2:
        return False
    target = node.args[0]
    if not (isinstance(target, ast.Name) and target.id == "self"):
        return False
    name = _fold_str(node.args[1])
    if name is None:
        return False
    if name.startswith("__") and name.endswith("__"):
        return False
    return name not in _TAGGED_STATE_FIELDS
```

The carrier rule and the `vars()` rule both resolve their module/callable identifier
through `_alias_names` — `import gc as _g`, `from builtins import vars as _v` and
`from gc import get_referents` were all clean until they did. Build the direct-binding
name set (`from <carrier> import <primitive>`) in ONE pass over `ast.ImportFrom`, not
inside the per-carrier loop: a `break` inside that loop attributes the finding to
whichever carrier the loop happened to be on.

- [ ] **Step 4: Restructure the walk loop and add the rules**

The current loop opens with `if not isinstance(node, ast.Call): continue`. Three new
rules key on `ast.Attribute` / `ast.Constant`, so that early-`continue` must go. The
resulting shape — note where the fence sits:

```python
        prose = _prose_string_ids(tree)
        enclosing = _enclosing_functions(tree)
        basemodel_names, basemodel_overflow = _alias_names(tree, "BaseModel")
        object_names, object_overflow = _alias_names(tree, "object")
        # ONE-POSITION WHITELIST. `Call.func` is the ONLY admissible position for a
        # `__setattr__` reference; every other position is the A05 vehicle.
        call_func_ids = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}

        if basemodel_overflow or object_overflow:
            _record(violations, lines, path, 1, _ALIAS_BUDGET_MESSAGE)

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", 1)
            try:
                findings = _detect(
                    node, prose, enclosing, basemodel_names, object_names,
                    call_func_ids, path,
                )
            except Exception as exc:
                raise GateInternalError(
                    f"{path}:{lineno}: {_GATE_INTERNAL_MESSAGE} {type(exc).__name__}: {exc}"
                ) from exc
            for message in findings:
                _record(violations, lines, path, lineno, message)
```

Three things about this shape are load-bearing and were fleet findings:

- **`lineno = getattr(node, "lineno", 1)`, not `node.lineno`.** `ast.walk` is typed
  `ast.AST`, which has no `lineno`. The existing code only type-checks because the
  `isinstance(node, ast.Call)` guard narrows it — and that guard is being removed.
  Measured: `mypy --strict` and `pyright` BOTH error, at 12 required sites including
  the pre-push `lefthook` hooks.
- **The four map constructions sit OUTSIDE the fence, and every detector predicate
  INSIDE it.** v1 contradicted itself here. A defect in `_prose_string_ids` landing in
  `_scan_text`'s broad `except Exception` would report `_UNSCANNABLE` at exit 1
  ("violations found") on a clean file — verbatim the #543 err-001 failure
  `GateInternalError` exists to prevent. `ast.parse` and `ast.walk` stay outside
  because they are genuinely input-driven.
- **`_detect` returns messages rather than recording them**, so the whole detector is
  one fenced call instead of nine separately fenced ones.

Write `_detect` as a pure function returning `list[str]`, containing: the three
original `_is_*` predicates, the vehicle-attribute rule, the `__class__` STORE rule,
the receiver-blind `__setattr__` rules, `vars()`, the carrier rule, the folded-string
rule, the `BaseModel` seam rule (Task 3) and the private-surface rule (Task 4).

Add the budget message alongside the others:

```python
_ALIAS_BUDGET_MESSAGE: str = (
    "alias chain deeper than the resolver's budget — the gate cannot decide what "
    "these names are bound to. Simplify the aliasing."
)
```

- [ ] **Step 5: Register all eight new messages in the drift guard**

At `tests/unit/security/test_check_tag_t3_gate_integrity.py:143`, add to `findings`:

```python
        # #538 sole-layer rules. FINDINGS, not collection failures: each means the
        # file WAS gated and failed, so neither reader of
        # _COLLECTION_FAILURE_MESSAGES should see them.
        check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE,
        check_tag_t3._RAW_VEHICLE_VARS_MESSAGE,
        check_tag_t3._RAW_VEHICLE_STR_MESSAGE,
        check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE,
        check_tag_t3._RAW_SETATTR_ALIASED_MESSAGE,
        check_tag_t3._RAW_CLASS_SWAP_MESSAGE,
        check_tag_t3._RAW_CARRIER_MESSAGE,
        check_tag_t3._ALIAS_BUDGET_MESSAGE,
```

- [ ] **Step 6: Flip the tripwire**

Verified by the fleet: Task 2 alone flips it (`_RESIDUAL_SPELLINGS` contains
`object.__setattr__` and `__dict__` writes), so every commit stays green.

In `tests/adversarial/tier_laundering/test_tier_laundering_copy_seams.py`, rename
`test_tl_2026_013_is_currently_undefended_at_the_authoring_layer_too` to
`test_tl_2026_013_is_now_defended_at_the_authoring_layer` and change the final
assertion from `== 0` to `== 1`, with this docstring:

```python
    """The residual's named fallback layer NOW detects it — #538 flipped this.

    Was ``..._is_currently_undefended_at_the_authoring_layer_too``, asserting ``== 0``.
    It was designed to FAIL when the #538 rules landed, and it did. The runtime still
    cannot refuse these spellings — that half of ``tl-2026-013`` is unchanged and
    ``out_of_scope`` stays ``true``. What changed is the authoring layer.

    ``== 1``, not ``!= 0``: exit 2 means "the gate could not run", and a test that
    accepts it would be green on a gate that scanned nothing.
    """
```

- [ ] **Step 7: Run the affected suites**

```bash
uv run pytest tests/unit/security/ tests/adversarial/tier_laundering -q
python3 scripts/check_tag_t3.py; echo "real-tree rc=$? (MUST be 0)"
```

- [ ] **Step 8: Mutation-test**

Stage the file first — see the warning in Task 1 Step 5.

Apply, confirm the NAMED test reds, revert. Every script carries `assert new != s`.
The seven rows marked **[fleet]** are mutations that survived v1's suite AND the
real-tree scan.

| Mutation | Must red |
| --- | --- |
| drop `"__dict__"` from `_RAW_STATE_VEHICLE_ATTRS` | `test_vehicle_attributes_are_refused` |
| drop `"__getstate__"` **[fleet M3]** | `test_vehicle_attributes_are_refused` |
| `_is_benign_setattr_target` -> always `True` | `test_setattr_shape_denies_every_tagged_content_field_target` |
| `_is_benign_setattr_target` -> always `False` (WIDENING) | `test_frozen_dataclass_post_init_idiom_stays_clean_with_a_positive_twin` |
| drop the `self` check **[fleet sec-002]** | `test_setattr_shape_denies_every_tagged_content_field_target` |
| drop `name != _TIER_FIELD` | `test_setattr_shape_denies_every_tagged_content_field_target` |
| drop the dunder check | `test_a01_object_setattr_writing_dunder_dict_is_refused` |
| `len(node.args) < 2` -> `True` **[fleet M8]** | `test_setattr_with_fewer_than_two_arguments_is_refused` |
| receiver matched as literal `"object"` **[fleet sec-001]** | `test_setattr_receiver_is_matched_by_alias_not_by_the_bare_name_object` |
| drop `id(node) not in call_func_ids` (WIDENING) | `test_frozen_dataclass_post_init_idiom_stays_clean_with_a_positive_twin` |
| drop `id(node) not in prose` from the STR rule (WIDENING) **[fleet M1]** | `test_a_raw_state_dunder_in_prose_stays_clean_with_a_positive_twin` |
| `__class__` banned by name, ignoring ctx (WIDENING) | `test_class_swap_is_refused_but_a_class_read_is_not` |
| drop `("gc", "get_referents")` **[fleet sec-003]** | `test_carrier_by_reference_primitives_are_refused` |
| carriers banned by MODULE not primitive (WIDENING) | `test_carrier_by_reference_primitives_are_refused` |
| `vars` matched as the literal `"vars"` **[self-audit]** | `test_every_keyed_identifier_is_alias_resolved` |
| carrier module matched as a literal **[fleet sec2-003]** | `test_every_keyed_identifier_is_alias_resolved` |
| `_RAW_STATE_VEHICLE_NAMES` = `_RAW_STATE_VEHICLE_ATTRS` **[fleet sec2-001]** | `test_a_vehicle_named_only_as_a_string_is_refused` |
| `__setattr__` ADDED to the attribute set (WIDENING) | `test_a_vehicle_named_only_as_a_string_is_refused` |
| `_TAGGED_STATE_FIELDS` reduced to `{"tier"}` **[fleet sec2-002]** | `test_setattr_denies_every_tagged_state_field_regardless_of_target` |
| `metadata` ADDED to `_TAGGED_STATE_FIELDS` (WIDENING) | `test_frozen_dataclass_post_init_idiom_stays_clean_with_a_positive_twin` |

- [ ] **Step 9: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/ \
        tests/adversarial/tier_laundering/test_tier_laundering_copy_seams.py
git commit -m "fix: #538 default-deny the raw-state-write vehicles, not their spellings"
```

> The ONLY commit carrying `fix: #538`.

---

## Task 3: Unbound `BaseModel` seam dispatch

**Files:**

- Modify: `scripts/check_tag_t3.py`
- Modify: `tests/unit/security/test_check_tag_t3_gate_integrity.py` (`findings`)
- Test: append to `tests/unit/security/test_check_tag_t3_sole_layer_rules.py`

**Interfaces produced:** `_BASEMODEL_VALUE_MESSAGE`, `_BASEMODEL_SEAM_ATTRS`,
`_is_unbound_basemodel_seam_call`.

- [ ] **Step 1: Write the failing tests**

```python
def test_unbound_basemodel_seam_dispatch_is_refused() -> None:
    """The original tl-2026-013 unbound-dispatch spellings, asserted by EQUALITY."""
    assert _messages('BaseModel.model_copy(low, update={"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]
    assert _messages('BaseModel.copy(low, update={"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]


def test_qualified_basemodel_receiver_is_refused() -> None:
    """FLEET FINDING test-005 — ``pydantic.BaseModel.model_copy(...)`` scanned CLEAN.

    The first revision hand-rolled ``isinstance`` checks on the receiver and missed
    the qualified spelling, reintroducing exactly the CR-138 round-2 finding #2 class
    that ``_arg_name`` exists to close. Collapse the receiver by identifier instead.
    """
    source = 'import pydantic\npydantic.BaseModel.model_copy(low, update={"tier": T3})\n'
    assert _messages(source) == [f"{_PROBE}:2: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"]


def test_qualified_receiver_does_not_widen_to_ordinary_modules() -> None:
    """NEGATIVE TWIN for the widening above — collapsing the receiver must not
    make every two-deep attribute call a finding."""
    assert check_tag_t3._scan_text("import os\np = os.path.join(a, b)\n", _PROBE) == []
    assert check_tag_t3._scan_text("x = mod.helper.copy()\n", _PROBE) == []


def test_basemodel_dunder_func_dispatch_is_refused() -> None:
    """``BaseModel.model_construct.__func__(cls, ...)`` — dispatch through the unbound
    function object, which skips every override on the way in. Asserted by EQUALITY
    (the plan's own constraint; v1 used containment on element 0)."""
    source = "built = BaseModel.model_construct.__func__(TaggedContent[T3], tier=T3)\n"
    assert _messages(source) == [f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"]


def test_import_aliased_basemodel_is_refused() -> None:
    """A09 — ``from pydantic import BaseModel as BM``."""
    source = "from pydantic import BaseModel as BM\nBM.model_copy(obj, update=u)\n"
    assert _messages(source) == [f"{_PROBE}:2: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"]


def test_every_declared_seam_attribute_is_enforced() -> None:
    """Loop over the constant, do not hardcode a pair.

    FLEET FINDING test-003 M2/M4: v1 tested ``copy``/``model_copy`` only, so dropping
    ``model_validate`` / ``model_validate_json`` from the set survived the suite.
    """
    for seam in sorted(check_tag_t3._BASEMODEL_SEAM_ATTRS):
        assert _messages(f"BaseModel.{seam}(low, update=u)\n") == [
            f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
        ], f"seam {seam!r} is declared but not enforced"


def test_a_non_seam_attribute_on_the_basemodel_receiver_stays_clean() -> None:
    """NEGATIVE FLOOR + TWIN. The receiver alone must not be sufficient.

    FLEET FINDING test-003 M4: a mutant ignoring ``_BASEMODEL_SEAM_ATTRS`` entirely
    survived v1's suite.
    """
    assert check_tag_t3._scan_text("s = BaseModel.model_json_schema()\n", _PROBE) == []
    assert _messages("s = BaseModel.model_construct()\n") == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]


def test_instance_model_copy_stays_clean_with_a_positive_twin() -> None:
    """NEGATIVE FLOOR + TWIN. ``obj.model_copy(...)`` is the supported API; a
    receiver-blind rule would red ordinary pydantic use across the tree."""
    assert check_tag_t3._scan_text('o = obj.model_copy(update={"a": 1})\n', _PROBE) == []
    assert _messages('o = BaseModel.model_copy(update={"a": 1})\n') == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]


def test_basemodel_named_only_in_prose_stays_clean_with_a_positive_twin() -> None:
    """NEGATIVE FLOOR + TWIN. ``tiers.py`` and ``quarantine.py`` docstrings name these
    spellings repeatedly; measured, every textual ``BaseModel.<attr>`` hit under both
    scan roots is prose and there are ZERO real accesses."""
    assert check_tag_t3._scan_text(
        '"""See ``BaseModel.model_copy(obj, update={"tier": T3})``."""\n', _PROBE
    ) == []
    assert _messages('BaseModel.model_copy(obj, update={"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -k basemodel -v
```

- [ ] **Step 3: Implement**

```python
# Seam methods that write field state when dispatched with the CLASS as receiver.
# `copy` is pydantic v1's spelling and does NOT route through `model_copy` (it merges
# `update` inside `copy_internals`); the `model_validate*` pair is included because a
# wire round-trip is a construction path.
_BASEMODEL_SEAM_ATTRS: frozenset[str] = frozenset(
    {"copy", "model_copy", "model_construct", "model_validate", "model_validate_json"}
)
_BASEMODEL_VALUE_MESSAGE: str = (
    "unbound BaseModel seam dispatch — builds field state through "
    "_copy_and_set_values, reaching neither the class overrides nor model_post_init. "
    "Call the seam on the INSTANCE, or use tag_t3_with_nonce()."
)


def _is_unbound_basemodel_seam_call(node: ast.Call, basemodel_names: frozenset[str]) -> bool:
    """``BaseModel.<seam>(obj, ...)`` — dispatch with the CLASS as receiver.

    The receiver is collapsed with :func:`_arg_name`, which maps ``ast.Name`` and
    ``ast.Attribute`` to the same identifier. Hand-rolled ``isinstance`` checks missed
    ``pydantic.BaseModel.model_copy(...)`` — the CR-138 round-2 finding #2 class this
    very helper exists to close. Reusing ``_arg_name`` also means the two widenings
    cannot drift apart.

    RECEIVER-SCOPED on purpose: a receiver-blind rule flagging every ``model_copy``
    reds ordinary instance use across the tree. Measured cost of this form: ZERO.

    Two shapes: ``BM.model_copy(obj, …)`` and ``BM.model_construct.__func__(cls, …)``,
    the latter one hop further through the unbound function object.

    WHAT THIS CANNOT DO: a cross-module re-export (``from x import BaseModel as Y`` in
    module A, imported from A by module B) is invisible — the alias set is per-file.
    ``TaggedContent.model_construct(...)`` is likewise not flagged here; it is refused
    at RUNTIME. Both are recorded residuals, not oversights.
    """
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if _arg_name(func.value) in basemodel_names and func.attr in _BASEMODEL_SEAM_ATTRS:
        return True
    receiver = func.value
    return (
        isinstance(receiver, ast.Attribute)
        and _arg_name(receiver.value) in basemodel_names
        and receiver.attr in _BASEMODEL_SEAM_ATTRS
    )
```

- [ ] **Step 4: Register the message, run the suites**

```bash
uv run pytest tests/unit/security/ -q
python3 scripts/check_tag_t3.py; echo "rc=$? (MUST be 0)"
```

- [ ] **Step 5: Mutation-test**

Stage the file first — see the warning in Task 1 Step 5.

| Mutation | Must red |
| --- | --- |
| `_arg_name(func.value)` -> `isinstance(func.value, ast.Name) and func.value.id` **[fleet test-005]** | `test_qualified_basemodel_receiver_is_refused` |
| drop the `ast.alias` arm from `_alias_names` | `test_import_aliased_basemodel_is_refused` |
| receiver check -> always `True` (WIDENING) | `test_instance_model_copy_stays_clean_with_a_positive_twin` |
| ignore `_BASEMODEL_SEAM_ATTRS` (WIDENING) **[fleet M4]** | `test_a_non_seam_attribute_on_the_basemodel_receiver_stays_clean` |
| remove `model_validate` from the set **[fleet M2]** | `test_every_declared_seam_attribute_is_enforced` |
| drop the nested-`Attribute` arm | `test_basemodel_dunder_func_dispatch_is_refused` |

- [ ] **Step 6: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/
git commit -m "test: #538 refuse unbound BaseModel seam dispatch through a collapsed receiver

Refs #538"
```

---

## Task 4: The `alfred.security.tiers` private-surface default-deny

Closes the two bypasses **nothing in the repo catches**. These are the authorisation
MECHANISM, so the runtime cannot refuse them by definition.

**Files:**

- Modify: `scripts/check_tag_t3.py` (including `_scan_file` / `_scan_text` docstrings)
- Modify: `tests/unit/security/test_check_tag_t3_gate_integrity.py` (`findings`)
- Test: append to `tests/unit/security/test_check_tag_t3_sole_layer_rules.py`

**Interfaces produced:** `_PRIVATE_SURFACE_MESSAGE`, `_TIERS_PRIVATE_SURFACE`,
`_FUNCTION_SCOPED_EXEMPTIONS`, `_IMPORT_ONLY_EXEMPT_PATHS`, `_private_surface_hit`,
`_private_surface_is_exempt`.

### Resolve the path ONCE, in `_scan_file`

`_scan_text`'s docstring says *"Pure: performs no filesystem access and applies no
exemption"*, and `test_scan_text_reports_a_violation_without_touching_the_filesystem`
pins it. v1 called `path.resolve()` per hit inside `_scan_text`; measured, identical
`(text, path)` arguments then returned **opposite verdicts depending on process cwd**,
while the purity pin stayed green — a vacuous guard whose docstring had become false.

Resolve once in `_scan_file` and pass the resolved path down as a separate parameter.
`_scan_text` stays pure over its arguments and the existing pin stays true.

- [ ] **Step 1: Write the failing tests**

```python
def test_import_aliased_nonce_setter_is_refused() -> None:
    """A16 — the import alias hides the name from every rule keyed on the CALL."""
    source = "from alfred.security.tiers import _set_authorized_t3_nonce as _reg\n_reg(mine)\n"
    assert _messages(source) == [f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"]


def test_getattr_string_nonce_setter_is_refused() -> None:
    """A17 — the name lives in a STRING, so no Name/Attribute node carries it.

    This is why the prose exclusion must be position-based: excluding every string
    constant would admit this line.
    """
    source = 'import alfred.security.tiers as _t\ngetattr(_t, "_set_authorized_t3_nonce")(mine)\n'
    assert _messages(source) == [f"{_PROBE}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"]


def test_a_private_name_assembled_by_binop_is_refused() -> None:
    """FLEET FINDING sec-004 — executed end-to-end, this forged the nonce and minted a
    fully legitimate TaggedContent[T3] for attacker content through the front door."""
    source = 'getattr(_t, "_set_authorized" + "_t3_nonce")(mine)\n'
    assert _messages(source) == [f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"]


def test_private_surface_reached_through_an_attribute_is_refused() -> None:
    """FLEET FINDING test-003 M10 — deleting the ``ast.Attribute`` arm survived v1."""
    assert _messages("if _t._AUTHORIZED_T3_NONCE is not None:\n    pass\n") == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_dotted_private_name_in_a_string_is_refused() -> None:
    """The docstring claims containment matching handles the dotted spelling — pin it."""
    assert _messages('n = "alfred.security.tiers._set_authorized_t3_nonce"\n') == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_context_var_authorisation_flip_is_refused() -> None:
    """``_T3_CONSTRUCTION_AUTHORIZED.set(True)`` flips the guard off wholesale."""
    assert _messages("_T3_CONSTRUCTION_AUTHORIZED.set(True)\n") == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_private_surface_named_only_in_prose_stays_clean_with_a_positive_twin() -> None:
    """NEGATIVE FLOOR + TWIN. THREE live docstrings name these symbols:
    ``cli/daemon/_failures.py:150``, ``hooks/invoke.py:407`` and ``:469``. The last is a
    PEP-258 ATTRIBUTE docstring, which ``ast.get_docstring`` does not see."""
    assert check_tag_t3._scan_text(
        '"""Sets ``alfred.security.tiers._AUTHORIZED_T3_NONCE`` once at start."""\n', _PROBE
    ) == []
    assert check_tag_t3._scan_text(
        'X = 1\n"""See :func:`alfred.security.tiers._tier_by_name`."""\n', _PROBE
    ) == []
    assert _messages('X = _tier_by_name("T3")\n') == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_nonce_factory_is_exempt_inside_its_registration_function_only() -> None:
    """(path, FUNCTION), never path-only, WITH the positive twin in the same test.

    ``_set_authorized_t3_nonce`` (``tiers.py:286``) is a bare ``global`` write with NO
    guard; the idempotency guard lives in the CALLER. A path-only exemption leaves the
    bypass open WITHIN the exempt file — which is the whole point of narrowing it.

    v1's version of this test had no twin and passed against the unmodified script.
    """
    inside = (
        "def create_and_register_t3_nonce():\n"
        "    nonce = CapabilityGateNonce()\n"
        "    _set_authorized_t3_nonce(nonce)\n"
        "    return nonce\n"
    )
    assert check_tag_t3._scan_text(inside, _NONCE_FACTORY) == []

    outside = "def some_other_helper():\n    _set_authorized_t3_nonce(attacker_nonce)\n"
    assert _messages(outside, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_nonce_factory_exemption_covers_async_def_too() -> None:
    """THE SILENT TRAP, WITH a twin so it cannot pass on a dead exemption.

    A ``FunctionDef``-only enclosing walk maps nothing for ``async def``, so the first
    body would red. Nothing else in the repo exercises the async half.
    """
    exempt = (
        "async def create_and_register_t3_nonce():\n    _set_authorized_t3_nonce(nonce)\n"
    )
    assert check_tag_t3._scan_text(exempt, _NONCE_FACTORY) == []

    not_exempt = "async def some_other_coro():\n    _set_authorized_t3_nonce(nonce)\n"
    assert _messages(not_exempt, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_import_exemption_is_module_level_only() -> None:
    """FLEET FINDING sec-005 — an ``ast.alias``-only exemption is still path-only.

    A FUNCTION-LOCAL aliased import inside ``nonce_factory.py`` bought the exemption
    under v1. Requiring module scope closes it for free.
    """
    module_level = (
        "from alfred.security.tiers import CapabilityGateNonce, _set_authorized_t3_nonce\n"
    )
    assert check_tag_t3._scan_text(module_level, _NONCE_FACTORY) == []

    function_local = (
        "def sneak():\n"
        "    from alfred.security.tiers import _set_authorized_t3_nonce as _reg\n"
        "    _reg(attacker)\n"
    )
    assert _messages(function_local, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}",
        f"{_NONCE_FACTORY}:3: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}",
    ]


def test_module_level_calls_in_nonce_factory_still_red() -> None:
    """The import exemption is scoped to ``ast.alias``, so a module-level CALL reds."""
    assert _messages("_set_authorized_t3_nonce(attacker_nonce)\n", _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_the_real_nonce_factory_file_scans_clean() -> None:
    """THE REAL FILE under its REAL path — a fixture resembling it proves nothing."""
    assert check_tag_t3._scan_file(_NONCE_FACTORY) == []


def test_nonce_factory_holds_exactly_one_private_reference_and_one_alias() -> None:
    """CARDINALITY PIN (fleet finding sec-005).

    The exemption is keyed on a function NAME, so a second function in this file
    renamed to ``create_and_register_t3_nonce`` would inherit it. Pinning the counts
    means any new private-surface reference in this file reds here and forces the
    author to justify it, rather than silently landing inside an exemption.
    """
    tree = ast.parse(_NONCE_FACTORY.read_text(encoding="utf-8"))
    prose = check_tag_t3._prose_string_ids(tree)
    hits = [n for n in ast.walk(tree) if check_tag_t3._private_surface_hit(n, prose)]
    aliases = [n for n in hits if isinstance(n, ast.alias)]
    assert len(aliases) == 1, f"expected exactly one exempt import alias, got {len(aliases)}"
    assert len(hits) == 3, (
        f"nonce_factory.py private-surface references changed ({len(hits)} != 3). "
        "Every one of them sits inside an exemption — justify the new reference or "
        "move it out."
    )


def test_scan_text_verdict_does_not_depend_on_the_working_directory() -> None:
    """PURITY, asserted as the property (fleet finding test-004).

    v1 resolved the path inside ``_scan_text``; identical arguments then returned
    opposite verdicts depending on cwd while the existing purity pin stayed green.
    """
    import os

    source = "_set_authorized_t3_nonce(x)\n"
    relative = Path("src/alfred/bootstrap/nonce_factory.py")
    cwd = os.getcwd()
    try:
        os.chdir(_REPO_ROOT)
        here = check_tag_t3._scan_text(source, relative)
        os.chdir("/")
        elsewhere = check_tag_t3._scan_text(source, relative)
    finally:
        os.chdir(cwd)
    assert here == elsewhere


def test_private_surface_constant_matches_the_real_tiers_module() -> None:
    """DRIFT GUARD — derive the expected set, do not restate it.

    Hard-coding keeps the gate free of import-time I/O (it runs under bare ``python3``
    with no venv and no ``alfred`` importable); this test stops it drifting. A new
    private module-level name in ``tiers.py`` reds HERE on the day it lands.

    DEFAULT-DENY the derivation (fleet findings sec-007 / test-006): collect every name
    a module-level statement BINDS, including inside ``if TYPE_CHECKING:`` / ``try:``
    blocks and tuple unpacking, which a ``tree.body``-only three-arm walk misses.
    """
    derived = check_tag_t3._derive_tiers_private_surface(_TIERS.read_text(encoding="utf-8"))
    assert derived == check_tag_t3._TIERS_PRIVATE_SURFACE, (
        f"tiers.py's private surface drifted. "
        f"Added: {sorted(derived - check_tag_t3._TIERS_PRIVATE_SURFACE)}. "
        f"Removed: {sorted(check_tag_t3._TIERS_PRIVATE_SURFACE - derived)}."
    )
    assert len(derived) == 21, f"expected 21 private names, derived {len(derived)}"


def test_every_keyed_identifier_is_alias_resolved() -> None:
    """THE META-GUARD. Seven Criticals across two review rounds were ONE shape.

    Every one was a rule keyed on a bare identifier that Python lets you rebind:
    ``object``, ``gc``, ``ctypes``, ``BaseModel``, ``vars``. Each was fixed as a
    SPELLING and the next round found the next spelling. This test is the only thing
    in the suite that closes the CLASS.

    An identifier is a NAME. Any name can be rebound by assignment or by an import
    alias. So for every identifier a rule keys on, all three spellings below must
    produce the SAME verdict — and the direct form is the positive control proving
    the probe reaches the rule at all.

    Adding a rule that keys on a new identifier means adding a row HERE. If you cannot
    write the row, the rule is not alias-resolved and it is bypassable.
    """
    cases = [
        # (identifier, direct spelling, rebound spelling, import-aliased spelling)
        (
            "vars",
            'vars(obj)["tier"] = T3',
            '_v = vars\n_v(obj)["tier"] = T3',
            'from builtins import vars as _v\n_v(obj)["tier"] = T3',
        ),
        (
            "gc",
            "import gc\ngc.get_referents(low)",
            "import gc as _g\n_g.get_referents(low)",
            "from gc import get_referents\nget_referents(low)",
        ),
        (
            "ctypes",
            "import ctypes\nctypes.cast(id(low), ctypes.py_object)",
            "import ctypes as _c\n_c.cast(id(low), _c.py_object)",
            "from ctypes import cast\ncast(id(low), py_object)",
        ),
        (
            "BaseModel",
            "BaseModel.model_copy(o, update=u)",
            "_B = BaseModel\n_B.model_copy(o, update=u)",
            "from pydantic import BaseModel as _B\n_B.model_copy(o, update=u)",
        ),
        (
            "object",
            'object.__setattr__(low, "tier", T3)',
            '_o = object\n_o.__setattr__(low, "tier", T3)',
            'from builtins import object as _o\n_o.__setattr__(low, "tier", T3)',
        ),
    ]
    for identifier, direct, rebound, aliased in cases:
        assert _messages(direct + "\n"), (
            f"{identifier}: the DIRECT spelling was not flagged — this probe never "
            f"reached the rule, so the two below prove nothing"
        )
        assert _messages(rebound + "\n"), f"{identifier}: REBOUND spelling admitted"
        assert _messages(aliased + "\n"), f"{identifier}: IMPORT-ALIASED spelling admitted"


def test_a_vehicle_named_only_as_a_string_is_refused() -> None:
    """The string vehicle set is WIDER than the attribute set, and must stay so.

    ``getattr(object, "__setattr__")(low, "tier", T3)`` produces NO ``ast.Attribute``
    node, so every attribute-keyed rule is blind to it. Executed, it turned a
    TaggedContent[T2] into T3.

    The twin below is why ``__setattr__`` must NOT join the ATTRIBUTE set: all three
    live benign sites carry that attribute node.
    """
    assert _messages('getattr(object, "__setattr__")(low, "tier", T3)\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"
    ]
    assert _messages('getattr(object, "__set" + "attr__")(low, "tier", T3)\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"
    ]
    assert check_tag_t3._scan_text(
        'object.__setattr__(self, "path_prefix", normalised)\n', _PROBE
    ) == []
    assert check_tag_t3._RAW_STATE_VEHICLE_ATTRS < check_tag_t3._RAW_STATE_VEHICLE_NAMES, (
        "the string vehicle set must be a strict superset of the attribute set"
    )


def test_setattr_denies_every_tagged_state_field_regardless_of_target() -> None:
    """``self`` is a NAMING CONVENTION, not a type guarantee.

    Round 2 disproved the earlier justification by execution: a plain function whose
    first parameter is called ``self`` reaches the admissible branch with no subclass
    involved. ``_TAGGED_STATE_FIELDS`` is the condition that actually holds.
    """
    for field in sorted(check_tag_t3._TAGGED_STATE_FIELDS):
        source = f'def _apply(self, v):\n    object.__setattr__(self, "{field}", v)\n'
        assert _messages(source) == [
            f"{_PROBE}:2: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
        ], f"field {field!r} admitted through a self-named parameter"
    assert "metadata" not in check_tag_t3._TAGGED_STATE_FIELDS, (
        "metadata is a documented residual — hooks/context.py:106 writes it on an "
        "unrelated frozen dataclass; banning it reds a legitimate site"
    )


def test_the_private_surface_derivation_sees_every_binding_shape() -> None:
    """ORACLE SELF-TEST. A drift guard that cannot see a shape is a drift guard that
    silently under-covers — and it stays green while doing so."""
    source = (
        "_a, _b = 1, 2\n"
        "type _Alias = int\n"
        "if TYPE_CHECKING:\n"
        "    _c = 3\n"
        "try:\n"
        "    def _d() -> None: ...\n"
        "except ImportError:\n"
        "    _e = None\n"
        "class _F: ...\n"
        "_g: int = 1\n"
    )
    derived = check_tag_t3._derive_tiers_private_surface(source)
    assert derived == {"_a", "_b", "_Alias", "_c", "_d", "_e", "_F", "_g"}
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -k private -v
```

- [ ] **Step 3: Implement**

Write `_derive_tiers_private_surface(source: str) -> frozenset[str]` as a default-deny
walk over module-level statements (recursing into `If` / `Try` / `With` bodies),
collecting `ast.Name(ctx=Store)` targets, `ast.TypeAlias` names, and `def` / `class`
names, filtered to `_`-prefixed non-dunder. Hard-code `_TIERS_PRIVATE_SURFACE` as the
21-name frozenset (the gate must not read `tiers.py` at import time).

`_private_surface_hit(node, prose)` returns the matched name or `None`, over four
carriers — `ast.Name`, `ast.Attribute`, `ast.alias` (name AND `asname`), and any
expression `_fold_str` resolves to a string in non-prose position, matched by
CONTAINMENT so the dotted spelling is caught.

`_private_surface_is_exempt(node, resolved_path, enclosing)`:

```python
    if isinstance(node, ast.alias) and resolved_path in _IMPORT_ONLY_EXEMPT_PATHS:
        # MODULE SCOPE ONLY. Scoped to `ast.alias` so a module-level CALL still reds,
        # and to module scope so a FUNCTION-LOCAL aliased import does not inherit the
        # exemption — which it did in the first revision, making the whole thing
        # functionally path-only.
        return enclosing.get(getattr(node, "lineno", 0)) is None
    function = enclosing.get(getattr(node, "lineno", 0))
    return function is not None and (resolved_path, function) in _FUNCTION_SCOPED_EXEMPTIONS
```

Also in this step, correct the two docstrings this task falsifies:

- `_scan_text`: it now takes a pre-resolved path parameter for exemption keying; state
  that the resolution happens in `_scan_file` and that `_scan_text` remains pure over
  its arguments.
- `GateInternalError` and the inline fence comment: drop the literal count ("The three
  predicates do constant work" -> "These predicates all do constant work") so it cannot
  rot again, and update the docstring's "Two-pass scan" enumeration to say the AST walk
  now visits EVERY node, not only `ast.Call`.

- [ ] **Step 4: Register the message, run the suites**

```bash
uv run pytest tests/unit/security/ -q
python3 scripts/check_tag_t3.py; echo "rc=$? (MUST be 0 — zero new exemptions)"
grep -nE '[Tt]he (two|three|four|five|six|seven) (predicates|rules|passes|approved|authoris)' \
     scripts/check_tag_t3.py; echo "count-rot grep rc=$? (MUST be 1 = no matches)"
```

- [ ] **Step 5: Mutation-test**

| Mutation | Must red |
| --- | --- |
| `_FUNCTION_SCOPED_EXEMPTIONS` -> path-only match | `test_nonce_factory_is_exempt_inside_its_registration_function_only` |
| drop the module-scope check on the alias arm **[fleet sec-005]** | `test_import_exemption_is_module_level_only` |
| drop the `ast.alias` arm from `_private_surface_hit` | `test_import_aliased_nonce_setter_is_refused` |
| drop the `asname` sub-arm **[fleet M7]** | `test_import_aliased_nonce_setter_is_refused` |
| drop the `ast.Attribute` arm **[fleet M10]** | `test_private_surface_reached_through_an_attribute_is_refused` |
| drop the folded-string arm | `test_getattr_string_nonce_setter_is_refused` |
| `_fold_str` -> `ast.Constant` only **[fleet sec-004]** | `test_a_private_name_assembled_by_binop_is_refused` |
| drop `id(node) not in prose` (WIDENING) | `test_private_surface_named_only_in_prose_stays_clean_with_a_positive_twin` |
| remove one name from `_TIERS_PRIVATE_SURFACE` | `test_private_surface_constant_matches_the_real_tiers_module` |
| derivation -> `tree.body` only, three arms **[fleet sec-007]** | `test_the_private_surface_derivation_sees_every_binding_shape` |
| `_prose_string_ids` -> first-statement only | `test_private_surface_named_only_in_prose_stays_clean_with_a_positive_twin` |

- [ ] **Step 6: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/
git commit -m "test: #538 default-deny the tiers private surface, the bypass nothing else catches

Refs #538"
```

---

## Task 5: Delete the dead `quarantine.py` exemption, pin it, and clear every stale claim

Re-measured against the **full v2 rule set**: **0 violations across 1634 lines, 0 `tag(`
calls, 0 `TaggedContent[` constructions.** The exemption is dead and its justification is
already false.

**Files:**

- Modify: `scripts/check_tag_t3.py` (`_APPROVED_PATHS` + THREE docstring sites)
- Modify: `tests/unit/security/test_tag_t3_capability_gate.py:345-352`
- Modify: `tests/unit/security/test_check_tag_t3_subscript.py:162`
- Modify: `.github/workflows/pr-validate-python.yml:299, :348`
- Test: append to `tests/unit/security/test_check_tag_t3_sole_layer_rules.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_quarantine_is_no_longer_an_approved_path() -> None:
    """The exemption is DELETED, not narrowed.

    Narrowing keeps a live soft-landing zone in a function that provably does not need
    one. Deletion means the day a line there DOES need it, the build fails loudly
    naming the decision.
    """
    assert _QUARANTINE not in check_tag_t3._APPROVED_PATHS
    assert not check_tag_t3._is_exempt(_QUARANTINE)
    assert check_tag_t3._APPROVED_PATHS == frozenset({_TIERS})


def test_quarantine_scans_clean_without_its_exemption() -> None:
    """THE PIN. The REAL file, REAL path, FULL rule set — not a fixture, not a copy."""
    assert check_tag_t3._scan_file(_QUARANTINE) == []


def test_tiers_still_needs_its_whole_file_exemption() -> None:
    """ANTI-VACUITY TWIN, discriminating on a #538 RULE.

    v1 asserted a bare ``assert violations``, which the PRE-EXISTING ``tag(T3`` rule
    satisfies — so it passed with every #538 rule deleted and could not tell a working
    detector from an empty diff. Requiring a #538 message is what makes it an oracle.
    """
    assert _TIERS in check_tag_t3._APPROVED_PATHS
    violations = check_tag_t3._scan_text(
        _TIERS.read_text(encoding="utf-8"),
        _REPO_ROOT / "src" / "alfred" / "security" / "TIERS_NOT_EXEMPT.py",
    )
    assert any(check_tag_t3._RAW_VEHICLE_VARS_MESSAGE in v for v in violations), (
        "tiers.py yielded no #538 finding without its exemption — the new rules are "
        "not live on this path, so the quarantine.py pin above proves nothing"
    )


def test_no_stale_claim_that_quarantine_is_an_authorised_home_survives() -> None:
    """INVARIANT SWEEP. Deleting the exemption without deleting the claims leaves the
    repo asserting a security invariant that is no longer true — including inside the
    workflow that RUNS this gate, and inside a test that stays green while saying it.
    """
    import subprocess

    hits = subprocess.run(
        ["git", "grep", "-nE", r"quarantine\.py"],
        cwd=_REPO_ROOT, capture_output=True, text=True, check=False,
    ).stdout.splitlines()
    live = [
        h for h in hits
        if any(w in h.lower() for w in ("approv", "authoris", "authoriz", "may call"))
        and "docs/superpowers/plans/" not in h
        and "docs/superpowers/specs/" not in h
    ]
    assert live == [], "stale 'quarantine.py is an authorised home' claims:\n" + "\n".join(live)
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -k quarantine -v
```

- [ ] **Step 3: Delete the exemption and clear all seven live claims**

`_APPROVED_PATHS` becomes a single-entry frozenset. Then fix, in order:

1. `scripts/check_tag_t3.py:7-10` — "from outside the two approved homes
   (`security/tiers.py` and `security/quarantine.py`)" -> the single approved home.
2. `scripts/check_tag_t3.py:33-40` — the "Authorised callers" bullet list.
3. `scripts/check_tag_t3.py:388-392` — inside
   `_is_tagged_content_t3_subscript_call`'s docstring, "The two authorised homes …".
4. `tests/unit/security/test_tag_t3_capability_gate.py:345-352` — rename
   `test_check_tag_t3_script_exempts_real_authorised_homes` to the singular and
   correct the docstring's "EXACTLY" list. **This test stays green while asserting a
   false invariant** because its body only exercises `tiers.py`.
5. `tests/unit/security/test_check_tag_t3_subscript.py:162` — rename
   `test_authorised_homes_are_exempt` to the singular (its docstring is already
   correct; only the plural name is over-broad).
6. `.github/workflows/pr-validate-python.yml:299` and `:348` — the release-blocking
   gate's own contract comments.

Each replacement should say what changed and why, e.g.:

```text
``security/quarantine.py`` was the second approved home until #538 deleted the
exemption after measuring it dead: 0 violations across 1634 lines, 0 ``tag(`` calls,
0 ``TaggedContent`` constructions, under the full rule set.
``test_quarantine_scans_clean_without_its_exemption`` pins the deletion, so the day a
line there needs the exemption back, the build fails loudly naming the decision.
```

- [ ] **Step 4: Verify the sweep is complete**

```bash
git grep -nE 'quarantine\.py' -- scripts/ tests/ .github/ src/ \
  | grep -iE 'approv|authoris|authoriz|may call'
echo "rc=$? (MUST be 1 — no matches)"
grep -niE 'two (approved|authoris|authoriz)' scripts/check_tag_t3.py
echo "rc=$? (MUST be 1)"
uv run pytest tests/unit/security/ tests/adversarial -q
```

- [ ] **Step 5: Mutation-test the pin — in a CLONE, never the main worktree**

v1 appended a laundering line to `src/alfred/security/quarantine.py` in the main
worktree and reverted with an unguarded `git checkout`; an interrupted run leaves a
live `TaggedContent[T3]` construction in the highest-care subsystem.

```bash
CLONE=$(mktemp -d)/alfredos
git clone --local --quiet /Users/iandominey/projects/AlfredOS "$CLONE"
git -C "$CLONE" checkout --quiet 538-sole-layer-rules

# Mutation A — a #538 vehicle, invisible to every PRE-#538 rule. A red here proves
# the NEW rules are live on this path. (v1 used TaggedContent[T3](...), which trips
# the pre-existing sec-S3-002 subscript rule and would pass identically with every
# #538 rule deleted.)
python3 - "$CLONE" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "src/alfred/security/quarantine.py"
s = p.read_text()
new = s + '\n_LAUNDERED = object.__setattr__(_obj, "__dict__", {"tier": _T3})\n'
assert new != s, "MUTATION DID NOT APPLY"
p.write_text(new)
PY
(cd "$CLONE" && uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py \
    -k quarantine -q); echo "rc=$? (MUST be non-zero)"
rm -rf "$CLONE"
```

- [ ] **Step 6: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/ .github/workflows/pr-validate-python.yml
git commit -m "refactor: #538 delete the dead quarantine.py exemption and every stale claim

Refs #538"
```

---

## Task 6: ADR-0058

CLAUDE.md: *"New ADR in `docs/adr/NNNN-title.md` whenever you change a structural
invariant."* Shrinking the authorised-T3-homes set from two to one is exactly that, and it
sits behind a release-blocking required check. No existing ADR names `_APPROVED_PATHS`, and
the PRD does not describe the exempt set — which is *why* this record is needed: without it
the gate's own docstring is the sole source of truth, and that docstring was already false.

*(The docs reviewer read the same evidence and concluded no ADR was required, on the grounds
that nothing goes stale. Both readings are defensible; writing it is the cheap, durable one.
Flagged here so the reviewer can overrule.)*

- [ ] **Step 1: Confirm the number is free**

```bash
ls docs/adr/ | tail -3
```

Expected: highest is `0057`.

- [ ] **Step 2: Write `docs/adr/0058-single-approved-t3-authoring-home.md`**

Context / Decision / Consequences / Alternatives, dated `2026-08-01`, citing: the measured
0 violations across 1634 lines under the full rule set; delete-not-narrow (a narrowed
exemption is a soft-landing zone in the one function that provably does not need one); the
new authorised set `{src/alfred/security/tiers.py} ∪ tests/unit/security/**`; the pin test
that makes re-adding it a loud decision; and the fact that #547's premise ("the two
`_APPROVED_PATHS` files always return `[]`") is invalidated by this change.

- [ ] **Step 3: Lint and commit**

```bash
npx --yes markdownlint-cli2@0.22.1 "docs/**/*.md" 2>&1 | tail -3
git add docs/adr/0058-single-approved-t3-authoring-home.md
git commit -m "docs: #538 ADR-0058 single approved T3 authoring home

Refs #538"
```

---

## Task 7: Corpus, matrix, limitations and the stale path strings

- [ ] **Step 1: Rewrite the corpus entry — `payload`, `note` AND `out_of_scope_rationale`**

All three, not just the rationale. `note:` currently prescribes *"the rule must key on the
written attribute (`tier`) rather than on the call"* — the design this plan's measured
baseline proves is defeated by construction. Left unedited it contradicts the new rationale
**in the same file**, and `payload_schema.py` cannot catch it (`note` is `str | None` with no
validator).

`payload` gains the three spellings that appear in no prior artefact
(`object.__setattr__(obj, "__dict__", …)`, `__dict__.update`, `vars()`).

`out_of_scope_rationale` must: keep `out_of_scope: true` for the RUNTIME layer; **preserve
the `BaseModel.model_construct.__func__` runtime-closed record**; name which spellings the
authoring layer now models; keep the recorded rejected alternative (guarded instance
`__dict__` interception and why it was not built); and name the residuals from the
"Accepted residuals" section above.

- [ ] **Step 2: Update the README matrix row 56**

Replace both columns. The right column carries an equally stale forward reference
("authoring-layer detection is the #518 detector follow-up"). The new row states runtime and
authoring separately and names the rule constants, so the DoD item is falsifiable rather
than satisfied by any edit.

```bash
uv run pytest tests/adversarial/tier_laundering -q
npx --yes markdownlint-cli2@0.22.1 "tests/**/*.md" 2>&1 | tail -3
```

- [ ] **Step 3: Add the limitations block to the gate's module docstring**

Verbatim the "Accepted residuals" list above, plus the escape hatch: *a legitimate future
need for one of these vehicles belongs behind a NAMED helper inside the already-exempt
`security/tiers.py`, not behind a loosened rule here.*

- [ ] **Step 4: Fix the stale path strings repo-wide**

v1's grep was scoped to three files and its `[^/]hooks/context.py` pattern cannot match a
line-start occurrence.

```bash
git grep -nE "(^|[^/[:alnum:]_])plugins/web_fetch/(allowlist|fetch_dispatcher)\.py"
git grep -nE "(^|[^/[:alnum:]_])hooks/context\.py"
```

Fix every hit — beyond `tiers.py`, the yaml and the constraints doc, that is
`src/alfred/memory/migrations/versions/0022_audit_result_closed_domain_gaps.py:153`,
`tests/unit/audit/test_audit_log_result_domain_closed.py:303`, and three dated docs. Note a
second `allowlist.py` exists at `src/alfred/egress/allowlist.py`, so the
`src/alfred/plugins/`-prefixed form is what disambiguates.

- [ ] **Step 5: Widen the `tiers.py` docstring edit beyond path strings**

Lines 46-51 still say *"`scripts/check_tag_t3.py` models none of these spellings today"* and
prescribe the defeated rule. Replace the whole paragraph (docstring text only — no behaviour
change).

- [ ] **Step 6: Commit**

```bash
git add tests/adversarial/tier_laundering/ scripts/check_tag_t3.py \
        src/alfred/security/tiers.py src/alfred/memory/migrations/ tests/unit/audit/ \
        docs/superpowers/plans/2026-07-29-518-detector-review-constraints.md
git commit -m "docs: #538 record what the detector now models and what it still cannot

Refs #538"
```

---

## Task 8: The standing gates

- [ ] **Step 1: Coverage, in an ISOLATED CLONE**

```bash
CLONE=$(mktemp -d)/alfredos
git clone --local --quiet /Users/iandominey/projects/AlfredOS "$CLONE"
git -C "$CLONE" checkout --quiet 538-sole-layer-rules
cd "$CLONE" && uv sync --all-extras
uv run coverage run --branch --source=scripts -m pytest tests/unit/security -q
uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100 -m
echo "coverage rc=$? (MUST be 0)"
```

Any uncovered branch is a MISSING TEST or a DESIGN fault. No pragmas.

- [ ] **Step 2: Type-check — this is what v1 failed**

```bash
cd /Users/iandominey/projects/AlfredOS
uv run mypy --strict src scripts/check_tag_t3.py
uv run pyright src scripts/check_tag_t3.py
```

Watch `getattr(node, "lineno", 1)` (never `node.lineno` on an `ast.AST`),
`node.asname is not None` before the `in frozenset[str]` test, and
`frozenset[tuple[Path, str]]`.

- [ ] **Step 3: Lint, format, markdown**

```bash
uv run ruff check . && uv run ruff format --check .
npx --yes markdownlint-cli2@0.22.1 "docs/**/*.md" "tests/**/*.md" 2>&1 | tail -3
```

- [ ] **Step 4: Release-blocking suites**

```bash
uv run pytest tests/adversarial -q
uv run pytest tests/unit -q
make check; echo "make check rc=$?"
```

Check `$?` on `make` itself — `| tail` MASKS it. The macOS integration lane is flaky under
load; verify any suspect in ISOLATION before treating it as real.

- [ ] **Step 5: Commit any fixes**

```bash
git add -u && git commit -m "test: #538 close coverage and type gaps in the sole-layer rules

Refs #538"
```

Never `git add -A` — untracked rulesync outputs get swept in.

---

## Definition of done

- [ ] Tripwire renamed and asserting `== 1`.
- [ ] `tl-2026-013`'s `payload`, `note` AND `out_of_scope_rationale` all rewritten; the
      `model_construct.__func__` runtime-closed record and the rejected-alternative record
      both intact.
- [ ] README row 56 names the rule constants and states runtime vs authoring separately.
- [ ] `_APPROVED_PATHS == frozenset({tiers.py})`, pinned by a real-file regression test whose
      anti-vacuity twin discriminates on a **#538** message.
- [ ] `git grep -nE 'quarantine\.py' -- scripts/ tests/ .github/ src/ | grep -iE 'approv|authoris|authoriz|may call'`
      returns nothing.
- [ ] Ten new per-rule messages — `_RAW_VEHICLE_ATTR`, `_RAW_VEHICLE_VARS`,
      `_RAW_VEHICLE_STR`, `_RAW_SETATTR_SHAPE`, `_RAW_SETATTR_ALIASED`, `_RAW_CLASS_SWAP`,
      `_RAW_CARRIER`, `_ALIAS_BUDGET`, `_BASEMODEL_VALUE`, `_PRIVATE_SURFACE` — all distinct,
      none a substring of another, all in the `findings` set. Listed by NAME rather than by
      count alone, so the checkbox cannot go stale the way a bare number does.
- [ ] `test_every_keyed_identifier_is_alias_resolved` covers EVERY identifier any rule
      keys on. Seven Criticals across two rounds were all this one shape; the meta-guard
      is what closes the class rather than the ninth spelling.
- [ ] `python3 scripts/check_tag_t3.py` exits 0 — **zero new exemptions**.
- [ ] 100% line + branch coverage, no new pragmas, no unreachable branches.
- [ ] `mypy --strict` + `pyright` clean; `ruff` clean; `markdownlint` clean.
- [ ] `uv run pytest tests/adversarial` green (release-blocking — `security/` touched).
- [ ] `make check` exits 0 (check `$?` on make itself).
- [ ] Exactly one commit subject contains `fix: #538`; **no** subject contains `#536`,
      `#539` or `#518`; the PR body contains no `Closes #536`. Verify issue state AFTER the
      merge — do not assume.
- [ ] `git diff main -- src/` shows docstring text only.
- [ ] Every negative floor has a positive twin in the same test. Re-run the v1 vacuity check:
      transcribe the test file onto `origin/main`'s `check_tag_t3.py` and confirm **zero**
      tests pass.

## Out of scope (deliberately)

- **#539** — the seven T3-construction shapes, the five-set alias environment,
  `_slice_verdict`, annotation immunity, `tokenize` suppression widening. All seven of its
  titular shapes are already refused at runtime; it is defence-in-depth and goes last.
  **Note for #539:** `_alias_names` here is already `seed`-parameterised, so #539's five sets
  should call it rather than writing a second resolver (#422).
- **#547** — the census counts COLLECTED files, not successfully SCANNED ones. Its body's
  premise ("the two `_APPROVED_PATHS` files always return `[]`") is **invalidated by Task 5**,
  and predates PR #549's `S_ISREG` change. The same stale premise is written into
  `docs/superpowers/plans/2026-07-30-541-542-543-gate-hardening.md:1458` and `:2757`.
  **RE-MEASURE before designing to it.**
