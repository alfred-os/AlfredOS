# #538 — `check_tag_t3` sole-layer rules: raw-state writes and the authorisation bypasses

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `scripts/check_tag_t3.py` refuse the raw-state-write vehicles and the
authorisation-bypass names — the two classes for which the authoring layer is the ONLY
enforcement layer that can exist — and delete the now-dead `quarantine.py` exemption.

**Architecture:** Four new AST rules on the existing `_scan_text` seam, plus two shared
helpers (a prose-position map and an enclosing-function map). Every rule is **default-deny
on the VEHICLE or the SHAPE**, never an enumeration of spellings — round-2 probes minted two
genuine `TaggedContent[T3]` objects from a file that scanned clean under the enumerated rule
set the original plan proposed. No `src/alfred/**` behaviour changes; the only `src/` edits
are docstring path-string corrections.

**Tech Stack:** Python 3.14+, `ast`, pytest. No new dependencies.

## Global Constraints

- **`scripts/check_tag_t3.py` is at 100% line + branch coverage under a REQUIRED CI check**
  (`.github/workflows/ci.yml:162`, `--include='scripts/check_tag_t3.py' --fail-under=100`).
  Every new branch must be covered by an in-process test. **Do not add `# pragma: no cover`;
  do not touch `[tool.coverage.report] exclude_also`.**
- **Coverage runs are NOT concurrency-safe in a shared directory.** Use an isolated clone
  for any coverage measurement run in parallel with other work.
- `mypy --strict` and `pyright` both run over this script at **six** invocation sites. No
  `Any` without justification; PEP 604/585/695 syntax only.
- **Touch no `src/alfred/**` behaviour.** Docstring text edits only (Task 7). If a rule
  forces a code change under `src/`, scope has slipped — stop and report.
- **`fix: #NNN` in a commit SUBJECT auto-closes issue NNN**, and the conventional-commit
  gate mandates that shape. Use `fix: #538 …` on exactly one commit. **Never put `#536`,
  `#539` or `#518` in a commit subject** — the epic and its siblings must survive. `Refs`
  lines in the BODY are safe.
- Per-rule **DISTINCT** messages, and **no message may be a substring of another**
  (`test_every_collection_failure_message_is_enumerated` matches by containment).
- **Every new `_*_MESSAGE` constant must be added to the `findings` set** in
  `tests/unit/security/test_check_tag_t3_gate_integrity.py:143`. That test derives the
  declared set from the module and will red by design otherwise — that is the drift guard
  working, not a bug to route around.
- Assert returned lists by **equality** (message + snippet + lineno) on the `_scan_text`
  seam. `assert returncode != 0` is vacuous — an unhandled exception also exits 1.
- **Every negative floor gets a positive twin** built from the same text with one token
  swapped, asserted to TRIP.
- Adversarial suite is release-blocking if `src/alfred/security/` is touched:
  `uv run pytest tests/adversarial`.

---

## Measured baseline (re-measured on `main` @ `78ab6573` — do not re-derive)

All figures below were produced by execution against the 332 tracked `.py` files under
`_DEFAULT_SCAN_ROOTS` (`src/alfred` 293 + `plugins` 39), **not** by reasoning.

| Proposed rule | Cost across BOTH scan roots | New exemptions |
| --- | --- | --- |
| Vehicle attributes `.__dict__ / __setstate__ / __getstate__ / __reduce__ / __new__` | 1 (`tiers.py:508`) | **0** |
| `vars(...)` | 3 (`tiers.py:451,463,652`) | **0** |
| Vehicle dunder as a **string literal** in code position | 0 | **0** |
| `object.__setattr__` outside the one-position whitelist | 0 | **0** |
| `BaseModel`-as-a-value seam dispatch | 0 | **0** |
| `alfred.security.tiers` private surface (21 names), prose excluded | 0 | **0** |
| **FULL rule set, all 332 files** | **0** | **0** |

`tiers.py` is already whole-file exempt, so every one of the above lands inside an existing
exemption. **The complete rule set costs zero new exemptions.**

### Attack corpus — 22/22 flagged, 0 false positives (executed)

A01–A07, A09, A16, A17 (the ten spellings round-2 proved runtime-ADMITTED **and** clean
under the enumerated rule set), the three original `tl-2026-013` spellings, the
`_T3_CONSTRUCTION_AUTHORIZED.set(True)` bypass, `__setstate__` / `__new__` / `__reduce__`,
`object.__setattr__` passed as an argument and as a return value, and both alias-ordering
cases. Nine benign floors stayed clean, including the three live
`object.__setattr__(self, "<field>", …)` frozen-dataclass sites and both docstring shapes.

### Three findings that SUPERSEDE the issue body

1. **Do NOT scope the vehicle ban to "files that mention `TaggedContent`".** The issue
   proposes that scoping; measurement shows the **unscoped** ban costs the same (zero) and
   the scoped form has a live bypass — a file that receives a `TaggedContent` as a parameter
   and never spells the name:
   ```python
   from alfred.security.tiers import T3
   def launder(obj):                                   # obj is a TaggedContent[T2]
       object.__setattr__(obj, "__dict__", {**vars(obj), "tier": T3})
   ```
   Ban the vehicles unscoped.
2. **The prose exclusion must be "bare string EXPRESSION STATEMENT", not `ast.get_docstring`.**
   `src/alfred/hooks/invoke.py:466` is a **PEP-258 attribute docstring** (a bare string after
   an assignment). It is not an AST docstring, so a `get_docstring`-based exclusion reds it.
   Measured: 1 false positive with `get_docstring`, **0** with the bare-`ast.Expr` form.
3. **The `nonce_factory.py` exemption needs (path, function) AND (path, ImportFrom).** The
   issue states only the first. `nonce_factory.py:40` is a **module-level** import
   (`from alfred.security.tiers import CapabilityGateNonce, _set_authorized_t3_nonce`) —
   outside `create_and_register_t3_nonce`, so a (path, function) exemption alone reds it.
   Scope the second exemption to `ast.alias` nodes ONLY, so a module-level
   `_set_authorized_t3_nonce(x)` call in that same file still reds.

### The two traps that fail SILENTLY

- The enclosing-function walk must match **both** `ast.FunctionDef` **and**
  `ast.AsyncFunctionDef`. A `FunctionDef`-only walk matches nothing for `async def` and **no
  existing test in the repo fails**. Use one `isinstance(n, (ast.FunctionDef,
  ast.AsyncFunctionDef))` so both node types are exercised by the 332-file real-tree scan.
- The `nonce_factory.py` exemption must be **(path, function)**, never path-only:
  `_set_authorized_t3_nonce` (`tiers.py:286`) is a bare `global` write with **no** guard,
  while the idempotency guard (`T3NonceAlreadyRegisteredError`) lives in the caller. A
  path-only exemption leaves the bypass open *within* the exempt file.

---

## File structure

| File | Responsibility | Change |
| --- | --- | --- |
| `scripts/check_tag_t3.py` | the gate — all rules, helpers, constants | **Modify** (~+260 lines) |
| `tests/unit/security/test_check_tag_t3_sole_layer_rules.py` | unit tests for the four new rules + two helpers | **Create** |
| `tests/unit/security/test_check_tag_t3_gate_integrity.py` | existing meta tests | **Modify** (`findings` set, Task 2/3/4) |
| `tests/adversarial/tier_laundering/test_tier_laundering_copy_seams.py` | the tripwire | **Modify** (Task 2) |
| `tests/adversarial/tier_laundering/tl_base_dispatch_and_raw_state_write.yaml` | corpus entry | **Modify** (Task 7) |
| `tests/adversarial/tier_laundering/README.md` | corpus matrix | **Modify** (Task 7) |
| `src/alfred/security/tiers.py` | **docstring text only** | **Modify** (Task 7) |
| `docs/superpowers/plans/2026-07-29-518-detector-review-constraints.md` | stale path strings | **Modify** (Task 7) |

**The gate stays ONE file.** Splitting it would break the coverage gate's
`--include='scripts/check_tag_t3.py'` and the six `mypy`/`pyright` invocation sites.

---

### Task 1: Shared helpers — prose positions and the enclosing-function map

Both later rules need these, and both carry a silent-failure trap. Landing them first with
their own tests means the traps are pinned before any rule depends on them.

**Files:**
- Modify: `scripts/check_tag_t3.py` (new helpers after `_arg_name`, ~line 355)
- Test: `tests/unit/security/test_check_tag_t3_sole_layer_rules.py` (create)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `_prose_string_ids(tree: ast.AST) -> frozenset[int]` — `id()` of every `ast.Constant`
    that is a bare string expression statement.
  - `_enclosing_functions(tree: ast.AST) -> dict[int, str]` — line number → innermost
    enclosing function name, for `def` and `async def` alike.

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

# The import must have reached the REAL script, not a copy (constraints doc).
assert check_tag_t3._REPO_ROOT == _REPO_ROOT, (
    f"loaded the wrong script: _REPO_ROOT={check_tag_t3._REPO_ROOT} != {_REPO_ROOT}"
)


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

    def m(self) -> None:
        """method docstring"""


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
        "method docstring",
        "async function docstring",
    }


def test_prose_string_ids_excludes_strings_in_code_position() -> None:
    """A string ARGUMENT is code, not prose — this is what catches A17.

    ``getattr(_t, "_set_authorized_t3_nonce")`` hides the name in a string. If the
    prose exclusion swallowed every string constant, A17 would walk straight through.
    """
    tree = ast.parse('getattr(_t, "_set_authorized_t3_nonce")\nx = "not prose"\n')
    prose = check_tag_t3._prose_string_ids(tree)
    strings = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]
    assert strings, "the fixture must actually contain string constants"
    assert all(id(n) not in prose for n in strings)


def test_enclosing_functions_matches_async_def_as_well_as_def() -> None:
    """THE SILENT TRAP: a ``FunctionDef``-only walk matches nothing for ``async def``.

    Nothing in the repo fails when that mutation is applied, because the one real
    (path, function) exemption is a plain ``def``. This test is the only thing that
    holds the async half honest.
    """
    source = "def sync_one():\n    a = 1\n\n\nasync def async_one():\n    b = 2\n"
    fmap = check_tag_t3._enclosing_functions(ast.parse(source))
    assert fmap[2] == "sync_one"
    assert fmap[6] == "async_one", (
        "async def was not mapped — the walk is matching ast.FunctionDef only"
    )


def test_enclosing_functions_reports_the_innermost_function() -> None:
    """A nested def must shadow its parent, or an exemption leaks outward."""
    source = "def outer():\n    def inner():\n        x = 1\n    y = 2\n"
    fmap = check_tag_t3._enclosing_functions(ast.parse(source))
    assert fmap[3] == "inner"
    assert fmap[4] == "outer"


def test_enclosing_functions_leaves_module_scope_unmapped() -> None:
    """Module-level lines have no enclosing function.

    Load-bearing: the ``nonce_factory.py`` module-level import is exempted by a
    SEPARATE, alias-only rule. If module scope resolved to some function name here,
    that separate exemption would silently widen to the whole module.
    """
    fmap = check_tag_t3._enclosing_functions(ast.parse("import os\n\n\ndef f():\n    x = 1\n"))
    assert 1 not in fmap
    assert fmap[5] == "f"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -v`
Expected: FAIL — `AttributeError: module 'check_tag_t3_sole_layer' has no attribute '_prose_string_ids'`

- [ ] **Step 3: Implement the two helpers**

Insert into `scripts/check_tag_t3.py` after `_arg_name` (~line 355):

```python
def _prose_string_ids(tree: ast.AST) -> frozenset[int]:
    """``id()`` of every string constant that is PROSE rather than code.

    Prose is a **bare string expression statement**: a module, class or function
    docstring, or a PEP-258 attribute docstring (a bare string following an
    assignment). ``ast.get_docstring`` covers only the first three;
    ``src/alfred/hooks/invoke.py:466`` is the fourth shape and is a MEASURED false
    positive for the private-surface rule without it.

    WHY NOT exclude every string constant: ``getattr(_t,
    "_set_authorized_t3_nonce")`` hides the name in a string ARGUMENT (spelling A17).
    Excluding all strings would admit it. The discriminator is POSITION — a string
    that is a whole statement documents; a string anywhere else is data the program
    uses.

    WHAT THIS CANNOT DO: a comment is invisible to the parser entirely, so a private
    name inside a ``#`` comment is neither prose-excluded nor flagged. That is the
    correct outcome (a comment cannot launder anything) but it is a different
    mechanism from this one, not the same one.
    """
    return frozenset(
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    """Map every line number to the name of its INNERMOST enclosing function.

    Lines at module scope are absent from the map, which is load-bearing: the
    module-level import exemption in :data:`_IMPORT_ONLY_EXEMPT_PATHS` is a separate,
    narrower rule, and a module line resolving to some function name here would
    silently widen it to the whole file.

    **Both ``def`` and ``async def``**, in ONE ``isinstance`` over the tuple. A walk
    matching only ``ast.FunctionDef`` silently maps nothing for ``async def`` and no
    test in this repo fails — the sole real (path, function) exemption is a plain
    ``def``, and ``downgrade_to_orchestrator`` (``quarantine.py:1493``) is the
    ``async def`` that would have gone unnoticed. Writing it as one tuple check also
    means the 332-file real-tree scan exercises both node types, so the branch cannot
    rot behind a fixture.

    Inner functions are written LAST for their own line range, so a nested ``def``
    correctly shadows its parent: ``ast.walk`` is breadth-first, so a nested function
    is always visited after the function that contains it.
    """
    mapping: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for line in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                mapping[line] = node.name
    return mapping
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -v`
Expected: 5 passed

- [ ] **Step 5: Mutation-test both traps**

Run each mutation, confirm the named test REDS, then revert:

```bash
cd /Users/iandominey/projects/AlfredOS
# Trap A — FunctionDef-only walk. MUST red test_enclosing_functions_matches_async_def_as_well_as_def
python3 - <<'PY'
import pathlib
p = pathlib.Path("scripts/check_tag_t3.py"); s = p.read_text()
new = s.replace("isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))",
                "isinstance(node, ast.FunctionDef)")
assert new != s, "MUTATION DID NOT APPLY — the assertion below would be meaningless"
p.write_text(new)
PY
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -q; echo "rc=$?  (MUST be non-zero)"
git checkout scripts/check_tag_t3.py

# Trap B — exclude EVERY string constant, not just bare-expression ones.
# MUST red test_prose_string_ids_excludes_strings_in_code_position
python3 - <<'PY'
import pathlib
p = pathlib.Path("scripts/check_tag_t3.py"); s = p.read_text()
new = s.replace("if isinstance(node, ast.Expr)\n        and isinstance(node.value, ast.Constant)",
                "if isinstance(node, (ast.Expr, ast.Call))\n        and isinstance(node.value, ast.Constant)")
assert new != s, "MUTATION DID NOT APPLY — the assertion below would be meaningless"
p.write_text(new)
PY
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -q; echo "rc=$? (inspect)"
git checkout scripts/check_tag_t3.py
```

> The `assert new != s` line is mandatory. A mutation script that silently stops
> matching after a reindent turns "the mutant survived" into a false conclusion — that
> exact false alarm cost a session on #552.

- [ ] **Step 6: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/test_check_tag_t3_sole_layer_rules.py
git commit -m "test: #538 prose-position and enclosing-function helpers for the sole-layer rules"
```

---

### Task 2: The raw-state-write vehicle ban (+ flip the tripwire)

Closes A01–A07 and the original `object.__setattr__(obj, "tier", T3)` spelling as a
**class**. The tripwire flips in this commit because these rules are what make it fire —
splitting them would leave `main` red between commits.

**Files:**
- Modify: `scripts/check_tag_t3.py` (constants ~line 90; rules inside `_scan_text`)
- Modify: `tests/unit/security/test_check_tag_t3_gate_integrity.py:143` (`findings` set)
- Modify: `tests/adversarial/tier_laundering/test_tier_laundering_copy_seams.py:216`
- Test: `tests/unit/security/test_check_tag_t3_sole_layer_rules.py` (append)

**Interfaces:**
- Consumes: `_prose_string_ids` (Task 1).
- Produces: `_RAW_VEHICLE_ATTR_MESSAGE`, `_RAW_VEHICLE_VARS_MESSAGE`,
  `_RAW_VEHICLE_STR_MESSAGE`, `_RAW_SETATTR_SHAPE_MESSAGE`,
  `_RAW_SETATTR_ALIASED_MESSAGE`, `_RAW_STATE_VEHICLE_ATTRS: frozenset[str]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/security/test_check_tag_t3_sole_layer_rules.py`:

```python
_PROBE = Path("/nonexistent/probe.py")  # non-exempt, and never read from disk


def _messages(source: str) -> list[str]:
    """Violation MESSAGE lines only — the odd-indexed entries are code snippets."""
    return [v for v in check_tag_t3._scan_text(source, _PROBE) if not v.startswith("  ")]


def test_a01_object_setattr_writing_dunder_dict_is_refused() -> None:
    """A01 — the decisive spelling. Round-2 minted a real TaggedContent[T3] with it.

    Asserted by EQUALITY, not by "returns something": the constraints doc records that
    ``assert returncode != 0`` is satisfied by an unhandled exception too.

    A01 defeats the "key on the written ``tier`` attribute" rule BY CONSTRUCTION — the
    attribute written here is ``__dict__``. That is why the vehicle is banned, not the
    spelling.
    """
    source = 'object.__setattr__(obj, "__dict__", {"tier": T3})\n'
    assert check_tag_t3._scan_text(source, _PROBE) == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}",
        '  object.__setattr__(obj, "__dict__", {"tier": T3})',
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}",
        '  object.__setattr__(obj, "__dict__", {"tier": T3})',
    ]


def test_the_original_tier_write_spelling_is_refused() -> None:
    """``object.__setattr__(obj, "tier", T3)`` — the headline tl-2026-013 spelling.

    A shape rule that allowed every plain string literal would admit exactly this.
    """
    assert _messages('object.__setattr__(low, "tier", T3)\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]


def test_object_setattr_with_a_variable_attribute_name_is_refused() -> None:
    """A04 — the attribute name is computed, so no lexical rule can read it."""
    assert _messages("object.__setattr__(obj, _ATTR, T3)\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]


def test_object_setattr_referenced_outside_call_position_is_refused() -> None:
    """A05 — aliasing the callable defeats every rule keyed on the CALL.

    The one-position whitelist is what closes it: ``Call.func`` is the only admissible
    position for this reference. Never an ancestor blacklist — a blacklist must
    ENUMERATE the bad positions and silently widens when a new one appears.
    """
    assert _messages("_osa = object.__setattr__\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_ALIASED_MESSAGE}"
    ]
    assert _messages("apply(object.__setattr__, obj, 'tier', T3)\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_ALIASED_MESSAGE}"
    ]


def test_dunder_dict_attribute_access_is_refused() -> None:
    """A02 and A07 — ``.update(...)`` and indirection through a local both need it."""
    assert _messages('obj.__dict__.update({"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE}"
    ]
    assert _messages('d = obj.__dict__\nd["tier"] = T3\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE}"
    ]


def test_vars_call_is_refused() -> None:
    """A03 — ``vars(obj)`` returns the same mapping ``__dict__`` does."""
    assert _messages('vars(obj)["tier"] = T3\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_VARS_MESSAGE}"
    ]


def test_vehicle_dunder_named_as_a_string_is_refused() -> None:
    """A06 — ``getattr(obj, "__dict__")`` never produces an ``ast.Attribute``.

    The attribute-node rule cannot see it. Keying on the NAME wherever it appears in
    code position closes the indirection class, including ``_A = "__dict__"``.
    """
    assert _messages('getattr(obj, "__dict__")["tier"] = T3\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"
    ]
    assert _messages('_A = "__dict__"\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"
    ]


def test_setstate_new_and_reduce_are_refused() -> None:
    """The rest of the raw-state class, banned as VEHICLES not as spellings."""
    assert _messages('obj.__setstate__({"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE}"
    ]
    assert _messages("o = TaggedContent.__new__(TaggedContent[T3])\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE}"
    ]
    assert _messages("f, args = obj.__reduce__()\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE}"
    ]


def test_frozen_dataclass_post_init_idiom_stays_clean() -> None:
    """NEGATIVE FLOOR — three live sites use this and none may red.

    ``hooks/context.py:106``, ``plugins/web_fetch/allowlist.py:139``,
    ``plugins/web_fetch/fetch_dispatcher.py:219``. Refusing ``object.__setattr__``
    outright would red all three; the SHAPE is what discriminates.
    """
    assert check_tag_t3._scan_text(
        'object.__setattr__(self, "metadata", dict(self.metadata))\n', _PROBE
    ) == []


def test_frozen_dataclass_positive_twin_trips_on_one_token() -> None:
    """POSITIVE TWIN of the floor above — same text, ``metadata`` swapped for ``tier``.

    Without this, nothing proves the benign text reached the rule at all.
    """
    assert _messages('object.__setattr__(self, "tier", dict(self.metadata))\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]


def test_benign_dunder_introspection_stays_clean() -> None:
    """NEGATIVE FLOOR — live at ``config/settings.py:95``, ``invoke.py:1265``,
    ``_extract_dlp_subscriber.py:318``. These dunders are not raw-state vehicles."""
    assert check_tag_t3._scan_text('n = getattr(inner, "__name__", "x")\n', _PROBE) == []
    assert check_tag_t3._scan_text('t = exc.__class__.__name__\n', _PROBE) == []
    assert check_tag_t3._scan_text('b = getattr(fn, "__self__", None)\n', _PROBE) == []


def test_ordinary_dynamic_getattr_stays_clean() -> None:
    """NEGATIVE FLOOR — ``getattr(prev, field)`` is four live sites in
    ``policies/snapshot_ref.py``. Banning non-literal ``getattr`` outright costs 7
    false positives (measured); this rule does not do that."""
    assert check_tag_t3._scan_text("prev_val = getattr(prev, field)\n", _PROBE) == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -v`
Expected: FAIL — `AttributeError: … has no attribute '_RAW_SETATTR_SHAPE_MESSAGE'`

- [ ] **Step 3: Add the message constants**

Insert into `scripts/check_tag_t3.py` after `_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE` (~line 89):

```python
# ---------------------------------------------------------------------------
# #538 — THE SOLE-LAYER RULES.
#
# The runtime CANNOT refuse these. Raw state writes never route through any
# method the model can override (`frozen=True` observes `__setattr__`, and none
# of these traverse it), so there is no seam left to guard. The authoring layer
# is therefore the ONLY enforcement layer that can exist for them, which is why
# these rules are release-blocking rather than advisory.
#
# DEFAULT-DENY THE VEHICLE, NEVER ENUMERATE THE SPELLING. Round-2 probes minted
# two genuine `TaggedContent[T3]` objects with attacker-controlled content from a
# file that scanned clean under BOTH the detector as merged AND the fully
# enumerated rule set the original plan proposed. Ten spellings were admitted.
# The decisive one:
#
#     object.__setattr__(obj, "__dict__", {..., "tier": T3})
#
# The constraints doc mandated "key on the written `tier` attribute, not on the
# call". That rule cannot see this line BY CONSTRUCTION — the attribute written
# is `__dict__`. Enumerating spellings closes what you thought of; denying the
# vehicle closes the class (#518, fifth instance in this file's history).
#
# Messages are per-rule DISTINCT and no message is a SUBSTRING of another:
# `test_every_collection_failure_message_is_enumerated` matches by containment,
# so a substring pair is mutually satisfiable and a shape test could be green on
# the wrong rule firing.
_RAW_STATE_VEHICLE_ATTRS: frozenset[str] = frozenset(
    {"__dict__", "__setstate__", "__getstate__", "__reduce__", "__new__"}
)
_RAW_VEHICLE_ATTR_MESSAGE: str = (
    "raw-state vehicle attribute — reaches instance state without traversing any "
    "method the model can guard. Use tag_t3_with_nonce()."
)
_RAW_VEHICLE_VARS_MESSAGE: str = (
    "vars() exposes the instance mapping directly — same unguarded reach as "
    "__dict__. Use tag_t3_with_nonce()."
)
_RAW_VEHICLE_STR_MESSAGE: str = (
    "a raw-state vehicle named as a string in code position — getattr() and "
    "friends reach it without an attribute node. Use tag_t3_with_nonce()."
)
_RAW_SETATTR_SHAPE_MESSAGE: str = (
    "object.__setattr__ with a computed, dunder or tier attribute name — bypasses "
    "frozen=True and every tier guard. Use tag_t3_with_nonce()."
)
_RAW_SETATTR_ALIASED_MESSAGE: str = (
    "object.__setattr__ referenced outside direct-call position — an alias defeats "
    "any rule keyed on the call. Call it inline with a literal field name."
)
```

- [ ] **Step 4: Add the rules to `_scan_text`**

In `_scan_text`, immediately after `tree = ast.parse(...)` succeeds and before the
existing `for node in ast.walk(tree):` loop, add the per-file maps:

```python
        prose = _prose_string_ids(tree)
        # ONE-POSITION WHITELIST. `Call.func` is the ONLY admissible position for
        # an `object.__setattr__` reference; every other position (an alias
        # binding, an argument, a return value) is the A05 vehicle. Never an
        # ancestor blacklist: a blacklist must ENUMERATE the bad positions and
        # silently widens the day a new one appears.
        call_func_ids = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
```

Then, inside the existing walk loop, replace the `if not isinstance(node, ast.Call): continue`
early-exit with a structure that visits every node. Add before the `ast.Call` handling:

```python
            if isinstance(node, ast.Attribute) and node.attr in _RAW_STATE_VEHICLE_ATTRS:
                _record(violations, lines, path, node.lineno, _RAW_VEHICLE_ATTR_MESSAGE)
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "object"
                and node.attr == "__setattr__"
                and id(node) not in call_func_ids
            ):
                _record(violations, lines, path, node.lineno, _RAW_SETATTR_ALIASED_MESSAGE)
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value in _RAW_STATE_VEHICLE_ATTRS
                and id(node) not in prose
            ):
                _record(violations, lines, path, node.lineno, _RAW_VEHICLE_STR_MESSAGE)
```

and inside the `ast.Call` arm:

```python
            if isinstance(node.func, ast.Name) and node.func.id == "vars":
                _record(violations, lines, path, node.lineno, _RAW_VEHICLE_VARS_MESSAGE)
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "object"
                and node.func.attr == "__setattr__"
                and not _is_benign_setattr_target(node)
            ):
                _record(violations, lines, path, node.lineno, _RAW_SETATTR_SHAPE_MESSAGE)
```

> **Restructuring `_scan_text`'s walk loop.** The existing loop opens with
> `if not isinstance(node, ast.Call): continue`, which skips every non-Call node —
> and three of the new rules key on `ast.Attribute` / `ast.Constant`. Replace that
> early-`continue` with an `if isinstance(node, ast.Call):` block wrapping the
> existing Call-only body (including the `GateInternalError` fence, which must keep
> wrapping the three original `_is_*` predicates and nothing else). The new
> non-Call rules go BEFORE that block. Do not widen the fence to cover the new
> predicates in the same `try` — see the note in Step 4b.

Add the two helpers next to the other predicates:

```python
def _record(
    violations: list[str], lines: list[str], path: Path, lineno: int, message: str
) -> None:
    """Append a violation MESSAGE line plus its source SNIPPET line.

    Every rule reports the same two-line shape, so tests can assert the returned
    list by equality rather than by substring search. Factored out because seven
    new rules repeating the pair would be seven places for the shape to drift
    (#422: a shared helper fails LOUD, N copies drift SILENTLY).

    ``path`` is passed explicitly rather than read from a module global:
    :func:`_scan_text` is documented as PURE and this repo forbids global state,
    so the label travels as an argument.
    """
    snippet = lines[lineno - 1].rstrip() if 0 <= lineno - 1 < len(lines) else ""
    violations.append(f"{path}:{lineno}: {message}")
    violations.append(f"  {snippet}")


def _is_benign_setattr_target(node: ast.Call) -> bool:
    """True for the established frozen-dataclass idiom, false for every vehicle.

    DEFAULT-DENY ON SHAPE. Admissible only when the attribute argument is a plain
    string literal that is neither a dunder nor the tier field:

    * a NON-literal name cannot be read by any lexical rule      -> denied (A04);
    * a DUNDER name reaches interpreter state, not a field       -> denied (A01);
    * the literal ``"tier"`` is the headline tl-2026-013 write   -> denied.

    Three live sites depend on the admissible case and none of them may red:
    ``hooks/context.py:106``, ``plugins/web_fetch/allowlist.py:139``,
    ``plugins/web_fetch/fetch_dispatcher.py:219``. Measured false-positive cost of
    this shape across both scan roots: ZERO.

    ESCAPE HATCH, named so nobody has to invent one: a frozen dataclass that
    genuinely needs a field called ``tier`` and is NOT a ``TaggedContent`` should
    set it through its own constructor, or the write belongs behind a named helper
    inside the already-exempt ``security/tiers.py`` — not behind a loosened rule.
    """
    if len(node.args) < 2:
        return False
    attr = node.args[1]
    if not (isinstance(attr, ast.Constant) and isinstance(attr.value, str)):
        return False
    name = attr.value
    if name.startswith("__") and name.endswith("__"):
        return False
    return name != "tier"
```

**Step 4b — keep the `GateInternalError` fence exactly as narrow as it is.**

The existing `try:` inside the walk loop wraps *only* the three original `_is_*`
predicates, and `_scan_text`'s docstring plus `GateInternalError`'s docstring both
state why: those three do constant work on an already-parsed node, so anything they
raise is a defect in this file, reported as exit 2 ("the gate could not run") rather
than exit 1 ("violations found"). The new predicates are the same kind of constant
work, so they belong **inside** the same fence — but `ast.walk` advancing, and the
new per-file map construction (`_prose_string_ids`, `_enclosing_functions`,
`_basemodel_alias_names`, `call_func_ids`), are genuinely input-driven and must stay
**outside** it, alongside `ast.parse`.

Concretely: build the four maps immediately after `ast.parse` succeeds, outside any
fence; put every `_is_*` / `_private_surface_hit` call inside the existing `try`.
Then update `GateInternalError`'s docstring, which currently says "The three
predicates do constant work" — it is seven now, and a stale count there is the
"comment outran the code" shape this repo has hit four times in one PR.

- [ ] **Step 5: Register the new messages in the drift guard**

In `tests/unit/security/test_check_tag_t3_gate_integrity.py`, add all five new constants
to the `findings` set at line 143 (they are FINDINGS — the file was gated and failed —
not collection failures):

```python
    findings = {
        check_tag_t3._TAG_T3_MESSAGE,
        check_tag_t3._CAST_TAGGED_CONTENT_MESSAGE,
        check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE,
        check_tag_t3._TYPE_IGNORE_MESSAGE,
        check_tag_t3._GATE_INTERNAL_MESSAGE,
        # #538 sole-layer rules. Findings, not collection failures: each means the
        # file WAS gated and failed, so neither reader of
        # _COLLECTION_FAILURE_MESSAGES should see them.
        check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE,
        check_tag_t3._RAW_VEHICLE_VARS_MESSAGE,
        check_tag_t3._RAW_VEHICLE_STR_MESSAGE,
        check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE,
        check_tag_t3._RAW_SETATTR_ALIASED_MESSAGE,
    }
```

- [ ] **Step 6: Flip the tripwire**

In `tests/adversarial/tier_laundering/test_tier_laundering_copy_seams.py`, replace the
final assertion of `test_tl_2026_013_is_currently_undefended_at_the_authoring_layer_too`
and rename the test to state the new fact:

```python
def test_tl_2026_013_is_now_defended_at_the_authoring_layer(
    tmp_path: Path,
) -> None:
    """The residual's named fallback layer NOW detects it — #538 flipped this.

    Was ``test_tl_2026_013_is_currently_undefended_at_the_authoring_layer_too``,
    asserting ``== 0``. It was designed to FAIL when the #538 rules landed, and it
    did. The runtime still cannot refuse these spellings — that half of
    ``tl-2026-013`` is unchanged and ``out_of_scope`` stays ``true``. What changed
    is the authoring layer.

    ``== 1``, not ``!= 0``: exit 2 means "the gate could not run", and a test that
    accepts it would be green on a gate that scanned nothing.
    """
    probe = tmp_path / "residual_spellings.py"
    probe.write_text(_RESIDUAL_SPELLINGS)

    # Positive control FIRST: proves the file is reachable and scanned, so the
    # result below cannot come from the detector silently skipping the path.
    control = tmp_path / "known_bad.py"
    control.write_text(_RESIDUAL_SPELLINGS + '\ntagged = tag(T3, "x")\n')
    assert check_tag_t3.main([str(control)]) == 1

    assert check_tag_t3.main([str(probe)]) == 1, (
        "scripts/check_tag_t3.py no longer flags the tl-2026-013 residual spellings. "
        "That is a REGRESSION of #538 — the authoring layer is the only layer that "
        "can refuse these; the runtime provably cannot."
    )
```

- [ ] **Step 7: Run the full affected suites**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py \
              tests/unit/security/test_check_tag_t3_gate_integrity.py \
              tests/unit/security/test_check_tag_t3_subscript.py \
              tests/adversarial/tier_laundering -q
python3 scripts/check_tag_t3.py; echo "real-tree scan rc=$?  (MUST be 0)"
```
Expected: all green, and the real-tree scan exits 0 — the rules cost zero new exemptions.

- [ ] **Step 8: Mutation-test each rule**

For each mutation: apply, confirm the NAMED test reds, revert. Every script must carry
`assert new != s`.

| Mutation | Must red |
| --- | --- |
| drop `"__dict__"` from `_RAW_STATE_VEHICLE_ATTRS` | `test_dunder_dict_attribute_access_is_refused` |
| `_is_benign_setattr_target` returns `True` unconditionally | `test_a01_…`, `test_the_original_tier_write_spelling_is_refused` |
| `_is_benign_setattr_target` returns `False` unconditionally (WIDENING) | `test_frozen_dataclass_post_init_idiom_stays_clean` |
| drop the `name != "tier"` check | `test_the_original_tier_write_spelling_is_refused` |
| drop the dunder check in `_is_benign_setattr_target` | `test_a01_object_setattr_writing_dunder_dict_is_refused` |
| drop `id(node) not in call_func_ids` (WIDENING) | `test_frozen_dataclass_post_init_idiom_stays_clean` |
| drop `id(node) not in prose` (WIDENING) | Task 4's docstring floor — note it here, verify after Task 4 |

- [ ] **Step 9: Commit**

```bash
git add scripts/check_tag_t3.py \
        tests/unit/security/test_check_tag_t3_sole_layer_rules.py \
        tests/unit/security/test_check_tag_t3_gate_integrity.py \
        tests/adversarial/tier_laundering/test_tier_laundering_copy_seams.py
git commit -m "fix: #538 default-deny the raw-state-write vehicles, not their spellings"
```

> This is the ONE commit carrying `fix: #538`. Every other commit in this branch uses
> `test:` / `refactor:` / `docs:` with `Refs #538` in the BODY, so the issue closes
> exactly once and `#536` never appears in a subject.

---

### Task 3: `BaseModel`-as-a-value seam dispatch, with a fixed-point alias set

Closes A09 and the two original unbound-dispatch spellings. Measured cost across both scan
roots: **zero** `BaseModel.<attr>` accesses exist in real code (every textual hit is
docstring prose), so this rule is free.

**Files:**
- Modify: `scripts/check_tag_t3.py`
- Modify: `tests/unit/security/test_check_tag_t3_gate_integrity.py` (`findings` set)
- Test: `tests/unit/security/test_check_tag_t3_sole_layer_rules.py` (append)

**Interfaces:**
- Consumes: `_record` (Task 2).
- Produces: `_BASEMODEL_VALUE_MESSAGE`, `_BASEMODEL_SEAM_ATTRS: frozenset[str]`,
  `_basemodel_alias_names(tree: ast.AST) -> frozenset[str]`.

- [ ] **Step 1: Write the failing tests**

```python
def test_unbound_basemodel_seam_dispatch_is_refused() -> None:
    """The two original tl-2026-013 unbound-dispatch spellings."""
    assert _messages('BaseModel.model_copy(low, update={"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]
    assert _messages('BaseModel.copy(low, update={"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]


def test_basemodel_dunder_func_dispatch_is_refused() -> None:
    """``BaseModel.model_construct.__func__(cls, ...)`` — dispatch through the
    unbound function object, which skips every override on the way in."""
    source = "built = BaseModel.model_construct.__func__(TaggedContent[T3], tier=T3)\n"
    assert check_tag_t3._BASEMODEL_VALUE_MESSAGE in _messages(source)[0]


def test_import_aliased_basemodel_is_refused() -> None:
    """A09 — ``from pydantic import BaseModel as BM`` defeats a name-literal rule."""
    source = "from pydantic import BaseModel as BM\nBM.model_copy(obj, update=u)\n"
    assert _messages(source) == [f"{_PROBE}:2: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"]


def test_alias_resolution_reaches_a_fixed_point() -> None:
    """REVERSE ORDER — ``C = B`` written BEFORE ``B = BaseModel``.

    PROVEN REQUIRED by mutation: a single-pass resolver yields ``{BaseModel, B}`` and
    MISSES ``C`` entirely. Asserted on the EXACT rule, not merely "trips" — the
    constraints doc records a sibling case where the single-pass mutant still tripped
    under a different rule, so a "does it trip" assertion let it survive.
    """
    source = "from pydantic import BaseModel\nC = B\nB = BaseModel\nC.model_copy(o, update=u)\n"
    assert _messages(source) == [f"{_PROBE}:4: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"]


def test_instance_model_copy_stays_clean() -> None:
    """NEGATIVE FLOOR — ``obj.model_copy(...)`` on an INSTANCE is the supported API.

    A receiver-blind rule that flagged every ``model_copy`` would red ordinary
    pydantic use. The receiver is what discriminates.
    """
    assert check_tag_t3._scan_text('other = obj.model_copy(update={"a": 1})\n', _PROBE) == []


def test_instance_model_copy_positive_twin_trips() -> None:
    """POSITIVE TWIN of the floor above — receiver swapped, one token."""
    assert _messages('other = BaseModel.model_copy(update={"a": 1})\n') == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]


def test_basemodel_named_only_in_prose_stays_clean() -> None:
    """NEGATIVE FLOOR — ``tiers.py`` and ``quarantine.py`` docstrings name these
    spellings repeatedly. Measured: every textual ``BaseModel.<attr>`` hit under both
    scan roots is prose; there are ZERO real accesses."""
    source = '"""See ``BaseModel.model_copy(obj, update={"tier": T3})`` for why."""\n'
    assert check_tag_t3._scan_text(source, _PROBE) == []
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -k basemodel -v`
Expected: FAIL — `AttributeError: … '_BASEMODEL_VALUE_MESSAGE'`

- [ ] **Step 3: Implement**

```python
# Seam methods that write field state when dispatched with the CLASS as receiver.
# `model_validate` / `model_validate_json` are included because the wire round-trip
# is a construction path; `copy` is pydantic v1's spelling and does NOT route
# through `model_copy` (it merges `update` inside `copy_internals`).
_BASEMODEL_SEAM_ATTRS: frozenset[str] = frozenset(
    {"copy", "model_copy", "model_construct", "model_validate", "model_validate_json"}
)
_BASEMODEL_VALUE_MESSAGE: str = (
    "unbound BaseModel seam dispatch — builds field state through "
    "_copy_and_set_values, reaching neither the class overrides nor "
    "model_post_init. Call the seam on the INSTANCE, or use tag_t3_with_nonce()."
)


def _basemodel_alias_names(tree: ast.AST) -> frozenset[str]:
    """Every local name bound to ``pydantic.BaseModel``, to a FIXED POINT.

    Two binding forms: ``from pydantic import BaseModel as BM`` and a plain
    ``B = BaseModel`` rebind, including chains (``C = B`` where ``B = BaseModel``).

    THE FIXED POINT IS PROVEN REQUIRED, not defensive. With ``C = B`` written
    BEFORE ``B = BaseModel``, a single pass over the tree yields ``{BaseModel, B}``
    and misses ``C`` entirely — measured by mutation. Source order is the author's
    to choose, so a resolver that depends on it is a resolver an attacker controls.

    Bounded rather than ``while True``: the name set only grows and is bounded by
    the number of distinct names in the file, so iterating until it stops changing
    terminates. The explicit bound exists so a pathological input cannot spin.
    """
    names = {"BaseModel"}
    assignments: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.alias) and node.name == "BaseModel" and node.asname:
            names.add(node.asname)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.append((target.id, node.value.id))
    for _ in range(len(assignments) + 1):
        grown = {t for t, s in assignments if s in names} - names
        if not grown:
            break
        names |= grown
    return frozenset(names)
```

Inside `_scan_text`, alongside the other per-file maps:

```python
        basemodel_names = _basemodel_alias_names(tree)
```

and inside the `ast.Call` arm:

```python
            if _is_unbound_basemodel_seam_call(node, basemodel_names):
                _record(violations, lines, path, node.lineno, _BASEMODEL_VALUE_MESSAGE)
```

with the predicate beside the other `_is_*` helpers:

```python
def _is_unbound_basemodel_seam_call(node: ast.Call, basemodel_names: frozenset[str]) -> bool:
    """``BaseModel.<seam>(obj, ...)`` — dispatch with the CLASS as receiver.

    RECEIVER-SCOPED on purpose. A receiver-blind rule flagging every
    ``model_copy`` reds ordinary instance use across the tree; the receiver is the
    whole discriminator. Measured cost of the receiver-scoped form: ZERO sites.

    Two shapes:

    * ``BM.model_copy(obj, update=…)``            — Attribute on a BaseModel name
    * ``BM.model_construct.__func__(cls, …)``     — one more hop through the
      unbound function object, which skips every override on the way in.

    WHAT THIS CANNOT DO: a cross-module re-export (``from x import BaseModel as Y``
    in module A, imported from A by module B) is invisible — the alias set is
    per-file. That residual is accepted; closing it needs whole-program analysis,
    which this gate deliberately is not.
    """
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    receiver = func.value
    if isinstance(receiver, ast.Name):
        return receiver.id in basemodel_names and func.attr in _BASEMODEL_SEAM_ATTRS
    if isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Name):
        return (
            receiver.value.id in basemodel_names and receiver.attr in _BASEMODEL_SEAM_ATTRS
        )
    return False
```

- [ ] **Step 4: Register the message in the drift guard**

Add `check_tag_t3._BASEMODEL_VALUE_MESSAGE` to the `findings` set.

- [ ] **Step 5: Run the tests**

```bash
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py tests/unit/security/test_check_tag_t3_gate_integrity.py -q
python3 scripts/check_tag_t3.py; echo "rc=$? (MUST be 0)"
```

- [ ] **Step 6: Mutation-test**

| Mutation | Must red |
| --- | --- |
| `range(len(assignments) + 1)` → `range(1)` (single pass) | `test_alias_resolution_reaches_a_fixed_point` |
| drop the `ast.alias` arm | `test_import_aliased_basemodel_is_refused` |
| receiver check → always `True` (WIDENING) | `test_instance_model_copy_stays_clean` |
| drop the nested-`Attribute` arm | `test_basemodel_dunder_func_dispatch_is_refused` |

- [ ] **Step 7: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/
git commit -m "test: #538 refuse unbound BaseModel seam dispatch through a fixed-point alias set

Refs #538"
```

---

### Task 4: The `alfred.security.tiers` private-surface default-deny

Closes A16, A17 and `_T3_CONSTRUCTION_AUTHORIZED.set(True)` — the two bypasses **nothing
in the repo catches today**. These are the authorisation MECHANISM, so the runtime cannot
refuse them by definition.

**Files:**
- Modify: `scripts/check_tag_t3.py`
- Modify: `tests/unit/security/test_check_tag_t3_gate_integrity.py` (`findings` set)
- Test: `tests/unit/security/test_check_tag_t3_sole_layer_rules.py` (append)

**Interfaces:**
- Consumes: `_prose_string_ids`, `_enclosing_functions` (Task 1); `_record` (Task 2).
- Produces: `_PRIVATE_SURFACE_MESSAGE`, `_TIERS_PRIVATE_SURFACE: frozenset[str]`,
  `_FUNCTION_SCOPED_EXEMPTIONS: frozenset[tuple[Path, str]]`,
  `_IMPORT_ONLY_EXEMPT_PATHS: frozenset[Path]`.

- [ ] **Step 1: Write the failing tests**

```python
_NONCE_FACTORY = _REPO_ROOT / "src" / "alfred" / "bootstrap" / "nonce_factory.py"


def test_import_aliased_nonce_setter_is_refused() -> None:
    """A16 — the import alias hides the name from every rule keyed on the CALL."""
    source = (
        "from alfred.security.tiers import _set_authorized_t3_nonce as _reg\n_reg(mine)\n"
    )
    assert _messages(source) == [f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"]


def test_getattr_string_nonce_setter_is_refused() -> None:
    """A17 — the name lives in a STRING, so no Name/Attribute node carries it.

    This is why the prose exclusion must be position-based: excluding every string
    constant would admit this line.
    """
    source = 'import alfred.security.tiers as _t\ngetattr(_t, "_set_authorized_t3_nonce")(mine)\n'
    assert _messages(source) == [f"{_PROBE}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"]


def test_context_var_authorisation_flip_is_refused() -> None:
    """``_T3_CONSTRUCTION_AUTHORIZED.set(True)`` — flips the guard off wholesale.

    One of the two bypasses NOTHING in the repo catches before this change.
    """
    assert _messages("_T3_CONSTRUCTION_AUTHORIZED.set(True)\n") == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_private_surface_named_only_in_prose_stays_clean() -> None:
    """NEGATIVE FLOOR — THREE live docstrings name these symbols.

    ``cli/daemon/_failures.py:150``, ``hooks/invoke.py:407`` and ``:469``. The last
    is a PEP-258 ATTRIBUTE docstring, which ``ast.get_docstring`` does not see —
    measured as a false positive without the bare-``ast.Expr`` form.
    """
    assert check_tag_t3._scan_text(
        '"""Sets ``alfred.security.tiers._AUTHORIZED_T3_NONCE`` once at start."""\n', _PROBE
    ) == []
    assert check_tag_t3._scan_text(
        'X = 1\n"""See :func:`alfred.security.tiers._tier_by_name`."""\n', _PROBE
    ) == []


def test_private_surface_prose_floor_has_a_positive_twin() -> None:
    """POSITIVE TWIN — the same name in CODE position, one token of difference."""
    assert _messages('X = _tier_by_name("T3")\n') == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_nonce_factory_is_exempt_inside_its_registration_function_only() -> None:
    """(path, FUNCTION), never path-only.

    ``_set_authorized_t3_nonce`` (``tiers.py:286``) is a bare ``global`` write with
    NO guard; the idempotency guard (``T3NonceAlreadyRegisteredError``) lives in the
    CALLER. A path-only exemption therefore leaves the bypass open WITHIN the exempt
    file — which is the whole point of narrowing it.
    """
    inside = (
        "def create_and_register_t3_nonce():\n"
        "    nonce = CapabilityGateNonce()\n"
        "    _set_authorized_t3_nonce(nonce)\n"
        "    return nonce\n"
    )
    assert check_tag_t3._scan_text(inside, _NONCE_FACTORY) == []

    outside = (
        "def some_other_helper():\n"
        "    _set_authorized_t3_nonce(attacker_nonce)\n"
    )
    assert check_tag_t3._scan_text(outside, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}",
        "      _set_authorized_t3_nonce(attacker_nonce)",
    ]


def test_nonce_factory_exemption_covers_async_def_too() -> None:
    """THE SILENT TRAP, asserted through the real exemption path.

    A ``FunctionDef``-only enclosing walk maps nothing for ``async def``, so this
    body would red. Nothing else in the repo exercises the async half — the one real
    exemption is a plain ``def``.
    """
    source = (
        "async def create_and_register_t3_nonce():\n"
        "    _set_authorized_t3_nonce(nonce)\n"
    )
    assert check_tag_t3._scan_text(source, _NONCE_FACTORY) == []


def test_nonce_factory_module_level_import_is_exempt_but_module_level_calls_are_not() -> None:
    """THE SECOND EXEMPTION, and its deliberate narrowness.

    ``nonce_factory.py:40`` is a MODULE-LEVEL import — outside every function — so a
    (path, function) exemption alone reds the real file. The import exemption is
    scoped to ``ast.alias`` nodes ONLY, so a module-level CALL in the same file still
    reds. Without that scoping the exemption would silently widen to the whole
    module.
    """
    assert check_tag_t3._scan_text(
        "from alfred.security.tiers import CapabilityGateNonce, _set_authorized_t3_nonce\n",
        _NONCE_FACTORY,
    ) == []
    assert _messages_for(
        "_set_authorized_t3_nonce(attacker_nonce)\n", _NONCE_FACTORY
    ) == [f"{_NONCE_FACTORY}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"]


def test_the_real_nonce_factory_file_scans_clean() -> None:
    """THE REAL FILE, under its REAL path — not a fixture approximation.

    The exemption exists for exactly one file; a fixture that merely resembles it
    proves nothing about whether the shipped file passes.
    """
    assert check_tag_t3._scan_file(_NONCE_FACTORY) == []


def test_private_surface_constant_matches_the_real_tiers_module() -> None:
    """DRIFT GUARD — derive the expected set, do not restate it.

    An enumeration only closes what it enumerates (#518). Hard-coding the tuple keeps
    the gate free of import-time I/O (it runs under bare ``python3``, with no venv
    and no ``alfred`` on the path), and this test is what stops it drifting: a new
    private module-level name in ``tiers.py`` reds HERE on the day it lands, instead
    of quietly falling outside the rule.
    """
    tree = ast.parse((_REPO_ROOT / "src" / "alfred" / "security" / "tiers.py").read_text())
    derived: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            derived.add(node.name)
        elif isinstance(node, ast.Assign):
            derived.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            derived.add(node.target.id)
    expected = {n for n in derived if n.startswith("_") and not n.startswith("__")}

    assert set(check_tag_t3._TIERS_PRIVATE_SURFACE) == expected, (
        "tiers.py's private module-level surface has drifted from the gate's "
        f"constant. Added: {sorted(expected - set(check_tag_t3._TIERS_PRIVATE_SURFACE))}. "
        f"Removed: {sorted(set(check_tag_t3._TIERS_PRIVATE_SURFACE) - expected)}."
    )
    assert expected, "derived an EMPTY surface — the derivation is broken, not the constant"
```

Add the small helper the module-level test needs, next to `_messages`:

```python
def _messages_for(source: str, path: Path) -> list[str]:
    """``_messages`` under a caller-chosen path — the exemption tests need both."""
    return [v for v in check_tag_t3._scan_text(source, path) if not v.startswith("  ")]
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -k private_surface -v`
Expected: FAIL — `AttributeError: … '_PRIVATE_SURFACE_MESSAGE'`

- [ ] **Step 3: Implement**

```python
# The PRIVATE SURFACE of `alfred.security.tiers` — every underscore-prefixed
# module-level name it defines. Reaching into any of them from outside the two
# authorised homes is a bypass of the authorisation MECHANISM itself, which is why
# the runtime cannot refuse it: these names ARE the mechanism.
#
# LEXICAL BY NAME, not by AST call shape. Round-2 defeated a call-shape rule twice
# over: `from … import _set_authorized_t3_nonce as _reg; _reg(mine)` (A16) and
# `getattr(_t, "_set_authorized_t3_nonce")(mine)` (A17). Neither leaves a call node
# naming the function. Keying on the NAME wherever it appears in CODE position
# closes both, and the string arm is what reaches A17.
#
# HARD-CODED, with a DERIVING drift guard rather than derived at import. This
# script runs under bare `python3` from the Makefile, with no venv and no `alfred`
# importable, so it cannot ask the module. `test_private_surface_constant_matches_
# the_real_tiers_module` parses `tiers.py` and asserts equality, so a new private
# name reds on the day it lands (#518: calibrate the list from reality).
#
# KNOWN LIMITATION, stated rather than left implicit: the rule is name-keyed, so an
# unrelated module defining its OWN `_log_t3` or `_bounded_repr` reds for a benign
# reason. Measured today: ZERO such collisions across both scan roots. The remedy
# when one appears is to RENAME the local symbol, or — if the collision is genuinely
# unavoidable — to narrow this tuple with the reason recorded here. Not to loosen
# the rule to a call shape, which is what A16/A17 already defeated.
_TIERS_PRIVATE_SURFACE: frozenset[str] = frozenset(
    {
        "_APPROVED_TIERS", "_AUTHORIZED_T3_NONCE", "_FORENSICALLY_OPAQUE_PACKAGES",
        "_FORENSIC_FRAME_LIMIT", "_MAX_FORENSIC_REPR", "_PARAMETRISATION_ATTRS",
        "_T3_CONSTRUCTION_AUTHORIZED", "_TIER_GUARD_NAMES", "_bounded_repr",
        "_coerce_and_guard_update", "_enforce_tier_admissible", "_guard_tier_value",
        "_is_forensically_opaque", "_is_unauthorized_t3", "_log_t3",
        "_nearest_foreign_module", "_record_unauthorized_t3_attempt",
        "_refuse_if_tier_is_narrowed_away", "_refuse_unauthorized_t3",
        "_set_authorized_t3_nonce", "_tier_by_name",
    }
)
_PRIVATE_SURFACE_MESSAGE: str = (
    "reaches into alfred.security.tiers' private surface — that surface IS the T3 "
    "authorisation mechanism, so no runtime guard can refuse this. Use the public "
    "tag_t3_with_nonce() front door."
)

# (path, enclosing-function) exemptions. NEVER path-only: `_set_authorized_t3_nonce`
# (`tiers.py:286`) is a bare `global` write with NO guard of its own — the
# idempotency guard (`T3NonceAlreadyRegisteredError`) lives in this caller. A
# path-only exemption would leave the bypass open inside the exempt file, which is
# precisely what narrowing it is for.
_FUNCTION_SCOPED_EXEMPTIONS: frozenset[tuple[Path, str]] = frozenset(
    {(_REPO_ROOT / "src" / "alfred" / "bootstrap" / "nonce_factory.py",
      "create_and_register_t3_nonce")}
)

# Paths whose MODULE-LEVEL `import` may bind a private name — and nothing else.
# `nonce_factory.py:40` is a module-level `from … import _set_authorized_t3_nonce`,
# OUTSIDE the exempt function, so the (path, function) rule alone reds the real
# file. Scoped to `ast.alias` nodes ONLY: a module-level CALL in the same file
# still reds, so this cannot widen into a whole-module exemption.
_IMPORT_ONLY_EXEMPT_PATHS: frozenset[Path] = frozenset(
    {_REPO_ROOT / "src" / "alfred" / "bootstrap" / "nonce_factory.py"}
)


def _private_surface_hit(node: ast.AST, prose: frozenset[int]) -> str | None:
    """The private name this node reaches, or ``None``.

    Four carriers, because round-2 proved a rule keyed on any one of them is
    bypassable by the other three:

    * ``ast.Name``      — the plain reference;
    * ``ast.Attribute`` — ``_t._AUTHORIZED_T3_NONCE``;
    * ``ast.alias``     — ``import … as _reg`` (A16), where no later node carries
      the real name at all;
    * ``ast.Constant``  — ``getattr(_t, "_set_authorized_t3_nonce")`` (A17), in CODE
      position only. Prose is excluded by position, not by type: excluding every
      string would readmit A17.

    The string arm uses CONTAINMENT rather than equality so a dotted spelling
    (``"alfred.security.tiers._set_authorized_t3_nonce"``) is caught too.
    """
    if isinstance(node, ast.Name) and node.id in _TIERS_PRIVATE_SURFACE:
        return node.id
    if isinstance(node, ast.Attribute) and node.attr in _TIERS_PRIVATE_SURFACE:
        return node.attr
    if isinstance(node, ast.alias):
        if node.name in _TIERS_PRIVATE_SURFACE:
            return node.name
        if node.asname in _TIERS_PRIVATE_SURFACE:
            return node.asname
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in prose:
        for name in sorted(_TIERS_PRIVATE_SURFACE):
            if name in node.value:
                return name
    return None
```

Inside `_scan_text`, alongside the other per-file maps:

```python
        enclosing = _enclosing_functions(tree)
```

and inside the walk loop:

```python
            private_name = _private_surface_hit(node, prose)
            if private_name is not None and not _private_surface_is_exempt(node, path, enclosing):
                _record(violations, lines, path, node.lineno, _PRIVATE_SURFACE_MESSAGE)
```

with:

```python
def _private_surface_is_exempt(node: ast.AST, path: Path, enclosing: dict[int, str]) -> bool:
    """Whether this private-surface reference sits in an authorised position.

    TWO exemption kinds, deliberately different shapes:

    * ``(path, function)`` — the reference is inside the named function body;
    * ``(path,)`` for ``ast.alias`` ONLY — the module-level import that binds the
      name. Scoped to the alias node so a module-level CALL in the same file still
      reds.

    ``path`` is compared RESOLVED, matching `_is_exempt`'s discipline: an unresolved
    comparison lets `src/alfred/bootstrap/../bootstrap/nonce_factory.py` present one
    identity to the matcher and another to the reader (#428, CR-138 finding #11).
    """
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        # A path we cannot resolve is not one of the known-good homes.
        return False
    if isinstance(node, ast.alias) and resolved in _IMPORT_ONLY_EXEMPT_PATHS:
        return True
    function = enclosing.get(getattr(node, "lineno", 0))
    return function is not None and (resolved, function) in _FUNCTION_SCOPED_EXEMPTIONS
```

> **`ast.alias` and `lineno`:** on Python 3.10+ `ast.alias` carries `lineno`, so the
> `getattr(node, "lineno", 0)` fallback is for node types that do not (e.g. some
> expression contexts reached by `ast.walk`). Verify with a quick
> `python3 -c "import ast; print(ast.parse('import os as o').body[0].names[0].lineno)"`
> before relying on it.

- [ ] **Step 4: Register the message in the drift guard**

Add `check_tag_t3._PRIVATE_SURFACE_MESSAGE` to the `findings` set.

- [ ] **Step 5: Run the tests**

```bash
uv run pytest tests/unit/security/ -q
python3 scripts/check_tag_t3.py; echo "rc=$? (MUST be 0 — zero new exemptions)"
```

- [ ] **Step 6: Mutation-test**

| Mutation | Must red |
| --- | --- |
| `_FUNCTION_SCOPED_EXEMPTIONS` → path-only match | `test_nonce_factory_is_exempt_inside_its_registration_function_only` |
| drop the `ast.alias` arm from `_private_surface_hit` | `test_import_aliased_nonce_setter_is_refused` |
| drop the `ast.Constant` arm | `test_getattr_string_nonce_setter_is_refused` |
| drop `id(node) not in prose` (WIDENING) | `test_private_surface_named_only_in_prose_stays_clean` |
| `_IMPORT_ONLY_EXEMPT_PATHS` check drops `isinstance(node, ast.alias)` (WIDENING) | `test_nonce_factory_module_level_import_is_exempt_but_module_level_calls_are_not` |
| remove one name from `_TIERS_PRIVATE_SURFACE` | `test_private_surface_constant_matches_the_real_tiers_module` |
| `_prose_string_ids` → `ast.get_docstring`-equivalent (first-statement only) | `test_private_surface_named_only_in_prose_stays_clean` (attribute-docstring half) |

- [ ] **Step 7: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/
git commit -m "test: #538 default-deny the tiers private surface, the bypass nothing else catches

Refs #538"
```

---

### Task 5: Delete the dead `quarantine.py` exemption and pin it

**Files:**
- Modify: `scripts/check_tag_t3.py` (`_APPROVED_PATHS` ~line 219, module docstring ~line 36)
- Test: `tests/unit/security/test_check_tag_t3_sole_layer_rules.py` (append)

**Interfaces:** consumes everything above; produces nothing new.

Re-measured on `main` @ `78ab6573` against the **full** rule set from Tasks 2–4 (not just
today's three rules): **0 violations across 1634 lines, 0 `tag(` calls, 0 `TaggedContent[`
constructions.** The exemption is dead and its docstring justification is already false.

- [ ] **Step 1: Write the failing test**

```python
_QUARANTINE = _REPO_ROOT / "src" / "alfred" / "security" / "quarantine.py"


def test_quarantine_is_no_longer_an_approved_path() -> None:
    """The exemption is deleted, not narrowed.

    Narrowing keeps a live soft-landing zone in a function that provably does not
    need one. Deletion means the day a line there DOES need it, the build fails
    loudly naming the decision — instead of a standing exemption silently absorbing
    it.
    """
    assert _QUARANTINE not in check_tag_t3._APPROVED_PATHS
    assert not check_tag_t3._is_exempt(_QUARANTINE)


def test_quarantine_scans_clean_without_its_exemption() -> None:
    """THE PIN. Scans the REAL file through the REAL path under the FULL rule set.

    Not a fixture and not a copy: a ``tmp_path`` copy recomputes ``_REPO_ROOT`` from
    ``__file__`` and inverts every exemption, so it would measure the wrong tree
    while still passing.

    This is the regression test the deletion buys. If a future line in
    ``quarantine.py`` needs the exemption back, THIS fails and names the decision.
    """
    assert check_tag_t3._scan_file(_QUARANTINE) == []


def test_tiers_still_needs_its_whole_file_exemption() -> None:
    """ANTI-VACUITY TWIN. Proves the pin above is not green because the detector
    stopped detecting: ``tiers.py`` IS the factory's home, and a non-exempt scan of
    it yields real violations.
    """
    assert _REPO_ROOT / "src" / "alfred" / "security" / "tiers.py" in check_tag_t3._APPROVED_PATHS
    non_exempt = _REPO_ROOT / "src" / "alfred" / "security" / "TIERS_NOT_EXEMPT.py"
    violations = check_tag_t3._scan_text(
        (_REPO_ROOT / "src" / "alfred" / "security" / "tiers.py").read_text(), non_exempt
    )
    assert violations, "tiers.py scanned clean without its exemption — the detector is inert"
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -k quarantine -v`
Expected: FAIL — `assert _QUARANTINE not in _APPROVED_PATHS`

- [ ] **Step 3: Delete the exemption**

In `scripts/check_tag_t3.py`, `_APPROVED_PATHS` becomes:

```python
_APPROVED_PATHS: frozenset[Path] = frozenset(
    {
        _REPO_ROOT / "src" / "alfred" / "security" / "tiers.py",
    }
)
```

Replace the `quarantine.py` bullet in the module docstring's "Authorised callers" list:

```
- ``src/alfred/security/tiers.py``      — the ``tag`` overload bodies
                                          (the home of the factory itself).
- ``tests/unit/security/**``            — tests assert the gate's behaviour
                                          using the same patterns.

``security/quarantine.py`` was on this list until #538 and is NOT any more. Its
justification ("the ``downgrade_to_orchestrator`` boundary that bridges T3 ➜
T3DerivedData") was already false: re-measured against the FULL rule set, that
file has 0 violations across 1634 lines, 0 ``tag(`` calls and 0 ``TaggedContent``
constructions. A standing exemption that nothing uses is a soft-landing zone for
the line that WILL need it. ``test_quarantine_scans_clean_without_its_exemption``
pins the deletion, so the day a line there needs the exemption back, the build
fails loudly naming the decision.
```

- [ ] **Step 4: Run the tests**

```bash
uv run pytest tests/unit/security/ tests/adversarial/tier_laundering -q
python3 scripts/check_tag_t3.py; echo "rc=$? (MUST be 0)"
```

- [ ] **Step 5: Mutation-test the pin**

```bash
# Put a real violation into quarantine.py. The pin MUST red. Then revert.
python3 - <<'PY'
import pathlib
p = pathlib.Path("src/alfred/security/quarantine.py"); s = p.read_text()
new = s + '\n_LAUNDERED = TaggedContent[T3](content="x", source="s", tier=T3, metadata={})\n'
assert new != s, "MUTATION DID NOT APPLY"
p.write_text(new)
PY
uv run pytest tests/unit/security/test_check_tag_t3_sole_layer_rules.py -k quarantine -q; echo "rc=$? (MUST be non-zero)"
git checkout src/alfred/security/quarantine.py
```

- [ ] **Step 6: Commit**

```bash
git add scripts/check_tag_t3.py tests/unit/security/
git commit -m "refactor: #538 delete the dead quarantine.py exemption and pin it

Refs #538"
```

---

### Task 6: Coverage, type-checkers and the whole-tree gate

No new behaviour — this task proves the branch satisfies the standing gates before any
review effort is spent on it.

**Files:** none (verification only), unless a gap is found.

- [ ] **Step 1: Run the detector coverage gate in an ISOLATED CLONE**

Coverage runs are **not** concurrency-safe in a shared directory.

```bash
CLONE=$(mktemp -d)/alfredos
git clone --local /Users/iandominey/projects/AlfredOS "$CLONE"
cd "$CLONE" && git checkout 538-sole-layer-rules
uv sync --all-extras
uv run coverage run --branch --source=scripts -m pytest \
    tests/unit/security/test_check_tag_t3_sole_layer_rules.py \
    tests/unit/security/test_check_tag_t3_gate_integrity.py \
    tests/unit/security/test_check_tag_t3_subscript.py -q
uv run coverage report --include='scripts/check_tag_t3.py' --fail-under=100 -m
echo "coverage rc=$?  (MUST be 0)"
```
Expected: 100% line and branch. **Do not add `# pragma: no cover`; do not touch
`[tool.coverage.report] exclude_also`.** An uncovered branch means a missing test.

- [ ] **Step 2: Type-check**

```bash
cd /Users/iandominey/projects/AlfredOS
uv run mypy --strict src scripts/check_tag_t3.py
uv run pyright src scripts/check_tag_t3.py
```
Expected: clean on both. `frozenset[tuple[Path, str]]` and `dict[int, str]` are the
annotations most likely to need a nudge.

- [ ] **Step 3: Lint and format**

```bash
uv run ruff check . && uv run ruff format --check .
```
`noqa` must sit on the line ruff REPORTS, and ruff's reformat can move it off target —
re-run `ruff check` after any `ruff format`.

- [ ] **Step 4: Run the release-blocking suites**

```bash
uv run pytest tests/adversarial -q     # release-blocking: security/ is touched
uv run pytest tests/unit -q
```

- [ ] **Step 5: Full gate**

```bash
make check; echo "make check rc=$?"
```
Check `$?` on `make` itself — piping through `tail` MASKS the exit code, and a task
notification reports the tail's status rather than make's. The macOS integration lane is
flaky under load: verify any suspect in ISOLATION before treating it as a real failure.

- [ ] **Step 6: Commit any fixes**

```bash
git add -u && git commit -m "test: #538 close coverage and type gaps in the sole-layer rules

Refs #538"
```
(Skip if nothing changed. **Never `git add -A`** — untracked rulesync outputs get swept in.)

---

### Task 7: Documentation — the corpus entry, the matrix, and the stale path strings

The DoD requires the corpus rationale to state **which spellings the detector now models
and which it still cannot**, or it becomes the next false claim in this file's history.

**Files:**
- Modify: `tests/adversarial/tier_laundering/tl_base_dispatch_and_raw_state_write.yaml`
- Modify: `tests/adversarial/tier_laundering/README.md:56`
- Modify: `scripts/check_tag_t3.py` (module docstring — the limitations section)
- Modify: `src/alfred/security/tiers.py` (docstring path strings ONLY)
- Modify: `docs/superpowers/plans/2026-07-29-518-detector-review-constraints.md`

- [ ] **Step 1: Rewrite the corpus `payload` and `out_of_scope_rationale`**

Add the three spellings that appear in **no** prior artefact to `payload`:

```yaml
payload: |
  low = TaggedContent[T2](content='ok', source='test', tier=T2, metadata={})
  # None of these passes through any TaggedContent method:
  object.__setattr__(low, 'tier', T3)
  object.__setattr__(low, '__dict__', {**vars(low), 'tier': T3})
  low.__dict__.update({'tier': T3})
  vars(low)['tier'] = T3
  laundered = BaseModel.model_copy(low, update={'tier': T3})
```

Rewrite `out_of_scope_rationale` to say what is true after #538. It MUST keep the
`BaseModel.model_construct.__func__` runtime-closed record (do not undo it), and it must
name the residual honestly:

```yaml
out_of_scope_rationale: >-
  Still not defensible at RUNTIME for the spellings listed — that half is unchanged.
  BaseModel.copy / BaseModel.model_copy on an existing instance build the result
  through _copy_and_set_values / __dict__.update, reaching neither the overrides nor
  model_post_init (verified across all six dispatch shapes); object.__setattr__ and
  __setstate__ never traverse __setattr__, so ConfigDict(frozen=True) cannot observe
  them. The sibling spelling BaseModel.model_construct.__func__(cls, ...) WAS closable
  and remains refused — pydantic invokes cls.model_post_init from inside the base
  implementation — so "unbound dispatch" is not uniformly unclosable and each spelling
  was checked individually. AUTHORING LAYER, as of #538: scripts/check_tag_t3.py now
  MODELS this class. It default-denies the raw-state VEHICLES (object.__setattr__
  outside a literal-field-name call, .__dict__/__setstate__/__getstate__/__reduce__/
  __new__, vars(), and those dunders named as strings in code position) and unbound
  BaseModel seam dispatch through a fixed-point alias set. Verified by execution: all
  five spellings above are flagged, and the three live object.__setattr__ frozen-
  dataclass sites under the scan root stay clean. WHAT IT STILL CANNOT DO, stated so
  the next reader does not have to measure it: cross-module re-export aliasing of
  BaseModel (the alias set is per-file), a private name reached through a computed
  string the parser cannot fold, exec/eval, and any vehicle reached from a file the
  gate does not scan. Those are the spec §3.2 class of limit already acknowledged for
  arbitrary code execution inside the privileged orchestrator.
```

- [ ] **Step 2: Update the README matrix row**

Replace line 56's status (`**still admitted, undefended at both layers**`) with the
post-#538 fact — runtime unchanged, authoring layer now defends it — and point at the
rule names rather than at prose.

- [ ] **Step 3: Add the limitations section to the gate's module docstring**

State what the guard **cannot** do, with the named escape hatch:

```
WHAT THIS GATE CANNOT DO (#538). Named here so the next reader does not have to
measure it, and so no future claim outruns the code:

* cross-module re-export aliasing — the BaseModel alias set is per-file, so
  ``from a import BaseModel as Y`` in module A and ``from A import Y`` in module B
  is invisible;
* a private name assembled at runtime (``"".join(...)``, ``exec``/``eval``) —
  the string arm reads literals, not computed values;
* a name-keyed collision — an unrelated module defining its own ``_log_t3`` reds
  for a benign reason (measured: zero such collisions today);
* anything in a file the gate does not scan.

THE ESCAPE HATCH, so nobody invents one: a legitimate future need for one of these
vehicles belongs behind a NAMED helper inside the already-exempt
``security/tiers.py`` — not behind a loosened rule here. Every loosening this file
has ever taken was later found to be a bypass.
```

- [ ] **Step 4: Fix the stale src-relative path strings**

Now that the scan root includes top-level `plugins/` (which contains none of these), the
bare spellings are actively misleading. In `src/alfred/security/tiers.py` (docstring text
only — **no code change**), the yaml, and the constraints doc:

- `plugins/web_fetch/allowlist.py` → `src/alfred/plugins/web_fetch/allowlist.py`
- `plugins/web_fetch/fetch_dispatcher.py` → `src/alfred/plugins/web_fetch/fetch_dispatcher.py`
- `hooks/context.py` → `src/alfred/hooks/context.py`

```bash
grep -rn "plugins/web_fetch/allowlist.py\|plugins/web_fetch/fetch_dispatcher.py\|[^/]hooks/context.py" \
     src/alfred/security/tiers.py \
     tests/adversarial/tier_laundering/tl_base_dispatch_and_raw_state_write.yaml \
     docs/superpowers/plans/2026-07-29-518-detector-review-constraints.md
```
Fix each hit, then re-run the grep and confirm every remaining match is already
`src/alfred/`-prefixed.

- [ ] **Step 5: Verify the corpus schema and markdown lint**

```bash
uv run pytest tests/adversarial/tier_laundering -q
npx markdownlint-cli2@0.22.1 "docs/**/*.md"     # no `| tail` — it masks the exit code
```

- [ ] **Step 6: Commit**

```bash
git add tests/adversarial/tier_laundering/ scripts/check_tag_t3.py \
        src/alfred/security/tiers.py \
        docs/superpowers/plans/2026-07-29-518-detector-review-constraints.md
git commit -m "docs: #538 record what the detector now models and what it still cannot

Refs #538"
```

---

## Definition of done

- [ ] The tripwire asserts `== 1` and is renamed to state the new fact.
- [ ] `tl-2026-013`'s `payload` carries all five spellings; `out_of_scope_rationale`
      names what is modelled AND what is not; the `model_construct.__func__`
      runtime-closed record is intact.
- [ ] `tests/adversarial/tier_laundering/README.md` matrix row updated.
- [ ] `quarantine.py` is out of `_APPROVED_PATHS`, pinned by a real-file regression test
      with an anti-vacuity twin on `tiers.py`.
- [ ] Seven new per-rule messages, all distinct, none a substring of another, all in the
      `findings` set.
- [ ] `python3 scripts/check_tag_t3.py` exits 0 on the real tree — **zero new exemptions**.
- [ ] 100% line + branch coverage on `scripts/check_tag_t3.py`, no new pragmas.
- [ ] `mypy --strict` + `pyright` clean; `ruff check` + `ruff format --check` clean.
- [ ] `uv run pytest tests/adversarial` green (release-blocking — `security/` touched).
- [ ] `make check` exits 0 (check `$?` on make itself).
- [ ] Exactly one commit subject contains `fix: #538`; **no** subject contains `#536`,
      `#539` or `#518`. Verify issue state AFTER the merge, do not assume.
- [ ] No `src/alfred/**` behaviour change — `git diff main -- src/` shows docstring text only.

## Out of scope (deliberately)

- **#539** — the seven T3-construction shapes, the five-set alias environment,
  `_slice_verdict` as a total function, annotation immunity, `tokenize`-based suppression
  widening. Sequenced last because all seven of its titular shapes are already refused at
  runtime; it is defence-in-depth.
- **#547** — the census counts COLLECTED files, not successfully SCANNED ones. Its body
  claims the failure condition is unreachable because both `_APPROVED_PATHS` files return
  `[]`. That premise predates PR #549's `S_ISREG` change AND this plan's deletion of
  `quarantine.py` from `_APPROVED_PATHS`. **RE-MEASURE before designing to it.**
