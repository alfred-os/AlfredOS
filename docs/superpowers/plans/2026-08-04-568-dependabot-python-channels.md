# #568 — Restore Dependabot's Python channels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the three Dependabot Python channels that have been dead for 44 days, replacing the lost install-time version refusal with an import-time floor guard, a liveness-first freshness monitor, and the detectors that stop each failure recurring.

**Architecture:** `requires-python` is relaxed to a series-level `>=3.14` in **both** `pyproject.toml` and `uv.lock` so Dependabot can resolve it; the real 3.14.6 floor moves to an import-time guard in `src/alfred/_python_floor.py`. Three detectors are added: a static test that both files stay series-level, a `uv lock --check` gate, and a scheduled monitor whose **primary** signal is per-channel liveness (content comparison is secondary and demonstrably lagging). Two pre-existing defects that this change activates are fixed alongside: the ADR-0030 closure gate's blindness to `src/alfred/__init__.py`, and the launcher's habit of guessing an audit-row reason.

**Tech Stack:** Python 3.14.6, `uv`, `tomllib` (stdlib), pytest, GitHub Actions, `gh` CLI, bash.

## Global Constraints

- Python floor `>=3.14` **declared**, `(3, 14, 6)` **enforced**. `.python-version` stays `3.14.6`.
- `ruff` line-length **100**. Rule set: `E,F,I,B,UP,N,S,ARG,RET,SIM,PTH,DTZ,FBT,PIE,RUF`.
- `mypy --strict` + `pyright` on `src/`. No `Any` without justification. PEP 604/585 idioms; never `Optional[X]` / `typing.List`.
- Commit subjects must match `^[a-z]+(\([^)]+\))?(!)?: .*#[0-9]+.*$`.
- **Only the FINAL commit may use `fix:`.** `fix: #568` auto-closes the issue on merge, and #568 must stay open until post-merge verification completes. All earlier commits use `build:` / `test:` / `ci:` / `chore:` / `docs:` / `feat:`.
- Never `git add -A` — add named paths only.
- Never `--no-verify`. Never `--admin` merge.
- Root `CLAUDE.md` is a **gitignored rulesync output** (`.gitignore:85`). Edit `.rulesync/rules/CLAUDE.md`, then run `rulesync generate -t '*' -f '*'` (CONTRIBUTING.md:35).
- `PRD.md` edits are **human-gated** — prepare a diff, never commit it.
- `src/alfred/security/` is touched, so the adversarial suite is release-blocking: `uv run pytest tests/adversarial`.
- Verify with `make check`; read `$?` directly. **Never** `make ... | tail` — the pipe masks the exit code.

---

### Task 1: Relax the specifier in both files, and gate it

`uv.lock:3` carries the same `requires-python` as `pyproject.toml` and is parsed by the same failing `uv` updater. Changing only `pyproject.toml` risks a green no-op: `uv sync --frozen` returns 0 on a pyproject/lock mismatch, all 11 `ci.yml` sync sites use `--frozen`, and nothing anywhere runs `uv lock --check`.

**Files:**

- Modify: `pyproject.toml:6-12`
- Modify: `uv.lock:3` (via `uv lock`, never by hand)
- Create: `tests/unit/meta/test_requires_python_is_dependabot_resolvable.py`
- Modify: `Makefile` (add `lockcheck` target, wire into `check`)

**Interfaces:**

- Consumes: nothing.
- Produces: `requires-python = ">=3.14"` in both files. Task 3's guard depends on this being series-level.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/meta/test_requires_python_is_dependabot_resolvable.py`:

```python
"""Dependabot resolves Python at SERIES granularity (#568).

A patch-level `requires-python` makes Dependabot abort with
`tool_version_not_supported` during file fetching, which silently killed three
channels for 44 days: dependency-graph submission, Dependabot security updates,
and the weekly pip updater. BOTH files carry the specifier and BOTH are parsed
by the `uv` updater, so both are pinned here — a pyproject-only check would
report green on a repo where the fix does not work.

The two manifests hold it at DIFFERENT depths: PEP 621 puts pyproject's under
`[project]`, while uv.lock carries it at top level. The accessor path is part of
each manifest's entry rather than a shared assumption, because assuming one
shape for both makes the pyproject case permanently red.

The real floor is enforced at import by `alfred._python_floor` (ADR-0061).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]

#: Series-level only: an operator, a major, a minor, and NO patch component.
#: Written as a literal rather than derived, so the oracle cannot inherit a bug
#: from whatever produces the value.
_SERIES_LEVEL = re.compile(r"^>=\d+\.\d+$")

#: (manifest, key path to `requires-python`). The paths differ — see the docstring.
_MANIFESTS: tuple[tuple[Path, tuple[str, ...]], ...] = (
    (Path("pyproject.toml"), ("project", "requires-python")),
    (Path("uv.lock"), ("requires-python",)),
)

_MANIFEST_IDS = [manifest.as_posix() for manifest, _ in _MANIFESTS]


def _specifier(manifest: Path, key_path: tuple[str, ...]) -> str:
    """Read `requires-python` out of `manifest` by walking `key_path`."""
    node: Any = tomllib.loads((_REPO_ROOT / manifest).read_bytes().decode())
    for key in key_path:
        assert key in node, (
            f"{manifest.as_posix()} has no {'.'.join(key_path)} — the manifest layout "
            f"changed and this pin is reading the wrong place"
        )
        node = node[key]
    assert isinstance(node, str)
    return node


@pytest.mark.parametrize(("manifest", "key_path"), _MANIFESTS, ids=_MANIFEST_IDS)
def test_requires_python_is_series_level(manifest: Path, key_path: tuple[str, ...]) -> None:
    spec = _specifier(manifest, key_path)
    assert _SERIES_LEVEL.match(spec), (
        f"{manifest.as_posix()} declares requires-python = {spec!r}, which carries a patch "
        f"component. Dependabot cannot resolve it and will abort with "
        f"tool_version_not_supported, silently killing dependency-graph submission, "
        f"security updates and the weekly pip updater (#568). Keep this series-level and "
        f"raise the ENFORCED floor in src/alfred/_python_floor.py instead."
    )


def test_both_manifests_agree() -> None:
    """A lockfile that drifts from pyproject re-breaks Dependabot silently."""
    specs = {
        manifest.as_posix(): _specifier(manifest, key_path)
        for manifest, key_path in _MANIFESTS
    }
    assert len(set(specs.values())) == 1, (
        f"requires-python differs between manifests: {specs}. `uv sync --frozen` returns 0 "
        f"on this mismatch, so nothing else catches it — run `uv lock`."
    )
```

- [ ] **Step 2: Run it and verify it FAILS**

```bash
uv run pytest tests/unit/meta/test_requires_python_is_dependabot_resolvable.py -v
```

Expected: both parametrised cases FAIL with an **AssertionError reporting `'>=3.14.6'`** — not a
`KeyError`. A `KeyError` means the accessor is reading the wrong depth and the test could never
go green; stop and fix the accessor. If any case PASSES now, stop — the premise is wrong.

- [ ] **Step 3: Relax `pyproject.toml`**

Replace `pyproject.toml:6-12` (the comment block and the `requires-python` line) with:

```toml
# SERIES-LEVEL ON PURPOSE (#568, ADR-0061). Dependabot resolves Python at series
# granularity (3.10.* ... 3.14.*) and aborts with `tool_version_not_supported`
# on a patch-level specifier. A `>=3.14.6` floor here silently killed THREE
# channels for 44 days: dependency-graph submission, Dependabot security
# updates, and the weekly pip updater. The ENFORCED floor is 3.14.6 and lives in
# `alfred._python_floor`, checked at import.
#
# gh-105936: `@dataclass(frozen=True, slots=True)` generates `__setattr__` /
# `__delattr__` that close over the PRE-slots class, so an unknown-attribute
# assignment raises a spurious `TypeError: super(type, obj)` instead of
# FrozenInstanceError. NOT a 3.14 regression — it is long-standing, and the fix
# (CPython GH-144021) was backported to 3.13 as well (GH-148476). It reached the
# 3.14 series via GH-148469, released in 3.14.5; measured broken on 3.14.0 and
# 3.14.4, correct on 3.14.5 and 3.14.6, so within 3.14 the affected patches are
# 3.14.0-3.14.4. AlfredOS has 36+ frozen+slots dataclasses, incl. trust-boundary
# types.
#
# This repo cited gh-135228 from #303 until #568. That is a DIFFERENT issue —
# "slot dataclasses classes leak original class" — same area and same underlying
# closure-cell change, but not the `__setattr__` behaviour this floor exists for.
requires-python = ">=3.14"
```

- [ ] **Step 4: Regenerate the lockfile**

```bash
uv lock
git diff --stat uv.lock
```

Expected: a small diff touching `requires-python` and the resolution markers, with **no package version churn**. If any package version changes, stop and report it — that is out of scope for this task.

- [ ] **Step 5: Run the test to verify it PASSES**

```bash
uv run pytest tests/unit/meta/test_requires_python_is_dependabot_resolvable.py -v
```

Expected: 3 passed.

- [ ] **Step 6: Mutation-verify the detector**

```bash
sed -i.bak 's/^requires-python = ">=3.14"$/requires-python = ">=3.14.6"/' pyproject.toml
uv run --frozen pytest tests/unit/meta/test_requires_python_is_dependabot_resolvable.py -q
```

Expected: **FAIL** on the `pyproject.toml` case. Then restore and repeat for the lockfile:

```bash
mv pyproject.toml.bak pyproject.toml
sed -i.bak '3s/.*/requires-python = ">=3.14.6"/' uv.lock
uv run --frozen pytest tests/unit/meta/test_requires_python_is_dependabot_resolvable.py -q
```

Expected: **FAIL** on the `uv.lock` case *and* on `test_both_manifests_agree`. Restore:

```bash
mv uv.lock.bak uv.lock
uv run --frozen pytest tests/unit/meta/test_requires_python_is_dependabot_resolvable.py -q   # 3 passed
```

A detector that cannot be made to fail is not a detector. Do not skip this step.

**`--frozen` is load-bearing in every command above.** Plain `uv run` performs an implicit
non-frozen `uv sync`, which REPAIRS a drifted `uv.lock` before pytest starts — the mutation
silently self-heals and the step reports a false pass. Any future mutation-verification that
touches `uv.lock` or `pyproject.toml` must use `uv run --frozen`.

- [ ] **Step 7: Add the `uv lock --check` gate**

Add to `Makefile` immediately after the `coverage-unit` target:

```makefile
lockcheck: ## Fail if uv.lock has drifted from pyproject.toml (#568).
    uv lock --check
```

**The recipe line must begin with a literal TAB, not the four spaces shown above.**
Markdown lint (MD010) forbids hard tabs in this document, so the fence cannot carry a
real one; a space-indented recipe fails with `missing separator`.

Add `lockcheck` to the `check` target's prerequisite list.

- [ ] **Step 8: Prove the gate can fail**

```bash
make lockcheck; echo "clean repo exit=$?"          # expect 0
sed -i.bak '3s/.*/requires-python = ">=3.14.6"/' uv.lock
make lockcheck; echo "drifted exit=$?"             # expect NON-ZERO
mv uv.lock.bak uv.lock
make lockcheck; echo "restored exit=$?"            # expect 0
```

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml uv.lock Makefile tests/unit/meta/test_requires_python_is_dependabot_resolvable.py
git commit -m "build: #568 relax requires-python to series-level in both manifests"
```

---

### Task 2: Fix the ADR-0030 closure gate before it is relied on

`tests/unit/security/test_quarantine_child_import_closure.py` measures the quarantine child's reachable surface by clearing modules and diffing `sys.modules`. Its `to_clear` list never includes `alfred` itself, so `src/alfred/__init__.py` never re-runs and **whatever `__init__.py` imports is invisible to the gate**.

This is currently inert only because `__init__.py` is 0 bytes — and Task 3 is what populates it. Fix the gate first, so Task 3 is measured by a gate that can see it.

**Measured, with the faithful precondition** (`alfred` already resident, as it always is mid-suite):

| precondition | current gate | fixed gate |
| --- | --- | --- |
| `alfred` not resident (file run alone) | mutant killed | mutant killed |
| `alfred` already resident (real session) | **MUTANT SURVIVED** | mutant killed |

The blindness is conditional on test-execution order, which is why it went unnoticed: running that file alone gives the correct answer.

**Files:**

- Modify: `tests/unit/security/test_quarantine_child_import_closure.py:99-107`

**Interfaces:**

- Consumes: nothing.
- Produces: a closure gate that measures `src/alfred/__init__.py`'s imports. Task 3 depends on this.

- [ ] **Step 1: Reproduce the blindness**

Write the mutant, then run the real test the way CI runs it — inside the full unit session, not alone:

```bash
printf 'import alfred.audit  # MUTANT\n' > src/alfred/__init__.py
uv run pytest tests/unit/security/ -q -k "import_closure"
```

Expected: **PASSES** (blind). Now confirm it is order-dependent:

```bash
uv run pytest tests/unit/security/test_quarantine_child_import_closure.py -q
```

Expected: FAILS. Record both outcomes before changing anything.

- [ ] **Step 2: Fix `to_clear` via a shared production helper**

In `tests/unit/security/test_quarantine_child_import_closure.py`, add a module-level helper
(after `_is_forbidden`) so the gate and its regression tests call the SAME predicate — a
regression test that rebuilds the predicate inline would still pass with the rule reverted:

```python
def _alfred_modules_to_clear(module_names: Iterable[str]) -> list[str]:
    """Every ``alfred`` module to evict before measuring the child's import delta.

    The ENTIRE tree, including the BARE package. Leaving ``alfred`` resident means
    ``src/alfred/__init__.py`` never re-executes, so whatever it imports is absent
    from the delta and the ADR-0030 reachable-surface bound cannot see it (#568).
    """
    return [name for name in module_names if name == "alfred" or name.startswith("alfred.")]
```

This needs `from collections.abc import Iterable` alongside the existing `importlib`/`sys`
imports. Then, inside `test_quarantine_child_import_closure_touches_no_privileged_module`,
replace the `to_clear` comprehension (currently lines 99-105) with a call to the helper:

```python
        # Drop the ENTIRE `alfred` tree, not just the child + forbidden roots.
        # #568: clearing only those leaves `alfred` itself resident, so
        # `src/alfred/__init__.py` never re-executes and anything IT imports is
        # absent from the delta — the gate was structurally blind to the package
        # __init__. Inert while that file was empty; `alfred._python_floor` now
        # populates it.
        #
        # The blindness was UNCONDITIONAL under pytest, not order-dependent:
        # `tests/unit/conftest.py` imports `alfred.audit.log` at module scope
        # (since 2026-05-27, #95), so `alfred` is already resident during
        # collection even when this file is run alone. There was no way to run
        # the pre-fix gate that would have caught it.
        to_clear = _alfred_modules_to_clear(sys.modules)
```

- [ ] **Step 3: Verify the mutant is now killed in the full session**

```bash
uv run pytest tests/unit/security/ -q -k "import_closure"
```

Expected: **FAILS**, naming `alfred.audit` in the forbidden list.

- [ ] **Step 4: Restore and confirm green**

```bash
git restore --source=HEAD --worktree src/alfred/__init__.py
wc -c src/alfred/__init__.py                      # expect 0
uv run pytest tests/unit/security/ -q -k "import_closure"
```

Expected: PASSES. Use `git restore --source=HEAD --worktree` — `git checkout --` restores the index, which would leave a staged mutant in place.

- [ ] **Step 5: Pin the fix with regression tests that call the production helper**

Append to `tests/unit/security/test_quarantine_child_import_closure.py`. Both tests call
`_alfred_modules_to_clear` from Step 2 rather than re-deriving the predicate — a test that
rebuilds it inline against a literal set passes even with the real rule reverted (verified
by mutation):

```python
def test_the_clearing_rule_evicts_the_bare_alfred_package() -> None:
    """#568: omitting the bare package is what made the gate blind.

    Calls the PRODUCTION helper. The previous version of this test rebuilt the
    predicate inline and so passed even with the rule reverted — verified by
    mutation.
    """
    cleared = _alfred_modules_to_clear(
        ["alfred", "alfred.security", "alfred.security.quarantine_child", "os"]
    )
    assert "alfred" in cleared, (
        "the closure gate must evict the bare `alfred` package so its __init__ re-runs; "
        "otherwise the dual-LLM reachable-surface bound cannot see what __init__ imports"
    )


def test_the_clearing_rule_leaves_unrelated_modules_resident() -> None:
    """`alfredo` must not match: the rule is `alfred.`-prefixed, not `alfred`-prefixed."""
    assert _alfred_modules_to_clear(["os", "sys", "alfredo"]) == []
```

- [ ] **Step 6: Run the security suite and the adversarial suite**

```bash
uv run pytest tests/unit/security/ -q
uv run pytest tests/adversarial -q
```

Expected: both pass. `src/alfred/security/` test surface changed, so the adversarial suite is release-blocking.

- [ ] **Step 7: Commit**

```bash
git add tests/unit/security/test_quarantine_child_import_closure.py
git commit -m "test: #568 close the ADR-0030 closure gate's blindness to alfred/__init__.py"
```

---

### Task 3: The import-time floor guard

**Files:**

- Create: `src/alfred/_python_floor.py`
- Modify: `src/alfred/__init__.py` (currently empty)
- Create: `tests/unit/test_python_floor.py`

**Interfaces:**

- Consumes: `alfred.errors.AlfredError` (13 lines; its only import is `from __future__ import annotations`; measured `sys.modules` delta for `import alfred.errors` is exactly `['alfred', 'alfred.errors']`, and it is **not** in `_FORBIDDEN_ROOTS`).
- Produces: `alfred._python_floor.FLOOR: Final[tuple[int, int, int]]`, `alfred._python_floor.REFUSAL_KEY: Final[str]`, `alfred._python_floor.UnsupportedPythonError`, `alfred._python_floor.enforce(version: tuple[int, int, int]) -> None`. Task 4 matches `REFUSAL_KEY`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_python_floor.py`:

```python
"""The enforced CPython floor, and — critically — that it is actually WIRED.

A pure `enforce()` nobody calls is not a guard. The wiring test is the one that
matters: without it, deleting the call from `alfred/__init__.py` leaves the
whole suite green.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from alfred._python_floor import FLOOR, REFUSAL_KEY, UnsupportedPythonError, enforce


class TestEnforce:
    @pytest.mark.parametrize("version", [(3, 14, 5), (3, 14, 0), (3, 13, 99), (2, 7, 18)])
    def test_below_floor_refuses(self, version: tuple[int, int, int]) -> None:
        with pytest.raises(UnsupportedPythonError) as exc_info:
            enforce(version)
        message = str(exc_info.value)
        assert ".".join(str(part) for part in FLOOR) in message, "must name the REQUIRED version"
        assert ".".join(str(part) for part in version) in message, "must name the FOUND version"

    @pytest.mark.parametrize("version", [(3, 14, 6), (3, 14, 7), (3, 15, 0), (4, 0, 0)])
    def test_at_or_above_floor_returns(self, version: tuple[int, int, int]) -> None:
        assert enforce(version) is None

    def test_refusal_is_an_alfred_error(self) -> None:
        """CLAUDE.md mandates a hierarchy rooted at AlfredError."""
        from alfred.errors import AlfredError

        assert issubclass(UnsupportedPythonError, AlfredError)

    def test_the_last_line_is_the_bare_launcher_key(self) -> None:
        """`alfred-plugin-launcher.sh` captures only the LAST stderr line.

        Prose on that line is recorded as `reason_unclassified` in the signed
        sandbox_refused audit row, so the key must be the final line exactly.
        """
        with pytest.raises(UnsupportedPythonError) as exc_info:
            enforce((3, 14, 4))
        assert str(exc_info.value).splitlines()[-1] == REFUSAL_KEY


class TestGuardIsWired:
    def test_importing_alfred_on_a_sub_floor_interpreter_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Kills the mutant that DELETES the enforce() call from __init__.py.

        A 5-tuple because production slices `sys.version_info[:3]`; a 3-tuple
        double would not model the real object.
        """
        monkeypatch.setattr(sys, "version_info", (3, 14, 4, "final", 0))
        with pytest.raises(UnsupportedPythonError):
            importlib.reload(importlib.import_module("alfred"))

    def test_importing_alfred_on_this_interpreter_succeeds(self) -> None:
        assert importlib.reload(importlib.import_module("alfred")) is not None
```

- [ ] **Step 2: Run to verify it fails**

```bash
uv run pytest tests/unit/test_python_floor.py -v
```

Expected: collection error — `No module named 'alfred._python_floor'`.

- [ ] **Step 3: Create the guard module**

Create `src/alfred/_python_floor.py`:

```python
"""Import-time CPython floor guard (#568, ADR-0061).

`pyproject.toml` declares a SERIES-level `requires-python = ">=3.14"` because
Dependabot cannot resolve a patch-level specifier — a `>=3.14.6` floor there
silently killed dependency-graph submission, Dependabot security updates and the
weekly pip updater for 44 days. The declared floor and the enforced floor
therefore diverge on purpose, and this module is where the real one lives.

i18n EXEMPTION (CLAUDE.md i18n rule #1). This message is deliberately NOT routed
through `t()`. The commonly-cited justification — that calling `t()` here would
be circular — is FALSE and was refuted by execution: `alfred.i18n` is
stdlib-only and imports no `alfred` module. The real reasons:

  * `t()` silently DROPS kwargs when the msgid is missing, so an absent or
    uncompiled catalog renders a bare key with NO version numbers — and for a
    floor guard the versions are the entire payload.
  * `import alfred.i18n` costs a measured 29.7 ms on EVERY `import alfred.*`
    and lands inside the ADR-0030-bounded quarantine-child import closure.

The LAST line of the message is a bare closed-vocabulary key rather than prose:
`bin/alfred-plugin-launcher.sh` captures only the final stderr line and writes
its classification into the signed `supervisor.plugin.sandbox_refused` audit
row. Prose there is recorded as `reason_unclassified`.
"""

from __future__ import annotations

import sys
from typing import Final

from alfred.errors import AlfredError

#: The ENFORCED floor. gh-105936 breaks `@dataclass(frozen=True, slots=True)`
#: `__setattr__` on 3.14.0-3.14.4 (measured on 3.14.0 and 3.14.4; fixed in 3.14.5
#: by CPython GH-144021 via GH-148469 — `_frozen_get_del_attr` ->
#: `_frozen_set_del_attr`, `cls` -> `__class__`). Long-standing, NOT a 3.14
#: regression. Held
#: at 3.14.6 rather than the true 3.14.5 boundary because 3.14.6 is
#: `.python-version` and the only patch any CI lane exercises — supported ==
#: tested, with no untested band.
FLOOR: Final[tuple[int, int, int]] = (3, 14, 6)

#: Closed-vocabulary key; twin of the `interpreter_below_floor` member of
#: `SANDBOX_REFUSED_REASONS` in `alfred.audit.audit_row_schemas`.
REFUSAL_KEY: Final[str] = "daemon.boot.interpreter_below_floor"

_DECLARED_SPECIFIER: Final[str] = ">=3.14"


class UnsupportedPythonError(AlfredError, RuntimeError):
    """The running interpreter is below the enforced AlfredOS floor."""


def enforce(version: tuple[int, int, int]) -> None:
    """Refuse ``version`` when it is below :data:`FLOOR`.

    Pure by design: takes the version rather than reading ``sys.version_info``,
    so the refusal path is executable in a test. The call site is covered
    separately — a pure function nothing calls is not a guard.
    """
    if version >= FLOOR:
        return
    required = ".".join(str(part) for part in FLOOR)
    found = ".".join(str(part) for part in version)
    raise UnsupportedPythonError(
        f"AlfredOS requires CPython >= {required} — this interpreter is {found} "
        f"({sys.executable}).\n"
        f"\n"
        f"Why: CPython 3.14.0-3.14.4 generate a broken __setattr__ for\n"
        f"@dataclass(frozen=True, slots=True) (gh-105936) — an unknown-attribute\n"
        f"assignment raises TypeError instead of FrozenInstanceError. AlfredOS has\n"
        f"36+ such frozen types, including trust-boundary types, so the failure is\n"
        f"silent rather than loud. Fixed upstream in 3.14.5; the floor is held at\n"
        f"{required} because that is the only patch CI exercises.\n"
        f"\n"
        f"Not caught at install time on purpose: pyproject.toml declares\n"
        f'"{_DECLARED_SPECIFIER}" (series-level) because Dependabot cannot parse a\n'
        f"patch-level requires-python and silently stops submitting the dependency\n"
        f"graph and opening security PRs (#568).\n"
        f"\n"
        f"Fix: uv python install && uv sync\n"
        f"{REFUSAL_KEY}"
    )
```

- [ ] **Step 4: Wire it**

Replace the (empty) `src/alfred/__init__.py` with:

```python
"""AlfredOS.

The CPython floor is enforced HERE, at package import, because `pyproject.toml`
declares a series-level `requires-python` so Dependabot can resolve it (#568,
ADR-0061). Keep this module's import closure minimal: it is inside the
ADR-0030-bounded quarantine-child reachable surface, and
`tests/unit/security/test_quarantine_child_import_closure.py` measures it.
"""

from __future__ import annotations

import sys

from alfred._python_floor import enforce

enforce(sys.version_info[:3])
```

- [ ] **Step 5: Run to verify it passes**

```bash
uv run pytest tests/unit/test_python_floor.py -v
```

Expected: all pass.

- [ ] **Step 6: Mutation-verify the WIRING (the step draft 1 lacked)**

```bash
cp src/alfred/__init__.py /tmp/init.bak
printf '"""AlfredOS."""\n' > src/alfred/__init__.py     # mutant: guard deleted
uv run pytest tests/unit/test_python_floor.py -q
```

Expected: `TestGuardIsWired::test_importing_alfred_on_a_sub_floor_interpreter_refuses` **FAILS**. If it passes, the wiring is untested and the whole guard is decorative — stop and fix.

```bash
cp /tmp/init.bak src/alfred/__init__.py
uv run pytest tests/unit/test_python_floor.py -q      # green again
```

- [ ] **Step 7: Verify the closure bound still holds**

```bash
uv run pytest tests/unit/security/ -q -k "import_closure"
uv run pytest tests/adversarial -q
```

Expected: pass. `alfred.errors` is not in `_FORBIDDEN_ROOTS`, so the new import is within bound — but Task 2's fixed gate is now actually watching, so confirm rather than assume.

- [ ] **Step 8: Type-check and lint**

```bash
uv run mypy src/ && uv run pyright src/
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/
```

`sys.version_info[:3]` reveals as `tuple[int, int, int]` under both checkers — no cast or ignore is needed.

- [ ] **Step 9: Commit**

```bash
git add src/alfred/_python_floor.py src/alfred/__init__.py tests/unit/test_python_floor.py
git commit -m "feat: #568 enforce the CPython floor at import instead of at install"
```

---

### Task 4: Stop the launcher guessing an audit-row reason

`bin/alfred-plugin-launcher.sh:241` runs `python3 -m alfred.plugins.manifest_reader --read-environment`, which imports `alfred` and therefore fires the new guard pre-exec. Its `*)` arm rewrites any unrecognised capture to `daemon.boot.environment_not_set`, and that reason is written into the signed, append-only `supervisor.plugin.sandbox_refused` row. A confidently wrong reason there violates CLAUDE.md hard rule 7.

The exemplar already exists at `bin/alfred-plugin-launcher.sh:440-444`, whose `*)` arm treats an unrecognised capture as `reason_unclassified` — "a drift/crash ALARM, not a routine refusal — say so rather than guessing".

**Files:**

- Modify: `src/alfred/audit/audit_row_schemas.py` (`SANDBOX_REFUSED_REASONS`, ~line 1225)
- Modify: `bin/alfred-plugin-launcher.sh:248-252`
- Create: `tests/unit/security/test_launcher_interpreter_floor_reason.py`

**Interfaces:**

- Consumes: `alfred._python_floor.REFUSAL_KEY` == `"daemon.boot.interpreter_below_floor"`.
- Produces: `interpreter_below_floor` in `SANDBOX_REFUSED_REASONS`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/security/test_launcher_interpreter_floor_reason.py`:

```python
"""The launcher must NAME a sub-floor interpreter, never guess (#568).

`:241` imports `alfred`, so the #568 floor guard fires there pre-exec. The old
`*)` arm rewrote any unrecognised capture to `environment_not_set` — wrong
subsystem, wrong remedy, and persisted to the SIGNED sandbox_refused row
(CLAUDE.md hard rule 7). Mirrors the `reason_unclassified` exemplar at `:440`.
"""

from __future__ import annotations

import re
from pathlib import Path

from alfred._python_floor import REFUSAL_KEY
from alfred.audit.audit_row_schemas import SANDBOX_REFUSED_REASONS

_LAUNCHER = Path(__file__).resolve().parents[3] / "bin" / "alfred-plugin-launcher.sh"


def test_the_floor_reason_is_in_the_closed_vocabulary() -> None:
    assert "interpreter_below_floor" in SANDBOX_REFUSED_REASONS


def test_the_refusal_key_maps_onto_the_vocabulary() -> None:
    """The guard's bare key and the audit reason must not drift apart."""
    assert REFUSAL_KEY.removeprefix("daemon.boot.") in SANDBOX_REFUSED_REASONS


def test_the_environment_arm_recognises_the_floor_key() -> None:
    source = _LAUNCHER.read_text()
    assert REFUSAL_KEY in source, (
        f"{REFUSAL_KEY} is not matched in the launcher, so a sub-floor interpreter "
        f"is classified by the fallback arm instead of being named"
    )


def test_the_environment_arm_does_not_guess() -> None:
    """The `*)` fallback must alarm, not invent `environment_not_set`."""
    source = _LAUNCHER.read_text()
    arm = re.search(
        r"daemon\.boot\.environment_unrecognised \| daemon\.boot\.environment_not_set.*?esac",
        source,
        re.DOTALL,
    )
    assert arm is not None, "the environment-capture case statement moved; re-anchor this test"
    assert "reason_unclassified" in arm.group(0), (
        "the environment-capture `*)` arm still guesses a specific reason. An "
        "unclassifiable capture is a drift/crash alarm — mirror the `:440` exemplar."
    )
```

- [ ] **Step 2: Run to verify it fails**

```bash
uv run pytest tests/unit/security/test_launcher_interpreter_floor_reason.py -v
```

Expected: all four FAIL.

- [ ] **Step 3: Extend the closed vocabulary**

In `src/alfred/audit/audit_row_schemas.py`, inside `SANDBOX_REFUSED_REASONS`, immediately after the `"environment_untrusted_source",` entry:

```python
        # #568: the interpreter running `manifest_reader` is below the ENFORCED
        # CPython floor. `pyproject.toml` is series-level so Dependabot can resolve
        # it, so this is the first check that refuses a sub-floor interpreter — and
        # `:241` imports `alfred`, so it fires there, pre-exec. Without this token
        # the `*)` arm recorded it as `environment_not_set`: wrong subsystem, wrong
        # remedy, in a signed append-only row.
        "interpreter_below_floor",
```

- [ ] **Step 4: Fix the launcher arm**

Replace `bin/alfred-plugin-launcher.sh:248-252` (the `case`/`esac` block on `_env_err_key`) with:

```sh
    _env_err_key="${_CAPTURE_ERR_LAST_LINE}"
    case "${_env_err_key}" in
        daemon.boot.environment_unrecognised | daemon.boot.environment_not_set | daemon.boot.environment_untrusted_source) : ;;
        # #568: the floor guard in `alfred/__init__.py` fires on ANY `alfred`
        # import, and this line imports it. Its message ends with this bare key
        # precisely so the capture below names the real cause.
        daemon.boot.interpreter_below_floor) : ;;
        # An empty or unrecognised capture is a drift/crash ALARM, not a routine
        # refusal — mirror the `:440` exemplar and say so rather than guessing
        # `environment_not_set` into a signed audit row (#434B, #568).
        *) _env_err_key="daemon.boot.reason_unclassified" ;;
    esac
```

- [ ] **Step 5: Run to verify it passes**

```bash
uv run pytest tests/unit/security/test_launcher_interpreter_floor_reason.py -v
```

Expected: 4 passed.

- [ ] **Step 6: Mutation-verify**

```bash
sed -i.bak 's/\*) _env_err_key="daemon.boot.reason_unclassified" ;;/*) _env_err_key="daemon.boot.environment_not_set" ;;/' bin/alfred-plugin-launcher.sh
uv run pytest tests/unit/security/test_launcher_interpreter_floor_reason.py -q
```

Expected: `test_the_environment_arm_does_not_guess` **FAILS**. Restore:

```bash
mv bin/alfred-plugin-launcher.sh.bak bin/alfred-plugin-launcher.sh
```

- [ ] **Step 7: Run the audit + adversarial suites**

```bash
uv run pytest tests/unit/security/ tests/unit/audit/ -q
uv run pytest tests/adversarial -q
```

- [ ] **Step 8: Commit**

```bash
git add src/alfred/audit/audit_row_schemas.py bin/alfred-plugin-launcher.sh \
        tests/unit/security/test_launcher_interpreter_floor_reason.py
git commit -m "feat(launcher): #568 name a sub-floor interpreter instead of guessing environment_not_set"
```

---

### Task 5: The freshness monitor script

Content comparison alone is a **lagging, noisy** signal: replayed against the frozen graph, its day-1 redness is entirely phantom version-less records, and de-noised it is green and blind for 16 days. Liveness is one API call and a perfect step function. So: liveness primary, content secondary behind a coverage floor and two-way containment, fail-closed throughout.

Draft 1's algorithm passed on four of five degenerate SBOMs — including one that *is* #568 recurring.

**Files:**

- Create: `scripts/check_dependency_graph_freshness.py`
- Create: `tests/unit/meta/test_dependency_graph_freshness.py`
- Create: `tests/fixtures/dependency_graph/sbom_stale_2026-06-19.json`

**`scripts/` is NOT an importable package.** Every existing script test loads its
subject with `importlib.util.spec_from_file_location` — see the `runner` fixture in
`tests/unit/meta/conftest.py`. A `from scripts.x import y` fails at collection. The test
therefore lives in `tests/unit/meta/` alongside its siblings, not in a new `tests/unit/scripts/`.

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: `check_dependency_graph_freshness.evaluate(sbom, lock, runs, *, min_packages) -> Verdict`, a frozen dataclass with fields `dead_channels: tuple[str, ...]`, `missing_from_sbom: tuple[str, ...]`, `version_mismatches: tuple[tuple[str, str, str], ...]`, `package_count: int`, `min_packages: int`, `unexpected_in_sbom: tuple[str, ...] = ()` (a graph-only package outside `_GRAPH_ONLY_ALLOWLIST`), `conflicting_versions: tuple[str, ...] = ()` (one package name with two distinct versioned purls in the graph), `unversioned_in_sbom: tuple[str, ...] = ()` (a lock package whose only SBOM record is version-less — no versioned record for that name exists anywhere in the document), and property `ok: bool`.

- [ ] **Step 1: Capture the real stale SBOM as a committed fixture**

```bash
mkdir -p tests/fixtures/dependency_graph
gh api repos/alfred-os/AlfredOS/dependency-graph/sbom \
  > tests/fixtures/dependency_graph/sbom_stale_2026-06-19.json
python3 -c "
import json,pathlib
d=json.loads(pathlib.Path('tests/fixtures/dependency_graph/sbom_stale_2026-06-19.json').read_text())
print('packages:', len(d['sbom']['packages']))
"
```

The live signal evaporates the moment the fix merges. A committed fixture is what keeps the negative case executable forever.

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/meta/test_dependency_graph_freshness.py`:

```python
"""The monitor must not pass on a degenerate SBOM (#568).

Draft 1's algorithm passed on FOUR of these five inputs. The zero-pypi case is
literally #568 recurring: the channel dies, the graph serves nothing, and a
content-only monitor reports clean.

`scripts/` is not a package — the subject is loaded with
`spec_from_file_location`, matching the `runner` fixture in this directory's
conftest.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "dependency_graph"
_SCRIPT = _REPO_ROOT / "scripts" / "check_dependency_graph_freshness.py"


@pytest.fixture(scope="session")
def freshness() -> ModuleType:
    """Load `scripts/check_dependency_graph_freshness.py` — a script, not a package."""
    spec = importlib.util.spec_from_file_location("check_dependency_graph_freshness", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_HEALTHY_RUNS = {"dependency-graph": "success", "dependabot-updates": "success"}
_LOCK = {"aiohttp": "3.14.3", "gitpython": "3.1.57", "certifi": "2026.7.1"}


def _sbom(*packages: tuple[str, str | None]) -> dict[str, Any]:
    return {
        "sbom": {
            "packages": [
                {
                    "name": name,
                    "versionInfo": version,
                    "externalRefs": [
                        {
                            "referenceLocator": (
                                f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"
                            )
                        }
                    ],
                }
                for name, version in packages
            ]
        }
    }


class TestDegenerateSbomsMustFail:
    def test_empty_sbom_fails(self, freshness: ModuleType) -> None:
        verdict = freshness.evaluate(_sbom(), _LOCK, _HEALTHY_RUNS, min_packages=50)
        assert not verdict.ok

    def test_sbom_with_no_pypi_packages_fails(self, freshness: ModuleType) -> None:
        """The #568 shape: the channel dies and the graph serves nothing."""
        sbom = {"sbom": {"packages": [{"name": "actions/checkout", "externalRefs": []}]}}
        verdict = freshness.evaluate(sbom, _LOCK, _HEALTHY_RUNS, min_packages=50)
        assert not verdict.ok

    def test_dropped_package_fails_via_containment(self, freshness: ModuleType) -> None:
        fresh = tuple((name, version) for name, version in _LOCK.items() if name != "aiohttp")
        verdict = freshness.evaluate(_sbom(*fresh), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert not verdict.ok
        assert "aiohttp" in verdict.missing_from_sbom

    def test_stale_version_fails(self, freshness: ModuleType) -> None:
        stale = (("aiohttp", "3.13.5"), ("gitpython", "3.1.57"), ("certifi", "2026.7.1"))
        verdict = freshness.evaluate(_sbom(*stale), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert not verdict.ok
        assert ("aiohttp", "3.13.5", "3.14.3") in verdict.version_mismatches


class TestPhantomRecords:
    def test_version_less_duplicates_do_not_cause_false_drift(
        self, freshness: ModuleType
    ) -> None:
        """`textual` and `alfred` appear twice in the live SBOM, once with no version.

        Keying off a naive {name: version} map yields None and a monitor that can
        never go green.
        """
        packages = (
            ("aiohttp", "3.14.3"),
            ("aiohttp", None),
            ("gitpython", "3.1.57"),
            ("certifi", "2026.7.1"),
        )
        verdict = freshness.evaluate(_sbom(*packages), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert verdict.ok, f"phantom record caused false drift: {verdict.version_mismatches}"


class TestLivenessIsPrimary:
    def test_a_dead_channel_fails_even_when_content_matches(
        self, freshness: ModuleType
    ) -> None:
        """The lagging-signal problem: content can match while the channel is dead."""
        runs = {**_HEALTHY_RUNS, "dependabot-updates": "failure"}
        verdict = freshness.evaluate(_sbom(*_LOCK.items()), _LOCK, runs, min_packages=2)
        assert not verdict.ok
        assert "dependabot-updates" in verdict.dead_channels

    def test_a_missing_channel_conclusion_fails_closed(self, freshness: ModuleType) -> None:
        """Absent must never read as success."""
        verdict = freshness.evaluate(_sbom(*_LOCK.items()), _LOCK, {}, min_packages=2)
        assert not verdict.ok


class TestHealthyRepo:
    def test_all_signals_green_passes(self, freshness: ModuleType) -> None:
        verdict = freshness.evaluate(_sbom(*_LOCK.items()), _LOCK, _HEALTHY_RUNS, min_packages=2)
        assert verdict.ok


class TestAgainstTheRealFrozenGraph:
    def test_the_committed_stale_fixture_is_detected(self, freshness: ModuleType) -> None:
        """The real 2026-06-19 graph must be reported stale, forever.

        The live signal evaporates on merge; this fixture is what keeps the
        negative case executable.
        """
        sbom = json.loads((_FIXTURES / "sbom_stale_2026-06-19.json").read_text())
        lock = {"aiohttp": "3.14.3", "gitpython": "3.1.57", "pydantic-settings": "2.14.2"}
        verdict = freshness.evaluate(sbom, lock, _HEALTHY_RUNS, min_packages=50)
        assert not verdict.ok
        assert any(name == "aiohttp" for name, _, _ in verdict.version_mismatches)
```

- [ ] **Step 3: Run to verify it fails**

```bash
uv run pytest tests/unit/meta/test_dependency_graph_freshness.py -v
```

Expected: collection error — module does not exist.

- [ ] **Step 4: Implement the script**

Create `scripts/check_dependency_graph_freshness.py`:

```python
#!/usr/bin/env python3
"""Is the submitted dependency graph alive and current? (#568)

LIVENESS IS THE PRIMARY SIGNAL. Content comparison is secondary and lagging:
replayed against the frozen 2026-06-19 graph, a content-only monitor is GREEN
AND BLIND for 16 days, reddening only via an unrelated bulk upgrade. The
per-channel run conclusion is a perfect step function — it would have gone red
at hour 0 instead of day 44.

Content comparison is guarded by five things that draft 1 lacked:
  * a coverage floor      -> an empty / zero-pypi SBOM cannot pass
  * two-way containment   -> a silently DROPPED package (in the lock, absent
                             from the graph) OR a silently KEPT-STALE one (in
                             the graph, absent from the lock and from
                             `_GRAPH_ONLY_ALLOWLIST`) cannot pass -- draft 2
                             only ever checked the first direction
  * purl-derived versions -> the live SBOM's version-less duplicate records
                             (`textual`, `alfred`) cannot cause false drift,
                             and two CONFLICTING versioned records for one
                             package cannot resolve by document order
  * versioned-record proof -> a lock package whose ONLY graph record is
                             version-less cannot pass by riding along on the
                             phantom-record allowance above -- a version-less
                             record is legitimate only when a VERSIONED
                             record for the same name also exists

Every unknown is fail-closed: a malformed document, a missing channel
conclusion, or an unreadable file is a FAILURE, never "no drift".

stdlib-only (`tomllib` is stdlib on 3.11+), so the workflow needs no `uv sync`.
"""

import argparse
import json
import sys
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

# NO `from __future__ import annotations` IN THIS FILE. Do not add it back.
#
# `tests/unit/meta/test_dependency_graph_freshness.py` loads this module the
# house way — `importlib.util.spec_from_file_location` +
# `importlib.util.module_from_spec` + `exec_module()` — WITHOUT registering it
# in `sys.modules` first (matching the `runner` fixture in
# tests/unit/meta/conftest.py). Combine that loader pattern with postponed
# annotations and a `@dataclass` below it, and CPython 3.14.6 raises a bare
# `AttributeError: 'NoneType' object has no attribute '__dict__'` at
# class-definition time: `@dataclass` resolves ClassVar/InitVar/KW_ONLY by
# string-evaling the postponed annotations against
# `sys.modules.get(cls.__module__).__dict__`, and that lookup is `None` for an
# unregistered module. Reproduced in isolation with a two-line probe script,
# and independently against `scripts/docs_check.py`'s own frozen dataclasses
# loaded the identical way — this is a latent trap in the load pattern itself,
# not something specific to this script's design.
#
# Leaving annotations un-postponed sidesteps the string-eval path entirely.
# PEP 604 (`X | Y`) and PEP 585 (`tuple[str, ...]`) are both native at runtime
# on 3.14 regardless of the future import, so nothing is lost by omitting it.
#
# See `Verdict` below for where this actually bites.

#: Channels that read `requires-python` and died together on 2026-06-21.
#:
#: TWO entries, not three. Dependabot's security-update and weekly-pip channels
#: are separate COMMANDS inside one workflow (282449388), so the runs API gives
#: them a single shared conclusion. Splitting them needs per-job inspection;
#: until that exists, claiming three independent signals would overstate what is
#: measured. `pip` had an unrelated failure on 2026-05-24, so the split is worth
#: doing later — tracked as a follow-up, not faked here.
REQUIRED_CHANNELS: Final[tuple[str, ...]] = (
    "dependency-graph",
    "dependabot-updates",
)

#: The package the repo itself publishes; it has no lockfile entry.
_SELF_PACKAGE: Final[str] = "alfred"

_PYPI_PURL_PREFIX: Final[str] = "pkg:pypi/"

#: Packages that legitimately appear in GitHub's live dependency graph but can
#: never have a `uv.lock` entry. This is an ALLOWLIST of specific, justified
#: names, NOT a snapshot of "whatever the graph contains today" -- extend it
#: only when you can name why the new entry belongs here. Anything else
#: present in the graph but absent from the lock is unexplained and must fail
#: closed (see `unexpected_in_sbom` on `Verdict`).
#:
#:   * "hatchling" -- the PEP 517 build backend declared in
#:     `[build-system].requires` (pyproject.toml). GitHub's dependency graph
#:     parses build-system requirements; `uv.lock` only resolves
#:     `[project]`/dependency-group entries, so this name can never land
#:     there.
#:   * "click" -- a real transitive dependency of `typer` (pulled in via
#:     `typer==0.25.1`) until #391 (2026-07-05) bumped `typer` to 0.26.8,
#:     which dropped it. GitHub's graph carried the old resolution forward as
#:     a stale leftover afterwards -- confirmed against the committed
#:     `sbom_stale_2026-06-19.json` fixture (predates #391), which names
#:     `click@8.4.1`, the exact version #391 removed from `uv.lock`.
_GRAPH_ONLY_ALLOWLIST: Final[frozenset[str]] = frozenset({"click", "hatchling"})


# This is the class whose existence forces the no-future-annotations rule at
# the top of this file — see that comment before "fixing" this by adding
# `from __future__ import annotations` back.
@dataclass(frozen=True, slots=True)
class Verdict:
    """Outcome of one freshness evaluation."""

    dead_channels: tuple[str, ...]
    missing_from_sbom: tuple[str, ...]
    version_mismatches: tuple[tuple[str, str, str], ...]
    package_count: int
    min_packages: int
    #: SBOM packages that are neither in `uv.lock` nor in
    #: `_GRAPH_ONLY_ALLOWLIST`. Reverse containment: `missing_from_sbom` above
    #: catches a lock package the graph silently DROPPED; this catches a
    #: stale package the graph silently KEPT after it left the lock.
    #: Defaulted to `()` so existing call sites that predate this field are
    #: unaffected.
    unexpected_in_sbom: tuple[str, ...] = ()
    #: Package names whose purls carry more than one distinct version in the
    #: SBOM. Two versions of one package in the graph is evidence of
    #: staleness in its own right, independent of which one (if either)
    #: matches `uv.lock` -- see `sbom_versions()`. Defaulted to `()` for the
    #: same reason as `unexpected_in_sbom`.
    conflicting_versions: tuple[str, ...] = ()
    #: Lock packages present in the graph ONLY via a versionless (phantom)
    #: purl -- no versioned record for that name exists anywhere in the
    #: document. `sbom_names()` counts a versionless purl as "present", so
    #: containment (`missing_from_sbom`) passes; `sbom_versions()` excludes
    #: versionless records entirely, so version comparison never runs for
    #: it either. Without this field, a graph in which EVERY lock package
    #: appears only as a versionless purl passes every other check. A
    #: versionless record stays legitimate only when a VERSIONED record for
    #: the same name also exists (the real `textual`/`alfred` duplicates --
    #: see `sbom_versions()`'s docstring). Defaulted to `()` for the same
    #: reason as `unexpected_in_sbom`.
    unversioned_in_sbom: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return (
            not self.dead_channels
            and not self.missing_from_sbom
            and not self.unexpected_in_sbom
            and not self.unversioned_in_sbom
            and not self.version_mismatches
            and not self.conflicting_versions
            and self.package_count >= self.min_packages
        )

    def report(self) -> str:
        if self.ok:
            return (
                f"dependency graph healthy: {self.package_count} pypi packages, all channels live"
            )
        lines = ["dependency graph UNHEALTHY:"]
        if self.dead_channels:
            lines.append(f"  dead channels: {', '.join(self.dead_channels)}")
        if self.package_count < self.min_packages:
            lines.append(
                f"  coverage floor: {self.package_count} pypi packages < {self.min_packages}"
            )
        if self.missing_from_sbom:
            lines.append(f"  absent from graph: {', '.join(self.missing_from_sbom)}")
        if self.unexpected_in_sbom:
            lines.append(f"  unexpected in graph: {', '.join(self.unexpected_in_sbom)}")
        if self.unversioned_in_sbom:
            lines.append(f"  versionless-only in graph: {', '.join(self.unversioned_in_sbom)}")
        for name, graph_version, lock_version in self.version_mismatches:
            lines.append(f"  {name}: graph {graph_version} vs lock {lock_version}")
        if self.conflicting_versions:
            lines.append(f"  conflicting versions in graph: {', '.join(self.conflicting_versions)}")
        return "\n".join(lines)


def sbom_versions(sbom: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """Map pypi package name -> every distinct version its purls carry.

    Records whose purl carries no `@version` are PHANTOMS (the live document has
    duplicate `textual` / `alfred` entries shaped that way) and are excluded
    here so a phantom duplicate alongside a real versioned record can never
    cause a false version mismatch. :func:`sbom_names` still counts a
    version-less purl as present by name -- containment alone does NOT catch
    a lock package whose ONLY graph record is version-less; that is caught
    separately, by `evaluate()`'s `unversioned_in_sbom` (a name present here
    would exclude it from that check; a name absent here that IS present in
    `sbom_names()` is exactly the fail-closed case).

    Retains every DISTINCT versioned record per name instead of last-write-wins:
    a `{name: version}` map lets two conflicting versioned purls for the same
    package resolve by document order alone, silently flipping the verdict on
    identical content. A package appearing twice with two different versions is
    itself evidence the graph is stale, so the caller (`evaluate()`) must be
    able to see that a name has more than one version, not just whichever one
    a `dict` write happened to land on last. Keys of the per-name dict here
    (rather than a `set`) preserve encounter order for readability in
    `Verdict.report()` without needing an extra sort key.
    """
    versions: dict[str, dict[str, None]] = {}
    for package in sbom.get("sbom", {}).get("packages", []):
        for ref in package.get("externalRefs", []):
            locator = ref.get("referenceLocator", "")
            if not locator.startswith(_PYPI_PURL_PREFIX):
                continue
            remainder = locator.removeprefix(_PYPI_PURL_PREFIX)
            name, separator, version = remainder.partition("@")
            if separator and name != _SELF_PACKAGE:
                versions.setdefault(name, {})[version] = None
    return {name: tuple(seen) for name, seen in versions.items()}


def sbom_names(sbom: Mapping[str, Any]) -> set[str]:
    """Every pypi package name in the document, with or without a version."""
    names: set[str] = set()
    for package in sbom.get("sbom", {}).get("packages", []):
        for ref in package.get("externalRefs", []):
            locator = ref.get("referenceLocator", "")
            if locator.startswith(_PYPI_PURL_PREFIX):
                name = locator.removeprefix(_PYPI_PURL_PREFIX).partition("@")[0]
                if name != _SELF_PACKAGE:
                    names.add(name)
    return names


def lock_versions(lock: Mapping[str, Any]) -> dict[str, str]:
    """Map package name -> version from a parsed `uv.lock`."""
    return {
        package["name"]: package["version"]
        for package in lock.get("package", [])
        if package.get("name") != _SELF_PACKAGE and "version" in package
    }


def dead_channels(runs: Mapping[str, str]) -> tuple[str, ...]:
    """Channels whose latest conclusion is anything but ``success``.

    Fail-closed: a channel absent from ``runs`` counts as dead, because "we
    could not tell" and "it is fine" must never be the same answer.
    """
    return tuple(
        channel for channel in REQUIRED_CHANNELS if runs.get(channel, "unknown") != "success"
    )


def evaluate(
    sbom: Mapping[str, Any],
    lock: Mapping[str, str],
    runs: Mapping[str, str],
    *,
    min_packages: int,
) -> Verdict:
    """Combine all seven signals into one verdict."""
    graph_versions = sbom_versions(sbom)
    present = sbom_names(sbom)
    missing = tuple(sorted(name for name in lock if name not in present))
    # Reverse containment: `missing` above catches a lock package the graph
    # DROPPED; this catches a stale package the graph KEPT after it left the
    # lock. Anything present in the graph that isn't in the lock AND isn't a
    # justified graph-only package (see `_GRAPH_ONLY_ALLOWLIST`) is
    # unexplained and must fail closed.
    unexpected = tuple(
        sorted(name for name in present if name not in lock and name not in _GRAPH_ONLY_ALLOWLIST)
    )
    # A lock package can be `present` (sbom_names counts a versionless purl)
    # while never appearing in `graph_versions` (sbom_versions excludes
    # versionless records) -- that combination means the graph carries the
    # name only as a version-less phantom, and nothing else here ever
    # demands a versioned record exist. Fail closed on it explicitly rather
    # than letting version comparison silently skip the package.
    unversioned = tuple(
        sorted(name for name in lock if name in present and name not in graph_versions)
    )
    # A package with more than one distinct version in the graph is stale on
    # its own terms -- skip it for the lock-vs-graph comparison below (its
    # ambiguity is already reported via `conflicting_versions`) rather than
    # picking one of its versions arbitrarily to compare.
    conflicting = tuple(sorted(name for name, seen in graph_versions.items() if len(seen) > 1))
    mismatches = tuple(
        sorted(
            (name, graph_versions[name][0], lock[name])
            for name in lock
            if name in graph_versions
            and len(graph_versions[name]) == 1
            and graph_versions[name][0] != lock[name]
        )
    )
    return Verdict(
        dead_channels=dead_channels(runs),
        missing_from_sbom=missing,
        version_mismatches=mismatches,
        package_count=len(present),
        min_packages=min_packages,
        unexpected_in_sbom=unexpected,
        conflicting_versions=conflicting,
        unversioned_in_sbom=unversioned,
    )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"fail-closed: cannot read {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit(f"fail-closed: {path} is not a JSON object")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", type=Path, required=True, help="fetched SBOM JSON")
    parser.add_argument("--runs", type=Path, required=True, help="channel -> conclusion JSON")
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument(
        "--min-packages",
        type=int,
        required=True,
        help="coverage floor; below this the graph is treated as not submitted",
    )
    args = parser.parse_args(argv)

    try:
        lock = tomllib.loads(args.lock.read_bytes().decode())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"fail-closed: cannot read {args.lock}: {exc}") from exc

    verdict = evaluate(
        _read_json(args.sbom),
        lock_versions(lock),
        {str(k): str(v) for k, v in _read_json(args.runs).items()},
        min_packages=args.min_packages,
    )
    print(verdict.report())
    return 0 if verdict.ok else 1


if __name__ == "__main__":
    sys.exit(main())
```

CodeRabbit round 4 (#569) found the guards above still had a gap: a lock package present in
the graph *only* via a version-less purl passed both containment (`sbom_names()` counts a
version-less purl as present) and content comparison (`sbom_versions()` excludes version-less
records entirely, so comparison silently never runs for that name) — a graph in which every
lock package appears only as a version-less purl would have passed cleanly. `unversioned_in_sbom`
closes that gap. Regression coverage lives in
`tests/unit/meta/test_dependency_graph_freshness.py::TestUnversionedOnlyPurlsBugRound4`: one case
where a lock package appears only as a version-less purl (must fail, named in
`verdict.unversioned_in_sbom`), and one where a version-less duplicate coexists with a real
versioned record for the same name — the live graph's actual `textual`/`alfred` shape — which
must still pass.

- [ ] **Step 5: Run to verify it passes**

```bash
uv run pytest tests/unit/meta/test_dependency_graph_freshness.py -v
```

Expected: all pass, including the real-fixture case.

- [ ] **Step 6: Mutation-verify each guard independently**

Run these one at a time, restoring between each. Every one must turn a test red:

```bash
# 1. remove the coverage floor
sed -i.bak 's/and self.package_count >= self.min_packages/and True/' scripts/check_dependency_graph_freshness.py
uv run pytest tests/unit/meta/test_dependency_graph_freshness.py -q   # expect FAIL
mv scripts/check_dependency_graph_freshness.py.bak scripts/check_dependency_graph_freshness.py

# 2. remove containment
sed -i.bak 's/and not self.missing_from_sbom/and True/' scripts/check_dependency_graph_freshness.py
uv run pytest tests/unit/meta/test_dependency_graph_freshness.py -q   # expect FAIL
mv scripts/check_dependency_graph_freshness.py.bak scripts/check_dependency_graph_freshness.py

# 3. make liveness fail-open
sed -i.bak 's/runs.get(channel, "unknown")/runs.get(channel, "success")/' scripts/check_dependency_graph_freshness.py
uv run pytest tests/unit/meta/test_dependency_graph_freshness.py -q   # expect FAIL
mv scripts/check_dependency_graph_freshness.py.bak scripts/check_dependency_graph_freshness.py

uv run pytest tests/unit/meta/test_dependency_graph_freshness.py -q   # green again
```

- [ ] **Step 7: Run it against the live repo and record the result**

```bash
gh api repos/alfred-os/AlfredOS/dependency-graph/sbom > /tmp/sbom.json
printf '{"dependency-graph":"failure","dependabot-updates":"failure"}' > /tmp/runs.json
uv run python3 scripts/check_dependency_graph_freshness.py \
  --sbom /tmp/sbom.json --runs /tmp/runs.json --min-packages 90; echo "exit=$?"
```

Expected: **exit 1**, listing dead channels and ~35 stale packages. Record the package count — it sets `--min-packages` in Task 6.

- [ ] **Step 8: Commit**

```bash
git add scripts/check_dependency_graph_freshness.py \
        tests/unit/meta/test_dependency_graph_freshness.py \
        tests/fixtures/dependency_graph/
git commit -m "feat: #568 add the liveness-first dependency-graph freshness check"
```

---

### Task 6: The monitor workflow, and the coverage-gate lockstep

**No `push: main` trigger.** Measured: the graph run is created **+6 s** after a push and completes in 34–45 s, plus ingest lag, so a push-triggered monitor reads the pre-push graph and reports false drift. The sha fix is unavailable — the SBOM carries no commit ref (`documentNamespace` is a per-request UUID, `created` is request time). `workflow_run:` does not fire on the `dynamic` Dependabot job.

Adding a `scripts/` file requires a **five-surface lockstep**; `zip(..., strict=True)` makes a partial edit fail at collection time rather than silently mispair.

**Files:**

- Create: `.github/workflows/dependency-graph-freshness.yml`
- Modify: `tests/unit/meta/test_gate_surfaces_are_pinned.py` (`_REQUIRED_COVERAGE_GATES:88`, `_GATE_STEP_NAMES:135`)
- Modify: `tests/unit/meta/test_coverage_gate_runner.py:48` (`_MIN_UNIT_GATES` 28 → 29)
- Modify: `.github/workflows/ci.yml` (`python` job: one new gate step)
- Modify: `Makefile:160` (`--min-gates 28` → `29`)
- Modify: `docs/ci/required-checks.md`
- Modify: `pyproject.toml` (Step 5a removes Task 5's transitional `[tool.coverage.run] omit` entry for this script)

**Interfaces:**

- Consumes: `scripts/check_dependency_graph_freshness.py` from Task 5.
- Produces: a non-required scheduled workflow; a 29th unit-tier coverage gate.

- [ ] **Step 1: Read the canonical gating-workflow process**

```bash
cat .rulesync/skills/author-gating-workflow/SKILL.md
```

This monitor is deliberately **not** promoted to a required check (see "Out of scope"), but the workflow-authoring conventions — least-privilege permissions, SHA-pinned actions, injection-safe `env:` passing — are mandatory because `Zizmor (workflow security)` is a required check.

- [ ] **Step 2: Add the coverage gate in lockstep**

In `tests/unit/meta/test_gate_surfaces_are_pinned.py`, append to `_REQUIRED_COVERAGE_GATES`:

```python
    ("scripts/check_dependency_graph_freshness.py", 100),
```

…and to `_GATE_STEP_NAMES`, in the SAME position:

```python
    "check_dependency_graph_freshness 100% line+branch coverage",
```

In `tests/unit/meta/test_coverage_gate_runner.py:48`, change `_MIN_UNIT_GATES = 28` to `29`. In `Makefile:160`, change `--min-gates 28` to `--min-gates 29`.

**Do NOT touch `_GATE_SCRIPT_RUN_RE` (line ~399).** That regex marks a job as *gate-script-bearing*, which then triggers `assert len(invocations) == 1` and an `_APPROVED_GATE_SCRIPT_STEPS[job_ref]` lookup. It is for scripts CI runs to enforce a merge gate. This monitor runs on a schedule in its own workflow and is not a merge gate, so adding it there would demand a pinning surface that does not apply and fail the meta suite. The lockstep here is five surfaces, not six.

- [ ] **Step 3: Add the ci.yml gate step**

In `.github/workflows/ci.yml`'s `python` job, alongside the existing script gates, add a step named exactly as pinned above:

```yaml
      - name: check_dependency_graph_freshness 100% line+branch coverage
        # #568: this script is the detector for three dependency channels that
        # died silently for 44 days. It is gate-enforcing code, so
        # tests/unit/meta/test_scripts_coverage_census.py requires it GATED at
        # 100% rather than omitted (#423 — gate on the allow-list, not the
        # calendar).
        if: steps.check.outputs.has_py == 'true'
        run: |
          uv run coverage report \
            --include='scripts/check_dependency_graph_freshness.py' \
            --fail-under=100
```

Two shape requirements, both load-bearing: the step name must match `_GATE_STEP_NAMES` byte-for-byte (`zip(..., strict=True)` pairs them positionally), and the `run:` body must keep the three-line continuation with the `if:` guard, matching every sibling gate step — two independent oracles read it, one parsing the YAML via `runner._iter_gates` and one matching the `python` job's raw text.

- [ ] **Step 4: Verify the lockstep holds**

```bash
uv run pytest tests/unit/meta/ -q
```

Expected: pass. If a `zip()` strict error appears at collection, one of the five surfaces was missed — that is the mechanism working.

- [ ] **Step 5: Confirm 100% coverage on the new script**

```bash
make coverage-unit
uv run coverage report --include='scripts/check_dependency_graph_freshness.py' --fail-under=100
```

If below 100%, add tests for the uncovered lines — do **not** add an omit entry; `tests/unit/meta/test_scripts_coverage_census.py` classifies this as gate-enforcing code, and `test_the_gate_enforcing_scripts_are_gated_not_omitted` will reject an omission.

- [ ] **Step 6: Write the workflow**

Create `.github/workflows/dependency-graph-freshness.yml`:

```yaml
name: dependency-graph-freshness

# Is the submitted Python dependency graph alive and current? (#568)
#
# NOT a required check, and deliberately NOT triggered on `push: main`. The
# Dependabot `update_graph` job is created ~6s AFTER a push and takes 34-45s
# plus ingest lag, so a push-triggered run reads the PRE-push graph and reports
# false drift. There is no sha to synchronise on: the SBOM's `documentNamespace`
# is a per-request UUID and `created` is request time, not snapshot time.
# `workflow_run:` does not fire on the Dependabot-hosted `dynamic` job.
#
# Failure is routed to a PERMANENTLY-OPEN tracking issue whose body is rewritten
# each run. "Open on drift, close on resync" would make SILENCE the healthy
# state — so a broken monitor would be indistinguishable from a healthy repo,
# which is #568's own failure class inside its remedy.

on:
  schedule:
    - cron: '17 6 * * *'
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}
  cancel-in-progress: false

permissions: {}

jobs:
  freshness:
    name: Dependency graph freshness
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
      # Needed by both `gh api repos/.../actions/workflows/<id>/runs` calls in
      # the fetch step below. An explicit `permissions:` block sets every
      # UNLISTED scope to `none`, so without this both calls 403.
      actions: read
      issues: write
    steps:
      - name: Checkout code
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 1
          persist-credentials: false

      - name: Fetch the submitted SBOM and the per-channel run conclusions
        env:
          GH_TOKEN: ${{ github.token }}
          REPO: ${{ github.repository }}
        run: |
          set -euo pipefail
          gh api "repos/${REPO}/dependency-graph/sbom" > sbom.json
          # Latest conclusion per channel. `// "unknown"` keeps the fail-closed
          # contract: absent is NOT success.
          graph=$(gh api "repos/${REPO}/actions/workflows/283281805/runs?per_page=1" \
            --jq '.workflow_runs[0].conclusion // "unknown"')
          # Workflow 282449388 ("Dependabot Updates") is shared across FOUR
          # ecosystems from .github/dependabot.yml: github-actions, pip/uv,
          # and docker in both "/" and "/docker". `.workflow_runs[0]` is
          # whichever of those four ran LAST, not the Python one — verified
          # live on 2026-08-02 and 2026-08-03: the most recent run both days
          # was a `github_actions in /` SUCCESS while the `uv` channel was
          # actively failing, so the unfiltered query reads SUCCESS straight
          # through a real Python-channel outage. Filter to the Python
          # ecosystem's own runs by `display_title`.
          #
          # That ecosystem is NOT one label. Dependabot titles the SAME
          # Python channel `uv` or `pip` depending on which manifest it
          # resolved against for that update — both are real Python-channel
          # runs, not two different ecosystems. Measured across the last 100
          # runs of this workflow on 2026-08-05: `uv in /.` 28 + `uv in /` 9
          # = 37 (22 failure / 15 success); `pip in /` 12 + `pip in /.` 8 =
          # 20 (17 failure / 3 success); `github_actions in ...` 27 + 8 = 35
          # (all success); `docker ...` 8. A selector anchored to `uv in`
          # alone reads through 17 real Python-channel FAILURES reported
          # only under the `pip` label — the exact fail-open this comment
          # describes, merely narrowed from four labels to one. Do NOT
          # narrow this back to a single label (real titles look like
          # "uv in /. for GitPython, aiohttp, ... - Update #NNNNNNN" or
          # "pip in / for requests - Update #NNNNNNN"); match both, anchored
          # at the start with the trailing space, so a future `uvx`- or
          # `pipenv`-style label can't slip through un-noticed either. Do
          # NOT "simplify" this back to an unfiltered `.workflow_runs[0]` —
          # that silently reintroduces the exact fail-open this comment
          # describes. `// "unknown"` still applies to the filtered result:
          # if no `uv in`/`pip in` run exists at all in the last 100, absent
          # must never read success.
          dependabot=$(gh api "repos/${REPO}/actions/workflows/282449388/runs?per_page=100" \
            --jq '[.workflow_runs[] | select(.display_title | test("^(uv|pip) in "))][0].conclusion // "unknown"')
          jq -n --arg g "$graph" --arg d "$dependabot" \
            '{"dependency-graph":$g,"dependabot-updates":$d}' > runs.json
          cat runs.json

      - name: Evaluate
        id: evaluate
        run: |
          set -euo pipefail
          if python3 scripts/check_dependency_graph_freshness.py \
               --sbom sbom.json --runs runs.json --min-packages 90 > report.txt 2>&1; then
            echo "healthy=true" >> "$GITHUB_OUTPUT"
          else
            echo "healthy=false" >> "$GITHUB_OUTPUT"
          fi
          cat report.txt

      - name: Update the tracking issue
        # `if: always()` — this step must still run when an EARLIER step (the
        # SBOM/run-conclusion fetch) fails, e.g. a `gh api` error. Without
        # this, a failed fetch skips straight past evaluation to this
        # (skipped) step, the job reddens, but the tracking issue keeps
        # whatever verdict its LAST successful run wrote — indistinguishable
        # from a fresh healthy run. That is #568's own failure class
        # (silence reading as healthy) recurring inside its own remedy.
        if: always()
        env:
          GH_TOKEN: ${{ github.token }}
          REPO: ${{ github.repository }}
          HEALTHY: ${{ steps.evaluate.outputs.healthy }}
          RUN_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
        run: |
          set -euo pipefail
          # report.txt is machine-generated from package names and versions.
          # It is passed as a FILE, never interpolated into this script, so a
          # hostile package name cannot reach the shell (this is the repo's
          # first `issues: write` workflow; check_tag_t3's roots are pinned to
          # src/alfred + plugins, so that discipline is not inherited here).
          # RUN_URL is likewise passed via `env:` rather than spliced into
          # this script — same discipline as HEALTHY above, even though
          # github.run_id/github.repository are not attacker-controlled.
          timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          {
            case "$HEALTHY" in
              true)
                printf 'Status as of %s: HEALTHY\n\n' "$timestamp"
                printf '```\n'
                cat report.txt
                printf '```\n\n'
                ;;
              false)
                printf 'Status as of %s: UNHEALTHY\n\n' "$timestamp"
                printf '```\n'
                cat report.txt
                printf '```\n\n'
                ;;
              *)
                # HEALTHY is neither "true" nor "false" — the evaluate step
                # never ran because an earlier step (most likely the SBOM/run
                # fetch) failed first. Say so explicitly instead of leaving
                # the previous verdict standing; report.txt may not exist in
                # this branch, so it is never `cat`.
                printf 'Status as of %s: COULD NOT BE EVALUATED\n\n' "$timestamp"
                printf 'An earlier step in this run failed before a verdict could be produced\n'
                printf '(see the run log). The status above is NOT a fresh healthy result —\n'
                printf 'it means the monitor itself did not complete this cycle.\n\n'
                ;;
            esac
            printf 'Run: %s\n\n' "$RUN_URL"
            printf 'Rewritten by `.github/workflows/dependency-graph-freshness.yml` (#568).\n'
            printf 'This issue stays OPEN permanently and is rewritten each run — an\n'
            printf 'absent issue means the MONITOR is broken, not that the repo is healthy.\n'
          } > body.md

          number=$(gh issue list --repo "$REPO" --state open \
            --label dependency-graph-health --limit 1 --json number --jq '.[0].number // empty')
          if [ -z "$number" ]; then
            gh issue create --repo "$REPO" \
              --title 'Dependency graph health (#568 monitor)' \
              --label dependency-graph-health --body-file body.md
          else
            gh issue edit "$number" --repo "$REPO" --body-file body.md
          fi

      - name: Fail if unhealthy
        if: steps.evaluate.outputs.healthy != 'true'
        run: |
          echo "::error::dependency graph is stale or a channel is dead — see the tracking issue"
          exit 1
```

- [ ] **Step 7: Lint the workflow**

```bash
uv run pytest tests/unit/test_workflow_invariants.py -q
docker run --rm -v "$PWD:/src:ro" ghcr.io/zizmorcore/zizmor:latest /src/.github/workflows/dependency-graph-freshness.yml
```

No `|| true`: a masked exit code here is a paper gate on workflow security, and `Zizmor (workflow
security)` is a required check on PRs — this local run must fail loudly on a finding (or on the
container failing to start) exactly like CI does. Address any zizmor finding before continuing.

- [ ] **Step 8: Create the label and dry-run**

```bash
gh label create dependency-graph-health --description "Dependabot Python channel health (#568)" --color FBCA04 || true
```

- [ ] **Step 9: Document it as deliberately NOT required**

Add a row under the existing `## Not currently required (but exists)` heading in `docs/ci/required-checks.md` (line ~135) — **not** under `## Currently required` and **not** under `## Pending required`, which means "awaiting promotion". This one is deliberately permanent: state that the monitor is schedule-only, that it cannot be a PR check because the Dependency Graph workflow has only ever run on `main` (41/41 runs), and that its failure is routed to a permanently-open tracking issue rather than to the merge button.

- [ ] **Step 10: Commit**

```bash
git add .github/workflows/dependency-graph-freshness.yml .github/workflows/ci.yml Makefile \
        tests/unit/meta/test_gate_surfaces_are_pinned.py \
        tests/unit/meta/test_coverage_gate_runner.py docs/ci/required-checks.md \
        pyproject.toml
git commit -m "ci: #568 add the scheduled dependency-graph freshness monitor"
```

---

### Task 7: Documentation, ADR-0061, and the human-gated PRD diff

**Files:**

- Modify: `tests/unit/test_frozen_slots_dataclass_regression_guard.py` (lines 3-8 and 26)
- Modify: `.rulesync/rules/CLAUDE.md:74`
- Create: `docs/adr/0061-declared-python-floor-diverges-from-enforced-floor.md`
- Prepare (do **not** commit): `PRD.md:618`

- [ ] **Step 1: Correct the guard test's docstring**

In `tests/unit/test_frozen_slots_dataclass_regression_guard.py`, fix BOTH the citation and the
range. The file cites **gh-135228** in four places (lines 1, 10, 28 as `gh135228` in a test NAME,
and 32); the correct issue is **gh-105936** — gh-135228 is "slot dataclasses classes leak original
class", a different bug in the same area. The fix PR is CPython GH-144021, reaching 3.14 via
GH-148469. Renaming the test method is part of this: `test_unknown_attribute_assignment_is_not_the_gh135228_typeerror`
carries the wrong number in its own name. Then correct the range claim on lines 3-8 and the class
docstring on line 26. The corrected fact: the regression is in **3.14.0–3.14.4** and was fixed in **3.14.5** (`_frozen_get_del_attr` → `_frozen_set_del_attr`, `cls` → `__class__`); the floor is held at 3.14.6 because that is the only patch CI exercises, and it is now enforced by `alfred._python_floor`, not by `requires-python`.

- [ ] **Step 2: Correct the canonical rules file**

Edit `.rulesync/rules/CLAUDE.md:74` — **not** the root `CLAUDE.md`, which is a gitignored rulesync output:

```markdown
- **Language (core):** Python 3.14+ (pyproject declares a series-level `>=3.14` so Dependabot can resolve it; the enforced floor is 3.14.6 in `alfred._python_floor` — see ADR-0061)
```

Then regenerate and confirm the output moved:

```bash
rulesync generate -t '*' -f '*'
git status --short          # root CLAUDE.md must remain UNTRACKED/ignored
```

- [ ] **Step 3: Write ADR-0061**

Create `docs/adr/0061-declared-python-floor-diverges-from-enforced-floor.md` following the format of `docs/adr/0060-the-census-counts-scanned-files.md`. Context: Dependabot resolves Python at series granularity; a patch-level `requires-python` killed three channels for 44 days. Decision: declare `>=3.14`, enforce `(3, 14, 6)` at import. Consequences: install-time refusal is lost (uv's resolver error was strictly better UX) and replaced by a loud import-time failure; the two floors can now drift, which the Task 1 detector and the `uv lock --check` gate constrain. Alternatives: keep the patch floor and abandon Python scanning; self-submit the graph (a half fix — the `pip` and security updaters read the same field).

- [ ] **Step 4: Run the doc gates**

```bash
npx --yes markdownlint-cli2@0.22.1 "docs/adr/0061-*.md"
make docs-check > /tmp/dc.log 2>&1; echo "exit=$?"; tail -2 /tmp/dc.log
```

Both must be clean. Read `$?` directly — never pipe `make` into `tail`.

- [ ] **Step 5: Prepare the PRD diff for human approval**

Write the proposed `PRD.md:618` replacement into the PR description verbatim, so a human can approve or reject it without opening an editor. DEC-001 becomes:

```markdown
- **DEC-001:** Core in Python 3.14+ (pyproject declares `>=3.14`; enforced floor `3.14.6` — ADR-0061). Plugins polyglot via MCP.
```

**Do not commit this.** `PRD.md` edits are human-gated.

- [ ] **Step 6: Full verification**

```bash
make check > /tmp/check.log 2>&1; echo "make check exit=$?"; tail -20 /tmp/check.log
uv run pytest tests/adversarial -q
uv run pytest tests/unit -q
```

All must pass. Read the exit status directly.

- [ ] **Step 7: Final commit — the ONLY one that may use `fix:`**

```bash
git add tests/unit/test_frozen_slots_dataclass_regression_guard.py \
        .rulesync/rules/CLAUDE.md docs/adr/0061-declared-python-floor-diverges-from-enforced-floor.md
git commit -m "fix: #568 restore Dependabot's three dead Python channels"
```

This subject auto-closes #568 on merge. Every earlier commit deliberately avoided `fix:` so the issue stayed open through implementation.

---

## Post-merge verification

The fix is not proven by CI — CI never exercises Dependabot. After merge:

- [ ] Re-run the Dependency Graph workflow; confirm it **succeeds** (it has failed 20 consecutive times).
- [ ] Confirm the graph reports `aiohttp 3.14.3` / `gitpython 3.1.57` / `pydantic-settings 2.14.2`.
- [ ] Confirm the Dependabot **security-update** channel (workflow `282449388`) succeeds — this is the channel that should have caught the aiohttp and GitPython CVEs, and it is the fastest real signal.
- [ ] Run `dependency-graph-freshness` via `workflow_dispatch`; confirm it flips to green and the tracking issue body says HEALTHY.
- [ ] Confirm the 27 open alerts auto-close. Any that do not must be dismissed **with a reason**, so the queue is trustworthy.
- [ ] Watch for the weekly `pip` PR to reappear (slowest signal — do not treat its absence as failure before the schedule elapses).
- [ ] Expect a burst: ~35 packages are behind. Triage rather than merging blind.

## Out of scope

- Promoting the freshness monitor to a required check. Steady-state it would mean an unrelated Dependabot outage blocking every PR; revisit once it has a track record.
- `.python-version` and the CI `3.14` pins.
- Extending `check_tag_t3.py`'s scan roots to `scripts/`.
- Adding `ruff`/`mypy` coverage for `scripts/` (neither runs there today — a real gap, but a separate one).
- #565, #564, #560.
