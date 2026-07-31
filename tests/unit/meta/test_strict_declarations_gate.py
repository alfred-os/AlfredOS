"""`scripts/check_strict_declarations.py` was measured at 0% (#543).

#537 added `--cov=scripts` so `check_tag_t3.py` could carry a 100% gate,
which pulled six other scripts into the measurement without gating any.
This one enforces #119 SEC-Med-1.

All four arms are driven with a REAL `grep` against a REAL planted tree.
`main()` derives its scan root from the module's own `__file__`, so
repointing `__file__` at a tmp_path gives a genuine end-to-end run with no
mocked subprocess — a double would be modelling the thing under test.

Skipif fragility: five of the six cases below carry `_NEEDS_GREP` (needs a
POSIX `grep` on PATH, and is skipped outright on `win32`). On the
coverage-measuring CI leg (`python` job, ubuntu-latest, non-root, GNU grep)
both skipif conditions are false, so the mark is inert and every arm
executes — the 100% gate is real, not conditionally satisfied. That inertness
is an environmental fact about that one runner, not a property of the code:
if the coverage-measuring job ever moved to a runner without `grep` (or to
Windows), the skips would fire for real and silently drop this file's
coverage back toward the 0% #543 measured it at. There is no independent
detector for that regression here — it would show up as `coverage report
--fail-under=100` reddening on `check_strict_declarations.py`, at which point
this comment is the pointer back to why.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_SCRIPT: Path = _REPO_ROOT / "scripts" / "check_strict_declarations.py"

# Assembled at runtime so THIS file cannot trip the guard under test if the
# scan root ever widens past src/.
_FORBIDDEN: str = "strict_declarations" + "=" + "False"

_NEEDS_GREP = pytest.mark.skipif(
    shutil.which("grep") is None or sys.platform == "win32",
    reason="the guard shells out to POSIX grep; the Windows unit leg has none",
)


def _load_script(root: Path | None = None) -> ModuleType:
    """Import the guard, optionally repointing its `__file__`-derived root."""
    spec = importlib.util.spec_from_file_location("check_strict_declarations", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if root is not None:
        module.__file__ = str(root / "scripts" / "check_strict_declarations.py")
    return module


@_NEEDS_GREP
def test_the_real_src_tree_is_clean() -> None:
    """The production invocation: `src/` must hold no occurrence."""
    assert _load_script().main() == 0


@_NEEDS_GREP
def test_a_planted_occurrence_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """grep rc==0 — a SEC-Med-1 regression must fail the gate."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "offender.py").write_text(
        f"registry = HookRegistry({_FORBIDDEN})\n", encoding="utf-8"
    )
    assert _load_script(tmp_path).main() == 1
    err = capsys.readouterr().err
    assert "SEC-Med-1" in err
    assert "offender.py" in err


@_NEEDS_GREP
def test_the_spaced_form_is_also_caught(tmp_path: Path) -> None:
    """The regex must catch what a formatter rewrites the kwarg into.

    A plain substring grep missed `strict_declarations = False` — the CR
    cycle-1 finding the current regex exists to fix. Without this case, a
    "simplification" back to a substring match passes every other test here.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "offender.py").write_text(
        "strict_declarations   =   False\n", encoding="utf-8"
    )
    assert _load_script(tmp_path).main() == 1


@_NEEDS_GREP
def test_a_clean_planted_tree_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """grep rc==1 — no matches is the clean path."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "fine.py").write_text("registry = HookRegistry()\n", encoding="utf-8")
    assert _load_script(tmp_path).main() == 0
    assert "OK:" in capsys.readouterr().out


def test_a_missing_src_tree_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No `src/` at all — refuse rather than report clean. Needs no grep."""
    assert _load_script(tmp_path).main() == 1
    assert "does not exist" in capsys.readouterr().err


@_NEEDS_GREP
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores the permission bits this case depends on",
)
def test_a_grep_error_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """grep rc>=2 — fail closed, not clean.

    A silently-skipped lint is the same shape as the regression it guards
    against. Driven with a REAL unreadable directory so grep really returns 2.
    """
    src = tmp_path / "src"
    unreadable = src / "locked"
    unreadable.mkdir(parents=True)
    (unreadable / "hidden.py").write_text("pass\n", encoding="utf-8")
    unreadable.chmod(0o000)
    try:
        assert _load_script(tmp_path).main() == 1
        assert "grep returned rc=" in capsys.readouterr().err
    finally:
        unreadable.chmod(0o700)
