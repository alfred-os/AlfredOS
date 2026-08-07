"""`conftest.py`'s `_load_script` must not crash on `from __future__ import
annotations` + `@dataclass` (#568).

`scripts/check_dependency_graph_freshness.py`'s header comment (and
`scripts/docs_check.py`'s equivalent shape) already document the mechanism
precisely: loading a script via `spec_from_file_location` + `exec_module`
WITHOUT registering it in `sys.modules` first raises a bare `AttributeError:
'NoneType' object has no attribute '__dict__'` DURING `exec_module` itself —
while the `@dataclass` decorator is running as part of executing the class
body, not at any later import or instantiation step. `@dataclass` resolves
ClassVar/InitVar/KW_ONLY markers by string-evaluating the postponed
annotations against `sys.modules.get(cls.__module__).__dict__`; that lookup
returns `None` for a module never registered under its own name, and
attribute access on `None` raises.

Neither `docs_check.py` nor `quarantine_spawn_probe.py` is currently loaded
this way by any test, so the bug is latent, not live — this pins the LOADER
itself rather than either script, so any future caller (including a test
that starts loading one of those two scripts this way) gets the safe
behaviour for free instead of rediscovering the crash.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from tests.unit.meta.conftest import _load_script

_FUTURE_ANNOTATIONS_DATACLASS_SOURCE = """\
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Point:
    x: int
    y: int
"""


def _load_unsafe(module_name: str, path: Path) -> ModuleType:
    """The pre-#568 pattern: `spec_from_file_location` + `exec_module`, no
    `sys.modules` registration. Reproduces the crash this file guards against.
    """
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def future_annotations_dataclass_script(tmp_path: Path) -> Path:
    script = tmp_path / "future_annotations_dataclass_mod.py"
    script.write_text(_FUTURE_ANNOTATIONS_DATACLASS_SOURCE, encoding="utf-8")
    return script


@pytest.fixture
def _clean_sys_modules() -> Iterator[None]:
    """Every test below loads a synthetic module under a name unique to that
    test (the test function's own name), so cross-test collision should never
    happen — but a test that raises mid-body could still leave an entry
    behind. Snapshot/restore is the same discipline used elsewhere in this
    suite (the ADR-0030 closure gate) for exactly this reason.
    """
    before = set(sys.modules)
    yield
    for name in set(sys.modules) - before:
        del sys.modules[name]


class TestTheUnsafePatternGenuinelyCrashes:
    """Anti-vacuity: proves the bug this file exists to prevent is real."""

    def test_the_old_pattern_crashes_inside_exec_module(
        self, future_annotations_dataclass_script: Path, _clean_sys_modules: None
    ) -> None:
        """Not at instantiation, not at some later import — the raise happens
        while `_load_unsafe` itself is still running, inside `exec_module`."""
        with pytest.raises(AttributeError, match="__dict__"):
            _load_unsafe(
                "test_the_old_pattern_crashes_inside_exec_module",
                future_annotations_dataclass_script,
            )


class TestLoadScriptIsSafe:
    def test_load_script_loads_a_future_annotations_dataclass(
        self, future_annotations_dataclass_script: Path, _clean_sys_modules: None
    ) -> None:
        module = _load_script(
            "test_load_script_loads_a_future_annotations_dataclass",
            future_annotations_dataclass_script,
        )
        point = module.Point(1, 2)
        assert (point.x, point.y) == (1, 2)

    def test_load_script_registers_the_module_before_exec_module_runs(
        self, future_annotations_dataclass_script: Path, _clean_sys_modules: None
    ) -> None:
        """The registration must happen BEFORE `exec_module`, not after.

        `@dataclass` resolves ClassVar/InitVar/KW_ONLY markers DURING
        `exec_module` (see the module docstring) — registering only after
        `exec_module` returns would be too late, and the sibling test above
        would go back to reproducing the crash. This asserts the module ends
        up present in `sys.modules`, which is the observable half of that
        ordering guarantee.
        """
        module_name = "test_load_script_registers_the_module_before_exec_module_runs"
        assert module_name not in sys.modules
        _load_script(module_name, future_annotations_dataclass_script)
        assert module_name in sys.modules

    def test_load_script_still_works_for_a_module_without_the_trap(
        self, tmp_path: Path, _clean_sys_modules: None
    ) -> None:
        """Non-regression: the ordinary case (no future-annotations dataclass)
        must keep working exactly as before — this is what the `runner`
        fixture exercises every session, so a break here would fail the
        whole meta suite."""
        script = tmp_path / "plain_mod.py"
        script.write_text("VALUE = 42\n", encoding="utf-8")
        module = _load_script("test_load_script_still_works_for_a_module_without_the_trap", script)
        assert module.VALUE == 42

    def test_load_script_cleans_up_sys_modules_on_a_real_exec_error(
        self, tmp_path: Path, _clean_sys_modules: None
    ) -> None:
        """A script that fails to execute for its OWN reasons (unrelated to
        the future-annotations trap) must not leave a half-initialised module
        registered in `sys.modules` for a later, unrelated import of the same
        name to find."""
        module_name = "test_load_script_cleans_up_sys_modules_on_a_real_exec_error"
        script = tmp_path / "broken_mod.py"
        script.write_text("raise RuntimeError('deliberately broken')\n", encoding="utf-8")

        assert module_name not in sys.modules
        with pytest.raises(RuntimeError, match="deliberately broken"):
            _load_script(module_name, script)
        assert module_name not in sys.modules, (
            "a script that fails to exec must not leave a stale entry in sys.modules"
        )

    def test_load_script_preserves_the_original_error_if_the_script_self_deletes(
        self, tmp_path: Path, _clean_sys_modules: None
    ) -> None:
        """#574 review: a script that removes ITSELF from `sys.modules`
        before raising must not have that raise masked by a `KeyError` from
        the loader's own cleanup. `del sys.modules[name]` on an absent key
        raises `KeyError`, which becomes what the caller sees — the original
        exception survives only as `__context__`, invisible to
        `except RuntimeError:` or `pytest.raises(RuntimeError, ...)`.
        Reproduced with the unfixed `del` before writing this test.
        """
        module_name = "test_load_script_preserves_the_original_error_if_the_script_self_deletes"
        script = tmp_path / "self_deleting_mod.py"
        script.write_text(
            "import sys\n"
            f"del sys.modules[{module_name!r}]\n"
            "raise RuntimeError('original error, not a KeyError')\n",
            encoding="utf-8",
        )

        assert module_name not in sys.modules
        with pytest.raises(RuntimeError, match="original error, not a KeyError"):
            _load_script(module_name, script)
        assert module_name not in sys.modules
