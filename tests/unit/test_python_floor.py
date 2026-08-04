"""The enforced CPython floor, and — critically — that it is actually WIRED.

A pure `enforce()` nobody calls is not a guard. The wiring test is the one that
matters: without it, deleting the call from `alfred/__init__.py` leaves the
whole suite green.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from alfred._python_floor import (
    FLOOR,
    REFUSAL_KEY,
    UnsupportedPythonError,
    enforce,
    enforce_implementation,
)


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


class TestEnforceImplementation:
    def test_non_cpython_refuses(self) -> None:
        with pytest.raises(UnsupportedPythonError) as exc_info:
            enforce_implementation("pypy")
        assert "pypy" in str(exc_info.value)

    def test_cpython_returns(self) -> None:
        assert enforce_implementation("cpython") is None

    def test_the_last_line_is_the_bare_launcher_key(self) -> None:
        """Twin of `TestEnforce`'s same-named test: both refusals share `REFUSAL_KEY`
        (see the docstring on `enforce_implementation` for why), so both must end
        the message with it.
        """
        with pytest.raises(UnsupportedPythonError) as exc_info:
            enforce_implementation("pypy")
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

    def test_importing_alfred_on_a_non_cpython_interpreter_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Kills the mutant that DELETES the enforce_implementation() call from
        __init__.py. Mutates `sys.implementation.name` in place (it is a
        `types.SimpleNamespace`, not swapped in whole) so every other attribute
        production code might read stays real.
        """
        monkeypatch.setattr(sys.implementation, "name", "pypy")
        with pytest.raises(UnsupportedPythonError):
            importlib.reload(importlib.import_module("alfred"))

    def test_importing_alfred_on_this_interpreter_succeeds(self) -> None:
        assert importlib.reload(importlib.import_module("alfred")) is not None
