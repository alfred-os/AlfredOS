"""Host-agnostic import invariant for the comms runner + transport (G6-2b-1, #288).

The G6-2b ``GatewayAdapterSupervisor`` REUSES :class:`CommsPluginRunner` and
:class:`CommsStdioTransport` to spawn + drive a comms-adapter child from the
gateway role — share-in-place, not a file move (Spec B §4; verified in the plan's
§8 precursor anchors). For that reuse to be honest the gateway must be able to
CONSTRUCT both without pulling the daemon or the CLI into its import graph: the
gateway is a separate always-up process, and a daemon coupling would (a) drag the
boot graph / orchestrator chain into the gateway and (b) make the "the gateway
hosts the adapter, the core only observes" inversion (ADR-0036) untrue.

This is the relocation INVARIANT, pinned as an AST guard so a future edit cannot
silently re-couple them. It walks each module's source AST and asserts that no
**runtime** (i.e. not ``TYPE_CHECKING``-guarded) ``import`` reaches into
``alfred.cli`` (the CLI / daemon command surface) — ``alfred.cli.daemon`` is the
specific daemon coupling, ``alfred.cli`` the broader CLI one. A ``TYPE_CHECKING``
import (e.g. the runner's ``from alfred.plugins.session import AlfredPluginSession,
_SupervisorLike``) is NOT a runtime coupling — it vanishes at import time — so the
guard deliberately excludes the body of an ``if TYPE_CHECKING:`` block (TE-low
correction #5).

If the guard FAILS, the fix is to break the daemon coupling (the modules are
already structured to avoid it: the runner binds ``_SupervisorLike`` structurally
under ``TYPE_CHECKING``, the transport computes ``_repo_root()`` itself instead of
reaching for ``alfred.cli``), NOT to weaken this test.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
from pathlib import Path
from types import ModuleType
from typing import Final

from alfred.plugins import comms_runner, comms_stdio_transport

# The forbidden runtime-import prefixes. ``alfred.cli`` covers the whole CLI
# surface; ``alfred.cli.daemon`` is the specific daemon-boot coupling Spec B
# forbids on the gateway-reuse path. Membership matches the exact dotted name or
# any deeper submodule.
_FORBIDDEN_PREFIXES: Final[tuple[str, ...]] = (
    "alfred.cli",
    "alfred.cli.daemon",
)


def _is_forbidden(module_name: str) -> bool:
    return any(
        module_name == prefix or module_name.startswith(prefix + ".")
        for prefix in _FORBIDDEN_PREFIXES
    )


def _runtime_imported_modules(module: ModuleType) -> set[str]:
    """Every module name a ``import`` / ``from ... import`` brings in at RUNTIME.

    Excludes imports nested inside an ``if TYPE_CHECKING:`` block — those are
    type-only and erased at runtime, so they are not a real coupling. Function-body
    (deferred) imports ARE included: a deferred ``import alfred.cli.daemon`` inside a
    method would still couple the module at call time, which is exactly the regression
    this guard must catch.
    """
    src = inspect.getsource(module)
    tree = ast.parse(src)

    type_checking_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _is_type_checking_test(node.test):
            for child in ast.walk(node):
                type_checking_nodes.add(id(child))

    imported: set[str] = set()
    for node in ast.walk(tree):
        if id(node) in type_checking_nodes:
            continue
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            imported.add(node.module)
    return imported


def _is_type_checking_test(test: ast.expr) -> bool:
    """True if ``test`` is ``TYPE_CHECKING`` or ``typing.TYPE_CHECKING``."""
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def test_comms_runner_has_no_runtime_daemon_or_cli_import() -> None:
    """``CommsPluginRunner``'s module imports nothing under ``alfred.cli`` at runtime."""
    offending = sorted(m for m in _runtime_imported_modules(comms_runner) if _is_forbidden(m))
    assert offending == [], (
        f"alfred.plugins.comms_runner gained a runtime alfred.cli/daemon import "
        f"(breaks gateway reuse, ADR-0036): {offending}"
    )


def test_comms_stdio_transport_has_no_runtime_daemon_or_cli_import() -> None:
    """``CommsStdioTransport``'s module imports nothing under ``alfred.cli`` at runtime."""
    offending = sorted(
        m for m in _runtime_imported_modules(comms_stdio_transport) if _is_forbidden(m)
    )
    assert offending == [], (
        f"alfred.plugins.comms_stdio_transport gained a runtime alfred.cli/daemon import "
        f"(breaks gateway reuse, ADR-0036): {offending}"
    )


def test_guard_excludes_type_checking_imports() -> None:
    """The walk must EXCLUDE ``if TYPE_CHECKING:`` imports (else it false-positives).

    The runner imports ``AlfredPluginSession`` / ``_SupervisorLike`` under
    ``TYPE_CHECKING`` from ``alfred.plugins.session`` — a type-only import. Prove the
    walk does not surface a TYPE_CHECKING-only module so the guard cannot regress into
    flagging type-only couplings (correction #5).
    """
    runtime = _runtime_imported_modules(comms_runner)
    # ``alfred.plugins.session`` is imported ONLY under TYPE_CHECKING in comms_runner,
    # so it must be absent from the runtime set — a positive proof the exclusion works.
    assert "alfred.plugins.session" not in runtime


# ---------------------------------------------------------------------------
# Non-vacuous guard proof: the walker CATCHES a runtime daemon import and IGNORES
# a TYPE_CHECKING-only one, on a synthetic module whose source we control.
# ---------------------------------------------------------------------------


def _module_from_source(tmp_path: Path, name: str, source: str) -> ModuleType:
    """Build an (unexecuted) module backed by a real temp file so ``inspect.getsource``
    can read its source for the AST walk. The module is NEVER executed, so its
    ``import`` statements do not actually pull in the daemon graph — the guard only
    PARSES the source, exactly as it does for the real modules under test.
    """
    path = tmp_path / f"{name}.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    # Build the module object but do NOT exec it — the guard only PARSES the source
    # (``inspect.getsource`` + ``ast.parse``), so the synthetic ``import`` statements
    # never actually pull the daemon graph into this test process.
    return importlib.util.module_from_spec(spec)


def test_guard_catches_a_runtime_daemon_import(tmp_path: Path) -> None:
    """POSITIVE proof: a synthetic module with a RUNTIME ``alfred.cli.daemon`` import
    is flagged by the walk. Without this the guard could silently become a no-op (e.g.
    a refactor that broke the AST walk) and still pass on the clean real modules."""
    source = (
        "from __future__ import annotations\n"
        "import alfred.cli.daemon  # a forbidden RUNTIME daemon coupling\n"
        "from alfred.cli import something  # the broader CLI surface, also forbidden\n"
    )
    module = _module_from_source(tmp_path, "synthetic_runtime_daemon_import", source)
    offending = sorted(m for m in _runtime_imported_modules(module) if _is_forbidden(m))
    assert offending == ["alfred.cli", "alfred.cli.daemon"]


def test_guard_ignores_a_type_checking_only_daemon_import(tmp_path: Path) -> None:
    """NEGATIVE control: the SAME forbidden import under ``if TYPE_CHECKING:`` is NOT
    flagged — it is erased at runtime, so it is not a real coupling. Pairs with the
    positive test to prove the guard discriminates by import KIND, not by presence."""
    source = (
        "from __future__ import annotations\n"
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    import alfred.cli.daemon  # type-only: erased at runtime, must be IGNORED\n"
        "    from alfred.cli import something\n"
    )
    module = _module_from_source(tmp_path, "synthetic_type_checking_daemon_import", source)
    offending = sorted(m for m in _runtime_imported_modules(module) if _is_forbidden(m))
    assert offending == []
