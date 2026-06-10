"""Inverted boundary guard: the in-process ``alfred.comms`` package is GONE.

History
-------

Through Slice 2/3 this file held an AST scan that enforced
"only ``alfred.comms`` modules may import the concrete adapter classes"
(ADR-0009 — the in-process ``CommsAdapter`` Protocol bound). PR-S4-10
(the TUI flag-day) deleted ``src/alfred/comms/`` outright: the in-process
TUI + Discord adapters are replaced by the out-of-process MCP plugins at
``plugins/alfred_tui/`` and ``plugins/alfred_discord/``, and the
comms wire-format contract now lives at ``src/alfred/comms_mcp/protocol.py``
(shipped PR-S4-8).

With the package gone, the guard's job inverts. There is no source tree to
scan for forbidden imports; instead the invariant becomes:

* ``src/alfred/comms/`` must not exist on disk, and
* ``import alfred.comms`` must raise ``ModuleNotFoundError``.

Any regression that reintroduces the in-process package — a stray
re-creation of ``src/alfred/comms/__init__.py``, a merge that resurrects a
deleted adapter module — is caught here. A third check confirms the
deletion did not collateral-damage the replacement wire-format module.

See:
  - ADR-0009 (caveat narrowed in PR-S4-10 — the in-process adapters are
    removed in Slice 4, not merely superseded for new adapters).
  - ADR-0016 (Slice-4 comms-MCP rewrite).
  - docs/superpowers/specs/2026-06-06-slice-4-design.md §8.8.
"""

from __future__ import annotations

import ast
import importlib
import pathlib

import pytest

#: Repo root: this file lives at ``tests/unit/comms/test_no_direct_adapter_imports.py``
#: so the root is four ``parent`` hops up.
_ROOT = pathlib.Path(__file__).resolve().parents[3]
_DELETED_DIR = _ROOT / "src" / "alfred" / "comms"
#: Runtime source tree scanned for latent ``alfred.comms`` import statements.
_SRC_ROOT = _ROOT / "src" / "alfred"


def _imports_legacy_comms(tree: ast.AST) -> bool:
    """True if ``tree`` contains a real ``import``/``from`` of ``alfred.comms``.

    Matches the deleted package exactly (``alfred.comms`` or a ``alfred.comms.``
    submodule) WITHOUT matching the surviving ``alfred.comms_mcp`` package — the
    dotted-prefix guard is the same one ``discord_cmd``'s import test uses.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            mod = node.module
        elif isinstance(node, ast.Import):
            if any(
                a.name == "alfred.comms" or a.name.startswith("alfred.comms.") for a in node.names
            ):
                return True
            continue
        else:
            continue
        if mod == "alfred.comms" or mod.startswith("alfred.comms."):
            return True
    return False


def test_src_alfred_comms_directory_is_absent() -> None:
    """The in-process comms package directory must not exist on disk."""
    assert not _DELETED_DIR.exists(), (
        f"{_DELETED_DIR} reintroduces the Slice-1/2 in-process comms package "
        "that PR-S4-10 deleted. The MCP plugins at plugins/alfred_tui/ and "
        "plugins/alfred_discord/ replace it. If a consumer needs the comms "
        "wire-format types, import from alfred.comms_mcp.protocol (shipped "
        "PR-S4-8). See ADR-0009 (caveat narrowed) and ADR-0016."
    )


def test_alfred_comms_is_not_importable() -> None:
    """``import alfred.comms`` must raise ``ModuleNotFoundError``."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("alfred.comms")


def test_alfred_comms_mcp_protocol_survives_the_deletion() -> None:
    """The replacement wire-format module IS importable.

    Sanity backstop: PR-S4-10's deletion of ``src/alfred/comms/`` must not
    collateral-damage the wire-format module shipped by PR-S4-8 at the
    adjacent ``src/alfred/comms_mcp/`` package. If a future cleanup over-
    broadens the deletion glob to ``comms*``, this fails loud.
    """
    module = importlib.import_module("alfred.comms_mcp.protocol")
    assert hasattr(module, "InboundMessageNotification")
    assert hasattr(module, "OutboundMessageRequest")


def test_no_runtime_source_imports_legacy_comms() -> None:
    """No runtime ``src/alfred`` module imports the deleted ``alfred.comms`` package.

    The deletion + non-importable checks above only prove the package STAYS
    gone. A lazily imported or never-exercised module could still add
    ``from alfred.comms ...`` and those runtime checks would stay green until
    that path is hit. This static AST scan over the runtime source tree catches
    such a latent consumer at test time, before any runtime import error. It is
    careful NOT to flag the surviving ``alfred.comms_mcp`` package. The
    ``comms_mcp`` subtree is itself skipped so its own internal imports never
    trip the dotted-prefix guard. (PR-S4-10 review #6.)
    """
    offenders: list[str] = []
    for source in _SRC_ROOT.rglob("*.py"):
        if "comms_mcp" in source.parts:
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        if _imports_legacy_comms(tree):
            offenders.append(str(source.relative_to(_ROOT)))
    assert not offenders, (
        "runtime source still imports the deleted alfred.comms package "
        f"(PR-S4-10 Component C deletion regression): {offenders}. Import the "
        "wire-format types from alfred.comms_mcp.protocol instead."
    )
