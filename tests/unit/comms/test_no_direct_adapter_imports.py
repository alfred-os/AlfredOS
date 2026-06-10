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

import importlib
import pathlib

import pytest

#: Repo root: this file lives at ``tests/unit/comms/test_no_direct_adapter_imports.py``
#: so the root is four ``parent`` hops up.
_ROOT = pathlib.Path(__file__).resolve().parents[3]
_DELETED_DIR = _ROOT / "src" / "alfred" / "comms"


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
