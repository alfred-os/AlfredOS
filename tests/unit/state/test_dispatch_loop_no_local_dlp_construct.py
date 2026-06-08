"""AST guard: the dispatch loop never constructs OutboundDlp locally (#173).

The DLP scanner MUST arrive via ``ProposalContext.outbound_dlp`` (injection
from the daemon-boot singleton through the Supervisor). A future refactor
that drops ``ctx.outbound_dlp`` for a local ``OutboundDlp(...)`` — or worse,
a ``lambda detail: detail`` "test stub" — would silently disarm the boundary.
This guard pins the non-bypass invariant from spec §3.3: the loop imports
the structural ``OutboundDlpProtocol`` (type-only), never the concrete class,
and never calls ``OutboundDlp(...)``.

Mirrors the AST-guard pattern in ``tests/unit/hooks`` (carrier-tier guards).
"""

from __future__ import annotations

import ast
import pathlib

_DISPATCH_LOOP = pathlib.Path("src/alfred/state/dispatch_loop.py")


def _tree() -> ast.Module:
    return ast.parse(_DISPATCH_LOOP.read_text())


def test_dispatch_loop_does_not_construct_outbound_dlp_locally() -> None:
    """No ``OutboundDlp(...)`` call anywhere in the dispatch-loop module."""
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "OutboundDlp", (
                "Local OutboundDlp construction is forbidden in dispatch_loop.py "
                "— the singleton MUST arrive via ctx.outbound_dlp (injection)."
            )


def test_dispatch_loop_imports_only_protocol_not_concrete() -> None:
    """If dispatch_loop imports from alfred.security.dlp, it is the Protocol only."""
    for node in ast.walk(_tree()):
        if isinstance(node, ast.ImportFrom) and node.module == "alfred.security.dlp":
            names = {alias.name for alias in node.names}
            assert "OutboundDlp" not in names, (
                "Import the structural OutboundDlpProtocol, never the concrete "
                "OutboundDlp — the loop must not be able to build its own scanner."
            )
