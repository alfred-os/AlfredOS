"""AST guard: the dispatch loop never constructs OutboundDlp locally (#173).

The DLP scanner MUST arrive via ``ProposalContext.outbound_dlp`` (injection
from the daemon-boot singleton through the Supervisor). A future refactor
that drops ``ctx.outbound_dlp`` for a local ``OutboundDlp(...)`` would silently
disarm the boundary. This guard pins the non-bypass invariant from spec §3.3:
the loop imports the structural ``OutboundDlpProtocol`` (type-only), never the
concrete class, and never CALLS ``OutboundDlp(...)`` — in either the bare
``OutboundDlp(...)`` (``ast.Name``) or the qualified ``dlp.OutboundDlp(...)``
(``ast.Attribute``) form.

What this guard does NOT catch (covered elsewhere, by design): a
``lambda detail: detail`` "no-op scanner" cannot reach the loop because
``ProposalContext.outbound_dlp`` is a REQUIRED field typed as
``OutboundDlpProtocol`` — a bare ``lambda`` is not a structural match for the
protocol (it has no ``scan`` method), so the type system + the required-field
contract reject it at the injection boundary, not here. This guard's job is
narrower: forbid the *concrete-class* construction inside the module.

Mirrors the AST-guard pattern in ``tests/unit/hooks`` (carrier-tier guards).
"""

from __future__ import annotations

import ast
import pathlib

_DISPATCH_LOOP = pathlib.Path("src/alfred/state/dispatch_loop.py")


def _tree() -> ast.Module:
    return ast.parse(_DISPATCH_LOOP.read_text())


def test_dispatch_loop_does_not_construct_outbound_dlp_locally() -> None:
    """No ``OutboundDlp(...)`` call — bare OR attribute-qualified — in the module."""
    for node in ast.walk(_tree()):
        if not isinstance(node, ast.Call):
            continue
        # Bare ``OutboundDlp(...)`` (Name) AND qualified ``mod.OutboundDlp(...)``
        # (Attribute) — the test-engineer-flagged attribute-form bypass.
        constructed = None
        if isinstance(node.func, ast.Name):
            constructed = node.func.id
        elif isinstance(node.func, ast.Attribute):
            constructed = node.func.attr
        assert constructed != "OutboundDlp", (
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
