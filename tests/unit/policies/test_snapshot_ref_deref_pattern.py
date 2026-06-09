"""Deref-pattern AST guard (PR-S4-4 Component D, Tasks 12-13).

core-003 closure + index §3: a consumer must call ``ref.current().x``
per-use and MUST NOT cache the result of ``ref.current()`` in a local that is
then read again on the far side of an ``await`` boundary. A swap during an
iteration would leave the stale local in play; the per-iteration deref
invariant (snapshot_ref.py module docstring) requires a fresh deref after each
await.

The guard is intentionally NARROW (spec §5.5 ¶7): it scans only the four
migrated consumer modules + the supervisor's ``_proposal_dispatch_loop``.
Broader enforcement would false-positive on unrelated ``.current()`` methods.

Mirrors the structural guard in
``tests/unit/state/test_dispatch_loop_no_local_dlp_construct.py``.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]

_TARGETS: tuple[pathlib.Path, ...] = (
    _REPO_ROOT / "src/alfred/plugins/web_fetch/rate_limit.py",
    _REPO_ROOT / "src/alfred/plugins/web_fetch/handle_cap.py",
    _REPO_ROOT / "src/alfred/plugins/web_fetch/content_store.py",
    _REPO_ROOT / "src/alfred/security/quarantine.py",
    _REPO_ROOT / "src/alfred/supervisor/core.py",
)


def _is_current_call(node: ast.expr) -> bool:
    """True if ``node`` is a ``<something>.current()`` call expression."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "current"
        and not node.args
        and not node.keywords
    )


def _rhs_contains_current_call(node: ast.expr) -> bool:
    return any(_is_current_call(child) for child in ast.walk(node))


def _nested_bodies(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Return the nested statement bodies of a compound statement (in order).

    Loop bodies are EXCLUDED here — the caller scans them with a deliberate
    two-pass to model cross-iteration binding survival.
    """
    bodies: list[list[ast.stmt]] = []
    if isinstance(stmt, ast.If | ast.With | ast.AsyncWith):
        bodies.append(stmt.body)
        bodies.append(stmt.orelse if isinstance(stmt, ast.If) else [])
    elif isinstance(stmt, ast.Try):
        bodies.append(stmt.body)
        for handler in stmt.handlers:
            bodies.append(handler.body)
        bodies.append(stmt.orelse)
        bodies.append(stmt.finalbody)
    return [b for b in bodies if b]


class _DerefVisitor(ast.NodeVisitor):
    """Per-function: flag a ``ref.current()`` binding read after a sibling await.

    Walks each function body in source order. When an assignment binds a name
    from a ``ref.current()`` call, the name is tracked. When an ``await``
    appears, every currently-tracked name becomes "tainted". A later *read* of
    a tainted name is a violation — the local crossed the await without a
    fresh deref.
    """

    def __init__(self) -> None:
        self.violations: list[str] = []

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scan_function(node.body)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scan_function(node.body)
        self.generic_visit(node)

    def _scan_function(self, body: list[ast.stmt]) -> None:
        bound: dict[str, int] = {}  # name -> lineno of the binding deref
        tainted: set[str] = set()
        # A loop is scanned twice so a tail-of-iteration binding read after the
        # head-of-iteration await is caught when the loop re-enters.
        self._scan_block(body, bound, tainted)

    def _scan_block(self, body: list[ast.stmt], bound: dict[str, int], tainted: set[str]) -> None:
        for stmt in body:
            self._scan_stmt(stmt, bound, tainted)
            if isinstance(stmt, ast.While | ast.For):
                # First pass scanned the loop body once. Re-scan so a binding
                # made late in the body and read after the head await on the
                # NEXT iteration is caught (cross-iteration survival).
                self._scan_block(stmt.body, bound, tainted)
                self._scan_block(stmt.body, bound, tainted)

    def _scan_stmt(self, stmt: ast.stmt, bound: dict[str, int], tainted: set[str]) -> None:
        # Flag any read of a tainted binding within this statement.
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in tainted:
                self.violations.append(
                    f"line {node.lineno}: '{node.id}' bound from .current() at "
                    f"line {bound.get(node.id, '?')} is read after an await — "
                    "re-deref ref.current() after the await (core-003)."
                )

        # Record any new current()-derived bindings.
        if isinstance(stmt, ast.Assign) and _rhs_contains_current_call(stmt.value):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    bound[target.id] = stmt.lineno
                    tainted.discard(target.id)  # a fresh deref un-taints

        # An await anywhere in this statement taints every live binding.
        if any(isinstance(node, ast.Await) for node in ast.walk(stmt)):
            tainted |= set(bound)

        # Descend into nested compound bodies in source order (the loop second
        # pass is handled by the caller; here we cover if/with/try and the
        # first pass of loop bodies).
        for child_body in _nested_bodies(stmt):
            self._scan_block(child_body, bound, tainted)


def _flag_bad_bindings(tree: ast.AST) -> list[str]:
    visitor = _DerefVisitor()
    visitor.visit(tree)
    return visitor.violations


_BAD_SRC = """
async def loop(self):
    while True:
        snap = self._ref.current()
        await do_thing()
        use(snap.x)
"""

_GOOD_SRC = """
async def loop(self):
    while True:
        await do_thing()
        snap = self._ref.current()
        use(snap.x)
"""

_GOOD_INLINE_SRC = """
async def loop(self):
    while True:
        await do_thing()
        use(self._ref.current().x)
"""

# Cross-iteration bad idiom: snap is bound mid-body, the await at the TAIL of
# iteration N taints it, and it is READ at the HEAD of iteration N+1 before any
# re-deref. A single forward pass cannot flag the head read (snap is unbound on
# the first textual visit); the guard's deliberate two-pass loop scan carries
# the tainted binding into the re-entry and catches it.
_BAD_CROSS_ITERATION_SRC = """
async def loop(self):
    snap = None
    while True:
        use(snap.x)
        snap = self._ref.current()
        await do_thing()
"""


def test_guard_flags_binding_read_after_await() -> None:
    """The guard itself is trustworthy: it flags the canonical bad idiom."""
    assert _flag_bad_bindings(ast.parse(_BAD_SRC))


def test_guard_flags_cross_iteration_binding_read_after_await() -> None:
    """The two-pass scan catches a tail-bound local read after the next-iteration await."""
    assert _flag_bad_bindings(ast.parse(_BAD_CROSS_ITERATION_SRC))


def test_guard_accepts_deref_after_await() -> None:
    assert not _flag_bad_bindings(ast.parse(_GOOD_SRC))


def test_guard_accepts_inline_per_use_deref() -> None:
    assert not _flag_bad_bindings(ast.parse(_GOOD_INLINE_SRC))


@pytest.mark.parametrize("target", _TARGETS, ids=lambda p: p.name)
def test_no_current_binding_crosses_await(target: pathlib.Path) -> None:
    tree = ast.parse(target.read_text(), filename=str(target))
    bad = _flag_bad_bindings(tree)
    assert not bad, (
        f"In {target}, a ref.current() binding is read across an await:\n"
        + "\n".join(f"  - {b}" for b in bad)
        + "\nRequired idiom: deref snapshot = ref.current() AFTER the await, "
        "per iteration."
    )
