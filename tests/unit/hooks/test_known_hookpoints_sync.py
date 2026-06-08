"""Drift detector: the canonical manifest MUST match runtime reality.

Imports every module listed in :data:`KNOWN_HOOKPOINTS`, forcing each
subsystem's ``declare_hookpoints()`` to run, then asserts the
resulting runtime registry equals the manifest's flat set. Any drift
(subsystem adds a hookpoint without updating the manifest, or vice
versa) fails loud.

This test is the load-bearing invariant for issue #151's hand-
maintained manifest. Without it, the manifest could silently rot —
defeating the cold-start guarantee the validator now relies on.

Two subsystems require explicit registration beyond a bare
``import``:

* :mod:`alfred.plugins.web_fetch` ships ``register_hookpoints(registry)``
  as a one-shot bootstrap call (see the module docstring); it does
  NOT auto-fire at import time. The plugin-host bootstrap calls it
  once at process startup; this test calls it directly so the
  ``tool.web.fetch`` declaration lands in the registry for the
  drift check.

* :mod:`alfred.supervisor.core` registers its six hookpoints inside
  :meth:`Supervisor._register_hookpoints` rather than a module-level
  ``declare_hookpoints()`` — plan-review decision core-010 rejected
  import-time registration for that subsystem to keep test isolation
  clean. The method body only consults ``self`` to dispatch to the
  registry singleton (it reads no instance state), so calling it on
  a bare ``object()`` produces the same registration side-effect a
  real ``Supervisor.__init__`` would.
"""

from __future__ import annotations

import ast
import importlib
import pathlib

from alfred.hooks import get_registry
from alfred.hooks._known_hookpoints import KNOWN_HOOKPOINTS, all_known_hookpoints


def test_manifest_matches_runtime_registry_after_full_import_sweep() -> None:
    """After importing every declarer module, the runtime registry MUST
    list exactly the set the manifest declares."""
    # Force every declarer module to run its module-init declare_hookpoints().
    for subsystem in KNOWN_HOOKPOINTS:
        importlib.import_module(subsystem)

    # web_fetch needs an explicit register_hookpoints call — see module docstring.
    import alfred.plugins.web_fetch

    alfred.plugins.web_fetch.register_hookpoints(get_registry())

    # Supervisor's hookpoints are registered inside _register_hookpoints,
    # which an instance calls from __init__. The body only dispatches to
    # the registry singleton (no self-reads), so a stub instance suffices.
    # Using a named stub class (rather than bare ``object()``) so a future
    # refactor that adds ``self.*`` reads to the method produces a clear
    # AttributeError pointing at THIS test, not a confusing traceback in
    # supervisor/core.py.
    from alfred.supervisor.core import Supervisor

    class _StubSupervisor:
        """No-state stub — pinned by the docstring above."""

    Supervisor._register_hookpoints(_StubSupervisor())  # type: ignore[arg-type]

    # PR-S4-3 (ADR-0022): the carrier-substitution meta-hookpoints are
    # registered by declare_meta_hookpoints (not a per-subsystem
    # declare_hookpoints, since they belong to the hooks subsystem
    # itself). Fire it explicitly so the runtime set includes them.
    from alfred.hooks._known_hookpoints import declare_meta_hookpoints

    declare_meta_hookpoints(get_registry())

    # Read the resulting runtime set.
    runtime_names = set(get_registry()._hookpoints.keys())
    manifest_names = set(all_known_hookpoints())

    # Floor guard: a silently-shrunk runtime set (e.g. a refactor that
    # let ``Supervisor._register_hookpoints`` early-return on a missing
    # self-attribute, or a regression that skipped ``web_fetch``'s
    # explicit ``register_hookpoints`` call) would still pass the
    # ``missing_in_manifest`` check below because an empty set is a
    # trivial subset of any manifest. The count floor refuses to let
    # that pass silently: if the runtime registers fewer than the
    # current 18 hookpoints the bootstrap path is broken and the test
    # MUST fail loud. Bump this constant when the manifest grows; the
    # fixture-driven sync check below catches the matching shrink-the-
    # manifest direction.
    expected_min_hookpoints = 23
    assert len(runtime_names) >= expected_min_hookpoints, (
        f"sync test environment registered only {len(runtime_names)} "
        f"hookpoints; expected at least {expected_min_hookpoints}. Either "
        f"Supervisor._register_hookpoints silently skipped (refactor that "
        f"now needs real instance state?) or web_fetch's "
        f"register_hookpoints bootstrap wasn't called. Investigate "
        f"before relaxing this assertion."
    )

    # Missing from manifest (subsystem registered, manifest didn't list).
    missing_in_manifest = runtime_names - manifest_names
    assert not missing_in_manifest, (
        f"runtime registry declares hookpoints the manifest doesn't list: "
        f"{sorted(missing_in_manifest)}. Add them to "
        f"src/alfred/hooks/_known_hookpoints.py under the correct subsystem."
    )

    # In manifest but not registered (manifest lists a name no subsystem registers).
    missing_at_runtime = manifest_names - runtime_names
    assert not missing_at_runtime, (
        f"manifest lists hookpoints no subsystem actually registers at "
        f"runtime: {sorted(missing_at_runtime)}. Either remove them from "
        f"src/alfred/hooks/_known_hookpoints.py or wire a subsystem's "
        f"declare_hookpoints() to register them."
    )


def _collect_module_string_constants(tree: ast.Module) -> dict[str, str]:
    """Collect module-level string-valued assignments.

    Handles both ``AnnAssign`` (``HOOKPOINT_X: Final[str] = "value"``) and
    plain ``Assign`` (``HOOKPOINT_X = "value"``). Only module-level
    constants are tracked — function-local string bindings are out of
    scope for this resolution pass (the AST scan is a static drift
    detector, not a full interpreter).
    """
    table: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                table[node.target.id] = node.value.value
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    table[target.id] = node.value.value
    return table


def _resolve_tuple_iterable(
    value: ast.expr,
    const_table: dict[str, str],
    tuple_table: dict[str, tuple[str, ...]],
) -> tuple[str, ...] | None:
    """Resolve an expression that appears as the iterable of a ``for`` loop
    or as the value of a tuple-table entry.

    Handles three shapes encountered in this codebase:

    * A tuple literal of string constants —
      ``("plugin.grant.requested", "plugin.grant.approved", ...)``.
    * A tuple literal of ``Name`` references to module-level string
      constants — ``(HOOKPOINT_GRANT_REQUESTED, HOOKPOINT_GRANT_APPROVED, ...)``.
    * A ``Name`` reference to a previously-resolved tuple table entry
      (handles ``for x in _GRANT_HOOKPOINTS:`` patterns).

    Returns ``None`` for any shape we cannot statically resolve; callers
    treat ``None`` as "trust the dynamic sync test to catch it" because
    those names will register at runtime regardless.
    """
    if isinstance(value, ast.Tuple | ast.List):
        resolved: list[str] = []
        for elt in value.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                resolved.append(elt.value)
            elif isinstance(elt, ast.Name) and elt.id in const_table:
                resolved.append(const_table[elt.id])
            else:
                return None
        return tuple(resolved)
    if isinstance(value, ast.Name) and value.id in tuple_table:
        return tuple_table[value.id]
    return None


def _collect_module_tuple_constants(
    tree: ast.Module, const_table: dict[str, str]
) -> dict[str, tuple[str, ...]]:
    """Collect module-level tuple-typed assignments whose elements
    resolve to strings.

    Handles ``_GRANT_HOOKPOINTS: Final[tuple[str, ...]] = (HOOKPOINT_X, ...)``
    so a later ``for hookpoint in _GRANT_HOOKPOINTS: register_hookpoint(name=hookpoint)``
    loop can be resolved against the table.
    """
    table: dict[str, tuple[str, ...]] = {}
    for node in tree.body:
        targets: list[ast.expr]
        value: ast.expr | None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        else:
            continue
        if value is None:
            continue
        resolved = _resolve_tuple_iterable(value, const_table, table)
        if resolved is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                table[target.id] = resolved
    return table


class _HookpointNameCollector(ast.NodeVisitor):
    """Walk a parsed module and collect every name passed to
    ``register_hookpoint(name=X)``.

    Resolution order for the ``X`` expression:

    1. Bare string constant — recorded directly.
    2. ``Name`` reference resolved against the module-level constant
       table built by :func:`_collect_module_string_constants`.
    3. ``Name`` reference resolved against the innermost enclosing
       ``for`` loop whose target matches: walk the loop's iterable via
       :func:`_resolve_tuple_iterable`. Supports tuple literals, name
       references to module-level tuples, AND tuple-of-tuples shapes
       where the loop target unpacks ``(name, ...)`` and the iterable is
       a tuple of tuples whose 0-th element is a string constant — the
       :meth:`Supervisor._register_hookpoints` shape.
    4. Anything else is skipped silently — the dynamic sync test still
       catches such names because the corresponding subsystem registers
       them at runtime when the test imports it.
    """

    def __init__(
        self, const_table: dict[str, str], tuple_table: dict[str, tuple[str, ...]]
    ) -> None:
        super().__init__()
        self._const_table = const_table
        self._tuple_table = tuple_table
        self._for_stack: list[ast.For] = []
        # Populated by :func:`_collect_register_hookpoint_names` before
        # ``visit`` is called. Declared up front so the type checker
        # sees the attribute exists.
        self._module_tree_walk: list[ast.AST] = []
        self.found: set[str] = set()

    def visit_For(self, node: ast.For) -> None:
        self._for_stack.append(node)
        try:
            self.generic_visit(node)
        finally:
            self._for_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if self._is_register_hookpoint_call(node):
            self._record_name_kwarg(node)
        self.generic_visit(node)

    @staticmethod
    def _is_register_hookpoint_call(node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "register_hookpoint":
            return True
        return isinstance(func, ast.Name) and func.id == "register_hookpoint"

    def _record_name_kwarg(self, node: ast.Call) -> None:
        for kw in node.keywords:
            if kw.arg != "name":
                continue
            self._record_value(kw.value)

    def _record_value(self, value: ast.expr) -> None:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            self.found.add(value.value)
            return
        if isinstance(value, ast.Name):
            if value.id in self._const_table:
                self.found.add(self._const_table[value.id])
                return
            # Loop-variable case — walk enclosing for-loop targets from
            # innermost outward.
            for for_node in reversed(self._for_stack):
                resolved = self._resolve_loop_variable(value.id, for_node)
                if resolved is not None:
                    self.found.update(resolved)
                    return
        # Unresolvable — silently skip; dynamic sync test backstops us.

    def _resolve_loop_variable(self, name: str, for_node: ast.For) -> tuple[str, ...] | None:
        """If ``name`` binds against ``for_node``'s target, return the
        possible string values for it by inspecting the iterable.

        Two shapes are supported:

        * ``for x in <iterable-of-strings>:`` — return the resolved
          tuple of strings.
        * ``for (x, ...) in <iterable-of-tuples>:`` — return the 0-th
          element of each inner tuple if (a) ``name`` matches the
          0-th unpack target and (b) each inner tuple's 0-th element
          is a string constant.
        """
        target = for_node.target
        # Simple ``for name in ...`` case.
        if isinstance(target, ast.Name) and target.id == name:
            return _resolve_tuple_iterable(for_node.iter, self._const_table, self._tuple_table)
        # Unpacking ``for (name, ...) in ...`` case.
        if isinstance(target, ast.Tuple) and target.elts:
            head = target.elts[0]
            if isinstance(head, ast.Name) and head.id == name:
                # Look for an iterable whose elements are themselves
                # tuples with a string constant at index 0.
                iter_node = for_node.iter
                # Resolve through a module-level Name binding first.
                if isinstance(iter_node, ast.Name) and iter_node.id in self._tuple_table:
                    # Shouldn't happen with the supervisor pattern (the
                    # iterable is a local variable), but harmless to
                    # check.
                    return self._tuple_table[iter_node.id]
                # Resolve through a function-local Name binding by
                # scanning the for-loop's enclosing function for the
                # binding's value. Pragmatic: only handle the
                # supervisor pattern (literal tuple-of-tuples assigned
                # to a local).
                if isinstance(iter_node, ast.Name):
                    local_value = self._lookup_local_assignment(iter_node.id, for_node)
                    if local_value is not None:
                        return self._extract_first_strings(local_value)
                # Inline tuple-of-tuples directly in the for-clause.
                return self._extract_first_strings(iter_node)
        return None

    def _lookup_local_assignment(self, name: str, near: ast.For) -> ast.expr | None:
        """Find a function-local assignment ``name = <expr>`` whose body
        encloses ``near``. Walks the visitor's scope conservatively by
        scanning every for-stack ancestor's parent function.

        Implementation pragmatic: we don't track parent pointers, so we
        re-scan the module's functions looking for an assignment whose
        target matches ``name`` AND whose lineno precedes ``near``.
        Returns the latest such assignment's value; ``None`` if none.

        This is sufficient for the supervisor pattern (``hookpoints = (...)``
        immediately before the ``for`` loop in
        :meth:`Supervisor._register_hookpoints`).
        """
        candidate: ast.expr | None = None
        for ancestor in self._enclosing_function_bodies(near):
            for stmt in ast.walk(ancestor):
                if (
                    isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                    and stmt.target.id == name
                    and stmt.value is not None
                    and stmt.lineno < near.lineno
                ):
                    candidate = stmt.value
                elif isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id == name
                            and stmt.lineno < near.lineno
                        ):
                            candidate = stmt.value
        return candidate

    def _enclosing_function_bodies(
        self, near: ast.For
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        # Without parent pointers we cannot directly enumerate
        # ancestors; the for-stack only tracks ``for`` nodes. Re-walking
        # the whole tree once per resolution is acceptable: AST scans
        # over ~80 src files in well under a second.
        return [
            node
            for node in self._module_tree_walk
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.lineno <= near.lineno <= node.end_lineno  # type: ignore[operator]
        ]

    @staticmethod
    def _extract_first_strings(value: ast.expr) -> tuple[str, ...] | None:
        if not isinstance(value, ast.Tuple | ast.List):
            return None
        resolved: list[str] = []
        for elt in value.elts:
            if not isinstance(elt, ast.Tuple | ast.List) or not elt.elts:
                return None
            head = elt.elts[0]
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                resolved.append(head.value)
            else:
                return None
        return tuple(resolved)


def _collect_register_hookpoint_names(tree: ast.Module) -> set[str]:
    const_table = _collect_module_string_constants(tree)
    tuple_table = _collect_module_tuple_constants(tree, const_table)
    collector = _HookpointNameCollector(const_table, tuple_table)
    # Stash the full tree on the collector so the local-assignment
    # lookup helper can scope-walk without parent pointers.
    collector._module_tree_walk = list(ast.walk(tree))
    collector.visit(tree)
    return collector.found


def test_no_off_manifest_hookpoint_registrations() -> None:
    """Static AST scan: every ``register_hookpoint(name=X)`` call in
    ``src/alfred/`` must use a name that appears in the manifest.

    Why a separate static check: the dynamic sync test above only sees
    subsystems it explicitly imports. A future subsystem that registers
    an off-manifest hookpoint at runtime — and that the test never
    imports — would slip past the dynamic check. The AST scan walks
    every Python file under ``src/alfred/`` and resolves the ``name=``
    argument of each ``register_hookpoint`` call (handling bare string
    constants, references to module-level constants, and loop-variable
    bindings used by the supervisor's tuple-of-tuples pattern). Any
    resolved name absent from the manifest fails this test loud.

    Names the resolver cannot statically pin down (e.g. dynamic
    construction from runtime metadata, which no current subsystem uses)
    are silently skipped — the dynamic sync test catches those via the
    full-import sweep regardless.
    """
    src_root = pathlib.Path(__file__).resolve().parents[3] / "src" / "alfred"
    found_names: set[str] = set()
    for py_file in src_root.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        found_names.update(_collect_register_hookpoint_names(tree))

    manifest = set(all_known_hookpoints())
    off_manifest = found_names - manifest
    assert not off_manifest, (
        f"register_hookpoint(name=...) call sites use names not in the manifest: "
        f"{sorted(off_manifest)}. Either add them to "
        f"src/alfred/hooks/_known_hookpoints.py under the correct subsystem "
        f"or remove the off-manifest registration."
    )
