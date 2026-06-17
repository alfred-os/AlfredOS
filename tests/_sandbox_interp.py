"""Shared bwrap-sandbox interpreter-bind computation for the launcher tests.

The sandbox-enforcement integration tests exec the venv interpreter
(``sys.executable``) inside a bwrap jail. To do that, every directory the
interpreter's path traverses must be ro-bound into the sandbox, or bwrap fails
``execvp .venv/bin/python: No such file or directory``.

A uv-managed venv's ``bin/python`` can symlink **through a minor-version alias
dir** that is NEITHER ``sys.prefix`` NOR ``sys.base_prefix``::

    .venv/bin/python
      -> .../uv/python/cpython-3.14-<plat>/bin/python3.14   # minor alias (a symlink dir)
         .../uv/python/cpython-3.14-<plat>  ->  cpython-3.14.6-<plat>   # patch dir (realpath)

Binding only ``sys.base_prefix`` (the resolved ``cpython-3.14.6-`` patch dir)
leaves the intermediate ``cpython-3.14-`` alias hop unbound, so the execvp through
the symlink fails inside bwrap. This first surfaced when GitHub's hosted Python
rolled 3.14.5 -> 3.14.6 and the alias layout appeared (proven in docker).

:func:`interpreter_sandbox_roots` walks ``sys.executable``'s full symlink chain
and returns every interpreter-root along it, so the binds are robust to the
uv-managed interpreter location regardless of patch drift. The callers still apply
their own ``/usr,/lib,/bin,/etc`` guard (the PR #231 finding-3 assertion) — this
helper only widens the set of *interpreter* roots, never host system dirs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def interpreter_sandbox_roots() -> set[str]:
    """Interpreter-root dirs to ro-bind so ``sys.executable`` is exec'able in bwrap.

    Returns ``sys.prefix`` (the venv), ``sys.base_prefix`` + the realpath'd
    interpreter root (the resolved patch dir), PLUS each interpreter-root along
    ``sys.executable``'s symlink chain (e.g. a uv minor-version alias dir). Pure;
    callers add their own non-interpreter binds (``plugin_dir``) and the
    ``/usr,/lib,/bin,/etc`` safety filter.
    """
    roots: set[str] = {
        sys.prefix,
        sys.base_prefix,
        str(Path(os.path.realpath(sys.executable)).parents[1]),
    }
    # Walk the symlink chain hop by hop. The interpreter file lives at
    # ``<root>/bin/<exe>``; for each hop we bind ``<root>`` (parents[1]) so an
    # intermediate alias dir is covered, not just the fully-resolved patch dir.
    #
    # The ``seen`` key is LEXICALLY NORMALIZED (``os.path.normpath`` collapses
    # ``.``/``..``) so a relative hop target containing ``..`` cannot revisit the
    # same node under a different string and slip the cycle guard. A hard depth
    # bound is the belt-and-braces backstop: a >64-deep interpreter symlink chain
    # is pathological, so the walk always terminates (CodeRabbit).
    current = Path(sys.executable)
    seen: set[str] = set()
    for _ in range(64):
        if not current.is_symlink():
            break
        key = os.path.normpath(str(current))
        if key in seen:
            break
        seen.add(key)
        target = current.readlink()
        current = target if target.is_absolute() else current.parent / target
        if len(current.parents) >= 2:
            roots.add(str(current.parents[1]))
    return roots


__all__ = ["interpreter_sandbox_roots"]
