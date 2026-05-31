"""AST-level static guards on :mod:`alfred.plugins.stdio_transport` (spec §5.3).

These tests don't exercise runtime behaviour — they parse the source file and
walk the AST to assert two invariants every Slice-3 plugin-host change has to
maintain:

1. The transport module never reads ``os.environ`` (spec §5.3 — the
   subprocess env is built explicitly, never inherited; the host process's
   own env vars are a secret-bearing surface that MUST NOT leak into the
   plugin sandbox).
2. Every call to ``asyncio.create_subprocess_exec`` supplies an explicit
   ``env=`` keyword (no implicit inheritance of parent env).

Both guards run at unit-test time so any patch to the file that re-introduces
the foot-gun fails CI before a runtime test catches the leak.
"""

from __future__ import annotations

import ast
import pathlib

_STDIO_TRANSPORT_PATH = (
    pathlib.Path(__file__).resolve().parents[3]
    / "src"
    / "alfred"
    / "plugins"
    / "stdio_transport.py"
)


def test_stdio_transport_has_no_bare_os_environ_read() -> None:
    """AST scan: ``stdio_transport.py`` must not read ``os.environ`` directly.

    Spec §5.3: the subprocess env is built explicitly. Reading ``os.environ``
    anywhere in the transport module is a release-blocking foot-gun because
    the parent's secret-bearing variables would otherwise be ambiently
    available to any code path that ever calls ``dict(os.environ)``.
    """
    source = _STDIO_TRANSPORT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
            and node.attr == "environ"
        ):
            raise AssertionError(
                "os.environ read found in stdio_transport.py — use an "
                "explicit env= dict (spec §5.3)"
            )


def test_create_subprocess_exec_has_explicit_env_kwarg() -> None:
    """Every ``create_subprocess_exec`` call site supplies ``env=``.

    AST-walk over every ``Call`` node whose function reference matches
    ``asyncio.create_subprocess_exec`` (or any alias). The keyword arg
    must be present — implicit env inheritance is a CLAUDE.md security
    rule violation and a spec §5.3 invariant.
    """
    source = _STDIO_TRANSPORT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    found_call = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Match: asyncio.create_subprocess_exec(...) or create_subprocess_exec(...)
        func = node.func
        is_target = False
        if (isinstance(func, ast.Attribute) and func.attr == "create_subprocess_exec") or (
            isinstance(func, ast.Name) and func.id == "create_subprocess_exec"
        ):
            is_target = True
        if not is_target:
            continue
        found_call = True
        kwarg_names = {kw.arg for kw in node.keywords}
        assert "env" in kwarg_names, (
            "create_subprocess_exec call must pass env= explicitly "
            "(spec §5.3 — no inherited parent env)"
        )
    assert found_call, (
        "expected at least one create_subprocess_exec call in stdio_transport.py "
        "— if this changed, this guard needs updating"
    )
