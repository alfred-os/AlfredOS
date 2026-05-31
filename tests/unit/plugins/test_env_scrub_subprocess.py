"""AST-level static guards on :mod:`alfred.plugins.stdio_transport` (spec §5.3).

These tests don't exercise runtime behaviour — they parse the source file and
walk the AST to assert two invariants every Slice-3 plugin-host change has to
maintain:

1. The transport module never reads the host's environment via *any* common
   surface (``os.environ`` attribute access, ``os.getenv`` call,
   ``os.environb``, or a ``from os import environ`` rebind) — spec §5.3
   says the subprocess env is built explicitly, never inherited; the host
   process's own env vars are a secret-bearing surface that MUST NOT leak
   into the plugin sandbox.
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

# Surfaces that read the host's environment. Each entry is a
# ``(module_attr_name, brief_reason)`` pair documenting why the
# AST tripwire treats it as a release-blocker. The list is
# intentionally exhaustive across the ``os`` module's
# environment-reading surface — CR on PR #140 flagged the prior
# implementation as having known bypasses (``os.getenv``,
# ``os.environb``, ``from os import environ``) that would sail
# past the guard while still leaking the host's env.
_DISALLOWED_OS_ENV_NAMES: frozenset[str] = frozenset(
    {
        "environ",  # dict view of the host env
        "environb",  # bytes view of the host env
        "getenv",  # single-var read
        "getenvb",  # bytes single-var read
    }
)


def _collect_os_aliases(tree: ast.AST) -> frozenset[str]:
    """Return every local name that aliases the ``os`` module.

    Covers:

    * ``import os`` → ``{"os"}``
    * ``import os as o`` → ``{"o"}``
    * ``from os import environ`` and ``from os import environ as env`` —
      these don't alias the *module*, they import a single name. Those
      cases are handled separately in the main walker (we scan for bare
      ``Name`` reads of the imported alias).
    """
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    aliases.add(alias.asname or "os")
    return frozenset(aliases)


def _collect_from_os_rebinds(tree: ast.AST) -> frozenset[str]:
    """Return every local name bound by ``from os import <env-name>[ as <alias>]``.

    These bypass the ``os.environ`` attribute-access form of the
    tripwire — a bare ``environ`` read after a ``from os import environ``
    would still leak the host's env. CR on PR #140 flagged the gap.
    """
    rebinds: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                if alias.name in _DISALLOWED_OS_ENV_NAMES:
                    rebinds.add(alias.asname or alias.name)
    return frozenset(rebinds)


def test_stdio_transport_has_no_bare_os_environ_read() -> None:
    """AST scan: the transport module reads no host-env surface.

    Spec §5.3: the subprocess env is built explicitly. Reading the host
    env anywhere in the transport module is a release-blocking foot-gun
    because the parent's secret-bearing variables would otherwise be
    ambiently available to any code path that ever calls
    ``dict(os.environ)``.

    Covered surfaces (CR PR #140 fix — the original guard had known
    bypasses):

    * ``<os-alias>.environ`` / ``<os-alias>.environb`` attribute reads.
    * ``<os-alias>.getenv(...)`` / ``<os-alias>.getenvb(...)`` calls.
    * ``<os-alias>.environ.get(...)`` chained reads.
    * Any bare ``Name`` read of a symbol imported from ``os`` via
      ``from os import environ`` (or any other env-reading name).
    """
    source = _STDIO_TRANSPORT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    os_aliases = _collect_os_aliases(tree)
    from_os_rebinds = _collect_from_os_rebinds(tree)

    # Hard fail if anyone re-imports ``environ`` / ``getenv`` / ``environb``
    # via ``from os import ...`` — the rebind itself is the foot-gun, even
    # before any read site appears.
    if from_os_rebinds:
        raise AssertionError(
            f"from-os import of host-env reader(s) {sorted(from_os_rebinds)} "
            "found in stdio_transport.py — use an explicit env= dict (spec §5.3)"
        )

    for node in ast.walk(tree):
        # (1) Attribute-access form: ``<os-alias>.environ``,
        #     ``<os-alias>.environb``, ``<os-alias>.getenv``,
        #     ``<os-alias>.getenvb`` — flag every leaf read regardless
        #     of whether it's called, awaited, subscripted, etc.
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in os_aliases
            and node.attr in _DISALLOWED_OS_ENV_NAMES
        ):
            raise AssertionError(
                f"{node.value.id}.{node.attr} read found in stdio_transport.py "
                "— use an explicit env= dict (spec §5.3)"
            )

        # (2) Chained read: ``<os-alias>.environ.get(...)``,
        #     ``<os-alias>.environb.get(...)``. The outer Attribute is
        #     ``.get`` (or any other method) whose value is the
        #     environ Attribute we already flag in (1) — but make the
        #     check explicit so the assertion message is precise.
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id in os_aliases
            and node.value.attr in _DISALLOWED_OS_ENV_NAMES
        ):
            raise AssertionError(
                f"{node.value.value.id}.{node.value.attr}.{node.attr} chained "
                "read found in stdio_transport.py — use an explicit env= dict "
                "(spec §5.3)"
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


# ---------------------------------------------------------------------------
# Self-test: the tripwire helpers must catch their target surfaces.
#
# These tests synthesize source strings that exercise each bypass CR
# flagged on PR #140, then run the same AST walkers against the source.
# A future change that narrows the walker would break these tests and
# surface the regression before a release lands.
# ---------------------------------------------------------------------------


def _walker_raises(source: str) -> bool:
    """Return True if the env-read AST walker flags ``source``."""
    tree = ast.parse(source)
    os_aliases = _collect_os_aliases(tree)
    from_os_rebinds = _collect_from_os_rebinds(tree)
    if from_os_rebinds:
        return True
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in os_aliases
            and node.attr in _DISALLOWED_OS_ENV_NAMES
        ):
            return True
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id in os_aliases
            and node.value.attr in _DISALLOWED_OS_ENV_NAMES
        ):
            return True
    return False


def test_tripwire_catches_os_environ_attribute_read() -> None:
    """``os.environ`` is flagged (original case)."""
    assert _walker_raises("import os\nx = os.environ\n")


def test_tripwire_catches_os_getenv_call() -> None:
    """``os.getenv("X")`` is flagged (CR PR #140 bypass)."""
    assert _walker_raises('import os\nx = os.getenv("X")\n')


def test_tripwire_catches_os_environb_read() -> None:
    """``os.environb`` is flagged (CR PR #140 bypass)."""
    assert _walker_raises("import os\nx = os.environb\n")


def test_tripwire_catches_aliased_os_environ_read() -> None:
    """``import os as o; o.environ`` is flagged (CR PR #140 bypass)."""
    assert _walker_raises("import os as o\nx = o.environ\n")


def test_tripwire_catches_chained_os_environ_get() -> None:
    """``os.environ.get("X")`` is flagged (CR PR #140 bypass)."""
    assert _walker_raises('import os\nx = os.environ.get("X")\n')


def test_tripwire_catches_from_os_import_environ_rebind() -> None:
    """``from os import environ`` is flagged at import time (CR PR #140 bypass).

    The rebind itself is the foot-gun — flagging at import means a
    bare ``environ`` read later in the file never gets a chance to
    bypass the walker.
    """
    assert _walker_raises("from os import environ\nx = environ\n")


def test_tripwire_catches_from_os_import_getenv_rebind() -> None:
    """``from os import getenv`` is flagged at import time (CR PR #140 bypass)."""
    assert _walker_raises('from os import getenv\nx = getenv("X")\n')


def test_tripwire_catches_from_os_import_environ_aliased() -> None:
    """``from os import environ as env`` is flagged (CR PR #140 bypass)."""
    assert _walker_raises("from os import environ as env\nx = env\n")


def test_tripwire_passes_clean_module() -> None:
    """Source that builds an explicit env dict from literals passes."""
    clean = """
import os

def spawn() -> None:
    env = {"PATH": "/usr/bin", "LANG": "C.UTF-8"}
    os.write(1, b"hello")
"""
    assert not _walker_raises(clean)
