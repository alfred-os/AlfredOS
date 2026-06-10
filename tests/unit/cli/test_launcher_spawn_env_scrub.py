"""Env-scrub guards for :mod:`alfred.cli._launcher_spawn` (PR-S4-10 review F2, #206).

Two layers, mirroring the stdio-transport precedent
(``tests/unit/plugins/test_env_scrub_subprocess.py``):

1. **Runtime** — the child env the launcher-spawn seam builds is SCRUBBED for
   an adversary-facing (``sandbox_kind != "none"``) plugin like the Discord
   relay (``kind="full"``, open egress per #230). An operator's exported
   ``ANTHROPIC_API_KEY`` / ``DISCORD_BOT_TOKEN`` must NOT cross into that
   child. The operator-local TUI (``kind="none"``) keeps full passthrough
   because the operator IS the trusted user and Textual needs the inherited
   session env.

2. **AST static guard** — the minimal-env builder
   (:func:`alfred.cli._launcher_spawn._minimal_child_env`) must never read the
   host env via a full ``dict(os.environ)`` / bare-environ surface. The guard
   walks that function's AST so any future patch that re-introduces a blanket
   passthrough into the adversary-facing path fails CI before a runtime test
   catches the leak.

Why a function-scoped guard rather than the whole module (unlike
stdio_transport): ``_launcher_spawn`` LEGITIMATELY reads ``os.environ`` for the
launcher path and for the ``kind="none"`` operator-local full passthrough. The
release-blocking invariant is narrower — the *minimal* (scrubbed) builder that
feeds the adversary-facing child must hold no full-env read.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from alfred.cli import _launcher_spawn
from alfred.cli._launcher_spawn import PluginLaunchSpec, _child_env


def _spec(sandbox_kind: str) -> PluginLaunchSpec:
    return PluginLaunchSpec(
        plugin_id="alfred_x",
        manifest_path=Path("/opt/alfred/manifest.toml"),
        module="x.server",
        adapter_id="x-instance",
        import_roots=(Path("/opt/alfred/src"),),
        inherit_stdio=False,
        sandbox_kind=sandbox_kind,
    )


# ---------------------------------------------------------------------------
# Runtime: the adversary-facing (kind != "none") child env is scrubbed.
# ---------------------------------------------------------------------------

_SECRET_NAMES = ("ANTHROPIC_API_KEY", "DISCORD_BOT_TOKEN", "OPENAI_API_KEY")


def test_full_kind_child_env_scrubs_operator_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``kind="full"`` (Discord) child env carries none of the operator's secrets."""
    for name in _SECRET_NAMES:
        monkeypatch.setenv(name, "super-secret-value")

    env = _child_env(_spec("full"))

    for name in _SECRET_NAMES:
        assert name not in env, f"{name} leaked into the adversary-facing child env"
    # The values must not survive under any other key either.
    assert "super-secret-value" not in env.values()


def test_full_kind_child_env_preserves_spec_and_launcher_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The scrubbed env still carries the spec-derived + launcher control vars."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "leak-me")

    env = _child_env(_spec("full"))

    assert env["ALFRED_PLUGIN_MANIFEST_PATH"] == "/opt/alfred/manifest.toml"
    assert env["ALFRED_PLUGIN_ADAPTER_ID"] == "x-instance"
    assert "/opt/alfred/src" in env["PYTHONPATH"]
    # The launcher itself needs ALFRED_ENVIRONMENT to resolve its sandbox policy.
    assert env["ALFRED_ENVIRONMENT"] == "production"
    assert "PATH" in env
    assert "ANTHROPIC_API_KEY" not in env


def test_none_kind_child_env_passes_operator_env_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator-local TUI (``kind="none"``) keeps full passthrough.

    The operator IS the trusted user and the foreground Textual app needs the
    inherited session env; scrubbing here would be a regression, not a fix.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "operator-local-ok")

    env = _child_env(_spec("none"))

    assert env["ANTHROPIC_API_KEY"] == "operator-local-ok"
    assert env["ALFRED_PLUGIN_MANIFEST_PATH"] == "/opt/alfred/manifest.toml"
    assert "/opt/alfred/src" in env["PYTHONPATH"]


# ---------------------------------------------------------------------------
# AST static guard: the minimal-env builder reads no full host-env surface.
# ---------------------------------------------------------------------------

#: The host-env reader surfaces. A per-key allowlisted read
#: (``os.environ[name]`` subscript, ``name in os.environ`` membership) is the
#: SANCTIONED minimal-env pattern and is NOT a foot-gun — the guard targets the
#: BLANKET copies (``dict(os.environ)``, ``os.environ.copy()``) and the
#: single-shot host reads (``os.getenv``) that re-leak the full secret-bearing
#: surface.
_ENVIRON_NAMES = frozenset({"environ", "environb"})
_GETENV_NAMES = frozenset({"getenv", "getenvb"})


def _function_source(name: str) -> str:
    return inspect.getsource(getattr(_launcher_spawn, name))


def _is_os_environ(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
        and node.attr in _ENVIRON_NAMES
    )


def _reads_full_env(source: str) -> bool:
    """True if ``source`` copies the WHOLE host env (the F2 foot-gun).

    Flags the blanket-copy surfaces that re-leak every operator secret:

    * ``dict(os.environ)`` / ``dict(os.environb)`` — wholesale dict copy.
    * ``os.environ.copy()`` — same via the mapping method.
    * ``os.getenv(...)`` / ``os.getenvb(...)`` — single host read (no
      allowlist gate; trivially loops to a full leak).

    Does NOT flag the allowlisted ``os.environ[name]`` subscript or
    ``name in os.environ`` membership — those are the sanctioned minimal-env
    primitives the builder is REQUIRED to use.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # dict(os.environ) / dict(os.environb)
        if (
            isinstance(func, ast.Name)
            and func.id == "dict"
            and any(_is_os_environ(a) for a in node.args)
        ):
            return True
        # os.environ.copy()
        if isinstance(func, ast.Attribute) and func.attr == "copy" and _is_os_environ(func.value):
            return True
        # os.getenv(...) / os.getenvb(...)
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
            and func.attr in _GETENV_NAMES
        ):
            return True
    return False


def test_minimal_child_env_builder_reads_no_full_host_env() -> None:
    """``_minimal_child_env`` builds the adversary-facing env from an allowlist.

    Release-blocker: a future patch that re-introduces ``dict(os.environ)`` (or
    any bare-environ read) inside the minimal builder would re-leak the
    operator's secrets into the ``kind="full"`` Discord child. The guard is
    scoped to this one function so the legitimate launcher-path /
    ``kind="none"`` reads elsewhere in the module stay allowed.
    """
    assert not _reads_full_env(_function_source("_minimal_child_env")), (
        "_minimal_child_env reads the full host env — build the adversary-facing "
        "child env from an explicit allowlist (PR-S4-10 review F2)"
    )


def test_guard_helper_catches_full_env_read() -> None:
    """Self-test: the AST helper flags blanket copies but allows allowlist reads."""
    # Foot-guns the guard MUST catch.
    assert _reads_full_env("import os\ndef f():\n    return dict(os.environ)\n")
    assert _reads_full_env("import os\ndef f():\n    return os.environ.copy()\n")
    assert _reads_full_env("import os\ndef f():\n    return os.getenv('X')\n")
    # Sanctioned minimal-env primitives the guard MUST allow.
    assert not _reads_full_env("def f():\n    return {'PATH': '/usr/bin'}\n")
    assert not _reads_full_env(
        "import os\ndef f():\n    return {k: os.environ[k] for k in ('PATH',) if k in os.environ}\n"
    )
