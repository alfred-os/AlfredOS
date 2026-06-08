"""Validator works on cold CLI start — issue #151 acceptance.

Boots a fresh Python interpreter (no shared sys.modules pollution
from other test modules) and verifies validate_hookpoint succeeds
against the manifest without forcing any subsystem's
declare_hookpoints() to run first.

Mirrors the pattern at tests/unit/cli/test_main_lazy_imports.py:
subprocess.run(sys.executable, "-c", ...) so other tests' import side
effects can't leak.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap


def _run_in_fresh_python(script: str) -> subprocess.CompletedProcess[str]:
    # ``-I`` (isolated mode) mirrors ``tests/unit/cli/test_main_lazy_imports.py``:
    # it disables ``sitecustomize``, ignores ``PYTHONPATH``, and ignores the
    # user site directory so the child interpreter cannot inherit an
    # environment that silently pre-imports ``alfred.*`` modules before the
    # test's assertion runs. ``timeout=10`` keeps a hung subprocess from
    # stalling CI — the validator's cold-start path completes in well under
    # a second on the dev mac, so 10s is a generous ceiling.
    return subprocess.run(  # noqa: S603 - sys.executable + literal script, no untrusted input
        [sys.executable, "-I", "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def test_validate_hookpoint_succeeds_on_cold_start_for_grant_requested() -> None:
    """The #149 CR-1 use case: alfred plugin grant on a freshly-spawned
    Python process. validate_hookpoint("plugin.grant.requested") must
    succeed without first importing alfred.security.capability_gate.proposals.
    """
    result = _run_in_fresh_python("""
        from alfred.cli._validators import validate_hookpoint
        out = validate_hookpoint("plugin.grant.requested")
        print(f"OK:{out}")
    """)
    assert result.returncode == 0, f"validator failed on cold start. stderr={result.stderr!r}"
    assert result.stdout.strip() == "OK:plugin.grant.requested"


def test_validate_hookpoint_succeeds_on_cold_start_for_web_fetch() -> None:
    """Cross-subsystem cold-start check: tool.web.fetch lives in
    alfred.plugins.web_fetch which the CLI doesn't necessarily import.
    """
    result = _run_in_fresh_python("""
        from alfred.cli._validators import validate_hookpoint
        out = validate_hookpoint("tool.web.fetch")
        print(f"OK:{out}")
    """)
    assert result.returncode == 0, f"validator failed on cold start. stderr={result.stderr!r}"
    assert result.stdout.strip() == "OK:tool.web.fetch"


def test_validate_hookpoint_rejects_unknown_on_cold_start() -> None:
    """An unknown hookpoint name MUST be rejected at parse time even on
    cold start — the validator's defensive contract is import-order-
    independent.
    """
    result = _run_in_fresh_python("""
        import typer
        from alfred.cli._validators import validate_hookpoint
        try:
            validate_hookpoint("nonexistent.event")
            print("WRONG: validator accepted unknown hookpoint")
        except typer.BadParameter as exc:
            print(f"REJECTED:{type(exc).__name__}")
    """)
    assert result.returncode == 0, f"subprocess crashed: {result.stderr!r}"
    assert "REJECTED:BadParameter" in result.stdout, result.stdout


def test_validate_hookpoint_does_not_force_subsystem_imports() -> None:
    """The validator MUST NOT import the heavy chain transitively.

    Cold-start invocation should NOT load any subsystem listed in the
    canonical hookpoint manifest (``KNOWN_HOOKPOINTS`` keys). Otherwise the
    perf-001 lazy-import discipline is silently defeated.

    The forbidden set is auto-derived from ``KNOWN_HOOKPOINTS.keys()`` so a
    future addition (a sixth declarer subsystem) is automatically covered
    without an edit here.
    """
    from alfred.hooks._known_hookpoints import KNOWN_HOOKPOINTS

    # Render the forbidden tuple once in the parent process and inline its
    # ``repr`` into the child script. ``repr`` produces a literal Python
    # tuple of string constants — safe to interpolate via ``str.replace``
    # without f-string nesting / brace-escaping landmines.
    #
    # ``alfred.hooks._known_hookpoints`` is excluded from the forbidden
    # set: it is the manifest module itself, which the validator imports
    # by definition (it reads ``all_known_hookpoints`` from it). PR-S4-3
    # added the carrier-substitution meta-hookpoints under this module's
    # own key (they are declared by ``declare_meta_hookpoints`` at
    # bootstrap, not by importing a heavyweight subsystem). The cold-start
    # guarantee is about not pulling in the SUBSYSTEM declarers (memory,
    # identity, security, supervisor) — not the always-loaded manifest.
    manifest_module = "alfred.hooks._known_hookpoints"
    forbidden_repr = repr(tuple(k for k in KNOWN_HOOKPOINTS if k != manifest_module))
    script_template = """
        import sys
        from alfred.cli._validators import validate_hookpoint
        validate_hookpoint("plugin.grant.requested")
        # After validation, NONE of the manifest's declarer modules should
        # be loaded. The tuple below is generated in the parent process
        # from ``KNOWN_HOOKPOINTS.keys()`` so this list cannot drift from
        # the manifest.
        forbidden = __FORBIDDEN__
        for mod in forbidden:
            assert mod not in sys.modules, f"validator leaked import of {mod}"
        print("OK")
    """
    result = _run_in_fresh_python(script_template.replace("__FORBIDDEN__", forbidden_repr))
    assert result.returncode == 0, (
        f"validator forced subsystem imports on cold start. "
        f"stderr={result.stderr!r}, stdout={result.stdout!r}"
    )
    assert result.stdout.strip() == "OK"
