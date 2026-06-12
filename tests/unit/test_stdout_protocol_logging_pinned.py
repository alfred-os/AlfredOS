"""Stdout-protocol entrypoints pin logging to stderr first (PR-S4-11c-2b0 BUG-1).

Mirrors the PR-S4-11a precedent ``tests/unit/comms_mcp/test_plugin_logging.py``
(``test_serve_configures_stderr_logging_first``), which asserts a comms plugin's
``serve()`` calls ``configure_stderr_json_logging`` BEFORE entering its stdio loop.
Here the same ordering invariant is asserted for the two non-structlog stdout
entrypoints:

* :mod:`alfred.plugins.manifest_reader` — ``configure_stderr_logging()`` must run
  at MODULE scope BEFORE the transitive ``from alfred...`` imports (which load the
  i18n translator and its import-time missing-catalog warning); and
* :mod:`alfred.security.quarantine_child.__main__` — ``main()`` must call
  ``configure_stderr_logging()`` BEFORE the fd-3 read / ``_run_mcp_server`` loop.

An AST walk pins the ordering so a regression that moves the pin *after* the first
stdout write passes no longer slips through silently.
"""

from __future__ import annotations

import ast
import inspect

from alfred.plugins import manifest_reader
from alfred.security.quarantine_child import __main__ as quarantine_child


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _call_lines(tree: ast.AST, callee: str) -> list[int]:
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_name(node) == callee
    ]


def test_manifest_reader_pins_stderr_before_alfred_imports() -> None:
    """The module pins stderr logging BEFORE the ``from alfred...`` imports.

    The translator's missing-catalog warning fires at import time, transitively
    via those imports. Pinning must come first so the warning can never reach the
    stdout the launcher captures as bwrap flags.
    """
    tree = ast.parse(inspect.getsource(manifest_reader))
    cfg_lines = _call_lines(tree, "configure_stderr_logging")
    assert cfg_lines, "manifest_reader must call configure_stderr_logging() at module scope"

    # The pin-helper import itself is exempt: ``alfred._stdio_logging`` logs
    # nothing and must precede the call. The guard is that every OTHER
    # ``from alfred...`` import (which may transitively log at import time) comes
    # AFTER the call.
    guarded_import_lines = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.startswith("alfred.")
        and node.module != "alfred._stdio_logging"
    ]
    assert guarded_import_lines, "expected at least one `from alfred...` import to guard"
    assert min(cfg_lines) < min(guarded_import_lines), (
        "configure_stderr_logging() must run BEFORE the first logging-capable "
        "`from alfred...` import so the translator's import-time warning cannot reach stdout"
    )


def test_quarantine_child_main_pins_stderr_before_loop() -> None:
    """``main()`` pins stderr logging BEFORE the fd-3 read and the stdio loop."""
    tree = ast.parse(inspect.getsource(quarantine_child.main))
    cfg_lines = _call_lines(tree, "configure_stderr_logging")
    fd3_lines = _call_lines(tree, "_read_provider_key_from_fd3")
    loop_lines = _call_lines(tree, "_run_mcp_server")

    assert cfg_lines, "quarantine child main() must call configure_stderr_logging()"
    assert fd3_lines and loop_lines, "expected the fd-3 read + loop entry to guard against"
    assert min(cfg_lines) < min(fd3_lines), (
        "configure_stderr_logging() must run BEFORE the fd-3 read"
    )
    assert min(cfg_lines) < min(loop_lines), (
        "configure_stderr_logging() must run BEFORE the stdio loop — logs must be "
        "stderr-bound before the first reply frame is written to stdout"
    )
