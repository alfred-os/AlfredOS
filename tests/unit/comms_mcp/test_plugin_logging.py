"""Stderr-only JSON logging for stdio plugins (PR-S4-10 review F4, #206).

A comms-MCP stdio plugin must keep stdout pristine for JSON-RPC frames; its
logs go to stderr. These tests pin that invariant for the shared helper and
assert both plugin ``serve()`` entry points install it before the stdio loop.
"""

from __future__ import annotations

import ast
import inspect
import json
import sys

import pytest
import structlog

from alfred.comms_mcp.plugin_logging import configure_stderr_json_logging


@pytest.fixture(autouse=True)
def _reset_structlog() -> object:
    """Restore structlog's default config after each test (global state)."""
    yield
    structlog.reset_defaults()


def test_log_event_goes_to_stderr_not_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    """A log event lands on stderr as JSON; stdout stays empty for wire frames."""
    configure_stderr_json_logging()
    structlog.get_logger("plugin.test").info("hello", k="v")

    captured = capsys.readouterr()
    assert captured.out == "", "log leaked onto stdout — would corrupt JSON-RPC frames"
    payload = json.loads(captured.err.strip())
    assert payload["event"] == "hello"
    assert payload["k"] == "v"
    assert payload["level"] == "info"


def test_factory_pins_stderr_sink() -> None:
    """The configured logger factory writes to ``sys.stderr`` (not stdout)."""
    configure_stderr_json_logging()
    config = structlog.get_config()
    factory = config["logger_factory"]
    logger = factory()
    assert logger._file is sys.stderr  # type: ignore[attr-defined]


def _serve_source(module_name: str) -> str:
    import importlib

    mod = importlib.import_module(module_name)
    return inspect.getsource(mod.serve)


def _call_name(node: ast.Call) -> str | None:
    """The callee name for a call node (``ast.Name`` or ``ast.Attribute``)."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


@pytest.mark.parametrize(
    ("module_name", "loop_entry"),
    [
        # The TUI flipped to the unix-socket carrier (ADR-0031 PR-S4-237-2): its
        # loop entry is the co-host ``run_cohosted`` (Textual + the socket serve
        # loop), NOT the daemon-spawned stdio reader. The stderr-logging-first
        # invariant is identical — only the loop-entry symbol differs.
        ("alfred_tui.server", "run_cohosted"),
        ("plugins.alfred_discord.server", "_serve_stdin_stdout"),
    ],
)
def test_serve_configures_stderr_logging_first(module_name: str, loop_entry: str) -> None:
    """Each plugin ``serve()`` configures stderr logging BEFORE entering its loop.

    The docstring on this guard promises "before the loop", but merely asserting
    the call exists *somewhere* in ``serve()`` lets a regression that moves the
    config call *after* the loop pass silently. This asserts ordering: the
    ``configure_stderr_json_logging`` call must appear at a lower line than the
    plugin's loop entry (``run_cohosted`` for the socket-carried TUI,
    ``_serve_stdin_stdout`` for the stdio-carried Discord relay), so logs are
    stderr-bound before the first wire frame is read. (PR-S4-10 review #7.)
    """
    tree = ast.parse(_serve_source(module_name))
    cfg_lines = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_name(node) == "configure_stderr_json_logging"
    ]
    loop_lines = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_name(node) == loop_entry
    ]
    assert cfg_lines, f"{module_name}.serve() must call configure_stderr_json_logging()"
    assert loop_lines, f"{module_name}.serve() must call {loop_entry}()"
    assert min(cfg_lines) < min(loop_lines), (
        f"{module_name}.serve() must configure stderr JSON logging BEFORE entering "
        "its loop, not after — logs must be stderr-bound before the first frame."
    )
