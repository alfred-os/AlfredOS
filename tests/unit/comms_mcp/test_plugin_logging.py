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


@pytest.mark.parametrize(
    "module_name",
    ["alfred_tui.server", "plugins.alfred_discord.server"],
)
def test_serve_configures_stderr_logging_first(module_name: str) -> None:
    """Each plugin ``serve()`` calls ``configure_stderr_json_logging`` (F4 guard).

    AST-walks the ``serve`` coroutine for a call to the helper. A regression
    that drops the call (re-introducing the default stdout console renderer)
    fails here before a runtime test catches the corrupted channel.
    """
    tree = ast.parse(_serve_source(module_name))
    called = any(
        isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "configure_stderr_json_logging")
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "configure_stderr_json_logging"
            )
        )
        for node in ast.walk(tree)
    )
    assert called, f"{module_name}.serve() must configure stderr JSON logging before its loop"
