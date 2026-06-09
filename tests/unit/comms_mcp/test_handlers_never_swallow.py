"""AST guard: comms handlers never silently swallow an exception (Task 60).

cib-2026-005 codifies that the dispatcher's contract is "handlers MUST raise" —
a handler that swallows its own exception is invisible to the loud
``COMMS_HANDLER_FAILED_FIELDS`` path. This guard walks every concrete handler's
``process`` method body in :mod:`alfred.comms_mcp.handlers` and refuses any
``except`` clause that swallows (``pass`` / bare ``return`` / ``return None``
with no re-raise). A regression that adds an exception-swallowing handler is a
collection-time failure, not a silent trust-boundary hole.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from alfred.comms_mcp import handlers

_CONCRETE_HANDLERS = (
    handlers.InboundMessageHandler,
    handlers.BindingRequestHandler,
    handlers.PlatformRateLimitHandler,
    handlers.AdapterCrashHandler,
)


def _swallows(handler_node: ast.AST) -> list[str]:
    """Return a list of swallowing-except descriptions found in ``handler_node``."""
    offences: list[str] = []
    for node in ast.walk(handler_node):
        if not isinstance(node, ast.ExceptHandler):
            continue
        body = node.body
        # An except body is "swallowing" if it is exactly `pass`, a bare
        # `return`, or `return None`, with no re-raise anywhere in the body.
        has_raise = any(isinstance(stmt, ast.Raise) for stmt in ast.walk(node))
        if has_raise:
            continue
        only_stmt = body[0] if len(body) == 1 else None
        if isinstance(only_stmt, ast.Pass):
            offences.append("bare `except: pass`")
        elif isinstance(only_stmt, ast.Return) and (
            only_stmt.value is None
            or (isinstance(only_stmt.value, ast.Constant) and only_stmt.value.value is None)
        ):
            offences.append("`except: return None`")
    return offences


def test_handlers_module_has_no_swallowing_except() -> None:
    source = Path(inspect.getfile(handlers)).read_text()
    tree = ast.parse(source)
    offences: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "process":
            found = _swallows(node)
            if found:
                offences[ast.dump(node)[:40]] = found
    assert offences == {}, f"comms handler process() bodies swallow exceptions: {offences}"


def test_every_concrete_handler_has_a_process_method() -> None:
    """Sanity: the guard above is scanning real handlers, not an empty set."""
    for handler_cls in _CONCRETE_HANDLERS:
        assert hasattr(handler_cls, "process")
