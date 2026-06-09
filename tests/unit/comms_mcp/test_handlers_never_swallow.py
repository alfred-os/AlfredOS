"""AST guard: comms handlers never silently swallow an exception (Task 60).

cib-2026-005 codifies that the dispatcher's contract is "handlers MUST raise" —
a handler that swallows its own exception is invisible to the loud
``COMMS_HANDLER_FAILED_FIELDS`` path. This guard walks every concrete handler's
``process`` method body in :mod:`alfred.comms_mcp.handlers` and refuses any
``except`` clause that swallows: it flags a clause with NO ``raise`` anywhere in
its body whose FINAL statement is a trailing ``pass``, bare ``return``, or
``return None`` — so a multi-statement swallow (``except: log(...); return``) is
caught, not only the single-statement form. A regression that adds an exception-
swallowing handler is a collection-time failure, not a silent trust-boundary hole.
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


def _except_swallows(handler: ast.ExceptHandler) -> str | None:
    """Return a swallow description for ``handler``, or ``None`` if it propagates.

    An except body swallows if NO ``raise`` appears anywhere within it (including
    nested blocks) AND its FINAL statement ends the clause without propagating — a
    trailing ``pass``, bare ``return``, or ``return None``. Checking the *last*
    statement (not only a single-statement body) catches the multi-statement
    swallow ``except: log(...); return`` the earlier single-stmt guard missed.
    """
    if any(isinstance(stmt, ast.Raise) for stmt in ast.walk(handler)):
        return None
    final_stmt = handler.body[-1] if handler.body else None
    if isinstance(final_stmt, ast.Pass):
        return "`except: ...; pass`"
    if isinstance(final_stmt, ast.Return) and (
        final_stmt.value is None
        or (isinstance(final_stmt.value, ast.Constant) and final_stmt.value.value is None)
    ):
        return "`except: ...; return None`"
    return None


def _swallows(handler_node: ast.AST) -> list[str]:
    """Return a list of swallowing-except descriptions found in ``handler_node``."""
    return [
        offence
        for node in ast.walk(handler_node)
        if isinstance(node, ast.ExceptHandler) and (offence := _except_swallows(node)) is not None
    ]


def test_handlers_module_has_no_swallowing_except() -> None:
    source = Path(inspect.getfile(handlers)).read_text()
    tree = ast.parse(source)
    offences: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "process":
            found = _swallows(node)
            if found:
                # Human-readable, collision-resistant key: method name + line.
                offences[f"{node.name}:L{node.lineno}"] = found
    assert offences == {}, f"comms handler process() bodies swallow exceptions: {offences}"


def test_every_concrete_handler_has_a_process_method() -> None:
    """Sanity: the guard above is scanning real handlers, not an empty set."""
    for handler_cls in _CONCRETE_HANDLERS:
        assert hasattr(handler_cls, "process")
