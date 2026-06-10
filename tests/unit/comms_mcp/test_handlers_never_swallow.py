"""AST guard: comms handlers never silently swallow an exception (Task 60).

cib-2026-005 codifies that the dispatcher's contract is "handlers MUST raise" —
a handler that swallows its own exception is invisible to the loud
``COMMS_HANDLER_FAILED_FIELDS`` path. This guard walks every concrete handler's
``process`` method body in :mod:`alfred.comms_mcp.handlers` and refuses any
``except`` clause that does NOT re-raise in its own control flow.

Hardened detection (CR #232 escalation). A clause swallows unless a ``raise``
appears in its OWN frame — directly in the body, or nested inside same-frame
control flow (``if`` / ``for`` / ``while`` / ``with`` / inner ``try``). Two holes
the earlier "trailing pass / return None" check missed are now closed:

* **deferred raise** — a ``raise`` inside an inner ``def`` / ``class`` /
  ``lambda`` does NOT count: that code does not run when the ``except`` fires, so
  the walk does not descend into nested scopes.
* **swallowing fall-through** — an ``except`` whose body ends in anything other
  than a re-raise (``log(...); return value``, a bare expression, an early
  ``return value``) swallows just as surely as ``pass``; the guard flags ANY
  clause with no same-frame reachable ``raise``, not only the trailing-pass /
  return-None shapes.

A regression that adds an exception-swallowing handler is a collection-time
failure, not a silent trust-boundary hole.
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

# Nodes that open a NEW frame — a ``raise`` inside one of these does not run when
# the surrounding ``except`` fires, so the same-frame walk must not descend.
_NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _has_same_frame_raise(node: ast.AST) -> bool:
    """True if a ``raise`` is reachable in ``node``'s own frame (no nested scopes).

    Walks ``node``'s children but stops at any nested ``def`` / ``class`` /
    ``lambda`` boundary — a ``raise`` deferred into such a scope does not
    propagate when the enclosing ``except`` fires, so it must not satisfy the
    re-raise requirement.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Raise):
            return True
        if isinstance(child, _NESTED_SCOPES):
            continue
        if _has_same_frame_raise(child):
            return True
    return False


def _except_swallows(handler: ast.ExceptHandler) -> str | None:
    """Return a swallow description for ``handler``, or ``None`` if it re-raises.

    An ``except`` clause swallows unless a ``raise`` is reachable in its OWN frame
    (CR #232): a raise deferred into a nested ``def`` / ``class`` / ``lambda``
    does not count, and a clause that simply falls through without re-raising —
    whatever its final statement — is a swallow.
    """
    for stmt in handler.body:
        if isinstance(stmt, _NESTED_SCOPES):
            # A nested ``def`` / ``class`` at the top of the except body is a
            # deferred frame — a ``raise`` inside it does not run now.
            continue
        if isinstance(stmt, ast.Raise) or _has_same_frame_raise(stmt):
            return None
    return "`except:` without a same-frame re-raise"


def _swallows(handler_node: ast.AST) -> list[str]:
    """Return a list of swallowing-except descriptions found in ``handler_node``."""
    return [
        offence
        for node in ast.walk(handler_node)
        if isinstance(node, ast.ExceptHandler) and (offence := _except_swallows(node)) is not None
    ]


def _swallows_in_source(source: str) -> list[str]:
    """Parse ``source`` and return swallow offences across every ``except`` clause."""
    return _swallows(ast.parse(source))


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


# --- hardened-detection synthetic cases (CR #232) ---------------------------


def test_guard_flags_bare_pass() -> None:
    src = "def f():\n    try:\n        g()\n    except Exception:\n        pass\n"
    assert _swallows_in_source(src) != []


def test_guard_flags_return_none() -> None:
    src = (
        "def f():\n    try:\n        g()\n    except Exception:\n"
        "        log()\n        return None\n"
    )
    assert _swallows_in_source(src) != []


def test_guard_flags_swallowing_fall_through_return_value() -> None:
    # An early ``return value`` (not None) without a re-raise still swallows —
    # the prior trailing-pass / return-None check missed this.
    src = (
        "def f():\n    try:\n        g()\n    except Exception:\n        log()\n        return 42\n"
    )
    assert _swallows_in_source(src) != []


def test_guard_flags_log_only_body() -> None:
    src = "def f():\n    try:\n        g()\n    except Exception:\n        log('boom')\n"
    assert _swallows_in_source(src) != []


def test_guard_flags_raise_deferred_into_nested_def() -> None:
    # A ``raise`` inside an inner def does NOT run when the except fires, so the
    # clause still swallows. The prior ``ast.walk`` saw the nested raise and
    # wrongly cleared the clause.
    src = (
        "def f():\n"
        "    try:\n"
        "        g()\n"
        "    except Exception:\n"
        "        def _later():\n"
        "            raise RuntimeError('not now')\n"
        "        return None\n"
    )
    assert _swallows_in_source(src) != []


def test_guard_flags_raise_deferred_into_lambda() -> None:
    src = (
        "def f():\n"
        "    try:\n"
        "        g()\n"
        "    except Exception:\n"
        "        cb = lambda: (_ for _ in ()).throw(RuntimeError())\n"
        "        return cb\n"
    )
    assert _swallows_in_source(src) != []


def test_guard_accepts_direct_reraise() -> None:
    src = "def f():\n    try:\n        g()\n    except Exception:\n        log()\n        raise\n"
    assert _swallows_in_source(src) == []


def test_guard_accepts_conditional_reraise() -> None:
    # A re-raise reachable via same-frame control flow (an ``if`` branch) counts
    # as propagation -- the guard must not flag it.
    src = (
        "def f():\n"
        "    try:\n"
        "        g()\n"
        "    except Exception as exc:\n"
        "        if recoverable(exc):\n"
        "            return None\n"
        "        raise\n"
    )
    assert _swallows_in_source(src) == []


def test_guard_accepts_reraise_nested_in_with() -> None:
    src = (
        "def f():\n"
        "    try:\n"
        "        g()\n"
        "    except Exception:\n"
        "        with ctx():\n"
        "            raise\n"
    )
    assert _swallows_in_source(src) == []
