"""#340 Task 1 — bind ``EGRESS_BROKER_REFUSED_REASONS`` to ``ControlFdBrokerError``'s vocab.

Same drift-guard shape as #432's ``test_sandbox_reason_vocab_sync.py``: the closed reason
vocabulary must be DERIVED from the exception source, never re-imported and compared to
itself (see ``domain_a_test_that_asks_the_code_if_the_code_is_right`` — an oracle that
restates the implementation passes through broken code).

**Two indirections this walk must see through** (both discovered while writing this test, not
present in the naive "match ``ControlFdBrokerError(...)`` call sites" form):

1. Five of the six reasons are raised as ``raise ControlFdBrokerError("some_reason")``
   directly, but two — ``ancillary_truncated`` and ``expected_exactly_one_fd`` — are raised via
   ``recv_passed_fd``'s local ``_refuse_and_close(reason: str)`` helper, which closes every
   leaked fd before constructing ``ControlFdBrokerError(reason)`` with the CALLER's string
   literal, not its own. A walk that only matches ``ControlFdBrokerError(...)`` call sites sees
   ``reason`` there as an ``ast.Name`` (a variable), not an ``ast.Constant`` — the two literals
   are attached to the ``_refuse_and_close(...)`` call one frame up. So the walk resolves BOTH
   call targets by name.

2. The sixth reason, ``control_fd_broker_failed``, is not raised as a literal ANYWHERE — it is
   the DEFAULT value of ``ControlFdBrokerError.__init__``'s ``reason`` parameter, and there is
   no bare ``ControlFdBrokerError()`` call site in the module for a call-site walk to see at
   all. Hardcoding it as a Python literal in this test file would make it a second stale copy
   of the same magic string — the exact tautology this file exists to prevent, just scoped to
   one member instead of all six. So it is read directly off the ``__init__`` signature's
   default value instead.
"""

from __future__ import annotations

import ast
from pathlib import Path

from alfred.audit.audit_row_schemas import EGRESS_BROKER_REFUSED_REASONS

_SOURCE = Path("src/alfred/egress/control_fd_broker.py")

# The two call targets that ultimately construct a ``ControlFdBrokerError`` with a string
# literal: the exception's own constructor (five direct raise sites) and the
# ``_refuse_and_close`` forwarding helper (the two fd-hygiene refusals). Named explicitly so a
# THIRD indirection (a future helper) fails loud here rather than silently under-counting —
# see ``test_derivation_is_not_vacuous`` below.
_CONSTRUCTING_CALL_NAMES = frozenset({"ControlFdBrokerError", "_refuse_and_close"})

_EXCEPTION_CLASS_NAME = "ControlFdBrokerError"


def _source_tree() -> ast.Module:
    return ast.parse(_SOURCE.read_text(encoding="utf-8"))


def _call_site_reasons(tree: ast.Module) -> set[str]:
    """String-literal args passed to ``ControlFdBrokerError`` or ``_refuse_and_close`` —
    positionally, or via a ``reason=`` keyword. Every real call site in
    ``control_fd_broker.py`` today is positional, but a keyword-form call site
    (``ControlFdBrokerError(reason="x")``) is legal Python the exception's signature
    already permits, so the walk must not blind itself to it (CodeRabbit #462)."""
    reasons: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") in _CONSTRUCTING_CALL_NAMES:
            candidates = [*node.args, *(kw.value for kw in node.keywords if kw.arg == "reason")]
            for arg in candidates:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    reasons.add(arg.value)
    return reasons


def _init_default_reason(tree: ast.Module) -> str:
    """The DEFAULT value of ``ControlFdBrokerError.__init__``'s ``reason`` parameter.

    ``control_fd_broker_failed`` is the bare-constructor fallback — no call site constructs
    ``ControlFdBrokerError()`` with zero args, so ``_call_site_reasons`` structurally cannot see
    it. Read it directly off the ``__init__`` signature instead of hardcoding the literal here,
    so a future rename of the default falls out of source, not a second stale copy of the
    magic string.
    """
    class_def = next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == _EXCEPTION_CLASS_NAME
        ),
        None,
    )
    assert class_def is not None, f"{_EXCEPTION_CLASS_NAME} class not found in {_SOURCE}"

    init_def = next(
        (
            node
            for node in class_def.body
            if isinstance(node, ast.FunctionDef) and node.name == "__init__"
        ),
        None,
    )
    assert init_def is not None, f"{_EXCEPTION_CLASS_NAME}.__init__ not found"

    # Positional match: `defaults` right-aligns to the trailing names of posonlyargs+args
    # (the standard Python arg/default pairing rule — a parameter can only carry a default if
    # every parameter after it also does).
    positional = [*init_def.args.posonlyargs, *init_def.args.args]
    names = [a.arg for a in positional]
    assert "reason" in names, f"{_EXCEPTION_CLASS_NAME}.__init__ has no `reason` parameter"
    reason_index = names.index("reason")
    defaults_start = len(positional) - len(init_def.args.defaults)
    default_index = reason_index - defaults_start
    assert 0 <= default_index < len(init_def.args.defaults), (
        f"{_EXCEPTION_CLASS_NAME}.__init__'s `reason` parameter has no default value"
    )

    default_node = init_def.args.defaults[default_index]
    assert isinstance(default_node, ast.Constant) and isinstance(default_node.value, str), (
        f"{_EXCEPTION_CLASS_NAME}.__init__'s `reason` default is not a string literal: "
        f"{ast.dump(default_node)}"
    )
    return default_node.value


def _controlfdbrokererror_reasons() -> set[str]:
    # Independently derive the FULL reason vocab from control_fd_broker.py's source: the
    # string literals ControlFdBrokerError is raised with (directly, or forwarded through
    # `_refuse_and_close`) UNION the default value of its `reason` __init__ parameter. This
    # test does NOT reuse EGRESS_BROKER_REFUSED_REASONS as its own oracle.
    tree = _source_tree()
    return _call_site_reasons(tree) | {_init_default_reason(tree)}


def test_broker_reason_vocab_matches_exception_source() -> None:
    assert EGRESS_BROKER_REFUSED_REASONS == _controlfdbrokererror_reasons()  # noqa: SIM300


def test_derivation_is_not_vacuous() -> None:
    """Floor the derived set at 6 — `set() == set()` is the canonical vacuous green
    (domain_paper_only_gates). A future refactor that hides a reason behind a THIRD call-site
    indirection this walk doesn't know about, or changes the `__init__` default to a
    non-literal, would silently under-count; this floor catches that even if it happened to
    still equal a (wrongly shrunk) constant. Covers both source paths: the five call-site
    literals + the `_refuse_and_close` forwarding pair, AND the `__init__` default-parameter
    path for the sixth.
    """
    derived = _controlfdbrokererror_reasons()
    assert len(derived) == 6, f"expected 6 reasons, derived {len(derived)}: {sorted(derived)}"


def test_call_site_walk_sees_keyword_form_reason() -> None:
    """Regression (CodeRabbit #462): ``_call_site_reasons`` must pick up a keyword-form
    ``reason=`` call site, not only the positional form every real call site in
    ``control_fd_broker.py`` uses today. A future call site written as
    ``ControlFdBrokerError(reason="some_new_reason")`` would otherwise slip past this
    drift-guard's walk entirely — silently under-counting, the exact failure mode this
    file exists to prevent.
    """
    synthetic_tree = ast.parse('ControlFdBrokerError(reason="synthetic_keyword_reason")')
    assert _call_site_reasons(synthetic_tree) == {"synthetic_keyword_reason"}
