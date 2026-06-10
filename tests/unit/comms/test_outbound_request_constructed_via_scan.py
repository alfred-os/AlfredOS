"""AST guard: every ``OutboundMessageRequest`` body passes through DLP scan.

PR-S4-8 round-2 closure #1 (sec-001 CRITICAL + comms-002 HIGH). The comms
``OutboundMessageRequest.body`` field is typed ``ScannedOutboundBody`` — a
``NewType`` minted ONLY by ``OutboundDlp.scan_for_outbound``. The type system
already forces this at construction sites the type-checker sees, but the
defence-in-depth guard here statically walks **every** ``OutboundMessageRequest(...)``
call site in ``src/`` and refuses any whose ``body=`` argument is not the
return value of a ``scan_for_outbound(...)`` call within the same function
scope (a local name bound to such a call, or the call inline).

Why a static guard on top of the type: a future contributor could
``# type: ignore`` a hand-rolled tuple, or feed a value typed ``Any`` into
``body=``. The AST walk has no escape hatch — it sees the source, not the
inferred type — so the DLP chokepoint cannot be bypassed by silencing mypy.

This PR ships zero production construction sites (PR-S4-9/10 add them); the
live-repo scan therefore asserts an empty violation set today and the
synthetic-source cases prove the guard bites when a site is added.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "alfred"
_TARGET_CALL = "OutboundMessageRequest"
_SCAN_FN = "scan_for_outbound"


_ScopeNode = ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef


def _scan_bound_names(scope: ast.AST) -> set[str]:
    """Names in ``scope`` bound to a ``scan_for_outbound(...)`` return value."""
    bound: set[str] = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign) and _is_scan_call(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bound.add(target.id)
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and _is_scan_call(node.value)
            and isinstance(node.target, ast.Name)
        ):
            bound.add(node.target.id)
    return bound


def _is_scan_call(node: ast.expr | None) -> bool:
    """True if ``node`` is a call to ``...scan_for_outbound(...)``."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr == _SCAN_FN
    return isinstance(func, ast.Name) and func.id == _SCAN_FN


def _body_arg(call: ast.Call) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == "body":
            return kw.value
    return None


def _nearest_scope(node: ast.AST) -> _ScopeNode | None:
    """Return the innermost enclosing scope (module / func / class) for ``node``.

    Climbs the ``parent`` chain set by :func:`_violations_in_source`. A call's
    own scope is the first scope node strictly ABOVE it, so the climb starts at
    the parent — this keeps a construction attributed to the scope it lives in.
    """
    current: ast.AST | None = getattr(node, "parent", None)
    while current is not None:
        if isinstance(current, _ScopeNode):
            return current
        current = getattr(current, "parent", None)
    return None


def _violations_in_source(source: str, *, filename: str) -> list[str]:
    """Return human-readable violation strings for one source file/string.

    Covers EVERY scope — module body, class body, and (async) function body —
    not just functions (CR #232): a module- or class-scope construction must not
    slip past the DLP chokepoint guard. Each ``OutboundMessageRequest(...)`` call
    is attributed to its nearest enclosing scope so it is checked exactly once
    against that scope's ``scan_for_outbound`` bindings (no double-counting, no
    cross-scope name leakage).
    """
    tree = ast.parse(source, filename=filename)

    # Link every node to its parent so a construction call can climb to its
    # nearest enclosing scope, and pre-compute each scope's scan-bound names.
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    scan_names_by_scope: dict[_ScopeNode, set[str]] = {
        scope: _scan_bound_names(scope) for scope in ast.walk(tree) if isinstance(scope, _ScopeNode)
    }

    violations: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_call_to(node, _TARGET_CALL)):
            continue
        scope = _nearest_scope(node)
        scan_names = scan_names_by_scope.get(scope, set()) if scope is not None else set()
        body = _body_arg(node)
        ok = body is not None and (
            _is_scan_call(body) or (isinstance(body, ast.Name) and body.id in scan_names)
        )
        if not ok:
            violations.append(f"{filename}:{node.lineno}: body= not via {_SCAN_FN}")
    return violations


def _is_call_to(call: ast.Call, name: str) -> bool:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id == name
    return isinstance(func, ast.Attribute) and func.attr == name


def test_no_unscanned_outbound_construction_in_src() -> None:
    all_violations: list[str] = []
    for py in _SRC_ROOT.rglob("*.py"):
        source = py.read_text(encoding="utf-8")
        if _TARGET_CALL not in source:
            continue
        all_violations.extend(_violations_in_source(source, filename=str(py)))
    assert all_violations == [], "Unscanned outbound construction sites:\n" + "\n".join(
        all_violations
    )


def test_guard_accepts_inline_scan_call() -> None:
    source = (
        "def f(dlp, raw):\n"
        "    return OutboundMessageRequest(\n"
        "        adapter_id='alfred_comms_test', idempotency_key=k,\n"
        "        target_platform_id='c', body=dlp.scan_for_outbound(raw),\n"
        "        attachments_refs=(), addressing_mode='dm',\n"
        "    )\n"
    )
    assert _violations_in_source(source, filename="<inline>") == []


def test_guard_accepts_local_bound_to_scan() -> None:
    source = (
        "def f(dlp, raw):\n"
        "    scanned = dlp.scan_for_outbound(raw)\n"
        "    return OutboundMessageRequest(\n"
        "        adapter_id='alfred_comms_test', idempotency_key=k,\n"
        "        target_platform_id='c', body=scanned,\n"
        "        attachments_refs=(), addressing_mode='dm',\n"
        "    )\n"
    )
    assert _violations_in_source(source, filename="<local>") == []


def test_guard_rejects_raw_tuple_body() -> None:
    source = (
        "def f(raw):\n"
        "    return OutboundMessageRequest(\n"
        "        adapter_id='alfred_comms_test', idempotency_key=k,\n"
        "        target_platform_id='c', body=(raw, None),\n"
        "        attachments_refs=(), addressing_mode='dm',\n"
        "    )\n"
    )
    assert _violations_in_source(source, filename="<raw>") != []


def test_guard_rejects_missing_body() -> None:
    source = "def f():\n    return OutboundMessageRequest(adapter_id='alfred_comms_test')\n"
    assert _violations_in_source(source, filename="<missing>") != []


def test_guard_rejects_module_scope_raw_body() -> None:
    # A module-level construction must NOT bypass the guard (CR #232): the
    # function-only walk skipped module + class scopes entirely.
    source = (
        "REQ = OutboundMessageRequest(\n"
        "    adapter_id='alfred_comms_test', idempotency_key=k,\n"
        "    target_platform_id='c', body=(raw, None),\n"
        "    attachments_refs=(), addressing_mode='dm',\n"
        ")\n"
    )
    assert _violations_in_source(source, filename="<module>") != []


def test_guard_rejects_class_body_raw_body() -> None:
    source = (
        "class C:\n"
        "    REQ = OutboundMessageRequest(\n"
        "        adapter_id='alfred_comms_test', idempotency_key=k,\n"
        "        target_platform_id='c', body=(raw, None),\n"
        "        attachments_refs=(), addressing_mode='dm',\n"
        "    )\n"
    )
    assert _violations_in_source(source, filename="<class>") != []


def test_guard_accepts_module_scope_scan_call() -> None:
    # The broadened walk must still accept a legitimate module-scope construction
    # whose body= traces to a scan_for_outbound call.
    source = (
        "scanned = dlp.scan_for_outbound(raw)\n"
        "REQ = OutboundMessageRequest(\n"
        "    adapter_id='alfred_comms_test', idempotency_key=k,\n"
        "    target_platform_id='c', body=scanned,\n"
        "    attachments_refs=(), addressing_mode='dm',\n"
        ")\n"
    )
    assert _violations_in_source(source, filename="<module-ok>") == []


def test_guard_does_not_double_count_function_scope() -> None:
    # A single bad construction inside a function must be reported exactly once,
    # not duplicated by the module-scope pass also seeing it.
    source = (
        "def f(raw):\n"
        "    return OutboundMessageRequest(\n"
        "        adapter_id='alfred_comms_test', idempotency_key=k,\n"
        "        target_platform_id='c', body=(raw, None),\n"
        "        attachments_refs=(), addressing_mode='dm',\n"
        "    )\n"
    )
    assert len(_violations_in_source(source, filename="<once>")) == 1
