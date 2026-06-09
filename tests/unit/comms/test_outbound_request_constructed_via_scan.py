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


def _scan_bound_names(func: ast.AST) -> set[str]:
    """Names in ``func`` bound to a ``scan_for_outbound(...)`` return value."""
    bound: set[str] = set()
    for node in ast.walk(func):
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


def _violations_in_source(source: str, *, filename: str) -> list[str]:
    """Return human-readable violation strings for one source file/string."""
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []
    # Walk every function/method; within each, find OutboundMessageRequest
    # calls and verify the body= argument traces to a scan_for_outbound call.
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        scan_names = _scan_bound_names(func)
        for node in ast.walk(func):
            if not (isinstance(node, ast.Call) and _is_call_to(node, _TARGET_CALL)):
                continue
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
