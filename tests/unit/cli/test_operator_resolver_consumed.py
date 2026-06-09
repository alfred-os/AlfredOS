"""AST guard: operator-attributed CLI audit rows must consume the resolver.

Tasks 4-5. Every module under ``src/alfred/cli/`` that emits an audit row
whose field-set includes ``operator_user_id`` MUST also consume the
operator-session resolver — otherwise the row would carry an
unauthenticated (or absent) operator id, defeating #153.

The closed set of "operator-attributed" constants is computed at runtime
from ``audit_row_schemas`` (every ``frozenset`` constant containing
``operator_user_id``), so a future constant added in a later PR is covered
automatically without editing this guard.

"Consumes the resolver" is satisfied structurally: the module references
one of the resolver symbols (``_resolve_operator``, ``_build_operator_resolver``,
``_resolve_operator_session_or_refuse``, or ``OperatorResolverProtocol``).
A negative fixture proves the guard catches a non-consuming module.
"""

from __future__ import annotations

import ast
from pathlib import Path

from alfred.audit import audit_row_schemas

_CLI_DIR = Path(__file__).resolve().parents[3] / "src" / "alfred" / "cli"
_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures_operator_resolver_guard"

# web.py (``alfred web allowlist``) is EXPLICITLY out of scope for #153 per
# spec §6.8, which enumerates only ``supervisor reset`` / ``config
# quarantined-provider`` / ``plugin grant|revoke``. The session-attribution
# wiring for ``web allowlist`` is tracked as a follow-up (Slice-5). The guard
# exempts it here with this provenance comment rather than scope-creeping —
# any OTHER non-consuming module still fails the guard loudly.
_EXEMPT_MODULES = frozenset({"web.py"})

_RESOLVER_SYMBOLS = frozenset(
    {
        "_resolve_operator",
        "_resolve_operator_session_or_refuse",
        "resolve_operator_user_id_or_refuse",
        "_build_operator_resolver",
        "OperatorResolverProtocol",
        "DefaultOperatorSessionResolver",
    }
)


def _operator_attributed_constants() -> frozenset[str]:
    """Every audit-row constant whose field-set includes ``operator_user_id``."""
    out: set[str] = set()
    for name in dir(audit_row_schemas):
        val = getattr(audit_row_schemas, name)
        if isinstance(val, frozenset) and "operator_user_id" in val:
            out.add(name)
    return frozenset(out)


def _referenced_names(tree: ast.Module) -> set[str]:
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}


def _module_emits_operator_attributed(tree: ast.Module, constants: frozenset[str]) -> bool:
    names = _referenced_names(tree)
    return bool(names & constants)


def _module_consumes_resolver(tree: ast.Module) -> bool:
    names = _referenced_names(tree)
    if names & _RESOLVER_SYMBOLS:
        return True
    # Also accept an attribute-access form (e.g. ``mod._resolve_operator``).
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _RESOLVER_SYMBOLS:
            return True
    return False


def test_operator_attributed_constants_nonempty() -> None:
    """Sanity: the guard has a non-trivial closed set to police."""
    assert _operator_attributed_constants()


def test_every_operator_attributed_cli_module_consumes_resolver() -> None:
    constants = _operator_attributed_constants()
    offenders: list[str] = []
    for module_path in _CLI_DIR.rglob("*.py"):
        rel = str(module_path.relative_to(_CLI_DIR))
        if rel in _EXEMPT_MODULES:
            continue
        tree = ast.parse(module_path.read_text())
        if _module_emits_operator_attributed(tree, constants) and not _module_consumes_resolver(
            tree
        ):
            offenders.append(rel)
    assert not offenders, (
        f"CLI modules emit operator-attributed audit rows without consuming the "
        f"operator-session resolver: {offenders}"
    )


def test_guard_catches_non_consuming_module() -> None:
    """Negative fixture: a module emitting an attributed row WITHOUT the resolver."""
    constants = _operator_attributed_constants()
    bad = _FIXTURE_DIR / "bad_module.py"
    tree = ast.parse(bad.read_text())
    assert _module_emits_operator_attributed(tree, constants)
    assert not _module_consumes_resolver(tree)


def test_guard_passes_consuming_module() -> None:
    """Positive fixture: emitting + consuming the resolver passes the guard."""
    constants = _operator_attributed_constants()
    good = _FIXTURE_DIR / "good_module.py"
    tree = ast.parse(good.read_text())
    assert _module_emits_operator_attributed(tree, constants)
    assert _module_consumes_resolver(tree)
