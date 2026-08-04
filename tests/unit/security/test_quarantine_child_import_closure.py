"""The quarantined-LLM child's reachable import surface is bounded (ADR-0030).

PR-S4-11c-2b0 (#237) moves the quarantined-LLM child INTO the installed package
(``alfred.security.quarantine_child``) so it ships in the wheel and is reachable
under the bwrap ``kind="full"`` policy's ``/usr`` ro-bind. That move is only safe
if the child's reachable import surface stays BOUNDED — a child running under the
adversary-facing sandbox must not be able to ``import`` its way to the privileged
host subsystems (the dual-LLM reachable-surface bound, ADR-0030 / PRD §5 DEC-007).

Two invariants, both load-bearing:

* the child entry package is IMPORTABLE by its wheel-path name (proves the move
  actually made it reachable off the default site-packages path — the whole point
  of Option A); and
* importing it pulls in NO privileged module — not ``alfred.audit`` (the real
  signed audit writer), ``alfred.core`` (orchestrator / loop / supervisor),
  ``alfred.memory`` (per-user stores), nor the secret broker. The child sees only
  the extraction schemas + ``ProviderCapability``.

**Scope — what this file does NOT check (#340 PR2b-golive correction).**

This module asserts the FORBIDDEN-PRIVILEGED-MODULE bound on the child's
module-scope import closure. It says nothing about the child's EGRESS
capability, at any scope.

The previous version of this docstring deferred that question to the go-live
egress gate, then named ``test_quarantined_llm_not_yet_spawned_while_egress_open.py``
as the thing enforcing it. That gate — since renamed to
``test_quarantined_llm_spawn_site_and_import_time_egress_backstop.py`` — carries a
standing warning DISCLAIMING exactly this: it inspects only ``tree.body``, so it
catches a module-scope egress import and nothing else. Each file pointed at the
other for a property NEITHER of them checks. The circularity is recorded here
rather than quietly deleted because a reader who followed the old pointer would
have concluded the property was covered.

Concretely: since golive the real Anthropic client is constructed inside
``_build_provider``, and ``socket`` / ``brokered_egress`` / ``provider_dispatch``
are all imported in-function. A lazily imported ``httpx`` on an unsanctioned path
would be caught by neither file. The load-bearing containment is the kernel
``--unshare-net`` plus the fd-4 SCM_RIGHTS broker, both independently gated.

Rebuilding an any-scope egress-import oracle is tracked in **#465**.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterable

# Privileged host subsystems the quarantined child must never be able to import.
# Roots are matched as ``m == root or m.startswith(root + ".")`` so a submodule
# (e.g. ``alfred.audit.log``) is caught too. ``alfred.security.capability_gate``
# (the broker-adjacent gate) and the secret broker module are named explicitly.
_FORBIDDEN_ROOTS: tuple[str, ...] = (
    "alfred.audit",
    "alfred.core",
    "alfred.memory",
    "alfred.orchestrator",
    "alfred.security.secrets",
    "alfred.security.capability_gate",
    "alfred.security.dlp",
)

_CHILD_PACKAGE = "alfred.security.quarantine_child"
_CHILD_ENTRY = "alfred.security.quarantine_child.__main__"


def _is_forbidden(module_name: str) -> bool:
    return any(
        module_name == root or module_name.startswith(root + ".") for root in _FORBIDDEN_ROOTS
    )


def _alfred_modules_to_clear(module_names: Iterable[str]) -> list[str]:
    """Every ``alfred`` module to evict before measuring the child's import delta.

    The ENTIRE tree, including the BARE package. Leaving ``alfred`` resident means
    ``src/alfred/__init__.py`` never re-executes, so whatever it imports is absent
    from the delta and the ADR-0030 reachable-surface bound cannot see it (#568).
    """
    return [name for name in module_names if name == "alfred" or name.startswith("alfred.")]


def test_quarantine_child_package_is_wheel_path_importable() -> None:
    """The child package imports by its installed-wheel name (Option A proof)."""
    module = importlib.import_module(_CHILD_PACKAGE)
    assert module.__name__ == _CHILD_PACKAGE
    # The entry module is reachable too — this is what ``python -m`` execs.
    entry = importlib.import_module(_CHILD_ENTRY)
    assert hasattr(entry, "_run_mcp_server")


def test_quarantine_child_import_closure_touches_no_privileged_module() -> None:
    """Importing the child entry pulls in NO privileged host module (ADR-0030).

    Measures the DELTA in ``sys.modules`` caused by importing the child entry
    fresh, so a module another test left resident does not mask a real reachable
    edge. Any privileged module appearing in that delta fails the bound loudly.
    """
    # Snapshot sys.modules so we restore the EXACT prior state in finally. This
    # test deletes modules (incl. ``alfred.security.secrets``) to measure a clean
    # import delta; without the restore it leaves them deleted/re-imported, and a
    # later test (e.g. test_secrets' monkeypatch-by-module-string) diverges from a
    # broker bound to the original module object. #237.
    _orig_modules = dict(sys.modules)
    try:
        # Drop the ENTIRE `alfred` tree, not just the child + forbidden roots.
        # #568: clearing only those leaves `alfred` itself resident, so
        # `src/alfred/__init__.py` never re-executes and anything IT imports is
        # absent from the delta — the gate was structurally blind to the package
        # __init__. Inert while that file was empty; `alfred._python_floor` now
        # populates it.
        #
        # The blindness was UNCONDITIONAL under pytest, not order-dependent:
        # `tests/unit/conftest.py` imports `alfred.audit.log` at module scope
        # (since 2026-05-27, #95), so `alfred` is already resident during
        # collection even when this file is run alone. There was no way to run
        # the pre-fix gate that would have caught it.
        to_clear = _alfred_modules_to_clear(sys.modules)
        for name in to_clear:
            del sys.modules[name]

        before = set(sys.modules)
        importlib.import_module(_CHILD_ENTRY)
        delta = set(sys.modules) - before

        forbidden = sorted(name for name in delta if _is_forbidden(name))
        assert not forbidden, (
            "the quarantined-LLM child reached a privileged host module via its import "
            f"closure — the dual-LLM reachable-surface bound (ADR-0030) is broken: "
            f"{forbidden}"
        )
    finally:
        # Restore the exact prior sys.modules state: drop anything the fresh import
        # added, re-instate the original module objects we deleted.
        for name in set(sys.modules) - set(_orig_modules):
            del sys.modules[name]
        sys.modules.update(_orig_modules)


def test_the_clearing_rule_evicts_the_bare_alfred_package() -> None:
    """#568: omitting the bare package is what made the gate blind.

    Calls the PRODUCTION helper. The previous version of this test rebuilt the
    predicate inline and so passed even with the rule reverted — verified by
    mutation.
    """
    cleared = _alfred_modules_to_clear(
        ["alfred", "alfred.security", "alfred.security.quarantine_child", "os"]
    )
    assert "alfred" in cleared, (
        "the closure gate must evict the bare `alfred` package so its __init__ re-runs; "
        "otherwise the dual-LLM reachable-surface bound cannot see what __init__ imports"
    )


def test_the_clearing_rule_leaves_unrelated_modules_resident() -> None:
    """`alfredo` must not match: the rule is `alfred.`-prefixed, not `alfred`-prefixed."""
    assert _alfred_modules_to_clear(["os", "sys", "alfredo"]) == []
