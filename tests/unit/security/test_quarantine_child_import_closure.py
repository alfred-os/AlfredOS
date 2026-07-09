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

The ``provider_dispatch`` import is a LAZY in-function import on the dead
``handle_extract`` path, so it is NOT on the module-scope closure the live
deterministic-echo loop reaches. As of #340 PR1, ``provider_dispatch`` itself is
also egress-free (it drives an INJECTED provider and imports no httpx/SDK) — the
egress-capable import lands in PR2's ``_build_provider``. That laziness (and, at
go-live, that import's egress-capability) is separately enforced by the go-live
egress gate (``test_quarantined_llm_not_yet_spawned_while_egress_open.py``); here
we assert the forbidden-privileged-module bound on the module-scope closure.
"""

from __future__ import annotations

import importlib
import sys

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
        # Drop any already-imported child + privileged modules so the delta
        # reflects the child's OWN reachable surface, not residue from a sibling.
        to_clear = [
            name
            for name in sys.modules
            if name == _CHILD_PACKAGE
            or name.startswith(_CHILD_PACKAGE + ".")
            or _is_forbidden(name)
        ]
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
