"""``alfred.hooks.boot`` — production boot HookRegistry (PR-S4-11b0).

ADR-0026: the daemon installs a fresh :class:`HookRegistry` wired to the
production RealGate and the durable boot audit sink, with EVERY
subsystem's hookpoints re-declared against it. Until this PR, the only
production registry was the lazy :func:`get_registry` fallback over the
fail-closed :class:`_DenyAllGate`, which denies every subscriber
registration — so a production :class:`alfred.security.quarantine.QuarantinedExtractor`
could never construct.

Pinned invariants:

* the boot registry DECLARES the ``security.quarantined.extract``
  hookpoint (and every other subsystem hookpoint) so a subscriber can
  register against it;
* BLAST RADIUS — a freshly-built boot registry has EMPTY subscriber
  buckets (declaration ≠ registration; no subscriber is wired by the
  boot builder itself);
* re-declaring every subsystem hookpoint against the boot registry
  raises NO drift :class:`HookError` (idempotent on equal metadata);
* :func:`install_boot_hook_registry` swaps the process singleton so
  :func:`get_registry` returns the boot registry.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping

import pytest

from alfred.hooks import get_registry, set_registry
from alfred.hooks.boot import (
    build_boot_hook_registry,
    install_boot_hook_registry,
)
from alfred.hooks.errors import HookError
from alfred.hooks.registry import HookRegistry
from tests.helpers.gates import make_deny_all_gate, make_quarantined_extract_chain_gate


class _RecordingSink:
    """Minimal :class:`AuditSink` double — records emits."""

    def __init__(self) -> None:
        self.emits: list[str] = []

    async def emit(
        self,
        *,
        event: str,
        correlation_id: str,
        fields: Mapping[str, object],
    ) -> None:
        self.emits.append(event)


@pytest.fixture
def _restore_registry() -> object:
    """Stash/restore the process singleton around install tests."""
    prior = get_registry()
    yield
    set_registry(prior)


def test_build_boot_registry_declares_quarantine_hookpoint() -> None:
    reg = build_boot_hook_registry(make_deny_all_gate(), sink=_RecordingSink())
    assert isinstance(reg, HookRegistry)
    assert reg.hookpoint_meta("security.quarantined.extract") is not None


def test_build_boot_registry_declares_every_subsystem_hookpoint() -> None:
    reg = build_boot_hook_registry(make_deny_all_gate(), sink=_RecordingSink())
    # A representative hookpoint from each declaring subsystem.
    for name in (
        "security.quarantined.extract",
        "supervisor.config_reload",
        "daemon.boot.failed",
    ):
        assert reg.hookpoint_meta(name) is not None, name


def test_boot_registry_blast_radius_empty_subscriber_buckets() -> None:
    """Declaration is NOT registration — the boot builder wires zero
    subscribers. The DLP subscriber lands later via the extractor's own
    constructor, not the boot registry build."""
    reg = build_boot_hook_registry(make_deny_all_gate(), sink=_RecordingSink())
    assert reg.subscribers_for("security.quarantined.extract", "post") == ()


def test_boot_registry_redeclare_is_drift_free() -> None:
    """Re-running the full subsystem re-declaration against an already-built
    boot registry raises no drift HookError (idempotent on equal metadata)."""
    sink = _RecordingSink()
    reg = build_boot_hook_registry(make_deny_all_gate(), sink=sink)
    # Build a SECOND registry sharing nothing, then re-declare into the FIRST
    # — equal metadata must be a no-op, not a drift error.
    build_boot_hook_registry(make_deny_all_gate(), sink=sink)
    # Re-import + re-declare every subsystem against reg directly.
    from alfred.hooks.boot import _declare_all_subsystem_hookpoints

    _declare_all_subsystem_hookpoints(reg)  # no raise


def test_install_boot_registry_swaps_singleton(_restore_registry: object) -> None:
    sink = _RecordingSink()
    reg = install_boot_hook_registry(make_deny_all_gate(), sink=sink)
    assert get_registry() is reg


def test_boot_registry_with_granted_gate_admits_dlp_subscriber(
    _restore_registry: object,
) -> None:
    """End-to-end: a boot registry over a gate that grants the first-party
    DLP subscriber lets :func:`register_extract_dlp_subscriber` land exactly
    one subscriber on the post chain (the RED-today case the daemon needs).

    Uses a FIXTURE scoped grant (``make_quarantined_extract_chain_gate``),
    NEVER a permissive always-allow shim — CLAUDE.md hard rule #2.
    """
    from alfred.security._extract_dlp_subscriber import register_extract_dlp_subscriber

    reg = install_boot_hook_registry(
        make_quarantined_extract_chain_gate(),
        sink=_RecordingSink(),
    )
    register_extract_dlp_subscriber(registry=reg, outbound_dlp=_make_dlp())
    subs = reg.subscribers_for("security.quarantined.extract", "post")
    assert len(subs) == 1


def test_boot_registry_with_deny_gate_refuses_dlp_subscriber(
    _restore_registry: object,
) -> None:
    """The deny-all RealGate (no first-party grant) refuses the system-tier
    DLP subscriber — the fail-closed posture the daemon's grant assertion
    detects and turns into a boot refusal. Uses ``make_deny_all_gate`` (a
    RealGate with empty grants), NOT a permissive shim — CLAUDE.md hard
    rule #2."""
    from alfred.security._extract_dlp_subscriber import register_extract_dlp_subscriber

    reg = install_boot_hook_registry(make_deny_all_gate(), sink=_RecordingSink())
    with pytest.raises(HookError):
        register_extract_dlp_subscriber(registry=reg, outbound_dlp=_make_dlp())


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=("POSIX-only: hardcoded forward-slash path-string literals in the guard (#246 review)"),
)
def test_boot_declares_every_in_tree_declare_hookpoints_publisher() -> None:
    """Completeness guard: every ``def declare_hookpoints`` in ``src/alfred``
    (except ``hooks/boot.py`` itself, which is the AGGREGATOR) MUST be wired
    into :func:`_declare_all_subsystem_hookpoints`.

    A new subsystem publisher that forgets to register here would leave its
    hookpoints undeclared at boot — subscribers against them would be
    refused with a confusing "hookpoint not declared" error. AST-scanning
    the source pins the boot aggregator to the actual publisher set so the
    drift surfaces as a failing test, not a runtime surprise.
    """
    import ast
    import pathlib

    src_root = pathlib.Path("src/alfred")
    publishers: set[str] = set()
    for path in src_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "declare_hookpoints":
                publishers.add(str(path))
                break

    # The aggregator module is itself a match (it defines the wrapper); drop it.
    publishers = {p for p in publishers if not p.endswith("hooks/boot.py")}

    import inspect

    from alfred.hooks import boot

    # AST-verify each publisher's declare_hookpoints is actually CALLED with
    # ``registry`` — not merely name-dropped in the source. A string-containment
    # check would pass even if a subsystem were imported-but-never-called (its
    # hookpoints would then NOT land on the boot registry). Parse the aggregator:
    # map ``<module> -> alias`` from its ``import declare_hookpoints as <alias>``,
    # and collect the aliases invoked with a positional ``registry`` argument.
    agg_tree = ast.parse(inspect.getsource(boot._declare_all_subsystem_hookpoints))
    module_to_alias: dict[str, str] = {}
    for node in ast.walk(agg_tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias_node in node.names:
                if alias_node.name == "declare_hookpoints" and alias_node.asname:
                    module_to_alias[node.module] = alias_node.asname
    called_with_registry: set[str] = {
        node.func.id
        for node in ast.walk(agg_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and any(isinstance(arg, ast.Name) and arg.id == "registry" for arg in node.args)
    }
    for publisher in publishers:
        # e.g. src/alfred/memory/episodic.py     -> alfred.memory.episodic
        #      src/alfred/cli/daemon/__init__.py -> alfred.cli.daemon
        module = publisher.replace("src/", "").replace("/", ".").removesuffix(".py")
        module = module.removesuffix(".__init__")
        alias = module_to_alias.get(module)
        assert alias is not None, f"{module}.declare_hookpoints not imported into boot aggregator"
        assert alias in called_with_registry, (
            f"{module}.declare_hookpoints is imported but never called with registry"
        )


def _make_dlp() -> object:
    """A stand-in DLP scanner.

    The registration path only stores the instance and runs identity
    checks against it — it never calls ``.scan`` — so a lightweight
    object is sufficient and avoids dragging the real broker/secret-store
    wiring into a registry test.
    """
    return object()
