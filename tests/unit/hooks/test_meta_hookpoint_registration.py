"""Meta-hookpoints register observation-only; subscribers cannot substitute.

PR-S4-3 Component E (ADR-0022). The two carrier-substitution
meta-hookpoints (``hooks.carrier_substituted``,
``hooks.carrier_substitution_refused``) describe the substitution
machinery itself. They MUST carry ``carrier_tier=None`` +
``allow_error_substitution=False`` so a subscriber against them
cannot substitute the meta-event's payload — closing the recursion
loop the recoverable-carrier semantic would otherwise open.
"""

from __future__ import annotations

from alfred.hooks._known_hookpoints import declare_meta_hookpoints
from alfred.hooks.registry import HookRegistry
from tests.helpers.gates import make_permissive_fixture_gate


def _registry() -> HookRegistry:
    return HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        strict_declarations=True,
    )


def test_declare_meta_hookpoints_registers_substituted_variant() -> None:
    """``hooks.carrier_substituted`` registers observation-only."""
    reg = _registry()
    declare_meta_hookpoints(reg)
    meta = reg.hookpoint_meta("hooks.carrier_substituted")
    assert meta is not None
    assert meta.carrier_tier is None
    assert meta.allow_error_substitution is False


def test_declare_meta_hookpoints_registers_refused_variant() -> None:
    """``hooks.carrier_substitution_refused`` registers observation-only."""
    reg = _registry()
    declare_meta_hookpoints(reg)
    meta = reg.hookpoint_meta("hooks.carrier_substitution_refused")
    assert meta is not None
    assert meta.carrier_tier is None
    assert meta.allow_error_substitution is False


def test_declare_meta_hookpoints_is_idempotent() -> None:
    """Re-declaring the meta-hookpoints with identical metadata is a no-op."""
    reg = _registry()
    declare_meta_hookpoints(reg)
    # Second call must not raise (idempotent re-declaration).
    declare_meta_hookpoints(reg)
    assert reg.hookpoint_meta("hooks.carrier_substituted") is not None


def test_meta_hookpoints_subscribable_system_only() -> None:
    """Meta-hookpoints lock subscription to the system tier only.

    Operator + user-plugin tiers are locked out — only AlfredOS
    internals observe the substitution machinery.
    """
    reg = _registry()
    declare_meta_hookpoints(reg)
    meta = reg.hookpoint_meta("hooks.carrier_substituted")
    assert meta is not None
    assert meta.subscribable_tiers == frozenset({"system"})


def test_declare_meta_hookpoints_rejects_wrong_typed_registry() -> None:
    """A non-HookRegistry, non-None ``registry`` arg fails fast (CR closure).

    Silently falling back to the global singleton on a bad injection
    would mask the caller bug and mutate global state unexpectedly.
    """
    import pytest

    with pytest.raises(TypeError, match="HookRegistry or None"):
        declare_meta_hookpoints("not-a-registry")  # type: ignore[arg-type]


def test_declare_meta_hookpoints_defaults_to_global_singleton() -> None:
    """With no arg, ``declare_meta_hookpoints`` targets the process singleton.

    Covers the production call shape (the bootstrap orchestrator calls
    it with no argument). Swaps in a fresh registry as the singleton so
    the declaration does not leak into sibling tests.
    """
    from alfred.hooks import get_registry, set_registry

    prior = get_registry()
    fresh = _registry()
    set_registry(fresh)
    try:
        declare_meta_hookpoints()  # no arg → get_registry()
        assert get_registry().hookpoint_meta("hooks.carrier_substituted") is not None
    finally:
        set_registry(prior)
