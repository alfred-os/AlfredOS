"""HookpointMeta gains carrier_tier + allow_error_substitution (PR-S4-3).

ADR-0022 recoverable-carrier semantic: every hookpoint declares its
``carrier_tier`` (the upper bound of a legal ``SubstituteResult.tier``
on the error chain) AND a binary ``allow_error_substitution`` opt-in.
Meta-hookpoints (the ``hooks.*`` family that emits *about* substitution
events) carry ``carrier_tier=None`` + ``allow_error_substitution=False``
to break the recursion loop. Every non-meta hookpoint MUST set
``carrier_tier`` explicitly — the registration helper refuses
``None`` outside the meta-hookpoint allow-list at module-init time.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from alfred.hooks.registry import HookpointMeta
from alfred.security.tiers import T0, T1, T2, T3


def test_hookpoint_meta_carries_carrier_tier() -> None:
    """A normal (non-meta) hookpoint sets ``carrier_tier`` to a tier class.

    The Slice-4 tier-upgrade guard reads this on every error-chain
    substitution to refuse ``substitute.tier > carrier_tier`` per
    strict total order.
    """
    meta = HookpointMeta(
        name="memory.episodic.record.before_validate",
        subscribable_tiers=frozenset({"system", "operator", "user-plugin"}),
        refusable_tiers=frozenset({"system", "operator", "user-plugin"}),
        fail_closed=False,
        carrier_tier=T2,
        allow_error_substitution=True,
    )
    assert meta.carrier_tier is T2


def test_hookpoint_meta_carrier_tier_none_for_meta_hookpoints() -> None:
    """Meta-hookpoints (``hooks.*`` family) carry ``carrier_tier=None``.

    Meta-hookpoints describe the substitution machinery itself; they
    are emitted from the error-chain dispatcher. Letting them carry
    a tier would invite recursion: a meta-hookpoint about substitution
    could itself substitute its own error. The closed semantic is
    ``carrier_tier=None`` + ``allow_error_substitution=False`` for
    every meta-hookpoint.
    """
    meta = HookpointMeta(
        name="hooks.carrier_substituted",
        subscribable_tiers=frozenset({"system"}),
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=None,
        allow_error_substitution=False,
    )
    assert meta.carrier_tier is None
    assert meta.allow_error_substitution is False


def test_hookpoint_meta_allow_error_substitution_defaults_true() -> None:
    """``allow_error_substitution`` defaults to ``True`` for non-meta hookpoints.

    The default-open posture matches the Slice-3 hookpoint philosophy:
    every registered hookpoint participates in the error chain unless
    the publisher explicitly opts out. The four sibling-site
    migrations in Task F use the default to stay terse; the meta-
    hookpoints in Task E set ``False`` explicitly.
    """
    meta = HookpointMeta(
        name="memory.episodic.record.write_failed",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system", "operator"}),
        fail_closed=False,
        carrier_tier=T2,
    )
    assert meta.allow_error_substitution is True


def test_hookpoint_meta_frozen_blocks_carrier_tier_mutation() -> None:
    """``HookpointMeta`` is frozen — ``carrier_tier`` cannot be rewritten.

    Frozen + slots: same hot-path discipline as ``Subscriber``. The
    metadata is consulted on every register and every dispatch;
    constructor-only configuration keeps the value semantics clean
    and prevents a subscriber from rewriting the contract at runtime
    via attribute assignment.
    """
    meta = HookpointMeta(
        name="x",
        subscribable_tiers=frozenset({"system"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
        carrier_tier=T0,
    )
    with pytest.raises(FrozenInstanceError):
        meta.carrier_tier = T3  # type: ignore[misc]


def test_hookpoint_meta_equality_includes_carrier_tier() -> None:
    """Field-wise equality picks up ``carrier_tier`` differences.

    The registry uses ``new == stored`` to detect idempotent re-
    declaration and ``new != stored`` to detect conflicting re-
    declaration. ``carrier_tier`` must participate in this check
    so a re-declaration that mismatches the live tier surfaces as a
    conflict rather than passing as a no-op.
    """
    a = HookpointMeta(
        name="x",
        subscribable_tiers=frozenset(),
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=T0,
    )
    b = HookpointMeta(
        name="x",
        subscribable_tiers=frozenset(),
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=T1,
    )
    assert a != b


def test_hookpoint_meta_equality_includes_allow_error_substitution() -> None:
    """``allow_error_substitution`` participates in field-wise equality.

    Twin coverage of the equality finding: ``carrier_tier`` AND
    ``allow_error_substitution`` are both load-bearing fields. A
    re-declaration that flips ``allow_error_substitution`` MUST
    surface as a conflict, not a silent no-op.
    """
    a = HookpointMeta(
        name="x",
        subscribable_tiers=frozenset(),
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=T0,
        allow_error_substitution=True,
    )
    b = HookpointMeta(
        name="x",
        subscribable_tiers=frozenset(),
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=T0,
        allow_error_substitution=False,
    )
    assert a != b


# ---------------------------------------------------------------------------
# Task A3 — register_hookpoint signature gate
# ---------------------------------------------------------------------------


from alfred.hooks.capability import CapabilityGate  # noqa: E402
from alfred.hooks.errors import HookError  # noqa: E402
from alfred.hooks.registry import HookRegistry  # noqa: E402
from tests.helpers.gates import make_permissive_fixture_gate  # noqa: E402


def grant_all_gate() -> CapabilityGate:
    """Build a permissive gate fixture for register_hookpoint tests."""
    return make_permissive_fixture_gate(allow_system=True)


def test_register_hookpoint_requires_carrier_tier_kwarg() -> None:
    """Calling ``register_hookpoint`` without ``carrier_tier=`` is a TypeError.

    Keyword-only required parameter — the publisher MUST declare the
    upper bound of legal SubstituteResult.tier values. A missing
    kwarg surfaces at module-init time before any subscriber runs.
    """
    reg = HookRegistry(gate=grant_all_gate(), strict_declarations=True)
    with pytest.raises(TypeError, match=r"missing.*carrier_tier"):
        reg.register_hookpoint(  # type: ignore[call-arg]
            name="something.action",
            subscribable_tiers=frozenset({"system"}),
            refusable_tiers=frozenset({"system"}),
            fail_closed=False,
        )


def test_register_hookpoint_refuses_none_for_non_meta_hookpoint() -> None:
    """``carrier_tier=None`` is refused for non-meta hookpoints.

    Only the meta-hookpoint allow-list (``hooks.carrier_substituted``,
    ``hooks.carrier_substitution_refused``) is permitted to declare
    ``carrier_tier=None``. Every other publisher MUST set a tier.
    """
    reg = HookRegistry(gate=grant_all_gate(), strict_declarations=True)
    with pytest.raises(HookError, match=r"meta-hookpoint allow-list"):
        reg.register_hookpoint(
            name="memory.episodic.record.before_validate",
            subscribable_tiers=frozenset({"system"}),
            refusable_tiers=frozenset({"system"}),
            fail_closed=False,
            carrier_tier=None,
        )


def test_register_hookpoint_accepts_none_for_carrier_substituted_meta_hookpoint() -> None:
    """``hooks.carrier_substituted`` is the canonical meta-hookpoint.

    Carries ``carrier_tier=None`` + ``allow_error_substitution=False``
    so the recursion loop closes: a meta-hookpoint about substitution
    cannot itself substitute its own error.
    """
    reg = HookRegistry(gate=grant_all_gate(), strict_declarations=True)
    reg.register_hookpoint(
        name="hooks.carrier_substituted",
        subscribable_tiers=frozenset({"system"}),
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=None,
        allow_error_substitution=False,
    )
    meta = reg.hookpoint_meta("hooks.carrier_substituted")
    assert meta is not None and meta.carrier_tier is None
    assert meta.allow_error_substitution is False


def test_register_hookpoint_refuses_tier_on_meta_hookpoint() -> None:
    """Meta-hookpoints MUST carry ``carrier_tier=None`` (symmetric guard)."""
    reg = HookRegistry(gate=grant_all_gate(), strict_declarations=True)
    with pytest.raises(HookError, match=r"meta-hookpoint.*non-None"):
        reg.register_hookpoint(
            name="hooks.carrier_substituted",
            subscribable_tiers=frozenset({"system"}),
            refusable_tiers=frozenset(),
            fail_closed=False,
            carrier_tier=T0,
            allow_error_substitution=False,
        )


def test_register_hookpoint_refuses_allow_substitution_on_meta_hookpoint() -> None:
    """Meta-hookpoints MUST carry ``allow_error_substitution=False`` (recursion guard)."""
    reg = HookRegistry(gate=grant_all_gate(), strict_declarations=True)
    with pytest.raises(HookError, match=r"allow_error_substitution=True"):
        reg.register_hookpoint(
            name="hooks.carrier_substituted",
            subscribable_tiers=frozenset({"system"}),
            refusable_tiers=frozenset(),
            fail_closed=False,
            carrier_tier=None,
            allow_error_substitution=True,
        )
