"""Subscriber-tier-attested tier-upgrade guard (PR-S4-3 / ADR-0022 §3).

The recoverable-carrier rewrite of ``_run_error`` keeps ``invoke()``
returning ``HookContext[T]`` so the 100+ existing call sites see no
signature change. The tier-upgrade guard is applied transparently
inside ``_run_error`` based on each hookpoint's registered
``carrier_tier``.

ADR-0022 §3: the substitute's ``source_tier`` is **dispatcher-attested**
from the firing subscriber's REGISTERED tier — the subscriber never
supplies it. The subscriber-tier → trust-tier map is:

* ``system``      → T0
* ``operator``    → T1
* ``user-plugin`` → T3

A subscriber embeds only the recovery payload under
``ctx.metadata["substitute_payload"]``; the dispatcher stamps the
attested ``source_tier``. This blocks a ``user-plugin``-tier subscriber
from spoofing ``source_tier="T0"`` to launder a substitute past the
guard.

This test proves the guard accepts iff ``attested_source <= carrier``,
across the realistic subscriber-tier / carrier-tier combinations —
including the genuine laundering case (a ``user-plugin`` subscriber, T3,
on a T1 carrier whose ``subscribable_tiers`` admits user-plugin).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from alfred.hooks import get_registry, set_registry
from alfred.hooks.context import HookContext
from alfred.hooks.invoke import invoke
from alfred.hooks.registry import OPEN_TIERS, HookRegistry
from alfred.security.tiers import T0, T1, T3, TrustTier
from tests.helpers.gates import make_permissive_fixture_gate


def _ctx(input_: str = "payload") -> HookContext[str]:
    return HookContext(
        action_id="action.test",
        hookpoint="hp",
        input=input_,
        correlation_id="corr-sibling",
        kind="error",
        metadata={},
    )


@pytest.fixture
def fresh_registry() -> Iterator[HookRegistry]:
    """A permissive registry for declaring ad-hoc test hookpoints."""
    prior = get_registry()
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        strict_declarations=False,
    )
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


def _payload_embedding_subscriber() -> Any:
    """Build an error subscriber that embeds a recovery payload only.

    Per ADR-0022 §3 the subscriber does NOT supply source_tier — it
    embeds just the payload; the dispatcher attests the tier from the
    subscriber's registration tier.
    """

    async def _sub(ctx: HookContext[str]) -> HookContext[str] | None:
        return ctx.with_metadata(substitute_payload="substituted")

    return _sub


@pytest.mark.parametrize(
    ("subscriber_tier", "carrier", "should_substitute"),
    [
        # carrier=T3 accepts every attested source tier.
        ("system", T3, True),  # attested T0 <= T3
        ("operator", T3, True),  # attested T1 <= T3
        ("user-plugin", T3, True),  # attested T3 <= T3
        # carrier=T1 accepts system/operator, REFUSES user-plugin (T3 > T1).
        ("system", T1, True),  # attested T0 <= T1
        ("operator", T1, True),  # attested T1 <= T1
        ("user-plugin", T1, False),  # attested T3 > T1 — laundering refused
        # carrier=T0 accepts only system; refuses operator + user-plugin.
        ("system", T0, True),  # attested T0 <= T0
        ("operator", T0, False),  # attested T1 > T0
        ("user-plugin", T0, False),  # attested T3 > T0
    ],
)
async def test_tier_upgrade_guard_attests_from_subscriber_tier(
    fresh_registry: HookRegistry,
    subscriber_tier: str,
    carrier: type[TrustTier],
    should_substitute: bool,  # noqa: FBT001
) -> None:
    """Substitution is accepted iff the ATTESTED source_tier <= carrier_tier.

    The attested source tier is derived from the subscriber's
    registration tier, NOT a subscriber-supplied value. ``OPEN_TIERS``
    subscription so every subscriber tier can register; the guard is the
    load-bearing gate.
    """
    fresh_registry.register_hookpoint(
        name="test.carrier.hookpoint",
        subscribable_tiers=OPEN_TIERS,
        refusable_tiers=OPEN_TIERS,
        fail_closed=False,
        carrier_tier=carrier,
    )
    fresh_registry.register(
        hook_fn=_payload_embedding_subscriber(),
        hookpoint="test.carrier.hookpoint",
        kind="error",
        tier=subscriber_tier,
    )
    upstream = ValueError("upstream failure")
    if should_substitute:
        result = await invoke(
            "test.carrier.hookpoint",
            _ctx(),
            kind="error",
            exc=upstream,
            subscribable_tiers=OPEN_TIERS,
        )
        assert result.input == "substituted"
    else:
        with pytest.raises(ValueError, match="upstream failure"):
            await invoke(
                "test.carrier.hookpoint",
                _ctx(),
                kind="error",
                exc=upstream,
                subscribable_tiers=OPEN_TIERS,
            )


# ---------------------------------------------------------------------------
# Refusal-arm coverage: recursion + wrong-type (unit-level so the hooks
# 100% coverage gate sees them — the adversarial corpus exercises the
# same arms but lives outside tests/unit/hooks/).
# ---------------------------------------------------------------------------


async def test_meta_hookpoint_substitution_refused_recursion(
    fresh_registry: HookRegistry,
) -> None:
    """A substitute on a meta-hookpoint (allow_error_substitution=False)
    is refused — the recursion guard fires and the upstream re-raises."""
    from alfred.hooks._known_hookpoints import declare_meta_hookpoints

    declare_meta_hookpoints(fresh_registry)

    async def _sub(ctx: HookContext[str]) -> HookContext[str] | None:
        return ctx.with_metadata(substitute_payload="recursion-attempt")

    fresh_registry.register(
        hook_fn=_sub,
        hookpoint="hooks.carrier_substituted",
        kind="error",
        tier="system",
    )
    with pytest.raises(ValueError, match="boom"):
        await invoke(
            "hooks.carrier_substituted",
            _ctx(),
            kind="error",
            exc=ValueError("boom"),
            subscribable_tiers=frozenset({"system"}),
        )


async def test_wrong_type_substitute_refused_through_invoke(
    fresh_registry: HookRegistry,
) -> None:
    """A substitute payload failing the declared carrier_type is refused;
    the upstream exception re-raises (payload_type_mismatch arm)."""
    fresh_registry.register_hookpoint(
        name="test.typed.carrier",
        subscribable_tiers=OPEN_TIERS,
        refusable_tiers=OPEN_TIERS,
        fail_closed=False,
        carrier_tier=T3,
    )

    async def _sub(ctx: HookContext[str]) -> HookContext[str] | None:
        # carrier_type is str (see invoke); embed an int → mismatch.
        return ctx.with_metadata(substitute_payload=42)

    fresh_registry.register(
        hook_fn=_sub,
        hookpoint="test.typed.carrier",
        kind="error",
        tier="system",
    )
    with pytest.raises(ValueError, match="boom"):
        await invoke(
            "test.typed.carrier",
            _ctx(),
            kind="error",
            exc=ValueError("boom"),
            subscribable_tiers=OPEN_TIERS,
            carrier_type=str,
        )
