"""The tier-upgrade guard fires at the 4 sibling hookpoints (PR-S4-3).

Component F (ADR-0022). The recoverable-carrier rewrite of
``_run_error`` keeps ``invoke()`` returning ``HookContext[T]`` so the
100+ existing call sites — including the four ADR-0022 sibling sites
(`QuarantinedExtractor.extract`, `EpisodicMemory.record`,
`_ingest_tier`, `dispatch_loop._record_failure`) — see no signature
change. The tier-upgrade guard is applied transparently inside
``_run_error`` based on each hookpoint's registered ``carrier_tier``.

This test proves the guard fires at the REAL sibling hookpoint names
with their REAL registered carrier tiers, via the embedded-
``SubstituteResult`` path a subscriber uses to substitute at a
declared tier:

* ``security.quarantined.extract`` — carrier_tier=T3 (accepts every tier)
* ``memory.episodic.record.write_failed`` — carrier_tier=T3 (accepts every tier)
* ``identity.t1_ingress`` — carrier_tier=T1 (refuses T2/T3 substitutes)
* ``supervisor.breaker.tripped`` — carrier_tier=T0 (refuses T1/T2/T3 substitutes)

The first two carriers are T3 (the top of the strict total order) so
they accept substitutes from any source tier — the load-bearing
property for the quarantine + episodic paths which handle untrusted
T3 content. The identity + supervisor carriers are tighter and refuse
tier-laundering attempts.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from alfred.hooks import get_registry, set_registry
from alfred.hooks.context import HookContext
from alfred.hooks.invoke import SubstituteResult, invoke
from alfred.hooks.registry import HookRegistry
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
def guarded_registry() -> Iterator[HookRegistry]:
    """A registry where the 4 sibling hookpoints carry their real tiers."""
    prior = get_registry()
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        strict_declarations=False,
    )
    # Declare the error-stage hookpoints with the carrier tiers Component
    # A registers in production.
    registry.register_hookpoint(
        name="security.quarantined.extract",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=False,
        carrier_tier=T3,
    )
    registry.register_hookpoint(
        name="memory.episodic.record.write_failed",
        subscribable_tiers=frozenset({"system", "operator", "user-plugin"}),
        refusable_tiers=frozenset({"system", "operator", "user-plugin"}),
        fail_closed=False,
        carrier_tier=T3,
    )
    registry.register_hookpoint(
        name="identity.t1_ingress",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=T1,
    )
    registry.register_hookpoint(
        name="supervisor.breaker.tripped",
        subscribable_tiers=frozenset({"system"}),
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=T0,
    )
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


def _make_substituting_subscriber(source_tier: str) -> Any:
    """Build an error subscriber that embeds a SubstituteResult."""

    async def _sub(ctx: HookContext[str]) -> HookContext[str] | None:
        substitute = SubstituteResult[str](
            payload="substituted",
            source_tier=source_tier,  # type: ignore[arg-type]
            subscriber_id="test._sub",
        )
        return ctx.with_metadata(substitute_result=substitute)

    return _sub


# Each sibling hookpoint's declared subscribable_tiers must be passed to
# invoke() so the dispatch-time defense-in-depth re-check (which compares
# invoked tiers against the declared meta) does not trip.
_SUBSCRIBABLE_TIERS_BY_HOOKPOINT = {
    "security.quarantined.extract": frozenset({"system", "operator"}),
    "memory.episodic.record.write_failed": frozenset({"system", "operator", "user-plugin"}),
    "identity.t1_ingress": frozenset({"system", "operator"}),
    "supervisor.breaker.tripped": frozenset({"system"}),
}


@pytest.mark.parametrize(
    ("hookpoint", "carrier", "source_tier", "should_substitute"),
    [
        # T3 carrier accepts every source tier.
        ("security.quarantined.extract", T3, "T0", True),
        ("security.quarantined.extract", T3, "T3", True),
        ("memory.episodic.record.write_failed", T3, "T2", True),
        ("memory.episodic.record.write_failed", T3, "T3", True),
        # T1 carrier refuses T2/T3 substitutes (tier-laundering).
        ("identity.t1_ingress", T1, "T0", True),
        ("identity.t1_ingress", T1, "T1", True),
        ("identity.t1_ingress", T1, "T2", False),
        ("identity.t1_ingress", T1, "T3", False),
        # T0 carrier refuses everything above T0.
        ("supervisor.breaker.tripped", T0, "T0", True),
        ("supervisor.breaker.tripped", T0, "T1", False),
        ("supervisor.breaker.tripped", T0, "T3", False),
    ],
)
async def test_tier_upgrade_guard_at_sibling_hookpoint(
    guarded_registry: HookRegistry,
    hookpoint: str,
    carrier: type[TrustTier],
    source_tier: str,
    should_substitute: bool,  # noqa: FBT001
) -> None:
    """Substitution is accepted iff source_tier <= carrier_tier.

    When accepted, ``invoke`` returns the substitute payload (the
    exception is swallowed). When refused, ``invoke`` re-raises the
    upstream exception (the tier-laundering attempt is rejected and
    the original failure propagates loud).
    """
    guarded_registry.register(
        hook_fn=_make_substituting_subscriber(source_tier),
        hookpoint=hookpoint,
        kind="error",
        tier="system",
    )
    upstream = ValueError("upstream failure")
    subscribable = _SUBSCRIBABLE_TIERS_BY_HOOKPOINT[hookpoint]
    if should_substitute:
        result = await invoke(
            hookpoint,
            _ctx(),
            kind="error",
            exc=upstream,
            subscribable_tiers=subscribable,
        )
        assert result.input == "substituted"
    else:
        with pytest.raises(ValueError, match="upstream failure"):
            await invoke(
                hookpoint,
                _ctx(),
                kind="error",
                exc=upstream,
                subscribable_tiers=subscribable,
            )
