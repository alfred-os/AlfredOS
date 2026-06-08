"""Adversarial wiring-smoke for the `hk-2026-003` corpus payload.

Asserts the **defense fired** at DISPATCH time: given a hookpoint
declared with ``subscribable_tiers={"system","operator"}`` and
``refusable_tiers={"system"}`` / ``fail_closed=True``, a publisher that
invokes the chain with a DRIFTED ``subscribable_tiers={"system"}``
(forgetting to update the call site after narrowing the declaration —
the realistic publisher-bug shape :func:`alfred.hooks.invoke._enforce_subscribable_tiers`
defends against) MUST:

1. Raise :class:`HookError` from :func:`invoke` BEFORE any subscriber
   runs — the dispatch-time defense-in-depth re-check fires first.
2. Emit exactly one :data:`HOOKS_TIER_REJECTED` audit row carrying
   ``drift_at="dispatch"`` + ``drift_kind="subscribable_tiers"`` so
   operators can grep both the publisher's declaration site AND the
   drifted invoke site (#119 review Group I closed-vocab attribution).
3. Carry both the declared and the invoked allow-lists on the row's
   ``fields`` mapping — the operator's grep-target for reconciling
   both sides of a publisher-version split.

Companion payload to :mod:`tests.adversarial.hooks.test_hk_2026_002_registration_tier_rejection`
(the register-time arm of #119). Together the two pin BOTH halves of
spec §6.2: registration-time enforcement + invoke-time re-check.

Spec anchor: lines 696-697 of
``docs/superpowers/specs/2026-05-27-slice-2.5-hooks-design.md``
documented the dispatch-time half of #119; ``_enforce_subscribable_tiers``
in ``src/alfred/hooks/invoke.py`` is the production implementation this
test pins.
"""

from __future__ import annotations

from typing import Any, Final
from uuid import uuid4

import pytest

from alfred.hooks.audit_sink import HOOKS_TIER_REJECTED
from alfred.hooks.context import HookContext
from alfred.hooks.errors import HookError
from alfred.hooks.invoke import invoke
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.security.tiers import T3
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_permissive_fixture_gate
from tests.unit.hooks.conftest import SpyAuditSink

_PAYLOAD_ID: Final[str] = "hk-2026-003"


@pytest.fixture
def dispatch_subscribable_tiers_drift_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus down to the wiring-smoke payload.

    Fails loudly if the payload isn't present so a future rename / delete
    in the corpus surfaces here. Mirrors the drift-guard pattern from
    :func:`tests.adversarial.hooks.test_hk_2026_002_registration_tier_rejection.registration_tier_rejection_payload`.
    """
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; "
            f"expected at tests/adversarial/hooks/dispatch_subscribable_tiers_drift.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            f"expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def _ctx(correlation_id: str) -> HookContext[Any]:
    """Build a fresh frozen :class:`HookContext` for a synthetic action.

    Mirrors the helper :func:`tests.unit.hooks.test_dispatch_publisher_drift._ctx`;
    duplicated here (not imported across the adversarial / unit boundary)
    so the adversarial harness stays self-contained — a future refactor
    of the unit test does not cascade into the corpus's wiring-smoke.
    """
    return HookContext(
        action_id="action.adversarial.hk-2026-003",
        hookpoint="action.adversarial.hk-2026-003",
        input=None,
        correlation_id=correlation_id,
        kind="pre",
    )


@pytest.mark.asyncio
async def test_dispatch_subscribable_tiers_drift_refused_and_audited(
    dispatch_subscribable_tiers_drift_payload: AdversarialPayload,
) -> None:
    """Dispatch with a drifted ``subscribable_tiers`` MUST refuse + audit.

    Reproduces the publisher-bug shape end-to-end:

    1. Install a fresh :class:`HookRegistry` carrying the spy sink so
       the audit row is observable from the test (no global structlog
       state, no cross-test contamination).
    2. Declare the hookpoint with the payload's declared meta.
    3. Invoke the chain with the payload's drifted invoke-time
       ``subscribable_tiers``.
    4. Assert :class:`HookError` raises BEFORE the chain runs, and the
       :data:`HOOKS_TIER_REJECTED` audit row carries the closed-vocab
       attribution fields the operator needs.

    The :class:`SpyAuditSink` is the adversarial-faithful sink — the
    spy records every emit synchronously, so the assertions below pin
    the row exactly as PR-B's :class:`alfred.audit.log.AuditWriter`-
    backed sink would project it.
    """
    payload_fields = dispatch_subscribable_tiers_drift_payload.payload
    assert isinstance(payload_fields, dict), (
        f"payload {_PAYLOAD_ID} must use the dict form for hook dispatch-drift "
        f"(got {type(payload_fields).__name__})"
    )

    hookpoint = payload_fields["hookpoint"]
    declared_subscribable = frozenset(payload_fields["declared_subscribable_tiers"])
    declared_refusable = frozenset(payload_fields["declared_refusable_tiers"])
    declared_fail_closed = payload_fields["declared_fail_closed"]
    invoked_subscribable = frozenset(payload_fields["invoked_subscribable_tiers"])
    invoked_refusable = frozenset(payload_fields["invoked_refusable_tiers"])
    invoked_fail_closed = payload_fields["invoked_fail_closed"]
    expected_drift_kind = payload_fields["drift_kind"]

    # Payload sanity-pin: only ``subscribable_tiers`` should differ from
    # the declared set. A drift in the payload that flips a different
    # field would route through the wrong dispatcher arm; pin the shape
    # here so a careless edit surfaces.
    assert expected_drift_kind == "subscribable_tiers", (
        f"payload {_PAYLOAD_ID} drift_kind drifted to {expected_drift_kind!r}; "
        f"this test pins the subscribable_tiers arm of the dispatch re-check"
    )
    assert declared_subscribable != invoked_subscribable
    assert declared_refusable == invoked_refusable
    assert declared_fail_closed == invoked_fail_closed

    spy_sink = SpyAuditSink()
    prior = get_registry()
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        sink=spy_sink,
        strict_declarations=True,
    )
    set_registry(registry)
    try:
        registry.register_hookpoint(
            name=hookpoint,
            subscribable_tiers=declared_subscribable,
            refusable_tiers=declared_refusable,
            fail_closed=declared_fail_closed,
            carrier_tier=T3,
        )

        correlation_id = uuid4().hex
        # The dispatcher's drift defense fires before any subscriber
        # runs; the HookError carries ``subscribable_tiers`` in its
        # message so the operator can grep the right arm.
        with pytest.raises(HookError, match="subscribable_tiers"):
            await invoke(
                hookpoint,
                _ctx(correlation_id),
                kind="pre",
                subscribable_tiers=invoked_subscribable,
                refusable_tiers=invoked_refusable,
                fail_closed=invoked_fail_closed,
            )
    finally:
        set_registry(prior)

    # Exactly one HOOKS_TIER_REJECTED row landed on the spy sink. A
    # second emission would indicate the drift check fired twice (or
    # an upstream check fell through into the drift arm) — both are
    # regressions.
    matching = [c for c in spy_sink.calls if c["event"] == HOOKS_TIER_REJECTED]
    assert len(matching) == 1, (
        f"expected exactly one HOOKS_TIER_REJECTED row for {_PAYLOAD_ID}; got "
        f"{[c['event'] for c in spy_sink.calls]}"
    )
    row = matching[0]
    fields = row["fields"]
    assert isinstance(fields, dict)
    # Closed-vocab attribution: ``drift_at`` distinguishes dispatch-time
    # from register-time rows on the same event id; ``drift_kind`` names
    # the specific field that disagreed. Both are load-bearing for
    # operator alerting (#119 review Group I).
    assert fields["hookpoint"] == hookpoint
    assert fields["kind"] == "pre"
    assert fields["drift_at"] == "dispatch"
    assert fields["drift_kind"] == "subscribable_tiers"
    # Both sets surface on the row so the operator can grep both the
    # publisher's declaration site AND the drifted invoke site.
    assert set(fields["declared_subscribable_tiers"]) == set(declared_subscribable)  # type: ignore[arg-type]
    assert set(fields["invoked_subscribable_tiers"]) == set(invoked_subscribable)  # type: ignore[arg-type]
