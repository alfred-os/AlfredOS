"""Adversarial wiring-smoke for the `hk-2026-004` corpus payload.

Asserts the **defense fired** at DISPATCH time for the
``refusable_tiers`` arm of the #119 Group I dispatch-time drift
re-check. The threat shape: a publisher declared
``refusable_tiers={"system"}`` (only DLP / capability-gate-tier subscribers
may short-circuit the action body) but invokes the chain with a
widened ``refusable_tiers={"system","operator"}``. Silently honouring
the wider set would let an operator-tier subscriber refuse on a
hookpoint the publisher explicitly locked to system-only refusals —
defeating the spec §6.5 refusal-authorization contract.

The dispatcher's defense-in-depth re-check
(:func:`alfred.hooks.invoke._enforce_subscribable_tiers`) MUST:

1. Raise :class:`HookError` from :func:`invoke` before any subscriber
   runs.
2. Emit exactly one :data:`HOOKS_TIER_REJECTED` audit row carrying
   ``drift_at="dispatch"`` + ``drift_kind="refusable_tiers"`` so the
   operator can grep the right field.
3. Carry the declared refusable allow-list (for grep + attribution to
   the publisher's declaration site).

Companion payloads in this PR:

* :mod:`tests.adversarial.hooks.test_hk_2026_003_dispatch_subscribable_tiers_drift`
  — the subscribable arm.
* :mod:`tests.adversarial.hooks.test_hk_2026_005_dispatch_fail_closed_drift`
  — the fail_closed arm (highest-blast).
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
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_permissive_fixture_gate
from tests.unit.hooks.conftest import SpyAuditSink
from alfred.security.tiers import T0, T1, T2, T3

_PAYLOAD_ID: Final[str] = "hk-2026-004"


@pytest.fixture
def dispatch_refusable_tiers_drift_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus down to the wiring-smoke payload."""
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; "
            f"expected at tests/adversarial/hooks/dispatch_refusable_tiers_drift.yaml"
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
    """Build a fresh frozen :class:`HookContext` for a synthetic action."""
    return HookContext(
        action_id="action.adversarial.hk-2026-004",
        hookpoint="action.adversarial.hk-2026-004",
        input=None,
        correlation_id=correlation_id,
        kind="pre",
    )


@pytest.mark.asyncio
async def test_dispatch_refusable_tiers_drift_refused_and_audited(
    dispatch_refusable_tiers_drift_payload: AdversarialPayload,
) -> None:
    """Dispatch with a drifted ``refusable_tiers`` MUST refuse + audit.

    The threat-model attribution: the dispatcher's #119 Group I check
    re-validates ALL three publisher-declared fields, not just
    subscribable_tiers (the spec's original wording). A drift on
    refusable_tiers silently widens which tiers may short-circuit the
    action body — the same threat shape as the subscribable case, on
    the refusal-authorization axis (spec §6.5).
    """
    payload_fields = dispatch_refusable_tiers_drift_payload.payload
    assert isinstance(payload_fields, dict)

    hookpoint = payload_fields["hookpoint"]
    declared_subscribable = frozenset(payload_fields["declared_subscribable_tiers"])
    declared_refusable = frozenset(payload_fields["declared_refusable_tiers"])
    declared_fail_closed = payload_fields["declared_fail_closed"]
    invoked_subscribable = frozenset(payload_fields["invoked_subscribable_tiers"])
    invoked_refusable = frozenset(payload_fields["invoked_refusable_tiers"])
    invoked_fail_closed = payload_fields["invoked_fail_closed"]
    expected_drift_kind = payload_fields["drift_kind"]

    # Payload sanity-pin: only ``refusable_tiers`` drifts.
    assert expected_drift_kind == "refusable_tiers"
    assert declared_subscribable == invoked_subscribable
    assert declared_refusable != invoked_refusable
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
        with pytest.raises(HookError, match="refusable_tiers"):
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

    matching = [c for c in spy_sink.calls if c["event"] == HOOKS_TIER_REJECTED]
    assert len(matching) == 1, (
        f"expected exactly one HOOKS_TIER_REJECTED row for {_PAYLOAD_ID}; got "
        f"{[c['event'] for c in spy_sink.calls]}"
    )
    fields = matching[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["hookpoint"] == hookpoint
    assert fields["kind"] == "pre"
    assert fields["drift_at"] == "dispatch"
    assert fields["drift_kind"] == "refusable_tiers"
    # The declared refusable allow-list surfaces on every dispatch-time
    # drift row (not gated on drift_kind) — pin its presence so a
    # future schema-trim that drops the field surfaces here.
    assert set(fields["declared_refusable_tiers"]) == set(declared_refusable)  # type: ignore[arg-type]
    # The invoked refusable allow-list is conditional: ``_enforce_subscribable_tiers``
    # only adds it to the row when refusable_tiers was passed at the
    # call site (not None). Our test passes it, so the row carries it.
    assert set(fields["invoked_refusable_tiers"]) == set(invoked_refusable)  # type: ignore[arg-type]
