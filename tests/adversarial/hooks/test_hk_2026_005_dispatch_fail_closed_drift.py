"""Adversarial wiring-smoke for the `hk-2026-005` corpus payload.

Asserts the **defense fired** at DISPATCH time for the highest-blast
arm of the #119 Group I dispatch-time drift re-check: a publisher
declared ``fail_closed=True`` (the correct posture for any security-
stage hookpoint per CLAUDE.md hard rule #7 — no silent failures) but
invokes the chain with ``fail_closed=False``. Silently honouring the
drifted bit would disarm the fail-closed timeout/subscriber-error
policy on every dispatch, letting a faulty subscriber proceed as
pass-through where the declaration explicitly required a hard refusal.

This is the HIGHEST-BLAST drift_kind because the other two
(``subscribable_tiers`` / ``refusable_tiers``) widen the allow-list
but the action body still completes normally; this one silently
DISARMS the entire fail-closed contract, so a botched DLP subscriber
on a security stage would silently let secret-shaped content through
on the timeout arm.

The dispatcher's :func:`alfred.hooks.invoke._enforce_subscribable_tiers`
MUST:

1. Raise :class:`HookError` from :func:`invoke` before any subscriber
   runs.
2. Emit exactly one :data:`HOOKS_TIER_REJECTED` audit row carrying
   ``drift_at="dispatch"`` + ``drift_kind="fail_closed"``.
3. Carry the declared and invoked ``fail_closed`` bits on the row's
   ``fields`` mapping so the operator can grep both the publisher's
   declaration site AND the drifted invoke site.

Companion payloads in this PR pin the other two drift arms; see
:mod:`tests.adversarial.hooks.test_hk_2026_003_dispatch_subscribable_tiers_drift`
+ :mod:`tests.adversarial.hooks.test_hk_2026_004_dispatch_refusable_tiers_drift`.
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

_PAYLOAD_ID: Final[str] = "hk-2026-005"


@pytest.fixture
def dispatch_fail_closed_drift_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus down to the wiring-smoke payload."""
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; "
            f"expected at tests/adversarial/hooks/dispatch_fail_closed_drift.yaml"
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
        action_id="action.adversarial.hk-2026-005",
        hookpoint="action.adversarial.hk-2026-005",
        input=None,
        correlation_id=correlation_id,
        kind="pre",
    )


@pytest.mark.asyncio
async def test_dispatch_fail_closed_drift_refused_and_audited(
    dispatch_fail_closed_drift_payload: AdversarialPayload,
) -> None:
    """Dispatch with a drifted ``fail_closed`` MUST refuse + audit.

    The highest-blast arm: a publisher's declared ``fail_closed=True``
    on a security stage is the load-bearing pin for CLAUDE.md hard
    rule #7 (no silent failures). A drift to ``fail_closed=False`` at
    the invoke site silently disarms the entire policy — every
    subsequent timeout / subscriber error becomes a pass-through
    instead of a hard fault. The dispatcher catches the drift on the
    NEXT invoke and refuses the chain BEFORE the disarmed policy can
    take effect.
    """
    payload_fields = dispatch_fail_closed_drift_payload.payload
    assert isinstance(payload_fields, dict)

    hookpoint = payload_fields["hookpoint"]
    declared_subscribable = frozenset(payload_fields["declared_subscribable_tiers"])
    declared_refusable = frozenset(payload_fields["declared_refusable_tiers"])
    declared_fail_closed = payload_fields["declared_fail_closed"]
    invoked_subscribable = frozenset(payload_fields["invoked_subscribable_tiers"])
    invoked_refusable = frozenset(payload_fields["invoked_refusable_tiers"])
    invoked_fail_closed = payload_fields["invoked_fail_closed"]
    expected_drift_kind = payload_fields["drift_kind"]

    # Payload sanity-pin: only fail_closed drifts, and the declared
    # posture is True (the security-stage default).
    assert expected_drift_kind == "fail_closed"
    assert declared_subscribable == invoked_subscribable
    assert declared_refusable == invoked_refusable
    assert declared_fail_closed != invoked_fail_closed
    assert declared_fail_closed is True
    assert invoked_fail_closed is False

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
        with pytest.raises(HookError, match="fail_closed"):
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
    assert fields["drift_kind"] == "fail_closed"
    # Both fail_closed bits surface on the row — the operator's
    # grep-target for reconciling both sides of the drift. Pin as
    # ``is True`` / ``is False`` to catch a future schema regression
    # that boolean-coerces (e.g. the bit ending up as the string
    # ``"True"``).
    assert fields["declared_fail_closed"] is True
    assert fields["invoked_fail_closed"] is False
