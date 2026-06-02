"""Adversarial wiring-smoke for the `hk-2026-002` corpus payload (#119).

Asserts the **defense fired** at registration time: given a hookpoint
declared with ``subscribable_tiers={"system","operator"}`` — the
allow-list contract :mod:`alfred.memory.episodic` declares for its
``before_db_write`` stem (the dotted form ``memory.episodic.record.before_db_write``
is the canonical threat-model identifier the corpus YAML carries; the
Slice-2.5 in-process publisher keys on the local stem per the "Hookpoint
naming" callout in :doc:`/subsystems/hooks`). The test re-declares the
payload's dotted identifier here so the faithfulness pin is
publisher-contract-equivalent without coupling the adversarial harness
to the publisher's stem-vs-dotted resolution. An attempt to register a
``user-plugin``-tier subscriber MUST:

1. Raise :class:`HookError` from :meth:`HookRegistry.register` (the
   registration-time tier-allowlist gate added in commit 2 of #119).
2. Emit a :data:`HOOKS_TIER_REJECTED` audit row carrying the
   hookpoint, the requested tier, the subscriber name, and the
   declared allow-list — the four fields the operator needs to attribute
   the rejection and grep the publisher's source.
3. Leave NO trace in the registry — ``subscribers_for(hookpoint,
   "pre")`` returns the empty singleton after the raise.

Mirrors the wiring-smoke pattern of
:mod:`tests.adversarial.hooks.test_hk_2026_001_tier_escalation` (the
gate-side check) and :mod:`tests.adversarial.dlp.test_dlp_payload_redaction`
(the load-and-fire shape every adversarial follows).

Spec anchor: lines 696-697 of
``docs/superpowers/specs/2026-05-27-slice-2.5-hooks-design.md``
documented the expected behaviour as part of the slice-2.5 follow-up
(#119); this test is the executable wiring for it.
"""

from __future__ import annotations

from typing import Final

import pytest

from alfred.hooks.audit_sink import HOOKS_TIER_REJECTED
from alfred.hooks.context import HookContext
from alfred.hooks.errors import HookError
from alfred.hooks.registry import HookRegistry
from alfred.memory.episodic import EpisodicRecordInput
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_default_test_gate
from tests.unit.hooks.conftest import SpyAuditSink

_PAYLOAD_ID: Final[str] = "hk-2026-002"


@pytest.fixture
def registration_tier_rejection_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus down to the wiring-smoke payload.

    Fails loudly if the payload isn't present so a future rename / delete
    in the corpus surfaces here. Mirrors the drift-guard pattern from
    :func:`tests.adversarial.hooks.test_hk_2026_001_tier_escalation.tier_escalation_payload`.
    """
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; "
            f"expected at tests/adversarial/hooks/registration_tier_rejection.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            f"expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def test_user_plugin_rejected_on_security_hookpoint(
    registration_tier_rejection_payload: AdversarialPayload,
) -> None:
    """Registration of a user-plugin subscriber on a
    ``{"system","operator"}``-declared hookpoint MUST raise + audit.

    Reproduces the registration-time tier-allowlist gate end-to-end:

    1. Construct a fresh :class:`HookRegistry` with a :class:`SpyAuditSink`
       so the audit row is observable from the test.
    2. Declare the hookpoint with the payload's
       ``declared_subscribable_tiers``.
    3. Attempt to register a no-op coroutine subscriber on the
       hookpoint at the payload's ``requested_tier``.
    4. Assert :class:`HookError` raises with the new "tier not allowed
       on hookpoint" message + the :data:`HOOKS_TIER_REJECTED` audit
       row lands + the registry's bucket stays empty.

    The :class:`make_default_test_gate` is constructed with ``allow_system=False`` —
    the production posture per sec-001. Were the registration to slip
    past the new tier-allowlist gate, the existing capability-gate
    deny path (covered by :mod:`tests.adversarial.hooks.test_hk_2026_001_tier_escalation`)
    would still catch the system-tier subset; this test ONLY exercises
    the new register-time tier-allowlist gate from #119, with a
    user-plugin tier the existing :class:`make_default_test_gate` would have
    accepted.
    """
    # Payload shape sanity — dict form is what the new payload uses.
    payload_fields = registration_tier_rejection_payload.payload
    assert isinstance(payload_fields, dict), (
        f"payload {_PAYLOAD_ID} must use the dict form for hook-registration "
        f"tier-rejection (got {type(payload_fields).__name__})"
    )

    hookpoint = payload_fields["hookpoint"]
    declared_tiers = frozenset(payload_fields["declared_subscribable_tiers"])
    requested_tier = payload_fields["requested_tier"]

    # The threat-model anchor: the requested tier is user-plugin (NOT
    # system, the hk-2026-001 shape). The new register-time gate must
    # catch THIS shape; the existing capability-gate path catches the
    # system-escalation shape.
    assert requested_tier == "user-plugin", (
        f"payload {_PAYLOAD_ID} requested_tier drifted to {requested_tier!r}; "
        f"this test asserts the user-plugin-rejected arm (the new #119 gate)"
    )
    assert declared_tiers == frozenset({"system", "operator"}), (
        f"payload {_PAYLOAD_ID} declared_subscribable_tiers drifted to "
        f"{sorted(declared_tiers)!r}; this test asserts the deny path for "
        f"a publisher that excluded user-plugin from the allow-list"
    )

    spy_sink = SpyAuditSink()
    # ``make_default_test_gate()`` is the production posture
    # (sec-001). For a user-plugin tier, ``the fixture-parity gate.check`` would return
    # True (user-plugin is unconditionally granted by the dev gate); the
    # rejection here comes from the new register-time tier-allowlist
    # gate, NOT the capability gate.
    registry = HookRegistry(gate=make_default_test_gate(), sink=spy_sink, strict_declarations=True)

    # Declare the hookpoint with the SAME metadata the production
    # publisher (:mod:`alfred.memory.episodic`) declares. The
    # adversarial faithfulness pin: a drift in the publisher's
    # declaration here would surface as this assertion drifting from
    # the payload's ``declared_subscribable_tiers``.
    registry.register_hookpoint(
        name=hookpoint,
        subscribable_tiers=declared_tiers,
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )

    async def hostile_user_plugin_subscriber(
        _ctx: HookContext[EpisodicRecordInput],
    ) -> HookContext[EpisodicRecordInput] | None:  # pragma: no cover — gate refuses pre-call
        return None

    # The defense fires: HookError carries the "tier not allowed on
    # hookpoint" message + the declared allow-list so the operator can
    # attribute the rejection without grepping the source.
    with pytest.raises(HookError, match="not allowed on hookpoint"):
        registry.register(
            hook_fn=hostile_user_plugin_subscriber,
            hookpoint=hookpoint,
            kind="pre",
            tier=requested_tier,
        )

    # The audit row landed synchronously through the spy sink.
    matching = [c for c in spy_sink.calls if c["event"] == HOOKS_TIER_REJECTED]
    assert len(matching) == 1, (
        f"expected exactly one HOOKS_TIER_REJECTED row for {_PAYLOAD_ID}; got "
        f"{[c['event'] for c in spy_sink.calls]}"
    )
    fields = matching[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["hookpoint"] == hookpoint
    assert fields["kind"] == "pre"
    assert fields["subscriber_tier"] == requested_tier
    assert fields["subscriber_name"] == hostile_user_plugin_subscriber.__qualname__
    # The declared allow-list surfaces so the operator can grep both
    # the publisher's declaration and the offending subscriber's source
    # without ambiguity.
    assert set(fields["subscribable_tiers"]) == set(declared_tiers)  # type: ignore[arg-type]

    # The bucket-invariant: a failed register MUST leave no trace.
    # Without this, a subsequent ``invoke(...)`` would call the refused
    # subscriber on every action — defeating the gate.
    assert registry.subscribers_for(hookpoint, "pre") == (), (
        f"refused user-plugin subscriber leaked into the registry's "
        f"({hookpoint!r}, 'pre') bucket — the failed-register-leaves-no-trace "
        f"contract was violated, which IS the escalation path payload "
        f"{_PAYLOAD_ID} describes"
    )
