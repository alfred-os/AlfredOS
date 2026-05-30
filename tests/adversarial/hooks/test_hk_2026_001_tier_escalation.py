"""Hook tier-escalation wiring-smoke assertion for the `hk-2026-001` corpus payload.

Asserts the **defense fired** (not an escalation path): given a user-plugin-
tier subscriber that tries to register on the canonical hookpoint
`memory.episodic.record.before_db_write` requesting
`system` tier, :meth:`HookRegistry.register` MUST raise :class:`HookError`
via the :class:`DevGate` deny path (capability-gate refusal — see Slice-2.5
spec §6.1 + §6.2 + `src/alfred/hooks/registry.py` ll. 412-421). The PoC
contract is:

1. Load the payload through the session-scoped `corpus_payloads` fixture
   (drift-guard — a rename / delete / schema regression on `hk-2026-001`
   surfaces here before the assertion can run).
2. Build a :class:`HookRegistry` with a production-shaped :class:`DevGate`
   (``allow_system=False`` — the deny path the payload's
   ``expected_outcome: refused`` is asserting).
3. Attempt to register a no-op coroutine subscriber on the hookpoint the
   payload names, at the tier the payload's ``requested_tier`` declares.
4. Assert :class:`HookError` is raised + the registry's
   ``subscribers_for(hookpoint, kind)`` returns an empty tuple (the
   ``register`` contract: a failed register MUST leave no trace).

The dispatched-call refusal path (§6.3 — a system-tier subscriber's
``raise HookRefusal(...)`` only honoured if the subscriber is itself
system-tier) is NOT exercised here because the payload's
``attempted_action: refuse`` happens at registration time in this
adversarial — the user-plugin can't even reach the per-call refuse step
without first registering, and the registration gate is the load-bearing
defense.

Mirrors `tests/adversarial/dlp/test_dlp_payload_redaction.py` — the
"payload is loaded AND its defense fires" pattern. See that file's
module docstring for the wiring-smoke discipline this test follows.
"""

from __future__ import annotations

from typing import Final

import pytest

from alfred.hooks.capability import DevGate
from alfred.hooks.context import HookContext
from alfred.hooks.errors import HookError
from alfred.hooks.registry import HookRegistry
from alfred.memory.episodic import EpisodicRecordInput
from tests.adversarial.payload_schema import AdversarialPayload

# Id of the payload this test exercises. Centralised so the failure message
# carries the right pointer if the corpus filter returns nothing.
_PAYLOAD_ID: Final[str] = "hk-2026-001"


@pytest.fixture
def tier_escalation_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus down to the wiring-smoke payload.

    Fails loudly if the payload isn't present so a future rename / delete in
    the corpus surfaces here (and not as a mysterious skipped assertion).
    Mirrors the same drift-guard pattern as the DLP wiring-smoke test.
    """
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; "
            f"expected at tests/adversarial/hooks/tier_escalation.yaml"
        )
        raise pytest.UsageError(msg)
    return matches[0]


def test_hook_registry_refuses_user_plugin_registering_at_system_tier(
    tier_escalation_payload: AdversarialPayload,
) -> None:
    """`HookRegistry.register` MUST raise on a user-plugin requesting system tier.

    Wires a production-shaped :class:`DevGate` (``allow_system=False`` —
    the deny posture per sec-001 in the Slice-2.5 spec) into a fresh
    :class:`HookRegistry`. Defines a no-op async subscriber, attempts to
    register it on the payload's ``hookpoint`` at the payload's
    ``requested_tier``. The capability gate MUST refuse:
    :class:`HookError` raised + ``subscribers_for`` returns empty.
    """
    # Payload shape sanity-pin: the YAML's payload field is the
    # `str | dict[str, Any]` union; this payload uses the dict form. Pin
    # the type so mypy's strict mode stays green and so a future YAML
    # drift into the str form trips this assertion before the real one.
    payload_fields = tier_escalation_payload.payload
    assert isinstance(payload_fields, dict), (
        f"payload {_PAYLOAD_ID} must use the dict form for hook-registration "
        f"escalation (got {type(payload_fields).__name__})"
    )

    # The payload's threat-model shape pins: the canonical fully-qualified
    # hookpoint `memory.episodic.record.before_db_write`, a `system`-tier
    # registration request, and an `attempted_action` of `refuse`. The first
    # two are what we exercise; the third is the downstream intent the gate
    # prevents from ever reaching the dispatcher.
    #
    # The canonical (dotted) form is the threat-model identifier — the form
    # an attacker reading PRD §7.1 / spec §6.3 would target. Runtime dispatch
    # uses the local short-name (`before_db_write`); a future executable
    # harness would need a canonical→runtime resolution layer. Tracked.
    hookpoint = payload_fields["hookpoint"]
    requested_tier = payload_fields["requested_tier"]
    assert hookpoint == "memory.episodic.record.before_db_write", (
        f"payload {_PAYLOAD_ID} hookpoint drifted to {hookpoint!r}; "
        f"this test asserts the registration-gate defense on "
        f"`memory.episodic.record.before_db_write` "
        f"specifically (the security stage per spec §7)"
    )
    assert requested_tier == "system", (
        f"payload {_PAYLOAD_ID} requested_tier drifted to {requested_tier!r}; "
        f"this test asserts the deny path for a `system` escalation"
    )

    # Production-shaped DevGate: `allow_system=False` is the default and
    # the posture sec-001 specifies. Test-only callers that need to
    # exercise the allow-path build `DevGate(allow_system=True)` (see
    # `EpisodicAuditSink`'s class docstring Example) — that posture is
    # NOT under test here.
    # ``strict_declarations=False`` keeps the test focused on the tier
    # gate (the load-bearing defense for this payload); the
    # registration-time tier-allowlist enforcement is its own dedicated
    # adversarial in ``tests/adversarial/test_hooks_tier_enforcement.py``.
    registry = HookRegistry(gate=DevGate(), strict_declarations=False)

    # No-op subscriber — the body is immaterial. The registration gate
    # rejects BEFORE the subscriber is added to any bucket, so the body
    # would never run even if registration somehow succeeded. Typed
    # against `HookContext[EpisodicRecordInput]` because that's the
    # carrier the `memory.episodic.record` action threads through the
    # dispatcher; the type matters for the contract documentation, not
    # for the gate consult.
    async def hostile_user_plugin_subscriber(
        _ctx: HookContext[EpisodicRecordInput],
    ) -> HookContext[EpisodicRecordInput] | None:  # pragma: no cover — gate refuses pre-call
        return None

    # The defense fires: HookError raised, message attributes the refusal
    # to the subscriber + hookpoint pair so the operator can grep the
    # audit graph for the offending plugin.
    with pytest.raises(HookError, match="Capability gate refused"):
        registry.register(
            hook_fn=hostile_user_plugin_subscriber,
            hookpoint=hookpoint,
            kind="pre",
            tier=requested_tier,
        )

    # And a failed register MUST leave no trace — the bucket invariant
    # the `register` docstring promises ("a failed register leaves the
    # registry in a partially-populated state" is the bug; "leaves no
    # trace" is the contract). If a refused subscriber slipped into the
    # bucket, the dispatcher would call it on the next `record(...)`
    # invocation — which IS the escalation hk-2026-001 describes.
    assert registry.subscribers_for(hookpoint, "pre") == (), (
        f"refused subscriber leaked into the registry's ({hookpoint!r}, 'pre') "
        f"bucket — the failed-register-leaves-no-trace contract was violated, "
        f"which IS the escalation path payload {_PAYLOAD_ID} describes"
    )
