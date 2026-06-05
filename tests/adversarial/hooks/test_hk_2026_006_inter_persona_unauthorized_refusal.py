"""Adversarial wiring-smoke for the `hk-2026-006` corpus payload — Cat-5
inter-persona escalation via unauthorized hook refusal.

Asserts the **defense fired** for the spec §6.5 refusal-authorization
contract under a Cat-5 inter-persona escalation shape. The threat:

* Persona A loaded a ``user-plugin``-tier subscriber on Persona B's
  security-stage hookpoint (this part is a separate threat — the
  subscriber was either granted via configuration or Persona A's
  plugin set drifted into Persona B's domain).
* The user-plugin subscriber raises :class:`HookRefusal` from the
  ``pre`` chain hoping to short-circuit the action body — the
  highest-blast move on a security stage, because a refusal denies
  the operation outright.
* The hookpoint's declared ``refusable_tiers={"system"}`` excludes
  user-plugin — only DLP / capability-gate-tier subscribers may
  short-circuit security-stage actions on Persona B's behalf.

The dispatcher's :func:`alfred.hooks.invoke._run_pre` §6.5 arm MUST:

1. Detect the subscriber's tier (``user-plugin``) is NOT in
   ``refusable_tiers`` (``{"system"}``).
2. Emit exactly one :data:`HOOKS_UNAUTHORIZED_REFUSAL` audit row
   carrying ``hookpoint`` / ``kind`` / ``subscriber_name`` /
   ``subscriber_tier`` so the operator can grep the offending
   plugin's source.
3. SWALLOW the refusal — the :class:`HookRefusal` MUST NOT reach the
   caller. The action body must still run with the last-good ctx
   (Persona B's action body is not blocked by a sibling persona's
   user-plugin refusal claim).
4. Continue the chain — a subsequent (legitimate) subscriber on the
   same hookpoint sees the last-good ctx (the would-be mutation
   from the unauthorized refuser is discarded).
5. NEVER copy the subscriber-supplied ``refusal.reason`` string
   onto the audit row — CLAUDE.md hard rule #1 (the reason may
   carry T3 user content, and the unauthorized arm has no
   propagating exception to carry it either; the reason is durably
   lost, by design).

Spec anchor: §6.5 lines 138-148 of
``docs/superpowers/specs/2026-05-27-slice-2.5-hooks-design.md``
describe the "fail-loud via audit, not raised error" disposition
the dispatcher implements here.

Companion payloads:

* :mod:`tests.adversarial.hooks.test_hk_2026_001_tier_escalation` —
  the register-time gate-side arm (escalation attempt at decoration
  time).
* :mod:`tests.adversarial.hooks.test_hk_2026_002_registration_tier_rejection`
  — the register-time tier-allowlist arm.
"""

from __future__ import annotations

from typing import Any, Final
from uuid import uuid4

import pytest

from alfred.hooks.audit_sink import HOOKS_REFUSAL, HOOKS_UNAUTHORIZED_REFUSAL
from alfred.hooks.context import HookContext
from alfred.hooks.errors import HookRefusal
from alfred.hooks.invoke import invoke
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_permissive_fixture_gate
from tests.unit.hooks.conftest import SpyAuditSink

_PAYLOAD_ID: Final[str] = "hk-2026-006"


@pytest.fixture
def inter_persona_unauthorized_refusal_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus down to the wiring-smoke payload."""
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; "
            f"expected at tests/adversarial/hooks/inter_persona_unauthorized_refusal.yaml"
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
        action_id="action.adversarial.hk-2026-006",
        hookpoint="action.adversarial.hk-2026-006",
        input="last-good-payload",
        correlation_id=correlation_id,
        kind="pre",
    )


@pytest.mark.asyncio
async def test_inter_persona_user_plugin_refusal_swallowed_and_audited(
    inter_persona_unauthorized_refusal_payload: AdversarialPayload,
) -> None:
    """A ``user-plugin``-tier refusal on a hookpoint with
    ``refusable_tiers={"system"}`` MUST be swallowed + audited.

    Reproduces the Cat-5 inter-persona escalation end-to-end:

    1. Install a fresh :class:`HookRegistry` carrying the spy sink so
       the audit row is observable.
    2. Declare the hookpoint with the payload's
       ``refusable_tiers={"system"}`` (the operator's locked-down
       security-stage posture).
    3. Register a ``user-plugin``-tier subscriber that raises
       :class:`HookRefusal` from its ``pre`` hook (the attacker's
       attempt).
    4. Invoke the chain. The dispatcher's §6.5 arm MUST swallow the
       refusal: :func:`invoke` returns normally with the last-good
       ctx (NOT raise :class:`HookRefusal` to the caller).
    5. Assert exactly one :data:`HOOKS_UNAUTHORIZED_REFUSAL` row
       landed, NO :data:`HOOKS_REFUSAL` row landed, and the row
       carries the closed-vocab attribution fields.
    """
    payload_fields = inter_persona_unauthorized_refusal_payload.payload
    assert isinstance(payload_fields, dict), (
        f"payload {_PAYLOAD_ID} must use the dict form for the §6.5 "
        f"unauthorized-refusal shape (got {type(payload_fields).__name__})"
    )

    hookpoint = payload_fields["hookpoint"]
    declared_subscribable = frozenset(payload_fields["declared_subscribable_tiers"])
    declared_refusable = frozenset(payload_fields["declared_refusable_tiers"])
    subscriber_tier = payload_fields["subscriber_tier"]
    attempted_action = payload_fields["attempted_action"]

    # Payload sanity-pin: the subscriber is user-plugin (in the
    # subscribable allow-list — the subscriber legitimately registered),
    # but the refusable allow-list is system-only (so the refusal claim
    # is unauthorized).
    assert subscriber_tier == "user-plugin", (
        f"payload {_PAYLOAD_ID} subscriber_tier drifted to {subscriber_tier!r}; "
        f"this test pins the §6.5 unauthorized-refusal arm for the "
        f"user-plugin tier specifically"
    )
    assert attempted_action == "refuse"
    assert subscriber_tier in declared_subscribable, (
        f"payload {_PAYLOAD_ID} subscriber_tier ({subscriber_tier!r}) NOT in "
        f"declared_subscribable_tiers ({sorted(declared_subscribable)!r}); "
        f"the subscriber must be able to REGISTER (subscribable arm) for the "
        f"§6.5 REFUSAL-authorization arm to engage. A subscribable-tier "
        f"refusal would route through the register-time gate, not §6.5."
    )
    assert subscriber_tier not in declared_refusable, (
        f"payload {_PAYLOAD_ID} subscriber_tier ({subscriber_tier!r}) IS in "
        f"declared_refusable_tiers ({sorted(declared_refusable)!r}); "
        f"this test pins the UNAUTHORIZED-refusal arm — the subscriber's "
        f"tier MUST be outside the refusable set for §6.5 to swallow"
    )

    spy_sink = SpyAuditSink()
    prior = get_registry()
    # ``allow_system=True`` so the system-tier subscriber path is
    # generically registerable on the fixture-parity gate, even though
    # the adversarial subscriber here is user-plugin (the gate is
    # permissive on user-plugin too). The
    # ``strict_declarations=False`` keeps the focus on the §6.5 arm —
    # the dispatch-time meta-drift arms are pinned by hk-2026-003/4/5,
    # not here.
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        sink=spy_sink,
        strict_declarations=False,
    )
    set_registry(registry)
    try:
        registry.register_hookpoint(
            name=hookpoint,
            subscribable_tiers=declared_subscribable,
            refusable_tiers=declared_refusable,
            fail_closed=True,
        )

        # The adversarial subscriber: a user-plugin-tier hook claiming
        # the right to refuse a security-stage action. The
        # ``refusal.reason`` carries an attacker-controlled string the
        # audit row MUST NOT propagate (CLAUDE.md hard rule #1) — the
        # assertion below confirms the reason never reaches the row.
        attacker_reason = "persona-a-claims-persona-b-action-violates-policy"

        async def adversarial_user_plugin_refuser(
            _ctx: HookContext[Any],
        ) -> HookContext[Any] | None:
            raise HookRefusal(
                hook_id="hook.adversarial.persona-a-relay",
                action_id="action.adversarial.hk-2026-006",
                reason=attacker_reason,
                correlation_id="corr-hk-006",
            )

        registry.register(
            hook_fn=adversarial_user_plugin_refuser,
            hookpoint=hookpoint,
            kind="pre",
            tier=subscriber_tier,
        )

        correlation_id = uuid4().hex
        # The §6.5 arm SWALLOWS the refusal — :func:`invoke` returns
        # normally with the last-good ctx. A :class:`HookRefusal`
        # reaching the caller would mean the dispatcher honoured the
        # unauthorized refusal, which IS the escalation hk-2026-006
        # describes.
        result = await invoke(
            hookpoint,
            _ctx(correlation_id),
            kind="pre",
            subscribable_tiers=declared_subscribable,
            refusable_tiers=declared_refusable,
            fail_closed=True,
        )
        # The chain returned the last-good ctx (input unchanged because
        # the unauthorized refuser's would-be mutation was discarded).
        assert result.hookpoint == hookpoint
        assert result.input == "last-good-payload", (
            f"the unauthorized refuser's would-be mutation should have "
            f"been discarded — last-good rewind is part of the §6.5 "
            f"swallow-and-continue contract. Got input={result.input!r}"
        )
    finally:
        set_registry(prior)

    # Exactly one HOOKS_UNAUTHORIZED_REFUSAL row landed; NO HOOKS_REFUSAL
    # row landed (the authorized-refusal arm did NOT fire).
    unauthorized = [c for c in spy_sink.calls if c["event"] == HOOKS_UNAUTHORIZED_REFUSAL]
    authorized = [c for c in spy_sink.calls if c["event"] == HOOKS_REFUSAL]
    assert len(unauthorized) == 1, (
        f"expected exactly one HOOKS_UNAUTHORIZED_REFUSAL row for {_PAYLOAD_ID}; "
        f"got events {[c['event'] for c in spy_sink.calls]}"
    )
    assert authorized == [], (
        f"expected NO HOOKS_REFUSAL row (the refusal is unauthorized — "
        f"§6.5 routes it to HOOKS_UNAUTHORIZED_REFUSAL exclusively). Got "
        f"{len(authorized)} HOOKS_REFUSAL rows."
    )

    row = unauthorized[0]
    fields = row["fields"]
    assert isinstance(fields, dict)
    # Closed-vocab attribution: hookpoint + kind + subscriber name +
    # subscriber tier. Operators grep on tier to spot a Cat-5
    # escalation pattern across the audit graph.
    assert fields["hookpoint"] == hookpoint
    assert fields["kind"] == "pre"
    assert fields["subscriber_name"] == adversarial_user_plugin_refuser.__qualname__
    assert fields["subscriber_tier"] == subscriber_tier

    # CLAUDE.md hard rule #1: the attacker-controlled ``refusal.reason``
    # string MUST NOT appear anywhere on the row. The unauthorized arm
    # has no propagating exception to carry it either, so the reason is
    # durably lost — by design (the spec's "an unauthorized subscriber's
    # reason is by definition untrustworthy" disposition).
    for value in fields.values():
        if isinstance(value, str):
            assert attacker_reason not in value, (
                f"attacker-controlled refusal.reason leaked into the audit "
                f"row field {value!r} — CLAUDE.md hard rule #1 violation"
            )
