"""Adversarial tier_laundering — user-plugin → system-only hookpoint refused.

Spec §4.3 + §8.2: ``subscriber_tier`` and ``content_tier`` are
orthogonal axes. The capability gate enforces both independently — a
``user-plugin`` subscriber registering on a hookpoint whose declared
``subscribable_tiers`` set is ``{"system"}`` is refused at registration
time by the ``HookRegistry.register`` tier-allowlist gate (#119 / spec
§6.2 registration-time enforcement). The refusal lands ``HookError``
with the tier-not-subscribable message AND emits a
``hooks.tier_rejected`` audit row.

This module covers the AI-architecture-critical attack: a hostile
user-plugin tries to slip into a T3-carrying integration hookpoint
(here ``memory.episodic.record.before_db_write``) by claiming
``subscriber_tier=user-plugin`` and hoping the orthogonal axis design
lets the registration past. The defence refuses BEFORE the gate's
content-tier check ever runs.

Mirrors ``test_hk_2026_001_tier_escalation.py`` — the "payload is
loaded AND its defense fires" wiring-smoke pattern. Spec §4.3, §8.2,
§12.2. Payload id: ``tl-2026-006``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
import yaml

from alfred.hooks.context import HookContext
from alfred.hooks.errors import HookError
from alfred.hooks.registry import HookRegistry
from alfred.memory.episodic import EpisodicRecordInput
from tests.helpers.gates import make_deny_all_gate

_PAYLOAD_ID: Final[str] = "tl-2026-006"
_PAYLOAD_PATH: Final[Path] = (
    Path(__file__).parent / "tl_capability_gate_bypass_subscriber_tier.yaml"
)


def test_payload_yaml_present_and_well_formed() -> None:
    """Drift-guard: the ``tl-2026-006`` YAML exists with the expected shape.

    A future rename / delete of the payload surfaces here before the
    behavioural test can ever run.
    """
    assert _PAYLOAD_PATH.exists(), f"Missing adversarial payload {_PAYLOAD_PATH.name}"
    payload = yaml.safe_load(_PAYLOAD_PATH.read_text())
    assert payload["id"] == _PAYLOAD_ID
    assert payload["category"] == "tier_laundering"
    assert payload["ingestion_path"] == "capability_gate"
    assert payload["expected_outcome"] == "refused"
    # The payload's intent: a user-plugin subscriber on the
    # memory.episodic.record T3-carrying hookpoint.
    assert payload["payload"]["requested_tier"] == "user-plugin"
    assert payload["payload"]["hookpoint"] == "memory.episodic.record.before_db_write"


def test_user_plugin_subscriber_refused_on_system_only_hookpoint() -> None:
    """``HookRegistry.register`` refuses a user-plugin tier on a system-only hookpoint.

    Wires the production-shaped :class:`RealGate` deny path
    (:func:`make_deny_all_gate` — Slice-3 spec §15.1 mandates the
    adversarial corpus assert against RealGate). The gate is
    consulted only after the registration-time tier-allowlist; here
    the allowlist fires first, with the gate as defense-in-depth.
    Defines a no-op async subscriber, attempts to register on the
    ``memory.episodic.record.before_db_write`` hookpoint at the
    ``user-plugin`` tier. The registry's ``subscribable_tiers``
    enforcement (#119) MUST refuse: HookError raised +
    ``subscribers_for`` returns empty.

    This is the bypass-impossible posture for the two-axis design — an
    attacker who tries to slip into a T3-carrying hookpoint by
    claiming an orthogonal subscriber_tier value never reaches the
    content-tier gate; the registration-time tier-allowlist refuses
    first.
    """
    # ``strict_declarations=True`` mirrors production: hookpoint
    # metadata MUST be declared before register accepts a subscriber.
    # The episodic publisher declares ``memory.episodic.record.*`` at
    # module-init time (a side-effect of importing
    # ``alfred.memory.episodic``). Force re-declaration via the local
    # registry below so the test doesn't depend on global import order.
    registry = HookRegistry(gate=make_deny_all_gate(), strict_declarations=True)
    registry.register_hookpoint(
        name="memory.episodic.record.before_db_write",
        subscribable_tiers=frozenset({"system"}),
        refusable_tiers=frozenset(),
        fail_closed=True,
    )

    async def hostile_user_plugin_subscriber(
        _ctx: HookContext[EpisodicRecordInput],
    ) -> HookContext[EpisodicRecordInput] | None:  # pragma: no cover — gate refuses pre-call
        return None

    # The defense fires: HookError raised with the tier-mismatch
    # message. ``tier_not_subscribable_message`` carries both the
    # requested tier AND the allowed set so the operator can
    # diagnose the mismatch from the audit log without grepping the
    # source.
    with pytest.raises(HookError) as excinfo:
        registry.register(
            hook_fn=hostile_user_plugin_subscriber,
            hookpoint="memory.episodic.record.before_db_write",
            kind="pre",
            tier="user-plugin",
        )

    message = str(excinfo.value)
    assert "user-plugin" in message, (
        f"Refusal message must mention the requested tier; got: {message!r}"
    )
    assert "system" in message, (
        f"Refusal message must reference the allowed tier set; got: {message!r}"
    )

    # And the failed register MUST leave no trace — the bucket
    # invariant the register docstring promises.
    assert registry.subscribers_for("memory.episodic.record.before_db_write", "pre") == (), (
        "Refused user-plugin subscriber leaked into the registry bucket — "
        f"the failed-register-leaves-no-trace contract was violated for "
        f"payload {_PAYLOAD_ID}."
    )
