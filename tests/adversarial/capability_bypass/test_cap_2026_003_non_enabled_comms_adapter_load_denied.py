"""Adversarial wiring-smoke for the ``cap-2026-003`` corpus payload.

Asserts the **defense fired** at the gate for the ADR-0027 config-sourced
comms-adapter load grants: a comms-adapter ``plugin_id`` the operator did NOT
enable is DENIED at the manifest-tier load handshake, even when it is
first-party-SHAPED (``alfred.comms-*``). ADR-0027 seeds ONE plugin-LOAD grant
per ENABLED adapter and the gate stays a pure grant evaluator — it is NOT
special-cased to "trust first-party by name" (the exact anti-pattern ADR-0026
/ cap-2026-002 guard for the static DLP seed). A pass here would let any
comms-shaped id load by riding the seed — a privilege escalation.

The fixture seeds the REAL output of the production
:func:`alfred.security.capability_gate._comms_adapter_grants.comms_adapter_load_grants`
builder into a :class:`RealGate` (via
:func:`tests.helpers.gates.make_comms_adapter_load_gate`) — NEVER a permissive
shim. The deny here is therefore the production grant policy's verdict, not a
test double's (CLAUDE.md hard rule #2). Mirrors the positive/negative-control
shape of the static-DLP analogue ``test_cap_2026_002_gate_denies_non_seeded_first_party_module``.
"""

from __future__ import annotations

from typing import Final

import pytest

from alfred.config.settings import Settings
from alfred.security.capability_gate._comms_adapter_grants import (
    comms_adapter_load_grants,
)
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_comms_adapter_load_gate

_PAYLOAD_ID: Final[str] = "cap-2026-003"

# The reference adapter the operator enables (dir id) + its manifest plugin id.
_ENABLED_ADAPTER: Final[str] = "alfred_comms_test"


@pytest.fixture
def non_enabled_denied_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus to the wiring-smoke payload.

    Fails loudly if the payload is missing/duplicated so a future rename or
    delete surfaces here (the drift-guard pattern shared across the corpus).
    """
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; expected at "
            "tests/adversarial/capability_bypass/"
            "non_enabled_comms_adapter_load_denied.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            "expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def test_non_enabled_comms_adapter_load_denied(
    non_enabled_denied_payload: AdversarialPayload,
) -> None:
    """A non-enabled comms-shaped plugin_id is DENIED at load.

    Positive control + negative control on the SAME RealGate seeded with the
    REAL builder output:

    * The ENABLED adapter's manifest plugin id is GRANTED at load — the gate
      really does grant the one seeded row, so the deny below is a
      grant-policy verdict, not a blanket-deny gate.
    * A first-party-SHAPED comms plugin_id that is NOT enabled is DENIED —
      proving no "trust by name" bypass rides the config-sourced seed.
    """
    payload_fields = non_enabled_denied_payload.payload
    assert isinstance(payload_fields, dict)
    assert payload_fields["gate_fixture"] == "make_comms_adapter_load_gate"
    assert non_enabled_denied_payload.expected_outcome == "refused"

    enabled_plugin_id = payload_fields["enabled_plugin_id"]
    non_enabled_plugin_id = payload_fields["non_enabled_plugin_id"]
    manifest_tier = payload_fields["manifest_tier"]

    # The non-enabled id must be first-party-SHAPED so the test genuinely
    # probes the "trust by name" bypass (an obviously-foreign id would deny
    # for the trivial reason of not looking like a comms adapter at all).
    assert non_enabled_plugin_id.startswith("alfred.comms-"), (
        f"payload {_PAYLOAD_ID} non_enabled_plugin_id must be first-party-shaped "
        "to probe the name-trust bypass"
    )

    # Seed the gate from the REAL builder output for the enabled adapter.
    settings = Settings(
        environment="test",
        deepseek_api_key="not-a-real-secret-adversarial-test-placeholder",
        comms_enabled_adapters=(_ENABLED_ADAPTER,),
    )
    grants = comms_adapter_load_grants(settings)
    # Sanity: the builder produced the enabled adapter's grant under the
    # manifest plugin id the payload asserts on.
    assert {g.plugin_id for g in grants} == {enabled_plugin_id}

    gate = make_comms_adapter_load_gate(grants)

    # Positive control: the ENABLED adapter loads — the gate is a real grant
    # evaluator, not a blanket deny.
    assert (
        gate.check_plugin_load(
            plugin_id=enabled_plugin_id,
            manifest_tier=manifest_tier,
        )
        is True
    ), "the seeded ENABLED comms-adapter load grant must be live on the fixture gate"

    # The defense: a NON-ENABLED first-party-shaped comms id is DENIED at
    # load — no "trust by name" bypass rides the config-sourced seed.
    assert (
        gate.check_plugin_load(
            plugin_id=non_enabled_plugin_id,
            manifest_tier=manifest_tier,
        )
        is False
    ), (
        f"the gate authorised a NON-ENABLED comms-shaped adapter "
        f"({non_enabled_plugin_id!r}) at load — that is a 'trust by name' "
        "bypass ADR-0027 explicitly forbids (the seed grants ONLY enabled adapters)"
    )
