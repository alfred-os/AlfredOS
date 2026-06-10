"""Adversarial wiring-smoke for the ``cap-2026-002`` corpus payload.

Asserts the **defense fired** at the gate: a first-party-SHAPED
``plugin_id`` (``alfred.security.<other>``) that is NOT in
:data:`FIRST_PARTY_SYSTEM_GRANTS` is DENIED at system tier on the
``security.quarantined.extract`` chain — proving there is no "trust
first-party by module name" bypass. ADR-0026 is explicit: the seed lands a
real grant row and the gate stays a pure grant evaluator; the gate is NOT
special-cased to trust a module by its name prefix. A pass here would be a
privilege escalation re-introducing the exact anti-pattern the seeded-grant
design exists to avoid.

The fixture is the REAL scoped :func:`make_quarantined_extract_chain_gate`
(:class:`RealGate` granting ONLY the seeded
``alfred.security._extract_dlp_subscriber`` plugin_id at system tier) —
NEVER a permissive shim. The deny here is therefore the production grant
policy's verdict, not a test double's (CLAUDE.md hard rule #2).

Mirrors the wiring-smoke pattern of
:mod:`tests.adversarial.hooks.test_hk_2026_001_tier_escalation` (the
gate-side check).
"""

from __future__ import annotations

from typing import Final

import pytest

from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_quarantined_extract_chain_gate

_PAYLOAD_ID: Final[str] = "cap-2026-002"


@pytest.fixture
def gate_denies_payload(
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
            "gate_denies_non_seeded_first_party_module.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            "expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def test_gate_denies_non_seeded_first_party_module(
    gate_denies_payload: AdversarialPayload,
) -> None:
    """An ``alfred.security.<other>`` module NOT in the seed is DENIED.

    Positive control + negative control on the SAME RealGate:

    * The SEEDED first-party DLP plugin_id is GRANTED (the gate really does
      grant the one seeded row — so the deny below is a grant-policy verdict,
      not a blanket-deny gate).
    * The UNSEEDED first-party-shaped plugin_id is DENIED at system tier on
      the same hookpoint — proving no module-name-prefix bypass.
    """
    payload_fields = gate_denies_payload.payload
    assert isinstance(payload_fields, dict)
    assert payload_fields["gate_fixture"] == "make_quarantined_extract_chain_gate"
    assert gate_denies_payload.expected_outcome == "refused"

    unseeded_plugin_id = payload_fields["unseeded_plugin_id"]
    hookpoint = payload_fields["hookpoint"]
    requested_tier = payload_fields["requested_tier"]

    # The unseeded id must be first-party-SHAPED so the test genuinely
    # probes the "trust by module name" bypass (an arbitrary id would deny
    # for the trivial reason of not looking first-party at all).
    assert unseeded_plugin_id.startswith("alfred.security."), (
        f"payload {_PAYLOAD_ID} unseeded_plugin_id must be first-party-shaped "
        "to probe the module-name-trust bypass"
    )

    gate = make_quarantined_extract_chain_gate()

    # Positive control: the SEEDED first-party plugin_id is granted — the
    # gate is a real grant evaluator, not a blanket deny.
    assert (
        gate.check(
            plugin_id="alfred.security._extract_dlp_subscriber",
            hookpoint=hookpoint,
            requested_tier=requested_tier,
        )
        is True
    ), "the seeded first-party DLP grant must be live on the scoped fixture gate"

    # The defense: an UNSEEDED first-party-shaped module is DENIED at system
    # tier — no "trust by module name" bypass (ADR-0026 Decision 1/2).
    assert (
        gate.check(
            plugin_id=unseeded_plugin_id,
            hookpoint=hookpoint,
            requested_tier=requested_tier,
        )
        is False
    ), (
        f"the gate authorised an UNSEEDED first-party-shaped module "
        f"({unseeded_plugin_id!r}) at system tier — that is a 'trust by "
        "module name' bypass ADR-0026 explicitly forbids"
    )
