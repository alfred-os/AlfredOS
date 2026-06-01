"""Adversarial tier_laundering — tag_t3_with_nonce from orchestrator-module context.

The nonce gate (spec §3.2) defends T3 content construction against ANY
caller — including code running inside the privileged orchestrator
process itself — that does not hold the live `CapabilityGateNonce`
reference. The forensic `caller_module_unverified` field, derived from
``sys._getframe(1).f_globals.get('__name__')``, is captured for audit
attribution; the actual gate is the ``is``-check on the nonce object.

This module covers the AI-architecture-critical case: an attacker who
reaches in-process code execution inside the orchestrator process tries
to forge T3 content by calling ``tag_t3_with_nonce`` without the live
nonce token. Even if the forged ``__name__`` reads as orchestrator-
internal (``alfred.core.orchestrator``), the call still fails — the
``ValueError`` is raised before the function returns, and the
``security.t3_boundary.refused`` structlog event records the forged
label so operators can trace the attempt.

Spec §3.2, §3.8, §12.2. Payload id: ``tl-2026-005``.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import ModuleType
from typing import Final

import pytest
import structlog.testing
import yaml

from alfred.security.tiers import tag_t3_with_nonce

# Id of the payload this test exercises. Centralised so the failure
# message carries the right pointer if the corpus filter returns nothing.
_PAYLOAD_ID: Final[str] = "tl-2026-005"
_PAYLOAD_PATH: Final[Path] = Path(__file__).parent / "tl_tag_t3_from_orchestrator_module.yaml"


def test_payload_yaml_present_and_well_formed() -> None:
    """The YAML payload exists and parses with the expected shape.

    Drift-guard: a future rename / delete of the YAML surfaces here
    instead of as a mysterious skipped assertion downstream.
    """
    assert _PAYLOAD_PATH.exists(), (
        f"Missing adversarial payload {_PAYLOAD_PATH.name}; expected the tl-2026-005 corpus entry."
    )
    payload = yaml.safe_load(_PAYLOAD_PATH.read_text())
    assert payload["id"] == _PAYLOAD_ID
    assert payload["category"] == "tier_laundering"
    assert payload["ingestion_path"] == "capability_gate"
    assert payload["expected_outcome"] == "boundary_refused"


def test_tag_t3_from_orchestrator_module_context_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calling ``tag_t3_with_nonce`` from inside ``alfred.core.orchestrator`` fails.

    The frame ``__name__`` reads as orchestrator-internal — exactly the
    forgery surface the audit-log reader has to distinguish from
    legitimate calls. The nonce ``is``-check refuses regardless: the
    in-process caller does not hold the live nonce reference, so the
    function raises ``security.tag_t3_unauthorized`` and the call
    never returns a ``TaggedContent[T3]`` object.

    This is the AI-architecture-critical case spec §3.2 was designed
    around. Without the nonce gate, ANY in-process caller could forge
    T3 content; with it, the forgery requires reach to the live
    module-level slot (a strictly stronger compromise — covered by
    ``tl-2026-003`` ``gc.get_objects()`` out-of-scope acknowledgement).
    """
    forged_name = "alfred.core.orchestrator"
    fake_module = ModuleType(forged_name)
    monkeypatch.setitem(__import__("sys").modules, forged_name, fake_module)

    # Install ``tag_t3_with_nonce`` into the forged module's globals so
    # the ``exec``'d snippet can call it from a frame whose
    # ``__name__`` is the forged orchestrator string.
    fake_module.__dict__["tag_t3_with_nonce"] = tag_t3_with_nonce

    # Define ``invoke`` *inside* the forged module's __dict__. The
    # function's ``__globals__`` is bound at definition time, so the
    # call to ``tag_t3_with_nonce`` from inside ``invoke`` shows
    # ``f_globals['__name__'] == forged_name`` for the calling frame
    # the gate inspects.
    exec(  # noqa: S102 — deliberate use of exec to forge frame globals
        "def invoke():\n"
        "    return tag_t3_with_nonce(\n"
        "        'forged from orchestrator',\n"
        "        source='attack',\n"
        "        caller_token=None,\n"
        "    )\n",
        fake_module.__dict__,
    )

    with (
        structlog.testing.capture_logs() as log_entries,
        pytest.raises(ValueError, match=re.escape("security.tag_t3_unauthorized")),
    ):
        fake_module.__dict__["invoke"]()

    # The forged label appears in the audit row exactly as forged —
    # forensic, not authoritative. Operators see the orchestrator-
    # internal-looking label and the refusal in the same row, which is
    # the signal that an in-process forgery attempt fired.
    refused = [e for e in log_entries if e.get("event") == "security.t3_boundary.refused"]
    assert refused, (
        "Expected security.t3_boundary.refused log entry on tag_t3_unauthorized; "
        f"got events: {[e.get('event') for e in log_entries]}"
    )
    assert refused[0].get("caller_module_unverified") == forged_name
