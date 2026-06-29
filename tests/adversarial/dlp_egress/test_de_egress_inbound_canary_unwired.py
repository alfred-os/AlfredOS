"""Executable counterpart to ``de_egress_inbound_canary_unwired.yaml`` (de-2026-012).

The web.fetch INBOUND egress-response canary scan is BUILT
(``ResponsePolicy.canary`` → ``response_inspection.inspect_response`` →
``_CanaryHit`` → ``InboundCanaryTripped``) but UNWIRED: the production factory
``build_web_fetch_egress_extractor`` defaults ``canary=None`` because no
core-side canary-token source exists (the only ``resolve_canary_tokens()`` reads
the gateway-only ``ALFRED_CANARY_TOKENS`` env and lives in
``alfred.gateway.egress_relay`` — importing it core-side is a layering inversion
AND the env is not set on the core). So a LIVE web.fetch caller would NOT trip on
a canary token reflected in the upstream RESPONSE.

This is the alfred-security-engineer-signed-off tracked residual for PR #339
(#347 obligation list). It is machine-visible here as a
``@pytest.mark.xfail(strict=True)`` stub that is an explicit **merge-blocker on
PR #339**, mirroring the de-2026-004 per-user-exhaustion deferral pattern in
``test_egress_no_orphan_and_inflight.py``.

Distinct from de-2026-008 (the OUTBOUND canary on the gateway relay's stage-3 DLP
scan of the REQUEST body — wired and tripping). This entry is the INBOUND
reflection seam on the RESPONSE side, which web.fetch does not yet wire.

CLAUDE.md security rule #7: a canary trip is loud, never fail-open.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final
from unittest.mock import Mock

import pytest
import yaml

from tests.adversarial.payload_schema import AdversarialPayload

_PAYLOAD_PATH: Final[Path] = Path(__file__).parent / "de_egress_inbound_canary_unwired.yaml"

# A relay URL the factory accepts so construction reaches the ResponsePolicy build
# (the fail-closed unset-URL branch refuses before the policy is assembled).
_RELAY_URL: Final[str] = "tcp://127.0.0.1:8890"


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


# ---------------------------------------------------------------------------
# Test 1 — corpus schema validation + deferred-property obligation
# ---------------------------------------------------------------------------


def test_payload_schema_valid() -> None:
    """Corpus YAML is well-formed and carries the de-2026-012 merge-blocker obligation."""
    payload = _load_payload()
    assert payload.id == "de-2026-012"
    assert payload.category == "dlp_egress"
    assert payload.ingestion_path == "web.fetch"
    assert payload.expected_outcome == "caught_by_dlp"
    # The deferred-property obligation is machine-documented in the payload so a
    # reviewer cannot miss it as prose: #339 must wire the inbound canary.
    assert isinstance(payload.payload, dict)
    deferred = payload.payload.get("deferred_property", {})
    assert isinstance(deferred, dict)
    assert deferred.get("id") == "inbound_response_canary_scan"
    assert deferred.get("deferred_to") == "PR #339"
    assert deferred.get("merge_blocker") is True


# ---------------------------------------------------------------------------
# Test 2 — deferred property: inbound egress-response canary scan
#          (xfail, #339 merge-blocker)
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    reason=(
        "web.fetch INBOUND egress-response canary scan deferred to PR #339 "
        "(no core-side canary-token source; resolve_canary_tokens is gateway-only; "
        "no live dispatch_web_fetch caller until after G7-3). "
        "This xfail is a MERGE-BLOCKER on PR #339: build_web_fetch_egress_extractor "
        "MUST thread a real CanaryMatcher (canary != None) before the first live "
        "caller merges, then this stub is converted to a passing reflected-canary test."
    ),
    # strict=True — the factory passes canary=None today so the assertion below
    # FAILS (XFAIL). When #339 wires a real CanaryMatcher the assertion passes →
    # XPASS → strict turns the XPASS into a FAILURE, mechanically forcing this
    # stub's conversion rather than leaving a silent XPASS.
    strict=True,
)
def test_inbound_canary_unwired_deferred_to_339(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deferred: web.fetch inbound egress-response canary (factory passes canary=None today).

    The C2 inbound-canary seam is built (``ResponsePolicy.canary`` →
    ``inspect_response`` → ``_CanaryHit`` → ``InboundCanaryTripped``), but
    ``build_web_fetch_egress_extractor`` defaults ``canary=None``: there is no
    core-side ``resolve_canary_tokens()`` source (the only one is gateway-only,
    reading ``ALFRED_CANARY_TOKENS``). So the assembled production
    ``ResponsePolicy.canary`` is ``None`` and a reflected canary in the upstream
    RESPONSE would pass the pre-extract seam.

    It is DEFERRED to PR #339 which:
      - Introduces the first live ``dispatch_web_fetch`` caller (after G7-3).
      - Supplies a core-side canary-token source.
      - MUST thread a real ``CanaryMatcher`` into
        ``build_web_fetch_egress_extractor`` BEFORE merging.

    Until then this test is a ``@pytest.mark.xfail(strict=True)`` stub — CI
    surfaces it as a machine-visible known-gap (XFAIL), not prose a reviewer may
    miss. When PR #339 wires the inbound canary:

    1. Thread a real ``CanaryMatcher`` (built from the core-side token source)
       into ``build_web_fetch_egress_extractor`` so ``ResponsePolicy.canary``
       is non-``None``.
    2. Convert this body to a real reflected-canary test (drive the assembled
       extractor over a loopback relay whose upstream reflects a seeded canary
       token; assert the inbound scan trips ``InboundCanaryTripped`` and records
       the terminal refusal before re-raising).
    3. The mark is already ``strict=True``: once the factory wires the canary the
       ``assert canary is not None`` below passes → the XPASS becomes a strict
       FAILURE that forces step 2.
    4. Remove the ``xfail`` mark entirely once stable, and flip the YAML
       ``payload.deferred_property.merge_blocker`` to ``false``.

    **PR #339 merge-blocker**: do NOT merge PR #339 until this xfail is converted
    to a passing test. The obligation is recorded in the G7-2.5 PR2 commit, in
    ADR-0041's Consequences, and in the de-2026-012 YAML
    ``payload.deferred_property.merge_blocker``.
    """
    from alfred.config.settings import Settings
    from alfred.plugins.web_fetch.assembly import build_web_fetch_egress_extractor

    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.delenv("ALFRED_EGRESS_RELAY_URL", raising=False)

    # Inert daemon-graph doubles — the factory only STORES these at construction;
    # none are invoked while assembling the ResponsePolicy.
    collaborator: dict[str, Any] = {
        "gate": Mock(name="gate"),
        "extractor": Mock(name="extractor"),
        "recorder": Mock(name="recorder"),
        "outbound_dlp": Mock(name="outbound_dlp"),
        "audit_writer": Mock(name="audit_writer"),
        "session_scope": lambda: None,
    }
    assembled = build_web_fetch_egress_extractor(
        settings=Settings(egress_relay_url=_RELAY_URL),
        gate=collaborator["gate"],
        extractor=collaborator["extractor"],
        recorder=collaborator["recorder"],
        outbound_dlp=collaborator["outbound_dlp"],
        audit_writer=collaborator["audit_writer"],
        session_scope=collaborator["session_scope"],
    )

    policy = assembled._response_policy
    assert policy is not None
    # POST-#339 desired state. Today the factory passes canary=None (no core-side
    # token source), so this assertion FAILS → strict-xfail XFAIL. When #339 wires
    # a real CanaryMatcher it passes → XPASS → strict FAILURE → forces conversion.
    assert policy.canary is not None, (
        "web.fetch inbound egress-response canary is NOT wired — "
        "ResponsePolicy.canary is None (no core-side canary-token source). "
        "PR #339 merge-blocker: thread a real CanaryMatcher into "
        "build_web_fetch_egress_extractor, then convert this xfail stub."
    )
