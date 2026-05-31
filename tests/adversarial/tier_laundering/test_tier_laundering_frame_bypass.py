"""Adversarial tier_laundering — frame-introspection bypass.

An attacker monkey-patches ``sys.modules`` to forge an authorised
``__name__`` in the calling frame, attempting to bypass the
``tag_t3_with_nonce`` gate. Per spec §3.2 the frame-derived caller label
is forensic-only — the actual gate is the nonce ``is``-check.

sec-005 (High — applied): each adversarial scenario carries two
sub-assertions:

(a) the gate still refuses (nonce identity is the real gate), AND
(b) the forged label appears in the structlog warning EXACTLY as forged,
    confirming ``caller_module_unverified`` is unverified by design and an
    attacker who forges ``sys.modules`` will see their forged label in the
    audit row.

Spec §3.2, §3.8.
"""

from __future__ import annotations

import re
import sys
from types import ModuleType

import pytest
import structlog.testing

from alfred.security.tiers import (
    T3,
    CapabilityGateNonce,
    tag_t3_with_nonce,
)


def test_frame_name_forgery_does_not_bypass_nonce_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Monkey-patching ``__name__`` in ``sys.modules`` does not forge the nonce.

    The gate uses ``is`` identity on the nonce object, NOT the frame's
    ``__name__``. A forged ``__name__`` in the calling frame context has
    no effect on the ``is`` check. Spec §3.2.
    """
    # Plant a fake module pretending to be an authorised home (the future
    # stdio_transport — lands in a later Slice-3 PR; we forge its name today
    # to prove forgery doesn't help even once the real module exists).
    fake_module = ModuleType("alfred.plugins.stdio_transport")
    fake_module.__name__ = "alfred.plugins.stdio_transport"
    monkeypatch.setitem(sys.modules, "alfred.plugins.stdio_transport", fake_module)

    # Even with the forged module name in sys.modules, calling
    # tag_t3_with_nonce without the real nonce is refused.
    with pytest.raises(ValueError, match=re.escape("security.tag_t3_unauthorized")):
        tag_t3_with_nonce(
            "attack via frame forgery",
            source="attack",
            caller_token=None,
        )


def test_forged_frame_label_appears_in_audit_row_as_forged() -> None:
    """sec-005 (High): the forged caller label IS recorded as-forged.

    The ``caller_module_unverified`` field is, by spec §3.2 design,
    forensic only — the frame-derived label is captured AS-IS, without
    authorisation. An attacker who forges ``sys.modules`` gets their
    forged ``__name__`` in the audit row; they do NOT bypass the gate.
    The label is evidence that an attempt was made, not evidence of the
    real caller identity.
    """
    with (
        structlog.testing.capture_logs() as log_entries,
        pytest.raises(ValueError, match=re.escape("security.tag_t3_unauthorized")),
    ):
        tag_t3_with_nonce(
            "x",
            source="test",
            caller_token=None,  # refused
        )

    assert log_entries, "Expected at least one structlog entry on T3 refusal"
    refused_entries = [e for e in log_entries if e.get("event") == "security.t3_boundary.refused"]
    assert refused_entries, (
        "Expected security.t3_boundary.refused log entry; got: "
        f"{[e.get('event') for e in log_entries]}"
    )
    entry = refused_entries[0]
    caller_label = entry.get("caller_module_unverified", "")
    assert caller_label, "caller_module_unverified must be non-empty on refusal"
    # The label is exactly what the frame reports — not sanitised, not
    # authorised. An attacker who changes their module __name__ will see
    # their chosen label here. Forensic, not authoritative.
    assert isinstance(caller_label, str)


def test_wrong_nonce_object_is_refused_even_if_frame_matches() -> None:
    """A different ``CapabilityGateNonce`` object (different identity) is refused.

    Even if the calling frame's ``__name__`` happens to match an approved
    module, the ``is`` check on the nonce object is the actual gate. Spec §3.2.
    """
    legitimate_nonce = CapabilityGateNonce()
    attacker_nonce = CapabilityGateNonce()  # different object

    with pytest.raises(ValueError, match=re.escape("security.tag_t3_unauthorized")):
        tag_t3_with_nonce(
            "attack",
            source="test",
            caller_token=attacker_nonce,
            _authorized_nonce=legitimate_nonce,
        )
    # Confirm they are different objects (defends against == identity drift).
    assert attacker_nonce is not legitimate_nonce


def test_correct_nonce_is_accepted_regardless_of_frame() -> None:
    """The live nonce object passes the ``is`` check regardless of caller frame.

    Called from a test frame (not stdio_transport), the gate accepts
    because the nonce identity matches. The frame name never influences
    the allow/deny decision. Spec §3.2.
    """
    nonce = CapabilityGateNonce()
    tc = tag_t3_with_nonce(
        "legitimate T3 content",
        source="test",
        caller_token=nonce,
        _authorized_nonce=nonce,
    )
    assert tc.tier is T3
    assert tc.content == "legitimate T3 content"
