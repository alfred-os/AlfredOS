"""Adversarial wiring-smoke for the ``cap-2026-005`` corpus payload.

Asserts the sink-local containment defense (#364) fired at the config-sourced
comms-adapter load-grant builder: a validator-bypassing traversal-shaped
adapter id (constructed via ``Settings.model_construct``, which bypasses
``_validate_comms_enabled_adapters``) is REFUSED at the builder BEFORE the
manifest read sink, proving no arbitrary-file read outside ``plugins/`` rides
the config-sourced seed.

Path-traversal safety of the ``comms_enabled_adapters`` -> manifest read
otherwise rests entirely on the construction-time validator. The builder is the
perimeter (CLAUDE.md: the tool layer, not the model, is the perimeter): it
RE-CHECKS containment at the sink and REFUSES a traversal-shaped id fail-closed
(:class:`CommsAdapterManifestEscapeError`, a :class:`ManifestError` subclass the
daemon boot maps to the audited ``boot_infra_install_failed`` refusal). A pass
here would let a validator-bypassed id read an arbitrary manifest off the host.

The test drives the REAL production
:func:`alfred.security.capability_gate._comms_adapter_grants.comms_adapter_load_grants`
builder — NEVER a permissive shim (CLAUDE.md hard rule #2). Mirrors the
positive/negative-control shape of ``cap-2026-004``.
"""

from __future__ import annotations

from typing import Final

import pytest

from alfred.config.settings import Settings
from alfred.plugins.errors import CommsAdapterManifestEscapeError, ManifestError
from alfred.security.capability_gate._comms_adapter_grants import comms_adapter_load_grants
from tests.adversarial.payload_schema import AdversarialPayload

_PAYLOAD_ID: Final[str] = "cap-2026-005"

# A real in-repo adapter id (positive control) and the traversal-shaped id the
# payload pins (the defense).
_REAL_ADAPTER: Final[str] = "alfred_comms_test"
_TRAVERSAL_ID: Final[str] = "../../../../etc"


@pytest.fixture
def sink_containment_payload(
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
            "tests/adversarial/capability_bypass/sink_local_containment_traversal_refused.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            "expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def test_sink_local_containment_traversal_refused(
    sink_containment_payload: AdversarialPayload,
) -> None:
    """A traversal-shaped comms adapter id is REFUSED at the builder's read sink.

    Positive control + negative control through the SAME production builder:

    * a REAL in-repo adapter (``alfred_comms_test``) against the real repo root
      seeds exactly one wildcard load grant — the builder really reads a
      contained manifest, so the refusal below is a containment verdict, not a
      blanket refusal; and
    * a traversal-shaped id constructed via ``model_construct`` (bypassing the
      Settings validator) is REFUSED before the read — proving no arbitrary-file
      read outside ``plugins/`` rides the config-sourced seed.
    """
    payload_fields = sink_containment_payload.payload
    assert isinstance(payload_fields, dict)
    assert payload_fields["builder"] == "comms_adapter_load_grants"
    assert payload_fields["enabled_adapter_id"] == _TRAVERSAL_ID
    assert sink_containment_payload.expected_outcome == "refused"

    # Positive control: a real in-repo adapter seeds one wildcard grant — the
    # builder reads a contained manifest, so the refusal below is a containment
    # verdict, not a blanket refusal.
    ok_settings = Settings(
        environment="test",
        deepseek_api_key="not-a-real-secret-adversarial-test-placeholder",
        comms_enabled_adapters=(_REAL_ADAPTER,),
    )
    (grant,) = comms_adapter_load_grants(ok_settings)
    assert grant.hookpoint == "*"

    # The defense: a traversal-shaped id (validator-bypassed via model_construct)
    # is REFUSED before the read. The assertion fires before any file access, so
    # the escaping path need not exist.
    evil_settings = Settings.model_construct(comms_enabled_adapters=(_TRAVERSAL_ID,))
    with pytest.raises(CommsAdapterManifestEscapeError) as excinfo:
        comms_adapter_load_grants(evil_settings)

    # The refusal leaf is caught by the daemon boot's manifest-family ``except``,
    # so it maps to the audited ``boot_infra_install_failed`` refusal rather than
    # a raw traceback.
    assert isinstance(excinfo.value, ManifestError), (
        "CommsAdapterManifestEscapeError must subclass ManifestError so the daemon "
        "boot maps the traversal refusal to the audited boot_infra_install_failed"
    )
    assert excinfo.value.adapter_id == _TRAVERSAL_ID
