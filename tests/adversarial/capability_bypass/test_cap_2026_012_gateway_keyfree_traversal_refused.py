"""Adversarial wiring-smoke for the ``cap-2026-012`` corpus payload.

Asserts the gateway's sole-guard property (#499) fired: a traversal-shaped
``ALFRED_COMMS_ENABLED_ADAPTERS`` id is REFUSED at
:class:`alfred.config.settings.GatewayHostedAdaptersSettings` construction
(``SettingsError``) BEFORE the gateway resolver's
:func:`alfred.cli.gateway._commands._resolve_adapter_kind` manifest
``read_text()`` sink, proving no arbitrary-file read outside ``plugins/``
rides the gateway's key-free hosted-adapter allowlist.

Unlike ``cap-2026-005``'s daemon-builder path (which RE-CHECKS containment at
the sink as defense-in-depth), the gateway resolver path has **no sink-local
re-check** — the construction-time
:func:`alfred.config.settings.validate_comms_adapter_ids` validator is the
SOLE guard (CLAUDE.md hard rule #7; ADR-0036). This entry pins that single
guard at the release-blocking layer, symmetric with cap-2026-005's
belt-and-braces daemon path.

The test drives the REAL production
:func:`alfred.cli.gateway._commands._resolve_hosted_adapter_ids` resolver —
NEVER a permissive shim (CLAUDE.md hard rule #2). Mirrors the
positive/negative-control shape of ``cap-2026-005``.
"""

from __future__ import annotations

import json
from typing import Final

import pytest

from alfred.cli.gateway._commands import _resolve_hosted_adapter_ids
from alfred.config.settings import SettingsError
from tests.adversarial.payload_schema import AdversarialPayload

_PAYLOAD_ID: Final[str] = "cap-2026-012"

# A real in-repo adapter id (positive control) and the traversal-shaped id the
# payload pins (the defense). alfred_comms_test's manifest declares
# ``adapter_kind = "alfred_comms_test"`` (identical to its plugin-package id),
# so the resolved canonical id equals the input id.
_REAL_ADAPTER: Final[str] = "alfred_comms_test"
_TRAVERSAL_ID: Final[str] = "../../../../etc"


@pytest.fixture
def gateway_traversal_payload(
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
            "tests/adversarial/capability_bypass/gateway_keyfree_traversal_refused.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            "expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def test_gateway_keyfree_traversal_refused(
    gateway_traversal_payload: AdversarialPayload, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A traversal-shaped comms adapter id is REFUSED before the gateway's read sink.

    Positive control + negative control through the SAME production resolver,
    driven entirely key-free (ADR-0036 — the gateway holds no provider secret):

    * a REAL in-repo adapter (``alfred_comms_test``) resolves to its canonical
      id — the resolver really reads a contained manifest, so the refusal
      below is a containment verdict, not a blanket refusal; and
    * a traversal-shaped id in ``ALFRED_COMMS_ENABLED_ADAPTERS`` is REFUSED at
      ``GatewayHostedAdaptersSettings`` construction — proving no
      arbitrary-file read outside ``plugins/`` rides the gateway's key-free
      allowlist.
    """
    payload_fields = gateway_traversal_payload.payload
    assert isinstance(payload_fields, dict)
    assert payload_fields["resolver"] == "gateway_hosted_adapters"
    assert payload_fields["enabled_adapter_id"] == _TRAVERSAL_ID
    assert gateway_traversal_payload.expected_outcome == "refused"

    # Key-free posture (ADR-0036): no provider secret, no ALFRED_ENVIRONMENT —
    # the gateway must resolve the hosted-adapter allowlist without either.
    monkeypatch.delenv("ALFRED_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)

    # The defense: a traversal-shaped id is REFUSED before the read. The
    # assertion fires before any file access, so the escaping path need not
    # exist.
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", json.dumps([_TRAVERSAL_ID]))
    with pytest.raises(SettingsError):
        _resolve_hosted_adapter_ids()

    # Positive control: a real in-repo adapter resolves — the guard is not
    # "reject everything", it is containment.
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", json.dumps([_REAL_ADAPTER]))
    assert _resolve_hosted_adapter_ids() == [_REAL_ADAPTER]
