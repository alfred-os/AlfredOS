"""Adversarial wiring-smoke for the ``cap-2026-004`` corpus payload.

Asserts the **defense fired** at the config-sourced comms-adapter load-grant
builder (ADR-0027 Decision 6 + FIX 1): a comms-adapter manifest declaring
``subscriber_tier="system"`` is REFUSED at the builder, proving no
self-escalation to the OS (system) trust tier rides the config seed.

ADR-0027 seeds ONE plugin-LOAD grant per ENABLED adapter, copying the manifest
``subscriber_tier`` into a wildcard :class:`GrantRow`. ``config-is-authorization``
was reasoned around ``operator`` / ``user-plugin`` adapters; a comms manifest
declaring ``system`` would otherwise auto-receive a ``system``-tier wildcard
load grant from config alone — a privilege jump DISTINCT from cap-2026-003's
"trust by name" bypass. The builder is the perimeter (CLAUDE.md: the tool layer,
not the model, is the perimeter): it REFUSES a ``system``-tier enabled adapter
fail-closed (:class:`CommsAdapterSystemTierError`, a :class:`ManifestError`
subclass the daemon boot maps to the audited ``boot_infra_install_failed``
refusal). A pass here would let a comms adapter self-grant ``system`` tier — a
privilege escalation.

The test drives the REAL production
:func:`alfred.security.capability_gate._comms_adapter_grants.comms_adapter_load_grants`
builder against a tmp repo whose enabled adapter manifest declares ``system`` —
NEVER a permissive shim. The refusal here is therefore the production builder's
verdict, not a test double's (CLAUDE.md hard rule #2). Mirrors the
positive/negative-control shape of the ``cap-2026-003`` load-by-name analogue.
"""

from __future__ import annotations

from typing import Final

import pytest

from alfred.config.settings import Settings
from alfred.plugins.errors import CommsAdapterSystemTierError, ManifestError
from alfred.security.capability_gate._comms_adapter_grants import comms_adapter_load_grants
from tests.adversarial.payload_schema import AdversarialPayload

_PAYLOAD_ID: Final[str] = "cap-2026-004"

# The enabled adapter id the payload pins (dir id under ``plugins/``).
_ENABLED_ADAPTER: Final[str] = "alfred_comms_test"


@pytest.fixture
def system_tier_refused_payload(
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
            "tests/adversarial/capability_bypass/system_tier_comms_adapter_refused.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            "expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


def _write_manifest_with_tier(repo_root, adapter_id: str, *, tier: str) -> None:
    """Write a minimal-but-valid comms manifest declaring ``subscriber_tier``."""
    adapter_dir = repo_root / "plugins" / adapter_id
    adapter_dir.mkdir(parents=True, exist_ok=True)
    (adapter_dir / "manifest.toml").write_text(
        "\n".join(
            (
                "alfred.manifest_version = 1",
                "[plugin]",
                f'id = "alfred.comms-{adapter_id}"',
                f'subscriber_tier = "{tier}"',
                'sandbox_profile = "user-plugin"',
                "[sandbox]",
                'kind = "none"',
                "[comms_mcp]",
                f'adapter_kind = "{adapter_id}"',
                "classifiers_optional = []",
                f'module = "{adapter_id}.main"',
                "",
            )
        ),
        encoding="utf-8",
    )


def test_system_tier_comms_adapter_refused(
    system_tier_refused_payload: AdversarialPayload,
    tmp_path,
    monkeypatch,
) -> None:
    """A ``system``-tier comms adapter is REFUSED at the load-grant builder.

    Positive control + negative control through the SAME production builder:

    * an ``operator``-tier manifest seeds exactly one wildcard load grant —
      the builder really does seed legitimate postures, so the refusal below is
      a tier-ceiling verdict, not a blanket refusal; and
    * a ``system``-tier manifest is REFUSED — proving no self-escalation to the
      OS trust tier rides the config-sourced seed.
    """
    payload_fields = system_tier_refused_payload.payload
    assert isinstance(payload_fields, dict)
    assert payload_fields["builder"] == "comms_adapter_load_grants"
    assert payload_fields["declared_tier"] == "system"
    assert system_tier_refused_payload.expected_outcome == "refused"

    settings = Settings(
        environment="test",
        deepseek_api_key="not-a-real-secret-adversarial-test-placeholder",
        comms_enabled_adapters=(_ENABLED_ADAPTER,),
    )

    repo_root = tmp_path / "repo"

    # Positive control: an operator-tier adapter seeds one wildcard grant — the
    # builder is a real tier evaluator, not a blanket refusal.
    _write_manifest_with_tier(repo_root, _ENABLED_ADAPTER, tier="operator")
    monkeypatch.setattr(
        "alfred.security.capability_gate._comms_adapter_grants._REPO_ROOT", repo_root
    )
    (operator_grant,) = comms_adapter_load_grants(settings)
    assert operator_grant.subscriber_tier == "operator"

    # The defense: a system-tier adapter is REFUSED at the builder — no
    # self-escalation to the OS trust tier rides the config-sourced seed.
    _write_manifest_with_tier(repo_root, _ENABLED_ADAPTER, tier="system")
    with pytest.raises(CommsAdapterSystemTierError) as excinfo:
        comms_adapter_load_grants(settings)

    # The refusal leaf is caught by the daemon boot's manifest-family ``except``
    # (FIX 2), so it maps to the audited ``boot_infra_install_failed`` refusal
    # rather than a raw traceback.
    assert isinstance(excinfo.value, ManifestError), (
        "CommsAdapterSystemTierError must subclass ManifestError so the daemon "
        "boot maps the system-tier refusal to the audited boot_infra_install_failed"
    )
    assert excinfo.value.adapter_id == _ENABLED_ADAPTER
