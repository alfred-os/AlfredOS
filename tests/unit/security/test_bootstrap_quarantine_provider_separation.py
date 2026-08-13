"""Provider-separation predicate — AI-3 fix.

Separating the privileged provider from the quarantined one is
defence-in-depth: with both set to the same provider, the dual-LLM split is
structurally a single-LLM split, and one compromised provider account can see
privileged orchestrator context and raw T3 content together.

It is **opt-in**, NOT required by default — see
[ADR-0064](../../../docs/adr/0064-quarantine-provider-separation-is-opt-in.md).
Do not cite "spec §5.4 / PRD §6.4" for a must-differ invariant: no PRD section
states one, and the design spec's §5.4 default-refuse / reviewer-gated
mechanism is superseded by that ADR. `ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION=true`
is what arms the check; left at its `false` default a collision boots, logged
and audited once.

These tests pin the predicate itself —
:func:`alfred.bootstrap.quarantine.assert_provider_separation` — independently
of whether a caller has armed it. Its opt-in boot call site is covered in
``tests/unit/cli/daemon/test_daemon_boot_egress_refuse.py``.
"""

from __future__ import annotations

import pytest

from alfred.bootstrap.quarantine import assert_provider_separation
from alfred.errors import AlfredError


def test_assert_provider_separation_accepts_distinct_ids() -> None:
    """Happy path: distinct provider ids pass without raising.

    ``deepseek`` (privileged) + ``anthropic`` (quarantined) is the
    routing.yaml default; the helper MUST accept it.
    """
    assert_provider_separation(
        privileged_provider_id="deepseek",
        quarantined_provider_id="anthropic",
    )


def test_assert_provider_separation_refuses_identical_ids() -> None:
    """Same provider on both sides → AlfredError.

    Structural defence: the dual-LLM split collapses when both sides
    are the same provider. The startup check refuses to boot rather
    than silently degrading the trust-tier guarantee.
    """
    with pytest.raises(AlfredError):
        assert_provider_separation(
            privileged_provider_id="deepseek",
            quarantined_provider_id="deepseek",
        )


def test_assert_provider_separation_refuses_case_variant_ids() -> None:
    """Case-only variation is still the same provider.

    An operator who wrote ``DeepSeek`` on one side and ``deepseek`` on
    the other would otherwise pass a string-equality check and boot a
    structurally-collapsed system. The normalised check closes that gap.
    """
    with pytest.raises(AlfredError):
        assert_provider_separation(
            privileged_provider_id="DeepSeek",
            quarantined_provider_id="deepseek",
        )


def test_assert_provider_separation_refuses_whitespace_variant_ids() -> None:
    """Trailing / leading whitespace is the same defence as case.

    YAML can leak trailing whitespace from a hand-edited file; the
    normalised check strips before comparing.
    """
    with pytest.raises(AlfredError):
        assert_provider_separation(
            privileged_provider_id="deepseek ",
            quarantined_provider_id="deepseek",
        )


def test_assert_provider_separation_refuses_blank_privileged() -> None:
    """An unconfigured privileged provider is a refuse-to-boot.

    The operator must explicitly declare both providers; defaulting to
    empty would let a misconfigured ``routing.yaml`` boot a system
    where the privileged tier has no provider at all.
    """
    with pytest.raises(AlfredError):
        assert_provider_separation(
            privileged_provider_id="",
            quarantined_provider_id="anthropic",
        )


def test_assert_provider_separation_refuses_blank_quarantined() -> None:
    """An unconfigured quarantined provider is a refuse-to-boot.

    Same defence as the privileged side: declaring only one provider
    is not a default-to-the-other fallback. The startup check is
    fail-closed.
    """
    with pytest.raises(AlfredError):
        assert_provider_separation(
            privileged_provider_id="deepseek",
            quarantined_provider_id="   ",
        )
