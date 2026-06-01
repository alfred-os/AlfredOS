"""Provider-separation invariant — AI-3 fix.

``config/routing.yaml`` documents that the privileged provider and the
quarantined provider "MUST differ" by default (spec §5.4, PRD §6.4).
Prior to PR-S3-4 fixup the only enforcement was the routing.yaml
comment — an operator who set both ids to the same value would boot a
system where the dual-LLM split is structurally a single-LLM split.

These tests pin the bootstrap-time assertion in
:func:`alfred.bootstrap.quarantine.assert_provider_separation`.
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
