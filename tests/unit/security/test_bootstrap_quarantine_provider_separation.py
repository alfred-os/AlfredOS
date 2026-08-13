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
:func:`alfred.bootstrap.quarantine.assert_provider_separation` and the
:func:`alfred.bootstrap.quarantine.provider_ids_collide` helper it shares with the
daemon boot graph's not-required WARN path — independently of whether a caller has
armed it. Its opt-in boot call site is covered in
``tests/unit/cli/daemon/test_daemon_boot_egress_refuse.py``.
"""

from __future__ import annotations

import pytest

from alfred.bootstrap.quarantine import assert_provider_separation, provider_ids_collide
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


# --------------------------------------------------------------------------- #
# provider_ids_collide — the SHARED collision predicate (#586 review fix).
#
# assert_provider_separation() (the require=True refuse path) and the daemon boot
# graph's require=False WARN path in alfred.cli.daemon._comms_boot both call this
# ONE function. Before the extraction the warn path re-implemented the
# .strip().lower() comparison inline; these tests pin the shared predicate directly
# so a future change to "what counts as the same provider" is caught here rather
# than by whichever of the two call sites happened to keep a test.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("deepseek", "deepseek"),
        ("DeepSeek", "deepseek"),
        ("deepseek ", " deepseek"),
        ("\tANTHROPIC\n", "anthropic"),
        ("", "   "),
    ],
    ids=["identical", "case", "whitespace", "case-and-whitespace", "both-blank"],
)
def test_provider_ids_collide_true(a: str, b: str) -> None:
    """Every shape of "the same provider written differently" collides.

    ``("", "   ")`` is deliberate: two blank ids normalise equal, so the predicate
    reports a collision. ``assert_provider_separation`` never observes that outcome
    (it rejects a blank id first, with its own distinct message), but the warn path
    does — and "both providers undeclared" is correctly a non-separated configuration,
    not something to pass over in silence.
    """
    assert provider_ids_collide(a, b) is True


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("deepseek", "anthropic"),
        ("anthropic", "deepseek"),
        ("DeepSeek", " anthropic "),
        ("deepseek", ""),
    ],
    ids=["defaults", "reversed", "normalised-distinct", "one-blank"],
)
def test_provider_ids_collide_false(a: str, b: str) -> None:
    """Oracle guard: genuinely distinct ids do NOT collide.

    Without this pair the collide-true tests above would stay green under a
    predicate that returned ``True`` unconditionally — which would refuse every
    boot under ``require=True`` and warn on every boot under ``require=False``.
    """
    assert provider_ids_collide(a, b) is False


def test_provider_ids_collide_is_symmetric() -> None:
    """Argument order must not change the verdict.

    The two call sites pass their arguments in the same (privileged, quarantined)
    order today, but nothing in the signature enforces that — a positional-argument
    swap at either site must not change what the system considers separated.
    """
    assert provider_ids_collide("DeepSeek ", "deepseek") == provider_ids_collide(
        "deepseek", "DeepSeek "
    )
    assert provider_ids_collide("deepseek", "anthropic") == provider_ids_collide(
        "anthropic", "deepseek"
    )
