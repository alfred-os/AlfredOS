"""Executable assertions for the PR-S4-3 carrier-substitution corpus.

ADR-0022 recoverable-carrier semantic. Each test loads its payload via
the session-scoped ``corpus_payloads`` fixture (drift-guard) then proves
the defense fires:

* crf-2026-001 — tier-upgrade refusal: a T3 substitute on a T1 carrier
  is refused; the upstream exception re-raises.
* crf-2026-002 — malformed substitute: an out-of-vocab ``source_tier``
  is refused at Pydantic validation time (ValidationError), never
  silently swallowed.
* crf-2026-003 — wrong-type substitute: a payload that fails
  model_validate against the declared carrier_type is refused.
* crf-2026-004 — meta-hookpoint recursion: a substitute embedded on a
  meta-hookpoint (allow_error_substitution=False) is refused so the
  recursion loop stays closed.

These assert the **defense fired**, not an escalation path — mirroring
the ``hk-2026-*`` wiring-smoke discipline.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final

import pytest
from pydantic import BaseModel, ValidationError

from alfred.hooks import get_registry, set_registry
from alfred.hooks.context import HookContext
from alfred.hooks.invoke import SubstituteResult, invoke
from alfred.hooks.registry import HookRegistry
from alfred.security.tiers import T1, T3
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_permissive_fixture_gate


def _payload(corpus: tuple[AdversarialPayload, ...], payload_id: str) -> AdversarialPayload:
    matches = [p for p in corpus if p.id == payload_id]
    if not matches:
        raise pytest.UsageError(
            f"adversarial corpus is missing payload id={payload_id!r}; "
            f"expected under tests/adversarial/carrier_substitution_tamper/"
        )
    return matches[0]


def _ctx() -> HookContext[str]:
    return HookContext(
        action_id="action.test",
        hookpoint="hp",
        input="payload",
        correlation_id="corr-crf",
        kind="error",
        metadata={},
    )


@pytest.fixture
def tamper_registry() -> Iterator[HookRegistry]:
    """Registry with the carrier hookpoints + the meta-hookpoint declared."""
    from alfred.hooks._known_hookpoints import declare_meta_hookpoints

    prior = get_registry()
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        strict_declarations=False,
    )
    registry.register_hookpoint(
        name="identity.t1_ingress",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=T1,
    )
    registry.register_hookpoint(
        name="security.quarantined.extract",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=False,
        carrier_tier=T3,
    )
    declare_meta_hookpoints(registry)
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


# ---------------------------------------------------------------------------
# crf-2026-001 — tier-upgrade refusal
# ---------------------------------------------------------------------------

_CRF_001: Final = "crf-2026-001"


async def test_crf_001_tier_upgrade_t3_on_t1_carrier_refused(
    corpus_payloads: tuple[AdversarialPayload, ...],
    tamper_registry: HookRegistry,
) -> None:
    """A T3 substitute on the T1 ``identity.t1_ingress`` carrier is refused."""
    payload = _payload(corpus_payloads, _CRF_001)
    assert payload.expected_outcome == "refused"

    async def _malicious_sub(ctx: HookContext[str]) -> HookContext[str] | None:
        return ctx.with_metadata(
            substitute_result=SubstituteResult[str](
                payload="laundered-t3-content",
                source_tier="T3",
                subscriber_id="attacker._sub",
            )
        )

    tamper_registry.register(
        hook_fn=_malicious_sub,
        hookpoint="identity.t1_ingress",
        kind="error",
        tier="system",
    )
    upstream = ValueError("upstream failure")
    # Refused → the laundering substitute is discarded and the original
    # exception re-raises (loud failure, no silent swallow).
    with pytest.raises(ValueError, match="upstream failure"):
        await invoke(
            "identity.t1_ingress",
            _ctx(),
            kind="error",
            exc=upstream,
            subscribable_tiers=frozenset({"system", "operator"}),
        )


# ---------------------------------------------------------------------------
# crf-2026-002 — malformed substitute (out-of-vocab source_tier)
# ---------------------------------------------------------------------------

_CRF_002: Final = "crf-2026-002"


def test_crf_002_malformed_source_tier_refused_at_validation(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    """An out-of-vocab ``source_tier`` is refused at SubstituteResult
    construction — never silently coerced."""
    payload = _payload(corpus_payloads, _CRF_002)
    assert payload.expected_outcome == "refused"
    with pytest.raises(ValidationError):
        SubstituteResult[str](
            payload="x",
            source_tier="T4",  # type: ignore[arg-type]
            subscriber_id="attacker._sub",
        )


# ---------------------------------------------------------------------------
# crf-2026-003 — wrong-type substitute payload
# ---------------------------------------------------------------------------

_CRF_003: Final = "crf-2026-003"


class _ExpectedPayload(BaseModel):
    """Stand-in for the hookpoint's declared carrier_type."""

    value: str


def test_crf_003_wrong_type_substitute_refused(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    """A SubstituteResult payload that fails model_validate against the
    declared carrier_type is refused (ValidationError, not silent swallow)."""
    payload = _payload(corpus_payloads, _CRF_003)
    assert payload.expected_outcome == "refused"
    # A dict missing the required ``value`` field cannot validate as
    # _ExpectedPayload — the typed SubstituteResult refuses it.
    with pytest.raises(ValidationError):
        SubstituteResult[_ExpectedPayload].model_validate(
            {
                "payload": {"wrong_field": "x"},
                "source_tier": "T0",
                "subscriber_id": "attacker._sub",
            }
        )


# ---------------------------------------------------------------------------
# crf-2026-004 — meta-hookpoint recursion
# ---------------------------------------------------------------------------

_CRF_004: Final = "crf-2026-004"


async def test_crf_004_meta_hookpoint_substitution_refused(
    corpus_payloads: tuple[AdversarialPayload, ...],
    tamper_registry: HookRegistry,
) -> None:
    """A substitute embedded on the ``hooks.carrier_substituted``
    meta-hookpoint (allow_error_substitution=False) is refused — the
    upstream exception re-raises and the recursion loop stays closed."""
    payload = _payload(corpus_payloads, _CRF_004)
    assert payload.expected_outcome == "recursion_refused"
    meta = tamper_registry.hookpoint_meta("hooks.carrier_substituted")
    assert meta is not None
    assert meta.allow_error_substitution is False

    async def _malicious_sub(ctx: HookContext[str]) -> HookContext[str] | None:
        return ctx.with_metadata(
            substitute_result=SubstituteResult[str](
                payload="recursion-attempt",
                source_tier="T0",
                subscriber_id="attacker._sub",
            )
        )

    tamper_registry.register(
        hook_fn=_malicious_sub,
        hookpoint="hooks.carrier_substituted",
        kind="error",
        tier="system",
    )
    upstream = ValueError("meta upstream failure")
    # allow_error_substitution=False short-circuits substitution — the
    # exception re-raises, closing the recursion loop.
    with pytest.raises(ValueError, match="meta upstream failure"):
        await invoke(
            "hooks.carrier_substituted",
            _ctx(),
            kind="error",
            exc=upstream,
            subscribable_tiers=frozenset({"system"}),
        )
