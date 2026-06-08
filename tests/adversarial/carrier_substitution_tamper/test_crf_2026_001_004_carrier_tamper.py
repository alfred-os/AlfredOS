"""Executable assertions for the PR-S4-3 carrier-substitution corpus.

ADR-0022 recoverable-carrier semantic. Each test loads its payload via
the session-scoped ``corpus_payloads`` fixture (drift-guard) then proves
the defense fires AND emits the required audit row:

* crf-2026-001 — tier-upgrade refusal: a ``user-plugin``-tier subscriber
  (attested source_tier=T3) on a T1 carrier is refused; the upstream
  exception re-raises and ``hooks.carrier_substitution_refused`` is
  emitted with ``reason="tier_upgrade_refused"``.
* crf-2026-002 — malformed substitute: an out-of-vocab ``source_tier``
  is refused at Pydantic validation time (the field is a closed Literal).
* crf-2026-003 — wrong-type substitute: a payload that fails the
  declared ``carrier_type`` isinstance check is refused through
  ``invoke()`` with ``reason="payload_type_mismatch"``.
* crf-2026-004 — meta-hookpoint recursion: a substitute on a
  meta-hookpoint (allow_error_substitution=False) is refused with
  ``reason="recursion_refused"`` so the recursion loop stays closed.

Per ADR-0022 §3 the ``source_tier`` is dispatcher-attested from the
firing subscriber's registered tier — the subscriber embeds only the
payload under ``ctx.metadata["substitute_payload"]``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final

import pytest
from pydantic import ValidationError

from alfred.hooks import get_registry, set_registry
from alfred.hooks.audit_sink import HOOKS_CARRIER_SUBSTITUTION_REFUSED
from alfred.hooks.context import HookContext
from alfred.hooks.invoke import SubstituteResult, invoke
from alfred.hooks.registry import OPEN_TIERS, SYSTEM_ONLY_TIERS, HookRegistry
from alfred.security.tiers import T1
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.audit import RecordingAuditSink
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
def recording_sink() -> RecordingAuditSink:
    return RecordingAuditSink()


@pytest.fixture
def tamper_registry(recording_sink: RecordingAuditSink) -> Iterator[HookRegistry]:
    """Registry with a recording sink so refusal rows are observable."""
    from alfred.hooks._known_hookpoints import declare_meta_hookpoints

    prior = get_registry()
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        sink=recording_sink,
        strict_declarations=False,
    )
    # A T1 carrier whose subscription admits user-plugin — the genuine
    # tier-laundering surface (a T3-attested subscriber on a T1 carrier).
    registry.register_hookpoint(
        name="test.t1_carrier",
        subscribable_tiers=OPEN_TIERS,
        refusable_tiers=OPEN_TIERS,
        fail_closed=False,
        carrier_tier=T1,
    )
    declare_meta_hookpoints(registry)
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


def _refusal_rows(sink: RecordingAuditSink, reason: str) -> list[dict[str, object]]:
    return [
        r["fields"]
        for r in sink.records
        if r["event"] == HOOKS_CARRIER_SUBSTITUTION_REFUSED and r["fields"].get("reason") == reason
    ]


# ---------------------------------------------------------------------------
# crf-2026-001 — tier-upgrade refusal (attested from subscriber tier)
# ---------------------------------------------------------------------------

_CRF_001: Final = "crf-2026-001"


async def test_crf_001_tier_upgrade_refused_and_audited(
    corpus_payloads: tuple[AdversarialPayload, ...],
    tamper_registry: HookRegistry,
    recording_sink: RecordingAuditSink,
) -> None:
    """A user-plugin subscriber (attested T3) on a T1 carrier is refused.

    The laundering substitute is discarded (upstream exception
    re-raises) AND a ``tier_upgrade_refused`` audit row is emitted.
    """
    payload = _payload(corpus_payloads, _CRF_001)
    assert payload.expected_outcome == "refused"

    async def _malicious_sub(ctx: HookContext[str]) -> HookContext[str] | None:
        # Embeds only the payload — the dispatcher attests source_tier
        # from this subscriber's registered tier (user-plugin → T3).
        return ctx.with_metadata(substitute_payload="laundered-t3-content")

    tamper_registry.register(
        hook_fn=_malicious_sub,
        hookpoint="test.t1_carrier",
        kind="error",
        tier="user-plugin",
    )
    with pytest.raises(ValueError, match="upstream failure"):
        await invoke(
            "test.t1_carrier",
            _ctx(),
            kind="error",
            exc=ValueError("upstream failure"),
            subscribable_tiers=OPEN_TIERS,
        )
    rows = _refusal_rows(recording_sink, "tier_upgrade_refused")
    assert len(rows) == 1, "expected exactly one tier_upgrade_refused audit row"
    assert rows[0]["attempted_source_tier"] == "T3"
    assert rows[0]["carrier_tier"] == "T1"


# ---------------------------------------------------------------------------
# crf-2026-002 — malformed substitute (out-of-vocab source_tier)
# ---------------------------------------------------------------------------

_CRF_002: Final = "crf-2026-002"


def test_crf_002_malformed_source_tier_refused_at_validation(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    """The closed ``source_tier`` Literal refuses an out-of-vocab value.

    Belt-and-braces: even though the dispatcher attests source_tier
    (so a subscriber cannot directly set it), the SubstituteResult
    model itself refuses a malformed tier — a defence-in-depth layer.
    """
    payload = _payload(corpus_payloads, _CRF_002)
    assert payload.expected_outcome == "refused"
    with pytest.raises(ValidationError):
        SubstituteResult[str](
            payload="x",
            source_tier="T4",  # type: ignore[arg-type]
            subscriber_id="attacker._sub",
        )


# ---------------------------------------------------------------------------
# crf-2026-003 — wrong-type substitute payload (through invoke)
# ---------------------------------------------------------------------------

_CRF_003: Final = "crf-2026-003"


async def test_crf_003_wrong_type_substitute_refused_through_invoke(
    corpus_payloads: tuple[AdversarialPayload, ...],
    tamper_registry: HookRegistry,
    recording_sink: RecordingAuditSink,
) -> None:
    """A substitute payload failing the declared carrier_type is refused.

    Drives the wrong-type defense through the real ``invoke()`` error
    path (not just Pydantic construction) and asserts the
    ``payload_type_mismatch`` audit row fires.
    """
    payload = _payload(corpus_payloads, _CRF_003)
    assert payload.expected_outcome == "refused"

    async def _wrong_type_sub(ctx: HookContext[str]) -> HookContext[str] | None:
        # carrier_type is str (see invoke call below); embed an int.
        return ctx.with_metadata(substitute_payload=12345)

    tamper_registry.register(
        hook_fn=_wrong_type_sub,
        hookpoint="test.t1_carrier",
        kind="error",
        tier="system",
    )
    with pytest.raises(ValueError, match="upstream failure"):
        await invoke(
            "test.t1_carrier",
            _ctx(),
            kind="error",
            exc=ValueError("upstream failure"),
            subscribable_tiers=OPEN_TIERS,
            carrier_type=str,
        )
    rows = _refusal_rows(recording_sink, "payload_type_mismatch")
    assert len(rows) == 1, "expected exactly one payload_type_mismatch audit row"


# ---------------------------------------------------------------------------
# crf-2026-004 — meta-hookpoint recursion
# ---------------------------------------------------------------------------

_CRF_004: Final = "crf-2026-004"


async def test_crf_004_meta_hookpoint_substitution_refused_and_audited(
    corpus_payloads: tuple[AdversarialPayload, ...],
    tamper_registry: HookRegistry,
    recording_sink: RecordingAuditSink,
) -> None:
    """A substitute on the ``hooks.carrier_substituted`` meta-hookpoint
    (allow_error_substitution=False) is refused with a
    ``recursion_refused`` audit row; the recursion loop stays closed."""
    payload = _payload(corpus_payloads, _CRF_004)
    assert payload.expected_outcome == "recursion_refused"
    meta = tamper_registry.hookpoint_meta("hooks.carrier_substituted")
    assert meta is not None
    assert meta.allow_error_substitution is False

    async def _malicious_sub(ctx: HookContext[str]) -> HookContext[str] | None:
        return ctx.with_metadata(substitute_payload="recursion-attempt")

    tamper_registry.register(
        hook_fn=_malicious_sub,
        hookpoint="hooks.carrier_substituted",
        kind="error",
        tier="system",
    )
    with pytest.raises(ValueError, match="meta upstream failure"):
        await invoke(
            "hooks.carrier_substituted",
            _ctx(),
            kind="error",
            exc=ValueError("meta upstream failure"),
            subscribable_tiers=SYSTEM_ONLY_TIERS,
        )
    rows = _refusal_rows(recording_sink, "recursion_refused")
    assert len(rows) == 1, "expected exactly one recursion_refused audit row"
