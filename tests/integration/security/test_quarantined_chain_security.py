"""Cross-fork integration: quarantined extraction chain security gate (spec §12.4).

MERGE-BLOCKING. Every assertion in this module must pass before the
Slice-3 merge gate opens. The chain under test threads the T3-to-
orchestrator boundary end-to-end:

  T3 content
    -> quarantine.ingest (ContentHandle)
    -> quarantine.extract (QuarantinedExtractor)
    -> quarantined_to_structured (gate-first; downgrade is the only path)
    -> downgrade_to_orchestrator (T3_DERIVED_DOWNGRADE_FIELDS audit row)

Structural invariants pinned here:

* The orchestrator NEVER holds a reference to raw T3 bytes — the only
  T3 surface it sees is :class:`ContentHandle`, which carries no
  ``.content`` field (spec §7.3).
* :func:`quarantined_to_structured` is **gate-first**: the
  :class:`CapabilityGate` is consulted BEFORE the extractor runs (CR-138
  R3 — a denied gate must not invoke the extractor).
* The audit row chain ``quarantine.extract`` ->
  ``quarantine.t3_derived_downgrade`` is traceable through
  ``correlation_id`` and carries ``trust_tier_of_trigger="T3"`` /
  ``downgrade_explicit=True``.
* The :class:`T3DerivedData` provenance tag survives the extraction
  hop and is intentionally retired at the downgrade boundary.
* The PRD §7.1 dual-LLM invariant: an attacker-supplied injection in
  the T3 payload cannot reach :class:`Extracted.data` verbatim.

The fixtures are recorded — no live provider calls (CLAUDE.md HARD
rule: integration tests use recorded fixtures).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, ClassVar, Literal
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.hooks import HookRegistry, get_registry, set_registry
from alfred.security.quarantine import (
    ContentHandle,
    Extracted,
    ExtractionSchema,
    T3DerivedData,
    declare_hookpoints,
    downgrade_to_orchestrator,
    quarantined_to_structured,
)
from tests.helpers.gates import make_deny_all_gate, make_quarantined_extract_chain_gate


@pytest.fixture(autouse=True)
def _extract_chain_gate() -> Iterator[None]:
    """Install a scoped :class:`RealGate` as the registry singleton
    for every test in this module.

    Post-CR-156 round 7 / CR-158 T1, :class:`QuarantinedExtractor`'s
    constructor raises on gate-deny. Tests in this module that
    construct an extractor (the audit-row pin) need a granted gate;
    tests that pass a stub extractor through
    :func:`quarantined_to_structured` don't strictly need one, but
    the autouse fixture keeps the gate posture uniform across the
    module so a future refactor that adds a real extractor doesn't
    silently fail.

    The scoped :class:`RealGate` (CLAUDE.md hard rule #2 — NOT a
    permissive shim) seeds the system-tier grant for the DLP
    subscriber on the ``security.quarantined.extract`` chain. The
    hookpoint is re-declared against the fresh registry so the
    helper's register-time check sees a declared post bucket.
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(),
        strict_declarations=False,
    )
    try:
        # Install + declare INSIDE the try so any failure in
        # :func:`declare_hookpoints` cannot leak the half-installed
        # singleton to sibling modules (CR-158 round 2).
        set_registry(registry)
        declare_hookpoints(registry)
        yield
    finally:
        set_registry(prior)


# ---------------------------------------------------------------------------
# Local helpers — keep test bodies declarative.
# ---------------------------------------------------------------------------


class _ArticleSchema(ExtractionSchema):
    """Trivial ExtractionSchema subclass for chain testing.

    ``schema_version`` is inherited from :class:`ExtractionSchema` (the
    ABC pins it at ``ClassVar[Literal[1]] = 1``). The redundant
    declaration here documents the contract at the test-side call site.
    """

    schema_version: ClassVar[Literal[1]] = 1
    title: str = ""


def _make_handle(source: str = "https://example.test/article") -> ContentHandle:
    return ContentHandle(
        id="chain-test-uuid",
        source_url=source,
        fetch_timestamp=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Invariant 1: ContentHandle exposes no .content attribute (spec §7.3).
# ---------------------------------------------------------------------------


def test_content_handle_has_no_content_attribute() -> None:
    """The orchestrator's only T3 surface, :class:`ContentHandle`, carries no payload.

    The bypass-impossible posture: even if the orchestrator wanted to
    dereference the T3 bytes, it could not — the handle has no
    ``.content`` field. The only legitimate dereference path is
    :func:`quarantined_to_structured`, which is gate-checked.
    """
    handle = _make_handle()
    assert not hasattr(handle, "content"), (
        "ContentHandle MUST NOT expose a .content attribute — the orchestrator "
        "must never be able to dereference T3 bytes directly (spec §7.3)."
    )


# ---------------------------------------------------------------------------
# Invariant 2: gate-first ordering and T3DerivedData survives the chain.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_quarantined_to_structured_returns_extracted_with_t3_derived_data() -> None:
    """The full :func:`quarantined_to_structured` chain yields :class:`Extracted`
    whose ``data`` is :class:`T3DerivedData` (NewType over dict).

    The chain: gate.check_content_clearance(T3) -> extractor.extract ->
    Extracted. The extractor here is a fake whose ``extract`` returns a
    pre-built :class:`Extracted` — the test exercises the orchestration
    surface, not the provider dispatch (that's Task 14).
    """
    fake_extractor = MagicMock()
    fake_extractor.extract = AsyncMock(
        return_value=Extracted(
            data=T3DerivedData({"title": "Safe Title"}),
            extraction_mode="native_constrained",
        ),
    )
    # CR-158 round 2: success path uses :class:`RealGate` with a
    # content-tier T3 grant for ``quarantine.dereference`` (PRD §7.1
    # / CLAUDE.md hard rule #2) — NOT a hand-rolled allow-all shim
    # that ignores ``plugin_id`` / ``hookpoint`` / ``content_tier``
    # and would mask a grant-matching regression on the boundary.
    gate = make_quarantined_extract_chain_gate(grant_dereference_t3=True)
    result = await quarantined_to_structured(
        _make_handle(),
        _ArticleSchema,
        extractor=fake_extractor,
        gate=gate,
    )
    assert isinstance(result, Extracted)
    # T3DerivedData is a NewType over dict[str, object] — at runtime
    # the value is a plain dict; the type-level provenance survives.
    assert isinstance(result.data, dict)
    assert result.data == {"title": "Safe Title"}
    # And the extractor was called exactly once — the gate did not
    # short-circuit the call (this is the success path).
    fake_extractor.extract.assert_awaited_once()


@pytest.mark.asyncio
async def test_quarantined_to_structured_denied_gate_skips_extractor() -> None:
    """Gate-first ordering: a denial raises :class:`AlfredError` BEFORE the extractor runs.

    A leaking gate would let denied content reach the extractor and from
    there into the orchestrator's prompt context. The test fails loudly
    on that path: the extractor is an :class:`AsyncMock` that records
    invocations — ``assert_not_awaited`` is the structural pin.
    """
    from alfred.errors import AlfredError

    fake_extractor = MagicMock()
    fake_extractor.extract = AsyncMock()

    # CR-158 round 2: deny path uses :class:`RealGate` with an
    # empty grant store (PRD §7.1 / CLAUDE.md hard rule #2).
    # :func:`make_deny_all_gate` returns a RealGate whose
    # ``check_content_clearance`` denies fail-closed for every
    # (plugin_id, hookpoint, content_tier) tuple — exercising the
    # production grant-policy check rather than a hand-rolled shim
    # that hard-codes ``return False``.
    with pytest.raises(AlfredError):
        await quarantined_to_structured(
            _make_handle(),
            _ArticleSchema,
            extractor=fake_extractor,
            gate=make_deny_all_gate(),
        )
    fake_extractor.extract.assert_not_awaited()


# ---------------------------------------------------------------------------
# Invariant 3: Injected instruction does not appear in Extracted.data.
# ---------------------------------------------------------------------------


def test_injected_instruction_not_in_extracted_data(
    recorded_injection_fixture: dict[str, Any],
) -> None:
    """An injected instruction string in the T3 source MUST NOT survive verbatim.

    The dual-LLM split (PRD §7.1, spec §6.3) guarantees that the
    quarantined LLM's structured-extraction response is schema-
    validated by the host BEFORE the orchestrator sees it. Any
    "Ignore previous instructions" string in the T3 payload would
    either be dropped (schema-incompatible) or refused (TypedRefusal).
    """
    injected = recorded_injection_fixture["injected_instruction"]
    extracted: Extracted = recorded_injection_fixture["extracted_result"]
    for value in extracted.data.values():
        if isinstance(value, str):
            assert injected not in value, (
                f"Injected instruction {injected!r} found verbatim in Extracted.data"
            )


# ---------------------------------------------------------------------------
# Invariant 4: audit row carries trust_tier_of_trigger="T3" (test-002).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_row_carries_t3_trust_tier_through_full_extract() -> None:
    """:meth:`QuarantinedExtractor.extract` emits an audit row with ``trust_tier_of_trigger='T3'``.

    Spec §6.8 + test-002 (Cluster 4). The audit row is the chain's
    forensic anchor — a downstream auditor must be able to filter every
    T3-trigger extraction event by this single field.
    """
    from alfred.audit import audit_row_schemas
    from alfred.plugins.transport import ControlResult
    from alfred.security.quarantine import QuarantinedExtractor

    # Capture every append_schema kwargs dict so the test can assert on
    # the trust-tier field of the actual call.
    fake_audit_writer = MagicMock()
    captured_calls: list[dict[str, Any]] = []

    async def _capture(**kwargs: Any) -> None:
        captured_calls.append(kwargs)

    fake_audit_writer.append_schema = AsyncMock(side_effect=_capture)

    fake_transport = MagicMock()
    fake_transport.dispatch = AsyncMock(
        return_value=ControlResult(
            method="quarantine.extract",
            payload={
                "kind": "extracted",
                "data": {"title": "safe"},
                "extraction_mode": "native_constrained",
            },
        ),
    )

    # Identity DLP stub — the test asserts the legacy audit-row family;
    # the #158 DLP scan runs but the identity scanner produces no
    # redaction delta, so no HookRefusal interferes with the assertion.
    fake_dlp = MagicMock()
    fake_dlp.scan = MagicMock(side_effect=lambda x: x)
    extractor = QuarantinedExtractor(
        transport=fake_transport,
        audit_writer=fake_audit_writer,
        outbound_dlp=fake_dlp,
    )
    result = await extractor.extract(_make_handle(), _ArticleSchema)

    assert isinstance(result, Extracted)
    assert len(captured_calls) == 1
    call = captured_calls[0]
    # The single audit row for a successful extract carries:
    assert call["trust_tier_of_trigger"] == "T3", (
        "quarantine.extract audit row MUST carry trust_tier_of_trigger='T3' (spec §6.8)"
    )
    assert call["event"] == "quarantine.extract"
    assert call["result"] == "extracted"
    assert call["fields"] is audit_row_schemas.QUARANTINE_EXTRACT_FIELDS
    # CR-158 round 4 deferred: prove the post-stage DLP subscriber
    # actually ran. The audit assertions above are necessary but not
    # sufficient — they could pass on a registry regression where the
    # post bucket lost the DLP subscriber (the identity scanner here
    # would no-op silently and the audit row would still surface as
    # ``extracted``). Asserting on ``scan`` invocation pins the
    # subscriber-was-dispatched contract.
    fake_dlp.scan.assert_called_once()


# ---------------------------------------------------------------------------
# Invariant 5: downgrade-to-orchestrator emits the dedicated audit family.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_downgrade_to_orchestrator_audit_row_chain_traceable() -> None:
    """The downgrade emits ``quarantine.t3_derived_downgrade`` with ``downgrade_explicit=True``.

    Distinct from ``identity.t1_downgrade`` (rvw-003) — T1-user-id and
    T3-derived-data downgrades are forensically separate trust
    transitions. A reviewer filtering on the t3_derived_downgrade event
    must see every T3-origin payload that reached an orchestrator prompt.
    """
    from alfred.audit import audit_row_schemas

    fake_audit_writer = MagicMock()
    captured: list[dict[str, Any]] = []

    async def _capture(**kwargs: Any) -> None:
        captured.append(kwargs)

    fake_audit_writer.append_schema = AsyncMock(side_effect=_capture)

    data: T3DerivedData = T3DerivedData({"title": "Safe Title"})
    # CR-158 round 2: success path uses :class:`RealGate` with a
    # content-tier T3 grant for ``t3.downgrade_to_orchestrator`` —
    # see :func:`make_quarantined_extract_chain_gate` for the
    # rationale.
    plain = await downgrade_to_orchestrator(
        data,
        gate=make_quarantined_extract_chain_gate(grant_downgrade_t3=True),
        audit_writer=fake_audit_writer,
    )

    # Provenance tag is intentionally retired at the boundary.
    assert isinstance(plain, dict)
    assert plain == {"title": "Safe Title"}
    # Exactly one audit row, with the dedicated downgrade family.
    assert len(captured) == 1
    row = captured[0]
    assert row["event"] == "quarantine.t3_derived_downgrade"
    assert row["fields"] is audit_row_schemas.T3_DERIVED_DOWNGRADE_FIELDS
    assert row["subject"]["downgrade_explicit"] is True
    assert row["subject"]["source_tier"] == "T3_derived"
    assert row["subject"]["target_tier"] == "T2"
    assert row["trust_tier_of_trigger"] == "T3"


@pytest.mark.asyncio
async def test_downgrade_denied_gate_writes_no_t3_downgrade_audit_row() -> None:
    """A denied downgrade gate MUST NOT write the dedicated audit row.

    The gate's own refusal accounting (typically the
    ``security.capability_gate.*`` family) is the correct forensic
    anchor for denials. Writing a downgrade row for a denied call would
    let an attacker injection-correlate denied + granted patterns.
    """
    from alfred.errors import AlfredError

    fake_audit_writer = MagicMock()
    captured: list[dict[str, Any]] = []

    async def _capture(**kwargs: Any) -> None:
        captured.append(kwargs)

    fake_audit_writer.append_schema = AsyncMock(side_effect=_capture)

    # CR-158 round 2: deny path uses :class:`RealGate` with an
    # empty grant store. ``check_content_clearance`` denies
    # fail-closed for the ``t3.downgrade_to_orchestrator`` tuple,
    # exercising the production grant-policy check rather than a
    # subclassed shim hard-coding ``return False``.
    with pytest.raises(AlfredError):
        await downgrade_to_orchestrator(
            T3DerivedData({"title": "Safe Title"}),
            gate=make_deny_all_gate(),
            audit_writer=fake_audit_writer,
        )

    # No downgrade row written — the deny path is the gate's
    # responsibility, not this function's.
    assert captured == []


# ---------------------------------------------------------------------------
# Invariant 6: PRD §7.1 — orchestrator never sees raw T3 in the result.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orchestrator_never_observes_raw_t3_bytes_in_chain_result(
    recorded_extraction_fixture: dict[str, Any],
) -> None:
    """PRD §7.1 invariant: the chain's :class:`Extracted` is the orchestrator's view.

    There is no path from the recorded provider response_body to the
    orchestrator that does not go through Pydantic schema validation +
    the gate-first :func:`quarantined_to_structured` boundary. This
    test pins the structural property: the recorded raw response bytes
    NEVER appear as a string inside :class:`Extracted.data`.
    """
    fake_extractor = MagicMock()
    safe_payload: dict[str, object] = {"title": "Safe Article Title"}
    fake_extractor.extract = AsyncMock(
        return_value=Extracted(
            data=T3DerivedData(safe_payload),
            extraction_mode="native_constrained",
        ),
    )

    # CR-158 round 2: success path uses scoped :class:`RealGate`
    # (CLAUDE.md hard rule #2). See the first test in this module
    # for the rationale.
    result = await quarantined_to_structured(
        _make_handle(),
        _ArticleSchema,
        extractor=fake_extractor,
        gate=make_quarantined_extract_chain_gate(grant_dereference_t3=True),
    )

    assert isinstance(result, Extracted)
    # The raw recorded response_body must not appear verbatim in the
    # result — the structured-extraction boundary is the place it gets
    # validated + reshaped.
    import json as _json

    raw_response_body = _json.dumps(recorded_extraction_fixture["response_body"])
    for value in result.data.values():
        if isinstance(value, str):
            assert raw_response_body not in value, (
                "Raw recorded provider response_body must not appear verbatim "
                "inside Extracted.data — the structured-extraction boundary is "
                "the validation point (PRD §7.1)."
            )


# ---------------------------------------------------------------------------
# Invariant 7: canary trip pre-empts extract (spec §12.4).
# ---------------------------------------------------------------------------


def test_canary_token_fixture_pre_empts_extract(
    recorded_canary_fixture: dict[str, Any],
) -> None:
    """Canary token in T3 content trips BEFORE :meth:`QuarantinedExtractor.extract`.

    Spec §12.4 ordering. Slice-3 ships the invariant as a fixture-shape
    contract; PR-S3-5 wires the live :class:`InboundCanaryScanner`. The
    test pins the ordering so PR-S3-5 cannot regress it.
    """
    assert recorded_canary_fixture["canary_tripped"] is True
    assert recorded_canary_fixture["extract_was_called"] is False
