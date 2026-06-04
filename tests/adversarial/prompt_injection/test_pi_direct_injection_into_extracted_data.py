"""Adversarial prompt_injection — direct injection into Extracted.data.

T3 web content with an "Ignore previous instructions" payload reaches
the quarantined LLM. The privileged orchestrator MUST NOT observe the
raw payload; it consumes only the validated :class:`Extracted` instance
whose ``data`` field is the structured-extraction response.

This module exercises the structural defences that make the direct-
injection laundering attempt fail-shut:

1. The privileged orchestrator NEVER calls ``ContentHandle.content``
   — that attribute does not exist on the frozen dataclass. The
   orchestrator can only hold the opaque handle; only the quarantined-
   LLM path can dereference it (spec §7.3).
2. :func:`quarantined_to_structured` is the ONLY path by which T3 data
   reaches orchestrator-readable structured form. The PR-S3-1 ship
   surfaces it as a fail-loud :class:`NotImplementedError` stub —
   PR-S3-4 lands the full extraction. The stub posture is itself a
   defence: any caller before PR-S3-4 fails loudly, preventing a
   silent partial-implementation that could ship without DLP post-scan.
3. The downgrade path requires ``content_tier="T3"`` clearance (PRD
   §7.1 canonical tier vocabulary) through :func:`downgrade_to_
   orchestrator` before injecting :data:`T3DerivedData` into a
   privileged prompt (spec §3.7). The ``T3_derived`` forensic
   provenance is recorded on the audit row's ``source_tier`` field.

Outcome: the payload is **neutralized** — the orchestrator's prompt
context never receives the injection text because every path between
the T3 plugin and the orchestrator's prompt is gated on Pydantic
schema validation + a capability-gate clearance.

Spec §3.5, §3.7, §5.5. Payload id: ``pi-2026-001``.
"""

from __future__ import annotations

from dataclasses import fields as dataclass_fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import pytest
import yaml

from alfred.security.quarantine import (
    ContentHandle,
    Extracted,
    T3DerivedData,
    quarantined_to_structured,
)

_PAYLOAD_ID: Final[str] = "pi-2026-001"
_PAYLOAD_PATH: Final[Path] = Path(__file__).parent / "pi_direct_injection_into_extracted_data.yaml"


def test_payload_yaml_present_and_well_formed() -> None:
    """Drift-guard: the ``pi-2026-001`` YAML exists with expected shape."""
    assert _PAYLOAD_PATH.exists(), f"Missing adversarial payload {_PAYLOAD_PATH.name}"
    payload = yaml.safe_load(_PAYLOAD_PATH.read_text())
    assert payload["id"] == _PAYLOAD_ID
    assert payload["category"] == "prompt_injection"
    assert payload["ingestion_path"] == "web.fetch"
    assert payload["expected_outcome"] == "neutralized"
    # The payload string MUST contain the canonical injection phrase so
    # a future scrub-rule promotion can grep the corpus for the shape.
    assert "Ignore all previous instructions" in payload["payload"]


def test_content_handle_has_no_content_attribute() -> None:
    """The orchestrator's view of T3 — :class:`ContentHandle` — exposes no payload.

    The bypass-impossible posture for direct injection laundering:
    even if the privileged orchestrator wanted to read the injection
    text it couldn't, because the only references it holds (the
    handle) carry no ``.content`` attribute. Dereference goes through
    :func:`quarantined_to_structured`, which lands DLP / schema
    validation / capability-gate clearance.
    """
    handle = ContentHandle(
        id="00000000-0000-0000-0000-000000000000",
        source_url="https://example.test/article",
        fetch_timestamp=datetime.now(UTC),
    )
    handle_field_names = {f.name for f in dataclass_fields(handle)}
    assert "content" not in handle_field_names, (
        "ContentHandle exposes a .content field — this is a direct-injection "
        "laundering path; T3 payload would be observable to the orchestrator. "
        f"Got fields: {handle_field_names!r}"
    )
    # And the only fields are the audit-attribution shape — no payload
    # surface for the orchestrator to enumerate.
    assert handle_field_names == {"id", "source_url", "fetch_timestamp"}


def test_extracted_data_field_is_t3_derived_data_type() -> None:
    """The ``Extracted.data`` field is typed as :data:`T3DerivedData`.

    :data:`T3DerivedData` is a :class:`typing.NewType` over
    ``dict[str, object]`` — the type-level provenance discriminant
    that tells :func:`downgrade_to_orchestrator` "this dict came from
    a T3 source; gate before injecting into a privileged prompt".
    Without that distinction the orchestrator could silently consume
    extracted dicts whose values came from injection-laundering
    attempts (the keys would be schema-validated, but the values are
    attacker-controlled strings).

    :class:`Extracted` is a Pydantic v2 :class:`~pydantic.BaseModel`
    (PR-S3-4 Task 3), not a dataclass — ``Extracted.model_fields``
    is the introspection surface; :func:`dataclasses.fields` raises
    ``TypeError`` on a BaseModel. The annotation is exposed via
    ``FieldInfo.annotation`` rather than the dataclass ``.type``
    string.
    """
    extracted_field_annotations = {
        name: field.annotation for name, field in Extracted.model_fields.items()
    }
    assert "data" in extracted_field_annotations
    # The Pydantic FieldInfo carries the resolved annotation object —
    # for a :data:`typing.NewType` over ``dict[str, object]`` that's the
    # NewType callable itself. Compare by identity rather than the
    # dataclass-era string compare.
    assert extracted_field_annotations["data"] is T3DerivedData, (
        f"Extracted.data must be typed T3DerivedData (the provenance "
        f"discriminant); got {extracted_field_annotations['data']!r}"
    )
    # And the NewType supertype IS dict[str, object] — operators can
    # rely on dict semantics inside the downgrade gate. ``__supertype__``
    # is the runtime attribute :func:`typing.NewType` injects; mypy
    # narrows the value to its type-checker form which lacks the
    # attribute, hence the ignore.
    assert T3DerivedData.__supertype__ is not None  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_quarantined_to_structured_refuses_on_denied_gate() -> None:
    """:func:`quarantined_to_structured` is gate-first.

    PR-S3-4 Task 7 promoted the prior fail-loud
    :class:`NotImplementedError` stub into the full impl: the function
    consults ``CapabilityGate.check_content_clearance(...,
    hookpoint="quarantine.dereference", content_tier="T3")`` BEFORE
    invoking the extractor. A denial raises :class:`AlfredError`
    without touching the extractor — the structural defence against
    silent T3 dereference. CLAUDE.md hard rule #4 (no bypass), hard
    rule #7 (loud refusal).

    The adversarial posture: a T3 web payload reaching
    :func:`quarantined_to_structured` MUST trip the gate before the
    extractor's :meth:`extract` runs — the extractor here is a stub
    whose ``extract`` would AttributeError if touched, so the test
    fails loudly on any path that skips the gate.
    """
    from alfred.errors import AlfredError
    from alfred.security.quarantine import ExtractionSchema
    from tests.helpers.gates import make_deny_all_gate

    handle = ContentHandle(
        id="00000000-0000-0000-0000-000000000000",
        source_url="https://attacker.example/leak-attempt",
        fetch_timestamp=datetime.now(UTC),
    )

    class _StubSchema(ExtractionSchema):
        pass

    # A bare object — any attempt to call ``.extract`` will AttributeError,
    # which proves the gate refused BEFORE the extractor was touched.
    class _DummyExtractor:
        pass

    # CLAUDE.md hard rule #2 + CR-158 round-3: drive the production
    # ``RealGate`` via the canonical deny-all factory rather than a
    # hand-rolled stub. The stub satisfied the protocol shape but did
    # NOT exercise the actual ``check_content_clearance`` matcher for
    # ``plugin_id="alfred.quarantined-llm" / hookpoint="quarantine.dereference"``,
    # so a regression in PRD §7.1's boundary gate could have passed
    # here unnoticed.
    with pytest.raises(AlfredError):
        await quarantined_to_structured(
            handle,
            _StubSchema,
            extractor=_DummyExtractor(),  # type: ignore[arg-type]
            gate=make_deny_all_gate(),
        )


@pytest.mark.asyncio
async def test_dlp_subscriber_refuses_canary_in_extracted_payload() -> None:
    """Pin MEDIUM #9 (CR-158): the post-stage
    :class:`OutboundDlpExtractSubscriber` on
    ``security.quarantined.extract`` MUST refuse an
    :class:`Extracted` whose ``data`` carries a canary token.

    The adversarial posture under test: a T3 web payload coerces the
    quarantined LLM into emitting a canary-marked secret inside the
    structured-extraction response (a free-text ``summary: str``
    field is the spec §6.5 primary exfil channel). Defence:
    :class:`OutboundDlp.scan` runs against
    :meth:`pydantic.BaseModel.model_dump`; a redaction delta means a
    canary tripped; the subscriber raises :class:`HookRefusal` and
    the validated payload NEVER returns to the privileged
    orchestrator.

    Pre-#158 the hookpoint was unregistered and the DLP scan never
    ran; this adversarial pin would have passed against a
    structurally-correct extract that silently leaked the canary
    into ``Extracted.data``. The fix wires the hookpoint chain;
    this test is the corpus-side proof.
    """
    import re
    from typing import ClassVar, Literal
    from unittest.mock import AsyncMock, MagicMock

    from alfred.hooks import HookRefusal
    from alfred.hooks.registry import HookRegistry, get_registry, set_registry
    from alfred.plugins.transport import ControlResult
    from alfred.security._extract_dlp_subscriber import (
        OutboundDlpExtractSubscriber,
        register_extract_dlp_subscriber,
    )
    from alfred.security.quarantine import (
        ExtractionSchema,
        QuarantinedExtractor,
        declare_hookpoints,
    )
    from tests.helpers.gates import make_quarantined_extract_chain_gate

    class _SummarySchema(ExtractionSchema):
        """Schema mirroring the spec §6.5 free-text exfil shape."""

        schema_version: ClassVar[Literal[1]] = 1
        summary: str = ""

    # CR-156 round-7 / CR-158 T4 (CLAUDE.md hard rule #2): scoped
    # :class:`RealGate` — production gate code, NOT
    # ``make_permissive_fixture_gate(allow_system=True)``. The
    # adversarial pin asserts a PRD §7.1 trust-boundary outcome
    # (the DLP subscriber refuses an extracted-payload canary); a
    # permissive shim would let a regression in the registry's
    # grant-policy check pass silently. The scoped gate seeds the
    # system-tier grant for the DLP subscriber's plugin_id on
    # security.quarantined.extract. Restore the singleton on
    # teardown — adversarial tests run inside the same process;
    # a leaked singleton would cross-contaminate the unit suite.
    prior = get_registry()
    registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(),
        strict_declarations=False,
    )
    set_registry(registry)
    try:
        declare_hookpoints(registry)

        # Canary token mirrors the
        # ``pi_direct_injection_into_extracted_data.yaml``
        # exfiltration shape — a string the orchestrator's DLP
        # broker recognises (or, as here, the test's mock DLP
        # redacts) as a leakage signal.
        canary = "CANARY-PI-2026-001"
        dlp = MagicMock()
        dlp.scan = MagicMock(side_effect=lambda x: re.sub(canary, "[REDACTED]", x))
        register_extract_dlp_subscriber(registry=registry, outbound_dlp=dlp)

        # Transport returns a schema-valid Extracted whose ``summary``
        # carries the canary — the LLM was coerced into emitting it.
        transport = MagicMock()
        transport.dispatch = AsyncMock(
            return_value=ControlResult(
                method="quarantine.extract",
                payload={
                    "kind": "extracted",
                    "data": {"summary": f"benign prose with {canary} embedded"},
                    "extraction_mode": "native_constrained",
                },
            ),
        )

        audit_writer = MagicMock()
        audit_writer.append_schema = AsyncMock()
        extractor = QuarantinedExtractor(
            transport=transport,
            audit_writer=audit_writer,
            outbound_dlp=dlp,
        )

        handle = ContentHandle(
            id="00000000-0000-0000-0000-000000000158",
            source_url="https://attacker.example/article",
            fetch_timestamp=datetime.now(UTC),
        )

        # Adversarial outcome: the DLP subscriber's post-stage scan
        # detects the canary and refuses. The privileged orchestrator
        # NEVER sees the validated payload.
        with pytest.raises(HookRefusal) as excinfo:
            await extractor.extract(handle, _SummarySchema)
        assert excinfo.value.hook_id == "security.quarantined.extract.post.dlp"
        assert excinfo.value.reason == "canary_or_secret_in_extracted_payload"

        # CR-158 round 4 deferred: pin the audit row's
        # ``post_stage_refused`` outcome AND ``refusing_hook_id``
        # explicitly. The HookRefusal raise alone is not enough — this
        # test would otherwise still pass if a regression stopped
        # emitting the refusal-attributed ``quarantine.extract`` row
        # (the round-3 BLOCKER #2 fix). The audit row IS the post-stage
        # forensic surface for refusing-subscriber identity because
        # ``alfred.hooks.invoke._run_post`` does not emit
        # ``HOOKS_REFUSAL`` (§6.5 is pre-only).
        audit_writer.append_schema.assert_awaited()
        refusal_calls = [
            call.kwargs
            for call in audit_writer.append_schema.await_args_list
            if call.kwargs.get("event") == "quarantine.extract"
        ]
        assert len(refusal_calls) == 1, (
            f"Expected exactly one quarantine.extract audit row on the "
            f"post-stage-refusal path; got {len(refusal_calls)}"
        )
        refusal_subject = refusal_calls[0]["subject"]
        assert refusal_subject["result"] == "post_stage_refused"
        assert refusal_subject["refusing_hook_id"] == OutboundDlpExtractSubscriber._SCAN_ID
    finally:
        set_registry(prior)
