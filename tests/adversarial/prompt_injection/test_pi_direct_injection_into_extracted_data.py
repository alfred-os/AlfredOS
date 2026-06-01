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
3. The downgrade path requires ``content_tier="T3_derived"``
   clearance through :func:`downgrade_to_orchestrator` before injecting
   :data:`T3DerivedData` into a privileged prompt (spec §3.7).

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
    """
    extracted_field_types = {f.name: f.type for f in dataclass_fields(Extracted)}
    assert "data" in extracted_field_types
    # The type hint is a string at the dataclass boundary (PEP 563
    # future-annotations); we compare by name rather than identity.
    assert extracted_field_types["data"] == "T3DerivedData", (
        f"Extracted.data must be typed T3DerivedData (the provenance "
        f"discriminant); got {extracted_field_types['data']!r}"
    )
    # And the NewType supertype IS dict[str, object] — operators can
    # rely on dict semantics inside the downgrade gate. ``__supertype__``
    # is the runtime attribute :func:`typing.NewType` injects; mypy
    # narrows the value to its type-checker form which lacks the
    # attribute, hence the ignore.
    assert T3DerivedData.__supertype__ is not None  # type: ignore[attr-defined]


async def test_quarantined_to_structured_stub_is_fail_loud() -> None:
    """:func:`quarantined_to_structured` raises :class:`NotImplementedError`.

    PR-S3-1 ships the function as a fail-loud deferred stub. PR-S3-4
    replaces the body with the full extraction + DLP post-scan +
    audit row. The stub posture itself is a defence — any caller
    before PR-S3-4 fails loudly, preventing a silent partial wiring
    that could ship without the DLP post-scan step. CLAUDE.md hard
    rule #7 (no silent security paths).

    The capability-gate clearance is intentionally NOT exercised here
    — the stub raises before the gate is consulted, which is the
    correct posture (the stub raise happens at the function boundary,
    not after a successful gate consult).
    """
    handle = ContentHandle(
        id="00000000-0000-0000-0000-000000000000",
        source_url="https://attacker.example/leak-attempt",
        fetch_timestamp=datetime.now(UTC),
    )

    # Use a minimal dummy schema; the stub doesn't get far enough to
    # care about the shape. The point is: the function MUST raise.
    class _DummyExtractor:
        pass

    class _DummyGate:
        pass

    with pytest.raises(NotImplementedError, match="PR-S3-4"):
        from alfred.security.quarantine import ExtractionSchema

        class _StubSchema(ExtractionSchema):
            pass

        await quarantined_to_structured(
            handle,
            _StubSchema,
            extractor=_DummyExtractor(),
            gate=_DummyGate(),  # type: ignore[arg-type]
        )
