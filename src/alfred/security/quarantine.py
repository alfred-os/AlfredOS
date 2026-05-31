"""T3-to-orchestrator boundary — the ONLY legitimate crossing point.

This module is the single grep anchor for all T3-derived-data handoffs
to orchestrator-readable structured form. Any code outside this module
that claims to convert T3 content is a security violation.

Contents:
- T3DerivedData: NewType over dict[str, object] — type-level provenance
  marker on Extracted.data (spec §3.7). Callers must use
  downgrade_to_orchestrator() before injecting T3DerivedData values into
  privileged prompts.
- ContentHandle: frozen opaque reference to T3 content in the plugin
  host's content store. The orchestrator holds this; it has no .content
  field (spec §7.3).
- quarantined_to_structured: STUB — full implementation is PR-S3-4
  (QuarantinedExtractor + ExtractionResult + DLP post-scan).
- downgrade_to_orchestrator: STUB — full implementation is PR-S3-4
  (capability-gate check + audit row with downgrade_explicit=True).

ADR-0013, ADR-0017.
PRD §7.1 invariant: the privileged orchestrator never processes raw T3
content; the quarantined LLM emits structured data only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, NewType

if TYPE_CHECKING:
    from pydantic import BaseModel

    from alfred.hooks.capability import CapabilityGate

# ---------------------------------------------------------------------------
# T3DerivedData — Slice-3 type-level provenance discriminant (spec §3.7)
# ---------------------------------------------------------------------------

T3DerivedData = NewType("T3DerivedData", dict[str, object])
"""Type-level provenance marker for data derived from T3 (untrusted) sources.

A NewType over dict[str, object]. At runtime it is a plain dict; at
type-check time mypy treats it as distinct so callers that attempt
`cast(dict, t3_data)` trigger the CI ruff/grep rule in
scripts/check_tag_t3.py.

Callers MUST call downgrade_to_orchestrator(data, audit_row=...) before
injecting T3DerivedData values into privileged prompts. That function
holds the CapabilityGate check + audit row write.

Slice 4 promotes this to a full type-parameter on TaggedContent (a
provenance axis alongside the tier axis). See spec §3.7.
"""


# ---------------------------------------------------------------------------
# ContentHandle — opaque T3 content reference (spec §7.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContentHandle:
    """Opaque reference to T3 content held in the plugin host's content store.

    The orchestrator holds this; the quarantined-LLM plugin dereferences
    it. The orchestrator NEVER calls .content — that field does not exist.

    `source_url` is for audit attribution only; it is NOT readable content
    in the sense that the orchestrator can act on it (it's a URL string,
    not the fetched bytes). `fetch_timestamp` enables forensic ordering.

    Single-use invariant: each `id` UUID is used for exactly one
    quarantine.extract call. The content store (PR-S3-5) enforces this
    via atomic DEL on first successful extract. A second extract against
    the same id receives ContentHandleExpired. See spec §7.2.
    """

    id: str
    source_url: str
    fetch_timestamp: datetime


# ---------------------------------------------------------------------------
# quarantined_to_structured — STUB (full impl PR-S3-4)
# ---------------------------------------------------------------------------


async def quarantined_to_structured(
    handle: ContentHandle,
    schema: type[BaseModel],
    *,
    extractor: Any,
    gate: CapabilityGate | None,
) -> Any:
    """Convert an opaque ContentHandle into a validated Pydantic model.

    THIS IS THE ONLY PATH by which T3-derived content reaches
    orchestrator-readable structured form. Any other path is a security
    violation.

    STUB in PR-S3-1. Full implementation is PR-S3-4 (QuarantinedExtractor,
    ExtractionResult discriminated union, DLP post-scan, audit row).

    The caller must hold check_content_clearance(plugin_id,
    hookpoint="quarantine.dereference", content_tier="T3") — a clearance
    distinct from the tag.T3 clearance (which is plugin-host-internal).
    See spec §3.4.
    """
    raise NotImplementedError("quarantined_to_structured stub — full implementation is PR-S3-4")


# ---------------------------------------------------------------------------
# downgrade_to_orchestrator — STUB (full impl PR-S3-4)
# ---------------------------------------------------------------------------


async def downgrade_to_orchestrator(
    data: T3DerivedData,
    *,
    audit_row: Any,
) -> dict[str, object]:
    """Gate for injecting T3DerivedData into a privileged prompt.

    Requires CapabilityGate.check_content_clearance(hookpoint=
    "t3.downgrade_to_orchestrator", content_tier="T3_derived") and
    writes an audit row using T3_DERIVED_DOWNGRADE_FIELDS (PR-S3-0a) with
    event "quarantine.t3_derived_to_orchestrator" and downgrade_explicit=True.

    NOTE (rvw-003): Do NOT reuse T1_DOWNGRADE_FIELDS here. T1_DOWNGRADE_FIELDS
    is for the T1→T2 broadcast-safe conversion; this event is a distinct
    T3-derived→orchestrator crossing. PR-S3-0a must define T3_DERIVED_DOWNGRADE_FIELDS
    and event "quarantine.t3_derived_to_orchestrator" before PR-S3-4 wires the
    full implementation.

    STUB in PR-S3-1. Full implementation is PR-S3-4.
    See spec §3.7.
    """
    raise NotImplementedError("downgrade_to_orchestrator stub — full implementation is PR-S3-4")


# ---------------------------------------------------------------------------
# ExtractionResult discriminated-union stubs (full impl PR-S3-4)
# ---------------------------------------------------------------------------
# sec-002: PR-S3-3a imports ExtractionResult from alfred.security.quarantine
# before PR-S3-4 merges. Declare the union type stubs here so the import
# chain is satisfied. PR-S3-4 replaces these stubs with the full
# QuarantinedExtractor implementation; it does NOT redefine the types.


@dataclass(frozen=True, slots=True)
class Extracted:
    """Successful extraction result: validated structured data from T3 content.

    STUB shape — PR-S3-4 wires the full QuarantinedExtractor consumer.
    The `.data` field is T3DerivedData (provenance-marked dict). Callers
    must use downgrade_to_orchestrator() before injecting into privileged
    prompts. See spec §5.5.
    """

    data: T3DerivedData
    handle: ContentHandle


@dataclass(frozen=True, slots=True)
class TypedRefusal:
    """Quarantine-LLM refusal: the model declined to extract from this content.

    STUB shape — PR-S3-4 wires the full consumer. `reason` is a string
    from a closed vocabulary (see spec §5.5 TypedRefusal.reason values).
    """

    reason: str
    handle: ContentHandle


# ExtractionResult discriminated union (spec §5.5).
# PR-S3-3a's DispatchResult uses this as the extraction branch.
ExtractionResult = Extracted | TypedRefusal
