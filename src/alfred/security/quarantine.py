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
from typing import TYPE_CHECKING, Any, ClassVar, Literal, NewType

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from alfred.hooks.capability import CapabilityGate


# ---------------------------------------------------------------------------
# ExtractionSchema — ABC for quarantined-LLM structured extraction (ai-001)
# ---------------------------------------------------------------------------


class ExtractionSchema(BaseModel):
    """ABC for Pydantic schemas the quarantined LLM extracts to.

    ADR-0017 Decision 7 + ai-001 (slice-3 retrospective): every
    extraction schema MUST carry ``schema_version: ClassVar[Literal[1]]``
    so the audit row's ``schema_version`` field (see
    :data:`alfred.audit.audit_row_schemas.QUARANTINE_EXTRACT_FIELDS`) is
    populated from a value the type system can pin. Pre-fix the field
    existed on the audit row but no class enforced it on extraction
    schemas — a Slice-4 author could ship a schema with no version, or
    with version 2, and the audit row would silently carry whatever was
    bound at the call site (or, worse, omit it).

    ``__init_subclass__`` enforces the invariant at class-construction
    time, NOT at extraction-call time: a typo'd ``schema_version = 2``
    fails ``import``-time, not run-time. The check uses ``Literal[1]``
    at the type level and an equality check at the runtime level —
    both are mandatory because Pydantic v2's metaclass doesn't enforce
    ClassVar Literal narrowing on subclass declarations.

    When :class:`QuarantinedExtractor.extract` lands in PR-S3-4 it will
    type-hint ``schema: type[ExtractionSchema]`` so an
    :class:`~pydantic.BaseModel` that forgets the version annotation is
    refused at the call site (Pydantic-only schemas remain valid for
    code outside the quarantine path; the ABC is the gate ONLY for the
    extraction path).

    Slice 4+: when the schema vocabulary evolves beyond v1, lift the
    ``Literal[1]`` to ``Literal[1, 2]`` and migrate the audit_row_schemas
    field to a discriminated union per version. Until then, the closed
    set keeps the audit-side consumer's deserialisation single-branched.
    """

    # ClassVar so Pydantic does NOT treat ``schema_version`` as a model
    # field (which would surface in ``.model_dump()`` and the wire
    # format). The ABC's contract is "every subclass pins the value at
    # the class level", not "every instance carries the value".
    #
    # ``Literal[1]`` makes mypy / pyright refuse a subclass that
    # rebinds the value to anything but 1; the ``__init_subclass__``
    # runtime check below is the defence-in-depth that survives
    # ``# type: ignore`` and ``python -O`` (which doesn't strip class
    # bodies but DOES strip asserts).
    schema_version: ClassVar[Literal[1]] = 1

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Pydantic's metaclass calls this *after* it processes the
        # subclass body, so ``cls.schema_version`` is the resolved
        # ClassVar binding. A subclass that simply omits the
        # annotation inherits the parent's ``1``; a subclass that
        # rebinds to ``2`` (via ``schema_version: ClassVar[Literal[2]] = 2``
        # — bypassing the Literal[1] static check with a wider literal
        # in the subclass) fails the equality check below.
        if getattr(cls, "schema_version", None) != 1:
            raise TypeError(
                "ExtractionSchema subclass "
                f"{cls.__name__} must keep schema_version: "
                "ClassVar[Literal[1]] = 1 — version bumps are not yet "
                "supported (ADR-0017 Decision 7 / ai-001)."
            )


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

    ``fetch_timestamp`` MUST be timezone-aware. Naive datetimes silently
    encode the producer's local clock, which breaks forensic ordering
    when audit rows from different hosts are correlated and can hide
    out-of-order extracts under DST boundaries. CR-138 finding #4.
    """

    id: str
    source_url: str
    fetch_timestamp: datetime

    def __post_init__(self) -> None:
        # tzinfo presence alone is insufficient — a tzinfo whose
        # ``utcoffset()`` returns ``None`` (legal per the datetime
        # contract for "unknown") is functionally naive. Both checks
        # must pass.
        if self.fetch_timestamp.tzinfo is None or self.fetch_timestamp.utcoffset() is None:
            raise ValueError(
                "ContentHandle.fetch_timestamp must be timezone-aware; "
                f"got naive datetime {self.fetch_timestamp!r}"
            )


# ---------------------------------------------------------------------------
# quarantined_to_structured — STUB (full impl PR-S3-4)
# ---------------------------------------------------------------------------


async def quarantined_to_structured(
    handle: ContentHandle,
    schema: type[ExtractionSchema],
    *,
    extractor: Any,
    gate: CapabilityGate,
) -> Any:
    """Convert an opaque ContentHandle into a validated Pydantic model.

    THIS IS THE ONLY PATH by which T3-derived content reaches
    orchestrator-readable structured form. Any other path is a security
    violation.

    STUB in PR-S3-1. Full implementation is PR-S3-4 (QuarantinedExtractor,
    ExtractionResult discriminated union, DLP post-scan, audit row).

    ``schema`` is typed as :class:`type[ExtractionSchema]` (ai-001) so
    a Pydantic schema that forgets to set ``schema_version: ClassVar[
    Literal[1]] = 1`` is refused at the call site. The audit row's
    ``schema_version`` field (see
    :data:`alfred.audit.audit_row_schemas.QUARANTINE_EXTRACT_FIELDS`)
    is populated from the class-level value the ABC enforces.

    The caller must hold check_content_clearance(plugin_id,
    hookpoint="quarantine.dereference", content_tier="T3") — a clearance
    distinct from the tag.T3 clearance (which is plugin-host-internal).
    See spec §3.4.

    ``gate`` is REQUIRED — no default, no ``| None``. A trust-boundary
    function whose capability gate can be elided through a default
    argument is a boundary with a bypass path codified in its public
    type signature. Tests inject a fixture gate (see
    ``tests/unit/security/conftest.py``); production callers inject the
    real ``CapabilityGate`` implementation. CR-138 finding #5.
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
# ExtractionResult discriminated union (PR-S3-4 — full Pydantic shape;
# spec §6.7).
# ---------------------------------------------------------------------------
# PR-S3-1 shipped stubs (data+handle; reason+handle); PR-S3-3a's
# DispatchResult union depends on these symbols at import time. PR-S3-4
# (this code) promotes the stubs to the full Pydantic shape.
#
# The full shape preserves T3 provenance through the orchestrator:
#
#   * Extracted.data is annotated T3DerivedData (NewType over dict) — the
#     type-level provenance tag survives serialisation round-trips and
#     blocks implicit dict substitution at the trust-boundary call site.
#   * downgrade_to_orchestrator() is the only path that escapes the tier;
#     it writes downgrade_explicit=True to the audit row.
#   * Extracted is NOT a dict subclass — duck-typing on __getitem__ does
#     not work, callers MUST go through .data and the downgrade path.
#
# kind="malformed_output" is deliberately absent from both Extracted.kind
# (Literal["extracted"]) and TypedRefusal.reason (closed Literal set). The
# host transport treats unexpected kind values as PluginProtocolViolation
# (spec §6.7 / prov-011), not as legitimate orchestrator outcomes.

# Closed reason vocabulary for TypedRefusal. Audit rows pin
# refusal_reason from this Literal so downstream consumers can branch on
# a fixed-domain string without parsing free-form text.
#
# Vocabulary sources:
#   * cannot_extract (plan §6.3)       — exhausted retries
#   * refused_by_safety (plan §6.7)    — provider safety filter
#   * ambiguous_input (plan §6.7)      — schema-incompatible input
#   * provider_refused                  — structured provider refusal
#   * provider_unavailable              — circuit breaker / supervisor down
#   * dlp_outbound_refused              — DLP post-scan blocked the result
#   * nonce_check_failed                — handle-id nonce mismatch (PR-S3-5)
TypedRefusalReason = Literal[
    "cannot_extract",
    "refused_by_safety",
    "ambiguous_input",
    "provider_refused",
    "provider_unavailable",
    "dlp_outbound_refused",
    "nonce_check_failed",
]

# Closed dispatch-path Literal — matches the three branches in spec §6.2
# and the audit-row extraction_mode field. Any drift here breaks audit-row
# continuity, so the closed set is enforced at the type level.
ExtractionMode = Literal[
    "native_constrained",
    "json_object_unconstrained",
    "prompt_embedded_fallback",
]


class Extracted(BaseModel):
    """Successful structured extraction from T3 content (spec §6.7).

    The .data field carries T3DerivedData — at runtime a dict, at type
    level a NewType that mypy/pyright refuse to silently widen to dict.
    The orchestrator MUST call :func:`downgrade_to_orchestrator` (which
    writes ``downgrade_explicit=True`` to the audit row) before injecting
    this value into a privileged prompt. The provenance tag IS the
    escape-hatch gate.

    Frozen so the audit-emit pipeline cannot mutate the result between
    construction and persistence. extra="forbid" catches typos at the
    transport boundary (a "kindd" field would silently survive a permissive
    config and break audit-row consumers).

    NOT a dict subclass — downstream code that duck-types
    ``result["data"]`` will fail loudly, preventing accidental
    transparent-T2 treatment of T3-derived structured data.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # kind discriminates the union at parse time when a Pydantic
    # TypeAdapter is constructed against Annotated[Extracted | TypedRefusal,
    # Field(discriminator="kind")]. The runtime alias is the plain union
    # (core-011) — dispatch sites branch by isinstance.
    kind: Literal["extracted"] = "extracted"
    data: T3DerivedData
    extraction_mode: ExtractionMode


class TypedRefusal(BaseModel):
    """Quarantined extractor refusal (spec §6.7).

    The closed reason vocabulary is the audit-row boundary: free-form
    reasons would leak provider-supplied (potentially T3-derived) text
    into orchestrator-readable fields. A new refusal cause requires a
    deliberate addition to :data:`TypedRefusalReason` and the matching
    reviewer-gated audit-schema migration.

    Frozen + extra="forbid" for the same audit-pipeline reasons as
    Extracted.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["typed_refusal"] = "typed_refusal"
    reason: TypedRefusalReason


# ExtractionResult: plain union of the two branches (core-011 — no
# Annotated discriminator wrapper at the alias level). The transport-layer
# DispatchResult flattens this union; dispatch sites branch by isinstance.
# Pydantic TypeAdapter callers that need the kind discriminator wrap the
# alias themselves at parse time:
#
#   TypeAdapter(Annotated[ExtractionResult, Field(discriminator="kind")])
#
# This keeps the runtime alias compatible with PR-S3-3a's
# typing.get_args(DispatchResult) walk (which flattens nested unions one
# level deep).
ExtractionResult = Extracted | TypedRefusal
