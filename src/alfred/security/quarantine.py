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
- QuarantinedExtractor: orchestrator-side client of the quarantined-LLM
  plugin. The only path that dispatches ``quarantine.extract`` JSON-RPC
  calls and lifts ControlResult payloads into typed ExtractionResult
  shapes. PR-S3-4 Task 6.
- quarantined_to_structured: full impl in PR-S3-4. Gate-first then
  delegate to QuarantinedExtractor.
- downgrade_to_orchestrator: full impl in PR-S3-4. Gate-checked T3-
  derived→orchestrator crossing; writes T3_DERIVED_DOWNGRADE_FIELDS
  audit row.

ADR-0013, ADR-0017.
PRD §7.1 invariant: the privileged orchestrator never processes raw T3
content; the quarantined LLM emits structured data only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar, Literal, NewType, cast, get_args

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.hooks.capability import CapabilityGate
    from alfred.plugins.transport import PluginTransport


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


# ---------------------------------------------------------------------------
# QuarantinedExtractor — orchestrator-side client of the quarantined-LLM
# plugin (PR-S3-4 Task 6, spec §6.4).
# ---------------------------------------------------------------------------


# ValidatorErrorCategory: closed-vocabulary tag for ``_build_retry_prompt``.
# The retry-prompt builder NEVER receives the raw Pydantic / JSON validator
# error string — that string can carry prior LLM output (a T3-derived
# fragment) which is the exact injection vector ``_build_retry_prompt``
# exists to close. The caller maps the concrete exception to one of these
# labels; the prompt body is fixed at the type level. prov-002 / err-009.
ValidatorErrorCategory = Literal[
    "schema_mismatch",
    "json_parse_error",
    "missing_required_field",
    "unknown",
]

# Human-readable labels for each category. The mapping lives in this
# module rather than alongside ``t()`` because the prompt body is
# host-side static text, not a localised UI string — the model receives
# the same prompt regardless of the operator's chosen locale.
_RETRY_CATEGORY_LABELS: dict[str, str] = {
    "schema_mismatch": "the previous response did not match the schema",
    "json_parse_error": "the previous response was not valid JSON",
    "missing_required_field": ("the previous response was missing one or more required fields"),
    "unknown": "the previous response was invalid",
}


class QuarantinedExtractor:
    """Orchestrator-side client of the quarantined-LLM plugin (spec §6.4).

    This is the only path by which T3 content becomes orchestrator-
    readable structured data. Raw provider response bytes never cross
    back to this process — only :class:`ExtractionResult`.

    The extractor dispatches a JSON-RPC ``quarantine.extract`` call on
    the supplied :class:`PluginTransport`, validates the response is a
    :class:`ControlResult`, and lifts the payload into the typed
    :class:`Extracted` / :class:`TypedRefusal` shape. Every call emits
    a ``quarantine.extract`` audit row via :meth:`AuditWriter.append_schema`
    with :data:`QUARANTINE_EXTRACT_FIELDS`.

    A non-:class:`ControlResult` response or a payload with an
    unexpected ``kind`` value is a transport-layer protocol violation
    (spec §6.7 / prov-011), NOT a typed refusal — the extractor emits a
    ``quarantine.protocol_violation`` audit row and raises
    :class:`PluginProtocolViolation`. Protocol mismatch and LLM refusal
    are distinct events; collapsing them would let a misbehaving plugin
    silently disguise transport failures as orchestrator outcomes.

    Construction takes a :class:`PluginTransport` (the structural
    Protocol so production and test fakes share one seam) and an
    :class:`AuditWriter`. The capability gate is consulted by the
    caller (:func:`quarantined_to_structured`), not by the extractor —
    the extractor's job is the transport + audit-row contract; the
    gate's job is the higher-level T3-clearance check.
    """

    # Closed-vocabulary plugin id for the quarantined LLM. The audit
    # rows and protocol-violation exception use this string verbatim;
    # drift here breaks audit-graph join keys.
    _PLUGIN_ID: ClassVar[str] = "alfred.quarantined-llm"

    def __init__(
        self,
        *,
        transport: PluginTransport,
        audit_writer: AuditWriter,
    ) -> None:
        self._transport = transport
        self._audit_writer = audit_writer

    # ------------------------------------------------------------------
    # Schema-class validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_schema_class(schema: type) -> None:
        """Refuse a schema that isn't an :class:`ExtractionSchema` subclass.

        The type signature on :meth:`extract` says ``type[ExtractionSchema]``;
        ai-001 + retrospective #142's ABC enforces
        ``schema_version: ClassVar[Literal[1]] = 1`` at subclass-construction
        time so an :class:`~pydantic.BaseModel` lacking the version
        cannot satisfy the type. This runtime backstop catches callers
        that bypassed the type system (``# type: ignore``).
        """
        if not (isinstance(schema, type) and issubclass(schema, ExtractionSchema)):
            raise TypeError(
                f"schema must be a subclass of ExtractionSchema; got {schema!r}",
            )

    # ------------------------------------------------------------------
    # Retry-prompt builder — token-set invariant (prov-002 / err-009)
    # ------------------------------------------------------------------

    @staticmethod
    def _build_retry_prompt(
        *,
        validator_error_category: ValidatorErrorCategory,
        schema_json: str,
    ) -> str:
        """Build a retry prompt from closed-vocabulary inputs only.

        The retry prompt is composed of the schema JSON (host-supplied,
        safe to echo) and a human-readable label drawn from a closed set
        keyed by ``validator_error_category``. The closed-vocabulary
        argument is the structural defence against the prov-002 / err-009
        injection vector: a free-form ``validator_error`` string can
        carry prior LLM output (a T3-derived fragment); passing that
        text into the retry prompt would close the laundering loop.

        Per CLAUDE.md hard rule #7 — no silent failures in security
        paths — an out-of-vocabulary category raises ``ValueError``.
        ``Literal`` is a type-level gate; the runtime check is the
        defence-in-depth backstop that survives ``# type: ignore`` and
        ``python -O``.

        This method NEVER accepts a parameter that echoes prior LLM
        output (``prior_response``, ``last_response``, etc.). The
        absence of those parameters from the signature is the
        structural defence that ``inspect.signature``-based tests pin.
        """
        if validator_error_category not in get_args(ValidatorErrorCategory):
            raise ValueError(
                "validator_error_category must be one of "
                f"{sorted(get_args(ValidatorErrorCategory))}; "
                f"got {validator_error_category!r}",
            )
        label = _RETRY_CATEGORY_LABELS[validator_error_category]
        return (
            f"Previous extraction failed: {label}.\n\n"
            "Try again. Output valid JSON matching this schema:\n"
            f"{schema_json}"
        )

    # ------------------------------------------------------------------
    # extract — the single public surface
    # ------------------------------------------------------------------

    async def extract(
        self,
        handle: ContentHandle,
        schema: type[ExtractionSchema],
    ) -> ExtractionResult:
        """Dispatch a ``quarantine.extract`` JSON-RPC call.

        The call carries only the opaque handle id and the schema JSON;
        ``source_url`` never crosses the wire (it is forensic-attribution
        only, held orchestrator-side for the audit row).

        On a :class:`ControlResult` with a payload kind of ``extracted``
        or ``typed_refusal`` — lifts the payload into the typed
        :class:`Extracted` / :class:`TypedRefusal` shape and emits the
        ``quarantine.extract`` audit row.

        On any other response shape — including a non-:class:`ControlResult`
        or a payload with an unexpected ``kind`` value — emits a
        ``quarantine.protocol_violation`` audit row and raises
        :class:`PluginProtocolViolation`. The audit row lands BEFORE
        the raise so an operator reading the log sees the failure even
        if the caller swallows the exception.
        """
        import json as _json

        # Local imports — keep the boundary module dependency-light at
        # import time. Both names are only needed inside this coroutine.
        from alfred.audit import audit_row_schemas
        from alfred.plugins.errors import PluginProtocolViolation
        from alfred.plugins.transport import ControlResult

        self._validate_schema_class(schema)

        # Per-invocation correlation id — never shared across calls
        # (prov-012). Audit rows on the same conversation are tied
        # through the parent trace_id, not through this field.
        correlation_id = str(uuid.uuid4())
        schema_name = schema.__name__
        # schema_version is guaranteed = 1 by ExtractionSchema.__init_subclass__
        # so we can pin the value at the audit-row boundary without re-reading
        # from the schema class (defence in depth — a future Literal[1, 2]
        # widening will require the field to flow through here).
        schema_version: int = 1
        schema_json = _json.dumps(schema.model_json_schema())

        # Wire dispatch. The handle id is the only T3-attribution token
        # that crosses the boundary; ``source_url`` is intentionally
        # withheld (it's forensic data, not a wire input).
        result_raw = await self._transport.dispatch(
            "quarantine.extract",
            {
                "handle_id": handle.id,
                "schema_json": schema_json,
                "schema_version": schema_version,
            },
        )

        # Protocol-violation guard: non-ControlResult or wrong kind.
        if not isinstance(result_raw, ControlResult):
            await self._emit_protocol_violation_audit(
                correlation_id=correlation_id,
                schema_name=schema_name,
                schema_version=schema_version,
            )
            raise PluginProtocolViolation(
                method="quarantine.extract",
                plugin_id=self._PLUGIN_ID,
            )

        payload = result_raw.payload
        payload_kind = payload.get("kind")
        if payload_kind not in ("extracted", "typed_refusal"):
            await self._emit_protocol_violation_audit(
                correlation_id=correlation_id,
                schema_name=schema_name,
                schema_version=schema_version,
            )
            raise PluginProtocolViolation(
                method="quarantine.extract",
                plugin_id=self._PLUGIN_ID,
            )

        # Lift the payload into the typed shape.
        result: ExtractionResult
        audit_result: str
        audit_extraction_mode: str
        if payload_kind == "extracted":
            data_obj = payload.get("data") or {}
            extraction_mode_value = payload.get("extraction_mode")
            # Closed-set validator — anything outside the Literal is a
            # protocol violation. Defence-in-depth alongside Pydantic's
            # own ``extra="forbid"``. The cast below is safe because the
            # ``in get_args(...)`` check rejects any other value first;
            # mypy can't see through the ``in`` to narrow ``object`` to
            # the Literal, so we cast at the boundary.
            if extraction_mode_value not in get_args(ExtractionMode):
                await self._emit_protocol_violation_audit(
                    correlation_id=correlation_id,
                    schema_name=schema_name,
                    schema_version=schema_version,
                )
                raise PluginProtocolViolation(
                    method="quarantine.extract",
                    plugin_id=self._PLUGIN_ID,
                )
            extraction_mode_narrowed = cast("ExtractionMode", extraction_mode_value)
            result = Extracted(
                data=T3DerivedData(dict(data_obj) if isinstance(data_obj, dict) else {}),
                extraction_mode=extraction_mode_narrowed,
            )
            audit_result = "extracted"
            audit_extraction_mode = extraction_mode_narrowed
        else:
            reason_value = payload.get("reason")
            if reason_value not in get_args(TypedRefusalReason):
                await self._emit_protocol_violation_audit(
                    correlation_id=correlation_id,
                    schema_name=schema_name,
                    schema_version=schema_version,
                )
                raise PluginProtocolViolation(
                    method="quarantine.extract",
                    plugin_id=self._PLUGIN_ID,
                )
            reason_narrowed = cast("TypedRefusalReason", reason_value)
            result = TypedRefusal(reason=reason_narrowed)
            audit_result = "refused"
            # closed-vocabulary tag for the audit row — the spec keeps
            # extraction_mode and result orthogonal so audit graphs can
            # filter on either independently. ``refused`` is the
            # extraction_mode value for typed refusals.
            audit_extraction_mode = "refused"

        await self._audit_writer.append_schema(
            fields=audit_row_schemas.QUARANTINE_EXTRACT_FIELDS,
            schema_name="QUARANTINE_EXTRACT_FIELDS",
            event="quarantine.extract",
            actor_user_id=None,
            subject={
                "extraction_mode": audit_extraction_mode,
                "provider": "quarantined-llm",
                "schema_name": schema_name,
                "schema_version": schema_version,
                "retry_count": 0,
                "trust_tier_of_trigger": "T3",
                "result": audit_result,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T3",
            result=audit_result,
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )

        return result

    async def _emit_protocol_violation_audit(
        self,
        *,
        correlation_id: str,
        schema_name: str,
        schema_version: int,
    ) -> None:
        """Audit a ``quarantine.protocol_violation`` event.

        Emitted BEFORE the :class:`PluginProtocolViolation` raise so
        the operator log carries the failure even if the caller
        swallows the exception (CLAUDE.md hard rule #7).
        """
        from alfred.audit import audit_row_schemas

        await self._audit_writer.append_schema(
            fields=audit_row_schemas.QUARANTINE_EXTRACT_FIELDS,
            schema_name="QUARANTINE_EXTRACT_FIELDS",
            event="quarantine.protocol_violation",
            actor_user_id=None,
            subject={
                "extraction_mode": "none",
                "provider": "quarantined-llm",
                "schema_name": schema_name,
                "schema_version": schema_version,
                "retry_count": 0,
                "trust_tier_of_trigger": "T3",
                "result": "protocol_violation",
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T3",
            result="protocol_violation",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )


# ---------------------------------------------------------------------------
# quarantined_to_structured — STUB (full impl Task 7)
# ---------------------------------------------------------------------------


async def quarantined_to_structured(
    handle: ContentHandle,
    schema: type[ExtractionSchema],
    *,
    extractor: QuarantinedExtractor,
    gate: CapabilityGate,
) -> ExtractionResult:
    """Convert an opaque :class:`ContentHandle` into a typed result.

    THIS IS THE ONLY PATH by which T3-derived content reaches
    orchestrator-readable structured form. Any other path is a security
    violation (spec §3.4).

    STUB in Task 6 (PR-S3-4). Task 7 lands the full implementation
    (gate-first check + extractor delegate).
    """
    raise NotImplementedError(
        "quarantined_to_structured stub — full implementation is PR-S3-4 Task 7",
    )


# ---------------------------------------------------------------------------
# downgrade_to_orchestrator — STUB (full impl Task 8)
# ---------------------------------------------------------------------------


async def downgrade_to_orchestrator(
    data: T3DerivedData,
    *,
    audit_row: object,
) -> dict[str, object]:
    """Gate for injecting T3DerivedData into a privileged prompt.

    STUB in Task 6 (PR-S3-4). Task 8 lands the full implementation
    (gate-first check + T3_DERIVED_DOWNGRADE_FIELDS audit row).
    """
    raise NotImplementedError(
        "downgrade_to_orchestrator stub — full implementation is PR-S3-4 Task 8",
    )
