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

import structlog
from pydantic import BaseModel, ConfigDict, ValidationError

from alfred.errors import AlfredError
from alfred.hooks import (
    SYSTEM_ONLY_TIERS,
    SYSTEM_OPERATOR_TIERS,
    HookContext,
    HookError,
    HookRefusal,
    HookRegistry,
    get_registry,
    invoke,
)
from alfred.i18n import t
from alfred.security.tiers import T3

# CR-156 round-7 / CR-158 T5: ``invoke`` is bound at module scope so
# ``mock.patch("alfred.security.quarantine.invoke", ...)`` swaps the
# actually-used reference at the call site. Pre-fix the symbol was
# imported locally inside :meth:`QuarantinedExtractor.extract` and
# :meth:`QuarantinedExtractor._dispatch_error_chain`; the test that
# exercised the defensive ``raise`` branch patched
# ``alfred.hooks.invoke`` but the bound-at-call-time semantics of a
# local ``from alfred.hooks import invoke`` left the replacement
# brittle — the patch only worked because the local re-binding hit
# the already-patched module attribute, NOT because the test had a
# stable handle on the quarantine-side symbol. Hoisting the import
# pins the patch target as a real module attribute.

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.hooks.capability import CapabilityGate
    from alfred.plugins.transport import PluginTransport
    from alfred.policies.model import BurstLimiterPolicy
    from alfred.policies.snapshot_ref import PoliciesSnapshotRef
    from alfred.security.dlp import OutboundDlp

_log = structlog.get_logger(__name__)


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
#   * dlp_outbound_refused              — TOMBSTONE. Retained for
#     forensic-history continuity; no live emit site uses this token.
#     Post-stage refusals (including DLP) now record
#     ``post_stage_refused``; the refusing subscriber's identity is on
#     the row's ``refusing_hook_id`` field (see
#     :data:`alfred.audit.audit_row_schemas.QUARANTINE_EXTRACT_FIELDS`).
#   * post_stage_refused                — Any post-stage hook subscriber
#     refused the validated payload. Generic by design so future
#     post-stage subscribers (not just the DLP one) attribute through
#     the same closed-vocab token and surface their identity on
#     ``refusing_hook_id``.
#   * nonce_check_failed                — handle-id nonce mismatch (PR-S3-5)
TypedRefusalReason = Literal[
    "cannot_extract",
    "refused_by_safety",
    "ambiguous_input",
    "provider_refused",
    "provider_unavailable",
    "dlp_outbound_refused",
    "post_stage_refused",
    "nonce_check_failed",
]

# Closed dispatch-path Literal — matches the three branches in spec §6.2
# and the audit-row extraction_mode field. Any drift here breaks audit-row
# continuity, so the closed set is enforced at the type level.
ExtractionMode = Literal[
    "native_constrained",
    # RESERVED (not selected at runtime since #340 fork b): the dispatcher no
    # longer routes any provider through DeepSeek json-object mode. The member is
    # retained for audit-row continuity + a future response_format seam extension.
    "json_object_unconstrained",
    "prompt_embedded_fallback",
]

# The quarantined extractor retries a schema-validation failure this many times
# (total attempts = EXTRACTION_MAX_RETRIES + 1). Hoisted here (#340 PR2b-golive)
# so BOTH the child dispatcher (validation-retry loop) AND the privileged host
# (which brokers one gateway socket per possible provider.complete() call) share
# one source of truth. Configurable later via policies.yaml quarantine.extraction_max_retries.
EXTRACTION_MAX_RETRIES: int = 2

# The number of one-shot gateway sockets the host brokers up-front per extraction
# (spec §6): one per attempt, since a consumed passed fd cannot serve a 2nd dial.
BROKER_SOCKET_COUNT: int = EXTRACTION_MAX_RETRIES + 1


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


def _build_retry_prompt(
    *,
    validator_error_category: ValidatorErrorCategory,
    schema_json: str,
) -> str:
    """Module-level retry-prompt builder shared with the quarantine plugin.

    Identical body to :meth:`QuarantinedExtractor._build_retry_prompt`;
    the module-level binding lets the plugin-side dispatcher import the
    closed-vocab builder without depending on the orchestrator-side
    extractor class (sec-001 / rvw-1 / AI-5 consolidation).

    The two sides of the trust boundary use the SAME prompt body — a
    drift between them would let a misbehaving plugin observe different
    retry text than the orchestrator's tests pin, breaking the
    inspect.signature contract that prov-002 relies on.

    See :meth:`QuarantinedExtractor._build_retry_prompt` for the
    closed-vocabulary rationale (no ``prior_response`` parameter,
    type-level + runtime gate, etc).
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
        outbound_dlp: OutboundDlp,
        policies_ref: PoliciesSnapshotRef | None = None,
    ) -> None:
        """Construct the orchestrator-side extractor.

        Args:
            transport: The plugin transport that dispatches the
                ``quarantine.extract`` JSON-RPC call. Keyword-only.
            audit_writer: The audit-row sink for the
                ``quarantine.extract`` /
                ``quarantine.protocol_violation`` /
                ``quarantine.transport_failed`` event family.
                Keyword-only.
            outbound_dlp: The DLP scanner the post-stage subscriber
                will run on :meth:`pydantic.BaseModel.model_dump`
                output. Keyword-only; REQUIRED. Spec §6.5 line 476
                names this as the canonical exfil defence on the
                quarantined-extract chain; a default would codify a
                bypass path in the signature (CR-138 R3 lesson).

                Registration of the
                :class:`OutboundDlpExtractSubscriber` happens here
                via :func:`register_extract_dlp_subscriber` (idempotent
                — multiple extractor instances in one process do not
                double-register). Subscriber lifecycle is anchored to
                extractor lifecycle: the first
                :class:`QuarantinedExtractor` constructed wires the
                scan; subsequent instances are no-ops; an extractor-
                less process (a tooling subprocess that never builds
                one) has no DLP scan registered, which is correct
                because no extract dispatches either.
        """
        self._transport = transport
        self._audit_writer = audit_writer
        self._outbound_dlp = outbound_dlp
        # PR-S4-4: the active policy snapshot ref. The LOW-BLAST per-(user,
        # persona) burst-limiter policy (``rate_limits.
        # quarantined_extract_per_user_persona``) is hot-reloadable; the
        # HIGH-BLAST ``quarantined_provider_url`` refuses hot-reload at the
        # watcher layer (closure arch-003). Additive + optional so Slice-3
        # construction keeps working until PR-S4-1 wires the real ref.
        self._policies_ref = policies_ref
        # Anchor the subscriber's lifecycle to extractor lifecycle.
        # Helper is idempotent against the active registry, so multiple
        # extractors per process land ONE post-subscriber on the
        # security.quarantined.extract chain. Imported locally to
        # avoid pulling the subscriber module into the quarantine
        # module's import-time dependency closure (the subscriber
        # itself imports from alfred.hooks which is fine at module-init
        # time but keeps the import graph one-directional).
        #
        # CR-156 round-7 / CR-158 T1: helper now raises
        # :class:`HookError` on the gate-deny / unavailable path —
        # we deliberately do NOT catch. A half-wired extractor (no
        # post-stage DLP scan) is an active trust-boundary violation
        # (PRD §7.1, CLAUDE.md hard rule #7). The raise propagates
        # out of ``__init__`` so a denied registration prevents the
        # extractor from existing at all. The same-instance
        # idempotency arm returns
        # :attr:`RegistrationOutcome.ALREADY_REGISTERED` — a benign
        # success outcome that ties into a sibling extractor's
        # already-active scan. The return value is intentionally
        # ignored here: both success outcomes satisfy the contract
        # "DLP scan is active after construction".
        from alfred.security._extract_dlp_subscriber import register_extract_dlp_subscriber

        register_extract_dlp_subscriber(outbound_dlp=outbound_dlp)

    def burst_limiter_policy(self) -> BurstLimiterPolicy | None:
        """Return the active per-(user, persona) burst-limiter policy.

        Per-call deref (core-003): reads ``ref.current()`` every invocation so
        a watcher swap to the LOW-BLAST
        ``rate_limits.quarantined_extract_per_user_persona`` block takes effect
        on the next extract without restarting the extractor. The HIGH-BLAST
        ``quarantined_provider_url`` is NOT read here — it refuses hot-reload at
        the watcher layer. Returns ``None`` when no snapshot ref is wired
        (legacy Slice-3 construction).
        """
        if self._policies_ref is None:
            return None
        return (
            self._policies_ref.current().policies.rate_limits.quarantined_extract_per_user_persona
        )

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
        return _build_retry_prompt(
            validator_error_category=validator_error_category,
            schema_json=schema_json,
        )

    # ------------------------------------------------------------------
    # extract — the single public surface
    # ------------------------------------------------------------------

    @dataclass(frozen=True, slots=True)
    class _BodyAuditMetadata:
        """Carries the audit-row attribution :meth:`_extract_body`
        would have emitted itself, returned to :meth:`extract` so the
        ``quarantine.extract`` row emits AFTER the post-stage DLP
        chain — never BEFORE (CR-158 BLOCKER #2).

        Pre-fix the row emitted at the bottom of :meth:`_extract_body`
        with ``result="extracted"`` even when the post-stage DLP
        subscriber subsequently refused the payload. That left a
        misleading "successful extraction" forensic record for an
        outcome the orchestrator never observed — the audit log was
        actively lying about the trust boundary's behaviour. Deferring
        the emission to :meth:`extract` lets the post-chain outcome
        decide which ``result`` value the row carries:

        * Post chain succeeds → ``result=audit_result`` (``"extracted"``
          or ``"refused"`` per the body's classification).
        * Post chain raises :class:`alfred.hooks.HookRefusal` →
          ``result="post_stage_refused"``,
          ``extraction_mode="refused"``, ``refusing_hook_id`` set to
          the subscriber's ``hook_id``. The validated payload NEVER
          returns to the caller; the audit row reflects that. (See the
          handler in :meth:`extract` for the §6.5 pre-only rationale.)

        Frozen + slots: same hot-path discipline as :class:`Extracted`.
        Carrier-only, no behaviour.
        """

        audit_result: str
        audit_extraction_mode: str
        correlation_id: str
        schema_name: str
        schema_version: int

    async def extract(
        self,
        handle: ContentHandle,
        schema: type[ExtractionSchema],
    ) -> ExtractionResult:
        """Dispatch a ``quarantine.extract`` JSON-RPC call through the
        ``security.quarantined.extract`` hookpoint chain (spec §6.5).

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

        **Hookpoint dispatch (#158).** The body is wrapped in the
        ``security.quarantined.extract`` chain:

        * ``pre`` stage — system + operator tier subscribers observe
          the dispatch-side context (schema name + handle id; never
          the wire payload, which is T3-derived). System-tier
          subscribers may refuse via :class:`HookRefusal`.
        * ``post`` stage — the :class:`OutboundDlpExtractSubscriber`
          (registered by :meth:`__init__`) runs
          :meth:`OutboundDlp.scan` on the validated
          :meth:`pydantic.BaseModel.model_dump` of the result. A
          DLP trigger raises :class:`HookRefusal`; the validated
          payload NEVER returns to the caller.
        * ``error`` stage — runs if any exception escapes the body or
          either chain. Subscribers may suppress (first non-None
          carrier wins). If every subscriber returns ``None`` the
          original exception re-raises so the upstream failure is
          NOT silently swallowed (CLAUDE.md hard rule #7).

        Dispatch is ADDITIVE to the existing audit-row family —
        ``quarantine.extract`` / ``quarantine.protocol_violation`` /
        ``quarantine.transport_failed`` continue to emit verbatim.
        """
        # Schema-class validation is hoisted out of :meth:`_extract_body`
        # to fail BEFORE the pre-chain dispatches — a programmer-bug
        # schema class is a build-time issue, not a runtime
        # failure-mode the error chain should observe. Pre/post/error
        # subscribers see only runtime extraction failures; a TypeError
        # raised against a bad ``schema`` type IS the right exception
        # for the call site to surface (it surfaces a missing
        # :class:`ExtractionSchema` subclass annotation), not a hook
        # outcome (LOW #11 — CR-158).
        self._validate_schema_class(schema)

        # Mint the chain's correlation id ONCE here so every audit
        # row (existing ``quarantine.*`` family emitted by the body
        # helpers + the new pre/post/error hookpoint chain rows
        # emitted by :func:`alfred.hooks.invoke.invoke`) ties to the
        # same key. CR-158 round 4: ``trace_id`` on the
        # ``quarantine.*`` rows IS this value; the body's per-
        # invocation ``correlation_id`` lives inside the row's subject
        # payload for finer-grained correlation within the extract
        # body. Forensic queries joining on ``trace_id`` see a single
        # coherent trace across the chain; ``subject.correlation_id``
        # further narrows to a specific body call.
        chain_correlation_id = uuid.uuid4().hex
        schema_name = schema.__name__

        # Build the pre-stage carrier. Carries closed-vocabulary
        # attribution ONLY — ``schema_name`` + the opaque ``handle.id``.
        # We DO NOT thread the wire payload or the model_dump through
        # the pre stage; those are T3-derived and must not surface on
        # a pre subscriber's audit attribution. The post stage carries
        # the model_dump (DLP needs to scan it); pre carries the
        # dispatch metadata only.
        pre_input: dict[str, object] = {
            "schema_name": schema_name,
            "handle_id": handle.id,
        }
        pre_ctx: HookContext[dict[str, object]] = HookContext(
            action_id="security.quarantined.extract",
            hookpoint="security.quarantined.extract",
            input=pre_input,
            correlation_id=chain_correlation_id,
            kind="pre",
        )

        # Pre chain — fail_closed=True per spec §6.5 declaration.
        # A system-tier subscriber may refuse via HookRefusal; the
        # invoke() dispatcher emits HOOKS_REFUSAL and re-raises so
        # the body never runs.
        try:
            await invoke(
                "security.quarantined.extract",
                pre_ctx,
                kind="pre",
                subscribable_tiers=SYSTEM_OPERATOR_TIERS,
                refusable_tiers=SYSTEM_ONLY_TIERS,
                fail_closed=True,
            )
        except Exception as pre_exc:
            # Error stage — let subscribers observe a pre-stage
            # failure. Re-raise on no-suppression so the original
            # cause propagates with the original traceback.
            await self._dispatch_error_chain(
                exc=pre_exc,
                pre_input=pre_input,
                chain_correlation_id=chain_correlation_id,
            )
            raise

        # Body — the existing extract flow. Returns the validated
        # result AND the audit-row metadata; the ``quarantine.extract``
        # row is DEFERRED to the post-chain outcome (BLOCKER #2 fix).
        # The upstream transport_failed / protocol_violation rows
        # still emit inline from inside :meth:`_extract_body` before
        # the corresponding exception raises — those are distinct
        # closed-vocabulary events and continue to land at the same
        # forensic point they always have.
        try:
            result, body_audit = await self._extract_body(
                handle,
                schema,
                chain_correlation_id=chain_correlation_id,
            )
        except Exception as body_exc:
            await self._dispatch_error_chain(
                exc=body_exc,
                pre_input=pre_input,
                chain_correlation_id=chain_correlation_id,
            )
            raise

        # Post chain — the DLP subscriber's load-bearing scan.
        # ``input`` is the result.model_dump (a dict) for an
        # Extracted; for a TypedRefusal it's still a model_dump so
        # the closed-vocabulary ``reason`` field surfaces. The
        # subscriber's json.dumps(default=str) handles both shapes.
        post_input = result.model_dump()
        post_ctx: HookContext[dict[str, object]] = HookContext(
            action_id="security.quarantined.extract",
            hookpoint="security.quarantined.extract",
            input=post_input,
            correlation_id=chain_correlation_id,
            kind="post",
        )
        try:
            await invoke(
                "security.quarantined.extract",
                post_ctx,
                kind="post",
                subscribable_tiers=SYSTEM_OPERATOR_TIERS,
                refusable_tiers=SYSTEM_ONLY_TIERS,
                fail_closed=True,
            )
        except HookRefusal as refusal:
            # The DLP subscriber (or another post-stage refuser) blocked
            # the validated payload. BLOCKER #2 fix: the audit row
            # MUST reflect the refusal, NOT the pre-refusal
            # ``result="extracted"`` classification the body chose.
            #
            # Use the generic ``post_stage_refused`` token + carry
            # refusing-subscriber identity in ``refusing_hook_id``. The
            # hooks subsystem's ``_run_post`` does NOT emit
            # ``HOOKS_REFUSAL`` for post-stage refusals (§6.5 is
            # pre-only — see ``alfred.hooks.invoke`` docstrings at
            # lines 519-521 + 282-286), so this row is the only
            # forensic surface for the refusing subscriber's identity.
            # Any future post-stage subscriber's refusal will land here
            # with its own ``hook_id`` without code change.
            #
            # ``extraction_mode="refused"`` matches the
            # :class:`TypedRefusal` audit shape so the audit graph
            # treats the canary-blocked outcome the same as a
            # typed-refusal outcome (both are refusals; the
            # ``correlation_id`` ties this row back to the post-chain
            # subscriber-error / chain-timeout audit rows
            # :func:`invoke` emits on the non-refusal post-stage arm).
            await self._emit_extract_audit(
                audit_result="post_stage_refused",
                audit_extraction_mode="refused",
                correlation_id=body_audit.correlation_id,
                schema_name=body_audit.schema_name,
                schema_version=body_audit.schema_version,
                chain_correlation_id=chain_correlation_id,
                refusing_hook_id=refusal.hook_id,
            )
            await self._dispatch_error_chain(
                exc=refusal,
                pre_input=pre_input,
                chain_correlation_id=chain_correlation_id,
            )
            raise
        except Exception as post_exc:
            # Non-refusal post-chain failure (a subscriber crashed,
            # the dispatcher tripped a fail_closed). The audit row
            # for the extract outcome is INTENTIONALLY NOT emitted
            # here — the upstream :data:`HOOKS_SUBSCRIBER_ERROR` /
            # :data:`HOOKS_CHAIN_TIMEOUT` row :func:`invoke` already
            # emitted is the forensic anchor; a second
            # ``quarantine.extract`` row would imply the extract
            # completed cleanly, which it didn't. The error chain
            # still dispatches and the exception re-raises.
            await self._dispatch_error_chain(
                exc=post_exc,
                pre_input=pre_input,
                chain_correlation_id=chain_correlation_id,
            )
            raise

        # Post chain succeeded — emit the audit row with the body's
        # classification (``"extracted"`` or ``"refused"``). The row
        # lands HERE so a DLP refusal that aborts the post chain
        # never produces a misleading ``result="extracted"`` audit
        # row (BLOCKER #2 — the audit log is the source of truth and
        # lying in it is worse than redundancy).
        await self._emit_extract_audit(
            audit_result=body_audit.audit_result,
            audit_extraction_mode=body_audit.audit_extraction_mode,
            correlation_id=body_audit.correlation_id,
            schema_name=body_audit.schema_name,
            schema_version=body_audit.schema_version,
            chain_correlation_id=chain_correlation_id,
        )

        return result

    async def _dispatch_error_chain(
        self,
        *,
        exc: BaseException,
        pre_input: dict[str, object],
        chain_correlation_id: str,
    ) -> None:
        """Run the ``security.quarantined.extract`` error chain.

        Called from :meth:`extract` on any exception escaping the
        pre / body / post stages. The error stage dispatch lets
        subscribers observe the failure (e.g. flush a span, emit
        a metric, write a forensic note); subscriber suppression IS
        allowed but the caller's ``raise`` short-circuits the
        suppression for now — Slice-4+ would honour
        :func:`invoke`'s "first non-None wins" carrier-substitution
        semantic. This slice ships the audit-and-raise discipline.
        See #170 for the Slice-4+ recoverable-carrier work.

        The dispatch itself never raises against the caller's
        traceback path — the error chain runs to completion and any
        :class:`alfred.hooks.HookError` raised by a subscriber is
        suppressed so the ORIGINAL ``exc`` is the value that
        propagates. CLAUDE.md hard rule #7 still applies: the
        subscriber's failure is audited by :func:`invoke` itself
        (the :data:`HOOKS_SUBSCRIBER_ERROR` row); we just don't let
        it displace the upstream failure on the caller's traceback.
        """
        error_ctx: HookContext[dict[str, object]] = HookContext(
            action_id="security.quarantined.extract",
            hookpoint="security.quarantined.extract",
            input=pre_input,
            correlation_id=chain_correlation_id,
            kind="error",
        )
        try:
            await invoke(
                "security.quarantined.extract",
                error_ctx,
                kind="error",
                subscribable_tiers=SYSTEM_OPERATOR_TIERS,
                # Spec §6.5 + §14 (post-alignment) both pin True;
                # per-kind fail_closed would require a registry
                # refactor — out of scope (MEDIUM #7 — CR-158; see
                # #167 for the per-kind feature request). The
                # value MUST equal the publisher's declared
                # ``fail_closed`` (see
                # :func:`alfred.hooks.invoke._enforce_subscribable_tiers`'s
                # dispatch-time drift check); weakening here would
                # trip the drift detector with HOOKS_TIER_REJECTED
                # audit and a HookError raise. The helper catches
                # the HookError below so the original ``exc`` is
                # preserved on the caller's traceback.
                fail_closed=True,
                exc=exc,
            )
        except HookError:
            # A subscriber crashed inside the error chain (the
            # dispatcher wrapped a non-:class:`HookError` raise as a
            # :class:`HookSubscriberError` via
            # :func:`alfred.hooks.invoke._wrap_subscriber_error`). The
            # dispatcher already emitted the
            # :data:`HOOKS_SUBSCRIBER_ERROR` row; swallow so the
            # ORIGINAL ``exc`` is what surfaces on the caller's
            # traceback. Re-raising here would displace the upstream
            # failure with a meta-failure.
            return
        except Exception as raised:
            # HIGH #3 (CR-158): narrow the catch from ``BaseException``
            # to ``Exception`` so :class:`asyncio.CancelledError`,
            # :class:`SystemExit`, and :class:`KeyboardInterrupt`
            # propagate. Cancellation MUST be honoured at every
            # async boundary; swallowing it here would let a chain
            # in the error stage outlive its caller and silently
            # leak a never-completing task.
            #
            # The remaining ``Exception`` arm covers
            # :func:`alfred.hooks.invoke.invoke`'s "no-suppression-
            # completed" path that re-raises ``exc`` itself. We
            # check identity: if the re-raise is the same object
            # we passed in via ``exc=``, swallow so the caller's
            # outer ``raise exc`` is the visible propagation site.
            # If it's a NEW exception we have no business absorbing
            # it — re-raise so the new failure is the value the
            # caller sees (the caller's ``raise`` of the original
            # ``exc`` will then chain via ``__context__``).
            if raised is not exc:
                raise
            return

    async def _extract_body(
        self,
        handle: ContentHandle,
        schema: type[ExtractionSchema],
        *,
        chain_correlation_id: str,
    ) -> tuple[ExtractionResult, QuarantinedExtractor._BodyAuditMetadata]:
        """The existing extract logic — wire dispatch + schema lift.

        Returns the validated :class:`ExtractionResult` AND the audit-
        row metadata :meth:`extract` will emit AFTER the post-stage
        DLP chain (BLOCKER #2 fix). The body does NOT emit the
        ``quarantine.extract`` row itself anymore — that emission is
        deferred so a post-chain refusal can override the
        classification before the row lands.

        The other audit rows the body owns —
        ``quarantine.protocol_violation`` and
        ``quarantine.transport_failed`` — DO emit inline before the
        corresponding exception raises; those are distinct
        closed-vocabulary events at distinct forensic anchors and
        their semantics are unaffected by the post-chain outcome.

        Factored out of :meth:`extract` so the hookpoint chain wraps a
        clean boundary. Body-side ``correlation_id`` is a per-invocation
        UUID minted inline; the chain's ``chain_correlation_id`` is the
        shared trace key (CR-158 round 4) that ties the
        ``quarantine.*`` rows the body emits to the pre/post/error
        hook-dispatch rows :meth:`extract` drives. Both are populated
        on every audit row this body writes — body-local
        ``correlation_id`` inside ``subject``, chain id on ``trace_id``
        — so forensic queries can either walk a single coherent trace
        (join on ``trace_id``) or narrow to a specific body call (filter
        on ``subject.correlation_id``).
        """
        import json as _json

        # Local imports — keep the boundary module dependency-light at
        # import time. Both names are only needed inside this coroutine.
        from alfred.plugins.errors import PluginProtocolViolation
        from alfred.plugins.transport import ControlResult

        # Per-invocation correlation id — never shared across calls
        # (prov-012). CR-158 round 4: this value lives inside the
        # ``subject`` payload of every audit row emitted from this
        # body; the row's TOP-LEVEL ``trace_id`` is
        # ``chain_correlation_id`` (the shared key minted by
        # :meth:`extract` at chain entry) so a forensic join across
        # the pre/post/error hook-dispatch rows + the
        # ``quarantine.*`` family rows lands a single coherent
        # trace. Filtering on ``subject.correlation_id`` narrows
        # further to a single body invocation.
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
        #
        # err-001 fix: wrap the transport await so a crash here lands
        # an audit row before propagating. The prior code had no
        # try/except — a supervisor-side transport failure (broken
        # pipe, framing error, premature subprocess death) would
        # silently leave the call without any audit attribution. The
        # ``transport_failed`` result tag is a closed-vocabulary value
        # distinct from ``protocol_violation`` so audit consumers can
        # tell transport-layer crashes apart from in-band protocol
        # violations.
        try:
            result_raw = await self._transport.dispatch(
                "quarantine.extract",
                {
                    "handle_id": handle.id,
                    "schema_json": schema_json,
                    "schema_version": schema_version,
                },
            )
        except Exception:
            await self._emit_transport_failed_audit(
                correlation_id=correlation_id,
                schema_name=schema_name,
                schema_version=schema_version,
                chain_correlation_id=chain_correlation_id,
            )
            raise

        # Protocol-violation guard: non-ControlResult or wrong kind.
        if not isinstance(result_raw, ControlResult):
            await self._emit_protocol_violation_audit(
                correlation_id=correlation_id,
                schema_name=schema_name,
                schema_version=schema_version,
                chain_correlation_id=chain_correlation_id,
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
                chain_correlation_id=chain_correlation_id,
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
            # Strict ``data`` shape (PRD §7.1 boundary contract): missing
            # or non-dict ``data`` is a protocol violation, NOT a permissively
            # defaulted empty dict. Coercing to ``{}`` here would let a
            # misbehaving plugin synthesise a valid Extracted outcome for
            # any schema whose required fields all carry defaults, weakening
            # the wire-format contract the dual-LLM split relies on.
            data_field = payload.get("data")
            if not isinstance(data_field, dict):
                await self._emit_protocol_violation_audit(
                    correlation_id=correlation_id,
                    schema_name=schema_name,
                    schema_version=schema_version,
                    chain_correlation_id=chain_correlation_id,
                )
                raise PluginProtocolViolation(
                    method="quarantine.extract",
                    plugin_id=self._PLUGIN_ID,
                )
            data_obj = data_field
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
                    chain_correlation_id=chain_correlation_id,
                )
                raise PluginProtocolViolation(
                    method="quarantine.extract",
                    plugin_id=self._PLUGIN_ID,
                )
            extraction_mode_narrowed = cast("ExtractionMode", extraction_mode_value)
            # Orchestrator-side schema validation (arch-1 / AI-1). The
            # plugin-side ``_validate_response`` only checks the response is
            # a dict — full Pydantic validation against the caller-supplied
            # schema class lives here, on the privileged side, where the
            # type system can pin :class:`type[ExtractionSchema]`. Without
            # this call a misbehaving quarantined LLM could return arbitrary
            # dicts that bypass the schema, get audit-rowed as
            # ``result=extracted``, and flow into the privileged
            # orchestrator (PRD §7.1 / spec §6.4 invariant).
            #
            # ``ValidationError`` is routed through the protocol-violation
            # audit path — the wire-format contract is "plugin emits
            # schema-valid data"; a violation of that contract is a
            # transport-layer event, not a legitimate refusal outcome
            # (collapsing them would let a misbehaving plugin disguise
            # schema-mismatches as ``result=refused`` audit rows).
            # ``data_obj`` is already validated as a dict above — the
            # ``isinstance`` short-circuit-to-{} fallback was removed because
            # it masked protocol violations as permissively-defaulted dicts.
            data_dict = dict(data_obj)
            try:
                schema.model_validate(data_dict)
            except ValidationError:
                await self._emit_protocol_violation_audit(
                    correlation_id=correlation_id,
                    schema_name=schema_name,
                    schema_version=schema_version,
                    chain_correlation_id=chain_correlation_id,
                )
                raise PluginProtocolViolation(
                    method="quarantine.extract",
                    plugin_id=self._PLUGIN_ID,
                ) from None
            result = Extracted(
                data=T3DerivedData(data_dict),
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
                    chain_correlation_id=chain_correlation_id,
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

        # Return the audit metadata for :meth:`extract` to emit AFTER
        # the post-stage DLP chain. The body intentionally does NOT
        # emit the ``quarantine.extract`` row here — see method
        # docstring for the BLOCKER #2 rationale.
        return result, QuarantinedExtractor._BodyAuditMetadata(
            audit_result=audit_result,
            audit_extraction_mode=audit_extraction_mode,
            correlation_id=correlation_id,
            schema_name=schema_name,
            schema_version=schema_version,
        )

    async def _emit_extract_audit(
        self,
        *,
        audit_result: str,
        audit_extraction_mode: str,
        correlation_id: str,
        schema_name: str,
        schema_version: int,
        chain_correlation_id: str | None,
        refusing_hook_id: str | None = None,
    ) -> None:
        """Emit the ``quarantine.extract`` audit row.

        Factored out of :meth:`_extract_body` so :meth:`extract` can
        choose the ``audit_result`` value AFTER the post-stage DLP
        chain returns (BLOCKER #2 fix). Two call sites:

        * Post chain succeeded — :meth:`extract` calls with the
          body's classification (``"extracted"`` or ``"refused"``);
          ``refusing_hook_id=None``.
        * Post chain raised :class:`alfred.hooks.HookRefusal` —
          :meth:`extract` calls with
          ``audit_result="post_stage_refused"``,
          ``audit_extraction_mode="refused"``, and
          ``refusing_hook_id=refusal.hook_id``. The refusing
          subscriber's identity surfaces ON this row because
          ``alfred.hooks.invoke._run_post`` does NOT emit
          ``HOOKS_REFUSAL`` for post-stage refusals — §6.5 is
          pre-only — so this row is the only forensic surface for
          attribution.

        The schema-validated fields the body computed
        (``schema_name``, ``schema_version``, ``correlation_id``)
        thread through verbatim so the audit-graph join key is the
        same regardless of which arm fires. Symmetric validation in
        :meth:`alfred.audit.AuditWriter.append_schema` forces every
        emit site to populate ``refusing_hook_id`` (None on the
        success arm) — the default exists for ergonomic call sites,
        not for forensic ambiguity.

        ``trace_id`` is the chain's shared key (``chain_correlation_id``
        minted at :meth:`extract`'s :func:`invoking`-equivalent entry)
        so the pre/post/error hook-dispatch rows and this row land in
        the same trace bucket — forensic queries joining on ``trace_id``
        see a single coherent trace (CR-158 round 4). The body-local
        ``correlation_id`` lives inside the ``subject`` payload for
        finer-grained correlation within the extract body. If
        ``chain_correlation_id`` is ``None`` (emit site outside the
        chain's scope — defence-in-depth fallback; the live code path
        always threads the chain id in), the helper falls back to the
        body-local ``correlation_id`` so a pre-chain row still carries
        SOME deterministic trace key rather than an empty field.
        """
        from alfred.audit import audit_row_schemas

        # Defence-in-depth fallback: every call site in this module
        # threads ``chain_correlation_id`` from :meth:`extract`, but
        # the ``| None`` keeps a future emit site that fires before
        # the chain mints its id (e.g. a constructor-time validation
        # path) auditable without a code change.
        effective_trace_id = (
            chain_correlation_id if chain_correlation_id is not None else correlation_id
        )

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
                "refusing_hook_id": refusing_hook_id,
            },
            trust_tier_of_trigger="T3",
            result=audit_result,
            cost_estimate_usd=0.0,
            trace_id=effective_trace_id,
        )

    async def _emit_transport_failed_audit(
        self,
        *,
        correlation_id: str,
        schema_name: str,
        schema_version: int,
        chain_correlation_id: str | None,
    ) -> None:
        """Audit a ``quarantine.transport_failed`` event (err-001 fix).

        Emitted BEFORE the transport exception re-raises so the operator
        log carries the failure even if the caller swallows it. The
        ``transport_failed`` result tag is closed-vocabulary and
        distinct from ``protocol_violation`` — a broken pipe / framing
        error / premature subprocess death is a transport-layer crash,
        not an in-band protocol violation.

        ``trace_id`` is the chain's shared key (CR-158 round 4); see
        :meth:`_emit_extract_audit` docstring for the model. Body-local
        ``correlation_id`` lives in the subject payload; falls back to
        body-local when ``chain_correlation_id`` is ``None``.

        We deliberately do NOT serialise the exception type or message
        into the audit row: the exception may carry handle-id or
        provider-key references through ``__cause__`` chains, and the
        closed-vocabulary ``result`` tag is the structural defence
        against that leakage.
        """
        from alfred.audit import audit_row_schemas

        effective_trace_id = (
            chain_correlation_id if chain_correlation_id is not None else correlation_id
        )

        await self._audit_writer.append_schema(
            fields=audit_row_schemas.QUARANTINE_EXTRACT_FIELDS,
            schema_name="QUARANTINE_EXTRACT_FIELDS",
            event="quarantine.transport_failed",
            actor_user_id=None,
            subject={
                "extraction_mode": "none",
                "provider": "quarantined-llm",
                "schema_name": schema_name,
                "schema_version": schema_version,
                "retry_count": 0,
                "trust_tier_of_trigger": "T3",
                "result": "transport_failed",
                "correlation_id": correlation_id,
                # Transport failures are not hookpoint refusals; the
                # attribution field stays explicitly ``None`` so the
                # symmetric-validation contract on
                # :data:`QUARANTINE_EXTRACT_FIELDS` is satisfied
                # without conflating transport crashes with post-stage
                # subscriber refusals.
                "refusing_hook_id": None,
            },
            trust_tier_of_trigger="T3",
            result="transport_failed",
            cost_estimate_usd=0.0,
            trace_id=effective_trace_id,
        )

    async def _emit_protocol_violation_audit(
        self,
        *,
        correlation_id: str,
        schema_name: str,
        schema_version: int,
        chain_correlation_id: str | None,
    ) -> None:
        """Audit a ``quarantine.protocol_violation`` event.

        Emitted BEFORE the :class:`PluginProtocolViolation` raise so
        the operator log carries the failure even if the caller
        swallows the exception (CLAUDE.md hard rule #7).

        ``trace_id`` is the chain's shared key (CR-158 round 4); see
        :meth:`_emit_extract_audit` docstring for the model. Body-local
        ``correlation_id`` lives in the subject payload; falls back to
        body-local when ``chain_correlation_id`` is ``None``.
        """
        from alfred.audit import audit_row_schemas

        effective_trace_id = (
            chain_correlation_id if chain_correlation_id is not None else correlation_id
        )

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
                # Protocol violations are not hookpoint refusals; the
                # attribution field stays explicitly ``None`` so the
                # symmetric-validation contract on
                # :data:`QUARANTINE_EXTRACT_FIELDS` is satisfied.
                "refusing_hook_id": None,
            },
            trust_tier_of_trigger="T3",
            result="protocol_violation",
            cost_estimate_usd=0.0,
            trace_id=effective_trace_id,
        )


# ---------------------------------------------------------------------------
# quarantined_to_structured — full impl (PR-S3-4 Task 7)
# ---------------------------------------------------------------------------


async def quarantined_to_structured(
    handle: ContentHandle,
    schema: type[ExtractionSchema],
    *,
    extractor: QuarantinedExtractor,
    gate: CapabilityGate,
) -> ExtractionResult:
    """Convert an opaque :class:`ContentHandle` into a typed
    :class:`ExtractionResult`.

    THIS IS THE ONLY PATH by which T3-derived content reaches
    orchestrator-readable structured form. Any other path is a security
    violation (spec §3.4).

    Gate-first ordering:
    ``gate.check_content_clearance(plugin_id="alfred.quarantined-llm",
    hookpoint="quarantine.dereference", content_tier="T3")`` is consulted
    BEFORE the extractor runs. A denial raises :class:`AlfredError`
    without invoking the extractor — the gate's refusal accounting is the
    audit-row escape for denied calls; this function's audit emission
    (via the extractor) is reserved for granted calls. ``plugin_id`` is
    pinned to :attr:`QuarantinedExtractor._PLUGIN_ID` so the audit-graph
    join key matches the extractor's own audit rows; see CR-156 round 1
    finding #3 (boundary doc alignment) and ``docs/subsystems/quarantine.md``.

    ``gate`` is REQUIRED — no default, no ``| None`` (CR-138 R3): a
    trust-boundary function whose gate can be elided through a default
    arg is a function with a bypass path codified in its signature.

    Returns the extractor's :class:`ExtractionResult` unchanged. A
    :class:`TypedRefusal` is NOT translated to an exception — refusal
    is a legitimate orchestrator outcome the caller branches on.
    """
    if not gate.check_content_clearance(
        plugin_id=QuarantinedExtractor._PLUGIN_ID,
        hookpoint="quarantine.dereference",
        content_tier="T3",
    ):
        raise AlfredError(t("security.quarantine.dereference_denied"))
    return await extractor.extract(handle, schema)


# ---------------------------------------------------------------------------
# downgrade_to_orchestrator — full impl (PR-S3-4 Task 8)
# ---------------------------------------------------------------------------


class DowngradeDeniedError(AlfredError):
    """The capability gate denied a T3-derived→orchestrator downgrade.

    Raised by :func:`downgrade_to_orchestrator` when
    ``gate.check_content_clearance(..., hookpoint="t3.downgrade_to_orchestrator",
    content_tier="T3")`` returns ``False`` (#338 PR2 review FOLD-R16). A
    dedicated subclass — rather than a bare :class:`AlfredError` — lets
    callers (notably
    :meth:`alfred.comms_mcp.real_turn_adapter.RealTurnOrchestratorAdapter.ingest`)
    narrow their ``except`` to THIS specific denial. A broad
    ``except AlfredError`` would also silently swallow any OTHER
    :class:`AlfredError` raised later in the same call chain (e.g. a
    transient provider/audit failure), committing the turn with no reply
    instead of propagating the unexpected failure loudly.
    """


# Closed-vocabulary downgrade-reason tags. The audit row carries this
# string verbatim; free-form text here would let a caller leak T3
# fragments into the audit log (spec §5.6). Adding a tag is a deliberate
# audit-schema migration, not a per-call decision.
_DOWNGRADE_REASON_DEFAULT: Literal["structured_extraction_consumed"] = (
    "structured_extraction_consumed"
)


async def downgrade_to_orchestrator(
    data: T3DerivedData,
    *,
    gate: CapabilityGate,
    audit_writer: AuditWriter,
) -> dict[str, object]:
    """Gate-checked downgrade of :class:`T3DerivedData` to a plain dict.

    Any orchestrator-output path that injects T3-derived data into a
    privileged prompt MUST call this first. The gate check enforces
    that the crossing is deliberate (``downgrade_explicit=True``); the
    audit row records the trust transition with the
    :data:`alfred.audit.audit_row_schemas.T3_DERIVED_DOWNGRADE_FIELDS`
    family.

    Gate-first ordering: ``check_content_clearance(...,
    hookpoint="t3.downgrade_to_orchestrator", content_tier="T3")``
    is consulted BEFORE the audit row writes. A denial raises
    :class:`AlfredError` with NO audit row from this family — the
    gate's own refusal accounting handles denied calls (typically the
    ``security.capability_gate.*`` audit family).

    Emits ``quarantine.t3_derived_downgrade`` — NOT
    ``identity.t1_downgrade`` (rvw-003). T1→T2 and T3-derived→T2 are
    distinct trust transitions with separate forensic attribution; the
    audit-row family separation is the type-level pin.

    The returned dict carries the same key-value pairs as the input.
    The :class:`T3DerivedData` provenance tag is intentionally retired
    at this boundary; the audit row is the receipt that links the
    plain dict back to its T3-derived origin.

    The audit row carries provenance attribution ONLY (source/target
    tier, correlation id, closed-vocabulary downgrade_reason). The
    payload values themselves are NEVER serialised into the audit row
    — that would bypass DLP and let downstream log consumers observe
    raw T3-derived content outside the privileged-orchestrator path.
    """
    # Gate uses the closed PRD §7.1 tier vocabulary ({T0, T1, T2, T3}).
    # ``T3_derived`` is an audit-row forensic label (see
    # T3_DERIVED_DOWNGRADE_FIELDS source_tier) NOT a policy tier — passing
    # it to the gate would drift policy off the canonical tier model.
    # The source of this content is T3 (a quarantined-LLM extraction);
    # the gate is asked to clear T3 crossing through the downgrade
    # hookpoint. The forensic ``T3_derived`` provenance is recorded in
    # the audit row below.
    if not gate.check_content_clearance(
        plugin_id="t3.downgrade_to_orchestrator",
        hookpoint="t3.downgrade_to_orchestrator",
        content_tier="T3",
    ):
        raise DowngradeDeniedError(t("security.quarantine.downgrade_denied"))

    from alfred.audit import audit_row_schemas

    correlation_id = str(uuid.uuid4())
    # extraction_id and quarantined_llm_invocation_id are forensic
    # attribution slots the caller MAY thread through (Slice 4+). Until
    # then they are explicitly ``None`` — append_schema's symmetric
    # validation requires every declared field to be present in
    # ``subject``, and ``None`` is the audit-graph sentinel for "not
    # threaded through". The closed-vocabulary downgrade_reason tag is
    # the immediate forensic linkage that ties the downgrade row back
    # to the extraction that produced it.
    await audit_writer.append_schema(
        fields=audit_row_schemas.T3_DERIVED_DOWNGRADE_FIELDS,
        schema_name="T3_DERIVED_DOWNGRADE_FIELDS",
        event="quarantine.t3_derived_downgrade",
        actor_user_id=None,
        subject={
            "extraction_id": None,
            "quarantined_llm_invocation_id": None,
            "source_tier": "T3_derived",
            "target_tier": "T2",
            "downgrade_reason": _DOWNGRADE_REASON_DEFAULT,
            "trust_tier_of_trigger": "T3",
            "trust_tier_of_response": "T2",
            "downgrade_explicit": True,
            "correlation_id": correlation_id,
        },
        trust_tier_of_trigger="T3",
        result="allowed",
        cost_estimate_usd=0.0,
        trace_id=correlation_id,
    )
    # ``data`` is a NewType over dict[str, object]; ``dict(data)`` builds
    # a plain dict snapshot — the provenance tag is intentionally retired
    # at this boundary. The audit row above is the receipt.
    return dict(data)


# ---------------------------------------------------------------------------
# Hookpoint declaration — security.quarantined.extract (spec §6.5, #158)
# ---------------------------------------------------------------------------


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Register the ``security.quarantined.extract`` hookpoint (spec §6.5).

    Called at module-init time so a CLI invocation or test fixture that
    imports :mod:`alfred.security.quarantine` finds the hookpoint
    pre-declared. Matches the precedent at
    :mod:`alfred.memory.episodic` / :mod:`alfred.identity._ingest` /
    :mod:`alfred.security.capability_gate.proposals`.

    Idempotent against the active registry: the registry's
    :meth:`HookRegistry.register_hookpoint` is a no-op on an identical
    re-declaration. Important because :mod:`pytest`'s test-isolation
    fixtures may swap the registry, after which the module-bottom call
    here re-runs against the new singleton at module reimport time.

    The three meta values are spec §6.5 verbatim and are the dispatch-
    time defense-in-depth recheck (see
    :func:`alfred.hooks.invoke._enforce_subscribable_tiers`) — weakening
    any of them silently disarms the trust boundary on the
    quarantined-extract post chain. The values MUST equal the publisher's
    invoke-time args at every dispatch site in :meth:`QuarantinedExtractor.extract`;
    spec §6.2 raises :class:`HookError` on drift.

    Args:
        registry: Optional override — passed by tests that want to
            exercise the declaration against a non-singleton registry.
            Defaults to :func:`get_registry` so the module-bottom call
            lands against the active process singleton.
    """
    target = registry if registry is not None else get_registry()
    target.register_hookpoint(
        name="security.quarantined.extract",
        subscribable_tiers=SYSTEM_OPERATOR_TIERS,
        refusable_tiers=SYSTEM_ONLY_TIERS,
        fail_closed=True,
        # PR-S4-3: T3 carrier — quarantined extract handles untrusted T3 content.
        carrier_tier=T3,
    )


# Module-bottom call — runs at import time so the hookpoint is declared
# before any subscriber registration or dispatch lands. The precedent
# (see :mod:`alfred.memory.episodic`) puts the call at the bottom of
# the module so every helper symbol the declaration references is
# already bound by the time the call evaluates.
declare_hookpoints()
