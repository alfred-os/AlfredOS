"""ADR-0024 comms-MCP wire-format schemas (PR-S4-8, #152).

The wire-format owner for the comms-MCP rewrite. Path is deliberately
``comms_mcp`` — **not** ``comms`` — because the legacy ``src/alfred/comms/``
package is dormant through this PR and deleted in PR-S4-10 (spec §8.8); the
two are unrelated and PR-S4-10's deletion leaves this module untouched.

This module owns:

* the eight ADR-0024 method request/result Pydantic schemas;
* the four plugin -> host notification schemas;
* the :data:`OutboundMessageResult` discriminated union (comms-008);
* the :data:`adapter_kind` frozenset extension contract (comms-011) — this
  PR ships ONLY the ``"alfred_comms_test"`` placeholder; PR-S4-9 adds
  ``"discord"`` and PR-S4-10 adds ``"tui"``;
* the :data:`BODY_FIELD_BY_KIND` body-field-path table (comms-011);
* the :data:`PersonaAddressingMode` Literal.

Every model is ``ConfigDict(frozen=True, extra="forbid")`` so a typo'd wire
field surfaces as a loud validation failure rather than silent drift, and
every closed-vocabulary field is ``Literal[...]`` not ``str``.

**DLP-mandatory outbound body (round-2 closure #1, sec-001 CRITICAL).**
``OutboundMessageRequest.body`` is typed :data:`ScannedOutboundBody` — a
``NewType`` over ``tuple[str, OutboundDlpScanResult]`` that can only be
minted by :meth:`alfred.security.dlp.OutboundDlp.scan_for_outbound`. No
outbound message can be constructed without first routing its body through
the DLP chokepoint; the AST guard
``tests/unit/comms/test_outbound_request_constructed_via_scan.py`` enforces
this at every construction site.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Annotated, Final, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from alfred.security.dlp import OutboundDlpScanResult, ScannedOutboundBody

PersonaAddressingMode = Literal["dm", "mention", "channel", "thread"]
"""How a persona's outbound message addresses the recipient on the platform."""

InboundAddressingSignal = Literal["dm", "mention", "channel", "thread"]
"""How an inbound message reached the bot (mirror of the outbound modes)."""

# The set of adapter kinds this host build knows about. Shipped as a
# ``frozenset`` extension contract (comms-011): PR-S4-9 adds ``"discord"``,
# PR-S4-10 adds ``"tui"``, each with the matching ``BODY_FIELD_BY_KIND`` and
# ``REQUIRED_CLASSIFIERS_BY_KIND`` entries. This PR ships ONLY the reference
# plugin placeholder so the lifecycle harness can register.
adapter_kind: Final[frozenset[str]] = frozenset(
    {
        "alfred_comms_test",  # reference plugin — PR-S4-8
        "discord",  # PR-S4-9 — with its BODY_FIELD_BY_KIND + classifier entries
        "tui",  # PR-S4-10 — operator-local terminal; plain-text body, no sub-payloads
    }
)

# Body-text field path per adapter kind (comms-011). The inbound scanner
# consults this to locate the plain-text body inside the adapter-specific
# notification ``body`` blob. Every ``adapter_kind`` member MUST have an
# entry here — pinned by ``test_body_field_by_kind_keys_match_adapter_kind``.
BODY_FIELD_BY_KIND: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        "alfred_comms_test": "content",
        "discord": "content",  # PR-S4-9 (spec §8.6)
        "tui": "content",  # PR-S4-10 — operator keystroke-batch body text
        # "telegram":  "text",      # post-MVP
    }
)


def _check_adapter_kind(value: str) -> str:
    """Reject an ``adapter_id`` that is not a known :data:`adapter_kind` member.

    Wire-frame defence: a plugin cannot announce a kind the host build does
    not recognise. New kinds arrive only by adding to :data:`adapter_kind`
    (PR-S4-9/10), never by an unvalidated wire string.
    """
    if value not in adapter_kind:
        msg = f"unknown adapter_kind {value!r}; known: {sorted(adapter_kind)}"
        raise ValueError(msg)
    return value


AdapterId = Annotated[str, AfterValidator(_check_adapter_kind)]

# L1 defence-in-depth: a pre-resolution platform identifier is bounded so a
# plugin cannot push an oversized id into the host's hashing / audit path. 512
# matches ``inbound._MAX_PLATFORM_USER_ID_LEN`` (the cheap-gate bound) — every
# real platform id (Discord snowflake, etc.) is far shorter.
PlatformUserId = Annotated[str, Field(min_length=1, max_length=512)]

# The durable wire dedup key the gateway/adapter stamps on each inbound frame
# (Spec A decision 4 / G0). Bounded to match the ``inbound_idempotency.inbound_id``
# column (VARCHAR(255)); non-empty so a blank id can never collapse two frames.
#
# TRUST ASSUMPTION: ``inbound_id`` is adapter-supplied OPAQUE metadata. In G0 the
# host validates SHAPE only (bounded, non-empty) — it does NOT yet trust an
# individual adapter to mint globally-unique ids. The ``inbound_idempotency``
# ledger's COMPOSITE ``(adapter_id, inbound_id)`` key isolates each adapter's id
# namespace so one adapter's id reuse cannot drop another adapter's distinct
# message. The gateway (G1+) makes this id host-trusted by deriving it from a
# ``(leg, seq, epoch)`` envelope.
#
# STABILITY: dedup requires a RETRIED frame to reproduce the SAME id. A fresh
# ``uuid4().hex`` per emit is correct ONLY for a non-buffering single-shot
# emitter (each emit is a genuinely new frame); a buffering / retrying emitter
# MUST carry a stable id across its own retries or dedup is a no-op for it (the
# Discord emitter derives the id from the platform ``message.id`` for this
# reason).
InboundId = Annotated[str, Field(min_length=1, max_length=255)]


def _assert_aware(value: datetime) -> datetime:
    """Reject a naive datetime (no tzinfo). Aware-timestamp invariant."""
    if value.tzinfo is None:
        msg = "datetime must be timezone-aware (naive datetimes are refused)"
        raise ValueError(msg)
    return value


def _assert_aware_or_none(value: datetime | None) -> datetime | None:
    """Reject a naive datetime; ``None`` passes through."""
    if value is not None:
        _assert_aware(value)
    return value


AwareDatetime = Annotated[datetime, AfterValidator(_assert_aware)]
AwareDatetimeOrNone = Annotated[datetime | None, AfterValidator(_assert_aware_or_none)]


class _WireModel(BaseModel):
    """Base for every comms-MCP wire model: frozen + ``extra="forbid"``."""

    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Lifecycle (host -> plugin requests + plugin -> host results)
# ---------------------------------------------------------------------------


class SeqAckCapability(_WireModel):
    """Negotiated out-of-band seq/ack support (Spec A G2 / ADR-0032).

    Advertised by the host in ``lifecycle.start`` params and ECHOED by the plugin
    in the ``lifecycle.start`` result when it speaks the same wire version. The
    out-of-band seq/ack header is emitted on the wire ONLY when BOTH peers carry
    this field (version-gate, default-OFF). ``version`` is a CLOSED ``Literal`` —
    only ``"1"`` exists in G2; widening it is a non-breaking change a future wire
    revision makes with its consumer. Carries NO T3: the field is pure
    transport-capability metadata, never payload-derived.
    """

    version: Literal["1"]


class LifecycleStartRequest(_WireModel):
    """Host asks the plugin to begin serving an adapter.

    ``seq_ack`` (Spec A G2 / ADR-0032) is the host advertising out-of-band
    seq/ack support; ``None`` (the default) is the explicit default-OFF signal. A
    plugin that speaks the same wire version echoes the field in its result.
    """

    adapter_id: AdapterId
    credentials_ref: str = Field(min_length=1)
    policies_snapshot_hash: str = Field(min_length=1)
    seq_ack: SeqAckCapability | None = None


class LifecycleStartResult(_WireModel):
    """Plugin acknowledges lifecycle start.

    ``plugin_version`` (spec §8.1) is the adapter's self-reported version string,
    threaded into the supervisor's lifecycle audit by PR-S4-9. It is REQUIRED
    here so the wire contract matches both spec §8.1 and the reference plugin's
    ``extra="forbid"`` output (``plugins/alfred_comms_test/main.py``) — omitting
    it would make a conformant plugin's result fail validation.

    ``seq_ack`` (Spec A G2 / ADR-0032) is the plugin ECHOING out-of-band seq/ack
    support; ``None`` (the default) means the plugin does not speak it, so the
    wire stays plain ADR-0025 (default-OFF fallback). A pre-G2 plugin that omits
    the field still validates because it defaults to ``None``.
    """

    ok: bool
    plugin_version: str = Field(min_length=1)
    seq_ack: SeqAckCapability | None = None


class LifecycleStopRequest(_WireModel):
    """Host asks the plugin to stop serving an adapter."""

    adapter_id: AdapterId
    reason: Literal["operator", "supervisor", "config_reload", "shutdown"]


class LifecycleStopResult(_WireModel):
    """Plugin acknowledges lifecycle stop, reporting flushed-message count."""

    ok: bool
    flushed_messages: int = Field(ge=0)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class AdapterHealthRequest(_WireModel):
    """Host probes the plugin for an adapter health snapshot."""

    adapter_id: AdapterId


class HealthReport(_WireModel):
    """Plugin's health snapshot for an adapter."""

    ok: bool
    last_inbound_at: AwareDatetimeOrNone = None
    queue_depth: int = Field(ge=0)
    error_count: int = Field(ge=0)


# ---------------------------------------------------------------------------
# Outbound message (host -> plugin request + discriminated result)
# ---------------------------------------------------------------------------


class ContentRef(_WireModel):
    """Reference to a host-held content handle attached to an outbound message."""

    handle_id: UUID
    kind: Literal[
        "embed",
        "attachment",
        "poll",
        "link_unfurl",
        "sticker",
        "voice_message",
        "component",
        "forwarded_ref",
        "pinned_ref",
    ]


class OutboundMessageRequest(_WireModel):
    """Host asks the plugin to deliver a message to the platform.

    ``body`` is :data:`ScannedOutboundBody` — see the module docstring's
    DLP-mandatory invariant. ``idempotency_key`` is a ``UUID`` so a redelivery
    is deduplicated by value, not by a fragile string compare.
    """

    adapter_id: AdapterId
    idempotency_key: UUID
    target_platform_id: str = Field(min_length=1)
    body: ScannedOutboundBody
    attachments_refs: tuple[ContentRef, ...]
    addressing_mode: PersonaAddressingMode


class _OutboundDelivered(_WireModel):
    """Outbound delivered successfully."""

    outcome: Literal["delivered"]
    platform_message_id: str = Field(min_length=1)


class _OutboundRetryable(_WireModel):
    """Outbound failed but is safe to retry after ``retry_after_seconds``."""

    outcome: Literal["retryable_failure"]
    retry_after_seconds: int = Field(ge=0)
    error_class: str = Field(min_length=1)


class _OutboundTerminal(_WireModel):
    """Outbound failed terminally; no retry. ``detail_redacted`` is bounded."""

    outcome: Literal["terminal_failure"]
    error_class: str = Field(min_length=1)
    detail_redacted: str = Field(max_length=256)


OutboundMessageResult = Annotated[
    _OutboundDelivered | _OutboundRetryable | _OutboundTerminal,
    Field(discriminator="outcome"),
]
"""Discriminated union of outbound delivery outcomes (comms-008).

The discriminator ``outcome`` routes a wire dict to exactly one variant.
Field coupling is forbidden by construction: a ``delivered`` result has no
``retry_after_seconds``; a ``retryable_failure`` requires it.
"""


# ---------------------------------------------------------------------------
# Plugin -> host notifications
# ---------------------------------------------------------------------------


class InboundMessageNotification(_WireModel):
    """Plugin reports a platform message inbound to the host.

    ``body`` is the raw adapter-specific blob (T3 host-side); the host's
    inbound scanner locates the body text via :data:`BODY_FIELD_BY_KIND`.
    ``inbound_id`` is the durable wire dedup key (Spec A decision 4): the host
    commits accept-once on the COMPOSITE ``(adapter_id, inbound_id)`` before any
    side effect, so a replayed frame short-circuits. ``inbound_id`` is opaque
    adapter-supplied metadata (see the :data:`InboundId` trust assumption).
    """

    adapter_id: AdapterId
    inbound_id: InboundId
    platform_user_id: PlatformUserId
    body: Mapping[str, object]
    sub_payload_refs: tuple[str, ...]
    received_at: AwareDatetime
    addressing_signal: InboundAddressingSignal


class BindingRequestNotification(_WireModel):
    """Plugin reports an unbound platform user attempting first contact."""

    adapter_id: AdapterId
    platform_user_id: PlatformUserId
    verification_phrase: str = Field(min_length=1)
    platform_metadata: Mapping[str, object]


class RateLimitSignal(_WireModel):
    """Plugin reports a platform rate-limit response (e.g. Discord 429)."""

    adapter_id: AdapterId
    retry_after_seconds: int = Field(ge=0)
    platform_endpoint: str = Field(min_length=1)


class CrashedNotification(_WireModel):
    """Plugin reports an unrecoverable adapter-side crash.

    ``detail`` is redacted by the plugin before it crosses the wire — the
    host re-scrubs it before any audit row carries it.
    """

    adapter_id: AdapterId
    error_class: str = Field(min_length=1)
    detail: str


# ---------------------------------------------------------------------------
# Host -> outward lifecycle notifications (Spec A G1 / ADR-0033)
#
# DIRECTION NOTE: every notification ABOVE is plugin -> host (an adapter
# reporting inbound). These two are the OPPOSITE direction: host -> outward
# (the core announcing its own lifecycle over the comms wire). They are
# DEFINED here in G1 but NOT SENT in G1 — there is no consumer yet (the
# gateway lands in G3). G1 emits only the AUDIT rows; G3 will send these
# frames onto the same line-delimited wire (a notification, an id-less
# JSON-RPC frame). They carry NO T3 content: the epoch is non-secret boot
# metadata and ``reason`` is a closed vocabulary.
# ---------------------------------------------------------------------------


LifecycleReason = Literal["shutdown"]
"""Closed vocabulary for a planned ``going_down``.

``shutdown`` = the planned drain (operator stop / container stop / unsignalled
SIGTERM, which carries no intent). G1 ships ONLY this value: there is no
producer of any other intent yet, and an unreachable enum member is dead
surface. Widening a CLOSED ``Literal`` is non-breaking, so G3 adds ``restart``
/ aligned tokens when a real intent-producer + consumer land together. Keep
this a CLOSED ``Literal`` forever — never ``str``. See ADR-0033.
"""


class GoingDownNotification(_WireModel):
    """Core announces it has begun its planned drain (Spec A §4).

    DEFINED in G1 for G3 to send; G1 itself emits only the audit row.
    """

    reason: LifecycleReason


class ReadyNotification(_WireModel):
    """Core announces its security boot graph is healthy + the boot epoch.

    The AUDIT row is emitted ONLY after the full boot graph is healthy
    (``ready`` = HEALTH, not socket-bind). DEFINED in G1 for G3 to send;
    G1 itself emits only the audit row. ``epoch`` is the non-secret per-boot
    value the gateway reconciles against (see
    ``alfred.bootstrap.lifecycle_epoch``).
    """

    # The per-boot epoch is a ``uuid4().hex`` (32 lowercase hex chars) minted by
    # ``alfred.bootstrap.lifecycle_epoch.mint_boot_epoch``. Pin the wire shape to
    # that exact format so a malformed epoch fails validation loudly and the
    # gateway's audit<->wire correlation cannot be fed a junk token.
    epoch: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")


__all__ = [
    "BODY_FIELD_BY_KIND",
    "AdapterHealthRequest",
    "AdapterId",
    "BindingRequestNotification",
    "ContentRef",
    "CrashedNotification",
    "GoingDownNotification",
    "HealthReport",
    "InboundAddressingSignal",
    "InboundId",
    "InboundMessageNotification",
    "LifecycleReason",
    "LifecycleStartRequest",
    "LifecycleStartResult",
    "LifecycleStopRequest",
    "LifecycleStopResult",
    "OutboundDlpScanResult",
    "OutboundMessageRequest",
    "OutboundMessageResult",
    "PersonaAddressingMode",
    "RateLimitSignal",
    "ReadyNotification",
    "ScannedOutboundBody",
    "SeqAckCapability",
    "_OutboundDelivered",
    "_OutboundRetryable",
    "_OutboundTerminal",
    "adapter_kind",
]
