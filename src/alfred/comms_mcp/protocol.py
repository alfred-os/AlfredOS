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

    ``credentials_ref`` and ``policies_snapshot_hash`` are OPTIONAL and
    adapter-dependent (Spec A G3-3b-2b / ADR-0035). The operator-local TUI leg
    has neither, and NO host producer sends them on the wire today: the runner
    handshake emits only ``{adapter_id, seq_ack, epoch?}`` and the sole strict
    consumer (the TUI co-host) reads only ``adapter_id``. Making them optional
    does NOT weaken any adapter's credential handling — REAL adapter
    credentials flow through the secret broker at the tool-call boundary (hard
    rule #6), never via these lifecycle.start params. They remain here so a
    future credential-bearing adapter's host can supply them, and a request that
    DOES carry them still validates (back-compat).
    """

    adapter_id: AdapterId
    credentials_ref: str | None = None
    policies_snapshot_hash: str | None = None
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
    # The carrier out-of-band wire seq (the gateway's per-connection client->core
    # send-seq), read off the seq-enabled SOCKET leg only (Spec A G4b-2a-pre /
    # ADR-0032). ``None`` (the default) for the plain/stdio adapters (Discord, the
    # reference plugin, the plain TUI leg) that carry NO seq — so every existing
    # producer and test is byte-for-byte unchanged. The host durable-intake ack
    # tracker (``BoundedSeqAckTracker``) ``observe``s this value ONLY on a fresh
    # G0 ``commit_once``, so it must be NON-NEGATIVE (``Field(ge=0)``) — a forged
    # negative is refused HERE, at the wire, so it can never reach ``observe``
    # (which raises ``ValueError`` on a negative). It is carrier HEADER metadata
    # the daemon legitimately reads off its OWN wire — NEVER payload-derived, and
    # NEVER used to derive ``inbound_id`` (that ``(leg, seq, epoch)`` derivation is
    # forbidden until Spec B/C). ``_WireModel``'s ``extra="forbid"`` is preserved;
    # the default keeps it optional for producers that omit it.
    wire_seq: int | None = Field(default=None, ge=0)


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


# Canonical wire method names for the two host -> outward lifecycle notifications
# (Spec A G3-2 / ADR-0033). They live HERE, next to the ``*Notification`` models,
# so BOTH the core-send (``_emit_ready`` / ``_emit_going_down`` reference the SAME
# constant for their audit ``event=`` AND the runner frames them on the wire) and
# the G3-3 gateway-consume import them without a gateway->runner dependency
# (architect L-1). The audit-event-name and the wire-method-name are therefore the
# SAME string by construction — they cannot drift. ``daemon.lifecycle.*`` matches
# the G1 audit events; do NOT rename to ``core.lifecycle.*``.
DAEMON_LIFECYCLE_READY: Final[str] = "daemon.lifecycle.ready"
DAEMON_LIFECYCLE_GOING_DOWN: Final[str] = "daemon.lifecycle.going_down"

# Canonical wire method name for the host -> outward durable-intake ACK control
# frame (Spec A G4b-2a-pre / ADR-0032). The daemon emits this id-less notification
# on a per-connection bounded timer carrying ``{"cumulative_ack": <int>}`` — the
# high-water of the gateway's client->core wire seqs the core has DURABLY intaken
# (advanced on each G0 ``commit_once``). It travels the SAME line-delimited comms
# wire as the lifecycle frames and is CONSUMED (payload-blind) by the gateway's
# ``_route_unit``, NEVER relayed to the client. ``daemon.comms.ack`` is a WIRE
# IDENTIFIER, not an operator string — no ``t()``. The ack SOURCE is the core's
# durable tracker (the gateway is the SENDER of inbound, so it cannot ack its own
# frames); the G3 relay owns the REVERSE (core->client) ack.
DAEMON_COMMS_ACK: Final[str] = "daemon.comms.ack"


LifecycleReason = Literal["shutdown"]
"""Closed vocabulary for a planned ``going_down``.

``shutdown`` = the planned drain (operator stop / container stop / unsignalled
SIGTERM, which carries no intent). G1 ships ONLY this value: there is no
producer of any other intent yet, and an unreachable enum member is dead
surface. Widening a CLOSED ``Literal`` is non-breaking, so G3 adds ``restart``
/ aligned tokens when a real intent-producer + consumer land together. Keep
this a CLOSED ``Literal`` forever — never ``str``. See ADR-0033.
"""

LIFECYCLE_REASON_SHUTDOWN: Final[LifecycleReason] = "shutdown"
"""The single ``going_down`` reason value, bound once (core-264-002).

``_emit_going_down`` writes this into the audit subject, the wire broadcast, and
the operator echo — binding it to one constant keeps those three call sites from
drifting when G3 widens the closed ``LifecycleReason`` vocabulary (architect L-1
no-drift discipline, applied to the reason value as well as the method name).
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


# ---------------------------------------------------------------------------
# Gateway -> client link-state control frames (Spec A G3-3a / ADR-0032)
# ---------------------------------------------------------------------------
# The gateway (the always-up front door) terminates the client connection and
# dials the core; when the core link gaps and recovers it signals the client so
# the TUI can paint a reconnect banner. These three frames are the WHOLE wire
# vocabulary for that. They are PURE STATE SIGNALS — id-less notifications that
# carry NO operator-text and NO ``adapter_id`` (see the per-model comments). The
# constant and the wire-method are the SAME string by construction (the G3-3b
# gateway sends them; the G5 client renders its own localized banner from the
# method), so the two cannot drift.
LINK_RECONNECTING: Final[str] = "link.reconnecting"
LINK_RESTORED: Final[str] = "link.restored"
LINK_UNAVAILABLE: Final[str] = "link.unavailable"


class LinkReconnectingNotification(_WireModel):
    """Gateway->client: the core link gapped; a reconnect is in progress.

    A pure STATE signal — NOT adapter-keyed (deliberately no ``adapter_id``), and
    NO ``banner``/``reason`` text on the wire. An open ``str`` field here would be
    a standing invitation to later smuggle a core-supplied / T3-derived reason into
    a client-visible frame, and operator text on the wire breaks i18n rule #1. The
    client (the TUI, G5) renders its own localized banner from the METHOD, against
    ``{user.language}`` where the user's language lives — the gateway sends only the
    state. ``extra="forbid"`` rejects any smuggled field loudly.
    """


class LinkRestoredNotification(_WireModel):
    """Gateway->client: the core link recovered after a gap.

    A pure STATE signal — NOT adapter-keyed (deliberately no ``adapter_id``), NO
    banner/reason text — the client renders its own localized banner from the
    method (see :class:`LinkReconnectingNotification`).
    """


class LinkUnavailableNotification(_WireModel):
    """Gateway->client: the core link is durably unavailable.

    A pure STATE signal — NOT adapter-keyed (deliberately no ``adapter_id``), NO
    banner/reason text — the client renders its own localized banner from the
    method (see :class:`LinkReconnectingNotification`). DEFINED in G3-3a to keep the
    wire vocabulary whole, but G3-3a emits NO transition that sends it: its trigger
    (the ReplayBuffer cap breach, spec §5) lands with the breaker in G4.
    """


__all__ = [
    "BODY_FIELD_BY_KIND",
    "DAEMON_COMMS_ACK",
    "DAEMON_LIFECYCLE_GOING_DOWN",
    "DAEMON_LIFECYCLE_READY",
    "LIFECYCLE_REASON_SHUTDOWN",
    "LINK_RECONNECTING",
    "LINK_RESTORED",
    "LINK_UNAVAILABLE",
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
    "LinkReconnectingNotification",
    "LinkRestoredNotification",
    "LinkUnavailableNotification",
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
