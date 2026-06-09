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
        "alfred_comms_test",  # reference plugin — this PR
        # "discord"  — added by PR-S4-9
        # "tui"      — added by PR-S4-10
    }
)

# Body-text field path per adapter kind (comms-011). The inbound scanner
# consults this to locate the plain-text body inside the adapter-specific
# notification ``body`` blob. Every ``adapter_kind`` member MUST have an
# entry here — pinned by ``test_body_field_by_kind_keys_match_adapter_kind``.
BODY_FIELD_BY_KIND: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        "alfred_comms_test": "content",
        # "discord":   "content",   # PR-S4-9
        # "tui":       "content",   # PR-S4-10
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


class LifecycleStartRequest(_WireModel):
    """Host asks the plugin to begin serving an adapter."""

    adapter_id: AdapterId
    credentials_ref: str = Field(min_length=1)
    policies_snapshot_hash: str = Field(min_length=1)


class LifecycleStartResult(_WireModel):
    """Plugin acknowledges lifecycle start.

    ``plugin_version`` (spec §8.1) is the adapter's self-reported version string,
    threaded into the supervisor's lifecycle audit by PR-S4-9. It is REQUIRED
    here so the wire contract matches both spec §8.1 and the reference plugin's
    ``extra="forbid"`` output (``plugins/alfred_comms_test/main.py``) — omitting
    it would make a conformant plugin's result fail validation.
    """

    ok: bool
    plugin_version: str = Field(min_length=1)


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
    """

    adapter_id: AdapterId
    platform_user_id: str = Field(min_length=1)
    body: Mapping[str, object]
    sub_payload_refs: tuple[str, ...]
    received_at: AwareDatetime
    addressing_signal: InboundAddressingSignal


class BindingRequestNotification(_WireModel):
    """Plugin reports an unbound platform user attempting first contact."""

    adapter_id: AdapterId
    platform_user_id: str = Field(min_length=1)
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


__all__ = [
    "BODY_FIELD_BY_KIND",
    "AdapterHealthRequest",
    "AdapterId",
    "BindingRequestNotification",
    "ContentRef",
    "CrashedNotification",
    "HealthReport",
    "InboundAddressingSignal",
    "InboundMessageNotification",
    "LifecycleStartRequest",
    "LifecycleStartResult",
    "LifecycleStopRequest",
    "LifecycleStopResult",
    "OutboundDlpScanResult",
    "OutboundMessageRequest",
    "OutboundMessageResult",
    "PersonaAddressingMode",
    "RateLimitSignal",
    "ScannedOutboundBody",
    "_OutboundDelivered",
    "_OutboundRetryable",
    "_OutboundTerminal",
    "adapter_kind",
]
