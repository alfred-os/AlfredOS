"""Ingress-refusal audit + metric sink for the gateway leg scheduler (Spec B G6-4 / #288).

Keystone K6: the new back-pressure surfaces (per-adapter ingress throttle, global-cap
refuse, forged/unknown-adapter refusal) are NEVER silent (CLAUDE.md hard rule #7) — each
emits a loud structlog row + a per-adapter counter. This module is the SINGLE place that:

* declares the FULL closed-vocab refusal-reason set (:class:`IngressRefusalReason`) so the
  vocabulary cannot drift across call sites;
* owns the per-adapter ``gateway_ingress_throttled_total{adapter}`` counter (sole label
  ``adapter`` — the gateway-chosen, bounded, spawn-known id, never payload-derived, so
  there is no per-user cardinality / label-injection surface);
* emits the refusal row through a FIELD-ALLOWLISTED sink (:func:`record_ingress_refusal`)
  whose signature can carry ONLY ``adapter_id`` + the closed-vocab reason + scalar
  counters (depth_frames / depth_bytes / inflight / cap_ratio) — there is NOWHERE to put
  a body, body-hash, body-sample, or platform-id, so the payload-blindness invariant
  (hard rule #5) is structural, not merely conventional.

**Gateway audit is structlog-only for G6-4** (the gateway holds no signing key; the
durable signed-log reconcile is the tracked G6-2b/design-§6 follow-up) — adding a new
core-side observer method would be scope creep. The reasons an operator could see
rendered carry an i18n catalog key (``gateway.ingress.refused.<reason>``); the keys are
reserved in :mod:`alfred.i18n._spec_b_reserve`.
"""

from __future__ import annotations

import enum
from typing import Final

import structlog
from prometheus_client import Counter

log = structlog.get_logger(__name__)


class IngressRefusalReason(enum.Enum):
    """The closed vocabulary of gateway ingress/admission refusal reasons (K6).

    Declared ONCE so every call site (the leg ingress gate, the global cap, the
    forged-envelope router) draws from the same set — no free-form reason strings.
    """

    OVERSIZED = "oversized"
    THROTTLED_RATE = "throttled_rate"
    THROTTLED_INFLIGHT = "throttled_inflight"
    GLOBAL_CAP_REFUSED = "global_cap_refused"
    UNKNOWN_ADAPTER = "unknown_adapter"
    QUEUE_FULL = "queue_full"
    # NB: QUEUE_FULL is the per-leg SEND-QUEUE back-pressure refusal (H2, Spec B G6-4 #288):
    # the scheduler's bounded pre-append working-memory queue (``max_per_leg_queue_bytes``,
    # K3/perf-M3) is full, so ``submit_tui_unit`` drops the frame LOUD rather than let the
    # ``LegQueueFullError`` escape + crash the relay TaskGroup. Distinct from the buffer/cap
    # tiers above: this bounds the queue BEFORE the leg buffer, never reached on the
    # non-binding TUI leg unless a producer outruns the single writer.
    # NB: OVERSIZED is the size-tier refusal (K3 max_frame_bytes). The TUI leg's gate is
    # NON-BINDING in G6-4 so it never fires live; a real adapter leg (G6-5) can. Declared
    # here (the single closed-vocab home, K6) so the reason cannot drift when G6-5 wires it.


# The EXACT field allowlist for every ingress-refusal audit row. NO body/body-hash/
# body-sample/platform-id may ever appear — the K6 field-allowlist test asserts a row's
# keys are a subset of this (plus structlog's own ``event``/``log_level``).
INGRESS_REFUSAL_AUDIT_FIELDS: Final[frozenset[str]] = frozenset(
    {"adapter_id", "reason", "depth_frames", "depth_bytes", "inflight", "cap_ratio"}
)

# The i18n key prefix for operator-rendered refusal reasons (reserved in
# ``alfred.i18n._spec_b_reserve``). A reason is rendered via
# ``t(f"{_REASON_KEY_PREFIX}{reason.value}")``.
_REASON_KEY_PREFIX: Final[str] = "gateway.ingress.refused."

# The FIXED metric label for a forged/unknown-adapter refusal (K4). The forged id is NEVER
# used as a label value (a flood of distinct forged ids would otherwise blow up the metric
# cardinality — a DoS) — every unknown-adapter refusal increments this single sentinel
# series instead. The forged id is recorded only as a BOUNDED structlog FIELD for forensics.
_UNKNOWN_ADAPTER_LABEL: Final[str] = "<unknown>"

# How many characters of a forged adapter_id to keep on the audit row. Bounded so a giant
# forged id cannot bloat the log line (audit-injection defence) while preserving enough for
# triage.
_FORGED_ID_MAX_LEN: Final[int] = 64

INGRESS_THROTTLED_TOTAL: Final[Counter] = Counter(
    "gateway_ingress_throttled",
    "Count of gateway per-adapter ingress refusals "
    "(oversized / rate / in-flight / global-cap / unknown-adapter / queue-full).",
    labelnames=["adapter"],
)


def touch_ingress_series(adapter_id: str) -> None:
    """Materialise the ``{adapter}`` counter series at leg construction (F8).

    A labelled prometheus collector yields NO sample for a label value until
    ``.labels(...)`` is first called; touching it at construction means the series
    exists (at 0) before any refusal, so a scrape sees the leg even before its first trip.
    """
    INGRESS_THROTTLED_TOTAL.labels(adapter=adapter_id)


def reason_i18n_key(reason: IngressRefusalReason) -> str:
    """The catalog key an operator-facing renderer uses for ``reason`` (i18n discipline)."""
    return f"{_REASON_KEY_PREFIX}{reason.value}"


def record_ingress_refusal(
    adapter_id: str,
    reason: IngressRefusalReason,
    *,
    depth_frames: int,
    depth_bytes: int,
    inflight: int,
    cap_ratio: float,
) -> None:
    """Increment the per-adapter counter + emit ONE field-allowlisted loud audit row.

    The sink's parameter list IS the allowlist: there is no way to pass a body / hash /
    platform-id, so the row is payload-blind by construction (K6). The scalar counters
    must be non-negative — a negative is a wiring bug, raised loud (hard rule #7) rather
    than written as a corrupt observation.
    """
    if depth_frames < 0 or depth_bytes < 0 or inflight < 0 or cap_ratio < 0:
        raise ValueError(
            "ingress-refusal scalar counters must be non-negative: "
            f"depth_frames={depth_frames} depth_bytes={depth_bytes} "
            f"inflight={inflight} cap_ratio={cap_ratio}"
        )
    INGRESS_THROTTLED_TOTAL.labels(adapter=adapter_id).inc()
    log.warning(
        "gateway.ingress.refused",
        adapter_id=adapter_id,
        reason=reason.value,
        depth_frames=depth_frames,
        depth_bytes=depth_bytes,
        inflight=inflight,
        cap_ratio=cap_ratio,
    )


def record_unknown_adapter_refusal(forged_adapter_id: str) -> None:
    """Refuse a forged/unknown-adapter envelope: SENTINEL-labelled metric + loud row (K4).

    The forged ``adapter_id`` is NEVER used as a prometheus label (cardinality DoS) — the
    fixed :data:`_UNKNOWN_ADAPTER_LABEL` series absorbs every such refusal. The forged id is
    recorded only as a BOUNDED structlog field (truncated to :data:`_FORGED_ID_MAX_LEN`) for
    triage; the opaque body is never passed here (payload-blind — there is nowhere to put
    it). This is the single sink for the ``unknown_adapter`` reason; it is loud + refusing,
    never a silent drop (CLAUDE.md hard rule #7).
    """
    INGRESS_THROTTLED_TOTAL.labels(adapter=_UNKNOWN_ADAPTER_LABEL).inc()
    log.warning(
        "gateway.ingress.refused",
        adapter_id=_UNKNOWN_ADAPTER_LABEL,
        reason=IngressRefusalReason.UNKNOWN_ADAPTER.value,
        forged_adapter_id=forged_adapter_id[:_FORGED_ID_MAX_LEN],
    )


__all__ = [
    "INGRESS_REFUSAL_AUDIT_FIELDS",
    "INGRESS_THROTTLED_TOTAL",
    "IngressRefusalReason",
    "reason_i18n_key",
    "record_ingress_refusal",
    "record_unknown_adapter_refusal",
    "touch_ingress_series",
]
