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

    THROTTLED_RATE = "throttled_rate"
    THROTTLED_INFLIGHT = "throttled_inflight"
    GLOBAL_CAP_REFUSED = "global_cap_refused"
    UNKNOWN_ADAPTER = "unknown_adapter"


# The EXACT field allowlist for every ingress-refusal audit row. NO body/body-hash/
# body-sample/platform-id may ever appear — the K6 field-allowlist test asserts a row's
# keys are a subset of this (plus structlog's own ``event``/``log_level``).
INGRESS_REFUSAL_AUDIT_FIELDS: Final[frozenset[str]] = frozenset(
    {"adapter_id", "reason", "depth_frames", "depth_bytes", "inflight", "cap_ratio"}
)

# The i18n key prefix for operator-rendered refusal reasons (reserved in
# ``alfred.i18n._spec_b_reserve``). A reason is rendered via ``t(f"{_REASON_KEY_PREFIX}{reason.value}")``.
_REASON_KEY_PREFIX: Final[str] = "gateway.ingress.refused."

INGRESS_THROTTLED_TOTAL: Final[Counter] = Counter(
    "gateway_ingress_throttled",
    "Count of gateway per-adapter ingress refusals (rate / in-flight / global-cap / unknown).",
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


__all__ = [
    "INGRESS_REFUSAL_AUDIT_FIELDS",
    "INGRESS_THROTTLED_TOTAL",
    "IngressRefusalReason",
    "reason_i18n_key",
    "record_ingress_refusal",
    "touch_ingress_series",
]
