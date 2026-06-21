"""Unit tests for the forged/unknown-adapter envelope router (Spec B G6-4, K4).

K4 (the #1 security add): an inbound frame whose out-of-band envelope ``adapter_id`` does
NOT match a REGISTERED leg is REFUSED + loud-audited (closed-vocab ``unknown_adapter``);
it is NEVER default-routed, NEVER silent-dropped, and NEVER given its own metric label
(label-cardinality DoS + audit-injection). The opaque body never reaches a buffer / log.
"""

from __future__ import annotations

import structlog

from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.global_replay_cap import GlobalReplayCap
from alfred.gateway.ingress_audit import (
    _FORGED_ID_MAX_LEN,
    _UNKNOWN_ADAPTER_LABEL,
    INGRESS_THROTTLED_TOTAL,
)
from alfred.gateway.ingress_gate import PerAdapterIngressGate
from alfred.gateway.leg_router import LegRouter, RouteOutcome
from alfred.gateway.leg_scheduler import GatewayLegScheduler
from alfred.gateway.replay_buffer import ReplayBuffer

_SENTINEL_BODY = b"SENTINEL-forged-body-9a8b7c-MUST-NOT-LEAK"


class _FakeClock:
    def __call__(self) -> float:
        return 0.0


class _RecordingCoreLink:
    def __init__(self) -> None:
        self.writes: list[tuple[str, bytes, int, int]] = []

    def core_cumulative_ack(self) -> int:
        return 0

    async def write_leg_unit(self, adapter_id: str, payload: bytes, *, seq: int, ack: int) -> None:
        self.writes.append((adapter_id, payload, seq, ack))


def _make_sched_with_leg(adapter_id: str) -> tuple[GatewayLegScheduler, GatewayLeg]:
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    sched = GatewayLegScheduler(_RecordingCoreLink(), max_per_leg_queue_bytes=1_000_000)
    clock = _FakeClock()
    leg = GatewayLeg(
        adapter_id=adapter_id,
        buffer=ReplayBuffer(max_frames=1000, max_bytes=1_000_000, ttl_seconds=30.0),
        ingress_gate=PerAdapterIngressGate(
            adapter_id,
            sustained_rate_per_s=1000.0,
            burst=1000,
            max_inflight=1000,
            ttl_seconds=30.0,
            max_frame_bytes=1_000_000,
            now=clock,
        ),
        global_cap=cap,
        now=clock,
    )
    sched.register_leg(leg)
    return sched, leg


def _unknown_label_count() -> float:
    return float(
        INGRESS_THROTTLED_TOTAL.labels(adapter=_UNKNOWN_ADAPTER_LABEL)._value.get()  # type: ignore[attr-defined]
    )


def test_known_adapter_is_routed_to_its_leg_queue() -> None:
    sched, _ = _make_sched_with_leg("discord")
    router = LegRouter(sched)
    outcome = router.route("discord", b"hello")
    assert outcome is RouteOutcome.ROUTED


def test_unknown_adapter_is_refused_not_routed() -> None:
    sched, _ = _make_sched_with_leg("discord")
    router = LegRouter(sched)
    outcome = router.route("evil-forged-id", _SENTINEL_BODY)
    assert outcome is RouteOutcome.REFUSED_UNKNOWN_ADAPTER


def test_unknown_adapter_never_mints_a_per_id_metric_label() -> None:
    # The forged id must NOT become a prometheus label (cardinality DoS). The refusal
    # increments a FIXED sentinel label instead.
    sched, _ = _make_sched_with_leg("discord")
    router = LegRouter(sched)
    before = _unknown_label_count()
    router.route("forged-1", b"x")
    router.route("forged-2", b"y")
    router.route("forged-3", b"z")
    # The forged ids never appeared as labels...
    forged_samples = [
        s
        for metric in INGRESS_THROTTLED_TOTAL.collect()
        for s in metric.samples
        if s.labels.get("adapter", "").startswith("forged-")
    ]
    assert forged_samples == []
    # ...and the sentinel label absorbed all three.
    assert _unknown_label_count() == before + 3


def test_unknown_adapter_emits_loud_audit_without_leaking_the_body() -> None:
    sched, _ = _make_sched_with_leg("discord")
    router = LegRouter(sched)
    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        router.route("forged-leak-test", _SENTINEL_BODY)
    finally:
        structlog.reset_defaults()
    assert cap.entries, "the refusal must emit a loud row"
    for row in cap.entries:
        assert _SENTINEL_BODY not in repr(row).encode()
        assert "payload" not in row
        assert "body" not in row


def test_unknown_adapter_id_is_truncated_on_the_audit_row() -> None:
    """L5 (Spec B G6-4, #288): a giant forged adapter_id is truncated to _FORGED_ID_MAX_LEN.

    The forged id is recorded only as a BOUNDED structlog field (audit-injection defence: a
    giant id must not bloat the log line). Route a forged id LONGER than the bound and assert
    the audited ``forged_adapter_id`` field is exactly ``_FORGED_ID_MAX_LEN`` chars (a prefix
    of the input) — the truncation property is otherwise untested.
    """
    sched, _ = _make_sched_with_leg("discord")
    router = LegRouter(sched)
    giant = "F" * (_FORGED_ID_MAX_LEN + 50)
    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        outcome = router.route(giant, b"x")
    finally:
        structlog.reset_defaults()
    assert outcome is RouteOutcome.REFUSED_UNKNOWN_ADAPTER
    refused = [r for r in cap.entries if r.get("event") == "gateway.ingress.refused"]
    assert len(refused) == 1
    truncated = refused[0]["forged_adapter_id"]
    assert truncated == giant[:_FORGED_ID_MAX_LEN]
    assert len(truncated) == _FORGED_ID_MAX_LEN


def test_unknown_adapter_body_never_reaches_a_leg_buffer() -> None:
    sched, leg = _make_sched_with_leg("discord")
    router = LegRouter(sched)
    router.route("not-discord", _SENTINEL_BODY)
    # The only registered leg's buffer is untouched.
    assert leg.depth_frames == 0
    assert leg.depth_bytes == 0
