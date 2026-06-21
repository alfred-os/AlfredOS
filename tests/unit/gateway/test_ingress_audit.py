"""Unit tests for the ingress-refusal audit + metric sink (Spec B G6-4 / #288, K6).

K6: every new audit row carries ONLY ``adapter_id`` + a closed-vocab reason + scalar
counters — NO body, body-hash, body-sample, or platform-id. The full closed-vocab
reason set lives in ONE ``Enum``. The metric label set is EXACTLY ``{"adapter"}``.
"""

from __future__ import annotations

import pytest
import structlog

from alfred.gateway.ingress_audit import (
    INGRESS_REFUSAL_AUDIT_FIELDS,
    INGRESS_THROTTLED_TOTAL,
    IngressRefusalReason,
    reason_i18n_key,
    record_ingress_refusal,
    record_unknown_adapter_refusal,
    touch_ingress_series,
)

# A high-entropy sentinel that would be unmistakable if a body ever leaked onto a row.
_SENTINEL_BODY = b"SENTINEL-7f3a9c2e-PRE-DLP-OPERATOR-INPUT-MUST-NOT-LEAK"


def _throttled(adapter: str) -> float:
    value = INGRESS_THROTTLED_TOTAL.labels(adapter=adapter)._value.get()  # type: ignore[attr-defined]
    return float(value)


def test_reason_set_is_exactly_the_closed_vocab_values() -> None:
    # Spec B G6-4 Task 7 (#288): ``oversized`` (the K3 size-tier refusal) joins the closed
    # vocab — declared once here (K6) so a future G6-5 wiring of a binding leg cannot drift
    # the reason. The TUI leg's gate is non-binding so it never fires live in G6-4.
    # H2 (Spec B G6-4 #288): ``queue_full`` (the per-leg send-queue back-pressure refusal)
    # joins the closed vocab so the ``LegQueueFullError`` boundary handler in
    # ``submit_tui_unit`` draws from the same single source-of-truth set.
    assert {r.value for r in IngressRefusalReason} == {
        "oversized",
        "throttled_rate",
        "throttled_inflight",
        "global_cap_refused",
        "unknown_adapter",
        "queue_full",
    }


def test_metric_label_set_is_exactly_adapter() -> None:
    # F8 cardinality guard: the sole label is ``adapter``.
    assert INGRESS_THROTTLED_TOTAL._labelnames == ("adapter",)


def test_touch_creates_the_series_at_construction() -> None:
    touch_ingress_series("touch-test-adapter")
    assert _throttled("touch-test-adapter") == 0.0


def test_record_increments_metric_and_emits_allowlisted_row() -> None:
    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        before = _throttled("disc-1")
        record_ingress_refusal(
            "disc-1",
            IngressRefusalReason.THROTTLED_RATE,
            depth_frames=3,
            depth_bytes=120,
            inflight=2,
            cap_ratio=0.5,
        )
    finally:
        structlog.reset_defaults()
    assert _throttled("disc-1") == before + 1.0
    assert len(cap.entries) == 1
    row = cap.entries[0]
    assert row["adapter_id"] == "disc-1"
    assert row["reason"] == "throttled_rate"
    # Only the allowlisted fields + the structlog event key may be present.
    allowed = INGRESS_REFUSAL_AUDIT_FIELDS | {"event", "log_level"}
    assert set(row) <= allowed, f"unexpected fields on row: {set(row) - allowed}"


def test_no_body_or_platform_id_field_ever_present() -> None:
    # The sentinel-body-absent assertion: even if a caller had a body in scope, the
    # sink's signature has nowhere to put it — assert no forbidden key appears.
    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        for reason in IngressRefusalReason:
            record_ingress_refusal(
                "disc-2",
                reason,
                depth_frames=0,
                depth_bytes=0,
                inflight=0,
                cap_ratio=0.0,
            )
    finally:
        structlog.reset_defaults()
    forbidden = {"body", "body_hash", "body_sample", "payload", "platform_user_id"}
    for row in cap.entries:
        assert forbidden.isdisjoint(row), f"forbidden field on row: {forbidden & set(row)}"
        serialized = repr(row).encode()
        assert _SENTINEL_BODY not in serialized


def test_unknown_adapter_row_stays_within_the_allowlist() -> None:
    # K6 totality (Spec B G6-4 #288): the forged/unknown-adapter sink emits a
    # ``gateway.ingress.refused`` row carrying ``forged_adapter_id`` — that field MUST be in
    # the allowlist so the K6 field-allowlist guarantee covers BOTH refusal sinks, not just
    # the scalar-counter one. A high-entropy forged id (longer than the truncation bound)
    # exercises the bound + proves no body leaks alongside it.
    forged = "FORGED-" + "z" * 200
    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        before = _throttled("<unknown>")
        record_unknown_adapter_refusal(forged)
    finally:
        structlog.reset_defaults()
    # Cardinality guard: the sentinel series absorbs it, never the forged id.
    assert _throttled("<unknown>") == before + 1.0
    assert len(cap.entries) == 1
    row = cap.entries[0]
    assert row["adapter_id"] == "<unknown>"
    assert row["reason"] == "unknown_adapter"
    # The forged id is BOUNDED on the row (audit-injection defence) and resolves within the
    # allowlist (plus structlog's own keys).
    assert len(row["forged_adapter_id"]) <= 64
    allowed = INGRESS_REFUSAL_AUDIT_FIELDS | {"event", "log_level"}
    assert set(row) <= allowed, f"unexpected fields on unknown-adapter row: {set(row) - allowed}"


def test_audit_fields_constant_includes_forged_adapter_id() -> None:
    # The forged-id forensic field is part of the closed allowlist (K6 totality).
    assert "forged_adapter_id" in INGRESS_REFUSAL_AUDIT_FIELDS


def test_audit_fields_constant_excludes_body_keys() -> None:
    forbidden = {"body", "body_hash", "body_sample", "payload", "platform_user_id"}
    assert forbidden.isdisjoint(INGRESS_REFUSAL_AUDIT_FIELDS)
    assert "adapter_id" in INGRESS_REFUSAL_AUDIT_FIELDS
    assert "reason" in INGRESS_REFUSAL_AUDIT_FIELDS


def test_operator_reason_keys_are_reserved() -> None:
    # Every reason rendered to an operator must have a catalog key (i18n discipline).
    from alfred.i18n import t

    for reason in IngressRefusalReason:
        key = reason_i18n_key(reason)
        assert key == f"gateway.ingress.refused.{reason.value}"
        rendered = t(key)
        assert rendered  # a missing key returns the key itself (still truthy) — the
        # catalog-drift gate is what proves the .po entry exists; here we prove the
        # render call site is wired for every reason.


@pytest.mark.parametrize("bad_inflight", [-1])
def test_negative_scalar_counters_are_loud(bad_inflight: int) -> None:
    # Scalar counters must be non-negative; a negative is a wiring bug, fail loud.
    with pytest.raises(ValueError, match="non-negative"):
        record_ingress_refusal(
            "disc-3",
            IngressRefusalReason.THROTTLED_INFLIGHT,
            depth_frames=0,
            depth_bytes=0,
            inflight=bad_inflight,
            cap_ratio=0.0,
        )
