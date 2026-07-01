"""Closed key-set for the G7 egress plane (Spec C, epic #333). Mirrors
tests/unit/test_catalog_slice_4_keys.py — every key must resolve with a non-empty
msgstr so a dropped/renamed egress key fails loud."""

from __future__ import annotations

from alfred.i18n import t

G7_EGRESS_KEYS: tuple[str, ...] = (
    "egress.io_plane_unavailable",
    "egress.denied",
    # G7-2c-1: in-doubt refusal for a non-idempotent request (H3 policy).
    "egress.in_doubt",
    # G7-2c-1: relay-reach-specific operator message (names ALFRED_EGRESS_RELAY_URL).
    "egress.relay_io_unavailable",
    # G7-2a: the egress-id ledger integrity-mismatch (duplicate id, different body-hash).
    "egress.id_integrity_mismatch",
    # G7-2a: record_response on an egress-id with no committed intent row.
    "egress.ledger_unknown_egress_id",
    # G7-2b: the fail-loud outbound canary trip (OutboundDlp stage 3).
    "egress.outbound_canary_tripped",
    # B2: the fail-closed egress-proxy bind refusal (alfred gateway start).
    "gateway.start.egress_proxy_bind_failed",
    # B5: the fail-closed mode-(b) relay bind refusal + its typed-error message.
    "gateway.start.egress_relay_bind_failed",
    "egress.relay_unavailable",
    # B4: the closed-vocab egress-CONNECT denial-reason presentations (gateway egress audit).
    "gateway.egress.denied.destination_not_allowlisted",
    "gateway.egress.denied.literal_ip_target",
    "gateway.egress.denied.resolved_ip_not_global",
    "gateway.egress.denied.malformed_connect",
    # B3: the closed-vocab mode-(b) inspecting-relay deny-reason presentations.
    "gateway.egress.relay_denied.destination_not_allowlisted",
    "gateway.egress.relay_denied.literal_ip_target",
    "gateway.egress.relay_denied.resolved_ip_not_global",
    "gateway.egress.relay_denied.dlp_redacted",
    "gateway.egress.relay_denied.canary_tripped",
    "gateway.egress.relay_denied.response_too_large",
    "gateway.egress.relay_denied.malformed_envelope",
    "gateway.egress.relay_denied.upstream_redirect_refused",
    # G7-2.5 Task 4: inbound canary trip on a web.fetch response (in-core D1 seam).
    "egress.inbound_canary_tripped",
    # G7-5 PR-A Task 4/5: ``alfred gateway egress`` operator CLI keys.
    "gateway.help.egress",
    "gateway.egress.unreachable",
    "gateway.egress.reachable",
    "gateway.egress.inflight_label",
    "gateway.egress.denies_label",
    "gateway.egress.denies_unavailable",
    "gateway.egress.no_denials",
    "gateway.egress.plane.proxy",
    "gateway.egress.plane.relay",
    "gateway.egress.plane.adapter",
    "gateway.egress.not_configured",
    # FIX 2: adapter series present but value < 1.0 (crashed/breaker-open/spawning).
    "gateway.egress.adapter_down",
    "gateway.egress.allowlist_label",
    "gateway.egress.allowlist_empty",
    "gateway.egress.allowlist_unresolved",
)


def test_g7_egress_keys_resolve() -> None:
    for key in G7_EGRESS_KEYS:
        value = t(key)
        assert value != key, f"G7 egress key {key!r} not found in catalog"
        assert value.strip(), f"G7 egress key {key!r} has empty msgstr"
    assert len(G7_EGRESS_KEYS) == len(set(G7_EGRESS_KEYS)), "duplicate G7 egress keys"
