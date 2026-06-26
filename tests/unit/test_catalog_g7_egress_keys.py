"""Closed key-set for the G7 egress plane (Spec C, epic #333). Mirrors
tests/unit/test_catalog_slice_4_keys.py — every key must resolve with a non-empty
msgstr so a dropped/renamed egress key fails loud."""

from __future__ import annotations

from alfred.i18n import t

G7_EGRESS_KEYS: tuple[str, ...] = (
    "egress.io_plane_unavailable",
    "egress.denied",
    # B2: the fail-closed egress-proxy bind refusal (alfred gateway start).
    "gateway.start.egress_proxy_bind_failed",
    # B4: the closed-vocab egress-CONNECT denial-reason presentations (gateway egress audit).
    "gateway.egress.denied.destination_not_allowlisted",
    "gateway.egress.denied.literal_ip_target",
    "gateway.egress.denied.resolved_ip_not_global",
    "gateway.egress.denied.malformed_connect",
)


def test_g7_egress_keys_resolve() -> None:
    for key in G7_EGRESS_KEYS:
        value = t(key)
        assert value != key, f"G7 egress key {key!r} not found in catalog"
        assert value.strip(), f"G7 egress key {key!r} has empty msgstr"
    assert len(G7_EGRESS_KEYS) == len(set(G7_EGRESS_KEYS)), "duplicate G7 egress keys"
