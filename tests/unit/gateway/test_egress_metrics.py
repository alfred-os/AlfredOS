"""Unit tests for the canonical egress metric family + shared in-flight collector."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.parser import text_string_to_metric_families

from alfred.gateway.egress_metrics import (
    EgressInflightCollector,
    build_denied_counter,
)


def test_inflight_collector_emits_one_sample_per_registered_plane() -> None:
    reg = CollectorRegistry()
    collector = EgressInflightCollector()
    reg.register(collector)
    proxy_conns: set[object] = {object(), object()}
    relay_conns: set[object] = set()
    collector.register("proxy", proxy_conns)
    collector.register("relay", relay_conns)

    families = list(text_string_to_metric_families(generate_latest(reg).decode()))
    inflight = next(f for f in families if f.name == "gateway_egress_inflight")
    samples = {s.labels["plane"]: s.value for s in inflight.samples}
    assert samples == {"proxy": 2.0, "relay": 0.0}


def test_inflight_collector_reads_len_at_scrape_time() -> None:
    reg = CollectorRegistry()
    collector = EgressInflightCollector()
    reg.register(collector)
    conns: set[object] = set()
    collector.register("proxy", conns)
    conns.add(object())
    conns.add(object())
    families = list(text_string_to_metric_families(generate_latest(reg).decode()))
    inflight = next(f for f in families if f.name == "gateway_egress_inflight")
    assert {s.labels["plane"]: s.value for s in inflight.samples} == {"proxy": 2.0}


def test_deregistered_plane_leaves_no_stale_series() -> None:
    reg = CollectorRegistry()
    collector = EgressInflightCollector()
    reg.register(collector)
    collector.register("adapter", {object()})
    collector.deregister("adapter")
    families = list(text_string_to_metric_families(generate_latest(reg).decode()))
    inflight = next((f for f in families if f.name == "gateway_egress_inflight"), None)
    assert inflight is None or inflight.samples == []


def test_denied_counter_labels_are_plane_and_reason() -> None:
    reg = CollectorRegistry()
    counter = build_denied_counter(reg)
    counter.labels(plane="proxy", reason="literal_ip_target").inc()
    families = list(text_string_to_metric_families(generate_latest(reg).decode()))
    # NB: the parser reports the counter FAMILY name WITHOUT the `_total` suffix
    # ("gateway_egress_denied"), while the SAMPLE keeps `_total`. This asymmetry is
    # load-bearing — key family lookups on the stripped name, sample filters on `_total`.
    denied = next(f for f in families if f.name == "gateway_egress_denied")
    hit = next(s for s in denied.samples if s.name == "gateway_egress_denied_total")
    assert hit.labels == {"plane": "proxy", "reason": "literal_ip_target"}
    assert hit.value == 1.0


def test_module_wrappers_register_and_deregister() -> None:
    # Direct coverage of the singleton wrappers (the 4 tests above use a fresh
    # instance; the module-level wrappers are otherwise only hit via proxy serve).
    from alfred.gateway.egress_metrics import (
        EGRESS_INFLIGHT_COLLECTOR,
        deregister_egress_inflight,
        register_egress_inflight,
    )

    conns: set[object] = {object()}
    register_egress_inflight("proxy", conns)
    assert EGRESS_INFLIGHT_COLLECTOR._planes.get("proxy") is conns
    deregister_egress_inflight("proxy")
    assert "proxy" not in EGRESS_INFLIGHT_COLLECTOR._planes
