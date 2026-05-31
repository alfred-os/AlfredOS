"""Transport-layer Prometheus histograms (spec §7a.1 — perf-002 / perf-009).

Four histograms covering the four spec §7a.1 p99 budgets:

* :data:`DISPATCH_DURATION` — ``alfred_stdio_transport_dispatch_seconds`` —
  :meth:`alfred.plugins.stdio_transport.StdioTransport.dispatch` end-to-end
  round-trip. Labels: ``plugin_id``, ``method_shape``
  (``content`` | ``control`` | ``extraction``), ``outcome``
  (``ok`` | ``dlp_refused`` | ``canary_trip`` | ``protocol_error`` |
  ``error``). Budget: p99 < 5ms.
* :data:`OUTBOUND_DLP_SCAN_DURATION` —
  ``alfred_outbound_dlp_scan_seconds`` — ``OutboundDlp.scan`` per frame.
  Labels: ``outcome`` (``allowed`` | ``refused``). Budget: 1 KB p99 < 200µs.
* :data:`INBOUND_SCANNER_SCAN_DURATION` —
  ``alfred_inbound_scanner_scan_seconds`` —
  :meth:`alfred.plugins.inbound_scanner.InboundContentScanner.scan` per
  frame. Labels: ``outcome`` (``clean`` | ``canary_trip``). Budget:
  1 MB p99 < 50 ms.
* :data:`PLUGIN_SPAWN_DURATION` — ``alfred_plugin_spawn_seconds`` —
  subprocess cold-start to manifest-handshake complete. Labels:
  ``plugin_id``, ``outcome`` (``ok`` | ``spawn_failed`` |
  ``handshake_rejected``). Budget: p99 < 500 ms.

Label-cardinality notes
-----------------------

``plugin_id`` is bounded by the operator's installed plugin set (Slice 3
ships single-digit plugins; Slice 4+ counts likely stay <100). ``outcome``
and ``method_shape`` are closed vocabularies (see the parenthesised lists
above) so the time-series count per histogram is
``plugin_id x |outcome|`` at most — well below Prometheus's
recommendations.

The histograms are intentionally module-level (created once at import
time) rather than constructed per-dispatch, because
:class:`prometheus_client.Histogram` registers itself on the default
:class:`CollectorRegistry` and a second instantiation with the same name
raises ``Duplicated timeseries``. Tests that need a fresh registry use a
local :class:`CollectorRegistry` rather than re-importing this module.

Module-private name (``_observability``) signals internal: the supervisor
re-exports the histograms it cares about for OpenTelemetry bridging; the
transport dispatch site imports them directly.
"""

from __future__ import annotations

from prometheus_client import Histogram

# StdioTransport.dispatch end-to-end. The bucket boundaries straddle the
# spec §7a.1 5ms p99 budget (0.005 is present, so the operator can read
# the p99 directly from the histogram).
DISPATCH_DURATION: Histogram = Histogram(
    "alfred_stdio_transport_dispatch_seconds",
    "StdioTransport.dispatch end-to-end duration (spec §7a.1 p99 < 5ms).",
    ["plugin_id", "method_shape", "outcome"],
    buckets=(0.0005, 0.001, 0.002, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0),
)

# OutboundDlp.scan per frame. Budget is 200µs on a 1KB payload; buckets
# centre on the sub-millisecond regime.
OUTBOUND_DLP_SCAN_DURATION: Histogram = Histogram(
    "alfred_outbound_dlp_scan_seconds",
    "OutboundDlp.scan duration per frame (spec §7a.1 p99 < 200µs at 1KB).",
    ["outcome"],
    buckets=(0.00005, 0.0001, 0.0002, 0.0005, 0.001, 0.005, 0.01),
)

# InboundContentScanner.scan per frame. Budget is 50ms on a 1MB payload;
# buckets straddle the millisecond-to-100ms regime.
INBOUND_SCANNER_SCAN_DURATION: Histogram = Histogram(
    "alfred_inbound_scanner_scan_seconds",
    "InboundContentScanner.scan duration per frame (spec §7a.1 p99 < 50ms at 1MB).",
    ["outcome"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5),
)

# Subprocess cold-start through manifest handshake. Budget is 500ms;
# buckets reach 2s so a misbehaving spawn shows up in the >budget bucket
# without falling into ``+Inf``.
PLUGIN_SPAWN_DURATION: Histogram = Histogram(
    "alfred_plugin_spawn_seconds",
    "Plugin subprocess cold-start to manifest-handshake complete (spec §7a.1 p99 < 500ms).",
    ["plugin_id", "outcome"],
    buckets=(0.05, 0.1, 0.2, 0.3, 0.5, 1.0, 2.0),
)


__all__ = [
    "DISPATCH_DURATION",
    "INBOUND_SCANNER_SCAN_DURATION",
    "OUTBOUND_DLP_SCAN_DURATION",
    "PLUGIN_SPAWN_DURATION",
]
