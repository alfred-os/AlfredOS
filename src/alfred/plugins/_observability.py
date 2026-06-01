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

Label-cardinality cap (perf-003)
--------------------------------

``plugin_id`` is an open-vocabulary label — any future plugin manifest
declares its own id, and a runaway proposal loop / misconfigured plugin
fleet could mint thousands of distinct ids that all land in the
histogram label index. At 1K plugins x 5 outcomes x 3 method_shapes the
``DISPATCH_DURATION`` series count crosses 15K — well above the
prometheus_client recommended ceiling for a single histogram.

The fix: route every label-emit through :func:`bucket_plugin_id`, which
maintains a fixed-size allowlist of recently-seen plugin ids
(:data:`MAX_TRACKED_PLUGINS = 100`). The first 100 distinct plugin ids
keep their actual label value (operators see the exact plugin in
dashboards); every subsequent id falls into the
:data:`PLUGIN_ID_OVERFLOW_BUCKET` (``"other"``) so the long tail
collapses to a single series. The bucket count is itself a useful signal
— a non-zero ``"other"`` bucket means the deployment has grown past the
tracked-plugin threshold and the allowlist needs raising (or the plugin
fleet needs auditing).

The allowlist is module-level (process-lifetime), thread-safe via a
single ``threading.Lock`` (Prometheus scrapes can race the dispatch
hot-path), and intentionally NOT persistent: a process restart resets
the allowlist, which is the safe shape — the post-restart cardinality
budget is fresh, and the histograms themselves reset on restart anyway.

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

import threading
from typing import Final

from prometheus_client import Histogram

# perf-003: open-vocabulary plugin_id label is the cardinality hotspot.
# 100 is a generous ceiling — Slice 3 ships single-digit plugins; a
# healthy Slice 4+ deployment with adapter plugins, integration plugins,
# and the host's own observability-emitting modules stays well under
# this. The constant lives at module scope so a test can lower it via
# monkeypatch to exercise the overflow branch without minting 100 ids.
MAX_TRACKED_PLUGINS: Final[int] = 100

# Long-tail bucket label value. ``"other"`` is the canonical Prometheus
# convention for "everything past the allowlist"; operators see a
# non-zero ``other`` bucket and know the allowlist is saturated.
PLUGIN_ID_OVERFLOW_BUCKET: Final[str] = "other"

# Process-lifetime allowlist + a lock guarding it. Prometheus scrapes
# the histograms from a separate thread (the WSGI exporter or the
# OpenTelemetry bridge), and the dispatch hot-path mutates the
# allowlist on first-sight of a new plugin id; without the lock the
# read / mutate race would let two simultaneously-arriving new ids
# both believe they slipped in under the cap. The lock is held only
# across the set-mutation; the histogram emit happens outside.
_tracked_plugin_ids: set[str] = set()
_tracked_plugin_ids_lock: threading.Lock = threading.Lock()


def bucket_plugin_id(plugin_id: str) -> str:
    """Return the histogram-label value for ``plugin_id``.

    Maintains a fixed-size allowlist (:data:`MAX_TRACKED_PLUGINS`) of
    recently-seen plugin ids. Inside the allowlist: returns ``plugin_id``
    unchanged so operators see the actual identifier in dashboards.
    Outside the allowlist: returns :data:`PLUGIN_ID_OVERFLOW_BUCKET`
    so every future plugin id past the cap shares one series.

    Thread-safe (Prometheus exporters scrape from separate threads).
    Idempotent on already-tracked ids — no allocation on the
    already-seen hot path past the lock acquisition.

    perf-003: this is the cardinality firewall — without it,
    :data:`DISPATCH_DURATION` and :data:`PLUGIN_SPAWN_DURATION` would
    leak unbounded series into Prometheus on any environment with more
    than O(100) distinct plugins.
    """
    with _tracked_plugin_ids_lock:
        if plugin_id in _tracked_plugin_ids:
            return plugin_id
        if len(_tracked_plugin_ids) < MAX_TRACKED_PLUGINS:
            _tracked_plugin_ids.add(plugin_id)
            return plugin_id
    return PLUGIN_ID_OVERFLOW_BUCKET


def _reset_tracked_plugin_ids_for_test() -> None:
    """Test-only allowlist reset. NOT for production use.

    Production code MUST NOT call this — the allowlist is process-
    lifetime by design (a refresh would shift cardinality boundaries
    mid-flight). Tests that exercise the cap-hit branch call this in a
    setUp / fixture to start from a known state.
    """
    with _tracked_plugin_ids_lock:
        _tracked_plugin_ids.clear()


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
    "MAX_TRACKED_PLUGINS",
    "OUTBOUND_DLP_SCAN_DURATION",
    "PLUGIN_ID_OVERFLOW_BUCKET",
    "PLUGIN_SPAWN_DURATION",
    "bucket_plugin_id",
]
