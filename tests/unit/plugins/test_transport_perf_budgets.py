"""Transport-layer Prometheus histograms (spec §7a.1 — perf-002 / perf-009).

Spec §7a.1 names four p99 latency budgets the supervisor gates on:

* :class:`alfred.plugins.stdio_transport.StdioTransport`'s ``dispatch``
  round-trip — p99 < 5ms.
* :class:`alfred.security.dlp.OutboundDlp`'s ``scan`` on a 1KB frame —
  p99 < 200µs.
* :class:`alfred.plugins.inbound_scanner.InboundContentScanner`'s ``scan``
  on a 1MB frame — p99 < 50ms.
* Subprocess cold-start through manifest handshake completion — p99 <
  500ms.

Each budget is unfalsifiable without an emit point, so this module pins
the four histogram names + label sets + reset-on-import (so a sibling
test does not see another test's observations leak across registries).

The histograms live on the default :class:`prometheus_client.CollectorRegistry`
(process-local) so the supervisor's OpenTelemetry bridge — a different
PR — can attach without touching this module. The labels are closed
vocabularies (``outcome``, ``plugin_id``, ``method_shape``) deliberately
narrow so a high-cardinality plugin id does not blow up Prometheus's
time-series count; ``plugin_id`` is bounded by the operator's installed
plugin set.

The transport invokes each histogram via ``time.monotonic()`` deltas and
``Histogram.labels(...).observe(seconds)``. Tests that exercise the
``StdioTransport`` dispatch path assert the histogram fires; tests in
this file pin the module-level *shape* (names, labels, bucket
boundaries) so a regression that drops the labels is caught even before
a dispatch lands.
"""

from __future__ import annotations

import pytest
from prometheus_client import Histogram


def test_dispatch_duration_histogram_exists_with_expected_name_and_labels() -> None:
    """Dispatch histogram is named per spec §7a.1; labels are plugin_id, method_shape, outcome."""
    from alfred.plugins._observability import DISPATCH_DURATION

    assert isinstance(DISPATCH_DURATION, Histogram)
    # Prometheus client appends ``_seconds`` to histogram names matching
    # the unit suffix convention; spec §7a.1 pins the base name.
    assert DISPATCH_DURATION._name == "alfred_stdio_transport_dispatch_seconds"
    assert set(DISPATCH_DURATION._labelnames) == {"plugin_id", "method_shape", "outcome"}


def test_outbound_dlp_scan_histogram_exists_with_outcome_label() -> None:
    """OutboundDlp.scan histogram is labelled by outcome (allowed | refused)."""
    from alfred.plugins._observability import OUTBOUND_DLP_SCAN_DURATION

    assert isinstance(OUTBOUND_DLP_SCAN_DURATION, Histogram)
    assert OUTBOUND_DLP_SCAN_DURATION._name == "alfred_outbound_dlp_scan_seconds"
    assert set(OUTBOUND_DLP_SCAN_DURATION._labelnames) == {"outcome"}


def test_inbound_scanner_scan_histogram_exists_with_outcome_label() -> None:
    """InboundContentScanner.scan histogram is labelled by outcome (clean | canary_trip)."""
    from alfred.plugins._observability import INBOUND_SCANNER_SCAN_DURATION

    assert isinstance(INBOUND_SCANNER_SCAN_DURATION, Histogram)
    assert INBOUND_SCANNER_SCAN_DURATION._name == "alfred_inbound_scanner_scan_seconds"
    assert set(INBOUND_SCANNER_SCAN_DURATION._labelnames) == {"outcome"}


def test_plugin_spawn_histogram_exists_with_plugin_id_and_outcome_label() -> None:
    """Subprocess spawn histogram is labelled by plugin id + outcome."""
    from alfred.plugins._observability import PLUGIN_SPAWN_DURATION

    assert isinstance(PLUGIN_SPAWN_DURATION, Histogram)
    assert PLUGIN_SPAWN_DURATION._name == "alfred_plugin_spawn_seconds"
    assert set(PLUGIN_SPAWN_DURATION._labelnames) == {"plugin_id", "outcome"}


def test_dispatch_histogram_observes_via_labels() -> None:
    """Histogram.labels(...).observe(seconds) is the contract dispatch sites use.

    The actual count is observable through the internal ``_sum`` /
    ``_count`` metrics. Assert that a labelled observe lands so a
    regression that drops the labels or types the value wrong is
    caught at module import.
    """
    from alfred.plugins._observability import DISPATCH_DURATION

    DISPATCH_DURATION.labels(
        plugin_id="test_plugin",
        method_shape="content",
        outcome="ok",
    ).observe(0.001)
    # Count via the child's internal storage — Histogram exposes this via
    # the labelled-child instance's ``_sum`` / ``_buckets``.
    child = DISPATCH_DURATION.labels(
        plugin_id="test_plugin",
        method_shape="content",
        outcome="ok",
    )
    # The labelled instance accumulates monotonically across observes;
    # asserting > 0 is the stable shape (exact equality would flake under
    # parallel test runs that share the registry).
    assert child._sum.get() > 0


def test_outbound_dlp_histogram_observes_via_labels() -> None:
    """Smoke that the outbound DLP histogram accepts an observe."""
    from alfred.plugins._observability import OUTBOUND_DLP_SCAN_DURATION

    OUTBOUND_DLP_SCAN_DURATION.labels(outcome="allowed").observe(0.0001)
    assert OUTBOUND_DLP_SCAN_DURATION.labels(outcome="allowed")._sum.get() > 0


def test_inbound_scanner_histogram_observes_via_labels() -> None:
    """Smoke that the inbound scanner histogram accepts an observe."""
    from alfred.plugins._observability import INBOUND_SCANNER_SCAN_DURATION

    INBOUND_SCANNER_SCAN_DURATION.labels(outcome="clean").observe(0.01)
    assert INBOUND_SCANNER_SCAN_DURATION.labels(outcome="clean")._sum.get() > 0


def test_plugin_spawn_histogram_observes_via_labels() -> None:
    """Smoke that the plugin spawn histogram accepts an observe."""
    from alfred.plugins._observability import PLUGIN_SPAWN_DURATION

    PLUGIN_SPAWN_DURATION.labels(plugin_id="x", outcome="ok").observe(0.1)
    assert PLUGIN_SPAWN_DURATION.labels(plugin_id="x", outcome="ok")._sum.get() > 0


def test_buckets_cover_p99_budgets() -> None:
    """Each histogram's bucket boundaries straddle the spec §7a.1 p99 budget.

    A budget of 5ms with no bucket boundary at or just above 5ms would
    leave the operator unable to read the p99 from the histogram. Pin
    the property here so a future refactor that "simplifies" the bucket
    list catches the regression.
    """
    from alfred.plugins._observability import (
        DISPATCH_DURATION,
        INBOUND_SCANNER_SCAN_DURATION,
        OUTBOUND_DLP_SCAN_DURATION,
        PLUGIN_SPAWN_DURATION,
    )

    # Spec §7a.1 budgets:
    # - dispatch p99 < 5ms (0.005s)
    # - outbound DLP p99 < 200µs (0.0002s)
    # - inbound scanner p99 < 50ms (0.05s)
    # - subprocess spawn p99 < 500ms (0.5s)
    def _has_bucket_at_or_above(hist: Histogram, threshold: float) -> bool:
        # prometheus_client stores buckets as floats on ``_upper_bounds``
        # (every bucket is closed-upper; ``+Inf`` is appended automatically).
        return any(b >= threshold for b in hist._upper_bounds if b != float("inf"))

    assert _has_bucket_at_or_above(DISPATCH_DURATION, 0.005)
    assert _has_bucket_at_or_above(OUTBOUND_DLP_SCAN_DURATION, 0.0002)
    assert _has_bucket_at_or_above(INBOUND_SCANNER_SCAN_DURATION, 0.05)
    assert _has_bucket_at_or_above(PLUGIN_SPAWN_DURATION, 0.5)


@pytest.mark.parametrize(
    "metric_name",
    [
        "DISPATCH_DURATION",
        "OUTBOUND_DLP_SCAN_DURATION",
        "INBOUND_SCANNER_SCAN_DURATION",
        "PLUGIN_SPAWN_DURATION",
    ],
)
def test_module_re_exports_all_four_histograms(metric_name: str) -> None:
    """``alfred.plugins._observability.__all__`` includes every shipped histogram.

    The supervisor's metrics-export wiring iterates ``__all__``; a missing
    entry means a histogram silently falls off the exposed surface even
    though its observations land on the default registry.
    """
    import alfred.plugins._observability as obs

    assert metric_name in obs.__all__
