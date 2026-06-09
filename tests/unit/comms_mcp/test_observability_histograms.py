"""The four PR-S4-8 comms Prometheus histograms exist and observe (Task 62).

Spec §13 done-item 7 names four metrics that must appear under ``/metrics``
once the comms path runs:

* ``alfred_comms_inbound_dispatch_seconds``
* ``alfred_comms_quarantined_extract_seconds``
* ``alfred_comms_burst_limiter_wait_seconds``
* ``alfred_comms_handler_failures_total``

This module pins their names + that an observe / increment moves the sample
count. The histograms register on the default ``CollectorRegistry`` at import,
so a duplicate-name regression (two modules constructing the same metric) is a
loud ``Duplicated timeseries`` ImportError this test would surface.
"""

from __future__ import annotations

from prometheus_client import REGISTRY

from alfred.comms_mcp import observability


def _sample_count(metric_name: str) -> float:
    """Return the current ``*_count`` sample for a histogram / counter."""
    value = REGISTRY.get_sample_value(f"{metric_name}_count")
    return value if value is not None else 0.0


def test_all_four_histograms_named() -> None:
    assert observability.INBOUND_DISPATCH_HISTOGRAM._name == "alfred_comms_inbound_dispatch_seconds"
    assert (
        observability.QUARANTINED_EXTRACT_HISTOGRAM._name
        == "alfred_comms_quarantined_extract_seconds"
    )
    wait_name = observability.BURST_LIMITER_WAIT_HISTOGRAM._name
    assert wait_name == "alfred_comms_burst_limiter_wait_seconds"
    # prometheus_client strips the ``_total`` suffix from a Counter's internal
    # ``_name``; the exposed sample is ``..._total`` (asserted in the increment
    # test below via ``get_sample_value``).
    assert observability.HANDLER_FAILURES_COUNTER._name == "alfred_comms_handler_failures"


def test_record_inbound_dispatch_observes() -> None:
    before = _sample_count("alfred_comms_inbound_dispatch_seconds")
    observability.record_inbound_dispatch_seconds(0.01)
    after = _sample_count("alfred_comms_inbound_dispatch_seconds")
    assert after == before + 1


def test_record_quarantined_extract_observes() -> None:
    before = _sample_count("alfred_comms_quarantined_extract_seconds")
    observability.record_quarantined_extract_seconds(0.02)
    after = _sample_count("alfred_comms_quarantined_extract_seconds")
    assert after == before + 1


def test_record_burst_limiter_wait_observes() -> None:
    before = _sample_count("alfred_comms_burst_limiter_wait_seconds")
    observability.record_burst_limiter_wait_seconds(0.0)
    after = _sample_count("alfred_comms_burst_limiter_wait_seconds")
    assert after == before + 1


def test_record_handler_failure_increments() -> None:
    before = REGISTRY.get_sample_value("alfred_comms_handler_failures_total") or 0.0
    observability.record_handler_failure()
    after = REGISTRY.get_sample_value("alfred_comms_handler_failures_total") or 0.0
    assert after == before + 1
