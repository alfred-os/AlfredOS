"""Supervisor observability — Prometheus histogram + OTel sub-spans (spec §7a.3).

Pins the ``alfred_orchestrator_action_duration_seconds`` Histogram shape:

* Name matches the spec §7a.3 metric identifier verbatim.
* Label set is ``{user_id_bucket, action_outcome, breaker_state}`` — three
  bounded-cardinality labels. ``user_id_bucket`` is the perf-001 firewall
  against per-user series explosion in Prometheus.
* :func:`record_action_duration` accepts the raw ``user_id`` and buckets
  internally; callers never thread the bucket form themselves.
* :func:`bucket_user_id` is deterministic, returns a 2-hex-digit string,
  and caps the distinct-values count at :data:`_BUCKET_COUNT` regardless of
  the input cardinality.

The histogram itself is module-level (Prometheus collectors must be
singletons per name); these tests assert against ``_name`` / ``_labelnames``
to verify identity without triggering ``Duplicated timeseries`` registration
errors on re-import.

Cross-references:
* PR-S3-3a ``src/alfred/plugins/_observability.py`` — same pattern for
  ``alfred_stdio_transport_dispatch_seconds`` (the supervisor histogram is
  the orchestrator-action analogue of the transport-dispatch one).
* Plan task 13 (the source of these assertions).
"""

from __future__ import annotations

from unittest.mock import patch


def test_histogram_registered() -> None:
    """The histogram is constructed with the spec §7a.3 metric name."""
    from alfred.supervisor.observability import ACTION_DURATION_HISTOGRAM

    assert ACTION_DURATION_HISTOGRAM._name == "alfred_orchestrator_action_duration_seconds"


def test_histogram_labels() -> None:
    """Three labels exactly — bounded cardinality (perf-001)."""
    from alfred.supervisor.observability import ACTION_DURATION_HISTOGRAM

    label_names = ACTION_DURATION_HISTOGRAM._labelnames
    assert set(label_names) == {"user_id_bucket", "action_outcome", "breaker_state"}


def test_histogram_buckets_cover_30s_deadline() -> None:
    """Buckets include 30s (the spec §10.5 default deadline) and +Inf."""
    from alfred.supervisor.observability import ACTION_DURATION_HISTOGRAM

    # prometheus_client appends +Inf internally; ``_upper_bounds`` is the
    # full bucket list including the open right-edge.
    upper_bounds = ACTION_DURATION_HISTOGRAM._upper_bounds
    assert 30.0 in upper_bounds
    assert upper_bounds[-1] == float("inf")
    # Lowest bucket sub-10ms so p50/p90 on sub-second actions resolves well
    # (perf-013): smallest non-inf bound is <= 10ms.
    finite = [b for b in upper_bounds if b != float("inf")]
    assert min(finite) <= 0.01


def test_record_duration_success() -> None:
    """``record_action_duration`` accepts the success path keyword shape."""
    from alfred.supervisor.observability import record_action_duration

    # Must not raise — the call is the contract.
    record_action_duration(
        duration_seconds=0.5,
        user_id="user-a",
        action_outcome="success",
        breaker_state="CLOSED",
    )


def test_record_duration_timeout() -> None:
    """``record_action_duration`` accepts the timeout path keyword shape."""
    from alfred.supervisor.observability import record_action_duration

    record_action_duration(
        duration_seconds=30.0,
        user_id="user-b",
        action_outcome="timeout",
        breaker_state="OPEN",
    )


def test_record_duration_cancelled() -> None:
    """``record_action_duration`` accepts the cancelled path keyword shape."""
    from alfred.supervisor.observability import record_action_duration

    record_action_duration(
        duration_seconds=0.123,
        user_id="user-c",
        action_outcome="cancelled",
        breaker_state="HALF_OPEN",
    )


def test_bucket_user_id_bounded_cardinality() -> None:
    """``bucket_user_id`` returns a value in ``[0, _BUCKET_COUNT)`` (perf-001).

    1000 distinct user_ids must collapse into at most ``_BUCKET_COUNT``
    distinct labels — that's the unbounded-cardinality firewall.
    """
    from alfred.supervisor.observability import _BUCKET_COUNT, bucket_user_id

    user_ids = [f"user-{i}" for i in range(1000)]
    buckets = {bucket_user_id(uid) for uid in user_ids}
    assert len(buckets) <= _BUCKET_COUNT
    for b in buckets:
        assert len(b) == 2  # 2-hex-digit string
        int(b, 16)  # must be valid hex


def test_bucket_user_id_deterministic() -> None:
    """Same input yields the same bucket — pinning makes dashboards stable."""
    from alfred.supervisor.observability import bucket_user_id

    assert bucket_user_id("user-12345") == bucket_user_id("user-12345")
    # Different inputs are highly likely to land in different buckets, but
    # collisions are allowed (hash-based bucketing). Pinning here is about
    # idempotency, not uniqueness.


def test_record_duration_uses_bucket() -> None:
    """``record_action_duration`` buckets the user_id before labelling (perf-001).

    The raw ``user_id`` MUST NOT appear in the histogram label set or
    Prometheus's series cap (~10K) collapses on a few thousand users.
    """
    from alfred.supervisor.observability import record_action_duration

    with patch("alfred.supervisor.observability.ACTION_DURATION_HISTOGRAM") as mock_hist:
        record_action_duration(
            duration_seconds=0.3,
            user_id="user-12345",
            action_outcome="success",
            breaker_state="CLOSED",
        )
        call_kwargs = mock_hist.labels.call_args.kwargs
        assert call_kwargs["user_id_bucket"] != "user-12345"
        assert len(call_kwargs["user_id_bucket"]) == 2  # 2-hex bucket label
        assert call_kwargs["action_outcome"] == "success"
        assert call_kwargs["breaker_state"] == "CLOSED"
        mock_hist.labels.return_value.observe.assert_called_once_with(0.3)


def test_span_web_fetch_is_a_context_manager() -> None:
    """Sub-span shim for ``tool.web.fetch`` returns an entered/exited CM.

    PR-S3-3b ships these as no-op ``nullcontext`` shims; Slice-4 swaps in
    real OpenTelemetry spans without touching caller sites. The contract
    pinned here is "the helper exists and produces a context manager that
    enters and exits cleanly" — both branches of the migration satisfy it.
    """
    from alfred.supervisor.observability import span_web_fetch

    cm = span_web_fetch()
    with cm:
        pass  # contract is the protocol, not a returned span object


def test_span_quarantine_extract_is_a_context_manager() -> None:
    """Sub-span shim for ``security.quarantined.extract`` (spec §7a.3)."""
    from alfred.supervisor.observability import span_quarantine_extract

    with span_quarantine_extract():
        pass


def test_span_hookchain_is_a_context_manager() -> None:
    """Sub-span shim for ``hookchain_total`` (spec §7a.3)."""
    from alfred.supervisor.observability import span_hookchain

    with span_hookchain():
        pass
