"""Smoke test (Task 2) + the BLOCKING oracle-independent /metrics leak-guard (Task 3, #470).

The leak-guard below is the DLP-equivalent control for the new outbound-shaped
disclosure surface the core's ``/metrics`` endpoint is (CLAUDE.md HARD rule 4
analog): it pins the exact metric families + declared label keys the core
exposes so a future collector — or a future label — cannot silently widen the
surface. ``_EXPECTED_FAMILIES`` / ``_EXPECTED_DECLARED_LABELS`` are
independently-authored literals, NOT derived from ``CORE_OWNED_COLLECTORS`` —
deriving them from the same source under test would be a tautological oracle
that passes through a widened surface undetected.
"""

from prometheus_client import generate_latest
from prometheus_client.parser import text_string_to_metric_families

from alfred.observability.core_metrics import CORE_OWNED_COLLECTORS, build_core_registry


def test_build_core_registry_serves_the_capability_counter():
    reg = build_core_registry()
    families = {f.name for f in text_string_to_metric_families(generate_latest(reg).decode())}
    assert "alfred_quarantine_capability_revoked" in families  # parser strips the Counter's _total


def test_ten_core_collectors():
    assert len(CORE_OWNED_COLLECTORS) == 10


# Reviewed allowlist in the PARSER's naming (counters WITHOUT _total; _created filtered).
# Frozen against the actual exposition (Step 2) — a human reviews this literal.
_EXPECTED_FAMILIES: frozenset[str] = frozenset(
    {
        "alfred_quarantine_capability_revoked",  # Counter — parser strips _total
        "alfred_comms_inbound_dispatch_seconds",
        "alfred_comms_quarantined_extract_seconds",
        "alfred_comms_burst_limiter_wait_seconds",
        "alfred_comms_handler_failures",  # Counter — parser strips _total
        "alfred_orchestrator_action_duration_seconds",
        "alfred_stdio_transport_dispatch_seconds",
        "alfred_plugin_spawn_seconds",
        "alfred_outbound_dlp_scan_seconds",
        "alfred_inbound_scanner_scan_seconds",
    }
)

# Declared label names, keyed on the collector's stored base name (`_name`). Present at t=0
# even with zero children — this is the value-boundedness invariant's enforcement (spec §5.2).
_EXPECTED_DECLARED_LABELS: dict[str, frozenset[str]] = {
    "alfred_orchestrator_action_duration_seconds": frozenset(
        {"user_id_bucket", "action_outcome", "breaker_state"}
    ),
    "alfred_stdio_transport_dispatch_seconds": frozenset({"plugin_id", "method_shape", "outcome"}),
    "alfred_plugin_spawn_seconds": frozenset({"plugin_id", "outcome"}),
    "alfred_outbound_dlp_scan_seconds": frozenset({"outcome"}),
    "alfred_inbound_scanner_scan_seconds": frozenset({"outcome"}),
    # every other core family declares NO labels (defaults to frozenset()).
}


def _exposed_family_names() -> set[str]:
    text = generate_latest(build_core_registry()).decode()
    return {f.name for f in text_string_to_metric_families(text) if not f.name.endswith("_created")}


def test_no_leak_no_stale_family():
    exposed = _exposed_family_names()
    assert exposed == set(_EXPECTED_FAMILIES), (
        f"extra={exposed - set(_EXPECTED_FAMILIES)} missing={set(_EXPECTED_FAMILIES) - exposed}"
    )
    assert not any(n.startswith("gateway_") for n in exposed), "gateway_* leaked onto core /metrics"


def test_declared_label_keys_bounded():
    # Read declared label names off the collector objects (robust at t=0 with no children —
    # a labeled family exposes no label keys in the exposition text until first `.labels(...)`).
    for c in CORE_OWNED_COLLECTORS:
        declared = frozenset(c._labelnames)  # prometheus_client stores the declared labels here
        expected = _EXPECTED_DECLARED_LABELS.get(c._name, frozenset())
        assert declared == expected, f"{c._name} declares labels {declared} != reviewed {expected}"


def test_source_of_truth_count_matches_reviewed_literal():
    # A collector added to CORE_OWNED_COLLECTORS without updating the reviewed literal fails here.
    assert len(CORE_OWNED_COLLECTORS) == len(_EXPECTED_FAMILIES)
