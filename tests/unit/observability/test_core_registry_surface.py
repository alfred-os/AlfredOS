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

import ast
from pathlib import Path

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


# ---------------------------------------------------------------------------
# arch-002: the OTHER direction — completeness, not just leakage.
#
# Every guard above is a LEAK guard: it fails when the exposed surface is WIDER
# than reviewed. But `CORE_OWNED_COLLECTORS` is an opt-in ALLOWLIST, and all four
# tests above close over the same reviewed literals — so a new `alfred_*` metric
# that someone registers but forgets to add to the tuple is silently UNEXPOSED
# with every gate green. That is verbatim the dead-metric class #470 exists to
# fix (`alfred_quarantine_capability_revoked_total` incremented for months with
# nothing serving it), reintroduced one metric at a time.
#
# The oracle is deliberately INDEPENDENT of `CORE_OWNED_COLLECTORS`: it derives
# the population of declared `alfred_*` families by parsing the SOURCE TREE for
# prometheus collector constructions, so it cannot be satisfied by the allowlist
# agreeing with itself.
# ---------------------------------------------------------------------------

_SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "alfred"

# The prometheus_client collector constructors whose FIRST positional argument is the
# metric family name.
_COLLECTOR_CTORS: frozenset[str] = frozenset(
    {"Counter", "Gauge", "Histogram", "Summary", "Info", "Enum"}
)

# Declared `alfred_*` families that are deliberately NOT on the core /metrics endpoint.
# EMPTY by design: today every `alfred_*` family in the tree is core-owned and exposed.
# A future entry here needs a one-line justification naming why the family is core-PRIVATE
# (e.g. registered only inside a short-lived subprocess whose registry is never served).
# An unjustified entry is how this guard rots back into the allowlist it replaces.
_DELIBERATELY_UNEXPOSED: dict[str, str] = {}


def _declared_alfred_family_names() -> dict[str, str]:
    """Every ``alfred_*`` metric family declared under ``src/alfred``, mapped to its file.

    Parses with :mod:`ast` rather than importing the world: importing every module that
    might register a collector would drag in the whole core graph (and re-register
    collectors on the default registry as a side effect), while the DEFAULT registry's
    population depends on whatever pytest happened to import first — a non-deterministic
    oracle. What a metric family IS, by contrast, is a literal string in a constructor call.

    Names are normalised the way ``prometheus_client`` normalises them (a Counter declared
    ``..._total`` stores ``_name`` without the suffix), so they compare directly against the
    collector objects.
    """
    declared: dict[str, str] = {}
    for path in _SRC_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name not in _COLLECTOR_CTORS:
                continue
            first = node.args[0]
            if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
                continue
            family = first.value
            if not family.startswith("alfred_"):
                continue
            declared[family.removesuffix("_total")] = str(path.relative_to(_SRC_ROOT))
    return declared


def test_declared_alfred_metrics_are_all_core_exposed():
    declared = _declared_alfred_family_names()
    # Sanity floor: if the AST walk silently stopped finding anything (a refactor to a
    # factory helper, a moved source root), the completeness assertion below would pass
    # VACUOUSLY. Pin that the oracle still sees the population it is meant to police.
    assert len(declared) >= len(CORE_OWNED_COLLECTORS), (
        f"the source-tree scan found only {len(declared)} alfred_* families "
        f"({sorted(declared)}) — fewer than the {len(CORE_OWNED_COLLECTORS)} curated "
        "collectors, so it is no longer seeing how metrics are declared. Fix the scan."
    )
    exposed = {c._name for c in CORE_OWNED_COLLECTORS}
    missing = {
        family: where
        for family, where in declared.items()
        if family not in exposed and family not in _DELIBERATELY_UNEXPOSED
    }
    assert not missing, (
        "these alfred_* metric families are declared but NOT exposed on the core /metrics "
        f"endpoint — add them to CORE_OWNED_COLLECTORS (or to _DELIBERATELY_UNEXPOSED with a "
        f"justification): {missing}"
    )


def test_unexposed_exclusions_are_all_justified():
    """An exclusion without a reason is an allowlist entry wearing a disguise."""
    for family, reason in _DELIBERATELY_UNEXPOSED.items():
        assert reason.strip(), f"{family} is excluded from the core exposition with no reason"
