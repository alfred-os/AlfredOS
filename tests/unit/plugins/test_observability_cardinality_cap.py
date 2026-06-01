"""perf-003: ``bucket_plugin_id`` caps the Prometheus label cardinality.

The ``plugin_id`` label on :data:`DISPATCH_DURATION` and
:data:`PLUGIN_SPAWN_DURATION` is an open vocabulary — any plugin
manifest declares its own id, and a runaway proposal loop / typo'd
manifest fleet can mint thousands of distinct values that all land in
the histogram label index. Without a cap that's a denial-of-service on
the operator's Prometheus + a label-explosion alert from cortex/mimir.

The defence under test: ``bucket_plugin_id`` maintains a fixed-size
allowlist of the first :data:`MAX_TRACKED_PLUGINS` distinct ids; every
subsequent id collapses into the single
:data:`PLUGIN_ID_OVERFLOW_BUCKET` series. Tests below pin:

* Within-allowlist ids round-trip unchanged.
* The 101st+ distinct id falls into the overflow bucket.
* The function is idempotent — repeated calls with the same id never
  expand the allowlist past its membership.
* The cap is configurable via :func:`MAX_TRACKED_PLUGINS` monkeypatch
  so future operator-tuning lands without code change to this module.
* The allowlist is process-wide (not per-transport / per-test) — the
  ``_reset_tracked_plugin_ids_for_test`` seam exists exactly so tests
  can avoid leaking state across modules.

Spec §7a.1 (label-cardinality discipline) + CLAUDE.md hard rule #7
(no silent failures): silently leaking thousands of label series IS
the silent failure — it does not crash the process; it slowly degrades
the observability stack until alerts stop firing.
"""

from __future__ import annotations

import pytest

from alfred.plugins._observability import (
    MAX_TRACKED_PLUGINS,
    PLUGIN_ID_OVERFLOW_BUCKET,
    _reset_tracked_plugin_ids_for_test,
    bucket_plugin_id,
)


@pytest.fixture(autouse=True)
def _reset_allowlist_around_each_test() -> None:
    """Start every test from an empty allowlist.

    The allowlist is module-level / process-lifetime in production; for
    the cap-hit tests below we need a known starting state, and the
    reset helper exists precisely for this purpose.
    """
    _reset_tracked_plugin_ids_for_test()


def test_first_seen_plugin_id_returned_unchanged() -> None:
    """A plugin id seen for the first time returns its own value.

    The allowlist starts empty; the first call admits the id.
    """
    assert bucket_plugin_id("alfred.web-fetch") == "alfred.web-fetch"


def test_repeated_plugin_id_returns_same_value() -> None:
    """Repeated calls with an already-tracked id are idempotent.

    No allocation, no allowlist growth — the membership check returns
    the id unchanged.
    """
    first = bucket_plugin_id("alfred.web-fetch")
    second = bucket_plugin_id("alfred.web-fetch")
    third = bucket_plugin_id("alfred.web-fetch")
    assert first == second == third == "alfred.web-fetch"


def test_distinct_plugin_ids_under_cap_each_round_trip() -> None:
    """The first ``MAX_TRACKED_PLUGINS`` distinct ids each return themselves.

    Within the allowlist the function behaves as identity. The 100-id
    walk below confirms there's no off-by-one at the cap boundary.
    """
    for i in range(MAX_TRACKED_PLUGINS):
        plugin_id = f"alfred.plugin_{i:04d}"
        assert bucket_plugin_id(plugin_id) == plugin_id, (
            f"plugin id #{i} unexpectedly bucketed before the cap"
        )


def test_plugin_id_past_cap_falls_into_overflow_bucket() -> None:
    """The ``MAX_TRACKED_PLUGINS + 1``-th distinct id buckets to ``"other"``.

    This is the firewall — without it, the Prometheus label index
    grows unboundedly with the plugin fleet.
    """
    for i in range(MAX_TRACKED_PLUGINS):
        bucket_plugin_id(f"alfred.plugin_{i:04d}")

    # The next distinct id is past the cap.
    overflow = bucket_plugin_id("alfred.plugin_overflow")
    assert overflow == PLUGIN_ID_OVERFLOW_BUCKET, (
        f"Expected past-cap id to bucket to {PLUGIN_ID_OVERFLOW_BUCKET!r}; got {overflow!r}"
    )


def test_already_tracked_id_keeps_returning_actual_value_after_cap_hit() -> None:
    """A within-cap id stays within-cap even after the overflow bucket fills.

    The membership check on already-tracked ids short-circuits before
    the cap check, so a healthy plugin's series does not silently move
    to ``"other"`` when a noisy neighbour saturates the allowlist.
    """
    bucket_plugin_id("alfred.web-fetch")
    # Saturate the rest of the allowlist.
    for i in range(MAX_TRACKED_PLUGINS - 1):
        bucket_plugin_id(f"alfred.filler_{i:04d}")
    # The allowlist is now full. Past-cap ids go to "other".
    assert bucket_plugin_id("alfred.new_plugin_1") == PLUGIN_ID_OVERFLOW_BUCKET
    assert bucket_plugin_id("alfred.new_plugin_2") == PLUGIN_ID_OVERFLOW_BUCKET
    # But the already-tracked id keeps its identity.
    assert bucket_plugin_id("alfred.web-fetch") == "alfred.web-fetch"


def test_overflow_bucket_string_is_lowercase_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The overflow bucket value is the exact string ``"other"``.

    Pinned because dashboards / alerting will key off the literal
    string; a refactor that changes it to ``"_other_"`` or ``"OTHER"``
    silently breaks the operator's dashboard filters.
    """
    monkeypatch.setattr("alfred.plugins._observability.MAX_TRACKED_PLUGINS", 1)
    # Force a cap-hit with the lowered ceiling.
    bucket_plugin_id("alfred.first")
    overflow = bucket_plugin_id("alfred.second")
    assert overflow == "other"


def test_cap_constant_lowered_via_monkeypatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cap can be tuned via monkeypatch for tests / operator config.

    Operators may want to raise the cap on a deployment with hundreds
    of plugins; pinning the monkeypatch behaviour confirms the lookup
    is dynamic (not captured at import time).
    """
    monkeypatch.setattr("alfred.plugins._observability.MAX_TRACKED_PLUGINS", 3)
    assert bucket_plugin_id("p1") == "p1"
    assert bucket_plugin_id("p2") == "p2"
    assert bucket_plugin_id("p3") == "p3"
    # 4th distinct id is past the lowered cap.
    assert bucket_plugin_id("p4") == PLUGIN_ID_OVERFLOW_BUCKET
