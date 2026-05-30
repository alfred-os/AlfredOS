"""Shared fixtures + helpers for ``tests/perf/`` — Slice-2.5 PR-C Task 2.

This module bundles the three pieces every dispatch-overhead bench in
``tests/perf/test_hook_dispatch_perf.py`` consumes:

* :data:`_run` — a module-level :class:`asyncio.Runner` reused across
  every bench AND the same-loop baseline. Loop construction cost is the
  single largest source of run-to-run variance in a micro-bench of an
  ``await`` chain; reusing one runner makes the cost cancel in the
  ``p99(measured) - p99(baseline)`` delta the gate keys off (see
  :func:`baseline_delta`).
* :func:`baseline_delta` — pure function over two pytest-benchmark
  ``Stats`` objects. Returns ``p99(measured) - p99(baseline)`` in
  seconds. p99 is computed from :attr:`Stats.sorted_data` because
  pytest-benchmark's ``Stats`` class exposes only min / max / mean /
  median / iqr / q1 / q3 (see ``Stats.fields`` — no percentile
  attribute), so the bench is responsible for picking the percentile
  it gates on. Linear-interpolation p99 is the canonical choice — it
  matches NumPy's default ``percentile`` semantic and survives a
  hardware switch better than ``sorted_data[int(0.99 * N)]``.
* :func:`fresh_registry` / :func:`fresh_registry_allow_system` —
  REDEFINED locally (mirroring the PR-B precedent at
  ``tests/unit/memory/test_episodic_hooks_wiring.py:173``). Cross-tree
  conftest discovery does NOT propagate ``tests/unit/hooks/conftest.py``
  to this directory: pytest only walks the path from rootdir DOWN to
  the test file, never sideways. Copying the fixture body keeps the
  swap-and-restore discipline (CLAUDE.md hard rule #4 — never stub the
  capability gate with an always-allow shim) without depending on a
  fixture import that pytest would refuse to discover.

Async-wrap pattern (the Task-1 spike's documented form):

  pytest-benchmark's :func:`BenchmarkFixture.pedantic` accepts a SYNC
  callable. The dispatch path under measurement is async — every
  subscriber, the registry sink, and :func:`alfred.hooks.invoke` itself
  are coroutines. We bridge with::

      def bench_target() -> None:
          _run.run(_do_one_dispatch())

      async def _do_one_dispatch() -> None:
          await mem.record(...)

      benchmark.pedantic(bench_target, rounds=..., iterations=..., warmup_rounds=...)

  ``_run = asyncio.Runner()`` is module-level so the same runner drives
  every round of every bench AND the baseline. The loop construction
  cost (``asyncio.new_event_loop`` + ``set_event_loop`` + the runner's
  internal lazy state) lands ONCE at module-import time and is then
  amortised across hundreds of measured rounds. The baseline bench
  uses the SAME runner, so the loop-driver overhead p99 contributes
  IDENTICALLY to both samples and cancels in the delta.

  Why a Runner not ``asyncio.run`` per round: ``asyncio.run`` creates
  a fresh loop on every call, which is 50-200 microseconds of pure
  overhead on a modern CPU — bigger than the budget the gate enforces.
  ``Runner.run`` reuses the loop and pays the dispatch hop only.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from typing import Any

import pytest

from alfred.hooks.capability import DevGate
from alfred.hooks.registry import OPEN_TIERS, HookRegistry, get_registry, set_registry

# Pinned bench knobs — mirrored from
# ``tests/perf/test_hook_dispatch_perf.py``. Centralising them lets the
# session-scoped :func:`baseline_p99` fixture run its own measurement
# with the SAME shape (rounds x iterations x warmup) the budgeted
# benches use, so the resulting p99 is directly comparable to theirs
# under the delta-over-baseline gate.
_BASELINE_ROUNDS: int = 100
_BASELINE_ITERATIONS: int = 20
_BASELINE_WARMUP_ROUNDS: int = 5

# Module-level asyncio runner. Constructed ONCE at import; reused across
# every bench (including the baseline). See module docstring for the
# rationale — loop construction cost cancels in the
# ``p99(measured) - p99(baseline)`` delta when both samples share a
# runner.
#
# NOT a fixture because pytest fixtures construct per-test (or per-
# session); a per-test runner would re-pay the loop-creation cost on
# every test invocation, which is exactly the variance the spike's
# shared-runner pattern eliminates. The module-level attribute is the
# single legitimate exception to "no module-level state in tests" —
# the runner is configuration of the bench harness, not test state.
_run: asyncio.Runner = asyncio.Runner()
"""Shared :class:`asyncio.Runner` driving every measured dispatch.

Reused across the baseline bench AND every dispatch-overhead bench so
the loop-driver overhead contributes identically to both p99 samples
and cancels in :func:`baseline_delta`. See module docstring for the
full async-wrap pattern.
"""


def _p99_from_sorted(sorted_data: list[float]) -> float:
    """Linear-interpolation p99 from a pre-sorted list (seconds).

    Shared math kernel for :func:`_p99` (pytest-benchmark stats holder
    path) and :func:`baseline_p99` (hand-rolled ``perf_counter_ns``
    path). Centralising this means a future change to the percentile
    interpolation propagates to both call sites uniformly — the prior
    duplicated bodies would have drifted otherwise.

    Linear interpolation formula (NumPy's default, "linear" method):
        index = (N - 1) * p   where p = 0.99
        lower = floor(index)
        upper = ceil(index)
        if lower == upper: return sorted_data[lower]
        frac = index - lower
        return sorted_data[lower] + (sorted_data[upper] - sorted_data[lower]) * frac

    Args:
        sorted_data: Pre-sorted list of samples (seconds).

    Returns:
        Linear-interpolation p99 in seconds.

    Raises:
        ValueError: If ``sorted_data`` is empty — no samples to compute
            a percentile over.
    """
    n = len(sorted_data)
    if n == 0:
        raise ValueError("_p99_from_sorted: empty list — no samples")
    if n == 1:
        return float(sorted_data[0])
    p = 0.99
    index = (n - 1) * p
    lower = int(index)  # floor
    upper = min(lower + 1, n - 1)
    if lower == upper:
        return float(sorted_data[lower])
    frac = index - lower
    return float(sorted_data[lower] + (sorted_data[upper] - sorted_data[lower]) * frac)


def baseline_delta(measured: Any, baseline: Any) -> float:
    """Return ``p99(measured) - p99(baseline)`` in seconds.

    Pure function over two pytest-benchmark ``Stats`` objects (the
    ``benchmark.stats.stats`` field on the :class:`BenchmarkFixture`).
    The Stats class exposes ``sorted_data`` (the sorted list of every
    round's measurement, in seconds) but NOT a percentile attribute —
    so we compute linear-interpolation p99 here from ``sorted_data``.

    Linear interpolation matches NumPy's default ``percentile`` semantic
    and is the canonical choice for a small N: with ``rounds=100`` the
    99th percentile lands BETWEEN ``sorted_data[98]`` and
    ``sorted_data[99]`` (index 99 * 0.99 = 98.01), so interpolation
    gives a more stable value than a naive ``sorted_data[int(0.99 * N)]``
    pick. The same formula is used for both inputs so any indexing
    quirk cancels in the delta.

    Args:
        measured: The :class:`BenchmarkFixture` (or its ``.stats.stats``
            substructure) from a dispatch bench.
        baseline: Same shape, from the baseline bench.

    Returns:
        The p99 delta in seconds. May be NEGATIVE if the measured
        bench's tail was lower than the baseline's — which can happen
        when the dispatch path is dominated by zero-subscriber lookup
        overhead and the baseline noop's first runs warm the runner.
        The budget assertions in the bench file treat negative deltas
        as "trivially within budget" — see each bench's docstring.
    """
    return _p99(measured) - _p99(baseline)


def _p99(stats_holder: Any) -> float:
    """Compute linear-interpolation p99 from a pytest-benchmark stats holder.

    Accepts either a :class:`BenchmarkFixture` (in which case we walk
    ``.stats.stats.sorted_data``) or the inner ``Stats`` object (in
    which case we read ``.sorted_data`` directly). Centralising the
    walk here lets the bench file pass either shape without caring
    which layer is which.

    The walk uses ``sorted_data`` rather than ``data`` because the
    sorted-by-value list is what NumPy-style percentile interpolation
    needs; the raw insertion-order list would require an extra sort
    per call.

    Linear interpolation formula (NumPy's default, "linear" method):
        index = (N - 1) * p   where p = 0.99
        lower = floor(index)
        upper = ceil(index)
        if lower == upper: return sorted_data[lower]
        frac = index - lower
        return sorted_data[lower] + (sorted_data[upper] - sorted_data[lower]) * frac

    Args:
        stats_holder: Either a :class:`BenchmarkFixture` or its inner
            ``Stats``. The function walks the attribute chain to find
            ``sorted_data``.

    Returns:
        Linear-interpolation p99 in seconds.

    Raises:
        AttributeError: If neither shape exposes ``sorted_data`` — i.e.
            pytest-benchmark's internals shifted under us. The loud
            failure is intentional (CLAUDE.md hard rule #7).
        ValueError: If ``sorted_data`` is present but empty (the bench
            produced no samples).
    """
    # Walk to the Stats object that owns ``sorted_data``. The fixture
    # exposes ``.stats`` (a Metadata) which exposes ``.stats`` (the real
    # Stats); the inner Stats exposes ``.sorted_data`` directly.
    if hasattr(stats_holder, "sorted_data"):
        sorted_data = stats_holder.sorted_data
    elif hasattr(stats_holder, "stats") and hasattr(stats_holder.stats, "sorted_data"):
        sorted_data = stats_holder.stats.sorted_data
    elif (
        hasattr(stats_holder, "stats")
        and hasattr(stats_holder.stats, "stats")
        and hasattr(stats_holder.stats.stats, "sorted_data")
    ):
        sorted_data = stats_holder.stats.stats.sorted_data
    else:
        raise AttributeError(
            "_p99: could not find sorted_data on the stats holder; "
            "pytest-benchmark's Stats internals may have shifted. "
            "Inspect the holder shape and update _p99."
        )

    # Delegate percentile math to the shared helper so a future change
    # to the interpolation propagates uniformly to ``baseline_p99``.
    return _p99_from_sorted(list(sorted_data))


def _declare_bench_hookpoints(registry: HookRegistry) -> None:
    """Declare every hookpoint the perf benches register subscribers on.

    The benches drive :meth:`EpisodicMemory.record` which invokes the
    five episodic hookpoints — production-side declarations happen in
    :func:`alfred.memory.episodic.declare_hookpoints`. But the benches
    also register their OWN pass-through subscribers on
    ``before_validate`` BEFORE constructing the
    :class:`EpisodicMemory` (the fixture-then-test ordering pytest
    enforces). Under the production-strict default
    (``strict_declarations=True``), the bench's register call would
    fail because the publisher hasn't run its module-init declaration
    against this fresh registry yet.

    The fix mirrors how production publishers will use the API: the
    fixture declares the hookpoint on the fresh registry BEFORE any
    subscriber-register call. The values match the
    :func:`alfred.memory.episodic.declare_hookpoints` defaults for
    ``before_validate`` so the bench measurement reflects the same
    metadata-lookup cost a production dispatch would pay.

    Only ``before_validate`` needs an upfront declaration here — the
    other four hookpoints are declared by
    :func:`alfred.memory.episodic.declare_hookpoints` when
    :class:`EpisodicMemory.__init__` runs (idempotent on equal meta).
    """
    registry.register_hookpoint(
        name="before_validate",
        subscribable_tiers=OPEN_TIERS,
        refusable_tiers=OPEN_TIERS,
        fail_closed=False,
    )


@pytest.fixture
def fresh_registry() -> Iterator[HookRegistry]:
    """Yield a brand-new :class:`HookRegistry` installed as the singleton.

    REDEFINED locally — mirrors the canonical fixture at
    ``tests/unit/hooks/conftest.py:93`` and the PR-B precedent at
    ``tests/unit/memory/test_episodic_hooks_wiring.py:173``. Cross-tree
    conftest discovery doesn't propagate to this directory; copying the
    fixture body keeps the swap-and-restore discipline (CLAUDE.md hard
    rule #4 — never stub the capability gate with an always-allow shim).

    The gate is a default :class:`DevGate` (``allow_system=False``); the
    sink is the registry's own default :class:`StructlogAuditSink`. The
    pre-test singleton is captured at fixture entry and restored on
    teardown so the perf bench cannot leak subscribers into a sibling
    test run.

    Strict declarations: the registry runs with the production default
    (``strict_declarations=True``). :func:`_declare_bench_hookpoints`
    declares ``before_validate`` upfront so the bench's pass-through
    subscriber registrations pass the strict gate exactly as a
    production publisher's would. Aligning the bench with the
    publisher-declares-first ordering preserves strict-mode dispatch
    measurement — see Group C in the #119 review report.
    """
    prior = get_registry()
    registry = HookRegistry(gate=DevGate())
    _declare_bench_hookpoints(registry)
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


@pytest.fixture
def fresh_registry_allow_system() -> Iterator[HookRegistry]:
    """Like :func:`fresh_registry` but the gate accepts the ``system`` tier.

    REDEFINED locally — same rationale as :func:`fresh_registry`. Used
    by benches that legitimately register a ``system``-tier subscriber
    (e.g. a DLP-style refuser on the 5-subscriber chain bench, should
    a future regression need it).
    """
    prior = get_registry()
    registry = HookRegistry(gate=DevGate(allow_system=True))
    _declare_bench_hookpoints(registry)
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


# ──────────────────────────────────────────────────────────────────────
# Session-scoped baseline measurement
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def baseline_p99() -> float:
    """Measure the same-loop noop p99 once per session.

    Replaces the prior module-level ``_BASELINE_P99`` global plus its
    collection-order dependency on ``test_baseline_noop_delta_floor``.
    Any bench (or assertion test) that needs the baseline floor takes
    this fixture as a parameter; pytest's session-scoped caching means
    the measurement runs ONCE per session even if every budgeted bench
    requests it.

    The measurement mirrors the pinned bench shape (rounds, iterations,
    warmup) so its p99 is directly comparable to the budgeted benches'
    p99s under :func:`baseline_delta`. We do NOT use the
    ``pytest-benchmark`` ``BenchmarkFixture`` here because that fixture
    is function-scoped — a session-scoped fixture can't take it as a
    dependency. Instead we drive the SAME ``_run.run(_noop())`` loop
    by hand with :func:`time.perf_counter_ns` and apply the SAME linear-
    interpolation p99 formula :func:`_p99` uses for benchmark output —
    so a future change to the percentile interpolation propagates to
    both the baseline and the dispatch deltas uniformly.

    Returns:
        Linear-interpolation p99 of the per-round noop dispatch in
        SECONDS. Mirrors the unit the budgeted benches' ``baseline_delta``
        consumes.

    Raises:
        RuntimeError: If the measurement collapsed to a non-finite or
            non-positive p99 — the loud-failure escape the prior
            module-level ``test_baseline_noop_delta_floor`` tripwires
            performed. CLAUDE.md hard rule #7.
    """

    async def _noop() -> None:
        return None

    # Warmup — drive the same Runner the budgeted benches drive so the
    # event-loop's lazy state lands before the measured rounds start.
    # Each warmup round runs ``_ITERATIONS`` noops, matching the
    # pytest-benchmark ``pedantic`` shape.
    for _ in range(_BASELINE_WARMUP_ROUNDS):
        for _ in range(_BASELINE_ITERATIONS):
            _run.run(_noop())

    # Measure — one timing per round; each round drives ``_ITERATIONS``
    # noops and we record the mean per-iteration time per round (the
    # pytest-benchmark convention).
    per_round_seconds: list[float] = []
    for _ in range(_BASELINE_ROUNDS):
        start_ns = time.perf_counter_ns()
        for _ in range(_BASELINE_ITERATIONS):
            _run.run(_noop())
        end_ns = time.perf_counter_ns()
        per_round_seconds.append((end_ns - start_ns) / _BASELINE_ITERATIONS / 1e9)

    # Linear-interpolation p99 — same formula as :func:`_p99`, shared
    # via :func:`_p99_from_sorted` so the two paths cannot drift.
    p99 = _p99_from_sorted(sorted(per_round_seconds))

    # Tripwires — match the prior module-level test's loud-failure
    # contract. A NaN baseline would silently pass downstream budget
    # checks because ``<`` against NaN resolves to False.
    import math

    if not math.isfinite(p99):
        raise RuntimeError(
            f"baseline_p99 fixture: p99 not finite (got {p99!r}); "
            f"the async runner is mis-wired or perf_counter_ns is broken."
        )
    if p99 <= 0.0:
        raise RuntimeError(
            f"baseline_p99 fixture: p99 must be > 0 (got {p99!r}); "
            f"a zero or negative sample means the timer is broken — "
            f"refuse to silently pass downstream budget checks."
        )
    return p99
