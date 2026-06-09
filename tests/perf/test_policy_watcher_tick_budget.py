"""PolicyWatcher ``_tick`` latency budget (PR-S4-4 closure perf-001).

Two budgets (ADR-0024 hardware budget; generous absolute caps, not delta-over-
baseline — the tick is millisecond-scale, not the microsecond-scale of the hook
dispatch benches):

* steady-state (cache-hit) path: ``< 5 ms`` p99 — the mtime gate short-circuits
  before any read.
* parse-and-swap path: ``< 50 ms`` p99 — full TOCTOU load + parse + validate +
  SHA + audit-then-swap.

A host-load tolerance guard skips under heavy contention so a noisy CI/dev box
does not flake the gate (mirrors the Slice-2.5 perf-gate hardening). The audit
+ hookpoint sinks are in-memory no-ops so the bench measures the watcher path,
not Postgres / the real hook chain.
"""

from __future__ import annotations

import asyncio
import os
import statistics
import time
from pathlib import Path
from typing import Any

import pytest

from alfred.policies.load import canonical_bytes, compute_sha256
from alfred.policies.model import PoliciesV1
from alfred.policies.snapshot_ref import PoliciesSnapshot, PoliciesSnapshotRef
from alfred.policies.watcher import PolicyWatcher

# Absolute p99 budgets (seconds).
_CACHE_HIT_BUDGET_S = 0.005
_PARSE_SWAP_BUDGET_S = 0.050

# Host-load tolerance: skip if the 1-min load average exceeds this multiple of
# the CPU count (a contended box produces meaningless p99s).
_LOAD_TOLERANCE = 4.0
_ITERATIONS = 200


def _host_overloaded() -> bool:
    getloadavg = getattr(os, "getloadavg", None)
    if getloadavg is None:  # pragma: no cover — Windows has no getloadavg
        return False
    one_min = getloadavg()[0]
    cpus = os.cpu_count() or 1
    return one_min > _LOAD_TOLERANCE * cpus


def _model(rate: int = 60) -> PoliciesV1:
    return PoliciesV1.model_validate(
        {
            "schema_version": 1,
            "rate_limits": {
                "web_fetch_per_user_per_hour": rate,
                "web_fetch_per_session_total": 200,
                "operator_daily_budget_usd": 5.0,
            },
            "handle_caps": {"web_fetch_max_concurrent_handles_per_user": 8},
            "high_blast": {
                "quarantined_provider_url": "https://quarantine.local/v1",
                "secret_broker_config_ref": "broker://default",
            },
        }
    )


class _NoopAudit:
    async def append_schema(self, **_kw: Any) -> None:
        return None


async def _noop_invoke(_name: str, _payload: dict[str, Any]) -> None:
    return None


def _snapshot(path: Path, model: PoliciesV1) -> PoliciesSnapshot:
    from datetime import UTC, datetime

    return PoliciesSnapshot(
        policies=model,
        loaded_at=datetime.now(UTC),
        file_mtime=path.stat().st_mtime,
        file_sha256=compute_sha256(canonical_bytes(model)),
        file_path=path.resolve(),
    )


def _p99(samples: list[float]) -> float:
    ordered = sorted(samples)
    # Linear-interpolation p99 (NumPy default semantic).
    rank = 0.99 * (len(ordered) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    frac = rank - lo
    return ordered[lo] + (ordered[hi] - ordered[lo]) * frac


@pytest.mark.skipif(_host_overloaded(), reason="host load too high for a stable p99")
def test_cache_hit_tick_under_budget(tmp_path: Path) -> None:
    cfg = tmp_path / "policies.yaml"
    model = _model()
    cfg.write_bytes(canonical_bytes(model))
    ref = PoliciesSnapshotRef(_snapshot(cfg, model))
    watcher = PolicyWatcher(
        config_path=cfg,
        snapshot_ref=ref,
        audit_writer=_NoopAudit(),
        invoke_fn=_noop_invoke,
    )

    async def _bench() -> list[float]:
        await watcher._tick()  # prime the (mtime, size) cache
        samples: list[float] = []
        for _ in range(_ITERATIONS):
            start = time.perf_counter()
            await watcher._tick()  # mtime unchanged -> cache-hit short-circuit
            samples.append(time.perf_counter() - start)
        return samples

    samples = asyncio.run(_bench())
    p99 = _p99(samples)
    assert p99 < _CACHE_HIT_BUDGET_S, (
        f"cache-hit _tick p99 {p99 * 1000:.3f}ms exceeds {_CACHE_HIT_BUDGET_S * 1000:.1f}ms "
        f"(median {statistics.median(samples) * 1000:.3f}ms)"
    )


@pytest.mark.skipif(_host_overloaded(), reason="host load too high for a stable p99")
def test_parse_swap_tick_under_budget(tmp_path: Path) -> None:
    cfg = tmp_path / "policies.yaml"
    model = _model()
    cfg.write_bytes(canonical_bytes(model))
    ref = PoliciesSnapshotRef(_snapshot(cfg, model))
    watcher = PolicyWatcher(
        config_path=cfg,
        snapshot_ref=ref,
        audit_writer=_NoopAudit(),
        invoke_fn=_noop_invoke,
    )

    async def _bench() -> list[float]:
        samples: list[float] = []
        for i in range(_ITERATIONS):
            # Alternate the rate so each tick is a genuine parse-and-swap (new SHA).
            cfg.write_bytes(canonical_bytes(_model(rate=60 + (i % 2) + 2 * i)))
            future = time.time() + 10_000 + i
            os.utime(cfg, (future, future))
            start = time.perf_counter()
            await watcher._tick()
            samples.append(time.perf_counter() - start)
        return samples

    # The rate-limit key is high-blast (ADR-0023 §5), so a production tick on
    # this edit refuses. To measure the heavier parse-AND-SWAP path the budget
    # exists for, allowlist the key under test for the benchmark window only —
    # mirrors the unit-suite ``allowlisted`` helper; the production allowlist is
    # untouched.
    import alfred.policies.watcher as watcher_mod

    original_allowlist = watcher_mod.LOW_BLAST_ALLOWLIST
    watcher_mod.LOW_BLAST_ALLOWLIST = original_allowlist | frozenset(  # type: ignore[assignment]
        {"rate_limits.web_fetch_per_user_per_hour"}
    )
    try:
        samples = asyncio.run(_bench())
    finally:
        watcher_mod.LOW_BLAST_ALLOWLIST = original_allowlist  # type: ignore[assignment]
    p99 = _p99(samples)
    assert p99 < _PARSE_SWAP_BUDGET_S, (
        f"parse-swap _tick p99 {p99 * 1000:.3f}ms exceeds {_PARSE_SWAP_BUDGET_S * 1000:.1f}ms "
        f"(median {statistics.median(samples) * 1000:.3f}ms)"
    )
