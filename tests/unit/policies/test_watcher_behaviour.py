"""PolicyWatcher behaviour matrix (PR-S4-4 Component C, Task 10).

Drives ``_tick`` directly over a real ``tmp_path`` file. Covers the mtime
gate, the SHA short-circuit, every rejection branch, the high-blast refusal,
the audit-write-failed fallback, and the degraded/recovered state machine.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from ._watcher_harness import (
    allowlisted,
    build_watcher,
    isolated_fallback,
    make_policies,
    write_policies,
)

# The dotted key a machinery test allowlists to drive the *applied* swap path
# without weakening the production (empty) low-blast allowlist (ADR-0023 §5).
_RATE_KEY = "rate_limits.web_fetch_per_user_per_hour"

pytestmark = pytest.mark.asyncio

_REJECTED = "CONFIG_RELOAD_REJECTED_FIELDS"
_APPLIED = "CONFIG_RELOAD_FIELDS"


def _bump_mtime(path: Path) -> None:
    future = time.time() + 5
    os.utime(path, (future, future))


async def test_allowlisted_change_swaps_and_emits_applied(tmp_path: Path) -> None:
    """An *allowlisted* key change hot-reloads (the applied path still works).

    The production allowlist is empty, so this test injects the key under test
    to drive the swap machinery; the refusal of the same edit under the
    default-empty allowlist is pinned by
    ``test_rate_limit_change_refused_by_default``.
    """
    watcher, ref, audit, invoker = build_watcher(tmp_path)
    new = make_policies(rate_limits={"web_fetch_per_user_per_hour": 120})
    write_policies(watcher._path, new)
    _bump_mtime(watcher._path)
    with allowlisted(_RATE_KEY):
        await watcher._tick()
    assert ref.current().policies.rate_limits.web_fetch_per_user_per_hour == 120
    assert audit.subjects_for(_APPLIED)
    assert invoker.count("supervisor.config_reload") == 1


async def test_rate_limit_change_refused_by_default(tmp_path: Path) -> None:
    """KEYSTONE (ADR-0023 §5 / arch-003): a rate-limit edit REFUSES hot-reload.

    With the empty production low-blast allowlist, shrinking/widening
    ``web_fetch_per_user_per_hour`` (DoS / anti-abuse bypass) is high-blast and
    must be refused — NOT applied silently with ``config.reload.applied``.
    """
    watcher, ref, audit, invoker = build_watcher(tmp_path)
    active = ref.current()
    new = make_policies(rate_limits={"web_fetch_per_user_per_hour": 0})
    write_policies(watcher._path, new)
    _bump_mtime(watcher._path)
    await watcher._tick()
    subjects = audit.subjects_for(_REJECTED)
    assert subjects and subjects[-1]["reason"] == "high_blast_change"
    assert subjects[-1]["offending_key"] == _RATE_KEY
    # Refusal is total: no applied row, active snapshot byte-identical.
    assert audit.subjects_for(_APPLIED) == []
    assert ref.current() is active
    assert invoker.count("supervisor.config_reload_rejected") == 1
    assert invoker.count("supervisor.config_reload") == 0


async def test_handle_cap_change_refused_by_default(tmp_path: Path) -> None:
    """A ``handle_caps.*`` edit is high-blast and refuses hot-reload (arch-003)."""
    watcher, ref, audit, _ = build_watcher(tmp_path)
    active = ref.current()
    new = make_policies(handle_caps={"web_fetch_max_concurrent_handles_per_user": 9999})
    write_policies(watcher._path, new)
    _bump_mtime(watcher._path)
    await watcher._tick()
    subjects = audit.subjects_for(_REJECTED)
    assert subjects and subjects[-1]["reason"] == "high_blast_change"
    assert subjects[-1]["offending_key"] == "handle_caps.web_fetch_max_concurrent_handles_per_user"
    assert ref.current() is active


async def test_burst_limiter_nested_change_refused_by_default(tmp_path: Path) -> None:
    """A nested ``quarantined_extract_per_user_persona.*`` edit refuses (arch-003).

    The burst-limiter capacity is the anti-abuse knob PR-S4-8 consumes; an edit
    to its nested ``capacity_tokens`` must not slip through the low-blast
    channel.
    """
    watcher, ref, audit, _ = build_watcher(tmp_path)
    active = ref.current()
    new = make_policies(
        rate_limits={"quarantined_extract_per_user_persona": {"capacity_tokens": 100}}
    )
    write_policies(watcher._path, new)
    _bump_mtime(watcher._path)
    await watcher._tick()
    subjects = audit.subjects_for(_REJECTED)
    assert subjects and subjects[-1]["reason"] == "high_blast_change"
    # ``_diff_keys`` reports two-level dotted paths; the nested sub-model field
    # surfaces as its owning sub-model key.
    assert subjects[-1]["offending_key"] == "rate_limits.quarantined_extract_per_user_persona"
    assert ref.current() is active


async def test_mtime_gate_skips_reread_when_unchanged(tmp_path: Path, monkeypatch) -> None:
    watcher, _ref, _audit, _ = build_watcher(tmp_path)
    # First tick caches (mtime, size).
    await watcher._tick()
    calls: list[Path] = []
    import alfred.policies.watcher as watcher_mod

    real_load = watcher_mod.load_yaml_bytes

    def _spy_load(path: Path, **kw: object) -> bytes:
        calls.append(path)
        return real_load(path, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(watcher_mod, "load_yaml_bytes", _spy_load)
    # No mtime change -> no re-read.
    await watcher._tick()
    assert calls == []


async def test_mtime_gate_uses_nanosecond_resolution(tmp_path: Path, monkeypatch) -> None:
    """CR round-3: the gate keys on ``st_mtime_ns`` so a same-SECOND edit re-reads.

    Two stats reporting the same integer-second ``st_mtime`` but different
    ``st_mtime_ns`` (and the same size) must NOT be collapsed by the gate — a
    second-resolution gate would false-negative. Drives ``_tick`` against a real
    file but forces ``os.stat`` to return a same-second / distinct-ns pair.
    """
    import alfred.policies.watcher as watcher_mod

    watcher, _ref, _audit, _ = build_watcher(tmp_path)
    size = watcher._path.stat().st_size
    # Whole-second mtime shared by both stats; nanosecond suffix differs.
    base_s = 1_000_000
    seq = iter([base_s * 10**9 + 1, base_s * 10**9 + 999_999])

    class _FakeStat:
        st_mtime = float(base_s)
        st_size = size

        def __init__(self, ns: int) -> None:
            self.st_mtime_ns = ns

    def _fake_stat(_p):
        return _FakeStat(next(seq))

    calls: list[Path] = []
    real_load = watcher_mod.load_yaml_bytes

    def _spy_load(path: Path, **kw: object) -> bytes:
        calls.append(path)
        return real_load(path, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(watcher_mod.os, "stat", _fake_stat)
    monkeypatch.setattr(watcher_mod, "load_yaml_bytes", _spy_load)
    await watcher._tick()  # caches (base_s*1e9+1, size)
    await watcher._tick()  # distinct ns -> gate opens -> re-read
    assert len(calls) == 2


async def test_sha_short_circuit_no_swap_when_content_unchanged(tmp_path: Path) -> None:
    watcher, ref, audit, invoker = build_watcher(tmp_path)
    active = ref.current()
    # Rewrite identical content but bump mtime so the mtime gate opens.
    write_policies(watcher._path, active.policies)
    _bump_mtime(watcher._path)
    await watcher._tick()
    assert audit.calls == []
    assert ref.current() is active
    assert invoker.events == []


async def test_file_vanished_emits_rejected(tmp_path: Path) -> None:
    watcher, ref, audit, invoker = build_watcher(tmp_path)
    active = ref.current()
    watcher._path.unlink()
    await watcher._tick()
    subjects = audit.subjects_for(_REJECTED)
    assert subjects and subjects[-1]["reason"] == "file_vanished"
    assert ref.current() is active
    assert invoker.count("supervisor.config_reload_rejected") == 1


async def test_stat_failed_emits_rejected(tmp_path: Path, monkeypatch) -> None:
    watcher, _ref, audit, _ = build_watcher(tmp_path)
    import alfred.policies.watcher as watcher_mod

    def _raise_oserror(_p: Path) -> os.stat_result:
        raise OSError("EIO")

    monkeypatch.setattr(watcher_mod.os, "stat", _raise_oserror)
    await watcher._tick()
    subjects = audit.subjects_for(_REJECTED)
    assert subjects and subjects[-1]["reason"] == "stat_failed"
    assert subjects[-1]["offending_key"] == "<filesystem>"


async def test_parse_failure_on_malformed_yaml(tmp_path: Path) -> None:
    watcher, ref, audit, _ = build_watcher(tmp_path)
    active = ref.current()
    watcher._path.write_bytes(b"key: : : :\n  - broken\n")
    _bump_mtime(watcher._path)
    await watcher._tick()
    subjects = audit.subjects_for(_REJECTED)
    assert subjects and subjects[-1]["reason"] == "parse_failure"
    assert ref.current() is active


async def test_validation_failure_on_negative_rate(tmp_path: Path) -> None:
    watcher, ref, audit, _ = build_watcher(tmp_path)
    active = ref.current()
    watcher._path.write_text(
        "schema_version: 1\n"
        "rate_limits:\n"
        "  web_fetch_per_user_per_hour: -1\n"
        "  web_fetch_per_session_total: 200\n"
        "  operator_daily_budget_usd: 5.0\n"
        "handle_caps:\n"
        "  web_fetch_max_concurrent_handles_per_user: 8\n"
        "high_blast:\n"
        "  quarantined_provider_url: https://quarantine.local/v1\n"
        "  secret_broker_config_ref: broker://default\n"
    )
    _bump_mtime(watcher._path)
    await watcher._tick()
    subjects = audit.subjects_for(_REJECTED)
    assert subjects and subjects[-1]["reason"] == "validation_failure"
    assert ref.current() is active


async def test_oversize_file_refused_as_parse_failure(tmp_path: Path) -> None:
    watcher, _ref, audit, _ = build_watcher(tmp_path)
    from alfred.policies.load import MAX_POLICIES_BYTES

    watcher._path.write_bytes(b"# pad\n" * (MAX_POLICIES_BYTES // 4))
    _bump_mtime(watcher._path)
    await watcher._tick()
    subjects = audit.subjects_for(_REJECTED)
    assert subjects and subjects[-1]["reason"] == "parse_failure"


async def test_high_blast_change_refused(tmp_path: Path) -> None:
    watcher, ref, audit, invoker = build_watcher(tmp_path)
    active = ref.current()
    new = make_policies(high_blast={"quarantined_provider_url": "https://evil.example/v1"})
    write_policies(watcher._path, new)
    _bump_mtime(watcher._path)
    await watcher._tick()
    subjects = audit.subjects_for(_REJECTED)
    assert subjects
    row = subjects[-1]
    assert row["reason"] == "high_blast_change"
    assert row["offending_key"] == "high_blast.quarantined_provider_url"
    # Refusal is total: the active snapshot is byte-identical to before.
    assert ref.current() is active
    assert invoker.count("supervisor.config_reload_rejected") == 1


async def test_swap_audit_failure_emits_rejected_keeps_active(tmp_path: Path) -> None:
    """err-011: Phase-1 swap audit failure -> rejected row, active unchanged."""
    watcher, ref, audit, invoker = build_watcher(tmp_path)
    active = ref.current()
    from sqlalchemy.exc import OperationalError

    audit.raise_on("CONFIG_RELOAD_FIELDS", OperationalError("stmt", {}, Exception("db down")))
    new = make_policies(rate_limits={"web_fetch_per_user_per_hour": 120})
    write_policies(watcher._path, new)
    _bump_mtime(watcher._path)
    with allowlisted(_RATE_KEY):
        await watcher._tick()
    subjects = audit.subjects_for(_REJECTED)
    assert subjects and subjects[-1]["reason"] == "audit_write_failed"
    assert ref.current() is active
    assert invoker.count("supervisor.config_reload_rejected") == 1


async def test_rejected_write_failure_falls_back_to_jsonl_and_degrades(tmp_path: Path) -> None:
    """sec-4: when the REJECTED audit write itself fails, fall back loudly."""
    watcher, ref, audit, invoker = build_watcher(tmp_path)
    active = ref.current()
    from sqlalchemy.exc import OperationalError

    # Both the applied AND the rejected writes fail -> the rejected branch hits
    # the SQLAlchemyError fallback (sec-4).
    audit.raise_on("CONFIG_RELOAD_FIELDS", OperationalError("a", {}, Exception("down")))
    audit.raise_on("CONFIG_RELOAD_REJECTED_FIELDS", OperationalError("b", {}, Exception("down")))
    new = make_policies(rate_limits={"web_fetch_per_user_per_hour": 120})
    write_policies(watcher._path, new)
    _bump_mtime(watcher._path)
    with isolated_fallback(tmp_path) as fallback, allowlisted(_RATE_KEY):
        await watcher._tick()
        assert fallback.exists()
        assert "audit_write_failed" in fallback.read_text()
    assert ref.current() is active
    assert invoker.count("policies.watcher.degraded") == 1


async def test_swap_programmer_error_propagates_not_reclassified(tmp_path: Path) -> None:
    """err-S4-4-4: a wrong-shape append_schema (ValueError) propagates loudly.

    The swap()-site except is narrowed to ``SQLAlchemyError`` so a programmer
    error is NOT silently reclassified as transient ``audit_write_failed``. A
    ValueError / TypeError / ValidationError from ``append_schema`` must escape
    ``_tick`` as a loud bug.
    """
    watcher, ref, audit, _ = build_watcher(tmp_path)
    active = ref.current()
    audit.raise_on("CONFIG_RELOAD_FIELDS", ValueError("append_schema wrong shape"))
    new = make_policies(rate_limits={"web_fetch_per_user_per_hour": 120})
    write_policies(watcher._path, new)
    _bump_mtime(watcher._path)
    with allowlisted(_RATE_KEY), pytest.raises(ValueError, match="wrong shape"):
        await watcher._tick()
    # No reclassification to audit_write_failed; active snapshot unchanged.
    assert audit.subjects_for(_REJECTED) == []
    assert ref.current() is active


async def test_fallback_write_oserror_does_not_kill_watcher(tmp_path: Path, monkeypatch) -> None:
    """err-S4-4-3: a read-only / full state dir must NOT crash the watcher.

    When BOTH the audit store AND the fallback sink are down, the watcher logs
    critically and continues — the OSError from ``mkdir``/``open``/``write``
    must never propagate out of ``_tick`` into ``run()``'s ``while True``.
    """
    import alfred.policies.watcher as watcher_mod

    watcher, ref, audit, invoker = build_watcher(tmp_path)
    active = ref.current()
    from sqlalchemy.exc import OperationalError

    audit.raise_on("CONFIG_RELOAD_FIELDS", OperationalError("a", {}, Exception("down")))
    audit.raise_on("CONFIG_RELOAD_REJECTED_FIELDS", OperationalError("b", {}, Exception("down")))

    # Point the fallback at a path whose PARENT is a regular file, so
    # ``Path.parent.mkdir`` raises NotADirectoryError (an OSError subclass).
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    monkeypatch.setattr(watcher_mod, "_fallback_jsonl_path", lambda: blocker / "fallback.jsonl")

    crit: list[dict[str, object]] = []
    monkeypatch.setattr(
        watcher_mod._LOG, "critical", lambda event, **kw: crit.append({"event": event, **kw})
    )

    new = make_policies(rate_limits={"web_fetch_per_user_per_hour": 120})
    write_policies(watcher._path, new)
    _bump_mtime(watcher._path)
    # Must NOT raise.
    with allowlisted(_RATE_KEY):
        await watcher._tick()

    assert any(c["event"] == "policies.watcher.fallback_write_failed" for c in crit)
    assert ref.current() is active
    # The degraded hookpoint still fires despite the sink failure.
    assert invoker.count("policies.watcher.degraded") == 1


async def test_fallback_write_failure_not_cached_so_retries(tmp_path: Path, monkeypatch) -> None:
    """A FAILED fallback write does not advance the dedup cursor (re-logged each tick)."""
    import alfred.policies.watcher as watcher_mod

    watcher, _ref, audit, _ = build_watcher(tmp_path)
    from sqlalchemy.exc import OperationalError

    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    monkeypatch.setattr(watcher_mod, "_fallback_jsonl_path", lambda: blocker / "fallback.jsonl")
    crit: list[str] = []
    monkeypatch.setattr(watcher_mod._LOG, "critical", lambda event, **kw: crit.append(event))

    for _ in range(2):
        audit.raise_on("CONFIG_RELOAD_REJECTED_FIELDS", OperationalError("x", {}, Exception("d")))
        await watcher._reject(
            reason="audit_write_failed", attempted_sha="sha-1", offending_key="<audit_store>"
        )
    # Both attempts re-logged because the failed write never set the dedup cursor.
    assert crit.count("policies.watcher.fallback_write_failed") == 2


async def test_fallback_dedup_one_line_per_distinct_bad_file(tmp_path: Path) -> None:
    """perf-S4-4-5: a sustained outage on the SAME bad file writes ONE fallback line."""
    from sqlalchemy.exc import OperationalError

    watcher, _ref, audit, _ = build_watcher(tmp_path)
    with isolated_fallback(tmp_path) as fallback:
        # Same (reason, attempted_sha256) twice -> deduped to a single line.
        for _ in range(2):
            audit.raise_on(
                "CONFIG_RELOAD_REJECTED_FIELDS", OperationalError("x", {}, Exception("d"))
            )
            await watcher._reject(
                reason="audit_write_failed", attempted_sha="sha-A", offending_key="<audit_store>"
            )
        assert fallback.read_text().count("\n") == 1
        # A DIFFERENT attempted_sha (a new bad file) appends a second line.
        audit.raise_on("CONFIG_RELOAD_REJECTED_FIELDS", OperationalError("x", {}, Exception("d")))
        await watcher._reject(
            reason="audit_write_failed", attempted_sha="sha-B", offending_key="<audit_store>"
        )
        assert fallback.read_text().count("\n") == 2


async def test_degraded_after_three_stat_failures(tmp_path: Path, monkeypatch) -> None:
    watcher, _ref, _audit, invoker = build_watcher(tmp_path)
    import alfred.policies.watcher as watcher_mod

    def _raise(_p: Path) -> os.stat_result:
        raise OSError("EIO")

    monkeypatch.setattr(watcher_mod.os, "stat", _raise)
    for _ in range(3):
        await watcher._tick()
    assert watcher.state == "degraded"
    assert invoker.count("supervisor.config_watcher.degraded") == 1
    # Cadence backs off 10x.
    assert watcher._effective_interval() == pytest.approx(watcher._interval * 10)


async def test_recovered_after_three_successes(tmp_path: Path, monkeypatch) -> None:
    watcher, _ref, _audit, invoker = build_watcher(tmp_path)
    import alfred.policies.watcher as watcher_mod

    def _raise(_p: Path) -> os.stat_result:
        raise OSError("EIO")

    with monkeypatch.context() as mp:
        mp.setattr(watcher_mod.os, "stat", _raise)
        for _ in range(3):
            await watcher._tick()
    assert watcher.state == "degraded"
    # Restore stat; three clean ticks recover.
    for _ in range(3):
        await watcher._tick()
    assert watcher.state == "normal"
    assert invoker.count("supervisor.config_watcher.recovered") == 1


async def test_rejection_re_emits_every_tick_until_fixed(tmp_path: Path) -> None:
    """sec-2: cache is NOT updated on reject -> sustained rejection signal."""
    watcher, _ref, audit, _ = build_watcher(tmp_path)
    watcher._path.write_bytes(b"key: : : :\n  - broken\n")
    _bump_mtime(watcher._path)
    await watcher._tick()
    await watcher._tick()
    rejects = [s for s in audit.subjects_for(_REJECTED) if s["reason"] == "parse_failure"]
    assert len(rejects) == 2


async def test_mtime_skew_far_future_still_loads(tmp_path: Path) -> None:
    """csb-2026-004: mtime is a change-gate, not a trust signal."""
    watcher, ref, audit, _ = build_watcher(tmp_path)
    new = make_policies(rate_limits={"web_fetch_per_user_per_hour": 120})
    write_policies(watcher._path, new)
    os.utime(watcher._path, (4_070_908_800, 4_070_908_800))  # year 2099
    with allowlisted(_RATE_KEY):
        await watcher._tick()
    assert ref.current().policies.rate_limits.web_fetch_per_user_per_hour == 120
    assert audit.subjects_for(_APPLIED)


async def test_first_tick_caches_then_idempotent(tmp_path: Path) -> None:
    watcher, ref, audit, _ = build_watcher(tmp_path)
    active = ref.current()
    await watcher._tick()  # same content as bootstrap snapshot -> SHA short-circuit
    assert ref.current() is active
    assert audit.calls == []


async def test_swap_writes_history_row_when_writer_present(tmp_path: Path) -> None:
    watcher, ref, _audit, _ = build_watcher(tmp_path)

    class _SpyHistory:
        def __init__(self) -> None:
            self.appended: list[str] = []

        async def append(
            self, snapshot, *, applied_at, operator_session_id, swapped_from_snapshot_id=None
        ):
            self.appended.append(snapshot.file_sha256)
            return "snap-id"

    history = _SpyHistory()
    watcher._history = history  # type: ignore[assignment]
    new = make_policies(rate_limits={"web_fetch_per_user_per_hour": 120})
    write_policies(watcher._path, new)
    _bump_mtime(watcher._path)
    with allowlisted(_RATE_KEY):
        await watcher._tick()
    assert history.appended == [ref.current().file_sha256]
