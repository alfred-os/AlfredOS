"""Executable counterparts to the csb-2026-* config-reload-bypass payloads.

The YAML payloads in this directory are corpus-density-validated by
``test_corpus_density.py`` and schema-validated by the session
``corpus_payloads`` fixture — but neither EXERCISES the runtime defense. A
payload could be silently weakened or renamed and the suite would stay green.

This module loads each csb payload and drives the REAL
:class:`alfred.policies.watcher.PolicyWatcher` against a real temp
``policies.yaml`` with a recording :class:`SpyAudit`, asserting the payload's
declared ``expected_outcome`` actually fires at the trust boundary:

* csb-2026-001 (TOCTOU symlink swap) -> the loader's ``O_NOFOLLOW`` refuses;
  the watcher emits a ``stat_failed`` / ``file_vanished`` rejection and the
  active snapshot is unchanged (``refused``).
* csb-2026-002 (high_blast provider-URL swap) -> ``high_blast_change`` refusal
  (``audit_row_emitted``).
* csb-2026-004 (cached-mtime rejection suppression) -> the rejection re-emits
  EVERY tick (``audit_row_emitted``).
* csb-2026-005 (oversize-file DoS) -> ``parse_failure`` refusal before the
  parser sees the bytes (``refused``).
* csb-2026-007 (rate-limit anti-abuse knob swap) -> ``high_blast_change``
  refusal naming ``rate_limits.web_fetch_per_user_per_hour``
  (``audit_row_emitted``).

csb-2026-003 (audit-write-failure abort, outcome
``policy_swap_aborted_on_audit_failure``) is exercised by the unit suite's
``test_swap_audit_failure_emits_rejected_keeps_active`` /
``test_rejected_write_failure_falls_back_to_jsonl_and_degrades`` against the
real ``PoliciesSnapshotRef.swap`` two-phase commit; it is asserted here only at
the schema level (the induced-failure injection needs the SpyAudit ``raise_on``
seam, which the unit suite already drives).

Mirrors the de-2026 executable-corpus pattern (PR-S4-2).
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
import yaml

from alfred.policies.load import MAX_POLICIES_BYTES, canonical_bytes, compute_sha256
from alfred.policies.model import PoliciesV1
from alfred.policies.snapshot_ref import PoliciesSnapshot, PoliciesSnapshotRef
from alfred.policies.watcher import PolicyWatcher
from tests.adversarial.payload_schema import AdversarialPayload
from tests.unit.policies._audit_spy import SpyAudit

_DIR = Path(__file__).parent
_REJECTED = "CONFIG_RELOAD_REJECTED_FIELDS"
_APPLIED = "CONFIG_RELOAD_FIELDS"


def _load(payload_id: str) -> AdversarialPayload:
    path = next(_DIR.glob(f"{payload_id.replace('-', '_')}*.yaml"))
    return AdversarialPayload.model_validate(yaml.safe_load(path.read_text()))


def _base_model(**overrides: object) -> PoliciesV1:
    data: dict[str, object] = {
        "schema_version": 1,
        "rate_limits": {
            "web_fetch_per_user_per_hour": 60,
            "web_fetch_per_session_total": 200,
            "operator_daily_budget_usd": 5.0,
        },
        "handle_caps": {"web_fetch_max_concurrent_handles_per_user": 8},
        "high_blast": {
            "quarantined_provider_url": "https://quarantine.local/v1",
            "secret_broker_config_ref": "broker://default",
        },
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key] = {**data[key], **value}  # type: ignore[dict-item]
        else:
            data[key] = value
    return PoliciesV1.model_validate(data)


def _build(tmp_path: Path) -> tuple[PolicyWatcher, PoliciesSnapshotRef, SpyAudit]:
    model = _base_model()
    cfg = tmp_path / "policies.yaml"
    cfg.write_bytes(canonical_bytes(model))
    snap = PoliciesSnapshot.model_validate(
        {
            "policies": model,
            "loaded_at": "2026-06-09T00:00:00+00:00",
            "file_mtime": cfg.stat().st_mtime,
            "file_sha256": compute_sha256(canonical_bytes(model)),
            "file_path": cfg.resolve(),
        }
    )
    ref = PoliciesSnapshotRef(snap)
    audit = SpyAudit()
    watcher = PolicyWatcher(
        config_path=cfg,
        snapshot_ref=ref,
        audit_writer=audit,
        poll_interval=0.01,
        invoke_fn=_noop_invoke,
    )
    return watcher, ref, audit


async def _noop_invoke(_name: str, _payload: dict[str, object]) -> None:
    return None


def _bump_mtime(path: Path) -> None:
    future = time.time() + 5
    os.utime(path, (future, future))


def test_all_csb_payloads_schema_valid() -> None:
    """Every csb payload validates and declares the config_reload_bypass shape."""
    for path in sorted(_DIR.glob("csb_*.yaml")):
        payload = AdversarialPayload.model_validate(yaml.safe_load(path.read_text()))
        assert payload.category == "config_reload_bypass"
        assert payload.ingestion_path == "mtime_poll"


@pytest.mark.asyncio
async def test_csb_002_high_blast_provider_url_refused(tmp_path: Path) -> None:
    payload = _load("csb-2026-002")
    assert payload.expected_outcome == "audit_row_emitted"
    watcher, ref, audit = _build(tmp_path)
    active = ref.current()
    watcher._path.write_bytes(
        canonical_bytes(
            _base_model(high_blast={"quarantined_provider_url": "https://evil.example/v1"})
        )
    )
    _bump_mtime(watcher._path)
    await watcher._tick()
    rejects = audit.subjects_for(_REJECTED)
    assert rejects and rejects[-1]["reason"] == "high_blast_change"
    assert rejects[-1]["offending_key"] == "high_blast.quarantined_provider_url"
    assert audit.subjects_for(_APPLIED) == []
    assert ref.current() is active


@pytest.mark.asyncio
async def test_csb_007_rate_limit_knob_refused(tmp_path: Path) -> None:
    """The keystone: a rate-limit edit REFUSES, naming the rate-limit key."""
    payload = _load("csb-2026-007")
    assert payload.expected_outcome == "audit_row_emitted"
    assert isinstance(payload.payload, dict)
    offending_key = str(payload.payload["offending_key"])
    watcher, ref, audit = _build(tmp_path)
    active = ref.current()
    watcher._path.write_bytes(
        canonical_bytes(_base_model(rate_limits={"web_fetch_per_user_per_hour": 0}))
    )
    _bump_mtime(watcher._path)
    await watcher._tick()
    rejects = audit.subjects_for(_REJECTED)
    assert rejects and rejects[-1]["reason"] == "high_blast_change"
    assert (
        rejects[-1]["offending_key"] == offending_key == "rate_limits.web_fetch_per_user_per_hour"
    )
    # Refusal is total: no applied row; active snapshot unchanged.
    assert audit.subjects_for(_APPLIED) == []
    assert ref.current() is active


@pytest.mark.asyncio
async def test_csb_007_burst_limiter_capacity_refused(tmp_path: Path) -> None:
    """The nested capacity_tokens anti-abuse knob also refuses hot-reload."""
    watcher, ref, audit = _build(tmp_path)
    active = ref.current()
    watcher._path.write_bytes(
        canonical_bytes(
            _base_model(
                rate_limits={"quarantined_extract_per_user_persona": {"capacity_tokens": 100}}
            )
        )
    )
    _bump_mtime(watcher._path)
    await watcher._tick()
    rejects = audit.subjects_for(_REJECTED)
    assert rejects and rejects[-1]["reason"] == "high_blast_change"
    assert rejects[-1]["offending_key"] == "rate_limits.quarantined_extract_per_user_persona"
    assert ref.current() is active


@pytest.mark.asyncio
async def test_csb_004_rejection_re_emits_every_tick(tmp_path: Path) -> None:
    payload = _load("csb-2026-004")
    assert payload.expected_outcome == "audit_row_emitted"
    watcher, _ref, audit = _build(tmp_path)
    watcher._path.write_bytes(b"key: : : :\n  - broken\n")
    _bump_mtime(watcher._path)
    await watcher._tick()
    await watcher._tick()
    rejects = [s for s in audit.subjects_for(_REJECTED) if s["reason"] == "parse_failure"]
    assert len(rejects) == 2, "rejection must re-emit each tick (no mtime-cache suppression)"


@pytest.mark.asyncio
async def test_csb_005_oversize_file_refused(tmp_path: Path) -> None:
    payload = _load("csb-2026-005")
    assert payload.expected_outcome == "refused"
    watcher, ref, audit = _build(tmp_path)
    active = ref.current()
    watcher._path.write_bytes(b"# pad\n" * (MAX_POLICIES_BYTES // 4))
    _bump_mtime(watcher._path)
    await watcher._tick()
    rejects = audit.subjects_for(_REJECTED)
    assert rejects and rejects[-1]["reason"] == "parse_failure"
    assert ref.current() is active


@pytest.mark.asyncio
async def test_csb_001_toctou_symlink_refused(tmp_path: Path) -> None:
    """The O_NOFOLLOW loader refuses a symlinked policies.yaml (TOCTOU)."""
    payload = _load("csb-2026-001")
    assert payload.expected_outcome == "refused"
    watcher, ref, audit = _build(tmp_path)
    active = ref.current()
    # Replace the regular file with a symlink to attacker-controlled YAML.
    target = tmp_path / "attacker-policies.yaml"
    target.write_bytes(
        canonical_bytes(_base_model(rate_limits={"web_fetch_per_user_per_hour": 999999}))
    )
    watcher._path.unlink()
    watcher._path.symlink_to(target)
    _bump_mtime(target)
    await watcher._tick()
    rejects = audit.subjects_for(_REJECTED)
    # O_NOFOLLOW raises at open(); the watcher routes it to a rejection branch.
    assert rejects and rejects[-1]["reason"] in {"stat_failed", "file_vanished", "parse_failure"}
    # The attacker policy was NOT applied: active snapshot unchanged.
    assert ref.current() is active
    assert ref.current().policies.rate_limits.web_fetch_per_user_per_hour == 60


def test_csb_003_audit_failure_outcome_declared() -> None:
    """csb-2026-003 declares the audit-write-abort outcome (driven by unit suite)."""
    payload = _load("csb-2026-003")
    assert payload.expected_outcome == "policy_swap_aborted_on_audit_failure"
