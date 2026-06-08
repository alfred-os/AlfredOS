"""Verify the snapshot-ref init probe loads config/policies.yaml or refuses (#174).

core-eng-002 closure: probe (b) does FILE-ONLY ops — no Postgres.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from alfred.cli.daemon._daemon_probes import probe_snapshot_ref_init
from alfred.cli.daemon._failures import SnapshotRefInitFailedFailure


def _default_policies_hash() -> str:
    return hashlib.sha256(b"_DEFAULT_POLICIES_V1_STUB").hexdigest()


@pytest.mark.asyncio
async def test_probe_passes_when_yaml_valid(tmp_path: Path) -> None:
    """Well-formed YAML loads; probe returns None + a non-empty hash."""
    cfg = tmp_path / "policies.yaml"
    cfg.write_text(
        "schema_version: 1\nrate_limits:\n  web_fetch_per_user_per_hour: 100\n",
        encoding="utf-8",
    )
    result, snapshot_ref = await probe_snapshot_ref_init(environment="test", config_path=cfg)
    assert result is None
    assert snapshot_ref is not None
    assert snapshot_ref.snapshot_hash()  # sha256 hex, non-empty
    assert snapshot_ref.current() == {
        "schema_version": 1,
        "rate_limits": {"web_fetch_per_user_per_hour": 100},
    }


@pytest.mark.asyncio
async def test_probe_passes_when_file_missing_uses_default_in_dev(tmp_path: Path) -> None:
    """Missing file falls back to the PR-S4-1 default stub OUTSIDE production."""
    missing = tmp_path / "no-such-policies.yaml"
    result, snapshot_ref = await probe_snapshot_ref_init(
        environment="development", config_path=missing
    )
    assert result is None
    assert snapshot_ref is not None
    assert snapshot_ref.snapshot_hash() == _default_policies_hash()
    # The default stub's parsed snapshot is None (no on-disk YAML).
    assert snapshot_ref.current() is None


@pytest.mark.asyncio
async def test_probe_refuses_when_file_missing_in_production(tmp_path: Path) -> None:
    """err-003: a missing policies file refuses the boot in production.

    Booting the privileged orchestrator with no policy set is a silent
    security failure — production must refuse rather than fall back to an
    empty-policy stub.
    """
    missing = tmp_path / "no-such-policies.yaml"
    result, snapshot_ref = await probe_snapshot_ref_init(
        environment="production", config_path=missing
    )
    assert isinstance(result, SnapshotRefInitFailedFailure)
    assert "FileNotFoundError" in result.detail_redacted
    assert snapshot_ref is None


@pytest.mark.asyncio
async def test_probe_refuses_on_malformed_yaml(tmp_path: Path) -> None:
    """Invalid YAML → typed failure with redacted detail (exception class only)."""
    cfg = tmp_path / "policies.yaml"
    cfg.write_text(":\n:::not valid yaml", encoding="utf-8")
    result, snapshot_ref = await probe_snapshot_ref_init(environment="test", config_path=cfg)
    assert isinstance(result, SnapshotRefInitFailedFailure)
    assert "ScannerError" in result.detail_redacted or "ParserError" in result.detail_redacted
    assert snapshot_ref is None


@pytest.mark.asyncio
async def test_probe_refuses_on_unreadable_file(tmp_path: Path) -> None:
    """A directory at config_path (IsADirectoryError) → typed failure."""
    cfg = tmp_path / "policies.yaml"
    cfg.mkdir()
    result, snapshot_ref = await probe_snapshot_ref_init(environment="test", config_path=cfg)
    assert isinstance(result, SnapshotRefInitFailedFailure)
    assert result.detail_redacted  # exception qualname, non-empty
    assert snapshot_ref is None
