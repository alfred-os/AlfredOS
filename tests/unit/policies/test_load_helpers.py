"""Load helpers: TOCTOU-safe read, size cap, parse, SHA (PR-S4-4 Tasks 4-5).

sec-1 closure: ``load_yaml_bytes`` is TOCTOU-safe — it opens the file with
``O_NOFOLLOW`` then ``fstat``s the already-open fd, so an inode swap between
stat and read cannot redirect the read to attacker content. The 256 KB cap
is enforced against the fstat result (authoritative for the fd we read).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from alfred.policies.load import (
    MAX_POLICIES_BYTES,
    PolicyFileTooLarge,
    compute_sha256,
    load_yaml_bytes,
    parse_policies,
)


def _valid_yaml_text() -> str:
    return (
        "schema_version: 1\n"
        "rate_limits:\n"
        "  web_fetch_per_user_per_hour: 60\n"
        "  web_fetch_per_session_total: 200\n"
        "  operator_daily_budget_usd: 5.0\n"
        "handle_caps:\n"
        "  web_fetch_max_concurrent_handles_per_user: 8\n"
        "high_blast:\n"
        "  quarantined_provider_url: https://quarantine.local/v1\n"
        "  secret_broker_config_ref: broker://default\n"
    )


def test_load_yaml_bytes_reads_file(tmp_path: Path) -> None:
    f = tmp_path / "policies.yaml"
    f.write_text("schema_version: 1\n")
    assert b"schema_version: 1" in load_yaml_bytes(f, max_size=MAX_POLICIES_BYTES)


def test_load_yaml_bytes_refuses_oversize(tmp_path: Path) -> None:
    f = tmp_path / "huge.yaml"
    f.write_bytes(b"# pad\n" * (MAX_POLICIES_BYTES // 4))
    with pytest.raises(PolicyFileTooLarge):
        load_yaml_bytes(f, max_size=MAX_POLICIES_BYTES)


def test_load_yaml_bytes_refuses_symlink(tmp_path: Path) -> None:
    """O_NOFOLLOW refuses to open the path if it is a symlink (sec-1)."""
    target = tmp_path / "attacker.yaml"
    target.write_text("schema_version: 1\n")
    link = tmp_path / "policies.yaml"
    link.symlink_to(target)
    with pytest.raises(OSError):
        load_yaml_bytes(link, max_size=MAX_POLICIES_BYTES)


def test_load_yaml_bytes_missing_file_raises_filenotfound(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_yaml_bytes(tmp_path / "nope.yaml", max_size=MAX_POLICIES_BYTES)


def test_parse_policies_happy_path() -> None:
    model = parse_policies(_valid_yaml_text().encode(), max_size_bytes=MAX_POLICIES_BYTES)
    assert model.rate_limits.web_fetch_per_user_per_hour == 60


def test_parse_policies_validation_failure_propagates() -> None:
    with pytest.raises(ValidationError):
        parse_policies(
            b"schema_version: 1\nrate_limits: {}\n",
            max_size_bytes=MAX_POLICIES_BYTES,
        )


def test_parse_policies_malformed_yaml_raises_yamlerror() -> None:
    with pytest.raises(yaml.YAMLError):
        parse_policies(b"key: : : :\n  - broken\n", max_size_bytes=MAX_POLICIES_BYTES)


def test_parse_policies_oversize_raw_refused() -> None:
    raw = b"# pad\n" * (MAX_POLICIES_BYTES // 4)
    with pytest.raises(PolicyFileTooLarge):
        parse_policies(raw, max_size_bytes=MAX_POLICIES_BYTES)


def test_compute_sha256_stable() -> None:
    assert compute_sha256(b"key: 1\n") == compute_sha256(b"key: 1\n")


def test_compute_sha256_differs_on_content_change() -> None:
    assert compute_sha256(b"key: 1\n") != compute_sha256(b"key: 2\n")


def test_load_yaml_bytes_reads_exactly_fstat_size(tmp_path: Path) -> None:
    """The read length is bounded by the fstat result, not an unbounded read."""
    f = tmp_path / "policies.yaml"
    payload = _valid_yaml_text().encode()
    f.write_bytes(payload)
    raw = load_yaml_bytes(f, max_size=MAX_POLICIES_BYTES)
    assert raw == payload
    assert len(raw) == f.stat().st_size
