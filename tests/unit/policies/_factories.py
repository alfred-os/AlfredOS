"""Snapshot factories shared across the policies unit suite."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from alfred.policies.load import canonical_bytes, compute_sha256
from alfred.policies.model import PoliciesV1
from alfred.policies.snapshot_ref import PoliciesSnapshot


def make_policies(**overrides: Any) -> PoliciesV1:
    data: dict[str, Any] = {
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
            data[key] = {**data[key], **value}
        else:
            data[key] = value
    return PoliciesV1.model_validate(data)


def make_snapshot(
    *,
    policies: PoliciesV1 | None = None,
    file_path: Path = Path("/etc/alfred/policies.yaml"),
    file_mtime: float = 1000.0,
    sha: str | None = None,
) -> PoliciesSnapshot:
    model = policies if policies is not None else make_policies()
    sha256 = sha if sha is not None else compute_sha256(canonical_bytes(model))
    return PoliciesSnapshot(
        policies=model,
        loaded_at=datetime.now(UTC),
        file_mtime=file_mtime,
        file_sha256=sha256,
        file_path=file_path,
    )
