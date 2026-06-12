"""Verify the DaemonBootFailure union ships the five spec §3.4 modes (#174).

core-eng-001 round-2 closure: the union lives at the CLI layer
(``alfred.cli.daemon._failures``), NOT ``alfred.supervisor.protocols``.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.cli.daemon._failures import (
    BootInfraInstallFailedFailure,
    CapabilityGateHandshakeFailedFailure,
    CommsPromoterMisconfiguredFailure,
    EnvironmentNotSetFailure,
    LauncherNotPolicyResolvingFailure,
    QuarantineChildSpawnFailedFailure,
    QuarantineGrantMissingFailure,
    SnapshotRefInitFailedFailure,
    T3NonceRegistrationFailedFailure,
    UnsandboxedEnvInProductionFailure,
)


@pytest.mark.parametrize(
    ("cls", "reason"),
    [
        (EnvironmentNotSetFailure, "environment_not_set"),
        (UnsandboxedEnvInProductionFailure, "unsandboxed_env_in_production"),
        (LauncherNotPolicyResolvingFailure, "launcher_not_policy_resolving"),
        (SnapshotRefInitFailedFailure, "snapshot_ref_init_failed"),
        (CapabilityGateHandshakeFailedFailure, "capability_gate_handshake_failed"),
        (QuarantineGrantMissingFailure, "quarantine_grant_missing"),
        (BootInfraInstallFailedFailure, "boot_infra_install_failed"),
        (T3NonceRegistrationFailedFailure, "t3_nonce_registration_failed"),
        (QuarantineChildSpawnFailedFailure, "quarantine_child_spawn_failed"),
        (CommsPromoterMisconfiguredFailure, "comms_promoter_misconfigured"),
    ],
)
def test_failure_carries_literal_reason(cls: type, reason: str) -> None:
    instance = cls()
    assert instance.failure_reason == reason


def test_comms_promoter_misconfigured_carries_adapter_id() -> None:
    """PR-S4-235-1: the boot-time M2 mirror carries the closed-vocab adapter id."""
    f = CommsPromoterMisconfiguredFailure(adapter_id="discord")
    d = f.model_dump()
    assert d["failure_reason"] == "comms_promoter_misconfigured"
    assert d["adapter_id"] == "discord"


def test_boot_infra_install_failure_is_distinct_from_grant_missing() -> None:
    """FIX 1: a seed/install fault carries its OWN failure_reason, distinct
    from the grant-assertion arm — so forensics can tell a broken seed/install
    apart from a seed that succeeded but failed to project the grant."""
    assert (
        BootInfraInstallFailedFailure().failure_reason
        != QuarantineGrantMissingFailure().failure_reason
    )


def test_environment_not_set_carries_no_extra_fields() -> None:
    """Pure refusal — nothing to attach beyond the literal reason."""
    f = EnvironmentNotSetFailure()
    assert f.model_dump() == {"failure_reason": "environment_not_set"}


def test_snapshot_ref_failed_carries_parse_error() -> None:
    """Failures that need detail carry it on the model."""
    f = SnapshotRefInitFailedFailure(detail_redacted="yaml.scanner.ScannerError")
    d = f.model_dump()
    assert d["failure_reason"] == "snapshot_ref_init_failed"
    assert d["detail_redacted"] == "yaml.scanner.ScannerError"


def test_launcher_failure_carries_probe_response() -> None:
    f = LauncherNotPolicyResolvingFailure(probe_response="slice-3-stub-signature")
    d = f.model_dump()
    assert d["failure_reason"] == "launcher_not_policy_resolving"
    assert d["probe_response"] == "slice-3-stub-signature"


def test_capability_gate_failure_carries_backing_store_kind() -> None:
    f = CapabilityGateHandshakeFailedFailure(backing_store_kind="postgres")
    d = f.model_dump()
    assert d["failure_reason"] == "capability_gate_handshake_failed"
    assert d["backing_store_kind"] == "postgres"


def test_models_are_frozen() -> None:
    """Boot-failure carriers are immutable — no mid-flight mutation."""
    f = EnvironmentNotSetFailure()
    with pytest.raises(ValidationError):  # frozen model rejects the set
        f.failure_reason = "other"  # type: ignore[misc]
