"""``DaemonBootFailure`` discriminated union (#174 PR-S4-1).

core-eng-001 round-2 closure: the daemon-boot refusal modes are
CLI-layer concepts (the probes run at the CLI layer, not inside
``Supervisor.start()``), so the union lives here rather than in
``alfred.supervisor.protocols``.

Each member maps 1:1 to a spec §3.4 ``failure_reason`` Literal. The
discriminated union lets the CLI's refusal path pattern-match on
``failure_reason`` and lets PR-S4-6 extend the union with
launcher-specific failure detail without re-touching the probes.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class _BootFailureBase(BaseModel):
    """Frozen, extra-forbidding base for every boot-failure carrier."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class EnvironmentNotSetFailure(_BootFailureBase):
    """``Settings.environment`` could not be resolved from either source."""

    failure_reason: Literal["environment_not_set"] = "environment_not_set"


class UnsandboxedEnvInProductionFailure(_BootFailureBase):
    """``ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED`` is truthy in production."""

    failure_reason: Literal["unsandboxed_env_in_production"] = "unsandboxed_env_in_production"


class LauncherNotPolicyResolvingFailure(_BootFailureBase):
    """The plugin launcher does not resolve per-plugin policies."""

    failure_reason: Literal["launcher_not_policy_resolving"] = "launcher_not_policy_resolving"
    # What the stub launcher returned — never raw operator content, just the
    # forward-compat probe token PR-S4-6's real check will assert against.
    probe_response: str = ""


class SnapshotRefInitFailedFailure(_BootFailureBase):
    """``config/policies.yaml`` failed to parse at boot."""

    failure_reason: Literal["snapshot_ref_init_failed"] = "snapshot_ref_init_failed"
    # Exception class qualname only — never the raw message (a parse error
    # could echo a fragment of the file, which §5.6 forbids in audit JSONB).
    detail_redacted: str = ""


class CapabilityGateHandshakeFailedFailure(_BootFailureBase):
    """The capability gate could not reach its backing store at boot."""

    failure_reason: Literal["capability_gate_handshake_failed"] = "capability_gate_handshake_failed"
    backing_store_kind: Literal["postgres", "state_git", "unknown"] = "unknown"


DaemonBootFailure = Annotated[
    EnvironmentNotSetFailure
    | UnsandboxedEnvInProductionFailure
    | LauncherNotPolicyResolvingFailure
    | SnapshotRefInitFailedFailure
    | CapabilityGateHandshakeFailedFailure,
    Field(discriminator="failure_reason"),
]
"""Discriminated union over the five spec §3.4 daemon-boot refusal modes."""
