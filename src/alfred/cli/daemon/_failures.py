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


class BootInfraInstallFailedFailure(_BootFailureBase):
    """Seeding the first-party gate or installing the boot registry FAILED.

    FIX 1 (PR-S4-11b0 review): distinct from
    :class:`QuarantineGrantMissingFailure`. That failure means the seed +
    install both SUCCEEDED but the grant did not project into the in-memory
    policy. THIS failure means the seed-gate build itself raised (a
    :class:`sqlalchemy.exc.SQLAlchemyError` — Postgres down / write failure)
    or the boot :class:`HookRegistry` install raised
    (a :class:`alfred.hooks.errors.HookError` — hookpoint metadata drift).

    Before FIX 1 either fault propagated as an UNCAUGHT crash out of
    ``_start_async`` — fail-closed and safe, but it skipped the audited
    ``_refuse_boot`` path (no ``daemon.boot.failed`` row, not exit 2). The
    grant-assertion arm was already audited; this carrier makes the
    seed/install arms match (CLAUDE.md hard rule #7 — a security-boot fault
    is loud + audited, never a silent traceback). The distinct
    ``failure_reason`` lets forensics tell a broken seed/install apart from a
    seed that succeeded but failed to project the grant.
    """

    failure_reason: Literal["boot_infra_install_failed"] = "boot_infra_install_failed"


class QuarantineGrantMissingFailure(_BootFailureBase):
    """The first-party DLP-subscriber grant was not live after boot install.

    PR-S4-11b0 / ADR-0026: after the daemon seeds the first-party system
    grants and installs the boot :class:`HookRegistry`, it asserts the
    seeded ``security.quarantined.extract`` system-tier grant is live by
    calling :meth:`RealGate.check`. A ``False`` result means the
    seed-then-load did not project the grant into the in-memory policy —
    a structurally-broken trust boundary where a
    :class:`QuarantinedExtractor` could not construct (its DLP-subscriber
    registration would be denied). Boot refuses fail-closed rather than
    continue with a quarantine path that cannot wire its DLP scan
    (CLAUDE.md hard rule #7).
    """

    failure_reason: Literal["quarantine_grant_missing"] = "quarantine_grant_missing"


DaemonBootFailure = Annotated[
    EnvironmentNotSetFailure
    | UnsandboxedEnvInProductionFailure
    | LauncherNotPolicyResolvingFailure
    | SnapshotRefInitFailedFailure
    | CapabilityGateHandshakeFailedFailure
    | QuarantineGrantMissingFailure
    | BootInfraInstallFailedFailure,
    Field(discriminator="failure_reason"),
]
"""Discriminated union over the daemon-boot refusal modes (spec §3.4 +
ADR-0026 ``quarantine_grant_missing`` + FIX 1 ``boot_infra_install_failed``)."""
