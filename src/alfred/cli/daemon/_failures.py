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

    FIX 2 (PR-S4-11b review): the seed-gate build ALSO runs the config-sourced
    comms-adapter grants-builder
    (:func:`alfred.security.capability_gate._comms_adapter_grants.comms_adapter_load_grants`),
    which raises :class:`alfred.plugins.errors.ManifestError` for a corrupt or
    ``system``-tier enabled-adapter manifest (the leaf
    :class:`alfred.plugins.errors.CommsAdapterSystemTierError`) or
    :class:`OSError` for an unreadable manifest file. Those faults map to THIS
    failure too — the same audited refusal, not a raw traceback.

    Before FIX 1/2 any of these faults propagated as an UNCAUGHT crash out of
    ``_start_async`` — fail-closed and safe, but it skipped the audited
    ``_refuse_boot`` path (no ``daemon.boot.failed`` row, not exit 2). The
    grant-assertion arm was already audited; this carrier makes the
    seed/install/grants-builder arms match (CLAUDE.md hard rule #7 — a
    security-boot fault is loud + audited, never a silent traceback). The
    distinct ``failure_reason`` lets forensics tell a broken
    seed/install/manifest apart from a seed that succeeded but failed to
    project the grant.
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


class T3NonceRegistrationFailedFailure(_BootFailureBase):
    """The per-process authorised T3 nonce could not be minted + registered.

    PR-S4-11c-2a0: the daemon mints the per-process
    :class:`alfred.security.tiers.CapabilityGateNonce` and installs it in the
    ``alfred.security.tiers._AUTHORIZED_T3_NONCE`` slot exactly once at process
    start via :func:`alfred.bootstrap.nonce_factory.create_and_register_t3_nonce`.
    A fresh process boots with an empty slot, so registration succeeds. A NON-empty
    slot at boot means a nonce was already minted (a re-entrant boot path, a leaked
    test fixture, a duplicate registration), at which point the factory raises
    :class:`alfred.bootstrap.nonce_factory.T3NonceAlreadyRegisteredError` — there is
    no production reset API by design (the silent-rotation failure mode of clearing
    a live slot is worse than a loud refusal). Boot refuses fail-closed rather than
    continue without owning the authorised nonce: without it EVERY authorised
    T3-tagging path (``tag_t3_with_nonce``) raises, so the comms inbound body could
    not be tagged ``TaggedContent[T3]`` (CLAUDE.md hard rule #7 — loud + audited,
    never a silent traceback).
    """

    failure_reason: Literal["t3_nonce_registration_failed"] = "t3_nonce_registration_failed"


class QuarantineChildSpawnFailedFailure(_BootFailureBase):
    """The bwrap-sandboxed quarantined-LLM child could not be spawned at boot.

    PR-S4-11c-2b (the daemon go-live flip): with a comms adapter enabled, the
    comms boot graph builds a REAL :class:`alfred.security.quarantine.QuarantinedExtractor`
    over a LIVE quarantined child spawned via
    :func:`alfred.security.quarantine_child_io.spawn_quarantine_child_io`. On a
    non-Linux / unprovisioned host (no ``bwrap``, no bound interpreter) that spawn
    raises :class:`alfred.security.quarantine_child_io.QuarantineChildSpawnError`.

    Fail-closed (CLAUDE.md hard rule #7): the daemon REFUSES boot with this audited
    failure rather than degrading to a fixture extractor in production — comms
    requires the dual-LLM quarantine child to be live. The operator-facing message
    points at the bwrap/Linux provisioning requirement. There is NO dev fixture
    fallback by design.
    """

    failure_reason: Literal["quarantine_child_spawn_failed"] = "quarantine_child_spawn_failed"


class CommsAdapterSpawnFailedFailure(_BootFailureBase):
    """An enabled comms adapter failed to spawn / handshake at boot (PR-S4-11b).

    Fail-closed (CLAUDE.md hard rule #7): an operator opted an adapter in via
    ``comms_enabled_adapters``, so a broken manifest / spawn / not-ok handshake
    must REFUSE the boot rather than silently skip the adapter and leave the
    operator believing comms is live. ``adapter_id`` is a closed-vocabulary
    config token (charset-validated by the Settings field), never raw content.
    """

    failure_reason: Literal["comms_adapter_spawn_failed"] = "comms_adapter_spawn_failed"
    adapter_id: str = ""


class CommsAdapterBindFailedFailure(_BootFailureBase):
    """A comms adapter's daemon-owned unix socket failed to bind at boot (ADR-0031).

    The TUI-over-socket adapter listens on a daemon-owned 0600 socket under the
    0700 runtime dir. A bind ``OSError`` (e.g. a foreign inode at the path the
    listener refuses to unlink, or a permission fault) is a daemon-side, boot-time
    fault — REFUSE fail-closed (CLAUDE.md hard rule #7) rather than park a
    half-bound adapter. Distinct from ``comms_adapter_spawn_failed`` so forensics
    can tell a socket-bind fault apart from a manifest/spawn/handshake refusal in
    the durable boot row (ADR-0031's "audited bind failure" contract). ``adapter_id``
    is a closed-vocabulary config token (charset-validated by the Settings field),
    never raw content.
    """

    failure_reason: Literal["comms_adapter_bind_failed"] = "comms_adapter_bind_failed"
    adapter_id: str = ""


class CommsPromoterMisconfiguredFailure(_BootFailureBase):
    """A classifier-bearing comms adapter kind yielded a ``None`` promoter (PR-S4-235-1).

    The boot-time mirror of the M2 fail-closed guard in
    :func:`alfred.comms_mcp.inbound.process_inbound_message`. An adapter kind whose
    :data:`alfred.comms_mcp.classifier_registry.REQUIRED_CLASSIFIERS_BY_KIND` set is
    non-empty (e.g. ``"discord"``) MUST receive a host-side
    :class:`alfred.comms_mcp.sub_payload_promotion.SubPayloadPromoter` so raw (T3)
    sub-payloads are promoted to single-use ``ContentHandle`` references BEFORE the
    quarantined extract (CLAUDE.md hard rule #5). The per-adapter promoter factory is
    deterministic — it builds a promoter for exactly the classifier-bearing kinds — so
    a ``None`` promoter for such a kind is a structural wiring defect, not a runtime
    data condition.

    Rather than wait for the FIRST inbound message to trip the M2 guard (an audited
    refusal mid-traffic), the daemon asserts the invariant at BOOT and REFUSES
    fail-closed with this distinct reason (CLAUDE.md hard rule #7). ``adapter_id`` is
    the closed-vocabulary config token (charset-validated by the Settings field),
    never raw content.
    """

    failure_reason: Literal["comms_promoter_misconfigured"] = "comms_promoter_misconfigured"
    adapter_id: str = ""


class CommsMultiAdapterUnsupportedFailure(_BootFailureBase):
    """More than one comms adapter is enabled — unsupported in this cut (FIX 4).

    PR-S4-11b builds ONE shared inbound orchestrator whose outbound sender is
    bound per-adapter (last-writer-wins), so with two enabled adapters one
    adapter's inbound turn would dispatch its ack through the OTHER adapter's
    runner — a cross-route. Until per-adapter inbound routing lands
    (PR-S4-11c), the daemon REFUSES boot fail-closed (CLAUDE.md hard rule #7)
    rather than parking a mis-wired multi-adapter graph. ``enabled_count`` is
    the number of enabled adapters (a small int derived from charset-validated
    config), safe in audit rows.
    """

    failure_reason: Literal["comms_multi_adapter_unsupported"] = "comms_multi_adapter_unsupported"
    enabled_count: int = 0


DaemonBootFailure = Annotated[
    EnvironmentNotSetFailure
    | UnsandboxedEnvInProductionFailure
    | LauncherNotPolicyResolvingFailure
    | SnapshotRefInitFailedFailure
    | CapabilityGateHandshakeFailedFailure
    | QuarantineGrantMissingFailure
    | BootInfraInstallFailedFailure
    | T3NonceRegistrationFailedFailure
    | QuarantineChildSpawnFailedFailure
    | CommsAdapterSpawnFailedFailure
    | CommsAdapterBindFailedFailure
    | CommsPromoterMisconfiguredFailure
    | CommsMultiAdapterUnsupportedFailure,
    Field(discriminator="failure_reason"),
]
"""Discriminated union over the daemon-boot refusal modes (spec §3.4 +
ADR-0026 ``quarantine_grant_missing`` + FIX 1 ``boot_infra_install_failed`` +
PR-S4-11c-2a0 ``t3_nonce_registration_failed`` + PR-S4-11c-2b
``quarantine_child_spawn_failed`` + PR-S4-11b ``comms_adapter_spawn_failed`` +
ADR-0031 ``comms_adapter_bind_failed`` +
PR-S4-235-1 ``comms_promoter_misconfigured`` +
FIX 4 ``comms_multi_adapter_unsupported``)."""
