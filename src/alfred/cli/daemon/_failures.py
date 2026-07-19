"""``DaemonBootFailure`` discriminated union (#174 PR-S4-1).

core-eng-001 round-2 closure: the daemon-boot refusal modes are
CLI-layer concepts (the probes run at the CLI layer, not inside
``Supervisor.start()``), so the union lives here rather than in
``alfred.supervisor.protocols``.

Each member carries a unique ``failure_reason`` Literal — the original set
was seeded by spec §3.4; later members (most of the union) postdate it and
are recorded via the union type's provenance-chain docstring below rather
than the spec. The discriminated union lets the CLI's refusal path
pattern-match on ``failure_reason`` and lets later slices extend the union
with failure-specific detail without re-touching the probes.
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


class SecretsConfigFailedFailure(_BootFailureBase):
    """A ``SecretBrokerConfigError`` at boot: the secrets file is misconfigured (#370 item 2).

    The daemon boot builds a :class:`alfred.security.secrets.SecretBroker` (in
    ``_build_boot_outbound_dlp``, and again in ``_build_comms_boot_graph``); an
    insecure / malformed / unreadable / missing-required / in-git-worktree
    secrets file raises :class:`alfred.security.secrets.SecretBrokerConfigError`.
    Previously both arms routed through :class:`BootInfraInstallFailedFailure`,
    so the durable ``daemon.boot.failed`` audit row could not tell a SECRETS
    misconfig apart from a capability-gate seed/install fault — both read
    ``boot_infra_install_failed``. This dedicated reason discriminates a secrets
    problem in the durable ``daemon.boot.failed`` audit row (DB-queryable) and
    the ``daemon.boot.failed`` hookpoint payload (devex dx-001). The
    ``alfred audit log`` CLI renders it in the REASON column too (``_row_reason``
    falls back to ``subject.failure_reason`` — #381).

    The OPERATOR-facing refusal message is UNCHANGED — it stays the exception's
    own ``str(exc)`` carrying the concrete remedy (chmod 600 / move out of the
    git repo / fix the TOML syntax); only the audit ``failure_reason`` changes
    (``_refuse_boot``'s fixed-subject discriminator, #374). No extra fields: the
    subtype detail (path / mode / parent) rides the operator message, never the
    audit row (spec §5.6 — an audit field could echo a filesystem fragment).
    """

    failure_reason: Literal["secrets_config_failed"] = "secrets_config_failed"


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


class QuarantineProviderKeyUnsetFailure(_BootFailureBase):
    """No quarantine provider key is configured at boot (#340 golive refuse-boot).

    The §20.2 PRIMARY refuse-boot: with a comms adapter enabled, the comms boot
    graph resolves the quarantined child's provider key from the secret broker
    (``_resolve_provider_key`` in ``comms_mcp.daemon_runtime``) SYNCHRONOUSLY,
    BEFORE the ``spawn_quarantine_child_io`` await. When
    ``quarantine_provider_api_key`` is unset that resolve raises
    :class:`alfred.comms_mcp.daemon_runtime.QuarantineProviderKeyUnsetError`.

    Fail-closed (CLAUDE.md hard rule #7 / §20.3.1 must-not-regress): the go-live
    child makes a REAL provider call, so an unset key must REFUSE boot rather than
    resolve to a fallback placeholder — a real client built on a bogus key would
    be a SILENT dead-LLM. Distinct from ``quarantine_child_spawn_failed`` (the
    child could not spawn) and from #444's ``provider_key_delivery_failed`` (a
    child-still-up POST-spawn fd-3 delivery fault): THIS is the PRE-spawn,
    key-unset-at-boot refusal. The operator-facing message names the
    ``quarantine_provider_api_key`` secret + how to set it; the audit row carries
    only the ``failure_reason`` (``_refuse_boot``'s fixed subject shape).
    """

    failure_reason: Literal["quarantine_provider_key_unset"] = "quarantine_provider_key_unset"


class QuarantineMaxTokensInvalidFailure(_BootFailureBase):
    """The quarantine per-extraction ``max_tokens`` budget is ``<= 0`` at boot (#340 golive).

    The §17 / §20.2 fail-loud: with a comms adapter enabled, the comms boot graph
    resolves the quarantined child's ``(model, max_tokens)`` SYNCHRONOUSLY, PRE-spawn
    (``_resolve_quarantine_model_config`` in ``comms_mcp.daemon_runtime``). A non-positive
    budget raises
    :class:`alfred.comms_mcp.daemon_runtime.QuarantineMaxTokensInvalidError`.

    Fail-closed (CLAUDE.md hard rule #7): a ``<= 0`` budget would make every extraction's
    ``CompletionRequest`` fail its ``>0`` validator — a retry-eligible
    :class:`pydantic.ValidationError` the dispatch loop LAUNDERS into a ``cannot_extract``
    refusal, masking the misconfiguration. REFUSE boot (audited, exit 2) rather than ship a
    child whose every extraction silently refuses. Distinct from
    ``quarantine_provider_key_unset`` (key unset) and ``quarantine_child_spawn_failed``
    (spawn fault): THIS is the pre-spawn, budget-invalid refusal. The audit row carries only
    the ``failure_reason`` (``_refuse_boot``'s fixed subject shape).
    """

    failure_reason: Literal["quarantine_max_tokens_invalid"] = "quarantine_max_tokens_invalid"


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


class CommsAdapterUnknownKindFailure(_BootFailureBase):
    """An enabled comms adapter declares an ``adapter_kind`` the host does not know (#374).

    The manifest's ``[comms_mcp] adapter_kind`` is a non-empty string but not a member
    of the host's closed vocabulary
    (:data:`alfred.comms_mcp.classifier_registry.REQUIRED_CLASSIFIERS_BY_KIND`) — a
    typo'd or unregistered kind. REFUSE fail-closed (CLAUDE.md hard rules #5 + #7):
    spawning it would wire a ``None`` promoter and no host classifiers, letting raw
    (T3) sub-payloads reach the orchestrator unpromoted. Distinct from
    ``comms_adapter_spawn_failed`` so forensics can tell a typo'd/unregistered kind
    apart from a missing-module / malformed-manifest / handshake refusal by the
    ``failure_reason`` in the durable boot row — and so the operator-facing refusal
    names the offending field + value rather than the misleading generic "missing or
    malformed manifest" text. Both ``adapter_id`` and ``adapter_kind`` are config-origin
    tokens from the plugin manifest (never raw content); they ride this carrier to the
    ``daemon.boot.failed`` hookpoint payload (``_invoke_boot_failed``), while the audit
    row itself carries only the ``failure_reason`` (``_refuse_boot``'s fixed subject
    shape, uniform across all boot failures).
    """

    failure_reason: Literal["comms_adapter_unknown_kind"] = "comms_adapter_unknown_kind"
    adapter_id: str = ""
    adapter_kind: str = ""


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


class EgressPlaneUnavailableFailure(_BootFailureBase):
    """The egress plane (``ALFRED_EGRESS_PROXY_URL``) is unset/blank at boot (#338 PR2).

    ``_build_comms_boot_graph`` is the first boot caller of
    :func:`alfred.cli._bootstrap.build_router`, which builds a REAL, egress-proxied
    :class:`alfred.providers.router.ProviderRouter` for the
    :class:`alfred.comms_mcp.real_turn_adapter.RealTurnOrchestratorAdapter` (the
    deterministic-echo adapter is gone). ``build_router`` calls
    :meth:`alfred.egress.client.EgressClient.from_settings` FIRST, which raises
    :class:`alfred.egress.errors.IOPlaneUnavailableError` when the proxy URL is
    unset/blank — the connectivity-free core (Spec C / ADR-0042) has no
    direct-egress fallback. REFUSE fail-closed (CLAUDE.md hard rule #7) rather than
    let this propagate as an uncaught traceback (the #368 anti-pattern) out of
    ``_start_async``. Reachable in practice: unlike ``deepseek_api_key``,
    ``egress_proxy_url`` is an OPTIONAL ``Settings`` field, so no earlier
    required-field guard trips first.
    """

    failure_reason: Literal["egress_plane_unavailable"] = "egress_plane_unavailable"


class RouterSecretMissingFailure(_BootFailureBase):
    """The router's ``deepseek_api_key`` secret lookup raised at boot (#338 PR2).

    The same ``build_router`` call (see :class:`EgressPlaneUnavailableFailure`)
    resolves the DeepSeek provider key via
    ``secret_broker.get("deepseek_api_key")``, which raises
    :class:`alfred.security.secrets.UnknownSecretError` (a ``KeyError`` subclass)
    when the key is unprovisioned. UNREACHABLE via a real ``_start_async`` boot
    TODAY: ``deepseek_api_key`` is a REQUIRED ``Settings`` field, so a missing key
    already trips the earlier required-field ``SettingsError`` guard (itself
    audited as ``EnvironmentNotSetFailure``) before ``_build_comms_boot_graph``
    ever runs. Kept as DEFENSE-IN-DEPTH — mirroring the ``SecretsConfigFailedFailure``
    "unreachable-today" precedent at the sibling ``_build_comms_boot_graph`` call
    site — so a future decoupling of the Settings field from the broker lookup
    (or a broker-layer secrets-file drift) still refuses fail-closed (audited,
    exit 2) rather than crash uncaught (CLAUDE.md hard rule #7).
    """

    failure_reason: Literal["router_secret_missing"] = "router_secret_missing"


class OperatorNotSeededFailure(_BootFailureBase):
    """No single live operator user exists when the comms boot graph assembles (#338 PR2).

    #338 PR2's cutover to :class:`alfred.comms_mcp.real_turn_adapter.RealTurnOrchestratorAdapter`
    makes ``_build_comms_boot_graph`` build a REAL
    :class:`alfred.orchestrator.core.Orchestrator`. Its constructor SYNCHRONOUSLY
    calls ``identity_resolver.get_operator()`` (``core.py:308``) to cache the
    household operator for the orchestrator's lifetime, which raises
    :class:`alfred.identity.errors.IdentityResolutionError` when ZERO or MORE THAN
    ONE operator user exists (``identity/resolver.py:191/197``). Before this arm
    that propagated as an UNCAUGHT crash out of ``_start_async`` (exit 1, no audit
    row) — the #368 anti-pattern this whole failure family exists to close
    (CLAUDE.md hard rule #7). Not one of the plan's originally-enumerated FOLD-2
    pair; carried forward from the Task-3 review as a must-fix sibling gap. The
    operator-facing message names the concrete remedy (``alfred user add
    --authorization operator``); the SAME reason covers both the zero- and
    multiple-operator cases (the resolver's message differs, but the CLI's
    ``except`` arm — and this discriminator — does not distinguish them; the
    audit row's content-free contract carries no operator-identifying detail
    either way).
    """

    failure_reason: Literal["operator_not_seeded"] = "operator_not_seeded"


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
    | SecretsConfigFailedFailure
    | T3NonceRegistrationFailedFailure
    | QuarantineChildSpawnFailedFailure
    | QuarantineProviderKeyUnsetFailure
    | QuarantineMaxTokensInvalidFailure
    | CommsAdapterSpawnFailedFailure
    | CommsAdapterBindFailedFailure
    | CommsAdapterUnknownKindFailure
    | CommsPromoterMisconfiguredFailure
    | CommsMultiAdapterUnsupportedFailure
    | EgressPlaneUnavailableFailure
    | RouterSecretMissingFailure
    | OperatorNotSeededFailure,
    Field(discriminator="failure_reason"),
]
"""Discriminated union over the daemon-boot refusal modes (spec §3.4 +
ADR-0026 ``quarantine_grant_missing`` + FIX 1 ``boot_infra_install_failed`` +
#370 item 2 ``secrets_config_failed`` +
PR-S4-11c-2a0 ``t3_nonce_registration_failed`` + PR-S4-11c-2b
``quarantine_child_spawn_failed`` + #340 golive ``quarantine_provider_key_unset`` +
#340 golive Task 15 ``quarantine_max_tokens_invalid`` +
PR-S4-11b ``comms_adapter_spawn_failed`` +
ADR-0031 ``comms_adapter_bind_failed`` +
#374 ``comms_adapter_unknown_kind`` +
PR-S4-235-1 ``comms_promoter_misconfigured`` +
FIX 4 ``comms_multi_adapter_unsupported`` +
#338 PR2 ``egress_plane_unavailable`` / ``router_secret_missing`` (FOLD-2) +
``operator_not_seeded`` (Task-3-review must-carry))."""
