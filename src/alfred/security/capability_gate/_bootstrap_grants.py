"""First-party system bootstrap grants — seeded, not reviewer-gated.

ADR-0026. A small, fixed set of AlfredOS's OWN defences must be live
before any operator-issued grant lands: the system-tier
``security.quarantined.extract`` DLP subscriber (spec §6.5, issue #158)
is registered inside :meth:`alfred.security.quarantine.QuarantinedExtractor.__init__`,
and the registry's capability gate denies that registration unless an
``approved`` grant exists for it. Routing a defence the host itself
ships through the reviewer-gate proposal flow would be circular — the
proposal flow runs INSIDE the same daemon whose extractor needs the
grant to construct.

The resolution (ADR-0026): the host seeds these first-party grants
directly into ``plugin_grants`` at boot, BEFORE
:meth:`alfred.security.capability_gate._gate.RealGate.create` loads the
in-memory policy. This is NOT a fail-open: the gate still denies every
registration not covered by an ``approved`` row. The ONLY thing the
seed changes is that the in-tree DLP subscriber is among the approved
rows — exactly as if an operator had issued the grant, but without the
circular dependency. We do NOT special-case the gate to "trust
first-party by module name" (the anti-pattern this constant exists to
avoid): the seed lands a real row, and the same hot-path
:meth:`GatePolicy.check` evaluates it.

The ``proposal_branch`` sentinel ``"bootstrap:first-party-system"``
marks these rows in the audit graph so a forensic query can tell a
host-seeded defence apart from an operator/reviewer grant. The seed is
idempotent (``ON CONFLICT DO UPDATE`` to the same values) and NEVER
runs the revoke-diff that a state.git rebuild does — seeding must never
revoke an operator grant.

Operator-visible behaviour to be aware of (NIT1): because the seed's
``ON CONFLICT DO UPDATE`` restores ``state='approved'`` (the same
``_execute_upsert_grant`` SQL the reviewer-merge rebuild uses), a boot
seed RE-PROMOTES a first-party row an operator had MANUALLY ``revoked``
back to ``approved``. This is intended — the first-party DLP subscriber
is a MANDATORY defence; the daemon refuses to boot without it (the
ADR-0026 grant-assertion), so a persisted manual revoke of it would
otherwise wedge every boot. An operator who revokes the first-party DLP
grant and reboots will see it ``approved`` again, by design. This is the
ONLY grant category the seed re-promotes; operator grants are never
touched (additive-only, no revoke-diff).
"""

from __future__ import annotations

from typing import Final

from alfred.security.capability_gate.policy import GrantRow

# The state.git ``proposal_branch`` value is a structural slot on every
# :class:`GrantRow`; first-party seeds carry this sentinel instead of a
# real branch name so audit-graph traversal can distinguish a
# host-seeded defence from an operator/reviewer-issued grant.
_FIRST_PARTY_PROPOSAL_BRANCH: Final[str] = "bootstrap:first-party-system"


FIRST_PARTY_SYSTEM_GRANTS: Final[tuple[GrantRow, ...]] = (
    # spec §6.5 / issue #158: the system-tier post-chain DLP scan on
    # ``security.quarantined.extract``. ``plugin_id`` MUST equal
    # ``OutboundDlpExtractSubscriber.__call__.__module__`` — the
    # attribution :func:`register_extract_dlp_subscriber` queries the
    # gate with. ``content_tier=None`` because this is a subscriber-tier
    # (capability-axis) grant, not a content-clearance grant — the two
    # axes are orthogonal (spec §4.3).
    GrantRow(
        # This literal MUST equal ``OutboundDlpExtractSubscriber.__call__.__module__``
        # (the attribution :func:`register_extract_dlp_subscriber` queries the
        # gate with). The drift-guard
        # ``test_bootstrap_grants.test_seeded_plugin_id_matches_dlp_subscriber_module``
        # pins the two together — a change here that desyncs from the module
        # path fails that test rather than silently denying the DLP subscriber
        # at register time.
        plugin_id="alfred.security._extract_dlp_subscriber",
        subscriber_tier="system",
        hookpoint="security.quarantined.extract",
        content_tier=None,
        proposal_branch=_FIRST_PARTY_PROPOSAL_BRANCH,
    ),
    # --- #339 PR3: the three grants the live agentic tool-dispatch T3 path
    # needs. Until seeded, a real turn's web.fetch dispatch fails LOUD
    # (downgrade_denied) at the second content-clearance boundary. Mirrors the
    # test fixtures tests.helpers.gates.make_tool_dispatch_gate() (grants 1+3)
    # and tests/integration/orchestrator/test_tool_assembly._assembly_gate()
    # (grant 2). ADR-0046 (dual-LLM tool-result flow) + ADR-0026.
    GrantRow(
        # dispatch_tool: gate.check(plugin_id=TOOL_DISPATCH_PLUGIN_ID,
        #   hookpoint="tool.dispatch", requested_tier="system").
        plugin_id="alfred.orchestrator.tool_dispatch",
        subscriber_tier="system",
        hookpoint="tool.dispatch",
        content_tier=None,
        proposal_branch=_FIRST_PARTY_PROPOSAL_BRANCH,
    ),
    GrantRow(
        # quarantined_to_structured: gate.check_content_clearance(
        #   plugin_id="alfred.quarantined-llm",
        #   hookpoint="quarantine.dereference", content_tier="T3").
        plugin_id="alfred.quarantined-llm",
        subscriber_tier="system",
        hookpoint="quarantine.dereference",
        content_tier="T3",
        proposal_branch=_FIRST_PARTY_PROPOSAL_BRANCH,
    ),
    GrantRow(
        # downgrade_to_orchestrator: gate.check_content_clearance(
        #   plugin_id="t3.downgrade_to_orchestrator",
        #   hookpoint="t3.downgrade_to_orchestrator", content_tier="T3").
        plugin_id="t3.downgrade_to_orchestrator",
        subscriber_tier="system",
        hookpoint="t3.downgrade_to_orchestrator",
        content_tier="T3",
        proposal_branch=_FIRST_PARTY_PROPOSAL_BRANCH,
    ),
)
"""The fixed first-party system grants seeded at boot (ADR-0026).

Four rows today: the DLP subscriber + the three #339 tool-dispatch grants.
Drives BOTH the seed
(:meth:`alfred.security.capability_gate.backend.PostgresBackend.seed_first_party_grants`)
AND the daemon's post-install grant assertion — the SAME constant on
both sides so the seed and the liveness check can never drift.
"""


__all__ = ["FIRST_PARTY_SYSTEM_GRANTS"]
