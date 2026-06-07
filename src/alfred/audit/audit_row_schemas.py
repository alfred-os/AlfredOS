"""Audit row field-list constants for all Slice-3 audit row families.

Every constant is a ``Final[frozenset[str]]`` naming the fields an audit
row in that family carries. Placement rationale: Slice 3 introduces five
emitter subsystems (plugins/, supervisor/, security/, orchestrator/,
identity/). Centralising constants here provides a single import surface
that prevents field-name drift; the Slice-2.5 co-located-with-emitter
pattern is superseded because the emitter count crossed the threshold
where mirroring becomes rot (spec §13).

Usage::

    from alfred.audit import audit_row_schemas
    assert "plugin_id" in audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS

**Conditional-field convention.** Every key in a ``*_FIELDS`` constant
MUST be present in the ``subject`` dict at emit time. Use ``None`` for
fields that are conditionally absent (e.g. ``plugin_id=None`` for
startup-level ``supervisor.config_insecure`` rows;
``denied_dispatch_count=None`` for the ``entering_fail_closed``
``supervisor.capability_gate_unavailable`` row). This is enforced by
``AuditWriter.append_schema()`` via symmetric key-set validation —
dropping a key entirely is a ``ValueError`` because the symmetric check
defends against typo'd field names silently shadowing the real field.

**Never include ``str(exc)`` or ``exc.args`` in audit row fields** — they
may carry T3 content fragments. Only the Python type name (``type(exc).__name__``)
is safe per spec §5.6 and the ``_SUBSCRIBER_ERROR_AUDIT_FIELDS`` pattern
from Slice 2.5.
"""

from __future__ import annotations

from typing import Final, Literal

# ---------------------------------------------------------------------------
# Closed-vocabulary type aliases
# ---------------------------------------------------------------------------

RateLimitBucket = Literal[
    "per_domain",
    "per_user",
    "daily_budget",
    "handle_cap",  # spec §6.2 widening — per-user concurrent ContentHandle cap
]
"""Closed vocabulary of rate-limit refusal buckets recorded in
``WEB_FETCH_FIELDS['rate_limit_bucket']``. Future emitter typos surface
at type-check time, not runtime."""

DlpScanResult = Literal[
    "clean",
    "scanned_dirty",
    "dlp_scan_error",
    "domain_not_allowed",
    "rate_limited",
    "transport_error",
    "dispatch_shape_error",
    "internal_ip_refused",
    "redirect_refused",
    "tls_verification_failed",
    "fetch_error",
    "handle_cap_exceeded",  # spec §6.2 — per-user concurrent ContentHandle cap refusal
    "handle_id_mismatch",  # spec §3 — host-side equality check failed
    "dispatch_param_invalid",  # #147 — host-side Pydantic validation of web.fetch params
]
"""Closed vocabulary recorded in ``WEB_FETCH_FIELDS['dlp_scan_result']``.
Widened across two trust-boundary PRs:
- ``handle_cap_exceeded`` / ``handle_id_mismatch`` by the handle-cap design
  (slice-3 design spec §7.10).
- ``dispatch_param_invalid`` by host-side Pydantic validation of the
  ``web.fetch`` JSON-RPC params dict (#147 spec §4).

See ``docs/subsystems/security.md`` for the audit-vocabulary section
and ``docs/runbooks/handle-cap-exceeded.md`` for the operator-facing
widening notice."""

# ---------------------------------------------------------------------------
# plugin.lifecycle.* family
# ---------------------------------------------------------------------------

# Fields common to loaded / load_refused / crashed / quarantined / reloaded.
# crashed rows additionally carry exception_type (see PLUGIN_LIFECYCLE_CRASHED_FIELDS).
PLUGIN_LIFECYCLE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "plugin_id",
        "manifest_subscriber_tier",
        "manifest_version",
        "sandbox_profile",
        "exit_code",
        "signal",
        "restart_count",
        "breaker_state",
        "correlation_id",
    }
)

# crashed-specific superset — Python type name only, never str(exc) or exc.args
# (a misbehaving subprocess can carry T3 fragments into its crash trace; see spec §5.6)
PLUGIN_LIFECYCLE_CRASHED_FIELDS: Final[frozenset[str]] = PLUGIN_LIFECYCLE_FIELDS | frozenset(
    {
        "exception_type",
    }
)

# quarantined-specific superset — emitted when circuit breaker trips or post-handshake
# hook-registration attack detected (SIGKILL path, spec §4.6, §10.2).
PLUGIN_LIFECYCLE_QUARANTINED_FIELDS: Final[frozenset[str]] = PLUGIN_LIFECYCLE_FIELDS | frozenset(
    {
        "quarantine_reason",  # "circuit_breaker_open" | "protocol_violation"
        "trip_count",
        # PR-S3-3a plan §1495-1526: audit row emits whether transport.kill() succeeded.
        # True = SIGKILL delivered; False = kill raised (subprocess already dead, asyncio
        # timeout, etc.). Both cases still emit the row so operators see the quarantine
        # event regardless of kill outcome.
        "kill_succeeded",
    }
)

# ---------------------------------------------------------------------------
# plugin.grant.* family
# ---------------------------------------------------------------------------

# Fields for requested / approved / denied / revoked rows.
# Note: field is "subscriber_tier" not "tier" — the subscriber-capability axis
# (system/operator/user-plugin), orthogonal to content trust tier (T0-T3).
# See spec §4.3 two-axis naming rule and docs/glossary.md.
PLUGIN_GRANT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "plugin_id",
        "subscriber_tier",
        "hookpoint",
        "operator_user_id",
        "proposal_branch",
        "correlation_id",
    }
)

# Operator-CLI ingress superset for the ``plugin.grant.requested`` row
# AND its sibling ``plugin.grant.revoke.requested`` row.
#
# CR-149 round-6: the previous alias to :data:`PLUGIN_GRANT_FIELDS`
# meant the requested-side row could not carry ``trust_tier_of_trigger``
# because :meth:`AuditWriter.append_schema` enforces symmetric keys.
# The terminal ``plugin.grant.rebuilt`` row (still on the lifecycle
# constant) lives in the T0 swimlane — the supervisor merges in
# response to a host-level state.git signal, not a user-typed CLI
# command. The ``*.requested`` row is the operator-typed ingress, so
# the canonical swimlane is T1 and the schema MUST allow the tag
# (PRD §7.1 + CLAUDE.md hard rule #3). Widening this constant lets
# every emit site attach ``trust_tier_of_trigger="T1"`` and surface in
# ``alfred audit graph --tier T1`` without drift.
#
# CR-149 round-7: the same superset now also backs the revoke request
# row. ``alfred plugin revoke`` is the second operator-typed CLI
# ingress for the plugin-grant subsystem; it queues a reviewer-gated
# proposal exactly like ``alfred plugin grant`` does, just with the
# opposite intent. Leaving the revoke row on :data:`PLUGIN_GRANT_FIELDS`
# (which does not carry ``trust_tier_of_trigger``) sank it into the T0
# lane next to the post-merge rebuild row and broke the audit-graph
# consistency the grant path's round-6 fix established. Both request
# rows now share this schema so an operator's audit-graph filter on
# ``--tier T1`` surfaces every reviewer-gated CLI ingress uniformly.
PLUGIN_GRANT_REQUESTED_FIELDS: Final[frozenset[str]] = PLUGIN_GRANT_FIELDS | frozenset(
    {"trust_tier_of_trigger"}
)

# ---------------------------------------------------------------------------
# quarantine.extract family
# ---------------------------------------------------------------------------

# Fields for every quarantine.extract audit row (extracted / refused / malformed_exhausted
# / content_expired result values — see migration 0007_audit_result_slice3_values).
# extraction_mode values: "native_constrained" | "json_object_unconstrained"
#   | "prompt_embedded_fallback"
# trust_tier_of_trigger: always "T3" for quarantine.extract rows
# result values: "extracted" | "refused" | "malformed_exhausted" | "content_expired"
#   | "post_stage_refused" | "protocol_violation" | "transport_failed"
#
# Audit-trace-key model (CR-158 round 4). The TOP-LEVEL ``trace_id``
# field (an :meth:`AuditWriter.append_schema` kwarg, NOT a member of
# this frozenset) on every ``quarantine.*`` audit row in this family
# carries the SHARED chain id (``chain_correlation_id`` minted at
# :meth:`alfred.security.quarantine.QuarantinedExtractor.extract`'s
# chain-entry point). The body-local per-invocation correlation id
# lives BELOW, as ``subject["correlation_id"]``, so forensic queries
# can either walk a single coherent trace (join on ``trace_id``,
# pulling in the pre/post/error hook-dispatch rows
# :func:`alfred.hooks.invoke.invoke` writes against the same chain
# id) or narrow to a specific body invocation (filter on
# ``subject["correlation_id"]``). The two ids are deliberately
# separate concepts at the audit-graph layer; the ``subject``
# field is the finer-grained correlation token, ``trace_id`` is
# the chain join key.
QUARANTINE_EXTRACT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "extraction_mode",
        "provider",
        "schema_name",
        "schema_version",
        "retry_count",
        "trust_tier_of_trigger",
        "result",
        # Body-local per-invocation correlation id (UUID minted inside
        # :meth:`_extract_body`). NOT the trace key — see the trace-key
        # model comment above. Finer-grained than ``trace_id``: a single
        # trace bucket (one ``chain_correlation_id``) contains exactly
        # one body invocation, so ``subject["correlation_id"]`` is a
        # 1-to-1 narrowing for the ``quarantine.extract`` /
        # ``quarantine.transport_failed`` / ``quarantine.protocol_violation``
        # rows. Cross-process audit consumers that have not adopted the
        # ``trace_id`` join key can still group on this field within a
        # single forensic export window.
        "correlation_id",
        # Set on ``post_stage_refused`` outcomes to the ``hook_id`` of the
        # refusing subscriber (e.g. ``OutboundDlpExtractSubscriber._SCAN_ID``).
        # ``None`` on all other outcomes. Required because post-stage
        # ``HookRefusal`` does NOT emit an upstream ``HOOKS_REFUSAL`` row
        # (``alfred.hooks.invoke._run_post`` is silent on this path —
        # §6.5 is pre-only by design), so this is the only forensic
        # surface for post-stage refusing-subscriber identity. Symmetric
        # validation in ``append_schema`` forces every emit site for
        # this family to populate the key explicitly.
        "refusing_hook_id",
    }
)

# ---------------------------------------------------------------------------
# tool.web.fetch family
# ---------------------------------------------------------------------------

# Fields for every tool.web.fetch audit row.
# manifest_commit_hash: forensic correlation for plugin version at fetch time
#   (spec §7.12).
# triggering_user_id: canonical_user_id of conversation turn — per-user
#   forensic attribution (spec §7.12).
# trust_tier_of_result: always "T3" for web.fetch rows.
# canary_tripped: bool.
WEB_FETCH_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "url",
        "domain",
        "status_code",
        "content_handle_id",
        "fetch_depth",
        "rate_limit_bucket",
        "manifest_commit_hash",
        "trust_tier_of_result",
        "dlp_scan_result",
        "canary_tripped",
        "triggering_user_id",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# supervisor.breaker.* family
# ---------------------------------------------------------------------------

# Fields for supervisor.breaker.reset rows (operator-initiated circuit-breaker reset).
# See also SUPERVISOR_BREAKER_TRIPPED_FIELDS for the tripped event.
SUPERVISOR_BREAKER_RESET_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "component_id",
        "old_state",
        "new_state",
        "trip_count",
        "operator_user_id",
        "correlation_id",
    }
)

# supervisor.breaker.tripped — distinct event from breaker.reset (spec §14 hookpoint table)
SUPERVISOR_BREAKER_TRIPPED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "component_id",
        "trip_count",
        "last_failure_type",
        "breaker_state",  # always "OPEN" at trip time
        "correlation_id",
    }
)

# Emitted by ``alfred supervisor reset --confirm`` at the moment the
# operator queues a reviewer-gated BreakerResetProposal (ADR-0021 #171).
# Mirrors the ``WEB_ALLOWLIST_REQUESTED_FIELDS`` / ``CONFIG_SET_REQUESTED_FIELDS``
# shape — operator-CLI ingress row carrying the proposal_branch +
# correlation_id so the audit-graph correlator can join the CLI emit
# with the eventual dispatcher-side ``state.proposal.processed`` row
# (which carries the same proposal_id under a different audit family).
#
# Distinct from SUPERVISOR_BREAKER_RESET_FIELDS (the eventual terminal
# row that fires when the supervisor actually mutates the breaker):
# this family is the operator-typed REQUEST stand-in. The supervisor's
# RESET row covers the post-dispatch effect.
SUPERVISOR_BREAKER_RESET_REQUESTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "component_id",
        "operator_user_id",
        "proposal_branch",
        # CR-149 round-6: operator-CLI ingress carries the T1 tag so the
        # audit-graph swimlane (``alfred audit graph --tier T1``) shows
        # the operator-typed origin. Same rationale as the plugin-grant
        # / web-allowlist / config-set requested families.
        "trust_tier_of_trigger",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# security.t3_boundary.refused family
# ---------------------------------------------------------------------------

# Fields for security.t3_boundary.refused audit rows.
# caller_module_unverified: heuristic frame-derived label; NOT an
#   authenticated identity (spec §3.2).
T3_BOUNDARY_REFUSAL_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "caller_module_unverified",
        "attempted_tier",
        "hookpoint",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# identity.t1_ingress family
# ---------------------------------------------------------------------------

# Fields emitted at the identity.t1_ingress hookpoint
# (role x adapter classification).
T1_INGRESS_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "user_id",
        "adapter_name",
        "trust_tier_of_trigger",
        "correlation_id",
    }
)

# identity.t1_downgrade — explicit T1 → T2 broadcast-safe conversion.
# downgrade_explicit=True required on the audit row; see spec §3.6.
T1_DOWNGRADE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "user_id",
        "trust_tier_of_trigger",
        "trust_tier_of_response",
        "downgrade_explicit",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# quarantine.t3_derived_downgrade family
# ---------------------------------------------------------------------------

# Fields for quarantine.t3_derived_downgrade rows (T3_derived → T2 crossing
# at the orchestrator boundary; emitted by
# ``alfred.security.quarantine.downgrade_to_orchestrator``).
#
# Distinct from T1_DOWNGRADE_FIELDS (rvw-003): T1_DOWNGRADE covers the
# explicit T1→T2 broadcast-safe conversion; this constant covers the
# T3-derived→T2 crossing, which is a different trust transition with
# different forensic attribution (the quarantined-LLM invocation that
# produced the structured extraction). Sharing the schema would conflate
# the two; spec §3.7 + §5.5 require they remain distinct families.
#
# source_tier: always the string "T3_derived".
# target_tier: always the string "T2".
# downgrade_explicit: always True (the gate check enforces deliberateness;
#   see spec §3.7 and CapabilityGate.check_content_clearance).
# quarantined_llm_invocation_id: links the audit row back to the specific
#   QuarantinedExtractor call that produced the structured payload, for
#   per-extraction forensic attribution.
# downgrade_reason: short tag (e.g. "structured_extraction_consumed") for
#   audit-graph filtering; NOT free-text and never carries T3 content.
T3_DERIVED_DOWNGRADE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "extraction_id",
        "quarantined_llm_invocation_id",
        "source_tier",
        "target_tier",
        "downgrade_reason",
        "trust_tier_of_trigger",
        "trust_tier_of_response",
        "downgrade_explicit",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# plugin.grant.revoked_inflight family
# ---------------------------------------------------------------------------

# Fields for in-flight dispatch denial rows (grant revoked while dispatch in progress).
PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "plugin_id",
        "hookpoint",
        "operator_user_id",
        "in_flight_dispatch_id",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# supervisor.capability_gate_unavailable family
# ---------------------------------------------------------------------------

# One row per state-transition: entering_fail_closed AND exiting_fail_closed.
# denied_dispatch_count: cumulative count since entering fail-closed (exit row only; spec §8.1).
SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "state_transition",  # "entering_fail_closed" | "exiting_fail_closed"
        "denied_dispatch_count",
        "backing_store_error_type",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# plugin.grant.rebuilt family
# ---------------------------------------------------------------------------

# Emitted by RealGate.rebuild_from_state_git on a successful state.git
# parse → Postgres projection. One row per cache miss (the head changed
# vs the cached sync hash); cache hits short-circuit silently per spec
# §8.1. grant_count records the size of the freshly-projected snapshot
# so an operator can correlate an unexpected churn between two adjacent
# rebuilds with the proposal-merge that triggered it. commit_hash is
# the full state.git HEAD SHA (not the 8-char display variant) — the
# audit-graph correlator matches across full-length hashes.
#
# trust_tier_of_trigger: always "T0" — the supervisor bootstraps the
# rebuild from a host-level proposal-merge signal, not user content.
# actor_user_id: always None — there is no per-user actor; the
# reviewer-approval row sits earlier in the audit graph and carries
# the operator's canonical id.
CAPABILITY_GATE_REBUILD_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "commit_hash",
        "grant_count",
        "trust_tier_of_trigger",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# supervisor.config_insecure family
# ---------------------------------------------------------------------------

# Emitted at every plugin start when ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1
# (spec §4.8). plugin_id may be absent for startup-level rows (not
# per-plugin-launch). Example insecure_config_key values:
# "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", "web_fetch.skip_tls_verify".
SUPERVISOR_CONFIG_INSECURE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "insecure_config_key",
        "plugin_id",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# supervisor.action_timeout family
# ---------------------------------------------------------------------------

# One row per turn that exceeds orchestrator.action_deadline_seconds (spec §10.5).
# phase_at_timeout: best-effort label for the phase in progress at deadline.
SUPERVISOR_ACTION_TIMEOUT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "user_id",
        "action_duration_seconds",
        "deadline_seconds",
        "phase_at_timeout",  # "web_fetch" | "quarantine_extract" | "hookchain" | "unknown"
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# web.allowlist.manifest_broadening_capped family
# ---------------------------------------------------------------------------

# Emitted on every manifest load where the effective allowlist is narrower
# than the manifest's declared allowed_domains (spec §7.4).
WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "plugin_id",
        "manifest_domains",
        "operator_allowed_domains",
        "capped_domains",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# web.allowlist.requested family
# ---------------------------------------------------------------------------

# Emitted by the ``alfred web allowlist add`` / ``alfred web allowlist
# remove`` CLI surfaces (arch-001 / cross-cutting R2) at the moment the
# operator queues a reviewer-gated proposal. The row stand-in goes out
# BEFORE the state.git write so a crash mid-write still leaves a
# forensic breadcrumb pointing at operator intent — see the supervisor
# CLI's ``_emit_breaker_reset_attempt_audit`` precedent (sec-pr-s3-6-04).
#
# action: ``"add"`` | ``"remove"`` — distinguishes the two reviewer-
#   gated entry points so the audit graph can join an ``add`` request
#   with the eventual ``web.allowlist.changed`` row the projection emits
#   on reviewer merge. Distinct from the manifest-broadening capped
#   family which fires at manifest load, not operator request.
# operator_user_id: canonical user_id of the human operator who queued
#   the proposal. PR-S3-7 wires the IdentityResolver bridge; until then
#   the emit site passes ``None`` (devex-007) and the row carries the
#   tag so the eventual upgrade is a single emit-site edit.
# proposal_branch: full ``proposal/web-allowlist-{add,remove}-<hex>``
#   name written into state.git. Carried so the audit-graph correlator
#   can join the CLI-side row with the reviewer-merge row by branch.
# path_prefix: same default + semantics as the CLI flag (``"/"`` when
#   omitted). Carried so the reviewer payload + audit row stay
#   structurally identical.
# domain: the bare domain (not URL, no scheme). Closed-set validator
#   refuses URL-shaped inputs at parse time so this field never carries
#   path-traversal or scheme injection material.
WEB_ALLOWLIST_REQUESTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "action",
        "domain",
        "path_prefix",
        "operator_user_id",
        "proposal_branch",
        # CR-149 round-6: operator-CLI ingress — every reviewer-gated
        # CLI command MUST tag the trust tier of its trigger so the
        # audit-graph swimlane (``alfred audit graph --tier``) renders
        # the row in the correct T1 lane. PRD §7.1 + CLAUDE.md hard
        # rule #3.
        "trust_tier_of_trigger",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# config.set.requested family
# ---------------------------------------------------------------------------

# Emitted by the ``alfred config set`` CLI surface on the high-blast-key
# branch (arch-001 / cross-cutting R2). Low-blast keys mutate
# ``config/policies.yaml`` directly and do NOT emit through this family
# — they have no reviewer gate so the audit-graph traversal does not
# need to join a CLI emit to a reviewer-merge.
#
# CLAUDE.md hard rule #6 (secrets in the broker, not in payload): the
# row does NOT carry ``value`` even though the proposal payload does.
# A future high-blast knob whose value carries secret material (the
# quarantined-provider knob does not today, but a hypothetical
# operator-secrets knob could) would silently leak the secret into the
# audit log if ``value`` lived here. The audit row carries only the
# config_key + the proposal-flow metadata; the reviewer reads the value
# from the proposal payload itself.
#
# config_key: the closed-set CLI key ("quarantined-provider" today).
#   The known set lives in :data:`alfred.cli.config._HIGH_BLAST_KEYS`.
# operator_user_id: same semantics as the plugin-grant + web-allowlist
#   families — PR-S3-7 wires the resolver, the row carries the tag
#   today as ``None`` (devex-007).
# proposal_branch: full ``proposal/config-<key>-<hex>`` name.
CONFIG_SET_REQUESTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "config_key",
        "operator_user_id",
        "proposal_branch",
        # CR-149 round-6: operator-CLI ingress for high-blast config
        # mutations — the row carries the T1 tag so the audit-graph
        # swimlane shows the operator-typed origin (PRD §7.1 +
        # CLAUDE.md hard rule #3). Same rationale as the plugin-grant
        # and web-allowlist requested families.
        "trust_tier_of_trigger",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# security.dlp_outbound_refused family
# ---------------------------------------------------------------------------

# Fields for security.dlp_outbound_refused audit rows (outbound DLP scan failure).
DLP_OUTBOUND_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "wire",
        "direction",
        "scan_rule_matched",
        "field_name",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# state.proposal.* family (ADR-0021 — side-effecting dispatch)
# ---------------------------------------------------------------------------

# ``state.proposal.processed`` — emitted on every dispatched proposal
# (success or handler-returned-failure). The closed-vocab ``result``
# value carries the dispatch outcome (``applied`` /
# ``failed_handler``); ``failure_kind`` is None on the applied path
# and carries the closed-vocab failure discriminator otherwise.
#
# ``commit_sha`` is the dispatch-cycle HEAD captured at the HEAD-diff
# walk (the head that brought the blob into ``main``) and is the
# non-repudiable forensic join key per ADR-0021 §Threat model — distinct
# from the ``operator_user_id`` field which is self-claimed forensic
# context only. DLP redaction of ``failure_detail`` is tracked at #173;
# today the field is truncated only and the realised emit-site vocab is
# closed-set strings (``type(exc).__name__``, handler-returned reasons).
#
# ``processed_at`` carries the ledger row's wall-clock timestamp so the
# audit-graph correlator can join against the
# :class:`alfred.memory.models.ProcessedProposal` row by primary key +
# timestamp without re-querying Postgres.
STATE_PROPOSAL_PROCESSED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "proposal_type",
        "proposal_id",
        "result",
        "failure_kind",
        "handler_version",
        "processed_at",
        "operator_user_id",
        "commit_sha",
        "correlation_id",
    }
)

# ``state.proposal.dispatch_failed`` — emitted on framework-level dispatch
# failures (unknown_proposal_type, payload_validation, blob_not_found,
# handler_uncaught_exception). Superset of PROCESSED + the
# ``framework_error_kind`` discriminator so an audit-graph consumer can
# distinguish operator-caused failures (handler-returned ``failed``,
# which still emits the processed family) from framework-level failures
# (parse / unknown-type / uncaught) without re-classifying via
# ``failure_kind``.
STATE_PROPOSAL_DISPATCH_FAILED_FIELDS: Final[frozenset[str]] = (
    STATE_PROPOSAL_PROCESSED_FIELDS | frozenset({"framework_error_kind"})
)

# ``state.proposal.dispatch_cycle_skipped`` — emitted when an entire
# cycle is aborted due to infrastructure failure (Postgres unreachable,
# git command failure). ADR-0021 §Consequences (Negative): no silent
# skips. The cycle never resolved which proposals it would have
# processed, so this row carries only the ``skip_reason`` closed-vocab
# discriminator — no per-proposal fields are knowable at the abort
# point.
STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "skip_reason",
        "correlation_id",
    }
)


# ---------------------------------------------------------------------------
# Slice-4 audit-row constants (PR-S4-0a foundations)
# ---------------------------------------------------------------------------
#
# Twenty-three new ``Final[frozenset[str]]`` constants spanning every Slice-4
# subsystem: daemon boot lifecycle, carrier substitution (ADR-0022), policies
# hot-reload (ADR-0023), operator sessions (#153), sandbox launcher (#152 §5),
# comms-MCP foundations + addressing (#152 §6, ADR-0009 supersession).
#
# Field-set authoring rules carry over from Slice-3:
# * every conditional emit-time field appears in the set;
# * forensic join keys (``correlation_id``, ``boot_id``, ``user_id``,
#   ``inbound_message_id``, ``policies_snapshot_hash``) live on the row, not on
#   the line above the emit;
# * tier-tagged ID fields (``platform_user_id_hash``, ``machine_id_hash``)
#   carry pepper-keyed HMAC-SHA256 values (PR-S4-0b ships ``audit.hash_pepper``);
# * ``language`` is a BCP-47 tag on every comms inbound family (i18n hard rule).
#
# Consumers in PR-S4-1..11 ingest these constants via
# :func:`alfred.audit.log.AuditWriter.append_schema`; the writer treats the
# frozenset as the closed contract surface.

# ---------------------------------------------------------------------------
# daemon.boot family — PR-S4-1
# ---------------------------------------------------------------------------

DAEMON_BOOT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "boot_id",
        "started_at",
        "state_git_head_sha",
        "slice_version",
        "policies_snapshot_hash",
        "environment",
    }
)

DAEMON_BOOT_FAILED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "boot_id",
        "attempted_at",
        "failure_reason",
        "environment_source",
    }
)

DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "boot_id",
        "env_var_value",
        "etc_file_value",
        "resolved_value",
    }
)

# ---------------------------------------------------------------------------
# state.proposal.dispatch_failure family (DLP-into-failure_detail; #173)
# ---------------------------------------------------------------------------

# Emitted on the SUCCESS path of ``_record_failure`` when the DLP scan completed
# and the ledger row was written. Disjoint from ``DLP_OUTBOUND_REFUSED_FIELDS``
# (which fires on the refusal path). ``redacted_detail`` is the scan-then-
# truncate output; ``dlp_redactions_count`` is >=0 (binary signal in PR-S4-2;
# Slice-5 may sharpen).
PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "proposal_branch",
        "dispatch_attempted_at",
        "failure_class",
        "redacted_detail",
        "dlp_redactions_count",
        "correlation_id",
    }
)

# ---------------------------------------------------------------------------
# hooks.carrier_substitution family (ADR-0022; #170)
# ---------------------------------------------------------------------------

# Observation row emitted when an ``error``-stage subscriber returns a
# ``SubstituteResult`` and the dispatcher accepts the substitution per the
# strict-total-order tier-upgrade guard.
CARRIER_SUBSTITUTION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "hookpoint",
        "subscriber_id",
        "source_tier",
        "carrier_tier",
        "substituted_at",
    }
)

# Refusal row emitted when the dispatcher refuses a substitution (tier-upgrade
# attempt, recursion guard, payload type mismatch, or meta-hookpoint policy
# violation).
CARRIER_SUBSTITUTION_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "hookpoint",
        "subscriber_id",
        "attempted_source_tier",
        "carrier_tier",
        "reason",
        "refused_at",
    }
)

# ---------------------------------------------------------------------------
# config.reload family (ADR-0023; #159)
# ---------------------------------------------------------------------------

CONFIG_RELOAD_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "file_path",
        "prev_sha256",
        "new_sha256",
        "changed_keys",
        "loaded_at",
        # ``operator_session_id`` joins to ``policies_snapshot_history``
        # ``applied_by_operator_session_id`` (PR-S4-4 round-2 closure 4).
        # None for auto-applied watcher reloads (the writer records None too).
        "operator_session_id",
    }
)

# ``reason`` closed-vocab: parse_failure | high_blast_change |
# validation_failure | file_vanished | stat_failed | audit_write_failed
# (per spec §4 / PR-S4-4 round-2 closures).
CONFIG_RELOAD_REJECTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "file_path",
        "attempted_sha256",
        # ``reason`` closed-vocab: parse_failure | high_blast_change |
        # validation_failure | file_vanished | stat_failed |
        # audit_write_failed (PR-S4-4 round-2 closure 7: on audit-write
        # failure the watcher MUST emit this row via the fallback sink AND
        # re-raise; the active snapshot stays consistent with the last
        # successful audit).
        "reason",
        "offending_key",
        "dlp_scan_result",
        "operator_session_id",
    }
)

# ---------------------------------------------------------------------------
# operator.session family (#153)
# ---------------------------------------------------------------------------

OPERATOR_SESSION_CREATED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "user_id",
        "issued_at",
        "expires_at",
        "host",
        "machine_id_hash",
        "via",
    }
)

OPERATOR_SESSION_REVOKED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "user_id",
        "revoked_at",
        "via",
    }
)

# ``reason`` closed-vocab: planted_file | expired | revoked | host_mismatch |
# machine_mismatch | token_user_mismatch | planted_file_invalid_user_id
# (per PR-S4-5 round-2 closures).
OPERATOR_SESSION_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        # ``attempted_user_id`` is the self-claimed user_id from the planted/
        # presented session file (Pydantic-validated for character class +
        # length per PR-S4-5 round-2 closure 4). ``resolved_user_id`` is the
        # DB-resolved owner of the token (None when token lookup misses).
        # When the two differ the row carries reason="token_user_mismatch"
        # (PR-S4-5 round-2 closure 11).
        "attempted_user_id",
        "resolved_user_id",
        "reason",
        "host",
        "machine_id_hash",
        "refused_at",
        "via",
    }
)

SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "component_id",
        "reason",
        "attempted_at",
    }
)

# ---------------------------------------------------------------------------
# supervisor.plugin.sandbox family (#152 §5, ADR-0015)
# ---------------------------------------------------------------------------

# ``reason`` closed-vocab: policy_ref_missing | policy_ref_os_mismatch |
# policy_ref_unreadable | policy_ref_escapes_root | bwrap_unavailable |
# bwrap_mode_userns_unavailable | kind_full_requires_keep_fd_3 |
# sandbox_info_handshake_mismatch
# (per PR-S4-6/7 round-2 closures; ``policy_ref_escapes_root`` covers the
# path-traversal case the sandbox_escape adversarial README documents and
# is distinct from ``policy_ref_unreadable``).
SANDBOX_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "plugin_id",
        "policy_ref",
        "host_os",
        "reason",
        "environment",
    }
)

# Emitted when a kind:stub plugin runs unsandboxed in a development environment.
# ``environment`` ∈ {"development", "test"} only — production refuses
# (PR-S4-6 sec-2 closure).
SANDBOX_STUB_USED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "plugin_id",
        "policy_ref",
        "host_os",
        "environment",
    }
)

# ---------------------------------------------------------------------------
# comms family — PR-S4-8/9/10 foundations
# ---------------------------------------------------------------------------

# Emitted at the wire-T3 → host promotion boundary; ``language`` is BCP-47
# per i18n hard rule (PR-S4-9 round-2 closure 1).
COMMS_INBOUND_T3_PROMOTION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "inbound_message_id",
        "platform_user_id_hash",
        "canonical_user_id",
        "sub_payload_kinds",
        "language",
        "addressing_signal",
    }
)

COMMS_BINDING_REQUESTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "platform_user_id_hash",
        "verification_phrase_hash",
        "requested_at",
        # ``language`` is the BCP-47 tag resolved from the inbound DM (the
        # binding-request prose is rendered back to the user in this language;
        # i18n hard rule + PR-S4-9 round-2 closure 1).
        "language",
    }
)

COMMS_ADAPTER_CRASHED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        # ``error_class`` is the open-vocab Python exception type;
        # ``reason`` is the closed-vocab SLO bucket the adapter-supervisor
        # uses for runbook routing (see ``COMMS_ADAPTER_CRASHED_REASONS``
        # discriminator vocab in spec §6.8).
        "error_class",
        "reason",
        "detail_redacted",
        "crashed_at",
    }
)

COMMS_RATE_LIMIT_SIGNAL_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "platform_endpoint",
        "retry_after_seconds",
        "signalled_at",
    }
)

COMMS_UNKNOWN_NOTIFICATION_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "method",
        "method_redacted_params",
        "observed_at",
    }
)

COMMS_HANDLER_FAILED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "notification_method",
        "handler_class",
        # ``error_class`` is the open-vocab Python exception type;
        # ``reason`` is the closed-vocab handler-failure bucket
        # (validation, ratelimited_self, broker_unavailable, ...).
        "error_class",
        "reason",
        "detail_redacted",
        "failed_at",
    }
)

COMMS_ADDRESSING_DRIFT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "inbound_signal",
        "outbound_mode",
        "canonical_user_id",
        "observed_at",
    }
)

# Emitted on BurstLimiter pre-resolution or per-user budget hit (PR-S4-8
# round-2 closure 3). ``dropped`` is True only after the 30s
# bucket-empty grace expires.
COMMS_INBOUND_BUDGET_CAPPED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "canonical_user_id",
        "persona",
        "tokens_available",
        "wait_seconds",
        "dropped",
        "observed_at",
        # ``language`` carries the user's resolved language so the
        # operator-facing "you were rate-limited" message renders in their
        # locale (i18n hard rule + PR-S4-9 round-2 closure 1).
        "language",
    }
)

# ---------------------------------------------------------------------------
# supervisor.plugin lifecycle (PR-S4-9/10 restart wiring)
# ---------------------------------------------------------------------------

SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "plugin_id",
        "reason",
        "requested_at",
        "requester",
    }
)


# ---------------------------------------------------------------------------
# Slice-4 fieldset roster (test surface)
# ---------------------------------------------------------------------------
#
# Names enumerated for ``tests/unit/audit/test_slice_4_audit_row_fields.py``
# AST-walk verification. Adding a new Slice-4 ``*_FIELDS`` constant requires
# adding its name to this tuple in the same commit (the AST guard catches
# omissions).
SLICE_4_FIELDSET_NAMES: Final[tuple[str, ...]] = (
    "DAEMON_BOOT_FIELDS",
    "DAEMON_BOOT_FAILED_FIELDS",
    "DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS",
    "PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS",
    "CARRIER_SUBSTITUTION_FIELDS",
    "CARRIER_SUBSTITUTION_REFUSED_FIELDS",
    "CONFIG_RELOAD_FIELDS",
    "CONFIG_RELOAD_REJECTED_FIELDS",
    "OPERATOR_SESSION_CREATED_FIELDS",
    "OPERATOR_SESSION_REVOKED_FIELDS",
    "OPERATOR_SESSION_REFUSED_FIELDS",
    "SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS",
    "SANDBOX_REFUSED_FIELDS",
    "SANDBOX_STUB_USED_FIELDS",
    "COMMS_INBOUND_T3_PROMOTION_FIELDS",
    "COMMS_BINDING_REQUESTED_FIELDS",
    "COMMS_ADAPTER_CRASHED_FIELDS",
    "COMMS_RATE_LIMIT_SIGNAL_FIELDS",
    "COMMS_UNKNOWN_NOTIFICATION_FIELDS",
    "COMMS_HANDLER_FAILED_FIELDS",
    "COMMS_ADDRESSING_DRIFT_FIELDS",
    "COMMS_INBOUND_BUDGET_CAPPED_FIELDS",
    "SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS",
)
