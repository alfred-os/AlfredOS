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

from typing import Final

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

# Operator-CLI ingress superset for the ``plugin.grant.requested`` row.
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
QUARANTINE_EXTRACT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "extraction_mode",
        "provider",
        "schema_name",
        "schema_version",
        "retry_count",
        "trust_tier_of_trigger",
        "result",
        "correlation_id",
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
