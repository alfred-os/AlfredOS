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
    "dlp_scan_error",
    "url_secret_refused",  # G7-2.5 — refuse-on-secret in the URL (re-homed dispatcher)
    "domain_not_allowed",
    "rate_limited",
    "inbound_canary_tripped",  # G7-2.5 — inbound canary reflected in the T3 response
    "mime_type_not_allowed",  # G7-2.5 — D1 pre-extract MIME refusal (response_inspection)
    "size_limit_exceeded",  # G7-2.5 — D1 pre-extract size refusal (response_inspection)
    "handle_cap_exceeded",  # RE-ADDED #339 PR4a — per-user concurrent-fetch refusal (spec §7.10)
    "header_secret_refused",  # #339 PR4b-broker — raw secret detected in a request header
    "secret_substitution_refused",  # #339 PR4b-broker — off-allowlist {{secret:*}} reference
    # Quarantined-extractor refusal tokens (TypedRefusalReason reach-through).
    # The re-homed dispatcher drives the quarantined extractor on the success path;
    # when that extractor refuses, the dispatcher surfaces the TypedRefusalReason as
    # the dlp_scan_result so operators can see WHY the extract sub-call failed.
    "cannot_extract",
    "refused_by_safety",
    "ambiguous_input",
    "provider_refused",
    "provider_unavailable",
    "post_stage_refused",
    "nonce_check_failed",
]
"""Closed vocabulary recorded in ``WEB_FETCH_FIELDS['dlp_scan_result']``.

Reconciled for the G7-2.5 ``web.fetch`` re-home (#333): the dispatcher no longer
drives a plugin subprocess, so the whole subprocess ``dlp_scan_result`` family
(``scanned_dirty`` / ``transport_error`` / ``dispatch_shape_error`` /
``internal_ip_refused`` / ``redirect_refused`` / ``tls_verification_failed`` /
``fetch_error`` / ``handle_id_mismatch`` / ``dispatch_param_invalid``) is now
unreachable and removed — each had NO live ``"dlp_scan_result": "<token>"`` emit
site after the re-home (grep-proven). The four NEW tokens are the re-homed
dispatcher's own emits: ``url_secret_refused`` (refuse-on-secret URL),
``inbound_canary_tripped`` (response canary reflection), and the two D1
pre-extract policy tokens ``mime_type_not_allowed`` / ``size_limit_exceeded``
(``response_inspection._SoftRefusal.subject_token``, surfaced via
``EgressExtractOutcome.policy_refusal_token``). The ``handle_cap_exceeded``
token was re-added in #339 PR4a for per-user concurrent-fetch refusal.

``header_secret_refused`` and ``secret_substitution_refused`` were added in
#339 PR4b-broker for the authenticated-``web.fetch`` confused-deputy defence
(ADR-0048): the re-homed dispatcher emits ``header_secret_refused`` when DLP
detects a raw (non-placeholder) secret value in a request header, and
``secret_substitution_refused`` when a ``{{secret:<name>}}`` placeholder names
a secret outside :data:`~alfred.plugins.web_fetch.auth_allowlist.WEB_FETCH_AUTH_SECRET_ALLOWLIST`.

The ``dlp_scan_result`` subject field is free-JSON (no DB CHECK constraint); this
Literal is the documentary contract pinned in lockstep by
``tests/unit/audit/test_audit_row_schemas.py``.

See ``docs/subsystems/security.md`` for the audit-vocabulary section."""

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
# tool.dispatch family (#339 PR2)
# ---------------------------------------------------------------------------

ToolDispatchOutcome = Literal[
    "dispatched",  # ok (internal <=T2 or T3 Extracted->downgrade->DLP clean)
    "unknown_tool",  # tool_name not present in the registry
    "invalid_arguments",  # call args failed the tool's Pydantic argument model
    "gate_denied",  # tool.dispatch capability-gate grant deny
    "tool_refused",  # tool returned a TypedRefusal
    "domain_not_allowed",  # web.fetch allowlist refusal
    "rate_limited",
    "tool_error",  # tool-raised error (e.g. WebFetchError) — never str(exc)
    "timeout",  # action-deadline surfaced TimeoutError (#347 blocker-2 seam)
    "downgrade_denied",  # T2->planner clearance deny (escalation)
    "canary_tripped",  # inbound canary in the T3 response (escalation)
    "dlp_canary",  # canary in the EXTRACTED T2 (escalation)
    "unexpected_error",  # defensive catch-all arm; type(exc).__name__ only
    # A stray/unexpected bare TimeoutError (the retained defensive arm), as
    # distinct from the well-understood action-deadline "timeout" above (the
    # enriched WebFetchActionTimeout path, #347 blocker 2). Free-JSON
    # dispatch_outcome subject value only — no DB CHECK constraint, no migration.
    "unexpected_timeout",
]
"""Granular per-dispatch outcome recorded in
``TOOL_DISPATCH_FIELDS['dispatch_outcome']`` (spec §10). The closed ``result``
column on the audit row reuses the existing vocab (success/refused/quarantined/
rate_limited/fault — the last emitted by the defensive ``unexpected_error``
arms) — this Literal is a finer-grained companion, not a replacement."""

TOOL_DISPATCH_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "tool_name",
        "call_id",
        "call_index",
        "result_tier",
        "dispatch_outcome",
        "triggering_user_id",
        "correlation_id",
        # §10 audit-graph disambiguator, e.g. "tool_dispatch:web.fetch:3" — set
        # by the dispatch_tool chokepoint, not by this schema module.
        "phase",
    }
)
"""Fields for the ``tool.dispatch`` audit family (#339 PR2). NEVER carries raw
tool arguments, the fetched URL/body, or ``str(exc)`` — only safe tokens +
attribution (HARD rule #7 / spec §5.6)."""

TOOL_DISPATCH_TIMEOUT_FIELDS: Final[frozenset[str]] = TOOL_DISPATCH_FIELDS | frozenset(
    {
        # sha256 egress-id of the timed-out logical call (deterministic; no T3).
        "egress_id",
        # The bare destination host ONLY (never the URL/path/query/userinfo).
        "destination_host",
        # True when the ledger is committed_no_response — the side effect may have
        # fired before the deadline and its outcome is unknown (#347 blocker 2).
        "in_doubt",
        # The ledger's committed state: "committed_no_response" |
        # "committed_with_response" | None (no row — timed out before commit) |
        # "read_unavailable" (the post-timeout ledger read itself failed —
        # FIX-1 sentinel, pairs with a forced in_doubt=True).
        "ledger_state",
    }
)
"""Superset of :data:`TOOL_DISPATCH_FIELDS` for the enriched action-deadline
``tool.dispatch`` timeout row (#347 blocker 2). Same ``event="tool.dispatch"``
family; the extra fields make the in-doubt side effect forensically auditable
(HARD rule #7). NEVER carries the URL/body or ``str(exc)``."""

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

# Spec A G1 (#237): core lifecycle signal rows (daemon.lifecycle.ready /
# daemon.lifecycle.going_down). Joins the rest of the boot lifecycle on
# ``boot_id``; carries the per-boot non-secret ``epoch`` so a consumer can
# correlate the two ends of one process lifetime (ADR-0033).
DAEMON_LIFECYCLE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        # The per-boot audit trace id this row joins on (same value as the
        # boot-completed row's boot_id).
        "boot_id",
        # The per-boot, non-secret lifecycle epoch (present on BOTH the ready
        # and going_down rows so a consumer can correlate the two ends of a
        # process lifetime).
        "epoch",
        # "ready" | "going_down".
        "phase",
        # The going_down reason (closed vocab); "" on the ready row.
        "reason",
        "occurred_at",
    }
)

# Spec A G3-2 (#237), arch-263-001: the daemon-side audit row a
# ``CommsSocketListener.on_peer_rejected`` callback writes when a mismatched-uid
# peer is refused on the 0600 comms socket. A rejection is an EXPECTED adversarial
# event (a same-uid race / wider-perm misconfig), so it does NOT refuse the boot —
# this is a loud audit row + metric, then the listener keeps waiting. ``peer_uid``
# is the rejected connector's reported uid (``None`` → "" on the wire); ``expected_uid``
# is the daemon's own uid. Both are non-secret integers — no T3 content.
COMMS_SOCKET_PEER_REJECTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "peer_uid",
        "expected_uid",
        "occurred_at",
    }
)

# G6-2b-2c (#288 / ADR-0038), arch-M1: the daemon-side audit row the
# ``DaemonControlServer.on_peer_rejected`` callback writes when a mismatched-uid peer is
# refused on the 0600 CONTROL socket. The control plane is daemon-GLOBAL (not
# adapter-keyed), so it does NOT reuse COMMS_SOCKET_PEER_REJECTED_FIELDS — there is no
# ``adapter_id`` to record. Like the comms-socket reject, a rejection is an EXPECTED
# adversarial event (a same-uid race / wider-perm misconfig): a loud audit row +
# ``result="refused"``, then the server keeps serving. ``peer_uid`` is the rejected
# connector's reported uid (``None`` → "" on the wire); ``expected_uid`` is the daemon's
# own uid. Both are non-secret integers — no T3 content.
DAEMON_CONTROL_PEER_REJECTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "peer_uid",
        "expected_uid",
        "occurred_at",
    }
)

# ---------------------------------------------------------------------------
# gateway.adapter.* status family (Spec B G6-2a / #288 / ADR-0036)
# ---------------------------------------------------------------------------
#
# The core-side AdapterStatusObserver writes ONE audit row per ACCEPTED status
# transition the gateway reports, plus a ``status_rejected`` row on every
# refused frame (malformed / forged-epoch / unknown-method). A malformed/forged
# status frame is NEVER silently dropped (Spec B §6) — the rejection row is the
# loud audit. The producer (GatewayAdapterSupervisor) + the live wire leg land in
# G6-2b; these constants ship now so the observer is fully testable in isolation.
#
# ``adapter_id`` is the closed-vocab adapter kind (the join key). ``occurred_at``
# is the observer's UTC ISO timestamp (the family-wide timestamp — internally
# consistent across all four transitions; this NEW family is not constrained by
# the older ``crashed_at`` of the in-child COMMS_ADAPTER_CRASHED row).
# ``crashed.detail`` is RE-SCRUBBED by the observer before it lands as
# ``detail_redacted`` (the wire ``detail`` is never persisted raw — the field name
# matches the existing COMMS_ADAPTER_CRASHED ``detail_redacted`` convention).
# The rejection row carries NO raw frame field — only the refused method, a
# closed-vocab reason, and the observed ``adapter_id`` ("" when it could not be
# parsed) — so a forged frame can never smuggle bytes into the audit log.

GATEWAY_ADAPTER_UP_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "epoch",
        "occurred_at",
        # G6-2b-2b (#288 / SEC-01): the incarnation being STARTED — the gateway's
        # per-adapter restart_count for this run. The reconciler advances its
        # current_incarnation to this on an accepted up so a later in-child crash
        # tags to the run that was actually serving (closing the common-order
        # double-count).
        "host_restart_seq",
    }
)

GATEWAY_ADAPTER_DOWN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "reason",
        "occurred_at",
    }
)

GATEWAY_ADAPTER_CRASHED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "error_class",
        "detail_redacted",
        "occurred_at",
        # G6-2b-2b (#288): the gateway's per-adapter incarnation this crash belongs to,
        # and the crash-dedup incident handle + which signal(s) corroborate it.
        "host_restart_seq",
        "crash_incident_id",
        "crash_signal_source",
        # TE-2: a replayed/duplicate gateway crash for an already-seen incarnation is
        # folded (no new incident) but STILL audited — this marker makes the replay
        # VISIBLE in the log (hard rule #7: never silently dropped).
        "duplicate",
    }
)

GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "retry_after_seconds",
        "occurred_at",
    }
)

GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        # The observed adapter_id; "" when the frame was unparseable (so a forged
        # adapter kind cannot be persisted as if it were a known one).
        "adapter_id",
        # The wire method that was refused (gateway.adapter.* or an unknown string).
        "rejected_method",
        # Closed-vocab rejection reason (see AdapterStatusObserver._RejectionReason).
        "rejection_reason",
        "occurred_at",
    }
)

# ---------------------------------------------------------------------------
# G6-3 credential round-trip family (Spec B G6-3 / #288 / ADR-0036)
# ---------------------------------------------------------------------------
#
# The real core-injects-at-spawn credential path. NONE of these rows carries the
# credential — ``credential_material`` is structurally absent from every field-set
# here (maintainer C1 / SEC-1): the credential crosses ONLY the trusted leg + fd 3,
# never an audit row. ``result`` is the closed-vocab outcome (granted / refused);
# the resolver writes the grant row, the gateway writes the awaiting-core +
# spawn-aborted rows. The gateway holds no signing key, so its rows reconcile into
# the CORE signed log the way the G6-2b-2a observer rows do (gateway-local audit is
# a tracked ADR-0036 follow-up — Spec C closes it).

# Resolver-side: gateway -> core spawn_request the core observed (granted/refused).
GATEWAY_ADAPTER_SPAWN_REQUEST_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "host_restart_seq",
        "epoch",
        "occurred_at",
        # Closed-vocab outcome: granted | refused (NO credential).
        "result",
    }
)

# Resolver-side: core -> gateway spawn_grant the resolver minted. ``duplicate`` is
# True on a true replay (all three of (adapter_id, host_restart_seq, epoch) matched
# an outstanding grant) — the replay is FLAGGED + still audited, never suppressed
# (hard rule #7), and the broker is NOT re-decrypted (correction H4).
CORE_ADAPTER_SPAWN_GRANT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "host_restart_seq",
        "epoch",
        "occurred_at",
        "result",
        "duplicate",
    }
)

# Gateway-side: the adapter parked in AWAITING_CORE because the credential leg was
# down (a non-spin bounded-backoff wait — Task 4). One row per awaiting-core entry.
GATEWAY_ADAPTER_AWAITING_CORE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "host_restart_seq",
        "reason",
        "occurred_at",
    }
)

# Gateway-side: a fail-closed spawn abort (grant-refusal / launcher-fail /
# fd-3-write-fail). ``reason`` is the closed-vocab audit string (mirrors
# quarantine_child_io's reason vocabulary); NO credential, NO raw frame field.
GATEWAY_ADAPTER_SPAWN_ABORTED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "host_restart_seq",
        "reason",
        "occurred_at",
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

# Emitted when ``OutboundDlp.scan`` raises a NON-``HookRefusal`` exception
# while scanning ``failure_detail`` (e.g. a regex-engine fault, an encoding
# error in a stage). Disjoint from both ``PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS``
# (clean/redacted success) and ``DLP_OUTBOUND_REFUSED_FIELDS`` (deliberate
# canary-trip refusal). The scan-failed path ABORTS the ledger insert — a
# scanner we cannot trust the output of MUST NOT let unscanned bytes land in
# ``processed_proposals.failure_detail``. ``scan_error_type`` is the
# ``type(exc).__name__`` closed-vocab discriminator (no T3 surface — the
# exception MESSAGE is never carried, only the class name). err-003 / sec-004.
PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "proposal_branch",
        "dispatch_attempted_at",
        "failure_class",
        "scan_error_type",
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
        # ``changed_values`` (CR round-3 Finding 4): a forensic before/after map
        # ``{dotted_key: {"old": ..., "new": ...}}`` for every changed key — the
        # applied row records WHAT the auto-reload changed, not just which keys
        # moved. Only LOW-BLAST keys reach an applied row (high-blast keys refuse
        # hot-reload before any swap), so the values are low-blast by
        # construction and carry no secret/high-blast material to redact.
        "changed_values",
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

# ``reason`` closed-vocab — session-bound refusals (a valid file parsed):
#   expired | host_mismatch | machine_mismatch | token_unknown |
#   token_user_mismatch | user_revoked
# File-less refusals (no valid file / no machine-id — emitted with every
#   self-claimed field None so no unparsed attacker bytes reach the log):
#   session_missing | parent_dir_insecure | parent_dir_not_owned |
#   bad_file_mode | bad_file_owner | planted_file_invalid |
#   machine_id_unavailable
# (per PR-S4-5 round-2 closures + the file-less audit-gap fix, hard rule #7).
OPERATOR_SESSION_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        # ``attempted_user_id`` is the self-claimed user_id from the planted/
        # presented session file (Pydantic-validated for character class +
        # length per PR-S4-5 round-2 closure 4), or ``None`` on the file-less
        # refusal path (file did not parse / no machine-id). ``resolved_user_id``
        # is the DB-resolved owner of the token (None when token lookup misses).
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
# sandbox_info_handshake_mismatch | sandbox_block_missing |
# unsandboxed_env_set_in_production | windows_stub_in_production |
# environment_not_set | provider_key_delivery_failed |
# soft_bind_forbidden_path | soft_bind_conflicts_with_hard_bind |
# arch_variable_path_hard_bound | policy_path_not_canonical
# (per PR-S4-6/7 round-2 closures; ``policy_ref_escapes_root`` covers the
# path-traversal case the sandbox_escape adversarial README documents and
# is distinct from ``policy_ref_unreadable``; ``provider_key_delivery_failed``
# is the fd-3 partial-write / EAGAIN refusal from
# ``alfred.supervisor.fd3_key_delivery`` — sec-3).
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
        # G6-2b-2b (#288): the crash-dedup incident handle this in-child crash folds
        # into + which signal(s) corroborate it. No host_restart_seq here — the
        # in-child frame is tagged to the current incarnation core-side. ``duplicate``
        # (TE-2) makes a replayed in-child crash visible in the log.
        "crash_incident_id",
        "crash_signal_source",
        "duplicate",
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

# Emitted when the durable accept-once commit loses the race on a replayed
# inbound frame (Spec A / G0). A replay short-circuit is a side-effecting DROP,
# so it is recorded in the SIGNED audit log — content-free: NO body, NO user
# text, NO platform_user_id, so no ``language`` column. ``result="dropped"``
# reuses the existing comms drop value (migration 0016) — no new migration.
COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        # The peppered hash of the wire inbound_id (never the raw string). A
        # replay DROP is content-free: NO body, NO user text, NO platform id.
        "inbound_id_hash",
        "observed_at",
    }
)

# Emitted when a FORWARDED inbound (the gateway dispatched-edge path, Spec B
# G6-7-4 / ADR-0039 item 4) fails at ``orchestrator.dispatch``. The frame is
# deliberately left NOT committed and NOT observed so the forwarding leg replays
# it — a recoverable event recorded in the SIGNED audit log. Same content-free
# shape as the replay row (adapter id + peppered inbound_id hash + observed_at;
# NO body, NO user text, NO platform_user_id, so no ``language`` column), but a
# DISTINCT ``result="dispatch_failed"`` so it never reads as the ``"dropped"``
# replay value. ``dispatch_failed`` is added to the ``ck_audit_log_result`` CHECK
# domain by migration 0019 (and the ``AuditEntry`` ORM model) — a free-text INSERT
# of an out-of-domain value would crash against real Postgres.
COMMS_INBOUND_DISPATCH_FAILED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "inbound_id_hash",
        "observed_at",
    }
)

# Emitted by process_inbound_message on the FORWARDED dispatched edge (Spec B
# G6-7-5 / ADR-0039 item 4b) when (adapter_id, inbound_id) has failed the post-extract
# region >= the ceiling N times. Terminal DEAD-LETTER: the frame is ack-to-drained and
# never re-dispatched. Content-free: closed-vocab adapter_id, peppered inbound_id hash
# (sec-010), the bounded attempt_count (a small int, non-secret), observed_at.
# result="poisoned" (migration 0020). subject is JSONB → adding attempt_count needs no migration.
COMMS_INBOUND_POISONED_FIELDS: Final[frozenset[str]] = frozenset(
    {"adapter_id", "inbound_id_hash", "attempt_count", "observed_at"}
)

# Emitted by the core-side GatewayForwardedInboundReceiver (Spec B G6-7-4 /
# ADR-0039) on a TERMINAL DROP of a gateway-forwarded inbound — the receive trust
# boundary's three refusal/drop dispositions. Content-free by construction: the
# row carries ONLY the closed-vocab ENVELOPE ``adapter_id`` (the routing key, NOT
# the body — SEC-309-1), a fixed closed-vocab ``reason`` discriminator, and the
# observation time. NO raw T3 body, NO ``inbound_id`` (the body may not even have
# re-parsed), NO ``str(exc)`` (the leak-safe structural summary from
# ``reparse_forwarded_inbound`` goes ONLY to a structlog ``.warning``, never the
# signed row — spec §3.3). The three drops REUSE in-domain ``result`` values (no
# migration): ``unknown_adapter`` + ``envelope_body_mismatch`` are K4-style /
# forge REFUSALS (``result="refused"``); ``body_malformed`` is an ack-to-drain
# DROP (``result="dropped"``, the same value the G0 replay row reuses).
#
# ``reason`` closed-vocab: unknown_adapter | envelope_body_mismatch | body_malformed |
# receive_fault (the SEC-G674-1 admission-fault terminal drop).
COMMS_FORWARDED_INBOUND_DROPPED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "reason",
        "observed_at",
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
# security.egress_relay_refused family (Spec C G7-2c-1 / #333)
# ---------------------------------------------------------------------------
#
# Emitted by the in-core RelayEgressClient (relay_client.py) on every refusal
# path: gateway deny, IO-plane down, or in-doubt (Spec C §5 H3). The row is
# PAYLOAD-BLIND: it carries ONLY the destination host authority (NOT the relay
# URL), the closed-vocab reason token, and the egress_id (a sha256 hex —
# already public, non-secret). No body, no header values, no raw T3 content.
#
# Gateway holds no DB (ADR-0036), so this durable core-side row is the sole
# non-skippable audit record for HARD rule #7 refusal paths.
#
# destination: the upstream host authority (not the relay_url — the relay is
#   core-internal plumbing; the *upstream* host is the forensic subject).
# reason: closed-vocab token — "io_plane_unavailable" | "egress_in_doubt" |
#   the str value of EgressRelayDenyReason (e.g. "destination_not_allowlisted").
# egress_id: the deterministic sha256 dedup key (64 lowercase hex chars).
EGRESS_RELAY_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "destination",
        "reason",
        "egress_id",
    }
)

# ---------------------------------------------------------------------------
# comms.inbound.real_turn.refused family (#338 PR2 Task 1)
# ---------------------------------------------------------------------------
#
# #338 PR2: the adapter-owned LOUD refusal row for a real-turn boundary failure
# (downgrade gate-DENY / malformed payload / BudgetError / turn-error / send-error).
# content-FREE — the PEPPERED inbound-id hash + the closed-vocab stage + the
# exception CLASS name only (never str(exc) — could embed T3-derived text). Keyed
# by inbound_id_hash like the sibling COMMS_INBOUND_DISPATCH_FAILED_FIELDS; per-user
# attribution rides actor_user_id=canonical_user_id RAW at the emit site (matching
# orchestrator.turn, core.py:1049). FOLD-5 / FOLD-R2 / CLAUDE.md hard rule #7.
COMMS_INBOUND_TURN_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
    {"adapter_id", "inbound_id_hash", "refusal_stage", "error_class", "observed_at"}
)

# ---------------------------------------------------------------------------
# Audit fieldset roster (test surface)
# ---------------------------------------------------------------------------
#
# Names enumerated for ``tests/unit/audit/test_slice_4_audit_row_fields.py``
# AST-walk verification. The AST guard sweeps EVERY ``*_FIELDS`` constant
# declared AFTER the Slice-4 section marker (it has no end-bound), so any new
# post-marker field-set — Slice-4 or a later spec — MUST be listed here in the
# same commit (the bidirectional walk catches both a missing roster entry and a
# missing constant). The roster is slice-agnostic: it owns Spec-B vocab too
# (#288 / G6-2a appended the ``GATEWAY_ADAPTER_*`` family below), so the name
# is ``AUDIT_FIELDSET_ROSTER`` rather than slice-specific (#295 rename) — those
# Spec-B field-sets are NOT Slice-4 work but ride the same AST guard because they
# live past the marker.
AUDIT_FIELDSET_ROSTER: Final[tuple[str, ...]] = (
    "COMMS_SOCKET_PEER_REJECTED_FIELDS",
    "DAEMON_CONTROL_PEER_REJECTED_FIELDS",
    "DAEMON_BOOT_FIELDS",
    "DAEMON_BOOT_FAILED_FIELDS",
    "DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS",
    "DAEMON_LIFECYCLE_FIELDS",
    "PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS",
    "PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS",
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
    "COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS",
    "COMMS_INBOUND_DISPATCH_FAILED_FIELDS",
    "COMMS_INBOUND_POISONED_FIELDS",
    "COMMS_FORWARDED_INBOUND_DROPPED_FIELDS",
    "SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS",
    # Spec B (#288) G6-2a gateway.adapter.* status family — listed here because
    # the AST guard sweeps all post-marker ``*_FIELDS`` (see the roster header).
    "GATEWAY_ADAPTER_UP_FIELDS",
    "GATEWAY_ADAPTER_DOWN_FIELDS",
    "GATEWAY_ADAPTER_CRASHED_FIELDS",
    "GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS",
    "GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS",
    # Spec B (#288) G6-3 credential round-trip family (NO credential in any row).
    "GATEWAY_ADAPTER_SPAWN_REQUEST_FIELDS",
    "CORE_ADAPTER_SPAWN_GRANT_FIELDS",
    "GATEWAY_ADAPTER_AWAITING_CORE_FIELDS",
    "GATEWAY_ADAPTER_SPAWN_ABORTED_FIELDS",
    # Spec C (#333) G7-2c-1 egress-relay refusal family (payload-blind; ADR-0036).
    "EGRESS_RELAY_REFUSED_FIELDS",
    # #338 PR2 Task 1: the RealTurnOrchestratorAdapter adapter-owned loud refusal
    # row (content-free; downgrade-deny / malformed / budget / turn-error / send-error).
    "COMMS_INBOUND_TURN_REFUSED_FIELDS",
)
