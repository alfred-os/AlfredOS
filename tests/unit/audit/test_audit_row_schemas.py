"""Tests for src/alfred/audit/audit_row_schemas.py.

Each constant is a Final[frozenset[str]] per spec §13. Tests assert:
- Every exported name is a frozenset of strings.
- The frozenset values are non-empty plain strings (no typing constructs leaked in).
- The exact field lists match the spec §13 tables (regression against accidental field removal).
- Nothing from `typing` leaks into the frozenset values
  (frozenset members are str, not type objects).
"""

from __future__ import annotations

from typing import Final

import pytest

from alfred.audit import audit_row_schemas

CONSTANT_NAMES: Final[tuple[str, ...]] = (
    "PLUGIN_LIFECYCLE_FIELDS",
    "PLUGIN_LIFECYCLE_CRASHED_FIELDS",
    "PLUGIN_LIFECYCLE_QUARANTINED_FIELDS",
    "PLUGIN_GRANT_FIELDS",
    "PLUGIN_GRANT_REQUESTED_FIELDS",
    "QUARANTINE_EXTRACT_FIELDS",
    "WEB_FETCH_FIELDS",
    "SUPERVISOR_BREAKER_RESET_FIELDS",
    "T3_BOUNDARY_REFUSAL_FIELDS",
    "T1_INGRESS_FIELDS",
    "T1_DOWNGRADE_FIELDS",
    "T3_DERIVED_DOWNGRADE_FIELDS",
    "PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS",
    "SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS",
    "SUPERVISOR_CONFIG_INSECURE_FIELDS",
    "SUPERVISOR_ACTION_TIMEOUT_FIELDS",
    "WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS",
    "WEB_ALLOWLIST_REQUESTED_FIELDS",
    "CONFIG_SET_REQUESTED_FIELDS",
    "DLP_OUTBOUND_REFUSED_FIELDS",
    "SUPERVISOR_BREAKER_TRIPPED_FIELDS",
    # ADR-0021 — state.git side-effecting dispatch audit family.
    "STATE_PROPOSAL_PROCESSED_FIELDS",
    "STATE_PROPOSAL_DISPATCH_FAILED_FIELDS",
    "STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS",
    # #339 PR2 — tool.dispatch chokepoint audit family.
    "TOOL_DISPATCH_FIELDS",
    # #339 PR4b — enriched action-deadline timeout row (#347 blocker 2).
    "TOOL_DISPATCH_TIMEOUT_FIELDS",
)


@pytest.mark.parametrize("name", CONSTANT_NAMES)
def test_constant_is_frozenset_of_strings(name: str) -> None:
    """Every audit row field-list constant is a frozenset[str]."""
    value = getattr(audit_row_schemas, name)
    assert isinstance(value, frozenset), f"{name} must be frozenset, got {type(value)}"
    assert len(value) > 0, f"{name} must be non-empty"
    for field in value:
        assert isinstance(field, str), f"{name} member {field!r} is not str"
        assert not field.startswith("_"), (
            f"{name} member {field!r} looks private; field names are public"
        )


def test_crashed_fields_is_superset_of_lifecycle_fields() -> None:
    """PLUGIN_LIFECYCLE_CRASHED_FIELDS must be a superset of PLUGIN_LIFECYCLE_FIELDS (spec §5.6)."""
    assert audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS.issubset(
        audit_row_schemas.PLUGIN_LIFECYCLE_CRASHED_FIELDS
    ), "crashed fields must include all lifecycle fields plus exception_type"
    assert "exception_type" in audit_row_schemas.PLUGIN_LIFECYCLE_CRASHED_FIELDS


def test_correlation_id_present_in_all_constants() -> None:
    """Every audit row family includes correlation_id per spec §13 audit-row discipline."""
    for name in CONSTANT_NAMES:
        value = getattr(audit_row_schemas, name)
        assert "correlation_id" in value, f"{name} is missing correlation_id"


def test_plugin_lifecycle_fields_exact() -> None:
    """PLUGIN_LIFECYCLE_FIELDS exact field list per spec §13."""
    assert audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS == frozenset(  # noqa: SIM300
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


def test_plugin_grant_fields_exact() -> None:
    """PLUGIN_GRANT_FIELDS exact field list per spec §13."""
    assert audit_row_schemas.PLUGIN_GRANT_FIELDS == frozenset(  # noqa: SIM300
        {
            "plugin_id",
            "subscriber_tier",
            "hookpoint",
            "operator_user_id",
            "proposal_branch",
            "correlation_id",
        }
    )


def test_quarantine_extract_fields_exact() -> None:
    """QUARANTINE_EXTRACT_FIELDS exact field list per spec §13.

    ``refusing_hook_id`` was added in #168 — it carries the refusing
    subscriber's identity on ``post_stage_refused`` outcomes; on every
    other arm (success / typed-refusal / transport-failed /
    protocol-violation) it is ``None``. The field exists on the schema
    because ``alfred.hooks.invoke._run_post`` does NOT emit
    ``HOOKS_REFUSAL`` audit rows for post-stage refusals (§6.5 is
    pre-only), so the ``quarantine.extract`` row is the only forensic
    surface for that attribution.
    """
    assert audit_row_schemas.QUARANTINE_EXTRACT_FIELDS == frozenset(  # noqa: SIM300
        {
            "extraction_mode",
            "provider",
            "schema_name",
            "schema_version",
            "retry_count",
            "trust_tier_of_trigger",
            "result",
            "correlation_id",
            "refusing_hook_id",
        }
    )


def test_web_fetch_fields_exact() -> None:
    """WEB_FETCH_FIELDS exact field list per spec §13."""
    assert audit_row_schemas.WEB_FETCH_FIELDS == frozenset(  # noqa: SIM300
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


def test_t3_derived_downgrade_fields_constant() -> None:
    """T3_DERIVED_DOWNGRADE_FIELDS exact field list (rvw-003, spec §3.7).

    Distinct from T1_DOWNGRADE_FIELDS: that family covers the explicit
    T1→T2 broadcast-safe conversion; this constant covers the
    T3-derived→T2 crossing at the orchestrator boundary. The two trust
    transitions are forensically distinct and MUST NOT share a schema
    family.
    """
    assert audit_row_schemas.T3_DERIVED_DOWNGRADE_FIELDS == frozenset(  # noqa: SIM300
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


def test_t3_derived_downgrade_distinct_from_t1_downgrade() -> None:
    """T3_DERIVED_DOWNGRADE_FIELDS must not be reused as T1_DOWNGRADE_FIELDS (rvw-003).

    The two constants share some backbone keys (trust_tier_of_trigger,
    trust_tier_of_response, downgrade_explicit, correlation_id) but the
    distinguishing subject keys differ — T1 carries user_id; T3-derived
    carries extraction_id + quarantined_llm_invocation_id + source/target
    tier markers + downgrade_reason. Equality between the two would mean
    we'd lost the rvw-003 invariant.
    """
    assert audit_row_schemas.T3_DERIVED_DOWNGRADE_FIELDS != audit_row_schemas.T1_DOWNGRADE_FIELDS, (
        "T3-derived downgrade must remain a distinct family from T1 downgrade (rvw-003)"
    )
    # T3-derived must NOT carry user_id (T3-derived downgrade is per-extraction,
    # not per-user — forensic attribution flows via quarantined_llm_invocation_id).
    assert "user_id" not in audit_row_schemas.T3_DERIVED_DOWNGRADE_FIELDS


def test_plugin_grant_requested_fields_supersets_plugin_grant_fields() -> None:
    """PLUGIN_GRANT_REQUESTED_FIELDS supersets PLUGIN_GRANT_FIELDS with the T1 tag.

    CR-149 round-6: the requested-side row tags the operator-typed CLI
    ingress with ``trust_tier_of_trigger="T1"`` so the audit-graph
    swimlane (``alfred audit graph --tier T1``) surfaces it in the
    operator-action lane. The lifecycle constant (``PLUGIN_GRANT_FIELDS``)
    stays narrower because the eventual ``plugin.grant.rebuilt`` twin
    fires off a host-level supervisor merge (T0). PRD §7.1 + CLAUDE.md
    hard rule #3 require the ingress-side tag; this assertion fails
    loudly if either constant drifts from the documented superset
    contract.
    """
    assert audit_row_schemas.PLUGIN_GRANT_FIELDS <= audit_row_schemas.PLUGIN_GRANT_REQUESTED_FIELDS
    assert "trust_tier_of_trigger" in audit_row_schemas.PLUGIN_GRANT_REQUESTED_FIELDS
    assert "trust_tier_of_trigger" not in audit_row_schemas.PLUGIN_GRANT_FIELDS


def test_web_allowlist_requested_fields_exact() -> None:
    """WEB_ALLOWLIST_REQUESTED_FIELDS exact field list.

    Stage 3 / arch-001: emitted at the moment ``alfred web allowlist
    add|remove`` queues a state.git proposal. The ``action`` field
    distinguishes the two reviewer-gated entry points so the audit graph
    can join the CLI emit with the eventual projection-side merge row.
    """
    assert audit_row_schemas.WEB_ALLOWLIST_REQUESTED_FIELDS == frozenset(  # noqa: SIM300
        {
            "action",
            "domain",
            "path_prefix",
            "operator_user_id",
            "proposal_branch",
            # CR-149 round-6: operator-CLI ingress carries the T1 tag.
            "trust_tier_of_trigger",
            "correlation_id",
        }
    )


def test_config_set_requested_fields_exact() -> None:
    """CONFIG_SET_REQUESTED_FIELDS exact field list.

    Stage 3 / arch-001: emitted at the moment ``alfred config set`` queues
    a high-blast-key proposal. Crucially does NOT include ``value`` — that
    field is reserved for the proposal payload the reviewer reads, never
    for the audit row (CLAUDE.md hard rule #6: a future high-blast knob
    whose value carries secret material would silently leak to the audit
    log otherwise).
    """
    assert audit_row_schemas.CONFIG_SET_REQUESTED_FIELDS == frozenset(  # noqa: SIM300
        {
            "config_key",
            "operator_user_id",
            "proposal_branch",
            # CR-149 round-6: operator-CLI ingress carries the T1 tag.
            "trust_tier_of_trigger",
            "correlation_id",
        }
    )


def test_config_set_requested_fields_excludes_value() -> None:
    """The config-set audit family MUST NOT carry the ``value`` key.

    CLAUDE.md hard rule #6: audit rows are structured records of
    identifiers + policy knobs. ``value`` lives in the proposal payload
    (which the reviewer reads) but never in the audit log — a future
    operator-secrets knob would silently leak into the audit table
    otherwise.
    """
    assert "value" not in audit_row_schemas.CONFIG_SET_REQUESTED_FIELDS


def test_no_typing_constructs_leaked() -> None:
    """Frozenset members are plain strings; no typing.Final or type objects leaked."""
    import typing

    for name in CONSTANT_NAMES:
        value = getattr(audit_row_schemas, name)
        for field in value:
            assert not isinstance(field, type), f"{name} member {field!r} is a type, not a string"
            assert not hasattr(typing, field), f"{name} member {field!r} looks like a typing name"


def test_quarantine_extract_result_values_subset_of_migration_domain() -> None:
    """QUARANTINE_EXTRACT_FIELDS includes 'result'; guard against drift with migration domain.

    Migration 0005 (base) allows: refused.
    Migration 0007 (Slice 3) adds: extracted, malformed_exhausted, content_expired,
    load_refused, crashed, quarantined, reloaded, requested, approved, denied, revoked,
    tripped, reset.

    This test verifies that the four quarantine.extract result values documented in
    spec §13 are a subset of the combined allowed domain from migrations 0005 + 0007.
    It does NOT import the migration module (avoids circular imports) but hardcodes
    the migration-defined domain, with a comment to update both when a new migration
    extends the domain. (mem-008: result-value Literal drift guard.)
    """
    # Combined allowed domain from migration 0005 (base) + 0007 (Slice 3).
    # Update this set when a future migration extends AuditEntry.result allowed values.
    migration_allowed_results: frozenset[str] = frozenset(
        {
            # migration 0005 base set:
            "refused",
            # migration 0007 Slice-3 additions:
            "extracted",
            "malformed_exhausted",
            "content_expired",
            "load_refused",
            "crashed",
            "quarantined",
            "reloaded",
            "requested",
            "approved",
            "denied",
            "revoked",
            "tripped",
            "reset",
        }
    )
    # The four quarantine.extract result values (spec §13):
    quarantine_extract_results: frozenset[str] = frozenset(
        {
            "extracted",
            "refused",
            "malformed_exhausted",
            "content_expired",
        }
    )
    assert "result" in audit_row_schemas.QUARANTINE_EXTRACT_FIELDS, (
        "QUARANTINE_EXTRACT_FIELDS must contain 'result' field"
    )
    orphans = quarantine_extract_results - migration_allowed_results
    assert not orphans, (
        f"quarantine.extract result values {orphans!r} are not in the migration-allowed "
        f"domain {migration_allowed_results!r}. Update migration 0007 or fix the constant."
    )


def test_rate_limit_bucket_literal_closed_set() -> None:
    """rate_limit_bucket's Literal pins the four-value closed vocabulary
    after the handle-cap widening (spec §6.2)."""
    from typing import get_args

    from alfred.audit.audit_row_schemas import RateLimitBucket

    assert set(get_args(RateLimitBucket)) == {
        "per_domain",
        "per_user",
        "daily_budget",
        "handle_cap",
    }


def test_dlp_scan_result_literal_includes_new_values() -> None:
    """dlp_scan_result's Literal pins the closed vocabulary AFTER the G7-2.5
    ``web.fetch`` re-home reconciliation (#333) and #339 PR4a per-user handle-cap
    reinstatement.

    Mirrors the ``RateLimitBucket`` pattern (exact-set equality) so a stray extra
    literal, a dropped existing one, or a typo all surface here — not at a
    downstream audit-graph consumer.

    The re-home removed the plugin subprocess, so the whole subprocess
    ``dlp_scan_result`` family (``scanned_dirty`` / ``transport_error`` /
    ``dispatch_shape_error`` / ``internal_ip_refused`` / ``redirect_refused`` /
    ``tls_verification_failed`` / ``fetch_error`` / ``handle_id_mismatch`` /
    ``dispatch_param_invalid``) is gone — none has a live
    ``"dlp_scan_result": "<token>"`` emit site after the re-home. The four NEW
    tokens are the re-homed dispatcher's emits (URL-secret refusal, inbound canary,
    and the two D1 MIME/size pre-extract policy tokens). The ``handle_cap_exceeded``
    token was re-added in #339 PR4a for per-user concurrent-fetch refusal.
    Update this set in lockstep with the schema.
    """
    from typing import get_args

    from alfred.audit.audit_row_schemas import DlpScanResult

    assert set(get_args(DlpScanResult)) == {
        "clean",
        "dlp_scan_error",
        "url_secret_refused",  # NEW per G7-2.5
        "domain_not_allowed",
        "rate_limited",
        "inbound_canary_tripped",  # NEW per G7-2.5
        "mime_type_not_allowed",  # NEW per G7-2.5
        "size_limit_exceeded",  # NEW per G7-2.5
        "handle_cap_exceeded",  # RE-ADDED #339 PR4a — per-user concurrency refusal
        # Quarantined-extractor refusal tokens added alongside G7-2.5 CR follow-ons.
        "cannot_extract",
        "refused_by_safety",
        "ambiguous_input",
        "provider_refused",
        "provider_unavailable",
        "post_stage_refused",
        "nonce_check_failed",
        "header_secret_refused",  # NEW #339 PR4b-broker — raw secret in a header
        "secret_substitution_refused",  # NEW #339 PR4b-broker — off-allowlist {{secret:*}}
    }


# ---------------------------------------------------------------------------
# state.proposal.* family (ADR-0021 — side-effecting dispatch)
# ---------------------------------------------------------------------------


def test_state_proposal_processed_fields_exact() -> None:
    """STATE_PROPOSAL_PROCESSED_FIELDS exact field list per ADR-0021 §Audit.

    Emitted on every dispatched proposal (success or handler-returned-failure).
    Carries the full forensic surface so the audit-graph correlator can
    join the dispatch row with both the operator-CLI ingress row and the
    git merge event (via commit_sha).

    ``commit_sha`` is the non-repudiable join key (ADR-0021 §Threat model);
    ``operator_user_id`` is self-claimed forensic context.
    """
    assert audit_row_schemas.STATE_PROPOSAL_PROCESSED_FIELDS == frozenset(  # noqa: SIM300
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


def test_state_proposal_dispatch_failed_fields_exact() -> None:
    """STATE_PROPOSAL_DISPATCH_FAILED_FIELDS exact field list per ADR-0021.

    Emitted on framework-level dispatch failures (unknown_proposal_type,
    payload_validation, blob_not_found, handler_uncaught_exception).
    Superset of PROCESSED + ``framework_error_kind`` so a forensic
    consumer can distinguish operator-caused failures (handler-returned)
    from framework-level failures (parse / unknown-type / uncaught).
    """
    assert audit_row_schemas.STATE_PROPOSAL_DISPATCH_FAILED_FIELDS == frozenset(  # noqa: SIM300
        {
            "proposal_type",
            "proposal_id",
            "result",
            "failure_kind",
            "framework_error_kind",
            "handler_version",
            "processed_at",
            "operator_user_id",
            "commit_sha",
            "correlation_id",
        }
    )


def test_state_proposal_dispatch_cycle_skipped_fields_exact() -> None:
    """STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS exact field list.

    ADR-0021 §Consequences (Negative): the dispatch loop uses log+skip
    semantics on cycle-level infrastructure failure (Postgres unreachable,
    git command failure). Every aborted cycle MUST emit this row — no
    silent skips. The ``skip_reason`` field carries the cause; no
    per-proposal fields because the cycle never resolved which proposals
    it would have processed.
    """
    assert audit_row_schemas.STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS == frozenset(  # noqa: SIM300
        {
            "skip_reason",
            "correlation_id",
        }
    )


def test_state_proposal_dispatch_failed_supersets_processed() -> None:
    """STATE_PROPOSAL_DISPATCH_FAILED_FIELDS is a superset of PROCESSED + framework key.

    Pins the relationship: framework-level rows carry every processed
    row's field plus framework_error_kind, so an audit-graph consumer
    can use the same join-key set and add a discriminator on the
    framework key only when needed.
    """
    processed = audit_row_schemas.STATE_PROPOSAL_PROCESSED_FIELDS
    failed = audit_row_schemas.STATE_PROPOSAL_DISPATCH_FAILED_FIELDS
    assert processed.issubset(failed)
    assert "framework_error_kind" in failed
    assert "framework_error_kind" not in processed


# ---------------------------------------------------------------------------
# tool.dispatch family (#339 PR2)
# ---------------------------------------------------------------------------


def test_tool_dispatch_fields_closed_set() -> None:
    """TOOL_DISPATCH_FIELDS exact 8-key field list per the #339 PR2 plan-review

    FIX-6 override: the brief's Task-2 draft showed 7 keys; a 6-reviewer
    plan-review added ``phase`` to carry the §10 audit-graph disambiguator
    (e.g. ``tool_dispatch:web.fetch:3``), set by the later ``dispatch_tool``
    chokepoint.
    """
    assert audit_row_schemas.TOOL_DISPATCH_FIELDS == frozenset(  # noqa: SIM300
        {
            "tool_name",
            "call_id",
            "call_index",
            "result_tier",
            "dispatch_outcome",
            "triggering_user_id",
            "correlation_id",
            "phase",
        }
    )


def test_tool_dispatch_outcome_literal_closed_set() -> None:
    """ToolDispatchOutcome's Literal pins the 14-token closed vocabulary.

    FIX-5 override (#339 PR2 plan-review): includes ``unexpected_error``
    for a defensive catch-all arm the later ``dispatch_tool`` chokepoint
    adds. Mirrors the ``RateLimitBucket`` / ``DlpScanResult`` exact-set
    pattern so a stray extra literal, a dropped existing one, or a typo
    all surface here.

    FOLD-LAYER FIX-3 (#339 PR4b): adds ``unexpected_timeout`` to
    distinguish a stray/unexpected bare ``TimeoutError`` (the retained
    defensive arm) from the well-understood action-deadline ``timeout``
    (the enriched ``WebFetchActionTimeout`` path, #347 blocker 2).
    """
    from typing import get_args

    from alfred.audit.audit_row_schemas import ToolDispatchOutcome

    assert set(get_args(ToolDispatchOutcome)) == {
        "dispatched",
        "unknown_tool",
        "invalid_arguments",
        "gate_denied",
        "tool_refused",
        "domain_not_allowed",
        "rate_limited",
        "tool_error",
        "timeout",
        "downgrade_denied",
        "canary_tripped",
        "dlp_canary",
        "unexpected_error",
        "unexpected_timeout",
    }


def test_tool_dispatch_timeout_fields_is_superset_of_tool_dispatch() -> None:
    """TOOL_DISPATCH_TIMEOUT_FIELDS supersets TOOL_DISPATCH_FIELDS (#339 PR4b).

    The enriched action-deadline timeout row (#347 blocker 2) carries every
    ``tool.dispatch`` field plus the four in-doubt-forensics fields
    (``egress_id``, ``destination_host``, ``in_doubt``, ``ledger_state``).
    Same ``event="tool.dispatch"`` family, same pattern as
    ``PLUGIN_LIFECYCLE_CRASHED_FIELDS = PLUGIN_LIFECYCLE_FIELDS | {...}``.
    """
    assert audit_row_schemas.TOOL_DISPATCH_FIELDS.issubset(
        audit_row_schemas.TOOL_DISPATCH_TIMEOUT_FIELDS
    )
    timeout_only_fields = (
        audit_row_schemas.TOOL_DISPATCH_TIMEOUT_FIELDS - audit_row_schemas.TOOL_DISPATCH_FIELDS
    )
    assert timeout_only_fields == {
        "egress_id",
        "destination_host",
        "in_doubt",
        "ledger_state",
    }
