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
    """QUARANTINE_EXTRACT_FIELDS exact field list per spec §13."""
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


def test_plugin_grant_requested_fields_aliases_plugin_grant_fields() -> None:
    """PLUGIN_GRANT_REQUESTED_FIELDS is the same object as PLUGIN_GRANT_FIELDS.

    Stage 3 (arch-001 / cross-cutting R2): the reviewer-gated CLI emits the
    ``plugin.grant.requested`` row through the helper, which references this
    name for emit-site clarity. The two constants are intentionally identical
    so the schema-module test corpus stays the single source of truth — a
    drift between them is a refactor bug that this assertion fails loudly on.
    """
    assert audit_row_schemas.PLUGIN_GRANT_REQUESTED_FIELDS is audit_row_schemas.PLUGIN_GRANT_FIELDS


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
