"""Verify ``tool.web.fetch`` audit row carries ``WEB_FETCH_FIELDS``
(spec §7.12, §13).

These tests pin the field-set the dispatcher must populate at every
audit emit site. Drift in either schema constant is a forensic loss —
historical audit rows become uncorrelatable with their source code.

The schemas live in :mod:`alfred.audit.audit_row_schemas` (PR-S3-0a);
this test asserts the dispatcher's required-field subset is a strict
subset of the declared schema, so a future schema widening
(adding more fields) stays compatible while a schema narrowing
(removing fields) fails loud.
"""

from __future__ import annotations

from alfred.audit.audit_row_schemas import (
    WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS,
    WEB_FETCH_FIELDS,
)


def test_web_fetch_fields_contains_required_fields() -> None:
    """WEB_FETCH_FIELDS declares every column the dispatcher writes."""
    required = {
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
    assert required <= WEB_FETCH_FIELDS, f"WEB_FETCH_FIELDS missing: {required - WEB_FETCH_FIELDS}"


def test_broadening_capped_fields_contains_required_fields() -> None:
    """WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS declares every
    column the dispatcher writes when emitting a broadening-cap event."""
    required = {
        "plugin_id",
        "manifest_domains",
        "operator_allowed_domains",
        "capped_domains",
        "correlation_id",
    }
    assert required <= WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS, (
        "WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS missing: "
        f"{required - WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS}"
    )
