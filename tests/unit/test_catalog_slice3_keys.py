# tests/unit/test_catalog_slice3_keys.py
"""Assert every new Slice-3 t() key resolves and its placeholders are renderable.

Two-part test (Cluster 6 / i18n-007):

1. test_slice3_key_resolves: every key returns a non-empty non-bare string.
   A bare key signals a missing catalog entry. Gates the catalog PR.

2. test_slice3_key_placeholder_integrity: every key with declared placeholders
   can be rendered with its expected kwargs without raising KeyError. Catches
   catalog/call-site kwarg mismatches (i18n-001 / i18n-002 / devex-004) at
   PR-S3-0b CI rather than at runtime in PR-S3-6.

i18n-003 note: the test list and the catalog msgid count must agree.
Current total: 86 keys (82 original + 3 new: plugin.transport.dlp_outbound_refused,
cli.supervisor.reset.rerun_hint, cli.audit.graph.since_invalid).
"""

from __future__ import annotations

import pytest

from alfred.i18n.translator import t

# Full list from spec §11.5 + fixup additions.
# i18n-003: count must match msgid count in Task 16's .po block.
_SLICE_3_KEYS: list[str] = [
    # CLI navigation / help keys (used as Typer group docstrings)
    "cli.plugin.help",
    "cli.plugin.grant.help",
    "cli.plugin.grant.usage",
    "cli.plugin.grant.follow_up_command",
    "cli.plugin.grant.success",
    "cli.web.help",
    "cli.web.allowlist.help",
    "cli.web.allowlist.add.usage",
    "cli.web.allowlist.add.denied",
    "cli.web.allowlist.remove.denied",
    "cli.config.help",
    "cli.config.set.key_help",
    "cli.config.set.value_help",
    "cli.config.set.denied",
    "cli.config.set.unknown_key",
    "cli.config.get.unknown_key",
    "cli.config.get.not_set",
    "cli.config.list.empty",
    "cli.supervisor.help",
    "cli.supervisor.reset.usage",
    "cli.audit.help",
    "cli.audit.graph.tier_help",
    "cli.audit.graph.since_help",
    "cli.audit.graph.empty",
    "cli.audit.graph.tier_header",
    "cli.audit.graph.header",
    # CLI action keys
    "cli.plugin.grant.pending_review",
    "cli.plugin.grant.denied",
    "cli.plugin.grant.confirm_prompt",
    "cli.plugin.grant.status.pending",
    "cli.plugin.grant.status.approved",
    "cli.plugin.grant.status.denied",
    "cli.plugin.grant.status.expired",
    "cli.web.allowlist.pending_review",
    "cli.web.allowlist.added",
    "cli.web.allowlist.removed",
    "cli.config.quarantined_provider_pending_review",
    "cli.config.web_fetch_budget_set",
    "cli.supervisor.reset.confirm_prompt",
    "cli.supervisor.reset.success",
    "cli.supervisor.reset.component_not_found",
    # devex-004 / i18n-004: rerun hint key (hardcoded English in PR-S3-6 Task N)
    "cli.supervisor.reset.rerun_hint",
    # devex-016: bad --since value error key
    "cli.audit.graph.since_invalid",
    # List/table column keys
    "cli.plugin.list.column.plugin_id",
    "cli.plugin.list.column.subscriber_tier",
    "cli.plugin.list.column.status",
    "cli.plugin.list.column.manifest_version",
    "cli.plugin.list.empty_hint",
    "cli.plugin.show.field.plugin_id",
    "cli.plugin.show.field.manifest_version",
    "cli.plugin.show.field.sandbox_profile",
    "cli.plugin.show.field.hookpoints",
    "cli.plugin.show.field.grants",
    "cli.plugin.show.field.last_lifecycle_event",
    "cli.web.allowlist.list.column.domain",
    "cli.web.allowlist.list.column.path_prefix",
    "cli.web.allowlist.list.column.granted_by",
    "cli.web.allowlist.list.column.granted_at",
    "cli.web.allowlist.list_empty",
    "cli.supervisor.status.column.component",
    "cli.supervisor.status.column.state",
    "cli.supervisor.status.column.trip_count",
    "cli.supervisor.status.column.last_trip_at",
    "cli.supervisor.status.empty_hint",
    "cli.supervisor.status.breaker_state.open",
    "cli.supervisor.status.breaker_state.closed",
    "cli.supervisor.status.breaker_state.half_open",
    # WebFetchError message keys
    "web.fetch.error.domain_not_allowed",
    "web.fetch.error.tls_failure",
    "web.fetch.error.rate_limited",
    "web.fetch.error.mime_type_not_allowed",
    "web.fetch.error.size_limit_exceeded",
    # System / bootstrap keys
    "bootstrap.quarantined_provider_same_as_privileged",
    "orchestrator.quarantine_unavailable",
    "orchestrator.action_timeout",
    "security.tag_t3_unauthorized",  # i18n-003: was missing from original list
    "security.tier_mismatch",
    "security.canary_tripped",
    "capability_gate.unavailable",
    "plugin.manifest_version_mismatch",
    "plugin.launcher_no_sandbox_policy",
    "plugin.grant_prompt",
    # Cluster 1: DLP outbound refused key (PR-S3-3a StdioTransport rewrite)
    "plugin.transport.dlp_outbound_refused",
    "quarantine.schema_version_missing",
    "bootstrap.capability_gate_unseeded",
]

# Cluster 6 / i18n-007: placeholder-integrity mapping.
# Keys that have placeholders declare the minimum required kwargs here.
# test_slice3_key_placeholder_integrity renders t(key, **kwargs) and asserts:
# (a) no KeyError raised, (b) rendered string differs from msgstr-without-subs.
# Kwargs are drawn from the call-sites planned in S3-1 .. S3-6.
# i18n-001: cli.config.web_fetch_budget_set uses {user} + {n} (not {key}/{value})
# i18n-002: cli.plugin.grant.pending_review uses {branch} + {proposal_id}
# devex-004: cli.supervisor.reset.confirm_prompt uses {component},{trip_count},{last_trip_at}
_KEY_REQUIRED_PLACEHOLDERS: dict[str, dict[str, object]] = {
    "cli.plugin.grant.follow_up_command": {"proposal_id": "prop-abc123"},
    "cli.plugin.grant.success": {"plugin_id": "alfred.web-fetch", "hookpoint": "tool.web.fetch"},
    "cli.web.allowlist.add.denied": {"reason": "quota exceeded"},
    "cli.web.allowlist.remove.denied": {"reason": "quota exceeded"},
    "cli.config.set.denied": {"reason": "high-blast change requires reviewer gate"},
    "cli.config.set.unknown_key": {"key": "web_fetch.unknown_field"},
    "cli.config.get.unknown_key": {"key": "web_fetch.unknown_field"},
    "cli.config.get.not_set": {"key": "web_fetch.user_agent"},
    "cli.audit.graph.empty": {"tier": "T3", "since": "24h"},
    "cli.audit.graph.tier_header": {"tier": "T3"},
    # i18n-002: caller sends branch= + proposal_id=
    "cli.plugin.grant.pending_review": {"branch": "proposal/abc123", "proposal_id": "prop-xyz"},
    "cli.plugin.grant.denied": {
        "plugin_id": "alfred.web-fetch",
        "hookpoint": "tool.web.fetch",
        "reason": "not approved",
    },
    "cli.plugin.grant.confirm_prompt": {
        "plugin_id": "alfred.web-fetch",
        "hookpoint": "tool.web.fetch",
        "tier": "operator",
        "blast_radius": "read-only web access",
    },
    # i18n-002: caller sends proposal_id=
    "cli.plugin.grant.status.pending": {"proposal_id": "prop-abc123"},
    "cli.plugin.grant.status.approved": {"commit_hash": "abc123def"},
    "cli.plugin.grant.status.denied": {"reason": "policy violation"},
    "cli.web.allowlist.pending_review": {
        "proposal_branch": "proposal/allow-abc",
        "proposal_id": "prop-xyz",
    },
    "cli.web.allowlist.added": {"domain": "example.com"},
    "cli.web.allowlist.removed": {"domain": "example.com"},
    "cli.config.quarantined_provider_pending_review": {
        "provider": "deepseek",
        "proposal_branch": "proposal/qprov-abc",
    },
    # i18n-001: caller sends user= + n= (not key=/value=)
    "cli.config.web_fetch_budget_set": {"user": "alice", "n": 50},
    # devex-004: caller sends component= + trip_count= + last_trip_at=
    "cli.supervisor.reset.confirm_prompt": {
        "component": "quarantined-llm",
        "trip_count": 3,
        "last_trip_at": "2026-05-31T00:00:00Z",
    },
    "cli.supervisor.reset.success": {"component": "quarantined-llm"},
    "cli.supervisor.reset.component_not_found": {"component": "quarantined-llm"},
    # devex-004 / i18n-004
    "cli.supervisor.reset.rerun_hint": {"component": "quarantined-llm"},
    # devex-016
    "cli.audit.graph.since_invalid": {"value": "7day", "example": "24h, 7d, or 90m"},
    "web.fetch.error.domain_not_allowed": {"domain": "blocked.example.com"},
    "web.fetch.error.tls_failure": {"url": "https://example.com"},
    "web.fetch.error.rate_limited": {"limit": "10/min", "scope": "domain", "retry_after": 30},
    "web.fetch.error.mime_type_not_allowed": {"mime_type": "application/pdf"},
    "web.fetch.error.size_limit_exceeded": {"size": 6291456, "limit": 5242880},
    "security.tag_t3_unauthorized": {"caller_id": "rogue-module"},
    "security.tier_mismatch": {"wire_tier": "T2", "expected_tier": "T3Content"},
    "security.canary_tripped": {"url": "https://attacker.example.com"},
    "plugin.manifest_version_mismatch": {"got": 2, "expected": 1},
    "plugin.launcher_no_sandbox_policy": {"plugin_id": "alfred.custom-plugin"},
    "plugin.grant_prompt": {
        "plugin_id": "alfred.web-fetch",
        "tier": "operator",
        "hookpoint": "tool.web.fetch",
        "blast_radius": "read-only web",
    },
    # Cluster 1: DLP outbound refused
    "plugin.transport.dlp_outbound_refused": {"plugin_id": "alfred.web-fetch"},
    "quarantine.schema_version_missing": {"schema_name": "MyExtractionSchema"},
    "bootstrap.capability_gate_unseeded": {},
    "bootstrap.quarantined_provider_same_as_privileged": {},
}


@pytest.mark.parametrize("key", _SLICE_3_KEYS)
def test_slice3_key_resolves(key: str) -> None:
    """t(key) returns a non-empty string that is not the bare key."""
    result = t(key)
    assert isinstance(result, str), f"t({key!r}) did not return str"
    assert result, f"t({key!r}) returned empty string"
    assert result != key, (
        f"t({key!r}) returned the bare key — "
        f"entry is missing from locale/en/LC_MESSAGES/alfred.po. "
        f"Add the entry and run pybabel extract + compile."
    )


@pytest.mark.parametrize(
    "key,kwargs",
    [(key, kwargs) for key, kwargs in _KEY_REQUIRED_PLACEHOLDERS.items()],
)
def test_slice3_key_placeholder_integrity(key: str, kwargs: dict[str, object]) -> None:
    """t(key, **kwargs) renders without KeyError and substitutes placeholder values.

    Cluster 6 / i18n-007: catches catalog/call-site kwarg mismatches at CI
    rather than at PR-S3-6 runtime. i18n-001 (cli.config.web_fetch_budget_set
    {user}/{n}), i18n-002 (cli.plugin.grant.pending_review {branch}), devex-004
    (cli.supervisor.reset.confirm_prompt {component}/{trip_count}/{last_trip_at})
    would all raise KeyError without this test.
    """
    try:
        rendered = t(key, **kwargs)
    except KeyError as exc:
        raise AssertionError(
            f"t({key!r}, **{kwargs!r}) raised KeyError({exc}) — "
            f"placeholder mismatch between catalog msgstr and expected kwargs. "
            f"Check locale/en/LC_MESSAGES/alfred.po entry for {key!r}."
        ) from exc
    assert rendered != key, f"t({key!r}) with kwargs still returned bare key"
    # Verify at least one kwarg value appears in the rendered string
    if kwargs:
        any_substituted = any(str(v) in rendered for v in kwargs.values() if v != "")
        assert any_substituted, (
            f"t({key!r}, **{kwargs!r}) = {rendered!r} — "
            f"none of the kwarg values appear in the output. "
            f"Check that the msgstr contains the expected placeholder names."
        )
