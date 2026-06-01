"""Verify t() keys used in Slice-3 CLI modules are declared in spec §11.5.

This test holds the line that every i18n key spec §11.5 lists as a
PR-S3-6 deliverable exists in ``locale/en/LC_MESSAGES/alfred.po`` with
a real ``msgstr`` (i.e. ``t(key) != key``). A missing key returns the
bare key string from :func:`t` — a developer-visible "this catalog
slot is empty" signal — and any operator-facing CLI surface that hits
the bare key is a hard regression of CLAUDE.md i18n rule #1.

Spec §11.5 splits ownership: the catalog-additions PR (PR-S3-0b) ships
the canonical English bodies; implementing fork PRs may polish the
copy. Per Task 20 of the PR-S3-6 plan (lines 2396-2495) this PR adds
the missing keys verbatim to keep the implementing surface unblocked,
with the editorial-review pass deferred to the catalog-additions PR's
copy review.
"""

from __future__ import annotations

import pytest

from alfred.i18n import t

# Keys declared in spec §11.5 that this PR introduces or relies on.
# Add new keys here as new t() calls are added to CLI modules in
# subsequent batches of PR-S3-6 — the parametrised test below pins
# each one against the catalog. PR-S3-7 follow-up: extend the set with
# the keys that the live audit-row emission and Postgres-projection
# wiring introduce (plugin.grant.status.{approved,denied,expired}
# already land here because the status subcommand already references
# the surface in the CLI module's deferred-stub note).
_SPEC_11_5_KEYS_THIS_PR: frozenset[str] = frozenset(
    {
        # cli.plugin.grant.* — async-UX surfaces
        "cli.plugin.grant.pending_review",
        "cli.plugin.grant.denied",
        "cli.plugin.grant.follow_up_command",
        "cli.plugin.grant.status.pending",
        "cli.plugin.grant.status.approved",
        "cli.plugin.grant.status.denied",
        "cli.plugin.grant.status.expired",
        # cli.plugin.list / show columns + status hints
        "cli.plugin.list.column.plugin_id",
        "cli.plugin.list.column.subscriber_tier",
        "cli.plugin.list.column.status",
        "cli.plugin.list.column.manifest_version",
        "cli.plugin.list.empty_hint",
        "cli.plugin.list.not_implemented_yet",  # devex-011
        "cli.plugin.show.field.plugin_id",
        # cli.web.allowlist.* — async-UX surfaces
        "cli.web.allowlist.pending_review",
        "cli.web.allowlist.add.denied",
        "cli.web.allowlist.remove.denied",
        "cli.web.allowlist.added",
        "cli.web.allowlist.removed",
        # cli.web.allowlist.list columns + empty hint
        "cli.web.allowlist.list.column.domain",
        "cli.web.allowlist.list.column.path_prefix",
        "cli.web.allowlist.list.column.granted_by",
        "cli.web.allowlist.list.column.granted_at",
        "cli.web.allowlist.list_empty",
        # cli.config.* — quarantined-provider + set/get/list
        "cli.config.quarantined_provider_pending_review",
        "cli.config.web_fetch_budget_set",
        "cli.config.set.denied",
        "cli.config.set.unknown_key",
        "cli.config.get.unknown_key",
        "cli.config.get.not_set",
        "cli.config.list.empty",
        "cli.config.error.malformed_yaml",  # err-002
        # cli.supervisor.reset.* — confirm + result surfaces
        "cli.supervisor.reset.confirm_prompt",
        "cli.supervisor.reset.rerun_hint",  # i18n-004 / devex-004
        "cli.supervisor.reset.success",
        "cli.supervisor.reset.component_not_found",
        "cli.supervisor.reset.unexpected_error",  # devex-005
        # cli.supervisor.status.* — table + empty hints
        "cli.supervisor.status.column.component",
        "cli.supervisor.status.column.state",
        "cli.supervisor.status.column.trip_count",
        "cli.supervisor.status.column.last_trip_at",
        "cli.supervisor.status.empty_hint",
        "cli.supervisor.status.no_supervisor_running",  # devex-013
        "cli.supervisor.status.breaker_state.open",
        "cli.supervisor.status.breaker_state.closed",
        "cli.supervisor.status.breaker_state.half_open",
        # cli.audit.graph + log surfaces
        "cli.audit.graph.tier_help",
        "cli.audit.graph.since_help",
        "cli.audit.graph.since_invalid",  # devex-016
        "cli.audit.graph.empty",
        "cli.audit.graph.tier_header",
        "cli.audit.graph.header",
        "cli.audit.log.event_help",  # devex-008
    }
)


@pytest.mark.parametrize("key", sorted(_SPEC_11_5_KEYS_THIS_PR))
def test_key_has_real_msgstr_in_catalog(key: str) -> None:
    """Spec §11.5 key has a non-fallback translation in the live catalog.

    :func:`t` returns the input key when the catalog has no entry (or
    when the entry's msgstr is the empty string). Any spec §11.5 key
    that round-trips to itself indicates either (a) the catalog is
    missing the entry, or (b) the pybabel compile step did not pick up
    the addition. Either way, the operator-facing CLI surface that
    routes through this key would render the bare key — a hard
    regression of CLAUDE.md i18n rule #1.
    """
    rendered = t(key)
    assert rendered != key, (
        f"i18n key {key!r} is missing from the catalog (or has an "
        f"empty msgstr). t(key) returned the bare key — the operator "
        f"would see {key!r} verbatim in the CLI. Add the canonical "
        f"English text to locale/en/LC_MESSAGES/alfred.po + run "
        f"`pybabel compile -d locale -D alfred`."
    )
