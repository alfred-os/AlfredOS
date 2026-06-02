"""Spec §11.5 catalog anchors for deferred CLI surfaces.

This module exists solely so :mod:`pybabel.extract` discovers — and
:mod:`pybabel.update` therefore preserves — the spec §11.5 i18n keys
whose live :func:`t` call sites land in a deferred PR. Without these
literal :func:`t` references the extractor sweeps the keys to ``#~
obsolete`` on the next ``pybabel update``, the .mo loses them, the
catalog test fails, and an operator on a preview build of the deferred
PR sees the bare key string in the CLI.

Why an anchor module (not inline anchors in the call-site modules):

* The CLI command bodies that legitimately reference these keys do
  not exist yet — they land in the deferred PR along with the Postgres
  projections, the live allowlist surface, and the quarantined-
  provider config wiring. Forcing a deferred-stub call site in each
  CLI module would scatter the deferred surface across five files
  and require dead-code branches whose own coverage gate
  contributes nothing.

* A dedicated anchor module is grep-able, single-file, and trivially
  removable when the deferred PR wires the live call sites — the
  anchor list shrinks one key per inline wiring delivered.

* The :func:`_anchor_deferred_keys` function is never called. The
  :func:`t` calls inside it run at extraction time only (pybabel
  parses the AST, it does not execute). The function-level scope
  keeps the keys away from any import-time side effect.

Per PR-S3-6 plan Task 20 (lines 2396-2495): the catalog-additions
PR shipped first (PR-S3-0b) by spec §11.5 ownership; PR-S3-6 verifies
coverage. Where PR-S3-0b's catalog is missing a spec §11.5 key whose
PR-S3-6 (or a deferred PR) consumer needs it, PR-S3-6 adds the key
verbatim so the implementing surface stays unblocked. The editorial-
copy review remains a catalog-additions-PR concern.

Module renamed from ``_pr_s3_7_key_anchors`` to ``_deferred_key_anchors``
during PR-S3-6 polish (arch-005): the previous name tied the module's
lifetime to a single PR identifier; the file's purpose — anchoring keys
whose call sites are deferred to a future PR — is PR-agnostic and
will recur in later slices.
"""

from __future__ import annotations

from alfred.i18n import t


def _anchor_deferred_keys() -> tuple[str, ...]:
    """Anchor every deferred spec §11.5 key in a literal :func:`t` call.

    Returns:
        Rendered translations in declaration order. The return value is
        immaterial — no caller invokes this helper; the value exists only
        so the function body is non-empty. The bytecode runs in tests
        only when a developer calls it explicitly to inspect rendering.

    Maintainer note: this list shrinks one entry per deferred-PR inline
    wiring delivered. When the deferred PR ships ``alfred plugin list``'s
    Postgres-projection query, drop the four ``cli.plugin.list.column.*``
    anchors here in the same PR — the live call sites in ``plugin.py``
    take over the extraction footprint.
    """
    return (
        # cli.plugin.grant.status.* — deferred PR's status-projection
        # query surfaces these three terminal states. Today only
        # `pending` is rendered (see alfred.cli.plugin._do_grant_status).
        t("cli.plugin.grant.status.approved"),
        t("cli.plugin.grant.status.denied"),
        t("cli.plugin.grant.status.expired"),
        # cli.plugin.list.* — deferred PR's plugin-manifest projection
        # surfaces a table; the four column headers + empty-hint
        # land here so the catalog is warm when the table prints.
        t("cli.plugin.list.column.plugin_id"),
        t("cli.plugin.list.column.subscriber_tier"),
        t("cli.plugin.list.column.status"),
        t("cli.plugin.list.column.manifest_version"),
        t("cli.plugin.list.empty_hint"),
        # cli.plugin.show.* — deferred PR's plugin-manifest projection
        # surfaces structured fields; today the CLI emits a short
        # `cli.plugin.show.plugin_id_label` fallback. The deferred PR's
        # surface adopts this canonical field key.
        t("cli.plugin.show.field.plugin_id"),
        # cli.web.allowlist.* — deferred PR wires the merged-grant
        # write path (today only the proposal-pending message exists).
        # The spec §11.5 set covers the success + projection-table keys.
        t("cli.web.allowlist.pending_review"),
        t("cli.web.allowlist.added"),
        t("cli.web.allowlist.removed"),
        t("cli.web.allowlist.list_empty"),
        # cli.config.* — deferred PR wires the quarantined-provider
        # config write path + per-user web-fetch budget surfacing.
        t("cli.config.quarantined_provider_pending_review"),
        t("cli.config.web_fetch_budget_set"),
        # cli.supervisor.status.breaker_state.* — referenced via a
        # dict lookup in alfred.cli.supervisor.status_cmd
        # (``state_key_map.get(state_raw, …)``). pybabel cannot
        # extract dict-literal lookups; these three anchors restore
        # extraction so the catalog stays compiled.
        t("cli.supervisor.status.breaker_state.open"),
        t("cli.supervisor.status.breaker_state.closed"),
        t("cli.supervisor.status.breaker_state.half_open"),
        # CR-149: ``unknown`` is the default branch when ``state_raw``
        # falls outside the closed-set enum. The anchor keeps pybabel
        # finding the key even though it is reached only through the
        # ``state_key_map.get(..., "cli.supervisor.status.breaker_state.unknown")``
        # default — extracting the literal at this anchor closes the
        # extraction gap.
        t("cli.supervisor.status.breaker_state.unknown"),
    )


__all__ = ["_anchor_deferred_keys"]
