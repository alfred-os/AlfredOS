"""Verify CLI i18n keys are present, fully substituted, and semantically correct.

Spec §11.5 splits ownership: the catalog-additions PR (PR-S3-0b) ships
the canonical English bodies; implementing fork PRs may polish the
copy. Per Task 20 of the PR-S3-6 plan (lines 2396-2495) this PR adds
the missing keys verbatim to keep the implementing surface unblocked,
with the editorial-review pass deferred to the catalog-additions PR's
copy review.

**Why per-key fingerprints, not just ``result != key``** (i18n-001 /
test-engineer carry-forward from web_fetch's prior pattern).

The earlier shape of this test asserted only that ``t(key) != key``.
That caught a missing msgstr but it did NOT catch a pybabel
**fuzzy-match wrong-msgstr swap** -- a real-world failure mode where
the build tool copies a similar-looking neighbouring msgstr onto a
new msgid. PR-S3-5's ``web_fetch`` corpus first surfaced this with
``web.fetch.error.redirect_refused``: pybabel populated it with the
``tls_failure`` body, the assertion still passed (the result was
non-empty and not the bare key), and the broken string only surfaced
when an operator hit a real redirect.

PR-S3-6 originally regressed back to ``t(key) != key`` for the CLI
surface; this test re-establishes the per-key fingerprint pattern.

i18n-002 placeholder-leak guard. ``alfred.i18n.t`` swallows
``KeyError`` / ``IndexError`` from ``str.format`` and returns the
unsubstituted template; a surviving ``{name}`` in the rendered string
reveals either a placeholder we forgot to pass OR a typo in the
catalog template. Both fail the test loudly so the build catches
them.

Adding a new ``t(...)`` call in this subsystem requires three edits:
adding the msgid to ``locale/en/LC_MESSAGES/alfred.po`` with a REAL
msgstr (not a pybabel fuzzy-copy of a neighbour), running
``pybabel update`` + ``pybabel compile``, and adding a row to
:data:`_FINGERPRINTS` below.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

import pytest

from alfred.i18n import t

# Per-key fingerprint table. Each entry pins:
#   - the placeholder kwargs the msgstr template needs (so str.format
#     succeeds and no ``{name}`` literal survives in the output);
#   - one or more EXPECTED SUBSTRINGS -- at least one must appear in
#     the rendered result (case-insensitively), anchoring the test to
#     *this* msgstr's semantics and not a fuzzy-match neighbour's.
#
# The fingerprint vocabulary points at the load-bearing nouns of each
# msgstr -- what a reviewer scanning a wrong fuzzy-swap would notice
# missing. e.g. ``cli.supervisor.reset.success`` fingerprints on
# "reset" + "audit row"; a fuzzy swap with the "denied" body contains
# neither and the test fails.
_FINGERPRINTS: Final[dict[str, tuple[Mapping[str, object], tuple[str, ...]]]] = {
    # cli.plugin.grant.* -- async-UX surfaces
    "cli.plugin.grant.pending_review": (
        {"branch": "proposal/policy-grant-aaaa", "proposal_id": "aaaa"},
        ("queued", "reviewer"),
    ),
    "cli.plugin.grant.denied": (
        {"reason": "push refused"},
        ("denied",),
    ),
    "cli.plugin.grant.follow_up_command": (
        {"proposal_id": "aaaa"},
        ("alfred plugin grant", "status"),
    ),
    # cli.plugin.revoke.* -- async-UX surfaces
    #
    # CR-149 round-10 (3339361819): the revoke keys are rendered by
    # the shipped CLI (``alfred plugin revoke <id>``) but were only
    # covered by the pybabel-anchor presence tests below. Those catch
    # a missing msgid and a surviving ``{placeholder}`` but not the
    # fuzzy-copy/wrong-msgstr swap this fingerprint table is meant
    # to detect. Mirroring the grant entries closes the semantic gap.
    "cli.plugin.revoke.pending_review": (
        {"branch": "proposal/policy-revoke-aaaa", "proposal_id": "aaaa"},
        ("revocation", "reviewer"),
    ),
    "cli.plugin.revoke.denied": (
        {"reason": "push refused"},
        ("denied",),
    ),
    "cli.plugin.grant.status.pending": (
        {"branch": "proposal/policy-grant-aaaa", "proposal_id": "aaaa"},
        ("pending",),
    ),
    "cli.plugin.grant.status.approved": (
        {"proposal_id": "aaaa", "merged_at": "2026-05-31"},
        ("approved",),
    ),
    "cli.plugin.grant.status.denied": (
        {"proposal_id": "aaaa", "reviewer": "ops"},
        ("denied",),
    ),
    "cli.plugin.grant.status.expired": (
        {"proposal_id": "aaaa"},
        ("expired",),
    ),
    # cli.plugin.list / show surfaces
    "cli.plugin.list.column.plugin_id": ({}, ("plugin",)),
    "cli.plugin.list.column.subscriber_tier": ({}, ("tier",)),
    "cli.plugin.list.column.status": ({}, ("status",)),
    "cli.plugin.list.column.manifest_version": ({}, ("manifest", "version")),
    "cli.plugin.list.empty_hint": ({}, ("plugin",)),
    "cli.plugin.list.not_implemented_yet": (
        {},
        ("not", "implemented"),
    ),
    "cli.plugin.show.field.plugin_id": ({}, ("plugin",)),
    # cli.web.allowlist.* -- async-UX surfaces
    #
    # CR-149: the keys the live CLI renders are the per-action
    # ``cli.web.allowlist.add.pending_review`` /
    # ``cli.web.allowlist.remove.pending_review`` pair (wired via
    # ``queue_proposal_or_exit(pending_review_key=...)`` in
    # ``src/alfred/cli/web.py``) and ``cli.web.allowlist.list.empty``
    # for the empty-list message. The bare ``cli.web.allowlist.pending_review``
    # + ``cli.web.allowlist.list_empty`` entries also live in the
    # catalog as deferred key anchors (see
    # ``src/alfred/i18n/_deferred_key_anchors.py``) for a future PR's
    # surface; they are fingerprinted by
    # :mod:`tests.unit.i18n.test_deferred_key_anchors` already. This
    # table pins the keys THIS PR's CLI actually renders.
    "cli.web.allowlist.add.pending_review": (
        {"branch": "proposal/web-allowlist-add-aaaa", "proposal_id": "aaaa"},
        ("allowlist", "reviewer"),
    ),
    "cli.web.allowlist.remove.pending_review": (
        {"branch": "proposal/web-allowlist-remove-aaaa", "proposal_id": "aaaa"},
        ("allowlist", "reviewer"),
    ),
    "cli.web.allowlist.add.denied": (
        {"reason": "push refused"},
        ("allowlist", "add", "denied"),
    ),
    "cli.web.allowlist.remove.denied": (
        {"reason": "push refused"},
        ("allowlist", "remove", "denied"),
    ),
    # cli.web.allowlist.list columns + empty hint
    "cli.web.allowlist.list.column.domain": ({}, ("domain",)),
    "cli.web.allowlist.list.column.path_prefix": ({}, ("path",)),
    "cli.web.allowlist.list.column.granted_by": ({}, ("granted",)),
    "cli.web.allowlist.list.column.granted_at": ({}, ("granted",)),
    "cli.web.allowlist.list.empty": (
        {},
        ("allowlist",),
    ),
    # cli.config.* -- quarantined-provider + set/get/list
    #
    # CR-149: ``cli.config.set.pending_review`` is the key the live CLI
    # renders for the high-blast quarantined-provider flow (wired via
    # ``queue_proposal_or_exit(pending_review_key="cli.config.set.pending_review")``
    # in ``src/alfred/cli/config.py``). The legacy
    # ``cli.config.quarantined_provider_pending_review`` entry stays
    # in the catalog as a deferred key anchor (see
    # ``src/alfred/i18n/_deferred_key_anchors.py``) for parity with the
    # rest of the deferred surface; the deferred-anchor presence test
    # in :mod:`tests.unit.i18n.test_deferred_key_anchors` fingerprints
    # it. This table pins the key the CLI actually renders today.
    "cli.config.set.pending_review": (
        {
            "branch": "proposal/config-quarantined-provider-aaaa",
            "proposal_id": "aaaa",
            "key": "quarantined-provider",
        },
        ("reviewer", "high-blast"),
    ),
    "cli.config.web_fetch_budget_set": (
        {"limit": 50, "user_id": "u-1"},
        ("budget",),
    ),
    "cli.config.set.denied": (
        {"reason": "push refused"},
        ("config", "denied"),
    ),
    "cli.config.set.unknown_key": (
        {"key": "no-such-key", "valid_keys": "web-fetch-budget, ..."},
        ("recognised", "valid keys"),
    ),
    "cli.config.get.unknown_key": (
        {"key": "no-such-key", "valid_keys": "web-fetch-budget, ..."},
        ("recognised", "valid keys"),
    ),
    "cli.config.get.not_set": (
        {"key": "web-fetch-budget"},
        ("not set", "policies.yaml"),
    ),
    "cli.config.list.empty": (
        {},
        ("policies.yaml",),
    ),
    "cli.config.error.malformed_yaml": (
        # err-002 catalog addition. Fingerprint anchors on the recovery
        # vocabulary so a future fuzzy swap with another "config refused"
        # body surfaces.
        {"yaml_path": "/etc/alfred/policies.yaml", "error": "expected ':'"},
        ("malformed", "fix"),
    ),
    "cli.config.error.read_failed": (
        # CR-149 round-6: OSError on policies.yaml read routes through
        # a dedicated key so the operator sees a permission-recovery
        # hint instead of a raw traceback.
        {"yaml_path": "/etc/alfred/policies.yaml", "error": "Permission denied"},
        ("read", "permissions"),
    ),
    # cli.supervisor.reset.* — ADR-0021 #171 rewires the path so reset
    # writes a state.git proposal. The old deferred-to-#171 +
    # confirm_help no-op bodies are tombstoned; fingerprints follow
    # the new copy.
    "cli.supervisor.reset.help.short": (
        {},
        ("reset", "proposal"),
    ),
    "cli.supervisor.reset.confirm_help": (
        {},
        ("confirm", "proposal"),
    ),
    # ADR-0021 #171: confirm gate restored. Body names the flag operators
    # need to add for the recovery action.
    "cli.supervisor.reset.confirm_required": (
        {},
        ("--confirm", "queue"),
    ),
    "cli.supervisor.reset.denied": (
        {"reason": "state.git push rejected"},
        ("denied",),
    ),
    "cli.supervisor.reset.proposal_submitted": (
        {
            "component": "quarantined-llm",
            "branch": "proposal/breaker-reset-abc",
            "proposal_id": "abc",
            "interval": 30,
        },
        ("proposal", "branch", "alfred supervisor proposals"),
    ),
    # ``cli.supervisor.reset.{success,component_not_found,unexpected_error}``
    # tombstoned in #154 / ADR-0020 (Task 3). The reset command is now
    # deferred to #171; the success / not-found / unexpected-error
    # dispositions are unreachable until #171 ships. The
    # ``deferred_to_issue_171`` entry above covers the new operator
    # surface.
    # cli.supervisor.status.* -- table + empty hints
    "cli.supervisor.status.column.component": ({}, ("component",)),
    "cli.supervisor.status.column.state": ({}, ("state",)),
    "cli.supervisor.status.column.trip_count": ({}, ("trip",)),
    "cli.supervisor.status.column.last_trip_at": ({}, ("trip",)),
    # #154 / ADR-0020: the two distinct "supervisor unreachable" /
    # "read path missing" dispositions collapse into
    # ``postgres_unavailable`` because the operator action (check the
    # stack) is identical. The empty-table case uses the more
    # operator-targeted ``no_components_yet`` key.
    "cli.supervisor.status.postgres_unavailable": (
        {},
        ("postgres", "database_url"),
    ),
    "cli.supervisor.status.no_components_yet": ({}, ("components",)),
    # CR-156 round-7 MEDIUM #14: freshness footer rendered after the table.
    "cli.supervisor.status.freshness_footer": (
        {},
        ("snapshot", "save_to_db"),
    ),
    # CR-156 round-7 BLOCKER #4: schema-not-initialised hint fingerprints
    # on the remediation vocabulary ("migrate" / "alembic upgrade") so a
    # future fuzzy swap with a generic "config broken" body surfaces.
    "cli.supervisor.status.schema_not_initialised": (
        {},
        ("migrate", "alembic"),
    ),
    # ADR-0021 #171: cli.supervisor.reset.deferred_to_issue_171 was
    # tombstoned when the dispatcher landed; the proposal_submitted +
    # confirm_required keys above replace it.
    "cli.supervisor.status.breaker_state.open": ({}, ("open",)),
    "cli.supervisor.status.breaker_state.closed": ({}, ("closed",)),
    "cli.supervisor.status.breaker_state.half_open": ({}, ("half",)),
    # CR-156 round-7 HIGH #5: the default branch when ``state_raw`` falls
    # outside the closed-set enum. Fingerprinted alongside the three live
    # breaker states so a future fuzzy swap is loud here too.
    "cli.supervisor.status.breaker_state.unknown": ({}, ("unknown",)),
    # cli.audit.graph + log surfaces
    "cli.audit.graph.tier_help": (
        {},
        ("tier", "swimlane"),
    ),
    "cli.audit.graph.since_help": (
        {},
        ("lookback", "24h"),
    ),
    "cli.audit.graph.since_invalid": (
        {"value": "abc", "example": "24h, 7d, or 30m"},
        ("--since", "expected"),
    ),
    "cli.audit.graph.empty": (
        {"tier": " (T3)", "since": "24h"},
        ("no audit rows",),
    ),
    "cli.audit.graph.tier_header": (
        {"tier": "T3"},
        ("audit graph", "swimlane"),
    ),
    "cli.audit.graph.header": (
        {},
        ("audit graph", "all tiers"),
    ),
    "cli.audit.log.event_help": (
        {},
        ("event",),
    ),
}


@pytest.mark.parametrize("key", sorted(_FINGERPRINTS.keys()))
def test_cli_i18n_key_resolves_with_fingerprint(key: str) -> None:
    """Key resolves to a non-empty, fully-substituted, semantically-correct string.

    Three checks, each defending a different failure mode:

    1. ``result != key`` -- guards against a missing/empty msgstr
       (gettext falls back to the bare key when there is no
       translation).
    2. No ``{`` or ``}`` survives in the output (i18n-002) -- guards
       against a msgstr that references a placeholder we forgot to
       supply or one that the template authored with the wrong name.
       The earlier ``except (KeyError, IndexError)`` swallow in
       :func:`alfred.i18n.t` returns the un-substituted template on
       missing kwargs, so a surviving ``{`` reveals a placeholder
       mismatch even when the runtime doesn't raise.
    3. At least one fingerprint substring is present (i18n-001) --
       guards against a pybabel fuzzy-match wrong-msgstr swap.
       Substrings match case-insensitively so a future capitalisation
       re-phrase ("PROPOSAL" -> "proposal") doesn't fail the test
       for a non-substantive reason.
    """
    placeholders, fingerprints = _FINGERPRINTS[key]
    result = t(key, **placeholders)

    # (1) Catalog presence.
    assert result != key, (
        f"i18n key {key!r} is missing from the catalog (or has an "
        f"empty msgstr). Add the canonical English text to "
        f"locale/en/LC_MESSAGES/alfred.po + run "
        f"`pybabel compile -d locale -D alfred`."
    )
    assert result.strip(), (
        f"i18n key {key!r} resolved to a whitespace-only string -- "
        f"msgstr is present but empty after substitution; fix the "
        f"msgstr in locale/en/LC_MESSAGES/alfred.po."
    )

    # (2) i18n-002: placeholder-leak guard. Surviving ``{`` / ``}``
    # means either the test kwargs miss a placeholder OR the msgstr
    # template references a name the call site does not pass.
    assert "{" not in result and "}" not in result, (
        f"i18n key {key!r} rendered with un-substituted placeholders -- "
        f"either the test kwargs in _FINGERPRINTS[{key!r}] are missing a "
        f"placeholder, or the msgstr template references a name the CLI "
        f"call site does not pass. Got: {result!r}"
    )

    # (3) i18n-001: fingerprint check. The canonical defence against a
    # pybabel fuzzy-match wrong-msgstr swap.
    lowered = result.lower()
    assert any(fp.lower() in lowered for fp in fingerprints), (
        f"i18n key {key!r} rendered without any expected fingerprint -- "
        f"pybabel fuzzy-match may have swapped the wrong msgstr onto "
        f"this key (i18n-001). Expected one of {fingerprints!r}; "
        f"got: {result!r}"
    )


# ---------------------------------------------------------------------------
# Pybabel-visibility anchor functions (cross-cutting R5)
# ---------------------------------------------------------------------------
#
# :func:`queue_proposal_or_exit` consumes the ``denied_key`` +
# ``pending_review_key`` strings via parameter, so the pybabel AST walker
# cannot find them statically. Each sub-app declares a private
# ``_register_proposal_keys_for_pybabel`` shim that returns the live
# ``t(...)`` renders — never called at runtime but it MUST work when
# invoked. A future refactor that decides to use it for e.g. catalog
# validation would silently get the bare msgids if the shim broke; pin
# the live shape here so the regression is loud.


def test_cli_plugin_register_proposal_keys_anchors_resolve_to_real_msgstrs() -> None:
    """``alfred.cli.plugin._register_proposal_keys_for_pybabel`` renders
    four non-bare strings for the grant/revoke denied + pending_review
    key pairs. Mirrors
    :func:`alfred.cli._state_git._register_hint_keys_for_pybabel` shape.
    """
    from alfred.cli.plugin import _register_proposal_keys_for_pybabel

    rendered = _register_proposal_keys_for_pybabel()
    assert len(rendered) == 4
    for body in rendered:
        # Bare msgid would still contain the dotted-path prefix.
        assert not body.startswith("cli.plugin.grant.")
        assert not body.startswith("cli.plugin.revoke.")
        assert body.strip() != ""
        # CR-149 round-3: the shim passes representative kwargs so the
        # rendered body fully substitutes every placeholder. A leaked
        # ``{`` / ``}`` means the shim regressed to the no-kwarg shape
        # OR the msgstr carries a placeholder the shim does not
        # supply — both surface as i18n-coverage failures here.
        assert "{" not in body and "}" not in body


def test_cli_web_register_proposal_keys_anchors_resolve_to_real_msgstrs() -> None:
    """``alfred.cli.web._register_proposal_keys_for_pybabel`` renders
    four non-bare strings for the allowlist add/remove denied + pending
    pairs.
    """
    from alfred.cli.web import _register_proposal_keys_for_pybabel

    rendered = _register_proposal_keys_for_pybabel()
    assert len(rendered) == 4
    for body in rendered:
        assert not body.startswith("cli.web.allowlist.")
        assert body.strip() != ""
        # CR-149 round-3: see plugin equivalent above.
        assert "{" not in body and "}" not in body


def test_cli_config_register_proposal_keys_anchors_resolve_to_real_msgstrs() -> None:
    """``alfred.cli.config._register_proposal_keys_for_pybabel`` renders
    two non-bare strings for ``config.set.denied`` +
    ``config.set.pending_review``.
    """
    from alfred.cli.config import _register_proposal_keys_for_pybabel

    rendered = _register_proposal_keys_for_pybabel()
    assert len(rendered) == 2
    for body in rendered:
        assert not body.startswith("cli.config.set.")
        assert body.strip() != ""
        # CR-149 round-3: see plugin equivalent above.
        assert "{" not in body and "}" not in body
