"""``alfred plugin`` CLI — grant / revoke / list / show plugin capabilities.

Reviewer-gated commands (``grant``, ``revoke``) queue state.git proposals
through the module-level :class:`StateGitProposalClient` and print an
async-UX message: the operator sees the proposal branch name and a
follow-up command rather than a success-applied message. Read-only
commands (``list``, ``show``, ``grant status``, ``grant list``) read
from injectable seams; the full Postgres-projection wiring lands in
PR-S3-7 once :class:`RealGate` is seeded.

Hard rules honoured at this layer (CLAUDE.md):

* **Rule #1 — operator-facing strings via** :func:`t`. The Typer ``help=``
  strings are routed through ``t()`` so localised help is the default.
* **Rule #6 — payload structure, not raw secrets.** The proposal payload
  carries identifiers (plugin_id, subscriber_tier, hookpoint) only.
  No secret-shaped fields are ever placed here.
* **Rule #7 — no silent failures in security paths.**
  :class:`StateGitError` from the client is converted into a localised
  stderr message and a non-zero exit code. The bare exception is never
  swallowed.

Module-level seams the tests patch:

* ``_state_git_client`` — production reviewer-gate writer.
* ``_list_pending_grants`` — Postgres projection stub for
  ``alfred plugin grant list --pending``; PR-S3-7 swaps in the real query.

Audit-row emission. Stage 3 (arch-001 / cross-cutting R2) closes the
silent-skip gap: every reviewer-gated CLI command emits a ``*.requested``
audit-row stand-in BEFORE the state.git write via the
:func:`alfred.cli._state_git.queue_proposal_or_exit` helper. The grant
path uses :data:`PLUGIN_GRANT_REQUESTED_FIELDS`; the revoke path uses
:data:`PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS`. Both rows carry the auto-
generated ``proposal_branch`` + ``correlation_id`` so the audit-graph
correlator can join the CLI emit with the eventual projection-merge row
the reviewer-side rebuild emits. The PR-S3-7 swap from structlog to
:class:`alfred.audit.AuditWriter` is a single-line replacement inside
:func:`queue_proposal_or_exit` — no per-command changes needed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Final

import typer

from alfred.cli._state_git import (
    StateGitProposalClient,
    queue_proposal_or_exit,
)
from alfred.cli._validators import (
    validate_hookpoint,
    validate_plugin_id,
    validate_subscriber_tier,
)
from alfred.i18n import t
from alfred.state.proposal_payloads import (
    PluginGrantProposal,
    PluginRevokeProposal,
)

if TYPE_CHECKING:
    # Type-only re-exports for the constants returned by ``__getattr__``.
    # The runtime import lives inside the command bodies + the lazy
    # module-attribute hook so ``alfred --help`` does not pay the
    # ~140 ms SQLAlchemy ORM load that the parent ``alfred.audit``
    # package init triggers.
    from alfred.audit.audit_row_schemas import (
        PLUGIN_GRANT_FIELDS,
        PLUGIN_GRANT_REQUESTED_FIELDS,
    )

# The CLI surface re-exports :data:`PLUGIN_GRANT_FIELDS` so the
# audit-row shape stays a single source of truth between the
# proposal-flow emission site
# (``alfred.security.capability_gate.proposals.create_proposal_branch``)
# and the eventual CLI-side audit-emission wiring (PR-S3-7). Importing
# the constant here documents the contract that a future ``grant`` /
# ``revoke`` audit-row emit MUST use these six fields verbatim — no
# locally-copied tuple is permitted. The
# :mod:`tests.unit.cli.test_plugin_grant_audit_wiring` test corpus
# fails loudly if a refactor drops this import.
#
# Spec §14 hookpoint table: the four ``plugin.grant.*`` hookpoints
# (``requested``, ``approved``, ``denied``, ``revoked``) are declared
# at module-import time by
# :func:`alfred.security.capability_gate.proposals.declare_hookpoints`.
# The CLI's :class:`StateGitProposalClient` callers transitively load
# that publisher, so by the time any operator runs ``alfred plugin
# grant`` the registry already carries the four hookpoint metadata
# records. No additional registration call is needed from this module.

# Module-level seams. Tests patch these symbols.
_state_git_client: StateGitProposalClient = StateGitProposalClient()

# Proposal-type tags used in the branch name. ADR-0018 moved the
# canonical discriminator onto the typed Pydantic payloads, but the
# audit-row stand-in references ``_PROPOSAL_TYPE_GRANT`` /
# ``_PROPOSAL_TYPE_REVOKE`` by name in regression tests; keeping the
# constants here as local mirrors of the payload ``proposal_type``
# ClassVars preserves those references without re-introducing a parallel
# string the caller has to keep in sync. The single source of truth is
# the Pydantic model; these constants merely surface it locally.
_PROPOSAL_TYPE_GRANT: Final[str] = PluginGrantProposal.proposal_type
_PROPOSAL_TYPE_REVOKE: Final[str] = PluginRevokeProposal.proposal_type


def _list_pending_grants() -> list[dict[str, object]]:
    """Return pending (unmerged) grant proposals for ``grant list --pending``.

    Returns an empty list until PR-S3-7 wires the
    :class:`RealGate` Postgres projection (``plugin_grants`` table) +
    state.git branch index. Until then, an empty result is the correct
    behaviour for a fresh deployment — no grants have been proposed yet.
    Tests patch this symbol to inject fake projection rows without
    touching Postgres.
    """
    return []


# ---------------------------------------------------------------------------
# Typer apps
# ---------------------------------------------------------------------------

plugin_app = typer.Typer(
    help=t("cli.plugin.help.group"),
    no_args_is_help=True,
)


def _queue_grant_proposal(
    *,
    plugin_id: str,
    subscriber_tier: str,
    hookpoint: str,
) -> None:
    """Write a ``policy-grant`` proposal via the shared helper.

    Stage 3 (arch-001 / cross-cutting R2): consolidated through
    :func:`queue_proposal_or_exit` so the audit-row stand-in fires
    BEFORE the state.git write. The per-command body now only supplies
    the i18n keys + the audit subject; the helper handles the typer
    error mapping, the localised denial hint, and the symmetric
    audit-field validation.

    The follow-up ``alfred plugin grant status <id>`` line stays a
    separate typer.echo (the helper's pending-review block does not
    render it) so the operator can copy-paste it cleanly. The list-
    pending follow-up (devex-006) is bundled into the pending-review
    catalog entry itself.

    perf-001: ``audit_row_schemas`` is imported lazily here — the
    constant is only needed on the grant-request emit path, and its
    parent ``alfred.audit`` package init eagerly loads
    :mod:`alfred.memory.models` (~140 ms of SQLAlchemy ORM). Deferring
    keeps ``alfred plugin --help`` light.
    """
    from alfred.audit.audit_row_schemas import PLUGIN_GRANT_REQUESTED_FIELDS

    result = queue_proposal_or_exit(
        payload=PluginGrantProposal(
            plugin_id=plugin_id,
            # The validator's :class:`SubscriberTier` StrEnum value is
            # already the closed-set string the Pydantic model expects;
            # the Literal at the model layer pins it again so a typo
            # introduced between the validator and this construction
            # site fails at construction.
            subscriber_tier=subscriber_tier,  # type: ignore[arg-type]
            hookpoint=hookpoint,
        ),
        denied_key="cli.plugin.grant.denied",
        pending_review_key="cli.plugin.grant.pending_review",
        audit_event="plugin.grant.requested",
        audit_schema_name="PLUGIN_GRANT_REQUESTED_FIELDS",
        audit_fields=PLUGIN_GRANT_REQUESTED_FIELDS,
        audit_subject_partial={
            "plugin_id": plugin_id,
            "subscriber_tier": subscriber_tier,
            "hookpoint": hookpoint,
            # devex-007: PR-S3-7 wires the IdentityResolver bridge.
            # Until then the audit row carries ``None`` and the eventual
            # upgrade is a single emit-site edit.
            "operator_user_id": None,
            # CR-149 round-6: operator-typed CLI ingress is the canonical
            # T1 swimlane (PRD §7.1). The reviewer-gated capability
            # request originates from a real operator at the CLI; the
            # tag pins the row to the operator-action lane so audit-graph
            # queries (``alfred audit graph --tier T1``) surface it
            # alongside its eventual ``plugin.grant.rebuilt`` (T0) merge
            # twin.
            "trust_tier_of_trigger": "T1",
        },
        client=_state_git_client,
    )
    # Follow-up command line. Kept separate from the helper's pending-
    # review block so the operator can copy-paste the status command
    # without picking it out of a prose paragraph.
    typer.echo(
        t(
            "cli.plugin.grant.follow_up_command",
            proposal_id=result.proposal_id,
        )
    )
    # devex-006: surface the ``grant list --pending`` follow-up so an
    # operator who queued multiple grants in a shift can find them
    # without grepping the structlog stream. Until Stage 3 this hint
    # only existed in the empty-list message, which an operator who
    # never called the list command would never see.
    typer.echo(t("cli.plugin.grant.list_pending_hint"))


# ---------------------------------------------------------------------------
# grant <plugin_id> <subscriber_tier> <hookpoint>   (shorthand)
# grant status <proposal_id>                        (status subcommand)
# grant list [--pending]                            (list subcommand)
#
# Implementation note (resolves devex-009 from plan §478-484):
# Typer cannot register a command AND a sub-typer under the same name
# (``grant`` as both verb + group). Click resolves the conflict in
# favour of the most recently added handler, silently shadowing the
# other surface. We instead make ``grant`` a single command that
# inspects its first positional argument: when it matches a reserved
# subcommand name (``status``/``list``), the body dispatches to the
# matching helper; otherwise it treats the three positionals as the
# shorthand grant-request payload. This keeps the operator surface
# documented in PRD §11 verbatim while staying within Typer's command-
# resolution rules. The reserved-name set is intentionally tiny + closed
# so a future ``grant <plugin>`` whose plugin id happens to be ``status``
# is the documented edge case the operator resolves by adding a sentinel
# (e.g. ``--``) or qualifying the plugin id.
# ---------------------------------------------------------------------------

_GRANT_RESERVED_SUBCOMMANDS: Final[frozenset[str]] = frozenset({"status", "list"})


@plugin_app.command(
    "grant",
    help=t("cli.plugin.grant.help.short"),
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def grant(
    ctx: typer.Context,
    first: Annotated[
        str,
        typer.Argument(help=t("cli.plugin.grant.arg.plugin_id")),
    ],
) -> None:
    """``alfred plugin grant`` dispatcher.

    Three operator-visible surfaces are unified here:

    * ``alfred plugin grant status <proposal_id>``
    * ``alfred plugin grant list [--pending]``
    * ``alfred plugin grant <plugin_id> <subscriber_tier> <hookpoint>``

    The first positional decides which branch runs. ``status``/``list``
    are the reserved subcommand names; any other value is treated as the
    shorthand grant-request payload (with the remaining two positionals
    parsed off ``ctx.args``).
    """
    extra = list(ctx.args)
    # CR-149: the reserved-subcommand branch only fires when the
    # token sequence EXACTLY matches the subcommand's allowed shape:
    #
    # * ``grant status <proposal_id>``      — first == "status", len(extra) == 1
    # * ``grant list``                       — first == "list",   extra == []
    # * ``grant list --pending``             — first == "list",   extra == ["--pending"]
    #
    # Any other shape (extra tokens, flag typos, mismatched count)
    # falls through to the normal grant-request path and surfaces the
    # usage error there. Two failure modes the previous shape
    # silently swallowed:
    #
    # 1. Plugin ids named ``status`` / ``list`` could never be
    #    granted: the reserved-name branch consumed them
    #    unconditionally, treating ``grant status foo bar`` as
    #    ``status foo bar`` (one positional too many → usage error)
    #    and ``grant list user-plugin tool.x`` as
    #    ``list user-plugin tool.x`` (silently accepting the
    #    extras because the list branch only checked for
    #    ``--pending`` membership).
    # 2. ``grant list --pendng`` (typo) silently rendered the
    #    non-pending list with no warning — the parser accepted
    #    every token whose membership test for ``"--pending"``
    #    returned False.
    #
    # Failing closed here means the operator gets the usage error
    # on a typo instead of silently observing the wrong surface.
    if first == "status" and len(extra) == 1:
        _do_grant_status(extra[0])
        return
    if first == "list" and (extra == [] or extra == ["--pending"]):
        _do_grant_list(pending=extra == ["--pending"])
        return
    if first in _GRANT_RESERVED_SUBCOMMANDS:
        # Reserved verb with mismatched extra tokens — emit the
        # usage error rather than falling through to the
        # grant-request path, which would interpret e.g. ``status``
        # as a plugin id and demand two extra positionals.
        if first == "status":
            typer.echo(t("cli.plugin.grant.status.usage_error"), err=True)
        else:
            typer.echo(t("cli.plugin.grant.usage_error"), err=True)
        raise typer.Exit(code=2)
    if len(extra) != 2:
        typer.echo(t("cli.plugin.grant.usage_error"), err=True)
        raise typer.Exit(code=2)
    subscriber_tier_raw, hookpoint_raw = extra
    # sec-pr-s3-6-01: closed-set parser-time validation BEFORE the
    # proposal-write path. ``grant`` swallows positionals via
    # ``ctx.args`` to multiplex the shorthand against the reserved
    # subcommands, so the per-Argument ``callback=`` plumbing the other
    # Typer commands use is not available here. The validator helpers
    # raise :class:`typer.BadParameter` with a localised body; Typer
    # converts that into a clean stderr line + exit code 2 — no raw
    # traceback, no proposal payload that the reviewer has to either
    # notice or merge.
    validated_plugin_id = validate_plugin_id(first)
    validated_tier = validate_subscriber_tier(subscriber_tier_raw)
    validated_hookpoint = validate_hookpoint(hookpoint_raw)
    _queue_grant_proposal(
        plugin_id=validated_plugin_id,
        subscriber_tier=validated_tier.value,
        hookpoint=validated_hookpoint,
    )


# ---------------------------------------------------------------------------
# grant status — dispatched from the ``grant`` command above
# ---------------------------------------------------------------------------


def _do_grant_status(proposal_id: str) -> None:
    """Show approval status for a queued grant proposal.

    Until PR-S3-7 wires the Postgres ``plugin_grants`` projection query,
    this helper emits the canonical proposal branch name so the operator
    can ``git`` against state.git directly. The four real states
    (pending / approved / denied / not_found) land when the projection
    is available.
    """
    branch = f"proposal/{_PROPOSAL_TYPE_GRANT}-{proposal_id}"
    typer.echo(
        t(
            "cli.plugin.grant.status.pending",
            branch=branch,
            proposal_id=proposal_id,
        )
    )


# ---------------------------------------------------------------------------
# grant list — dispatched from the ``grant`` command above
# ---------------------------------------------------------------------------


def _do_grant_list(*, pending: bool) -> None:
    """List grants. With ``pending=True``, restrict to unmerged proposals."""
    rows: list[dict[str, object]] = _list_pending_grants() if pending else []
    if not rows:
        typer.echo(t("cli.plugin.grant.list.empty"))
        return
    typer.echo(
        "  ".join(
            [
                t("cli.plugin.grant.list.column.plugin_id").ljust(32),
                t("cli.plugin.grant.list.column.subscriber_tier").ljust(12),
                t("cli.plugin.grant.list.column.hookpoint").ljust(28),
                t("cli.plugin.grant.list.column.status").ljust(10),
            ]
        )
    )
    for row in rows:
        plugin_id = str(row.get("plugin_id", ""))
        subscriber_tier = str(row.get("subscriber_tier", ""))
        hookpoint = str(row.get("hookpoint", ""))
        status = str(row.get("status", "pending"))
        typer.echo(f"{plugin_id:<32}  {subscriber_tier:<12}  {hookpoint:<28}  {status:<10}")


# ---------------------------------------------------------------------------
# revoke <plugin_id>
# ---------------------------------------------------------------------------


@plugin_app.command("revoke", help=t("cli.plugin.revoke.help.short"))
def revoke(
    plugin_id: Annotated[
        str,
        typer.Argument(
            help=t("cli.plugin.revoke.arg.plugin_id"),
            callback=validate_plugin_id,
        ),
    ],
) -> None:
    """Queue a reviewer-gated revocation proposal for a plugin's grants.

    sec-pr-s3-6-01: ``plugin_id`` is parser-time-validated via
    :func:`alfred.cli._validators.validate_plugin_id`.

    Stage 3 (arch-001 / cross-cutting R2): the audit-row stand-in fires
    via :data:`PLUGIN_GRANT_FIELDS` BEFORE the state.git write. The
    ``subscriber_tier`` + ``hookpoint`` fields are ``None`` on the
    revoke path because a revocation targets every grant against the
    plugin (not a single hookpoint or tier); the audit family carries
    the fields anyway so the audit-graph correlator's join condition
    with the grant-request row stays uniform. The CLI request is
    distinct from the supervisor-side in-flight revocation denial
    (which uses :data:`PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS`); the two
    families capture different events at different layers.

    perf-001: ``audit_row_schemas`` is imported lazily here for the
    same reason as :func:`_queue_grant_proposal` — keep the typer
    --help surface light.
    """
    from alfred.audit.audit_row_schemas import PLUGIN_GRANT_FIELDS

    # CR-149: the audit event for the proposal-enqueue path is
    # ``plugin.grant.revoke.requested`` (an inflight / requested
    # row), NOT the terminal ``plugin.grant.revoked``. The proposal
    # is not yet approved or applied at this point: the reviewer
    # has to approve it, and the rebuild/apply path then emits the
    # terminal ``plugin.grant.revoked`` audit row when the row
    # actually leaves the ``plugin_grants`` table. Collapsing the
    # two into a single name skews ``alfred audit graph`` (the
    # operator sees "revoked" rows for proposals the reviewer has
    # not even seen yet) and breaks the trust-sensitive
    # request → approval → terminal-state correlation downstream
    # consumers depend on. The schema (``PLUGIN_GRANT_FIELDS``) is
    # unchanged because the row shape is the same — only the event
    # name differs between request-time and apply-time.
    queue_proposal_or_exit(
        payload=PluginRevokeProposal(plugin_id=plugin_id),
        denied_key="cli.plugin.revoke.denied",
        pending_review_key="cli.plugin.revoke.pending_review",
        audit_event="plugin.grant.revoke.requested",
        audit_schema_name="PLUGIN_GRANT_FIELDS",
        audit_fields=PLUGIN_GRANT_FIELDS,
        audit_subject_partial={
            "plugin_id": plugin_id,
            # Revoke targets every grant against the plugin; no per-
            # tier or per-hookpoint scoping. The audit fields are
            # ``None`` so the join condition with the grant-side row
            # (which has specific values) stays uniform across the
            # family.
            "subscriber_tier": None,
            "hookpoint": None,
            # devex-007: PR-S3-7 wires IdentityResolver.
            "operator_user_id": None,
        },
        client=_state_git_client,
    )


# ---------------------------------------------------------------------------
# list / show
# ---------------------------------------------------------------------------


@plugin_app.command("list", help=t("cli.plugin.list.help.short"), hidden=True)
def plugin_list() -> None:
    """List registered plugins (deferred to a follow-up PR).

    Hidden from ``alfred plugin --help`` per arch-006: the stub
    behaviour (exit 2 + localised "not implemented yet" message) is
    correct for an operator who has guessed the verb exists, but
    advertising it as a first-class command via ``--help`` overstates
    the surface this PR ships. The hidden flag keeps the command
    reachable for operators who type it deliberately while keeping
    the help table honest about what works today.

    devex-011 in plan §548: until the Postgres manifest projection is
    seeded, we MUST NOT emit silent-blank output — an operator could
    misread that as "no plugins loaded" rather than "this command is
    not implemented yet." Exit code 2 + a localised stderr message
    closes the failure mode.
    """
    typer.echo(t("cli.plugin.list.not_implemented_yet"), err=True)
    raise typer.Exit(code=2)


@plugin_app.command("show", help=t("cli.plugin.show.help.short"), hidden=True)
def plugin_show(
    plugin_id: Annotated[
        str,
        typer.Argument(
            help=t("cli.plugin.show.arg.plugin_id"),
            callback=validate_plugin_id,
        ),
    ],
) -> None:
    """Show manifest details for a registered plugin (deferred to a follow-up PR).

    Hidden from ``alfred plugin --help`` per arch-006 — same reasoning
    as :func:`plugin_list` above: deliberate invokers still hit a
    correct stub, but the help table no longer advertises a surface
    this PR does not implement.

    Until the Postgres manifest projection is wired, we echo the plugin
    id back + a localised "no manifest available yet" hint so the
    operator distinguishes "this is planned" from "no such plugin."
    """
    typer.echo(t("cli.plugin.show.plugin_id_label", plugin_id=plugin_id))
    typer.echo(t("cli.plugin.show.no_manifest_yet"))


def _register_proposal_keys_for_pybabel() -> tuple[str, ...]:
    """Surface the four proposal-flow i18n keys to pybabel's static extractor.

    Stage 3 (cross-cutting R5): :func:`queue_proposal_or_exit` consumes
    the ``denied_key`` + ``pending_review_key`` strings via parameter
    (not literal :func:`t` call), so the pybabel AST walker would
    otherwise drop the four keys to the obsoleted block when re-running
    ``pybabel update``. Surfacing them here pins them as live entries.
    Same pattern as :func:`alfred.cli._state_git._register_hint_keys_for_pybabel`.

    The function is never called at runtime — the return value only
    documents the canonical key list for grep + extractor visibility.
    """
    # CR-149 round-3: pass representative kwargs so each rendered
    # body fully substitutes its placeholders (``{reason}`` for the
    # denied keys; ``{branch}`` + ``{proposal_id}`` for the
    # pending-review keys). The earlier no-kwarg shape leaked the
    # literal ``{...}`` placeholders, which weakens the callable-
    # validation seam :mod:`tests.unit.cli.test_i18n_key_coverage`
    # depends on.
    return (
        t("cli.plugin.grant.denied", reason="example"),
        t("cli.plugin.grant.pending_review", branch="example", proposal_id="0123456789abcdef"),
        t("cli.plugin.revoke.denied", reason="example"),
        t("cli.plugin.revoke.pending_review", branch="example", proposal_id="0123456789abcdef"),
    )


# ---------------------------------------------------------------------------
# Lazy module-attribute resolution for the audit-row-schema re-exports
# ---------------------------------------------------------------------------
#
# perf-001: ``test_plugin_grant_audit_wiring.py`` asserts
# ``alfred.cli.plugin.PLUGIN_GRANT_FIELDS is PLUGIN_GRANT_FIELDS`` to pin
# the contract that the CLI's audit-row schema name resolves to the same
# canonical constant as ``alfred.audit.audit_row_schemas`` ships. Eagerly
# importing the constants at module-top forced the parent ``alfred.audit``
# package init to load :mod:`alfred.memory.models` (SQLAlchemy ORM, ~140 ms)
# on every ``alfred --help`` invocation that imported any sub-app.
#
# PEP 562's module-level ``__getattr__`` defers the import until the
# attribute is actually read. The test contract (``plugin.PLUGIN_GRANT_FIELDS
# is X``) keeps working because Python caches ``__getattr__`` resolutions
# the same way it caches regular module attributes — repeat reads return
# the same object. Any unknown attribute raises the standard
# ``AttributeError`` rather than silently importing something unintended.
_LAZY_AUDIT_SCHEMA_NAMES: Final[frozenset[str]] = frozenset(
    {"PLUGIN_GRANT_FIELDS", "PLUGIN_GRANT_REQUESTED_FIELDS"}
)


def __getattr__(name: str) -> object:
    """Lazy resolver for the audit-row-schema re-exports.

    Resolves :data:`PLUGIN_GRANT_FIELDS` and
    :data:`PLUGIN_GRANT_REQUESTED_FIELDS` from
    :mod:`alfred.audit.audit_row_schemas` on first access. Caches by
    setting the resolved value as a real module attribute so repeat
    reads do not re-trigger the import lookup.
    """
    if name in _LAZY_AUDIT_SCHEMA_NAMES:
        import alfred.audit.audit_row_schemas as schemas

        value = getattr(schemas, name)
        # Cache so subsequent attribute reads bypass __getattr__.
        globals()[name] = value
        return value
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


__all__ = ["PLUGIN_GRANT_FIELDS", "PLUGIN_GRANT_REQUESTED_FIELDS", "plugin_app"]
