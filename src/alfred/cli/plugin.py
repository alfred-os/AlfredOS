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

Audit-row emission for the grant/revoke paths is currently scoped to the
state.git write itself (every proposal commit is materially auditable in
state.git's reflog). The Postgres ``plugin_grants`` projection emits its
own ``plugin.grant.requested`` row when ``RealGate.rebuild_from_state_git``
ingests the merged branch; the per-CLI-call audit row is therefore
intentionally deferred to PR-S3-7 to avoid double-counting the same
event in the audit graph.
"""

from __future__ import annotations

from typing import Annotated, Final

import typer

from alfred.cli._state_git import (
    ProposalResult,
    StateGitError,
    StateGitProposalClient,
)
from alfred.i18n import t

# Module-level seams. Tests patch these symbols.
_state_git_client: StateGitProposalClient = StateGitProposalClient()

# Proposal-type tags used in the branch name. The schema is shared with
# ``alfred.security.capability_gate.proposals._write_proposal_to_state_git``
# (the async writer that consolidates with this one in PR-S3-7). Any change
# here MUST land there simultaneously — see _state_git.py module docstring.
_PROPOSAL_TYPE_GRANT: Final[str] = "policy-grant"
_PROPOSAL_TYPE_REVOKE: Final[str] = "policy-revoke"


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


def _render_grant_pending(result: ProposalResult) -> None:
    """Print the canonical pending-review block for a queued grant.

    Single helper so the grant + revoke surfaces stay byte-identical in
    formatting — a divergence here would surface as a UAT nit and force
    a fixup commit. The follow-up command is emitted as a separate line
    so an operator can copy-paste the ``alfred plugin grant status <id>``
    string without picking it out of a prose paragraph.
    """
    typer.echo(
        t(
            "cli.plugin.grant.pending_review",
            branch=result.branch,
            proposal_id=result.proposal_id,
        )
    )
    typer.echo(
        t(
            "cli.plugin.grant.follow_up_command",
            proposal_id=result.proposal_id,
        )
    )


def _queue_grant_proposal(
    *,
    plugin_id: str,
    subscriber_tier: str,
    hookpoint: str,
) -> None:
    """Write a ``policy-grant`` proposal and print the pending-review block.

    Hoisted out of the Typer command so the error-path and success-path
    are testable as a pure function. The ``except`` arm narrows on
    :class:`StateGitError` only — broader catches would swallow
    ``KeyboardInterrupt`` and violate CLAUDE.md hard rule #7.
    """
    try:
        result = _state_git_client.create_proposal(
            proposal_type=_PROPOSAL_TYPE_GRANT,
            payload={
                "plugin_id": plugin_id,
                "subscriber_tier": subscriber_tier,
                "hookpoint": hookpoint,
            },
        )
    except StateGitError as exc:
        typer.echo(
            t("cli.plugin.grant.denied", reason=str(exc)),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    _render_grant_pending(result)


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
    if first in _GRANT_RESERVED_SUBCOMMANDS:
        if first == "status":
            if len(extra) != 1:
                typer.echo(t("cli.plugin.grant.status.usage_error"), err=True)
                raise typer.Exit(code=2)
            _do_grant_status(extra[0])
            return
        # first == "list"
        pending = "--pending" in extra
        _do_grant_list(pending=pending)
        return
    if len(extra) != 2:
        typer.echo(t("cli.plugin.grant.usage_error"), err=True)
        raise typer.Exit(code=2)
    subscriber_tier, hookpoint = extra
    _queue_grant_proposal(
        plugin_id=first,
        subscriber_tier=subscriber_tier,
        hookpoint=hookpoint,
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
        typer.Argument(help=t("cli.plugin.revoke.arg.plugin_id")),
    ],
) -> None:
    """Queue a reviewer-gated revocation proposal for a plugin's grants."""
    try:
        result = _state_git_client.create_proposal(
            proposal_type=_PROPOSAL_TYPE_REVOKE,
            payload={"plugin_id": plugin_id},
        )
    except StateGitError as exc:
        typer.echo(
            t("cli.plugin.revoke.denied", reason=str(exc)),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    typer.echo(
        t(
            "cli.plugin.revoke.pending_review",
            branch=result.branch,
            proposal_id=result.proposal_id,
        )
    )


# ---------------------------------------------------------------------------
# list / show
# ---------------------------------------------------------------------------


@plugin_app.command("list", help=t("cli.plugin.list.help.short"))
def plugin_list() -> None:
    """List registered plugins (PR-S3-7 follow-up).

    devex-011 in plan §548: until the Postgres manifest projection is
    seeded, we MUST NOT emit silent-blank output — an operator could
    misread that as "no plugins loaded" rather than "this command is
    not implemented yet." Exit code 2 + a localised stderr message
    closes the failure mode.
    """
    typer.echo(t("cli.plugin.list.not_implemented_yet"), err=True)
    raise typer.Exit(code=2)


@plugin_app.command("show", help=t("cli.plugin.show.help.short"))
def plugin_show(
    plugin_id: Annotated[
        str,
        typer.Argument(help=t("cli.plugin.show.arg.plugin_id")),
    ],
) -> None:
    """Show manifest details for a registered plugin (PR-S3-7 follow-up).

    Until the Postgres manifest projection is wired, we echo the plugin
    id back + a localised "no manifest available yet" hint so the
    operator distinguishes "this is planned" from "no such plugin."
    """
    typer.echo(t("cli.plugin.show.plugin_id_label", plugin_id=plugin_id))
    typer.echo(t("cli.plugin.show.no_manifest_yet"))


__all__ = ["plugin_app"]
