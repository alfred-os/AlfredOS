"""``alfred web allowlist`` CLI — manage the web-fetch domain allowlist.

``add`` + ``remove`` are reviewer-gated (spec §11.1) and write state.git
proposals via the module-level :class:`StateGitProposalClient`. ``list``
reads from the operator-config projection via the injectable
:func:`_list_allowlist_entries` seam; PR-S3-7 wires the real Postgres
projection query.

Hard rules honoured at this layer (CLAUDE.md):

* **Rule #1 — operator-facing strings via** :func:`t`. All ``help=`` /
  ``echo`` strings route through the catalog.
* **Rule #6 — payload structure, not raw secrets.** The proposal payload
  carries the domain + path_prefix (identifiers, not secret material).
* **Rule #7 — no silent failures in security paths.**
  :class:`StateGitError` from the client is converted into a localised
  stderr message and a non-zero exit code.

Module-level seams the tests patch:

* ``_state_git_client`` — production reviewer-gate writer.
* ``_list_allowlist_entries`` — Postgres projection stub for
  ``alfred web allowlist list``; PR-S3-7 swaps in the real query.

Why the CLI does not write a per-call audit row here. The state.git
proposal-branch commit itself is the durable forensic record for the
``add``/``remove`` paths; the Postgres ``web_allowlist`` projection
emits its own ``web.allowlist.changed`` row when the reviewer merges
the proposal and the supervisor rebuilds. Emitting a CLI-side row
would double-count the same event in the audit graph. Cross-reference:
:data:`alfred.audit.audit_row_schemas.WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS`
— the manifest-side row family the projection eventually populates.
"""

from __future__ import annotations

from typing import Annotated, Final

import typer

from alfred.cli._state_git import (
    StateGitError,
    StateGitProposalClient,
)
from alfred.cli._validators import validate_domain
from alfred.i18n import t

# Module-level seams. Tests patch these symbols.
_state_git_client: StateGitProposalClient = StateGitProposalClient()

# Proposal-type tags. Shared with the async writer (see
# alfred.security.capability_gate.proposals); any change here must land
# there simultaneously to keep the reviewer-side branch parser in sync.
_PROPOSAL_TYPE_ADD: Final[str] = "web-allowlist-add"
_PROPOSAL_TYPE_REMOVE: Final[str] = "web-allowlist-remove"

# Default path_prefix used when --path-prefix is omitted. Matches spec
# §7.4 normalisation: an unspecified prefix scopes the allowlist entry
# to every path under the domain.
_DEFAULT_PATH_PREFIX: Final[str] = "/"


def _list_allowlist_entries() -> list[dict[str, object]]:
    """Return current allowlist rows for ``alfred web allowlist list``.

    Returns an empty list until PR-S3-7 wires the Postgres
    ``web_allowlist`` projection. Tests patch this symbol to inject
    fake projection rows without touching Postgres.
    """
    return []


# ---------------------------------------------------------------------------
# Typer apps
# ---------------------------------------------------------------------------

web_app = typer.Typer(
    help=t("cli.web.help.group"),
    no_args_is_help=True,
)

allowlist_app = typer.Typer(
    help=t("cli.web.allowlist.help.group"),
    no_args_is_help=True,
)
web_app.add_typer(allowlist_app, name="allowlist")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


# Each pending-review surface inlines its own ``t()`` call at the use
# site so pybabel's static extractor can resolve the key literal.
# Indirect lookups via a variable (the natural DRY refactor) would
# show up as obsoleted entries in the catalog and silently degrade
# every render to the bare msgid — see PR-S3-6 batch-2 i18n catalog
# regen experience.


# ---------------------------------------------------------------------------
# allowlist add <domain> [--path-prefix /]
# ---------------------------------------------------------------------------


@allowlist_app.command("add", help=t("cli.web.allowlist.add.help.short"))
def allowlist_add(
    domain: Annotated[
        str,
        typer.Argument(
            help=t("cli.web.allowlist.add.arg.domain"),
            callback=validate_domain,
        ),
    ],
    path_prefix: Annotated[
        str,
        typer.Option(
            "--path-prefix",
            help=t("cli.web.allowlist.add.flag.path_prefix"),
        ),
    ] = _DEFAULT_PATH_PREFIX,
) -> None:
    """Queue a reviewer-gated proposal to add ``domain`` to the allowlist.

    sec-pr-s3-6-01: ``domain`` is parser-time-validated via
    :func:`alfred.cli._validators.validate_domain` — a URL paste,
    path-traversal attempt, or off-shape string raises
    :class:`typer.BadParameter` at parse time so it cannot reach the
    state.git proposal payload.

    Does NOT activate the entry. Spec §11.1: allowlist additions widen
    the trust surface and require reviewer approval + human merge.
    """
    try:
        result = _state_git_client.create_proposal(
            proposal_type=_PROPOSAL_TYPE_ADD,
            payload={
                "domain": domain,
                "path_prefix": path_prefix,
            },
        )
    except StateGitError as exc:
        typer.echo(
            t("cli.web.allowlist.add.denied", reason=str(exc)),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    typer.echo(
        t(
            "cli.web.allowlist.add.pending_review",
            branch=result.branch,
            proposal_id=result.proposal_id,
        )
    )


# ---------------------------------------------------------------------------
# allowlist remove <domain>
# ---------------------------------------------------------------------------


@allowlist_app.command("remove", help=t("cli.web.allowlist.remove.help.short"))
def allowlist_remove(
    domain: Annotated[
        str,
        typer.Argument(
            help=t("cli.web.allowlist.remove.arg.domain"),
            callback=validate_domain,
        ),
    ],
) -> None:
    """Queue a reviewer-gated proposal to remove ``domain`` from the allowlist.

    sec-pr-s3-6-01: same parser-time domain validation as ``add`` so an
    operator cannot queue a remove proposal against a malformed string
    that the projection would silently ignore.
    """
    try:
        result = _state_git_client.create_proposal(
            proposal_type=_PROPOSAL_TYPE_REMOVE,
            payload={"domain": domain},
        )
    except StateGitError as exc:
        typer.echo(
            t("cli.web.allowlist.remove.denied", reason=str(exc)),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    typer.echo(
        t(
            "cli.web.allowlist.remove.pending_review",
            branch=result.branch,
            proposal_id=result.proposal_id,
        )
    )


# ---------------------------------------------------------------------------
# allowlist list
# ---------------------------------------------------------------------------


@allowlist_app.command("list", help=t("cli.web.allowlist.list.help.short"))
def allowlist_list() -> None:
    """List the current web-fetch domain allowlist."""
    rows: list[dict[str, object]] = _list_allowlist_entries()
    if not rows:
        typer.echo(t("cli.web.allowlist.list.empty"))
        return
    header = "  ".join(
        [
            t("cli.web.allowlist.list.column.domain").ljust(40),
            t("cli.web.allowlist.list.column.path_prefix").ljust(20),
            t("cli.web.allowlist.list.column.granted_by").ljust(15),
            t("cli.web.allowlist.list.column.granted_at").ljust(20),
        ]
    )
    typer.echo(header)
    for row in rows:
        domain = str(row.get("domain", ""))
        path_prefix = str(row.get("path_prefix", "/"))
        granted_by = str(row.get("granted_by", ""))
        granted_at = str(row.get("granted_at", ""))
        typer.echo(f"{domain:<40}  {path_prefix:<20}  {granted_by:<15}  {granted_at:<20}")


__all__ = ["allowlist_app", "web_app"]
