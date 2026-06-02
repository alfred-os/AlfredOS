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

Audit-row emission. Stage 3 (arch-001 / cross-cutting R2) closes the
silent-skip gap: both ``add`` and ``remove`` emit a
``web.allowlist.requested`` row stand-in via
:data:`alfred.audit.audit_row_schemas.WEB_ALLOWLIST_REQUESTED_FIELDS`
BEFORE the state.git write. The ``action`` field distinguishes
``"add"`` from ``"remove"`` so the audit-graph correlator can join the
CLI emit with the eventual projection-merge row the supervisor emits
post-reviewer-approval. Cross-reference:
:data:`alfred.audit.audit_row_schemas.WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS`
— the manifest-side row family the projection eventually populates;
the requested-side row is the CLI-time twin.
"""

from __future__ import annotations

from typing import Annotated, Final

import typer

from alfred.cli._state_git import (
    StateGitProposalClient,
    queue_proposal_or_exit,
)
from alfred.cli._validators import validate_domain
from alfred.i18n import t
from alfred.state.proposal_payloads import WebAllowlistProposal

# Module-level seams. Tests patch these symbols.
_state_git_client: StateGitProposalClient = StateGitProposalClient()

# Proposal-type tags. ADR-0018 moved the canonical discriminator onto
# the typed :class:`WebAllowlistProposal` payload's ``action`` field
# (composed with ``proposal_type`` by :func:`_branch_type_tag_for`).
# These constants stay for the regression tests that pin the resolved
# branch name.
_PROPOSAL_TYPE_ADD: Final[str] = f"{WebAllowlistProposal.proposal_type}-add"
_PROPOSAL_TYPE_REMOVE: Final[str] = f"{WebAllowlistProposal.proposal_type}-remove"

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

    Stage 3 (arch-001): the audit-row stand-in fires via
    :data:`WEB_ALLOWLIST_REQUESTED_FIELDS` with ``action="add"``
    BEFORE the state.git write.

    perf-001: ``audit_row_schemas`` is imported lazily here — its
    parent ``alfred.audit`` package init eagerly loads
    :mod:`alfred.memory.models` (SQLAlchemy ORM, ~140 ms), and the
    constant is only needed when the operator actually queues an
    allowlist mutation. ``alfred web allowlist --help`` does not pay.
    """
    from alfred.audit.audit_row_schemas import WEB_ALLOWLIST_REQUESTED_FIELDS

    queue_proposal_or_exit(
        payload=WebAllowlistProposal(
            action="add",
            domain=domain,
            path_prefix=path_prefix,
        ),
        denied_key="cli.web.allowlist.add.denied",
        pending_review_key="cli.web.allowlist.add.pending_review",
        audit_event="web.allowlist.requested",
        audit_schema_name="WEB_ALLOWLIST_REQUESTED_FIELDS",
        audit_fields=WEB_ALLOWLIST_REQUESTED_FIELDS,
        audit_subject_partial={
            "action": "add",
            "domain": domain,
            "path_prefix": path_prefix,
            # devex-007: PR-S3-7 wires IdentityResolver.
            "operator_user_id": None,
        },
        client=_state_git_client,
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

    Stage 3 (arch-001): the audit-row stand-in fires via
    :data:`WEB_ALLOWLIST_REQUESTED_FIELDS` with ``action="remove"``
    BEFORE the state.git write. ``path_prefix`` is ``None`` on the
    remove path because the operator targets an entire allowlist entry,
    not a single path-prefix slice (the audit family carries the field
    anyway so the join condition with the add-side row stays uniform).

    perf-001: same lazy-import rationale as :func:`allowlist_add` — the
    constant only matters when an operator actually issues the mutation.
    """
    from alfred.audit.audit_row_schemas import WEB_ALLOWLIST_REQUESTED_FIELDS

    # CR-149: the remove proposal explicitly sets ``path_prefix=None``
    # so the on-disk payload, the audit row, and the eventual merge
    # consumer all agree on whole-entry deletion. The prior shape
    # left ``path_prefix`` at the model default (``"/"``) — the audit
    # row recorded ``None`` ("remove entry") but the proposal payload
    # the reviewer saw still said ``"/"`` ("remove root prefix only").
    # That mismatch could silently turn a whole-entry delete into a
    # root-prefix-only delete, defeating spec §11.1's reviewer-gated
    # intent. The model field is nullable for the remove path; the
    # add path still defaults to ``"/"``.
    queue_proposal_or_exit(
        payload=WebAllowlistProposal(
            action="remove",
            domain=domain,
            path_prefix=None,
        ),
        denied_key="cli.web.allowlist.remove.denied",
        pending_review_key="cli.web.allowlist.remove.pending_review",
        audit_event="web.allowlist.requested",
        audit_schema_name="WEB_ALLOWLIST_REQUESTED_FIELDS",
        audit_fields=WEB_ALLOWLIST_REQUESTED_FIELDS,
        audit_subject_partial={
            "action": "remove",
            "domain": domain,
            # Remove targets the entry as a whole; no per-prefix scope.
            "path_prefix": None,
            "operator_user_id": None,
        },
        client=_state_git_client,
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


def _register_proposal_keys_for_pybabel() -> tuple[str, ...]:
    """Surface the four proposal-flow i18n keys to pybabel's static extractor.

    Stage 3 (cross-cutting R5): :func:`queue_proposal_or_exit` consumes
    the ``denied_key`` + ``pending_review_key`` strings via parameter,
    so the pybabel AST walker would otherwise drop the four keys to
    the obsoleted block. Surfacing them here pins them as live entries.
    Same pattern as :func:`alfred.cli._state_git._register_hint_keys_for_pybabel`.

    CR-149 round-3: pass representative kwargs so the rendered bodies
    fully substitute every placeholder the msgstr carries (``{reason}``
    for ``.denied``; ``{branch}`` + ``{proposal_id}`` for
    ``.pending_review``). Without the kwargs the shim returned templates
    with the literal ``{...}`` markers, undercutting the callable-
    validation seam contract the adjacent
    :mod:`tests.unit.cli.test_i18n_key_coverage` tests enforce.
    """
    return (
        t("cli.web.allowlist.add.denied", reason="example"),
        t("cli.web.allowlist.add.pending_review", branch="example", proposal_id="0123456789abcdef"),
        t("cli.web.allowlist.remove.denied", reason="example"),
        t(
            "cli.web.allowlist.remove.pending_review",
            branch="example",
            proposal_id="0123456789abcdef",
        ),
    )


__all__ = ["allowlist_app", "web_app"]
