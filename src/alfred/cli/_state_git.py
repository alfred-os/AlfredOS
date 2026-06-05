"""StateGitProposalClient — thin state.git proposal branch writer.

PR-S3-6 Component A (plan §93-289). The CLI surface
(``alfred plugin grant``, ``alfred web allowlist add``, ``alfred config
quarantined-provider``) writes reviewer-gated proposals into the bare
``/var/lib/alfred/state.git`` repo through this client. The client is
synchronous (CLI context) and shells subprocess calls to ``git`` so it
has zero dependency on any Slice-3 async subsystem.

devex-006 layering note. PR-S3-2 ships
:func:`alfred.security.capability_gate.proposals.create_proposal_branch`
— an async writer that targets the same state.git paths. This
sync client exists because the CLI is synchronous and cannot await the
async version without ``asyncio.run``. Consolidation into one canonical
writer (with the CLI using ``asyncio.run`` to bridge) is a PR-S3-7 task.
Until then, both writers exist and MUST produce identical branch-name
schemas — ``proposal/<type>-<16-hex-id>`` — so the reviewer flow does
not race a mismatch between the two writers. Any format change here
must land in :func:`_write_proposal_to_state_git` simultaneously.

CLAUDE.md hard rule #6 (secrets in the broker, not in payload): proposal
payloads MUST be structured dicts of identifiers and policy knobs only.
Callers MUST NOT embed raw secret values in the payload; the broker
substitution happens at runtime, not at proposal time. This module does
not enforce the rule mechanically (no good shape to do so without
domain knowledge of every payload), so every caller's unit test pins
the absence of secret-shaped strings.

CLAUDE.md hard rule #7 (no silent failures in security paths): every git
subprocess failure surfaces as :class:`StateGitError` (rooted at
:class:`AlfredError`). The CLI ``except`` arm narrows on this to render
a localised operator-facing error; raising bare :class:`subprocess.CalledProcessError`
would leak git's English stderr into operator UX and bypass the t()
localisation layer.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

import structlog

from alfred.errors import AlfredError
from alfred.state.proposal_payloads import (
    BreakerResetProposal,
    ConfigSetProposal,
    PluginGrantProposal,
    PluginRevokeProposal,
    StateGitProposalPayload,
    WebAllowlistProposal,
)


class StateGitErrorKind(StrEnum):
    """Tag distinguishing the three real state.git failure modes.

    devex-004: previously every git subprocess failure surfaced as a
    single ``StateGitError`` whose ``str(exc)`` carried the raw argv +
    stderr. The CLI top-level handler echoed that string to the
    operator, leaking ``-C /var/lib/alfred/state.git push origin
    proposal/...`` -- noise that taught the operator nothing
    actionable. Tagging the error mode lets the CLI map each kind to a
    localised hint pointing at the operator's actual recovery lever
    (start the stack, install git, fix the gate config, ...).

    Three modes the wrapper actually distinguishes:

    * :attr:`PATH_MISSING` -- ``/var/lib/alfred/state.git`` does not
      exist on disk. The operator hasn't run ``alfred-setup`` yet.
    * :attr:`GIT_MISSING` -- the ``git`` binary is not on PATH. Almost
      always means the container image is wrong or the operator is
      running outside the supported environment.
    * :attr:`PUSH_REJECTED` -- everything else (push refused,
      permission denied, branch already exists, ...). The structured
      log carries the real stderr for the operator's structlog stream;
      the CLI surface stays generic so we do not leak argv.
    """

    PATH_MISSING = "path_missing"
    GIT_MISSING = "git_missing"
    PUSH_REJECTED = "push_rejected"


# Branch-name schema. ADR-0018 consolidates the two writers around this
# constant; the async-shim entry point (``proposals.create_proposal_branch``)
# now bridges through :meth:`StateGitProposalClient.create_proposal_from_payload`
# rather than duplicating the prefix.
_BRANCH_PREFIX: Final[str] = "proposal/"
_PROPOSAL_FILENAME: Final[str] = "proposal.json"

# ADR-0018 Decision 3: plugin-grant proposals land at this directory so
# :func:`alfred.security.capability_gate._state_git_parser.parse_state_git_head`
# re-hydrates them on the post-merge rebuild. Centralised so the writer
# and the parser share a single literal — a drift would silently break
# the round-trip.
_GRANTS_TREE_PATH: Final[str] = "policies/grants"

# ADR-0021: side-effecting BreakerResetProposal blobs land here so the
# dispatch loop's HEAD-diff walker keys the discriminator off the path
# prefix. Centralised so the writer and the dispatcher's path-derivation
# helpers share a single literal — drift would silently misroute or
# skip side-effecting proposals.
_BREAKER_RESETS_TREE_PATH: Final[str] = "policies/breaker-resets"

# ``token_hex(8)`` yields 16 hex characters — collision in a single
# state.git lifetime is statistically zero. Matches the proposal-flow
# writer's id width so the audit-graph correlator can join across both
# writers without a width-mismatch wart.
_PROPOSAL_ID_BYTES: Final[int] = 8

# CR-149 round-3: caller-supplied proposal IDs are embedded verbatim
# into the branch name (``proposal/<type>-<proposal_id>``) AND the
# on-disk grant path (``policies/grants/<plugin_id>/<proposal_id>.json``).
# A non-canonical value with ``/``, ``..``, or wrong width can create
# invalid refs or escape the canonical grants-tree layout — exactly
# the parse-time refusal surface ADR-0018's round-trip contract
# depends on. The pattern below pins the closed shape
# :func:`secrets.token_hex` produces (16 lowercase hex chars) so any
# non-conforming caller fails loud at the public API boundary.
_PROPOSAL_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{16}$")

# CR-149 round-6: caller-supplied ``proposal_type`` strings are
# embedded into both the branch name (``proposal/<type>-<id>``) and
# the commit message. Inputs containing ``/``, ``..``, whitespace, or
# mixed casing drift from PRD §8.3's branch-name contract and only
# fail deep inside git. The typed entry point
# (:meth:`create_proposal_from_payload`) already pins the type via
# :func:`_branch_type_tag_for`; this regex closes the legacy
# :meth:`create_proposal` surface so both writers fail at the same
# boundary. Canonical shape: lowercase ASCII letters / digits in
# dash-separated tokens (e.g. ``"policy-grant"``, ``"web-allowlist-add"``,
# ``"config-quarantined-provider"``).
_PROPOSAL_TYPE_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _validated_proposal_id(proposal_id: str) -> str:
    """Refuse caller-supplied proposal ids outside the 16-hex-char shape.

    Spec §8.3 / ADR-0018: every proposal id embedded in a state.git
    branch + grants-tree path is unpredictable + width-stable. The
    :func:`secrets.token_hex(_PROPOSAL_ID_BYTES)` generator is the
    canonical source on the no-id path; this validator is the matching
    parse-time refusal for caller-supplied ids so the boundary fails
    closed regardless of which entry point produced the value (PRD
    §11.3 reviewer-gated boundary discipline).

    Critical refusals:

    * ``/``, ``..`` — would escape the canonical grants-tree layout or
      compose an invalid ref.
    * Uppercase / non-hex — collides with the writer's normalised form
      and would silently route the audit-graph correlator to a
      different bucket on the join key.
    * Wrong length — desynchronises the joinable id space between the
      two writers (the proposal-flow async writer + this sync CLI
      writer both share the same 16-hex contract).

    Returns ``proposal_id`` unchanged on success so callers chain the
    validated value into the branch / path composition without a
    second rebind.
    """
    if not _PROPOSAL_ID_RE.fullmatch(proposal_id):
        msg = "proposal_id must be 16 lowercase hex characters"
        raise ValueError(msg)
    return proposal_id


def _validated_proposal_type(proposal_type: str) -> str:
    """Refuse caller-supplied proposal types outside the dash-canonical shape.

    CR-149 round-6: the legacy :meth:`StateGitProposalClient.create_proposal`
    entry point splices ``proposal_type`` straight into the branch
    name and commit message. Inputs containing ``/``, ``..``,
    whitespace, or mixed casing drift from PRD §8.3's branch-name
    contract and only surface deep inside git's ref parser — exactly
    the silent-skip shape CLAUDE.md hard rule #7 forbids.

    The typed entry point (:meth:`create_proposal_from_payload`)
    closes this boundary via :func:`_branch_type_tag_for` (the
    ``proposal_type`` ClassVar is hard-coded on the Pydantic model);
    this validator gives the legacy public API the same parse-time
    refusal so both writers fail at the same shape.

    Returns ``proposal_type`` unchanged on success so callers chain
    the validated value into branch composition without a second
    rebind.
    """
    if not _PROPOSAL_TYPE_RE.fullmatch(proposal_type):
        msg = (
            "proposal_type must be lowercase dash-separated tokens "
            "(e.g. 'policy-grant', 'web-allowlist-add')"
        )
        raise ValueError(msg)
    return proposal_type


# CR-149 round-7: composite-type dispatch table for the legacy
# ``(proposal_type, dict)`` entry point. ADR-0018 consolidated every
# state.git payload onto a typed Pydantic model; the legacy shape
# survived as a thin compat shim so existing test fixtures don't churn,
# but the shim MUST drive every dict through Pydantic validation BEFORE
# the writer touches state.git. Otherwise a typo at the dispatcher
# (``subscribe_tier`` vs ``subscriber_tier``) lands in the proposal
# branch as-is and either silently drops in the projection downstream
# or breaks the audit-graph join — exactly the silent-drift CLAUDE.md
# hard rule #7 + ADR-0018 close.
#
# Two of the four payload types have composite branch tags
# (``web-allowlist-{action}``, ``config-{config_key}``) and need a
# small parse step BEFORE construction so the dict can drop the
# ``action``/``config_key`` field the caller embedded in the branch
# tag. The dispatcher below handles the parse so callers can keep the
# canonical "branch tag is the type" mental model.
def _legacy_payload_from_dict(
    proposal_type: str,
    payload: dict[str, object],
) -> StateGitProposalPayload | None:
    """Map a legacy ``(proposal_type, dict)`` shape to a typed payload.

    CR-149 round-7: the canonical entry point is
    :meth:`StateGitProposalClient.create_proposal_from_payload` which
    takes a typed :class:`StateGitProposalPayload` and runs Pydantic
    validation at construction. The legacy
    :meth:`StateGitProposalClient.create_proposal` accepted a raw dict
    that bypassed every Pydantic invariant — leaving a typo at the
    dispatcher (``subscribe_tier`` vs ``subscriber_tier``) to land in
    the proposal branch verbatim and silently drop downstream.

    This helper closes that boundary: every canonical ``proposal_type``
    has a typed-model class, and the helper constructs the matching
    instance from ``payload``. Pydantic's ``extra='forbid'`` +
    closed-set ``Literal`` validators raise
    :class:`pydantic.ValidationError` at construction so the typo fails
    BEFORE state.git sees it.

    Composite type tags (``web-allowlist-add``, ``web-allowlist-remove``,
    ``config-<key>``) parse here too: the dispatcher routes
    ``web-allowlist-{action}`` to :class:`WebAllowlistProposal` with the
    matching ``action`` field, and ``config-{config_key}`` to
    :class:`ConfigSetProposal` with the matching ``config_key`` field.
    This keeps the legacy caller's "branch tag IS the type" surface
    intact.

    Returns ``None`` for ``proposal_type`` values that have no typed
    model yet (test corpus only — production callers always use a
    canonical type). The :meth:`create_proposal` shim then falls back
    to the raw-dict write path for those values, emitting a structured
    warning so the gap is visible in the log stream. A future ADR that
    adds a typed model for the new ``proposal_type`` lands here in one
    edit.

    Args:
        proposal_type: dash-canonical type tag (already validated by
            :func:`_validated_proposal_type`).
        payload: the legacy dict payload — passed straight to the
            Pydantic model constructor; field names + values are
            validated by the model.

    Returns:
        Typed :class:`StateGitProposalPayload` instance on a known
        type tag, or ``None`` when no typed model exists. The
        ``None`` branch is the test-corpus seam; production callers
        always hit a known tag.

    Raises:
        pydantic.ValidationError: if ``payload`` does not satisfy
            the typed model's field requirements. This is the
            load-bearing failure mode the shim exists to surface.
    """
    if proposal_type == PluginGrantProposal.proposal_type:
        return PluginGrantProposal(**payload)  # type: ignore[arg-type]
    if proposal_type == PluginRevokeProposal.proposal_type:
        return PluginRevokeProposal(**payload)  # type: ignore[arg-type]
    if proposal_type == BreakerResetProposal.proposal_type:
        # ADR-0021: the side-effecting breaker-reset payload is part of
        # the canonical typed surface. Without this arm the legacy
        # dict-form ``create_proposal("breaker-reset", {...})`` shape
        # falls through to the unknown-type fallback that writes the
        # blob to ``/proposal.json`` instead of the
        # ``policies/breaker-resets/<id>.json`` path the dispatch loop's
        # HEAD-diff walker watches. The blob would land in state.git
        # but the dispatcher would never pick it up — a silent drop.
        return BreakerResetProposal(**payload)  # type: ignore[arg-type]
    if proposal_type.startswith(f"{WebAllowlistProposal.proposal_type}-"):
        # ``web-allowlist-{action}`` — parse the action off the tag so
        # the typed payload carries the closed-set Literal value.
        #
        # CR-149 round-10 (3339361774): canonical legacy shapes
        # (``{"action": "add", ...}``) carry ``action`` in BOTH the
        # type-tag and the payload dict. Splatting the payload as-is
        # would raise ``TypeError: got multiple values for keyword
        # argument 'action'`` before Pydantic ever validates the
        # value. Strip the composite discriminator from the payload
        # copy so the parsed value from the tag wins and the legacy
        # round-trip remains lossless.
        action = proposal_type[len(WebAllowlistProposal.proposal_type) + 1 :]
        payload_without_action = {k: v for k, v in payload.items() if k != "action"}
        return WebAllowlistProposal(action=action, **payload_without_action)  # type: ignore[arg-type]
    if proposal_type.startswith(f"{ConfigSetProposal.proposal_type}-"):
        # ``config-{config_key}`` — parse the config_key off the tag
        # so the typed payload carries the closed-set Literal value.
        # See the WebAllowlistProposal branch above for the
        # discriminator-dedup rationale (CR-149 round-10).
        config_key = proposal_type[len(ConfigSetProposal.proposal_type) + 1 :]
        payload_without_config_key = {k: v for k, v in payload.items() if k != "config_key"}
        return ConfigSetProposal(
            config_key=config_key,  # type: ignore[arg-type]
            **payload_without_config_key,  # type: ignore[arg-type]
        )
    # Unknown type tag — no typed model yet. Test corpus seam only;
    # production callers always pass a canonical tag.
    return None


class StateGitError(AlfredError):
    """Raised when a state.git operation fails.

    Subclasses :class:`AlfredError` so the CLI top-level dispatch can
    narrow on the AlfredOS error hierarchy without swallowing unrelated
    exceptions (e.g. :class:`KeyboardInterrupt`).

    Carries a :class:`StateGitErrorKind` tag (devex-004) so the CLI
    handler can map to a localised hint matching the recovery lever,
    rather than echoing the raw git argv. ``kind`` defaults to
    :attr:`StateGitErrorKind.PUSH_REJECTED` so existing callers that
    raise ``StateGitError("...")`` without classification keep working
    -- the test corpus exercises that legacy shape too.
    """

    def __init__(
        self,
        message: str,
        *,
        kind: StateGitErrorKind = StateGitErrorKind.PUSH_REJECTED,
    ) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class ProposalResult:
    """Outcome of a :meth:`StateGitProposalClient.create_proposal` call.

    Returned to the CLI layer so the operator-facing output can render
    both the branch name (for ``alfred plugin grant status`` follow-up)
    and the raw proposal id (for audit-graph correlation queries).
    Frozen + slots — the CLI must not mutate the result before
    rendering it.
    """

    proposal_id: str
    branch: str


@dataclass(frozen=True, slots=True)
class ProposalRef:
    """A single pending-proposal reference returned by :meth:`list_pending_proposals`.

    The reference carries only the branch name; the CLI looks up the
    diff via :meth:`StateGitProposalClient.get_proposal_diff` when the
    operator drills into a specific proposal. Keeping the ref payload
    small avoids re-reading every proposal blob on the index call.
    """

    branch: str


class StateGitProposalClient:
    """Thin wrapper around ``git`` for state.git proposal-branch creation.

    Each :meth:`create_proposal` call:

    1. Generates an unpredictable proposal id via :func:`secrets.token_hex`.
       Spec §8.3 implicitly requires unpredictability so an adversary who
       reads one branch name from the audit log cannot enumerate future
       proposal ids.
    2. Clones the bare repo into a temp directory, checks out a new
       branch, writes ``proposal.json`` with the payload, commits, and
       pushes the branch back to ``origin``.
    3. Returns a :class:`ProposalResult` with the canonical branch name
       and the raw proposal id.

    The temp clone is scoped to a :class:`tempfile.TemporaryDirectory`
    so it disappears after the call returns — there is no persistent
    working directory the CLI must clean up.
    """

    def __init__(
        self,
        *,
        state_git_path: Path = Path("/var/lib/alfred/state.git"),
    ) -> None:
        """Bind to a bare state.git repo.

        Defaults to ``/var/lib/alfred/state.git`` per the Slice-3 operator
        runbook (spec §15.4). Tests override with a per-test
        :class:`tempfile.TemporaryDirectory`-backed bare repo so the suite
        stays driver-free and does not require real host state.
        """
        self._repo = state_git_path

    def create_proposal_from_payload(
        self,
        payload: StateGitProposalPayload,
        *,
        proposal_id: str | None = None,
    ) -> ProposalResult:
        """Create a proposal branch from a typed :class:`StateGitProposalPayload`.

        ADR-0018 typed entry point. The legacy
        :meth:`create_proposal` ``(proposal_type, dict)`` shape stays
        as a thin compatibility wrapper that constructs the matching
        model — every new caller MUST use this method so the
        Pydantic validator runs against the payload BEFORE state.git
        sees it.

        The method dispatches on the concrete payload type to derive
        both the branch-name suffix (e.g. ``"web-allowlist-add"``
        composed from ``proposal_type`` + ``action``) and the on-disk
        layout:

        * :class:`PluginGrantProposal` lands at
          ``policies/grants/<plugin_id>/<grant_id>.json`` so the
          :func:`alfred.security.capability_gate._state_git_parser.parse_state_git_head`
          round-trips it directly.
        * Every other type writes a single ``proposal.json`` at the
          repo root — their merged-tree projections live in different
          tables (web allowlist → ``web_allowlist`` row;
          config-set → operator-config projection).

        Args:
            payload: a frozen :class:`StateGitProposalPayload`
                subclass instance. Construct via the model's
                ``__init__`` so Pydantic validation runs against the
                fields BEFORE this method is called.
            proposal_id: optional pre-generated 16-hex-char identifier
                (same semantics as :meth:`create_proposal`).

        Returns:
            :class:`ProposalResult` with the canonical branch name and
            raw proposal id.

        Raises:
            StateGitError: if any git subprocess fails.
        """
        if proposal_id is None:
            proposal_id = secrets.token_hex(_PROPOSAL_ID_BYTES)
        else:
            # CR-149 round-3: caller-supplied ids reach the branch
            # name AND the on-disk grants-tree path verbatim. Refuse
            # anything outside the 16-hex-char shape here so a typo /
            # malicious value cannot escape the canonical layout.
            proposal_id = _validated_proposal_id(proposal_id)
        type_tag = _branch_type_tag_for(payload)
        branch = f"{_BRANCH_PREFIX}{type_tag}-{proposal_id}"
        return self._write_branch(
            branch=branch,
            type_tag=type_tag,
            proposal_id=proposal_id,
            files=_on_disk_files_for(payload, proposal_id=proposal_id),
        )

    def create_proposal(
        self,
        proposal_type: str,
        payload: dict[str, object],
        *,
        proposal_id: str | None = None,
    ) -> ProposalResult:
        """Create a proposal branch with the payload committed as ``proposal.json``.

        The branch name is ``proposal/<proposal_type>-<16-char-hex-id>``.
        The payload is serialised as JSON with ``indent=2`` and
        ``sort_keys=True`` so the reviewer sees a stable, diff-friendly
        representation across reruns.

        Args:
            proposal_type: short tag identifying the proposal family
                (e.g. ``"policy-grant"``, ``"web-allowlist-add"``). The
                tag becomes part of the branch name and the commit
                message — keep it dash-separated and lowercase.
            payload: structured dict the reviewer reads to make the
                approve/reject decision. MUST NOT contain raw secret
                values — see module docstring.
            proposal_id: optional pre-generated 16-hex-char identifier.
                Stage 3 (arch-001 / cross-cutting R2): the
                :func:`queue_proposal_or_exit` helper pre-generates the
                id so it can emit the ``*.requested`` audit row stand-in
                with the resolved branch name BEFORE this method writes
                to state.git. The audit row would otherwise either fire
                without the branch (broken correlation) or fire after a
                successful write (no row on crash). Callers that do not
                emit a per-proposal audit row pass ``None`` and the
                method generates the id internally as before.

        Returns:
            :class:`ProposalResult` with ``proposal_id`` (raw hex) and
            ``branch`` (full ``proposal/...`` name).

        Raises:
            StateGitError: if any git subprocess fails (missing repo,
                permission error, push rejected, …). The CLI narrows on
                this to render a localised operator-facing error.
        """
        # CR-149 round-6: refuse non-canonical ``proposal_type`` strings
        # BEFORE the id is generated. The legacy entry point splices
        # the type into both the branch name and the commit message;
        # an input with ``/``, ``..``, whitespace, or mixed casing
        # drifts from PRD §8.3 and would only surface as a deep
        # git-ref error. The typed entry point closes this shape via
        # the Pydantic ``proposal_type`` ClassVar; the legacy public
        # API needs the same parse-time refusal.
        proposal_type = _validated_proposal_type(proposal_type)

        # CR-149 round-7: compat-shim discipline. ADR-0018 consolidated
        # every state.git payload onto a typed Pydantic model; this
        # legacy entry point now constructs the typed payload from the
        # dict (where a canonical model exists) and delegates to
        # :meth:`create_proposal_from_payload`. That routes the legacy
        # surface through the same Pydantic validation as new callers
        # so a typo at the dispatcher (``subscribe_tier`` vs
        # ``subscriber_tier``) fails with
        # :class:`pydantic.ValidationError` at the shim BEFORE state.git
        # is touched, instead of landing in proposal.json verbatim and
        # silently dropping in the projection downstream. CR-149 round-7
        # explicitly identified the raw-dict path as the ADR-0018 schema
        # drift this consolidation exists to close.
        typed = _legacy_payload_from_dict(proposal_type, payload)
        if typed is not None:
            return self.create_proposal_from_payload(
                typed,
                proposal_id=proposal_id,
            )

        # No typed model maps to this ``proposal_type`` — the legacy
        # raw-dict path stays as a narrow test-corpus seam so a future
        # not-yet-typed proposal type stays writeable while the
        # canonical path (every production caller) routes through
        # Pydantic. The structured warning surfaces the gap in the log
        # stream so on-call sees the unvalidated write.
        _log.warning(
            "state_git.legacy_unvalidated_proposal",
            proposal_type=proposal_type,
            payload_keys=sorted(payload.keys()),
        )

        # ``secrets.token_hex`` is cryptographically unpredictable per
        # the :mod:`secrets` contract — spec §8.3 requires the branch
        # namespace stay opaque so an adversary reading the audit log
        # cannot enumerate future proposal ids. Caller-supplied ids must
        # honour the same width so the audit-graph correlator joins
        # without width-mismatch warts.
        if proposal_id is None:
            proposal_id = secrets.token_hex(_PROPOSAL_ID_BYTES)
        else:
            # CR-149 round-3: same caller-supplied-id refusal as in
            # :meth:`create_proposal_from_payload`. The legacy entry
            # point is still on the public surface so the boundary
            # must close here too.
            proposal_id = _validated_proposal_id(proposal_id)
        branch = f"{_BRANCH_PREFIX}{proposal_type}-{proposal_id}"
        payload_json = json.dumps(payload, indent=2, sort_keys=True)

        # Legacy fallback: writes a single ``proposal.json`` at the
        # repo root. Production callers never reach this branch — the
        # ``_legacy_payload_from_dict`` dispatcher above covers every
        # canonical type.
        return self._write_branch(
            branch=branch,
            type_tag=proposal_type,
            proposal_id=proposal_id,
            files={_PROPOSAL_FILENAME: payload_json},
        )

    def _write_branch(
        self,
        *,
        branch: str,
        type_tag: str,
        proposal_id: str,
        files: dict[str, str],
    ) -> ProposalResult:
        """Materialize ``files`` on ``branch`` and push to ``origin``.

        Internal helper shared between :meth:`create_proposal` (legacy
        dict shape) and :meth:`create_proposal_from_payload` (typed
        ADR-0018 shape). Keeps the git-subprocess sequence identical
        across both entry points so the audit-trail tests that pin
        the subprocess shape do not branch on which entry point was
        used.

        Args:
            branch: full ``proposal/...`` branch name.
            type_tag: the type tag embedded in the commit message
                (e.g. ``"policy-grant"`` or ``"web-allowlist-add"``).
                Distinct from ``branch`` so the commit message can be
                shorter than the branch name without re-deriving it.
            proposal_id: raw 16-hex-char id (echoed back in the result).
            files: dict mapping repo-relative path → file contents.
                Parents are created as needed (so
                ``policies/grants/<plugin_id>/<grant_id>.json`` lands at
                the right depth without each caller mkdir-ing).
        """
        with tempfile.TemporaryDirectory() as work_dir:
            work = Path(work_dir)
            self._run(["git", "clone", str(self._repo), str(work)])
            self._run(["git", "-C", str(work), "checkout", "-b", branch])
            for rel_path, contents in files.items():
                dest = work / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(contents)
                self._run(["git", "-C", str(work), "add", rel_path])
            # ``-c`` flags scope identity to this commit so the wrapper
            # never depends on the developer's global git config (which
            # may carry signing keys or commit hooks that block in CI).
            self._run(
                [
                    "git",
                    "-c",
                    "user.name=alfred-cli",
                    "-c",
                    "user.email=alfred-cli@localhost",
                    "-C",
                    str(work),
                    "commit",
                    "-m",
                    f"proposal({type_tag}): {proposal_id}",
                ]
            )
            self._run(["git", "-C", str(work), "push", "origin", branch])

        return ProposalResult(proposal_id=proposal_id, branch=branch)

    def list_pending_proposals(self) -> list[ProposalRef]:
        """Return every ``proposal/...`` branch present in the bare repo.

        Used by ``alfred plugin grant list --pending``. Non-proposal
        branches (e.g. ``main``) are filtered out at the source so the
        CLI sees only proposal refs.

        Returns:
            A list of :class:`ProposalRef`, one per proposal branch.
            Empty list when only ``main`` exists.

        Raises:
            StateGitError: if the git query fails (missing repo, …).
        """
        out = self._run(
            [
                "git",
                "--git-dir",
                str(self._repo),
                "for-each-ref",
                "--format=%(refname:short)",
                f"refs/heads/{_BRANCH_PREFIX}",
            ]
        )
        refs: list[ProposalRef] = []
        for line in out.splitlines():
            name = line.strip()
            if name.startswith(_BRANCH_PREFIX):
                refs.append(ProposalRef(branch=name))
        return refs

    def get_proposal_diff(self, branch: str) -> str:
        """Return the diff of ``branch`` against ``main`` for reviewer display.

        Args:
            branch: full proposal branch name (``proposal/...``).

        Returns:
            The text of ``git diff main..<branch>`` — typically the
            single-file addition of ``proposal.json``.

        Raises:
            StateGitError: if the branch is unknown or the diff fails.
        """
        return self._run(["git", "--git-dir", str(self._repo), "diff", f"main..{branch}"])

    def _run(self, cmd: list[str]) -> str:
        """Run a git subprocess; raise :class:`StateGitError` on failure.

        Centralises the failure-shape conversion so every callsite raises
        the same typed error tagged with a :class:`StateGitErrorKind`
        (devex-004). ``capture_output=True`` keeps stderr off the
        operator's terminal until the CLI explicitly chooses to surface
        it (post-redaction).

        Failure-mode classification:

        * :class:`FileNotFoundError` -- distinguishes "git missing"
          from "state.git repo missing" by checking whether the bound
          repo path actually exists. Both surface as the typed error
          with the matching :class:`StateGitErrorKind`.
        * Non-zero return code -- catch-all
          :attr:`StateGitErrorKind.PUSH_REJECTED`. The structlog stream
          carries the real stderr for the operator's forensic record;
          the exception message intentionally does NOT embed the argv
          (devex-004: leaking ``git push origin proposal/...`` taught
          the operator nothing).
        """
        # CR-149 round-2: the bound repo path check runs BEFORE
        # ``subprocess.run`` so the common "operator hasn't bootstrapped
        # state.git yet" case maps to :attr:`StateGitErrorKind.PATH_MISSING`
        # regardless of how the argv shape encodes the path
        # (``git clone <missing>``/``git --git-dir=<missing>`` both return
        # a non-zero exit without raising ``FileNotFoundError`` from
        # ``subprocess``, so relying on exception alone falls through to
        # :attr:`PUSH_REJECTED` with the wrong recovery hint — CLAUDE.md
        # hard rule #7, PRD §4.1).
        #
        # Use ``stat`` not ``exists``: ``Path.exists`` returns False for
        # genuinely-missing AND for present-but-permission-denied paths,
        # which would surface the "run alfred-setup" hint to an operator
        # whose real problem is access. Catch ONLY ``FileNotFoundError``;
        # let ``PermissionError`` and other ``OSError`` subclasses
        # propagate so the existing arm below maps them to
        # :attr:`PUSH_REJECTED` (the operator's actionable signal there
        # is "check audit log + filesystem ACLs", not bootstrap).
        try:
            self._repo.stat()
        except FileNotFoundError as exc:
            msg = "state.git repo missing"
            raise StateGitError(msg, kind=StateGitErrorKind.PATH_MISSING) from exc
        except OSError as exc:
            # PermissionError and other access-denied shapes — the
            # operator's actionable signal here is "check audit log +
            # filesystem ACLs", not "bootstrap state.git". Map to
            # PUSH_REJECTED matching the catch-all downstream. Keeping
            # this branch ABOVE the subprocess.run preserves the
            # "no subprocess fork on a doomed pre-check" property.
            msg = "state.git pre-check failed"
            raise StateGitError(msg, kind=StateGitErrorKind.PUSH_REJECTED) from exc
        try:
            # S603/S607: ``cmd[0]`` is always the literal ``"git"`` constructed
            # from this module's hard-coded argv lists; the only operator-
            # influenced arguments are branch names + payload JSON, which git
            # handles as data via ``-C``/``--git-dir`` and the commit body.
            # No shell interpolation, no user-provided executable.
            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            # ``FileNotFoundError`` after the repo-exists pre-check above
            # narrows to "``git`` binary missing on PATH" — the operator's
            # next action is install/restore git, not bootstrap state.git.
            msg = "git binary missing"
            raise StateGitError(msg, kind=StateGitErrorKind.GIT_MISSING) from exc
        except OSError as exc:
            # Other OS-level errors (permission denied, exec format
            # error, ...) surface as PUSH_REJECTED -- the operator's
            # next action is the same generic "check audit log" path.
            msg = "state.git subprocess failed"
            raise StateGitError(msg, kind=StateGitErrorKind.PUSH_REJECTED) from exc
        if result.returncode != 0:
            # The real stderr never enters the exception ``str`` -- it
            # lands only in the structured-log stream the bootstrap's
            # redactor processes. The exception carries the tag the CLI
            # uses to pick a localised hint.
            #
            # CR-149 round-6: previously the stderr only landed as an
            # exception note (``err.add_note``).
            # :func:`queue_proposal_or_exit` catches :class:`StateGitError`
            # and never surfaces those notes, so clone / push / diff
            # failures lost their only detailed diagnostic. Emit a
            # structured log entry BEFORE raising so on-call sees the
            # sanitised stderr in the structlog stream (the
            # bootstrap's redactor handles secret-shape masking;
            # ``strip()`` collapses trailing newlines so the log entry
            # is single-line searchable).
            sanitised_stderr = result.stderr.strip()
            _log.warning(
                "state_git.push_rejected",
                argv=cmd,
                returncode=result.returncode,
                sanitised_stderr=sanitised_stderr,
            )
            msg = "state.git push rejected"
            err = StateGitError(msg, kind=StateGitErrorKind.PUSH_REJECTED)
            err.add_note(f"git stderr: {sanitised_stderr}")
            raise err
        return result.stdout


def _hint_key_for(kind: StateGitErrorKind) -> str:
    """Return the localised hint key matching a :class:`StateGitErrorKind`.

    Centralised so every CLI helper that consumes :class:`StateGitError`
    routes through the same kind -> key mapping. Adding a new
    :class:`StateGitErrorKind` value requires adding the matching
    catalog entry + a row here in the same PR.

    The string literals below are referenced verbatim by
    :func:`_register_hint_keys_for_pybabel` so the pybabel static
    extractor picks them up despite the indirection through this
    mapping. Without that registration block the catalog would silently
    miss the keys and ``t(hint_key)`` would render the bare msgid.
    """
    return {
        StateGitErrorKind.PATH_MISSING: "cli.state_git.error.path_missing",
        StateGitErrorKind.GIT_MISSING: "cli.state_git.error.git_missing",
        StateGitErrorKind.PUSH_REJECTED: "cli.state_git.error.push_rejected",
    }[kind]


def _render_hint(kind: StateGitErrorKind, *, state_git_path: Path) -> str:
    """Render the localised hint for ``kind``, threading the configured path.

    CR-149 round-3: the ``PATH_MISSING`` hint previously hard-coded
    ``/var/lib/alfred/state.git`` in the msgstr. The bootstrap now
    threads ``state_git_path`` through the gate / client constructors
    so the operator can deploy at a non-default path (e.g. a per-host
    bind volume). The catalog msgstr now carries a ``{state_git_path}``
    placeholder; this renderer substitutes the actual configured path
    so a misconfigured deployment surfaces the right remediation target.

    Only ``PATH_MISSING`` references the path today — ``GIT_MISSING``
    points at PATH and ``PUSH_REJECTED`` points at the audit log, both
    of which are path-agnostic. Passing ``state_git_path`` as a kwarg
    on the other branches is harmless (``t()`` ignores unused kwargs)
    so we keep the call shape uniform for future hints.
    """
    # perf-001 / lazy-import discipline: same pattern as the pybabel
    # anchor shim below — :mod:`alfred.i18n` pulls in the catalog
    # loader which has its own startup cost. Defer the import so the
    # ``alfred --help`` surface (which never touches this branch)
    # stays light.
    from alfred.i18n import t

    return t(_hint_key_for(kind), state_git_path=str(state_git_path))


def _register_hint_keys_for_pybabel() -> tuple[str, ...]:
    """Surface the three hint keys to pybabel's static extractor.

    pybabel walks the AST looking for :func:`t` calls with literal
    string arguments; the indirection in :func:`_hint_key_for` would
    otherwise hide these keys and the catalog would silently miss
    them. The function is never called at runtime -- the return value
    only documents the canonical key list for grep.

    CR-149 round-3: pass a representative ``state_git_path`` kwarg so
    the ``path_missing`` body fully renders rather than leaking the
    literal ``{state_git_path}`` placeholder. The validation test
    that lives next to this shim asserts a fully-substituted render so
    a regression in the catalog msgstr (e.g. dropping the placeholder)
    surfaces here as a placeholder-leak failure.
    """
    from alfred.i18n import t

    return (
        t("cli.state_git.error.path_missing", state_git_path="/var/lib/alfred/state.git"),
        t("cli.state_git.error.git_missing"),
        t("cli.state_git.error.push_rejected"),
    )


# Module-level structlog binding. Stage 3 (arch-001 / cross-cutting R2):
# the helper emits a fail-loud audit-row stand-in via structlog BEFORE
# the state.git write. The bootstrap's structlog redactor (see
# :mod:`alfred.cli._bootstrap`) runs in front of every output processor
# so any accidental secret-shaped string in the subject is masked before
# render. PR-S3-7 swaps the structlog stand-in for an
# :class:`alfred.audit.AuditWriter` call once the sync-from-CLI bridge
# lands; until then this is the same pattern :mod:`alfred.cli.supervisor`
# uses for ``_emit_breaker_reset_attempt_audit`` (sec-pr-s3-6-04).
_log = structlog.get_logger(__name__)


def _emit_requested_audit_row(
    *,
    event: str,
    schema_name: str,
    fields: frozenset[str],
    subject: dict[str, object],
) -> None:
    """Emit the ``*.requested`` audit-row stand-in BEFORE the state.git write.

    Stage 3 (arch-001 / cross-cutting R2): every reviewer-gated CLI
    command MUST leave a forensic breadcrumb at the moment the operator
    queues the proposal. The supervisor CLI established the pattern
    (see :func:`alfred.cli.supervisor._emit_breaker_reset_attempt_audit`,
    sec-pr-s3-6-04): emit via structlog now, swap for
    :class:`alfred.audit.AuditWriter` in PR-S3-7 without restructuring
    the emit site.

    Ordering rationale: BEFORE the state.git write so a crash inside
    ``create_proposal`` (the bare repo missing, ``git push`` rejected,
    permission error mid-clone, ...) still leaves the operator-intent
    row in the structlog stream. The supervisor reset-breaker path
    documents the same load-bearing order: "attempt-row first, reset
    call second; if the audit emission itself fails, the reset is
    aborted." CLAUDE.md hard rule #7 forbids the silent-skip alternative.

    Validation: ``subject.keys()`` must match ``fields`` exactly. The
    symmetric check defends against typo'd field names silently
    shadowing the real field, and against a refactor accidentally
    persisting an undeclared field (which spec §5.6 forbids because the
    field could carry T3 content fragments). Same shape as
    :meth:`alfred.audit.AuditWriter.append_schema` so the eventual
    PR-S3-7 swap is structurally identical.

    Args:
        event: dotted event name (``"plugin.grant.requested"`` etc.) —
            the structlog key the audit-graph correlator joins on.
        schema_name: the importable identifier of ``fields`` (e.g.
            ``"PLUGIN_GRANT_REQUESTED_FIELDS"``) — threaded into the
            structlog payload so a log-grepping audit collector can
            validate the row at parse time.
        fields: the :class:`frozenset` of declared field names
            (a constant from :mod:`alfred.audit.audit_row_schemas`).
        subject: structured dict of the row's fields. Keys MUST equal
            ``fields`` exactly; values MUST NOT carry T3 content
            fragments (spec §5.6).

    Raises:
        ValueError: if ``subject.keys()`` does not equal ``fields``.
            The raise is loud so a refactor that drops a field surfaces
            at the emit site instead of producing a malformed row.
    """
    missing = fields - subject.keys()
    extra = subject.keys() - fields
    if missing or extra:
        # Mirror :meth:`AuditWriter.append_schema`'s message shape so the
        # eventual PR-S3-7 swap is a drop-in replacement. The schema
        # name appears in the message so on-call can map the row back
        # to :mod:`alfred.audit.audit_row_schemas` without grepping.
        msg_parts = [f"audit emit for event={event!r} (schema={schema_name})"]
        if missing:
            msg_parts.append(f"subject missing required fields: {sorted(missing)!r}")
        if extra:
            msg_parts.append(f"subject has unexpected fields: {sorted(extra)!r}")
        msg_parts.append(
            f"declared fields for {schema_name} are {sorted(fields)!r}; "
            f"consult alfred.audit.audit_row_schemas.{schema_name}"
        )
        raise ValueError("; ".join(msg_parts))
    _log.info(
        event,
        schema_name=schema_name,
        # ``schema_fields`` round-trips the declared field set so a
        # log-grepping audit collector can validate the row at parse
        # time and surface schema drift if the constant gains a key
        # without this emit site being updated.
        schema_fields=sorted(fields),
        **subject,
    )


def _branch_type_tag_for(payload: StateGitProposalPayload) -> str:
    """Derive the branch-name type tag from a typed payload.

    ADR-0018 Decision 2: most payload types map straight through their
    ``proposal_type`` ClassVar. Two compose a richer tag from a payload
    field so the branch reads naturally to the reviewer:

    * :class:`WebAllowlistProposal` → ``"web-allowlist-{action}"``
      (so ``proposal/web-allowlist-add-<hex>``,
      ``proposal/web-allowlist-remove-<hex>``).
    * :class:`ConfigSetProposal` → ``"config-{config_key}"``
      (so ``proposal/config-quarantined-provider-<hex>``).

    The two composition rules are centralised here so the writer never
    sees the composition logic inline — adding a third composition rule
    in a future PR lands in one place.
    """
    if isinstance(payload, WebAllowlistProposal):
        return f"{payload.proposal_type}-{payload.action}"
    if isinstance(payload, ConfigSetProposal):
        return f"{payload.proposal_type}-{payload.config_key}"
    return payload.proposal_type


def _on_disk_files_for(
    payload: StateGitProposalPayload,
    *,
    proposal_id: str,
) -> dict[str, str]:
    """Map a typed payload to the repo-relative file paths it lands at.

    ADR-0018 Decision 3: plugin-grant proposals materialize at
    ``policies/grants/<plugin_id>/<grant_id>.json`` so the parser
    round-trips them. Every other type writes the legacy
    ``proposal.json`` at the repo root — their merged-tree projections
    live in different tables (web allowlist → ``web_allowlist`` row;
    config-set → operator-config projection).

    The grant blob's on-disk shape mirrors
    :class:`alfred.security.capability_gate.policy.GrantRow` exactly:
    ``plugin_id``, ``subscriber_tier``, ``hookpoint``, ``content_tier``,
    ``proposal_branch``. The ``proposal_branch`` field is composed here
    so the parser sees the branch name attribution without the caller
    having to thread it through the typed payload itself (the branch
    name is known only at write time).
    """
    if isinstance(payload, PluginGrantProposal):
        branch_name = f"{_BRANCH_PREFIX}{payload.proposal_type}-{proposal_id}"
        grant_blob = {
            "plugin_id": payload.plugin_id,
            "subscriber_tier": payload.subscriber_tier,
            "hookpoint": payload.hookpoint,
            "content_tier": payload.content_tier,
            "proposal_branch": branch_name,
        }
        rel_path = f"{_GRANTS_TREE_PATH}/{payload.plugin_id}/{proposal_id}.json"
        return {rel_path: json.dumps(grant_blob, indent=2, sort_keys=True)}

    # ADR-0021: side-effecting BreakerResetProposal blobs land at the
    # ``policies/breaker-resets/<proposal_id>.json`` convention so the
    # dispatch loop's HEAD-diff walker discriminates them from
    # declarative-projection blobs by path prefix. Pydantic's
    # mode='json' dump produces a stable shape (sorted keys, no
    # environment-dependent timestamps) — the dispatcher round-trips
    # the same blob via :meth:`BreakerResetProposal.model_validate`.
    if isinstance(payload, BreakerResetProposal):
        rel_path = f"{_BREAKER_RESETS_TREE_PATH}/{proposal_id}.json"
        payload_dict = payload.model_dump(mode="json")
        return {rel_path: json.dumps(payload_dict, indent=2, sort_keys=True)}

    # Every other payload type carries its full state in the
    # proposal.json blob at the repo root. Pydantic's mode='json' dump
    # is stable across runs (deterministic key ordering, no environment-
    # dependent timestamps).
    payload_dict = payload.model_dump(mode="json")
    return {_PROPOSAL_FILENAME: json.dumps(payload_dict, indent=2, sort_keys=True)}


def queue_proposal_or_exit(
    *,
    payload: StateGitProposalPayload,
    denied_key: str,
    pending_review_key: str,
    pending_review_extra_kwargs: dict[str, object] | None = None,
    audit_event: str | None = None,
    audit_schema_name: str | None = None,
    audit_fields: frozenset[str] | None = None,
    audit_subject_partial: dict[str, object] | None = None,
    client: StateGitProposalClient | None = None,
) -> ProposalResult:
    """Queue a reviewer-gated proposal and surface the canonical async-UX block.

    Cross-cutting R5 (DRY): five copies of ``try / except StateGitError /
    echo denied / exit 1 / echo pending_review`` previously lived across
    :mod:`alfred.cli.plugin`, :mod:`alfred.cli.web`, and
    :mod:`alfred.cli.config`. Each copy independently constructed the
    denied + pending-review echo blocks. Consolidating here means:

    * Every reviewer-gated CLI command produces structurally identical
      stderr on failure (operator can grep / parse the prefix).
    * The localised hint mapping from :class:`StateGitErrorKind` lives
      in one place.
    * A future ADR that changes the async-UX block (e.g. emits JSON to
      a structured channel as well as text to stderr) flips every call
      site in one edit.

    Stage 3 (arch-001 / cross-cutting R2): the helper now ALSO emits a
    fail-loud ``*.requested`` audit-row stand-in BEFORE writing to
    state.git. The four audit kwargs (``audit_event``,
    ``audit_schema_name``, ``audit_fields``, ``audit_subject_partial``)
    must all be supplied together; passing them separately is a typer
    bug at the call site. The helper pre-generates the
    :func:`secrets.token_hex` proposal id so the audit row can carry
    the resolved branch name + correlation_id BEFORE the state.git
    write — without that, a crash inside ``create_proposal`` would
    leave no forensic trail (the silent-skip CLAUDE.md hard rule #7
    forbids). The partial subject the caller passes is augmented with
    the auto-generated ``proposal_branch`` + ``correlation_id`` keys
    so the emit site never has to thread either through the call.

    Args:
        payload: typed :class:`StateGitProposalPayload` subclass instance
            (ADR-0018). The writer derives the branch-name type tag
            from the payload's discriminator (``proposal_type``
            ClassVar + composition rules in :func:`_branch_type_tag_for`).
            Pydantic validation runs at construction time — a typo at
            the call site fails BEFORE this helper executes.
            MUST NOT contain raw secret values (CLAUDE.md hard rule #6).
        denied_key: i18n key for the denial message rendered on
            :class:`StateGitError`. The kwargs are ``reason`` (a
            localised hint matching the error kind) + ``detail`` (the
            short typed error message, for the audit log).
        pending_review_key: i18n key for the success-queued message.
            Kwargs supplied automatically: ``branch``, ``proposal_id``.
        pending_review_extra_kwargs: optional extra kwargs to forward
            into ``t(pending_review_key, ...)`` -- for callers whose
            catalog template references additional placeholders (e.g.
            the ``cli.config.set.pending_review`` shape carries ``key``).
        audit_event: dotted event name for the audit row stand-in
            (``"plugin.grant.requested"`` etc.). Must be supplied
            alongside the other three audit kwargs; supplying it without
            them raises :class:`ValueError`.
        audit_schema_name: importable identifier of ``audit_fields``
            (e.g. ``"PLUGIN_GRANT_REQUESTED_FIELDS"``). Surfaces in the
            structlog payload so a log-grepping collector can validate
            the row at parse time.
        audit_fields: declared field set for the audit row (a constant
            from :mod:`alfred.audit.audit_row_schemas`). Used for the
            symmetric key-set check that mirrors
            :meth:`AuditWriter.append_schema`.
        audit_subject_partial: the caller's portion of the audit row
            subject — every key in ``audit_fields`` EXCEPT
            ``proposal_branch`` and ``correlation_id`` (the helper
            auto-fills both). Passing the same keys here is a refactor
            bug surfaced as :class:`ValueError`.
        client: state.git client. Defaults to the module-level
            :data:`_default_client` for production use; tests inject a
            mock.

    Returns:
        The :class:`ProposalResult` for the queued branch. Most callers
        ignore the return value; ``alfred plugin grant`` uses it to emit
        the ``follow_up_command`` line on a separate ``typer.echo`` so
        the operator can copy-paste the status sub-command.

    Raises:
        typer.Exit(code=1): on any :class:`StateGitError`, after
            emitting the localised denial message + the kind-specific
            hint. The audit row stand-in has already been emitted at
            this point (the breadcrumb pointing at operator intent
            survives the state.git failure).
        ValueError: if any of the four audit kwargs is supplied without
            the others, or if ``audit_subject_partial`` carries
            ``proposal_branch`` / ``correlation_id`` (the helper
            auto-fills both), or if the final subject's keys do not
            match ``audit_fields`` after augmentation.
    """
    # Lazy import keeps this module importable from CLI bootstrap without
    # forcing typer/i18n at import time -- ``_state_git`` is loaded by
    # several non-CLI consumers (the audit-graph correlator, the
    # reviewer-gate state machine) that have no Typer dependency.
    import typer

    from alfred.i18n import t

    audit_args = (audit_event, audit_schema_name, audit_fields, audit_subject_partial)
    audit_supplied = sum(1 for arg in audit_args if arg is not None)
    if audit_supplied not in (0, len(audit_args)):
        # All-or-none: supplying a subset is always a refactor bug.
        # The raise is loud so a partial port from a legacy call site
        # cannot silently skip the audit row.
        msg = (
            "queue_proposal_or_exit: audit_event, audit_schema_name, "
            "audit_fields, and audit_subject_partial must all be supplied "
            f"together (got {audit_supplied}/{len(audit_args)})."
        )
        raise ValueError(msg)

    state_git = client if client is not None else _state_git_client

    # Pre-generate the proposal id + branch BEFORE the state.git write
    # so the audit row can carry both. The same width / source the
    # client uses internally so a future tightening of the id namespace
    # only needs to land in :data:`_PROPOSAL_ID_BYTES`. The branch
    # composition routes through :func:`_branch_type_tag_for` so the
    # type tag matches the writer's view exactly (no parallel string
    # the caller has to keep in sync).
    proposal_id = secrets.token_hex(_PROPOSAL_ID_BYTES)
    type_tag = _branch_type_tag_for(payload)
    branch = f"{_BRANCH_PREFIX}{type_tag}-{proposal_id}"
    correlation_id = str(uuid.uuid4())

    if (
        audit_event is not None
        and audit_schema_name is not None
        and audit_fields is not None
        and audit_subject_partial is not None
    ):
        # Refuse caller-supplied ``proposal_branch`` / ``correlation_id``
        # so the auto-fill never silently shadows operator-typed data.
        # A future ADR that wants the caller to override either would
        # land an explicit knob, not a quiet last-write-wins.
        reserved = {"proposal_branch", "correlation_id"} & audit_subject_partial.keys()
        if reserved:
            msg = (
                "queue_proposal_or_exit: audit_subject_partial must NOT carry "
                f"helper-auto-filled keys: {sorted(reserved)!r}. The helper "
                "fills proposal_branch + correlation_id from the pre-generated "
                "branch + uuid."
            )
            raise ValueError(msg)
        subject = {
            **audit_subject_partial,
            "proposal_branch": branch,
            "correlation_id": correlation_id,
        }
        _emit_requested_audit_row(
            event=audit_event,
            schema_name=audit_schema_name,
            fields=audit_fields,
            subject=subject,
        )

    try:
        result = state_git.create_proposal_from_payload(
            payload=payload,
            proposal_id=proposal_id,
        )
    except StateGitError as exc:
        # ``reason`` carries the localised hint matching the failure
        # kind, NOT the raw argv (devex-004). Existing catalog keys
        # already take ``{reason}`` so this maps cleanly across plugin,
        # web, and config sub-apps without a catalog edit at call sites.
        # CR-149 round-3: render the hint through ``_render_hint`` so the
        # ``PATH_MISSING`` body interpolates the operator-configured
        # state.git path rather than the hard-coded default literal.
        #
        # CR-149 round-5 (devex-cr149-r5): :func:`queue_proposal_or_exit`
        # documents ``client`` as an injectable seam. Reaching directly
        # into ``state_git._repo`` made a typed :class:`StateGitError`
        # surface as :class:`AttributeError` whenever a test or future
        # caller injected a duck-typed fake that only implements
        # :meth:`create_proposal_from_payload`. Use a defensive
        # ``getattr`` with the production default so the denial path
        # stays loud-but-typed (CLAUDE.md hard rule #7).
        state_git_path = getattr(state_git, "_repo", Path("/var/lib/alfred/state.git"))
        typer.echo(
            t(denied_key, reason=_render_hint(exc.kind, state_git_path=state_git_path)),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    kwargs: dict[str, object] = {
        "branch": result.branch,
        "proposal_id": result.proposal_id,
    }
    if pending_review_extra_kwargs is not None:
        kwargs.update(pending_review_extra_kwargs)
    typer.echo(t(pending_review_key, **kwargs))
    return result


# Backwards-compatible module-level singleton other modules import.
# Kept as a re-bindable seam so existing tests that patch
# ``alfred.cli.plugin._state_git_client`` etc. keep their patching path;
# the helper above defaults to this when no explicit client is passed.
_state_git_client: StateGitProposalClient = StateGitProposalClient()


__all__ = [
    "ProposalRef",
    "ProposalResult",
    "StateGitError",
    "StateGitErrorKind",
    "StateGitProposalClient",
    "queue_proposal_or_exit",
]
