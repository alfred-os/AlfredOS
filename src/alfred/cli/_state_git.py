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
import secrets
import subprocess
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

from alfred.errors import AlfredError


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


# Branch-name schema. Shared with
# ``alfred.security.capability_gate.proposals._write_proposal_to_state_git``;
# any change here must land there simultaneously per devex-006.
_BRANCH_PREFIX: Final[str] = "proposal/"
_PROPOSAL_FILENAME: Final[str] = "proposal.json"

# ``token_hex(8)`` yields 16 hex characters — collision in a single
# state.git lifetime is statistically zero. Matches the proposal-flow
# writer's id width so the audit-graph correlator can join across both
# writers without a width-mismatch wart.
_PROPOSAL_ID_BYTES: Final[int] = 8


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

    def create_proposal(
        self,
        proposal_type: str,
        payload: dict[str, object],
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

        Returns:
            :class:`ProposalResult` with ``proposal_id`` (raw hex) and
            ``branch`` (full ``proposal/...`` name).

        Raises:
            StateGitError: if any git subprocess fails (missing repo,
                permission error, push rejected, …). The CLI narrows on
                this to render a localised operator-facing error.
        """
        proposal_id = secrets.token_hex(_PROPOSAL_ID_BYTES)
        branch = f"{_BRANCH_PREFIX}{proposal_type}-{proposal_id}"
        payload_json = json.dumps(payload, indent=2, sort_keys=True)

        with tempfile.TemporaryDirectory() as work_dir:
            work = Path(work_dir)
            self._run(["git", "clone", str(self._repo), str(work)])
            self._run(["git", "-C", str(work), "checkout", "-b", branch])
            proposal_file = work / _PROPOSAL_FILENAME
            proposal_file.write_text(payload_json)
            self._run(["git", "-C", str(work), "add", _PROPOSAL_FILENAME])
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
                    f"proposal({proposal_type}): {proposal_id}",
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
            # ``FileNotFoundError`` fires when ``git`` itself is missing
            # OR when ``-C <missing-path>`` is passed. Distinguish via
            # the bound repo path so the CLI can render the matching
            # recovery hint.
            if not self._repo.exists():
                msg = "state.git repo missing"
                raise StateGitError(msg, kind=StateGitErrorKind.PATH_MISSING) from exc
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
            msg = "state.git push rejected"
            err = StateGitError(msg, kind=StateGitErrorKind.PUSH_REJECTED)
            err.add_note(f"git stderr: {result.stderr.strip()}")
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


def _register_hint_keys_for_pybabel() -> tuple[str, ...]:
    """Surface the three hint keys to pybabel's static extractor.

    pybabel walks the AST looking for :func:`t` calls with literal
    string arguments; the indirection in :func:`_hint_key_for` would
    otherwise hide these keys and the catalog would silently miss
    them. The function is never called at runtime -- the return value
    only documents the canonical key list for grep.
    """
    from alfred.i18n import t

    return (
        t("cli.state_git.error.path_missing"),
        t("cli.state_git.error.git_missing"),
        t("cli.state_git.error.push_rejected"),
    )


def queue_proposal_or_exit(
    *,
    proposal_type: str,
    payload: dict[str, object],
    denied_key: str,
    pending_review_key: str,
    pending_review_extra_kwargs: dict[str, object] | None = None,
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

    Args:
        proposal_type: short dash-separated tag identifying the proposal
            family (``"policy-grant"``, ``"web-allowlist-add"``, ...).
            Forwarded to :meth:`StateGitProposalClient.create_proposal`
            verbatim; the branch name carries this as a prefix.
        payload: structured dict the reviewer reads. MUST NOT contain
            raw secret values (CLAUDE.md hard rule #6).
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
        emitting the localised denial message + the kind-specific hint.
    """
    # Lazy import keeps this module importable from CLI bootstrap without
    # forcing typer/i18n at import time -- ``_state_git`` is loaded by
    # several non-CLI consumers (the audit-graph correlator, the
    # reviewer-gate state machine) that have no Typer dependency.
    import typer

    from alfred.i18n import t

    state_git = client if client is not None else _state_git_client
    try:
        result = state_git.create_proposal(
            proposal_type=proposal_type,
            payload=payload,
        )
    except StateGitError as exc:
        hint_key = _hint_key_for(exc.kind)
        # ``reason`` carries the localised hint matching the failure
        # kind, NOT the raw argv (devex-004). Existing catalog keys
        # already take ``{reason}`` so this maps cleanly across plugin,
        # web, and config sub-apps without a catalog edit at call sites.
        typer.echo(
            t(denied_key, reason=t(hint_key)),
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
