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
from pathlib import Path
from typing import Final

from alfred.errors import AlfredError

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
    """


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
        the same typed error. ``capture_output=True`` keeps stderr off
        the operator's terminal until the CLI explicitly chooses to
        surface it (post-redaction).
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
        except OSError as exc:
            # Includes FileNotFoundError when ``git`` itself is missing
            # — surface as the same typed error so the CLI narrows once.
            msg = f"state.git command failed: {' '.join(cmd)}\n{exc}"
            raise StateGitError(msg) from exc
        if result.returncode != 0:
            msg = f"state.git command failed: {' '.join(cmd)}\nstderr: {result.stderr.strip()}"
            raise StateGitError(msg)
        return result.stdout


__all__ = [
    "ProposalRef",
    "ProposalResult",
    "StateGitError",
    "StateGitProposalClient",
]
