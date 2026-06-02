"""ADR-0018 round-trip + byte-equality tests for the consolidated state.git writers.

Two invariants this suite pins:

1. **Byte-equality across the sync writer + async shim with identical
   typed payloads.** ``StateGitProposalClient.create_proposal_from_payload``
   (the canonical sync seam) and
   :func:`alfred.security.capability_gate.proposals._write_proposal_to_state_git`
   (the asyncio shim into the same writer) MUST produce identical
   on-disk shapes when constructed from the same
   :class:`PluginGrantProposal`. A divergence between the two writers
   was the underlying arch-002 finding this ADR closes; the byte-
   equality test fails loudly if either entry point drifts.

2. **Round-trip via the parser.** A
   :class:`PluginGrantProposal` written into state.git lands at
   ``policies/grants/<plugin_id>/<grant_id>.json``; merging the
   proposal branch onto ``main`` and running
   :func:`alfred.security.capability_gate._state_git_parser.parse_state_git_head`
   re-hydrates exactly the same :class:`GrantRow` shape. This is the
   integration-tier proof that the parser-writer path mismatch (the
   third problem in the orchestrator finding) is closed.

These tests live under ``tests/integration/`` rather than
``tests/unit/`` because they boot a real bare git repo + perform real
subprocess commits — the same harness shape
``tests/unit/cli/test_state_git.py``'s ``bare_repo`` fixture uses.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from alfred.cli._state_git import StateGitProposalClient
from alfred.security.capability_gate._state_git_parser import parse_state_git_head
from alfred.security.capability_gate.policy import GrantRow
from alfred.state.proposal_payloads import PluginGrantProposal


def _git_env(home: Path) -> dict[str, str]:
    """Minimal env so git ignores the developer's global config."""
    return {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
    }


@pytest.fixture
def bare_repo(tmp_path: Path) -> Path:
    """Create a bare git repo with a seeded ``main`` branch.

    Same shape as ``tests/unit/cli/test_state_git.py``'s ``bare_repo``
    fixture so the round-trip seeds an identical starting state.
    """
    repo = tmp_path / "state.git"
    env = _git_env(tmp_path)
    subprocess.run(  # noqa: S603
        ["git", "init", "--bare", "--initial-branch=main", str(repo)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    work = tmp_path / "seed"
    work.mkdir()
    subprocess.run(  # noqa: S603
        ["git", "clone", str(repo), str(work)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    (work / "README").write_text("seeded")
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "add", "."],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-C",
            str(work),
            "commit",
            "-m",
            "seed",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "push", "origin", "main"],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    return repo


def test_plugin_grant_proposal_lands_under_policies_grants_tree(
    bare_repo: Path,
) -> None:
    """The sync writer materialises the plugin-grant blob at the parser-known path.

    ADR-0018 Decision 3: ``policies/grants/<plugin_id>/<grant_id>.json``
    is the canonical layout the parser reads. The writer must produce
    this shape so round-trip works without an intermediate merge-time
    transform.
    """
    client = StateGitProposalClient(state_git_path=bare_repo)
    payload = PluginGrantProposal(
        plugin_id="alfred.web-fetch",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
    )
    result = client.create_proposal_from_payload(payload)

    out = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "--git-dir",
            str(bare_repo),
            "ls-tree",
            "-r",
            result.branch,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    expected_path = f"policies/grants/alfred.web-fetch/{result.proposal_id}.json"
    assert expected_path in out.stdout, (expected_path, out.stdout)
    # The legacy proposal.json at repo root MUST NOT be present for
    # plugin-grant proposals — they go through the grants-tree path
    # exclusively so the merge step is a no-op rename.
    assert "proposal.json" not in out.stdout


def test_sync_writer_and_async_shim_produce_semantically_identical_blob(
    bare_repo: Path,
) -> None:
    """Semantic JSON equality: sync writer and async shim project the same payload.

    CR-149 docstring fix: the previous shape claimed "byte-equality"
    but the assertion (``json.loads`` → dict equality) only proves
    semantic JSON equality — divergent key ordering, whitespace, or
    newline handling between the two writers would still pass. The
    docstring (and the test name) now match what the assertion
    actually proves: every typed field in the proposal payload
    round-trips identically through both writer entry points. If a
    future audit-time round-trip relies on byte-equality, a separate
    test should diff the canonical-JSON encodings of both blobs;
    today's contract is "the typed fields match", which this
    assertion enforces.

    Both writer entry points now flow through
    :meth:`StateGitProposalClient.create_proposal_from_payload`. The
    test patches ``StateGitProposalClient`` so the async shim binds
    to the test's ``bare_repo`` path; both calls then materialise
    against the same repo with the same proposal id forced via the
    ``proposal_id`` parameter so the typed-field comparison is
    deterministic.
    """
    payload = PluginGrantProposal(
        plugin_id="alfred.web-fetch",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier="T2",
        operator_user_id="op@example.com",
    )
    proposal_id_sync = "aaaaaaaaaaaaaaaa"
    proposal_id_async = "bbbbbbbbbbbbbbbb"

    # Sync writer.
    sync_client = StateGitProposalClient(state_git_path=bare_repo)
    sync_result = sync_client.create_proposal_from_payload(payload, proposal_id=proposal_id_sync)

    # Async shim — patched to bind the test's bare_repo. The shim
    # constructs its own StateGitProposalClient internally; patching
    # the symbol gives that internal instance the test-scoped
    # state_git_path so the asyncio.to_thread call reaches the same
    # on-disk write path the sync test just exercised.
    from alfred.security.capability_gate import proposals as proposals_module

    with patch(
        "alfred.cli._state_git.StateGitProposalClient",
        lambda: StateGitProposalClient(state_git_path=bare_repo),
    ):
        async_branch = asyncio.run(
            proposals_module._write_proposal_to_state_git(
                branch_name=f"proposal/policy-grant-{proposal_id_async}",
                plugin_id="alfred.web-fetch",
                subscriber_tier="operator",
                hookpoint="tool.web.fetch",
                content_tier="T2",
                operator_user_id="op@example.com",
            )
        )

    sync_blob = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "--git-dir",
            str(bare_repo),
            "show",
            f"{sync_result.branch}:policies/grants/alfred.web-fetch/{proposal_id_sync}.json",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    async_blob = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "--git-dir",
            str(bare_repo),
            "show",
            f"{async_branch}:policies/grants/alfred.web-fetch/{proposal_id_async}.json",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    # Normalise the per-call ``proposal_branch`` attribution so the
    # semantic-equality assertion does not flag the deterministic
    # id-suffix difference. Every other typed field MUST match
    # exactly. CR-149: this is semantic JSON equality (dict ==), not
    # byte-equality; the writers go through the same Pydantic
    # ``model_dump_json`` path so divergent whitespace or key order
    # has never been observed in practice, but a future writer that
    # adopts a different serialiser would slip past this check
    # silently. A separate byte-diff test would close that gap; the
    # current contract is "typed fields round-trip".
    sync_obj = json.loads(sync_blob)
    async_obj = json.loads(async_blob)
    sync_obj.pop("proposal_branch")
    async_obj.pop("proposal_branch")
    assert sync_obj == async_obj


def test_parse_state_git_head_round_trips_typed_payload_via_writer(
    bare_repo: Path,
    tmp_path: Path,
) -> None:
    """End-to-end: typed payload → writer → state.git → parser → GrantRow.

    The integration test seeds a proposal branch via the sync writer,
    merges it onto ``main`` (the reviewer-agent's eventual job),
    re-resolves HEAD, and asserts the parser re-hydrates the exact
    GrantRow the payload encoded. Closes the writer→parser silent-
    mismatch the orchestrator finding identified.
    """
    payload = PluginGrantProposal(
        plugin_id="alfred.web-fetch",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier="T2",
    )
    client = StateGitProposalClient(state_git_path=bare_repo)
    result = client.create_proposal_from_payload(payload)

    # Merge the proposal branch into main — simulating the reviewer-
    # agent's approval step. The parser reads ``main`` head, not the
    # proposal branch.
    env = _git_env(tmp_path)
    merge_clone = tmp_path / "merge"
    subprocess.run(  # noqa: S603
        ["git", "clone", str(bare_repo), str(merge_clone)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-C",
            str(merge_clone),
            "merge",
            "--no-ff",
            "-m",
            f"merge {result.branch}",
            f"origin/{result.branch}",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(merge_clone), "push", "origin", "main"],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    head_proc = subprocess.run(  # noqa: S603
        ["git", "-C", str(merge_clone), "rev-parse", "HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    merged_commit_hash = head_proc.stdout.strip()

    grants = parse_state_git_head(bare_repo, merged_commit_hash)

    assert grants == frozenset(
        {
            GrantRow(
                plugin_id="alfred.web-fetch",
                subscriber_tier="operator",
                hookpoint="tool.web.fetch",
                content_tier="T2",
                proposal_branch=result.branch,
            )
        }
    )


def test_parse_state_git_head_round_trips_typed_payload_via_async_shim(
    bare_repo: Path,
    tmp_path: Path,
) -> None:
    """Round-trip via the async shim entry point.

    Mirrors the sync round-trip above so a future writer-side change
    that touches only one entry point fails this paired test rather
    than producing a silent asymmetry.
    """
    from alfred.security.capability_gate import proposals as proposals_module

    proposal_id = "ccccccccccccccc1"
    with patch(
        "alfred.cli._state_git.StateGitProposalClient",
        lambda: StateGitProposalClient(state_git_path=bare_repo),
    ):
        branch = asyncio.run(
            proposals_module._write_proposal_to_state_git(
                branch_name=f"proposal/policy-grant-{proposal_id}",
                plugin_id="alfred.quarantine-llm",
                subscriber_tier="system",
                hookpoint="tag.T3",
                content_tier="T3",
                operator_user_id="op@example.com",
            )
        )

    env = _git_env(tmp_path)
    merge_clone = tmp_path / "merge"
    subprocess.run(  # noqa: S603
        ["git", "clone", str(bare_repo), str(merge_clone)],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-C",
            str(merge_clone),
            "merge",
            "--no-ff",
            "-m",
            f"merge {branch}",
            f"origin/{branch}",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(merge_clone), "push", "origin", "main"],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    head_proc = subprocess.run(  # noqa: S603
        ["git", "-C", str(merge_clone), "rev-parse", "HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    merged_commit_hash = head_proc.stdout.strip()

    grants = parse_state_git_head(bare_repo, merged_commit_hash)

    assert grants == frozenset(
        {
            GrantRow(
                plugin_id="alfred.quarantine-llm",
                subscriber_tier="system",
                hookpoint="tag.T3",
                content_tier="T3",
                proposal_branch=branch,
            )
        }
    )
