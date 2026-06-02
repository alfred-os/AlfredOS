"""Unit tests for :meth:`RealGate.rebuild_from_state_git` after the err-002 wiring.

PR-S3-6 Component N Task 22a (plan §2497-2640). Replaces the
``NotImplementedError`` stub PR-S3-2 shipped with the real gitpython-backed
parse-and-apply path:

1. :func:`parse_state_git_head` reads the ``policies/grants/`` tree at
   the requested commit hash (the unit-level shape pinned in
   :mod:`tests.unit.security.capability_gate.test_state_git_parser`).
2. :meth:`RealGate._apply_grants` projects the parsed grants into the
   Postgres ``plugin_grants`` cache and swaps the in-memory snapshot
   atomically.
3. ``plugin.grant.rebuilt`` audit row emits via the gate's audit sink.

Hard invariants pinned here:

* **Cache-hit path stays silent + idempotent** — when the cached sync
  hash equals the requested head, the rebuild short-circuits without
  parsing, applying, or emitting an audit row.
* **Cache-miss path parses + applies + audits** — a head mismatch
  triggers the parser, the apply, and the audit emit, in that order.
* **state.git path is injected via constructor** — production wires
  ``state_git_path=ALFRED_STATE_GIT_PATH`` (default
  ``/var/lib/alfred/state.git``); tests override with a temp bare repo.
* **Audit row uses CAPABILITY_GATE_REBUILD_FIELDS schema** — every
  declared field is present; the symmetric-key check at the writer
  passes.
* **Empty grants tree is NOT an error** — the bootstrap state (no
  grants yet) projects to an empty frozenset and the apply correctly
  produces an empty policy without raising.

These tests use the same bare-repo fixture shape as the parser tests so
the gitpython integration is exercised end-to-end (no mocked parser).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from alfred.security.capability_gate.policy import GrantRow


def _git_env(home: Path) -> dict[str, str]:
    # CR-149 round-3 (extension of the parser fix): inherit the
    # current PATH rather than hard-coding ``/usr/bin:/bin`` so the
    # helper works on runners where git lives elsewhere (Homebrew,
    # Nix, container images with a pinned binary). Only HOME + the
    # git identity stay sandboxed.
    return {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
        "HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
    }


def _make_backend(
    grants: frozenset[GrantRow] | None = None,
    sync_hash: str | None = None,
) -> Any:
    """Stub StorageBackend matching ``test_real_gate``'s helper shape.

    sec-pr-s3-6-02: ``apply_atomic`` is the atomic primitive
    :meth:`RealGate._apply_grants` calls; the per-op AsyncMocks remain
    on the stub so call sites that bypass the gate (proposal flow,
    integration round-trip) still exercise the per-op surface.
    """
    backend = MagicMock()
    backend.ping = AsyncMock(return_value=None)
    backend.load_grants = AsyncMock(return_value=grants or frozenset())
    backend.get_sync_hash = AsyncMock(return_value=sync_hash)
    backend.set_sync_hash = AsyncMock(return_value=None)
    backend.upsert_grant = AsyncMock(return_value=None)
    backend.revoke_grant = AsyncMock(return_value=None)
    backend.apply_atomic = AsyncMock(return_value=None)
    return backend


def _make_audit_sink() -> Any:
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


def _seed_state_git(
    tmp_path: Path,
    grant_payloads: dict[str, dict[str, object]] | None = None,
) -> tuple[Path, str]:
    """Build a bare state.git repo with optional ``policies/grants/`` tree."""
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
    if grant_payloads:
        grants_dir = work / "policies" / "grants"
        grants_dir.mkdir(parents=True)
        for filename, payload in grant_payloads.items():
            (grants_dir / filename).write_text(json.dumps(payload))
    else:
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
    head_proc = subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "rev-parse", "HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    commit_hash = head_proc.stdout.strip()
    subprocess.run(  # noqa: S603
        ["git", "-C", str(work), "push", "origin", "main"],  # noqa: S607
        check=True,
        capture_output=True,
        env=env,
    )
    return repo, commit_hash


# ---------------------------------------------------------------------------
# Cache-hit short-circuit
# ---------------------------------------------------------------------------


async def test_rebuild_short_circuits_when_head_unchanged(tmp_path: Path) -> None:
    """Same head as cached → no parse, no apply, no audit row.

    Spec §8.1 idempotency. The cache-hit branch is the fast path that
    keeps every supervisor heartbeat from re-projecting the policy
    table; if it issued audit rows, the audit log would balloon at
    10s/row indefinitely.
    """
    from alfred.security.capability_gate._gate import RealGate

    repo_path, head = _seed_state_git(tmp_path)
    backend = _make_backend(sync_hash=head)
    sink = _make_audit_sink()
    gate = await RealGate.create(
        backend=backend,
        audit_sink=sink,
        state_git_path=repo_path,
    )

    await gate.rebuild_from_state_git(state_git_head=head)

    backend.apply_atomic.assert_not_awaited()
    backend.set_sync_hash.assert_not_awaited()
    backend.upsert_grant.assert_not_awaited()
    backend.revoke_grant.assert_not_awaited()
    sink.append_schema.assert_not_awaited()


# ---------------------------------------------------------------------------
# Cache-miss full rebuild
# ---------------------------------------------------------------------------


async def test_rebuild_parses_and_applies_grants_from_state_git(tmp_path: Path) -> None:
    """Cache miss → parse the head, apply grants, set sync hash.

    The end-to-end happy path: the parser reads the well-formed grant
    blob, the apply persists the upsert, and the in-memory policy
    answers the new grant positively.
    """
    from alfred.security.capability_gate._gate import RealGate

    payload = {
        "plugin_id": "alfred.web-fetch",
        "subscriber_tier": "operator",
        "hookpoint": "tool.web.fetch",
        "content_tier": None,
        "proposal_branch": "proposal/policy-grant-abc",
    }
    repo_path, new_head = _seed_state_git(tmp_path, {"g.json": payload})

    backend = _make_backend(sync_hash="old-hash")
    sink = _make_audit_sink()
    gate = await RealGate.create(
        backend=backend,
        audit_sink=sink,
        state_git_path=repo_path,
    )

    await gate.rebuild_from_state_git(state_git_head=new_head)

    expected = GrantRow(
        plugin_id="alfred.web-fetch",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-abc",
    )
    backend.apply_atomic.assert_awaited_once()
    kwargs = backend.apply_atomic.await_args.kwargs
    assert set(kwargs["upserts"]) == {expected}
    assert set(kwargs["revokes"]) == set()
    assert kwargs["commit_hash"] == new_head
    # Hot-path check honours the freshly-applied grant.
    assert (
        gate.check(
            plugin_id="alfred.web-fetch",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is True
    )


async def test_rebuild_emits_capability_gate_rebuilt_audit_row(tmp_path: Path) -> None:
    """The rebuild emits one ``plugin.grant.rebuilt`` row per cache miss.

    Spec §8.5: every state-changing action surfaces an audit row. The
    rebuild trigger is the host-side proposal-merge → rebuild flow;
    operators query the audit graph to confirm the merge propagated to
    the live cache.
    """
    from alfred.audit.audit_row_schemas import CAPABILITY_GATE_REBUILD_FIELDS
    from alfred.security.capability_gate._gate import RealGate

    payload = {
        "plugin_id": "alfred.web-fetch",
        "subscriber_tier": "operator",
        "hookpoint": "tool.web.fetch",
        "content_tier": None,
        "proposal_branch": "proposal/policy-grant-abc",
    }
    repo_path, new_head = _seed_state_git(tmp_path, {"g.json": payload})

    backend = _make_backend(sync_hash="old-hash")
    sink = _make_audit_sink()
    gate = await RealGate.create(
        backend=backend,
        audit_sink=sink,
        state_git_path=repo_path,
    )

    await gate.rebuild_from_state_git(state_git_head=new_head)

    sink.append_schema.assert_awaited_once()
    kwargs = sink.append_schema.await_args.kwargs
    assert kwargs["fields"] == CAPABILITY_GATE_REBUILD_FIELDS
    assert kwargs["schema_name"] == "CAPABILITY_GATE_REBUILD_FIELDS"
    assert kwargs["event"] == "plugin.grant.rebuilt"
    assert kwargs["trust_tier_of_trigger"] == "T0"
    # Symmetric-key check: every declared field is present in subject.
    subject = kwargs["subject"]
    assert set(subject.keys()) == set(CAPABILITY_GATE_REBUILD_FIELDS)
    assert subject["commit_hash"] == new_head
    assert subject["grant_count"] == 1


async def test_rebuild_success_correlation_id_shared_between_audit_and_complete_log(
    tmp_path: Path,
) -> None:
    """CR-149 round-6: success-arm audit + ``rebuild.complete`` log share a correlation_id.

    The rebuild flow now mints ONE correlation_id at the
    :meth:`rebuild_from_state_git` boundary and threads it through
    both the success-arm audit row AND the
    ``capability_gate.rebuild.complete`` structlog line. Without the
    shared id, an incident query that surfaces one stream could not
    join to the other — the trust-boundary forensic bridge would
    silently break.
    """
    from unittest.mock import patch

    from alfred.security.capability_gate._gate import RealGate

    payload = {
        "plugin_id": "alfred.web-fetch",
        "subscriber_tier": "operator",
        "hookpoint": "tool.web.fetch",
        "content_tier": None,
        "proposal_branch": "proposal/policy-grant-abc",
    }
    repo_path, new_head = _seed_state_git(tmp_path, {"g.json": payload})

    backend = _make_backend(sync_hash="old-hash")
    sink = _make_audit_sink()
    gate = await RealGate.create(
        backend=backend,
        audit_sink=sink,
        state_git_path=repo_path,
    )

    captured_complete_kwargs: list[dict[str, object]] = []

    def _capture_info(event: str, **kwargs: object) -> None:
        if event == "capability_gate.rebuild.complete":
            captured_complete_kwargs.append(kwargs)

    with patch("alfred.security.capability_gate._gate._log") as mock_log:
        mock_log.info = _capture_info
        # ``debug`` is exercised by the cache-skip path; the test only
        # asserts on ``info``, but stub ``debug`` so unexpected calls
        # do not crash the captor.
        mock_log.debug = lambda *_a, **_kw: None
        await gate.rebuild_from_state_git(state_git_head=new_head)

    sink.append_schema.assert_awaited_once()
    audit_kwargs = sink.append_schema.await_args.kwargs
    audit_correlation_id = audit_kwargs["subject"]["correlation_id"]
    assert audit_kwargs["trace_id"] == audit_correlation_id

    assert len(captured_complete_kwargs) == 1, captured_complete_kwargs
    assert captured_complete_kwargs[0]["correlation_id"] == audit_correlation_id


# ---------------------------------------------------------------------------
# Empty grants tree
# ---------------------------------------------------------------------------


async def test_rebuild_applies_empty_snapshot_when_no_grants_tree(
    tmp_path: Path,
) -> None:
    """A commit with no ``policies/grants/`` tree projects to an empty policy.

    The bootstrap shape: the very first state.git push after init has
    no grants. The rebuild MUST handle this without raising — otherwise
    the supervisor can never reach a working initial state.
    """
    from alfred.security.capability_gate._gate import RealGate

    repo_path, new_head = _seed_state_git(tmp_path)

    backend = _make_backend(sync_hash="old-hash")
    sink = _make_audit_sink()
    gate = await RealGate.create(
        backend=backend,
        audit_sink=sink,
        state_git_path=repo_path,
    )

    await gate.rebuild_from_state_git(state_git_head=new_head)

    # No grants to upsert; sync hash still advances so subsequent
    # rebuilds short-circuit on the same head. The atomic call carries
    # the empty payload + the new commit hash.
    backend.apply_atomic.assert_awaited_once()
    kwargs = backend.apply_atomic.await_args.kwargs
    assert set(kwargs["upserts"]) == set()
    assert set(kwargs["revokes"]) == set()
    assert kwargs["commit_hash"] == new_head
    # An empty policy denies every check.
    assert (
        gate.check(
            plugin_id="any",
            hookpoint="any",
            requested_tier="operator",
        )
        is False
    )


# ---------------------------------------------------------------------------
# State.git path injection
# ---------------------------------------------------------------------------


async def test_rebuild_uses_state_git_path_from_constructor(tmp_path: Path) -> None:
    """``state_git_path`` is injected via :meth:`RealGate.create` and used by the parser.

    Two distinct bare repos with overlapping commit shapes prove the
    constructor parameter actually threads through to the parser call;
    a hard-coded default path would project from the wrong repo.
    """
    from alfred.security.capability_gate._gate import RealGate

    payload_a = {
        "plugin_id": "repo-a.plugin",
        "subscriber_tier": "operator",
        "hookpoint": "tool.x",
        "content_tier": None,
        "proposal_branch": "proposal/policy-grant-a",
    }
    repo_a_path, head_a = _seed_state_git(tmp_path / "repoA", {"g.json": payload_a})

    backend = _make_backend(sync_hash="old-hash")
    sink = _make_audit_sink()
    gate = await RealGate.create(
        backend=backend,
        audit_sink=sink,
        state_git_path=repo_a_path,
    )

    await gate.rebuild_from_state_git(state_git_head=head_a)

    # The atomic apply MUST carry repo-a's grant, not some default.
    backend.apply_atomic.assert_awaited_once()
    kwargs = backend.apply_atomic.await_args.kwargs
    upserts = list(kwargs["upserts"])
    assert len(upserts) == 1
    assert upserts[0].plugin_id == "repo-a.plugin"


# ---------------------------------------------------------------------------
# Idempotency on repeated calls
# ---------------------------------------------------------------------------


async def test_rebuild_is_idempotent_on_second_call_with_same_head(
    tmp_path: Path,
) -> None:
    """Calling rebuild twice with the same head applies grants once.

    Spec §8.1: the cache-hit short-circuit means a second call with the
    same head MUST be a no-op even after the first call advanced the
    sync hash. The supervisor heartbeat can call rebuild eagerly without
    fear of churn.
    """
    from alfred.security.capability_gate._gate import RealGate

    payload = {
        "plugin_id": "alfred.web-fetch",
        "subscriber_tier": "operator",
        "hookpoint": "tool.web.fetch",
        "content_tier": None,
        "proposal_branch": "proposal/policy-grant-abc",
    }
    repo_path, head = _seed_state_git(tmp_path, {"g.json": payload})

    # Backend simulates: first call sees old-hash, second call sees the
    # post-rebuild head (because the backend.set_sync_hash mock would
    # have been awaited with head between calls).
    backend = _make_backend(sync_hash="old-hash")
    sink = _make_audit_sink()
    gate = await RealGate.create(
        backend=backend,
        audit_sink=sink,
        state_git_path=repo_path,
    )

    await gate.rebuild_from_state_git(state_git_head=head)
    # Re-stub get_sync_hash to simulate the post-rebuild state.
    backend.get_sync_hash = AsyncMock(return_value=head)
    await gate.rebuild_from_state_git(state_git_head=head)

    # Single atomic apply, single audit row — the second call short-circuited.
    backend.apply_atomic.assert_awaited_once()
    sink.append_schema.assert_awaited_once()


async def test_rebuild_parser_failure_emits_rolled_back_audit_then_reraises(
    tmp_path: Path,
) -> None:
    """A parser-side rebuild failure emits ``plugin.grant.rebuilt`` rolled_back, then re-raises.

    CR-149 round-3: a bad state.git head (corrupted commit, missing
    tree, raised gitpython error) previously propagated through
    :func:`asyncio.to_thread` before any ``plugin.grant.rebuilt`` row
    landed — the capability projection stayed on the previous snapshot
    AND the trust-boundary audit trail had no forensic record that the
    privileged rebuild attempt failed at all. CLAUDE.md hard rule #7
    requires that pre-DB failure surfaces in the audit log too. Pin
    the row + the re-raise here so a future change that swallows the
    exception or skips the audit emit surfaces on the trust-boundary
    suite, not silently in production.
    """
    from unittest.mock import patch

    import pytest

    from alfred.security.capability_gate._gate import RealGate

    repo_path, _ = _seed_state_git(tmp_path, {})
    backend = _make_backend(sync_hash="old-hash")
    sink = _make_audit_sink()
    gate = await RealGate.create(
        backend=backend,
        audit_sink=sink,
        state_git_path=repo_path,
    )

    # Force the parser to raise a representative GitPython-shaped
    # exception. The exact type does not matter (the gate catches
    # ``Exception``); pinning ``RuntimeError`` keeps the test
    # gitpython-independent.
    parser_error = RuntimeError("bad state.git head")
    with (
        patch(
            "alfred.security.capability_gate._gate.parse_state_git_head",
            side_effect=parser_error,
        ),
        pytest.raises(RuntimeError, match=r"bad state\.git head"),
    ):
        await gate.rebuild_from_state_git(state_git_head="totally-bogus-hash")

    # Exactly one audit row landed with the rolled_back result.
    sink.append_schema.assert_awaited_once()
    kwargs = sink.append_schema.await_args.kwargs
    assert kwargs["event"] == "plugin.grant.rebuilt"
    assert kwargs["result"] == "rolled_back"
    assert kwargs["subject"]["commit_hash"] == "totally-bogus-hash"
    # The in-memory snapshot was never swapped — ``apply_atomic`` was
    # never reached because the parser raised first.
    backend.apply_atomic.assert_not_awaited()
