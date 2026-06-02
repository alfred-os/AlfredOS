"""state.git grant-policy parser (PR-S3-6, err-002).

Spec §8.1 (Fork 7): grant policy source of truth is state.git; Postgres
is a derived projection. This module owns the
``git tree → frozenset[GrantRow]`` step that
:meth:`alfred.security.capability_gate._gate.RealGate.rebuild_from_state_git`
invokes on every cache miss.

ADR-0018 Decision 4: the parser traverses ``policies/grants/`` recursively
so the per-plugin nested layout
(``policies/grants/<plugin_id>/<grant_id>.json``) written by the
canonical writers re-hydrates by construction. Pre-ADR-0018 flat-layout
grants at ``policies/grants/<file>.json`` continue to project unchanged
— ``tree.traverse()`` yields both the legacy flat blobs and the new
nested blobs in deterministic order.

Why a dedicated module:

* **Trust-boundary scrutiny.** A bug here mis-projects the capability
  policy — the highest-blast surface in AlfredOS. Keeping the parser
  in its own file gives reviewers exactly one place to look when
  auditing the state.git → in-memory snapshot mapping.
* **CLAUDE.md hard rule #7 (no silent failures in security paths).**
  Every grant blob that fails :class:`GrantRow` validation is logged
  at WARNING and skipped — never silently accepted. The skip path
  surfaces the blob path AND the validation error type (no message
  body — :class:`ValueError` messages from
  :meth:`GrantRow.__post_init__` carry the offending tier string only,
  which is safe to log) so an operator can find and fix the corrupted
  blob.
* **No gitpython on the hot path.** Production wires this parser via
  :func:`asyncio.to_thread` so the synchronous gitpython object DB
  reads never block the asyncio event loop.

This module is private (leading underscore) because the parser is an
internal seam of the capability_gate package; production callers reach
it via :meth:`RealGate.rebuild_from_state_git`. Tests import directly
to pin the projection semantics.
"""

from __future__ import annotations

import json
from pathlib import Path

import git
import structlog

from alfred.security.capability_gate.policy import GrantRow

_log = structlog.get_logger(__name__)

# Spec §8.1: the state.git policy tree lives at this exact path.
# Hard-coded because changing it requires a coordinated state.git
# migration; centralising the literal keeps the parser and the
# proposal-writer aligned without forcing a config seam.
_GRANTS_TREE_PATH = "policies/grants"


def parse_state_git_head(state_git_path: Path, commit_hash: str) -> frozenset[GrantRow]:
    """Project every grant blob under ``policies/grants/`` into :class:`GrantRow`.

    Reads the state.git tree at the exact commit hash (never ``HEAD``
    alias — the caller resolves aliasing) and returns the authoritative
    snapshot. Files that fail :class:`GrantRow` validation are logged
    at WARNING and skipped; the rebuild MUST continue for the remaining
    well-formed grants so a single corrupted proposal does not wedge
    the gate.

    Args:
        state_git_path: filesystem path to the bare state.git repo
            (typically ``/var/lib/alfred/state.git``).
        commit_hash: the exact commit SHA to read from. The caller
            (:meth:`RealGate.rebuild_from_state_git`) resolves the host
            HEAD pointer before calling — this function takes a literal
            hash so the projection is reproducible across replays.

    Returns:
        The frozenset of every well-formed :class:`GrantRow` in the
        ``policies/grants/`` tree at ``commit_hash``. Empty frozenset
        when the tree is missing (bootstrap state) or empty.

    Notes:
        gitpython reads the object DB synchronously. Callers in async
        contexts MUST wrap this in :func:`asyncio.to_thread` so the
        event loop is not blocked on a cold-cache rebuild.
    """
    repo = git.Repo(str(state_git_path), odbt=git.GitCmdObjectDB)
    commit = repo.commit(commit_hash)
    try:
        grants_tree = commit.tree[_GRANTS_TREE_PATH]
    except KeyError:
        # Bootstrap state — the very first state.git push after init
        # has no grants. Not an error; the gate stays at the
        # empty-policy fail-closed default until the first proposal
        # merges.
        _log.info(
            "capability_gate.rebuild.no_grants_tree",
            commit_hash=commit_hash,
        )
        return frozenset()

    rows: list[GrantRow] = []
    # ADR-0018 Decision 4: traverse subtrees recursively so the
    # ``policies/grants/<plugin_id>/<grant_id>.json`` layout the new
    # writers produce round-trips. ``tree.traverse()`` walks every
    # nested blob in deterministic order — the same blob set the
    # historical single-level ``grants_tree.blobs`` scan returned for
    # legacy flat-layout grants stays included.
    for blob in grants_tree.traverse():
        # ``traverse`` yields both Blob and Tree nodes; filter to blobs
        # via the ``type`` discriminator gitpython exposes. JSON-only —
        # a future ADR that flips the format flips this guard too.
        if blob.type != "blob":  # type: ignore[union-attr]
            continue
        if not blob.path.endswith(".json"):  # type: ignore[union-attr]
            # Skip README / .gitkeep / future YAML peer files so the
            # parser stays JSON-only by structural guard, not by
            # ``except yaml.YAMLError`` after the fact.
            continue
        try:
            raw = json.loads(blob.data_stream.read())  # type: ignore[union-attr]
            rows.append(GrantRow(**raw))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            # CLAUDE.md hard rule #7: skip-and-log, never silently accept.
            # Only the exception type name (never str(exc) or exc.args) per
            # spec §5.6 — although GrantRow's ValueError carries only
            # closed-domain tier strings, the parser stays disciplined so a
            # future custom exception with richer payload data does not
            # leak into the structured log without re-review.
            _log.warning(
                "capability_gate.rebuild.skip_invalid_grant",
                path=blob.path,  # type: ignore[union-attr]
                error_type=type(exc).__name__,
                commit_hash=commit_hash,
            )
    return frozenset(rows)


__all__ = ["parse_state_git_head"]
