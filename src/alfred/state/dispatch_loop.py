"""Dispatch cycle for side-effecting state.git proposals (ADR-0021).

One :func:`_proposal_dispatch_cycle` invocation = a single tick of the
supervisor's :func:`_proposal_dispatch_loop`. The cycle:

1. **Read the sentinel.** ``processed_proposals_head.head_sha`` is the
   last state.git HEAD the dispatcher walked from. NULL means the
   migration ran but the loop has not bootstrapped — the cycle writes
   ``git rev-parse origin/main`` and returns (forward-from-now
   semantics per ADR-0021 §A6).
2. **HEAD-diff walk.** ``git diff -z <last>..origin/main --diff-filter=A``
   enumerates blobs added between cycles, filtered to the registered
   side-effect type prefixes. Sorted lexicographically so ordering is
   deterministic across filesystems / git versions.
3. **Per blob:** derive ``(proposal_type, proposal_id)`` from the path
   convention ``policies/<type>/<id>.json``; check the ledger PK; parse
   the JSON to a typed payload; verify the path-derived type matches
   ``type(payload).proposal_type``; dispatch to the registered handler;
   record the result + ledger row in the SAME transaction as the
   handler's effect; emit the ``state.proposal.processed`` audit row.
4. **Bump the sentinel** in a separate transaction once every blob in
   the diff batch has been dispatched.

Atomicity model (ADR-0021 §Atomicity, CR rework round-1 CRITICAL #1)
--------------------------------------------------------------------

At-least-once delivery with an **idempotent-handler contract**. The
dispatcher invokes each handler exactly once per ledger row; a crash
between the handler's transaction commit and the framework's ledger
commit causes the next cycle's PK lookup to miss the row and re-invoke
the handler. Because handlers are required to be idempotent
(:data:`alfred.state.dispatch_registry.ProposalHandler` docstring), the
re-invocation produces no observable divergence — the breaker-reset
handler against a CLOSED breaker is a no-op; a future handler MUST be
designed similarly.

Error discipline (ADR-0021 §Consequences):

* Cycle-level infrastructure failure (Postgres outage, git command
  failure, missing repo) → log WARNING, emit
  ``state.proposal.dispatch_cycle_skipped`` audit row, return. NO crash.
  Diverges from ``_capability_heartbeat_loop`` (which propagates into
  the TaskGroup) — the dispatch loop's work is non-critical-path; a
  skipped cycle delays a single operator action by ≤30 s. The heartbeat
  is critical-path. Both emit audit rows — neither is silent.
* Per-blob parse / unknown-type / handler exception → record a ledger
  row + emit ``state.proposal.dispatch_failed``; continue with the
  next blob.

Non-blocking git: every ``subprocess.run`` call is wrapped in
``asyncio.to_thread(...)`` per the precedent at
``src/alfred/security/capability_gate/_gate.py:284``. The supervisor's
event loop never blocks on a git object-DB read.

Path/body type verification: the dispatcher narrows
``type(payload).proposal_type == path_derived_type`` BEFORE invoking
the handler. Mismatch → ``failure_kind="payload_validation"`` ledger
row + handler skipped. Closes the type-confusion vector where a blob's
JSON claims a different type than its path.

DLP redaction of ``failure_detail`` (#173, PR-S4-2). Every failure-row
write runs the failure detail through ``ctx.outbound_dlp.scan(...)``
BEFORE the 512-char truncation (:func:`_redacted_detail`), so a secret
or canary that reached this channel — via ``type(exc).__name__``,
handler-returned reasons, or any future emit site that drops a richer
string here — is redacted (or, on a canary-trip ``HookRefusal``,
refused) before it can land in ``processed_proposals.failure_detail``.
The boundary is truthful regardless of what the call sites pass: the
scan is not opt-out (CLAUDE.md hard rule #4). ``_record_failure`` emits
two **disjoint** audit rows per spec §2.1 — ``state.proposal.failure_detail_redacted``
on success (count >=0) and the Slice-3 ``security.dlp_outbound_refused``
on refusal (which aborts the row insert). A non-``HookRefusal`` scan
exception emits ``state.proposal.dispatch_dlp_scan_failed`` and likewise
aborts the insert.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import re
import subprocess
import uuid
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

import structlog
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.audit.audit_row_schemas import (
    DLP_OUTBOUND_REFUSED_FIELDS,
    PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS,
    PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS,
    STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS,
    STATE_PROPOSAL_DISPATCH_FAILED_FIELDS,
    STATE_PROPOSAL_PROCESSED_FIELDS,
)
from alfred.hooks.errors import HookRefusal
from alfred.memory.models import AuditEntry, ProcessedProposal, ProcessedProposalsHead
from alfred.state.dispatch_registry import (
    PROPOSAL_HANDLERS,
    ProposalContext,
    ProposalHandler,
)
from alfred.state.proposal_payloads import (
    BreakerResetProposal,
    StateGitProposalPayload,
)

# CR rework round-1 CRITICAL #4: refuse blobs whose ``<proposal_id>``
# does not match the writer's :data:`alfred.cli._state_git._PROPOSAL_ID_RE`
# shape (16 lowercase hex chars). A future operator typo or malicious
# branch landing at ``policies/<type>/<128-bytes-of-garbage>.json`` would
# otherwise hit the ``ProcessedProposal.proposal_id`` String(64) limit at
# write time and abort the cycle with a DataError. Refusing at the walk
# is the cheaper, louder boundary — the per-blob ``failed_unknown_type``
# audit row still fires.
_PROPOSAL_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{16}$")


# CR-rework round-2 MAJOR T5: every git subprocess call carries a
# wall-clock timeout. The supervisor's
# :meth:`alfred.supervisor.core.Supervisor.stop` issues an asyncio cancel,
# but :func:`asyncio.to_thread` work cannot be cancelled mid-flight —
# the thread itself ignores the cancellation. Without ``timeout=`` a
# stuck ``git diff`` (e.g. lock file held by another process,
# pack-fetch hang) blocks the cycle indefinitely and the supervisor
# can never drain. 30 seconds gives the local subprocess plenty of
# headroom while still bounding the worst-case stall. On
# ``TimeoutExpired`` the cycle skips loudly with
# ``skip_reason="git_subprocess_timeout"``.
_GIT_SUBPROCESS_TIMEOUT_SECONDS: Final[int] = 30


# CR rework round-1 HIGH #8: closed-vocab narrowing on ``failure_kind``
# alongside the ``ck_processed_proposals_failure_kind`` CHECK constraint.
# A future emit site that drops a new free-form kind here fails at
# type-check time, not at production-cycle Postgres time.
FailureKind = Literal[
    "handler_returned_failed",
    "handler_uncaught_exception",
    "payload_validation",
    "unknown_proposal_type",
    "blob_not_found",
    "handler_timeout",
]

_log = structlog.get_logger(__name__)

# Mapping from on-disk path prefix to the concrete payload class. The
# dispatcher discriminates by the directory under ``policies/``; the
# class drives Pydantic parsing + the ``proposal_type`` ClassVar pin.
# Future side-effecting types widen this in lockstep with
# :data:`alfred.state.dispatch_registry.PROPOSAL_HANDLERS` and the
# writer's :func:`alfred.cli._state_git._on_disk_files_for` branch.
_PATH_PREFIX_TO_PAYLOAD: Mapping[str, type[StateGitProposalPayload]] = {
    "policies/breaker-resets": BreakerResetProposal,
}


@dataclass(frozen=True, slots=True)
class _ProposalBlobRef:
    """A single (added) proposal blob discovered by the HEAD-diff walk."""

    proposal_type: str
    proposal_id: str
    blob_sha: str
    commit_sha: str
    repo_path: Path
    content_path: str  # repo-relative path, e.g. policies/breaker-resets/abc.json


class _PostHandlerAuditFailure(Exception):  # noqa: N818 — internal marker, not exposed
    """Audit emission failed AFTER handler + ledger committed (HIGH #6).

    Raised from :func:`_record_applied` / :func:`_record_failure` when
    ``ctx.audit_writer.append_schema`` raises. The cycle catches this
    and emits :func:`_emit_cycle_skipped` with
    ``skip_reason="audit_write_failed_post_handler"`` before aborting
    the remainder of the batch. The handler effect + ledger row stay
    committed; the next cycle's PK lookup short-circuits the
    just-applied proposal so the audit-emit retry is harmless.
    """


# ---------------------------------------------------------------------------
# Non-blocking git helpers
# ---------------------------------------------------------------------------


async def _git(repo_path: Path, *args: str) -> str:
    """Run ``git -C <repo> <args>`` off the event loop; return stdout.

    Raises :class:`subprocess.CalledProcessError` on non-zero exit,
    :class:`FileNotFoundError` if the repo or the binary is missing,
    and :class:`subprocess.TimeoutExpired` if the git subprocess
    exceeds :data:`_GIT_SUBPROCESS_TIMEOUT_SECONDS`. The cycle catches
    all three and treats them as cycle-level infrastructure failure
    (log+skip + cycle_skipped audit row).

    CR-rework round-2 MAJOR T5: the ``timeout=`` kwarg bounds the
    worst-case stall. Without it a stuck ``git diff`` / ``git show``
    (lock contention, pack-fetch hang) would block the
    :func:`asyncio.to_thread` thread indefinitely; the supervisor's
    cooperative shutdown depends on bounded work per cycle so the
    thread can return and the next ``shutdown_event`` check fires.
    """

    def _run() -> str:
        # S603/S607: ``args`` is always literal git argv constructed by
        # this module; no shell interpolation; no operator-influenced
        # executable. Mirror the discipline in ``_state_git.py``.
        result = subprocess.run(  # noqa: S603
            ["git", "-C", str(repo_path), *args],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=_GIT_SUBPROCESS_TIMEOUT_SECONDS,
        )
        return result.stdout

    return await asyncio.to_thread(_run)


async def _resolve_origin_main(repo_path: Path) -> str:
    """Return the current ``origin/main`` HEAD SHA."""
    out = await _git(repo_path, "rev-parse", "origin/main")
    return out.strip()


async def _walk_added_blobs(
    repo_path: Path,
    last_head: str,
    current_head: str,
) -> list[tuple[str, str, str]]:
    """Return (path, blob_sha, commit_sha) tuples for blobs added in the range.

    The walk surfaces any path matching ``policies/<type>/<id>.json``
    where ``<type>`` is a non-empty segment and ``<id>`` is 16 lowercase
    hex chars (mirrors :data:`alfred.cli._state_git._PROPOSAL_ID_RE`).
    Two consequences:

    * Declarative-projection blobs at ``policies/grants/<plugin>/<id>.json``
      have an EXTRA nested segment and are filtered out at the shape
      check — declarative projection is the gate's job per
      ADR-0021 §Scope.
    * Paths under ``policies/<unknown-type>/<id>.json`` (with a valid
      16-hex id) DO surface so the dispatcher records
      ``failed_unknown_type`` rather than silently ignoring them
      (ADR-0021 §Failure handling + spec §4.3 test).

    Paths whose proposal-id segment fails the regex are dropped at the
    walker without surfacing — they cannot have been written by the
    canonical CLI writer (which validates the id at construction).
    Refusing them here is the cheaper boundary; the alternative is
    hitting the ``ProcessedProposal.proposal_id`` String(64) limit at
    write time (CR rework round-1 CRITICAL #4).

    CR rework round-1 CRITICAL #3: ``commit_sha`` is now the cycle's
    ``current_head`` directly — the head we're walking up to. Every
    blob in this diff window arrived in ``main`` at or before
    ``current_head``; recording ``current_head`` as the commit binds
    the dispatch outcome to the head we ACTED on (the dispatch-time
    HEAD that brought the blob into main), which is the relevant
    forensic key. The previous shape called ``git log
    --diff-filter=A`` per blob to find an introducing-commit SHA;
    that was incorrect (the introducing commit is the operator's
    proposal-branch commit, not the merge commit on main) AND
    introduced N+1 subprocess calls per cycle.

    The walk uses ``-z`` so paths with literal whitespace or shell
    metacharacters cannot smuggle past the parser, and sorts the
    resulting paths lexicographically so two cycles on the same diff
    surface produce the same ordering across filesystems / git
    versions (MEDIUM/LOW from the review).
    """
    if last_head == current_head:
        return []

    out = await _git(
        repo_path,
        "diff",
        "-z",
        f"{last_head}..{current_head}",
        "--name-only",
        "--diff-filter=A",
    )
    # ``-z`` separates paths with a NUL byte and emits NO trailing
    # newline. Splitting on NUL gives an empty final element which we
    # drop.
    paths = [p for p in out.split("\x00") if p]
    paths.sort()

    refs: list[tuple[str, str, str]] = []
    for path in paths:
        # Shape filter — exactly three segments and the leaf is JSON.
        # Declarative-projection blobs (``policies/grants/<plugin>/<id>.json``)
        # have an extra segment and never reach the dispatcher.
        parts = path.split("/")
        if len(parts) != 3 or parts[0] != "policies" or not parts[2].endswith(".json"):
            continue
        proposal_id = parts[2][: -len(".json")]
        if not parts[1] or not proposal_id:
            continue
        # CR rework round-1 CRITICAL #4: enforce the 16-hex shape
        # before the per-blob blob_sha rev-parse — a malformed id
        # cannot have been written by the canonical CLI writer.
        if not _PROPOSAL_ID_RE.fullmatch(proposal_id):
            continue
        # Resolve the blob SHA at the current HEAD's tree.
        blob_sha_raw = await _git(repo_path, "rev-parse", f"{current_head}:{path}")
        blob_sha = blob_sha_raw.strip()
        refs.append((path, blob_sha, current_head))
    return refs


async def _read_blob(repo_path: Path, commit_sha: str, content_path: str) -> str:
    """Return the blob content at ``<commit>:<path>``."""
    return await _git(repo_path, "show", f"{commit_sha}:{content_path}")


# ---------------------------------------------------------------------------
# Cycle
# ---------------------------------------------------------------------------


async def _proposal_dispatch_cycle(
    *,
    ctx: ProposalContext,
    repo_path: Path,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    handlers: Mapping[str, ProposalHandler] | None = None,
) -> None:
    """Run one cycle of the proposal dispatcher.

    Top-level error discipline: log+skip on cycle-level infrastructure
    failure (Postgres outage, git command failure). Per-blob failures
    record a ledger row and continue with the next blob.
    """
    handlers = handlers if handlers is not None else PROPOSAL_HANDLERS
    correlation_id = str(uuid.uuid4())

    try:
        last_head = await _read_sentinel(session_scope)
    except SQLAlchemyError as exc:
        # CR rework round-1 CRITICAL #4: widen the catch from
        # ``OperationalError`` to ``SQLAlchemyError`` so a Postgres-side
        # data violation (a malformed payload landing past the writer's
        # validation that the sentinel read happens to observe) skips
        # the cycle rather than crashing the supervisor task. The
        # subclass name discriminator preserves the operator's view of
        # WHICH SQLAlchemy class failed: ``OperationalError`` ≠
        # connection-refused vs ``DataError`` = oversized column.
        skip_reason = (
            "postgres_unreachable"
            if isinstance(exc, OperationalError)
            else "postgres_data_violation"
        )
        await _emit_cycle_skipped(ctx, skip_reason=skip_reason, correlation_id=correlation_id)
        _log.warning(
            "state.dispatch_cycle.postgres_outage",
            error_type=type(exc).__name__,
            correlation_id=correlation_id,
            exc_info=True,
        )
        return

    try:
        current_head = await _resolve_origin_main(repo_path)
    except subprocess.TimeoutExpired as exc:
        # CR-rework round-2 MAJOR T5: a stuck ``git rev-parse`` (lock
        # file, hung pack-fetch) returns control to the cycle via the
        # ``_GIT_SUBPROCESS_TIMEOUT_SECONDS`` bound. Distinct skip_reason
        # so an operator scrolling the audit graph can tell a stuck
        # process from a missing repo or a malformed argv.
        await _emit_cycle_skipped(
            ctx, skip_reason="git_subprocess_timeout", correlation_id=correlation_id
        )
        _log.warning(
            "state.dispatch_cycle.state_git_timeout",
            error_type=type(exc).__name__,
            correlation_id=correlation_id,
            exc_info=True,
        )
        return
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        await _emit_cycle_skipped(
            ctx, skip_reason="state_git_unreachable", correlation_id=correlation_id
        )
        _log.warning(
            "state.dispatch_cycle.state_git_outage",
            error_type=type(exc).__name__,
            correlation_id=correlation_id,
            exc_info=True,
        )
        return

    if last_head is None:
        # Bootstrap cycle — seed the sentinel, do not process anything.
        try:
            await _bump_sentinel(session_scope, current_head)
        except SQLAlchemyError as exc:
            await _emit_cycle_skipped(
                ctx, skip_reason="postgres_error", correlation_id=correlation_id
            )
            _log.warning(
                "state.dispatch_cycle.sentinel_bootstrap_failed",
                error_type=type(exc).__name__,
                correlation_id=correlation_id,
                exc_info=True,
            )
        return

    try:
        added = await _walk_added_blobs(repo_path, last_head, current_head)
    except subprocess.TimeoutExpired as exc:
        # CR-rework round-2 MAJOR T5: ``git diff``-side timeout. Same
        # disposition as the rev-parse arm above: skip loudly with the
        # ``git_subprocess_timeout`` reason and resume on the next tick.
        await _emit_cycle_skipped(
            ctx, skip_reason="git_subprocess_timeout", correlation_id=correlation_id
        )
        _log.warning(
            "state.dispatch_cycle.walk_timeout",
            error_type=type(exc).__name__,
            correlation_id=correlation_id,
            exc_info=True,
        )
        return
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        await _emit_cycle_skipped(
            ctx, skip_reason="state_git_unreachable", correlation_id=correlation_id
        )
        _log.warning(
            "state.dispatch_cycle.walk_failed",
            error_type=type(exc).__name__,
            correlation_id=correlation_id,
            exc_info=True,
        )
        return

    for path, blob_sha, commit_sha in added:
        ref = _build_blob_ref(path, blob_sha, commit_sha, repo_path)
        if ref is None:  # pragma: no cover — _walk_added_blobs filtered earlier
            # Path is registered but does not match the expected shape
            # ``policies/<type>/<id>.json``. Treated like an unknown type.
            continue
        try:
            await _dispatch_one(ctx, ref, session_scope, handlers, correlation_id)
        except _PostHandlerAuditFailure as exc:
            # HIGH #6: audit emit failed AFTER the handler effect +
            # ledger row committed. We cannot roll back the handler;
            # we must abort the rest of the cycle so the sentinel
            # stays at the old head. The next cycle's PK lookup will
            # short-circuit the just-applied proposal (idempotency
            # via the ledger row), so the audit-emit retry is
            # harmless. ``_emit_cycle_skipped`` is also best-effort
            # (if the audit writer is the failure mode it will hit
            # the same exception path again — that case downgrades to
            # a structlog WARNING per HIGH #9).
            await _emit_cycle_skipped(
                ctx,
                skip_reason="audit_write_failed_post_handler",
                correlation_id=correlation_id,
            )
            _log.warning(
                "state.dispatch_cycle.audit_emit_failed_post_handler",
                error_type=type(exc.__cause__).__name__ if exc.__cause__ else type(exc).__name__,
                correlation_id=correlation_id,
                exc_info=True,
            )
            return
        except SQLAlchemyError as exc:  # pragma: no cover — covered by dispatcher tests
            # A per-blob SQLAlchemy failure (connection lost mid-cycle
            # OR a data-violation hit at the ledger insert) is treated
            # as cycle-level infrastructure failure — skip the rest of
            # the cycle so we do not bump the sentinel past
            # unprocessed blobs. Same subclass discriminator as the
            # sentinel-read branch above.
            skip_reason = (
                "postgres_unreachable"
                if isinstance(exc, OperationalError)
                else "postgres_data_violation"
            )
            await _emit_cycle_skipped(ctx, skip_reason=skip_reason, correlation_id=correlation_id)
            _log.warning(
                "state.dispatch_cycle.postgres_outage_during_blob",
                error_type=type(exc).__name__,
                correlation_id=correlation_id,
                exc_info=True,
            )
            return

    try:
        await _bump_sentinel(session_scope, current_head)
    except SQLAlchemyError as exc:
        await _emit_cycle_skipped(ctx, skip_reason="postgres_error", correlation_id=correlation_id)
        _log.warning(
            "state.dispatch_cycle.sentinel_bump_failed",
            error_type=type(exc).__name__,
            correlation_id=correlation_id,
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# Cycle helpers
# ---------------------------------------------------------------------------


async def _read_sentinel(
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> str | None:
    """Return the sentinel ``head_sha`` (NULL → None)."""
    async with session_scope() as session:
        row = (
            await session.execute(
                select(ProcessedProposalsHead).where(ProcessedProposalsHead.id == 1)
            )
        ).scalar_one()
        return row.head_sha


async def _bump_sentinel(
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    new_head: str,
) -> None:
    """Update the sentinel row in a separate transaction.

    Atomicity model per ADR-0021 §Atomicity: handler effect + ledger
    insert commit together; sentinel bump commits afterward. Crash
    between the two is provably safe.
    """
    async with session_scope() as session:
        row = (
            await session.execute(
                select(ProcessedProposalsHead).where(ProcessedProposalsHead.id == 1)
            )
        ).scalar_one()
        row.head_sha = new_head
        row.updated_at = dt.datetime.now(dt.UTC)


def _build_blob_ref(
    path: str,
    blob_sha: str,
    commit_sha: str,
    repo_path: Path,
) -> _ProposalBlobRef | None:
    """Derive ``(proposal_type, proposal_id)`` from a ``policies/<type>/<id>.json`` path.

    Registered types map to the canonical ``proposal_type`` (the ClassVar
    on the payload subclass). Unregistered types pass through with the
    raw directory name as ``proposal_type`` so the dispatcher records a
    ``failed_unknown_type`` ledger row rather than silently dropping the
    blob (ADR-0021 §Failure handling).

    Returns None only on a shape-failure path (extra nested directory,
    missing JSON extension) — that filter already runs in
    ``_walk_added_blobs`` so this branch is defensive.
    """
    parts = path.split("/")
    if len(parts) != 3 or not parts[2].endswith(".json"):  # pragma: no cover — filtered earlier
        return None
    dir_name = parts[1]
    proposal_id = parts[2][: -len(".json")]
    proposal_type_prefix = f"{parts[0]}/{dir_name}"
    payload_cls = _PATH_PREFIX_TO_PAYLOAD.get(proposal_type_prefix)
    proposal_type = payload_cls.proposal_type if payload_cls is not None else dir_name
    return _ProposalBlobRef(
        proposal_type=proposal_type,
        proposal_id=proposal_id,
        blob_sha=blob_sha,
        commit_sha=commit_sha,
        repo_path=repo_path,
        content_path=path,
    )


async def _dispatch_one(
    ctx: ProposalContext,
    ref: _ProposalBlobRef,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    handlers: Mapping[str, ProposalHandler],
    correlation_id: str,
) -> None:
    """Dispatch a single blob; record ledger + emit audit row.

    All per-blob failure paths (parse / unknown-type / handler raise /
    handler returns failed) leave a ledger row + an audit row but do
    NOT raise — the next blob in the cycle still runs.
    :class:`SQLAlchemyError` propagates so the cycle short-circuits
    without bumping the sentinel; ``_PostHandlerAuditFailure``
    propagates so the loop can emit ``audit_write_failed_post_handler``.

    Idempotent-handler contract per ADR-0021 §Atomicity (CR rework
    round-1 CRITICAL #1): a crash between the handler's transaction
    commit and the framework's ledger commit causes the next cycle to
    re-invoke the handler against the same payload; the handler must
    produce no observable divergence on re-apply.
    """
    # Replay safety — composite PK lookup BEFORE any handler invocation.
    async with session_scope() as session:
        existing = (
            await session.execute(
                select(ProcessedProposal).where(
                    ProcessedProposal.proposal_type == ref.proposal_type,
                    ProcessedProposal.proposal_id == ref.proposal_id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return

    # Handler lookup. Path-derived type that has no registered handler
    # lands in the ledger as ``failed_unknown_type`` — the closed
    # discriminator-vocab guard against silent drops (CLAUDE.md hard
    # rule #7).
    handler = handlers.get(ref.proposal_type)
    if handler is None:
        await _record_failure(
            ctx,
            ref,
            session_scope,
            result="failed_unknown_type",
            failure_kind="unknown_proposal_type",
            failure_detail=None,
            operator_user_id=None,
            correlation_id=correlation_id,
            framework_error_kind="unknown_proposal_type",
        )
        return

    # CR rework round-1 MEDIUM/LOW: the dead-code defensive arm that
    # repeated the ``failed_unknown_type`` write when ``payload_cls``
    # was ``None`` is dropped — the ``handler is None`` check above
    # already filtered every discriminator not in the
    # :data:`_PATH_PREFIX_TO_PAYLOAD` registry (same source of truth).
    # If a future refactor desynchronises the two registries this
    # ``next(...)`` raises ``StopIteration`` and the cycle surfaces
    # the bug loudly instead of swallowing it.
    payload_cls: type[StateGitProposalPayload] = next(
        cls for cls in _PATH_PREFIX_TO_PAYLOAD.values() if cls.proposal_type == ref.proposal_type
    )

    try:
        raw = await _read_blob(ref.repo_path, ref.commit_sha, ref.content_path)
    except (
        subprocess.CalledProcessError,
        FileNotFoundError,
        OSError,
    ):  # pragma: no cover — race-condition path; blob existed at walk time
        await _record_failure(
            ctx,
            ref,
            session_scope,
            result="failed_parse",
            failure_kind="blob_not_found",
            failure_detail=None,
            operator_user_id=None,
            correlation_id=correlation_id,
            framework_error_kind="blob_not_found",
        )
        return

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        await _record_failure(
            ctx,
            ref,
            session_scope,
            result="failed_parse",
            failure_kind="payload_validation",
            failure_detail=type(exc).__name__,
            operator_user_id=None,
            correlation_id=correlation_id,
            framework_error_kind="payload_validation",
        )
        return

    try:
        payload = payload_cls.model_validate(parsed)
    except ValidationError as exc:
        await _record_failure(
            ctx,
            ref,
            session_scope,
            result="failed_parse",
            failure_kind="payload_validation",
            # CR rework round-1 CRITICAL #2: ``ValidationError`` carries
            # the malformed input verbatim — never let that string near
            # the ledger. Use the exception class name (closed vocab,
            # zero T3 surface). #173 / PR-S4-2: ``_record_failure`` now
            # runs ``ctx.outbound_dlp.scan(...)`` over this value before
            # the ledger write regardless, so the boundary stays truthful
            # even if a future emit site widens what it passes here.
            failure_detail=type(exc).__name__,
            operator_user_id=None,
            correlation_id=correlation_id,
            framework_error_kind="payload_validation",
        )
        return

    # CR rework round-1 MEDIUM/LOW + test #3 + holistic #4: the
    # path/body type verification ``type(payload).proposal_type !=
    # ref.proposal_type`` was a defensive arm marked
    # ``# pragma: no cover``. Per
    # :data:`_PATH_PREFIX_TO_PAYLOAD` construction the two values come
    # from the same source — the only way the arm fires is via a
    # programmer-introduced refactor that desynchronises the two
    # registries, and that surface is already covered by the dead-code
    # path above (which raises ``StopIteration``). Dropped to keep the
    # branch-coverage surface honest.

    operator_user_id: str | None = getattr(payload, "operator_user_id", None)

    # Run the handler. ADR-0021 §Atomicity (revised per CR rework
    # round-1 CRITICAL #1): the framework guarantees at-least-once
    # dispatch + replay safety via the composite-PK lookup above; the
    # handler MUST be idempotent so a re-invocation after a crash
    # between handler-commit and ledger-commit is safe.
    try:
        outcome = await handler(payload, ctx)
    except Exception as exc:
        await _record_failure(
            ctx,
            ref,
            session_scope,
            result="failed_handler",
            failure_kind="handler_uncaught_exception",
            failure_detail=type(exc).__name__,
            operator_user_id=operator_user_id,
            correlation_id=correlation_id,
            framework_error_kind="handler_uncaught_exception",
        )
        return

    if outcome.kind == "applied":
        await _record_applied(
            ctx,
            ref,
            session_scope,
            operator_user_id=operator_user_id,
            correlation_id=correlation_id,
        )
        return

    # outcome.kind == "failed_handler"
    await _record_failure(
        ctx,
        ref,
        session_scope,
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail=outcome.reason or "",
        operator_user_id=operator_user_id,
        correlation_id=correlation_id,
        framework_error_kind=None,
    )


async def _record_applied(
    ctx: ProposalContext,
    ref: _ProposalBlobRef,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    *,
    operator_user_id: str | None,
    correlation_id: str,
) -> None:
    """Insert the ledger row + emit the processed audit row for applied outcome.

    HIGH #6: the audit-emit step is wrapped — a failure here lands
    AFTER the handler effect + ledger row committed. We cannot roll
    back the handler; instead we raise :class:`_PostHandlerAuditFailure`
    so the cycle aborts the remainder of the batch loudly via
    :func:`_emit_cycle_skipped`. Next cycle's PK lookup short-circuits
    the just-applied proposal (idempotency invariant per ADR-0021
    §Atomicity), so the retry is harmless.
    """
    processed_at = dt.datetime.now(dt.UTC)
    async with session_scope() as session:
        session.add(
            ProcessedProposal(
                proposal_type=ref.proposal_type,
                proposal_id=ref.proposal_id,
                blob_sha=ref.blob_sha,
                commit_sha=ref.commit_sha,
                processed_at=processed_at,
                result="applied",
                handler_version=1,
                failure_kind=None,
                failure_detail=None,
                operator_user_id=operator_user_id,
            )
        )

    try:
        await ctx.audit_writer.append_schema(
            fields=STATE_PROPOSAL_PROCESSED_FIELDS,
            schema_name="STATE_PROPOSAL_PROCESSED_FIELDS",
            event="state.proposal.processed",
            actor_user_id=operator_user_id,
            actor_persona="supervisor",
            subject={
                "proposal_type": ref.proposal_type,
                "proposal_id": ref.proposal_id,
                "result": "applied",
                "failure_kind": None,
                "handler_version": 1,
                "processed_at": processed_at.isoformat(),
                "operator_user_id": operator_user_id,
                "commit_sha": ref.commit_sha,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T1",
            result="success",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=correlation_id,
        )
    except Exception as exc:
        raise _PostHandlerAuditFailure("audit emit failed after applied-row commit") from exc


async def _emit_dlp_outbound_refused(
    ctx: ProposalContext,
    ref: _ProposalBlobRef,
    refusal: HookRefusal,
    *,
    correlation_id: str,
) -> None:
    """Emit the Slice-3 ``DLP_OUTBOUND_REFUSED_FIELDS`` row on a canary-trip refusal.

    sec-004: ``OutboundDlp.scan`` raised :class:`HookRefusal` (the canary
    stage said no-write). No ``ProcessedProposal`` row is inserted — the
    failure detail is too dangerous to land even truncated. The refusal
    row reuses the Slice-3 constant verbatim so the audit-graph reads the
    proposal-dispatch refusal on the same wire as the stdio-transport
    refusal (``security.dlp_outbound_refused``).

    An audit-emit failure here raises :class:`_PostHandlerAuditFailure` so
    the cycle aborts loudly (CLAUDE.md #7) — narrowed to the DB-write
    family per err-001 so a programmer error in the subject propagates.
    """
    try:
        await ctx.audit_writer.append_schema(
            fields=DLP_OUTBOUND_REFUSED_FIELDS,
            schema_name="DLP_OUTBOUND_REFUSED_FIELDS",
            event="security.dlp_outbound_refused",
            actor_user_id=None,
            actor_persona="supervisor",
            subject={
                "wire": "proposal_dispatch_failure",
                "direction": "outbound",
                "scan_rule_matched": refusal.reason,
                "field_name": "failure_detail",
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T1",
            result="refused",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=correlation_id,
        )
    except SQLAlchemyError as exc:
        raise _PostHandlerAuditFailure("audit emit failed during DLP outbound refusal") from exc
    _log.warning(
        "state.dispatch.failure_detail_dlp_refused",
        proposal_type=ref.proposal_type,
        proposal_id=ref.proposal_id,
        scan_rule_matched=refusal.reason,
        correlation_id=correlation_id,
    )


async def _emit_dlp_scan_failed(
    ctx: ProposalContext,
    ref: _ProposalBlobRef,
    exc: Exception,
    *,
    correlation_id: str,
) -> None:
    """Emit ``PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS`` on a non-refusal scan fault.

    err-003: ``OutboundDlp.scan`` raised something other than
    :class:`HookRefusal` (a regex-engine fault, an encoding error in a
    stage). A scanner whose output we cannot trust MUST NOT let unscanned
    bytes reach the ledger, so the row insert is aborted. Only the
    exception CLASS name is carried (``scan_error_type``) — the message is
    never persisted, keeping the row free of any T3 surface the scan was
    meant to catch.
    """
    try:
        await ctx.audit_writer.append_schema(
            fields=PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS,
            schema_name="PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS",
            event="state.proposal.dispatch_dlp_scan_failed",
            actor_user_id=None,
            actor_persona="supervisor",
            subject={
                "proposal_branch": ref.content_path,
                "dispatch_attempted_at": dt.datetime.now(dt.UTC).isoformat(),
                "failure_class": "dlp_scan_error",
                "scan_error_type": type(exc).__name__,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T1",
            result="refused",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=correlation_id,
        )
    except SQLAlchemyError as audit_exc:
        raise _PostHandlerAuditFailure(
            "audit emit failed during DLP scan-failed abort"
        ) from audit_exc


def _validate_subject_keys(subject: Mapping[str, object], fields: frozenset[str]) -> None:
    """Symmetric key-validation mirroring ``AuditWriter.append_schema``.

    The same security guard the writer applies (missing OR extra key →
    raise) re-applied here because the #173 redacted row is written
    INSIDE the ledger session (err-002 transactional lockstep) rather
    than through ``append_schema``'s own-session path. A typo'd field or
    an accidental T3 fragment in the subject fails loudly at the emit
    site rather than persisting an off-contract JSONB blob.
    """
    missing = fields - subject.keys()
    extra = subject.keys() - fields
    if missing or extra:
        msg = (
            f"failure-detail redacted audit subject mismatch: "
            f"missing={sorted(missing)!r} extra={sorted(extra)!r}; "
            f"declared fields are {sorted(fields)!r}"
        )
        raise ValueError(msg)


async def _record_failure(
    ctx: ProposalContext,
    ref: _ProposalBlobRef,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    *,
    result: str,
    # HIGH #8: closed-vocab narrowing alongside the
    # ``ck_processed_proposals_failure_kind`` CHECK constraint.
    failure_kind: FailureKind,
    failure_detail: str | None,
    operator_user_id: str | None,
    correlation_id: str,
    framework_error_kind: str | None,
) -> None:
    """Insert the ledger row + emit processed-or-failed audit row for a failure path.

    DLP boundary (#173 / PR-S4-2). Before the ledger insert, ``failure_detail``
    is run through ``ctx.outbound_dlp.scan(...)`` and then truncated by
    :func:`_redacted_detail`:

    * **clean / redacted** → the redacted text lands in the ledger and a
      ``PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS`` row is written IN THE
      SAME session as the ledger insert (err-002 transactional lockstep:
      the ledger row and its audit twin commit atomically, so an
      audit-emit failure rolls back the ledger row and the cycle retries).
    * **canary-trip ``HookRefusal``** → the row insert is ABORTED, a
      Slice-3 ``DLP_OUTBOUND_REFUSED_FIELDS`` row is emitted, and the
      function returns without landing a ledger row (sec-004).
    * **other scan exception** → ABORTED, a
      ``PROPOSAL_DISPATCH_DLP_SCAN_FAILED_FIELDS`` row is emitted carrying
      only the exception CLASS name (no T3 surface), and the function
      returns (err-003).

    Audit-emit failures on the trailing PROCESSED / DISPATCH_FAILED row
    land in :class:`_PostHandlerAuditFailure` per HIGH #6 — handler-returned
    -failed cases hold the same ledger-row invariant as the applied path.
    """
    # --- DLP scan the failure detail BEFORE it can reach the ledger. ---
    dlp_redactions_count = 0
    scanned_detail: str | None
    if failure_detail is None:
        scanned_detail = None
    else:
        try:
            scanned = ctx.outbound_dlp.scan(failure_detail)
        except HookRefusal as refusal:
            await _emit_dlp_outbound_refused(ctx, ref, refusal, correlation_id=correlation_id)
            return
        except Exception as exc:
            await _emit_dlp_scan_failed(ctx, ref, exc, correlation_id=correlation_id)
            return
        if scanned != failure_detail:
            dlp_redactions_count = 1
        scanned_detail = _redacted_detail(scanned)

    processed_at = dt.datetime.now(dt.UTC)

    # err-002 transactional lockstep: the ledger row AND its
    # PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS audit twin land in the SAME
    # session so they commit atomically. If the audit row write raises, the
    # session context manager rolls BOTH back and the cycle retries next
    # tick (sentinel unbumped). This is the one audit row that must NOT use
    # AuditWriter's own-session path — a ledger row landing without its
    # redaction-accounting twin is silent divergence (CLAUDE.md #7).
    redacted_subject: dict[str, object] = {
        "proposal_branch": ref.content_path,
        "dispatch_attempted_at": processed_at.isoformat(),
        "failure_class": failure_kind,
        "redacted_detail": scanned_detail if scanned_detail is not None else "",
        "dlp_redactions_count": dlp_redactions_count,
        "correlation_id": correlation_id,
    }
    _validate_subject_keys(redacted_subject, PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS)
    async with session_scope() as session:
        session.add(
            ProcessedProposal(
                proposal_type=ref.proposal_type,
                proposal_id=ref.proposal_id,
                blob_sha=ref.blob_sha,
                commit_sha=ref.commit_sha,
                processed_at=processed_at,
                result=result,
                handler_version=1,
                failure_kind=failure_kind,
                failure_detail=scanned_detail,
                operator_user_id=operator_user_id,
            )
        )
        # sec-001: the redacted row's result mirrors the DLP OUTCOME, never
        # "refused" (that value is reserved for DLP_OUTBOUND_REFUSED_FIELDS).
        session.add(
            AuditEntry(
                trace_id=correlation_id,
                event="state.proposal.failure_detail_redacted",
                actor_user_id=operator_user_id,
                actor_persona="supervisor",
                subject=redacted_subject,
                trust_tier_of_trigger="T1",
                result=(
                    "dispatched_with_redactions" if dlp_redactions_count > 0 else "dispatched_clean"
                ),
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
            )
        )

    # ``handler_returned_failed`` is operator-caused so it lands on
    # the PROCESSED row family; everything else lands on
    # DISPATCH_FAILED with the framework_error_kind discriminator.
    try:
        if framework_error_kind is None:
            await ctx.audit_writer.append_schema(
                fields=STATE_PROPOSAL_PROCESSED_FIELDS,
                schema_name="STATE_PROPOSAL_PROCESSED_FIELDS",
                event="state.proposal.processed",
                actor_user_id=operator_user_id,
                actor_persona="supervisor",
                subject={
                    "proposal_type": ref.proposal_type,
                    "proposal_id": ref.proposal_id,
                    "result": result,
                    "failure_kind": failure_kind,
                    "handler_version": 1,
                    "processed_at": processed_at.isoformat(),
                    "operator_user_id": operator_user_id,
                    "commit_sha": ref.commit_sha,
                    "correlation_id": correlation_id,
                },
                trust_tier_of_trigger="T1",
                result="refused",
                cost_estimate_usd=0.0,
                cost_actual_usd=0.0,
                trace_id=correlation_id,
            )
            return

        await ctx.audit_writer.append_schema(
            fields=STATE_PROPOSAL_DISPATCH_FAILED_FIELDS,
            schema_name="STATE_PROPOSAL_DISPATCH_FAILED_FIELDS",
            event="state.proposal.dispatch_failed",
            actor_user_id=operator_user_id,
            actor_persona="supervisor",
            subject={
                "proposal_type": ref.proposal_type,
                "proposal_id": ref.proposal_id,
                "result": result,
                "failure_kind": failure_kind,
                "framework_error_kind": framework_error_kind,
                "handler_version": 1,
                "processed_at": processed_at.isoformat(),
                "operator_user_id": operator_user_id,
                "commit_sha": ref.commit_sha,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T1",
            result="refused",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=correlation_id,
        )
    except SQLAlchemyError as exc:
        # err-001: narrow to the DB-write failure family. The audit row's
        # own session flush is the only thing that can fail here for an
        # infrastructure reason; a ValueError/TypeError from a wrong-shape
        # subject is a programmer error and MUST propagate loud (a typo in
        # the emit site is a bug, not a transient audit-writer outage).
        raise _PostHandlerAuditFailure("audit emit failed after failure-row commit") from exc


async def _emit_cycle_skipped(
    ctx: ProposalContext,
    *,
    skip_reason: str,
    correlation_id: str,
) -> None:
    """Emit the cycle_skipped audit row (no per-proposal fields).

    CR rework round-1 HIGH #9: the audit-writer-itself-is-down branch
    logs with ``exc_info=True`` and ``error_type`` so the operator's
    structlog stream carries the underlying cause. This is the
    explicit "audit-writer is the failure" exception to CLAUDE.md
    hard rule #7 ("no silent failures in security paths") — when the
    audit graph itself is unavailable the structlog WARNING is the
    only forensic signal we can emit; not propagating keeps the
    dispatch task alive so the next cycle retries.
    """
    try:
        await ctx.audit_writer.append_schema(
            fields=STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS,
            schema_name="STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS",
            event="state.proposal.dispatch_cycle_skipped",
            actor_user_id=None,
            actor_persona="supervisor",
            subject={
                "skip_reason": skip_reason,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="refused",
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=correlation_id,
        )
    except Exception as exc:  # pragma: no cover — audit writer is healthy in tests
        # CLAUDE.md hard rule #7 documented exception: when the audit
        # writer itself is the failing surface, the forensic loudness
        # falls back to structlog. The ``exc_info=True`` keeps the
        # underlying traceback in the dev log so the operator can
        # diagnose the audit-writer outage.
        _log.warning(
            "state.dispatch_cycle.audit_emit_failed_on_skip",
            skip_reason=skip_reason,
            correlation_id=correlation_id,
            error_type=type(exc).__name__,
            exc_info=True,
        )


def _redacted_detail(text: str) -> str:
    """Truncate DLP-scanned text bound for the ``failure_detail`` column.

    This helper is **only the truncation step**. Callers MUST run
    ``ctx.outbound_dlp.scan(text)`` BEFORE passing text here — the DLP
    scan happens at the :func:`_record_failure` call site, not inside this
    helper, so the single-purpose truncate stays trivially testable and
    audit-graphable (#173, PR-S4-2).

    The name is now truthful: the text reaching this helper has already
    been through :meth:`alfred.security.dlp.OutboundDlp.scan` (broker
    redaction + generic-API-key regex + canary stage), so what lands in
    ``processed_proposals.failure_detail`` carries no secret bytes. Before
    PR-S4-2 this helper was misleadingly named ``_redacted_detail`` while
    only truncating (CR rework round-1 CRITICAL #2 / #173); the scan is
    now wired so the name is accurate.

    The 512-char truncation matches ``ProcessedProposal.failure_detail``'s
    String(512) column width; an overlong (post-redaction) input gets the
    same shape Postgres would refuse with at insert time, just at the
    Python layer so the cycle's audit emit doesn't fail with a DataError.
    """
    return text[:512]


__all__ = [
    "_proposal_dispatch_cycle",
]
