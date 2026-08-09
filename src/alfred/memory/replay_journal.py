"""Deterministic tool-call replay journal (#410 PR2).

On the forwarded dispatched-edge path, a crash between "the planner decided
to call these tools" and `commit_once` leaves the frame uncommitted, so it
replays (ADR-0039 item 4). Without this journal, a resumed
:meth:`Orchestrator._orient_and_act` would ask the planner AGAIN for a fresh,
possibly non-deterministic plan — the Spec C egress ledger's body-hash
integrity check (`src/alfred/memory/egress_idempotency.py:220`) then either
catches a genuine divergence loudly (`EgressIdIntegrityError`) or, worse, if
the resumed plan happens to omit a call the original attempt already fired
for real, silently drops that already-applied side effect from the resumed
turn's accounting.

This journal records the COMMITTED ordered dispatch decision —
``(adapter_id, inbound_id, call_index) -> (iteration, ToolCall)`` — as the Act
loop makes it, in ONE atomic write per ITERATION, covering every call that
iteration's completion requested, BEFORE any of them is dispatched (never
after, and never one row per call: recording the whole iteration's decision
atomically and early is what lets a resume fast-forward through it even if
the crash happened mid-dispatch of that SAME iteration — a per-call write
would leave a crash-window where a later call in the same iteration is
dispatched for real but never durably recorded, silently vanishing from any
resumed replay; found during the `/review-plan` fleet's second pass,
2026-08-07). ``ToolCall`` (id, name, arguments,
:class:`alfred.providers.base.ToolCall`) is the identity `dispatch_tool`
already receives for ANY tool — NOT
:func:`alfred.egress.egress_id.compute_request_descriptor`, which is
internal to web.fetch's own extraction path and has no meaning for
`clock.now`. ``iteration`` is additionally stored so a replay can
reconstruct the tool-call/tool-result message grouping faithfully (a single
assistant completion can request multiple tool calls at once).

**Composite ``(adapter_id, inbound_id, call_index)`` key, not ``(inbound_id,
call_index)`` alone** (a #410 design correction found during the
`/review-plan` fleet pass, the same root cause as PR1's `TurnSideEffectLedger`
finding, independently repeated in this table's first draft): ``inbound_id``
is a free-form, per-adapter-minted opaque string
(``src/alfred/comms_mcp/protocol.py``) — a two-column key would let two
DIFFERENT adapters' turns collide on the same ``inbound_id`` string and splice
one turn's already-decided tool calls into a DIFFERENT turn's reconstructed
transcript, corrupting the privileged LLM's belief about its own conversation
history.

Durable-across-restart on purpose, same rationale as every sibling ledger in
this module (`forwarded_dispatch_attempts.py`, `turn_side_effects.py`): the
forwarded-edge replay happens ACROSS core restarts.

``tool_arguments`` is stored as an explicit JSON-serialized TEXT column, not
a native JSONB column — this codebase has no established precedent for a
raw-``sa.text()`` JSONB round-trip. ``PoliciesSnapshotHistory.policies_json``
(migration 0013, ``src/alfred/memory/models.py:656``) is the only genuinely
JSONB-typed precedent, and it too goes through the declarative ORM, not raw
SQL (``src/alfred/policies/snapshot_ref.py:224``) — ``AuditEntry.subject`` is
plain ``sa.JSON`` with no JSONB dialect variant, so it isn't a JSONB
precedent at all (corrected during the `/review-plan` fleet's second pass,
2026-08-07: an earlier draft of this docstring miscounted it as one). Either
way, asyncpg's default JSON(B) codec behavior is not something to gamble on
without a raw-SQL integration-tested precedent, which this codebase has none
of. Explicit ``json.dumps``/``json.loads``
in Python is simple, safe, and dialect-independent. The column carries a
size-cap CHECK constraint (Task 2) matching the codebase's other JSON
payload columns (e.g. migration 0013's 256 KB cap) — a tool-call argument
payload is attacker-influenced (a T3-derived planner decision), so an
unbounded column would be a real storage-exhaustion surface.

**Accepted, documented gap: this journal provides NO dedup protection for
`InternalToolSpec` tools** (found during `/review-plan`) — only
`ExternalToolSpec` (web.fetch) is wired to the Spec C
`compute_egress_id`/memoize-and-replay ledger. A replayed `InternalToolSpec`
call (e.g. `clock.now`, PR3's only live tool) re-dispatches for real on every
fast-forward, with no dedup at all. Safe today only because `clock.now` is
side-effect-free by construction — this is a convention, not a
type/registry-enforced guarantee, and a future `InternalToolSpec` with real
side effects would inherit this gap silently.

**Two concrete consequences of the gap above (found during the
`/review-plan` fleet's second pass, 2026-08-07):**

1. **Audit-log duplication.** `dispatch_tool` writes a `tool.dispatch` audit
   row on every dispatch, replay included (Task 4's fast-forward calls the
   SAME `dispatch_tool`). A turn that crashes and retries N times before a
   successful send produces N `tool.dispatch` rows for the SAME logical
   call — identical `trace_id`, `call_index`, and `tool_call_id` — each
   independently claiming a successful dispatch. Not a security or
   cost-accounting issue, but an `alfred audit graph` reader for a resumed
   turn should not be misled into seeing apparent duplicate successful
   dispatches as N distinct events. No test in this plan drives a
   multi-attempt replay to observe or pin this behaviour — a future PR
   adding a second `InternalToolSpec` tool should account for it, e.g. by
   threading a replay marker into the audit subject on the fast-forward
   path or adding a test that drives two replay attempts and asserts on the
   resulting audit-row count.
2. **Precedent risk.** Nothing in `ToolRegistry`, `InternalToolSpec`, or
   `FIRST_PARTY_LE_T2_TOOL_ALLOWLIST` (`tool_registry.py:26`) enforces "this
   tool's dispatch has no side effects" as a property distinct from "this
   tool is first-party and its `result_tier` claim is T2." A future
   `InternalToolSpec` tool with real side effects could be added to that
   allowlist and silently inherit this same no-dedup-on-replay gap — this
   time with real consequences on a forwarded-path resume-storm. This
   docstring is currently the only place the gap is written down; PR3
   Task 2a closes a DIFFERENT, related gap on the same branch (the missing
   DLP scan) — whoever adds the second `InternalToolSpec` tool should also
   relocate or duplicate this accepted-risk note onto `InternalToolSpec`'s
   own docstring in `tool_registry.py`, visible at the point that future
   decision is actually made, rather than only here.

**Invariant (disputed severity during `/review-plan` — security-engineer
rated High, comms-engineer rated Low; both agreed this pinning matters
regardless): `tool_arguments_json` NEVER contains a resolved secret value,
only an unresolved `{{secret:name}}` placeholder if one is present.** This
holds STRUCTURALLY, not by luck of call ordering: `Orchestrator._orient_and_act`
(Task 4) calls `self._replay_journal.append_batch(...)` with the planner's raw
`ToolCall`s BEFORE any of that iteration's `dispatch_tool` calls run at all
— broker secret substitution happens INSIDE a tool's own dispatcher
(e.g. `dispatch_web_fetch`'s Step 1c),
strictly downstream of the journal write, and writes the resolved value into
a local dict that is never round-tripped back into `call.arguments`. Task 4
pins this with a regression test. If a FUTURE refactor ever moved secret
substitution earlier (e.g. into a shared pre-dispatch step `dispatch_tool`
itself owns), this invariant would need re-verifying — it is a property of
the CURRENT call order, not an enforced type-level guarantee.

A genuine DB failure (``SQLAlchemyError``) PROPAGATES — never caught.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.providers.base import ToolCall

__all__ = [
    "JournalEntry",
    "PostgresReplayJournal",
    "ReplayJournal",
]

_APPEND_SQL = sa.text(
    "INSERT INTO tool_call_journal "
    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, tool_name, "
    "tool_arguments_json) "
    "VALUES (:adapter_id, :inbound_id, :call_index, :iteration, :tool_call_id, "
    ":tool_name, :tool_arguments_json)"
)

_READ_SQL = sa.text(
    "SELECT call_index, iteration, tool_call_id, tool_name, tool_arguments_json "
    "FROM tool_call_journal WHERE adapter_id = :adapter_id AND inbound_id = :inbound_id "
    "ORDER BY call_index ASC"
)


@dataclass(frozen=True, slots=True)
class JournalEntry:
    call_index: int
    iteration: int
    tool_call: ToolCall


@runtime_checkable
class ReplayJournal(Protocol):
    """Durable per-``(adapter_id, inbound_id)`` ordered log of committed tool-dispatch decisions."""

    async def append_batch(
        self,
        *,
        adapter_id: str,
        inbound_id: str,
        iteration: int,
        calls: Sequence[tuple[int, ToolCall]],
    ) -> None:
        """Record an ENTIRE iteration's tool-dispatch decisions atomically, before dispatch.

        Durable and deterministic: provides replay safety across restarts.

        ``calls`` is the ``(call_index, ToolCall)`` pairs the planner's
        completion requested for THIS iteration, in call order. All of them
        commit in ONE transaction. Deliberately NOT a single-call primitive
        (a #410 design correction found during the `/review-plan` fleet's
        second pass, 2026-08-07): a per-call write would leave a crash
        window between journaling call N and call N+1 of the SAME
        iteration, after which a resume's fast-forward — which groups
        entries by iteration and assumes each group is COMPLETE — would
        silently believe the iteration only ever requested N calls,
        dropping the un-journalled tail forever. Journalling the whole
        iteration atomically means a crash mid-iteration either leaves it
        fully recorded or not recorded at all, so a resume correctly falls
        back to full re-planning of that iteration in the latter case
        instead of silently truncating it.

        Raises:
            ValueError: if ``calls`` is empty. An empty batch is a caller
                contract violation (review-pr fleet, 2026-08-11) — the sole
                production caller only invokes this when the planner
                actually requested tool calls, and SQLAlchemy 2.0 silently
                no-ops ``session.execute(stmt, [])`` rather than raising, so
                an empty batch would otherwise vanish without a trace
                instead of failing loud (CLAUDE.md hard rule #7).
        """
        ...

    async def read(self, *, adapter_id: str, inbound_id: str) -> tuple[JournalEntry, ...]:
        """Return journalled entries for ``(adapter_id, inbound_id)``, ordered by ``call_index``.

        Returns ``()`` if none exist (the overwhelmingly common case — every
        first-ever attempt, and every direct/fixture call with its
        always-fresh synthesized ``inbound_id``).
        """
        ...


class PostgresReplayJournal:
    """Postgres-backed :class:`ReplayJournal`.

    Owns its own ``session_scope`` — a fresh, immediately-committing
    transaction per ITERATION (not per call — see :meth:`append_batch`),
    independent of the per-turn rollback-able session, same shape as
    :class:`~alfred.memory.forwarded_dispatch_attempts.PostgresForwardedDispatchAttemptStore`
    (review-pr fleet, 2026-08-10: NOT
    :class:`~alfred.memory.turn_side_effects.PostgresTurnSideEffectLedger`,
    which is the ADR-0062 INVERSION of this shape — stateless, no
    session_scope of its own, every call runs on the caller's session
    inside the caller's transaction; see that class's own docstring).
    """

    def __init__(
        self,
        *,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_scope = session_scope

    async def append_batch(
        self,
        *,
        adapter_id: str,
        inbound_id: str,
        iteration: int,
        calls: Sequence[tuple[int, ToolCall]],
    ) -> None:
        if not calls:
            # SQLAlchemy 2.0 silently no-ops `session.execute(stmt, [])` —
            # no error, no rows written — so an empty batch would vanish
            # without a trace instead of failing loud (review-pr fleet,
            # 2026-08-11, CLAUDE.md hard rule #7). See the Protocol
            # docstring's `Raises` section for the full contract.
            raise ValueError("append_batch called with an empty `calls` sequence")
        # "Atomic" (per the Protocol docstring) means ONE transaction, not
        # ONE SQL statement (review-pr fleet, 2026-08-10): `_APPEND_SQL` is
        # `sa.text()`-based, which SQLAlchemy 2.0's insertmanyvalues rewrite
        # does not apply to (that only covers Core `insert()` constructs), so
        # this compiles to a DBAPI `executemany` — N prepared-statement
        # executions, not one multi-VALUES INSERT. Atomicity is real
        # regardless: asyncpg's own `executemany` has been atomic since
        # 0.22.0, doubly guaranteed by this method's enclosing transaction.
        async with self._session_scope() as session:
            await session.execute(
                _APPEND_SQL,
                [
                    {
                        "adapter_id": adapter_id,
                        "inbound_id": inbound_id,
                        "call_index": call_index,
                        "iteration": iteration,
                        "tool_call_id": call.id,
                        "tool_name": call.name,
                        "tool_arguments_json": json.dumps(dict(call.arguments)),
                    }
                    for call_index, call in calls
                ],
            )

    async def read(self, *, adapter_id: str, inbound_id: str) -> tuple[JournalEntry, ...]:
        async with self._session_scope() as session:
            result = await session.execute(
                _READ_SQL, {"adapter_id": adapter_id, "inbound_id": inbound_id}
            )
            return tuple(
                JournalEntry(
                    call_index=row.call_index,
                    iteration=row.iteration,
                    tool_call=ToolCall(
                        id=row.tool_call_id,
                        name=row.tool_name,
                        arguments=json.loads(row.tool_arguments_json),
                    ),
                )
                for row in result.all()
            )
