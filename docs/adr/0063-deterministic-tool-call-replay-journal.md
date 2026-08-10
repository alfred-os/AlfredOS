# ADR-0063 — Deterministic tool-call replay journal

- **Status**: Accepted (on #410 PR2 merge)
- **Date**: 2026-08-07
- **Slice**: 4 — #410 PR2 (`docs/superpowers/plans/2026-08-07-issue-410-pr2-replay-journal.md`)
- **Relates to**: [ADR-0039](0039-gateway-adapter-inbound-bridge.md) (the
  forwarded dispatched-edge replay this journal makes safe for tool-bearing
  turns), [ADR-0049](0049-real-privileged-turn-comms-inbound.md) (the #338
  cutover this journal was deferred from — see its Context),
  [ADR-0062](0062-three-phase-turn-and-role-scoped-connection-pools.md) (the
  three-phase turn / `_run_turn_phases` + `_orient_and_act` split this
  journal wires into, Task 4), the Spec C egress-idempotency ledger
  (`src/alfred/egress/egress_id.py`, `src/alfred/memory/egress_idempotency.py`)
  this journal makes converge rather than raise, issue #410 (epic), issue
  #338 (predecessor)

## Context

Issue #338 PR2 (ADR-0049) shipped a real privileged turn on the comms inbound path
with egress tools explicitly DEFERRED — the Act loop advertises an empty
tool registry, so it runs exactly one completion and writes no egress-ledger
rows. #410 turns tools on. Doing so reintroduces a hazard #338's own design
spec named but deliberately left out of scope: on the forwarded dispatched-
edge path (`commit_at_dispatch_edge=True`, ADR-0039 item 4), a crash between
"the planner decided to call these tools" and `commit_once` leaves the frame
uncommitted, so it replays. Before this journal, a resumed turn asks the
planner AGAIN — a fresh, potentially non-deterministic completion.

Verifying the existing Spec C egress-idempotency ledger against that
scenario (rather than assuming it) found it already stronger than the
original issue text implied: `compute_egress_id` is positional
(`(adapter_id, inbound_id, session_id, call_index)`), but
`compute_egress_body_hash` additionally binds the full request identity, and
`egress_idempotency.py:220` raises `EgressIdIntegrityError` on any
divergence. So a resumed turn whose planner diverges does not silently
misattribute a stale result to a new call — it fails loud, replaying until
the poison ceiling (`ForwardedDispatchAttemptStore`). That is fail-safe but
not fail-useful: a resumed tool-bearing turn could never complete if the
planner was even slightly non-deterministic between attempts.

## Decision

A new durable `tool_call_journal` table records the committed ordered
tool-dispatch decision — `(adapter_id, inbound_id, call_index) ->
(iteration, ToolCall)`. `append_batch` commits the COMPLETE iteration's
decisions in one atomic write, awaited to completion before ANY
`dispatch_tool` call for that iteration begins — not one row per call (a
per-call write would leave a crash window between journaling call N and
call N+1 of the same iteration; see the method's own docstring for the
full failure mode this closes). **This PR is dark by default**
(review-pr fleet, 2026-08-10): `_fast_forward_journalled_calls` checks
`self._tool_registry is None` FIRST, unconditionally, and PR2 constructs
`PostgresReplayJournal` without wiring a live tool registry — so nothing
in this PR reads or replays journal rows yet. The replay behavior
described below is the design this journal exists to serve once PR3 wires
a live registry, not active behavior in PR2 itself. Composite-keyed, not `(inbound_id, call_index)` alone (a design
correction found during the `/review-plan` fleet pass): `inbound_id` is a
free-form, per-adapter-minted opaque string, so a two-column key would let
two different adapters' turns collide and splice one turn's decided tool
calls into a different turn's reconstructed transcript. `session_id` is
deliberately NOT part of the key, even though `compute_egress_id`
(`src/alfred/egress/egress_id.py`) binds `(adapter_id, inbound_id, session_id,
call_index)`: the two identifiers answer different questions. `(adapter_id,
inbound_id)` IS the turn identity — the same pair the sibling
`inbound_idempotency`, `forwarded_dispatch_attempts` and
`turn_side_effect_ledger` tables key on, and the pair a forwarded replay
re-presents unchanged — whereas `compute_egress_id` must additionally be
unique per CALL and per session, since it names an individual outbound
request rather than the turn that decided it. On a forwarded-path
resume, the Act loop reads any journalled entries for the turn's
`(adapter_id, inbound_id)` and **fast-forwards** through them: each is
replayed via the SAME `dispatch_tool` call the normal path uses (the
existing Spec C ledger's memoize-and-replay handles the actual dedup for
`ExternalToolSpec`/web.fetch tools — this journal adds no egress-level
dedup logic of its own), reconstructing the ephemeral tool transcript
grouped by the journalled `iteration`. The loop then resumes **unmodified**,
from `max_journalled_iteration + 1` onward, with `tool_choice="auto"` — the
planner remains free to make further tool calls. `max_journalled_iteration`
is a running `max()` over the grouped entries, not "whatever the last group
carried": `read()` orders by `call_index ASC` and iteration is
monotonic-in-`call_index` only by write-side construction, which is an
unenforced invariant rather than a guarantee. **The journalled prefix
always dispatches BEFORE the ceiling check runs** — fast-forward replay
happens first, unconditionally; only once it returns does the Act loop
check whether the resume point it computed is at or past
`MAX_TOOL_ITERATIONS`. A resume point at or past that ceiling would make
the Act loop's iteration range empty (no completion, nothing to answer
with), so it raises `ReplayIterationCeilingError` rather than silently
no-op-ing the turn (CLAUDE.md hard rule #7) — without ever invoking the
planner, but only after every already-committed call in the prefix has
already been replayed.

**The journal read happens only for a FORWARDED turn.** When
`handle_user_message` receives no `TurnEgressContext`, the orchestrator
synthesizes one whose `inbound_id` is the per-turn `trace_id` — a fresh
uuid4 that by construction has never been journalled — so the Act loop skips
the read entirely instead of paying a guaranteed-empty Postgres round-trip on
every direct / `alfred chat` turn once PR3 arms a live tool registry. The
journal WRITE stays unconditional, and that asymmetry is deliberate: writing
rows under a fresh-by-construction identity is inert because nothing can ever
read them back, whereas reading under an identity that later stopped being
fresh (say, a future `_synthesize_egress_context` keyed on message content
rather than `trace_id`) would splice a foreign turn's decided tool calls into
this one. The hazardous direction is the one guarded.

A single forced `tool_choice="none"` wrap-up completion was considered and
rejected: if the original attempt crashed BEFORE the planner decided to stop
calling tools, forcing a premature text-only answer on resume would
truncate legitimate further tool use the resumed turn should still be free
to take.

`temperature=0` threads to both provider adapters for tool-bearing
completions as defence-in-depth ON TOP OF the journal — a resumed turn
should ideally re-derive an identical plan even before the fast-forward
above ever consults history. This is not a substitute for the journal: it
only makes convergence more LIKELY, never guaranteed.

**Explicitly out of scope: dedup protection for `InternalToolSpec` tools.**
Only `ExternalToolSpec` (web.fetch) is wired to the Spec C
`compute_egress_id`/memoize-and-replay ledger. A replayed `InternalToolSpec`
call (`clock.now`, PR3's only live tool) re-dispatches for real on every
fast-forward, with no dedup at all — accepted because `clock.now` is
side-effect-free by construction; a future `InternalToolSpec` with real side
effects would need this addressed first.

**No longer in scope (retired by a PR1 design correction, found during the
same `/review-plan` pass): budget-charge iteration-awareness.** PR1's
`TurnSideEffectLedger` was originally going to gate the budget charge with a
single boolean per turn, correct only while tools were off — and PR1's own
construction-time guard against combining that gate with a live
`tool_registry` was found, during this review, to make the daemon fail to
boot the moment PR3 wired one in. The fix: PR1 leaves the budget charge
permanently ungated instead (see ADR-0049's amendment). There is therefore
no PR3 obligation regarding budget-charge granularity for this journal to
name.

## Consequences

### Positive

- Positive: a resumed tool-bearing turn converges instead of poison-looping
  or losing accounting for already-real egress side effects.
- Positive: no new egress-level dedup mechanism for `ExternalToolSpec` tools
  — this journal is a pure "what to replay," the existing ledger remains the
  sole authority on "did this already happen."

### Negative

- Negative: `tool_call_journal` grows without a retention/pruning story in
  this PR — a committed frame never resumes again, so pruning on
  `commit_once` is the natural follow-up. **Tracked as
  [#581](https://github.com/alfred-os/AlfredOS/issues/581)**, which also
  covers PR1's identical gap on `turn_side_effect_ledger`; both tables should
  be addressed together (e.g. one shared prune-on-`commit_once` sweep)
  rather than solved twice independently.
- Negative (accepted, **not tracked by an issue either**): `InternalToolSpec`
  tools have no dedup protection on replay at all (see above) — safe only by
  the side-effect-free convention, not an enforced guarantee. Recorded here
  and in `_fast_forward_journalled_calls`'s docstring; whoever adds the first
  `InternalToolSpec` tool with real side effects inherits the obligation to
  close it before doing so.

## Alternatives considered

### Store tool RESULTS in the journal, not just the decision

Rejected: result dedup is already the egress ledger's job (memoize-and-replay); a
second copy of results here would be redundant state that could drift
from the ledger's own.

### Key the journal entry on `compute_request_descriptor`

Rejected: that function is internal to web.fetch's own extraction path
(`method`/`url`/`schema_id`) and has no meaning for `clock.now` or any
future non-HTTP tool. `ToolCall` (id/name/arguments) is the identity
`dispatch_tool` already receives generically, for any tool.

### Key the journal on `(inbound_id, call_index)` alone

Rejected during `/review-plan`: reintroduces a cross-adapter collision class the sibling
`inbound_idempotency`/`forwarded_dispatch_attempts` ledgers already guard
against for the identical reason.
