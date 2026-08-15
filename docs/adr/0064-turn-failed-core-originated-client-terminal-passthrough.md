# ADR-0064 — `turn.failed`: a core-originated, client-terminal, gateway-pass-through control frame

- **Status**: Accepted (implemented on this branch; landing with the #591/#592/#593 combined PR)
- **Date**: 2026-08-14
- **Slice**: 4 — #593 (Tasks 9-15 of the #591/#592/#593 combined PR)
- **Relates to**: [ADR-0032](0032-gateway-comms-resume-transport.md) (the
  `link.*` gateway-ORIGINATED control-frame family this ADR is a structural
  sibling to, and the `_route_unit` consumed-method dispatch this frame
  deliberately does NOT join), [ADR-0033](0033-core-owned-lifecycle-signalling.md)
  (the `daemon.lifecycle.*` core-originated-but-gateway-CONSUMED family this
  ADR's direction is the mirror image of), [ADR-0049](0049-real-privileged-turn-comms-inbound.md)
  (the `RealTurnOrchestratorAdapter.dispatch` refusal legs this frame is
  raised off), issues #591, #592, #593

## Context

The comms wire already carries two directions of host-to-outward control
frame, and neither fits what #593 needs:

- **`link.*` (`link.reconnecting` / `link.restored` / `link.unavailable`,
  ADR-0032) is GATEWAY-originated.** The gateway itself observes its core-link
  connection state and synthesizes these frames; the core never sends them.
  They are pure connection-state signals, consumed client-terminally by the
  TUI's reconnect banner.
- **`daemon.lifecycle.{ready, going_down}` / `daemon.comms.ack` /
  `core.adapter.spawn_grant` (ADR-0033, ADR-0032 §G4b-2a-pre, ADR-0036) are
  CORE-originated but gateway-CONSUMED.** `GatewayCoreLink._route_unit`
  recognizes exactly these four method constants, decodes and acts on them
  itself (epoch reconciliation, ack-driven buffer trim, credential relay),
  and never forwards the raw frame past the gateway.

Issue #593's problem is a THIRD, previously-uncovered direction: before this PR,
`alfred chat` gave the operator zero feedback on ANY turn-failure path — no
"thinking..." indicator, no error, ever (the gap the whole combined PR
exists to close). The signal that closes it — "the turn you just started
produced no reply, and here is the (coarse) reason" — is decided entirely
inside the daemon's `RealTurnOrchestratorAdapter.dispatch` (a `BudgetError`,
an `OutboundCanaryTripped` DLP trip, or a generic turn error/`_HaltNoReply`
leg). It has no meaning to the gateway (which does not parse turn semantics
and must not start — hard rule #5, payload-blindness) and every meaning to
the TUI operator staring at a disabled input box. Neither existing family's
plumbing fits: it is not gateway-observable state (rules out reusing
`link.*`), and it is not something the gateway needs to act on (rules out
extending the `daemon.*`/`core.*` consumed vocabulary).

## Decision

**A new frame, `turn.failed` (`TURN_FAILED` in `src/alfred/comms_mcp/protocol.py`),
in a genuinely new wire direction: core-originated, client-terminal, and
gateway-PASS-THROUGH (opaque relay, not consumed).**

1. **A fresh top-level namespace, `turn.*`, deliberately outside every
   existing prefix.** `daemon.`, `core.`, and `gateway.` are all, on some
   leg, a CONSUMED namespace (the previous two families above). Naming this
   frame `daemon.turn_failed` or similar would misleadingly suggest the
   gateway might one day consume it the way it consumes
   `daemon.lifecycle.*`. `turn.*` sits parallel to `link.*` — both are
   client-terminal-only namespaces — but flows the opposite direction
   (gateway-authored vs. core-authored).

2. **The gateway needs, and gets, ZERO new code.**
   `GatewayCoreLink._route_unit` recognizes exactly the four consumed
   constants named above; every other method — `turn.failed` included —
   falls through to the existing `_payload_relay` arm untouched. Task 10
   proved this with a REGRESSION TEST
   (`test_route_unit_turn_failed_is_relayed_not_consumed`,
   `tests/unit/gateway/test_core_link.py`), not a production change — the
   frame rides the existing opaque-relay path by construction, the same way
   an ordinary `outbound.message` request does. This preserves the
   payload-blindness invariant (hard rule #5): the gateway staying ignorant
   of `turn.failed`'s existence is the point, not an oversight.

3. **A closed, coarse, client-facing vocabulary — `TurnFailureStage =
   Literal["refused", "budget_exhausted", "internal_error"]` — deliberately
   NOT the private audit `_RefusalStage` Literal it is mapped from.** The
   audit taxonomy is forensic and has already widened three times
   (`downgrade_denied`, `downgrade_malformed`, `budget_denied`,
   `dlp_canary_tripped`, `dlp_scan_failed`, `turn_error`, `send_failed`);
   aliasing the wire to
   it would let a future audit-only stage silently become an unmapped (and
   therefore unrendered) wire value. `_client_turn_failure_stage` in
   `real_turn_adapter.py` is an exhaustive `match`/`assert_never` over the
   audit Literal, so a new audit stage added without a client decision is a
   type-check failure, not a silent drop. The mapping is also a security
   boundary: `downgrade_denied` and `dlp_canary_tripped` both collapse to
   the coarse `"refused"` — naming which control fired would be a free
   boundary-probing oracle. `TurnFailedNotification` carries `stage` and
   NOTHING else (`extra="forbid"`, frozen, no `str` field of any kind) — the
   same no-free-text-on-the-wire discipline `link.*`'s notifications already
   establish, so no core-supplied or T3-derived text can ever reach the
   wire as raw operator-visible bytes.

4. **A fail-closed per-adapter-kind capability table,
   `TURN_STATE_CLIENT_KINDS = frozenset({"tui"})`**, mirroring the existing
   `BODY_FIELD_BY_KIND` pattern. `real_turn_adapter._notify_turn_failed`
   checks membership before ever calling `sender.send_turn_state`; an
   adapter kind absent from the table (Discord, today) gets no `turn.failed`
   send at all, rather than a frame its plugin has no handler for. A kind is
   added here only in the same commit as its client-side handler.

5. **Best-effort wire, authoritative audit — the same posture ADR-0033
   Decision 5 establishes for `daemon.lifecycle.*`.** The refusal's audit
   row (`_emit_refused`) is written and durable BEFORE the notify is
   attempted; `_notify_turn_failed` never raises. `TimeoutError` is caught
   and logged on its own leg, and every OTHER `Exception` is contained by a
   deliberately bare `except Exception` (#594 R1 Fix B): a narrow
   wire-fault tuple made the never-raises contract a lie, letting anything
   outside it — a `ValidationError` from constructing the notification, a
   bug in a sender implementation — escape and do exactly the damage this
   decision exists to prevent. `CancelledError` derives from
   `BaseException`, so it is NOT caught and still propagates BY DESIGN: a
   caller-level cancellation must genuinely cancel an in-flight notify
   rather than be logged like a wire fault. Containment is not silence —
   each leg logs a `_log.warning` carrying `error_class` only, never
   `str(exc)`. A dead or wedged client wire can therefore never turn a
   deterministic halt into a replay-poisoning re-raise. If the frame never
   arrives, the client's own 90-second turn watchdog (Task 14) is the
   backstop — the operator recovers either way, just via a different
   signal.

6. **Client-side routing mirrors the `link.*` wire-contract-violation
   discipline exactly.** `alfred_tui.cohost._serve_wire` recognizes
   id-LESS `turn.failed` frames in their own branch (immediately after the
   `link.*` allowlist, before `dispatch`) and routes them to an
   `on_turn_failed` callback; an id-BEARING `turn.failed` is a wire-contract
   violation (`turn.failed` is spec'd id-less, exactly like `link.*`) and is
   logged loud + falls through to `dispatch` rather than being silently
   answered-and-dropped. In production (`run_cohosted`) the callback is
   wired to `AlfredTuiApp.set_turn_failed`, which ends the pending turn
   (stops the watchdog, re-enables `#user_input`, refocuses it) and renders
   the stage's localized `tui.turn_failed.*` copy into the conversation
   log — a transcript event, not a banner, so it survives the next
   link-state change instead of being overwritten by it.

## Consequences

### Positive

- The actual gap #593 exists to close is closed: a turn that produces no
  reply now visibly ends, with localized operator-facing copy, instead of
  leaving the input box disabled forever (or until the 90s watchdog).
- Zero new gateway code and zero new gateway attack surface — the frame
  rides the existing opaque-relay path, proved by a regression test rather
  than trusted by inspection.
- The client-facing vocabulary is coarse by construction, so this channel
  cannot become a security-control oracle even as the private audit
  taxonomy continues to widen.

### Negative / accepted

- **Best-effort delivery, not guaranteed.** A `turn.failed` send that races
  a dead client wire is logged and dropped, never retried — the 90-second
  watchdog is the sole backstop for that case. Accepted because retrying a
  best-effort UX signal against a deterministic-halt leg would risk
  reintroducing the replay-poisoning hazard `_HaltNoReply` exists to avoid.
- **Only `"tui"` is wired into `TURN_STATE_CLIENT_KINDS` today.** The
  Discord adapter (and any future comms adapter) gets silent-by-omission
  behavior — no `turn.failed` send, no client-visible signal beyond
  whatever that adapter already has — until its own client-side handler
  lands in the same commit that adds it to the table.
- **The stage collapse is content-coarsening, not timing-coarsening — accepted,
  with a tripwire.** `downgrade_denied` and `dlp_canary_tripped` produce
  byte-identical `turn.failed` frames (pinned by `cib-2026-009`), but they do
  not ARRIVE at the same time: `downgrade_denied` fires from the capability
  gate in `ingest` (`real_turn_adapter.py`), which is reached after the
  quarantined extract but before the privileged turn, while
  `dlp_canary_tripped` fires only from inside `handle_user_message` after at
  least one further privileged completion. A client that samples enough turns
  can separate the two legs on latency and so recover the phase boundary the
  coarse `"refused"` value hides. The same applies to `downgrade_malformed`
  vs. `turn_error` inside `"internal_error"`, though `turn_error`'s latency
  distribution (anything from an instant config fault to a 60s provider
  timeout) largely swallows the distinction.

  **Accepted for the current threat model**, on four grounds:
  (1) `TURN_STATE_CLIENT_KINDS` contains only `"tui"`, whose transport is a
  0600 AF_UNIX socket under a 0700 runtime dir with `SO_PEERCRED` same-uid
  enforcement (ADR-0031, `src/alfred/plugins/_local_socket.py`) — the only
  party who can submit a turn AND observe the frame is a process running as
  the operator's UID. (`SO_PEERCRED` establishes UID equality, not human
  identity: this reaches any process sharing that UID, not only the human
  operator. Same-UID processes are inside this ADR's trust boundary and out
  of scope for the current threat model — but the "no privilege gained"
  conclusion below holds regardless of which one is observing, since a
  same-UID process already has the full-fidelity signal too.) That party
  already reads the full-fidelity `_RefusalStage` verbatim out of the
  `comms.inbound.real_turn.refused` structured-log line (the surface
  `docs/runbooks/slice-3-operator-migration.md` names as sanctioned while
  `alfred audit log` is stubbed) — a 0600 file, and the audit DB credentials,
  that a same-UID process already has read access to — so no privilege is
  gained; that party is in any case also shown turn latency directly by
  `tui.thinking_elapsed`, the 90s watchdog line, and the
  `alfred_comms_inbound_dispatch_seconds` histogram; (2) the collapse has
  one reachable member today —
  `dlp_canary_tripped` is inert until `web.fetch` (#583) ships a tool whose
  output can carry a canary token (`real_turn_adapter.py`, the
  `OutboundCanaryTripped` leg's own comment); (3) the marginal bit ("did my
  input pass the downgrade gate?") is already leaked with perfect fidelity by
  the presence or absence of a reply on the success path, and is not closable
  on any channel that answers questions at all; (4) the obvious mitigation — a
  minimum-latency floor — cannot work here: the slow leg is an unbounded LLM
  turn (`read=60.0`, `max_retries=2`, 1..N completions), so no fixed floor
  separates the distributions, while a floor large enough to try would delay
  every legitimate fast policy refusal and regress the exact responsiveness
  gap #593 exists to close.

  **Tripwire.** This acceptance is void the moment `TURN_STATE_CLIENT_KINDS`
  gains any non-local kind, because a remote client is a party that can both
  submit turns and observe frame arrival. That widening commit MUST re-derive
  this analysis alongside the `turn_error` notify-then-raise ordering caveat
  in `RealTurnOrchestratorAdapter.dispatch`'s docstring, which is void at the
  same moment and for a related reason.
  `tests/unit/comms_mcp/test_protocol_schemas.py::test_turn_state_client_kinds_is_exactly_tui`
  pins the set by exact equality so the widening cannot land silently.
- **`TurnFailedNotification` carries no `adapter_id` because "the runner IS
  the address" — an assumption that holds only while exactly one adapter is
  bound.** `RealTurnOrchestratorAdapter` holds a single `_sender` slot
  (`src/alfred/comms_mcp/real_turn_adapter.py:304`), rebound last-writer-wins
  by each `bind_outbound_sender` call at boot
  (`real_turn_adapter.py:317-319`, invoked once per adapter at
  `src/alfred/cli/daemon/_comms_boot.py:1186-1187`); with two adapters
  wired, adapter-A's turn would dispatch its `turn.failed` frame through
  adapter-B's runner — a cross-route the daemon's own boot-time comment
  names explicitly (`# FIX 4`, `src/alfred/cli/daemon/_commands.py:990-1006`).
  Accepted today because boot fail-closed refuses more than one enabled
  comms adapter (`CommsMultiAdapterUnsupportedFailure`,
  `src/alfred/cli/daemon/_commands.py:1000-1007`; exit 2, audited) — the
  same guard that keeps the timing acceptance above from becoming live.
  Shares the exact tripwire moment: per-adapter inbound routing
  (PR-S4-11c) must reintroduce `adapter_id`-scoped outbound dispatch in the
  same commit that lifts the single-adapter boot refusal, not after.
- **The client's zero-correlation design depends on a SERVER-SIDE
  submission-order guarantee, not a wire one — and that guarantee needed a
  second mechanism to actually hold (arc-001, PR #594 Task S1).**
  `_resolve_pending_turn`'s stale-turn debt counter
  (`plugins/alfred_tui/src/alfred_tui/textual/app.py`) has no wire-level way
  to tell "this signal is for my currently-pending turn" from "this is a
  late signal for a watchdog-abandoned one" — it relies entirely on the core
  sending one session's turn-completion signals in submission order. Before
  this PR that was true only for the `_PreparedTurn` outcome:
  `RealTurnOrchestratorAdapter.ingest`'s two ingest-resolved outcomes
  (`_HaltNoReply` / `_RefusalReply`) never touched the per-`(persona, slug)`
  mutex at all, so a later same-key turn's refusal could signal the client
  before an earlier same-key turn's own answer, reproduced by execution
  against the real adapter
  (`root-cause-arc-001-turn-order-race.md`). The fix is a per-key ORDERING
  BARRIER (`RealTurnOrchestratorAdapter._await_turn_ordering_barrier`): both
  ingest-resolved outcomes now acquire-then-immediately-release the same
  mutex as a pure ordering fence before their notify/send, giving them the
  identical acquire-then-signal shape the `_PreparedTurn` leg already had —
  no turn work runs under the barrier, and it releases before the
  notify/send so the timing-side-channel acceptance above is unaffected.
  This is the mechanism that keeps rejected option (b) — a wire correlation
  token added to `TurnFailedNotification` — properly CLOSED rather than
  merely unconsidered: the zero-correlation design this ADR commits to
  (Decision 3) is sound only because the server independently guarantees
  submission order; had that guarantee stayed silently false, the honest
  fix eventually would have been the wire change this ADR explicitly
  rejects.

  **Accepted cost, live TODAY — not a future-only tripwire.** The ordering
  barrier is UNCONDITIONAL by design (report §5.2 step 3: "acquire the
  barrier unconditionally... default-deny closes the class") — it is never
  gated on `TURN_STATE_CLIENT_KINDS`, which governs only whether
  `_notify_turn_failed` puts a frame on the wire, not whether the barrier
  itself runs. So `TURN_STATE_CLIENT_KINDS == frozenset({"tui"})` says
  nothing about whether the barrier is exercised, and an earlier draft of
  this note wrongly reasoned from it that the barrier was inert until that
  set widened.

  It is already exercised, today, on the forwarded/gateway path.
  `GatewayForwardedInboundReceiver` calls `process_inbound_message` with
  `commit_at_dispatch_edge=True`
  (`src/alfred/comms_mcp/forwarded_inbound_receiver.py:247`) against the
  SAME `RealTurnOrchestratorAdapter` instance the TUI's direct path shares —
  both are constructed and wired together in the one boot function
  (`src/alfred/cli/daemon/_comms_boot.py`: `inbound_orchestrator` is built,
  then threaded into `_build_forwarded_inbound_registry` and from there into
  `GatewayForwardedInboundReceiver`). So a forwarded adapter's
  `_RefusalReply` — driven by the ROUTINE `cannot_extract` /
  `provider_unavailable` `TypedRefusal` reasons, not a rare
  misconfiguration — already takes the same `dispatch()` call and already
  sits on the barrier if an earlier same-key turn is in flight. Unlike the
  TUI, the forwarded path has no client-side turn-pending lockout gating one
  in-flight turn per session behind a 90s watchdog, so same-user overlap
  there is ordinary traffic, not a rare failure mode.

  Accepted because the barrier's cost when contended IS the behaviour the
  fix exists to produce — a later same-key signal correctly waiting behind
  an earlier one's completion, bounded by however long that earlier turn
  takes, exactly like `_PreparedTurn`-vs-`_PreparedTurn` contention already
  was — not a latent defect; and because when uncontended (the common case)
  an `asyncio.Lock` acquire/release is negligible.

  **Tripwire, re-keyed on what can actually regress** (in addition to the
  one above, which is still about `TurnFailedNotification`'s missing
  `adapter_id`). The invariant this ADR and `_TurnFailed`'s docstring depend
  on is that the barrier's acquire-then-release is UNCONDITIONAL over every
  ingest-resolved outcome. A future change that re-gates it — e.g. skipping
  it for an adapter kind outside `TURN_STATE_CLIENT_KINDS` on the mistaken
  belief that only client-notifiable kinds need ordering — would silently
  reopen arc-001 for every excluded kind, forwarded/gateway included.
  `test_ordering_barrier_is_unconditional_for_a_non_client_adapter_kind`
  (`tests/unit/comms_mcp/test_real_turn_adapter_dispatch.py`) pins this: it
  proves the barrier still blocks a `adapter_id="discord"` halt behind an
  earlier same-key turn's held lock, a kind outside
  `TURN_STATE_CLIENT_KINDS` that the sibling
  `test_notify_skipped_for_non_client_adapter_kind` only ever drives
  uncontended (so it cannot see the barrier at all).

## Alternatives considered

### Fold `turn.failed` into the `link.*` family

Rejected: `link.*` is gateway-ORIGINATED connection-state; `turn.failed` is
core-originated turn-state. Conflating the two would make the gateway either
parse turn semantics it has no business touching, or fake-author a frame on
the core's behalf — both worse than a parallel, independently-owned
namespace.

### Widen the `daemon.*`/`core.*` gateway-consumed vocabulary to include it

Rejected: the whole point of a gateway-consumed frame (`daemon.lifecycle.*`,
`daemon.comms.ack`, `core.adapter.spawn_grant`) is that the gateway ACTS on
it (epoch reconciliation, buffer trim, credential relay). `turn.failed` has
no gateway-side action — adding it to that vocabulary would mean writing
gateway code whose only job is to re-emit the frame unchanged, which is
exactly what the existing opaque-relay fallback already does for free.

### Carry a free-text `reason`/`detail` string instead of a closed `Literal`

Rejected for the same reason `link.*`'s notifications carry no text: an open
string field is a standing invitation to smuggle core-supplied or
T3-derived content into a client-visible frame, and breaks the i18n rule
that operator-facing strings render via `t()` from a closed vocabulary,
never as raw wire text.
