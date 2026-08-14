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

#593's problem is a THIRD, previously-uncovered direction: before this PR,
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
   audit taxonomy is forensic and has already widened twice
   (`downgrade_denied`, `downgrade_malformed`, `budget_denied`,
   `dlp_canary_tripped`, `turn_error`, `send_failed`); aliasing the wire to
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
   attempted; `_notify_turn_failed` never raises (`TimeoutError` and the
   narrow wire-fault tuple `BrokenPipeError` / `ConnectionResetError` /
   `CommsProtocolError` / `OSError` are caught and logged, never
   `Exception`/`BaseException` bare — `CancelledError` still propagates), so
   a dead or wedged client wire can never turn a deterministic halt into a
   replay-poisoning re-raise. If the frame never arrives, the client's own
   90-second turn watchdog (Task 14) is the backstop — the operator recovers
   either way, just via a different signal.

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
