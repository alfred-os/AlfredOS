# ADR-0047 — `web.fetch` `HandleCap` re-attach + inbound-canary closure

- **Status**: Accepted (on #339 PR4a merge)
- **Date**: 2026-07-06
- **Slice**: #339 (LLM tool-calling epic), PR4a
- **Relates to**: [ADR-0041](0041-web-fetch-fused-fetch-extract-contract.md) (supersedes its
  Decision 2; closes two of its Consequences residuals),
  [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md) (Spec C egress control
  plane), issue #339 (LLM tool-calling epic), issue #347 (the #339-first-live-caller
  merge-blocker obligation list, blockers 1 and 5)
- **Supersedes**: [ADR-0041](0041-web-fetch-fused-fetch-extract-contract.md) Decision 2 only
  (`HandleCap` detached from `dispatch_web_fetch`) — the rest of ADR-0041's decisions and
  consequences stand as recorded

> **Sign-off flag.** This ADR reverses part of an already-accepted decision (ADR-0041
> Decision 2). ADRs are agent-authored and are not human-gated the way `CLAUDE.md` / `PRD.md`
> are (self-improvement rule #4), so this record ships in the same PR as the code. A
> structural reversal of this shape still wants `alfred-architect` / user confirmation at PR
> time, not only a merged ADR — flagged here and on the #339 PR4a pull request; treat the
> reversal as provisional until that sign-off lands.

## Context

ADR-0041 (the G7-2.5 `web.fetch` re-home) recorded two Consequences residuals as explicit
merge-blockers on "#339's first live `dispatch_web_fetch` caller": the per-user
resource-exhaustion refusal bound, lost when `HandleCap` was detached because the fused
fetch+extract model removed the Redis-backed parked resource the cap was built to bound; and
the inbound egress-response canary, built but wired `canary=None` because no core-side
canary-token source existed on the core container. Issue #347 tracks both as an obligation
list. PR3 (#399, merged `4a0d6b7f`) wired the agentic act-phase loop and the `dispatch_tool`
chokepoint (ADR-0046); PR4a is the first PR that gives `dispatch_web_fetch` a live production
caller, which is exactly the trigger both residuals were deferred to.

The two closures land in one ADR because they are the same PR's two changes to the same
dispatcher (`dispatch_web_fetch`, `src/alfred/plugins/web_fetch/fetch_dispatcher.py`) and
because Decision 1 is explicitly **not** a rollback of ADR-0041 — it re-purposes a component
ADR-0041 detached, under a materially different rationale. That distinction is the reason this
gets its own ADR rather than a silent revert of ADR-0041 Decision 2.

## Decision

### Decision 1 — `HandleCap` re-attached to `dispatch_web_fetch` as a per-user concurrency bound

`HandleCap.try_reserve` / `HandleCap.release` (`src/alfred/plugins/web_fetch/handle_cap.py`) are
re-attached to `dispatch_web_fetch` at Step 3b
(`src/alfred/plugins/web_fetch/fetch_dispatcher.py:416-462`): the dispatcher mints a synthetic
`handle_id = str(uuid.uuid4())`, reserves a slot on the per-user ZSET
(`alfred:handles:user:{user_id}`) **before** the network fire, and releases it in a `finally`
block (`fetch_dispatcher.py:594-612`) on every exit path — success, soft refusal, an
`InboundCanaryTripped` re-raise, a `TimeoutError`, or a transport fault.

This is a **re-purpose, not a straight undo**, of ADR-0041 Decision 2. ADR-0041 detached
`HandleCap` because the fused fetch+extract model removed the Redis content-store write — the
parked-body resource the cap was built to bound. That rationale still holds: there is no Redis
`ContentHandle` on this path. PR4a re-attaches `HandleCap` for a different reason — a pure
per-user *concurrency* bound on in-flight fetches. The T3 body now stages transiently in-memory
in the `QuarantineStagingMap` (drained on every exit by the ADR-0041 C9 fix), not as a
Redis-parked resource; the ZSET now counts in-flight reservations, not parked bodies.

Consequence: `handle_id` is a synthetic UUID4 ZSET member, not a real Redis `ContentHandle` id.
The pre-G7-2.5 host-side `handle_id`-equality check does not return to the dispatch path — its
`WebFetchHandleIdMismatch` exception class remains defined in
`src/alfred/plugins/web_fetch/errors.py` (unit-tested in isolation) but nothing in the shipped
dispatcher raises it; the ADR-0041 removal of that specific mechanism stands. A cap-exceeded
reserve raises `WebFetchRateLimited("handle_cap")`, audited as
`dlp_scan_result="handle_cap_exceeded"` — the token is re-added to the `DlpScanResult` vocabulary
(`src/alfred/audit/audit_row_schemas.py`) after ADR-0041 had removed it. A reserve **transport**
fault (`RedisError` / `ValueError` / `RuntimeError` out of `try_reserve`) is not caught by a
dedicated dispatcher `transport_error` arm — G7-2.5 removed that arm, and the promise of its
return, left in `handle_cap.py`'s docstring, is corrected by this ADR. The fault instead
propagates uncaught out of `dispatch_web_fetch` to `dispatch_tool`'s
(`src/alfred/orchestrator/tool_dispatch.py`) final catch-all, audited
`dispatch_outcome="unexpected_error"` / `result="fault"`, and escalates (halts the turn) — the
same totality guarantee ADR-0046 Decision 4 already documents for any un-enumerated dispatch
exception.

Closes #347 blocker 1: the `alfred-security-engineer` dissent recorded in ADR-0041's
Alternatives section (per-user fairness lost in the fused path) is discharged now that a live
caller exists — reconciled by G7-2.5's zero-exposure window (there was no live caller until
this PR). Proven by `de-2026-004`
(`tests/adversarial/dlp_egress/egress_inflight_and_no_orphan.yaml` +
`test_egress_no_orphan_and_inflight.py::test_per_user_handle_cap_refuses_sixth_pre_network`),
converted from its ADR-0041 re-targeted no-orphan/liveness-only form back to an active per-user
refusal assertion, plus a Redis-backed integration test
(`tests/integration/egress/test_handle_cap_exhaustion.py::test_sixth_reserve_refused_then_release_frees_a_slot`).

Reservation TTL: `_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS = 120`
(`src/alfred/plugins/web_fetch/constants.py`) is a self-heal backstop comfortably above the 30s
`_DEFAULT_ACTION_DEADLINE_SECONDS` — a `release()` that no-ops on a transient Redis error
(the class's documented fail-quiet contract) self-frees via passive `ZREMRANGEBYSCORE` eviction
rather than leaking the slot for the process lifetime.

### Decision 2 — inbound-reflection canary residual closed

ADR-0041's Consequences residual — "Inbound egress-response canary deferred to #339" — is
closed. A new core-side token source, `Settings.web_fetch_canary_tokens`
(`src/alfred/config/settings.py`), fed by env `ALFRED_WEB_FETCH_CANARY_TOKENS`
(comma-separated, blanks skipped, `NoDecode`-annotated so the raw string reaches the
`mode="before"` validator before pydantic-settings' JSON decoding would otherwise consume it),
feeds `_resolve_web_fetch_canary` (`src/alfred/plugins/web_fetch/assembly.py`).
`build_web_fetch_egress_extractor` now derives a non-`None` `ResponsePolicy.canary` by default:
an explicit `canary` argument (tests) is honoured; otherwise the settings-derived matcher is
used, and it is **always** non-`None` — zero tokens yield a no-op `CanaryMatcher` rather than a
skipped seam. `ALFRED_WEB_FETCH_CANARY_TOKENS` is deliberately distinct from the gateway-only
`ALFRED_CANARY_TOKENS` (hard-forbidden on the core container per
`tests/unit/test_compose_invariants.py`) — the gateway keeps its own, separate OUTBOUND exfil
scanner; this closes only the web.fetch INBOUND-reflection tripwire.

Closes #347 blocker 5. Proven by `de-2026-012`
(`tests/adversarial/dlp_egress/de_egress_inbound_canary_unwired.yaml` +
`test_de_egress_inbound_canary_unwired.py`, covering
`test_inbound_canary_reflected_response_trips`,
`test_factory_wires_non_none_canary_from_settings`, and the no-trip regression
`test_armed_canary_benign_body_does_not_trip`), converted from its ADR-0041 unwired-residual
form to a real reflected-canary assertion set, plus an integration test proving the
settings-derived matcher trips over a real loopback relay
(`tests/integration/egress/test_web_fetch_assembly.py::test_factory_canary_from_settings_trips_over_real_relay`).

## Consequences

### Positive

- Per-user fairness is restored on the only path that can exhaust it: a single user can no
  longer hold unbounded concurrent `web.fetch` calls against the shared gateway relay.
- The inbound-reflection tripwire is armed by default in every environment that builds the
  factory extractor, closing the gap between the outbound canary (gateway) and the inbound
  canary (core) that ADR-0041 left open.
- Both #347 xfail merge-blockers on #339's first live `dispatch_web_fetch` caller are closed,
  with the `de-2026-004` / `de-2026-012` conversions as the machine-checked evidence.

### Negative / accepted

- Two #347 residuals are still **open** and explicitly **not** closed by this PR, so the record
  stays honest: the action-deadline `TimeoutError` / `in_doubt` cross-layer audit (ADR-0041's
  "Action-deadline `TimeoutError` surfaces un-audited at the dispatcher" residual), and broker
  `SecretId`-based authenticated fetch (ADR-0041's broker secret-injection residual, HARD rule
  #6). Both are deferred to **PR4b**.
- `HandleCap`'s Redis round-trip is back on the `dispatch_web_fetch` hot path (one Lua-atomic
  reserve, one `ZREM` release) — a cost ADR-0041 had removed. Accepted: the per-user fairness
  property it buys back is worth one extra Redis round-trip per fetch, and the reservation is
  pre-network so it fails fast relative to the fetch itself.

## Alternatives considered

### (a) — a defaulted-`None` `handle_cap` parameter

Make `handle_cap` an optional dependency on `dispatch_web_fetch`, defaulting to `None` and
skipping the reserve/release when absent. Rejected: a fail-open footgun — any assembly path
that forgets to wire `handle_cap` silently loses the per-user bound rather than failing loud,
and the whole point of PR4a is that this bound is a merge-blocker, not best-effort.

### (b) — leave the canary `None`, defer wiring to #338

Keep `build_web_fetch_egress_extractor`'s `canary` parameter defaulting to `None` and wire a
real matcher only when #338 does the live comms cutover. Rejected: the seam
(`ResponsePolicy.canary` → `inspect_response` → `InboundCanaryTripped`) was already built in
G7-2.5; deriving it from settings is cheap, and `de-2026-012` is a merge-blocker on #339's first
live caller (this PR), not on #338 — leaving it `None` here would ship a live tool-calling path
with a known-open security residual.

## References

- PRD [§7.1](../../PRD.md#71-security--prompt-injection-defense) (Security &
  Prompt-Injection Defense)
- [ADR-0041](0041-web-fetch-fused-fetch-extract-contract.md) — `web.fetch` fused fetch+extract
  contract (the ADR this one amends)
- [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md) — connectivity-free
  core / mandatory egress chokepoint (Spec C)
- [ADR-0045](0045-provider-tool-protocol.md) — provider tool-protocol seam (#339 PR1)
- [ADR-0046](0046-dual-llm-tool-result-flow.md) — dual-LLM tool-result-flow trust boundary
  (#339 PR2/PR3); Decision 4's escalation/recoverable classification is the same totality
  contract Decision 1 above relies on for the reserve-transport-fault path
- Issue #339 (LLM tool-calling epic) — PR4a
- Issue #347 — the #339-first-live-caller merge-blocker obligation list (blockers 1 and 5
  closed here; the `TimeoutError`/`in_doubt` and broker-secret residuals remain open for PR4b)
