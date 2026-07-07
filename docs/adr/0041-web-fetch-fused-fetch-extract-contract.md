# ADR-0041 — `web.fetch` fused fetch+extract contract

- **Status**: Proposed (accepted on G7-2.5 PR1 merge)
- **Date**: 2026-06-28
- **Slice**: Spec C — G7-2.5 web.fetch re-home (`docs/superpowers/specs/2026-06-28-g7-2.5-web-fetch-rehome-design.md`)
- **Relates to**: ADR-0040 (reserved — comprehensive Spec-C egress ADR, G7-5, see note below),
  [ADR-0036](0036-gateway-adapter-hosting-inversion.md) (gateway privilege model — gateway holds no `CapabilityGateNonce`),
  [ADR-0039](0039-gateway-adapter-inbound-bridge.md) (gateway adapter inbound bridge),
  epic [#333](https://github.com/alfred-os/AlfredOS/issues/333) (Spec C),
  issue [#339](https://github.com/alfred-os/AlfredOS/issues/339) (per-user fairness / live wiring),
  issue [#347](https://github.com/alfred-os/AlfredOS/issues/347) (the deferred-residual merge-blockers on #339's first live caller)
- **Supersedes**: —

> **Amendment (2026-07-06, #339 PR4a):** Decision 2 (`HandleCap` detached) is **superseded** —
> `HandleCap` is re-attached to `dispatch_web_fetch` as a per-user *concurrency* bound (a
> re-purpose, not the parked-body bound this ADR detached). The "Inbound egress-response canary
> deferred to #339" residual is **closed** (core-side `ALFRED_WEB_FETCH_CANARY_TOKENS` source).
> See [ADR-0047](0047-web-fetch-handle-cap-reattach-and-inbound-canary.md). (Factual amendment;
> the ADR-0015/0016 amendment precedent — status flips stay with the maintainer.)

> **Amendment (2026-07-07, #339 PR4b-audit — #347 blocker 2 closed).** The "Action-deadline
> `TimeoutError` surfaces un-audited at the dispatcher" residual noted under Negative/accepted
> below is **closed**. `dispatch_web_fetch` now raises a typed `WebFetchActionTimeout`
> (`src/alfred/plugins/web_fetch/errors.py`) carrying `egress_id` / `destination_host` /
> `in_doubt` / `ledger_state`; `dispatch_tool` (`src/alfred/orchestrator/tool_dispatch.py`)
> writes one enriched `tool.dispatch` row via `TOOL_DISPATCH_TIMEOUT_FIELDS`
> (`src/alfred/audit/audit_row_schemas.py`) before returning. Three invariants pin this shut:
>
> 1. The `except WebFetchActionTimeout` arm MUST precede `except WebFetchError` in
>    `dispatch_tool` — `WebFetchActionTimeout` is a `WebFetchError` subclass, and Python
>    resolves `except` clauses top-down; reordering would silently swallow the forensic
>    fields into the generic `tool_error` row (subclass-before-base).
> 2. Exactly ONE audit row is written, at the orchestrator wiring (`dispatch_tool`) — not a
>    second `tool.web.fetch` row at the dispatcher (`dispatch_web_fetch`). This is consistent
>    with this ADR's existing layering (the dispatcher does not audit the timeout itself); the
>    Negative/accepted bullet below is closed by adding the audit one layer up, not by
>    re-layering where the audit lives.
> 3. `in_doubt = (ledger_state == "committed_no_response")`. A ledger-read failure during
>    classification forces the sentinel `ledger_state="read_unavailable"` with `in_doubt=True`
>    — the unsafe-but-safe direction; a read failure is never silently treated as "no side
>    effect occurred".
>
> **Scope: this closes #347 blocker 2 only.** The **C8 canary-`record_response`-cancellation
> residual** (a distinct bullet under Negative/accepted below) and the **DB-down
> durable-reconcile residual** (the ADR-0040 reservation note above) remain **OPEN** — this
> change does not touch the canary `record_response` write path or reconciliation against a
> down ledger backend. See
> [docs/subsystems/security.md](../subsystems/security.md#trust-boundary-contract) for the
> audit-vocabulary entry and [ADR-0046](0046-dual-llm-tool-result-flow.md) for the
> tool-result-flow cross-reference. (Factual amendment; status flips stay with the
> maintainer.)

> **ADR-0040 reservation note.** ADR-0040 is reserved for the comprehensive Spec-C egress ADR
> landing human-gated at G7-5. It is already referenced in `docker-compose.yaml`,
> `gateway/egress_relay.py`, `egress_audit.py`, `egress_relay_audit.py`, and two gateway tests
> as the home for the durable-reconcile and canary-env residuals. This ADR-0041 is its
> web.fetch-contract precursor and forward-links to it.

## Context

The C1 `RelayEgressClient` and C2 `EgressResponseExtractor` shipped in G7-2c
(PRs #345/#346, merge `d782812d`) proved the in-core relay-to-gateway wire end-to-end
via a synthetic driver. G7-2.5 re-homes the live `web.fetch` tool egress so that relay
machinery becomes a production path — the **side-effecting cutover**.

Three design decisions are coupled:

- Changing the `dispatch_web_fetch` return type is forced by the dedup ledger contract
  (which stores post-extraction T2, not raw T3 bytes), and in turn forces re-evaluation
  of `HandleCap`'s rationale.
- Removing `HandleCap` requires closing the shipped C2 unbounded-staging-map orphan before
  the removal is sound.
- Re-targeting rather than retiring the release-blocking adversarial test de-2026-004
  follows from both: the old property (active per-user refusal) no longer applies; the
  new property (global in-flight bound + no-orphan) does.

`dispatch_web_fetch` has zero production callers today (verified), so the return-type
change's only blast radius is tests.

## Decision

### Decision 1 — T3 `ContentHandle` → T2 `EgressExtractOutcome`

`dispatch_web_fetch` now returns a T2 `EgressExtractOutcome` instead of an opaque T3
`ContentHandle`. This is forced by the §5 dedup ledger shipped in C1: the ledger stores
*post-extraction T2*. A `IntentReplayComplete` replay returns the stored T2 — there are
no raw bytes to reconstruct a `ContentHandle` from. The fused fetch+extract model is the
only contract compatible with a ledger-backed web.fetch.

Consequence: web.fetch becomes a **fetch+extract unit**. The extraction schema (`schema:
type[ExtractionSchema]`) is a required per-call parameter, not baked in. The schema bounds
what the orchestrator may receive from attacker-influenced T3 bytes; a default would be a
wide free-text passthrough and would prejudge issue #339's live tool-call→schema mapping.

### Decision 2 — `HandleCap` detached from `dispatch_web_fetch`

`HandleCap` is **detached** from the `web.fetch` dispatcher path (no longer reserved or
released by `dispatch_web_fetch`). The `handle_cap.py` module and `test_handle_cap.py`
remain in-tree — a `canary_scanner.py` consumer keeps the module live; file-level deletion
is deferred.

`HandleCap` was designed to bound parked T3 bodies in the Redis content-store per user.
The fused model removes the Redis content-store write, eliminating the parked resource
`HandleCap` was built to bound. However, the parked resource is not fully eliminated: the
shipped C2 `QuarantineStagingMap` is unbounded and carries no TTL. A gate-deny or
extract-failure before the extractor transport drains the map orphans a `TaggedContent[T3]`
body for process lifetime.

Detachment is therefore sound only paired with the **C2 drain-on-error fix** (§4 fold C9):
stage-after-gate, or a `finally` block that drains the staging map if extraction did not
complete. With that fix there is no parked resource, and `HandleCap` is genuinely vestigial
on the `dispatch_web_fetch` path.

The C9 fix is a co-shipped prerequisite of detaching `HandleCap` from `dispatch_web_fetch`
in PR1.

### Decision 3 — de-2026-004 re-targeted, not retired

The release-blocking adversarial test de-2026-004 proves an *active refusal* bound:
the 6th call is refused with a typed audit row, pre-network. The C1 semaphore queues
rather than refuses, so that property no longer applies to the fused path.

The re-target asserts two properties instead:

1. **Global in-flight liveness / no-hang bound** — the semaphore never deadlocks; in-flight
   count is bounded; all completions (success, error, gate-deny) release the slot. Anchored
   alongside `tests/integration/egress/test_quarantine_contention.py`.
2. **No orphaned T3 body on gate-deny** — the C9 drain-on-error fix is exercised; a
   gate-deny leaves the `QuarantineStagingMap` empty.

The resource-exhaustion-*refusal* payload — per-user fairness, `strict=True` xfail flip —
is explicitly deferred to issue #339. The re-target requires **explicit
`alfred-security-engineer` sign-off** in PR1.

## Consequences

### Positive

- The dedup ledger is internally consistent: the stored T2 and the returned T2 are the
  same type. A replay short-circuits without raw-byte reconstruction.
- `HandleCap` is detached from `dispatch_web_fetch` (zero production callers on this
  path). The `handle_cap.py` module and `test_handle_cap.py` remain in-tree; the
  `canary_scanner.py` consumer keeps them live. File-level deletion is deferred.
- de-2026-004 is preserved as a release-blocking adversarial property, now aligned with
  the correct post-C2 threat model (in-flight bound + no-orphan).
- The C2 drain-on-error fix closes the shipped staging-map leak regardless of how future
  callers fail, hardening the shipped C2 independently of G7-2.5.

### Negative / accepted

- **Per-user resource-exhaustion refusal bound deferred to #339.** Zero production exposure
  in G7-2.5 (no live caller until #339). This is a **merge-blocker on #339's first live
  `dispatch_web_fetch` caller PR** — security sign-off M4 required. The `alfred-security-engineer`
  dissent (correctly noting the C1 semaphore is global, not per-user) is recorded as the
  obligation that #339 must discharge.
- **Inbound egress-response canary deferred to #339.** The C2 inbound-canary seam
  (`ResponsePolicy.canary` → `inspect_response` → `InboundCanaryTripped`) is built, but the
  PR2 factory `build_web_fetch_egress_extractor` passes `canary=None`: there is no core-side
  canary-token source (`resolve_canary_tokens` is gateway-only, reading `ALFRED_CANARY_TOKENS`,
  and an env not set on the core). The gateway's OUTBOUND canary still runs (de-2026-008); the
  web.fetch INBOUND-reflection canary — a hostile origin reflecting a seeded token in its
  RESPONSE — is wired by #339 once a core-side token source exists. Enforced machine-visibly by
  the `de-2026-012` strict-xfail merge-blocker (#347 obligation list).
- **Action-deadline `TimeoutError` surfaces un-audited at the dispatcher.** This is defensible
  layering (the supervisor owns timeout audit; the pre-fire ledger intent + replay `in_doubt`
  makes the side-effect safe), but #339's orchestrator wiring MUST audit the surfaced
  `TimeoutError` and include a cross-layer test.
- **C8 residual — second trigger: canary `record_response` cancellation.** The C8 fix moves
  the ledger to a terminal-refused state on a canary trip. However, a cancellation during the
  canary `record_response` write itself (not only DB-down) also leaves the ledger
  `committed_no_response`, so an idempotent replay re-fires — re-sending the seeded canary to
  the hostile origin. #339's orchestrator wiring must audit and close this cancellation window;
  add it to the #347 obligation list alongside the C8 DB-down residual.
- **`language` source is a #339 residual.** The turn-user's `User.language` lands in #339.
  A `None` language is never stored silently; the choice is stated explicitly at the call
  site. HARD rule #3 is satisfied deferentially, not silently.
- **Broker secret-injection for authenticated fetch is a #339 residual** (HARD rule #6;
  C1b in §4 of the design spec). G7-2.5 is unauthenticated GET-only. Core-side DLP is the
  sole broker-secret defence for URL and headers at this slice; the defense-in-depth
  overclaim (that gateway DLP provides an independent layer) is corrected in PR1.
- **Schema-stability-in-dedup is load-bearing.** A replay must use the same schema; the
  method + URL + stable schema identity descriptor folds into the `compute_body_hash` input
  (C6 fix). A schema change invalidates any cached T2 at the same slot and fires a loud
  `EgressIdIntegrityError`.
- **5 MiB response size limit** (Spec C5) is enforced via the C2 `ResponsePolicy.max_bytes`
  assembled in PR2 (production assembly). The old `_DEFAULT_SIZE_LIMIT_BYTES` constant is
  removed; the size gate is now stateful, not global.
- The comprehensive ADR-0040 (G7-5, human-gated) and PRD §7.1 rewrite absorb the full
  record. This ADR-0041 is the precursor and will be superseded when ADR-0040 lands.

## Alternatives considered

### D1 1b — gateway per-tool MIME enforcement

MIME content-type enforcement placed in `gateway/egress_relay.py` per tool, rather than in
a generic pre-extract seam in C2. Rejected: the gateway relay is tool-agnostic by design
(ADR-0036, ADR-0039); adding per-tool logic couples the relay to tool semantics and
contradicts the tool-egress abstraction. The C2 pre-extract inspection seam is the correct
placement: it runs after the relay returns an `EgressResponse` and before minting or staging
the body, keeping the gateway relay a generic fetch+return component.

### D1 1c — drop MIME enforcement entirely

MIME checking omitted; rely on the dual-LLM split + Pydantic schema validation as the sole
containment. Rejected: the MIME gate is advisory defense-in-depth against content-type
laundering (a hostile origin claiming `text/html` over binary or multi-part payloads).
Dropping it removes a cheap narrowing — a failed MIME check surfaces as a soft
`TypedRefusal` recorded in the ledger so replay short-circuits — with no structural gain.
The gate is never the injection control (that is the dual-LLM split); it is a cost/quality
narrowing that pays for itself on the first correctly-refused binary response.

### D3 3a — keep `HandleCap`

Retain the per-user `HandleCap` even in the fused model, either adapting it to the
`QuarantineStagingMap` resource or keeping it as a no-op placeholder for #339. Three
reviewers to one (3-to-1 disposition) favored removal from the dispatcher path (detach,
not delete the module — `handle_cap.py` remains in-tree for its `canary_scanner.py`
consumer); one reviewer (`alfred-security-engineer`)
dissented, correctly noting the C1 semaphore is global, not per-user, so per-user fairness
is lost on the fused path.

Reconciled by four facts:

1. Zero production exposure until #339 — there is no live caller, so the fairness loss has
   no operational effect in G7-2.5.
2. The C9 drain-on-error fix closes the actual in-memory leak regardless of `HandleCap`.
3. de-2026-004 is re-targeted (not retired) to the correct in-flight property.
4. Explicit `alfred-security-engineer` sign-off is granted for G7-2.5 on condition that
   the per-user bound is a hard merge-blocker on #339's first live caller.

The dissent is the #339 obligation recorded in Consequences above.

## References

- PRD §7.1 (Security & Prompt-Injection Defense), Spec C (G7 egress control plane /
  connectivity-free core)
- Design spec: `docs/superpowers/specs/2026-06-28-g7-2.5-web-fetch-rehome-design.md`
- ADR-0040 (reserved — comprehensive Spec-C egress ADR, G7-5)
- [ADR-0036](0036-gateway-adapter-hosting-inversion.md) — gateway adapter hosting inversion
  (gateway privilege model; gateway holds no `CapabilityGateNonce`)
- [ADR-0039](0039-gateway-adapter-inbound-bridge.md) — gateway adapter inbound bridge
- Epic [#333](https://github.com/alfred-os/AlfredOS/issues/333) (Spec C — egress control plane)
- Issue [#339](https://github.com/alfred-os/AlfredOS/issues/339) (per-user fairness / live
  wiring of `dispatch_web_fetch`)
