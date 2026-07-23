# ADR-0039 — Gateway-hosted-adapter inbound → core bridge (forward, don't dispatch; inbound-only)

- **Status**: Accepted
- **Date**: 2026-06-21
- **Slice**: Spec B inbound bridge (epic #309) —
  `docs/superpowers/specs/2026-06-21-gateway-adapter-inbound-bridge-design.md`
- **Relates to**: [ADR-0031](0031-comms-socket-transport-for-the-foreground-tui.md)
  (the comms socket / leg the forward rides),
  [ADR-0032](0032-gateway-comms-resume-transport.md) (seq/ack codec + replay buffer the
  forward inherits), [ADR-0033](0033-core-owned-lifecycle-signalling.md) (the per-boot
  epoch + lifecycle the leg carries),
  [ADR-0036](0036-gateway-adapter-hosting-inversion.md) (the gateway hosts + supervises
  the adapter child; the core observes — this ADR adds the *inbound data path* that
  inversion left open),
  [ADR-0025](0025-comms-stdio-transport-line-delimited-and-thin.md) (the child wire).
  Issues [#288](https://github.com/alfred-os/AlfredOS/issues/288) (Spec B),
  [#309](https://github.com/alfred-os/AlfredOS/issues/309) (this epic),
  [#235](https://github.com/alfred-os/AlfredOS/issues/235) (deferred persona-outbound),
  [#230](https://github.com/alfred-os/AlfredOS/issues/230) (egress / Spec C).
- **Supersedes**: —
- **Human-gated**: yes (AI agents propose; humans approve).

## Context

ADR-0036 inverted adapter hosting: the always-up, privileged gateway spawns and supervises
the sandboxed comms-adapter child; the core *observes* lifecycle via audited
`gateway.adapter.*` status frames and *provides the spawn credential* over a core round-trip
(fd-3). The G6-2b/G6-3/G6-5 substrate realised spawn, supervision, credential delivery, and
status — but **left the adapter child's actual inbound messages with no wired consumer.** The
seam is `GatewayProcess._unwired_runner_factory` (`src/alfred/gateway/process.py:209-228`),
which fails loud precisely because the standalone gateway does not build the daemon's
session/dispatch graph.

There is a genuine architecture fork on *how* a hosted adapter's inbound reaches dispatch:

1. **Forward (option 1):** the gateway forwards the opaque inbound to the core over the
   ADR-0031 leg; the core dispatches (`process_inbound_message`:
   identity-resolve → burst-limit → quarantined-extract → ingest → dispatch).
2. **Gateway runs the session (option 2):** the gateway builds a full session-bearing
   `CommsPluginRunner` and dispatches locally. This is the latent assumption in the merged
   G6-5 plan ("reuse the daemon's `_build_comms_runner`").
3. **RPC (option 3):** the gateway calls a per-inbound core dispatch RPC.

Option 2 would force the privileged, network-facing gateway to hold the orchestrator, the
quarantined extractor, the secret broker, the capability gate, and the audit DB — collapsing
the connectivity-free-core posture and concentrating the highest-value trust surface in the
most-exposed process. Option 3 re-builds resume/exactly-once on a new control surface that
the leg already provides for free, and couples inbound liveness to a live core.

The decision is therefore taken (per the #309 brief) **before** the flag-day, because the
flag-day deletes the daemon-spawn path and must not be done atop the wrong inbound model.

**Wire fact established (was open as F4a).** The hosted child's `inbound.message` is a
**fire-and-forget JSON-RPC notification with no id** (`plugins/alfred_discord/notifications.py`,
`inbound_emitter.py`). The child awaits **nothing** for an inbound. The daemon's fixed-shape
`_FIXED_ACK` is **not** a reply to that notification — it is a *separate* host-initiated
`outbound.message` **request** (daemon_runtime.py:183-217) the child answers with an
`OutboundMessageResult` (server.py:97-128) and that produces a real platform send. This makes
the epic **inbound-only** and the fixed ack itself part of outbound (#235).

## Decision

**Adopt option 1, inbound-only: the gateway forwards a hosted adapter's inbound to the core
as an opaque leg payload; the core re-parses and dispatches via `process_inbound_message`.
The epic carries no reverse core→gateway→child path; all outbound is deferred to #235.**

Concretely:

1. **`_unwired_runner_factory` is replaced by a session-LESS `GatewayInboundForwardRunner`.**
   It reuses the `CommsPluginRunner` single-reader pump mechanics (read / crash / EOF /
   teardown) via an injectable **inbound disposition** seam, but its inbound leaf
   **forwards** the child's `inbound.message` instead of dispatching it. It runs no identity
   resolution, no burst limit, no quarantine, no sub-payload promotion, no capability gate,
   no audit DB — all of those stay core-side. The gateway disposition carries no session and
   no crash-synth/restart path (the supervisor owns crash detection). It gives **every** child
   notification an explicit disposition: `inbound.message` → forward; `adapter.crashed` →
   supervisor + status leg; `adapter.rate_limit_signal` and `adapter.binding_request` →
   gateway-local **loud audited drop** (no core route exists yet, and blind-forwarding
   `binding_request` would be an audit-write DoS amplifier on the un-rate-limited plugin
   path) — any unhandled-but-known method is a loud audited drop, never a silent skip.

2. **The forward is payload-blind, and the envelope `adapter_id` is minted from the spawn
   binding (HARD requirement).** The opaque T3 body rides the **per-adapter `GatewayLeg`
   payload-unit channel** (the same `write_leg_unit` → seq/ack → `ReplayBuffer` path the TUI
   leg uses) and is **byte-stable across replay** (so the embedded `inbound_id` is stable and
   G0 dedup is never a silent no-op). The routing metadata (`adapter_id`) is carried
   out-of-band in a method-bearing `gateway.adapter.inbound` envelope and **MUST** be sourced
   from the gateway's **per-child spawn binding** (the value the child was spawned under),
   **NEVER** read from the body — this is a stated requirement, not implementation discretion,
   because envelope==body equality alone is vacuous if an implementation copies the body's id
   into the envelope. The `inbound_id` stays *inside* the opaque body for the core to extract.
   The gateway never `json.loads` a forwarded body.

3. **The core receives via a new method route with two-sided admission.** The daemon already
   runs a `CommsPluginRunner` as HOST over the gateway leg (credential resolver + status
   observer wired). Its `_route_notification` gains a `gateway.adapter.inbound` arm that
   (a) validates the envelope `adapter_id` **equals the body-derived `adapter_id`**, and
   (b) **mirrors K4 registered-leg admission on the RECEIVE side** — refusing an envelope
   `adapter_id` that is not a known/registered adapter the gateway is authorised to host
   (mismatch or unregistered → loud K4-style refusal + signed audit row, frame dropped, never
   default-routed). `adapter_id` is a **closed-vocab KIND** (`"discord"`, `"tui"`), so a spoof
   = self-attributing a registered kind; the registered-leg admission is what makes the closed
   vocabulary load-bearing. It then selects the **per-`adapter_id` core-side collaborator set**
   (sub-payload promoter keyed on the validated kind, identity resolver, rate-limiter,
   handler) — `process_inbound_message` is collaborator-parameterised and fail-closes
   (`PromoterRequiredError`) without the Discord promoter, so the receive arm is **not** a bare
   pipeline call — and feeds the re-parsed `InboundMessageNotification` into the dispatch. The
   discriminator from a TUI dial-in frame is the **method name** (consistent with the existing
   `gateway.adapter.spawn_request` / `gateway.adapter.*` status discriminators), not an
   `adapter_id` heuristic. A malformed/unparseable forwarded body is a loud bounded-field audit
   drop that **acks the leg frame to drain it** (no infinite replay) and is caught by the HOST
   runner's catch-and-continue (no reader crash).

4. **The leg ack means DISPATCHED on the forwarded path (no silent inbound loss); the honest
   guarantee is at-least-once on the dispatched edge.** The durable-intake signal is the leg's
   **contiguous high-water** — `BoundedSeqAckTracker.cumulative_ack()`, a single CONTIGUOUS
   high-water emitted periodically, **not** a per-frame ack. On the direct daemon/TUI path a
   frame's seq enters that high-water on G0 commit (receipt) — that is **unchanged**. But #309
   makes the leg the durable-intake authority, so on the **forwarded** path the core records the
   seq (`ack_tracker.observe(wire_seq)`) **only after it has successfully DISPATCHED**, never on
   receipt. The G0 commit and the `observe` **move together** to this dispatched edge. A
   dispatch failure → the seq is **not** `observe`d → it never enters the high-water → the leg
   replays it on reconnect → re-dispatch, with a closed-vocab `dispatch_failed` audit row
   distinct from `replay_observed`. Because the high-water is contiguous, an un-`observe`d
   (failed) seq **stalls the high-water**, so on replay the failed frame **and its
   successfully-dispatched tail** are re-delivered + re-parsed (the tail re-dedups via G0 to
   `replay_observed`, not re-dispatched — **head-of-line replay amplification**, bounded by item
   4b). The forwarded-path G0 commit on `(adapter_id, inbound_id)` is durable **only once
   dispatch succeeds**, so no committed-but-undispatched row can dedup a retry into a silent
   loss. **The honest delivery guarantee is therefore exactly-once *once committed*;
   at-least-once on the dispatched edge** — there is no atomic commit↔dispatch, so a crash
   between dispatch returning and the commit becoming durable re-dispatches the frame (and its
   tail) on replay. On the steady (no-crash) path this collapses to exactly-once. (Mechanism —
   commit-after-dispatch / transactional / compensating — is an engineer call; the semantic
   invariant is fixed.)

   - **4b. Bounded failure-replay + crash-window posture (the poison ceiling).** The
     at-least-once loop is **bounded**: the core keeps a per-`(adapter_id, inbound_id)`
     dispatch-attempt counter; each re-`quarantined_extract` attempt **charges the cost budget**
     and writes a `dispatch_failed` row with the attempt count; on exceeding a small ceiling **N**
     the frame is routed to a **terminal `gateway.adapter.inbound.poisoned` dead-letter row** and
     **ack-to-drain**ed (`observe(wire_seq)` purely to release the stalled contiguous high-water
     so the tail can trim) — never dispatched, never committed, never an unbounded replay or
     provider-cost drain. The crash-window double-dispatch (dispatch-success-then-crash-before-
     commit) posture is **at-least-once-with-idempotent-effect-where-possible**: the same poison
     ceiling bounds it and common-path G0 dedups the ordinary replay; where an effect cannot be
     idempotent, the bounded double-dispatch is the accepted, documented cost of the
     no-atomic-commit design.

   - **4c. One-path-per-`adapter_id` invariant.** The two coexisting G0 semantics — receipt-time
     (direct TUI/daemon-spawned) and dispatched-edge (forwarded) — are safe **only because each
     `adapter_id` maps to exactly one leg / one entry route** (kind `"tui"` is always direct;
     a hosted kind like `"discord"` is always forwarded). An `adapter_id` is never delivered over
     both routes, so the same `(adapter_id, inbound_id)` can never be committed under both
     semantics. The registered-leg admission (item 3) + the spawn-binding-minted envelope id
     enforce this single-route mapping; it is an explicit invariant.

5. **#309 includes NO reverse path. All outbound is #235.** Because `inbound.message` is
   fire-and-forget, there is no inbound ack to deliver; the `core.adapter.outbound` frame, the
   gateway lifecycle-router outbound consume arm, and any reverse envelope model are **cut**.
   The daemon's fixed protocol ack (a separate host→child `outbound.message` request that
   lands a platform send and returns an `OutboundMessageResult`) and any persona-authored reply
   (rich outbound, DLP-scanned body, `OutboundQueue`, addressing-drift) stay the **#235**
   deferral. The only feedback crossing core→gateway in #309 is the existing leg ack (item 4).

6. **Resume + the dispatched-edge delivery guarantee come from the leg + G0.** A registered
   per-adapter leg gives the forward the per-leg `ReplayBuffer` (replayed on reconnect) and the
   core's G0 commit-once on `(adapter_id, inbound_id)` for free — so a hosted adapter's inbound
   gets the **exactly-once-once-committed; at-least-once-on-the-dispatched-edge** guarantee
   (item 4) across a core restart (the Spec B goal), with the dispatched-edge ack closing the
   core-side-dispatch-failure silent-loss window and the poison ceiling (item 4b) bounding the
   replay.

The bridge lands first (sub-slices G6-7-1..6 + the privileged real-spawn proof G6-7-7); the
flag-day (delete the daemon-spawned Discord path + Compose service + secret cutover — the
deferred G6-5 Tasks 11–15) is a follow-on slice (G6-7-8) gated on G6-7-7 going green **and**
the `integration-privileged` lane being promoted to currently-required (see Consequences /
lane honesty). **The sub-slices use the G6-7 banner** because the merged G6-5 plan already
assigns G6-6 to the separate adversarial-corpus / `adversarial.yml`-to-required scope.

## Invariants this preserves

- **Gateway payload-blind (hard rule #5):** the T3 body is forwarded opaque + byte-stable; the
  only method-peek stays the gateway's lifecycle router; `adapter_id` is spawn-binding metadata
  minted by the gateway, never read from the body.
- **Quarantine + capability gate stay core-side (hard rule #5):** `quarantined_extract` runs
  on the core, on the body the core re-parses; the gateway has no extractor and no gate for
  forwarded inbound.
- **Credential never returns to the gateway (hard rule #6):** the inbound forward carries no
  credential and there is no reverse path in #309; the credential path is spawn-only fd-3
  (G6-3).
- **Fail-loud / no silent loss / no unbounded replay (hard rule #7):** a forward-transport
  fault is a loud drop with the frame left buffered for replay; a **core dispatch fault leaves
  the frame un-acked → replayed → re-dispatched** (item 4); a **deterministically-failing
  (poison) frame is bounded by the dispatch-retry ceiling → terminal `poisoned` dead-letter +
  ack-to-drain** (item 4b); a forge mismatch / unregistered adapter / malformed body is a loud
  audited drop; a leg-full halts the child reader (back-pressure, not drop). No path silently
  loses an inbound and no path replays (or re-charges provider budget) forever.
- **Connectivity-free core posture (ADR-0036):** the core still observes + dispatches; the
  gateway stays a T1 carrier — the inversion's data path is completed without moving trust into
  the front door.
- **Dual-LLM split (PRD §7.1):** unchanged — the privileged orchestrator never sees raw T3;
  only the core's quarantined extractor does.

## Consequences

**Positive.**

- The Spec B resume goal extends to platform adapters with the least new trust-bearing code:
  the forward reuses the leg's seq/ack + `ReplayBuffer` + G0 already adversarially tested.
- The privileged gateway gains **no** new trust surface (no orchestrator, no extractor, no
  vault, no audit DB) — it stays "stable-code, privileged, payload-blind."
- The flag-day becomes a clean follow-on, not an atomic mega-change atop an unproven model.
- The core's dispatch pipeline **logic** is unchanged — only a new entry route, a per-adapter
  collaborator registry, the forwarded-path dispatched-edge ack, and the poison ceiling — so the
  trust-boundary code that is already 100%-covered + adversarially gated is not rewritten.
- Cutting the reverse path removes the epic's former "sharpest call" and a whole reverse
  vocabulary; #309 is materially smaller and cleaner (inbound forward + durable leg + the
  dispatched-edge delivery guarantee only).

**Negative / costs.**

- A new method (`gateway.adapter.inbound`) + an envelope model widen the leg's method
  vocabulary (mitigated: the same pattern as the existing status + credential frames; the
  method route keeps it explicit and audited).
- The `CommsPluginRunner` single-reader pump must grow an injectable inbound disposition (a
  refactor of the most-tested I/O module; mitigated by keeping the existing session-dispatch
  the default disposition — behaviour-preserving, gated by a byte-for-byte-unchanged test).
- The core receive arm is **not** "feed the unchanged pipeline": it needs a per-`adapter_id`
  collaborator registry (promoter + classifier expectations) keyed on the validated envelope
  `adapter_id`, or the Discord promoter-required guard trips.
- A narrow **strengthening** of the leg-router "no new core wire field" principle (arch-M3):
  the envelope carries `adapter_id` to the core as the route discriminator, mitigated by the
  spawn-binding origin (item 2) + core-side equals-body-derived validation + registered-leg
  admission (item 3) — the body stays authoritative and a forged-body/valid-leg mismatch is
  now closed loud.
- **Head-of-line replay amplification** is the disclosed cost of the contiguous-ack +
  dispatched-edge model (item 4): an un-`observe`d failed/poison seq stalls the contiguous
  high-water, so on reconnect the failed frame and its successfully-dispatched tail are
  re-delivered + re-parsed (the tail re-dedups via G0, not re-dispatched). Bounded by the poison
  ceiling (item 4b); accepted as the price of resume + no-silent-loss.
- New trust-boundary modules (`inbound_forward_runner.py`, the core-side disposition +
  collaborator registry) must be added to **both** ci.yml per-file 100%-coverage sites (the
  python-job `hashFiles` guard + the `coverage-gates --include` list).
- **Lane honesty (#245):** the privileged real-spawn e2e (G6-7-7) lands on
  `integration-privileged`, which is currently **PENDING-required** (`docs/ci/required-checks.md`
  §Pending) — not yet a merge gate. Until it is promoted, the **gating property lives on the
  non-root in-process companions**; promoting the lane to currently-required
  (`gh api POST …/contexts` + the required-checks manifest row) is part of G6-7-7's
  done-definition, and the flag-day (G6-7-8) must wait on a check that is actually required.

## Alternatives (rejected)

- **Option 2 — gateway runs the session.** Collapses the connectivity-free-core posture;
  puts T3 dispatch, the extractor, the vault, and the gate behind the most-exposed privileged
  process — the inverse of ADR-0036's intent for the data path. Rejected.
- **Option 3 — per-inbound core dispatch RPC.** Re-builds resume/exactly-once on a new
  control surface the leg already provides; couples inbound liveness to a live core; adds a
  second core-facing surface. Rejected.
- **A reverse inbound-ack path in #309.** Rejected on the wire fact: `inbound.message` is
  fire-and-forget, so no inbound ack exists or is needed; the only request/response is the
  outbound direction, which is #235.

## Amendments

### 2026-06-22 — G6-7-3 forward shape was non-conformant; corrected in G6-7-4 Task 0 (commit af9c3b5e)

**What the original decision said (item 3).** The core's `_route_notification` gains a
`gateway.adapter.inbound` arm that discriminates the forwarded inbound from other leg frames by
**METHOD NAME**.

**What G6-7-3 actually shipped.** `forward_adapter_inbound` serialized the
`GatewayAdapterInboundEnvelope` via `model_dump_json()` as a **bare JSON object** — no
`"jsonrpc"` field, no `"method"` field. The daemon pump parses leg units as JSON-RPC frames; a
frame with no `"method"` key is treated as a **response frame** (it has no `id` either, so it is
silently dropped). Item 3's method-name discriminator was therefore **unimplementable** against the
G6-7-3 forward shape: the core's router never saw a `gateway.adapter.inbound` method to route.

**Correction (G6-7-4 Task 0, commit af9c3b5e).** `forward_adapter_inbound` now serializes the
forward as a **JSON-RPC notification frame**:

```json
{"jsonrpc": "2.0", "method": "gateway.adapter.inbound", "params": {"adapter_id": "…", "body": "…"}}
```

No `"id"` (fire-and-forget, mirroring the child's own `inbound.message` notification). The opaque
body rides verbatim inside `params.body` (payload-blind, byte-stable for G0 — SEC-309-2
preserved). The Decision body above is unchanged and remains authoritative; this amendment records
the G6-7-3 non-conformance and the G6-7-4 correction.

**PERF-309-1 — unbounded per-replay `quarantined_extract` cost (deferred to G6-7-5).** Item 4b
specifies a dispatch-attempt poison ceiling that bounds the replay cost of a deterministically-
failing forwarded frame. That ceiling (**item 4b**) is **not yet implemented** — it is deferred to
G6-7-5. Today, a forwarded frame that fails dispatch on every attempt replays **unbounded** across
core reconnects, re-charging the `quarantined_extract` cost on each replay. This is contained by
two test-only posture facts:

- The gateway-hosted Discord forward leg is **test-only** until G6-7-5 ships the poison ceiling
  and G6-7-8 completes the flag-day; no production inbound traverses the forwarded path today.
- The daemon's quarantined child runs a **deterministic-echo loop** (no real LLM, no provider
  cost, no network egress) — PR-S4-11c-2b; the real LLM child is hard-blocked behind issue #230.

Item 4b does NOT bound replay cost today. Do not imply otherwise when describing the current
system.

### 2026-06-22 — G6-7-5: item-4b poison ceiling implemented; PERF-309-1 closed

**Item 4b is now implemented.** The ceiling is **N=5**
(`_FORWARDED_DISPATCH_ATTEMPT_CEILING` in `src/alfred/comms_mcp/inbound.py`). The durable
counter is the new Postgres `forwarded_dispatch_attempts` table (composite primary key
`(adapter_id, inbound_id)`), backed by `PostgresForwardedDispatchAttemptStore`
(`src/alfred/memory/forwarded_dispatch_attempts.py`). The store is Postgres-backed —
not in-memory — because forwarded-dispatch replay happens **across core restarts**; an
in-memory counter resets exactly when the bound is needed. That alternative is explicitly
rejected in the module docstring.

**Mechanics (off-by-one stated honestly).** The increment fires AFTER `quarantined_extract`,
at entry to the post-extract region. The ceiling check fires BEFORE `quarantined_extract`,
reading the current count. This means:

- Attempts 1 through N each call `quarantined_extract`, then increment the ledger.
- On attempt N+1 (the 6th, at N=5) the pre-extract read returns N ≥ ceiling → the frame is
  dead-lettered (`comms.inbound.poisoned` audit event, `result="poisoned"`, migration 0020)
  and ack-to-drained without ever calling `quarantined_extract` again.

The ceiling therefore bounds `quarantined_extract` to at most N=5 calls per
`(adapter_id, inbound_id)`.

**Coverage scope.** The increment is placed at post-extract entry, so any un-observed /
non-draining downstream failure — T3-promotion emit, ingest, OR dispatch — is ceilinged.
This is not "dispatch-only"; the count rises on every attempt that reaches the post-extract
region, regardless of where the tail fails. This is the complete closure of PERF-309-1:
the prior amendment marked item 4b as deferred and stated that a deterministically-failing
forwarded frame replays unbounded. **PERF-309-1 is now closed.**

**BudgetGuard clarification.** `BudgetGuard` (`src/alfred/budget/guard.py`) exists in the
system. `quarantined_extract` is NOT wired into it here (it records only latency). The
poison ceiling — not the budget mechanism — is the bound on re-extract cost. Wiring
`quarantined_extract` into `BudgetGuard` is explicitly declined for this slice: the
deterministic-echo child carries no provider cost until the real-LLM child lands behind
issue #230; there is nothing to meter yet.

**Deliberate sheds stay distinct from poison.** The burst-drop, budget-capped, and
unbound-binding deterministic-refusal arms all DRAIN without calling `increment`. Only a
frame that reaches post-extract entry charges the ledger. An attacker or system error that
causes a deliberate shed on every replay can never accumulate a poison count; the audit
vocabulary stays distinct (`budget_capped` / `dropped` / `binding_requested` vs `poisoned`).

**"At least N" semantics.** The read and increment are not a single atomic operation, so
under concurrent replay the ceiling fires after AT LEAST N attempts (never fewer). The
atomic UPSERT increment and the idempotent `BoundedSeqAckTracker.observe` keep the count
correct without locking — no lost increment, no double-effective-drain.

**Head-of-line amplification (unchanged, disclosed).** Each of the N replays re-delivers and
re-parses the dispatched tail behind the stalled seq (the tail re-dedups via G0 to
`replay_observed`, not re-dispatched). Total bounded cost: N × extract + N × tail-reparse.
This is a known, documented consequence of the contiguous-ack model.

**Migration 0020 downgrade exception.** The downgrade path deletes `result='poisoned'` audit
rows (with a loud `RAISE NOTICE`). This is a known append-only-audit exception, mirroring
the same pattern in migration 0019. Operators who run a downgrade lose the dead-letter history
for that window.

**No TTL / sweeper (follow-up).** The `forwarded_dispatch_attempts` ledger has no GC sweep in
this slice — it grows unboundedly, like the never-swept sibling `inbound_idempotency` table.
A `last_failed_at` index exists for future GC. A sweep is a tracked follow-up, not a
blocker.

**Triage.** `alfred audit log` now has a `--reason` filter and renders the drop reason via
`_row_reason`. For terminal receiver drops the reason comes from `subject.reason`; for the
`comms.inbound.poisoned` dead-letter it comes from the `result="poisoned"` discriminator
(the `poisoned` row carries no `subject.reason`). The render + filter logic shipped in G6-7-5;
operator-visible value lands once PR-S3-7 wires the `_query_audit_log` backend (currently a
stub that raises).

The Decision body above is unchanged and remains authoritative. This amendment records what
shipped in G6-7-5 and closes PERF-309-1.

### 2026-06-23 — G6-7-6: end-to-end composition proof + adversarial-corpus lane promotion

**The forwarded path is now proven end-to-end over real infrastructure.** Two new integration
tests cover the composition; they run under different CI gates (see `docs/ci/required-checks.md`):

- `tests/integration/comms/test_forwarded_poison_ceiling_postgres.py` — composes the N=5
  poison ceiling through the REAL `GatewayForwardedInboundReceiver` +
  `process_inbound_message(commit_at_dispatch_edge=True)` + the REAL
  `PostgresForwardedDispatchAttemptStore` + `PostgresInboundIdempotencyStore` + a real Postgres
  `AuditWriter`. Asserts: exactly N extracts per `(adapter_id, inbound_id)` pair (the ceiling
  bounds it to ≤N; the sequential drive charges exactly N); exactly one content-free
  `comms.inbound.poisoned` audit row; the durable ledger reaching the ceiling; G0 never committed
  on the poison path; and the drain releasing the stalled contiguous high-water so the tail can
  advance. **No root requirement → this leg genuinely gates under the currently-required
  `Integration` check.**
- `tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py` — drives a
  forwarded **discord** `gateway.adapter.inbound` frame over the REAL `comms-tui.sock` + seq
  codec into the real daemon HOST runner via the production `core_link.forward_adapter_inbound`.
  Asserts: a discord `comms.inbound.t3_promoted` audit row and a committed dispatched-edge G0
  `inbound_idempotency` row. **Carries `@pytest.mark.skipif(_LAUNCHER_REQUIRES_ROOT)` (Linux and
  non-root), so it SKIPS on the non-root `Integration` runner and executes only under the root
  `integration-privileged` job — itself still PENDING-required (promoted at G6-7-7). Until then
  this leg's merge-gating value is Pending, exactly as the existing TUI / PR-S4-11b launcher-spawn
  legs; the poison-ceiling test above is the leg that gates the forwarded path on a
  currently-required check.**

**Explicit chain to the 2026-06-22 G6-7-5 amendment (arch-006).** That amendment closed
PERF-309-1 with a MOCK-store proof and covered the durable store only in isolation. This A2
test is the REAL-Postgres composition that the mock-store proof deferred: the ceiling's coverage
story is now end-to-end — in-memory ledger → real `PostgresForwardedDispatchAttemptStore`
through the real `GatewayForwardedInboundReceiver` + `process_inbound_message`.

**The adversarial corpus becomes a required merge gate.** `adversarial.yml` is release-blocking
(`continue-on-error` removed), unfiltered (the `paths:` filter dropped so it runs on every PR),
and fail-closed on an empty or moved corpus. This PR ESTABLISHES the gate; the `Adversarial
corpus` status check is registered Pending-required in `docs/ci/required-checks.md` and is moved
to currently-required by the tracked post-merge promotion (`gh api POST …/contexts` once the
workflow has run on a subsequent PR) — at which point the G6-6 governance follow-up (the
`Comms credential adversarial corpus` step's NOTE in `ci.yml`) is fully closed and that interim
discrete step is removed.

**COVERAGE HONESTY (sec-001).** The required `Adversarial corpus` check gates the NON-bwrap
corpus only — the 6 `@_bwrap_required` `sandbox_escape` payloads (`sbx-2026-012`/`-013`) SKIP
on its non-root runner and are NOT yet on any currently-required check (`integration-privileged`
is still PENDING-required). Promoting that lane to required and the Discord flag-day are G6-7-7
and G6-7-8 respectively. **The gateway Discord leg stays TEST-ONLY until G6-7-8.** A
reasoned-skip CI guard asserts those payloads stay collected so they cannot silently vanish. Note
for operators: the now-unfiltered required gate depends on ambient Docker (Postgres/Redis via
Testcontainers in the `dlp_egress`/`state` legs); a testcontainer hiccup is infra flake, not a
corpus regression — the workflow fails loud on Docker-absence rather than skipping.

The Decision body above is unchanged and remains authoritative.

### 2026-06-23 — G6-7-7: packaged probe + env-gated launch-target override (privileged real-spawn proof)

**Explicit chain to the 2026-06-23 G6-7-6 amendment (arch-006).** The G6-7-6 amendment
stated, in future tense: "Promoting that lane to required and the Discord flag-day are G6-7-7
and G6-7-8 respectively" and "carries `@pytest.mark.skipif(_LAUNCHER_REQUIRES_ROOT)` (Linux
and non-root), so it SKIPS on the non-root `Integration` runner and executes only under the root
`integration-privileged` job — itself still PENDING-required (promoted at G6-7-7)." This
amendment fulfils the G6-7-7 half of that promise: the real-spawn proof now EXISTS and the
`integration-privileged` lane now RUNS it. The promotion to currently-required remains
post-merge and soak-gated (see below) — the doc does not move the row until that step
completes. The flag-day promise ("G6-7-8 respectively") is unchanged.

**Option A rejected (sec-001/sec-002).** The first candidate design used an
`ALFRED_ENVIRONMENT`-gated test-injection seam inside the PRODUCTION Discord adapter
(`plugins/alfred_discord/lifecycle.py`) — a conditional branch that would have redirected
`lifecycle.start` to a no-op stub in `{development,test}`. Rejected on two grounds: (1) the
adapter's `lifecycle.start` immediately calls `bot.login()`, an HTTP call that raises in the
hermetic privileged lane (child is reaped before the pump starts → vacuous test), so the
seam would not even exercise the target; and (2) introducing a conditional branch into a
credential-bearing, network-connected, shipped adapter weakens a trust boundary that is already
in production — a seam that exists in the production binary is a permanent attack surface
expansion, not just a test convenience (sec-001/sec-002).

**Option B shipped: packaged probe module + env-gated constructor-injected override.** Two
components together form the privileged real-spawn proof:

1. **`src/alfred/gateway/discord_probe.py`** — a dedicated packaged probe module (in the
   wheel via `packages=["src/alfred"]`) that speaks the gateway adapter wire: handshake-first,
   reads a credential over fd-3 (content-free ack — it does not authenticate), emits exactly
   ONE scripted `inbound.message`, then blocks until stdin EOF so the host pump completes
   cleanly. Being a packaged module (not under `plugins/`) is load-bearing: the `kind=full`
   bwrap sandbox binds the interpreter prefix read-only, so `alfred.gateway.discord_probe`
   resolves off the bound proto py3.14 interpreter; a `plugins/` module would raise
   `ModuleNotFoundError` inside the sandbox.

2. **Env-gated launch-target override in `GatewayAdapterChildFactory`.** An `override_map`
   constructor parameter (type `Mapping[str, tuple[str, str]] | None`) redirects an adapter id's bwrap
   launch target (e.g. `discord` → the probe) when `ALFRED_ENVIRONMENT ∈ {development,test}`,
   read via the sanctioned `resolve_environment()` (renamed from `load_environment()`
   by [ADR-0053](0053-three-layer-environment-precedence.md), which also added the
   `.env` layer and the trust-floor refinement described there) **at each spawn call**
   (inside `_resolve_launch_target`, not at construction — `__init__` only stores the
   map). The guard is
   fail-closed by default: any non-None override map passed when `ALFRED_ENVIRONMENT` is
   `production` (or unset/unrecognised) raises `LaunchTargetOverrideRefusedError`, a subclass
   of `GatewayAdapterSpawnError`, which the supervisor's spawn-error arm audits as a
   `gateway.adapter.crashed` row. The rejected module string never appears in any audit
   field or log line (sec-003). This is a NEW test-only trust seam. It is recorded here as an
   amendment rather than a new ADR because it is a narrow, env-gated addition to an existing
   decision boundary (docs-003 disposition).

**The proof.** `tests/integration/cli/daemon/test_gateway_real_probe_spawn_forwarded_inbound.py`
(DOCKER-ONLY, `integration-privileged`, marked `@pytest.mark.skipif(_LAUNCHER_REQUIRES_ROOT)`):

- Spawns the REAL bwrap-sandboxed probe child via the production `GatewayAdapterChildFactory`
  (override `discord` → `alfred.gateway.discord_probe`, `ALFRED_ENVIRONMENT=test`).
- Delivers the bot-token credential over fd-3. Asserts it is ABSENT from the child's
  `/proc/<pid>/environ` — the G6-3 fd-3 delivery invariant is unbroken by the forwarding path.
- The probe emits its scripted `inbound.message`; the `GatewayInboundForwardRunner` forwards it
  over the real leg to real core dispatch.
- End-to-end assertions: a `discord` `comms.inbound.t3_promoted` audit row; a committed
  dispatched-edge G0 `inbound_idempotency` row for `(discord, inbound_id)`.

The non-root wire-contract companion is the G6-7-6 A1 test
(`test_forwarded_inbound_gateway_to_core_turn.py`). No new in-process companion is added
(#245 discipline: the existing A1 test covers the wire contract on the non-root `Integration`
runner).

**Provisioning.** `ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON` is the ADR-0030 twin of
`ALFRED_QUARANTINE_CHILD_PYTHON` — both are set to the same bound proto py3.14 interpreter
provisioned by the `integration-privileged` CI job. The launcher binds that prefix read-only
into the `kind=full` bwrap sandbox so the packaged probe module resolves.

**Promotion deferred (soak gate, devops-002/sec-004).** `integration-privileged` (now RUNNING
the real-spawn test for real) and `Adversarial corpus` are promoted to currently-required in a
POST-MERGE follow-up, after N≥3 consecutive green `integration-privileged` PRs, via
`gh api -X POST repos/alfred-os/AlfredOS/branches/main/protection/required_status_checks/contexts`.
Rollback: `gh api -X DELETE .../contexts/<name>` to de-require a flaking lane while
investigating. See `docs/ci/required-checks.md` for the full runbook.

**The gateway Discord leg stays TEST-ONLY until G6-7-8** (the flag-day: delete the
daemon-spawn path, add the `alfred-discord` Compose service, cut the credential source
over to the gateway). G6-7-7 proves the bridge is real; G6-7-8 makes it production.

The Decision body above is unchanged and remains authoritative.

### 2026-06-25 — G6-7-8: Discord flag-day complete; inbound bridge now production

**G6-7-8 annotation (#309):** the inbound bridge this ADR specifies is now in production. The Discord flag-day completed (standalone `alfred-discord` service deleted; gateway hosts the Discord child; token via core `ALFRED_DISCORD_BOT_TOKEN` → spawn-grant → fd-3); the first real platform inbound traverses the forwarded path in production.

## Resolved decisions (formerly open maintainer-steer flags)

- **F1 (runner factoring):** the injectable inbound-disposition seam with the daemon dispatch
  as the behaviour-preserving default; clean against `CommsPluginRunner`'s narrow session use.
- **F2 (carrier):** the opaque payload-unit / leg channel (for resume + G0), not the status
  `send` channel.
- **F3 (route discriminator):** new method `gateway.adapter.inbound` + core-validated
  envelope==body equality + registered-leg admission, envelope id minted from the spawn binding
  (Decision items 2–3) — a strengthening of arch-M3.
- **F4 / F4a (ack scope):** #309 is **inbound-only**; `inbound.message` is fire-and-forget;
  the reverse path is **cut**; all outbound (incl. the fixed protocol ack) is **#235**
  (Decision item 5).
