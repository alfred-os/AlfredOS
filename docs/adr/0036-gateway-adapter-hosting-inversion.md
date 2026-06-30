# ADR-0036 — Gateway adapter-hosting inversion + the SETUID privilege reframe

- **Status**: Accepted — security co-sign captured 2026-06-18 (maintainer, during
  the Spec B design session). This ADR **records** that captured co-sign; it does
  **not** request a new one.
- **Date**: 2026-06-18
- **Slice**: Spec B (Gateway Adapter-Hosting Inversion) —
  `docs/superpowers/specs/2026-06-18-spec-b-adapter-inversion-design.md` (§2, §5, §6, §8)
- **Relates to**: [ADR-0015](0015-slice4-containerised-quarantined-llm.md) /
  [ADR-0030](0030-first-party-kind-full-plugin-ships-in-wheel-under-bound-prefix.md)
  (launcher / bwrap sandbox — the gateway becomes a second launcher host),
  [ADR-0031](0031-comms-socket-transport-for-the-foreground-tui.md) (the TUI
  socket carrier the gateway also relays),
  [ADR-0032](0032-gateway-comms-resume-transport.md) /
  [ADR-0033](0033-core-owned-lifecycle-signalling.md) (the Spec A wire + lifecycle
  the gateway-hosted adapter legs and spawn-credential control frames reuse),
  [ADR-0037](0037-production-quarantine-sandbox-boundary.md) (the
  `alfred-bwrap` AppArmor/seccomp profiles the gateway now also carries),
  issue [#288](https://github.com/alfred-os/AlfredOS/issues/288) (the Spec B epic)
- **Supersedes**: —
- **Human-gated**: yes (AI agents propose; humans approve). The maintainer
  security co-sign for the privilege reframe was captured in the 2026-06-18 design
  session and is recorded here, not re-requested.

## Context

Today a comms adapter dies with the core. Discord runs as a standalone
long-running `alfred-discord` Compose service (reusing the core image, **no
SETUID**, a `secrets.toml` bind-mount); a core restart does not by itself kill
that service, but the adapter is not resume-integrated — it has no buffered /
replayed path to a restarted core, and the daemon-spawned adapter model ties an
adapter's life to the core boot graph.

Spec A introduced an always-up gateway that holds the **dial-in TUI** across a
core restart and replays its un-acked input. **Spec B generalizes that resume to
platform adapters** by making the gateway their host and supervisor: the gateway
spawns the sandboxed adapter child, owns its full lifecycle, and buffers + replays
its inbound to the core across a restart (spec §1). Once the gateway hosts the
adapter runner, *something* in the always-up tier must spawn the
`bwrap`-sandboxed adapter child — and must be able to do so during a core outage,
or resume breaks.

This ADR records the locked Spec B decisions (spec §2 decisions 2–5, §5, §6, §8)
that this PR (G6-1) realizes in isolation: the privilege reframe of the
`alfred-gateway` Compose service and the `devops-010` compose-invariant
reconciliation. **No adapter-hosting code lands in G6-1** — the
`GatewayAdapterSupervisor` and the credential client arrive in G6-2 / G6-3. The
SETUID capability and the sandbox profiles are granted here and lie **dormant**
until G6-2 hosts an adapter.

## Decision

### Lifecycle authority split (decision 2)

All five plugin mechanics — handshake, lifecycle, crash detection,
restart-backoff, circuit breaker — terminate in the **gateway**, because the
gateway is the adapter child's parent process and supervisor. The **core never
commands** an adapter's lifecycle; it **observes** via audited status
notifications (`gateway.adapter.{up,down,crashed,breaker_open}`,
Pydantic-validated core-side). "Core never commands" means the core issues no
start / stop / restart *directives*; it is **not** a claim that a (re)spawn is
possible with the core down — the core does *provide the spawn credential*
(decision 4), which is a precondition of any (re)spawn (see Credential, below).
This maximizes resume: running adapters survive a core restart untouched.

### Privilege reframe (decision 3) — the load-bearing G6-1 change

The **gateway gains `cap_add: SETUID` + bubblewrap + the launcher** *(maintainer
security co-sign, 2026-06-18)*. The single privileged always-up host is the
gateway itself, rather than a separate spawner sidecar (same trust tier, added
IPC, marginal isolation). The gateway is reframed from "dumb / stable /
low-privilege relay" to **"stable-code, privileged."**

Concretely in G6-1 (Compose service only — the image already carries
bubblewrap + the launcher via the shared `docker/alfred-core.Dockerfile`):

- `alfred-gateway` gains `cap_add: [SETUID]`.
- `alfred-gateway` gains the same `alfred-bwrap` AppArmor + seccomp profiles
  `alfred-core` carries (ADR-0037) — `security_opt: [apparmor=alfred-bwrap,
  seccomp=docker/seccomp/alfred-bwrap.json]` — so it *can* build the
  unprivileged user namespace a `bwrap` adapter child needs.

**`devops-010` reconciliation.** The compose-invariant test moves to a
**positive allowed-set** assertion rather than per-service negatives:

- `services-with-SETUID == {alfred-core, alfred-gateway}` — a new service silently
  gaining SETUID fails loud, and the privilege concentration is auditable in one
  place.
- `services-with-the-alfred-bwrap-profiles == {alfred-core, alfred-gateway}` — the
  two `bwrap`-spawning hosts (core: the quarantine child; gateway: adapter
  children).
- Adapters (`alfred-discord`) **never** get SETUID or `state_git`, and **never**
  carry the `alfred-bwrap` profiles — an adapter that could build the userns
  sandbox could impersonate the quarantine UID.
- The gateway **never** mounts `alfred_state_git` (the grant store stays
  core-only); this pre-existing invariant is verified, not changed, in G6-1.

The `alfred-discord` negatives stay in G6-1 (the service exists until the G6-5
flag-day); the positive-set assertions subsume but do not replace them until the
service is removed.

### Credential contract (decision 4 / §5)

The credential is **core-injects-at-spawn**, realized in Spec B as **fd-3
transient delivery**. The credential-concentration invariant ("no
network-holding process decrypts more than one platform cred plaintext") is
fundamentally a **Spec C** property; in B the core still has external network and
holds the vault, so B's job is **correct placement so C flips the switch with
zero credential movement**, not satisfying the invariant. Mechanism:

- On each (re)spawn the gateway sends `gateway.adapter.spawn_request{adapter_id}`
  to the core over the trusted leg; the core resolves the platform credential from
  its vault / secret-broker and returns
  `core.adapter.spawn_grant{adapter_id, credential_material}`, bound to the
  per-core-boot epoch and dedup-keyed.
- The gateway delivers the plaintext to the `bwrap` child **over fd 3**,
  mirroring the existing `quarantine_child_io.deliver_*_via_fd3` discipline —
  **never** via the child's environment (`/proc/<pid>/environ` is readable for the
  child's whole life, and env injection would breach the secret-broker-not-env
  HARD rule). The gateway holds the plaintext only transiently: received over the
  wire, written to the child's fd-3 write-end, then its own copy zeroed. It never
  retains across spawns, never caches, never holds a vault key, never decrypts.
- **B-achievable testable invariant:** the gateway never holds a vault key and
  never retains a credential past a single spawn; the credential never appears in
  the child's environment.
- **Credential during a core outage (default, recommended):** every (re)spawn
  requires a fresh `spawn_grant`; the gateway never caches the credential. Running
  adapters survive a core restart untouched (they need no re-credentialing). The
  only gap is an adapter that *crashes during* a core-down window: its restart
  loop **awaits the core link** — a **non-spin, loud + audited, bounded-backoff**
  wait with a **terminal alert ceiling** (past it the adapter is marked durably
  down with a distinct alert; no quiet-dark). A `spawn_request` interrupted
  mid-round-trip surfaces a typed loud error, not a hang. `spawn_grant` refusal,
  launcher-spawn failure, and fd-3 write / zero-after-write failure each raise a
  loud, audited spawn-abort — never log-and-continue.
- **Rejected overturn:** caching the resolved credential in `MADV_DONTDUMP` /
  zeroed memory so the gateway can re-spawn a crashed adapter during a core
  outage. It buys crash-resilience across outages but trades away the
  no-retention invariant — the most network-exposed process would hold platform
  plaintext over time. Rejected by default; revisit only if crash-during-outage
  proves operationally common.
- **Deferred to Spec C:** the core writes the credential **directly to the
  child's fd, bypassing the gateway entirely** (SCM_RIGHTS fd-pass), so the
  gateway never transits plaintext — closing the serial-harvest residual below.
  B's spawn contract is shaped so this is a drop-in swap (same fd-3 child-read
  path; only the *writer* moves from gateway to core).

### Credential contract realized (G6-3 annotation, #288)

G6-3 implements the decision-4 contract above. Three facts the original decision did
not pin down, recorded here so they cannot drift:

- **A third frame class on the ADR-0031 leg.** The gateway↔core leg was a
  fire-and-forget notification pump (opaque T3 payload units + `gateway.adapter.*`
  status notifications). G6-3 adds the **FIRST request/response pair** on that leg:
  `gateway.adapter.spawn_request{request_id, adapter_id, host_restart_seq, epoch}`
  (gateway→core) and `core.adapter.spawn_grant{request_id, …, credential_material}`
  (core→gateway — the first core→gateway *response* frame). A new id-correlation
  primitive on `GatewayCoreLink` (`request_spawn_grant` + a `_pending_grants` waiter
  registry; `_consume_frame`/`_route_unit` route the grant to its waiter) carries it.
  The grant is a **response to a gateway-initiated request** (a precondition the
  gateway consumes), NOT a core directive — the gateway decides whether/when to spawn.
- **Bounded-await, two distinct fail-closed arms.** await-core (decision 4) covers
  the link **down**. G6-3 adds a **bounded `wait_for` on the reply** so an UP leg
  whose grant is dropped/unrouted fails closed loudly (`CredentialReplyTimeoutError`)
  instead of hanging — distinct from `CredentialLegDownError` (link down → the
  supervisor's AWAITING_CORE). The epoch is sourced **live** per spawn from
  `current_core_epoch()` (a stale construction-time snapshot would DoS every spawn
  after a core bounce or accept a wrong-epoch grant). Dedup/replay key is canonical
  `(adapter_id, host_restart_seq, epoch)`; the resolver calls the broker **exactly
  once** on a true replay; the gateway **never caches** (it verifies the grant matches
  its outstanding request, else discards); an unsolicited/forged grant is refused.
- **Honest str-residency residual (maintainer C1, option (a)).** The credential is
  carried as a Python `str` end-to-end (matching `SecretBroker.get() -> str` and the
  shipped quarantine fd-3 path). An immutable `str` cannot be zeroed; the ONLY
  verifiably-zeroed object is the ephemeral `writev` `bytearray` *inside* the reused
  `supervisor/fd3_key_delivery.deliver_provider_key_via_fd3`. The brief
  broker-read→fd-3-write window is mitigated (not eliminated) the same way the
  quarantine path is. A cross-cutting `SecretBroker.get_bytes` + bytes-end-to-end that
  upgrades **both** the quarantine and adapter cred paths together is a **separate
  future hardening** (NOT in G6-3) — it keeps the two credential paths consistent. The
  credential is, however, **structurally un-loggable** in B: `SpawnGrant.credential_material`
  is `repr=False` with overridden `__repr__`/`__str__`, and `AdapterCredentialError`
  is built from `adapter_id` + a closed-vocab reason only (never from a `ValidationError`
  carrying raw input), so a value-sentinel sweep confirms the credential appears only on
  the fd-3 sink — never in an audit row, log line, frame repr, or exception.

### Ingress gate (decision 5)

The gateway enforces a **coarse two-tier per-adapter, payload-blind** gate: a
per-adapter sustained-rate token bucket **plus** an in-flight / concurrency cap on
the adapter→core leg, bounding any single adapter's flood without parsing
identities. This is an **explicit overturn of roadmap finding comms-F2** (which
proposed a per-platform-id gate at the gateway): payload-blindness is a
load-bearing invariant; a flood is bounded correctly by *volume*, not identity
(per-id keying misses the distributed-id case and would leak a stable per-user
identifier into the most-exposed process). Per-platform-id fairness stays the
core's existing `_PreResolutionLimiter`, **demoted to defense-in-depth and
explicitly not weakened or consolidated away** — the gateway cap is *additive*.
On trip: `ReplayBuffer` back-pressure + a `gateway_ingress_throttled_total{adapter}`
metric + an audit row; never a silent drop.

## Consequences

### Honest scope (§6)

- The gateway stays **payload-blind for T3 message bodies** — it parses only the
  out-of-band envelope (seq / ack / dedup / `adapter_id`); T3 tagging + extraction
  stay core-side at `process_inbound_message` (hard rule #5 intact).
- **Plaintext-credential transit (recorded honestly):** with
  core-injects-at-spawn where the gateway is the spawner, the gateway **does**
  transit *plaintext platform credentials* at spawn time — over the trusted
  `0600` / `SO_PEERCRED` / epoch leg, transient, written to fd-3, zeroed.
  "Payload-blind" applies to **message bodies**, not to spawn-time credential
  control frames.
- **Serial-harvest residual:** a **compromised gateway can serially harvest every
  platform credential** via legitimate `spawn_request` / `spawn_grant` calls. This
  is distinct from (and not mitigated by) "holds no vault key." The bound is
  **per-adapter bwrap + netns + scrubbed env + fd-3 transient cred + no vault
  key** — *not* the process count. The residual is closed by Spec C's
  connectivity-free core (the gateway loses the network that makes harvest
  exfiltrable) + the C-era core→child fd-pass.
- **Per-adapter isolation:** each adapter is a separate `bwrap` child receiving
  its credential over its own fd-3 with a scrubbed env and no shared credential
  memory; a compromise of one adapter cannot read another's credential.
- **Audit non-skippable:** every adapter lifecycle transition (spawn, handshake,
  crash, each restart attempt, breaker trip, awaiting-core-for-respawn,
  ingress-gate trip) writes an audit row; status notifications reconcile into the
  signed core audit log (the gateway holds no signing key). A malformed / forged
  status frame is never silently dropped — it is refused, audited, and triggers
  link scrutiny.
  > **G6-4 annotation (ingress-refusal sink is structlog-only this slice).** The
  > per-adapter ingress-refusal audit (`ingress_audit.py` —
  > `record_ingress_refusal` / `record_unknown_adapter_refusal`, the K6 closed-vocab
  > field-allowlisted rows incl. the H2 `queue_full` back-pressure row) is a LOUD
  > **structlog** breadcrumb + per-adapter counter for G6-4; it does NOT yet reconcile
  > into the signed core audit log (the gateway holds no signing key — the same posture
  > as the G6-2b status-leg local audit, see the 2b-2a annotation above). The
  > durable signed-log reconcile is a tracked follow-up (design §6); "audit
  > non-skippable" holds in the never-silent sense (every refusal is loud + counted),
  > not yet in the signed-durable sense for the ingress sink.

### Status-leg carrier-auth posture (G6-2a / G6-2b-1 follow-up annotation)

G6-2a (the core-side `AdapterStatusObserver`) and G6-2b-1 (the gateway-side
producer: `GatewayAdapterSupervisor` + `AdapterStatusEmitter`) flagged that the
**authenticity** of the `gateway.adapter.*` status leg rests on two distinct,
complementary layers — recorded here so the split is auditable ADR-side and not
only in the module docstrings:

- **Carrier-auth (the live leg, Spec A mechanism).** The live gateway→core status
  leg's `0600` socket + `SO_PEERCRED` peer-uid check + per-core-boot-epoch envelope
  is what authenticates each status frame's **origin** and **anti-replays it across
  boots**. This is the authoritative defence for the non-`up` frames
  (`down` / `crashed` / `breaker_open`), which are deliberately **not** epoch-bound
  in their payload (spec-faithful — only `up` asserts liveness). A forged-downgrade's
  blast radius is low: the core only **observes** (it issues no lifecycle directive
  per decision 2), so a forged `down` / `crashed` mutates only the `alfred status`
  snapshot + an audit row, never an actuation.
- **Application-level false-liveness defence (the producer's `up` payload-epoch).**
  The producer (G6-2b-1) stamps the per-core-boot epoch onto the **`up`** frame —
  the only liveness-asserting frame — and the observer (G6-2a) reconciles it,
  refusing an `up` against a stale / foreign epoch (the G3 anti-forgery lesson: a
  forged `up` while dark is a false-liveness attack). This is the **additional**
  application-level anti-replay defence Spec B §6(f) mandates on top of the carrier.

The live leg itself is **2b-2** (G6-2b-1 emits to an injected sink, not the wire),
so the carrier-auth is proven by 2b-2's live-leg integration test + the existing
Spec A link-auth tests; G6-2b-1's unit suite proves the application-level
validation (validate-on-produce + epoch reconcile) in isolation.

> **G6-2b-2a annotation (audit-of-record):** Spec §6 calls the gateway-LOCAL
> signed audit append + reconcile "Spec A's mechanism reused", but that
> gateway-local signed-reconcile component does NOT exist on main (Spec A shipped
> only structlog breadcrumbs; the gateway holds no DB and no signing key). For the
> 2b-2a slice the per-transition **audit-of-record is the CORE-side
> `AdapterStatusObserver`'s `audit.append_schema`** (one row per accepted
> transition + one `status_rejected` row per refusal, written into the signed core
> audit log) — which is spec-faithful (the signed reconcile target IS the core log).
> The gateway-LOCAL signed reconcile is a later-slice component, not a Spec A reuse.

> **G6-2b-2b annotation (crash de-dup correlation):** the two coexisting crash
> signals — the gateway's process-level `gateway.adapter.crashed` (carrier-auth'd,
> authoritative) and the in-child `adapter.crashed` (a finer diagnostic, NOT
> epoch/anti-forgery bound) — are correlated core-side into ONE audited incident per
> `(adapter_id, host_restart_seq)` by `src/alfred/comms_mcp/crash_incident_reconciler.py`
> (`CrashIncidentReconciler`), shared by the observer (gateway arm) and every
> per-adapter `AdapterCrashHandler` (in-child arm). Folding NEVER elides a row
> (hard rule #7): both arms still audit, a replayed crash is flagged `duplicate=true`
> and still written. **SEC-02:** `crash_signal_source == "both"` is a diagnostic hint,
> NOT authenticated corroboration — only the gateway frame is carrier-authenticated, so
> a forged in-child crash can upgrade a real incident's source label to `both` without
> masking the genuine gateway incident. The release-blocking forged/duplicate-crash
> adversarial entry is deferred to G6-6 (the in-process unit-level guards ship in 2b-2b).

### Adversarial corpus (before ship, §6)

- **(a)** cross-adapter credential read attempt → refused + audited.
- **(b)** gateway memory inspected after a spawn → no retained plaintext
  credential (the credential `bytearray` is zeroed post-write) + a structural
  "gateway holds no vault key" invariant. **(release-blocking)**
- **(c)** adapter crash-loop → bounded backoff + breaker + loud audit; never
  silently dark. **(release-blocking)**
- **(d)** per-adapter ingress flood (incl. the distributed-id variant) →
  bounded + back-pressured + audited.
- **(e)** spoofed / replayed `spawn_grant` (forged or stale-epoch credential
  frame) → refused; epoch-reconcile on the cred leg. **(release-blocking)**
- **(f)** forged `gateway.adapter.*` status (a peer asserting a false "up" while
  dark) → refused by Pydantic validation + epoch / peer-auth; audited.
  **(release-blocking)**
- **(g)** compromised-gateway serial cred harvest → bounded / observable (each
  grant is per-adapter + audited, so harvest is *visible*, not silent).

### Concentration acknowledged

The gateway is now the most network-adjacent process **and** SETUID-privileged
**and** the transient credential handler. The concentration is accepted, bounded
by enforcement-of-record (per-adapter bwrap + netns + scrubbed env + fd-3
transient cred + no vault key), gated per-PR by the adversarial suite (security
always in `/review-pr`), and closed by Spec C. The realizing epic is
G6-2 (`GatewayAdapterSupervisor` + status observer) → G6-3 (credential client /
resolver) → G6-4 (ingress gate + leg scheduler + per-leg `ReplayBuffer`) → G6-5
(Discord flag-day) → G6-6 (adversarial corpus + restart-survival integration test).

### Dormant-privilege window `[security plan-review]`

G6-1 grants the SETUID capability + sandbox profiles to the network-facing
gateway **before** the hosting code (G6-2) uses it, so for the G6-1→G6-2 window
the gateway is privileged but **spawns nothing**. This is an accepted, bounded
ordering: the capability is inert without the supervisor. The alternative —
granting it atomically with the hosting PR — couples the maintainer security
co-sign to a larger, less-reviewable change and was rejected for reviewability.

### Operator deployment hazard `[devops plan-review]`

The gateway now requires the `alfred-bwrap` AppArmor profile loaded on the host
(the same named profile `alfred-core` already needs, ADR-0037). On an AppArmor
host that has not run `bin/alfred-setup.sh`, Docker will refuse to create the
gateway container. The profile-preload note already exists for `alfred-core`; the
named profile is host-global once loaded, so there is **no new load step** — G6-5's
migration runbook owns the operator-facing restatement. No new CI gate breaks:
the live-compose gateway smokes are skip-marked; merge-gating gateway tests run
in-process.

## Alternatives considered

- **Separate spawner sidecar (not the gateway).** Rejected: a sidecar sits in the
  same trust tier as the gateway, adds an IPC hop, and buys only marginal
  isolation — the network-adjacent + privileged + credential-handling
  concentration is not actually broken by splitting the process. A single
  privileged always-up host is simpler and no less safe.
- **Rootless bwrap via unprivileged user namespaces / no SETUID.** Rejected:
  AlfredOS deliberately chose the privileged-launcher model for hardened hosts
  where unprivileged userns is disabled (ADR-0015 / ADR-0037). Switching to
  rootless userns is a *global* sandbox-model change, out of Spec B's scope.

> **G7-4 annotation (2026-06-30, #333).** Spec C G7-4 adds an **in-model duty** to the
> gateway: it binds and serves a second `EgressForwardProxy` instance on a bind-mounted
> AF_UNIX socket (`alfred_discord_egress` volume) for the Discord adapter child. This is
> not a new privilege — the gateway is already SETUID-privileged and the sole egress plane;
> hosting the AF_UNIX listener is within its current capability set. See
> [ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md).

## References

- `docs/superpowers/specs/2026-06-18-spec-b-adapter-inversion-design.md` —
  Spec B (§2 decisions 2–5, §5 credential-during-outage, §6 trust posture +
  adversarial corpus, §8 ADRs).
- `docs/superpowers/specs/2026-06-13-gateway-control-plane-roadmap.md` — the
  three-epic gateway control-plane program (A / B / C).
- [ADR-0037](0037-production-quarantine-sandbox-boundary.md) — the
  `alfred-bwrap` AppArmor + seccomp profiles the gateway now also carries.
- PRD §5 (hybrid isolation, dual-LLM split), §7.1 (security & prompt-injection
  defense).
- `tests/unit/test_compose_invariants.py` — the `devops-010` compose invariants
  reconciled by this ADR.

### Per-adapter ingress + fair leg multiplex realized (G6-4 annotation, #288)

> **G6-4 annotation (#288):** decision 5 (the per-adapter ingress gate + per-leg
> resume under a global aggregate cap) is now wired; this records the facts the
> decision-5 prose left open so they cannot drift.
>
> **K1 — leg ownership.** A per-leg `GatewayLeg` (`src/alfred/gateway/gateway_leg.py`)
> owns each leg's `ReplayBuffer`, per-leg seq counter, breaker latch, ingress gate,
> and bounded send queue. The foreground **TUI is the canonical FIRST `GatewayLeg`** —
> one `GatewayLeg` instance on the same code path as every future hosted adapter leg,
> not a special case (**one code path**). The `GatewayLegScheduler` is the **sole
> drainer**: it mints the wire seq + appends to the per-leg buffer at DRAIN time and is
> the only caller of `core_link.write_leg_unit` on the steady path. Temporal mutual
> exclusion with reconnect is enforced by the scheduler awaiting the **replay-pending
> gate** before each drain round; while replay is pending, `_flush_pending_replay` is
> the single sanctioned reconnect-internal direct `write_leg_unit` caller (the scheduler
> is parked, so there is never a second concurrent physical writer). The breaker feed
> moved from `relay_to_core` to a **drain-time seam** in the leg/scheduler.
>
> **K2/K3 — cap precedence.** Two distinct ceilings bind in order: the per-leg
> `ReplayBuffer` **hard ceiling** (8192 frames / 16 MiB — `_HARD_CAP_MULTIPLIER` 2× the
> **soft** cap of 4096 frames / 8 MiB, which trips the breaker but keeps the frame) binds
> FIRST for a single leg; the `GlobalReplayCap` (`global_replay_cap.py`) is the
> **aggregate-across-legs** bound on the SUM of all legs' resident pre-DLP T1 bytes, set
> strictly above one leg's hard ceiling so the per-leg cap fires before the global one. The global cap is
> released on every byte-reclaim path (trim / evict / discard / reset / hard-ceiling
> rollback). `max_frame_bytes` at ingress admission bounds the fairness unit (round-robin
> by-frame over the single physical writer); the residual head-of-line delay is honestly
> bounded by `max_frame_bytes`, and the TUI leg holds a reserved minimum credit so
> interactive latency has a floor in N.
>
> **comms-F2 overturn realized.** The gateway ingress gate is **additive volumetric**
> back-pressure keyed only on `adapter_id` (payload-blind; no per-platform-id keying at
> the gateway). The core's `_PreResolutionLimiter` (per-`(adapter_id,
> platform_user_id_hash)`) is NOT touched, duplicated, or weakened — it remains as per-id
> defense-in-depth. The two layers are complementary: the gateway volumetric gate does
> NOT subsume the core's per-id limiter (the comms-F2 overturn, now realized in code).

> **G6-5 annotation (#288):** the gateway adapter-hosting **SPAWN substrate** is now
> shipped — the gateway can spawn, sandbox, and handshake a hosted adapter child. This
> records what landed and what was deliberately held back so the boundary cannot drift.
>
> **What G6-5 shipped (additive, no flag-day).** The hosted adapter child reads its
> credential from **fd-3** (the copied fd-3 spawn window, shared with the quarantine
> child-launcher and pinned by a single shared property test — GAP-2); `GatewayAdapterStdioTransport`
> (`src/alfred/gateway/adapter_stdio_transport.py`) is the `Popen`-backed stdio transport
> for the hosted child; `GatewayAdapterChildFactory`
> (`src/alfred/gateway/adapter_child_factory.py`) is the fd-3 credential spawn window plus
> child-reaping; the `GatewayAdapterSupervisor` `aclose` reap hook reaps every spawned
> child on shutdown; per-adapter **binding** ingress legs are wired; `adapter_ids` is read
> from settings; `alfred gateway adapters --wait-ready` queries readiness via daemon-control
> `status.query`; and the `discord` adapter-id namespace is reconciled end-to-end. Both new
> trust-boundary modules are gated at 100% line+branch in CI (the L2 two-gates pattern).
>
> **What G6-5 deferred to epic #309.** The hosted-adapter **inbound→core bridge** and the
> **Discord flag-day** (delete the daemon-spawn path, delete the `alfred-discord` Compose
> service, cut the secret source over to the gateway) are NOT in this slice. Discord still
> runs via the daemon-spawn path; the `alfred-discord` Compose service is un-deleted; no
> secret was rewired. The bridge seam is `GatewayProcess._unwired_runner_factory` — a
> **documented injectable fail-loud seam** that raises on use until #309 wires the inbound
> relay. This PR is therefore purely additive: the substrate exists and is sandbox-tested,
> but nothing on the live Discord path changed.
>
> **Correction (append-only) — one source DID change, behavior-neutrally.** The "no secret
> was rewired" / "nothing on the live Discord path changed" wording above understates one
> diff: the Discord adapter's credential SOURCE was rewired from `_EnvBroker` to
> `Fd3TokenSource` (`plugins/alfred_discord/lifecycle.py`) — the child now reads its bot
> token from fd-3 rather than the environment. This is behavior-neutral **today** because
> the launcher-spawn path already hands the child a scrubbed env with no fd-3 writer, so
> NEITHER source authenticated on the live daemon-spawn path (the credential cut-over
> itself is #309). So no LIVE flow changed, but the credential source is no longer
> untouched — the accurate framing is: the Discord credential SOURCE was rewired to fd-3;
> no live flow changed (the daemon-spawn path was already scrubbed-env).

> **G6-7-8 annotation (#309):** the Discord flag-day is complete. The standalone
> `alfred-discord` Compose service is deleted; the gateway hosts the Discord bwrap child
> in production. The credential is sourced from the core's `ALFRED_DISCORD_BOT_TOKEN`
> env var (GAP-4 Option A) and delivered to the gateway-hosted child over spawn-grant →
> fd-3; the gateway and child hold no vault key. The daemon-spawn path and the
> `alfred discord verify` CLI command are removed. Unset-token blast-radius tracking:
> issue #331. PRD §7.1 vault (Spec C): issue #330.
