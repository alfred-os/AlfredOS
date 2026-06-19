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
