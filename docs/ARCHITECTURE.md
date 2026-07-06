# AlfredOS — Architecture & Roadmap (current state)

> **Purpose.** A single, human-skimmable map of *where AlfredOS is today* and *what
> it is being built towards*. The detail lives in the PRD, the ADRs, the design
> specs, and the subsystem deep-docs — this page is the index that ties them
> together so you do not have to reconstruct the picture from a dozen files.
>
> **This is a navigational aid, not a source of truth.** [`PRD.md`](../PRD.md) remains
> the product source-of-truth for *what AlfredOS is and why*. Where this page and the
> PRD disagree, that is drift to fix — see *Known doc drift* at the bottom.

---

## 1. What AlfredOS is (the as-built product)

A multi-user, multi-persona, security-hardened agentic OS, self-hostable, Apache-2.0.
The load-bearing design pillars (all in [`PRD.md`](../PRD.md)) are:

- **Trust tiers T0–T3.** Every external input is tagged at the boundary; the
  privileged orchestrator never sees raw T3 content. See
  [`docs/subsystems/security.md`](subsystems/security.md).
- **Dual-LLM split.** A privileged orchestrator (T0/T1) plus a quarantined LLM that
  is the only thing allowed to read raw T3, and only via a structured-extraction path
  inside a bwrap sandbox. See [`docs/subsystems/quarantine.md`](subsystems/quarantine.md).
- **Secret broker, capability gate, DLP, audit log.** Secrets live in the broker (not
  plugin-visible env); every tool call passes the capability gate; outbound passes
  DLP; side-effects + security events write to the signed audit log.
- **6-layer memory** (working → episodic → summarized → semantic → vector → knowledge
  graph) in Postgres + Qdrant.
- **Personas + comms adapters.** Personas (Alfred default) reachable over comms
  adapters (Discord, TUI, …) implemented as MCP plugins. See
  [`docs/subsystems/comms.md`](subsystems/comms.md).
- **Self-improvement via a reviewer-gated proposal flow** against `/var/lib/alfred/state.git`.

The runtime is a long-lived **daemon** (`alfred daemon`) that hosts the core
(orchestrator / OODA loop, plugin supervisor, memory, security). The `alfred` CLI is a
separate operator-owned process; the TUI (`alfred chat`) is another.

This product surface was built across Slices 1–4 (see `docs/superpowers/specs/`,
`docs/adr/`). The **gateway program** below is the major architectural arc layered on
top of that foundation.

---

## 2. The gateway program (the current major arc)

**Thesis:** make the gateway the *mandatory chokepoint for all external network I/O*,
so the **core becomes connectivity-free** (no external sockets except via the gateway).
This strengthens the egress-allowlist posture from *policy-gated* to
*structurally-gated*. Delivered as three gated epics — each ships and proves out before
the next opens.

| Epic | Scope | Status |
| --- | --- | --- |
| **Spec A — Comms-resume gateway** (G0–G5) | Resumable dial-in transport for the TUI so a platform session survives a core restart. No adapter hosting, no egress proxy. | **Merged to main** |
| **Spec B — Adapter-hosting inversion** (G6) | Move comms adapters (Discord → Telegram) from daemon-spawned to **gateway-hosted + sandbox-supervised**, so resume generalizes beyond the TUI. | **Complete (#288)** |
| **Spec C — Egress control plane + connectivity-free core** (G7) | Gateway becomes the sole egress for *all* outbound I/O (tools + providers); the core loses its external network; the PRD §5 invariant is rewritten. | **Complete (#333)** |

**Authoritative reading order for the program:**

1. [`docs/superpowers/specs/2026-06-13-gateway-control-plane-roadmap.md`](superpowers/specs/2026-06-13-gateway-control-plane-roadmap.md)
   — the program north-star: the three epics, the locked maintainer decisions, the
   deferred-work ledger. **Read this first.**
2. [`docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md`](superpowers/specs/2026-06-13-comms-gateway-resume-design.md)
   — Spec A (shipped).
3. [`docs/superpowers/specs/2026-06-18-spec-b-adapter-inversion-design.md`](superpowers/specs/2026-06-18-spec-b-adapter-inversion-design.md)
   — Spec B (merged).
4. ADRs: **0031** comms socket, **0032** resume transport, **0033** lifecycle
   signalling, **0036** adapter-hosting inversion, **0037** quarantine sandbox,
   **0038** daemon control socket.

### Spec B / Spec C completion

Spec B complete (G6-0…G6-7, #288); Spec C complete (G7, #333). The PRD §5
egress-invariant rewrite has landed.

---

## 3. The three planes (a clarifying distinction)

"How does X talk to the system" has three genuinely different answers. Keeping them
separate prevents conflating decisions that belong to different boundaries.

### Plane 1 — Comms data plane (inbound user messages)

Platform users (Discord, TUI, …) → adapter → core. T3 inbound bodies cross a
payload-blind wire; **identity-resolve, rate-limit, trust-tagging, and quarantined
extraction are core-side** — reached over the wire, not performed in the adapter.
(This is the as-built post-Slice-4 reality, per the Spec B roadmap; PRD §5's original
"adapters do ingress" split is superseded here and is reconciled by the
**G7 §5 rewrite** (landed — see D2). Outbound DLP runs on the *outbound* path.) Spec A/B
re-home the adapter *hosting* into the gateway; the ingress logic stays core-side.
Carrier: the ADR-0025/0031 line-delimited JSON-RPC comms wire.

### Plane 2 — Local control plane (operator CLI ↔ daemon, same host)

The `alfred` CLI / `alfred daemon status` reading the daemon's live in-process state
(per-adapter status, crash incidents, and — later — readiness). Same host, **same
Unix user**. Auth is "are you the same uid" (`SO_PEERCRED` + a `0600` socket under a
`0700` runtime dir; `SO_PEERCRED` degrades open to FS-perms-of-record on a
non-`SO_PEERCRED` host such as a macOS dev box — acceptable only because this plane is
read-only + non-sensitive, and any future mutating/sensitive method re-opens that auth
decision per ADR-0038). This is **G6-2c**.

- **Decision (locked):** a **request/response control socket** (`~/.run/alfred/control.sock`),
  JSON-RPC over a unix socket, reusing the audited ADR-0025/0031 framing + peer-auth
  primitives — zero new dependencies, one IPC idiom. A live query (no snapshot, no
  staleness) is the single source of truth: the daemon answering the `0600`/`SO_PEERCRED`
  socket *is*, by construction, the live daemon. (See ADR-0038.)
- **Why not HTTP/gRPC here:** the consumers are local first-party CLI. HTTP/gRPC are
  over-build for same-uid local introspection and would add a web-framework / `grpcio`
  dependency. The **contract** (the method schema + Pydantic request/response models)
  is deliberately transport-agnostic so the remote management plane (Plane 3) can reuse
  it later — see below.

### Plane 3 — Remote management plane (dashboards, remote ops) — FUTURE, undecided

Web dashboards, remote operations, an ops console. Different host boundary, different
auth (authenticated *operators*, RBAC, TLS, sessions). **This is wanted and important**,
but it is **not yet designed or captured in any spec** — see *Open architectural
decisions* below. It will reuse the Plane 2 *contract* (the introspection method schema
and models) over a different *transport*; certainty about Plane 3 does **not** make
Plane 2's local transport HTTP.

---

## 4. Open architectural decisions (captured, not yet decided)

### D1 — Remote management plane: via the gateway, direct to the core, or a dedicated management service?

Dashboards + remote ops are a committed product direction, but **how they reach the
system is undecided**, and the program's existing roadmap covers only *outbound* egress
(Spec C) — *inbound* remote management is captured nowhere else. The tension:

- The program's whole thesis is a **connectivity-free core**. A remote management API
  is inbound external I/O — pointing it *directly at the core* punches an inbound socket
  into the most privileged component (orchestrator + secret broker + Postgres), which
  contradicts the invariant the gateway program exists to establish. (Leans **against
  core-direct.**)
- But a management API needs rich core state (memory, personas, audit, cost, users)
  that lives in the core/Postgres, not the comms gateway — so bolting it onto the
  *comms* gateway (a comms relay) is also awkward.
- **One candidate (NOT selected — to be decided in D1's spec):** a **dedicated
  management/control-plane service** — a sibling that holds the external HTTP surface +
  operator auth + RBAC and reaches core/daemon state over the *internal* network using
  the Plane 2 contract. It would preserve connectivity-free-core, keep the management
  attack surface off the orchestrator, and keep the comms gateway focused on comms. The
  other candidates (management-on-the-gateway, or a sanctioned core-direct exception)
  are weighed in the spec; this page only records the tension, it does not pick. (Note:
  Prometheus/Grafana already scrape *metrics* out-of-band; the new thing is an
  interactive ops/management surface.)
- **Status:** needs its own `brainstorming → spec → ADR` cycle. G7 (Spec C) and the
  PRD §5 rewrite have both landed, so this decision is no longer blocked on unshipped
  work — it can be spec'd against the now-stable G7 topology whenever it is
  prioritized. It must **not** be decided inside a status-render sub-slice.

### D2 — PRD §5 rewrite (the connectivity-free invariant) — RESOLVED

The "connectivity-free core / all-I/O-via-gateway" invariant is now **true**: Spec C
(G7, #333) shipped, and the PRD §5 rewrite (gateway above the core as the I/O plane;
the invariant promoted; §7.1 egress enforcement centralized; the stale Redis-streams
comms-bus depiction removed) has landed — see [`PRD.md`](../PRD.md) §5. Kept here as a
historical record of the decision and its sequencing rationale.

---

## 5. Doc map (where to read what)

| You want… | Read |
| --- | --- |
| What AlfredOS is + why (product design) | [`PRD.md`](../PRD.md) |
| How to work in the repo (agent operating manual) | `CLAUDE.md` (repo root; generated from `.rulesync/`, not committed) |
| The gateway program north-star + decisions | [`docs/superpowers/specs/2026-06-13-gateway-control-plane-roadmap.md`](superpowers/specs/2026-06-13-gateway-control-plane-roadmap.md) |
| A specific epic's design | [Spec A](superpowers/specs/2026-06-13-comms-gateway-resume-design.md), [Spec B](superpowers/specs/2026-06-18-spec-b-adapter-inversion-design.md) |
| Why a structural decision was made | [`docs/adr/`](adr/) (the decision ledger) |
| How a subsystem works | [`docs/subsystems/`](subsystems/) (comms, security, quarantine, supervisor, identity, hooks, plugins, policies) |
| Vocabulary | [`docs/glossary.md`](glossary.md) |
| Operator walkthroughs | [`docs/runbooks/`](runbooks/) |

---

## 6. Known doc drift (be honest about it)

- **The PRD now describes the gateway program.** The PRD §5 rewrite (D2 above) landed
  alongside Spec C — the PRD documents the gateway as the I/O plane and the
  connectivity-free core invariant (see [`PRD.md`](../PRD.md) §5). This page keeps the
  finer-grained epic/G-number history the PRD does not restate.
- **The remote management plane (Plane 3 / D1) is captured only here.** It needs its
  own spec when its turn comes; this page is a placeholder so the intent and the open
  decision are not lost.
- This page should be updated when D1 is decided.
