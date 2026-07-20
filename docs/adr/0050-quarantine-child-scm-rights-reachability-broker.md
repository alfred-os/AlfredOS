# ADR-0050 — Quarantine-child SCM_RIGHTS reachability-broker (core-side topology)

- **Status**: Accepted (on #340 PR2a merge)
- **Date**: 2026-07-10
- **Amended**: 2026-07-19 — Decision 7 updated: the per-extraction core-side egress-audit row
  recorded there as a "hard PR2b pre-gate, not yet wired" has **shipped** ahead of PR2b, as its
  own egress-audit family (`EgressBrokerAuditor`, `src/alfred/egress/broker_audit.py`), ratified
  by the golive spec's §21 amendment (`2026-07-11-issue-340-pr2b-golive-cutover-design.md`). See
  Decision 7 and the corresponding [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md)
  residual (vii) amendment.
- **Amended**: 2026-07-19 (PR2b-golive) — the dormancy-flip forward-gates this ADR recorded
  (Decision 8 `control_fd`, the "What is unchanged" CA bind + `keep_fds=[3,4]`, Decision 4's
  companion `_CONSTRUCT_ALLOWLIST` flip, Decision 5's CONNECT-location fork) are now **activated**
  by [ADR-0052](0052-real-quarantine-child-golive.md) (the real quarantine-child go-live). See the
  "PR2b-golive amendment" section at the end. This amendment does **not** re-flip the Status or
  re-claim the Decision 7 row (the pre-gate PR shipped those; the 2026-07-19 amendment above records
  them).
- **Slice**: #340 (2c real-LLM quarantine child) — PR2a fd-broker topology mechanism
  (`docs/superpowers/specs/2026-07-10-issue-340-pr2a-fd-broker-topology-design.md`)
- **Relates to**: [ADR-0015](0015-slice4-containerised-quarantined-llm.md) (quarantine-child
  containerisation; the fd-3 provider-key delivery primitive this ADR's fd-4 control channel
  mirrors), [ADR-0036](0036-gateway-adapter-hosting-inversion.md) (gateway hosting duty
  precedent; gateway holds no vault key), [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md)
  (connectivity-free core / mandatory egress chokepoint — the two-layer enforcement model this
  ADR maps onto; residuals (iv) and (vii)), [ADR-0042](0042-connectivity-free-core-cutover.md)
  (G7-3 cutover; the raw-socket exemption "by design" this ADR's ratchet narrows),
  [ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md) (the sibling ADR that
  reserved "Option C — empty netns + SCM_RIGHTS fd-broker" for the in-house 2c child; this ADR
  realises that reservation), epic [#340](https://github.com/alfred-os/AlfredOS/issues/340)
  (2c real-LLM quarantine child), issue [#358](https://github.com/alfred-os/AlfredOS/issues/358)
  (core→proxy `Proxy-Authorization`/mTLS — the forward-gate named in Decision 5), issue
  [#230](https://github.com/alfred-os/AlfredOS/issues/230) (2c real-LLM provider-only egress —
  the tracking issue this mechanism closes toward)
- **Supersedes**: —

## Context

ADR-0040/ADR-0042 made `alfred-core` connectivity-free: `alfred_internal` is `internal: true`,
`alfred-core` is off `alfred_external`, and `EgressClient` has no direct-egress fallback. The
gateway is the sole external egress plane. G7-1a additionally gave the quarantine child
`--unshare-net` (an empty network namespace), which is sufficient today because the shipped
child is a deterministic-echo loop with no provider client and nothing network-capable in its
live import graph.

The 2c real-LLM child (tracked by `#230`/`#340`) breaks that sufficiency: it needs a real path
to its LLM provider's HTTPS endpoint through the gateway's L7 CONNECT proxy. Simply removing
`--unshare-net` would reopen the exact gap G7-1/G7-4 closed for the echo child and the Discord
adapter respectively — any compromise of the adversary-facing quarantine child would regain a
route to an arbitrary host. The design problem is: how does a process in an **empty** network
namespace reach a TCP listener that necessarily lives **outside** that namespace, without
widening the namespace itself?

ADR-0043 already surveyed this exact problem for a different child (the Discord adapter) and
recorded, as a rejected-for-Discord alternative, "Option C — empty netns + SCM_RIGHTS
fd-broker," explicitly reserving it "for the in-house 2c child" because `discord.py`/`aiohttp`
expose no per-connection fd-request hook. This ADR realises that reservation.

`#340`'s PR1 (provider-seam reconciliation, merged) already speaks the real completion-request
seam but is still dead code on the live path (the echo child is unchanged). A throwaway
feasibility spike (branch `340-fd-broker-spike`, local-only, not pushed) proved the full
CONNECT+TLS+HTTP+decode round-trip over a passed fd works with the official Anthropic SDK
(verdict **M1**: keep the SDK over the brokered socket). PR2a — this ADR's slice — ships the
**core-side half** of that mechanism as a genuinely dormant precursor: opt-in, defaulted off,
no shipped-policy edit, no live caller. PR2b, behind its own human sign-off, builds the
child-side transport and flips the mechanism live.

## Decision

### 1. The core-side raw-socket + SCM_RIGHTS reachability-broker

`src/alfred/egress/control_fd_broker.py` is a new, deliberate, audited egress exception: the
core opens a bare TCP socket toward the gateway's L7 CONNECT proxy (the same destination
`EgressClient` proxies to) and hands the connected file descriptor to the quarantine child over
an inherited AF_UNIX control socket, via `sendmsg(..., SCM_RIGHTS, ...)`. The core writes
**zero application bytes** over that socket — it originates the TCP connection and passes it
away, nothing more. The child performs the CONNECT handshake, TLS, and HTTP; **TLS terminates
in the child**, never in the core. The module's docstring must state this distinction from
`EgressClient` explicitly: `EgressClient` does I/O over the connections it opens;
`control_fd_broker` opens a connection and immediately gives it away. Naming it a
**reachability**-broker (not a data-plane broker) is deliberate — it brokers *reachability to
the proxy*, not content.

### 2. The empty-netns-preserved invariant

`--unshare-net` stays on the quarantine child's shipped Linux bwrap policy. PR2a does not edit
`config/sandbox/quarantined-llm.linux.bwrap.policy`. Only **reachability** is brokered — never
netns membership. The child's network namespace remains genuinely empty; it still cannot open
its own socket to anywhere. The evidence for this is the **C1 negative control**: inside the
child, a *fresh* `socket.create_connection((literal_ip, 443))` — attempted independently of the
passed fd — MUST fail `ENETUNREACH`. A pass on C1 proves the only working connection has to be
the one the core handed over; the namespace itself grants no route.

### 3. The two-layer mapping, stated precisely

This mechanism sits astride two different enforcement frames and the ADR states the mapping
precisely so neither is mistaken for the other:

- **For the child**, kernel empty-netns is enforcement-of-record (ADR-0040 Layer 1, unchanged):
  a compromised child that ignores every userspace control still cannot open an external
  socket, because the kernel has no route in that namespace.
- **For the core**, `control_fd_broker`'s `connect()` to `alfred-gateway` is **internal
  `alfred_internal` traffic** — the identical hop `EgressClient` already makes to reach the same
  proxy. It is not a regaining of *external* reach by the core.

Consequently this mechanism is **not** a connectivity-free-core weakening: PRD §5's default-deny
invariant and ADR-0040/ADR-0042's cutover are about the core opening **external** sockets. A
core process connecting to the gateway over the internal network — the mechanism this ADR
records is just one more such connection, whose payload happens to be an fd rather than bytes —
does not touch that boundary at all.

### 4. The guard-exemption as a conscious extension, bounded by a new ratchet

ADR-0042 §3 already documents that the in-core httpx/SDK import-guard (G4) exempts raw sockets
"by design," because the kernel isolation (`internal: true`), not the guard, is the
enforcement-of-record for that vector. `control_fd_broker.py`'s raw `socket.create_connection`
therefore needs **no** `_CONSTRUCT_ALLOWLIST` entry — it is a conscious use of an
already-documented exemption, not a new one.

But no *existing* guard sees the specific new pattern this module introduces — a raw,
network-connected fd handed to a sandboxed child via SCM_RIGHTS — so PR2a adds a **new
raw-socket-egress ratchet**: an AST check pinned on the **conjunction** of (a) any connect call
— a `.connect()` or `socket.create_connection()` — **and** (b) a `sendmsg(..., SCM_RIGHTS, ...)`
call in the *same* module. (The as-shipped guard matches any `.connect()`/`create_connection()`;
it deliberately does *not* additionally gate on `AF_INET`/`AF_INET6` socket construction, since
that companion check would be dead code once the connect half already fires.) Either
half alone is a poor discriminator — bare `.connect()` is common (database clients), and bare
`SCM_RIGHTS` fd-passing is pervasive in-core (the fd-3 key delivery precedent) — but the
conjunction is distinctive, and `control_fd_broker.py` is asserted to be the sole module in
`src/alfred/` matching it. This is a narrow, consciously-documented AST residual in the
ADR-0042 tradition (an accepted static-analysis gap, backstopped by the kernel netns as the
real control), not a claim of the same strength as the "`EgressClient` is the only httpx
constructor" gate.

PR2b will flip a companion child-side ratchet: it will declare the child-side transport module
egress-capable (broadening the child-egress-import guard, G3) and add a `_CONSTRUCT_ALLOWLIST`
entry for the child's `httpx.AsyncClient`. Those flips are safe for the same reason the core-side
exemption is safe: the child's `--unshare-net` empty namespace means `import socket` (or
`import httpx`) inside the child grants **no route** — widening what the *static* guards permit
does not widen what the *kernel* actually reaches. The guard surface and the reachability
surface are independent; only the latter is the enforcement-of-record.

### 5. The CONNECT-location decision

Two shapes were considered for **who** performs the gateway CONNECT handshake:

- **(A) Child does CONNECT** — the child drives CONNECT+TLS+HTTP over the passed bare fd (the
  shape the feasibility spike proved, verdict M1). The **gateway** enforces the destination
  allowlist, not the child.
- **(B) Core does CONNECT, passes a post-CONNECT socket** — the core performs the CONNECT
  handshake itself and hands the child an already-tunnelled socket; the child does only TLS+HTTP.
  This keeps any proxy-credential in the privileged core, but it is a materially different
  transport shape the spike did not exercise.

**Decision: (A) child-does-CONNECT is the documented reference shape.** It matches what the
spike proved green, and the gateway (not the child) remains the destination-allowlist
enforcement point, consistent with every other egress path in the system. PR2a's broker passes
a **bare** (pre-CONNECT) TCP socket, which is (A)-compatible and does not foreclose (B).

**Forward-gate (`#358`).** If per-caller `Proxy-Authorization`/mTLS lands on the core→proxy
channel before PR2b's go-live, PR2b must re-decide: composing that credential in the child (via
`httpcore.AsyncHTTPProxy(proxy_headers=...)`) means a proxy credential crosses into the
adversary-facing child, which shape (B) would avoid. This ADR records the fork point; it does
not pre-empt PR2b's answer.

### 6. Why the Discord AF_UNIX bridge cannot be reused (corrected)

The rev.1 rationale for not reusing ADR-0043's Discord bridge was a **false inference**: "a
plaintext relay would expose raw T3." That is wrong on its own terms — ADR-0043's TCP→unix
byte-splice shim carries TLS **ciphertext**, not plaintext, because the Discord adapter *also*
terminates TLS end-to-end inside its own child. "The child terminates TLS" is therefore true of
*both* designs and does not distinguish them.

The real, structural reasons the Discord bridge cannot be reused for the quarantine child are:

- **(a) Hosting.** The quarantine child is spawned by the connectivity-free **core**
  (`spawn_quarantine_child_io`), not by the gateway. ADR-0043's AF_UNIX egress socket lives on a
  gateway-only volume (`alfred_discord_egress`), mounted into `alfred-gateway` **only** —
  devops-001 states plainly that mounting it into `alfred-core` would let the connectivity-free
  core reach the Discord allowlist directly, reopening the G7-3 cutover. The same reasoning
  applies here in reverse: a gateway-hosted egress socket cannot be bind-mounted into a
  core-hosted child without the identical reopening.
- **(b) Transport.** The Discord path runs on `aiohttp`, which exposes no per-connection
  fd-request hook — realising an fd-broker there means forking `aiohttp`'s connection pool.
  ADR-0043's own Alternatives section rejects this for Discord and reserves the SCM_RIGHTS
  fd-broker specifically for "the in-house 2c child," i.e. this one, whose transport (the
  official Anthropic SDK, per the spike's verdict M1) does not share that constraint.

Cross-references: [ADR-0015](0015-slice4-containerised-quarantined-llm.md) — the fd-3
provider-key-delivery primitive is the sibling resource-passing mechanism this ADR's fd-4
control channel extends (a second inherited, non-CLOEXEC fd delivered at spawn time, this time
carrying a socketpair end rather than key bytes); [ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md)
— the reservation this ADR realises; [ADR-0042](0042-connectivity-free-core-cutover.md) — the
raw-socket guard exemption this mechanism relies on and narrows.

### 7. The per-extraction core-side egress-audit row — shipped ahead of PR2b, as its own egress-audit family

ADR-0040 residual (vii) records that routine egress audit today is gateway-local (structlog +
Prometheus counters), not the signed, hash-chained core audit log. A natural question for this
mechanism is whether a signed core-side row should record each brokered-socket target
(host:port) per extraction, not merely rely on the gateway-local CONNECT audit.

**PR2a did not wire this.** There was no live caller of `control_fd_broker` on the audited path
in PR2a — only the docker C1/C2 probe test drove it, spawned outside the daemon's boot graph.
PR2a defined only the loud-failure error type, `ControlFdBrokerError` (rooted at `AlfredError`,
per the fail-loud-in-security-paths rule), and its closed `reason` vocabulary. This ADR originally
recorded the durable per-call, core-side egress-audit row as a **hard PR2b pre-gate** — decided
and implemented before the go-live sign-off, not left as an open residual at that point.

**Shipped (2026-07-19).** `EgressBrokerAuditor` (`src/alfred/egress/broker_audit.py`) now writes
that row on both arms of a broker call: `egress.broker.connected` (success,
`EGRESS_BROKER_SUCCESS_FIELDS`) and `egress.broker.refused` (failure,
`EGRESS_BROKER_REFUSED_FIELDS`), via the same `append_schema` + fail-closed T0 hookpoint pattern
`SandboxRefusalAuditor` established (#433, ADR-0051). It is a **distinct audit family**, not an
extension of the sandbox-refusal one: a broker failure is an egress event carrying `destination`
(host:port) — a field `SANDBOX_REFUSED_FIELDS` cannot hold and was never meant to. The per-call
hot-path await is bounded (5s) so a hung write fails loud rather than wedging the per-extraction
N-broker loop. This egress-audit-family choice, and the pre-gate carve-out itself, are ratified
by the golive spec's §21 amendment (`docs/superpowers/specs/2026-07-11-issue-340-pr2b-golive-cutover-design.md`).

`EgressBrokerAuditor` still ships **dormant**: golive's `broker_sockets` wiring (the flip to
`control_fd=True`, Decision 8) is its only production caller, so today it is exercised solely by
its own unit tests. The two-layer dormancy invariant (Decision 8) is unchanged by this shipment.
Once golive wires the live caller, PR2b's remaining audit-row task shrinks to wiring the
already-shipped auditor rather than designing and building it. See also
[ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md) residual (vii), amended
alongside this decision.

### 8. The dormancy contract as an explicit, auditable invariant

PR2a's entire safety case rests on two independent layers, and this ADR states both explicitly
so a future reader (or reviewer) cannot mistake "the mechanism exists in `src/`" for "the
mechanism is live":

- **Software guard:** `spawn_quarantine_child_io(*, control_fd: bool = False, ...)` — the live
  echo-child spawn path passes `control_fd` as neither `True` nor at all, so no control fd is
  ever delivered to the production child. This is an application-level, opt-in-off default.
- **Kernel guard:** the empty network namespace (Decision 2), which holds regardless of the
  software guard's state.

The two-layer dormancy invariant is: **even if the software guard were misconfigured, the
kernel guard alone still prevents unauthorised egress; and today, the software guard alone
already prevents the mechanism from being reachable in production at all.** This is not
redundant — it is defense-in-depth applied to the mechanism's own on/off switch, not only to
its data path.

This dormancy contract becomes an explicit **PR2b sign-off checklist item**: "the control fd is
opt-in-off until this PR flips it; flipping `control_fd` to always-on for the live spawn path
is *the* security-posture change under review at go-live" — not the ratchet, not the ADR, not
the docker probe, all of which PR2a already ships and reviews.

## Consequences

### Security posture

- **A deliberate, narrowly-scoped egress exception, not an ad hoc one.** The reachability-broker
  is the sole new raw-socket egress site in `src/alfred/`, pinned by the conjunction ratchet
  (Decision 4), and its only effect — even once live in PR2b — is to hand a single already-scoped
  TCP connection to a child that remains in an empty network namespace.
- **Two-layer dormancy holds today.** The mechanism ships in `src/`, is exercised by unit tests
  and a docker-gated C1/C2 probe, and is nonetheless inert on every live path: the opt-in default
  is off, and the shipped bwrap policy is untouched.
- **No weakening of the connectivity-free-core model.** Decision 3's mapping means an auditor
  checking "does the core open an external socket" still gets "no" — the broker's own connection
  is internal, gateway-bound traffic, identical in kind to what `EgressClient` already does.

### Honest residuals accepted at sign-off

These are recorded, not claimed caught — matching ADR-0040's and ADR-0043's convention.

- **[L-5] The probe's import-closure residual.** `_brokered_probe.py` imports
  `control_fd_broker`, which in turn imports `egress.errors`, the i18n catalog module, and the
  shared error hierarchy. This import chain is bounded by **no guard** today: G1 (the
  `quarantine_child_import_closure` guard) measures only `__main__`'s `sys.modules` delta, and
  the probe is a separate module the guard does not walk. The chain is clean as of this ADR (no
  forbidden root — `alfred.{audit,core,memory,orchestrator,security.secrets,
  security.capability_gate,security.dlp}` — appears in it), but this is an accepted, unenforced
  residual, not a proven-closed one. A future import added to `control_fd_broker` or its
  dependencies would not be caught by any existing static check.
- **[core-L4] The fd-4 process-wide clobber widening.** Prior to this mechanism, the spawn-time
  fd-clobber window (the synchronous, zero-`await` `dup2` dance inside `spawn_quarantine_child_io`)
  touched fd 3 only. With the control-fd plumbing, the same window now clobbers **both** fd 3
  and fd 4 process-wide. This is accepted as a widened, not a new, risk: the zero-`await`
  discipline that protects the event-loop selector from the #237-class regression still holds
  (both `dup2` calls execute inside the same synchronous window), but the window's blast radius —
  what it temporarily reassigns — is now twice as large. This is recorded here rather than left
  implicit because a future refactor that adds a third fd to the same window should re-examine
  this note, not rediscover the discipline from scratch.

### What is unchanged

- The shipped quarantine-child Linux bwrap policy (`--unshare-net`, `keep_fds=[3]`, no
  `/etc/ssl/certs` bind) is **not edited** by PR2a. The CA bind and the `keep_fds=[3,4]`
  declaration land only in PR2b, when the child begins driving real TLS.
- `sbx-2026-005` (the adversarial assertion that the empty-netns child cannot egress) stays valid
  unchanged — no socket is brokered on the live path.
- G1 (import closure), G2 (net-unshare + sanctioned-spawn), and G3 (child-egress-import) are
  untouched: `__main__.py` is byte-for-byte unchanged, and the probe is a separate module.
- `docs/glossary.md` (defining "reachability-broker" once) and the `docs/subsystems/{quarantine,security}.md`
  deep-docs are deferred to `alfred-docs-author` at PR2b; this ADR is the load-bearing record
  until then.

## Alternatives considered

### Reuse the Discord AF_UNIX egress bridge (ADR-0043)

Rejected — see Decision 6. The gateway-hosted egress socket cannot be mounted into a
core-hosted child without reopening the G7-3 connectivity-free-core cutover, and the Discord
transport (`aiohttp`) exposes no fd-request hook in any case — which is precisely why ADR-0043
reserved this exact SCM_RIGHTS approach for this child instead of applying it to Discord.

### pasta/slirp4netns as the reachability transport

Rejected for the same structural reasons ADR-0043's Alternatives section rejects it for the
Discord child: these inject a userspace IP stack via `setns` rather than providing a socket to
connect to, require a daemon with a handle into the child's network namespace (not available
from a core-hosted spawn), and add a full NAT stack that would then need firewalling back down
to a single destination — strictly more surface for equivalent enforcement than passing one
already-scoped fd.

### Core does CONNECT, passes a post-CONNECT socket (Option B)

Not rejected outright — deferred, see Decision 5. Kept in reserve as the answer if `#358`'s
`Proxy-Authorization`/mTLS lands on the core→proxy channel before PR2b's go-live and the
maintainer judges the credential should not cross into the adversary-facing child.

### No brokering — give the child a real, restricted network namespace

Not seriously considered: any namespace membership beyond loopback reopens the class of gap
G7-1/G7-4 closed for the echo child and the Discord adapter (a compromised child regains a
route, subject only to whatever restriction the namespace itself expresses, which is materially
harder to make as tight as "one already-vetted fd, one already-scoped destination, brokered by
a process that never executes the child's untrusted output").

## References

- [PRD §5](../../PRD.md#5-architecture-overview) — hybrid-isolation invariant; the "no
  capability to spawn further subprocesses" / network-restriction axis this mechanism extends
  for the 2c child.
- [ADR-0015](0015-slice4-containerised-quarantined-llm.md) — quarantine-child containerisation;
  the fd-3 provider-key delivery primitive.
- [ADR-0036](0036-gateway-adapter-hosting-inversion.md) — gateway hosting/privilege model.
- [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md) — connectivity-free
  core / mandatory egress chokepoint; the two-layer enforcement model (Decision 3) and residuals
  (iv)/(vii) this ADR touches.
- [ADR-0042](0042-connectivity-free-core-cutover.md) — G7-3 cutover; the raw-socket guard
  exemption "by design" (Decision 4).
- [ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md) — the sibling ADR that
  reserved "Option C — empty netns + SCM_RIGHTS fd-broker" for this in-house child.
- Epic [#340](https://github.com/alfred-os/AlfredOS/issues/340) — 2c real-LLM quarantine child.
- Issue [#358](https://github.com/alfred-os/AlfredOS/issues/358) — core→proxy
  `Proxy-Authorization`/mTLS forward-gate (Decision 5).
- Issue [#230](https://github.com/alfred-os/AlfredOS/issues/230) — 2c real-LLM provider-only
  egress path.
- Spec: `docs/superpowers/specs/2026-07-10-issue-340-pr2a-fd-broker-topology-design.md` §6, §7,
  §8 — the design this ADR records.

## PR2b-golive amendment (2026-07-19)

[ADR-0052](0052-real-quarantine-child-golive.md) (the real quarantine-child go-live) flips the
dormant mechanism this ADR shipped live. The forward-gates recorded above are now activated:

- **Decision 8 dormancy flip — `control_fd` off → on.** The production spawn site now passes
  `spawn_quarantine_child_io(control_fd=True, child_module=<real child>, egress_config=…)`. The
  security-posture change Decision 8 named as "*the* PR2b sign-off item" is the change under
  golive's human sign-off. The two-layer dormancy contract's kernel guard (Decision 2, the empty
  netns) is **unchanged** — only the software guard is flipped on.
- **The "What is unchanged" CA bind + `keep_fds` land.** The shipped bwrap policy's
  `keep_fds = [3]` → `[3, 4]` declaration and the narrow `["/etc/ssl/certs", "/etc/ssl/certs"]`
  CA bind (both deferred to PR2b in the "What is unchanged" section) are now applied — the child
  drives real in-child TLS against its brokered gateway socket and needs the public-CA trust store
  to verify. `sbx-2026-005` stays valid: no socket is opened *from within* the child's empty netns;
  the brokered fd is connected by the trusted core and passed in.
- **Decision 4's companion `_CONSTRUCT_ALLOWLIST` flip.** The child's `httpx.AsyncClient`
  construction (in `brokered_egress`) gets exactly one in-core HTTP-egress guard
  `_CONSTRUCT_ALLOWLIST` entry. There is **no** `_IMPORT_ALLOWLIST` entry: the module reaches
  egress through the `alfred.providers` seam (already allowed), not a direct SDK import. The
  core-side raw-socket ratchet (Decision 4) is untouched — the child only `recvmsg`s the fd, so the
  connect ∧ `SCM_RIGHTS` conjunction never fires in the child.
- **Decision 5 CONNECT-location stays Option A (child-does-CONNECT).** Decision 5's forward-gate
  said PR2b must re-decide if #358 (`Proxy-Authorization`/mTLS) landed first. #358 is still open,
  so golive keeps Option A: the child drives CONNECT + TLS + HTTP over the bare passed fd and the
  gateway remains the destination-allowlist enforcement point. Option B stays in reserve for when
  #358 lands.

- **Decision 7's "still ships dormant" paragraph is superseded.** That paragraph states
  `EgressBrokerAuditor` "still ships **dormant** … today it is exercised solely by its own unit
  tests," and names golive's `broker_sockets` wiring as the auditor's only production caller. Golive
  has now landed that caller: `QuarantineStdioTransport` holds the auditor and writes an
  `egress.broker.connected` row per brokered destination and an `egress.broker.refused` row on every
  failure arm, both live on the comms-inbound path. The two hookpoints are declared in
  `alfred/egress/hookpoints.py` and registered through `alfred.hooks.boot`. The paragraph is left
  in place as a record of the PR2a/pre-gate epoch; read it as history, not current state.

The Decision 7 audit row and the Status `Proposed → Accepted` flip were shipped by the broker-audit
pre-gate PR, **not** by golive — see the 2026-07-19 amendment at the head of this ADR.
