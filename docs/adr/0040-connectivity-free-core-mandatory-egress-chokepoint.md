# ADR-0040 — Connectivity-free core / mandatory egress chokepoint

- **Status**: Accepted (G7-5 closeout)
- **Date**: 2026-07-01
- **Slice**: Spec C — G7-5 closeout
  (`docs/superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md`)
- **Relates to**: [ADR-0041](0041-web-fetch-fused-fetch-extract-contract.md) (web.fetch
  fused fetch+extract), [ADR-0042](0042-connectivity-free-core-cutover.md) (G7-3
  connectivity-free-core cutover), [ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md)
  (Discord adapter AF_UNIX bridge), epic [#333](https://github.com/alfred-os/AlfredOS/issues/333),
  issues [#230](https://github.com/alfred-os/AlfredOS/issues/230) (closed by G7-1a + G7-4)
- **Supersedes**: —

## Context

From Slice 1 through Spec B, every external network connection in AlfredOS was opened
directly by the process that needed it — `AnthropicProvider`, `DeepSeekProvider`, the
Discord adapter, the web-fetch tool — with no kernel-level chokepoint. PRD §7.1
stated "Default-deny for outbound network calls" as a goal, but the structural property
was not true: `alfred-core` had unrestricted outbound NAT, and every sandboxed child ran
without `--unshare-net`.

Spec B (ADR-0036) achieved credential-concentration in placement only: the core held the
vault and decrypted credentials but no longer had external network — that flip waited for
Spec C. Spec C (G7-0..G7-4) built the machinery; this ADR is the comprehensive record of
the design, the two-layer enforcement model, and the honest residuals accepted at sign-off.

## Decision

### 1. The core is connectivity-free; the gateway is the sole external I/O plane

`alfred-core` joins only `alfred_internal` (`internal: true` in Docker Compose). The
gateway joins both `alfred_internal` and `alfred_external` and is the only service with
external-network access. No process inside the core can open an external socket — the
kernel enforces this without application-level cooperation.

### 2. Two independent enforcement layers; kernel is enforcement-of-record

**Layer 1 — kernel network isolation (enforcement-of-record).** `internal: true` on
`alfred_internal` plus `--unshare-net` on all sandboxed children (quarantine child and
Discord adapter) produces an empty network namespace for those processes. A compromised
process that ignores every userspace control still cannot open an external socket: the
kernel has no route.

**Layer 2 — gateway forward-proxy destination allowlist + mode-(b) DLP pass (defense-in-depth).**
The gateway's L7 CONNECT forward-proxy checks every outbound CONNECT against a destination
allowlist, performs gateway-side DNS resolution, rejects literal-IP CONNECTs, rejects
non-globally-routable resolved IPs (DNS-rebinding TOCTOU), and audits every connection.
For mode-(b) tool-egress bodies the gateway re-runs the full `OutboundDlp` (redaction +
outbound canary scanner) as an independent second pass over the already-core-redacted body.

Neither layer depends on the other being intact. A gap in one leaves the other standing.

### 3. Two egress modes

**Mode (a) — L7 CONNECT / TLS-passthrough.** Providers (Anthropic, DeepSeek) and the
hosted Discord adapter use the gateway as an HTTPS forward-proxy. TLS terminates at the
remote endpoint: the gateway enforces the destination and audits the CONNECT but never
sees the decrypted prompt, API key, or bot token. Provider responses are tagged **T2**
(assistant output), not T3. Discord adapter traffic is destination-gated to the Discord
allowlist.

**Mode (b) — Inspecting relay with gateway DLP.** Tool egress (web POST, email, `web.fetch`)
sends an `egress.request` frame carrying a core-DLP-redacted body to the **inspecting
tool-egress relay** (`EgressRelay` — a separate component from the mode-(a) forward-proxy,
§4). The relay re-runs `OutboundDlp` as an independent pass, destination-checks, audits, and
forwards. The **raw** tool-egress response is **T3**; it is structured-extracted (a fused
fetch+extract for `web.fetch`, [ADR-0041](0041-web-fetch-fused-fetch-extract-contract.md))
into a **T2** outcome before the privileged orchestrator sees it — never handed raw. The
idempotency ledger (§5) stores and replays that T2 outcome.

### 4. Unified L7 CONNECT forward-proxy implementation, two instances

One `EgressForwardProxy` implementation (mode a — TLS-passthrough), two runtime instances on
the gateway:

- **TCP listener** on `alfred_internal` — serves the core's `EgressClient` provider calls
  with the provider destination allowlist.
- **AF_UNIX pathname-socket listener** (on the gateway-only `alfred_discord_egress`
  volume) — serves the Discord adapter child via an in-child TCP→unix byte-splice shim
  (`src/alfred/egress/adapter_proxy_shim.py`), operating the Discord destination allowlist.

Mode-(b) tool egress is a **separate** inspecting relay (`EgressRelay`, Decision 3), not a
forward-proxy instance — it terminates TLS to run the gateway DLP pass, which a
TLS-passthrough proxy cannot do.

The `_authorize` chain (literal-IP refusal, gateway-side DNS, non-globally-routable-IP
rejection, destination-allowlist check, deny-audit write) is shared by both instances
unchanged. The AF_UNIX socket lives on a gateway-only volume: never mounted into
`alfred-core`, so the connectivity-free core cannot reach the Discord allowlist and reopen
the G7-3 invariant (ADR-0043 §4 — devops-001).

### 5. Egress idempotency

The core stamps a deterministic `egress-id` and commits a tri-state Postgres row —
`committed-no-response-yet` before the side-effect, then `committed-with-response` after.
On a duplicate egress-id the stored T2 result is replayed flagged `deduplicated`; it is
never silently dropped. The gateway is stateless with respect to idempotency. A forged or
unknown egress-id is rejected core-side before the CONNECT reaches the gateway.

### 6. Credential-concentration payoff

No process that decrypts more than one platform credential's plaintext also holds external
network. The core decrypts credentials but is connectivity-free. The gateway has external
network but never holds a vault key (ADR-0036). The Discord child decrypts one credential
(its bot token over fd-3) and reaches only Discord via the L7 proxy.

The payoff turns on the verb **decrypts**: the gateway does hold external network and does
**transit** each credential's plaintext to adapter children at spawn (over fd-3, then zeroes
its copy), but it never *decrypts* the vault. That serial cred-transit is the honest
qualifier — see residual (iii); the Positive framing and residual (iii) must be read together.

## Consequences

### Positive

- PRD §7.1 "Default-deny for outbound network calls" is structurally true, not just a goal.
- A compromised core module cannot open an external socket — the kernel enforces this.
- The gateway DLP pass (mode b) provides a second content barrier independent of core
  correctness.
- DNS exfil (QNAME side-channel) is closed: the core performs no client-side DNS
  resolution for egress.

### Negative

- The gateway is a single point of failure for all external I/O: gateway unavailability
  triggers `IOPlaneUnavailableError` for every provider and tool call.
- Mode-(a) TLS-passthrough is payload-blind: the gateway cannot inspect prompt content for
  outbound DLP on provider calls. This is a deliberate trade-off (prompt confidentiality,
  SDK streaming semantics), not an oversight.

### Neutral

- The AST import-guard lint and compose-invariant tests are permanent structural ratchets.
  They do not enforce the kernel invariant — the kernel does — but they prevent accidental
  regressions in code review.
- `Proxy-Authorization` / mTLS authentication of the core-to-proxy connection is a future
  add (named in ADR-0042). The current control is network-membership plus destination
  allowlist.

## Honest residuals accepted at sign-off

These are recorded, not claimed caught.

**(i) Discord SNI-spoof-to-cotenant and CDN-cotenant.** An allowlisted CONNECT authority
can carry a different inner SNI; TLS-passthrough is SNI-blind. Encrypted Client Hello
(ECH) defeats any SNI-peek attempt. Discord is Cloudflare-fronted; allowlisted hosts share
a CDN edge with attacker-controlled infrastructure.

**(ii) Mode-(a) provider-prompt exfil is destination-gated only.** TLS terminates at the
provider: the gateway cannot inspect the prompt or the API key. An instruction in a prompt
to exfiltrate to `api.anthropic.com` reaches the provider. This is the explicit cost of
TLS-passthrough — SDK streaming, retry semantics, and prompt confidentiality toward the
gateway operator are preserved; payload-blindness is the trade-off.

**(iii) Under full gateway compromise the two-layer framing degrades.** The gateway is both
the sole egress point and the serial cred-transit point (it relays each credential's
plaintext to adapter children at spawn over fd-3, then zeroes its copy — ADR-0036
serial-harvest residual). A `Proxy-Authorization` credential for the core→proxy channel
and the encrypted vault (#330) narrow this surface in future slices.

## Alternatives considered

### Per-plugin kernel egress cap (iptables / seccomp BPF per plugin)

Each plugin gets a pinned iptables rule or a seccomp BPF filter. Rejected: there was no
prior per-plugin kernel cap to regress from. A container-scoped `internal: true` is
deployable without root-escalation inside the container and covers the entire core
uniformly. BPF per-plugin is a future option for in-process plugins with unusually tight
egress profiles.

### Full-stack TLS termination at the gateway (provider traffic)

The gateway terminates TLS, reads plaintext, and re-encrypts to the provider. This enables
outbound DLP on provider prompts, removing residual (ii). Rejected: the gateway would then
hold both the decrypted prompt and external network, becoming the highest-value exfiltration
target; prompt confidentiality toward the operator is lost; native SDK streaming semantics
break. The marginal DLP gain does not justify the concentration.

### pasta/slirp4netns as the child-egress forwarder

A userspace IP stack injected into the child netns via `setns`. Rejected: pasta/slirp
inject a network stack, not a proxy you connect to; they require a daemon with a handle
to the child's netns inside the gateway container (not structurally available); and they
add a full NAT stack that then needs firewalling back to the permitted destinations —
strictly more surface for equivalent enforcement. ADR-0043 records the Discord-specific
analysis.

## References

- [PRD §7.1](../../PRD.md#71-security--prompt-injection-defense) — "Default-deny for
  outbound network calls"; this ADR closes the gap between goal and invariant.
- [ADR-0036](0036-gateway-adapter-hosting-inversion.md) — gateway privilege model;
  credential-concentration placement Spec C activates.
- [ADR-0042](0042-connectivity-free-core-cutover.md) — G7-3 atomic cutover; macOS
  host-port consequence; seam-vs-boot hand-off.
- [ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md) — Discord adapter
  AF_UNIX bridge; the devops-001 gateway-only volume constraint.
- [Spec C design §2, §8, §10](../superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md)
  — locked decisions, credential-concentration analysis, PRD/ADR change spec.
- Epic [#333](https://github.com/alfred-os/AlfredOS/issues/333) — Spec C tracking.
