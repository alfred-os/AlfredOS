# ADR-0040 — Connectivity-free core / mandatory egress chokepoint

- **Status**: Accepted (G7-5 closeout)
- **Date**: 2026-07-01
- **Amended**: 2026-07-02 — residual set expanded to (iv)–(vii) and the core→proxy
  authentication mitigation tracked as
  [#358](https://github.com/alfred-os/AlfredOS/issues/358). (iv)–(vi) + the (ii) framing fix
  are from the ADR-0040 sign-off residual panel; (vii) surfaced in the follow-up PR review.
- **Amended**: 2026-07-10 — see sibling [ADR-0050](0050-quarantine-child-scm-rights-reachability-broker.md)
  (the 2c quarantine-child SCM_RIGHTS reachability-broker, `#340` PR2a), which records the
  mechanism that touches residual (iv) (its core→gateway `connect()` inherits the same
  confused-deputy/no-per-caller-authentication gap until `#358` lands) and residual (vii) (it
  defers the durable per-extraction core-side egress-audit row to a hard PR2b pre-gate).
- **Amended**: 2026-07-19 — the 2026-07-10 deferral above is now partially resolved: the
  ADR-0050 SCM_RIGHTS broker path writes durable, signed, core-side rows for its own per-call
  egress events (`EgressBrokerAuditor`, `src/alfred/egress/broker_audit.py`; ADR-0050 Decision
  7; golive spec §21). This resolves residual (vii) for that one path only — see the residual
  (vii) text below for scope.
- **Amended**: 2026-07-19 (PR2b-golive) — see [ADR-0052](0052-real-quarantine-child-golive.md)
  (the real quarantine-child go-live), which activates the *live* brokered caller of the ADR-0050
  broker path: residual (iv)'s confused-deputy gap now has a live caller (until #358), and the
  `EgressBrokerAuditor` recorded as dormant in the 2026-07-19 amendment above is now driven on the
  live extraction path. See residuals (iv) and (vii) below.
- **Amended**: 2026-07-21 ([#470](https://github.com/alfred-os/AlfredOS/issues/470) PR1) — Decision 1
  gains the **inbound-listener class-line** (an inbound listener on `alfred_internal` is not the
  "external socket" the invariant forbids), and the residual panel gains **(viii)**: the core
  `/metrics` exposition is unauthenticated plaintext HTTP readable by any `alfred_internal` peer.
  Both facts went live when PR1 merged. #470's third ADR arm — the two new internal-only
  third-party services (Prometheus + Grafana) and the Prometheus TSDB attached to the
  connectivity-free stack — landed with **PR2**; see the 2026-07-22 entry below.
- **Amended**: 2026-07-22 ([#470](https://github.com/alfred-os/AlfredOS/issues/470) PR2) — #470's
  third ADR arm lands: the bundled observability stack attaches **two new internal-only
  third-party services** — Prometheus (`alfred-prometheus`, `prom/prometheus`) and Grafana
  (`alfred-grafana`, `grafana/grafana`) — plus the **Prometheus TSDB** (`alfred_prom_data`
  volume) to the connectivity-free stack. CLAUDE.md's actual rule is narrower than "third-party
  service" — it says only "Do not introduce new datastores without an ADR." The Prometheus TSDB
  IS a new datastore, so that rule applies directly and is this amendment's justification; this
  ADR additionally chooses to record the two new third-party *service* attachments (Prometheus,
  Grafana) as a deliberate extension of that discipline, not because CLAUDE.md's datastore rule
  itself names services. Both services join `alfred_internal` **only** — neither is added to
  `alfred_external`, so `test_only_gateway_on_external`'s generic any-new-service guard
  (`tests/unit/test_compose_invariants.py`) stays intact and the gateway remains the sole
  external-egress plane (Decision 1); zero egress from either service.

  **Content is bounded; the TSDB widens the ACCESS surface vs. residual (viii), not just an
  equivalent restatement of it.** The Prometheus TSDB holds the same bounded
  operational-aggregate set residual (viii) describes (turn/scrape counters, revoke counts,
  DLP-refusal rates — no T3 content, no PII, no secret), scraped off **both** exposition
  endpoints per `ops/prometheus/prometheus.yml`'s two scrape jobs: the core's curated
  `CORE_OWNED_COLLECTORS` registry (residual (viii)) and the gateway's own `/metrics` exposition
  (`gateway_*` series such as `gateway_core_link_up`, surfaced in
  `ops/grafana/dashboards/gateway.json`), bounded by a separate mechanism —
  `test_gateway_exposition_has_no_per_user_labels` — rather than the core's curated-registry
  ratchet. But residual (viii) describes an *instantaneous, single-shot* `/metrics` read: a
  peer that scrapes gets the current values and nothing more. The TSDB persists ~15 days of
  that same content, queryable via Prometheus's own **unauthenticated** PromQL API on
  `alfred-prometheus:9090` — readable by any `alfred_internal` peer, the same "authenticated by
  network membership alone" gap residual (iv) names for the egress proxy. That is a genuine
  widening of the *access* surface (history + a query language over it), not merely the same
  content read twice — a peer can now ask trend/aggregate questions ("how did the revoke rate
  change over the last week") that a single `/metrics` scrape cannot answer. Content stays
  bounded (same curated, non-reversible label set), so the TSDB is **not** a system-of-record
  datastore alongside Postgres/Redis/Qdrant — it is a disposable, rebuildable-from-source,
  15-day-retention cache of that bounded content — but it is a new edge of residual (viii), not
  an equivalence with it. Same fix-shape as (iv)/(viii): per-caller authentication on
  `alfred_internal` (#358); not separately tracked today.

  Grafana's sole datasource is Prometheus, provisioned `access: proxy`
  (`ops/grafana/provisioning/datasources/`) — the query is proxied **server-side**, inside the
  Grafana pod, to `http://alfred-prometheus:9090` over `alfred_internal`, never issued
  client-side from an operator's browser. That server-side-proxy shape is precisely why Grafana
  is never given an `alfred_external` bridge of its own: **the operator's browser reaches
  Grafana through the host loopback mapping; Grafana reaches Prometheus server-side over
  `alfred_internal`, and neither service joins `alfred_external`.** (The browser leg does not
  itself traverse `alfred_internal` — only Grafana's own server-side request to Prometheus
  does.)
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

**Class-line: an inbound listener on `alfred_internal` is not an "external socket"
(2026-07-21, #470).** The invariant governs *outbound* reachability — the whole two-layer
model (§2) is about a core process being able to reach a destination off the stack. A TCP
listener that only *accepts* connections from peers already on the kernel-isolated
`alfred_internal` network creates no route out and cannot break `internal: true`. The core
has always bound inbound listeners on that network (the `comms-tui.sock` the gateway dials);
`alfred daemon start` now also binds a Prometheus `/metrics` exposition there
(`prometheus_client.start_http_server`, which is listen-only). Adding such a listener trips
no `tests/unit/test_compose_invariants.py` ratchet and needs no new egress grant. What it
*does* create is a read surface — see residual (viii). Opening an **outbound** socket from
core code remains forbidden regardless of who initiated the flow.

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
- `Proxy-Authorization` / mTLS authentication of the core-to-proxy connection is a tracked
  future add (#358, also named in ADR-0042); until then the caller is only gated by
  network-membership plus destination allowlist (no per-caller authentication — see residual
  (iv) for the confused-deputy consequence).

## Honest residuals accepted at sign-off

These are recorded, not claimed caught.

**(i) Discord SNI-spoof-to-cotenant and CDN-cotenant.** An allowlisted CONNECT authority
can carry a different inner SNI; TLS-passthrough is SNI-blind. Encrypted Client Hello
(ECH) defeats any SNI-peek attempt. Discord is Cloudflare-fronted; allowlisted hosts share
a CDN edge with attacker-controlled infrastructure. Recorded in the adversarial corpus
(de-2026-016, `out_of_scope`).

**(ii) Mode-(a) provider-prompt exfil is destination-gated only.** TLS terminates at the
provider: the gateway cannot inspect the prompt or the API key. An instruction in a prompt
to exfiltrate to `api.anthropic.com` reaches the provider. This is the explicit cost of
TLS-passthrough — SDK streaming, retry semantics, and prompt confidentiality toward the
gateway operator are preserved; payload-blindness is the trade-off. The compensating
barrier is upstream, not at egress: the privileged orchestrator that composes the provider
prompt never sees raw T3 content (dual-LLM split, PRD §7.1), so an injected exfil
instruction is structured-extracted to T2 rather than interpreted as an instruction; and
secrets are broker-substituted at the tool-call boundary rather than embedded in the prompt,
so no plaintext secret sits in the provider prompt to exfiltrate. These barriers reduce, not
eliminate, the risk — see residual (v) for the case they do not cover. Destination-gating is
the last line here, not the only one. This residual is recorded in the adversarial corpus
(de-2026-014, `out_of_scope`).

**(iii) Under full gateway compromise the two-layer framing degrades.** The gateway is both
the sole egress point and the serial cred-transit point (it relays each credential's
plaintext to adapter children at spawn over fd-3, then zeroes its copy — ADR-0036
serial-harvest residual). A `Proxy-Authorization` credential for the core→proxy channel
(#358) and the encrypted vault (#330) narrow this surface in future slices.

**(iv) The provider forward-proxy authenticates callers by network membership alone —
confused-deputy.** `EgressForwardProxy._authorize` (`src/alfred/gateway/egress_proxy.py`)
checks literal-IP refusal and the destination allowlist but performs **no per-caller
authentication**. Any process that can reach the TCP listener on `alfred_internal` — not
just the orchestrator, but Postgres, Redis, Qdrant, or a compromised in-core plugin — can
use the proxy as a deputy to reach any allowlisted destination. This generalises residual
(iii) from "gateway RCE" to "any `alfred_internal`-peer compromise": the kernel-isolation
layer still bars a *direct* external socket, but not this proxied path. Same fix as (iii) —
per-caller `Proxy-Authorization` / mTLS on the core→proxy channel, tracked in #358. The
AF_UNIX Discord instance is materially less exposed: its socket lives on a gateway-only
volume never mounted into the core (§4; ADR-0043 devops-001).

**Live brokered caller since #340 golive (2026-07-19).** Until the quarantine-child go-live
([ADR-0052](0052-real-quarantine-child-golive.md)) this gap had no live audited caller — the
ADR-0050 SCM_RIGHTS reachability-broker shipped dormant (`control_fd=False`). Golive flips
`control_fd=True` on the live spawn path, so the quarantine child's brokered CONNECT is now a
*live* path through this same per-caller-unauthenticated provider forward-proxy. The kernel
empty-netns isolation still bars a *direct* external socket from the child, and the brokered fd is
one already-scoped, core-vetted connection to one allowlisted destination — but the confused-deputy
consequence above is now exercised, not merely latent. Same fix (#358); tracked there.

**(v) Reply-path / tool-arg laundering to an allowlisted destination.** A T3 injection can
drive the model to launder a secret — or other sensitive content already in its context —
into its user-visible **reply** (egressed to a correctly-allowlisted `discord.com` over
mode (a)) or into a **tool argument** that egresses to an allowlisted destination over the
mode-(b) relay. Destination-gating passes it (the destination is legitimately allowlisted),
and the mode-(b) DLP is shape / known-value / canary matching
(`src/alfred/security/dlp.py`), which base64, paraphrase, or homoglyph encoding defeats; the
mode-(a) reply path is TLS-passthrough with no *gateway-side* content inspection (the
core-side `OutboundDlp` that does run on the reply is the same defeatable matcher).
Destination-gating is therefore *not* the control for this class. The controls are upstream
and architectural: the **dual-LLM quarantine boundary** (the privileged orchestrator never
sees raw T3 — an injected instruction is structured-extracted to T2 rather than interpreted
as an instruction, PRD §7.1) and the
**secret-broker** (secrets are substituted at the tool-call boundary and never enter a
prompt, so there is no plaintext secret for the model to launder). Where those barriers are
imperfect — e.g. laundering sensitive context the model legitimately holds rather than a
broker-held secret — this residual stands. A reply-path-laundering `dlp_egress` corpus entry
(out-of-scope-residual class, cf. de-2026-014 / de-2026-016) is an un-filed corpus candidate.

**(vi) The outbound-canary detector's token set is readable from the gateway environment.**
`ALFRED_CANARY_TOKENS` is read from the gateway process environment / `docker-compose.yaml`
(`src/alfred/gateway/egress_relay.py`), so an attacker who can read that environment learns
the canary set and can shape an exfiltration payload to avoid tripping the mode-(b)
outbound-canary *detector*. The canary is defense-in-depth — a detector, not a primary
control (a hit fails loud and refuses egress) — so this weakens a secondary layer, not the
destination allowlist or the kernel isolation. (`ALFRED_TOOL_EGRESS_ALLOWLIST` is read from
the same env, but disclosing it carries no weakening — it is a public default-deny policy,
not a secret.) The relay code records the canary case as accepted.

**(vii) Routine egress audit is gateway-local, not the signed append-only core audit log.**
Every CONNECT (`egress_audit.py`) and every relay forward (`egress_relay_audit.py`) is
audited — field-allowlisted and payload-blind — but on the gateway's structlog tier plus
Prometheus counters, not the hash-chained core audit log. This follows from the gateway's
deliberate privilege model: it holds no vault key and no audit-signing key (ADR-0036), so it
cannot write a signed durable row. Security-critical relay events are *not* lost — a mode-(b)
DLP / canary trip is surfaced core-side off the typed `EgressDeniedError` the in-core relay
client raises, which writes the durable core row — but the durable signed reconcile of the
full egress audit stream into the core log is deferred (both egress-audit modules mark it a
deferred ADR-0040 residual, mirroring the G6-2b durable-audit disposition). Until it lands,
the routine allow/forward audit stream is only as durable as the gateway's logs and metrics.

**Partial resolution for the SCM_RIGHTS broker path (2026-07-19).** Unlike the gateway-hosted
CONNECT/relay paths above, the ADR-0050 SCM_RIGHTS reachability-broker is core-side code — it
holds no vault-key constraint and can write the signed core audit log directly. `EgressBrokerAuditor`
(`src/alfred/egress/broker_audit.py`; ADR-0050 Decision 7; golive spec §21) now writes a durable,
signed, core-side row on every per-call broker outcome — `egress.broker.connected` and
`egress.broker.refused` — so that path's routine egress audit is no longer only as durable as
gateway logs and metrics. This is a **partial** resolution scoped to the one path: the gateway's
routine CONNECT/relay-forward audit stream (`egress_audit.py` / `egress_relay_audit.py`) is
unaffected, and the full signed reconcile of that stream into the core log remains the open
residual described above. **The live caller lands with #340 golive**
([ADR-0052](0052-real-quarantine-child-golive.md)): the pre-gate shipped `EgressBrokerAuditor`
dormant, and golive's `control_fd=True` flip is what drives it on the live extraction path, so
these durable broker rows are now written in production rather than only exercised by unit tests.

**Deny-log signal hygiene: abandoned connections are not denials (2026-07-20, #340 golive).**
The broker pre-connects `BROKER_SOCKET_COUNT` (3) gateway sockets per extraction because a
consumed passed fd cannot re-dial, and the child consumes one per retry attempt. A
first-attempt success therefore discards the remaining sockets *unused* — closed without ever
writing a CONNECT request line. The proxy originally classified each such close as
`MALFORMED_CONNECT`, which put **two false denials on every successful extraction**: it pinned
`GatewayEgressDenyRate` (`ops/alerts/gateway.yml`) permanently on and swamped the very deny-log
this residual describes with benign noise, degrading it as an exfiltration signal.
`EgressForwardProxy._read_connect_target` now separates the two at the read site using
`asyncio.IncompleteReadError.partial`: a clean EOF having read **zero bytes** is an abandoned
connection (counted under `gateway_egress_connect_total{outcome="abandoned",plane=…}`, never
audited), while **any** partial request line followed by EOF — and an idle peer that trips
the per-handshake timeout — remain full `malformed_connect` denials. The split is deliberately
keyed on zero-bytes-read so it narrows noise without weakening the truncated-handshake or
slow-loris signal, and the documented sum invariant
(`sum(gateway_egress_denied_total{plane})` == `gateway_egress_connect_total{outcome="denied"}`)
is preserved — now **per plane**, since the outcome counter carries `plane` too (strictly
stronger than the plane-less form this ADR originally described).

Abandoned connects *are* alerted, but only off the provider plane. `plane` was added to
`gateway_egress_connect_total`'s label set precisely because the reclassification made a benign
provider-plane flood (our own discarded broker sockets) indistinguishable from the same flood on
the adapter plane (an unauthenticated peer probing the listener). `GatewayEgressAbandonedConnectFlood`
(`ops/alerts/gateway.yml`) excludes `plane="proxy"` by name. The log line stays at `debug`
deliberately: raising it would recreate in the log stream the exact deny-storm the
reclassification removed, re-burying this residual's exfiltration signal. Note the *eager* N-socket broker is not itself the thing to fix here: brokering
just-in-time instead was considered and rejected in
[ADR-0052](0052-real-quarantine-child-golive.md) ("Reverse fd-4 to request/response…") because
it would reopen reverse-fd-injection on a channel PR2a deliberately made one-way (core→child).
Classifying the discards correctly at the gateway is the fix that does not trade a security
property for log hygiene.

**(viii) The core `/metrics` exposition is unauthenticated plaintext HTTP, readable by any
`alfred_internal` peer (2026-07-21, #470).** `alfred daemon start` binds a Prometheus
exposition (default `9465`, `ALFRED_CORE_METRICS_PORT`) via
`alfred.observability.metrics_server.start_metrics_server`, which uses
`prometheus_client.start_http_server` — it binds `0.0.0.0` inside the container, speaks
cleartext HTTP, and performs **no** client authentication. Any process that can reach the
core on `alfred_internal` — Postgres, Redis, Qdrant, the gateway, a compromised in-core
plugin — can scrape it. This is the same class already recorded for the gateway's own
`:9464` exposition and for residual (iv)'s "authenticated by network membership alone", now
extended to a *read* surface on the core rather than a proxied *write* surface on the
gateway. The port is compose-internal and never host-published
(`test_core_metrics_port_never_host_published`), so the reachable set is bounded by
`alfred_internal` membership.

What bounds the disclosure is **content**, not access control: the endpoint serves a
**curated** `CollectorRegistry` built from the single `CORE_OWNED_COLLECTORS` source of truth
(`src/alfred/observability/core_metrics.py`), not the process default registry, and a
BLOCKING leak-guard (`tests/unit/observability/test_core_registry_surface.py`) pins the exact
family and label-**key** set. Every core-owned label is absent, a closed enum, or a
fixed-cardinality non-reversible bucket (`user_id_bucket` is SHA-256 mod-256; `plugin_id` is
allowlist-bucketed), so the exposition carries operational aggregates only — no T3 content,
no PII, no secret. Accepted on that basis. The residual has two live edges: (a) *timing and
volume* are still inferable by any internal peer (turn rates, revoke counts, DLP-refusal
rates), and (b) the leak-guard is a CI-time **schema** ratchet — it pins label keys, and
cannot decide that a future label *value* stays bounded (see the spec's value-boundedness
invariant, `docs/superpowers/specs/2026-07-21-470-core-metrics-observability-design.md` §5.2).
Authenticating the scrape shares the same fix-shape as residual (iv) (per-caller
authentication on `alfred_internal`, #358); it is not separately tracked today.

*Scope of this amendment:* residual (viii) above records PR1's fact only — the core `/metrics`
exposition itself. Nothing in PR1 attaches a third-party service. The third arm of #470's ADR
work — recording the two new internal-only third-party services (Prometheus + Grafana) and the
Prometheus TSDB attached to the connectivity-free stack (the TSDB is a new datastore, so
CLAUDE.md's "no new datastores without an ADR" applies directly; the two services are recorded
as this ADR's own extension of that discipline) — landed with **PR2**; see the
**Amended: 2026-07-22 (#470 PR2)** entry in the header above.

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
- Issue [#358](https://github.com/alfred-os/AlfredOS/issues/358) — core→proxy authentication
  (`Proxy-Authorization` / mTLS); the tracked mitigation for residuals (iii)/(iv).
- Epic [#333](https://github.com/alfred-os/AlfredOS/issues/333) — Spec C tracking.
