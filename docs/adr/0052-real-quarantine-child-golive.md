# ADR-0052 — Real quarantine-child go-live: the raw-T3 → real-provider cutover

- **Status**: Proposed (accepted on #340 PR2b-golive merge)
- **Date**: 2026-07-19
- **Slice**: #340 — PR2b-golive
  (`docs/superpowers/plans/2026-07-19-issue-340-pr2b-golive.md`; spec
  `docs/superpowers/specs/2026-07-11-issue-340-pr2b-golive-cutover-design.md`
  §14 forks 2 + 3, §20 handshake-reconciliation appendix, §21 broker-audit
  appendix)
- **Relates to**: [ADR-0015](0015-slice4-containerised-quarantined-llm.md)
  (the Slice-4 containerised quarantined-LLM subprocess this cutover makes
  real — until now a deterministic-echo loop), [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md)
  (the dual-LLM split whose quarantined half this ADR ships live),
  [ADR-0037](0037-production-quarantine-sandbox-boundary.md) (the production
  bwrap boundary this ADR amends — its "no `/etc` bind" property is carved out
  for `/etc/ssl/certs`), [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md)
  (the connectivity-free core whose residual (iv) gains a *live* brokered
  caller here), [ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md)
  (the sibling ADR that reserved "Option C — empty netns + SCM_RIGHTS
  fd-broker" for this in-house child), [ADR-0049](0049-real-privileged-turn-comms-inbound.md)
  (the **privileged**-half go-live this ADR is the quarantined-half sibling of),
  [ADR-0050](0050-quarantine-child-scm-rights-reachability-broker.md) (the
  SCM_RIGHTS reachability-broker whose dormancy-flip decisions this ADR
  activates), [ADR-0051](0051-launcher-to-core-sandbox-refusal-audit-path.md)
  (the launcher-to-core sandbox-refusal audit path whose sec-001 gate the new
  boot-ordering invariant must not trip into a forged row), epic
  [#340](https://github.com/alfred-os/AlfredOS/issues/340) (2c real-LLM
  quarantine child), issue [#230](https://github.com/alfred-os/AlfredOS/issues/230)
  (2c real-LLM provider-only egress), issue [#358](https://github.com/alfred-os/AlfredOS/issues/358)
  (core→proxy `Proxy-Authorization`/mTLS — the residual (iv) forward-gate),
  issue [#269](https://github.com/alfred-os/AlfredOS/issues/269) (arm64
  `/lib64` soft bind)
- **Supersedes**: —

> **Sign-off flag.** This ADR records the first production wiring of the
> **quarantined** half of the [dual-LLM split](../glossary.md#dual-llm-split)
> — the extractor that, until this cutover, was a deterministic-echo child that
> never called a provider. This is the *first time raw
> [T3](../glossary.md#t3-untrusted-ingestion-tier) content reaches a real LLM*
> anywhere in AlfredOS. Per CLAUDE.md's dual-LLM-boundary rule it ships with
> `alfred-security-engineer` sign-off, the adversarial suite (the release-
> blocking T3-steers-extraction corpus), and 100% line-and-branch coverage on
> the touched security paths as release-blocking gates, mirroring the
> [ADR-0049](0049-real-privileged-turn-comms-inbound.md) precedent for the
> privileged half. The merge itself is **human-gated**: the maintainer attests
> to the §13 sign-off checklist before the raw-T3 → real-provider path goes
> live.

## Context

[ADR-0015](0015-slice4-containerised-quarantined-llm.md) committed the
quarantined LLM — the only component that ever touches raw T3 content — to a
bubblewrap `kind=full` sandboxed subprocess. [ADR-0037](0037-production-quarantine-sandbox-boundary.md)
made that child spawnable in the production non-root posture, and Spec C
([ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md) /
[ADR-0042](0042-connectivity-free-core-cutover.md)) put it in an **empty
network namespace** (`--unshare-net`). But the shipped child was, throughout,
a **deterministic-echo loop**: no provider client, no real extraction, no
egress. Every trust-boundary property (empty netns, TLS-in-child, the dual-LLM
invariant) was proven against a *stand-in* — most visibly in
[ADR-0049](0049-real-privileged-turn-comms-inbound.md), whose HARD #5
provenance property was validated against an `_ExtractionAwareChildDouble`,
explicitly flagged there as "a faithful stand-in for the CONTRACT, not proof
the contract holds against the eventual real implementation" once #340 lands.

[ADR-0050](0050-quarantine-child-scm-rights-reachability-broker.md) shipped
the core-side half of the reachability mechanism — a raw TCP socket toward the
gateway's L7 CONNECT proxy handed to the child over an inherited AF_UNIX
control fd via `sendmsg(..., SCM_RIGHTS, ...)` — but genuinely **dormant**:
`spawn_quarantine_child_io(control_fd=False, ...)` on the live path, the shipped
bwrap policy untouched, no live caller. ADR-0050 recorded that dormancy as the
explicit PR2b sign-off item: "flipping `control_fd` to always-on for the live
spawn path is *the* security-posture change under review at go-live."

This ADR records that go-live. It is the quarantined-half sibling to ADR-0049
(the privileged-half go-live): together they complete the dual-LLM split as a
live production path. The two remaining ratification forks the golive design
resolved — the retry × one-shot-socket problem (fork 2) and the provider
construction reshape (fork 3) — are recorded here as decided, alongside the
per-call socket lifecycle, the CA carve-out, refuse-boot, and the boot-ordering
invariant the #443 two-frame handshake introduced.

## Decision

**Flip the dormant reachability-broker live and delete the echo path.** The
production spawn site passes `control_fd=True` with the real child module; the
child performs real `provider.complete()` extraction over a brokered gateway
socket in its empty network namespace. The specific decisions:

- **Fork 2 — the host brokers N sockets up-front per extraction; the child
  consumes one per attempt and drains leftovers.** `dispatch_extraction`
  retries `complete()` up to `_MAX_RETRIES+1 = 3` times (schema-validation
  failures), each attempt needs a fresh one-shot socket, and fd-4 is strictly
  one-way (core→child) so the child cannot request more mid-extraction.
  `QuarantineStdioTransport.dispatch` therefore brokers all N **concurrently**
  (`asyncio.gather`, not `N × _CONNECT_TIMEOUT_S` serial) *before* writing the
  extract frame; the child consumes one socket per attempt and drains the
  `(N − attempts_used)` leftovers with a **non-blocking** `MSG_DONTWAIT`
  recv-until-EAGAIN sweep in the extract-branch `finally`. A hard-count
  blocking drain would wedge the child on a miscount. **N = 3 is a hard ceiling
  conditional on P1a** (`max_retries=0` on the child provider + httpcore
  `retries=0`): with any SDK-layer re-dial the one-shot `PassedFdBackend`
  cannot serve a second `connect_tcp` and demand balloons to 3×3; a unit test
  pins `max_retries=0`. fd-4 stays strictly one-way — PR2a's
  reverse-fd-injection closure is untouched.

- **A partial fd hand-off REVOKES the child; connect-defer alone is not enough.**
  Connect-defer makes the CONNECT half all-or-nothing, but it cannot make the
  SEND half atomic: if `_send_one` fails on socket *k* of *N*, *k−1* descriptors
  are already in the child's SCM_RIGHTS queue. Because a failed batch writes **no
  extract frame**, the child's `drain_leftovers()` `finally` — its only reclaim
  path — never runs, and the `transport_failed` arm never calls `aclose()`. The
  child would be left holding live, gateway-reachable capability behind an audit
  row that says the broker *refused*, accumulating up to `N−1` such sockets per
  failure. So `QuarantineStdioTransport` **tears the child down** on any preamble
  failure that could have delivered an fd (`ControlFdBrokerError.delivered > 0`,
  the preamble deadline, or a post-broker audit failure): killing the child
  revokes the capability and discards the desynced queue atomically, in one step
  the kernel guarantees. A `delivered == 0` failure — the common gateway-down
  case — deliberately does **not** revoke; nothing reached the child, and killing
  it would turn a transient outage into a hard-down quarantine path.

  **Accepted operational consequence.** The child is spawned exactly once, at
  daemon boot (`_build_comms_inbound_extractor`); there is **no respawn
  scheduler**. A revoke therefore takes the quarantine path down until the daemon
  restarts. It degrades gracefully rather than crashing — with the control parent
  closed, `_send_one` fails immediately and every later extraction returns the
  same `provider_unavailable` typed refusal plus its own `egress.broker.refused`
  row — but the path stays down. This is the deliberate fail-closed trade against
  leaving un-revoked gateway capability in a T3-holding child. A supervised
  respawn for the quarantine child is a tracked follow-up (see References).

- **Fork 3 — a `BrokeredProviderSource` wrapper-provider, not a bare factory.**
  `dispatch_extraction` is egress-free by contract (its docstring guarantees it
  imports no SDK/httpx), so the per-call socket must not come from a factory the
  dispatcher rebinds inside its loop. `_build_provider(key)` returns a frozen
  `_ProviderFactory` (key + model, key-free `__repr__`, anti-leak test), not a
  live client. `BrokeredProviderSource(factory, control_end)` keeps the egress
  imports lazy in `brokered_egress` only and exposes a **socket-free**
  `capabilities()` (Anthropic caps are a model-invariant classvar, so
  `extraction_mode` is picked once before the loop with no bound provider) plus
  a per-attempt `bind()` `@asynccontextmanager` that receives the next
  pre-brokered socket, builds a per-call `httpx.AsyncClient`, yields the
  provider, and `await client.aclose()`s in `finally`. `aclose()` is the **sole
  fd owner** — no second `socket.socket(fileno=fd)` close (EBADF / reused-fd
  hazard).

- **Per-call, no-keepalive socket lifecycle.** One brokered socket → one client
  → one request → close. Pooling/keepalive over a one-shot passed fd is
  unusable (a consumed fd cannot serve a second dial). TLS terminates **in the
  child** (HARD #5): the core opens a bare TCP socket, writes **zero
  application bytes**, and hands it away; the gateway blind-splices ciphertext;
  the child drives CONNECT + TLS + HTTP.

- **The `/etc/ssl/certs` CA carve-out.** The child now needs the public-CA
  trust store to verify the provider's certificate. The shipped bwrap policy
  gains the **narrowest** possible bind — `["/etc/ssl/certs", "/etc/ssl/certs"]`,
  HARD (not soft), read-only — and the spawn env carries
  `SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`. This is a **real
  system-store verify path, not disabled verification**. It is the sole `/etc`
  subpath bound anywhere in the policy: `/etc/passwd`, `/etc/shadow`,
  `resolv.conf`, and ssh configs stay invisible. This narrows — and makes
  precise — ADR-0037's "no `/etc` bind" property (amended alongside this ADR).

- **Refuse-boot = Option A (host-primary, two-layer).** An unset/empty provider
  key must refuse the daemon boot, not silently degrade. The **primary** check
  is host-side and **synchronous**: `_resolve_provider_key`
  (`comms_mcp/daemon_runtime.py`) verifies the resolved key is non-empty
  *before* the single `spawn_quarantine_child_io` await, and refuses through the
  existing `_refuse_boot` arm (`cli/daemon/_commands.py`) — mirroring the shipped
  `SecretBrokerConfigError`/`QuarantineChildSpawnError` handling. It lives in the
  *trusted* host, costs no spawn, and — because the key is already resolved
  synchronously — adds **no** await to the fd-3/fd-4 clobber window. The
  **secondary** check is a child last-line guard (defense-in-depth) that refuses
  if it reaches provider construction with no real provider.

- **Delete `_PROVIDER_KEY_PLACEHOLDER` (the silent-dead-LLM must-not-regress).**
  `_resolve_provider_key` today returns a *non-empty* placeholder under a TODO
  to "flip to fail-closed once the child makes a real call." A surviving
  placeholder would build a **real client on a bogus key = a silent dead LLM** —
  the daemon-side sibling of the echo-path deletion (raw T3 laundered with no
  working LLM in the loop; a HARD #7 silent-security-path-failure shape). The
  constant *and* the placeholder-return branch are deleted, with a
  no-placeholder test. The Option A primary refuse is what replaces it.

- **The boot-ordering invariant is load-bearing.** Since #443 the child emits a
  `hello` frame (provenance) and a `ready` frame (liveness) at boot, read by the
  host's `_await_boot_handshake`. Golive *adds* fd-4 control-socket
  reconstruction to `main()`, and the exact order must be `emit_hello` →
  `_build_provider` (the factory — boot-cheap, opens **no** socket) → **fd-4
  control-socket reconstruction** (must precede `_write_boot_ready` and refuse
  on its own failure, else a `ready` frame would lie about a child that cannot
  broker) → `_write_boot_ready` → loop. The secondary refuse-boot guard fires
  **strictly between `emit_hello` and `_write_boot_ready`**: a child that
  refused *before* `emit_hello` would produce a zero-stdout EOF, and the
  ADR-0051 sec-001 gate (`quarantine_child_io.py`,
  `if refusal_candidate and not self._child_wrote_stdout`) would **mis-attribute
  it to the T0 launcher — a forged `sandbox_refused` row**. An ordering
  assertion pins the sequence so a `main()` refactor cannot reorder it.

- **`ready` = liveness (initialized + serving), NOT provider reachability.** A
  wrong-but-non-empty key (a "class-3" failure) passes *both* refuse layers and
  surfaces only at first extraction. The go-live gate attests boot-refuses an
  *unset/empty* key — it does **not** attest the key is *valid*. This is an
  explicit sign-off non-claim (§13).

- **The broker-failure typed refusal reason is `provider_unavailable`, not
  `quarantine.transport_failed`.** The golive spec §7 called for a
  `quarantine.transport_failed` typed refusal on a broker `ControlFdBrokerError`.
  That string is **not a valid `TypedRefusalReason`**: the orchestrator lift
  (`QuarantinedExtractor._extract_body`, `security/quarantine.py`) validates the
  frame's `reason` against `get_args(TypedRefusalReason)` and would raise a
  `PluginProtocolViolation` on it — `transport_failed` is an audit-**result** /
  event value, not a member of the closed refusal Literal. The reason is
  therefore **`provider_unavailable`** (an existing, valid member): semantically
  faithful (the child cannot reach provider egress), HARD #7 holds (loud, typed,
  no silent fallback), and the broker-vs-provider forensic distinction is
  durably preserved in the **separate** `egress.broker.refused` audit row (which
  carries `destination` (host:port) + a closed-vocab `reason`). This deviation
  from spec §7 is ratified here, not silent.

- **The gateway provider-plane CONNECT-wait timeout rises to 22s
  (per-listener).** Pre-brokered sockets #2/#3 sit accepted-but-idle at the
  gateway until a late retry uses them. The gateway handshake idle timeout was
  `_HANDSHAKE_TIMEOUT_S = 10.0`s < the 20s child budget, so a socket used on
  attempt 3 (≈ t=17.5s) was dead-on-arrival — a legitimate retry silently lost.
  The gateway handshake timeout becomes a **per-instance** constructor parameter
  (default 10.0s unchanged) and the **provider-plane** CONNECT proxy
  (`cli/gateway/_commands.py`) passes **22.0s**; the Discord AF_UNIX adapter and
  the tool-egress relay keep their tight 10s slow-loris guard. The timeout
  nesting becomes `action_deadline(30) > host_read(25) > gateway_handshake(22) >
  child_budget(20) > SDK_read(8)`, pinned by an ordering-invariant unit test.
  This composes with the child-side socket-deadline prerequisite and with
  connect-defer. **Correction (fix round, batch B):** that prerequisite was first
  recorded as `sock.settimeout(read)` alone. It is not sufficient —
  `settimeout` is a per-syscall **idle** timeout that resets on every byte
  received, so a slow-drip response stays unbounded under it, and
  `asyncio.wait_for` cannot help because `anyio.to_thread.run_sync` runs the
  blocking SDK `recv` with `abandon_on_cancel=False` (it cancels, then *awaits*
  the shielded thread). What makes the 20s budget a real ceiling is that
  `dispatch_extraction` passes the REMAINING budget to
  `BrokeredProviderSource.bind()`, which anchors it as an **absolute deadline**
  every socket operation of that attempt is clamped against
  (`min(read_timeout, deadline - now)`, an expired deadline refusing outright).
  The idle cap survives as the inner per-syscall dead-peer detector. Without
  this, the worst case was `20 + 8 = 28s` — past the host's 25s
  `_READ_FRAME_TIMEOUT_S`, so the host tore the child down and its in-budget
  refusal was lost.

- **The broker preamble is bounded at 4s and joins the nesting as a SUM term.**
  The per-extraction preamble (`broker_sockets` plus its
  `egress.broker.connected` rows) was the one term bounded by nothing. Unbounded
  it sits *outside* the hierarchy above: under gateway degradation the outer
  `action_deadline` fires mid-preamble and the extraction dies as an anonymous
  deadline kill, so the graceful `provider_unavailable` refusal and the
  `egress.broker.refused` forensic row — the artefacts this path exists to
  produce — are never reached. Because the preamble is **sequential with**, not
  nested inside, the `read_frame` bound, the invariant is a sum rather than an
  ordering: `preamble(4) + host_read(25) = 29 < action_deadline(30)` on the
  success path, and `preamble(4) + failure-row(≤5) = 9 ≪ 30` on the refusal path.
  The concurrent CONNECT phase is what makes a bound this tight viable (a serial
  loop's `N × _CONNECT_TIMEOUT_S = 30s` could not fit under any of it). Two
  consequences are deliberate and recorded: this bound, not
  `control_fd_broker._CONNECT_TIMEOUT_S` (10s), is the effective connect ceiling
  on the golive path; and it is *tighter* than `EgressBrokerAuditor`'s own 5s
  per-write budget, so a hung `append_schema` surfaces as
  `broker_preamble_deadline_exceeded` rather than the auditor's
  `egress.broker.audit_write_timeout`. Both are loud, typed and fail closed; an
  invariant test pins the inversion so a future retune cannot silently restore an
  unbounded hot-path stall.

- **The echo path is DELETED, not bypassed.** `_echo_extracted_frame`,
  `_DeterministicProvider`, and the `_build_provider` sentinel return are
  removed. A surviving echo behind any residual branch/flag would let a misconfig
  route to echo, the child would fabricate a schema-valid `extracted` frame from
  raw T3, and the host would tag it T2 and trust it — raw T3 laundered to trusted
  T2 with no LLM in the loop (HARD #7). A no-echo test asserts the child cannot
  emit an `extracted` frame without a real `provider.complete()`.

- **HARD #5 provenance is re-validated against the real extractor schema,
  restated structurally.** ADR-0049's provenance property was validated against
  a child double and flagged for re-validation once #340 lands. The real
  extractor projects raw body text into `{text, intent}`, so "the marker never
  rides a returned field" is *wrong* for it (the schema is designed to carry
  content). HARD #5 is restated structurally: the reply is schema-valid,
  `extra="forbid"`, has **no `tool_calls`** and no extra keys (no free-form
  escape); it is tagged **T2**; no control-frame / raw-envelope passthrough; and
  the raw T3 **envelope** (transport framing, `handle_id`, host envelope) never
  appears verbatim — the message *content* is what the schema is designed to
  carry. The privileged process only ever sees the validated
  `Extracted`/`TypedRefusal`.

## Consequences

### Positive

- The dual-LLM split is a **live production path** for the first time: raw T3
  content is extracted by a real LLM in an empty-netns bwrap sandbox, and only
  the schema-validated, T2-tagged `Extracted`/`TypedRefusal` reaches the
  privileged orchestrator. Together with ADR-0049 this completes the split the
  PRD's DEC-007 mandates.
- The containment case is unchanged by the cutover and holds by construction:
  the child's network namespace stays empty (ADR-0050 Decision 2 / the C1
  ENETUNREACH negative control), so a compromised child still cannot open its
  own socket; the *only* reachable connection is the one already-scoped fd the
  trusted core brokered. The kernel isolation, not any userspace control, is the
  enforcement-of-record.
- The silent-failure surface is closed at both ends: the echo path is deleted
  and the non-empty key placeholder is deleted, so neither a misconfigured
  provider key nor a routing slip can launder raw T3 to trusted T2 with no live
  LLM. Both refuse loud (host-primary refuse-boot; no-echo test).
- The broker-failure audit forensics improve: `provider_unavailable` is the
  operator-visible refusal, while the destination-carrying
  `egress.broker.refused` row (ADR-0050 Decision 7 / the pre-gate
  `EgressBrokerAuditor`) records the host:port that failed — a distinction the
  single refusal reason could not carry.

### Negative

- **The provider forward-proxy's confused-deputy gap (ADR-0040 residual (iv))
  gains a *live* brokered caller.** Until #340 golive the broker had no live
  audited caller; now the child's brokered CONNECT is a real path through the
  gateway L7 proxy, which authenticates callers by network membership alone (no
  per-caller `Proxy-Authorization`/mTLS until #358). The kernel-isolation layer
  still bars a *direct* external socket, but this proxied path is live. Tracked
  by #358; ADR-0040 residual (iv) is amended alongside this ADR.

- **The turn-level cost of the quarantine extraction is aggregated by no one
  yet.** `dispatch_extraction` now returns a summed `cost_usd` that accrues
  across every paid attempt and rides both the `extracted` and `typed_refusal`
  returns (P1c). But the host consumer — `QuarantinedExtractor._extract_body`
  (`security/quarantine.py`) — parses the frame into `Extracted`/`TypedRefusal`
  and **drops `cost_usd`**. The natural join point is the turn record assembled
  in `orchestrator/core.py` (the `per_turn_spent_usd` / `turn_cost_usd`
  accumulation), which today sums only the #338 **privileged** provider cost, not
  the quarantine extraction cost. Wiring the quarantine cost through the frame
  lift into that turn record is a **tracked follow-up** (telemetry, not a
  security gate) — see References. Until it lands, cost reporting under-counts a
  turn by its quarantine-extraction spend.

- **A wrong-but-non-empty provider key is not caught at boot** (the `ready` =
  liveness non-claim). It surfaces as a `provider_unavailable` refusal at first
  extraction, not a boot refusal. Accepted: validating a live key at boot would
  require a real paid provider round-trip on the connectivity-free core's boot
  path, which the design deliberately avoids.

### Neutral

- **Deviation from spec §7 recorded, not silent.** The broker-failure typed
  refusal is `provider_unavailable` (spec §7 wrote `quarantine.transport_failed`,
  which is not a valid `TypedRefusalReason`). See the corresponding Decision
  bullet; the forensic `destination` distinction lives in the `egress.broker.*`
  audit family, not the refusal reason.
- **The ADR-0050 Decision 7 audit row + Status flip already shipped ahead of
  this ADR** in the broker-audit pre-gate PR (`src/alfred/egress/broker_audit.py`;
  golive spec §21), so ADR-0052 does **not** re-claim them. This ADR activates
  ADR-0050's remaining *dormancy-flip* decisions only (`control_fd=True`, the CA
  bind, `keep_fds=[3,4]`, the new `_CONSTRUCT_ALLOWLIST` entry).
- **The child module reaches egress-capable imports via the provider seam, not a
  direct SDK import**, so the in-core HTTP-egress guard gets exactly one
  `_CONSTRUCT_ALLOWLIST` entry (`brokered_egress` constructs `httpx.AsyncClient`)
  and **no** `_IMPORT_ALLOWLIST` entry. The raw-socket ratchet
  (`test_only_sanctioned_raw_socket_egress_site.py`) is not tripped — the child
  only `recvmsg`s an fd, it never does an INET-connect ∧ `sendmsg(SCM_RIGHTS)`.
  Where a module-scope egress import is unavoidable, the closed-egress anchor
  (`test_quarantined_llm_not_yet_spawned_while_egress_open.py`) is inverted with
  the sbx-2026-005 precedent and the inversion justified.
- **The canned-Anthropic integration stub validates nothing about the real
  gateway's acceptance policy** — destination allowlist, gateway-side DNS,
  refuse-literal-IP, reject-non-globally-routable, `Proxy-Authorization`/mTLS
  (the #358 residual) are all exercised only by the nightly real-key smoke
  follow-up, not by this cutover's tests. #269 (arm64 `/lib64` soft bind) is
  unchanged.

## Alternatives considered

### Reverse fd-4 to request/response so the child requests sockets just-in-time

Rejected — a security regression versus PR2a, which made fd-4 strictly one-way
(core→child) to close reverse-fd-injection. The host brokering `_MAX_RETRIES+1`
sockets up-front keeps fd-4 one-way and is essentially forced: the host reads
exactly one reply frame, so there is no host-side loop to service just-in-time
socket requests.

### Move the retry loop host-side (one socket, retries in the privileged core)

Rejected. The T3 *content* lives only in the child's cache and the socket
binding is child-side; moving the loop would drag T3 handling back toward the
privileged process, exactly the boundary the dual-LLM split exists to hold. (The
earlier "the retry prompt embeds the previous attempt" rationale was factually
wrong — `_build_extraction_prompt` rebuilds from a closed-vocab category + schema
only, the prior response deliberately removed per sec-001 — but the conclusion
stands.)

### One socket + keep SDK retries on

Rejected: a consumed one-shot fd cannot serve a second dial, and disabling
schema-validation retries loses extraction reliability. Per-call no-keepalive
with N pre-brokered sockets is the spike-proven shape.

### Force the broker-failure refusal into the `sandbox_refused` audit family

Rejected (golive spec §21). `SANDBOX_REFUSED_FIELDS` cannot hold `destination`
or `egress_id` and its closed 35-reason vocabulary is about bwrap/policy/bind,
not egress transport. The broker rows live in the egress-audit family
(`egress.broker.connected` / `egress.broker.refused`), mirroring the shipped
`EGRESS_RELAY_REFUSED_FIELDS` precedent.

### Keep `quarantine.transport_failed` as the typed refusal reason

Rejected: it is not a member of `TypedRefusalReason`, so the orchestrator lift
would reject the frame as a protocol violation. `provider_unavailable` is the
valid, semantically faithful member; the transport-level detail is preserved in
the `egress.broker.refused` audit row.

## References

- [PRD §5 Architecture Overview](../../PRD.md#5-architecture-overview) — the
  privileged-orchestrator / quarantined-LLM split this ADR ships live in full.
- [PRD §7.1 Security & Prompt Injection Defense](../../PRD.md#71-security--prompt-injection-defense)
  — DEC-007, the non-negotiable dual-LLM invariant.
- [ADR-0049](0049-real-privileged-turn-comms-inbound.md) — the privileged-half
  go-live; this ADR is its quarantined-half sibling, and re-validates the HARD #5
  provenance property ADR-0049 flagged for re-validation once #340 lands.
- [ADR-0050](0050-quarantine-child-scm-rights-reachability-broker.md) — the
  SCM_RIGHTS reachability-broker; this ADR activates its dormancy-flip decisions
  (`control_fd=True`, the CA bind, `keep_fds=[3,4]`, the `_CONSTRUCT_ALLOWLIST`
  entry) and confirms Decision 5's CONNECT-location = child-does-CONNECT (since
  #358 is still open).
- [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md) —
  residual (iv) (the provider forward-proxy gains a live brokered caller here)
  and residual (vii) (the per-call signed egress-audit row, partially resolved
  for this path by the pre-gate `EgressBrokerAuditor`).
- [ADR-0037](0037-production-quarantine-sandbox-boundary.md) — the production
  bwrap boundary; its "no `/etc` bind" property is amended for the
  `/etc/ssl/certs` CA carve-out.
- Spec: [2026-07-11-issue-340-pr2b-golive-cutover-design.md](../superpowers/specs/2026-07-11-issue-340-pr2b-golive-cutover-design.md)
  — §14 forks 2 + 3, §20 handshake-reconciliation appendix (refuse-boot Option A,
  the placeholder deletion, the boot-ordering invariant, the `ready` = liveness
  non-claim, ADR = ADR-0052), §21 broker-audit appendix (§21.5 the gateway 22s
  CONNECT-wait resolution).
- Plan: [2026-07-19-issue-340-pr2b-golive.md](../superpowers/plans/2026-07-19-issue-340-pr2b-golive.md)
- Glossary: [dual-LLM split](../glossary.md#dual-llm-split),
  [trust tier](../glossary.md#trust-tier),
  [T3 (untrusted-ingestion tier)](../glossary.md#t3-untrusted-ingestion-tier).

### Tracked follow-ups (recorded, not filed here)

- **Turn-level quarantine-cost aggregation.** Wire the frame-lifted
  `cost_usd` (dropped today by `QuarantinedExtractor._extract_body`) into the
  `orchestrator/core.py` turn record so the quarantine extraction cost joins the
  #338 privileged cost in one `turn_cost_usd`. Telemetry, not a security gate.
- **CLAUDE.md HARD #5 + PRD note (human-gated).** Golive makes CLAUDE.md's HARD
  #5 ("the privileged orchestrator never sees raw T3; only the quarantined LLM
  does") *fully* true — the quarantined LLM is now real. CLAUDE.md and PRD edits
  are human-gated; a human-gated follow-up should update HARD #5's note and the
  PRD to reflect the live cutover. Not edited by this ADR.
- **Hub deep-docs golive note (human/docs-author follow-up).** The
  `docs/subsystems/quarantine.md` and `docs/subsystems/security.md` deep-docs
  still describe the deterministic-echo child; an `alfred-docs-author` pass
  should record the live real-LLM child. Recorded per golive spec §19-E5; not
  written here.
- **Supervised respawn for the quarantine child.** The child is spawned once at
  daemon boot with no respawn scheduler, so the partial-hand-off revoke (and any
  other child death) takes the quarantine path down until the daemon restarts.
  Extractions degrade to a graceful `provider_unavailable` refusal rather than
  crashing, so this is availability, not a security gate — but a supervised
  respawn would turn a revoke into a self-healing event.
- **#358** — core→proxy `Proxy-Authorization`/mTLS (the residual (iv)
  forward-gate the live brokered caller now exercises).
- **Nightly real-key smoke** — real Anthropic + real gateway + real key in CI
  secrets; the only real-external-egress exercise; not gating the cutover.
