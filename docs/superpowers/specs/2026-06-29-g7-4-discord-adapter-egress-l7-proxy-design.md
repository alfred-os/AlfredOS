# G7-4 — Discord-adapter egress hardening via the gateway L7 CONNECT proxy

- **Status:** Design (approved to plan) — revised 2026-06-30 after an 8-lens `/review-plan` pass (see §12)
- **Date:** 2026-06-29
- **Epic:** Spec C (G7) egress control plane / connectivity-free core — [#333](https://github.com/alfred-os/AlfredOS/issues/333)
- **Slice:** G7-4 (the tail of the egress-mechanism work; G7-5 is the docs/ADR-0040/ops/CLI closeout)
- **Supersedes/relates:** the Spec C design doc
  [`2026-06-25-spec-c-egress-control-plane-design.md`](2026-06-25-spec-c-egress-control-plane-design.md)
  (decision 10 — Discord-adapter egress; §3/§4.1/§4.3/§8/§9/§11). Reconciles a
  contradiction decision 10 left unspecified (see §2).
- **Closes:** the Discord half of the `#230` egress gap (the quarantine half closed in G7-1a).

---

## 1. Context

Spec C makes the connectivity-free-core invariant structurally true: the gateway is
the **sole external egress plane**, and the core is kernel-isolated on an
`internal: true` network (shipped in G7-3, PR #350 / ADR-0042). Two *gateway-hosted*
children still need egress and were brought under control incrementally:

1. the deterministic-echo **quarantine child** — closed in G7-1a (`--unshare-net`; it
   needs zero network);
2. the **Discord adapter** — still open. Its bwrap policy
   (`config/sandbox/discord-adapter.linux.bwrap.policy`) deliberately omits
   `--unshare-net`, so a compromised adapter (a crafted Discord gateway frame
   triggering a `discord.py`/parser bug) has **full unrestricted outbound** and could
   exfiltrate the T3 content it relays plus its bot token to any host. This is the
   open `#230` gap.

**The topology (verified).** The Discord adapter is a **bwrap child process *inside*
the gateway container** — `GatewayAdapterChildFactory.spawn_and_handshake`
(`src/alfred/gateway/adapter_child_factory.py`) `subprocess.Popen`s it through
`bin/alfred-plugin-launcher.sh`. It shares the gateway's network namespace unless the
bwrap policy adds `--unshare-net`. It is not a compose service; there is no
compose-layer handle to its namespace.

**Scope: mechanism-hardening, not go-live.** The Discord adapter has **no production
privileged turn** yet (the forwarded-inbound bridge is wired, but `build_orchestrator`
is not in the daemon `start` graph — ADR-0042 "seam vs boot"; #338/#339/#235 open). So
G7-4 — like G7-1's quarantine flip and G7-2c's synthetic-driver relay — hardens the
**mechanism** (policy migration + the proxy/allowlist/shim + corpus addition + test
migration), proven by a synthetic/loopback driver and a docker-gated kernel egress
proof. It does **not** stand up a live Discord bot.

**Out of scope:** G7-5 (PRD §5/§7.1 + ADR-0040 + the full adversarial corpus + ops
dashboards/alerts + the operator egress-state CLI); the encrypted secret vault (#330);
the gateway-side serial-credential-transit residual (ADR-0036; survives G7-4 — see §6);
the config-as-interface DIP pass (#351).

---

## 2. The load-bearing question, and the reconciliation

Decision 10 locked the mechanism as `--unshare-net` **and** `discord.py`'s
`Client(proxy=...)` pointed at the gateway's L7 CONNECT proxy (same listener as the
providers, mode (a)) — explicitly **not** pasta/slirp (L3/L4, can't hostname/SNI-
allowlist a Cloudflare-fronted rotating-IP host), and **not** any seccomp/apparmor
widening or new forwarder tooling. But it left a contradiction unspecified:

> `--unshare-net` gives the child an **empty network namespace** (only its own
> loopback). `aiohttp`'s `proxy=` needs a **TCP URL**. The gateway proxy's TCP listener
> lives in the *gateway's* netns — **unreachable** from an empty child netns. The only
> primitive that crosses an `--unshare-net` boundary without veth/slirp is an **AF_UNIX
> *pathname* socket** bind-mounted into the child's mount namespace (abstract AF_UNIX
> sockets are net-namespace-scoped and do **not** cross).

**The reconciliation (this design).** The gateway gains a **bind-mounted AF_UNIX CONNECT
listener** (a second instance of the existing proxy, carrying a Discord-only allowlist);
a **thin in-child TCP→unix byte-splice shim** lets `discord.py`'s
`Client(proxy="http://127.0.0.1:PORT")` work unmodified. The empty netns is the
kernel enforcement-of-record; the AF_UNIX socket is the single hole; the proxy's
Discord allowlist is the userspace defense-in-depth. This is the same shape as the
existing fd-3 broker channel — a sanctioned, bind-mounted, cross-sandbox-boundary
primitive.

This was confirmed by a four-lens specialist panel (security, devops, comms,
architect) and tightened by an 8-lens `/review-plan` pass (§12).

### Why not the alternatives

- **A — shared netns + `Client(proxy=...)` routing only.** No `--unshare-net`, no
  shim. Routes the happy path, but the child still shares the gateway netns, so a
  compromised adapter opens a raw socket to any host — *exactly* the threat we are
  closing. No kernel boundary; does not close `#230`. **Rejected** (the status quo gap,
  relabeled).
- **C — empty netns + SCM_RIGHTS fd-broker** (the spec's reserved-for-2c model).
  `discord.py`/`aiohttp` expose no per-connection fd-request hook; realizing it means
  forking `aiohttp`'s connection pool — the "transport surgery" decision 10 retired.
  **Rejected** (infeasible for a third-party library; reserved for the in-house 2c
  child).
- **pasta/slirp4netns as transport (not enforcer).** Rejected on three grounds:
  (1) **category error** — they are not network daemons you connect to; they take a
  target PID/netns and *inject* a userspace IP stack via `setns`, so a separate
  container has no handle to a bwrap child's empty netns inside the gateway container.
  (2) **More network, not less** — they hand the netns a full userspace stack (NAT to
  the host = broad egress by default) that must then be firewalled back down with
  IP/port rules, which can't pin Discord's rotating IPs, so the L7 proxy is *still*
  required on top. (3) **Strictly larger surface** — a full TCP/IP stack the
  compromised adapter can probe, vs an empty netns with one unix socket; plus the
  `setns`/CAP_NET_ADMIN plumbing and the tooling decision 10 retired.
- **`socat` as the shim binary.** `socat TCP-LISTEN:…,fork UNIX-CONNECT:…` does the
  splice, but embedding a powerful multi-address binary in the adversary-facing sandbox
  is itself the "new forwarder tooling + new bwrap bind" decision 10 retired, and gives
  a compromised parser a far larger capability than a single-purpose in-process splice.
  **Rejected** in favour of the stdlib splice.
- **`aiohttp.UnixConnector` / a custom connector** to dial the proxy over the unix
  socket directly (no shim). `UnixConnector` ignores `req.proxy` and emits no CONNECT
  line — it would send requests *directly* over the unix socket with no tunnel,
  silently defeating the gateway's CONNECT enforcement. A custom `TCPConnector`
  subclass binds to `aiohttp` private internals (version-fragile — the surgery
  decision 10 avoids). **Rejected**; the dumb shim is strictly safer and stable.

---

## 3. Decision

Adopt **Option B**. Concretely:

1. **One `EgressForwardProxy` class, two instances.** Add a bind selector to the
   existing proxy: `serve()` accepts **either** a pre-bound listening socket (`sock=`,
   for the AF_UNIX instance) **or** a TCP `(host, port)` (the existing provider
   instance). The security-critical chain
   (`_serve_connection`/`_read_connect_target`/`_authorize`/`_tunnel`) is **shared, not
   copy-pasted**; the *only* per-instance variation is the allowlist contents and an
   injected **match predicate** (see #3). The gateway runs **two** instances:
   - TCP listener on `alfred_internal` + the **provider** allowlist (existing,
     unchanged, byte-identical `serve()` path);
   - AF_UNIX listener (a bind-mounted 0600 pathname socket) + the **Discord** allowlist
     (new).
2. **Per-caller allowlist = listener reachability.** The TCP listener is reachable only
   by the core (post-`internal:true`); the AF_UNIX listener is bind-mounted into exactly
   one child. The *listener* is the caller-discriminator, so the two instances carry
   **separate** allowlist frozensets — that separation is the per-caller control.
   **No `SO_PEERCRED` check** is added: the kind:full child runs at the gateway uid (no
   `--unshare-user`), so a same-uid check would authenticate nothing while modifying the
   shared `_handle_client` and adding an undefined refusal path. Reachability (the
   bind-mount into one child) is the honest, sufficient control.
3. **Per-*entry* match-mode for the allowlist** (NOT a per-instance suffix mode).
   Each allow entry carries a mode: **`exact` is the default**; **`suffix` is used only
   for `*.discord.gg`** (the dynamic `resume_gateway_url` regional subdomain). The
   provider listener's entries are all `exact` (untouched); the Discord listener's entries
   are `discord.com` exact, `*.discord.gg` suffix, (CDN exact when added). The matcher is
   a small predicate injected into the **single shared** `_authorize` — `literal-IP`
   refusal, `RESOLVED_IP_NOT_GLOBAL`, and the deny-audit stay single-sourced across both
   instances. The suffix predicate is anchored: `host == base or host.endswith("." + base)`
   (never a bare `endswith` — that would match `evildiscord.gg`).
4. **A dumb in-child TCP→unix byte-splice shim, located under `src/alfred/`.** It accepts
   on `127.0.0.1:PORT` and splices each connection to the bind-mounted unix socket via a
   **shared splice helper** (extracted from the proxy's `_pipe`; see #1/§4.5 — the shim
   does **not** import a gateway-private symbol across the package boundary). **Zero**
   CONNECT parsing, **zero** allowlisting — it is transport glue, not a policy plane.
   Living under `src/alfred/` makes it both coverage-gated and reliably importable inside
   bwrap (the bound-interpreter prefix); `plugins/alfred_discord/` imports it.
5. **`discord.py` `proxy=` threading.** One construction site:
   `AlfredDiscordBot.__init__` forwards a `proxy: str | None` to
   `super().__init__(..., proxy=proxy)`. The URL is `http://127.0.0.1:PORT` (scheme
   pinned to `http://`). `discord.py` 2.7.1 routes its *entire used surface* — REST, the
   gateway WSS, RESUME/reconnect, CDN, rate-limit retries — through that one knob via
   `aiohttp` HTTP-CONNECT (payload-blind; no client-side DNS for Discord hosts). The only
   bypass paths (webhooks, voice) are unused; a static-symbol guard test forbids
   regressing that.
6. **Bwrap policy migration.** Add `"net"` to `unshare` and bind-mount the socket
   directory in `discord-adapter.linux.bwrap.policy`; keep the `/etc/ssl/certs` ro-bind
   (TLS verification still happens end-to-end in the child) and `keep_fds=[3]` (the
   bot-token broker channel). **Prefer `--ro-bind`** for the socket dir (least
   privilege; `connect()` needs only the 0600 socket's w-bit, not a writable mount) and
   fall back to `rw_binds`/`--bind` only if the bookworm repro shows `connect()` fails on
   `MNT_READONLY`. No `SandboxPolicy` schema change (`ro_binds`/`rw_binds` already exist).
7. **Corpus + tests.** Mint a **new** Discord-specific adversarial corpus entry (next
   free `sbx-2026-0NN`, `policy_ref` = the Discord policy) asserting enforced
   containment — `"net" in discord-policy.unshare` + proxy-only egress + the named
   near-miss DENYs (§8). **Leave `sbx-2026-005` untouched** (it is the *quarantine*
   marker, already flipped in G7-1; reusing it would regress that assertion). **Migrate,
   don't drop** `test_discord_adapter_sandbox_policy.py` — *flip* its `#230`-deferral
   assertions to the enforced posture.

---

## 4. Components

Each unit, its interface, and what it depends on.

### 4.1 `EgressForwardProxy` bind selector — `src/alfred/gateway/egress_proxy.py`

- **What:** `serve()` binds via `start_unix_server(sock=<pre-bound>)` **or**
  `start_server(host, port)` (exactly one mode; a both/neither is a loud construction
  error). The AF_UNIX socket is **pre-bound by the listener-lifecycle module (§4.3)** and
  passed in — `serve()` never binds a path itself (avoids the EADDRINUSE/double-bind the
  eager-bind would otherwise race). `_handle_client` and the SSRF chain are unchanged.
- **Interface:** `EgressForwardProxy(*, allowlist, match, audit, resolve, open_upstream,
  unix_sock=None, bind_host=None, port=None)`. `match` is the injected per-entry
  predicate (default exact); the provider instance passes the exact-only matcher.
- **Depends on:** the shared splice helper (§4.5); the per-entry allowlist type (§4.2).

### 4.2 Discord allowlist + per-entry matcher — `src/alfred/egress/allowlist.py`

- **What:** a per-entry allow type carrying a match mode (e.g.
  `EgressAllowEntry = frozenset of (host, port, Literal["exact","suffix"])`, default
  `exact`), and a `discord_egress_allowlist()` returning the Discord set, **distinct**
  from `provider_egress_allowlist`. Fix the `provider_egress_allowlist` docstring drift
  (`allowlist.py:60`, "G7-4 adds the Discord hosts" — it must **not** merge Discord into
  the provider set). The matcher predicate resolves the mypy-strict type cleanly (one
  entry type, two strategies; provider entries are all `exact`).
- **Discord destination set (verified against `discord.py` 2.7.1):**

  | Destination | Mode | Source | Notes |
  | --- | --- | --- | --- |
  | `discord.com:443` | exact | `Route.BASE` REST | login, sends, fetches |
  | `discord.gg` + `*.discord.gg:443` | suffix | `DEFAULT_GATEWAY` + dynamic `resume_gateway_url` | WSS connect + RESUME (dynamic regional subdomain) |
  | `cdn.discordapp.com:443` | exact | `Asset.BASE` | only if asset/attachment fetch is added |
  | `media.discordapp.net:443` | exact | attachment `proxy_url` | only if attachment fetch is added; today inbound marshals text only |

  Shipped default is the minimal set the adapter actually uses; CDN/media are added only
  when attachment fetch is. Delivered via a **public** gateway env
  `ALFRED_DISCORD_EGRESS_ALLOWLIST` (gateway-reads-env-never-`Settings`, ADR-0036),
  mirroring `ALFRED_TOOL_EGRESS_ALLOWLIST`/`resolve_*`.

### 4.3 AF_UNIX listener lifecycle — new module `src/alfred/gateway/adapter_egress_listener.py`

- **What (extracted into its own coverable module, NOT buried in `_commands.py`):**
  create + **eagerly bind** the Discord AF_UNIX socket via
  `_local_socket.bind_owner_only_unix_socket` (0700 dir, 0600 socket, pathname not
  abstract) **before** the gateway TaskGroup is entered, then hand the pre-bound socket
  to the `EgressForwardProxy` AF_UNIX instance whose `serve()` runs as a fail-closed
  sibling task. `_commands.py` calls this module (one line), keeping its own coverage
  untouched and letting the new boundary reach **per-file 100% line+branch**.
- **Socket path:** under the existing `alfred_run` mount / trust chain (align with the
  established run-dir, not a bespoke `/run/alfred/egress/...`), in a dedicated dir holding
  only that socket. One shared **path constant** is referenced by the gateway bind, the
  bwrap bind target, and the shim's `open_unix_connection` (§4.5) — never three literals.
- **Fail-closed + distinctly typed:** a bind failure maps to a **new**
  `EgressAdapterProxyUnavailableError(IOPlaneUnavailableError)` with its **own exit code**
  (proxy=7, relay=8 precedent → adapter-proxy=9) and a distinct `t()` key — so the
  operator sees "Discord egress listener failed", not the provider-proxy outage. (Like
  the provider proxy, this fail-closed sibling crash-loops the gateway under
  `restart: unless-stopped`; the distinct error/exit prevents mislabelling.)
- **Depends on:** `_local_socket`; the proxy (§4.1); the allowlist (§4.2).

### 4.4 Bwrap policy migration — `config/sandbox/discord-adapter.linux.bwrap.policy`

- **What:** `unshare += ["net"]`; bind the socket dir (**`ro_binds` preferred**, `rw_binds`
  fallback per §3 #6) using the shared path constant; rewrite **both** egress comment
  blocks — the "DELIBERATELY DO NOT unshare net" note (lines ~76-78) and the "EGRESS IS
  CURRENTLY UNRESTRICTED — #230" header (lines ~92-115) — to the enforced posture; **do
  not** touch the unrelated `#230` `/usr`-prefix-tightening reference (lines ~46-48).
  Keep `ro_binds` `/etc/ssl/certs`, `keep_fds=[3]`, the tmpfs, and the
  pid/uts/cgroup/ipc unshares.
- **Empirical check (in the plan):** confirm `connect()` to the `--ro-bind` socket in a
  `debian:bookworm` bwrap repro; only switch to `--bind` if `connect()` fails on
  `MNT_READONLY`.
- **Depends on:** nothing new in `sandbox_policy.py` (the schema already expresses it).

### 4.5 In-child TCP→unix shim + shared splice helper — `src/alfred/egress/`

- **What:** a shared splice helper (extract the proxy's `_pipe` byte-splice into e.g.
  `src/alfred/egress/byte_splice.py`; `egress_proxy._pipe` refactors to call it,
  behaviour-neutral) and the shim module `src/alfred/egress/adapter_proxy_shim.py`: an
  asyncio task that `start_server`s on `127.0.0.1:PORT` and splices each accepted
  connection to `open_unix_connection(<shared path constant>)`. No parsing, no allowlist,
  no DNS, no `0.0.0.0`, no fallback. Both files are under `src/alfred/` → coverage-gated.
- **Lifecycle (process scope):** started in `plugins/alfred_discord/server.serve()`
  (after stderr-json logging, **before** `_serve_stdin_stdout`), **awaited (listening)**
  before `discord.py`'s first egress (the synchronous `login()` `/users/@me` REST). NOT
  in `DiscordLifecycle.start` (that carries a latent EADDRINUSE on a stop→start cycle).
  The shim port comes from one shared **port constant** also used to build the bot's
  `proxy=` URL (a port skew would silently ECONNREFUSE `login()`).
- **Supervised termination (hard rule #7):** the shim runs under the adapter's crash
  discipline so its death is a **terminal, audited** adapter exit — never a silent
  ECONNREFUSED→`discord.py`-reconnect spin. This mechanism + its guard test are mandated
  here (not deferred).
- **Depends on:** loopback up in the empty netns (bwrap brings `lo` up under
  `--unshare-net`; the `RTM_NEWADDR` skip-guard handles unprivileged CI runners).

### 4.6 `proxy=` threading — `plugins/alfred_discord/discord_gateway.py` + `server.py`

- **What:** `AlfredDiscordBot.__init__(*, proxy: str | None = None, ...)` →
  `super().__init__(command_prefix="!", intents=_least_privilege_intents(),
  proxy=proxy)`. `_build_server` reads the proxy URL (`http://127.0.0.1:PORT` from the
  shared port constant) and passes it. `login()`/`connect()` need no change.

---

## 5. Data flow (one Discord CONNECT, end to end)

```
discord.py (in the --unshare-net child)
  Client(proxy=http://127.0.0.1:PORT)
  -> aiohttp issues:  CONNECT gateway-us-east1-b.discord.gg:443 HTTP/1.1   (to 127.0.0.1:PORT)
        |
        v  child loopback (lo up in the empty netns)
  [in-child shim: src/alfred/egress/adapter_proxy_shim.py]
        accept 127.0.0.1:PORT  ->  open_unix_connection(<shared path>)   (byte-splice, no parsing)
        |
  ======= --unshare-net kernel boundary; only this AF_UNIX pathname socket crosses =======
        |
        v  gateway netns
  EgressForwardProxy (AF_UNIX instance, Discord allowlist, per-entry matcher)
     _read_connect_target -> _authorize (suffix-match *.discord.gg, refuse literal-IP)
     -> gateway-side DNS -> reject non-global resolved IP -> 200 Connection Established
     -> opaque byte splice to the resolved upstream on alfred_external
        |
        v
  Discord (TLS terminates in the child end-to-end; proxy is payload-blind)
```

A compromised adapter that ignores the shim and talks straight to the unix socket
reaches the **same** gateway enforcement; any *other* destination has **no route**
(empty netns). Containment holds regardless of the shim's integrity — the shim is not a
security control.

---

## 6. Security model

- **Enforcement-of-record:** the empty netns (`--unshare-net`). A direct
  `socket.create_connection(('attacker.example', 443))` fails at the kernel: no route,
  no interface.
- **Defense-in-depth:** the gateway proxy's Discord allowlist + the full SSRF chain
  (literal-IP refusal, gateway-side DNS, reject-non-globally-routable-resolved-IP).
- **Cred-concentration (Spec B §8):** preserved and narrowed. The child still decrypts
  exactly one credential (its bot token, over fd-3); post-G7-4 it reaches only Discord,
  so the blast radius drops from "any host" to "allowlisted Discord + the cotenant
  residual".
- **Honest residuals (recorded, NOT claimed caught):**
  - SNI-spoof-to-cotenant (allowlisted CONNECT authority, different inner SNI) — TLS-
    passthrough is SNI-blind; ECH defeats any SNI-peek.
  - CDN-cotenant (allowlisted host shares a Cloudflare edge with attacker infra).
  - T3 exfil **through Discord itself** — the adapter legitimately reaches Discord, so it
    can post relayed T3 to an attacker-owned server/DM. That is the comms
    `OutboundDlp`/canary path's job, **not** the egress proxy's.
  - **Detection blind-spot:** kernel-blocked direct-egress attempts produce **no gateway
    audit row** (the kernel drops the packet before it reaches the gateway), so a
    compromised adapter probing for egress is invisible to the egress audit. Record this
    honestly; host-level netns/seccomp telemetry is the future detection path, not G7-4.
  - The gateway still **serially transits** each credential's plaintext at spawn over
    fd-3 (ADR-0036 serial-harvest residual; the gateway keeps egress). G7-4 does not
    close this; ADR-0043 cross-references ADR-0040's honest-residual (iii) and does not
    claim closure.

---

## 7. Error handling / fail-closed posture

| Condition | Behaviour |
| --- | --- |
| Gateway AF_UNIX bind fails | `EgressAdapterProxyUnavailableError` (exit 9, distinct `t()` key) → gateway crash-loops — never mislabelled as the provider-proxy outage |
| `lo` can't come up in the empty netns | bwrap exits non-zero before the child runs → `GatewayAdapterSpawnError` → supervisor restart/breaker. `RTM_NEWADDR` skip-guard for restricted CI runners |
| Socket not bind-mounted | shim `open_unix_connection` raises → adapter can't reach the proxy → fail-closed, loud |
| Shim task dies | terminal + audited adapter exit under the crash discipline (§4.5) — never a silent `discord.py` reconnect spin |
| Non-allowlisted / literal-IP / rebind / suffix near-miss | proxy `_deny` with the closed-vocab reason + audit; tunnel refused |

There is no fallback path: the shim has a fixed loopback accept, a fixed unix path, no
DNS, no `0.0.0.0`. In an empty netns there is nothing to fall back to.

---

## 8. Testing / proof bar

The established Spec C pattern — **no live Discord bot**:

- **Unit (per-file 100% line+branch, two-gates, both ci.yml jobs):** the proxy bind
  selector + injected matcher (`egress_proxy.py`); the per-entry matcher + Discord
  allowlist (`allowlist.py`); the shared splice helper (`byte_splice.py`); the shim
  (`adapter_proxy_shim.py`); the AF_UNIX listener lifecycle
  (`adapter_egress_listener.py`); the `proxy=` threading. **All new boundary files live
  under `src/alfred/`** so the existing `[tool.coverage.run] source=["src/alfred"]` gate
  actually traces them (the shim must NOT live in `plugins/alfred_discord/`, which is
  uncovered).
- **Suffix-matcher near-miss DENYs (security-critical):** named adversarial entries —
  `evildiscord.gg`, `discord.gg.evil.com`, `gateway.discord.gg.attacker.com`, an
  allowlisted suffix on a non-443 port, a trailing-dot host — each asserted DENIED. A
  *generic* "non-allowlisted host" deny is insufficient (it passes against a regressed
  bare `endswith`).
- **Synthetic/loopback integration:** a real `EgressForwardProxy` AF_UNIX instance + a
  real shim + real `discord.py` `Client(proxy=...)` against a fake upstream (reusing the
  `egress_doubles`/`fake_external_world` helpers): full CONNECT path, payload-blindness,
  refusal, and a **regional `resume_gateway_url`** (e.g. `gateway-us-east1-b.discord.gg`)
  so the suffix path is exercised (a smoke test that only sees `gateway.discord.gg` masks
  the regional failure). Plus a shim-listening-**before**-first-`login()` ordering
  assertion (the production wiring orders it, not just "works when up").
- **Docker-gated kernel proof — `integration-privileged` lane (NOT plain Integration):**
  clone `test_quarantined_llm_policy_kernel_enforced.py`; run as euid-0 (apparmor
  relaxed) so the netns is configurable and the `RTM_NEWADDR` skip cannot fire; assert
  (a) direct external connect **blocked**, (b) `getaddrinfo` external **fails**, (c) an
  allowlisted host via the bridge **succeeds**, (d) a non-allowlisted host via the bridge
  **denied**. Pin with a **precondition assertion + per-test not-skipped guard** in the
  privileged lane (the plain-lane `RTM_NEWADDR` skip and the `#245` not-skipped guard have
  *opposite* semantics — pick the privileged lane explicitly). Backed by the non-root
  structural assertion `"net" in discord-policy.unshare` (so the gate is not paper-only).
  Local runs: `DOCKER_HOST=unix:///…/docker.sock` is a developer note, **not** committed
  to CI.
- **Adversarial:** the **new** Discord `sbx-2026-0NN` enforced-containment entry (mint a
  fresh id; do **not** touch `sbx-2026-005`); the §6 residuals tracked as corpus rows
  (CAUGHT vs honest-RESIDUAL split). Touching `src/alfred/security/` and the egress/sandbox
  boundary makes the **full adversarial suite release-blocking**.
- **Migrate-don't-drop:** `test_discord_adapter_sandbox_policy.py` — *flip* its
  `#230`-deferral assertions to the enforced posture (don't delete them).
- **Compose-invariants:** `ALFRED_DISCORD_EGRESS_ALLOWLIST` on the gateway, **absent** on
  the core; no new host-published port/socket; the socket dir is container-internal.
- **happy/error/refusal trio** for each new unit.

---

## 9. Cross-platform surface

Linux/bwrap is the **enforced** plane. The macOS `.sb` (Seatbelt) and Windows stub are
**dev stubs with a documented gap** — the launcher already refuses `kind:full` on macOS
(`macos_full_not_yet_shipped`), and neither platform has an empty-netns/unix-bridge
primitive. G7-4 tightens the (inert) macOS `.sb` network allow toward the Discord remotes
and documents the gap; there is no runtime path to harden there.

---

## 10. ADR + docs plan

- **New ADR-0043** — "Discord-adapter egress via the gateway L7 CONNECT proxy (the
  empty-netns AF_UNIX bridge)". Records: the bind-mounted AF_UNIX CONNECT listener as a
  second proxy *instance*; per-caller allowlist via listener reachability (and **why
  `SO_PEERCRED` was dropped** — it authenticates nothing at the shared gateway uid); the
  per-entry matcher; the non-enforcing in-child shim (fd-3-channel analog); the
  decision-10 reconciliation; the policy migration; the honest residuals (incl. the
  kernel-blocked-egress audit blind-spot). Follows the ADR-0042 (G7-3) precedent.
- **Amend ADR-0016** (Discord adapter egress; already factually amended in G7-1a) with a
  G7-4 block pointing at ADR-0043 and closing the `#230`/G7-4 thread; flip its status from
  "Proposed" if now accurate. **Touch ADR-0015's** egress-deferral text (now stale once
  `#230` is fully closed).
- **Cross-reference ADR-0036** (gateway privilege) — an in-model duty, no new capability.
- **Deep-doc updates (English-only, NON-human-gated → G7-4 deliverables, same PR):**
  `docs/subsystems/comms.md` (~L341-372, "Sandbox posture and egress" — asserts the policy
  does NOT `--unshare-net`; goes false on merge); `docs/subsystems/security.md` (the
  egress-planes prose — the adapter is now a third egress consumer);
  `config/sandbox/README.md` (the Discord egress note). The plan must size these.
- **Human-gated → G7-5 (do NOT edit here):** CLAUDE.md HARD rule #9's "adapter-egress G7-4"
  status line; PRD §5/§7.1; **ADR-0040** (reserved comprehensive egress ADR).
- **i18n:** the new operator-facing strings (`EgressAdapterProxyUnavailableError` /
  shim-failure messages) need `t()` keys + catalog entries (the plan adds them; run the
  pybabel extract→update→compile flow).
- **Spec erratum note** (in the Spec C design doc, mirror the G7-1 §3 TCP-proxy
  reconciliation note): factual reconciliation of decision 10 — `Client(proxy=...)`
  preserved on the enforcement axis; the empty-netns constraint forces a thin in-child
  transport bridge; this re-introduces nothing decision 10 retired (it enforces nothing).
  Correct §3's "one L7 CONNECT *listener*" to "one *implementation*, per-caller instances".
  Drafting the factual note is in-remit; authoritative PRD/ADR-0040 prose is human-gated.

---

## 11. Open items for the plan (genuinely deferrable)

- The `--ro-bind`-vs-`--bind` socket `connect()` empirical result (debian:bookworm repro)
  — decides §4.4's bind mode.
- Whether to enumerate CDN/media hosts now or gate them behind an attachment-fetch
  capability (today: text-only inbound → omit until needed, logged).
- The exact next-free `sbx-2026-0NN` id (mechanical; the plan reads the corpus).

(Resolved by this revision — no longer open: the suffix-match shape = per-entry match-mode;
the shim placement = `server.serve()` process scope; the shared path + port constants; the
bind lifecycle = pre-bind + `serve(sock=)`; SO_PEERCRED dropped; the corpus = a new id.)

---

## 12. Plan-review revisions (2026-06-30)

Folded from an 8-lens `/review-plan` pass (architect, reviewer, test, security, comms,
devops, provider, docs — 0 Critical, 9 High, 29 Medium, 21 Low). Highlights:

- **Suffix-match → per-entry match-mode** (only `*.discord.gg` is suffix; exact default),
  injected as a predicate into the single shared `_authorize`; mypy type resolved; named
  near-miss DENY tests mandated `[arch-001, rev-001, prov-001, sec-001/002]`.
- **Boundary code relocated under `src/alfred/`** (shim + listener) and **extracted into
  own modules** so the per-file 100% gate has real data `[test-001/002, ops-002]`.
- **Kernel proof pinned to `integration-privileged`** with a precondition + not-skipped
  guard (reconciling the opposite skip semantics) `[test-003, ops-003]`.
- **New Discord corpus id** instead of flipping `sbx-2026-005` (the quarantine marker)
  `[test-004]` — maintainer-chosen.
- **Bind lifecycle**: pre-bind + `serve(sock=)` (no double-bind race) `[prov-003, ops-001]`.
- **Distinct typed error + exit 9** for the adapter-proxy bind fault `[prov-002, ops-004]`.
- **Shim-death supervised termination + test** mandated, not deferred `[rev-003, comms-002,
  sec-005]`.
- **SO_PEERCRED dropped** (authenticates nothing at the shared gateway uid) `[arch-003,
  rev-002, ops-006]` — maintainer-chosen.
- **Shared path + port constants** `[rev-005, comms-003]`; **`ro-bind` preferred**
  `[sec-003, ops-008]`; **deep-doc enumeration** as G7-4 deliverables `[docs-001, arch-002]`;
  **kernel-blocked-egress audit blind-spot** recorded `[sec-006]`.
