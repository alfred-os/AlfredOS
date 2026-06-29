# G7-4 — Discord-adapter egress hardening via the gateway L7 CONNECT proxy

- **Status:** Design (approved to plan)
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
   open `#230` gap; `sbx-2026-005` is its adversarial-corpus marker.

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
**mechanism** (policy migration + the proxy/allowlist/shim + corpus flip + test
migration), proven by a synthetic/loopback driver and a docker-gated kernel egress
proof. It does **not** stand up a live Discord bot.

**Out of scope:** G7-5 (PRD §5/§7.1 + ADR-0040 + the full adversarial corpus + ops
dashboards/alerts + the operator egress-state CLI); the encrypted secret vault (#330);
the gateway-side serial-credential-transit residual (ADR-0036; survives G7-4 — see §7).

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

**The reconciliation (this design).** The gateway proxy gains a **bind-mounted AF_UNIX
CONNECT listener**; a **thin in-child TCP→unix byte-splice shim** lets `discord.py`'s
`Client(proxy="http://127.0.0.1:PORT")` work unmodified. The empty netns is the
kernel enforcement-of-record; the AF_UNIX socket is the single hole; the proxy's
Discord allowlist is the userspace defense-in-depth. This is the same shape as the
existing fd-3 broker channel — a sanctioned, bind-mounted, cross-sandbox-boundary
primitive.

This was confirmed by a four-lens specialist panel (security, devops, comms,
architect), unanimous on the mechanism below.

### Why not the alternatives

- **A — shared netns + `Client(proxy=...)` routing only.** No `--unshare-net`, no
  shim. Routes the happy path, but the child still shares the gateway netns, so a
  compromised adapter opens a raw socket to any host — *exactly* the sbx-2026-005
  threat. No kernel boundary; does not close `#230`. **Rejected** (it is the status quo
  gap, relabeled).
- **C — empty netns + SCM_RIGHTS fd-broker** (the spec's reserved-for-2c model).
  `discord.py`/`aiohttp` expose no per-connection fd-request hook; realizing it means
  forking `aiohttp`'s connection pool — the "transport surgery" decision 10 retired.
  **Rejected** (infeasible for a third-party library; reserved for the in-house 2c
  child).
- **pasta/slirp4netns as transport (not enforcer).** A fair reframing — let the proxy
  do the allowlisting and use pasta/slirp only to carry bytes from the empty netns to
  the proxy. Rejected on three grounds: (1) **category error** — slirp4netns/pasta are
  not network daemons you connect to; they take a target PID/netns and *inject* a
  userspace IP stack into it via `setns`, so a separate container (its own netns) has
  no handle to a bwrap child's empty netns inside the gateway container. (2) **More
  network, not less** — they hand the netns a full userspace stack (NAT to the host =
  broad egress by default) that must then be firewalled back down with IP/port rules,
  which can't pin Discord's rotating IPs, so the L7 proxy is *still* required on top.
  (3) **Strictly larger surface** — a full TCP/IP stack the compromised adapter can
  probe, vs an empty netns with one unix socket; plus the `setns`/CAP_NET_ADMIN
  plumbing and the tooling decision 10 retired. The AF_UNIX bridge gives the identical
  "reach only the proxy" property with one socket and ~30 lines.
- **`socat` as the shim binary.** `socat TCP-LISTEN:…,fork UNIX-CONNECT:…` does exactly
  the splice, but embedding a powerful multi-address binary in the adversary-facing
  sandbox is itself the "new forwarder tooling + new bwrap bind" decision 10 retired,
  and gives a compromised parser a far larger capability than a single-purpose
  in-process splice. **Rejected** in favour of the stdlib splice (reusing
  `egress_proxy._pipe`).
- **`aiohttp.UnixConnector` / a custom connector** to dial the proxy over the unix
  socket directly (no shim). `UnixConnector` ignores `req.proxy` and emits no CONNECT
  line — it would send requests *directly* over the unix socket with no tunnel,
  silently defeating the gateway's CONNECT enforcement. A custom `TCPConnector`
  subclass that overrides the proxy-dial step binds to `aiohttp` private internals
  (version-fragile — the surgery decision 10 avoids). **Rejected**; the dumb shim is
  strictly safer and version-stable.

---

## 3. Decision

Adopt **Option B**. Concretely:

1. **One `EgressForwardProxy` class, two instances.** Add a mutually-exclusive
   AF_UNIX-bind option to the existing proxy (`start_unix_server` instead of
   `start_server`); the security-critical CONNECT splice + SSRF chain
   (`_serve_connection`/`_read_connect_target`/`_authorize`/`_tunnel`) is **reused
   verbatim, never copy-pasted**. The gateway runs **two** instances:
   - TCP listener on `alfred_internal` + the **provider** allowlist (existing,
     unchanged);
   - AF_UNIX listener (a bind-mounted 0600 pathname socket) + the **Discord**
     allowlist (new).
2. **Per-caller allowlist = listener reachability**, not invented caller-auth. The TCP
   listener is reachable only by the core (post-`internal:true`); the AF_UNIX listener
   is bind-mounted into exactly one child. The *listener* is the caller-discriminator,
   so the two instances carry **separate** allowlist frozensets — that separation is
   the per-caller control. A cheap `SO_PEERCRED` same-uid check on the unix listener is
   added as defense-in-depth (caller-auth the TCP path structurally cannot have).
3. **Suffix/wildcard matching for the Discord allowlist** (scoped to the Discord
   listener only; the provider listener keeps exact-match). `discord.py` connects to a
   **dynamic** `resume_gateway_url` (a regional `*.discord.gg` subdomain returned on
   every `READY`) that is not knowable up front — an exact `(host, port)` allowlist
   would deny the live RESUME and invalidate the session. The Discord allowlist matches
   a small set of **suffixes**.
4. **A dumb in-child TCP→unix byte-splice shim.** ~30 lines of stdlib asyncio in the
   adapter wheel: accept on `127.0.0.1:PORT`, splice each connection to the
   bind-mounted unix socket (reuse the `egress_proxy._pipe` pattern). **Zero** CONNECT
   parsing, **zero** allowlisting — it is transport glue, not a policy plane. All
   enforcement stays at the gateway proxy (the single policy surface).
5. **`discord.py` `proxy=` threading.** One construction site:
   `AlfredDiscordBot.__init__` forwards a `proxy: str | None` to
   `super().__init__(..., proxy=proxy)`. Verified that `discord.py` 2.7.1 routes its
   *entire used surface* — REST, the gateway WSS, RESUME/reconnect, CDN, rate-limit
   retries — through that one knob via `aiohttp` HTTP-CONNECT (payload-blind; no
   client-side DNS for Discord hosts). The only bypass paths (webhooks, voice) are
   unused; a guard test forbids regressing that.
6. **Bwrap policy migration.** Add `"net"` to `unshare` and an `rw_binds` entry for the
   socket directory in `discord-adapter.linux.bwrap.policy`; keep the `/etc/ssl/certs`
   ro-bind (TLS verification still happens end-to-end in the child) and `keep_fds=[3]`
   (the bot-token broker channel). No `SandboxPolicy` schema change — `rw_binds` →
   `--bind` already exists.
7. **Corpus + tests.** Flip `sbx-2026-005` for the Discord policy to enforced
   containment (assert `"net" in discord-policy.unshare` + proxy-only egress); add the
   §6 corpus entries; **migrate, don't drop** `test_discord_adapter_sandbox_policy.py`.

---

## 4. Components

Each unit, its interface, and what it depends on.

### 4.1 `EgressForwardProxy` AF_UNIX bind option — `src/alfred/gateway/egress_proxy.py`

- **What:** add a constructor selector so `serve()` binds via `start_unix_server(path)`
  **or** `start_server(host, port)` (mutually exclusive). `_handle_client` and the whole
  enforcement chain are unchanged.
- **Interface:** `EgressForwardProxy(*, allowlist, audit, resolve, open_upstream,
  unix_path=None, bind_host=None, port=None)` — exactly one bind mode supplied
  (validated; a both/neither is a loud construction error).
- **Depends on:** the existing SSRF chain; the new suffix matcher (4.2); `_local_socket`
  for the 0600/0700 bound socket (4.3).
- **Enforcement parity (free):** literal-IP refusal, default-deny allowlist, gateway-
  side DNS, reject-non-globally-routable-resolved-IP (DNS-rebind TOCTOU), bounded
  handshake, payload-blind splice, per-CONNECT audit — all inherited via the shared
  `_handle_client`.

### 4.2 Discord allowlist + suffix matcher — `src/alfred/egress/allowlist.py`

- **What:** a new `discord_egress_allowlist()` returning the Discord destination set as
  **suffix rules**, distinct from the exact-tuple `provider_egress_allowlist`. Fix the
  `provider_egress_allowlist` docstring drift ("G7-4 adds the Discord hosts" — it must
  **not** merge Discord into the provider set).
- **Matcher:** the proxy `_authorize` gains a per-instance match strategy: providers
  keep exact `(host, port) in allowlist`; the Discord instance matches host **suffix**
  (`host == base or host.endswith("." + base)`) for the suffix set, port-checked. The
  suffix set is closed and small.
- **Discord destination set (verified against `discord.py` 2.7.1):**

  | Destination | Source | Notes |
  | --- | --- | --- |
  | `discord.com:443` | `Route.BASE` REST | login, sends, fetches |
  | `*.discord.gg:443` | `DEFAULT_GATEWAY` + dynamic `resume_gateway_url` | WSS connect + RESUME (dynamic regional subdomain) |
  | `cdn.discordapp.com:443` | `Asset.BASE` | only if asset/attachment fetch occurs |
  | `media.discordapp.net:443` | attachment `proxy_url` | only if attachment fetch is added; today inbound marshals text only |

  The shipped default is the minimal set the adapter actually uses; CDN/media are added
  only when attachment fetch is. Delivered via a **public** gateway env
  `ALFRED_DISCORD_EGRESS_ALLOWLIST` (gateway-reads-env-never-`Settings`, ADR-0036),
  mirroring `ALFRED_TOOL_EGRESS_ALLOWLIST`/`resolve_*`.

### 4.3 AF_UNIX listener lifecycle — `src/alfred/cli/gateway/_commands.py`

- **What:** create + **eagerly bind** the Discord AF_UNIX listener **before** entering
  the gateway TaskGroup (the supervisor's spawn is a sibling task with no ordering
  guarantee; bwrap `--bind` of a missing socket path fails the spawn). Serve it in a
  fail-closed sibling task, mirroring the existing `EgressForwardProxy`/relay mounts.
- **Socket:** reuse `_local_socket.bind_owner_only_unix_socket` — `0700` dir, `0600`
  socket, owned by the gateway uid (the kind:full child runs at the gateway uid; no
  `--unshare-user`), under a dedicated per-adapter dir (e.g.
  `/run/alfred/egress/discord/`) holding only that socket. Pathname socket (never
  abstract).
- **Fail-closed:** a bind failure maps to `IOPlaneUnavailableError` (gateway
  crash-loops under `restart: unless-stopped`) — never "no listener but child spawned".
- **Depends on:** `_local_socket`; the proxy (4.1).

### 4.4 Bwrap policy migration — `config/sandbox/discord-adapter.linux.bwrap.policy`

- **What:** `unshare += ["net"]`; `rw_binds += [["/run/alfred/egress/discord", "..."]]`
  (a dedicated dir, so a write-mode bind exposes only the socket); rewrite the
  "EGRESS IS CURRENTLY UNRESTRICTED — #230" header (lines ~92-115) to the enforced
  posture; keep `ro_binds` `/etc/ssl/certs`, `keep_fds=[3]`, the tmpfs, and the
  pid/uts/cgroup/ipc unshares.
- **Empirical check (in the plan):** confirm `connect()` to a `--ro-bind`-vs-`--bind`
  socket in a `debian:bookworm` bwrap repro (a socket inode is likely exempt from
  `MNT_READONLY`, but use `rw_binds`/`--bind` as the unambiguous default and verify).
- **Depends on:** nothing new in `sandbox_policy.py` (the schema already expresses it).

### 4.5 In-child TCP→unix shim — `plugins/alfred_discord/` (new small module + wiring)

- **What:** an asyncio task that `start_server`s on `127.0.0.1:PORT` and splices each
  accepted connection to `open_unix_connection(<bind-mounted path>)` bidirectionally.
  No parsing, no allowlist, no DNS, no `0.0.0.0`, no fallback.
- **Lifecycle:** **awaited (listening) before** `discord.py`'s first egress (the
  synchronous `login()` `/users/@me` REST inside `lifecycle.start → gateway.connect →
  bot.login`). Started in `server.serve()` (after stderr-json logging, before
  `_serve_stdin_stdout`) **or** in `DiscordLifecycle.start` immediately before
  `gateway.connect`. Run under the adapter's crash discipline (a shim death is terminal
  and audited, not a silent reconnect spin).
- **Depends on:** loopback up in the empty netns (bwrap brings `lo` up under
  `--unshare-net`; the `RTM_NEWADDR` skip-guard handles unprivileged CI runners).

### 4.6 `proxy=` threading — `plugins/alfred_discord/discord_gateway.py` + `server.py`

- **What:** `AlfredDiscordBot.__init__(*, proxy: str | None = None, ...)` →
  `super().__init__(command_prefix="!", intents=_least_privilege_intents(),
  proxy=proxy)`. `_build_server` reads the proxy URL (env-derived
  `http://127.0.0.1:PORT`) and passes it. `login()`/`connect()` need no change (the
  proxy lives on the `HTTPClient` built at `Client.__init__`).

---

## 5. Data flow (one Discord CONNECT, end to end)

```
discord.py (in the --unshare-net child)
  Client(proxy=http://127.0.0.1:PORT)
  -> aiohttp issues:  CONNECT gateway.discord.gg:443 HTTP/1.1   (to 127.0.0.1:PORT)
        |
        v  child loopback (lo up in the empty netns)
  [in-child shim]  accept 127.0.0.1:PORT  ->  open_unix_connection(/run/.../discord.sock)
        |                                          (byte-splice, no parsing)
  ======= --unshare-net kernel boundary; only this AF_UNIX path crosses =======
        |
        v  gateway netns
  EgressForwardProxy (AF_UNIX instance, Discord allowlist)
     _read_connect_target -> _authorize (suffix match *.discord.gg, refuse literal-IP)
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
  `socket.create_connection(('attacker.example', 443))` — the sbx-2026-005 probe —
  fails at the kernel: no route, no interface.
- **Defense-in-depth:** the gateway proxy's Discord allowlist + the full SSRF chain
  (literal-IP refusal, gateway-side DNS, reject-non-globally-routable-resolved-IP).
- **Cred-concentration (Spec B §8):** preserved and narrowed. The child still decrypts
  exactly one credential (its bot token, over fd-3); post-G7-4 it reaches only Discord,
  so the blast radius of that one credential drops from "any host" to "allowlisted
  Discord + the cotenant residual".
- **Corpus (`sbx-2026-005` Discord half + new entries):**
  - Discord direct-egress from the empty netns → **CAUGHT** (kernel).
  - proxy-bypass attempt from the empty netns → **CAUGHT** (no route).
  - literal-IP CONNECT via the proxy → **CAUGHT** (`LITERAL_IP_TARGET`).
  - non-allowlisted host via the proxy → **CAUGHT** (`DESTINATION_NOT_ALLOWLISTED`).
  - DNS-rebind (allowlisted name → private IP) → **CAUGHT** (`RESOLVED_IP_NOT_GLOBAL`).
  - SNI-spoof-to-cotenant (allowlisted CONNECT authority, different inner SNI) →
    **HONEST RESIDUAL** (TLS-passthrough is SNI-blind; ECH defeats any SNI-peek) —
    recorded, not claimed caught.
  - CDN-cotenant (allowlisted host shares a Cloudflare edge with attacker infra) →
    **HONEST RESIDUAL** — recorded.
- **Residuals that survive G7-4 (do not over-claim):**
  - T3 exfil **through Discord itself** (the adapter legitimately reaches Discord, so it
    can post relayed T3 to an attacker-owned server/DM). That is the comms
    `OutboundDlp`/canary path's job, **not** the egress proxy's.
  - The gateway still **serially transits** each credential's plaintext at spawn over
    fd-3 (ADR-0036 serial-harvest residual; the gateway keeps egress, so a compromised
    gateway can still harvest-and-exfil). G7-4 does not close this; ADR-0043
    cross-references ADR-0040's honest-residual (iii) and does not claim closure.

---

## 7. Error handling / fail-closed posture

| Condition | Behaviour |
| --- | --- |
| Gateway AF_UNIX bind fails | `IOPlaneUnavailableError` → gateway crash-loops (fail-closed; the proxy is the gateway's reason to exist) |
| `lo` can't come up in the empty netns (unprivileged userns) | bwrap exits non-zero before the child runs → `GatewayAdapterSpawnError` → supervisor restart/breaker (no egress, adapter down). `RTM_NEWADDR` skip-guard for restricted CI runners |
| Socket not bind-mounted (policy/gateway error) | shim `open_unix_connection` raises → adapter can't reach the proxy → fail-closed, loud |
| Shim dies | `discord.py` CONNECT gets ECONNREFUSED; the shim death is terminal + audited under the adapter crash discipline (never a silent reconnect storm) |
| Non-allowlisted / literal-IP / rebind destination | proxy `_deny` with the closed-vocab reason + audit; child's tunnel refused |

There is no fallback path anywhere: the shim has a fixed loopback accept, a fixed unix
path, no DNS, no `0.0.0.0`. In an empty netns there is nothing to fall back to — keep
it structurally so.

---

## 8. Testing / proof bar

The established Spec C pattern (G7-1 quarantine flip, G7-2c synthetic relay, G7-3
kernel proof) — **no live Discord bot**:

- **Unit:** the proxy AF_UNIX bind + suffix matcher; the Discord allowlist set; the
  shim splice; the `proxy=` threading; the policy migration (`test_discord_adapter_
  sandbox_policy.py`, migrated). The two new boundary files (the AF_UNIX listener
  wiring + the shim) each get their own **per-file 100% line+branch** two-gates
  coverage step in `ci.yml` (alongside the existing egress gates).
- **Synthetic/loopback integration:** a real `EgressForwardProxy` AF_UNIX instance on
  loopback + a real shim + real `discord.py` `Client(proxy=...)` against a fake upstream
  (reusing the `egress_doubles`/`fake_external_world` helpers): proves the full CONNECT
  path, suffix match (incl. a synthetic `gateway-us-east1-b.discord.gg` resume host),
  payload-blindness, and refusal.
- **Docker-gated kernel proof** in the REQUIRED Integration lane (clone
  `tests/integration/egress/test_core_network_isolation_kernel.py` /
  `test_quarantined_llm_policy_kernel_enforced.py`): spawn the Discord policy (or the
  `discord_probe` via the env-gated `override_map`) with `--unshare-net` + the bound
  socket and assert (a) direct external connect is **blocked**, (b) `getaddrinfo`
  external **fails**, (c) an allowlisted host via the bridge **succeeds**, (d) a
  non-allowlisted host via the bridge is **denied** — with the `RTM_NEWADDR`
  netns-unconfigurable skip-guard and a **#245-style not-skipped CI guard**.
- **Adversarial:** the `sbx-2026-005` Discord flip + the §6 corpus entries. Touching
  `src/alfred/security/` and the egress/sandbox boundary makes the **full adversarial
  suite release-blocking**.
- **Compose-invariants:** `ALFRED_DISCORD_EGRESS_ALLOWLIST` on the gateway, **absent**
  on the core; no new host-published port/socket.
- **Smoke-test trap to avoid:** Discord often returns `gateway.discord.gg` itself as
  `resume_gateway_url`, so an exact-match bug can hide behind green. The synthetic
  driver MUST exercise a regional resume host.

Run docker-driven tests with `DOCKER_HOST=unix:///Users/iandominey/.orbstack/run/docker.sock`.

---

## 9. Cross-platform surface

Linux/bwrap is the **enforced** plane. The macOS `.sb` (Seatbelt) and Windows stub are
**dev stubs with a documented gap** — the launcher already refuses `kind:full` on macOS
(`macos_full_not_yet_shipped`), and neither platform has an empty-netns/unix-bridge
primitive. G7-4 tightens the (inert) macOS `.sb` network allow toward the Discord
remotes and documents the gap; there is no runtime path to harden there. This matches
the existing policy-header/README posture.

---

## 10. ADR plan

- **New ADR-0043** — "Discord-adapter egress via the gateway L7 CONNECT proxy (the
  empty-netns AF_UNIX bridge)". Records: the bind-mounted AF_UNIX CONNECT listener as a
  second proxy *instance*; per-caller allowlist via listener reachability (+ the
  `SO_PEERCRED` check); the non-enforcing in-child shim (fd-3-channel analog); the
  decision-10 reconciliation; the policy migration; the honest residuals. Follows the
  ADR-0042 precedent (G7-3 got its own focused cutover ADR alongside reserved-0040).
- **Amend ADR-0016** (Discord adapter egress; already factually amended in G7-1a) with a
  G7-4 block pointing at ADR-0043 and closing the `#230`/G7-4 thread.
- **Cross-reference ADR-0036** (gateway privilege) — the gateway gains an in-model duty
  (hosting a bind-mounted unix proxy listener) and **no new capability**; the
  serial-transit residual is unchanged. A note, not a re-decision.
- **Do NOT consume ADR-0040** (reserved — the comprehensive G7-5 egress ADR).
- **Spec erratum note** (in the Spec C design doc, mirror the G7-1 §3 TCP-proxy
  reconciliation note): factual reconciliation of decision 10 — `Client(proxy=...)` is
  preserved on the enforcement axis; the empty-netns constraint forces a thin in-child
  transport bridge to a bind-mounted AF_UNIX listener; this re-introduces nothing
  decision 10 retired (it enforces nothing). Correct §3's "one L7 CONNECT *listener*"
  to "one *implementation*, per-caller instances"; soften decision 10's "a config knob,
  not transport surgery" overclaim. Drafting the factual note is in-remit; the
  authoritative PRD §5/§7.1 + ADR-0040 prose stays **human-gated** to G7-5.

---

## 11. Open items for the plan (not blockers)

- The exact `_authorize` suffix-match API shape (per-instance strategy vs a typed
  allowlist that carries match-mode) — decide in the plan; keep the provider exact-match
  untouched.
- The `--ro-bind`-vs-`--bind` socket `connect()` empirical result (debian:bookworm
  repro).
- The precise shim-start site (`server.serve()` vs `DiscordLifecycle.start`) and its
  crash-emitter wiring.
- The fixed shim loopback port (a constant; the relay/proxy-port `resolve_*` precedent).
- Whether to enumerate CDN/media hosts now or gate them behind an attachment-fetch
  capability (today: text-only inbound → omit until needed, logged).
