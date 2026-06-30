# ADR-0043 — Discord-adapter egress via the gateway L7 CONNECT proxy (the empty-netns AF_UNIX bridge)

- **Status**: Accepted (G7-4 merge)
- **Date**: 2026-06-30
- **Slice**: Spec C — G7-4 Discord-adapter egress hardening
  (`docs/superpowers/specs/2026-06-29-g7-4-discord-adapter-egress-l7-proxy-design.md`)
- **Relates to**: [ADR-0016](0016-slice4-discord-tui-comms-mcp-rewrite.md) (Discord adapter
  sandbox posture; G7-4 amends it), [ADR-0015](0015-slice4-containerised-quarantined-llm.md)
  (quarantine-child egress; parallel deferred path), [ADR-0036](0036-gateway-adapter-hosting-inversion.md)
  (gateway privilege; G7-4 is an in-model duty, no new capability), [ADR-0042](0042-connectivity-free-core-cutover.md)
  (G7-3 kernel isolation the Discord child now joins), ADR-0040 (reserved — comprehensive
  Spec-C egress ADR, G7-5), epic [#333](https://github.com/alfred-os/AlfredOS/issues/333),
  issue [#230](https://github.com/alfred-os/AlfredOS/issues/230) (the Discord half closed here;
  the 2c real-LLM child egress remains open under #230/#340)
- **Supersedes**: —

## Context

G7-3 (ADR-0042) made the core connectivity-free: `alfred_internal` is `internal: true`,
`alfred-core` is off `alfred_external`, and `EgressClient` has no direct-egress fallback.
The **gateway is the sole external egress plane**.

Two gateway-hosted bwrap children still needed egress control at G7-3's merge:

1. The **quarantine child** — closed in G7-1a: the shipped deterministic-echo loop needs
   no network; its Linux policy now `--unshare-net`s it into an empty namespace.
2. The **Discord adapter** — the open gap. Its bwrap policy
   (`config/sandbox/discord-adapter.linux.bwrap.policy`) deliberately omitted
   `--unshare-net`, leaving a compromised adapter free to open raw sockets to any host
   and exfiltrate T3 content and the bot token. This was the open `#230` egress gap.

**The topology constraint.** The Discord adapter is a bwrap child *inside* the gateway
container, sharing the gateway's network namespace unless the policy adds `--unshare-net`.
`--unshare-net` gives the child an **empty network namespace** (only loopback). But
`discord.py`'s `Client(proxy=...)` (the mechanism Spec C decision 10 locked) needs a TCP
URL — and the gateway proxy's TCP listener lives in the gateway's netns, unreachable from
an empty child netns. The only primitive that crosses an `--unshare-net` boundary without
veth/slirp is an **AF_UNIX pathname socket bind-mounted into the child's mount namespace**.
Abstract AF_UNIX sockets are net-namespace-scoped and do **not** cross.

**Scope: mechanism-hardening, not go-live.** The Discord adapter has no production
privileged turn yet (`build_orchestrator` is not in the daemon `start` graph — G7-3
"seam vs boot"; #338/#339/#235 open). G7-4 hardens the mechanism and is proven by
synthetic/loopback driver + a docker-gated kernel egress proof; it does not stand up a
live Discord bot.

## Decision

### 1. One `EgressForwardProxy` class, two instances

`serve()` accepts **either** a pre-bound listening socket (`sock=`, for the AF_UNIX
instance) **or** a TCP `(host, port)` (the existing provider instance). The
security-critical chain (`_serve_connection` / `_read_connect_target` / `_authorize` /
`_tunnel`) is **shared, not copy-pasted**; the only per-instance variations are the
allowlist contents and an injected **per-entry match predicate**. The gateway runs two
instances:

- TCP listener on `alfred_internal` + the **provider** allowlist (existing, unchanged).
- AF_UNIX listener (a bind-mounted 0600 pathname socket) + the **Discord** allowlist (new).

### 2. Per-caller allowlist via listener reachability

The TCP listener is reachable only by the core (post-`internal: true`); the AF_UNIX
listener is bind-mounted into exactly one child. The *listener* is the caller-discriminator,
so the two instances carry **separate** allowlist frozensets — listener reachability is the
per-caller control.

**Why `SO_PEERCRED` was dropped.** A `SO_PEERCRED` check was considered and rejected:
the `kind: full` Discord child runs at the **same gateway uid** (no `--unshare-user`), so a
same-uid peer-credential check would authenticate **nothing** (any process at the gateway
uid passes) while modifying the shared `_handle_client` path and introducing an undefined
new refusal category. Listener reachability (the bind-mount into one child) is the honest,
sufficient, and auditable control.

### 3. Per-entry match predicate (not a per-instance suffix mode)

Each allowlist entry carries a mode: **`exact` is the default**; **`suffix` is used only
for `*.discord.gg`** (the dynamic `resume_gateway_url` regional subdomain). The provider
instance's entries are all `exact` (provably the same as the prior `host in allowlist`
membership check — a pinning test asserts this equivalence). The Discord instance's entries
are `discord.com` (exact) and `*.discord.gg` (suffix). The suffix predicate is anchored:
`host == base or host.endswith("." + base)` — never a bare `endswith` that would match
`evildiscord.gg`. The shared `_authorize` is the single source for literal-IP refusal,
`RESOLVED_IP_NOT_GLOBAL`, and the deny-audit; both instances share it unchanged.

### 4. The AF_UNIX socket is on a gateway-only volume — devops-001

The socket lives on a **new `alfred_discord_egress` volume mounted into `alfred-gateway`
ONLY** — never `alfred-core`, never `alfred_run`. This is the load-bearing constraint:

- `alfred_run` is mounted into **both** `alfred-core` and `alfred-gateway` at the same uid.
- An AF_UNIX pathname socket is **filesystem-namespace-scoped** — not gated by
  `internal: true` (a net-ns control).
- A socket on `alfred_run` would let the connectivity-free core `connect()` the Discord
  egress proxy and reach the Discord allowlist — **reopening G7-3 / HARD rule #9**.

One shared **path constant** spans the gateway bind / bwrap target / in-child shim.

### 5. AF_UNIX listener lifecycle — `src/alfred/gateway/adapter_egress_listener.py`

The socket is **pre-bound** (0700 dir, 0600 socket, pathname not abstract, unlink-before-bind
so a stale socket from a prior crash cannot `EADDRINUSE` a restart) before the gateway
`TaskGroup` is entered, then handed to the `EgressForwardProxy` AF_UNIX instance whose
`serve(sock=)` runs as a fail-closed sibling task. Extracted into its own module so the
per-file 100% line+branch gate has real coverage data; `_commands.py` calls it in one line.

A bind failure raises `EgressAdapterProxyUnavailableError(IOPlaneUnavailableError)` with
**exit code 9** (proxy=7, relay=8 precedent) and its own distinct `t()` key
(`egress.adapter_proxy_unavailable`). Because it **subclasses** `IOPlaneUnavailableError`,
its `except` clause in `_commands.py` **must** precede `except IOPlaneUnavailableError`
or it falls through to exit 7 and the provider error line. A pinning test asserts exit 9
and the distinct key. The fail-closed coupling is accepted and stated honestly: a
Discord-listener bind fault crash-loops the **whole gateway**, dropping live provider
egress too. That is the intended loud fail-closed signal.

### 6. In-child TCP→unix byte-splice shim — `src/alfred/egress/adapter_proxy_shim.py`

A shared splice helper (`src/alfred/egress/byte_splice.py`, extracted from the proxy's
`_pipe`) enables the shim: it accepts on `127.0.0.1:PORT` (loopback inside the empty
netns, which bwrap brings up) and splices each connection to the bind-mounted unix socket
via `open_unix_connection(<shared path>)`. **Zero** CONNECT parsing, **zero** allowlisting,
no DNS, no `0.0.0.0`, no fallback.

The shim is **not a security control**. A compromised adapter that ignores the shim and
talks straight to the unix socket reaches the **same** gateway enforcement. Any *other*
destination has no route (empty netns). Containment holds regardless of the shim's
integrity — the shim is transport glue, the same structural role as the fd-3 broker
channel.

The shim task is bound to the adapter's structured concurrency via a **done-callback /
`TaskGroup` propagation** (the `CrashEmitter` pattern), NOT a bare `asyncio.create_task`.
Its death is a terminal, audited adapter exit — never a silent `discord.py` reconnect spin.

Both files live under `src/alfred/` — coverage-gated and reliably importable inside bwrap.

### 7. `discord.py` `Client(proxy=...)` threading

`AlfredDiscordBot.__init__` forwards a `proxy: str | None` to
`super().__init__(..., proxy=proxy)`. The URL is `http://127.0.0.1:PORT` (scheme pinned
to `http://`). `discord.py` 2.7.1 routes its entire used surface — REST, the gateway
WSS, RESUME/reconnect, rate-limit retries — through that one knob via `aiohttp`
HTTP-CONNECT. Unused bypass paths (webhooks, voice) are not wired; a static-symbol guard
test forbids regressing that.

### 8. Bwrap policy migration

`"net"` is added to `unshare` and the socket directory is bind-mounted via **`rw_binds`
(`--bind`)** in `config/sandbox/discord-adapter.linux.bwrap.policy`. A `--ro-bind` causes
`connect(2)` to fail with `EACCES` — empirically confirmed in the FIX-5 Debian Bookworm
repro. The writable mount is not a cross-uid concern: the `kind: full` Discord child runs
as the same `alfred` uid as the gateway, so the rw mount gives the child no uid-escalation
surface beyond what it already holds. The socket directory is a dedicated gateway-only
volume holding only the egress socket, so mount-writability confers no additional filesystem
reach. `/etc/ssl/certs` ro-bind and `keep_fds=[3]` are preserved (TLS verification still
happens end-to-end in the child; the bot token still arrives over fd-3).

## Consequences

### Security posture

- **Enforcement-of-record:** the empty netns (`--unshare-net`). A direct
  `socket.create_connection(('attacker.example', 443))` fails at the kernel: no route, no
  interface. This closes the Discord half of `#230`.
- **Defense-in-depth:** the gateway proxy's Discord allowlist + the full SSRF chain
  (literal-IP refusal, gateway-side DNS, reject-non-globally-routable-resolved-IP).
- **Cred-concentration narrowed.** The child still decrypts exactly one credential (its bot
  token, over fd-3); post-G7-4 it reaches only Discord, so the blast radius drops from
  "any host" to "allowlisted Discord + the cotenant residual" (see residuals below).

### Honest residuals (recorded, not claimed caught)

- **SNI-spoof-to-cotenant.** An allowlisted CONNECT authority can carry a different inner
  SNI; TLS-passthrough is SNI-blind; ECH defeats any SNI-peek. Accepted residual.
- **CDN-cotenant.** Allowlisted hosts share a Cloudflare edge with attacker infrastructure.
  Accepted residual.
- **T3 exfil through Discord itself.** The adapter legitimately reaches Discord, so it can
  post relayed T3 to an attacker-owned server or DM. That is the comms `OutboundDlp`/canary
  path's job, not the egress proxy's.
- **Detection blind-spot.** Kernel-blocked direct-egress attempts produce **no gateway
  audit row** — the kernel drops the packet before the gateway sees it, so a compromised
  adapter probing for raw egress is invisible to the egress audit. Host-level
  netns/seccomp telemetry is the future detection path; this gap is tracked honestly here.
- **Gateway serial-credential-transit residual.** The gateway still serially transits each
  credential's plaintext at spawn over fd-3 (ADR-0036 serial-harvest residual). G7-4 does
  not close this. The reserved ADR-0040 (human-gated, G7-5) will enumerate the
  gateway-compromise residuals; this ADR does not cite into the unwritten ADR-0040.
- **PRD lag.** The PRD §5/§7.1 prose and ADR-0040 are human-gated to G7-5 and are NOT
  updated by this PR.

### What is unchanged

- `EgressDestination = tuple[str, int]` — the provider allowlist's 2-tuple alias is
  unchanged; no 3-tuple ripple into existing callers or tests.
- The gateway gains **no new capability** (no new `cap_add`, no new AppArmor/seccomp
  profile change) — hosting the bind-mounted AF_UNIX proxy listener is an in-model duty
  within the already-SETUID-privileged gateway (ADR-0036).
- The 2c real-LLM quarantine child's egress deferred to `#230/#340` is **unaffected**.

## Alternatives considered

- **Shared netns + `Client(proxy=...)` routing only (Option A).** No `--unshare-net`, no
  shim. Closes the happy path but leaves the child in the gateway netns — a compromised
  adapter opens a raw socket to any host. Does not close `#230`. Rejected (the status quo
  gap, relabeled).
- **Empty netns + SCM_RIGHTS fd-broker (Option C).** `discord.py`/`aiohttp` expose no
  per-connection fd-request hook; realizing it means forking `aiohttp`'s connection pool
  (the "transport surgery" decision 10 retired). Rejected; reserved for the in-house 2c
  child.
- **pasta/slirp4netns as transport.** Category error (they inject a userspace IP stack via
  `setns`, not a daemon you connect to; no handle to a bwrap child's netns inside the
  gateway container) + more network, not less (full NAT stack, must then be firewalled back
  to Discord-only) + strictly larger surface. Rejected.
- **`socat` as the shim binary.** Multi-address binary in the adversary-facing sandbox —
  "new forwarder tooling + new bwrap bind" decision 10 retired; far larger capability than
  a stdlib splice. Rejected.
- **`aiohttp.UnixConnector` / custom connector.** `UnixConnector` ignores `req.proxy` and
  emits no CONNECT line — silently defeats gateway enforcement. A custom `TCPConnector`
  subclass binds to `aiohttp` private internals (version-fragile). Rejected.
