# #340 PR2a — SCM_RIGHTS fd-broker topology mechanism (core-side) — design

**Status:** **rev.2 — best-judgment THIN-CUT; 7-lens `/review-plan` folded (0 Critical, 3 High
[all one corroborated issue], 14 Medium, 20 Low, 0 disputed, 0 gaps); HOLDING at ratification.**
This doc REVERSES the earlier "precursor infra + stub round-trip" (fat-cut) selection — see §2 for
why, and ratify the thin cut (or redirect to the fat cut) before `writing-plans`. The `/review-plan`
folds (§13) OVERRIDE the rev.1 body where they conflict.
**Date:** 2026-07-10
**Epic:** [#340](https://github.com/alfred-os/AlfredOS/issues/340) — Real-LLM quarantine child (2c).
**Follows:** PR1 (provider-seam reconciliation, MERGED, main `9c347580`) → the fd-broker feasibility
spike (RAN GREEN; verdict **M1** — keep the official Anthropic SDK over the brokered socket).
**Precedes:** PR2b (go-live cutover — carries the **human sign-off**).
**Predependency:** #251 (child-IO swallows child stderr) lands as a STANDALONE PR **before** this
branch — the docker probe test drives a real bwrapped child and needs readable stderr.

> **Spike provenance note.** The feasibility spike's throwaway harness (`spikes/issue-340-fd-broker/`)
> and its findings doc (`…-fd-broker-feasibility-spike-design.md` §11) live on the local
> `340-fd-broker-spike` branch (unpushed, per maintainer choice). This spec is **self-contained** —
> the load-bearing §11 findings are summarised inline where needed.

---

## 1. What this is (and is NOT)

PR2a ships the **core-side half** of the SCM_RIGHTS fd-broker as a **genuinely dormant,
ratchet-free precursor**: the core primitive that opens a TCP socket toward the gateway L7 CONNECT
proxy and hands the connected fd to the empty-netns quarantine child over an inherited AF_UNIX
control fd, plus the spawn-time plumbing to deliver that control fd — **opt-in, defaulted off on the
live path**. A docker-gated integration test proves the two properties only the real sandbox can
show: **C1** (the child cannot open its own socket — empty netns) and **C2** (SCM_RIGHTS carries a
live connected fd across the bwrap boundary).

PR2a does **NOT**: build the child-side httpx/SDK transport, touch the shipped bwrap policy, loosen
the in-core egress ratchet (`_CONSTRUCT_ALLOWLIST`), wire `_build_provider`, swap the extract
branch, or make any real provider call. **All of that is PR2b, behind the sign-off** (§11).

**Why "topology mechanism only, not go-live":** the spike already proved the full
CONNECT+TLS+HTTP+decode round-trip (M1). PR2a's job is to land the **core primitive + spawn
plumbing** in `src/` with real guards, at the smallest blast radius, leaving every child-side egress
capability — the part that actually changes the sandbox's security posture — behind the human
sign-off gate where it is reviewed.

---

## 2. The scope boundary — drawn on the RATCHET fault line (this reverses the earlier cut)

An earlier fork chose "PR2a = behaviour-neutral precursor infra + a docker stub round-trip"
(the **fat cut**: ship the child-side `brokered_egress.py` transport too, proven end-to-end against
a local stub). A 5-lens review panel (architect, security, core, provider, test) found that cut
**drags a security-posture change into the non-sign-off PR for little benefit**:

- **The fat cut is not behaviour-neutral at the ratchet level (architect + test).** The child-side
  transport constructs `httpx.AsyncClient`, which the tree-wide in-core egress guard
  (`tests/unit/egress/test_in_core_http_egress_guard.py`, whole-`src/alfred` scan) flags — forcing a
  `_CONSTRUCT_ALLOWLIST` entry = **loosening the connectivity-free-core egress ratchet**. Under the
  fat cut that loosening lands OUTSIDE the go-live sign-off.
- **It re-proves the spike without de-risking the real new thing (security).** Because `__main__.py`
  is left untouched (echo stays live), the fat cut re-proves "SDK over a passed fd" — which the spike
  already showed — but leaves the genuinely-new **fd0-extract / fd4-socket / fd1-reply** three-channel
  wire choreography to PR2b anyway.
- **It breaks the 100%-`security/*` coverage gate (test).** The `integration-privileged` docker leg
  runs `--cov-fail-under=0` and uploads no coverage, so every docker-only line in a `security/*`
  file is uncovered against the 100% gate — forcing either a broken gate or `# pragma: no cover` on
  the most security-critical lines.
- **The fat cut's "keep `socket` lazy → guard stays enforced" rationale is a non-sequitur
  (security).** The child-egress gate reads only `__main__.py`; a separate `brokered_egress.py` is
  invisible to it *by filename*, not *by enforcement*.

**Decision (best-judgment, ratify): draw the 2a/2b line on the ratchet fault line.** PR2a is
everything that touches **no egress ratchet and no shipped security policy**; PR2b is everything that
does. This is a far more defensible seam than "does runtime behaviour change?".

| Concern | PR2a (this spec — no sign-off) | PR2b (sign-off) |
| --- | --- | --- |
| Core `control_fd_broker` (connect + SCM_RIGHTS) | ✅ ships (raw socket — guard-exempt) | — |
| `spawn_quarantine_child_io` control fd | ✅ **opt-in**, live path passes none | flip to always-on at go-live |
| Raw-socket-egress ratchet (NEW guard) | ✅ ships | — |
| ADR-0050 (topology) | ✅ ships | amended at go-live |
| Docker C1/C2 probe test | ✅ ships (minimal probe child) | full round-trip added |
| Child-side `brokered_egress` httpx transport | ❌ | ✅ |
| `_CONSTRUCT_ALLOWLIST` loosening | ❌ | ✅ (behind sign-off) |
| Shipped bwrap policy edit (CA bind, `keep_fds=[3,4]`) | ❌ **not needed** (see §7) | ✅ |
| `_build_provider` flip / extract-branch swap / refuse-boot | ❌ | ✅ |
| Provider `max_retries=0` / teardown / timeout / cost | ❌ | ✅ |
| HARD #5 provenance re-validation | mechanism-level only (**core wrote zero bytes**) | full (real extractor schema) |

PR2b remains the substantial security PR; the thin cut does not hollow it out.

---

## 3. Verified anchors (current tree, `main` 9c347580)

- **Live child echoes; `_build_provider` returns a sentinel.**
  `src/alfred/security/quarantine_child/__main__.py`: `main()` reads the fd-3 key, `_build_provider`
  returns `_DeterministicProvider()`, `_run_mcp_server`'s extract branch calls `_echo_extracted_frame`
  and never reaches `handle_extract` → `provider_dispatch`. **PR2a leaves `__main__.py` byte-for-byte
  unchanged.**
- **Host spawn seam.** `src/alfred/security/quarantine_child_io.py`:
  `spawn_quarantine_child_io(*, provider_key)` does the fd-3 dup2 dance inside a SYNCHRONOUS,
  zero-`await` `subprocess.Popen` window (`_PROVIDER_KEY_FD = 3`, save/restore of prior fd 3,
  `pass_fds=(3,)`), then `deliver_provider_key_via_fd3`. `_SubprocessChildIO` frames JSON-RPC over the
  child stdio; `aclose` terminates+reaps (the single teardown seam, CR-#255). `_CHILD_MODULE =
  "alfred.security.quarantine_child"` is **hardcoded** in argv (no module override today).
- **fd-3 delivery primitive to mirror.** `src/alfred/supervisor/fd3_key_delivery.py`:
  `deliver_provider_key_via_fd3(*, write_fd, key)` — framed `writev`, refuse-on-partial,
  fd-close+scrub in `finally`; `ProviderKeyDeliveryError(reason=…)` (rooted at `Exception`).
- **Egress config seam.** `src/alfred/egress/client.py` `EgressClient` reads
  `EgressProxyConfig.egress_proxy_url` (`_config_protocols.py:19/34`, `-> str | None`) and fail-closes
  via `IOPlaneUnavailableError` (`egress/errors.py:23`, an `AlfredError`) when it is unset/blank.
- **The four guards** (verified shapes):
  - **G1 import-closure** (`tests/unit/security/test_quarantine_child_import_closure.py`):
    `_FORBIDDEN_ROOTS` = `alfred.{audit,core,memory,orchestrator,security.secrets,
    security.capability_gate,security.dlp}`; measures the `__main__` `sys.modules` delta. Does **NOT**
    cover `socket` or `alfred.providers`.
  - **G2 net-unshare + sanctioned-spawn** (`tests/adversarial/sandbox_escape/
    test_quarantined_llm_not_yet_spawned_while_egress_open.py`): asserts the policy still
    `unshare=[…,"net"]`; `_SANCTIONED_SPAWN_SITE = "security/quarantine_child_io.py"` is the ONLY
    allowlisted live spawn; `#230` doc-anchors required in the policy + `config/sandbox/README.md`.
  - **G3 child-egress-import** (same file): `_EGRESS_CAPABLE_MODULES` INCLUDES `socket`; scans only
    `__main__.py` **module-scope** imports (lazy in-function imports not reported).
  - **G4 in-core httpx/SDK** (`tests/unit/egress/test_in_core_http_egress_guard.py`): whole-`src/alfred`
    scan; forbids `anthropic`/`openai`/`requests`/`aiohttp` imports + `httpx.AsyncClient(...)`
    construction outside `_IMPORT_ALLOWLIST`/`_CONSTRUCT_ALLOWLIST`. **Explicitly ALLOWS `import socket`,
    `socket.socket()`, `socketpair`, `sendmsg`, `SCM_RIGHTS`** ("unix-domain sockets are pervasive
    in-core"). ⇒ the core broker needs no G4 entry; **no existing guard sees `socket.create_connection`
    toward the gateway** — PR2a adds one (§7).
- **CI reality (test lens).** The real-spawn precedent `tests/integration/test_quarantine_child_real_spawn.py`
  runs only in `integration-privileged` (`ci.yml`, `ubuntu-latest` = amd64; `--cov-fail-under=0`, uploads
  no coverage), guarded by a `bwrap+Linux+root+provisioned` `skipif`. There is deliberately **no arm64
  privileged twin** — its first arm64 run caught the truncated-frame bug tracked in **#269** (blocked on
  **#251**). The `security/*` 100% gate is `ci.yml` `--include='src/alfred/security/*'`; `quarantine_child_io.py`
  has an explicit named per-file gate.

---

## 4. Architecture & components (PR2a)

### 4.1 `src/alfred/egress/control_fd_broker.py` — the core-side primitive (NEW)

Lives in **`egress/`** (peer to `EgressClient`), not `supervisor/`: its identity is an
**egress origination toward the gateway proxy** — it `connect()`s the same
`EgressProxyConfig.egress_proxy_url` destination `EgressClient` proxies to, and fails-closed with the
same `IOPlaneUnavailableError` (which lives in `egress/errors.py`). An auditor enumerating "every
core path that opens a connection toward the gateway" finds both in one subsystem. Its docstring must
distinguish it from `EgressClient`: this primitive **passes the socket away and writes ZERO
application bytes over it** (HARD #5), rather than doing I/O over it.

Surface (mirrors `fd3_key_delivery.py`; pure functions, injected config — no global state):

- `make_control_socketpair() -> tuple[socket.socket, socket.socket]` — `socket.socketpair(AF_UNIX,
  SOCK_STREAM)`; the **child end** is `set_inheritable(True)` (non-CLOEXEC so bwrap inherits it; PEP 446
  makes fds CLOEXEC by default); the **parent end** stays non-inheritable (default) so the child gets
  no copy of it.
- `broker_connected_socket(*, parent_end, proxy_config) -> None` — resolves `host:port` by
  `urlsplit`-ing `proxy_config.egress_proxy_url` (mirror `EgressClient`; handle a missing port loudly —
  do NOT re-parse by hand), fail-closed `IOPlaneUnavailableError` if unset/blank (identical to
  `EgressClient.from_settings`), then, **off-loop** (use `run_in_executor(None, …)` — the module's
  existing `_blocking_read_exactly` idiom, kept consistent; SCM_RIGHTS `sendmsg`/`recvmsg` have no
  asyncio ancillary helper):
  1. `sock = socket.create_connection((host, port), timeout=<bounded>)` — a **bounded connect timeout**
     (core-002: an unset proxy raises `IOPlaneUnavailableError`, but a *set-but-unreachable* proxy would
     otherwise wedge the executor thread; a connect-timeout maps to a loud `ControlFdBrokerError`).
     Then **`sock.settimeout(None)`** BEFORE the pass — `create_connection(timeout=)` leaves `O_NONBLOCK`
     set on the returned socket, and that flag rides the shared file description across the SCM_RIGHTS
     pass; restoring blocking mode honours the child-side blocking-recv contract (the "never leave
     `O_NONBLOCK` set on the passed fd" invariant).
  2. `parent_end.sendmsg([frame], [(SOL_SOCKET, SCM_RIGHTS, array('i', [sock.fileno()]))])` — the data
     `frame` carries **≥1 byte** always (an ancillary-only `sendmsg` over `SOCK_STREAM` can drop the fd)
     and is **length-checked** (`sent == len(frame)` else refuse — the partial-data-write hole the spike
     ignored; mirror `fd3_key_delivery`'s refuse-on-partial).
  3. `sock.close()` in a **`finally`** (not merely "after sendmsg"): SCM_RIGHTS *duplicates* the
     descriptor (refcount 2), so the core MUST drop its copy immediately or (a) leak one fd/extraction
     and (b) suppress the child's FIN. `finally` also covers a raise between `connect` and `sendmsg` (or
     an EPIPE mid-`sendmsg` on child death), which must map to a loud `ControlFdBrokerError`, never a
     hang or a leaked half-open gateway connection.
- `ControlFdBrokerError(AlfredError)` — **rooted at `AlfredError`** (unlike `ProviderKeyDeliveryError`'s
  bare `Exception`), closed-vocabulary `reason`; any operator-facing string goes through `t()` (HARD
  i18n). **PR2a defines the error type + its reason vocabulary only** — the `SANDBOX_REFUSED` audit-ROW
  write (and its test) is PR2b: PR2a has no live caller of the broker on the audited path (only the
  docker probe drives it), so a "PR2a wires the audit row" claim would be an HARD #7 overstatement
  (rev-002/sec-008). §8 item 7 is corrected accordingly.

The `broker_connected_socket` failure of "gateway unreachable" reuses the **same typed
`IOPlaneUnavailableError`** `EgressClient` raises; broker faults fold into the existing supervisor
breaker path (via `QuarantineChildSpawnError` at spawn-time, and the extractor's existing refusal per
call) — **no parallel silent channel** (HARD #7). **OTel trace context is NOT wired in PR2a** — it
belongs on the fd-0 request frame that PR2b introduces (prov-005/rev-005); wiring it onto the bare
broker frame now would be premature. (Deferred to §11.)

### 4.2 `spawn_quarantine_child_io` — opt-in control-fd plumbing (EDIT)

Signature grows a **defaulted-off opt-in**: `spawn_quarantine_child_io(*, provider_key,
control_fd: bool = False, child_module: str = _CHILD_MODULE)`. The live/echo spawn passes neither —
**byte-for-byte unchanged on the live path** (this is what makes PR2a genuinely dormant, per security:
unconditional `pass_fds=(3,4)` would hand the adversary-facing echo child a dangling control socket,
and `keep_fds` is declaration-only so the child would inherit fd 4 regardless of the policy).

When `control_fd=True` (docker test only):

- `make_control_socketpair()` is called **before** the clobber window opens. **Detach the child-end to
  a raw int** for the window (`child_fd = child_end.detach()` / operate on `child_end.fileno()`): the
  `dup2`/save/restore machinery must act on **raw detached fds, not live `socket` objects** — mixing a
  `socket` object into the fd-int dance reintroduces the object-vs-fd aliasing the raw-int fd-3 path
  already avoids (core-001).
- **Both** fd 3 (key) and fd 4 (control child-end) are `dup2`'d onto their literal numbers inside the
  **same synchronous zero-`await` window** as today's fd-3 dance, with:
  - **both** prior fd 3 **and** fd 4 saved and restored in the `finally` (today only `saved_fd3` is
    saved — fd 4 must be too; the loop's selector can be fd 4 → the same `OSError [Errno 22]` #237
    regression);
  - the **source-aliasing guard** ported from the spike (`while src in (3,4): src = os.dup(src)` for
    *both* sources) **and its temp-dups closed** in the `finally` (the spike leaks them — invisible in
    green because its fds landed above the targets; the real per-turn hot path will leak);
  - the `finally` **also closes the parent's copy of the socketpair child-end fd** (the fd-4 analog of
    today's `os.close(read_fd)` for the fd-3 pipe read-end — core-001: the current single-fd code has no
    such close for a second descriptor, so it must be added or the parent leaks the child-end each spawn);
  - `set_inheritable(True)` on both literal targets; `pass_fds=(3, 4)`.
- The **parent control-end is owned by `_SubprocessChildIO`** (stored on it, closed in `aclose`) — NOT
  returned as a bare tuple. This preserves the CR-#255 single-teardown seam (all child teardown routes
  through one `aclose`); a third caller-threaded object would re-introduce the leak class CR-#255 closed.
- `_SubprocessChildIO` gains an async `broker_socket()` (added to the `ChildIO` Protocol + the in-test
  double) that calls `control_fd_broker.broker_connected_socket(parent_end=…, proxy_config=…)`. The
  `EgressProxyConfig` is injected into `spawn_quarantine_child_io` (a new keyword, required only when
  `control_fd=True`) and stored on `_SubprocessChildIO` alongside the parent control-end. **PR2a does
  not wire `broker_socket()` into `QuarantineStdioTransport.dispatch`** (that per-extraction wiring is
  PR2b); the docker probe test drives `broker_socket()` directly.

**`child_module` is a closed-set seam, not a free string** (test lens): validated against a **frozen
allowlist** `{_CHILD_MODULE, _BROKERED_PROBE_MODULE}` — anything else raises `QuarantineChildSpawnError`
loudly. A unit guard asserts (a) the rejection and (b) that the live inbound-assembly path never passes
`child_module` at all. This closes the spawn-arbitrary-module hole the seam would otherwise open (the
probe child inherits fd 3 + fd 4).

### 4.3 The docker probe child — minimal, wheel-co-located (NEW)

`src/alfred/security/quarantine_child/_brokered_probe.py` — a diagnostic entry (the `--self-test`
/ `_daemon_probes` precedent), **inert in production**, spawned only by the docker test. It ships
**inside the wheel** so it lands under the policy's `/usr` ro-bind (ADR-0030) — no policy widening, no
extra bind (a `tests/`-resident child cannot exec under the bound interpreter). It is a **thin
`# pragma: no cover` subprocess-entry** (like `__main__.py`'s `main()`); its reusable `recvmsg`/frame
mechanics are factored into a unit-covered helper so only the netns-only C1 line is pragma'd (§9, H1).
It reconstructs the inherited control socket (fd 4), `recvmsg`s the passed fd, writes its verdict to
**stdout (fd 1)** — never back over fd 4 (§5, sec-002) — and reports:

- **C1 negative control:** a *fresh* `socket.create_connection((literal_ip, 443))` MUST fail
  `ENETUNREACH` — proves the netns is genuinely empty and the round-trip could only use the passed fd.
- **C2 liveness:** `getpeername()` + `SO_ERROR == 0` on the passed fd (then `detach()`, never
  double-close) — a live connected socket, confirmed **before** any I/O.
- **Minimal usability:** a trivial plaintext round-trip over the passed fd against the stub proxy
  (proves the fd is usable for I/O inside the netns) — **no TLS, no httpx** (that's PR2b, so `_CONSTRUCT_
  ALLOWLIST` stays untouched and `import socket` here is fine — the probe is not `__main__.py`, so G3 is
  unaffected either way).

The child module keeps its `socket`/`recvmsg` import at whatever scope is clean; `__main__.py` is not
touched, so G1/G3 (which read only `__main__.py`) are unaffected. **G4 is untouched too** — the probe
constructs no httpx client.

---

## 5. Data flow (PR2a)

```
 core (privileged)                                  child (bwrapped, --unshare-net, empty netns)
 ─────────────────                                  ───────────────────────────────────────────
 spawn_quarantine_child_io(control_fd=True):
   make_control_socketpair() → (parent, child_end)
   [zero-await window] dup2 key→3, dup2 child_end→4,
       save/restore both, aliasing-guard, pass_fds=(3,4)
   Popen(launcher … _brokered_probe)  ──fork──────►  inherits fd 3 (key) + fd 4 (control)
   restore fds; deliver key on fd 3
   _SubprocessChildIO owns `parent`                  probe main(): socket(fileno=4)  (control end)
 ── per probe pass (driven by the docker test) ──
   child_io.broker_socket():
     off-loop: create_connection(gateway-proxy)
     sendmsg(parent, [≥1 byte], SCM_RIGHTS=tcp_fd) ►  recvmsg(control fd 4) → tcp_fd   (fd 4 = SEND-ONLY)
     tcp.close()  (finally; refcount drops)           C2: getpeername/SO_ERROR (live) ; detach
                                                       C1: fresh socket → ENETUNREACH (empty netns)
                                                       minimal plaintext I/O over tcp_fd (usable)
   read_frame() (STDOUT / fd 1)  ◄── framed C1/C2/usability verdict ── write to fd 1  (existing seam)
   child_io.aclose(): terminate+reap, close `parent`
```

Two sequential probe passes to the **same still-alive child** validate the per-call-over-long-lived
model (a fresh SCM_RIGHTS pass over the *same* persistent control fd).

**fd 4 is strictly ONE-WAY, core→child (sec-002 + core-003).** The probe returns its C1/C2/usability
verdict over **stdout (fd 1)**, read by the existing `_SubprocessChildIO.read_frame` seam — NOT back
over fd 4. Two reasons: (a) `read_frame` is a *pipe* read and structurally cannot carry `SCM_RIGHTS`
anyway, so the verdict channel was always stdout; (b) more importantly, **the core never `recv`s on
the fd-4 parent-end**, which closes reverse-fd-injection *by construction* — a compromised child cannot
pass a fd back into the privileged core because the core never reads the ancillary buffer on that
socket. (PR2b residuals, recorded in §11: if a future design ever reads fd 4, it must use a plain
`recv` with **no** ancillary/CMSG buffer, add a unit guard that `control_fd_broker`'s parent-end is
never `recvmsg`'d, `shutdown(SHUT_RD)` the parent-end, and defensively parse the child's reply bytes.)

**Intra-pass ordering contract (core lens):** the core brokers the socket (`sendmsg` on fd 4) and the
child `recvmsg`s fd 4 **before** the child writes its verdict to stdout / blocks on any other read —
documented in the transport + the probe loop so a split-channel deadlock cannot arise. (In PR2b's real
`dispatch`, the broker step precedes the ingest/extract frames.)

---

## 6. The CONNECT-location fork (recorded; best-judgment child-does-CONNECT)

Security flagged: WHO performs the gateway CONNECT handshake is expensive to rework later. Options:

- **(A) Child does CONNECT** — the proven spike M1 shape (`httpcore.AsyncHTTPProxy` drives
  CONNECT+TLS+HTTP over the passed *bare* fd). The **gateway** enforces the destination allowlist. If
  #358 later adds `Proxy-Authorization`/mTLS on the core→proxy channel, the child composes it via
  `httpcore.AsyncHTTPProxy(proxy_headers=…)` (provider lens confirmed the seam is clean) — a
  value-passing change, but it means the proxy credential crosses into the adversary-facing child.
- **(B) Core does CONNECT, passes a post-CONNECT socket** — keeps any proxy-auth/mTLS credential in the
  privileged core; child does only TLS+HTTP. Still HARD #5 (TLS terminates in the child). BUT it is a
  DIFFERENT transport shape the spike did **not** prove (no `AsyncHTTPProxy` tunnel) → needs
  re-validation.

**Best-judgment (ratify): (A) child-does-CONNECT is the documented reference** — it matches what ran
green (M1) and the gateway (not the child) enforces the destination allowlist. **PR2a's broker passes a
bare TCP socket**, which is (A)-compatible and does not foreclose (B): if #358 lands `Proxy-Authorization`
before go-live, PR2b re-decides. ADR-0050 records (A) as the reference + this as an explicit **#358
forward-gate**.

---

## 7. Guards & security posture (PR2a)

- **NEW raw-socket-egress ratchet.** `control_fd_broker` is the FIRST sanctioned in-core site that
  passes a *network-connected* fd to a sandboxed child, and **no existing guard sees it** (G4 explicitly
  exempts raw sockets — a conscious residual, ADR-0042 §3, where the kernel netns is the
  enforcement-of-record). PR2a adds an AST ratchet (mirroring `test_only_sanctioned_quarantined_llm_
  spawn_site`) making `control_fd_broker.py` the **sole** allowlisted site for that pattern.
  **The pattern must be pinned on the distinctive CONJUNCTION (sec-001), not on `create_connection`
  alone** (which is trivially bypassable via `socket.socket(AF_INET*, …)` + `.connect()`, and bare
  `sendmsg(…, SCM_RIGHTS)` is a *pervasive* fd-passing signal — either half alone is a bad discriminator):
  key on **an INET connect/construct (`socket.create_connection` OR `socket.socket(AF_INET/AF_INET6)`
  followed by `.connect()`) AND a `sendmsg(…, SCM_RIGHTS, …)` in the same module.** This is a **narrow,
  consciously-documented AST residual** in the ADR-0042 tradition — NOT the full-strength "`EgressClient`
  is the only httpx constructor" gate (which keys on the more distinctive `httpx.AsyncClient(...)`
  construction). The rev.1 "raw-socket analog of the httpx constructor gate" framing over-claimed and is
  corrected here; the residual (an obfuscated raw-socket egress evading the AST match) is the same class
  of accepted static-analysis gap G4 already documents, backstopped by the child's empty netns.
- **G2 stays green; the shipped policy is NOT edited (and needs no throwaway copy).** The control-fd setup
  lives INSIDE `spawn_quarantine_child_io` (the only sanctioned spawn site — no second site). **PR2a does
  not touch `config/sandbox/quarantined-llm.linux.bwrap.policy`:** the probe test runs under the
  **shipped policy unedited** — fd 4 crosses via bwrap's default inheritance of the non-CLOEXEC passed fd
  (`keep_fds` is a parse-time DECLARATION that emits no bwrap flag, so the shipped `keep_fds=[3]` does not
  block fd 4), and the probe does **no TLS** so it needs **no `/etc/ssl/certs` CA bind**. The CA bind +
  `keep_fds=[3,4]` declaration land in PR2b (behind sign-off, when the child drives real TLS); the live
  echo child — which makes zero TLS calls — must not gain a CA bind or an undeclared fd for no live
  benefit, which is exactly why the control fd is opt-in (§4.2) and the policy is untouched here.
- **G4 untouched.** No child-side httpx construction in PR2a ⇒ **no `_CONSTRUCT_ALLOWLIST` loosening**.
  (The core broker is raw-socket, G4-exempt.)
- **G1/G3 untouched.** `__main__.py` is byte-for-byte unchanged.
- **`sbx-2026-005` stays valid unchanged.** It asserts the empty-netns child can't egress; the netns
  stays empty and no socket is brokered on the live path.
- **NEW dormant-mechanism adversarial gate** (a corpus entry, category `sandbox_escape`; threat-model:
  HARD #5 + ADR-0040 + #230/#340; provenance #340 PR2a). Assertions:
  1. the **live echo spawn passes no control fd** (`control_fd` defaults off) — behaviour-neutrality,
     proven mechanically;
  2. the **child still cannot self-connect** — the C1 `ENETUNREACH` negative control, re-run in-tree,
     proving the control fd did not widen the netns;
  3. **capability envelope** — the control channel passes *only* a connected gateway socket, one
     direction (the `MSG_CTRUNC` + exactly-one-fd check); the child cannot request or hand back arbitrary
     fds.
- **Mechanism-level HARD #5 assertion (docker):** the core writes **zero** bytes to the TCP socket
  before passing it; the stub sees only what crosses. (Full ciphertext-only + the real-extractor
  provenance re-validation of `test_real_turn_inbound_boundary.py` are PR2b, once the child drives TLS.)

**Explicitly NOT de-risked by PR2a (record in the test docstring + ADR-0040 touchpoint + the PR2b
sign-off checklist):** the fd0-extract / fd4-socket / fd1-reply three-channel wire choreography (the
child loop is untouched); real gateway acceptance (destination allowlist, gateway-side DNS,
refuse-literal-IP / reject-non-globally-routable); `Proxy-Authorization`/mTLS (#358); a real
provider / real key / paid call; self-signed CA ≠ public CA chain.

---

## 8. ADR-0050 (NEW) + doc touchpoints

A **new ADR-0050** (next free number; 0049 is highest), **sibling to ADR-0043** (the Discord L7-proxy
netns bridge), NOT merely an ADR-0040 amendment — the established pattern is one ADR per mechanism that
touches the connectivity-free-core *model* (ADR-0042 cutover, ADR-0043 Discord bridge). ADR-0043 already
**reserved this exact "Option C — empty netns + SCM_RIGHTS fd-broker" for the in-house 2c child**;
ADR-0050 realises it. It records:

1. The core-side raw-socket + SCM_RIGHTS **reachability-broker** as a deliberate, audited egress
   exception (core opens a bare TCP socket to the gateway proxy, passes the fd, writes zero application
   bytes; child performs CONNECT+TLS+HTTP; TLS terminates in the child).
2. The **empty-netns-preserved invariant** — `--unshare-net` stays; shipped policy not loosened; only
   *reachability* is brokered, not netns membership (evidence: the C1 `ENETUNREACH` negative control).
3. The **two-layer mapping, stated precisely** — for the *child*, kernel empty-netns is
   enforcement-of-record; for the *core*, `connect()` to `alfred-gateway` is **internal-network traffic
   on `alfred_internal`** (the same hop `EgressClient` makes), NOT a regaining of *external* reach, so it
   is **not** a connectivity-free-core weakening (PRD §5 is about external sockets).
4. The guard-exemption as a **conscious extension** (raw sockets are G4-exempt by design; the new
   raw-socket-egress ratchet is what bounds it), and the child-side ratchet flips PR2b will make and why
   they're safe (empty netns → `import socket` grants no route).
5. The **CONNECT-location decision** (§6: child-does-CONNECT reference) + the **#358 forward-gate**.
6. Why the **Discord AF_UNIX bridge cannot be reused** (arch-001, corrected — the rev.1 rationale was a
   FALSE inference). The ADR-0043 bridge is NOT a plaintext relay: the Discord adapter child *also*
   terminates TLS end-to-end, so the byte-splice carries TLS **ciphertext** — "a plaintext relay would
   expose raw T3" is wrong, and "the child terminates TLS" does not distinguish the two designs. The
   real, structural reasons the bridge can't be reused: (a) the quarantine child is hosted in the
   **connectivity-free core**, so the gateway-egress socket the Discord bridge mounts cannot be mounted
   here without reopening the G7-3 cutover; and (b) the Discord path uses `aiohttp`, which **exposes no
   fd hook**, so ADR-0043 itself reserved the SCM_RIGHTS fd-broker for the in-house child. Cross-ref
   ADR-0015 (the fd-3 sibling resource-passing primitive).
7. The **per-extraction core-side egress audit row** decision (should the signed core log record each
   brokered-socket target host:port, not just the gateway-local CONNECT audit — ADR-0040 residual vii).
   **PR2a does NOT wire this audit row** (rev-002/sec-008: no live caller — only the docker probe drives
   the broker; a "PR2a wires the audit" claim would overstate). PR2a records the loud-failure error type
   + reason vocabulary; the durable per-call egress-audit row + its write-path test are a **hard PR2b
   pre-gate** decided before go-live (sec-007).
8. **The dormancy contract as an explicit, auditable invariant** (arch-003, `requires_human_judgment`).
   PR2a's whole safety rests on a *software* guard — `control_fd=False` by default keeps the live child
   with no control fd — layered over the *kernel* empty netns. ADR-0050 must state this two-layer
   dormancy invariant explicitly, and it becomes a **PR2b sign-off checklist item** ("the control fd is
   opt-in-off until this PR flips it; the flip is the security-posture change under review").
9. A **back-reference from ADR-0040's residual panel to sibling ADR-0050** (arch-004), so the
   connectivity-free-core model's residual list points at the mechanism that consumes residuals iv/vii.

**Human-gated doc drift to FLAG in the PR (do NOT edit — CLAUDE.md self-improvement rule #4):**
CLAUDE.md security rule ("never open an external socket directly from core") wants a one-line carve-out
acknowledging the sanctioned raw-socket reachability-broker toward the **internal** gateway proxy
(ADR-0050 pointer) — the broker opens an internal socket, so it is not a literal violation, but a
reviewer could misread it. `docs/glossary.md` (define "reachability-broker" / control-fd broker once)
and `docs/subsystems/{quarantine,security}.md` are for `alfred-docs-author` at **PR2b**.

---

## 9. Testing (PR2a)

- **Docker-gated integration test** (`integration-privileged`, amd64; identical `bwrap+Linux+root+
  provisioned` `skipif` shape to the echo real-spawn precedent — inherits amd64-only, which is correct;
  **do NOT add an arm64 privileged leg** — that's #269 after #251). Uses `pytest.mark.skipif` (not
  `importorskip`) so the module still **collects** on non-bwrap runners with a `reason` naming the
  precondition (no silent vanish). Drives real `spawn_quarantine_child_io(control_fd=True,
  child_module=_BROKERED_PROBE_MODULE)` against a minimal stdlib stub proxy; asserts: **C1**
  (ENETUNREACH), **C2** (getpeername/SO_ERROR live), **minimal usability** round-trip, **≥2 sequential
  passes**, **fd-count stable** across passes (sample the **CORE process** `/proc/self/fd` — flat —
  guards close-after-sendmsg on the *core* side, which is where the leak would be; test-004), **HARD #5
  mechanism** (core wrote zero bytes).
- **"Assert the docker leg RAN (not skipped)" paper-gate** in `integration-privileged` — mirror **BOTH
  halves** of the #245 pattern (test-006/dev-003): not only the deterministic precondition **pre-check**
  (the brokered probe's provisioning holds) but also the **runtime skip-parse** (parse the pytest
  `-rs`/report to assert the brokered test node actually *ran*, not merely that preconditions looked OK)
  — the #245 comment itself notes the pre-check alone is insufficient. **This is the single biggest
  paper-gate risk** — the brokered path is release-blocking only if CI proves it executed.
- **Unit tests (no bwrap/root — carry the coverage):**
  - `control_fd_broker`: `make_control_socketpair` inheritability; `broker_connected_socket` over a real
    `socketpair` — SCM_RIGHTS pass, **partial-`sendmsg` refusal**, **≥1-byte** frame, `IOPlaneUnavailableError`
    on blank proxy URL, close-in-`finally` on a mid-send raise, EPIPE→`ControlFdBrokerError`.
  - `spawn_quarantine_child_io`: the `child_module` frozen-allowlist rejection; the opt-in default
    (live path passes no control fd); the two-fd save/restore + aliasing-guard temp-dup close + the
    socketpair-child-end close (mockable at the `os.dup2`/`pass_fds` boundary).
  - `_SubprocessChildIO`: `aclose` closes the parent control-end idempotently; **`broker_socket()`
    itself unit-exercised** with a mocked `control_fd_broker.broker_connected_socket` (test-002 — it
    lives in the named-gated `quarantine_child_io.py`, so an unexercised `broker_socket` breaks that
    100% gate).
- **`_brokered_probe.py` coverage treatment (H1 — the corroborated High: rev-001/test-001/dev-001).**
  The probe sits under `src/alfred/security/quarantine_child/`, which the **recursive** `security/*`
  100% gate (`--include='src/alfred/security/*'`, confirmed to recurse) covers against the *unit* suite
  — but its body runs docker-only (that leg uploads no coverage), so as-placed it makes the gate
  **unsatisfiable on `main`** (the exact anti-pattern §2 rejects). Resolution: keep the probe a **thin
  `# pragma: no cover` subprocess-entry** (the `__main__.py` precedent — `main()` there is already
  pragma'd as a subprocess entry), and **factor its reusable mechanics** (the `recvmsg`/`SCM_RIGHTS`
  extraction + frame parsing) into a **unit-covered helper** (in `control_fd_broker` or a sibling) so
  the only pragma'd lines are the genuinely netns-only ones (the C1 `ENETUNREACH` probe *cannot* be
  unit-covered — it requires the empty netns). Writing-plans picks pragma-vs-relocate and records it;
  either way the `security/*` gate must stay green without pragma'ing security-critical *logic*.
- **Explicit named 100% per-file coverage gate for `control_fd_broker.py`** — wired in **BOTH** the unit
  `--include` list AND the combined `coverage-gates` `--include` list (arch-002/test-005/dev-002: there
  is **no** `egress/*` glob — `egress/` files are protected only by enumerated `--include` entries, and
  the two-gates convention every `egress/*` file follows must be honoured; mirror the named
  `quarantine_child_io.py` gate so a reviewer sees it). Its mechanics are fully unit-testable; the docker
  leg proves only C1/C2, which the unit lane cannot.
- **The raw-socket-egress ratchet guard** (§7) + the **dormant-mechanism corpus payload** (§7) —
  the payload's node-id **must be registered in `adversarial.yml`'s hardcoded collected-node enumeration
  and marked `@_bwrap_required`** (test-003), or the release-blocking gate is blind to its silent
  deletion.

**Adversarial suite is release-blocking** (PR2a edits `src/alfred/security/`); run it even though PR2a is
behaviour-neutral on the live path.

---

## 10. Decisions (best-judgment; RATIFY forks 1–2 below before writing-plans)

1. **Scope = THIN cut** (core-side broker + opt-in fd-4 plumbing + ratchet + ADR-0050 + docker C1/C2
   probe). Child-side transport + `_CONSTRUCT_ALLOWLIST` + shipped-policy edit + `_build_provider` flip +
   provider taming/teardown/cost + full HARD #5 provenance → PR2b, behind sign-off. **REVERSES the
   earlier fat-cut selection.**
2. **CONNECT location = (A) child-does-CONNECT** (reference); PR2a passes a bare socket (A-compatible);
   #358 forward-gate recorded in ADR-0050.
3. **Layout = `egress/`** (peer to `EgressClient`; shared config + `IOPlaneUnavailableError`).
4. **#251 = standalone PR before this branch** (predependency).
5. **Ownership = `_SubprocessChildIO` owns the parent control-end** (CR-#255 single-teardown seam).
6. **Control fd = opt-in, defaulted off** (live spawn byte-for-byte unchanged).

---

## 11. What PR2b absorbs (so the PR2b spec has the agenda)

Child-side `brokered_egress` transport (§4.1 spike reference shape: `PassedFdBackend` → `httpcore.
AsyncHTTPProxy(retries=0,max_connections=1,max_keepalive_connections=0)` → custom `httpx.AsyncHTTPTransport`
subclass → `httpx.AsyncClient` → injected into `AnthropicProvider`) + its `_CONSTRUCT_ALLOWLIST` entry
paired with a **fine-grained fd-bound-client invariant**; the shipped bwrap policy edit (narrow
`/etc/ssl/certs` bind + `keep_fds=[3,4]`) + anchor churn; `_build_provider` real-adapter flip + extract-branch
swap; **refuse-boot** on unset key; the provider-lens must-fixes — **parameterize `max_retries` on
`AnthropicProvider.from_settings` AND `DeepSeekProvider.from_settings`** (Anthropic's `from_settings`
hardcodes `2`; DeepSeek inherits the SDK default rather than hardcoding it — prov-002 phrasing fix — so
both paths still need an explicit `max_retries=0` override; the `max_retries=0` taming is an SDK-ctor
arg the injected client cannot carry, so without this the spike's arm-1 re-dial silently returns), a
**per-extraction teardown contract** (the long-lived child else accumulates httpx clients),
`follow_redirects=False` explicit + no client-level timeout (rider-4); the **timeout hierarchy**
(prov-001 — the rev.1 "host read-frame > child budget ≥ SDK read" was **inverted** by the shipped
constants: child `_MAX_TOTAL_WALL_CLOCK_SECONDS = 30s` is SMALLER than the Anthropic SDK read `60s`,
so the fix is to **LOWER the quarantine SDK read below the 30s budget** — host read-frame > child
budget > SDK read — not raise the budget above the 30s action-deadline); `max_tokens` threading;
the **cost channel** (every extraction is now a billable call with no cost path out of the child today
— the cost metadata must ride the existing **fd-1 reply frame** into the standard per-call
metrics/budget record — prov-004); an **SSLContext module-scope singleton** (the spike builds
per-transport — a genuine correction); a `proxy_headers` seam for #358; **OTel trace context on the
fd-0 request frame** (deferred from PR2a §4.1 — prov-005/rev-005); the **tool-use canned body** so the
docker round-trip exercises the real `native_constrained` decode (a plain-text body drives the
*refusal* path) and asserts a real `Extracted`; keeping the child-side transport **provider-AGNOSTIC**
(it must serve DeepSeek's fork-b `prompt_embedded_fallback` path too, not just Anthropic — prov-003);
broadening G3 / a companion guard to declare `brokered_egress` egress-capable with a reachability
assertion; `sbx-2026-005` rewrite (a socket is brokered live) + capability-envelope assertions; the
fd-4-reverse-read hardening if ever read (plain `recv` no-CMSG + a "no `recvmsg` on the parent-end"
unit guard + `shutdown(SHUT_RD)` — sec-002 residual); the full HARD #5 provenance re-validation against
the real extractor schema; the T3-steers-extraction adversarial corpus; a real-provider connectivity
smoke; the durable **per-call core-side egress-audit row** (§8 item 7); a broker **Prometheus metric**
(dev-004); the **human sign-off**.

---

## 12. Panel-review fold log (5-lens, 2026-07-10)

Reviewers: architect, security, core, provider, test (all read the specs + live code + spike harness).
**0 disputed after resolution.** Convergent finding across architect + security + test: the fat cut drags
a ratchet loosening + a coverage break + a spike re-proof into the non-sign-off PR → **redraw thin**
(§2). Corroborated hardening folded (§4/§7/§9). Disputes resolved: (a) raw-socket guard — *none exists*
(Explore/G4-exempt); PR2a *adds* a ratchet (§7) — reconciles core's §11.5.3 intuition with the guard map;
(b) layout — `egress/` (architect's egress-origination reasoning) over `supervisor/` (core's fd3-mirror);
(c) `child_module` seam — frozen-allowlist param + guard (test) over free env string (core). Provider's
`max_retries`/teardown/cost + test's tool-use-body/coverage-factoring move to PR2b with the child-side
transport (§11). Security's "genuine dormancy" conditions (opt-in fd, no shipped-policy edit, real guard
coverage not filename-invisibility) are satisfied by the thin cut *by construction*.

---

## 13. Plan-review fold log (7-lens `/review-plan`, rev.2 — 2026-07-10)

Reviewers: architect, reviewer, test-engineer, security-engineer, core-engineer, provider-engineer,
devops-engineer + the review-coordinator. **37 findings: 0 Critical, 3 High (one corroborated issue),
14 Medium, 20 Low. 0 disputed, 0 gaps, 0 retracted.** 6 cross-checks dispatched, **6/6 confirmed.**
Security verdict: the thin cut is *sound and ratifiable*; the dormancy argument verified airtight
against the tree. Folds below OVERRIDE the rev.1 body where they conflict.

**High — corroborated ×3 (rev-001 + test-001 + dev-001), the one must-fix:**
- **Probe `security/*` coverage-gate break** → §9 H1 + §4.3: thin `# pragma: no cover` subprocess-entry
  (the `__main__.py` precedent) with reusable mechanics factored into a unit-covered helper.

**Medium — cross-check-confirmed (6/6), folded with the added residuals:**
- **arch-001** (sec-confirmed) → §8 item 6 rewritten: the Discord byte-splice carries TLS *ciphertext*;
  the real non-reuse reasons are connectivity-free-core hosting + aiohttp-has-no-fd-hook.
- **sec-002 + core-003** (sec + core confirmed; SAME underlying issue) → §5 + §4.3: verdict returns over
  **stdout**; **fd 4 strictly one-way** (core never `recv`s it) → reverse-fd-injection closed by
  construction; PR2b residuals (plain `recv` no-CMSG, no-`recvmsg` guard, `shutdown(SHUT_RD)`) → §11.
- **sec-001** (core-confirmed) → §7: ratchet pinned on the **conjunction** (INET connect/construct AND
  `sendmsg(SCM_RIGHTS)` in one module); the "httpx-gate analog" over-claim corrected to a documented
  AST residual.
- **core-002** (prov-confirmed) → §4.1: bounded connect timeout + **`settimeout(None)` before the pass**
  (`create_connection(timeout=)` leaves `O_NONBLOCK` set — honours the never-`O_NONBLOCK` invariant).
- **test-002** (dev-confirmed) → §9: `broker_socket()` unit-exercised (else the named `quarantine_child_io.py`
  gate breaks).
- **test-003** (dev-confirmed) → §7/§9: register the new payload in `adversarial.yml`'s node enumeration
  + `@_bwrap_required`.

**Corroborated clusters (peer-confirmed, no cross-check) — folded:**
- control_fd_broker **two-gates** in BOTH `--include` lists, no `egress/*` glob (arch-002/test-005/dev-002) → §9.
- **"wires the audit" overstatement** (rev-002/sec-008) → §4.1 + §8 item 7: PR2a defines the error type
  only; the audit-row write is PR2b.
- **"(ciphertext)" mislabel** (rev-003/sec-003) → §2 table "core wrote zero bytes".
- **OTel premature** (rev-005/prov-005) → moved to §11 (fd-0 request frame, PR2b).
- **core-side fd leak** (core-001/test-004) → §4.2 (close the socketpair child-end in `finally`; raw fds
  not socket objects) + §9 (fd-count test samples the CORE process).
- **broker urlsplit/missing-port** (core-004/prov-006) → §4.1.
- **paper-gate both #245 halves** (test-006/dev-003) → §9 (runtime skip-parse, not just pre-check).

**Single-reviewer, carried forward (in-domain, low-stakes or PR2b-agenda — not blocking):**
- Provider §11 precision: **prov-001** timeout inversion (30s < 60s; LOWER the SDK read), **prov-002**
  DeepSeek inherits the SDK default (not "hardcode 2"), **prov-003** transport must stay
  provider-agnostic, **prov-004** cost rides the fd-1 frame — all folded into §11.
- **arch-003** (`requires_human_judgment`) → §8 item 8: dormancy contract as an explicit auditable
  invariant + a PR2b sign-off checklist item.
- **arch-004** → §8 item 9 (ADR-0040 residual-panel back-reference). **dev-004** → §11 (broker Prometheus
  metric, PR2b). **sec-004** (tree-wide `child_module` guard), **sec-005** (sentinel-byte content),
  **sec-006** (probe import-isolation), **rev-004** (signature/idiom polish) — writing-plans nits, noted.

**One open item for the maintainer at ratification (arch-003, `requires_human_judgment`):** confirm the
two-layer dormancy invariant (opt-in-off software guard over the kernel empty netns) is the right
contract to make explicit + auditable in ADR-0050, and that the `control_fd`-flip in PR2b is the correct
security-posture boundary for the sign-off.
