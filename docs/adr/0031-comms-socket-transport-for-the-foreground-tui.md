# ADR-0031 — A unix-socket comms transport closes the foreground-TUI ↔ daemon wire

- **Status**: Proposed (accepted at Slice-4 graduation, per the ADR-0015/0016/0025 precedent)
- **Date**: 2026-06-12
- **Slice**: 4 — `docs/superpowers/specs/2026-06-06-slice-4-design.md`
- **Relates to**: [ADR-0025](0025-comms-stdio-transport-line-delimited-and-thin.md) (the line-delimited comms wire + thin-transport contract this reuses), [ADR-0026](0026-first-party-system-bootstrap-grants-and-boot-hook-registry.md) (the first-party comms LOAD grant), [ADR-0027](0027-daemon-comms-runtime-fixture-extractor-first-cut.md) (daemon comms boot graph), issue #237 (graduation criterion #7 — a real `alfred chat` turn)
- **Supersedes**: —
- **Amended by**: [ADR-0036](0036-gateway-adapter-hosting-inversion.md) — Spec B G6-1: the gateway becomes a privileged adapter-hosting tier in addition to the socket relay.

## Context

PR-S4-11a/11b/11c built the host-side comms substrate: a line-delimited `CommsStdioTransport` ([ADR-0025](0025-comms-stdio-transport-line-delimited-and-thin.md)), a `CommsPluginRunner` that owns the single-reader notification pump, and a daemon boot path (`_build_comms_boot_graph` → `_spawn_comms_adapter`) that spawns each enabled comms adapter as a launcher-exec'd subprocess and routes its `inbound.message` notifications into `process_inbound_message`. That closes the wire for a **daemon-spawned** adapter (Discord, the reference plugin): the daemon owns both ends.

The foreground TUI does not fit that model. `alfred chat` is a **separate, operator-owned, foreground** process: it must own the operator's PTY (`inherit_stdio=True`, `sandbox.kind = "none"`) so Textual can render. It is started by the operator's shell, not by the daemon, and it long-outlives no daemon-owned subprocess handle. Today `alfred chat` (`src/alfred/cli/main.py`) spawns `plugins/alfred_tui` directly via `spawn_plugin_via_launcher` and **never connects to the running daemon** — its `inbound.message` frames go to its own stdout and reach nobody. So an operator who types into the TUI gets no orchestrator turn: graduation criterion #7 ("a real `alfred chat` turn traverses the daemon") cannot be met by the stdio-subprocess shape, because the daemon cannot spawn-and-own a process that must instead own the operator's terminal.

The missing piece is a **rendezvous** between two already-running processes: the daemon (which holds the comms boot graph — quarantined extractor, identity resolver, burst limiter, inbound orchestrator) and the foreground TUI (which holds the PTY). A local IPC channel both can open is the natural seam. The wire shape over it is **identical** to the stdio wire — the same ADR-0025 line-delimited JSON-RPC frames, the same `lifecycle.start` handshake, the same `inbound.message`/`outbound.message` exchange — only the byte-carrier changes from an anonymous pipe-to-a-child to a named local socket between peers.

## Decision

**Decision 1 — A `CommsSocketTransport` satisfies the existing `_CommsTransportLike` seam; the runner is unchanged.** A new `src/alfred/plugins/comms_socket_transport.py` `CommsSocketTransport` implements the same four-awaitable structural contract (`spawn`, `send`, `read_frame`, `close`) the `CommsPluginRunner` already binds to. The runner, the session, the handshake, the dispatch/ack path, and the ADR-0025 frame codec are all **reused byte-for-byte**. This is a transport swap, not a new conversation: a comms adapter reachable over a socket runs the exact same runner→session→`process_inbound_message` path as one reachable over a pipe, so the trust boundary it traverses is identical and single-sourced (no second scan point, no new orchestrator path).

**Decision 2 — `spawn()` is a no-op; the accepted connection IS the wire.** A daemon-spawned adapter's `spawn()` execs a subprocess and owns its pipe. The socket transport owns no subprocess — the peer (the foreground TUI) is its own process. The daemon's boot path instead **binds a listener** and **accepts one connection**; the accepted `(StreamReader, StreamWriter)` pair is the wire. `spawn()` is therefore an inert success (the connection is already established before the runner's handshake runs), and `send`/`read_frame` drive the accepted streams using the same line-delimited codec and the same `_MAX_COMMS_LINE_BYTES` frame bound and `CommsProtocolError` loud-failure discipline as `CommsStdioTransport`.

**Decision 3 — One socket per adapter id, owner-only, fresh each boot.** The listener binds `~/.run/alfred/comms-<adapter_id>.sock` under the already-`0700` daemon runtime dir (the same dir + permission discipline as `daemon.pid`), mode `0600`, owned by the daemon's uid. The path is keyed by `adapter_id` — self-documenting, and it leaves room for a future per-adapter listener at zero cost now even though **this cut accepts exactly one connection**. A stale socket from a prior boot is unlinked-then-bound (a crashed daemon leaves a socket inode behind; binding over it would `EADDRINUSE`). The socket and listener are reaped on **every** exit path — clean shutdown, a boot refusal, or a supervisor failure — mirroring `_CommsBootGraph.aclose()`'s leak-discipline.

**Decision 4 — Fail-closed and audited; never a silent drop.** The same security posture as the stdio transport: an over-bound line, non-JSON bytes, or a non-object top-level frame raises `CommsProtocolError` (loud, audited via the runner's existing malformed-frame arm) rather than being silently discarded (CLAUDE.md hard rule #7). The socket is `0600` owner-only, so the only peer that can connect is a same-uid process (the operator's own `alfred chat`); there is no network ingress and no cross-uid reach. The accept is bounded so a single connection is served this cut; a second connection attempt does not race the first. No trust-boundary primitive is bypassed: T3 body tagging, quarantined extraction, and the outbound DLP scan all happen exactly where they already do (`process_inbound_message` / `ScannedOutboundBody`), upstream and downstream of this dumb carrier.

**Decision 5 — Reuse the first-party comms LOAD grant; do not widen.** The socket-backed TUI adapter is loaded under the **same** first-party comms LOAD grant ([ADR-0026](0026-first-party-system-bootstrap-grants-and-boot-hook-registry.md)) seeded for every enabled first-party comms adapter at boot. The socket transport adds no new capability and no new grant — it is authorized to load by the identical config-is-authorization seed. The multi-adapter boot refusal is unchanged and still fires: a TUI-over-socket adapter **counts as an enabled adapter**, so enabling it alongside any second comms adapter refuses boot fail-closed exactly as a second stdio adapter would, until per-adapter inbound routing lands (PR-S4-11c).

## Consequences

### Positive

- `alfred chat` can, for the first time, drive a real orchestrator turn through the running daemon: the foreground TUI connects to the daemon's socket, its `inbound.message` reaches `process_inbound_message`, and the ack returns over the same socket. Graduation criterion #7 is reachable.
- The runner, session, codec, and the entire trust boundary are reused unchanged. The new surface is one transport class + one listener; the conversation and security contracts are inherited, so there is no second place for them to drift.
- The socket lives under the existing `0700` runtime dir with the existing `0600` owner-only discipline (the `daemon.pid` precedent), so the local-IPC attack surface is the operator's own uid and nothing wider.

### Negative / accepted

- A third byte-carrier now exists (length-prefixed control-plane pipe, line-delimited comms pipe, line-delimited comms socket). The cost is one more transport class; the wire shape and codec are shared with the stdio comms transport, so it is a carrier swap, not a new protocol. The alternative — teaching the daemon to spawn-and-own the foreground TUI — is impossible, because the TUI must own the operator's PTY, not the daemon's.
- This cut accepts exactly **one** connection on the socket. A multi-client TUI (several `alfred chat` sessions against one daemon) is out of scope; the adapter-keyed socket path is chosen now so the future per-adapter/per-session form is a path change, not a contract change.
- The foreground `alfred chat` launch path (`src/alfred/cli/main.py`) is **not** flipped to dial the socket in this ADR's scope — the daemon-side listener + transport are the shippable substrate here. Wiring `alfred chat` to connect is the immediately-following step (it consumes this transport's peer end).

### Scope boundary (this ADR)

This ADR ships the **daemon-side** socket listener + `CommsSocketTransport` + the boot-path branch that selects it for the socket-shaped (TUI) adapter, proven by unit tests over the listener lifecycle (bind/accept/perms/stale-unlink/reap), the transport's `_CommsTransportLike` conformance, and the daemon boot wiring (default-empty unchanged, multi-adapter refusal still fires, reap on every exit path). The client-side `alfred chat` dial-the-socket change, and any multi-connection / per-session socket fan-out, are follow-ups.

## Amendment — 2026-06-13 (PR-S4-237-2): the foreground TUI consumes the peer end (Shape A, in-process dial)

PR-1 (this ADR's original cut) shipped the **daemon-side** listener + `CommsSocketTransport`. PR-S4-237-2 ships the **client (peer) end** that consumes it: the foreground `alfred chat` now DIALS the daemon's bound socket and cohosts the Textual app + the wire in one asyncio program.

- **The planned PR-2/PR-3 split collapsed into one PR.** The wire the TUI cohosts IS the dial — there is no useful intermediate state where the dialer exists but the TUI does not cohost it (or vice versa), so splitting them only churned the same files twice. PR-2 therefore delivers both the client dialer and the cohost.

- **Topology = Shape A (in-process dial; the `chat` launcher-spawn is retired).** `alfred chat` runs the TUI code **in its own process** (no `spawn_plugin_via_launcher` subprocess) — one asyncio program cohosting Textual (via the async `App.run_async()`, never the loop-owning blocking `App.run()`) and the socket serve loop under a single `asyncio.TaskGroup`. The PR-S4-10 launcher-spawn path for `chat` is retired: the TUI is a `sandbox.kind = "none"`, operator-local, trusted foreground PTY app, so launcher scrubbing buys nothing for it, and the daemon cannot spawn-and-own a process that must instead own the operator's terminal.

- **The TUI is the PLUGIN end of the wire; it does NOT use `CommsPluginRunner`.** On the socket the DAEMON runs the host-side `CommsPluginRunner` (it SENDS `lifecycle.start` / `outbound.message` requests and RECEIVES `inbound.message` notifications). So the cohost's wire task is a thin serve loop: `read_frame` → route the request through the existing `TuiServer.dispatch` → write the response back via `transport.send`; the session's inbound sink writes `inbound.message` frames to `transport.send` (replacing the retired daemon-spawned stdout sink). The runner/session/codec/dispatch path are reused unchanged — only the carrier and the direction-of-drive differ from the stdio adapter.

- **New surface.** `dial_comms_socket(adapter_id)` (the connect-analog of `CommsSocketListener.accept`, reusing the carrier-symmetric `CommsSocketTransport` and pinning the dialed reader to the same `_MAX_COMMS_LINE_BYTES` frame bound) + `alfred_tui.cohost.run_cohosted` (the cohost harness). `_chat_main` flips from the launcher spawn to the in-process dial-and-cohost; a daemon-absent dial raises an `OSError` family member (`ConnectionRefusedError` / `FileNotFoundError`), mapped to the EXISTING `comms.tui.daemon_required_to_chat` t() string + exit 3 — same operator contract, detection moved from "launcher exited nonzero" to "dial failed". No new i18n key.

- **Stubbed ack (scope).** The daemon still acks a fixed `{"content": "ack"}`; a real `alfred chat` turn round-trips and paints the literal `ack` into the conversation log — that IS the PR-2 success signal. The real persona reply is the separate 2c / #230 track and is out of scope here.

- **Trust boundary unchanged.** PR-2 introduces no new trust-tag path: the operator's typed body crosses as a plain `inbound.message` over the dumb socket carrier; T3 tagging happens host-side in `process_inbound_message` on receipt. The `subscriber_tier = "operator"` (T1) is orthogonal to content trust tier and unchanged.

- **Core→plugin layering (sanctioned narrowly).** The core CLI imports the first-party bundled `alfred_tui` package directly via `sys.path`; this is sanctioned ONLY for the operator-local foreground TUI (`alfred chat`), NOT a precedent that any sandboxed/third-party plugin may be imported into core.

## Amendment — dial-side peer-auth (G3-3b-1, PR-S4-G3-3b)

PR-2 (above) shipped the dialer with a daemon-absent dial mapped to `OSError`. The gateway core-link (Spec A G3-3b-1, #237) DIALS this same socket and adds the **dial-side** half of the `SO_PEERCRED` peer-auth, extending PR-2's `dial_comms_socket`. ADR-0032 references this as "recorded under ADR-0031" because socket-transport peer-auth is this ADR's concern (it owns the accept-side check); this records the symmetric dial-side half.

The dial side now authenticates the peer in **both directions** (the accept side already verifies the connector's uid), via two layers:

- **Post-connect `SO_PEERCRED` (Linux-enforcing).** After `connect`, the connected peer's uid is read off `writer.get_extra_info("socket")` (the CONNECTED socket, never a listener) and the dial is refused with a `CommsPeerAuthError` (a `CommsProtocolError` subclass) if it is not the current uid.
- **Pre-dial `lstat` owner backstop (degrade-open hosts).** On a host without `SO_PEERCRED` (e.g. a macOS dev box) the post-connect check returns `None` → authorized. The dialer does NOT own the dialed inode (the daemon binds it), so a pre-dial `lstat` is the only owner enforcement there: the resolved path must be an `S_ISSOCK` inode owned by `os.getuid()`, or the dial is refused. It uses `lstat` (never `stat`) so a planted symlink target is never followed — reusing `CommsSocketListener._unlink_stale`'s discipline.

A daemon-absent / socket-missing dial still surfaces LOUD as the existing `FileNotFoundError` / `ConnectionRefusedError` daemon-required contract (CLAUDE.md hard rule #7); only an uid-mismatch / non-owned-inode refusal raises `CommsPeerAuthError`. The gateway reconnect loop treats a dial peer-auth reject as a transient and retries; the foreground TUI cohost (`alfred chat`) maps it — like the daemon-absent `OSError` — to the daemon-required operator message + exit 3, so a planted-inode / uid-squat / wider-perm misconfig is one clean operator line, never a traceback.

## Amendment — the `alfred gateway` process (Spec A G3-3b-2b)

G3-3b-2b ships the runnable `alfred gateway` PROCESS (`src/alfred/gateway/process.py` + `alfred gateway start|status`) wrapping the merged relay engine. It mirrors the daemon socket-carrier (`_listen_socket_comms_adapter`): bind the `GatewayClientListener` inline (fail-closed on `OSError`), accept ONE client racing the shutdown event, run the client-leg HOST handshake, build `GatewayCoreLink` + `GatewayRelay`, supervise `relay.run()`, and reap the listener (the accepted transport + the socket file) on EVERY exit path — including a cancel / `KeyboardInterrupt` unwind, via `run()`'s `finally`.

### Client-leg HOST handshake

The gateway is HOST on the client leg: it sends `lifecycle.start` with `{adapter_id: "tui", seq_ack: {version}}` (the same minimal shape the merged runner sends — see ADR-0035, which relaxed `LifecycleStartRequest.credentials_ref`/`policies_snapshot_hash` to optional because no producer ever sent them and the sole strict consumer, the TUI, discards them). It enables client-leg seq/ack IFF the client echoes `seq_ack` — the real TUI returns `seq_ack=None`, so the production client leg is PLAIN. A bounded pre-ack frame cap (`_MAX_PRE_ACK_FRAMES`) keeps a torn/hostile peer from hanging the handshake; a not-ok / EOF / over-cap / malformed result is a fail-closed `GatewayHandshakeError`.

### Dual-identity invariant (do NOT align them)

The gateway BINDS its client socket on adapter-id `"gateway"` (`comms-gateway.sock` — path ownership) but HANDSHAKES toward the TUI with wire `adapter_id="tui"` (wire compat — the TUI's `AdapterId` validator only knows `{"alfred_comms_test","discord","tui"}`). These are deliberately different axes; a future contributor must not "fix" the apparent inconsistency.

### Security sign-offs (recorded deliberately)

- **Peer-auth reject is metric + structlog ONLY in the G3→G4 window.** A wrong-uid client at the gateway's client socket increments `gateway_peer_auth_rejected_total` + emits a loud `gateway.process.peer_uid_rejected` row (preserving `peer_uid`), but the durable SIGNED reject audit row is HARD-SCHEDULED for G4 (the gateway has no audit sink yet). This is the accepted interim: the gateway is NOT the production front door until G5 re-points `alfred chat`, by which point G4's audit sink is in place — so production peer-reject exposure never runs without a durable trail.
- **Bind-side owner guarantee is the 0700 parent dir.** The client socket lives under `~/.run/alfred` (mode 0700, owner-only). G3-4's shared-volume socket relocation MUST re-establish an equivalent owner-only-parent invariant or a shared-volume socket becomes plantable.
- **`status` never speaks the wire.** `alfred gateway status` is a `Path.exists()` + runtime-dir-posture check only — it never dials or reads the socket (no un-authenticated wire read).

### Criterion #7 scope

2b PROVES the TRANSPORT substance of #237 criterion #7 — a real opaque payload relays byte-for-byte through the running process, and the client is held across a core reconnect (`reconnecting`/`restored` reaches it) — via a non-root in-process e2e + adversarial gate. The full real-orchestrator turn (real client → real core → real persona reply) is gated on 2c/#230 (no real reply yet) and production `alfred chat` re-pointing (G5).

## Amendment — `alfred chat` re-pointed at the gateway (Spec A G5)

G5 makes `alfred chat` dial the gateway (`comms-gateway.sock`) instead of the daemon directly (`comms-tui.sock`): the foreground TUI → gateway → daemon. The TUI renders the gateway's reconnect banner, and the #259 direct cohost→daemon dial is DELETED (Spec A: no dual-mode).

### The re-point + the dual-identity (unchanged invariant)

Both chat-client dial sites (`cli/main.py` `_chat_main` + `alfred_tui/server.py` `serve()`) now dial `_GATEWAY_ADAPTER_ID="gateway"` (the gateway's bind path). The wire `adapter_id` the gateway sends in `lifecycle.start` is still `"tui"` (the kind the TUI's `AdapterId` validator knows) — the dual-identity invariant holds: dial-path-id = `gateway`, wire-adapter-id = `tui`. The cohost is protocol-agnostic on the dial-id, so the re-point does not touch its handshake or turn shape. A gateway-absent dial surfaces the existing `DaemonUnavailableError` → a friendly "start the gateway with `alfred gateway start`" message + exit 3.

### TUI banners — the gateway sends state, the TUI renders its own text

The gateway's id-less `link.reconnecting`/`link.restored`/`link.unavailable` notifications are routed by the cohost's `_serve_wire` (a NARROW allowlist BEFORE `TuiServer.dispatch` — they are NOT in the plugin's method set; they are client-TERMINAL, never relayed/acked) to an `on_link_state` callback that paints a Textual banner with the TUI's OWN localized `t("tui.banner.*")` text. The gateway carries no operator text on the wire (i18n rule #1). `link.unavailable` is rendered but its gateway trigger is G4 (ReplayBuffer cap-breach) — the render ships ahead of the trigger.

### The operator prerequisite + the three failure modes

`alfred chat` now requires THREE processes: (1) `alfred daemon start` with `comms_enabled_adapters=("tui",)` so the daemon binds `comms-tui.sock`; (2) `alfred gateway start`; (3) `alfred chat`. The daemon default is NOT changed (not every deployment wants the socket; the Compose deploy that wires this is G3-4). The deleted direct-dial path means three failure modes the operator must distinguish (the runbook enumerates them; the chat error stays honest and does not overclaim to diagnose the gateway-internal ones): (a) gateway down → "start the gateway" + exit 3; (b) gateway up but daemon down → a reconnect/unavailable banner, no turn echoes; (c) daemon up but the tui adapter not enabled → the gateway's core dial fails → also a banner.

### THREE real bugs the first real connection surfaced (the never-connected chain)

The gateway, the cohost, and the daemon's outbound ack were built to a shared spec but NEVER connected — the prior tests used a fake core (#274), the reference plugin tolerated loose wire shapes, and the launcher legs skip on non-root CI. G5's real-socket integration test (real daemon + real gateway + real cohost + real Postgres) is their first connection, and it surfaced three real production bugs (all fixed in G5):

1. **Handshake seq-framing asymmetry (gateway):** `GatewayCoreLink._peer_handshake` flipped `enable_seq_ack()` BEFORE sending its ack, so the ack went out seq-framed while the daemon read it plain (the daemon flips after validating) → the leg broke → REDIALING forever. Fixed: send the ack PLAIN, flip AFTER — the handshake-ack-is-plain invariant (both peers flip-after-read).
2. **Missing `tui`→Platform resolver mapping (comms):** `_ADAPTER_KIND_TO_PLATFORM` omitted `"tui"` (and `"discord"`) → a real TUI inbound's binding could not resolve (`UnknownAdapterKindError`). Fixed: map the native kinds to their `Platform` members.
3. **Stubbed ack bypassed DLP + the wire contract (security):** the daemon's `{"content":"ack"}` ack was a raw dict that bypassed the outbound DLP chokepoint (hard rule #4) and failed `OutboundMessageRequest` validation → the real client rejected it. Fixed: the ack routes through `OutboundDlp.scan_for_outbound` (the only `ScannedOutboundBody` minter) + is constructed as a valid `OutboundMessageRequest` — the first production construction site of that model.

### Criterion #7 scope — transport substance CLOSED

With the three fixes, the real `cohost → gateway → daemon → DLP-scanned ack → cohost` turn round-trips end-to-end (proven by the G5 integration test against real Postgres, with the reconnect banner firing on a daemon-socket re-bind and the held connection surviving). This CLOSES #237 criterion #7's transport substance. The real persona REPLY (vs the stubbed ack) is 2c/#230; the production Compose deploy + the PTY-against-Compose smoke are G3-4; resume (no message loss across a gap) is G4 — the interim no-resume window between #259 and G4 stands, per Spec A.
