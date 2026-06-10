# ADR-0025 — The comms-MCP host transport is line-delimited and thin

- **Status**: Proposed (accepted at Slice-4 graduation, per the ADR-0015/0016 precedent)
- **Date**: 2026-06-10
- **Slice**: 4 — `docs/superpowers/specs/2026-06-06-slice-4-design.md`
- **Relates to**: [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (Decision 2 — `StdioTransport`), [ADR-0024](0024-perf-gate-hardware-budget.md) (wire-contract numbering), issues #237 / #235 (the daemon comms-MCP runtime epic)
- **Supersedes**: —

## Context

Slice 3 shipped `StdioTransport` ([ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) Decision 2) as the host side of the MCP plugin wire: a **length-prefixed** (4-byte big-endian header + body), strictly **request→one-response** transport whose `dispatch()` applies the trust-boundary primitives inline per frame — outbound DLP scan, secret-broker substitution, inbound canary scan, T3 tag-and-store. That shape is correct for the Slice-3 control-plane plugins it was built for (`alfred_quarantined_llm`, `alfred_web_fetch`): the host drives them, every exchange is a request the host initiated, and the security work belongs on that frame because there is no other place it happens.

The Slice-4 comms-MCP plugins are a different animal. All three merged adapters — `alfred_tui` (PR-S4-10), `alfred_discord` (PR-S4-9), and the `alfred_comms_test` reference plugin — speak **line-delimited JSON-RPC** (`readline()` inbound; `sys.stdout.write(json.dumps(frame) + "\n")` outbound), and their server docstrings assert "the host transport speaks line-delimited JSON-RPC". They were written against a host comms transport that **did not exist**: nothing in `src/alfred/` could read their frames, and — more fundamentally — nothing read the **unsolicited plugin→host notifications** (`inbound.message`, `adapter.binding_request`, `adapter.rate_limit_signal`, `adapter.crashed`) that are the entire point of a comms adapter. `AlfredPluginSession._on_post_handshake_method`, the comms-notification fan-out, was only ever invoked directly in tests; no serve loop pumped it from the wire. So in production an inbound platform message could never reach `process_inbound_message`. This is the keystone gap blocking the #237/#235 daemon comms runtime.

Two forces shape the resolution. First, the comms wire is **duplex and asymmetric**: the host sends requests (`lifecycle.start`, later `outbound.message`) while the plugin emits notifications at any time — `StdioTransport.dispatch()`'s single write-then-read-one cannot model an unbounded notification stream. Second, the comms trust-boundary work **already lives elsewhere**: inbound T3 sub-payload promotion, quarantined extraction, identity resolution, burst limiting, and peppered audit hashing all happen host-side in `process_inbound_message` (`src/alfred/comms_mcp/inbound.py`), and outbound bodies are carried as the `ScannedOutboundBody` NewType whose very existence is the proof that `DLP.scan` ran upstream. Re-running those primitives in the comms transport would double-tag content and contradict the `process_inbound_message` chokepoint contract.

## Decision

**Decision 1 — A separate, line-delimited `CommsStdioTransport`.** The comms host wire is line-delimited JSON-RPC, implemented by a new `src/alfred/plugins/comms_stdio_transport.py` `CommsStdioTransport`, NOT by reusing or re-framing `StdioTransport`. The merged plugins are not flag-dayed to length-prefixed. `StdioTransport` remains the length-prefixed control-plane transport for the quarantined-LLM and web-fetch plugins; the two transports coexist by design, one per wire shape.

**Decision 2 — The comms transport is thin; the trust boundary is upstream.** `CommsStdioTransport` carries NO DLP scan, NO secret substitution, NO T3 tagging, NO canary scan. Its sole security responsibility is a frame-size bound (DoS guard) and loud failure on a broken or malformed wire. Inbound trust work is `process_inbound_message`'s; outbound DLP is proven by `ScannedOutboundBody` upstream of the wire; platform credentials are fetched by the plugin inside its own sandbox via the broker, never substituted into a host→plugin comms frame. This is a deliberate departure from `StdioTransport`'s "the transport mediates every frame and applies the primitives" model ([ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md)), justified because the comms boundary work has a different, already-load-bearing home.

**Decision 3 — A `CommsPluginRunner` owns the serve loop; the session stays a pure state machine.** The handshake + single-reader notification pump live on a new `src/alfred/plugins/comms_runner.py` `CommsPluginRunner` that owns `(session, transport)`, not on `AlfredPluginSession`. The session keeps its "pure synchronous state init, no I/O" contract; the runner is the imperative shell. `run()` sequences spawn → `lifecycle.start` handshake (which drives the capability-gate check via `_on_handshake_complete`) → single-reader pump that feeds each notification into `_on_post_handshake_method` under the session's existing per-adapter semaphore → `close()` in a `finally` so a supervisor `TaskGroup` cancellation never leaks a subprocess.

**Decision 4 — Spawn through the launcher; keep the wire handle.** `CommsStdioTransport.spawn()` runs `bin/alfred-plugin-launcher.sh <plugin_id> <python> -m <module>` with piped stdio and retains the process handle. The launcher `exec`s the plugin (process replacement) and writes only to stderr, so the piped stdout is a clean line-delimited wire with the sandbox/UID-drop fully preserved — the reconciliation `spawn_plugin_via_launcher` (fire-and-forget) and `StdioTransport._spawn` (direct exec, no sandbox) each lacked. No provider-key fd is passed (comms needs no LLM key), so the macOS/Python-3.14 fd-3 selector hazard does not apply. The child env is built from a single shared allowlist (`src/alfred/plugins/_comms_child_env.py`, de-duplicated with `_launcher_spawn`), assembled explicitly — never `dict(os.environ)` — under its own AST env-scrub guard. Daemon-hosted comms plugins always get the scrubbed allowlist (a security tightening: the full-env passthrough remains exclusive to the operator-local foreground `alfred chat` path).

## Consequences

### Positive

- An inbound platform message can, for the first time, traverse plugin → wire → runner → session → handler in production; the #237/#235 daemon runtime now has a substrate to build on.
- The trust boundary stays single-sourced in `process_inbound_message` + `ScannedOutboundBody`; the comms transport cannot double-tag or drift from that contract.
- The sandbox is preserved on the live wire (launcher exec) without the fd-3 portability hazard.
- One env allowlist serves both the CLI launcher seam and the daemon comms transport (DRY), each AST-guarded against a secret leak.

### Negative / accepted

- Two host transports now coexist (length-prefixed control-plane + line-delimited comms). The cost is two framers; the alternative — converging on one framing — is a three-plugin flag-day for no security benefit.
- The per-adapter dispatch semaphore's headroom (`value > 1`) is unused by design while the runner dispatches strictly one frame at a time; a future fan-out PR may use it. Recorded so a later reader does not mistake the sequential pump for a bug.
- The runner is the single reader of the wire. Outbound `request`/response correlation (PR-S4-11b) must be owned by that single reader (a runner-side pending-response map), not a second concurrent `read_frame()`.

### Scope boundary (this ADR / PR-S4-11a)

PR-S4-11a ships the substrate only — `CommsStdioTransport`, `CommsPluginRunner`, the shared env seam — proven by an integration test that spawns the reference plugin through the real launcher and routes one notification to a recording handler. The daemon does not yet construct a comms runner: building the production `Orchestrator`, enumerating/spawning configured comms plugins, and wiring inbound→orchestrator→outbound is PR-S4-11b; the #235 deferred primitives (SubPayloadPromoter, OutboundQueue, BindingEmitter, addressing_drift, ThreadConversationLedger) and the live Discord spawn are PR-S4-11c.
