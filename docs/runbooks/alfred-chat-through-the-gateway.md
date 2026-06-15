# Runbook — `alfred chat` through the gateway (Spec A G5)

`alfred chat` dials the **gateway** (`comms-gateway.sock`), which relays to the **core daemon** (`comms-tui.sock`). Three processes must be running, in order.

## Start sequence

1. **Enable the TUI comms adapter** so the daemon binds its socket. The daemon binds `~/.run/alfred/comms-tui.sock` ONLY when `comms_enabled_adapters` includes a `tui`-kind adapter (default is empty — no socket). Set it in your config / env:

   ```bash
   export ALFRED_COMMS_ENABLED_ADAPTERS='["tui"]'   # or set comms_enabled_adapters in config
   ```

2. **Start the core daemon** (owns the orchestrator graph; binds `comms-tui.sock`):

   ```bash
   alfred daemon start
   ```

3. **Start the gateway** (binds `comms-gateway.sock`; dials the daemon's `comms-tui.sock`; relays; signals reconnect banners):

   ```bash
   alfred gateway start
   ```

4. **Start chat** (dials the gateway):

   ```bash
   alfred chat
   ```

A typed turn round-trips `chat → gateway → daemon → ack → chat`. When the core link gaps and recovers, the TUI paints a reconnect/restored banner. (The reply is the daemon's stubbed ack until the real persona path lands — 2c/#230. There is no message-resume across a gap until G4 — an in-flight frame during a core restart is dropped.)

## Failure modes (the direct cohost→daemon dial is deleted — no dual-mode)

| Symptom | Cause | Fix |
|---|---|---|
| `alfred chat` exits 3 with "start the gateway" | The gateway isn't running (the dial to `comms-gateway.sock` failed). | `alfred gateway start`. |
| chat connects but a turn never echoes; a reconnect/unavailable banner shows | The gateway is up but cannot reach the daemon (daemon down). | Start the daemon; check the gateway's logs (`gateway.core_link.*`). |
| same as above, but the daemon IS up | The daemon did not bind `comms-tui.sock` — the `tui` adapter is not enabled. | Set `comms_enabled_adapters=("tui",)` and restart the daemon. |

The `alfred chat` error reports only what the CLIENT can see ("can't reach the gateway"); the gateway-can't-reach-core cases surface in the gateway's own logs + the TUI banner — `alfred chat` does not overclaim to diagnose them.

## Production deploy

The single-host start sequence above is for development. The production multi-container deploy (a long-running `alfred-core` service + an `alfred gateway` service + the shared-volume socket relocation) is **G3-4**; the PTY-against-Compose smoke lands there.
