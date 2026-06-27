# Discord flag-day migration — Spec B G6-7-8 (#309)

This runbook guides operators through the breaking changes shipped by
[#309](https://github.com/alfred-os/AlfredOS/issues/309) (Spec B G6-7-8,
Discord adapter-hosting inversion). Read it if your deployment ran the
now-deleted `alfred-discord` Compose service before this release.

Related design records: [ADR-0036](../adr/0036-gateway-adapter-hosting-inversion.md)
(gateway adapter-hosting inversion) and
[ADR-0039](../adr/0039-gateway-adapter-inbound-bridge.md)
(gateway-adapter inbound bridge).

## What changed

Before this release the Discord adapter ran as a separate long-running
`alfred-discord` Compose service. The token lived in `secrets.toml` as
`discord_bot_token`. Operators verified the adapter with `alfred discord verify`.

After this release:

- The `alfred-discord` Compose service is **deleted**. `docker compose up`
  no longer starts it.
- `alfred discord verify` is **retired**. Use `alfred gateway adapters` instead.
- The Discord adapter is now hosted by the gateway process (`alfred-gateway`)
  per [ADR-0036](../adr/0036-gateway-adapter-hosting-inversion.md).
- The Discord bot token moves from `secrets.toml` (`discord_bot_token`) to
  `.env` as `ALFRED_DISCORD_BOT_TOKEN`.

None of these changes require a database migration — the token just moves
env vars. Rollback is a plain PR revert.

## Step 1 — Move the Discord bot token

Remove the old key from `~/.config/alfred/secrets.toml`:

```toml
# Delete this line (or the whole file if Discord was the only key):
discord_bot_token = "MTI..."
```

Add the token to `.env` (the Docker Compose env file at the repo root):

```bash
ALFRED_DISCORD_BOT_TOKEN=MTI...
```

Confirm the file is not world-readable:

```bash
chmod 600 .env
```

### The `_PREFER_FILE` shadow footgun

AlfredOS secrets resolve through a `_PREFER_FILE` precedence chain: a
file-sourced value shadows an env var of the same logical name. If you
leave `discord_bot_token` in a re-mounted `secrets.toml` after setting
`ALFRED_DISCORD_BOT_TOKEN`, the file value silently wins and the env var
is ignored. Remove the old `secrets.toml` key first, then set the env var.

## Step 2 — Pull and restart the gateway

```bash
docker compose pull
docker compose up -d alfred-gateway
```

The `alfred-discord` service is gone from `docker-compose.yaml` — Docker
Compose will emit a warning about it being undefined if you reference it
explicitly; that warning is expected and harmless.

## Step 3 — Verify the Discord adapter is ready

Use `alfred gateway adapters --wait-ready discord` to poll until the adapter
reaches the `up` state (or until the timeout elapses):

```bash
alfred gateway adapters --wait-ready discord
```

The default timeout is 30 seconds. Override with `--timeout <seconds>` if the
gateway takes longer to start in your environment.

### Exit-code reference

| Exit | Meaning | Operator action |
| --- | --- | --- |
| `0` | Adapter reached `up` — ready | None. Proceed. |
| `1` | Adapter not ready within the timeout | Check `ALFRED_DISCORD_BOT_TOKEN` is set and correct. Inspect `docker compose logs alfred-gateway` for the `missing_secret` or connection-error audit row. |
| `2` | Daemon / control plane unavailable | Confirm `docker compose ps alfred-gateway` shows the service running. The control socket is unreachable — `up -d alfred-gateway` if the service is not started. |
| `3` | Adapter name cannot be resolved (typo or adapter not enabled) or `--wait-ready` called without naming an adapter | Check the adapter id spelling. Confirm the adapter is listed in your configuration as enabled. If you called `--wait-ready` without an adapter name, add the adapter id: `--wait-ready discord`. |

One-shot status (no polling) is available without the `--wait-ready` flag:

```bash
alfred gateway adapters
alfred gateway adapters discord   # narrow to one adapter
```

One-shot exits `0` (rendered), `2` (daemon / control unavailable), or `3`
(a named adapter is not in the live status map) — it does not poll and never
exits `1`.

## Step 4 — Switch log commands

The `alfred-discord` container no longer exists. Any monitoring scripts or
operator habits that reference `docker compose logs alfred-discord` must
switch to:

```bash
docker compose logs alfred-gateway
docker compose logs -f alfred-gateway    # follow
```

Per-adapter adapter lifecycle events (`gateway.adapter.up`,
`gateway.adapter.down`, `gateway.adapter.crashed`) are emitted to the
structured audit log and appear in `alfred-gateway` container output.

## Misconfig: unset token

**Symptom**: `docker compose up -d` exits green, but `alfred-gateway` stops
shortly after. The bot is silent — no replies from Discord. `alfred gateway
adapters` fails with control-plane-unavailable (exit 2) because the gateway
process has exited.

**Cause**: `ALFRED_DISCORD_BOT_TOKEN` is not set in `.env` (or is empty).
When the gateway resolves the Discord adapter's spawn credential it finds no
secret, raises `AdapterCredentialError` with `reason="missing_secret"`, and
writes a signed `result="refused"` audit row (hard rules #5 and #7 — a
missing credential is a non-skippable security event). Today this path
causes the **entire gateway process to abort** (fail-closed). The bot is
silent because the gateway has stopped. The structural fix — park the broken
adapter without aborting the gateway — is tracked by
[#331](https://github.com/alfred-os/AlfredOS/issues/331).

**What the logs show**:

```
docker compose logs alfred-gateway | grep missing_secret
```

You should see a structured log line with `reason=missing_secret` and
`adapter_id=discord`. The container will have exited.

**Fix**:

1. Set the token in `.env`:

   ```bash
   ALFRED_DISCORD_BOT_TOKEN=MTI...
   ```

2. Restart the gateway:

   ```bash
   docker compose up -d alfred-gateway
   ```

3. Verify:

   ```bash
   alfred gateway adapters --wait-ready discord
   ```

   Exit `0` confirms the adapter is live.

## Rollback

Revert PR #309 (the flag-day PR). There is no data migration — the token
moved between env var stores; no database rows changed. After reverting:

1. Restore `discord_bot_token` to `secrets.toml`.
2. Remove `ALFRED_DISCORD_BOT_TOKEN` from `.env`.
3. `docker compose up -d` restarts `alfred-discord` and the old service
   resumes.

## Troubleshooting matrix

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `alfred gateway adapters --wait-ready discord` exits `2` | `alfred-gateway` not running | `docker compose ps alfred-gateway` — start if missing: `docker compose up -d alfred-gateway` |
| `alfred gateway adapters --wait-ready discord` exits `1` (timeout) | Token wrong, missing, or adapter crash-looping | `docker compose logs alfred-gateway \| grep missing_secret`; set correct token; `docker compose up -d alfred-gateway` |
| `alfred gateway adapters --wait-ready discord` exits `3` | Typo in adapter id or adapter not enabled | Check spelling — `discord` (lowercase). Confirm the adapter is enabled in config. |
| Gateway container exits immediately after `up -d` | `ALFRED_DISCORD_BOT_TOKEN` unset → gateway aborts fail-closed (#331) | Set the token; `docker compose up -d alfred-gateway` |
| `docker compose logs alfred-discord` gives "no such service" | Expected — `alfred-discord` service deleted in this release | Switch to `docker compose logs alfred-gateway` |
| `alfred discord verify` gives "no such command" | Expected — `alfred discord verify` retired in this release | Use `alfred gateway adapters --wait-ready discord` |
| Bot was up but stopped responding after redeployment | Old `discord_bot_token` in `secrets.toml` shadowing the env var (`_PREFER_FILE`) | Remove `discord_bot_token` from `secrets.toml`; `docker compose up -d alfred-gateway` |

## Related docs

- [ADR-0036](../adr/0036-gateway-adapter-hosting-inversion.md) — gateway
  adapter-hosting inversion (the architectural decision that drives this
  migration).
- [ADR-0039](../adr/0039-gateway-adapter-inbound-bridge.md) — gateway-hosted
  adapter inbound bridge.
- [docs/runbooks/slice-2-discord-smoke.md](./slice-2-discord-smoke.md) —
  the original Discord deployment guide (pre-inversion; kept for reference).
- [docs/subsystems/plugins.md](../subsystems/plugins.md) — gateway adapter
  transport architecture.
