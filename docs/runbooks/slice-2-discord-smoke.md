# Slice 2 — Discord gateway deployment runbook

Operator-facing walkthrough for taking a fresh AlfredOS deployment from "Docker
is installed" to "I can DM the bot from Discord and the conversation lands in
the audit log." Companion to the automated smoke test at
[`tests/smoke/test_discord_gateway_smoke.py`](../../tests/smoke/test_discord_gateway_smoke.py)
— the smoke is the release gate, this runbook is the human-readable deployment
story.

## Prerequisites

- Docker + Docker Compose installed; `docker compose version` returns a 2.x line.
- AlfredOS repo cloned and [`bin/alfred-setup.sh`](../../bin/alfred-setup.sh)
  already run once. Setup wrote the secrets file at
  `~/.config/alfred/secrets.toml` with `0600` permissions and added the
  operator row to the `users` table.
- Your operator slug exists. Verify with
  `docker compose run --rm alfred-core user list` — at least one row with
  `authorization = operator` must be present.
- A Discord account you control (the bot owner). You do not need to be a
  member of any server — AlfredOS uses DM-only delivery (see ADR-0009).

## Step 1 — Provision a Discord bot token

1. Open <https://discord.com/developers/applications> and sign in with the
   Discord account you want to own the bot.
2. Click **New Application**, name it (`alfred-<household>` is a fine
   convention), accept the developer terms.
3. In the left sidebar select **Bot**. The bot user is auto-created.
4. Click **Reset Token**, copy the token to the clipboard, and treat it like
   a password — anyone with the token can post as the bot.
5. Under **Privileged Gateway Intents**, ensure these are toggled OFF:
   - Presence Intent — OFF.
   - Server Members Intent — OFF.
   - Message Content Intent — **OFF**.

   AlfredOS only reads `msg.content` from DMs, not guild messages, and that
   does not require the privileged Message Content intent. Leaving these OFF
   keeps the surface area Discord exposes to the bot minimal.

> Discord changes the developer-portal layout occasionally. The
> authoritative reference for the intents toggle URL is
> <https://discord.com/developers/applications> — navigate to your
> application → **Bot** → **Privileged Gateway Intents**.

## Step 2 — Enable Developer Mode + copy your snowflake

The bot needs to know which Discord user is the operator before it will
respond to anyone.

1. In the Discord desktop or web client open **Settings**.
2. Navigate to **Advanced** in the left sidebar.
3. Toggle **Developer Mode** ON.
4. Close settings, right-click your own name anywhere (a DM with yourself,
   any server member list), and select **Copy User ID**.

The clipboard now holds your Discord snowflake — a long numeric string like
`123456789012345678`. Keep it for Step 4.

## Step 3 — Edit `~/.config/alfred/secrets.toml`

Open the file with your editor. The full path is host-dependent
(`~` expands to your home directory). Add the Discord token:

```toml
discord_bot_token = "MTI..."  # paste the token from Step 1.4
```

Save the file. The
[`SecretBroker`](../glossary.md#secretbroker) re-validates the
file's permissions every read; if `chmod` flipped during editing, fix it
with `chmod 0600 ~/.config/alfred/secrets.toml`. The broker fails closed
on group/world-readable bits — the verify step in Step 5 surfaces the
error if it slipped.

> The file MUST live outside any git working tree. The broker walks the
> path's ancestors looking for `.git/` and refuses if it finds one — a
> defence-in-depth against accidentally committing the secrets file.

## Step 4 — Pre-map yourself

Bind your Discord snowflake to the operator row:

```bash
docker compose run --rm alfred-core user bind operator \
    --platform discord \
    --id 123456789012345678   # paste your snowflake from Step 2
```

Expected output: a one-line confirmation naming the operator slug and the
platform. The command bumps the `IdentityVersionCounter` so any running
`alfred-discord` process picks up the new binding within 60 seconds (per
[ADR-0010](../adr/0010-canonical-user-id-and-listen-notify.md)) — or
immediately, on Postgres deployments where `LISTEN/NOTIFY` is live.

The bind is mandatory before Step 5. The Discord adapter rejects DMs from
unknown snowflakes with a polite refusal echoing the snowflake plus a
bind hint; without the bind, your first DM in Step 7 lands as a
`discord.unknown_user_dm` audit row, not a real conversation.

## Step 5 — Run `alfred discord verify`

Verify everything is wired correctly before you start the long-running
service:

```bash
docker compose run --rm alfred-core discord verify
```

The probe takes up to 30 seconds. It connects to the Discord gateway, waits
for the `on_ready` signal, and exits. The exit code tells you the result.

### Exit-code → structlog event → remediation matrix

| Exit | structlog event | What happened | Remediation |
|---|---|---|---|
| `0` | `discord.verify.ok` | Bot reached `on_ready` within 30s. Healthy. | None — proceed to Step 6. |
| `1` | `discord.verify.upstream_unrecoverable` | Repeated reconnect failure during the probe. Discord-side outage or network issue. | Check <https://discordstatus.com>. Retry with exponential backoff. |
| `2` | `discord.verify.config_failed` | Secrets file unreadable, missing key, intents misconfigured, or the operator row missing. | Re-read Steps 1, 3, and 4. The structlog event carries a `detail` field naming the specific config error. |
| `3` | `discord.verify.login_failed` | Token rejected at handshake (`discord.LoginFailure`). The token is wrong, revoked, or for a deleted application. | Re-issue the token from Step 1.4 and re-paste it into `secrets.toml`. Save, re-`chmod 0600`. |
| `4` | `discord.verify.timeout` | 30 seconds elapsed without `on_ready`. Network slow, Discord slow, or the bot is rate-limited by Discord at the gateway. | Wait a few minutes, retry. If persistent, check the bot is not banned (the Developer Portal shows banned applications). |
| `130` | `discord.verify.interrupted` | Operator pressed `Ctrl-C` during the probe. | Re-run. |

The internal 30-second timeout is enforced by the verify subcommand
itself; if the verify hangs longer than that, the container layer has a
problem (Docker network, DNS, …), not the probe.

## Step 6 — Launch the gateway service

With a green verify, bring the long-running adapter up:

```bash
docker compose up -d alfred-discord
```

Use `up -d`, **not** `run`. `run` launches a one-shot container with
`--rm` semantics; the long-running service needs the persistent container
declared in `docker-compose.yaml` so `restart: unless-stopped` and the
256M memory cap are honoured.

Confirm with `docker compose ps alfred-discord`. The container should be
`Up` with a healthy status. Stream logs with
`docker compose logs -f alfred-discord` to watch the gateway ready event.

## Step 7 — DM the bot from Discord; observe the audit row

1. In Discord, find the bot in your friends list or DMs sidebar (it
   appears as soon as you add the application to *any* mutual server, but
   you can also send a DM directly from the Developer Portal's bot page
   via the "Add to Server" → "OAuth2 URL Generator" flow).
2. Send any short message: `hello alfred`.
3. The bot DMs you back. The orchestrator's audit row lands within a
   second or two.

Confirm from the host:

```bash
docker compose run --rm alfred-core audit log --since 1m
```

Expected rows (one per turn):

- `discord.dm_received` — DM ingress, the operator's slug, the language.
- `orchestrator.turn` — provider call, tokens, cost.
- `dlp.outbound_redacted` — only if a redaction fired (none expected for a
  plain "hello").

If the bot does not reply: inspect `docker compose logs alfred-discord`
for a `discord.unknown_user_dm` row — that means Step 4's bind did not
take. Re-run the bind, wait 60 seconds for the TTL backstop to expire
(per [ADR-0010](../adr/0010-canonical-user-id-and-listen-notify.md)), or
restart the service to pick up the change immediately.

## Troubleshooting matrix

| Symptom | Probable cause | Action |
|---|---|---|
| `verify` exits `2`, log mentions `permissions` | `secrets.toml` group/world-readable | `chmod 0600 ~/.config/alfred/secrets.toml` |
| `verify` exits `2`, log mentions `discord_bot_token` missing | Token line missing from `secrets.toml` or empty string | Re-paste from Step 1.4 |
| `verify` exits `2`, log mentions `no operator` | Operator row missing in `users` | `docker compose run --rm alfred-core user list`; if empty, re-run `bin/alfred-setup.sh` |
| `verify` exits `3` | Token rejected at handshake | Re-issue token in Developer Portal; old token has been revoked |
| `verify` exits `4` | 30s elapsed without `on_ready` | Check <https://discordstatus.com>; check container DNS (`docker compose exec alfred-discord getent hosts discord.com`) |
| Bot is `Up` but ignores DMs | Discord snowflake not bound or bound to the wrong slug | `user bind operator --platform discord --id <snowflake>`; wait 60s |
| Bot DMs back `[REDACTED:…]` text | Outbound DLP fired on a known secret value | Expected — the redactor caught a secret in the outbound text; check `dlp.outbound_redacted` audit row for `stages_triggered` |
| Bot replies, then `alfred-discord` crashes | Container OOM (256M cap exceeded) | `docker compose logs alfred-discord` for OOM kill; reduce concurrency or raise the cap in `docker-compose.yaml` |
| `discord.unknown_user_dm` rows flooding | Spam bot iterating snowflakes | Audit-DoS dedup + global cap throttle this automatically; verify the cap counter has not saturated via the audit log |

## What's automated

The release gate for this flow is the smoke test at
[`tests/smoke/test_discord_gateway_smoke.py`](../../tests/smoke/test_discord_gateway_smoke.py).
It is gated by the `ALFRED_SMOKE_DISCORD_TOKEN` repo secret and exercises
`alfred discord verify` against a real Discord gateway from CI. The
companion TUI end-to-end smoke at
[`tests/smoke/test_tui_e2e.py`](../../tests/smoke/test_tui_e2e.py)
covers the orchestrator's full interactive path with mock and (optionally)
real providers.

This runbook is **complementary** to those smokes, not a substitute. The
smokes prove the system works on every PR; the runbook is how a human
operator brings a fresh deployment to the same green state for the first
time.
