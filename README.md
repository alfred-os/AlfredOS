# AlfredOS

[![Discord](https://img.shields.io/discord/1508136189830369300?label=chat&logo=discord&logoColor=white&style=flat-square)](https://discord.gg/HeNwaBhJfU)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/alfred-os/AlfredOS)

> An open-source, self-hostable, multi-user, multi-persona, security-hardened agentic OS.

**Status:** Pre-implementation. The design is in [`PRD.md`](./PRD.md); the operating manual for AI agents working in this repo is in [`.rulesync/rules/CLAUDE.md`](./.rulesync/rules/CLAUDE.md).

**Community:** Join the [**AlfredOS Discord**](https://discord.gg/HeNwaBhJfU) to ask questions, share builds, or follow development.

## What is AlfredOS?

AlfredOS is a long-lived agentic runtime that hosts AI **personas** — specialized agents with their own purposes — and lets them:

- Converse with users across pluggable platforms (Discord + Telegram + TUI for MVP).
- Share multi-layered memory (working, episodic, semantic, vector, knowledge graph) per user, with auto-save and auto-recall.
- Coordinate with each other, with explicit safety rails (loop detection, budget caps, audit visualization).
- Extend themselves with new skills under a reviewer-gated change process — never validating their own work.
- Run continuously as a bounded autonomous OODA loop, with full audit trail and one-command rollback.

AlfredOS is hardened from day one against prompt injection, credential leakage, and PII exfiltration. Trust tiers, a dual-LLM split, a capability-gated tool layer, outbound DLP, secret brokering, canary tokens, and a cross-provider reviewer agent are all part of the MVP — not later additions.

**Alfred** (no "OS") is the name of the default persona — the head butler — who ships enabled out of the box. Specialist personas (Lucius, Oracle, Diana) are bundled as examples; operators enable them as needed.

## Quickstart

> Not yet implemented. Target experience for v0.1:

```sh
git clone https://github.com/alfred-os/AlfredOS
cd AlfredOS
cp .env.example .env       # then set ALFRED_QUARANTINE_PROVIDER_API_KEY (see below)
bin/alfred-setup.sh        # macOS/Linux; on Windows, run inside WSL
docker compose up -d
alfred user add --authorization operator --name "Your Name"   # one-time
alfred chat                 # start a TUI conversation
```

> **A provider key is required before the first `docker compose up -d`.**
> `ALFRED_QUARANTINE_PROVIDER_API_KEY` in `.env` is the credential for the
> quarantined half of the dual-LLM split, which now makes real provider calls. With
> it unset the core exits 2 (`quarantine_provider_key_unset`) and crash-loops under
> `restart: unless-stopped`. This is deliberate — a real client on a placeholder key
> would be a silently dead LLM — but it means a keyless first run does not start.
> `bin/alfred-setup.sh` warns when the key is missing; it cannot seed one for you.

`docker compose up -d` now starts **`alfred-core`** as a **long-running daemon**
(`alfred daemon start`, `restart: unless-stopped`) — earlier releases ran it as a
one-shot command runner. One-off subcommands still work via
`docker compose run --rm alfred-core <cmd>` (`migrate`, `user add`, `chat`, …) because
`run` overrides the service `command`. **Run `bin/alfred-setup.sh` _before_
`docker compose up -d`**: it seeds the `audit.hash_pepper` and provisions secrets the
daemon requires to boot. Skip it and the daemon refuse-boots and, under
`restart: unless-stopped`, crash-loops. The script seeds what it can and warns about
what it cannot — `ALFRED_QUARANTINE_PROVIDER_API_KEY` has to come from you.

`docker compose up -d` also starts **`alfred-gateway`** — the always-up resumable front
door that holds an `alfred chat` session across a core restart. As of this release the
gateway **links to the core**: the daemon binds `comms-tui.sock` on the shared
`alfred_run` volume and the gateway dials it (its compose-internal
`alfred-gateway:9464/metrics` `gateway_core_link_up` gauge reads `1` once both are up;
see `ops/prometheus/prometheus.yml`). Note: the `alfred_run` volume inherits ownership
from the image on **first** creation; if you are upgrading an older deployment that
already has an `alfred_run` volume with the wrong owner, run
`docker compose down && docker volume rm <project>_alfred_run` before `up -d` so it is
re-created owned by the `alfred` user.

> **AppArmor hosts (Ubuntu 23.10+ and other userns-restricted Linux):** the dual-LLM
> quarantine child runs under bubblewrap, which builds an unprivileged user namespace.
> On hosts with `kernel.apparmor_restrict_unprivileged_userns=1` (the modern Ubuntu
> default) the kernel refuses that namespace unless the container runs under an AppArmor
> profile carrying `userns,`. `bin/alfred-setup.sh` loads the bundled
> `docker/apparmor/alfred-bwrap` profile for you. If you run `docker compose` directly
> (skipping the setup script), load it first or `alfred-core` crash-loops with
> `bwrap: No permissions to create new namespace`:
>
> ```sh
> sudo apparmor_parser -r docker/apparmor/alfred-bwrap
> ```
>
> Run all `docker compose` commands **from the repository root**: the compose
> `security_opt: seccomp=docker/seccomp/alfred-bwrap.json` path resolves relative to the
> compose-invocation directory, not the compose file. macOS and non-AppArmor Linux hosts
> need none of this (the `security_opt` lines are runtime no-ops there). The bundled PBS
> interpreter adds roughly +110 MB to the `alfred-core` image.

### macOS host access to Postgres (G7-3 connectivity-free core)

`alfred_internal` is `internal: true`, so on Docker-Desktop/OrbStack (macOS) the
`alfred-postgres` host-published port `5432` is not forwarded — `psql -h localhost` from a
Mac host will not connect. The compose-internal core reaches Postgres over `alfred_internal`,
and the dev test loop uses testcontainers, so neither is affected. For a one-off host query,
exec into the network: `docker compose exec alfred-postgres psql -U alfred -d alfred`. On
Linux, published ports NAT independently of the internal network, so host access still works.

### Mandatory egress proxy

`ALFRED_EGRESS_PROXY_URL` is mandatory — the core has no direct-egress fallback.

**DeepSeek:** if you override `ALFRED_DEEPSEEK_BASE_URL` from its default, set the same value on
**both** `alfred-core` and `alfred-gateway`. The gateway derives its destination allowlist from
that variable; a mismatch means the core dials a host the gateway denies.

**Anthropic:** the gateway allowlist is hardcoded to `api.anthropic.com`. A custom Anthropic
endpoint is not supported — it would be denied by the allowlist.

### Enable Discord (Developer Mode walkthrough)

AlfredOS ships a DM-only Discord adapter hosted by the gateway. Operator
workflow for a fresh deploy:

1. **Create a bot in the Discord developer portal.** Visit
   <https://discord.com/developers/applications>, create a new
   application, then create a Bot user under it.
2. **Enable the Message Content gateway intent.** Bot settings →
   Privileged Gateway Intents → toggle **Message Content** on. Without
   this, the adapter sees every DM as empty content and never reaches
   the orchestrator.
3. **Copy the bot token.** Bot settings → Reset Token → copy.
4. **Set the token in `.env`.** Open your `.env` file (copy from
   `.env.example` if you have not already) and set:

   ```sh
   ALFRED_DISCORD_BOT_TOKEN=YOUR-TOKEN-HERE
   ```

   The token is read by `alfred-core` on boot and delivered to the
   gateway-hosted Discord child over fd-3 at spawn time. The gateway
   and child never hold the token in their environment.
5. **Invite the bot to a server with the `bot` scope.** AlfredOS only
   reads DMs; you do not need any guild-message permissions yet.
6. **Bind your Discord user to the operator identity.** In Discord:
   Settings → Advanced → Developer Mode → right-click your user → Copy
   ID. Then on the host:

   ```sh
   alfred user bind --slug <your-operator-slug> --platform discord --platform-id <snowflake>
   ```

   The setup script offers an interactive prompt for this in its final
   step.
7. **Start the gateway.**

   ```sh
   docker compose up -d alfred-gateway
   ```

8. **Verify the adapter is ready.** Once the gateway is up, run:

   ```sh
   alfred gateway adapters --wait-ready discord
   ```

   This polls until the Discord adapter reports ready or the timeout
   expires. Exit `0` means the adapter reached `on_ready` and is
   accepting DMs. Then send the bot a DM from your Discord account; the
   round-trip lands through the orchestrator with audit + budget +
   episodic memory + DLP all in place.

### Secrets file — permission propagation matrix

`~/.config/alfred/secrets.toml` is plaintext for Slices 2 and 3.
[ADR-0012](docs/adr/0012-file-backed-secret-broker.md) documents this as
a known risk; secrets management hardening (containerised secret broker)
ships in Slice 4 per
[ADR-0015](docs/adr/0015-slice4-containerised-quarantined-llm.md).

The broker reads this host-default file when `ALFRED_SECRETS_FILE` is unset (completing
ADR-0012). If you already keep secrets there — or your `~/.config` is a git repo — read the
[upgrade note](docs/runbooks/2026-07-03-secrets-file-host-default.md) first.

**In the meantime:**

- **macOS:** Docker Desktop maps the host file's uid/gid to the
  container uid/gid directly; `chmod 600` on the host applies inside
  the container too. The setup script runs `export UID GID` because
  macOS bash 3.2 does not export `UID` by default.
- **Linux:** `user: "${UID:-1000}:${GID:-1000}"` in
  `docker-compose.yaml` resolves to the operator's real uid/gid; the
  bind-mount's `chmod 600` is enforced by the kernel exactly as on the
  host.
- **WSL2:** same as Linux, with the caveat that running `docker compose`
  from PowerShell (vs `wsl`) sees a different uid namespace. Run the
  setup script from inside WSL to keep the perms consistent.

**Backup-vector reminder:** if you back up your `~/.config` with
`restic`, `borg`, or similar, **exclude `~/.config/alfred/secrets.toml`**
or the backup will contain plaintext API keys. The `ALFRED_DISCORD_BOT_TOKEN`
lives in `.env` (not in `secrets.toml`); exclude `.env` from any backup
that should not retain plaintext credentials. The containerised secret
broker lands in Slice 4; until then, the operator owns both exclusions.

## Configuration

Operator-facing environment variables live in [`.env.example`](./.env.example);
copy it to `.env` and edit. The Slice-3 trust-boundary section documents the
plugin-launcher, capability-gate, and supervisor knobs (sandbox policy
directory, plugin UID, perf-gate force-run, redis maxmemory, state-git path).

### Gate selection

The capability gate has two implementations: `RealGate` (Postgres-backed)
and `DevGate` (fail-open stubs, development-only). Selection is effectively
**opt-out of DevGate**: only `ALFRED_ENV=development` (or unset/empty/whitespace,
which short-circuits the bootstrap to DevGate) selects the stub. Anything else
— including typos — falls through to `RealGate`:

| `ALFRED_ENV` value | Gate constructed |
| --- | --- |
| `development` | `DevGate` (fail-open stubs) |
| Unset, empty, or whitespace-only | `DevGate` |
| Anything else (`production`, `staging`, `prdouction` typo, ...) | `RealGate` |

This means a typo in a production deployment safely falls through to
`RealGate`. The matching startup log event (`bootstrap.gate_selected`,
INFO-level) carries the exact env value the bootstrap read so an operator
who set `ALFRED_ENV=prod` (instead of `production`) can confirm which gate
they ended up on. The plugin runbook
([`docs/runbooks/slice-3-plugins.md`](./docs/runbooks/slice-3-plugins.md))
walks through the full Slice-3 deployment, including the launcher and the
supervisor.

## Design

See [`PRD.md`](./PRD.md) for the full design, including:

- Architecture overview
- The 7 capability pillars + persona system
- Security model and prompt-injection defenses
- Memory model
- Reviewer-gated self-improvement
- Token caching and cost control
- Deployment and self-healing
- MVP scope vs. roadmap

## Contributing

Contributions welcome. Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) and our [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md). Contributions are licensed under the project's [Apache-2.0 license](./LICENSE).

For Python work specifically: [`docs/python-conventions.md`](./docs/python-conventions.md) is the canonical reference (tooling, types, errors, async, testing, security, i18n). AI agents should dispatch the [`alfred-python-developer`](./.rulesync/subagents/alfred-python-developer.md) subagent, which applies it without being asked. The [`docs/adr/`](./docs/adr/) directory holds the Architecture Decision Records that explain _why_ the conventions look the way they do. The most recent — [ADR-0014: pluggable hooks for every action](./docs/adr/0014-pluggable-hooks-for-every-action.md) — records the Slice 2.5 hooks subsystem.

If you (or an AI agent) are contributing to this repository, also read [`.rulesync/rules/CLAUDE.md`](./.rulesync/rules/CLAUDE.md) for repo conventions, security rules, and the self-improvement process.

## Security

If you have found a security vulnerability, **do not open a public issue**. Use [GitHub Security Advisories](https://github.com/alfred-os/AlfredOS/security/advisories/new) to report privately. See [`SECURITY.md`](./SECURITY.md) for details.

## License

AlfredOS is licensed under the [Apache License, Version 2.0](./LICENSE). See the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for the full terms.

Plugins communicate with the core via the MCP subprocess boundary (stdio / HTTP) and are not considered derivative works; plugin authors may license their work however they choose.
