# AlfredOS

[![Discord](https://img.shields.io/discord/1508136189830369300?label=chat&logo=discord&logoColor=white&style=flat-square)](https://discord.gg/HeNwaBhJfU)

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
bin/alfred-setup.sh        # macOS/Linux; on Windows, run inside WSL
docker compose up -d
alfred user add --authorization operator --name "Your Name"   # one-time
alfred chat                 # start a TUI conversation
```

`docker compose up -d` also starts **`alfred-gateway`** — the always-up resumable front
door that (once linked to the core in a later release) holds an `alfred chat` session
across a core restart. It exposes Prometheus metrics on the compose-internal
`alfred-gateway:9464/metrics` (see `ops/prometheus/prometheus.yml`). Note: the
`alfred_run` volume inherits ownership from the image on **first** creation; if you are
upgrading an older deployment that already has an `alfred_run` volume with the wrong
owner, run `docker compose down && docker volume rm <project>_alfred_run` before
`up -d` so it is re-created owned by the `alfred` user.

### Enable Discord (Developer Mode walkthrough)

Slice 2 ships a DM-only Discord adapter. Operator workflow for a fresh
deploy:

1. **Create a bot in the Discord developer portal.** Visit
   <https://discord.com/developers/applications>, create a new
   application, then create a Bot user under it.
2. **Enable the Message Content gateway intent.** Bot settings →
   Privileged Gateway Intents → toggle **Message Content** on. Without
   this, the adapter sees every DM as empty content and never reaches
   the orchestrator.
3. **Copy the bot token.** Bot settings → Reset Token → copy.
4. **Write the token to `~/.config/alfred/secrets.toml`.** The setup
   script created the file with `chmod 600` for you; add:

   ```toml
   discord_bot_token = "YOUR-TOKEN-HERE"
   ```

5. **Invite the bot to a server with the `bot` scope.** Slice 2 only
   reads DMs; you do not need any guild-message permissions yet.
6. **Bind your Discord user to the operator identity.** In Discord:
   Settings → Advanced → Developer Mode → right-click your user → Copy
   ID. Then on the host:

   ```sh
   alfred user bind --slug <your-operator-slug> --platform discord --platform-id <snowflake>
   ```

   The setup script offers an interactive prompt for this in its final
   step.
7. **Verify the gateway is reachable.** Run:

   ```sh
   docker compose run --rm alfred-discord verify
   ```

   Exit codes: `0` ok / `1` upstream / `2` config (bad token, intents
   off) / `3` LoginFailure / `4` timeout / `130` SIGINT. The error
   message names the remediation surface.
8. **Start the adapter as a daemon.** Once `verify` returns 0:

   ```sh
   docker compose up -d alfred-discord
   ```

   Send the bot a DM from your Discord account; the round-trip lands
   through the orchestrator with audit + budget + episodic memory + DLP
   all in place.

### Secrets file — permission propagation matrix

`~/.config/alfred/secrets.toml` is plaintext for Slices 2 and 3.
[ADR-0012](docs/adr/0012-file-backed-secret-broker.md) documents this as
a known risk; secrets management hardening (containerised secret broker)
ships in Slice 4 per
[ADR-0015](docs/adr/0015-slice4-containerised-quarantined-llm.md).
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
or the backup will contain plaintext API keys and your Discord bot
token. The containerised secret broker lands in Slice 4; until then, the
operator owns the exclusion.

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

For Python work specifically: [`docs/python-conventions.md`](./docs/python-conventions.md) is the canonical reference (tooling, types, errors, async, testing, security, i18n). AI agents should dispatch the [`alfred-python-developer`](./.rulesync/subagents/alfred-python-developer.md) subagent, which applies it without being asked. The [`docs/adr/`](./docs/adr/) directory holds the Architecture Decision Records that explain *why* the conventions look the way they do. The most recent — [ADR-0014: pluggable hooks for every action](./docs/adr/0014-pluggable-hooks-for-every-action.md) — records the Slice 2.5 hooks subsystem.

If you (or an AI agent) are contributing to this repository, also read [`.rulesync/rules/CLAUDE.md`](./.rulesync/rules/CLAUDE.md) for repo conventions, security rules, and the self-improvement process.

## Security

If you have found a security vulnerability, **do not open a public issue**. Use [GitHub Security Advisories](https://github.com/alfred-os/AlfredOS/security/advisories/new) to report privately. See [`SECURITY.md`](./SECURITY.md) for details.

## License

AlfredOS is licensed under the [Apache License, Version 2.0](./LICENSE). See the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for the full terms.

Plugins communicate with the core via the MCP subprocess boundary (stdio / HTTP) and are not considered derivative works; plugin authors may license their work however they choose.
