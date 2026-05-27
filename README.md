# AlfredOS

> An open-source, self-hostable, multi-user, multi-persona, security-hardened agentic OS.

**Status:** Pre-implementation. The design is in [`PRD.md`](./PRD.md); the operating manual for AI agents working in this repo is in [`.rulesync/rules/CLAUDE.md`](./.rulesync/rules/CLAUDE.md).

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

`~/.config/alfred/secrets.toml` is plaintext for Slice 2. ADR-0012
documents this as a known risk; Slice 3 replaces it with an
age-encrypted equivalent. **In the meantime:**

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
token. Slice 3 ships an age-encrypted alternative; until then, the
operator owns the exclusion.

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

For Python work specifically: [`docs/python-conventions.md`](./docs/python-conventions.md) is the canonical reference (tooling, types, errors, async, testing, security, i18n). AI agents should dispatch the [`alfred-python-developer`](./.rulesync/subagents/alfred-python-developer.md) subagent, which applies it without being asked. The [`docs/adr/`](./docs/adr/) directory holds the Architecture Decision Records that explain *why* the conventions look the way they do.

If you (or an AI agent) are contributing to this repository, also read [`.rulesync/rules/CLAUDE.md`](./.rulesync/rules/CLAUDE.md) for repo conventions, security rules, and the self-improvement process.

## Security

If you have found a security vulnerability, **do not open a public issue**. Use [GitHub Security Advisories](https://github.com/alfred-os/AlfredOS/security/advisories/new) to report privately. See [`SECURITY.md`](./SECURITY.md) for details.

## License

AlfredOS is licensed under the [Apache License, Version 2.0](./LICENSE). See the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for the full terms.

Plugins communicate with the core via the MCP subprocess boundary (stdio / HTTP) and are not considered derivative works; plugin authors may license their work however they choose.
