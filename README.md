# AlfredOS

> An open-source, self-hostable, multi-user, multi-persona, security-hardened agentic OS.

**Status:** Pre-implementation. The design is in [`PRD.md`](./PRD.md); the operating manual for AI agents working in this repo is in [`CLAUDE.md`](./CLAUDE.md).

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
alfred chat                 # start a TUI conversation
```

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

If you (or an AI agent) is contributing to this repository, also read [`CLAUDE.md`](./CLAUDE.md) for repo conventions, security rules, and the self-improvement process.

## Security

If you have found a security vulnerability, **do not open a public issue**. Use [GitHub Security Advisories](https://github.com/alfred-os/AlfredOS/security/advisories/new) to report privately. See [`SECURITY.md`](./SECURITY.md) for details.

## License

AlfredOS is licensed under the [Apache License, Version 2.0](./LICENSE). See the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for the full terms.

Plugins communicate with the core via the MCP subprocess boundary (stdio / HTTP) and are not considered derivative works; plugin authors may license their work however they choose.
