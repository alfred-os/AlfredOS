# Alfred

> An open-source, self-hostable, multi-user, multi-persona, security-hardened agentic OS.

**Status:** Pre-implementation. The design is in [`PRD.md`](./PRD.md); the operating manual for AI agents working in this repo is in [`CLAUDE.md`](./CLAUDE.md).

## What is Alfred?

Alfred is a long-lived agentic runtime that hosts AI **personas** — specialized agents with their own purposes — and lets them:

- Converse with users across pluggable platforms (Discord + Telegram + TUI for MVP).
- Share multi-layered memory (working, episodic, semantic, vector, knowledge graph) per user, with auto-save and auto-recall.
- Coordinate with each other, with explicit safety rails (loop detection, budget caps, audit visualization).
- Extend themselves with new skills under a reviewer-gated change process — never validating their own work.
- Run continuously as a bounded autonomous OODA loop, with full audit trail and one-command rollback.

Alfred is hardened from day one against prompt injection, credential leakage, and PII exfiltration. Trust tiers, a dual-LLM split, a capability-gated tool layer, outbound DLP, secret brokering, canary tokens, and a cross-provider reviewer agent are all part of the MVP — not later additions.

## Quickstart

> Not yet implemented. Target experience for v0.1:

```sh
git clone https://github.com/<your-org>/alfred
cd alfred
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

## Working on Alfred

If you (or an AI agent) is contributing to this repository, read [`CLAUDE.md`](./CLAUDE.md) first.

## License

Apache-2.0 (see [`LICENSE`](./LICENSE) — file to be added).
