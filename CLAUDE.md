# CLAUDE.md — AlfredOS Repo Operating Manual

This file is loaded by AI agents working in this repository. Read it before doing anything.

## What this is

**AlfredOS** is a multi-user, multi-persona, security-hardened agentic OS. Self-hostable. Licensed AGPL-3.0-or-later (community) with commercial dual-licensing available (CLA required from contributors). **Alfred** (no "OS") is the name of the default persona that ships enabled.

Full design: see [`PRD.md`](./PRD.md). Read it before proposing any architectural change.

## Where things live

```
AlfredOS/
├── PRD.md                          # the design — source of truth for *what* and *why*
├── CLAUDE.md                       # this file — operating manual for AI agents
├── README.md                       # user-facing quickstart
├── LICENSE                         # AGPL-3.0-or-later
├── NOTICE                          # copyright + third-party attributions
├── CLA.md                          # contributor license agreement (required to merge)
├── CODE_OF_CONDUCT.md              # Contributor Covenant 2.1
├── CONTRIBUTING.md                 # how to contribute, including CLA process
├── SECURITY.md                     # vulnerability reporting
├── docker-compose.yaml             # default deployment
├── bin/                            # CLI + setup scripts (alfred-setup.sh, alfred-setup.ps1)
├── src/alfred/                     # Python core
│   ├── core/                       # orchestrator, loop, plugin registry, event bus
│   ├── personas/                   # persona registry & routing
│   ├── memory/                     # 6-layer memory subsystem
│   ├── security/                   # trust tiers, DLP, secret broker, capability gate
│   ├── providers/                  # LLM provider adapters (Anthropic, OpenAI, internal-CLI)
│   ├── caching/                    # prompt cache, semantic cache, embedding cache
│   ├── reviewer/                   # reviewer-gate client
│   ├── audit/                      # audit log + git repo writer
│   └── cli/                        # `alfred` CLI commands
├── plugins/                        # first-party MCP plugins (comms adapters, integrations)
├── personas/                       # bundled persona definitions (Alfred default; Lucius/Oracle/Diana examples)
├── skills/                         # bundled skill examples (the agent will add its own at runtime)
├── config/                         # default config (routing.yaml, policies.yaml, ...)
├── ops/                            # grafana dashboards, prometheus alerts
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   └── adversarial/                # MUST-PASS security suite — see PRD §8.1
└── docs/
    ├── adr/                        # Architecture Decision Records
    └── superpowers/specs/          # design docs (this is the path the brainstorming skill expects)
```

**Runtime state lives outside the repo** at `/var/lib/alfred/state.git`. The agent commits its proposed self-modifications there; the reviewer agent reviews; merges activate. Never commit runtime state into the source repo.

## Tech stack

- **Language (core):** Python 3.12+
- **Async runtime:** asyncio
- **Plugins:** MCP (stdio for in-process, HTTP for remote) — polyglot
- **Datastores:** Postgres 16 (+ pgvector), Redis 7, Qdrant
- **Containerization:** Docker + Docker Compose
- **Type system:** Pydantic v2 for data models; mypy in strict mode for the core
- **Test framework:** pytest + testcontainers + custom adversarial harness
- **Observability:** structlog + Prometheus client + OpenTelemetry
- **Lint/format:** ruff + black
- **Package manager:** uv

## Commands you should know

| Purpose | Command |
|---|---|
| Set up dev environment | `bin/dev-setup.sh` (creates `.venv`, installs deps, pulls test fixtures) |
| Run unit tests | `uv run pytest tests/unit -q` |
| Run integration tests | `uv run pytest tests/integration` (boots ephemeral containers) |
| Run e2e tests | `uv run pytest tests/e2e` (requires `docker compose up` running) |
| Run adversarial suite | `uv run pytest tests/adversarial` (release-blocking) |
| Lint + format check | `uv run ruff check . && uv run black --check .` |
| Type check | `uv run mypy src/` |
| Local stack up | `docker compose up -d` |
| TUI conversation | `alfred chat` |
| Inspect state | `alfred status`, `alfred audit log`, `alfred audit graph --since 24h` |
| Inspect a user's memory | `alfred memory show <user>` |
| Cost report | `alfred cost report --since 7d --by persona` |

If a command does not yet exist, that's a signal it needs to be implemented — flag it.

## How to work in this repo

### Process

1. **Read the PRD before structural changes.** If a change conflicts with the PRD, propose updating the PRD first.
2. **Use ADRs for architectural decisions.** New ADR in `docs/adr/NNNN-title.md` whenever you change a structural invariant.
3. **TDD where practical** — write a failing test, then make it pass. Especially for security boundaries.
4. **Small PRs.** One responsibility per PR. Reviewer (human or agent) should be able to hold the change in their head.
5. **Verify before claiming done.** Run the relevant test layer; do not assert "this works" without running it.

### Coding conventions

- **Single responsibility, narrow interfaces.** A module's public surface is small; internals are not exported.
- **DRY across skills/plugins** via shared utilities. Reviewer rejects copy-paste reimplementations.
- **SOLID applied with judgment** — no premature abstractions; refactor on the second duplication, not the first.
- **Strict typing.** No `Any` without justification. Pydantic models at all serialization boundaries.
- **Async-first** in the core. Avoid blocking calls in async code.
- **No global state.** Pass dependencies explicitly.
- **Comments only when WHY is non-obvious** — name things well so WHAT doesn't need a comment.
- **Karpathy guidelines** — surgical changes, surface assumptions, verifiable success criteria. (See `andrej-karpathy-skills:karpathy-guidelines` skill.)

### Tests

- **Every skill** must ship with: happy-path test, error-path test, out-of-scope refusal test.
- **Every security boundary** must have 100% line and branch coverage (input tagging, capability gate, DLP, secret broker, audit writes).
- **Integration tests** use real Postgres/Redis/Qdrant via testcontainers; LLM responses are recorded fixtures except in `tests/e2e/`.
- **Adversarial tests** are release-blocking. If you change anything in `src/alfred/security/`, you must run the full adversarial suite locally.

## Security rules — HARD

These rules override everything else. Violating them is a release blocker.

1. **Never log secrets.** Use the redactor on every log path. Tests verify this.
2. **Never bypass the tool capability layer.** Even in tests, do not stub it to "always allow." Use a fixture grant.
3. **Always tag input trust tier.** Every function that ingests external content (web, email, file, MCP tool output) tags it `T3` at the boundary. No exceptions.
4. **DLP is on by default and cannot be disabled per-call.** Pure-internal tools can declare "no DLP needed" once in their manifest and the test suite verifies the claim.
5. **The privileged orchestrator never sees raw T3 content.** Only the quarantined LLM does, and only via the structured-extraction path.
6. **Secrets live in the broker, not in env vars accessible to plugins.** Plugins request secret IDs; the broker substitutes at the tool-call boundary.
7. **No silent failures in security paths.** Failed DLP, failed capability check, canary trip → loud audit entry + alert + (where appropriate) quarantine.
8. **No skipping pre-commit hooks** with `--no-verify`. If a hook fails, fix the issue.

## Internationalization rules — HARD

i18n is baked in from Slice 1 because retrofitting it later is materially harder. Violating these is a release blocker.

1. **All operator-/user-facing strings go through `t()`.** Hardcoded English in `src/alfred/` outside the catalog source files is a release blocker. CLI output, TUI text, error messages, log messages destined for an operator's eyes — all `t()`.
2. **Persona system prompts honour `{user.language}`.** Every persona prompt template includes the user's language; the orchestrator substitutes the active user's language before each provider call.
3. **Every stored user content row has a `language` field.** `episodes`, `audit_log`, `semantic_facts` — anything that holds user text — carries a BCP-47 language tag.
4. **`pybabel extract` runs in pre-commit; `pybabel compile --check` runs in CI.** Catalog drift fails the build.
5. **Doc files stay English-only.** PRD, CLAUDE.md, ADRs, agent definitions, skill definitions. Localizing contributor docs is out of scope.

## Self-improvement rules

When you (the AI agent, future-you, or another agent) propose modifying Alfred itself:

1. **Reviewer-gated changes go through the proposal flow.** Branch `proposal/<id>` in `/var/lib/alfred/state.git`. Auto-generated tests. Sandboxed test run. Reviewer agent review. Merge on approval.
2. **Plugin install/remove requires additional human approval.** Not just the reviewer.
3. **Never edit `personas/`, `skills/`, or security policy on `main` directly** at runtime. Always via the proposal flow.
4. **Editing this `CLAUDE.md` or `PRD.md` is human-gated.** AI agents propose changes; humans approve.

## Memory etiquette

Two separate memory systems exist:

- **Alfred's runtime memory** is per-user, in Postgres + Qdrant. Managed by `src/alfred/memory/`. Do not touch outside that module.
- **Project memory (AI working memory)** for AI agents helping build Alfred lives in `~/.claude/memory/projects/alfred/` (canonical). Symlinked from the cwd-keyed location when this is a git repo. Writes go through `~/.claude/memory/bin/memory-write`, never direct Write/Edit.

When you learn something about the project, the user, or how to work here that future sessions will benefit from — write it to the right canonical file via the `/memory` skill.

## When you get stuck

1. Re-read the PRD section that covers what you're doing.
2. Look for an ADR that explains the decision.
3. Check `docs/superpowers/specs/` for design docs.
4. Use the `superpowers:brainstorming` skill before any creative work.
5. Use the `superpowers:systematic-debugging` skill before any bug fix.
6. Use the `superpowers:test-driven-development` skill before any feature.
7. Use the `superpowers:verification-before-completion` skill before claiming done.
8. Ask the user. Don't make decisions you cannot defend.

## Do not

- Do not commit secrets, even to `.env.example`. Use placeholders.
- Do not edit `/var/lib/alfred/state.git` directly — only via the proposal flow.
- Do not weaken security defaults to make tests pass. Fix the test or the design.
- Do not introduce new datastores without an ADR.
- Do not add a fourth-party dependency without justification in the PR description.
- Do not silently catch exceptions in security paths.
- Do not skip the adversarial suite if you touched `src/alfred/security/`.

## Reference

- **PRD:** [`PRD.md`](./PRD.md) — the design
- **License:** Apache-2.0
- **Issue tracker:** (set at repo creation)
- **CI:** GitHub Actions; nightly adversarial run is release-blocking
