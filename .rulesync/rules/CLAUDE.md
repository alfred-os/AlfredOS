---
root: true
targets:
  - '*'
globs:
  - '**/*'
---
# CLAUDE.md — AlfredOS Repo Operating Manual

This file is loaded by AI agents working in this repository. Read it before doing anything.

## What this is

**AlfredOS** is a multi-user, multi-persona, security-hardened agentic OS. Self-hostable. Licensed under **Apache-2.0**. **Alfred** (no "OS") is the name of the default persona that ships enabled.

Full design: see [`PRD.md`](./PRD.md). Read it before proposing any architectural change.

## Where things live

```
AlfredOS/
├── PRD.md                          # the design — source of truth for *what* and *why*
├── CLAUDE.md                       # this file — operating manual for AI agents
├── README.md                       # user-facing quickstart
├── LICENSE                         # Apache-2.0
├── NOTICE                          # copyright + third-party attributions
├── CODE_OF_CONDUCT.md              # Contributor Covenant 2.1
├── CONTRIBUTING.md                 # how to contribute
├── SECURITY.md                     # vulnerability reporting
├── docker-compose.yaml             # default deployment
├── bin/                            # CLI + setup scripts (alfred-setup.sh, alfred-setup.ps1, alfred-plugin-launcher.sh, alfred-state-git-seed.sh)
├── src/alfred/                     # Python core
│   ├── core/                       # orchestrator, loop, plugin registry, event bus
│   ├── personas/                   # persona registry & routing
│   ├── memory/                     # 6-layer memory subsystem
│   ├── security/                   # trust tiers, DLP, secret broker, capability gate
│   │   └── capability_gate/        # RealGate, GatePolicy, GrantRow, StorageBackend
│   ├── plugins/                    # MCP plugin transport, session, manifest, content store
│   ├── supervisor/                 # plugin supervisor, circuit breaker (Slice 3+)
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
│   ├── smoke/                      # end-to-end happy path against a running stack
│   └── adversarial/                # MUST-PASS security suite — see PRD §8.1
└── docs/
    ├── adr/                        # Architecture Decision Records
    ├── glossary.md                 # single vocabulary source — every system-specific term defined once here, linked elsewhere
    ├── runbooks/                   # operator-facing deployment walkthroughs (e.g. slice-2-discord-smoke.md)
    ├── subsystems/                 # per-subsystem deep-docs — hub-and-spoke, one file per subsystem
    │   ├── identity.md             # identity / multi-user / IdentityResolver / canonical user id
    │   ├── comms.md                # CommsAdapter / DiscordAdapter / OutboundDlp / RateLimiter
    │   ├── hooks.md                # hookpoints, hook kinds, hook tiers, dispatcher
    │   ├── security.md             # trust tiers (T0-T3), nonce gate, capability gate (Slice 3)
    │   ├── plugins.md              # MCP transport, StdioTransport, session lifecycle (Slice 3)
    │   ├── supervisor.md           # plugin supervisor, circuit breaker, action-deadline (Slice 3)
    │   └── quarantine.md           # dual-LLM split, T3 structured extraction, ContentHandle (Slice 3)
    └── superpowers/specs/          # design docs (this is the path the brainstorming skill expects)
```

**Runtime state lives outside the repo** at `/var/lib/alfred/state.git`. The agent commits its proposed self-modifications there; the reviewer agent reviews; merges activate. Never commit runtime state into the source repo.

## Tech stack

- **Language (core):** Python 3.12+
- **Async runtime:** asyncio
- **Plugins:** MCP (stdio for in-process, HTTP for remote) — polyglot
- **Datastores:** Postgres 16 (+ pgvector), Redis 7, Qdrant
- **Containerization:** Docker + Docker Compose
- **Type system:** Pydantic v2 for data models; `mypy --strict` (primary) + `pyright` (secondary) for the core
- **Test framework:** pytest + testcontainers + custom adversarial harness
- **Observability:** structlog + Prometheus client + OpenTelemetry
- **Lint/format:** `ruff check` + `ruff format` (replaces black; see [`docs/python-conventions.md`](./docs/python-conventions.md))
- **Type-check (secondary):** `pyright` alongside mypy
- **Property tests:** `hypothesis` (where the function has a property you can state in one sentence)
- **Package manager:** uv

## Commands you should know

The **Available** column names the slice in which the command first
shipped. `Slice 4+` rows are planned but not yet implemented — the
binary will surface them as `TypedRefusal(reason="not_implemented")`
or `--help` will simply not list them; do not assume them present.

| Purpose | Available | Command |
| --- | --- | --- |
| Set up dev environment | Slice 1 | `bin/dev-setup.sh` (creates `.venv`, installs deps, pulls test fixtures) |
| Run unit tests | Slice 1 | `uv run pytest tests/unit -q` |
| Run integration tests | Slice 1 | `uv run pytest tests/integration` (boots ephemeral containers) |
| Run smoke tests | Slice 1 | `uv run pytest tests/smoke` (requires `docker compose up` running) |
| Run adversarial suite | Slice 1 | `uv run pytest tests/adversarial` (release-blocking) |
| Lint + format check | Slice 1 | `uv run ruff check . && uv run ruff format --check .` |
| Type check | Slice 1 | `uv run mypy src/ && uv run pyright src/` |
| All quality gates | Slice 1 | `make check` (lint + format + type + test) |
| Local stack up | Slice 1 | `docker compose up -d` |
| TUI conversation | Slice 1 | `alfred chat` (dials the running gateway) |
| Gateway (comms front door) | Slice 4 | `alfred gateway start` · `status` · `adapters` · `healthcheck` |
| Gateway egress state | Spec C | `alfred gateway egress` — reports inflight counts, deny-reason breakdown, and static allowlists per egress plane (proxy / relay / adapter); exit 2 on metrics unavailable |
| Status snapshot | Slice 1 | `alfred status` |
| Inspect audit log/graph | Slice 3 | `alfred audit log` / `alfred audit graph --since 24h` |
| Inspect a user's memory | Slice 4+ (planned) | `alfred memory show <user>` |
| Cost report | Slice 4+ (planned) | `alfred cost report --since 7d --by persona` |
| Manage users | Slice 1 | `alfred user add` · `list` · `show` · `set` · `remove` · `bind` · `unbind` (see ADR-0010) |
| Plugin management | Slice 3 | `alfred plugin grant <id> <tier> <hookpoint>` · `alfred plugin grant status <id>` · `alfred plugin grant list --pending` · `alfred plugin revoke <id>` (`alfred plugin list` / `show` hidden from `--help` per arch-006 follow-up) |
| Web fetch allowlist | Slice 3 | `alfred web allowlist add <domain>` · `alfred web allowlist remove <domain>` · `alfred web allowlist list` |
| Config (reviewer-gated + direct) | Slice 3 | `alfred config set <key> <value>` (high-blast keys queue a state.git proposal; low-blast keys write `policies.yaml` directly) · `alfred config get <key>` · `alfred config list` — see `alfred config set --help` for the closed key set (`quarantined-provider`, `web-fetch-budget`, `operator-fetch-budget`, `extraction-max-retries`, `action-deadline`, `user-agent`) |
| Supervisor | Slice 3 | `alfred supervisor status` · `alfred supervisor reset <component> --confirm` · `alfred supervisor proposals [--since DURATION] [--limit N] [--all]` |
| Audit (extended) | Slice 3 | `alfred audit graph --tier T0/T1/T2/T3 --since 24h` |

If a command lacks a slice marker, flag it. Commands
marked `(planned — Slice N+)` are scheduled — do NOT implement ahead of
slice (slice plans schedule WHEN each piece lands; CLAUDE.md and the PRD
are aspirational on overall command surface).

## How to work in this repo

### Process

1. **Read the PRD before structural changes.** If a change conflicts with the PRD, propose updating the PRD first.
2. **Use ADRs for architectural decisions.** New ADR in `docs/adr/NNNN-title.md` whenever you change a structural invariant.
3. **TDD where practical** — write a failing test, then make it pass. Especially for security boundaries.
4. **Small PRs.** One responsibility per PR. Reviewer (human or agent) should be able to hold the change in their head.
5. **Verify before claiming done.** Run the relevant test layer; do not assert "this works" without running it.

### Coding conventions

**Python work — use the [`alfred-python-developer`](./.rulesync/subagents/alfred-python-developer.md) subagent.** It applies the full conventions in [`docs/python-conventions.md`](./docs/python-conventions.md) without being asked: modern Python 3.12+ idioms, SOLID + FP, Pydantic v2, SQLAlchemy 2.0 typed, async-first, strong typing (mypy strict + pyright), hypothesis property tests, structlog with redaction.

The headline rules — restated here so they're impossible to miss:

- **Single responsibility, narrow interfaces.** A module's public surface is small; internals are not exported.
- **DRY across skills/plugins** via shared utilities. Reviewer rejects copy-paste reimplementations.
- **SOLID applied with judgment** — no premature abstractions; refactor on the second duplication, not the first.
- **Strong typing.** No `Any` without justification. Pydantic models at all serialization boundaries. `mypy --strict` + `pyright`.
- **Modern Python 3.12+.** PEP 604 unions (`X | Y`), PEP 585 built-in generics, PEP 695 generic syntax. Never `Optional[X]` or `typing.List`.
- **Immutability by default.** Frozen dataclasses, frozen Pydantic, `Mapping` over `dict` for read-only inputs.
- **Pure functions for transformations; classes for stateful machines.** Functional core, imperative shell.
- **Async-first** in the core. Avoid blocking calls in async code. Structured concurrency via `asyncio.TaskGroup`.
- **No global state.** Pass dependencies explicitly.
- **Errors loud at boundaries, structured inside.** No `except Exception: pass`. Custom exception hierarchy rooted at `AlfredError`.
- **Comments only when WHY is non-obvious** — name things well so WHAT doesn't need a comment.
- **Karpathy guidelines** — surgical changes, surface assumptions, verifiable success criteria. (See `andrej-karpathy-skills:karpathy-guidelines` skill.)

### Tests

- **Every skill** must ship with: happy-path test, error-path test, out-of-scope refusal test.
- **Every security boundary** must have 100% line and branch coverage (input tagging, capability gate, DLP, secret broker, audit writes).
- **Integration tests** use real Postgres/Redis/Qdrant via testcontainers; LLM responses are recorded fixtures except in `tests/smoke/`.
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
9. **The gateway is the sole external egress plane; the core is connectivity-free (Spec C).** Never open an external socket directly from core `src/alfred/` code — provider/tool/adapter egress routes through the gateway L7 CONNECT forward-proxy (default-deny destination allowlist, refuse-literal-IP, gateway-side DNS, reject-non-globally-routable-resolved-IP, audit every CONNECT). The core builds provider SDK clients with a proxied `httpx.AsyncClient` via the `EgressClient` seam; the in-core HTTP-egress import-guard forbids new direct provider-SDK / alt-HTTP-lib / `httpx` client construction. A proxy bind failure is fail-closed (the gateway refuses to start). Spec C mechanism complete (G7-0..G7-4 merged, G7-3 `internal:true` connectivity-free cutover done); see [ADR-0040](docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md) for the full two-layer enforcement model and accepted residuals.

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

**First-run seed (Slice 3+):** every `alfred plugin grant`, `alfred web allowlist add/remove`, and the reviewer-gated (high-blast) keys of `alfred config set` write a proposal branch to `/var/lib/alfred/state.git` (low-blast `config set` keys write `policies.yaml` directly per the command table above). If the repo doesn't exist yet, `bin/alfred-setup.sh` runs `bin/alfred-state-git-seed.sh` inside the `alfred-core` container, which is just `git init --bare /var/lib/alfred/state.git` + a seeded `main` branch. Safe to re-run; idempotent. If you see `bootstrap.capability_gate_unseeded` at startup, run the seed script.

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
