# AlfredOS — Product Requirements Document

| | |
| --- | --- |
| **Project** | AlfredOS |
| **Tagline** | An open-source, self-hostable, multi-user, multi-persona, security-hardened agentic OS. |
| **Status** | Draft v0.1 — pre-implementation |
| **Owner** | 4990954+MrReasonable@users.noreply.github.com |
| **Last updated** | 2026-05-24 |
| **License** | Apache-2.0 |

> **Naming convention.** **AlfredOS** is the product / runtime / GitHub repo. **Alfred** is the name of the default persona that ships enabled. Other personas (Lucius, Oracle, Diana, …) are specialists. Throughout this document, "AlfredOS" refers to the OS itself; "Alfred" refers to the default persona; "an AlfredOS household" refers to a particular deployment.

---

## 1. Executive Summary

AlfredOS is a self-hostable agentic operating system: an always-on runtime that hosts one or more AI **personas** (agents specialized to particular purposes), gives them shared multi-layered memory of their users, lets them coordinate with each other, and lets them extend themselves with new skills under a reviewer-gated change process. AlfredOS speaks to users through pluggable communication adapters (Discord, Telegram, TUI for MVP; Slack, WhatsApp, voice post-MVP) and is hardened from day one against prompt injection, credential leakage, and PII exfiltration.

AlfredOS is **fully autonomous** (an OODA-style continuous loop) but **bounded** — every action is audited, every change is gated, every cost is budgeted, every output is scanned for leaks, and every component can be rolled back via an internal git repository.

The default persona is **Alfred** — the head butler — but operators can enable specialists (research, communication, knowledge retrieval) and AlfredOS itself can propose new personas when usage patterns warrant.

**Licensing model.** AlfredOS is released under the **Apache License 2.0**. The choice prioritises frictionless adoption by organisations of any size — Apache 2.0 is the de facto enterprise-friendly OSS license, with an explicit patent grant (§3) that gives users defensive protection against patent claims from contributors. Plugins communicate with the core via the MCP subprocess boundary (stdio / HTTP), are not considered derivative works, and may be licensed however their authors choose.

The trade-off versus a copyleft licence (AGPL) is that we accept the possibility of third-party forks: anyone may take AlfredOS, modify it (including in ways that weaken its security guarantees), and redistribute it. The mitigations are non-legal: the AlfredOS trademark protects the canonical name; signed releases let users verify they are running the upstream version; brand and community trust differentiate the maintained-secure distribution from any variants. We consider this a better trade than gating enterprise adoption.

## 2. Mission & Vision

**Mission:** Make running your own multi-persona AI household practical, safe, and extensible. A user should be able to converse with their AI staff across the messaging platforms they already use, trust that the system will not leak their secrets or fall for a poisoned web page, and watch the system get better at serving them over time.

**Non-mission:** Alfred is not a chatbot framework, a model trainer, or a one-shot agent. It is a long-lived household.

**Vision (post-MVP):** A reference deployment that an enthusiast can spin up on a NAS in 10 minutes; a marketplace of signed persona bundles and skills; a path to hosted multi-tenant offerings; mobile and voice as first-class surfaces.

## 3. Primary Users & Use Cases

**Primary user (MVP):** A self-hoster running Alfred for themselves, their family, or their team. Comfortable with Docker. Wants a persistent AI presence that remembers them, can be talked to from any of their existing chat apps, and can take real actions on their behalf with strong safety rails.

**Day-1 use cases the MVP must support:**

1. **Continuous conversation across sessions** — message Alfred on Discord on Monday, follow up on Telegram on Thursday, expect coherent continuity.
2. **Multi-user isolation** — multiple users in the same Discord server, each gets a private memory, none can read another's facts.
3. **Skill creation on request** — "Alfred, please write a skill that pulls my GitHub notifications every morning" → proposal → tests → reviewer gate → live skill.
4. **Persona handoff** — "Alfred, ask Lucius to research X" → handoff with announcement → Lucius answers → user can continue with either.
5. **Group session** — `@alfred @lucius @diana help me plan a trip` → all three join, Alfred moderates, group transcript is shared episodic memory.
6. **Background coordination** — without explicit prompting, Pepper-equivalent updates Alfred about a scheduled event; Alfred surfaces it to the user proactively (rate-limited, budget-bounded, audit-visible).
7. **Rollback** — user runs `alfred rollback <commit>` to undo a skill or a memory consolidation pass.
8. **Adversarial robustness** — a poisoned web page or email cannot exfiltrate a credential or PII; verified by the adversarial test suite.

## 4. Success Criteria — MVP (v0.1)

Each criterion is binary; all must pass for v0.1.

1. **Onboarding:** `git clone && bin/alfred-setup.sh && docker compose up` brings up a working stack on macOS, Linux, or Windows-via-WSL.
2. **Cross-platform identity:** A user authenticated via Discord and Telegram is correctly bound to one user identity, and their semantic memory persists across both.
3. **Continuous loop:** Alfred runs the OODA loop continuously without runaway cost; per-user daily token budget is enforced.
4. **Self-improvement, end-to-end:** A user can request a new skill; the agent proposes; tests are auto-generated and run; the reviewer agent (different provider) approves or rejects; on approval, skill activates without restart.
5. **Persona system, end-to-end:** Alfred handles a request; Alfred hands off to Lucius; Lucius answers; group session with both works; background coordination event from one to the other is logged and visible in `alfred audit graph`.
6. **Security:** The adversarial suite passes — prompt-injection corpus, DLP corpus, capability-bypass corpus, canary-trip suite, inter-persona-poisoning suite all green.
7. **Rollback:** `alfred rollback <commit>` reverts a skill or memory change, verified by automated test.
8. **Audit:** Every tool call, every memory write, every reviewer decision is in the audit log and queryable.
9. **Observability:** The default Grafana dashboard shows tokens-by-tier-and-persona, cache hit rates, plugin error rates, and security events.

## 5. Architecture Overview

```
                ┌─────────────────────────────────────────────────────┐
                │                       USER                          │
                │  Discord    Telegram    TUI    (Slack/WA post-MVP)  │
                └────────┬───────────┬───────┬────────────────────────┘
                         │           │       │
        ┌────────────────▼───────────▼───────▼──────────────────┐
        │     COMMS ADAPTERS  (MCP plugins, per platform)        │
        │  - Auth & identity binding   - Rate limit per user     │
        │  - Untrusted-content tagging - Outbound DLP scan       │
        └──────────────────────────┬─────────────────────────────┘
                                   │ gateway socket transport (Spec A/B)
        ┌──────────────────────────▼─────────────────────────────┐
        │             AGENTIC CORE (Python 3.12+)                 │
        │                                                         │
        │  ┌──────────────────────────────────────────────────┐   │
        │  │   PERSONA ROUTER (addressing / group session)    │   │
        │  └──────┬────────────────────────────┬──────────────┘   │
        │         │                            │                  │
        │  ┌──────▼──────────┐         ┌──────▼─────────────┐     │
        │  │ Privileged      │         │ Quarantined LLM    │     │
        │  │ Orchestrator    │         │ (T3 content only,  │     │
        │  │ (per persona,   │◄────────│  emits structured  │     │
        │  │  sees T0–T2)    │         │  data, no tools)   │     │
        │  └──────┬──────────┘         └────────────────────┘     │
        │         │                                               │
        │  ┌──────▼──────────────────────────────────────────┐    │
        │  │ Tool Layer + Capability Gate + Secret Broker    │    │
        │  └──────┬──────────────────────────────────────────┘    │
        │         │                                               │
        │  ┌──────▼──────────────────────────────────────────┐    │
        │  │ Plugins (MCP):  skills | memory backends |      │    │
        │  │                 integrations | reviewer agent   │    │
        │  └──────────────────────────────────────────────────┘   │
        │                                                         │
        │  ┌──────────────────────────────────────────────────┐   │
        │  │ Inter-persona bus (typed messages, budgeted,     │   │
        │  │ loop-detected, trust-tier-aware)                 │   │
        │  └──────────────────────────────────────────────────┘   │
        └─────────────────────────────┬───────────────────────────┘
                                      │
        ┌─────────────────────────────▼──────────────────────────┐
        │   MEMORY:  working  episodic  semantic  vector  graph  │
        │   STATE:   Postgres + Redis + Qdrant + internal git    │
        │   AUDIT:   append-only signed log                      │
        │   SECRETS: broker — LLM never sees values              │
        └─────────────────────────────────────────────────────────┘
```

**Architectural invariants (non-negotiable, baked into every component):**

- **Plugins are MCP servers.** Comms adapters, skills, memory backends, integrations, and the reviewer agent are all MCP servers — stdio for in-process, HTTP for remote.
- **Hybrid isolation.** Plugins declare a trust tier; official → in-process subprocess; third-party or agent-authored → containerized with declared capabilities (network allowlist, fs mounts, secret IDs). **Slice 3 relaxation:** the quarantined-LLM plugin runs as a dedicated-UID subprocess with env scrubbing rather than a container — a time-bounded deviation recorded in [ADR-0017](docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md). Full containerisation lands in Slice 4 per [ADR-0015](docs/adr/0015-slice4-containerised-quarantined-llm.md).
- **Internal git repo at `/var/lib/alfred/state.git`** holds: skills, persona definitions, prompt/persona configs, routing config, security policy. The agent commits proposed changes to `proposal/*` branches; the reviewer agent reviews; merged commits become active. Rollback is `git revert`.
- **The LLM never holds secrets.** The secret broker substitutes values at the tool-call boundary; the LLM sees opaque references (`{{secret:gmail_oauth}}`).
- **Dual-LLM split.** The privileged orchestrator never processes raw T3 content; the quarantined LLM is the only consumer of T3 content and can only emit structured data.
- **Every action is hookable.** Every unit of work the agentic core dispatches — tool calls, provider calls, memory writes, comms outbounds, consolidation passes, audit writes, inter-persona messages, skill invocations — is registered with a hookable interface (pre / post / error / cancel). Hook registration is plugin-scoped and capability-gated; hook ordering is deterministic (system tier → operator tier → user-plugin tier, registration order within tier). Detail in §5.1; ADR-0014 carries the rationale and the slice-placement decision.
- **Gateway as external I/O plane (from Spec B / Spec C).** Comms adapters are hosted in the gateway container (Spec B, [ADR-0036](docs/adr/0036-gateway-adapter-hosting-inversion.md)). The gateway is the sole external egress plane for all outbound network I/O: provider calls, tool-egress, and adapter-egress all route through the gateway's L7 CONNECT forward-proxy (Spec C, [ADR-0040](docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md)).
- **Connectivity-free core (from Spec C / G7).** `alfred-core` runs on an isolated internal network (`internal: true`); it cannot open external sockets. The kernel enforces this without application-level cooperation. See [ADR-0040](docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md).

### 5.1 Hookable actions

Plugins, the operator, and AlfredOS core components extend the system by registering **hooks** on actions other components take. The four hook kinds are:

- **Pre-action** — observes or mutates the input before the action runs; may refuse the action (typed `HookRefusal`).
- **Post-action** — observes or mutates the result after the action succeeds.
- **Error** — observes the exception when the action raises; may swallow and replace with a synthesised result.
- **Cancel** — runs cleanup on `asyncio.CancelledError`; cannot suppress the cancellation.

Every action carries up to four hook chains, one per kind. Each chain is ordered by capability tier (**system**, **operator**, **user-plugin**) and by registration order within tier. Pre-action chains short-circuit on first refusal; the refusal is itself an event the error chain and the audit log observe.

Plugin authors register hooks via the MCP protocol (a `hooks` block in the plugin manifest declares `(action, kind)` tuples) or via an in-process Python decorator for in-tree plugins. Both paths route through the same capability-gated registry; a plugin without the `hook.<action-name>` capability is refused at load time.

Hooks coexist with the event bus: the event bus stays the observation-only surface for components that do not need to mutate or refuse, hooks are the synchronous in-band interception surface. Hooks coexist with the audit log: every hook invocation is itself auditable, keyed to the originating action's correlation ID.

**Status — planned for Slice 2.5** (between Slice 2's identity/Discord/secret-broker scope and Slice 3's MCP-transport + T1/T3 rewrite). ADR-0014 records the decision, alternatives considered (event-bus-only, MCP-only, AOP decorators, retrofit into Slice 2, defer to Slice 3), and the performance + security consequences. Final slice placement is the architect's call at Slice-2 graduation planning.

## 6. Capability Pillars

### 6.1 Multi-modal Comms

**MVP adapters:** Discord, Telegram, TUI.
**Post-MVP:** Slack, WhatsApp, voice (STT/TTS), email.

**Adapter contract:** Each adapter is an MCP plugin that:

- Authenticates with its platform (bot token, OAuth, etc.).
- Maps platform identities to Alfred's canonical `user_id` (first-contact binding flow; cross-platform binding via a verification code).
- Tags inbound content with trust tiers (user message body → T2; web previews, link unfurls, forwarded content → T3).
- Maps Alfred's three addressing modes to platform idioms (mentions, channels, slash-commands).
- Routes outbound through the DLP scanner before send.
- Enforces per-user rate limits.

**Identity binding:** First message from `discord:user#1234` triggers a first-contact handshake — Alfred asks for a verification phrase that can be set up via TUI by the operator, or links to an existing user if the operator has pre-mapped accounts. Cross-platform: a user already known on Discord can bind a Telegram identity by sharing a one-time code.

### 6.2 Multi-layered Memory

| Layer | Purpose | Store | Persona scope |
| --- | --- | --- | --- |
| **Working memory** | Active turn buffer (~2k words) | Redis | Per-persona-per-user |
| **Episodic log** | Raw conversation transcript | Postgres | Per-persona-per-user (+ shared group sessions) |
| **Summarized episodes** | Narrative summaries of notable events | Postgres | Per-persona-per-user |
| **Semantic facts** | Distilled facts about the user | Postgres | Shared across personas, per-user, source-attributed |
| **Vector / contextual** | Embedded chunks of episodes, facts, ingested docs | Qdrant | Shared, with optional persona-scoped views |
| **Knowledge graph** | Entities + relations (people, projects, concepts) | Postgres (ltree + recursive CTEs) | Shared, degradable |

**Auto-save:** A **consolidation pass** runs as a background job after every conversation ends (idle timeout or explicit close). It summarizes the episode, extracts new facts, updates the graph, re-embeds where needed. Runs on a cheap-tier model and is itself budget-bounded.

**Auto-query:** Before every inbound message reaches the orchestrator, an **auto-retrieve step** queries vector + graph + facts for the active user and persona, and injects top-k into the prompt's cacheable prefix.

**User control:** Every memory write commits to the internal git repo with attribution. Users can:

- `alfred memory show <user>` — view their entire memory
- `alfred memory forget <fact-id>` — delete a fact
- `alfred memory rollback <commit>` — undo a consolidation pass
- Operator can configure per-user retention policies

### 6.3 Agentic Skills & MCP Integration

**MCP is the universal plugin protocol.** Every capability beyond the core orchestrator is an MCP server:

- **Skills** (procedural how-to plugins) — what the agent can *do*
- **Memory backends** — how memory is stored and queried
- **Integrations** — Google Workspace, GitHub, Linear, etc.
- **Reviewer agent** — itself an MCP server, ideally a different provider

**Skill registry** lives in the internal git repo at `skills/<name>/` with:

- `manifest.json` — name, version, capabilities required, trust tier, dependencies
- `skill.{py,ts,go,...}` — the implementation (polyglot)
- `tests/` — happy-path, error-path, out-of-scope refusal
- `README.md` — agent-readable description of when to invoke

**Skill lifecycle:**

1. Agent proposes a skill (or operator/user adds one)
2. Proposal lands in `proposal/skill-<id>` branch
3. Tests run in sandbox
4. Reviewer agent reviews diff + tests
5. On approval → merge to `main` → hot reload → metrics watched for first N invocations

**Engineering rules the agent must follow when authoring skills:**

- One clear purpose per skill (single responsibility).
- All side-effecting tools parameterized with capability requirements declared up front.
- Mandatory tests: happy-path, error-path, refusal-when-out-of-scope.
- No global state; idempotent where possible.
- DRY across skills via a shared utilities module; reviewer rejects copy-paste reimplementations.
- Apply SOLID and the Karpathy guidelines (surgical changes, surface assumptions, verifiable success criteria).

### 6.4 Self-Improvement with Reviewer Gate

**Gated change types (all four are gated):**

1. Skills — create / modify
2. Prompt / persona / routing rules
3. Memory schema and consolidation rules
4. Plugin install/remove — reviewer + **explicit human approval**

**Flow:**

```
Agent proposes change
   │
   ▼
Branch `proposal/<id>` in /var/lib/alfred/state.git
   │
   ▼
Auto-generate tests (skill proposals get a pytest harness with mocked tools)
   │
   ▼
Run tests in sandboxed container
   │  (fail → reject, capture report, surface to operator)
   ▼
Reviewer agent (different provider) reads diff + tests + proposal rationale
   │
   ├─ approve  → merge to main + hot-reload
   ├─ request changes → bounce back to agent with feedback (max N iterations)
   └─ reject   → close proposal, log decision, notify operator
                 (plugin install: also requires explicit human approval here)
   ▼
Audit log gets the full proposal + decision chain
```

**Reviewer agent requirements:**

- Runs on a different provider from the primary by default (cross-provider so a single jailbreak does not compromise both sides).
- Sees only the diff + tests + rationale, never the original conversation that produced the proposal (diff-only review minimizes attack surface).
- Can reject, request changes (with bounded iteration count), or escalate to operator.
- Reviewer's own behavior is also reviewer-gated (changes to the reviewer's prompt go through a meta-review by the same agent under stricter rules).

### 6.5 Token Caching & Cost Control

**Four caching layers, all MVP:**

1. **Provider prompt caching** — Anthropic / OpenAI native. Persona system prompt + tool definitions + retrieved memory prefix marked as cache-control. Expected hit rate > 90% on conversational turns.
2. **Semantic response cache** — Redis. Keys are `(tier, embedding-hash(prompt))`; values include response + TTL + `cacheable` flag. Skipped for high-stakes tools and security-sensitive paths.
3. **Context compression / sliding-summary** — when context exceeds the model's effective budget, a cheap-tier summarizer compacts older turns. Summaries themselves get cached.
4. **Embedding cache** — `sha256(text) → embedding` in Postgres. Eliminates re-embedding identical chunks.

**Budget enforcement:**

- Per-user daily token budget (default + per-user override).
- Per-task max cost ceiling.
- Per-persona daily coordination budget (caps non-user-facing chatter).
- When a budget is exhausted, the loop pauses and the operator is notified.

### 6.6 AI Platform Integration

**Tiered routing with capability fallback:**

```yaml
# config/routing.yaml (sketch)
tiers:
  cheap-classifier:   { provider: anthropic, model: claude-haiku-4-5 }
  conversation:       { provider: anthropic, model: claude-sonnet-4-6 }
  deep-reasoning:     { provider: anthropic, model: claude-opus-4-7 }
  code-gen:           { provider: anthropic, model: claude-sonnet-4-6, capabilities: [tool_use] }
  vision:             { provider: openai,    model: gpt-4o-mini,        capabilities: [vision] }
  reviewer:           { provider: openai,    model: gpt-5-thinking }    # different provider

fallback_chain:
  - prefer:  primary
  - require: capabilities-match
  - then:    cheapest-capable

internal_clis:                      # optional: route via local CLI subagents
  - name: claude-code
    invoke: "claude --print --output-format=stream-json"
    use_for: [heavy-coding-task]
    isolation: container
```

**Provider plugin contract:** Each provider is an MCP plugin that exposes:

- `complete(prompt, params) -> response`
- `embed(text) -> vector`
- `capabilities() -> [vision, tool_use, 1M-context, ...]`
- `cost(prompt, response) -> usd`
- `cache_marker(prefix) -> handle` (for provider caching)

**Internal-CLI providers** (Claude Code, Codex, etc.) are wrapped as providers that spawn the CLI in a controlled environment, feed prompt via stdin, capture stdout. Useful for offloading heavy coding tasks to a subagent CLI.

### 6.7 Deployment & Setup

**Default deployment (single-host):**

```yaml
# docker-compose.yaml (sketch)
services:
  alfred-core:       # Python core
  alfred-postgres:   # Postgres 16 + pgvector
  alfred-redis:      # Redis 7
  alfred-qdrant:     # Qdrant
  alfred-reviewer:   # reviewer agent (different API key)
  # one container per containerized plugin (third-party / agent-authored)
```

**Setup script:**

- `bin/alfred-setup.sh` (POSIX; runs natively on macOS/Linux, in WSL on Windows)
- `bin/alfred-setup.ps1` (native PowerShell; calls into the POSIX script in WSL or sets up Docker Desktop on Windows)
- **Idempotent.** Safe to re-run.
- Generates `.env` with secrets prompted interactively (or from a sealed env file).
- Writes default `config/` tree.
- Creates Docker volumes with correct ownership for read/write separation:
  - User writes config in `~/.config/alfred/` (mounted RO into containers for runtime, RW for `alfred config edit`)
  - Alfred writes state to `/var/lib/alfred/` (owned by `alfred` user inside containers; user has read access but not write, except via `alfred ...` CLI commands which mediate writes)
- Initializes the internal git repo.

**Self-healing:**

- Each container has liveness + readiness probes; Compose restart-policy `unless-stopped`.
- Plugin supervisor in `alfred-core` restarts crashed plugin subprocesses with exponential backoff and a circuit breaker (3 crashes in 5 min → quarantine + notify).
- State is recoverable from Postgres + git repo; in-memory state is rebuildable.

**Checkpoints:**

- Periodic snapshot of (Postgres dump + Qdrant snapshot + git bundle) to a configured location.
- `alfred snapshot` + `alfred restore <id>` CLI.

**Scale path (designed for, not MVP-required):**

- `alfred-core` is stateless behind the event bus → replicable.
- Postgres → read replicas or managed.
- Redis → cluster mode.
- Qdrant → cluster mode.
- Reviewer is naturally horizontal.

### 6.8 Persona System

**Concepts:**

- A **persona** is a versioned config bundle: name, system prompt, character traits, capability allowlist, routing tier preferences, memory access policy, daily coordination budget.
- The **persona registry** lives in the internal git repo at `personas/<name>/`. Adding/modifying a persona is reviewer-gated.
- **Alfred** is the default persona (the head butler). Other personas are specialists.

**Addressing model:**

| Mode | How invoked | Behavior |
| --- | --- | --- |
| **Default** | DM to Alfred or unprefixed message | Alfred answers, or hands off (announcing the handoff) |
| **Direct** | `@lucius plan my week` or per-persona channel | Specialist answers directly; Alfred is silent unless asked |
| **Group** | `@alfred @lucius help me plan this trip` or `/group ...` | Multiple personas join one thread, moderated by Alfred (or first-addressed persona) |

**Group session rules:**

- Moderator tracks the floor; prevents stepping-on-each-other; summarizes when needed.
- Each persona's turn is bounded by a per-message token cap.
- Personas can decline to participate ("Pepper has nothing to add on this") to keep noise down.
- Group transcript becomes shared episodic memory for all participating personas.

**Background coordination (free, with safety rails):**

Coordination is free-form by design but bounded by these structural rails:

1. **Per-persona daily coordination budget** — token cap on non-user-facing messages per 24h.
2. **Loop detection** — message cycle A→B→A (or any cycle of length ≤ K) triggers a circuit breaker on that pair.
3. **Inter-persona trust tier** — sibling personas are T2 (trusted), but content originating from T3 stays T3 when relayed. A persona that says "the web page told me X" must mark X as T3, and the receiver's tool layer treats it as such.
4. **Stated purpose required** — every inter-persona message is structured: `{ from, to, purpose, content, refs }`. Reviewer rejects coordination patterns without clear purpose.
5. **Audit visualization** — `alfred audit graph --since 24h` renders a Graphviz of inter-persona traffic with token costs per edge.
6. **Convergence requirement** — an initiated coordination must close with a user-facing message or a structured "done" event within a configured budget; orphan coordinations are flagged.

**Persona-aware memory:** see §6.2.

**Starter persona pack** (bundled in `examples/personas/`, disabled by default, renameable):

| Persona | Specialty | Default tier | Capabilities |
| --- | --- | --- | --- |
| **Alfred** (default, enabled) | Coordination, routing, general assistance, household-management | conversation | Broad |
| **Lucius** | Research, deep reading, source-checking, technical analysis | deep-reasoning | Web fetch, doc readers, citation tools |
| **Oracle** | Information retrieval, knowledge-graph queries, cross-reference | conversation | Memory query, graph traversal, vector search |
| **Diana** | Communication drafting — emails, messages, social, tone-aware editing | conversation | Drafting tools, sentiment analysis, no send authority (Alfred or user sends) |

## 7. Cross-Cutting Concerns

### 7.1 Security & Prompt Injection Defense

This is foundational, not a feature. Alfred ingests T3 content (web pages, emails, RAG snippets, tool outputs, file contents) and must remain trustworthy.

**Trust tiers on every input:**

```
T0 system          — Alfred's own code, prompts, configs (highest trust)
T1 operator        — Person running the instance (can change config)
T2 authenticated   — Known users in their own scope; sibling personas
T3 untrusted       — Web pages, emails, MCP tool outputs, file contents, link previews
```

**Dual-LLM split:**

- **Privileged orchestrator** holds tools, executes actions, sees only T0–T2.
- **Quarantined LLM** is the only consumer of T3 content. It emits structured data (JSON with a schema) — never tool calls, never free text fed back as instructions.
- T3 content is spotlighted (delimited, sometimes encoded) so the orchestrator cannot accidentally process it as instructions.

**Tool-call enforcement (defense in depth):**

- Each tool has a capability manifest (network: allowlist, fs: paths, secrets: which IDs).
- Each conversation has a capability grant (what tools are in scope for this request).
- The tool layer refuses calls outside the grant, even if the LLM tries.
- **Step-up auth** required for high-blast actions (sending money, deleting data, accessing credentials, contacting people outside an allowlist): out-of-band confirmation via Telegram/Discord DM, not an in-conversation "yes".

**Outbound DLP:**

- Every outbound message (to user, to web, to plugin) passes through a redactor:
  - Regex patterns for known token formats (AWS, Stripe, OpenAI, JWT, GitHub, OAuth tokens, etc.)
  - Entropy detector for unknown secret-looking strings
  - NER for PII (names, emails, phone, addresses)
- Strictness configurable per channel (public Discord channel = strict; user's own DM = relaxed for their own info).

**Secret broker:**

- Secrets live in an encrypted vault. Default: age-encrypted file. Pluggable: HashiCorp Vault, AWS Secrets Manager, OS keychain.
- LLM sees opaque references: `{{secret:gmail_oauth}}`.
- Substitution happens at the tool-call boundary, never round-trips through the LLM.

**Canary tokens:**

- Synthetic credentials seeded into ingested untrusted content. Any attempted use trips quarantine + alert + audit entry.

**Egress allowlists:**

- Default-deny for outbound network calls (from Spec C / G7). The gateway is the
  structural enforcement point: a destination allowlist plus a gateway-side DLP pass
  (mode b) form the structural ceiling for all outbound I/O. See
  [ADR-0040](docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md) for
  the two-layer enforcement model (kernel isolation as enforcement-of-record; gateway
  allowlist + DLP as independent defense-in-depth).
- Per-session capability grants narrow within that ceiling: tools requiring network declare
  the domains they need; those domains must also be in the gateway's destination allowlist.
  Each conversation starts with an empty per-session grant.

**Audit & rollback:**

- Append-only audit log: every tool call, every memory write, every config change, every reviewer decision, every persona coordination message. Includes full prompt + trust-tier of triggering content.
- Internal git repo at `/var/lib/alfred/state.git`. Reviewer-pending changes on `proposal/*` branches; active on `main`. Rollback = `git revert` + reload.

**Reviewer agent specifics (security-relevant):**

- Different provider from primary by default.
- Sees only diff + tests + rationale, never the original conversation.
- Diff-only review minimizes attack surface from poisoned context.

### 7.2 Multi-User Identity & Authorization

- **Canonical `user_id`** is internal. Platform identities (Discord snowflake, Telegram chat_id) map to it.
- **First-contact binding** is interactive (verification phrase) or pre-mapped by operator.
- **Cross-platform binding** by one-time code from an already-bound channel.
- **Per-user permissions:** read-only / standard / trusted / operator. Operator-tier required for changing config or installing plugins (and even then, plugin install is reviewer-gated and requires explicit confirmation).
- **Memory scoping:** semantic facts source-attributed but visible to any persona serving the same user; episodic logs per-persona-per-user; users cannot read each other's memory.
- **Rate limits** per platform identity and per canonical user.

### 7.3 Self-Healing & Auto-Recovery

- Liveness + readiness probes on every container.
- Plugin supervisor restarts crashed subprocesses with exponential backoff; quarantines repeat offenders.
- State persisted to Postgres + git repo; in-memory state rebuildable from durable stores.
- Background consolidation jobs are idempotent and resumable (checkpointed).
- Reviewer queue persists across restarts.

### 7.4 Audit Trail & Rollback

- **Audit log** is append-only, signed with the operator's signing key, separate retention from operational logs.
- **Internal git repo** is the source of truth for skills, personas, prompts, configs, security policy.
- **CLI:**
  - `alfred audit log --since 24h` — text view
  - `alfred audit graph --since 24h` — Graphviz of persona coordination
  - `alfred audit show <action-id>` — detail view
  - `alfred rollback <commit>` — revert a state-repo commit and reload
  - `alfred memory rollback <commit>` — revert a memory-write commit

### 7.5 Observability

- **Structured JSON logs** to stdout per container, with `trace_id`, `user_id`, `persona`, `tier`, `tokens_in/out`, `cost_estimate`.
- **Metrics (Prometheus):** tokens by `tier × provider × persona`, cache hit ratios, plugin call latency p50/p95/p99, plugin error rates, reviewer queue depth + age, budget consumption per user, security events.
- **Tracing (OpenTelemetry):** propagated across personas and plugin subprocesses.
- **Dashboards:** default Grafana bundle in `ops/grafana/` — tokens & cost, persona activity, security events, plugin health.
- **Alerts:** rules YAML in `ops/alerts/` — daily-budget-breach, canary-hit, circuit-breaker-open, reviewer-queue-age > 6h, DLP-redactions spike.
- **Cost reports:** `alfred cost report --since 7d --by user|persona|tier`.

### 7.6 Scalability Path (Post-MVP Design)

MVP is single-host. The design accommodates these without rewrites:

- Stateless `alfred-core` behind a queue (multiple replicas).
- Postgres read replicas or managed service.
- Redis cluster mode for event bus and cache.
- Qdrant cluster mode.
- Reviewer agent horizontal scaling (stateless).

### 7.7 Internationalization

Localization is baked in from Slice 1 because retrofitting i18n into a deployed multi-user agent is materially harder than building it in from day one.

**Per-user language preference.** Every user has a `language` field (BCP-47 tag — e.g. `en-US`, `fr-FR`, `ja-JP`). On first contact the operator's `Settings.operator_language` is the default; users can change theirs via CLI / chat command.

**Alfred speaks the user's language.** Persona system prompts include a `{user.language}` placeholder; the orchestrator substitutes the active user's language before each provider call. The model handles the translation — Alfred is "the same Alfred" in every language, but his replies are in the user's preferred language.

**Operator-/user-facing strings go through a translation function.** The codebase uses a `t()` helper backed by **Babel + gettext** translation catalogs:

```python
from alfred.i18n import t

# In CLI / TUI / setup-script-bridging code:
print(t("status.primary_provider", provider=settings.primary_provider))
```

Catalogs live at `locale/<lang>/LC_MESSAGES/alfred.po`. English is the source catalog; other languages are community translations. Pre-commit extracts new messages with `pybabel extract`; CI runs `pybabel update` and `pybabel compile --check` to fail on catalog drift.

**Stored content is language-tagged.** `episodes`, `audit_log`, and (later) `semantic_facts` carry a `language` column. Consolidation passes respect the language at write time. Cross-language memory queries are supported (we store as-is, translate at query time when needed).

**Prompt-cache implications.** Stable prompt prefixes vary by language (persona prompt + recent memory). Provider prompt caching keys on the full prefix, so we lose some hit rate when users switch language mid-conversation. Acceptable trade-off; caching still hits ~85%+ in steady-state.

**What's deferred to later slices:**

- Community translation workflow (Crowdin / Weblate integration, translation-PR automation) — Slice 0.0.4 or later.
- RTL layout in the TUI — when an RTL language community translation lands.
- Locale-aware date / number / currency formatting (`babel.dates`, `babel.numbers`) — applied progressively as needed; Slice 1 ships English defaults.

**Doc language policy.** The PRD, CLAUDE.md, agent definitions, skill definitions, and ADRs stay English-only. They are contributor-facing artifacts; localizing them is out of scope.

## 8. Testing Strategy

| Layer | Tool | What it covers |
| --- | --- | --- |
| **Unit** | pytest | Every component in isolation; LLM & plugin deps mocked |
| **Integration** | pytest + testcontainers | Real Postgres/Redis/Qdrant; recorded LLM responses (VCR-style fixtures) |
| **End-to-end** | pytest + full Docker Compose | Scripted multi-turn conversations across Discord/Telegram/TUI; real cheap-tier LLM calls behind per-test budget guard |
| **Adversarial security** | Custom harness in `tests/adversarial/` | See §8.1 — runs nightly, blocks release |
| **Skill-author tests** | Generated per skill | Happy-path + error-path + out-of-scope refusal; executed in sandbox during review |

### 8.1 Adversarial Security Suite (MVP requirement, blocks release)

1. **Prompt-injection corpus** — curated payloads attempting to escape trust-tier isolation via web pages, emails, RAG snippets, tool outputs, file contents, inter-persona messages. Every payload must be neutralized — orchestrator must not perform tool calls instructed by T3 content.
2. **DLP corpus** — synthetic-secret canaries (fake AWS keys, Stripe tokens, JWTs, PII) seeded into outbound paths. DLP must catch every variant.
3. **Capability-bypass corpus** — adversarial transcripts attempting to coerce the orchestrator into calling tools outside the current capability grant. Tool layer must refuse, even if LLM tries.
4. **Canary-trip suite** — canary tokens in ingested content. Any use trips quarantine within N seconds; metric + alert + audit entry verified.
5. **Inter-persona poisoning** — Persona A receives T3 content and tries to relay instructions to Persona B as if T2. B's tool layer must still treat the relayed content as T3.

**Coverage targets:** ≥ 80% for core; **100% for security boundaries** (input tagging, tool capability check, DLP, secret broker, audit log writes).

**CI:** GitHub Actions runs unit + integration on every PR; full e2e + adversarial nightly. Release-blocking. Pre-commit hooks for lint + type-check + the fast subset of unit tests.

## 9. MVP Scope vs. Roadmap

**MVP (v0.1) must include:**

- Comms: Discord + Telegram + TUI
- Memory: all 6 layers operational; knowledge graph may be sparse but functional
- Providers: DeepSeek + Anthropic + OpenAI; tiered routing with all 4 caching layers
- Internationalization: Babel + gettext catalogs, `t()` discipline, per-user `language`, persona prompts honour the active user's language
- Self-improvement: skill creation + reviewer gate + auto-generated tests
- Persona system: registry + 3 addressing modes + group sessions + safety-railed background coordination + audit graph CLI; ships with Alfred enabled + Lucius/Oracle/Diana as disabled examples
- Security: dual-LLM, secret broker, DLP, audit log, canaries, full adversarial suite passing
- Deployment: docker compose + setup script (macOS/Linux native, Windows via WSL)
- Multi-user: per-user identity, scoped memory, per-user budgets
- Audit + rollback via internal git
- Observability: structured logs + Prometheus + default Grafana
- CLI: `alfred status | memory | snapshot | rollback | plugin | persona | cost | audit`

**Explicit MVP non-goals:**

- Slack, WhatsApp, voice, email — post-MVP
- Web dashboard — post-MVP (CLI only for v0.1)
- Mobile push for step-up auth — post-MVP (Telegram/Discord DM for v0.1)
- Horizontal scale — post-MVP (single-node only)
- Native Windows (non-WSL) — post-MVP
- Marketplace / plugin registry — post-MVP

**Post-MVP roadmap (sequenced, not committed dates):**

1. **v0.2** — Web dashboard for memory, audit, proposals, persona management
2. **v0.3** — Slack + WhatsApp adapters
3. **v0.4** — Voice (STT/TTS plugins) + email adapter
4. **v0.5** — Plugin marketplace + signing
5. **v0.6** — Horizontal scale + managed-service install path
6. **v0.7** — Mobile companion for step-up auth + notifications

## 10. Open Questions & Decisions Log

Decisions captured during design (2026-05-24):

- **DEC-001:** Core in Python 3.12+. Plugins polyglot via MCP.
- **DEC-002:** Postgres + Redis + Qdrant as default datastores.
- **DEC-003:** Hybrid plugin isolation — trusted in-process subprocess, untrusted in container.
- **DEC-004:** Tiered routing with capability fallback; reviewer on a different provider.
- **DEC-005:** All four caching layers in MVP.
- **DEC-006:** Reviewer gates skills, prompt/persona/routing, memory schema, and plugin install (latter with additional human approval).
- **DEC-007:** Dual-LLM (privileged orchestrator + quarantined T3 processor) is non-negotiable.
- **DEC-008:** Persona addressing supports default + direct + group; coordination is free but rail-bounded.
- **DEC-009:** MVP ships Alfred enabled + Lucius/Oracle/Diana as disabled examples.
- **DEC-010:** Open source from day 1; Apache-2.0 to maximise frictionless enterprise adoption. Patent grant in §3 protects users defensively against contributor-held patents.
- **DEC-011:** Single-host Docker Compose for MVP; horizontal scale post-MVP.
- **DEC-012:** Internationalization baked in from Slice 1. Babel + gettext catalogs; per-user `language` field on the User model; persona system prompts honour `{user.language}`; all operator-/user-facing strings go through `t()`. Doc files (PRD, CLAUDE.md, ADRs) stay English-only.
- **DEC-013:** Specialist reviewer agents (error, performance, docs, i18n, devex) created alongside the subsystem-engineer agents to enable comprehensive adversarial review without overloading any single agent's scope.

**Open questions (TBD before implementation plan):**

- Exact persona-bundle file format (TOML vs YAML vs Python module)
- Whether to use Pydantic v2 throughout or split between Pydantic and dataclasses
- Choice of test recorder (VCR.py vs custom)
- Reviewer prompt design — diff-only is settled; specific prompt and rubric TBD
- Exact rate-limit defaults per platform
- Knowledge-graph schema (which entity/relation types are first-class)

## 11. Glossary

- **Persona** — A versioned agent configuration with its own prompt, capabilities, and policy.
- **Orchestrator** — The privileged LLM call that drives a persona's reasoning and tool use.
- **Quarantined LLM** — A separate LLM call with no tool access, used only to process untrusted (T3) content into structured data.
- **Trust tier (T0–T3)** — Classification of input content by source trust; gates what the orchestrator may consider as instructions.
- **MCP** — Model Context Protocol; the stdio-/HTTP-based plugin protocol all plugins implement.
- **Capability grant** — The set of tools and parameters allowed for a given conversation; enforced by the tool layer.
- **Step-up auth** — Out-of-band confirmation required for high-blast actions.
- **DLP** — Data Loss Prevention; the outbound redactor that catches secrets and PII before send.
- **Canary token** — Synthetic credential seeded into untrusted content; any use trips quarantine.
- **Reviewer gate** — The process by which proposed changes (skills, prompts, configs) are reviewed by a different-provider LLM before activation.
- **Internal git repo** — `/var/lib/alfred/state.git`; the source of truth for skills, personas, configs, security policy; supports rollback via revert.
- **Consolidation pass** — Background job that turns raw conversation into summarized episodes + semantic facts + graph updates + embeddings.
- **Inter-persona bus** — Typed-message channel between personas with stated purpose, budget caps, loop detection, and audit visualization.
