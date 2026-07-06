# Design: Devin DeepWiki info set (`.devin/wiki.json`)

**Date:** 2026-07-06
**Status:** Proposed — awaiting review
**Author:** brainstormed with `alfred-devex-reviewer`, `alfred-docs-author`, `alfred-architect`, `alfred-security-engineer`

## Goal

Add a Devin DeepWiki steering file at `.devin/wiki.json` (repo root) so the
auto-generated public wiki that people land on to understand AlfredOS reflects
the *real* architecture — security-boundary-forward, drift-resistant, and
honest about what is shipped vs. scaffolded. Authored fresh; none exists today.

## Non-goals (scope: wiki file only)

This branch ships **only** `.devin/wiki.json`. It does **not**:

- Write the 13 missing `docs/subsystems/*` deep-docs.
- Backfill glossary terms or de-stale `docs/ARCHITECTURE.md`.
- Add Devin cloud Knowledge notes, playbooks, or automations (cloud store, not
  repo-committed).
- Touch `CLAUDE.md` or `PRD.md` (human-gated).

Those doc/glossary gaps are real and affect wiki quality; they are handled
defensively in the file (see *Anchor-gap discipline*) and recorded as
**follow-ups** below, not done here.

## The mechanism

Devin's DeepWiki reads `.devin/wiki.json` at the repository root during wiki
generation. Confirmed schema (Devin official docs, 2026-07-06):

- **`repo_notes[]`** — global steering. Each: `{ content: string (≤10,000
  chars, required), author: string (optional) }`.
- **`pages[]`** — explicit page specifications. When present, Devin generates
  **exactly** these pages (bypasses default cluster planning). Each:
  `{ title: string (unique, non-empty, required), purpose: string (required),
  parent: string (optional — parent page title for hierarchy),
  page_notes: string[] (optional) }`.

**Hard limits:** ≤30 pages, ≤100 notes total (`repo_notes` + all `page_notes`),
≤10,000 chars per note, page titles unique and non-empty.

## Strategy

**Explicit `pages` tree + global `repo_notes`** (chosen over `repo_notes`-only).
We control the full page tree, and the invariants that must hold across *every*
page live in `repo_notes` (Devin generates pages semi-independently, so an
invariant not in global steering *will* get contradicted on some page).

Organizing principle: **hub-and-spoke, security-forward, with concept-question
roots** (a blend the panel converged on). Roots read as a newcomer's four
questions; children carry subsystem fidelity. Rationale:

- **Drift resistance is the deciding factor.** Devin fixes the page tree and
  re-derives content on every regeneration. The hazard is page titles/purposes
  that *become lies* as the repo moves. So: anchor pages to **curated docs**
  (`docs/subsystems/*`, ADRs, glossary, PRD) that carry maintenance discipline —
  never to churn-prone `src/alfred/` directories. Prefer **concept titles**
  ("Connectivity-Free Core & Egress Topology") over path titles ("gateway
  module"); concept titles survive refactors.
- **The trust boundary is the differentiator**, so Security Model is a
  first-class subtree, not one page among many.
- **`Overview` is a hard-working router**, not a throat-clear: a three-sentence
  pitch, the trust-boundary in one diagram, and an explicit audience fork
  (self-hosters → Security Model, operators → Operating, contributors →
  Extending & Contributing).

## Page tree (28 pages, under the 30 cap; ~2 slots headroom)

Legend: `→` names the **anchor doc** a page's `page_notes` should pin. `⚠` marks
a **shipped-vs-scaffolded** caveat the `page_notes` must carry so Devin does not
present a planned/partial surface as operational.

### Root: `Overview`
Front-door router. Three-sentence "what it is", the trust-boundary diagram, and
the audience fork. → `PRD.md` §1–§2.

### Root: `Architecture`
Structural spine — "what it is, structurally". → `docs/ARCHITECTURE.md`, `PRD.md`
§5 (the 8 non-negotiable invariants).

| Page | parent | purpose (one line) | anchor / caveat |
| --- | --- | --- | --- |
| Orchestrator & Act-Phase Loop | Architecture | The OODA turn and the agentic tool-calling loop that drives a persona's response. | → `PRD.md` §5, ADR-0003/0045/0046. ⚠ real-LLM engine not fully wired; #339 in progress (this branch is PR3 of 4) — describe as *designed*, not *shipped*. |
| Memory Model (6 Layers) | Architecture | Working, episodic, summarized, semantic, vector, knowledge-graph layers and consolidation. | → `PRD.md` §6.2, `src/alfred/memory/`. ⚠ working+episodic live; semantic/vector/graph partial/planned. |
| Personas & Routing | Architecture | Persona registry, addressing modes, inter-persona bus with safety rails. | → `PRD.md` §6.8, `src/alfred/personas/`. No ADR — say so. ⚠ only **Alfred** ships enabled; Lucius/Oracle/Diana are example definitions. |
| Providers & Routing | Architecture | Tiered provider routing, capability fallback, caching, tool-call protocol. | → `PRD.md` §6.5/§6.6, ADR-0001/0045/0046, `src/alfred/providers/`, `src/alfred/caching/`. |
| Plugins & MCP Transport | Architecture | MCP plugin transport (stdio/HTTP), session lifecycle, manifest, capability declarations. | → `docs/subsystems/plugins.md`. `comms_mcp` folded in here. |
| Comms & Gateway Inbound | Architecture | Comms adapters (Discord/TUI), identity binding, the gateway as comms front door + resume. | → `docs/subsystems/comms.md`, ADR-0036. ⚠ Discord + TUI only; Telegram/Slack/WhatsApp post-MVP. |
| Connectivity-Free Core & Egress Topology | Architecture | Kernel-isolated core (`internal:true`); the gateway as sole external egress plane (L7 CONNECT proxy, default-deny allowlist). | → ADR-0040/0042/0043, `docs/ARCHITECTURE.md` §2. **Cross-linked from Security Model.** |
| Self-Modification: Reviewer-Gate Loop | Architecture | Proposal branches in `/var/lib/alfred/state.git` → reviewer agent → merge activates; rollback = revert. | → `PRD.md` §6.4, ADR-0018/0021. |

### Root: `Security Model`
The differentiator — "how it's secured". → `docs/subsystems/security.md`,
`docs/subsystems/quarantine.md`, `PRD.md` §7.1.

| Page | parent | purpose (one line) | anchor / caveat |
| --- | --- | --- | --- |
| Trust Tiers (T0–T3) | Security Model | Provenance tiers, boundary tagging, immutability; T3 minting capability-gated to a closed set of boundary call sites. | → `docs/subsystems/security.md`, ADR-0028 (boot-time T3 nonce auth folded in as *principle*, not mechanics). |
| Dual-LLM Split & Quarantine | Security Model | Privileged orchestrator never sees raw T3; the quarantined LLM is the only T3 consumer; the single sanctioned T3→T2 dispatch chokepoint. | → `docs/subsystems/quarantine.md`, ADR-0046. Purpose **must** name the T3→T2 crossing. |
| Capability Gate, Grants & Secret Broker | Security Model | Fail-closed gate, grants-before-dispatch, secret-IDs-not-values substituted at the tool boundary, out-of-band step-up for high-blast actions. | → `docs/subsystems/security.md`. ⚠ reviewer-gated config step-up exists; general high-blast tool step-up more scaffold than flow. |
| DLP, Canary Tokens & Outbound Redaction | Security Model | On-by-default outbound DLP (per-call-undisableable), canary-token tripwires, redaction — the content-scanning family. | → `docs/subsystems/security.md`. Mechanism-level only (disclosure guardrail C). |
| Audit Log, Audit Graph & Reviewer Trail | Security Model | Append-only signed audit, `alfred audit graph`, and the reviewer-gate decision trail. | → `PRD.md` §7.4, `src/alfred/audit/`. No ADR — say so. |

### Root: `Operating & Deploying`
"How to run it". → `README.md`, `docs/runbooks/`.

| Page | parent | purpose (one line) | anchor / caveat |
| --- | --- | --- | --- |
| Deployment & First-Run Setup | Operating & Deploying | Docker Compose stack, setup scripts, `state.git` seed, datastores (Postgres 18 / Redis 8 / Qdrant). | → `README.md`, `docker-compose.yaml`, `bin/`. |
| CLI & Operator Surface | Operating & Deploying | The `alfred` command tree by area (user, plugin, web, config, supervisor, audit, gateway). | → `CLAUDE.md` command table. ⚠ honour slice markers — `alfred memory show`, `alfred cost report` are Slice 4+ / not implemented. |
| Configuration & Policies | Operating & Deploying | `policies.yaml`, reviewer-gated vs direct config keys, hot reload. | → `docs/subsystems/policies.md`. |

### Root: `Extending & Contributing`
"How to extend it". → `CONTRIBUTING.md`, `docs/python-conventions.md`.

| Page | parent | purpose (one line) | anchor / caveat |
| --- | --- | --- | --- |
| Writing Plugins, Personas & Skills | Extending & Contributing | Authoring MCP plugins, persona definitions, and runtime skills; manifest + capability model. | → `docs/subsystems/plugins.md`, `CONTRIBUTING.md`. |
| Conventions & i18n | Extending & Contributing | Python 3.14+ idioms, SOLID+FP, typing bar, and the day-one i18n discipline (`t()`, language fields). | → `docs/python-conventions.md`, `PRD.md` §7.7. |
| Testing & the Adversarial Suite | Extending & Contributing | Unit/integration/smoke/adversarial layers; the adversarial suite is release-blocking. | → `PRD.md` §8.1. **Cross-linked from Security Model** (it is posture evidence, not just contributor detail). |

### Root: `Reference`
Lookups and honesty. → `docs/glossary.md`, `docs/adr/`.

| Page | parent | purpose (one line) | anchor / caveat |
| --- | --- | --- | --- |
| Glossary | Reference | The single canonical AlfredOS vocabulary. | → `docs/glossary.md` (headings are canonical, GitHub-slugified anchors). |
| Decision Records (ADR Index) | Reference | Index of the 46 ADRs; the ~6 load-bearing ones are pinned as `page_notes` on the concept pages they govern. | → `docs/adr/`. Top-tier pins: 0040, 0017, 0046, 0045, 0014. |
| Slice / Roadmap Status | Reference | **Explicitly forward-looking** page absorbing planned surfaces so no other page oversells them. | → `PRD.md` slice plan; `CLAUDE.md` current-state. |

## `repo_notes` (global steering — the load-bearing deliverable)

11 notes. Six architectural anti-pattern invariants + five security-framing
notes (the last three of which are the disclosure guardrails). Each is phrased
to tell Devin the *specific false sentence it must not write*.

### Architectural invariants (6)

1. **Dual-LLM / trust flow.** The privileged orchestrator sees only T0–T2. The
   quarantined LLM is the ONLY consumer of raw T3 (web/email/file/tool-output)
   and emits ONLY schema-validated structured data — never tool calls, never
   free text fed back as instructions. All external content is tagged T3 at
   ingest. Never write "the orchestrator reads a web page / processes tool
   output": T3 reaches the privileged side only as structured extraction via
   the T3→T2 dispatch chokepoint. Non-negotiable (PRD §5, DEC-007).
2. **Gateway sole-egress / connectivity-free core.** The core runs on
   `internal:true` and cannot open external sockets (kernel-enforced). ALL
   egress — provider calls, tool egress, adapter egress — routes through the
   gateway L7 CONNECT proxy via the `EgressClient` seam. Never write that a
   provider adapter or plugin "connects to" / "makes an HTTP request to" an
   external host from the core.
3. **Self-modification reviewer-gate loop.** Alfred improves itself via proposal
   branches in `/var/lib/alfred/state.git` (OUTSIDE the source tree) → reviewer
   agent reviews diff+tests+rationale → merge activates → rollback is
   `git revert`. Never describe Alfred editing its own personas/skills/policy
   in place on `main` at runtime. Plugin install/remove needs additional human
   approval.
4. **Functional-core / imperative-shell, no global state.** Pure functions for
   transforms; classes only for state machines; dependencies injected via
   Protocols; fail-loud at trust boundaries. Don't describe modules as global
   singletons or ambient services.
5. **Shipped-vs-scaffolded honesty.** The security/infra chassis (Slices 1–4;
   gateway program Specs A/B/C) is complete and merged. The real-LLM engine is
   not fully wired: most paths are deterministic-echo; the exception is the
   agentic tool-calling epic (#339), in progress. Describe the architecture as
   built and tested; do NOT present tool-calling, live dual-LLM extraction, or
   end-to-end autonomous task execution as fully operational. When unsure
   whether something is shipped or planned, say "is designed to", not "does".
6. **Vocabulary lock.** `docs/glossary.md` is the single source of AlfredOS
   vocabulary; every `##` heading is a canonical, stable, GitHub-slugified
   anchor — reuse exact terms and link to them, never coin a synonym for a
   concept it defines. Use: trust tiers T0–T3, privileged orchestrator /
   quarantined LLM, capability gate + grants, secret broker, DLP, reviewer
   gate, gateway / egress plane, hookpoints, ContentHandle. Alfred = the
   default persona; AlfredOS = the system. If a concept has no glossary entry
   yet, describe it plainly in the page body but do NOT present it as fixed
   terminology or invent a definitional heading for it.

### Security framing (5)

7. **The model is not the perimeter; the tool layer is.** Every security
   guarantee is enforced in code at the tool/transport boundary, independent of
   what any LLM is prompted or persuaded to do. Describe defenses as enforced
   by the boundary — never as "the model is instructed to…".
8. **Trust tiers are provenance, not capability; do not conflate the two tier
   axes.** A plugin's subscriber-capability tier (system/operator/user-plugin)
   is orthogonal to a content trust tier (T0–T3). A plugin is never "T2";
   *content* is. Conflating them is a named bug class (tier-laundering) — keep
   the axes separate in all prose. (Highest-risk fidelity item.)
9. **Disclosure guardrail A — no "how to weaken it" recipe.** Describe controls
   and their threat model in full (Apache-2.0, public repo, Kerckhoffs — full
   design disclosure is correct). But do NOT compile a step-by-step checklist
   for disabling DLP, widening the egress allowlist, or lowering a grant; that
   is operator-runbook material, not public-wiki headline material.
10. **Disclosure guardrail B — pair every residual with its boundary.** Whenever
    a page states a limitation or accepted residual, it must state, in the same
    breath, the assumption that puts it out of scope — e.g. the `gc.get_objects`
    heap read of the T3 nonce presupposes full process compromise, so it is
    outside the threat boundary. A residual must read as *documented accepted
    risk*, never as an unpatched hole.
11. **Disclosure guardrail C — mechanism yes, live values never.** Describe
    canaries, allowlists, and secrets at the mechanism level. Never enumerate
    literal canary strings, per-deployment seeding positions, real egress-
    allowlist domains, or anything token-shaped from `.env.example` / test
    fixtures.

**Note-budget check:** 11 `repo_notes` + `page_notes`. Typical page carries 1–2
`page_notes`; the caveated pages carry up to 3 (anchor pin + shipped-vs-
scaffolded + anchor-gap). Worst case ≈ 11 + 3×28 = 95, under the 100 cap but
with only ~5 slots of slack — so the implementation **must** keep `page_notes`
lean (≤3 per page) and the CI check (verification step 3) enforces the total.
Each note is well under 10,000 chars.

## Anchor-gap discipline (the "wiki file only" safety net)

13 of 21 subsystems lack a `docs/subsystems/*` deep-doc — including headline
pages (Memory, Orchestrator, Personas, Providers, Audit, Egress). For each such
page, `page_notes` must explicitly say: *"No curated deep-doc exists yet —
anchor to PRD §X + `src/alfred/<dir>/` (+ ADR-NNNN if any); treat claims as
unverified until a deep-doc lands."* This makes the confidence gap **visible
per-page** instead of silently making the differentiator pages the least
trustworthy ones. `page_notes` stay pointers + a 2–3 sentence steer — never
inlined doc content (a second copy rots independently).

## Verification

`.devin/wiki.json` is a data file; verification is structural, not behavioural
(the `verify` skill is N/A — nothing to drive at runtime):

1. **Valid JSON** — `python -c "import json,sys; json.load(open('.devin/wiki.json'))"`.
2. **Schema conformance** — every page has non-empty `title` + `purpose`; every
   `parent` references an existing page `title`; every `repo_notes`/`page_notes`
   entry has required fields.
3. **Limit conformance** — `pages` ≤ 30; total notes ≤ 100; each note ≤ 10,000
   chars; page titles unique.
4. **Anchor liveness** — every doc path referenced in `page_notes` exists on
   disk (guards against pinning a moved/renamed anchor).
5. **markdownlint / repo lint** — the file is JSON, but ensure it is
   `.gitignore`-clean and not swept by `git add -A` habits (add the named path
   only).

A small `scripts/` or test check enforcing (2)–(4) is proposed in the
implementation plan so drift is caught in CI rather than by eye.

## Follow-ups (recorded, not done here)

- **Deep-doc backfill** — write `docs/subsystems/{memory,orchestrator,personas,
  providers,audit,gateway}.md`; several graduated their slice long ago and
  never got the deep-doc (a standing violation of the "every graduation gets a
  deep-doc" rule, independent of this wiki).
- **Glossary top-up** — add entries for persona, OODA loop / act-phase loop,
  reviewer gate, capability grant, audit graph (+ the six memory-layer names as
  one cross-referenced entry).
- **`docs/ARCHITECTURE.md` de-stale** — it calls Spec B "in progress" and Spec C
  "future"; both are merged (#288, #333 closed). Fix before it misinforms the
  wiki as the wiki's own best Architecture anchor.

## Open questions

None blocking. The egress-page placement (Architecture vs Security) is resolved:
the page lives under **Architecture** (its identity is topology), is prominently
cross-linked from **Security Model**, and the invariant is carried in
`repo_notes` #2 regardless of subtree.
