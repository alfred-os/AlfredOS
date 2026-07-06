# Design: Devin DeepWiki info set (`.devin/wiki.json`)

**Date:** 2026-07-06
**Status:** Proposed — revised after a 5-agent `/review-plan` pass (issue #398)
**Author:** brainstormed with `alfred-devex-reviewer`, `alfred-docs-author`, `alfred-architect`, `alfred-security-engineer`; reviewed by `alfred-architect`, `alfred-reviewer`, `alfred-test-engineer`, `alfred-security-engineer`, `alfred-docs-reviewer` + `alfred-review-coordinator`.

## Goal

Add a Devin DeepWiki steering file at `.devin/wiki.json` (repo root) so the
auto-generated public wiki that people land on to understand AlfredOS reflects
the *real* architecture — security-boundary-forward, drift-resistant, and
honest about what is shipped vs. scaffolded. Authored fresh; none exists today.

## Scope & deliverables

Four deliverables (widened from "wiki file only" after the review found the
first depends on the second, the third removes a stale anchor the wiki would
otherwise inherit, and the fourth is the only zero-effort auto-refresh lever —
see *Regeneration lifecycle*):

1. **`.devin/wiki.json`** — the steering file: explicit page tree + global
   `repo_notes`.
2. **A tested validator + required CI check** — `scripts/` validator enforcing
   the file's structural, limit, and anchor-resolution invariants (see
   *Validation*), wired as a **required status check** on `main`. Ships with
   happy-path, failure-path, and boundary fixtures.
3. **De-stale `docs/ARCHITECTURE.md`** — fix its Spec B/C status table (both
   merged: #288, #333) so the doc the wiki's Architecture spine anchors to does
   not contradict `repo_notes` #5. `ARCHITECTURE.md` is **not** human-gated.
4. **DeepWiki README badge** — add the official DeepWiki badge to `README.md`.
   It is the only documented *set-and-forget* refresh automation (~weekly
   auto-regeneration) and doubles as discoverability. `README.md` is not
   human-gated.

### Non-goals

- Write the remaining missing `docs/subsystems/*` deep-docs (backfill is a
  follow-up; `ARCHITECTURE.md` de-stale above is the one exception, because a
  headline anchor pins to it).
- Backfill glossary terms (follow-up).
- Add Devin cloud Knowledge notes, playbooks, or automations (cloud store, not
  repo-committed).
- Touch `CLAUDE.md` or `PRD.md` (human-gated). Note the **root `CLAUDE.md` is a
  gitignored `rulesync` output** anyway — see the anchor rule below.

## The mechanism

Devin's DeepWiki reads `.devin/wiki.json` at the repository root during wiki
generation. Confirmed against Devin's official docs (2026-07-06):

- **`repo_notes[]`** — global steering. Each: `{ content: string (≤10,000
  chars, required), author: string (optional) }`.
- **`pages[]`** — explicit page specifications. When present, Devin generates
  **exactly** these pages (bypasses default cluster planning). Each:
  `{ title: string (unique, non-empty, required), purpose: string (required),
  parent: string (optional — parent page title for hierarchy),
  page_notes: string[] (optional) }`.

**Hard limits:** ≤30 pages, ≤100 notes total (`repo_notes` + all `page_notes`),
≤10,000 **characters (code points)** per note, page titles unique and non-empty.
The premise that Devin honours an explicit page tree + `repo_notes` + these caps
is the one external-vendor contract no in-repo reviewer owns; it is taken from
the official schema doc and re-checked whenever the file is regenerated.

## Strategy

**Explicit `pages` tree + global `repo_notes`** (chosen over `repo_notes`-only).
We control the full page tree, and the invariants that must hold across *every*
page live in `repo_notes` (Devin generates pages semi-independently, so an
invariant not in global steering *will* get contradicted on some page).

Organizing principle: **hub-and-spoke, security-forward, with concept-question
roots**. Roots read as a newcomer's questions; children carry subsystem
fidelity. Rationale:

- **Drift resistance is the deciding factor.** Devin fixes the page tree and
  re-derives content on every regeneration. The hazard is page titles/purposes
  that *become lies* as the repo moves. So: anchor pages to **curated docs that
  Devin can actually see in the committed tree** (`docs/subsystems/*`, ADRs,
  glossary, PRD, `.rulesync/rules/CLAUDE.md`) — never as a page's *primary*
  anchor to a churn-prone `src/alfred/` directory (a `src/alfred/<dir>/` path
  may appear only as a *secondary* pointer where no deep-doc exists yet), and
  never to a gitignored generated output. Prefer **concept titles** over path
  titles; concept titles survive refactors.
- **The trust boundary is the differentiator**, so Security Model is a
  first-class subtree.
- **`Overview` is a hard-working router**: a three-sentence pitch, the
  trust-boundary diagram, and an explicit audience fork (self-hosters →
  Security Model, operators → Operating, contributors → Extending).

## Page tree (29 pages, under the 30 cap)

Legend: `→` names the **anchor doc** a page's `page_notes` should pin. `⚠` marks
a **shipped-vs-scaffolded** caveat the `page_notes` must carry.

### Root: `Overview`

Front-door router. Three-sentence "what it is", the trust-boundary diagram, and
the audience fork. → `PRD.md` §1–§2.

### Root: `Architecture`

Structural spine — "what it is, structurally". → `docs/ARCHITECTURE.md` (after
de-stale), `PRD.md` §5 (the 8 non-negotiable invariants).

| Page | parent | purpose (one line) | anchor / caveat |
| --- | --- | --- | --- |
| Orchestrator & Act-Phase Loop | Architecture | The OODA turn and the agentic tool-calling loop that drives a persona's response. | → `PRD.md` §5, ADR-0003/0045/0046, `src/alfred/orchestrator/`. ⚠ real-LLM engine not fully wired; #339 in progress (this branch is PR3 of 4) — describe as *designed*, not *shipped*. |
| Memory Model (6 Layers) | Architecture | Working, episodic, summarized, semantic, vector, knowledge-graph layers and consolidation. | → `PRD.md` §6.2, `src/alfred/memory/`. ⚠ working+episodic live; semantic/vector/graph partial/planned. |
| Personas & Addressing | Architecture | Persona registry, addressing modes, inter-persona bus with safety rails. | → `PRD.md` §6.8, `src/alfred/personas/`. No ADR — say so. ⚠ only **Alfred** ships enabled; Lucius/Oracle/Diana are example definitions. (Distinct from "Providers & Routing" — this is persona addressing, that is model routing.) |
| Providers & Routing | Architecture | Tiered provider routing, capability fallback, caching, tool-call protocol. | → `PRD.md` §6.5/§6.6, ADR-0001/0045/0046, `src/alfred/providers/`, `src/alfred/caching/`. |
| Plugins & MCP Transport | Architecture | MCP plugin transport (stdio/HTTP), session lifecycle, manifest, capability declarations. | → `docs/subsystems/plugins.md`. `comms_mcp` folded in here. |
| Comms & Gateway Inbound | Architecture | Comms adapters (Discord/TUI), identity binding, the gateway as comms front door + resume. | → `docs/subsystems/comms.md`, ADR-0036. ⚠ Discord + TUI implemented; **Telegram is an MVP-target adapter not yet built**; Slack/WhatsApp/voice/email are post-MVP (PRD §6.1). |
| Hooks & Hookpoints | Architecture | Every action is hookable; hook kinds, tiers, and the dispatcher. | → `docs/subsystems/hooks.md`, ADR-0014, `PRD.md` §5/§5.1. A PRD §5 non-negotiable invariant — first-class page, not folded prose. |
| Connectivity-Free Core & Egress Topology | Architecture | Kernel-isolated core (`internal:true`); the gateway as sole external egress plane (L7 CONNECT proxy, default-deny allowlist). | → ADR-0040/0042/0043, `docs/ARCHITECTURE.md` §2 (after de-stale). **Cross-linked from Security Model.** Has a curated ADR anchor — the anchor-gap note does NOT apply. |
| Self-Modification: Reviewer-Gate Loop | Architecture | Proposal branches in `/var/lib/alfred/state.git` → reviewer agent → merge activates; rollback = revert. | → `PRD.md` §6.4, ADR-0018/0021. |

### Root: `Security Model`

The differentiator — "how it's secured". → `docs/subsystems/security.md`,
`docs/subsystems/quarantine.md`, `PRD.md` §7.1.

| Page | parent | purpose (one line) | anchor / caveat |
| --- | --- | --- | --- |
| Trust Tiers (T0–T3) | Security Model | Provenance tiers, boundary tagging, immutability; T3 minting capability-gated to a closed set of boundary call sites. | → `docs/subsystems/security.md`, **ADR-0017** (trust-tier completion) + ADR-0028 (boot-time T3 nonce auth, folded in as *principle*, not mechanics). |
| Dual-LLM Split & Quarantine | Security Model | Privileged orchestrator never sees raw T3; the quarantined LLM is the only T3 consumer; the single sanctioned T3→T2 dispatch chokepoint. | → `docs/subsystems/quarantine.md`, ADR-0046. Purpose **must** name the T3→T2 crossing. |
| Capability Gate, Grants & Secret Broker | Security Model | Fail-closed gate, grants-before-dispatch, secret-IDs-not-values substituted at the tool boundary, out-of-band step-up for high-blast actions. | → `docs/subsystems/security.md`. ⚠ reviewer-gated config step-up exists; general high-blast tool step-up more scaffold than flow. |
| DLP, Canary Tokens & Outbound Redaction | Security Model | On-by-default outbound DLP (per-call-undisableable), canary-token tripwires, redaction — the content-scanning family. | → `docs/subsystems/security.md`. Mechanism-level only (disclosure guardrail C). |
| Audit Log, Audit Graph & Reviewer Trail | Security Model | Append-only signed audit, `alfred audit graph`, and the reviewer-gate decision trail. | → `PRD.md` §7.4, `src/alfred/audit/`. No ADR — say so. |

### Root: `Operating & Deploying`

"How to run it". → `README.md`, `docs/runbooks/`.

| Page | parent | purpose (one line) | anchor / caveat |
| --- | --- | --- | --- |
| Deployment & First-Run Setup | Operating & Deploying | Docker Compose stack, setup scripts, `state.git` seed, datastores (Postgres 18 / Redis 8 / Qdrant). | → `README.md`, `docker-compose.yaml`, `bin/`. ⚠ README is "Pre-implementation" status — carry a maturity caveat, don't present the quickstart as fully live. |
| CLI & Operator Surface | Operating & Deploying | The `alfred` command tree by area (user, plugin, web, config, supervisor, audit, gateway). | → **`.rulesync/rules/CLAUDE.md`** command table (the committed source; root `CLAUDE.md` is a gitignored `rulesync` output Devin cannot see) + `src/alfred/cli/`. ⚠ honour slice markers — `alfred memory show`, `alfred cost report` are Slice 4+ / not implemented. |
| Configuration & Policies | Operating & Deploying | `policies.yaml`, reviewer-gated vs direct config keys, hot reload. | → `docs/subsystems/policies.md`. |

### Root: `Extending & Contributing`

"How to extend it". → `CONTRIBUTING.md`, `docs/python-conventions.md`.

| Page | parent | purpose (one line) | anchor / caveat |
| --- | --- | --- | --- |
| Writing Plugins, Personas & Skills | Extending & Contributing | Authoring MCP plugins, persona definitions, and runtime skills; manifest + capability model. | → `docs/subsystems/plugins.md`, `CONTRIBUTING.md`. |
| Conventions & i18n | Extending & Contributing | Python 3.14+ idioms, SOLID+FP, typing bar, and the day-one i18n discipline (`t()`, language fields). | → `docs/python-conventions.md`, `PRD.md` §7.7. |
| Testing & the Adversarial Suite | Extending & Contributing | Unit/integration/smoke/adversarial layers; the adversarial suite is release-blocking. | → `PRD.md` §8.1. **Cross-linked from Security Model** (posture evidence, not just contributor detail). |

### Root: `Reference`

Lookups and honesty. → `docs/glossary.md`, `docs/adr/`.

| Page | parent | purpose (one line) | anchor / caveat |
| --- | --- | --- | --- |
| Glossary | Reference | The single canonical AlfredOS vocabulary. | → `docs/glossary.md` (headings are canonical, GitHub-slugified anchors). |
| Decision Records (ADR Index) | Reference | Index of the ADRs (47 after ADR-0047 adds the DeepWiki-adoption decision); the load-bearing ones are pinned as `page_notes` on the concept pages they govern (see the ADR-pin map below). | → `docs/adr/`. |
| Slice / Roadmap Status | Reference | **Explicitly forward-looking** page absorbing planned surfaces so no other page oversells them. | → `PRD.md` slice plan; **`.rulesync/rules/CLAUDE.md`** current-state (committed source, not the generated root `CLAUDE.md`). |

### ADR-pin map (fixes the "pinned on the pages they govern" claim)

Every load-bearing ADR is pinned on the page it governs, so the Reference/ADR
index claim is true, not aspirational:

- **0040** (+0042/0043) → Connectivity-Free Core & Egress Topology
- **0017** → Trust Tiers (T0–T3)
- **0046** → Dual-LLM Split & Quarantine (also Providers/Orchestrator)
- **0045** → Providers & Routing, Orchestrator & Act-Phase Loop
- **0014** → Hooks & Hookpoints
- 0003 → Orchestrator; 0028 → Trust Tiers; 0036 → Comms; 0018/0021 →
  Self-Modification; 0001 → Providers.

## `repo_notes` (global steering — the load-bearing deliverable)

12 notes: seven architectural/operational invariants + five security &
vocabulary framing notes (the last two of which carry the three disclosure
guardrails). Each is phrased to tell Devin the *specific false sentence it must
not write*.

### Architectural invariants (7)

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
4. **Every action is hookable.** Hookpoints wrap every side-effecting action
   (a PRD §5 non-negotiable invariant, ADR-0014). Describe capabilities as
   dispatched through hookpoints, not as direct un-interceptable calls.
5. **Secrets & outbound DLP.** Plugins/tools request **secret IDs** from the
   broker; the broker substitutes the value at the tool-call boundary — never
   write "the plugin reads the API key from an env var". Every outbound path is
   DLP-scanned on by default and cannot be disabled per-call. (HARD rules 4 & 6.)
6. **Shipped-vs-scaffolded honesty.** The security/infra chassis (Slices 1–4;
   gateway program Specs A/B/C) is complete and merged. The real-LLM engine is
   not fully wired: most paths are deterministic-echo; the exception is the
   agentic tool-calling epic (#339), in progress. Describe the architecture as
   built and tested; do NOT present tool-calling, live dual-LLM extraction, or
   end-to-end autonomous task execution as fully operational. When unsure
   whether something is shipped or planned, say "is designed to", not "does".
7. **Functional-core / imperative-shell, no global state.** Pure functions for
   transforms; classes only for state machines; dependencies injected via
   Protocols; fail-loud at trust boundaries. Don't describe modules as global
   singletons or ambient services.

### Security & vocabulary framing (5)

8. **The model is not the perimeter; the tool layer is.** Every security
   guarantee is enforced in code at the tool/transport boundary, independent of
   what any LLM is prompted or persuaded to do. Describe defenses as enforced
   by the boundary — never as "the model is instructed to…".
9. **Trust tiers are provenance, not capability; do not conflate the two tier
   axes.** A plugin's subscriber-capability tier (system/operator/user-plugin)
   is orthogonal to a content trust tier (T0–T3). A plugin is never "T2";
   *content* is. Conflating them is a named bug class (tier-laundering) — keep
   the axes separate in all prose. (Highest-risk fidelity item; matches
   `capability_gate/policy.py`.)
10. **Vocabulary lock (with a gap fail-safe).** `docs/glossary.md` is the single
    source of AlfredOS vocabulary; where a `##` heading exists (canonical,
    GitHub-slugified anchor), reuse the exact term and link to it, never coin a
    synonym. **Some terms do NOT have a heading yet** (reviewer gate, egress
    plane, capability grant, audit graph) — for those, describe the concept
    plainly in the page body and do NOT invent a definitional heading or fake an
    anchor link. Alfred = the default persona; AlfredOS = the system.
11. **Disclosure guardrail A — no "how to weaken it" recipe.** Describe controls
    and their threat model in full (Apache-2.0, public repo, Kerckhoffs — full
    design disclosure is correct). But do NOT compile a step-by-step checklist
    for disabling DLP, widening the egress allowlist, or lowering a grant; that
    is operator-runbook material, not public-wiki headline material.
12. **Disclosure guardrails B & C — residuals paired, live values never.**
    (B) Whenever a page states a limitation or accepted residual, it must state,
    in the same breath, the assumption that puts it out of scope — e.g. "this
    presupposes an attacker with code execution inside the core container, which
    is full compromise and outside the tool-layer's threat boundary." A residual
    must read as *documented accepted risk*, never as an unpatched hole. (C)
    Describe canaries, allowlists, and secrets at the mechanism level; never
    enumerate literal canary strings, per-deployment seeding positions, real
    egress-allowlist domains, or anything token-shaped. **C is model-enforced
    only** — the wiki is generated in Devin's cloud, so it is backstopped by an
    input-side secret-shape scan over the files Devin ingests (see *Validation*),
    not by trusting the generator.

**Note-budget check:** 12 `repo_notes` + `page_notes`. Target ≤2 `page_notes`
per page; hard cap 3 (anchor pin + shipped-vs-scaffolded + anchor-gap on the few
pages that need all three). Worst case 12 + 3×29 = 99, under the 100 cap — so
`page_notes` MUST stay lean and the validator (Validation step 3) enforces the
running total, failing the build before the cap is breached. Each note is well
under 10,000 code points.

## Anchor-gap discipline (for pages without a curated anchor)

Several subsystems lack a `docs/subsystems/*` deep-doc — the headline pages
Memory, Orchestrator, Personas, Providers, Audit. For a page that has **neither
a deep-doc NOR a governing ADR**, `page_notes` must say: *"No curated deep-doc
exists yet — anchor to PRD §X + `src/alfred/<dir>/`; treat claims as unverified
until a deep-doc lands."* This makes the confidence gap visible per-page. The
note does **not** go on pages that DO have a curated anchor (e.g.
Connectivity-Free Core & Egress has ADR-0040; Hooks has `hooks.md` + ADR-0014).
`page_notes` stay pointers + a 2–3 sentence steer — never inlined doc content.

## Validation (deliverable 2)

`.devin/wiki.json` is a data file; a `scripts/` validator (reusing
`scripts/docs_check.py`'s heading-resolution machinery) enforces the following,
ships with **happy-path + failure-path + boundary fixtures** (a fixture
`wiki.json` violating each rule below MUST fail the validator — the validator
itself is untrustworthy without a red-path test), and is wired as a **required
status check** on `main` (a workflow that merely runs is not a gate):

1. **Valid JSON.**
2. **Schema conformance** — every page has non-empty `title` + `purpose`; every
   note has required fields; `repo_notes`/`page_notes` `content` non-empty.
3. **Limit conformance** — `pages` ≤ 30; total notes ≤ 100; each note ≤ 10,000
   **code points** (not bytes); page `title`s unique (exact-match, since `title`
   is the `parent` join key).
4. **Referential integrity** — every `parent` references an existing page
   `title`; **no parent cycle / self-ancestor** (a page cannot be its own
   ancestor); no dangling parent.
5. **Anchor resolution (not mere existence)** — for every anchor referenced in a
   `page_note`: the path exists **in the committed tree** (`git cat-file`/
   `git ls-files`, not the working tree — this catches gitignored generated
   outputs like root `CLAUDE.md`); a `PRD §N` / heading reference resolves to an
   actual heading; an `ADR-NNNN` file exists; a glossary `#slug` resolves to a
   real heading. Bare file-existence is insufficient — a renamed heading or
   stale ADR is exactly the "page becomes a lie" drift the file exists to
   prevent.
6. **Secret-shape scan (disclosure guardrail C backstop)** — scan the files
   Devin ingests for token-shaped strings / real secrets; `.env.example` is
   confirmed placeholders-only and per-deployment values are runtime (never in
   Devin's input), so this is a defense-in-depth tripwire, not the sole control.

## `docs/ARCHITECTURE.md` de-stale (deliverable 3)

`ARCHITECTURE.md` currently shows Spec B "in progress" and Spec C "future";
both are merged (#288, #333 closed). Because the Architecture root and the
Egress page anchor to it, and `repo_notes` #2/#6 assert those specs are
complete, the anchor must be corrected in-branch. Small edit; not human-gated.

## Regeneration lifecycle (how the wiki picks up changes)

`.devin/wiki.json` is read **during wiki generation** — there is no separate
"config changed" trigger, and (confirmed against Devin's docs, 2026-07-06) **no
webhook, GitHub Action, or public API to re-scrape on push to `main`**. The new
page tree / `repo_notes` take effect on the *next* regeneration, whichever fires
first:

- **Scheduled** — Cognition regenerates on its own cadence; an active repo can
  lag `main` by hours to days. Baseline, no action.
- **README badge (deliverable 4)** — ~weekly auto-regeneration; the only
  documented set-and-forget lever.
- **Manual on-demand** — an authenticated Devin user re-triggers generation from
  the repo's DeepWiki page. This is the **post-merge verification step**: after
  merging `wiki.json`, regenerate once and eyeball that the page tree + steering
  landed, rather than waiting for the schedule.

So the operational loop is: merge → manual regenerate once to verify → badge +
schedule handle steady state. A tighter "on every significant change" refresh is
not a first-class feature; if it's ever wanted, the only avenue is a Devin API
v3 generate endpoint (plan-dependent, not publicly documented) driven from CI —
recorded as a follow-up, not built here.

## Follow-ups (recorded, not done here)

- **Deep-doc backfill** — write deep-docs for the highest-priority of the
  currently-undocumented subsystems (Memory, Orchestrator, Personas, Providers,
  Audit, Gateway among ~13 without one); several graduated their slice long ago
  and never got the deep-doc.
- **Glossary top-up** — add the confirmed-missing entries **reviewer gate,
  egress plane, capability grant, audit graph** (Persona, OODA loop, Gateway,
  trust tier, dual-LLM split already exist — verified). Then `repo_notes` #10's
  gap fail-safe can be tightened.
- **CI-driven refresh** — if a tighter-than-weekly refresh is ever wanted, a
  push-to-`main` GitHub Action calling a Devin API v3 generate endpoint
  (plan-dependent, not publicly documented) is the only avenue; confirm against
  the Cognition plan first. See *Regeneration lifecycle*.

## Review incorporated (5-agent `/review-plan`, issue #398)

0 Critical. The trust-boundary `repo_notes` were verified accurate against code
(`capability_gate/policy.py`, ADR-0040/0046). Highs addressed in this revision:
Hooks page added (arch-001); `CLAUDE.md` anchors re-pointed to the committed
`.rulesync/rules/CLAUDE.md` (docs-001, verified: root `CLAUDE.md` is gitignored,
`.rulesync/rules/CLAUDE.md` holds the command table); `ARCHITECTURE.md` de-stale
promoted to a deliverable (docs-003); anchor-liveness upgraded to
anchor-**resolution** over the committed tree + validator fixtures + required
check (test-001/002, docs-002, test-004). Mediums: secrets+DLP now a global
`repo_note` (arch-005/sec-002); ADR-pin map added (arch-002); guardrail C
reframed as model-enforced + input scan (sec-001); vocab-lock note gap fail-safe
corrected against the live glossary (docs-004/005); README maturity caveat added
(docs-006). The gc.get_objects example was **swapped for a tamer in-core-code-
execution example** (sec-003). Self-contradictions the coordinator flagged are
reconciled (scope vs validator; anchor-gap scope; ADR-pin claim; vocab-lock).
Remaining Lows fixed: the "never anchor to src/" absolute softened to "never as
*primary* anchor" (arch-006); Telegram corrected to an MVP-target adapter, not
post-MVP (arch-007, per PRD §6.1); `Personas & Routing` renamed `Personas &
Addressing` to disambiguate from `Providers & Routing` (arch-008).
**Consciously deferred to the implementation plan / accepted:** the validator's
anchor-*extraction* contract from free-text `page_notes` (test-003) is an
implementation detail the plan pins down; the anchor-gap `page_note` template
(rev-004) is filled per-page at build time; the minor static string-rot risk
(docs-007) is an accepted residual the regenerate-on-change model keeps small.

## Open questions

None blocking. Egress-page placement resolved: page under **Architecture**
(topology identity), cross-linked from **Security Model**, invariant carried in
`repo_notes` #2.
