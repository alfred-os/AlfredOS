# ADR-0047: Adopt Devin DeepWiki for the public repository wiki

- **Status:** Accepted
- **Date:** 2026-07-06
- **Deciders:** #398 (Devin DeepWiki info set); 9-agent `/review-pr` fleet (architect finding)
- **Related:** the design spec
  (`../superpowers/specs/2026-07-06-devin-wiki-info-set-design.md`),
  [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md)
  (connectivity-free core), and `CLAUDE.md`'s "no fourth-party dependency
  without justification" rule (source of truth: `.rulesync/rules/CLAUDE.md`)

## Context

AlfredOS is public and Apache-2.0. People who land on the repository need to
understand it quickly — above all the **trust-boundary architecture**, which is
the whole differentiator. Cognition's **DeepWiki** auto-generates a public wiki
for any GitHub repository from its source. Left ungoverned, DeepWiki clusters
pages itself and can misdescribe the security model or present the not-yet-wired
real-LLM engine as operational.

DeepWiki supports a repo-committed steering file, `.devin/wiki.json`
(`repo_notes` + explicit `pages`), that fully controls the generated wiki.
Adopting it means taking on DeepWiki as a third-party service, which
`CLAUDE.md` asks us to justify with a decision record. The `/review-pr`
architect reviewer flagged that the committed spec + plan already serve as a
de-facto record, but that a canonical ADR — which the wiki's own ADR-index page
then references — is the right home for the decision.

## Decision

Adopt DeepWiki, governed by three committed artifacts:

1. **`.devin/wiki.json`** — an explicit 29-page tree plus 12 global `repo_notes`
   that encode the trust-boundary invariants as anti-pattern rules ("never write
   X") and mark shipped-vs-scaffolded state honestly. Pages are drift-anchored to
   curated committed docs, never to churn-prone `src/` directories or gitignored
   generated outputs.
2. **A stdlib validator** (`../../scripts/validate_devin_wiki.py`) that enforces
   the Devin schema and limits, referential integrity, **anchor resolution
   against the git-tracked tree**, and a token-shape secret scan. It gates under
   the existing required `Python (lint, types, unit)` check (its real-file test
   lives in `tests/unit/`), so no new branch-protection context is added.
3. **The DeepWiki README badge** — the only documented set-and-forget refresh
   lever (~weekly auto-regeneration); there is no push webhook or public API to
   re-scrape on demand.

## Why this is compatible with the connectivity-free-core mandate

DeepWiki is Cognition's **cloud** service reading the **already-public** GitHub
repository. It is **not** a runtime dependency of AlfredOS: the core opens no
socket to it, shares no secret with it, and the connectivity-free-core /
gateway-sole-egress invariant ([ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md))
is untouched. No credential, no PII, and no T3 content crosses to DeepWiki
beyond what is already public on GitHub. This is a docs-time external service
operating on public source, not a fourth-party dependency of the running system.

## Consequences

- The public wiki regenerates on Devin's own schedule, the weekly README badge,
  or a manual on-demand regenerate. `.devin/wiki.json` takes effect on the
  **next** regeneration — there is no config-change trigger — so a manual
  regenerate is the post-merge verification step.
- `.devin/wiki.json` and its `repo_notes` must stay accurate as the architecture
  evolves. The CI validator catches anchor drift (a moved doc, a renamed
  heading, a stale ADR number); content fidelity remains a maintenance
  obligation.
- **Disclosure posture:** full design and threat-model disclosure (Kerckhoffs;
  the repository is already public), bounded by three `repo_notes` guardrails —
  no "how to weaken it" recipe, pair every residual with its threat-model
  boundary, and describe mechanisms without enumerating live values.
- **Follow-ups** (recorded, out of scope here): deep-doc backfill for the
  currently-undocumented subsystems, and a glossary top-up (reviewer gate,
  egress plane, capability grant, audit graph).

## Alternatives considered

- **A hand-maintained wiki** (GitHub wiki or a docs site): higher maintenance,
  drifts from the code, and forgoes DeepWiki's structural analysis of the repo.
- **`repo_notes`-only steering** (let DeepWiki cluster the pages itself): less
  control and a non-deterministic structure; the security subtree would not be
  guaranteed first-class.
- **No wiki / no steering file:** DeepWiki still auto-generates an *ungoverned*
  public wiki that can misdescribe the trust boundary and oversell unshipped
  surfaces — strictly worse than steering it.
