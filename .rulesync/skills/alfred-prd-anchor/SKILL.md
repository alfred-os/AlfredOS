---
name: alfred-prd-anchor
description: >-
  Use whenever you need to ground a decision in the AlfredOS PRD. Fetches the
  relevant section instead of re-reading the whole document. Every agent should
  pull this in before proposing design changes.
targets:
  - '*'
---
# Anchoring to the AlfredOS PRD

The PRD (`PRD.md`) is the source of truth. Don't infer from code; read the section.

## Common section anchors

| You need to know about... | Look at PRD section |
|---|---|
| Mission, primary user, success criteria | §1–§4 |
| Architecture overview + invariants | §5 |
| Comms adapters | §6.1 |
| Memory model (6 layers, consolidation, auto-retrieve) | §6.2 |
| MCP plugin protocol & skill lifecycle | §6.3 |
| Reviewer gate & self-improvement flow | §6.4 |
| Caching layers & cost control | §6.5 |
| Provider routing & internal-CLI providers | §6.6 |
| Deployment, setup script, self-healing | §6.7 |
| Persona system, addressing, group sessions, coordination rails | §6.8 |
| Trust tiers, dual-LLM split, secret broker, DLP, canaries, audit & rollback | §7.1 |
| Multi-user identity & authorization | §7.2 |
| Self-healing & auto-recovery | §7.3 |
| Audit trail & rollback | §7.4 |
| Observability (logs/metrics/traces/dashboards/alerts) | §7.5 |
| Scalability path | §7.6 |
| Testing strategy + adversarial suite | §8 |
| MVP scope vs. roadmap | §9 |
| Decisions log (DEC-NNN) | §10 |
| Glossary | §11 |

## How to use

1. **Grep the PRD first.** `grep -n "<term>" PRD.md`
2. **Read just the relevant section.** Use `Read` with `offset` + `limit` for surgical context.
3. **Quote the PRD line** in PR descriptions and ADRs: "Per PRD §7.1: 'The privileged orchestrator never sees raw T3 content...'"
4. **If the PRD doesn't answer your question**, flag it — propose an ADR or surface to `alfred-architect`. Don't guess.

## When the code disagrees with the PRD

The PRD wins. Either the code drifted (open a fix PR) or the PRD needs updating (ADR + PRD edit). Never silently match the code's behavior.
