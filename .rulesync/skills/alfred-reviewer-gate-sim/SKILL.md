---
name: alfred-reviewer-gate-sim
description: >-
  Use before submitting a proposal through the runtime reviewer gate. Simulates
  the gate locally so devs can preview how their proposal will be evaluated and
  fix issues before the gate spends real reviewer-agent tokens.
targets:
  - '*'
---
# Simulating the runtime reviewer gate

The runtime reviewer gate processes proposals (new skills, prompt changes, persona changes, plugin install). Simulating it locally lets you fix issues before incurring reviewer-agent cost.

## When to use the sim

- Before submitting a new skill proposal
- Before changing a persona definition
- Before modifying routing.yaml or security policy
- During PR-time review of any proposal-shaped change

## What the sim checks

1. **Single responsibility** — manifest's `single_responsibility` reads as one sentence with no "and."
2. **Tests present** — happy + error + refusal tests exist and are runnable.
3. **Tests pass** — run them in the sandbox; report results.
4. **Capability declarations are minimal** — flag any over-granted capabilities not exercised by tests.
5. **No DRY violations** — grep for similar existing skills; flag overlap.
6. **No silent failures** — grep the changeset for catch-without-rethrow patterns in trust-boundary paths.
7. **Trust-tier propagation** — if the change ingests external content, tier tagging is present.
8. **PRD alignment** — section the change relates to is cited in the proposal rationale.
9. **Audit emissions** — every side-effecting code path emits an audit entry.

## How to run

```bash
alfred propose simulate path/to/proposal/
```

The sim outputs a checklist with pass/fail and quotes the specific lines the runtime reviewer will flag.

## Mapping sim output → action

| Sim says | You do |
| --- | --- |
| "no refusal test" | Add `tests/test_refusal.py` |
| "capability X granted but unused" | Remove from manifest or add a test that exercises it |
| "similar skill 'foo' already exists" | Refactor to use the existing skill, or document why duplication is necessary |
| "side-effect without audit emission" | Add the `audit_log.append(...)` call |

## What the sim does NOT do

- It does not call a real reviewer-agent LLM. It runs deterministic checks.
- It does not approve anything. The actual gate runs in production with the reviewer agent.
