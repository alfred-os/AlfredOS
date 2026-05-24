---
name: alfred-runtime-skill-author
description: Use when authoring a runtime skill that AlfredOS itself will use (procedural plugin in skills/). Covers manifest format, mandatory tests, refusal logic, and reviewer-gate expectations. Different from authoring Claude Code skills - this is for AlfredOS's own runtime skills.
---

# Authoring a runtime skill for AlfredOS

Runtime skills are procedural plugins AlfredOS personas use to do things. They live in `skills/<name>/`, are reviewer-gated, and must come with mandatory tests.

## Layout

```
skills/<name>/
├── manifest.json
├── README.md              # agent-readable: when to invoke this skill
├── skill.py               # or skill.ts, skill.go, etc.
└── tests/
    ├── test_happy.py
    ├── test_error.py
    └── test_refusal.py
```

## Manifest

- `name` — kebab-case
- `version` — semver
- `description` — one paragraph (this is what an agent reads to decide whether to invoke)
- `single_responsibility` — one sentence describing the skill's single purpose
- `capabilities_required` — same shape as MCP plugin manifest
- `inputs` / `outputs` — typed schema
- `trust_tier` — defaults to `T2` (agent-internal). T3 only if the skill processes raw untrusted content (and then it must emit structured data, not free text)
- `tests` — pointer to the test files

## Single responsibility

Each skill does **one thing**. If your skill description has the word "and" in it, you probably need two skills.

## Mandatory tests

1. **Happy path** — input → expected output
2. **Error path** — upstream failure → meaningful error, no crash
3. **Out-of-scope refusal** — called for something the skill should not do → declines and explains why

The reviewer rejects skills missing any of the three.

## Reviewer-gate expectations

- The agent proposing the skill writes the manifest, the code, and the tests.
- Tests run in a sandboxed container before the reviewer sees the diff.
- The reviewer (different model) reads only diff + tests + rationale; it does not see the conversation that produced the proposal.
- Approve → merge to `main` in the internal git repo → hot reload.
- Request changes → bounce back with feedback (max N iterations).
- Reject → close proposal, log decision, notify operator.

## Common antipatterns

- Side-effects outside the declared capabilities.
- Copy-pasting logic that exists in another skill (DRY across skills).
- Tests that mock out the capability gate to "always allow" (forbidden).
- Free-text outputs when structured data would suffice.
- Catching exceptions silently in trust-boundary paths.
