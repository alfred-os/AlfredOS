---
name: alfred-trust-tiers
description: >-
  Use whenever you write or review code that ingests external content (web,
  email, files, MCP tool outputs, file contents, inter-persona messages) or
  whenever you design a new flow that involves data crossing the AlfredOS trust
  boundary. Covers the T0-T3 system, the dual-LLM split, and common tagging
  patterns.
targets:
  - '*'
---
# Trust tiers in AlfredOS

AlfredOS classifies every piece of content by trust tier. The classification gates what the privileged orchestrator may consider as instructions.

## The four tiers

| Tier | Source | Examples |
|---|---|---|
| T0 system | AlfredOS itself | Code in `src/`, prompts in `personas/`, configs in `config/` |
| T1 operator | Person running the instance | Operator-set config edits, plugin enable/disable decisions |
| T2 authenticated user / sibling persona | A logged-in user, or another persona | A user's typed Discord message body; an inter-persona request from `lucius` to `oracle` |
| T3 untrusted | External content the user did not author | Web pages, email bodies, file contents, RAG snippets, MCP tool outputs, URL unfurls, link previews |

## The dual-LLM split

The privileged orchestrator sees T0 + T1 + T2 only. It never sees raw T3.

The quarantined LLM is the only consumer of T3 content. It emits **structured data** (typed JSON), never free text fed back as instructions, never tool calls.

When the orchestrator needs information from T3 content (summarize an email, extract a number from a web page), it asks the quarantined LLM, which returns structured data. The orchestrator treats the response as **data**, not as new instructions.

## Tagging at the boundary

Every function that ingests external content tags it at the boundary. The pattern:

```python
from alfred.security.tiers import tag

result = tag(raw_content, tier="T3", source="web.fetch", url=url)
# `result` is a TaggedContent[T3] — the type system enforces that it can only
# flow into the quarantined LLM path, never the privileged orchestrator.
```

No untagged external content is allowed anywhere in the codebase. Tests verify this with static analysis.

## Sibling-persona content

When persona A relays content from a T3 source to persona B, the content **stays T3** even though the persona-to-persona message itself is T2. Use:

```python
relay = build_relay(
    from_persona="lucius",
    to_persona="oracle",
    purpose="cite_source",
    content=TaggedContent[T3](text=fetched_page),  # type preserves the tier
)
```

The receiver's tool layer treats the relayed content as T3.

## Common antipatterns (release-blockers)

1. **Untagged external content reaching the orchestrator.** Always tag at the boundary.
2. **String concatenation that mixes tiers.** Use `TaggedContent` wrappers, not plain strings.
3. **"Trusting" T3 because the quarantined LLM extracted it cleanly.** The extraction is just data; treat as data.
4. **Bypassing the tier system in tests** to make a test pass. Fix the test, not the boundary.
5. **Sibling-persona relays that strip the original tier.** The tier travels with the content.

## When you find a leak

1. Stop and audit how much of the codebase touches the leaked path.
2. Write the failing test that demonstrates the leak.
3. Add tagging at the boundary.
4. Make the test pass.
5. Extend the adversarial corpus with a payload that would exploit the leak.
6. Open a private security advisory if the leak shipped.

## See also

- PRD §7.1 — full trust-boundary section
- Skill: `alfred-adversarial-corpus` — how to write adversarial payloads for new tier rules
- Skill: `alfred-audit-write` — every tier-related decision is audited
