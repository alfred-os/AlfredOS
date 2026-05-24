---
name: alfred-audit-write
description: Use whenever you need to write to the AlfredOS audit log - tool calls, memory writes, config changes, reviewer decisions, persona coordination messages. Covers attribution fields, append-only patterns, and signing.
---

# Writing to the AlfredOS audit log

The audit log is append-only, signed, and separately retained from operational logs. It is forensic infrastructure. Treat it accordingly.

## What gets logged

Every:

- Tool call (success and failure)
- Memory write (semantic fact, episodic summary, graph edit, vector embed)
- Config change (in `/var/lib/alfred/state.git`)
- Reviewer decision (approve / request changes / reject)
- Persona coordination message
- Capability grant + capability denial
- DLP redaction
- Canary trip
- Step-up auth request + response

## Required attribution

Every entry must include:

- `event_id` — UUIDv7
- `trace_id` — propagated from the originating user request
- `timestamp` — RFC3339 with timezone
- `actor` — `{user_id?, persona, model?}`
- `subject` — what was acted on (tool name + args, fact_id, commit_sha, etc.)
- `prompt_excerpt` — the proximate prompt that triggered the action (for forensic post-mortems)
- `trust_tier_of_trigger` — T0/T1/T2/T3
- `result` — outcome (success/failure/refused/quarantined)
- `cost_estimate` — usd, where relevant

## How to write

Use the helper:

```python
from alfred.security.audit import audit_log

audit_log.append(
    event="tool_call",
    actor={"user_id": user.id, "persona": "lucius"},
    subject={"tool": "web.fetch", "args": redact(args)},
    trust_tier_of_trigger="T2",
    result="success",
    cost_estimate=0.0024,
)
```

The helper handles signing, ordering, and retention. **Never bypass it** with a direct DB write.

## Failure semantics

- A failed audit write is loud and trips quarantine on the originating conversation.
- The originating action should not proceed if the audit write fails.
- Audit writes are non-skippable in tests too.

## Querying

- `alfred audit log --since 24h --user <id>` — text view
- `alfred audit show <event_id>` — single-event detail
- `alfred audit graph --since 24h` — graphviz of inter-persona traffic with token costs per edge
- Direct SQL is allowed for operator-tier reads, never for writes
