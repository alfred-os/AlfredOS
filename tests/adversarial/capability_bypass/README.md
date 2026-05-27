# Capability-bypass adversarial corpus

Transcripts attempting tool calls outside the current persona's grant —
coerced via role-play, faux-system messages, or chained tool output. The
defense under test is the capability gate at the tool layer; payloads must
be **refused** at call-issue time, never silently dispatched. ID prefix
`cap-`.

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
