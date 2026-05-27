# Canary-trip adversarial corpus

Canary tokens seeded into ingested content (web pages, RAG snippets, file
bodies). The defense under test is the canary-watcher on outbound paths —
any reuse of a planted token by the orchestrator must trip the
**quarantined** state within the SLA window. ID prefix `cnry-`.

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
