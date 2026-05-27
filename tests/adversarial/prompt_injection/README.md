# Prompt-injection adversarial corpus

T3 content (web pages, emails, RAG snippets, tool outputs, file contents,
inter-persona messages) trying to issue instructions to the privileged
orchestrator. The defense under test is the dual-LLM split + the quarantined
LLM's structured-extraction path; payloads must be **neutralized** — the
attacker's instructions never reach a tool-calling step. ID prefix `pi-`.

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
