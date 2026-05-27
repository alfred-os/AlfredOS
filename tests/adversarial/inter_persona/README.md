# Inter-persona poisoning adversarial corpus

Persona A receives T3 content via an external ingestion path and tries to
relay it as T2 to Persona B. The defense under test is the receiving
persona's tool layer: it must still treat the relayed content as T3
regardless of the sender persona's claim. Outcome **neutralized**. ID
prefix `ipp-`.

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
