# Hook tier-escalation adversarial corpus

A user-plugin tries to register a callback (or refuse a turn) at a tier it
was never granted — typically targeting a system-only hookpoint such as
`memory.episodic.record.before_db_write`. The defense under test is the
two-gate model in the Slice-2.5 hooks spec (§6.1 capability gate + §6.3
runtime tier check, with §6.2 DevGate denial as backstop): every
registration and every per-call dispatch must verify the caller's granted
tier matches the hookpoint's declared tier. Outcome **refused**. ID prefix
`hk-`.

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
