# Hook tier-escalation adversarial corpus

A user-plugin tries to register a callback (or refuse a turn) at a tier it
was never granted — typically targeting a system-only hookpoint such as
`memory.episodic.record.before_db_write`. The defense under test is the
two-gate model in the Slice-2.5 hooks spec (§6.1 capability gate + §6.3
runtime tier check, with §6.2 deny-path semantics as backstop — Slice-2.5
shipped these via `DevGate`; post-PR-S3-7 the production gate is
`alfred.security.capability_gate._gate.RealGate`, and adversarial
deny-path tests assert against it via
`tests.helpers.gates.make_deny_all_gate` per Slice-3 spec §15.1):
every registration and every per-call dispatch must verify the
caller's granted tier matches the hookpoint's declared tier.
Outcome **refused**. ID prefix `hk-`.

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
