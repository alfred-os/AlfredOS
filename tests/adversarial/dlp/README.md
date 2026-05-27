# DLP adversarial corpus

Synthetic secrets (fake AWS keys, Stripe tokens, JWTs, Discord bot tokens,
personal-data variants) seeded into outbound paths. The defense under test
is `OutboundDlp.scan` — payloads must be **caught_by_dlp** (broker.redact
stage 1 or generic-API-key regex stage 2). Payloads exercise the redaction,
never assert a leak path. ID prefix `dlp-`.

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
