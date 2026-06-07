# Comms identity-boundary adversarial corpus

Attacks against the comms-MCP wire's platform-identity → canonical-user
resolution boundary (PR-S4-8 foundations, PR-S4-9 Discord, PR-S4-10 TUI).
Covers platform-id spoofing, addressing-drift, verification-phrase replay,
attachment SHA-mismatch TOCTOU, and DLP-bypass on outbound retry.

**Attack vectors covered**

- Inbound message claiming a `platform_user_id` that resolves to a different
  canonical `User` than the bound DB row (binding-cache poisoning attempt).
- Addressing-drift: thread retitle that changes the addressing signal mid-thread
  (refused with `COMMS_ADDRESSING_DRIFT_FIELDS`).
- Verification-phrase replay from a different `platform_user_id` than the one
  that requested binding (PR-S4-9 round-2 closure 12;
  `reason="phrase_platform_user_mismatch"`).
- Attachment SHA mismatch TOCTOU between DLP scan and broker substitution
  (PR-S4-8 round-2 closure 4; `ContentRef.content_sha256` verification refuses).
- Outbound DLP bypass via queue.pause → policy-tighten → queue.resume race
  (PR-S4-9 round-2 closure 6 `cib-2026-004`).
- Per-platform-user rate-limit DoS via spray of fresh `platform_user_id`s
  before resolution (PR-S4-8 round-2 closure 3 — pre-resolution coarse
  limiter refuses).
- Prompt injection through Discord sub-payloads (embed-title, embed-description,
  embed-field-name, etc. — PR-S4-9 round-2 closure 9 lists nine surfaces).

**Prefix.** `cib-`

**Owning PRs.** PR-S4-8 (foundations), PR-S4-9 (Discord), PR-S4-10 (TUI).

**Ingestion paths.** `inbound_notification_handler`, `comms_inbound_message`.

**Expected outcomes.** `refused`, `audit_row_emitted` anchored to
`COMMS_INBOUND_BUDGET_CAPPED_FIELDS` / `COMMS_INBOUND_T3_PROMOTION_FIELDS`,
or `boundary_refused` (the existing Slice-3 outcome reused for tier
refusal at the wire).

**Status at graduation.** Minimum 3 entries.

## Coverage matrix

Maps each enumerated attack vector to the Slice-4 PR / task that lands its implementing
payload. Vectors labelled **TBD — Slice-4 follow-on (no current task)** have no
implementing payload in any current Slice-4 plan; they require a follow-on PR or
an explicit out-of-scope decision before Slice-4 closes. The matrix is the
contract between this category's threat model and the slice's task graph —
drift is a release-blocker.

| Attack vector | Owning PR / Task |
|---|---|
| Inbound platform_user_id resolves to different canonical User | PR-S4-8 (`cib-2026-001`) |
| Addressing-drift via thread retitle mid-thread | PR-S4-9 (`cib-2026-005` — `COMMS_ADDRESSING_DRIFT_FIELDS`) |
| Verification-phrase replay from different platform_user_id | PR-S4-9 (`cib-2026-003` — `phrase_platform_user_mismatch` refusal) |
| Attachment SHA mismatch TOCTOU between DLP scan and broker substitution | PR-S4-8 (`cib-2026-006` — `ContentRefShaSizeMismatch`) |
| Outbound DLP bypass via queue.pause → policy-tighten → queue.resume | PR-S4-9 (`cib-2026-004` — re-scan defensively at resume) |
| Pre-resolution DoS via spray of fresh platform_user_ids | PR-S4-8 (`cib-2026-002` — pre-resolution coarse limiter) |
| Prompt injection through Discord sub-payloads (9 surfaces) | PR-S4-9 (`cib-2026-007..015`) |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
