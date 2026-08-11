# DLP adversarial corpus

Synthetic secrets (fake AWS keys, Stripe tokens, JWTs, Discord bot tokens,
personal-data variants) seeded into outbound paths, plus T0/T1/T2-origin DLP
mechanics generally (distinct from `dlp_egress`, which is specifically for
exfiltration vectors where untrusted T3 ingestion is the attack entry point —
see `dlp_egress/README.md`). The defense under test is `OutboundDlp.scan` —
payloads must be **caught_by_dlp**, **quarantined** (a canary trip), or
**audit_row_emitted** (a non-canary DLP fault still leaves a terminal audit
row before propagating). Payloads exercise the defense, never assert a leak
path. ID prefix `dlp-`.

## Coverage matrix

Maps each enumerated attack vector to the PR/task that implements it — the contract
between this category's threat model and the implementing task graph.

| Attack vector | Owning PR / Task |
| --- | --- |
| Model output emits a known SUPPORTED_SECRETS value verbatim into a user-facing reply via an MCP tool-output ingestion path | Slice-2 PR-E (`dlp-2026-001` `known_secret_leak.yaml`) |
| `dispatch_tool`'s `InternalToolSpec` (T2, first-party) leg's own dispatch result carries an operator-registered canary token; the leg must scan it through DLP and ESCALATE (`dlp_canary`/`quarantined`, `OutboundCanaryTripped` propagates) — before #410 PR3 Task 2a this leg never called `dlp.scan()` at all | #410 PR3 Task 2a (`dlp-2026-002` `internal_tool_dlp_canary.yaml`) |
| A non-canary `dlp.scan()` failure on the `InternalToolSpec` leg (broker bug, DLP-internal audit-sink failure, canary-matcher bug) must still leave a loud terminal `unexpected_error`/`fault` audit row before propagating — the sec-001 totality-wrapper correction | #410 PR3 Task 2a (`dlp-2026-003` `internal_tool_dlp_non_canary_fault.yaml`) |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
