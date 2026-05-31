# DLP-egress adversarial corpus

Attacks where T3-origin content carries or enables exfiltration of secrets,
credentials, or canary tokens through an AlfredOS output channel. Distinct
from the existing `dlp` category (which covers T0/T1/T2-origin DLP mechanics)
— `dlp_egress` is specifically for exfiltration vectors where untrusted T3
ingestion is the attack entry point (spec §12.1 category disambiguation:
"dlp_egress = T3-origin exfiltration paths; dlp = T0/T1/T2-origin DLP mechanics").

Attack vectors covered:
- Canary token planted in T3 web content propagating through quarantined LLM
  into structured output → DLP scan → audit row.
- Cross-field secret leak via headers + cookies in a web request.
- Subprocess env-leak via misconfigured launcher (missing explicit `env=` dict).
- Manifest allowlist broadening: malicious manifest update declares wider
  `allowed_domains` — asserts `web.allowlist.manifest_broadening_capped` audit row
  fires and the broadened domain is not reachable.

Outcome: **audit_row_emitted** (specific canary/DLP audit row asserted), or
**boundary_refused** (DLP scan refuses the exfiltration path). ID prefix: `de-`.

Implementations land in PR-S3-5 (`web.fetch` + `InboundCanaryScanner` payloads).

## Coverage matrix

Maps each enumerated attack vector to the Slice-3 PR/task that implements it. Vectors labelled
**TBD — Slice-3 follow-on (no current task)** have no implementing payload in any current
Slice-3 plan; they require a follow-on PR or an explicit out-of-scope decision before Slice-3
closes. The matrix is the contract between this category's threat model and the slice's task
graph — drift between the two is a release-blocker.

| Attack vector | Owning PR / Task |
|---|---|
| Canary token planted in T3 web content → quarantined LLM → structured output → DLP scan → audit row | PR-S3-5 Task 12 (`de-2026-001` `canary_token_html.yaml`) |
| Cross-field secret leak via headers + cookies in a web request | PR-S3-5 Task 13 (`de-2026-002` `cross_field_secret_leak.yaml`) |
| Subprocess env-leak via misconfigured launcher (missing explicit `env=` dict) | **TBD — Slice-3 follow-on (no current task)** — PR-S3-3a covers the env-scrub spawn in `tests/unit/plugins/test_env_scrub_subprocess.py` but no `dlp_egress` adversarial payload formalises the exfiltration vector. Unit-test coverage protects against regression; the adversarial payload would close the threat-model loop |
| Manifest allowlist broadening (malicious manifest update widens `allowed_domains`) | **TBD — Slice-3 follow-on (no current task)** — PR-S3-5 implements the three-way allowlist intersection and the `web.allowlist.manifest_broadening_capped` audit row in `tests/unit/`, but no `dlp_egress` adversarial payload exercises the manifest-update attack end-to-end |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
