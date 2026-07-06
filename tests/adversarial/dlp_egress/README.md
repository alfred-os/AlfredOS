# DLP-egress adversarial corpus

Attacks where T3-origin content carries or enables exfiltration of secrets,
credentials, or canary tokens through an AlfredOS output channel. Distinct
from the existing `dlp` category (which covers T0/T1/T2-origin DLP mechanics)
— `dlp_egress` is specifically for exfiltration vectors where untrusted T3
ingestion is the attack entry point (spec §12.1 category disambiguation:
"dlp_egress = T3-origin exfiltration paths; dlp = T0/T1/T2-origin DLP mechanics").

Attack vectors covered (Slice-3 seed → Spec C G7 egress plane):

- Canary token planted in T3 web content propagating through the quarantined LLM
  into structured output → DLP scan → audit row.
- Cross-field secret leak via headers + cookies in a web request.
- DNS-rebinding SSRF to a non-globally-routable IP (resolved-IP guard).
- Gateway DLP second-pass + egress canary trip on the mode-(b) tool-egress relay.
- Egress-id replay / forgery and IO-plane-down audit completeness.
- Connectivity-free-core DNS exfil, L7-proxy literal-IP CONNECT refusal, and the
  recorded mode-(a) provider-prompt / SNI-cotenant residuals (Spec C §9).

Outcome: one of the schema `ExpectedOutcome` values (**audit_row_emitted**,
**caught_by_dlp**, **refused**, **boundary_refused**, …). Recorded residuals are
flagged `out_of_scope: true` + a rationale rather than claiming a catch. ID prefix: `de-`.

The authoritative per-entry mapping is the coverage matrix below.

## Coverage matrix

Maps each enumerated attack vector to the PR/task that implements it. Vectors labelled
**TBD — Slice-3 follow-on (no current task)** have no implementing payload yet; they require a
follow-on PR or an explicit out-of-scope decision. The matrix is the contract between this
category's threat model and the implementing task graph — drift between the two is a
release-blocker.

| Attack vector | Owning PR / Task |
| --- | --- |
| Canary token planted in T3 web content → quarantined LLM → structured output → DLP scan → audit row | PR-S3-5 Task 12 (`de-2026-001` `canary_token_html.yaml`) |
| Cross-field secret leak via headers + cookies in a web request | PR-S3-5 Task 13 (`de-2026-002` `cross_field_secret_leak.yaml`) |
| Subprocess env-leak via misconfigured launcher (missing explicit `env=` dict) | **TBD — Slice-3 follow-on (no current task)** — PR-S3-3a covers the env-scrub spawn in `tests/unit/plugins/test_env_scrub_subprocess.py` but no `dlp_egress` adversarial payload formalises the exfiltration vector. Unit-test coverage protects against regression; the adversarial payload would close the threat-model loop |
| Manifest allowlist broadening (malicious manifest update widens `allowed_domains`) | **TBD — Slice-3 follow-on (no current task)** — PR-S3-5 implements the three-way allowlist intersection and the `web.allowlist.manifest_broadening_capped` audit row in `tests/unit/`, but no `dlp_egress` adversarial payload exercises the manifest-update attack end-to-end |
| DNS-rebinding SSRF: an allowlisted hostname resolves (attacker-controlled DNS) to an internal/metadata IP (169.254.169.254, RFC1918, loopback); the netloc allowlist does not check resolved IPs, so the gateway relay resolves server-side and refuses non-globally-routable IPs (`RESOLVED_IP_NOT_GLOBAL`) before opening upstream | PR #333 G7-2b / issue #333 (`de-2026-003` `dns_rebinding_to_metadata.yaml`) |
| Egress no-orphan + in-flight liveness: a gate-denied/cancelled egress fetch must not orphan a raw T3 body in the unbounded `QuarantineStagingMap` (C9), and concurrent egress on the shared quarantine child must not deadlock (C1); the per-user resource-exhaustion refusal (`handle_cap`, spec §7.10) is CONVERTED — a real passing per-user `handle_cap` refusal test (#339 PR4a, `merge_blocker: false`; see ADR-0047) | PR #333 / issue #333 (`de-2026-004` `egress_inflight_and_no_orphan.yaml` + `test_egress_no_orphan_and_inflight.py`) |
| Planted secret in the state.git proposal-dispatch `failure_detail` channel → `OutboundDlp.scan` redacts before the ledger write | PR-S4-2 / issue #173 (`de-2026-005` `dispatch_loop_failure_detail_leak.yaml` + `test_dispatch_loop_failure_detail_leak.py`) |
| Canary token in the proposal-dispatch `failure_detail` channel → `HookRefusal` aborts the write + emits `security.dlp_outbound_refused` | PR-S4-2 / issue #173 (`de-2026-006` `dispatch_loop_failure_detail_canary_refused.yaml` + `test_dispatch_loop_failure_detail_canary_refused.py`; Slice-5 TODO on the real canary mechanism) |
| Gateway DLP second-pass catch: compromised in-core `OutboundDlp` (no-op) passes a secret-shaped value; gateway stages 2+3 catch it and deny with `deny_reason=dlp_redacted`; `RelayEgressClient` raises `EgressDeniedError` + writes `security.egress_relay_refused` audit row before raise | PR #333 G7-2c-2 / issue #333 (`de-2026-007` `de_egress_gateway_dlp_non_canary_catch.yaml` + `test_de_egress_gateway_dlp_non_canary_catch.py`) |
| Canary trip on egress: canary token appears verbatim in egress body; gateway `EgressRelay` DLP stage-3 canary scanner denies with `deny_reason=canary_tripped`; `RelayEgressClient` raises `EgressDeniedError` + writes `security.egress_relay_refused` audit row | PR #333 G7-2c-2 / issue #333 (`de-2026-008` `de_egress_canary_trip.yaml` + `test_de_egress_canary_trip.py`) |
| Egress-id replay / forgery / different-hash: four ledger-integrity sub-scenarios — `replay_complete` (dedup, no re-fire), `in_doubt_non_idempotent` (`EgressInDoubtError`), `different_hash` (`EgressIdIntegrityError`), `forged_unknown_id` (`EgressLedgerStateError`); no upstream re-fire on any path | PR #333 G7-2c-2 / issue #333 (`de-2026-009` `de_egress_id_replay_forgery.yaml` + `test_de_egress_id_replay_forgery.py`) |
| IO-plane-down audit completeness: three typed error paths (relay unreachable → `RelayIOPlaneUnavailableError`, gateway deny → `EgressDeniedError`, in-doubt non-idempotent → `EgressInDoubtError`) each emit exactly one payload-blind `security.egress_relay_refused` audit row before raising | PR #333 G7-2c-2 / issue #333 (`de-2026-010` `de_egress_io_plane_down_audit.yaml` + `test_de_egress_io_plane_down_audit.py`) |
| Content-type laundering: a malicious upstream returns `application/octet-stream` (off the web.fetch MIME allowlist) to smuggle binary bytes through the D1 response seam; caught pre-extract (`cannot_extract`, payload-blind) | PR #333 G7-2 / issue #333 (`de-2026-011` `de_egress_content_type_laundering.yaml` + `test_de_egress_content_type_laundering.py`) |
| Inbound egress-response canary reflected in a hostile upstream body; the web.fetch inbound-canary scan is now WIRED (core-side `ALFRED_WEB_FETCH_CANARY_TOKENS` token source → factory-derived non-`None` `ResponsePolicy.canary`) — CONVERTED to a real passing reflected-canary test (#339 PR4a, `merge_blocker: false`; see ADR-0047) | PR #333 / issue #333 (`de-2026-012` `de_egress_inbound_canary_unwired.yaml` + `test_de_egress_inbound_canary_unwired.py`) |
| DNS exfil: the connectivity-free core cannot resolve an external name in the split topology (§7 probe) — asserts the shipped compose precondition (+ positive control) and anti-rot on the docker kernel proof (`EXTERNAL_DNS_BLOCKED`) | PR #333 G7-5 / issue #333 (`de-2026-013` `de_egress_core_dns_isolation.yaml` + `test_de_egress_core_dns_isolation.py`) |
| Mode-(a) provider-prompt exfil — RECORDED RESIDUAL (`out_of_scope=true`): TLS-passthrough is destination-gated only, no body inspection (ADR-0040 residual (ii), to be drafted by PR-D) | PR #333 G7-5 / issue #333 (`de-2026-014` `de_egress_mode_a_provider_prompt_residual.yaml` + `test_de_egress_recorded_residuals.py`) |
| L7-proxy literal-IP CONNECT refusal: drives the real `EgressForwardProxy`, asserts `403` + `literal_ip_target` (buffer + audit) | PR #333 G7-5 / issue #333 (`de-2026-015` `de_egress_literal_ip_connect_refused.yaml` + `test_de_egress_literal_ip_refused.py`) |
| Discord SNI-spoof-to-cotenant / CDN-cotenant — RECORDED RESIDUAL (`out_of_scope=true`): TLS-passthrough is SNI-blind within allowlisted fronting (ADR-0040 residual (i), to be drafted by PR-D) | PR #333 G7-5 / issue #333 (`de-2026-016` `de_egress_sni_spoof_cotenant_residual.yaml` + `test_de_egress_recorded_residuals.py`) |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
