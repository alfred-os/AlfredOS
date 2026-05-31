# Tier-laundering adversarial corpus

Attacks that attempt to make T3 content (untrusted ingestion) appear as T2
(authenticated-user) or T0 (system) content — bypassing the type-level
discriminants AlfredOS uses to keep the privileged orchestrator from ever
processing raw T3. The defence under test is the full T3 boundary: the
nonce-gated `tag(T3, ...)` factory (spec §3.2), the wire-format serialiser's
cross-tier rejection (spec §3.5), the `cast(TaggedContent[T2], t3_value)`
ruff/grep CI rule (spec §3.7-3.8), and the capability-gate's
`check_content_clearance` method (spec §8.2).

Attack vectors covered:
- `cast(TaggedContent[T2], t3_value)` bypass — pytest module (requires Python-level
  code execution; spec §12.2 fixture-vs-pytest allocation).
- Wire-format tier confusion — JSON payload with `"tier": "T2"` but T3-constructed
  content; YAML payload.
- `tag(T3, ...)` from orchestrator module context — pytest module.
- Frame-introspection bypass — monkey-patch `sys.modules` to forge `__name__`; pytest module.
- Capability-gate bypass via `subscriber_tier=user-plugin` on a T3-carrying hookpoint — YAML payload.
- Post-handshake hook registration attack — pytest module (requires live subprocess).
- In-flight grant revocation race — YAML payload.
- Retry-guidance hygiene — malformed-output corpus through prompt-embedded fallback; pytest module.
- `gc.get_objects()`-style T3 token retrieval — pytest module labelled `out_of_scope`; asserts
  explicit rationale rather than treating as unresolved gap (spec §3.2 threat model limits).

Outcome: **boundary_refused** (type-system refusal), or **audit_row_emitted** (specific
named audit row asserted). ID prefix: `tl-`.

Implementations land in PR-S3-1 (type-system payloads), PR-S3-2 (capability-gate payloads),
PR-S3-3a (post-handshake attack payload), PR-S3-4 (retry-guidance payload),
and PR-S3-7 (integration test gate).

## Coverage matrix

Maps each enumerated attack vector to the Slice-3 PR/task that implements it. Vectors labelled
**TBD — Slice-3 follow-on (no current task)** have no implementing payload in any current
Slice-3 plan; they require a follow-on PR or an explicit out-of-scope decision before Slice-3
closes. The matrix is the contract between this category's threat model and the slice's task
graph — drift between the two is a release-blocker.

| Attack vector | Owning PR / Task |
|---|---|
| `cast(TaggedContent[T2], t3_value)` bypass | PR-S3-1 Tasks 22 + 25 (`tl_cast_bypass.yaml` + `test_tier_laundering_cast_bypass.py`) |
| Wire-format tier confusion (JSON + YAML) | PR-S3-1 Task 23 (`tl_wire_tier_confusion.yaml`) |
| `tag(T3, ...)` from orchestrator module context | **TBD — Slice-3 follow-on (no current task)** — PR-S3-1 implements the per-process-nonce gate (spec §3.2) but no dedicated adversarial payload exercises the "called from orchestrator module" failure mode |
| Frame-introspection bypass (monkey-patch `sys.modules` to forge `__name__`) | PR-S3-1 Task 26 (`test_tier_laundering_frame_bypass.py`) |
| Capability-gate bypass via `subscriber_tier=user-plugin` on T3-carrying hookpoint | **TBD — Slice-3 follow-on (no current task)** — PR-S3-2 implements the `subscriber_tier` axis but no adversarial payload exercises a user-plugin tier attempting to subscribe to a T3-carrying hookpoint |
| Post-handshake hook registration | PR-S3-3a Task (`test_post_handshake_hook_registration.py`) |
| In-flight grant revocation race | **TBD — Slice-3 follow-on (no current task)** — PR-S3-2 covers the race in `tests/unit/` (`plugin.grant.revoked_inflight` audit row) but no `tier_laundering` adversarial payload formalises the attack |
| Retry-guidance hygiene (strict token-set invariant + poisoned-input control) | PR-S3-4 (`test_tier_laundering_retry_guidance_hygiene.py`) |
| `gc.get_objects()`-style T3 token retrieval (out-of-scope acknowledgement) | PR-S3-1 Task 24 (`tl_gc_traversal_out_of_scope.yaml`) — explicit out-of-scope label per spec §3.2 threat model limits |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
