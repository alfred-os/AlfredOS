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
| --- | --- |
| `cast(TaggedContent[T2], t3_value)` bypass | PR-S3-1 Tasks 22 + 25 (`tl_cast_bypass.yaml` + `test_tier_laundering_cast_bypass.py`) |
| Wire-format tier confusion (JSON + YAML) | PR-S3-1 Task 23 (`tl_wire_tier_confusion.yaml`) |
| `tag(T3, ...)` from orchestrator module context | PR #134 retrospective (`tl_tag_t3_from_orchestrator_module.yaml` + `test_tier_laundering_tag_t3_from_orchestrator_module.py`) — formalises the within-orchestrator forgery branch of the §3.2 nonce-gate threat model |
| Frame-introspection bypass (monkey-patch `sys.modules` to forge `__name__`) | PR-S3-1 Task 26 (`test_tier_laundering_frame_bypass.py`) |
| Capability-gate bypass via `subscriber_tier=user-plugin` on T3-carrying hookpoint | PR #134 retrospective (`tl_capability_gate_bypass_subscriber_tier.yaml` + `test_tier_laundering_capability_gate_bypass.py`) — `subscribable_tiers` registration-time refusal on `memory.episodic.record.before_db_write` |
| Post-handshake hook registration | PR-S3-3a (`tl_post_handshake_hook_register.yaml` + `test_post_handshake_hook_register_attack.py`) |
| In-flight grant revocation race | PR #134 retrospective (`tl_inflight_grant_revocation_race.yaml` + `test_tier_laundering_inflight_grant_revocation_race.py`) — atomic `_apply_grants` swap + revoke-before-upsert audit ordering |
| Retry-guidance hygiene (strict token-set invariant + poisoned-input control) | PR-S3-4 (`test_tier_laundering_retry_guidance_hygiene.py`) |
| `gc.get_objects()`-style T3 token retrieval (out-of-scope acknowledgement) | PR-S3-1 Task 24 (`tl_gc_traversal_out_of_scope.yaml`) — explicit out-of-scope label per spec §3.2 threat model limits |
| Cross-mode tier-downgrade: `EgressResponse.body` (raw T3 bytes) treated as T2 `ExtractionResult` — structural gate refuses; `quarantined_to_structured()` is the only T2-producing path; dedup path returns stored T2 without re-extracting raw T3 (HARD rule #5) | PR #333 G7-2c-2 / issue #333 (`tl-2026-010` `tl_cross_mode_tier_downgrade.yaml` + `test_tier_laundering_cross_mode_tier_downgrade.py`) |
| Deprecated `BaseModel.copy(update={"tier": T3})` — does NOT route through the guarded `model_copy`; yielded a statically-`TaggedContent[T2]` object whose runtime tier read T3 | #518 follow-on (`tl-2026-011` `tl_deprecated_copy_tier_upgrade.yaml` + `test_tier_laundering_copy_seams.py`) — `copy` override + single-read `update` coercion |
| `TaggedContent` subclass shadowing `_validate_tier` / `_assert_tier_admissible` — pydantic rebinds validator targets by NAME off the subclass MRO, so any subclass is a lever on the guard | #518 follow-on (`tl-2026-012` `tl_tagged_content_subclass_validator_shadow.yaml` + `test_tier_laundering_copy_seams.py`) — `__init_subclass__` refuses on defining module, `_TIER_GUARD_NAMES` shadowing, OR any namespace a genuine parametrisation would not produce; behind it `model_post_init` + module-level guard dispatch |
| Unbound base dispatch (`BaseModel.copy`/`model_copy` on an instance) and raw state writes (`object.__setattr__`, an `obj.__dict__` write or `.update`, `vars(obj)`) — **RUNTIME: still admitted, structurally**; the copy paths reach neither the overrides nor `model_post_init`, and none of the raw writes traverse `__setattr__`, so `frozen=True` cannot observe them. `BaseModel.model_construct.__func__` was in this row and is now runtime-CLOSED: pydantic invokes `cls.model_post_init` from inside the base implementation. **AUTHORING: refused since #538** | #518 follow-on + #538 (`tl-2026-013` `tl_base_dispatch_and_raw_state_write.yaml` + `test_tier_laundering_copy_seams.py::test_tl_2026_013_is_now_defended_at_the_authoring_layer`) — `out_of_scope=true` still holds for the RUNTIME layer only. Authoring layer: `scripts/check_tag_t3.py` `_RAW_VEHICLE_ATTR` / `_RAW_VEHICLE_NAME` / `_RAW_VEHICLE_VARS` / `_RAW_VEHICLE_STR` / `_RAW_SETATTR_SHAPE` / `_RAW_SETATTR_ALIASED` / `_RAW_DELATTR_SHAPE` / `_RAW_DELATTR_ALIASED` / `_RAW_INIT_SHAPE` / `_RAW_INIT_ALIASED` / `_RAW_CLASS_SWAP` / `_RAW_CARRIER` / `_BASEMODEL_VALUE` / `_PRIVATE_SURFACE` / `_ALIAS_BUDGET`, each default-deny on the vehicle or the call shape. This list is checked against the gate's own constants in both directions by `test_the_corpus_record_matches_the_shipped_rule_set` — it is not maintained by hand. Residuals are enumerated in the payload's `out_of_scope_rationale`, not claimed closed |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
