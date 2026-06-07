# Carrier-substitution tamper adversarial corpus

Attacks against the recoverable-carrier semantic for error-stage hookpoint
dispatch (ADR-0022). Covers tier-upgrade spoofing, meta-hookpoint recursion,
payload-type mismatch on `SubstituteResult[T]`, and AST-guard escape via
`**kwargs` wrapper forwarding.

**Attack vectors covered**

- Subscriber registered at T3 returns `SubstituteResult(source_tier="T0", ...)`
  attempting to defeat the strict-total-order tier-upgrade guard (the dispatcher
  MUST override `source_tier` from the registered tier — PR-S4-3 round-2
  closure 1).
- Error-stage subscriber registered against a meta-hookpoint
  (`hooks.carrier_substituted` / `hooks.carrier_substitution_refused`) where
  `allow_error_substitution=False` — registration AND dispatch refuse with
  `CARRIER_SUBSTITUTION_REFUSED_FIELDS(reason="recursion_refused")`.
- `SubstituteResult[T]` generic-binding violation (subscriber returns wrong
  payload type) — refused with `reason="payload_type_mismatch"`, original
  exception re-raised.
- AST-guard `**kwargs` escape attempt via wrapper forwarding (caught by the
  self-test in `tests/unit/hooks/test_carrier_tier_required.py`).
- Substitution attempt after `_dispatch_by_kind` chain-completion (caught by
  the ErrorOutcome union exhaustiveness check).

**Prefix.** `crf-`

**Owning PR.** PR-S4-3 (carrier substitution).

**Ingestion paths.** Internal to the orchestrator (hookpoint dispatch); not
operator-visible. The corresponding `IngestionPath` literal in
`tests/adversarial/payload_schema.py` is `"hookpoint_dispatch"` — every
`crf-*` corpus YAML MUST set `ingestion_path: hookpoint_dispatch` to round-trip
through the schema validator.

**Expected outcomes.** `refused`, `audit_row_emitted` (anchored to
`CARRIER_SUBSTITUTION_REFUSED_FIELDS`), or the new `recursion_refused`
outcome.

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
| Subscriber spoofs `source_tier="T0"` while registered at T3 | PR-S4-3 (`crf-2026-001` — dispatcher-attested `source_tier`) |
| Error subscriber registered against meta-hookpoint (`hooks.carrier_substituted`) | PR-S4-3 (`crf-2026-002` — `recursion_refused` at registration + dispatch) |
| `SubstituteResult[T]` payload-type mismatch | PR-S4-3 (`crf-2026-003` — `payload_type_mismatch` refusal + ReRaise) |
| AST-guard `**kwargs` escape via wrapper forwarding | PR-S4-3 (`crf-2026-004` + guard self-test) |
| Tier-upgrade attempt across strict-total-order boundary | PR-S4-3 (`crf-2026-005`) |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
