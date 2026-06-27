# PR-S4-3: Carrier Substitution — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the recoverable-carrier semantic for error-stage hookpoint dispatch (ADR-0022 / #170). Extend `HookpointMeta` with `carrier_tier: TrustTier | None = None` (Optional at first per the **wave-migration discipline** below — sec-idx-001 + core-eng-004 + mem-002 closures from PR #205 round-1 review) and `allow_error_substitution: bool = True`. Introduce the `ErrorOutcome[T]` discriminated union (`ReRaise | SubstituteResult[T]`). Rewrite `_run_error()` to return `ErrorOutcome[T]` and consult `HookpointMeta.allow_error_substitution`. Add a strict total-order tier-upgrade guard that refuses `substitute_tier > carrier_tier` — NOT the Slice-3-drafted "refuse T3 only" rule (Critical 5 closure). Migrate four sibling production sites to the new outcome pattern. Register the two meta-hookpoints (`hooks.carrier_substituted` / `hooks.carrier_substitution_refused`) as observation-only, `fail_closed=False`, `allow_error_substitution=False`. Ship the `crf-` adversarial corpus category. Ship the merge-blocking integration test `tests/integration/test_error_chain_substitution_propagates.py` AND the AST guard `tests/unit/hooks/test_carrier_tier_required.py`.

**Wave-migration discipline** (mid-PR): the field ships in TWO stages within this PR. Stage A — `carrier_tier: TrustTier | None = None` (Optional). All existing publishers continue passing tests. Stage A migration commits update every in-tree `register_hookpoint(...)` call site to pass an explicit `carrier_tier=<TrustTier>` value. The 6+ existing Supervisor hookpoints in `src/alfred/supervisor/core.py`, Slice-2.5 episodic publishers in `src/alfred/memory/episodic.py`, and Slice-3 quarantine + capability-gate hookpoints all get explicit values. **Episodic `carrier_tier` is computed per-call from `EpisodicRecordInput.trust_tier` — NOT hardcoded T2** (mem-002 closure: episodic record handles T2 *and* T3 inbound bodies from PR-S4-8 comms; hardcoded T2 would refuse legitimate T3 substitutes via the tier-upgrade guard). Stage B (final PR commit) — flip the field to required (`carrier_tier: TrustTier`). The Pydantic field-validator catches runtime-registered hookpoints (plugins/skills) and the AST guard catches in-tree call sites; both layers ship in this PR.

**Architecture:** `HookpointMeta` gains two fields per the wave-migration discipline above. `ErrorOutcome[T]` is a PEP 695 type alias over a discriminated union of two frozen Pydantic v2 models — `ReRaise` (no payload) and `SubstituteResult[T]` (payload + source_tier + subscriber_id). `_run_error()` gains a `carrier_type: type[T]` parameter and returns `ErrorOutcome[T]` instead of `HookContext[T]`. The caller pattern-matches the outcome. The tier-upgrade guard uses a strict total order on `T0 < T1 < T2 < T3` — implemented via a `TrustTier`-to-rank dict (rather than monkey-patching `__lt__` onto `TrustTier` subclasses) so the comparison stays explicit and the AST guard can lint it. The four sibling sites — `QuarantinedExtractor.extract` (the original ADR-0022 motivation), `EpisodicMemory.record` (Slice-2.5 precedent), `_ingest_tier` (Slice-3 ingress), `_record_failure` in `state.dispatch_loop` (Slice-3 dispatch-failure path) — all migrate to construct the appropriate `carrier_type` and pattern-match on `outcome`. **A revert of this PR after downstream hookpoint-registering PRs have merged silently weakens the trust boundary** (sec-idx-005 closure): the revert ships a coordinated cascade script at `scripts/revert-pr-s4-3-cascade.sh` that the post-revert PR uses to atomically downgrade every dependent PR's hookpoint registration to remove the `carrier_tier=` kwarg.

**Tech Stack:** Python 3.12+ (PEP 604 unions, PEP 695 generic syntax, PEP 695 type aliases), Pydantic v2 (`ConfigDict(frozen=True)`), `match`/`case` exhaustiveness via mypy strict, structlog with redactor, pytest + hypothesis for property tests, testcontainers (Postgres/Redis) for the integration test, `uv run mypy --strict` + `pyright` clean, 100% line + branch coverage on `src/alfred/hooks/invoke.py::_run_error`, `src/alfred/hooks/registry.py::HookpointMeta`, and the four migrated sibling sites.

**PR #205 round-2 review closures** (load-bearing corrections — apply at implementation time):

1. **arch-002 + sec-001 HIGH (self-declared source_tier defeats Critical 5)**: `SubstituteResult.source_tier` MUST NOT be subscriber-supplied. The dispatcher derives `source_tier` from the subscriber's registered tier provenance at subscribe-time: when `register_hook(...)` is called the subscriber's container/sandbox/process trust-tier is recorded in `HookRegistration.subscriber_tier` (frozen at registration). At dispatch time, `_extract_substitute_from_ctx` reads the substitute's `source_tier` exclusively from `HookRegistration.subscriber_tier` of the firing subscriber — NOT from any field on the user-payload. `SubstituteResult` keeps a `payload` field only; `source_tier` becomes a dispatcher-attested field set after the chain returns. New unit test: `crf-2026-005-subscriber_spoofs_source_tier` plants a subscriber returning `payload + source_tier="T0"` while registered at T3; assertion: dispatcher rewrites source_tier to T3 from registration provenance, tier-upgrade guard refuses, audit emits `reason="tier_upgrade_attempt"`.

2. **arch-001 + reviewer-001 + core-002 HIGH (Stage A→B wave-migration never lands)**: a NEW task **Component A.B (Stage B tightening)** sequences between F8 and G1 — the field flips from `TrustTier | None = None` to `TrustTier` (required, no default). This task runs ONLY after Stage A migrates every in-tree `register_hookpoint(...)` call site to an explicit `carrier_tier=` value. The AST guard test (`tests/unit/hooks/test_carrier_tier_required.py`) runs in CI BEFORE Stage B — it catches in-tree call sites that haven't been migrated. The runtime Pydantic field-required gate catches plugin/skill registrations at import time. Both layers ship in this PR — that's the wave-migration promise the §1 narrative asserts.

3. **reviewer-002 + sec-003 + test-003 HIGH (ValidationError swallow violates CLAUDE.md #7)**: `_extract_substitute_from_ctx` MUST NOT silently swallow `ValidationError`. The corrected pattern: `try: substitute = SubstituteResult[T].model_validate(raw); except ValidationError as exc: await audit.append_schema(CARRIER_SUBSTITUTION_REFUSED_FIELDS, reason="payload_type_mismatch", subscriber_id=subscriber.id, exc_summary=truncate(str(exc), 256)); return ReRaise()`. The audit emit and explicit `ReRaise()` return preserve the "loud at boundaries" discipline. crf-2026-003 asserts both the audit row AND the ReRaise propagation. NO `except Exception: return None` patterns anywhere in the substitution path.

4. **sec-002 + test-002 HIGH (registration-time recursion guard missing)**: Component A4 expands to BOTH publisher-side and subscriber-side guards. The new sub-task A4.b: at `register_hook(hookpoint_name, callback, ...)` time, look up the hookpoint's `allow_error_substitution` flag; if `False` (i.e., this is a meta-hookpoint observing other hookpoints) AND the registration is `kind="error"`, REFUSE registration with `HookRegistrationError` carrying the same `reason="recursion_refused"` token. crf-2026-004 first arm validates this at registration time; second arm validates dispatch-time enforcement as backstop.

5. **arch-002-dispatch + test-002 HIGH (AST guard `**kwargs` escape)**: the AST guard at `tests/unit/hooks/test_carrier_tier_required.py` MUST NOT exempt wrappers forwarding `**kwargs`. The corrected pattern: when an AST walker sees a `Call` to `register_hookpoint` whose callable expression includes `**kwargs` expansion, the test fails with `ASTGuardEscape` UNLESS the wrapping function appears on an explicit allow-list (`hooks/_wrappers.py::WRAPPER_ALLOWLIST: frozenset[str]`). The allow-list is empty initially; adding a name to it requires a corresponding `_carrier_tier_assertion` unit test that pins the wrapper's tier-resolution behaviour. A self-test (`test_ast_guard_catches_starstar_escape`) plants a synthetic call with `**kw` expansion and asserts the guard fails — protecting the guard against regression of its own escape semantics.

6. **arch-004 HIGH (Flow.body(carrier_type=…) missing Component D task)**: a NEW Component D task **D7 (Flow.body(carrier_type=)** ships the `carrier_type: type[T]` parameter addition to `Flow.body(...)` at `src/alfred/hooks/flow.py`. This task precedes F2/F4/F6/F8. Without it the four sibling migrations don't compile. Existing in-tree `Flow.body(...)` calls with no `carrier_type=` continue to work (Optional default for Stage A); Stage B requires it.

7. **core-001 HIGH (return-type breakage on _dispatch_by_kind)**: `_dispatch_by_kind` at `src/alfred/hooks/invoke.py:601-645` currently returns `HookContext[T]`; `_run_error` migration changes its return shape to `ErrorOutcome[T]`. The caller chain in `invoke()` at line 404 needs explicit handling — task A2.b expands to: `outcome = await _run_error(...)` then `match outcome: case ReRaise(): raise original_error; case SubstituteResult(payload=p, source_tier=t): return HookContext(...)`. The migration preserves the public `invoke()` return type as `HookContext[T]` so downstream callers see no breakage; only the internal `_run_error` path changes shape.

8. **core-003 MEDIUM (missed register_hookpoint sites)**: Stage A migration includes TWO additional in-tree sites the plan currently omits: `src/alfred/security/capability_gate/proposals.py:134` and `src/alfred/plugins/web_fetch/__init__.py:92`. The migration commit list expands; the AST guard catches these regardless if they're missed.

9. **arch-003 + sec-004 MEDIUM (revert script must ship or claim drops)**: `scripts/revert-pr-s4-3-cascade.sh` ships in Component G2 with: (a) the script body computes the set of merged PR-S4-* hookpoint-registering commits AFTER PR-S4-3; (b) for each, creates `revert/<sha>` branches that strip the `carrier_tier=` kwarg; (c) opens a meta-revert PR; (d) the script's behaviour is exercised in `tests/unit/scripts/test_revert_cascade.py` against a fixture git repo. If the script cannot ship in S4-3, the sec-idx-005 closure is REPLACED with a forward-only constraint documented in ADR-0022: "PR-S4-3 cannot be reverted in isolation; reverting requires manual coordinated reversion of every dependent hookpoint registration."

10. **reviewer-003 MEDIUM (subscriber-registration-time refusal task)**: rolled into closure 4 above (Component A4.b).

11. **reviewer-004 MEDIUM (_ingest_tier identity-resolution attack surface)**: PR-S4-3 OPENS 5 hookpoints on the identity-resolution path via `_ingest_tier`. This is acknowledged Slice-4 surface expansion; the closure requires alfred-architect signoff via an explicit ADR note in ADR-0022: "Identity-resolution hookpoints are T1-carrier (per the trust ladder in §7); subscribers MUST be registered at T0 or T1 to avoid tier-upgrade refusal. Plugin subscribers default to T3 and are refused." A new test `test_ingest_tier_t3_subscriber_refused` validates the refusal.

12. **core-004 MEDIUM (generic Pydantic validation binding)**: `SubstituteResult[T]` uses PEP 695 generic syntax; Pydantic v2 generic validation requires a `model_validate` call with explicit type binding (`SubstituteResult[ExpectedType].model_validate(raw)`). The dispatcher resolves `ExpectedType` from `Flow.body(carrier_type=...)` (closure 6 above). Without explicit binding Pydantic generic validation falls back to `Any` and the type contract erodes. Unit test `test_substitute_result_generic_binding_explicit` plants a `SubstituteResult[int]` with `payload="not-int"` and asserts ValidationError.

13. **test-003 MEDIUM (100% coverage gate completion)**: §6 test list expands to cover: (a) `TimeoutError → ReRaise` branch in `_run_error`; (b) empty-chain terminal handling (no subscribers registered → trivial ReRaise); (c) `HookRefusal` propagation when the substitution-refusal canary trips; (d) the silent ValidationError swallow path at lines 1096-1097 is REMOVED entirely per closure 3 — coverage on the replacement (audit-then-ReRaise) is asserted by crf-2026-003.

**Depends on:**

- PR-S4-0a (merged) — ships `CARRIER_SUBSTITUTION_FIELDS` and `CARRIER_SUBSTITUTION_REFUSED_FIELDS` audit-row constants, the `crf` prefix in `_PREFIX_TO_CATEGORY` / `_ID_PATTERN`, and the ADR-0022 body. **Verified in `docs/superpowers/plans/2026-06-07-slice-4-pr-s4-0a-docs-adrs-foundations.md` lines 87-88, 803-823, 843-856.**
- PR-S4-0b (merged) — Alembic migration covering the audit-row columns; `audit.hash_pepper` secret bootstrap (not consumed by this PR).
- Slice-3 trust-tier types — `TrustTier` / `T0` / `T1` / `T2` / `T3` exist as classes in `src/alfred/security/tiers.py` at lines 28 / 36 / 42 / 54 / 60. **`tag()` returns `TaggedContent[TierT]`; the `tier` field is `type[TrustTier]`, not an instance** (verified — `src/alfred/security/tiers.py:184`).
- Slice-2.5 hook subsystem — `HookpointMeta` is a `@dataclass(frozen=True, slots=True)` at `src/alfred/hooks/registry.py:175-229`; `register_hookpoint` is the method on `HookRegistry` at `src/alfred/hooks/registry.py:539-670`; the `@hook` decorator + dispatcher live in `src/alfred/hooks/invoke.py` and `src/alfred/hooks/decorators.py`.

**Blocks (rev-009 ancestry):** PR-S4-1, PR-S4-4, PR-S4-5, PR-S4-6, PR-S4-7, PR-S4-8, PR-S4-9 — every downstream PR that calls `register_hookpoint(...)` must populate the new `carrier_tier` field this PR adds. The AST guard `tests/unit/hooks/test_carrier_tier_required.py` shipped here is the source of truth: a downstream PR that omits `carrier_tier=` fails its `make check`.

**Closes:** #170.

---

## §1 Goal

ADR-0022 (full body in PR-S4-0a) defines the recoverable-carrier semantic: an error-stage hookpoint subscriber may return a substitute payload that replaces the original exception, AND that substitution is gated by a strict total-order tier comparison so a malicious subscriber cannot upgrade the action's effective trust tier through the error-recovery path. The semantic landed in spec §4 (4.1-4.7) of `docs/superpowers/specs/2026-06-06-slice-4-design.md`. This PR delivers the runtime.

The CodeRabbit observation on PR #168 was the original motivation: `_dispatch_error_chain` in `src/alfred/security/quarantine.py` does not honour `alfred.hooks.invoke`'s "first non-None wins" carrier-substitution semantic — an error subscriber that returns a substitute carrier has no way to propagate it back, because the caller's outer `raise exc` short-circuits. The inline doc-comment in `quarantine.py` already documented the slice-scoped deferral. Slice 4 lands it.

The Critical 5 closure (spec §4.4) is the tier-upgrade rule. The Slice-3-drafted "refuse T3 only" rule silently permitted a T2 substitute on a T0/T1 hookpoint to upgrade the action's effective tier. The chosen rule is strict total order `T0 < T1 < T2 < T3`: a substitute is refused if `substitute_tier > carrier_tier`. This refuses every upgrade across every tier pair, not just the T3 corner.

The rev-007 closure (index §3 / spec §4.4) pinned `HookpointMeta.carrier_tier` and `HookpointMeta.allow_error_substitution` to PR-S4-3 (NOT PR-S4-0a, which was the round-2 placement). This PR ships those field additions alongside the runtime that consumes them.

This PR also lands four sibling-site migrations in the same PR. PR-S4-3 is the smallest atomic unit that delivers a working semantic — the registry change, the runtime change, the consumer migrations, the meta-hookpoint declarations, the AST guard, the adversarial corpus, and the merge-blocking integration test all ship together. There is no "stub now, wire later" split.

---

## §2 Architecture overview

```
src/alfred/hooks/registry.py                 (modify)
  HookpointMeta                              add carrier_tier + allow_error_substitution
  register_hookpoint                         require carrier_tier= kwarg
  _DECLARATION_DOCS_LINK                     (existing const — unchanged)

src/alfred/hooks/invoke.py                   (modify)
  ErrorOutcome[T]                            PEP 695 type alias
  ReRaise                                    frozen Pydantic model, no payload
  SubstituteResult[T]                        frozen Pydantic model, payload + source_tier + subscriber_id
  _run_error[T]                              gains carrier_type: type[T]; returns ErrorOutcome[T]
  _enforce_substitute_tier                   strict total-order helper
  _TRUST_TIER_RANK                           module-private dict (T0=0, T1=1, T2=2, T3=3)
  _META_HOOKPOINT_NAMES                      frozenset({"hooks.carrier_substituted",
                                                          "hooks.carrier_substitution_refused"})

src/alfred/hooks/_known_hookpoints.py        (modify)
  declare_hookpoints                         register the two meta-hookpoints
                                              (observation-only, fail_closed=False,
                                               allow_error_substitution=False,
                                               carrier_tier=None — meta-hookpoints have no carrier)

src/alfred/security/quarantine.py            (modify — sibling 1)
  QuarantinedExtractor.extract               match outcome pattern
  _dispatch_error_chain                      becomes a thin caller around _run_error;
                                              consumes ErrorOutcome[ExtractionResult]

src/alfred/memory/episodic.py                (modify — sibling 2)
  EpisodicMemory.record                      Flow.body's error chain consumes ErrorOutcome
                                              [EpisodicRecordOutcome] (new payload type)
  EpisodicRecordOutcome                      typed substitute payload for the .record site

src/alfred/identity/_ingest.py               (modify — sibling 3)
  _ingest_tier                               wrap in invoking() block AND consume
                                              ErrorOutcome[IngestTierOutcome]
  IngestTierOutcome                          typed substitute payload for the _ingest_tier site
  declare_hookpoints                         existing function — declarations gain
                                              carrier_tier=

src/alfred/state/dispatch_loop.py            (modify — sibling 4)
  _record_failure                            wrap in error chain; consume
                                              ErrorOutcome[DispatchFailureOutcome]
  DispatchFailureOutcome                     typed substitute payload for the _record_failure site

tests/unit/hooks/test_carrier_tier_required.py             (new) AST guard — every register_hookpoint
                                                                    call site MUST pass carrier_tier=
tests/unit/hooks/test_hookpoint_meta_carrier_tier.py       (new) field shape + immutability
tests/unit/hooks/test_error_outcome_discriminated_union.py (new) PEP 695 alias + frozen models
tests/unit/hooks/test_run_error_signature.py               (new) signature contract + back-compat absence
tests/unit/hooks/test_tier_upgrade_guard.py                (new) strict total-order matrix
tests/unit/hooks/test_meta_hookpoint_registration.py       (new) meta-hookpoint declaration shape
tests/unit/security/test_quarantine_extract_carrier.py     (new) sibling 1 migration
tests/unit/memory/test_episodic_record_carrier.py          (new) sibling 2 migration
tests/unit/identity/test_ingest_tier_carrier.py            (new) sibling 3 migration
tests/unit/state/test_dispatch_loop_record_failure_carrier.py (new) sibling 4 migration

tests/adversarial/carrier_substitution_tamper/__init__.py
tests/adversarial/carrier_substitution_tamper/crf-2026-001-tier-upgrade.yaml
tests/adversarial/carrier_substitution_tamper/crf-2026-002-malformed-payload.yaml
tests/adversarial/carrier_substitution_tamper/crf-2026-003-wrong-type-payload.yaml
tests/adversarial/carrier_substitution_tamper/crf-2026-004-meta-hookpoint-recursion.yaml
tests/adversarial/carrier_substitution_tamper/test_tier_upgrade_refused.py
tests/adversarial/carrier_substitution_tamper/test_malformed_substitute.py
tests/adversarial/carrier_substitution_tamper/test_wrong_type_substitute.py
tests/adversarial/carrier_substitution_tamper/test_meta_hookpoint_recursion_refused.py

tests/integration/test_error_chain_substitution_propagates.py  (new, merge-blocking)
```

The `_TRUST_TIER_RANK` mapping is the design hinge for the tier-upgrade guard:

```python
# Module-private in src/alfred/hooks/invoke.py.
# Strict total order T0 < T1 < T2 < T3. Lower rank = lower trust.
# A substitute is refused if rank[substitute] > rank[carrier].
_TRUST_TIER_RANK: Final[Mapping[type[TrustTier], int]] = MappingProxyType({
    T0: 0,
    T1: 1,
    T2: 2,
    T3: 3,
})
```

**Why a dict, not `TrustTier.__lt__`.** Spec §4.4 reads: `TrustTier("T0") < TrustTier("T3") returns True`. **That call shape does not exist.** Per `src/alfred/security/tiers.py`, `TrustTier` and its `T0`/`T1`/`T2`/`T3` subclasses are CLASS objects with a `name` class attribute, never instantiated. There is no `__lt__` operator. The plan introduces ordering via the dict lookup so the comparison is grep-able, lint-able, and AST-guardable. Adding `__lt__` to every `TrustTier` subclass would mean a Slice-3 file modification AND a new module export, both larger blast radius than necessary for this PR.

**Spec drift acknowledgement.** Spec §4.4 also references `src/alfred/security/trust_tiers.py`. **That file does not exist.** The Slice-3 file is `src/alfred/security/tiers.py`. This plan uses the real filename throughout. A separate spec-correction follow-up tracks the typo (added to `docs/superpowers/specs/2026-06-06-slice-4-design.md`'s next revision via the "fabricated-surfaces watchlist for writing-plans" backlog entry, index §8).

The meta-hookpoint registration shape: `carrier_tier=None` is permitted ONLY for the two meta-hookpoints. The runtime guard (in `register_hookpoint`) refuses `carrier_tier=None` for any other name. The AST guard (in `tests/unit/hooks/test_carrier_tier_required.py`) refuses `register_hookpoint(...)` calls that omit `carrier_tier=` entirely — passing `carrier_tier=None` explicitly is allowed at the syntax level; only the runtime gate checks the name allow-list. This split keeps the AST guard simple (a pure-syntactic kwarg check) and pushes the policy logic to runtime where the meta-hookpoint allow-list lives.

---

## §3 File structure

| File | Status | Responsibility |
| --- | --- | --- |
| `src/alfred/hooks/registry.py` | Modify | Extend `HookpointMeta` with `carrier_tier: type[TrustTier] \| None` (None only for meta-hookpoints) and `allow_error_substitution: bool = True`. Update `register_hookpoint` to require `carrier_tier=` kwarg, validate `None` only for meta-hookpoints, and treat conflicting re-declarations as drift (per existing `register_hookpoint` semantics). Update `_TIER_RANK` is untouched (that's the subscriber tier rank for in-chain ordering — `system`/`operator`/`user-plugin`, NOT trust tiers). |
| `src/alfred/hooks/invoke.py` | Modify | Add `ReRaise` (Pydantic frozen), `SubstituteResult[T]` (Pydantic frozen + PEP 695 generic), `ErrorOutcome[T]` type alias. Rewrite `_run_error` to take `carrier_type: type[T]`, return `ErrorOutcome[T]`. Add `_enforce_substitute_tier` helper. Add `_TRUST_TIER_RANK` mapping. Update `_dispatch_by_kind` (line 638-645) to pass `carrier_type` through. Update `invoke[T]` public entry to accept `carrier_type: type[T] \| None = None` and forward to `_run_error`. The `error` kind requires `carrier_type` — same shape as the existing `exc` requirement at lines 541-545. |
| `src/alfred/hooks/_known_hookpoints.py` | Modify | Add `declare_meta_hookpoints(registry)` registering `hooks.carrier_substituted` and `hooks.carrier_substitution_refused` with `subscribable_tiers=SYSTEM_ONLY_TIERS`, `refusable_tiers=frozenset()`, `fail_closed=False`, `carrier_tier=None`, `allow_error_substitution=False`. Called from the bootstrap surface that already calls `declare_hookpoints` (consistent with the Slice-2.5 pattern at `src/alfred/memory/episodic.py:59`). |
| `src/alfred/security/quarantine.py` | Modify | `QuarantinedExtractor.extract` migrates its error-chain dispatch from the slice-3 stub to `_run_error(...)` with `carrier_type=ExtractionResult`. The existing `_dispatch_error_chain` body becomes a thin caller. Pattern-match on `outcome`. The existing `ExtractionResult` discriminated union (already defined in this file per Slice-3) is the substitute payload type. |
| `src/alfred/memory/episodic.py` | Modify | `EpisodicMemory.record` already routes through `invoking("memory.episodic.record", inp)` at line 268. The `Flow.body(error=...)` context already calls `invoke(error_hookpoint, ..., kind="error", exc=exc)` — the call site receives a `HookContext[T]` from the current dispatcher. PR-S4-3 expands `Flow.body` to support `carrier_type=` and to return an `ErrorOutcome[T]` from `Flow.body`'s exception branch. Add `EpisodicRecordOutcome` Pydantic model. The five existing hookpoint declarations gain `carrier_tier=T2` (episodic memory writes user content). |
| `src/alfred/identity/_ingest.py` | Modify | `_ingest_tier` currently has no `invoking()` wrap. Wrap it: `async with invoking("identity._ingest_tier", inp) as flow: ...`. Add `IngestTierOutcome` (Pydantic frozen, carries the `type[TrustTier]` result). Existing `declare_hookpoints` (line 59) extends to also declare `identity._ingest_tier.before_validate`, `.before_resolve`, `.after_resolve`, `.resolve_failed`, `.cancelled` — five new hookpoints, all `carrier_tier=T1` (identity ingestion crosses operator surfaces). |
| `src/alfred/state/dispatch_loop.py` | Modify | `_record_failure` at line 819 — the actual function name (NOT `_handle_dispatch_failure`, which was the user-prompt placeholder; verified non-existent). Wrap in `invoking("state.dispatch_loop._record_failure", inp)`. Add `DispatchFailureOutcome` Pydantic model. Add five new hookpoints `state.dispatch_loop._record_failure.{before_validate,before_db_write,after_flush,write_failed,cancelled}` with `carrier_tier=T0` (the dispatch loop runs system-tier; carrier content is internal). |
| `tests/unit/hooks/test_carrier_tier_required.py` | Create | AST guard. Walks every `.py` file under `src/alfred/` and `plugins/`, collects every call expression whose `func.attr == "register_hookpoint"` or `func.id == "register_hookpoint"`, refuses any call missing the `carrier_tier` keyword. Runs in `make check`. |
| `tests/unit/hooks/test_hookpoint_meta_carrier_tier.py` | Create | Field-shape tests: `HookpointMeta(... carrier_tier=T0)` round-trips; mutation refused (frozen); equality includes carrier_tier; the meta-hookpoint case `carrier_tier=None` only valid for the two whitelisted names; `allow_error_substitution` default is `True`. |
| `tests/unit/hooks/test_error_outcome_discriminated_union.py` | Create | `ReRaise()` is a frozen Pydantic v2 model with no fields; `SubstituteResult[T](payload=..., source_tier="T0", subscriber_id="x")` is a frozen Pydantic v2 model; the PEP 695 type alias `ErrorOutcome[T] = ReRaise \| SubstituteResult[T]` resolves correctly; mypy strict + pyright pass with `match`/`case` exhaustiveness. |
| `tests/unit/hooks/test_run_error_signature.py` | Create | `inspect.signature(_run_error)` shows `carrier_type` as a keyword-only required arg; the return-type annotation evaluates to `ErrorOutcome[T]`; old call sites that omit `carrier_type` are a type error (test asserts via mypy run-on-fixture). |
| `tests/unit/hooks/test_tier_upgrade_guard.py` | Create | Full strict-total-order matrix (10 PASS cases for `substitute ≤ carrier`, 6 REFUSE cases for `substitute > carrier`). Tests `_enforce_substitute_tier` directly + the integration through `_run_error`. |
| `tests/unit/hooks/test_meta_hookpoint_registration.py` | Create | Meta-hookpoints register with the documented shape; a subscriber declared with `kind="error"` and a `SubstituteResult` return is refused at registration time (`Protocol` guard in `register_hookpoint` consults `allow_error_substitution`). |
| `tests/unit/security/test_quarantine_extract_carrier.py` | Create | Sibling 1 — `QuarantinedExtractor.extract` propagates a `SubstituteResult[ExtractionResult]` returned by an error subscriber; a `ReRaise` outcome propagates the original exception identity. |
| `tests/unit/memory/test_episodic_record_carrier.py` | Create | Sibling 2 — `EpisodicMemory.record` propagates a `SubstituteResult[EpisodicRecordOutcome]` returned by an error subscriber. |
| `tests/unit/identity/test_ingest_tier_carrier.py` | Create | Sibling 3 — `_ingest_tier` wraps in `invoking()` and propagates `ErrorOutcome[IngestTierOutcome]`. |
| `tests/unit/state/test_dispatch_loop_record_failure_carrier.py` | Create | Sibling 4 — `_record_failure` propagates `ErrorOutcome[DispatchFailureOutcome]`. |
| `tests/adversarial/carrier_substitution_tamper/__init__.py` | Create | Package marker. |
| `tests/adversarial/carrier_substitution_tamper/crf-2026-001-tier-upgrade.yaml` | Create | T3 substitute on T0/T1/T2 carrier (3 sub-cases); T2 substitute on T0/T1 carrier (2 sub-cases); T1 substitute on T0 carrier (1 sub-case). |
| `tests/adversarial/carrier_substitution_tamper/crf-2026-002-malformed-payload.yaml` | Create | `SubstituteResult(payload=malformed_payload, source_tier="T0")`. |
| `tests/adversarial/carrier_substitution_tamper/crf-2026-003-wrong-type-payload.yaml` | Create | `SubstituteResult(payload=truthy_but_wrong_type, source_tier="T0")`. |
| `tests/adversarial/carrier_substitution_tamper/crf-2026-004-meta-hookpoint-recursion.yaml` | Create | Subscriber on `hooks.carrier_substituted` returns a `SubstituteResult` — refused at registration AND dispatch. |
| `tests/adversarial/carrier_substitution_tamper/test_tier_upgrade_refused.py` | Create | Executes the YAML matrix; verifies `CARRIER_SUBSTITUTION_REFUSED_FIELDS` audit row with `reason="tier_upgrade_refused"`. |
| `tests/adversarial/carrier_substitution_tamper/test_malformed_substitute.py` | Create | Loads YAML; verifies original exception re-raises identity-preserved. |
| `tests/adversarial/carrier_substitution_tamper/test_wrong_type_substitute.py` | Create | Loads YAML; verifies type validation refuses; original exception re-raises. |
| `tests/adversarial/carrier_substitution_tamper/test_meta_hookpoint_recursion_refused.py` | Create | Loads YAML; verifies registration refuses AND dispatch refuses with `reason="recursion_refused"`. |
| `tests/integration/test_error_chain_substitution_propagates.py` | Create | Merge-blocking. Boots a real Postgres + Redis via testcontainers; runs each of the four sibling sites with a known-good substitute subscriber; asserts the substitute returns end-to-end (DB row written / fact recorded / dispatch failure ledger row carries substituted reason). |

---

## §4 Cross-PR contracts (what later PRs may assume)

These contracts are this PR's surface to the rest of Slice 4. A downstream PR (PR-S4-1, PR-S4-4, PR-S4-5, PR-S4-6, PR-S4-7, PR-S4-8, PR-S4-9) MAY assume these are stable on day 1 after PR-S4-3 merges.

### `HookpointMeta` shape (new in PR-S4-3)

```python
@dataclass(frozen=True, slots=True)
class HookpointMeta:
    name: str
    subscribable_tiers: frozenset[str]
    refusable_tiers: frozenset[str]
    fail_closed: bool
    carrier_tier: type[TrustTier] | None   # NEW — required positional
    allow_error_substitution: bool = True  # NEW — default True
```

- `carrier_tier=None` is permitted ONLY when `name` is in `_META_HOOKPOINT_NAMES` (`hooks.carrier_substituted` / `hooks.carrier_substitution_refused`). Every other hookpoint MUST pass a concrete `type[TrustTier]` (one of `T0`, `T1`, `T2`, `T3`).
- `allow_error_substitution=False` MUST be paired with `name in _META_HOOKPOINT_NAMES` (the two are co-load-bearing — see meta-hookpoint registration shape below).
- Equality is field-wise (dataclass default). The existing `register_hookpoint` idempotent-re-declaration semantic (in `register_hookpoint` at `src/alfred/hooks/registry.py:539`) carries over: re-declaring with the same fields succeeds; re-declaring with different fields raises `HookError` via `hookpoint_drift_message`.

### `register_hookpoint(...)` call shape (extended)

```python
registry.register_hookpoint(
    name="memory.episodic.record.before_validate",
    subscribable_tiers=OPEN_TIERS,
    refusable_tiers=OPEN_TIERS,
    fail_closed=False,
    carrier_tier=T2,                  # NEW — required kwarg
    allow_error_substitution=True,    # NEW — default True; omittable for non-meta hookpoints
)
```

- Every existing `register_hookpoint(...)` call site in `src/` updates to pass `carrier_tier=`. The AST guard test refuses calls that omit it; CI fails until every site updates.
- `carrier_tier=None` is the only spelling allowed for the two meta-hookpoints; spelling it for any other hookpoint raises `HookError` with message rendered via a new i18n key `hooks.carrier_tier_required` (catalog addition shipped in this PR).

### `_run_error(...)` signature (changed)

```python
async def _run_error[T](
    name: str,
    ctx: HookContext[T],
    *,
    exc: BaseException | None,
    carrier_type: type[T],            # NEW — required kwarg
    subscribable_tiers: frozenset[str],
    fail_closed: bool,
) -> ErrorOutcome[T]:                 # CHANGED — was HookContext[T]
    ...
```

- The `_dispatch_by_kind` (at `src/alfred/hooks/invoke.py:638-645`) routing for `kind == "error"` updates to thread `carrier_type` through.
- The public `invoke[T](name, ctx, *, kind, ...)` entry point at line 404 gains `carrier_type: type[T] | None = None`. For `kind == "error"` and `kind == "cancel"`, omitting `carrier_type` raises `RuntimeError` (the same shape as the existing `exc is None` guard at lines 541-550).
- Callers MUST pattern-match the returned `ErrorOutcome[T]`:

```python
outcome: ErrorOutcome[ExtractionResult] = await invoke(
    "security.quarantined.extract.write_failed",
    ctx,
    kind="error",
    exc=exc,
    carrier_type=ExtractionResult,
    subscribable_tiers=SYSTEM_OPERATOR_TIERS,
    fail_closed=True,
)
match outcome:
    case ReRaise():
        raise exc
    case SubstituteResult(payload=p, source_tier=substitute_tier, subscriber_id=sid):
        # tier-upgrade guard applied INSIDE _run_error before
        # SubstituteResult is constructed. By the time the caller sees a
        # SubstituteResult, the upgrade guard has already passed.
        return p
```

- `_run_error` internally consults the registered `HookpointMeta.allow_error_substitution`. If `False`, every subscriber return value is ignored AND a `CARRIER_SUBSTITUTION_REFUSED_FIELDS` audit row with `reason="substitution_not_allowed"` is emitted for every subscriber that returned non-`None`.
- `_run_error` internally consults `HookpointMeta.carrier_tier` (the declared carrier tier) and applies `_enforce_substitute_tier` against every subscriber's `source_tier`. Refusals emit `CARRIER_SUBSTITUTION_REFUSED_FIELDS` with `reason="tier_upgrade_refused"` AND the original `exc` re-raises (via `ReRaise()` outcome).

### `ErrorOutcome[T]` discriminated union (new)

```python
class ReRaise(BaseModel):
    """The error chain decided not to substitute — the original exception propagates."""
    model_config = ConfigDict(frozen=True)


class SubstituteResult[T](BaseModel):
    """An error-stage subscriber produced a recovery payload that replaces the exception.

    `payload` is the typed substitute (matched against the caller's `carrier_type`).
    `source_tier` declares the substitute's trust origin — refused if strictly greater
    than the surrounding hookpoint's declared `carrier_tier` (strict total order T0<T1<T2<T3).
    `subscriber_id` is the `hook_fn.__qualname__` of the subscriber that substituted; surfaces on
    the `CARRIER_SUBSTITUTION_FIELDS` audit row.
    """
    payload: T
    source_tier: Literal["T0", "T1", "T2", "T3"]
    subscriber_id: str
    model_config = ConfigDict(frozen=True)


type ErrorOutcome[T] = ReRaise | SubstituteResult[T]
```

- `source_tier` is a `Literal[...]` string (the wire-format name), NOT `type[TrustTier]`. This mirrors the wire-format choice already made in `src/alfred/security/tiers.py:_tier_by_name` at line 320 and keeps `SubstituteResult` JSON-serialisable for the audit row.
- The discriminated union resolves under `match`/`case` with full mypy exhaustiveness — a third future variant would surface as a non-exhaustive match warning at every consume site.

### Meta-hookpoint registration shape (new)

```python
# In src/alfred/hooks/_known_hookpoints.py — called once at bootstrap.
def declare_meta_hookpoints(registry: HookRegistry) -> None:
    """Declare the two observation-only meta-hookpoints (PR-S4-3)."""
    registry.register_hookpoint(
        name="hooks.carrier_substituted",
        subscribable_tiers=SYSTEM_ONLY_TIERS,
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=None,
        allow_error_substitution=False,
    )
    registry.register_hookpoint(
        name="hooks.carrier_substitution_refused",
        subscribable_tiers=SYSTEM_ONLY_TIERS,
        refusable_tiers=frozenset(),
        fail_closed=False,
        carrier_tier=None,
        allow_error_substitution=False,
    )
```

- Observation-only: subscribers may register `pre`/`post` kinds against these hookpoints, but `kind="error"` subscribers that return a `SubstituteResult` are refused at registration (via the `allow_error_substitution=False` gate in `register_hookpoint`'s subscriber surface, layered in Task 5 below). The dispatcher also re-checks at runtime (defence-in-depth — `crf-2026-004` exercises both arms).
- `subscribable_tiers=SYSTEM_ONLY_TIERS` keeps user-plugin tier subscribers out — operators do not want a third-party plugin observing every carrier substitution across the system.
- `fail_closed=False` — observation-only + fail-closed is semantically undefined; the spec §4.7 resolution is `False`.
- `carrier_tier=None` — meta-hookpoints have no carrier (the original event has already happened by the time the meta-hookpoint fires).

### Audit-row constants (consumed from PR-S4-0a)

PR-S4-0a defines `CARRIER_SUBSTITUTION_FIELDS` and `CARRIER_SUBSTITUTION_REFUSED_FIELDS` in `src/alfred/audit/audit_row_schemas.py`. **Verified in `docs/superpowers/plans/2026-06-07-slice-4-pr-s4-0a-docs-adrs-foundations.md` lines 87-88, 803-823.**

```python
CARRIER_SUBSTITUTION_FIELDS = frozenset({
    "hookpoint", "subscriber_id", "source_tier", "carrier_tier", "substituted_at",
})

CARRIER_SUBSTITUTION_REFUSED_FIELDS = frozenset({
    "hookpoint", "subscriber_id", "attempted_source_tier", "carrier_tier",
    "reason", "refused_at",
})
```

`reason` is a `Literal[...]` string. PR-S4-3's usage:

- `reason="tier_upgrade_refused"` — strict total-order violation.
- `reason="substitution_not_allowed"` — `HookpointMeta.allow_error_substitution=False`.
- `reason="recursion_refused"` — meta-hookpoint substitution attempt (crf-2026-004).
- `reason="payload_type_mismatch"` — Pydantic validation of `SubstituteResult.payload` against `carrier_type` failed (crf-2026-003).

The full `Literal[...]` enumeration is locked here. A downstream PR that needs a new reason value extends the Literal in PR-S4-0a's constant; PR-S4-3 does NOT extend it.

### Adversarial category (`crf-` prefix)

PR-S4-0a registered the `crf` prefix in `_PREFIX_TO_CATEGORY` and the `_ID_PATTERN` regex. **Verified in index §3 lines 155-166.** This PR ships the four corpus YAML files + their executable tests under `tests/adversarial/carrier_substitution_tamper/`. The `payload_schema.py` Literal addition `"carrier_substitution_tamper"` (per index line 151) is already live in `main` post-PR-S4-0a.

### Hookpoint declarations registered by THIS PR (per index §3 hookpoint surface)

| Hookpoint | Subscribable | Refusable | fail_closed | carrier_tier | allow_error_substitution |
| --- | --- | --- | --- | --- | --- |
| `hooks.carrier_substituted` | SYSTEM_ONLY | ∅ | False | None | False |
| `hooks.carrier_substitution_refused` | SYSTEM_ONLY | ∅ | False | None | False |
| `identity._ingest_tier.before_validate` | OPEN | OPEN | False | T1 | True |
| `identity._ingest_tier.before_resolve` | OPEN | OPEN | False | T1 | True |
| `identity._ingest_tier.after_resolve` | OPEN | OPEN | False | T1 | True |
| `identity._ingest_tier.resolve_failed` | OPEN | OPEN | False | T1 | True |
| `identity._ingest_tier.cancelled` | OPEN | OPEN | False | T1 | True |
| `state.dispatch_loop._record_failure.before_validate` | SYSTEM_OPERATOR | OPEN | True | T0 | True |
| `state.dispatch_loop._record_failure.before_db_write` | SYSTEM_OPERATOR | OPEN | True | T0 | True |
| `state.dispatch_loop._record_failure.after_flush` | SYSTEM_OPERATOR | OPEN | False | T0 | True |
| `state.dispatch_loop._record_failure.write_failed` | SYSTEM_OPERATOR | OPEN | False | T0 | True |
| `state.dispatch_loop._record_failure.cancelled` | SYSTEM_OPERATOR | OPEN | False | T0 | True |

This PR also UPDATES the existing five `memory.episodic.record.*` declarations to add `carrier_tier=T2` (episodic memory writes user content). The existing `security.quarantined.extract.*` declarations (Slice-3 shipped) update to add `carrier_tier=T3`.

### What this PR does NOT change

- The Slice-2.5 subscriber-tier model (`system`/`operator`/`user-plugin` and `_TIER_RANK`) is untouched. That ordering governs in-chain dispatch order; it is orthogonal to the trust-tier ordering this PR introduces.
- The `pre`/`post`/`cancel` kind handlers are untouched. Only `_run_error` changes signature; `_run_pre`, `_run_post`, `_run_cancel` retain `-> HookContext[T]`.
- The `Flow.body` helper in `src/alfred/hooks/invoke.py:1895` gains a new `carrier_type=` kwarg required for the `error=` branch. The success / cancel branches are untouched.
- No PR-S4-3 hookpoint subscriber attribute on registration changes shape. `@hook(...)` decorator users continue to write `@hook(hookpoint, kind="error", tier="system")`; the dispatcher infers `carrier_type` from the hookpoint's registered meta.
- The `T3DerivedData` `NewType` in `src/alfred/security/quarantine.py:145` is untouched. This PR uses it only insofar as `ExtractionResult.data` (the quarantine substitute payload) carries it.

---

## §5 TDD tasks

Tasks are sequenced so each test fails for the right reason before its implementation lands. The order follows the dependency hierarchy: registry → invoke runtime → sibling migrations → meta-hookpoint declarations → adversarial corpus → integration test.

### Component A — `HookpointMeta` extension

- [ ] **Task A1 — Failing test: `HookpointMeta` carries `carrier_tier` and `allow_error_substitution`**

  **Files:** Create `tests/unit/hooks/test_hookpoint_meta_carrier_tier.py`.

  ```python
  """HookpointMeta gains carrier_tier + allow_error_substitution (PR-S4-3)."""

  from __future__ import annotations

  import pytest
  from dataclasses import FrozenInstanceError

  from alfred.hooks.registry import HookpointMeta
  from alfred.security.tiers import T0, T1, T2, T3


  def test_hookpoint_meta_carries_carrier_tier() -> None:
      meta = HookpointMeta(
          name="memory.episodic.record.before_validate",
          subscribable_tiers=frozenset({"system", "operator", "user-plugin"}),
          refusable_tiers=frozenset({"system", "operator", "user-plugin"}),
          fail_closed=False,
          carrier_tier=T2,
          allow_error_substitution=True,
      )
      assert meta.carrier_tier is T2


  def test_hookpoint_meta_carrier_tier_none_for_meta_hookpoints() -> None:
      meta = HookpointMeta(
          name="hooks.carrier_substituted",
          subscribable_tiers=frozenset({"system"}),
          refusable_tiers=frozenset(),
          fail_closed=False,
          carrier_tier=None,
          allow_error_substitution=False,
      )
      assert meta.carrier_tier is None
      assert meta.allow_error_substitution is False


  def test_hookpoint_meta_allow_error_substitution_defaults_true() -> None:
      meta = HookpointMeta(
          name="memory.episodic.record.write_failed",
          subscribable_tiers=frozenset({"system", "operator"}),
          refusable_tiers=frozenset({"system", "operator"}),
          fail_closed=False,
          carrier_tier=T2,
      )
      assert meta.allow_error_substitution is True


  def test_hookpoint_meta_frozen() -> None:
      meta = HookpointMeta(
          name="x",
          subscribable_tiers=frozenset({"system"}),
          refusable_tiers=frozenset({"system"}),
          fail_closed=True,
          carrier_tier=T0,
      )
      with pytest.raises(FrozenInstanceError):
          meta.carrier_tier = T3  # type: ignore[misc]


  def test_hookpoint_meta_equality_includes_new_fields() -> None:
      a = HookpointMeta(
          name="x", subscribable_tiers=frozenset(), refusable_tiers=frozenset(),
          fail_closed=False, carrier_tier=T0,
      )
      b = HookpointMeta(
          name="x", subscribable_tiers=frozenset(), refusable_tiers=frozenset(),
          fail_closed=False, carrier_tier=T1,
      )
      assert a != b
  ```

  **Run:** `uv run pytest tests/unit/hooks/test_hookpoint_meta_carrier_tier.py -x`

  **Expected:** `FAILED` with `TypeError: HookpointMeta.__init__() got an unexpected keyword argument 'carrier_tier'`.

- [ ] **Task A2 — Implementation: extend `HookpointMeta`**

  **Files:** Modify `src/alfred/hooks/registry.py`.

  Add to the imports: `from alfred.security.tiers import TrustTier`.

  Replace the `HookpointMeta` dataclass body (lines 175-229) by adding two fields. Update the docstring to mention them. Carrier_tier is `type[TrustTier] | None`; the dataclass field ordering keeps `carrier_tier` BEFORE `allow_error_substitution` so the constructor signature reads naturally:

  ```python
  @dataclass(frozen=True, slots=True)
  class HookpointMeta:
      name: str
      subscribable_tiers: frozenset[str]
      refusable_tiers: frozenset[str]
      fail_closed: bool
      carrier_tier: type[TrustTier] | None
      allow_error_substitution: bool = True
  ```

  Note: the `type[TrustTier]` annotation is the same shape the Slice-3 `TaggedContent.tier` field uses (verified at `src/alfred/security/tiers.py:184`).

  **Run:** `uv run pytest tests/unit/hooks/test_hookpoint_meta_carrier_tier.py -x`

  **Expected:** `5 passed`.

  **Run quality gate:** `uv run mypy src/alfred/hooks/registry.py --strict`

  **Expected:** clean.

  **Commit:**

  ```
  feat(hooks): extend HookpointMeta with carrier_tier + allow_error_substitution (#170)
  ```

- [ ] **Task A3 — Failing test: `register_hookpoint` requires `carrier_tier=`; refuses `None` outside meta-hookpoint allow-list**

  **Files:** Extend `tests/unit/hooks/test_hookpoint_meta_carrier_tier.py`.

  ```python
  from alfred.hooks.errors import HookError
  from alfred.hooks.registry import HookRegistry
  from tests.helpers.gates import grant_all_gate


  def test_register_hookpoint_requires_carrier_tier_kwarg() -> None:
      reg = HookRegistry(gate=grant_all_gate(), strict_declarations=True)
      with pytest.raises(TypeError, match="missing.*carrier_tier"):
          reg.register_hookpoint(
              name="something.action",
              subscribable_tiers=frozenset({"system"}),
              refusable_tiers=frozenset({"system"}),
              fail_closed=False,
              # carrier_tier omitted -- must be a TypeError
          )


  def test_register_hookpoint_refuses_none_for_non_meta_hookpoint() -> None:
      reg = HookRegistry(gate=grant_all_gate(), strict_declarations=True)
      with pytest.raises(HookError, match="hooks.carrier_tier_required"):
          reg.register_hookpoint(
              name="memory.episodic.record.before_validate",
              subscribable_tiers=frozenset({"system"}),
              refusable_tiers=frozenset({"system"}),
              fail_closed=False,
              carrier_tier=None,
          )


  def test_register_hookpoint_accepts_none_for_carrier_substituted() -> None:
      reg = HookRegistry(gate=grant_all_gate(), strict_declarations=True)
      reg.register_hookpoint(
          name="hooks.carrier_substituted",
          subscribable_tiers=frozenset({"system"}),
          refusable_tiers=frozenset(),
          fail_closed=False,
          carrier_tier=None,
          allow_error_substitution=False,
      )
      meta = reg.hookpoint_meta("hooks.carrier_substituted")
      assert meta is not None and meta.carrier_tier is None
  ```

  **Run:** `uv run pytest tests/unit/hooks/test_hookpoint_meta_carrier_tier.py::test_register_hookpoint_requires_carrier_tier_kwarg tests/unit/hooks/test_hookpoint_meta_carrier_tier.py::test_register_hookpoint_refuses_none_for_non_meta_hookpoint tests/unit/hooks/test_hookpoint_meta_carrier_tier.py::test_register_hookpoint_accepts_none_for_carrier_substituted -x`

  **Expected:** `FAILED` — the first test fails with `TypeError` raised by the dataclass (good; that's already the right shape); the second fails because no `None` gate exists; the third may fail because the registry has no allow-list yet.

- [ ] **Task A4 — Implementation: `register_hookpoint` gates `carrier_tier=None`**

  **Files:** Modify `src/alfred/hooks/registry.py`.

  Update `register_hookpoint` signature (line 539) to add the `carrier_tier` and `allow_error_substitution` keyword arguments (no default for `carrier_tier` — required; `allow_error_substitution: bool = True`).

  Add a module-level constant `_META_HOOKPOINT_NAMES: Final[frozenset[str]] = frozenset({"hooks.carrier_substituted", "hooks.carrier_substitution_refused"})` near the existing `OPEN_TIERS` constant (line 301).

  In `register_hookpoint`'s body, immediately after the `unknown_tiers` validation block (around line 646), add the carrier_tier_required validation:

  ```python
  if carrier_tier is None and name not in _META_HOOKPOINT_NAMES:
      raise HookError(carrier_tier_required_message(name=name))
  if carrier_tier is not None and name in _META_HOOKPOINT_NAMES:
      raise HookError(carrier_tier_must_be_none_for_meta_hookpoint_message(name=name))
  if allow_error_substitution and name in _META_HOOKPOINT_NAMES:
      raise HookError(allow_error_substitution_must_be_false_for_meta_hookpoint_message(name=name))
  ```

  Add the three message helpers to `src/alfred/hooks/errors.py` (consistent with the existing `unknown_tier_in_declaration_message` pattern at line 96). Each routes through `t("hooks.carrier_tier_required")`, `t("hooks.carrier_tier_must_be_none_for_meta_hookpoint")`, and `t("hooks.allow_error_substitution_must_be_false_for_meta_hookpoint")` respectively. Catalog entries land in this PR via `pybabel extract` (CLAUDE.md i18n rule #4).

  Pass `carrier_tier` and `allow_error_substitution` through to the `HookpointMeta(...)` constructor in `register_hookpoint`.

  **Run:** `uv run pytest tests/unit/hooks/test_hookpoint_meta_carrier_tier.py -x`

  **Expected:** `8 passed`.

  **Run quality gate:** `uv run mypy src/alfred/hooks/registry.py --strict && uv run ruff check src/alfred/hooks/`

  **Expected:** clean.

  **Commit:**

  ```
  feat(hooks): require carrier_tier= on register_hookpoint; gate None to meta-hookpoints (#170)
  ```

### Component B — AST guard `test_carrier_tier_required.py`

- [ ] **Task B1 — Failing test: AST guard refuses register_hookpoint without carrier_tier**

  **Files:** Create `tests/unit/hooks/test_carrier_tier_required.py`.

  ```python
  """AST guard — every register_hookpoint(...) call site MUST pass carrier_tier=.

  Walks src/ and plugins/ at test time, collects every call expression whose
  func.attr == "register_hookpoint" or func.id == "register_hookpoint", and
  refuses any call missing the carrier_tier keyword. Lints downstream PR
  hookpoint registrations during `make check` so a missing carrier_tier surfaces
  at PR-author time, not at runtime first-import time.

  PR-S4-3 ships this guard. Per rev-009 round-3 closure, this gate is what makes
  PR-S4-3 the ancestor of every other hookpoint-registering PR.
  """

  from __future__ import annotations

  import ast
  from collections.abc import Iterator
  from pathlib import Path

  import pytest

  REPO_ROOT = Path(__file__).resolve().parents[3]
  SCAN_DIRS = (REPO_ROOT / "src" / "alfred", REPO_ROOT / "plugins")


  def _iter_python_files() -> Iterator[Path]:
      for root in SCAN_DIRS:
          if not root.exists():
              continue
          yield from root.rglob("*.py")


  def _find_register_hookpoint_calls(tree: ast.AST) -> list[ast.Call]:
      out: list[ast.Call] = []
      for node in ast.walk(tree):
          if not isinstance(node, ast.Call):
              continue
          func = node.func
          if isinstance(func, ast.Attribute) and func.attr == "register_hookpoint":
              out.append(node)
          elif isinstance(func, ast.Name) and func.id == "register_hookpoint":
              out.append(node)
      return out


  def test_every_register_hookpoint_call_passes_carrier_tier() -> None:
      offenders: list[str] = []
      for path in _iter_python_files():
          try:
              tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
          except SyntaxError:
              continue
          for call in _find_register_hookpoint_calls(tree):
              kwarg_names = {kw.arg for kw in call.keywords if kw.arg is not None}
              has_starstar = any(kw.arg is None for kw in call.keywords)
              if "carrier_tier" not in kwarg_names and not has_starstar:
                  offenders.append(f"{path}:{call.lineno}")
      assert not offenders, (
          "register_hookpoint(...) calls missing carrier_tier= kwarg:\n"
          + "\n".join(offenders)
      )
  ```

  Note: the `**kwargs` escape (`has_starstar`) is intentional — a wrapper that forwards `**kwargs` is opaque to AST and the caller must take responsibility. The wrapper itself, when registered, will be one of the inspected call sites.

  **Run:** `uv run pytest tests/unit/hooks/test_carrier_tier_required.py -x`

  **Expected:** `FAILED` — every existing `register_hookpoint(...)` call site in `src/` currently omits `carrier_tier=`. The failure lists every offender. The Component C / D / E / F migrations close them one site at a time.

  Do NOT commit the test green yet — it stays red through Component C until every site lands.

### Component C — `ErrorOutcome[T]` discriminated union

- [ ] **Task C1 — Failing test: `ReRaise` / `SubstituteResult` / `ErrorOutcome[T]` shape**

  **Files:** Create `tests/unit/hooks/test_error_outcome_discriminated_union.py`.

  ```python
  """ErrorOutcome[T] discriminated union (PR-S4-3, ADR-0022)."""

  from __future__ import annotations

  from typing import get_args, get_origin

  import pytest
  from pydantic import BaseModel, ConfigDict, ValidationError

  from alfred.hooks.invoke import ErrorOutcome, ReRaise, SubstituteResult


  class _DemoPayload(BaseModel):
      model_config = ConfigDict(frozen=True)
      value: str


  def test_reraise_is_frozen_pydantic_model_no_fields() -> None:
      r = ReRaise()
      with pytest.raises(ValidationError):
          ReRaise(extra="x")  # type: ignore[call-arg]
      # frozen — can't mutate
      with pytest.raises(ValidationError):
          r.__dict__["arbitrary"] = "x"  # frozen Pydantic raises on assign  # type: ignore[index]


  def test_substitute_result_typed_payload() -> None:
      p = _DemoPayload(value="ok")
      s = SubstituteResult[_DemoPayload](payload=p, source_tier="T0", subscriber_id="m.func")
      assert s.payload.value == "ok"
      assert s.source_tier == "T0"
      assert s.subscriber_id == "m.func"


  def test_substitute_result_source_tier_literal_rejects_invalid() -> None:
      p = _DemoPayload(value="ok")
      with pytest.raises(ValidationError):
          SubstituteResult[_DemoPayload](payload=p, source_tier="T4", subscriber_id="x")  # type: ignore[arg-type]


  def test_error_outcome_alias_resolves_union() -> None:
      # PEP 695 type alias is a TypeAliasType — calling .value_origin / __value__ gives the unioned form
      assert ErrorOutcome.__name__ == "ErrorOutcome"
      # `match`/`case` exhaustiveness pinned by mypy strict in CI; here we
      # verify the runtime shape.
      reraise_outcome: ErrorOutcome[_DemoPayload] = ReRaise()
      substitute_outcome: ErrorOutcome[_DemoPayload] = SubstituteResult[_DemoPayload](
          payload=_DemoPayload(value="x"), source_tier="T0", subscriber_id="s",
      )
      match reraise_outcome:
          case ReRaise():
              ok_reraise = True
          case SubstituteResult():
              ok_reraise = False
      match substitute_outcome:
          case SubstituteResult(payload=p, source_tier=t, subscriber_id=sid):
              ok_sub = p.value == "x" and t == "T0" and sid == "s"
          case ReRaise():
              ok_sub = False
      assert ok_reraise and ok_sub
  ```

  **Run:** `uv run pytest tests/unit/hooks/test_error_outcome_discriminated_union.py -x`

  **Expected:** `FAILED` with `ImportError: cannot import name 'ErrorOutcome' from 'alfred.hooks.invoke'`.

- [ ] **Task C2 — Implementation: ship `ReRaise`, `SubstituteResult`, `ErrorOutcome`**

  **Files:** Modify `src/alfred/hooks/invoke.py`.

  Add to imports near line 144-146: `from pydantic import BaseModel, ConfigDict`. Add `Literal` to the typing imports if not already present.

  Insert after the module constants block (after `_REENTRY_BYPASS_AUDIT_FIELDS` declaration, around line 368), before `_spawn_subscriber`:

  ```python
  # ──────────────────────────────────────────────────────────────────────
  # ErrorOutcome[T] discriminated union — PR-S4-3 / ADR-0022
  # ──────────────────────────────────────────────────────────────────────

  class ReRaise(BaseModel):
      """The error chain decided not to substitute -- the original
      exception propagates.

      Returned by :func:`_run_error` when every subscriber returned
      ``None`` OR when the tier-upgrade guard refused every substitute
      OR when the hookpoint's :attr:`HookpointMeta.allow_error_substitution`
      is ``False``.

      Frozen Pydantic v2 -- no payload, no fields. Equality is "all
      `ReRaise()` instances are equal" so a caller pattern-matching on
      ``case ReRaise():`` matches every Re-raise outcome.
      """
      model_config = ConfigDict(frozen=True, extra="forbid")


  class SubstituteResult[T](BaseModel):
      """An error-stage subscriber produced a recovery payload that
      replaces the exception.

      Attributes:
          payload: The typed substitute. Matched against the caller's
              ``carrier_type`` at construction; a mismatch raises
              :class:`pydantic.ValidationError`.
          source_tier: The substitute's trust origin. Wire-format string
              (NOT ``type[TrustTier]`` — kept JSON-serialisable for the
              audit row, mirroring :func:`alfred.security.tiers._tier_by_name`).
          subscriber_id: The substituting subscriber's
              ``hook_fn.__qualname__``. Surfaces on the
              :data:`CARRIER_SUBSTITUTION_FIELDS` audit row.
      """
      payload: T
      source_tier: Literal["T0", "T1", "T2", "T3"]
      subscriber_id: str
      model_config = ConfigDict(frozen=True, extra="forbid")


  type ErrorOutcome[T] = ReRaise | SubstituteResult[T]
  """Discriminated union over the two error-stage dispositions.

  Callers MUST exhaustively pattern-match on this type. Mypy strict
  enforces exhaustiveness; a future third variant surfaces as a
  non-exhaustive match warning at every consume site.
  """
  ```

  **Run:** `uv run pytest tests/unit/hooks/test_error_outcome_discriminated_union.py -x`

  **Expected:** `4 passed`.

  **Run quality gate:** `uv run mypy src/alfred/hooks/invoke.py --strict`

  **Expected:** clean.

  **Commit:**

  ```
  feat(hooks): add ErrorOutcome[T] = ReRaise | SubstituteResult[T] discriminated union (#170)
  ```

### Component D — `_run_error` signature change + tier-upgrade guard

- [ ] **Task D1 — Failing test: `_run_error` accepts `carrier_type=` and returns `ErrorOutcome[T]`**

  **Files:** Create `tests/unit/hooks/test_run_error_signature.py`.

  ```python
  """_run_error gains carrier_type: type[T]; returns ErrorOutcome[T]."""

  from __future__ import annotations

  import inspect
  from typing import get_type_hints

  from alfred.hooks.invoke import _run_error, ErrorOutcome


  def test_run_error_has_carrier_type_kwarg() -> None:
      sig = inspect.signature(_run_error)
      assert "carrier_type" in sig.parameters
      param = sig.parameters["carrier_type"]
      assert param.kind == inspect.Parameter.KEYWORD_ONLY
      assert param.default is inspect.Parameter.empty


  def test_run_error_return_annotation_is_error_outcome() -> None:
      # Resolve forward refs in PR-S4-3's _run_error signature.
      hints = get_type_hints(_run_error)
      assert "return" in hints
      # ErrorOutcome[T] resolves to a TypeAliasType bound to T.
      # We assert the alias name appears in the repr of the return hint.
      assert "ErrorOutcome" in repr(hints["return"])
  ```

  **Run:** `uv run pytest tests/unit/hooks/test_run_error_signature.py -x`

  **Expected:** `FAILED` — `_run_error` does not yet accept `carrier_type`.

- [ ] **Task D2 — Failing test: tier-upgrade guard matrix**

  **Files:** Create `tests/unit/hooks/test_tier_upgrade_guard.py`.

  ```python
  """Strict total-order tier-upgrade guard (Critical 5 closure).

  Matrix:
                  carrier=T0   carrier=T1   carrier=T2   carrier=T3
    sub_tier=T0   PASS         PASS         PASS         PASS
    sub_tier=T1   REFUSE       PASS         PASS         PASS
    sub_tier=T2   REFUSE       REFUSE       PASS         PASS
    sub_tier=T3   REFUSE       REFUSE       REFUSE       PASS
  """

  from __future__ import annotations

  from typing import Literal

  import pytest

  from alfred.hooks.invoke import _enforce_substitute_tier
  from alfred.security.tiers import T0, T1, T2, T3, TrustTier


  Tier = Literal["T0", "T1", "T2", "T3"]


  @pytest.mark.parametrize(
      ("carrier", "substitute", "should_pass"),
      [
          (T0, "T0", True),  (T1, "T0", True),  (T2, "T0", True),  (T3, "T0", True),
          (T0, "T1", False), (T1, "T1", True),  (T2, "T1", True),  (T3, "T1", True),
          (T0, "T2", False), (T1, "T2", False), (T2, "T2", True),  (T3, "T2", True),
          (T0, "T3", False), (T1, "T3", False), (T2, "T3", False), (T3, "T3", True),
      ],
  )
  def test_strict_total_order_matrix(
      carrier: type[TrustTier],
      substitute: Tier,
      should_pass: bool,
  ) -> None:
      passed = _enforce_substitute_tier(carrier_tier=carrier, source_tier=substitute)
      assert passed is should_pass
  ```

  **Run:** `uv run pytest tests/unit/hooks/test_tier_upgrade_guard.py -x`

  **Expected:** `FAILED` with `ImportError: cannot import name '_enforce_substitute_tier'`.

- [ ] **Task D3 — Implementation: `_TRUST_TIER_RANK` + `_enforce_substitute_tier`**

  **Files:** Modify `src/alfred/hooks/invoke.py`.

  Add to imports: `from types import MappingProxyType`, `from collections.abc import Mapping`, `from alfred.security.tiers import T0, T1, T2, T3, TrustTier` (the `Mapping` import may already be present).

  Insert after the `ErrorOutcome[T]` definition from Task C2:

  ```python
  # ──────────────────────────────────────────────────────────────────────
  # Trust-tier strict total order — PR-S4-3 / Critical 5 closure
  # ──────────────────────────────────────────────────────────────────────

  _TRUST_TIER_RANK: Final[Mapping[type[TrustTier], int]] = MappingProxyType({
      T0: 0,
      T1: 1,
      T2: 2,
      T3: 3,
  })
  """Strict total order on the four approved tiers: T0 < T1 < T2 < T3.

  Used by :func:`_enforce_substitute_tier` to refuse substitutes whose
  declared source tier strictly exceeds the surrounding hookpoint's
  declared carrier tier. Implemented as a dict (NOT as `__lt__` operators
  on TrustTier subclasses) so the comparison stays grep-able and the AST
  guard at tests/unit/hooks/test_carrier_tier_required.py can lint it.

  MappingProxyType wraps the dict so callers cannot mutate it at runtime --
  same immutability discipline as :data:`alfred.hooks.registry.OPEN_TIERS`.
  """

  _SOURCE_TIER_TO_CLASS: Final[Mapping[str, type[TrustTier]]] = MappingProxyType({
      "T0": T0, "T1": T1, "T2": T2, "T3": T3,
  })
  """Wire-format string -> TrustTier class. Mirrors the Slice-3
  :func:`alfred.security.tiers._tier_by_name` table; duplicated here to
  avoid an import cycle (alfred.security.tiers does not import alfred.hooks).
  """


  def _enforce_substitute_tier(
      *,
      carrier_tier: type[TrustTier],
      source_tier: Literal["T0", "T1", "T2", "T3"],
  ) -> bool:
      """Return True iff source_tier <= carrier_tier in strict total order.

      Strict total order T0 < T1 < T2 < T3 (rank 0..3). A substitute is
      ACCEPTED when rank[source] <= rank[carrier]; REFUSED when
      rank[source] > rank[carrier]. The refusal disposition (audit row,
      re-raise) is the caller's responsibility -- this helper is the
      pure predicate.

      The carrier_tier=None case is the meta-hookpoint shape; that path
      never reaches this helper because the meta-hookpoint dispatch arm
      in :func:`_run_error` consults :attr:`HookpointMeta.allow_error_substitution`
      first and shortcuts the chain.
      """
      source_class = _SOURCE_TIER_TO_CLASS[source_tier]
      return _TRUST_TIER_RANK[source_class] <= _TRUST_TIER_RANK[carrier_tier]
  ```

  **Run:** `uv run pytest tests/unit/hooks/test_tier_upgrade_guard.py -x`

  **Expected:** `16 passed`.

- [ ] **Task D4 — Implementation: rewrite `_run_error` to return `ErrorOutcome[T]`**

  **Files:** Modify `src/alfred/hooks/invoke.py`.

  Locate `_run_error` at line 1519. Rewrite the signature + body. Key changes:

  1. Add the required keyword arg `carrier_type: type[T]`.
  2. Change the return type from `HookContext[T]` to `ErrorOutcome[T]`.
  3. Replace the chain-walking body so it returns `ErrorOutcome[T]` and consults `HookpointMeta.allow_error_substitution` + `HookpointMeta.carrier_tier`.
  4. Update the early `if exc is None` guard (lines 1656-1664) to remain — but now the `raise exc` arm is unreachable on the normal flow; the caller pattern-matches on `ReRaise()` and re-raises. Move that defensive check to the top of the function (immediately after the `_enforce_subscribable_tiers` call).

  Replacement body sketch:

  ```python
  async def _run_error[T](
      name: str,
      ctx: HookContext[T],
      *,
      exc: BaseException | None,
      carrier_type: type[T],
      subscribable_tiers: frozenset[str],
      fail_closed: bool,
  ) -> ErrorOutcome[T]:
      """Dispatch the ``error`` chain. Returns ErrorOutcome[T].

      ... (full docstring — see below for the narrative)
      """
      await _enforce_subscribable_tiers(
          name, ctx, kind="error",
          subscribable_tiers=subscribable_tiers, fail_closed=fail_closed,
      )

      if exc is None:
          raise RuntimeError(
              "invoke(kind='error', ...) called without an exc argument; "
              "the error stage requires the upstream exception."
          )

      registry = get_registry()
      meta = registry.hookpoint_meta(name)
      # In strict mode the publisher-drift guard above guarantees meta is
      # not None; in permissive mode we fall back to "substitution allowed"
      # to preserve the legacy semantic. Permissive mode is dev-only.
      allow_substitution = (meta.allow_error_substitution if meta is not None else True)
      carrier_tier_for_guard = (meta.carrier_tier if meta is not None else None)

      subscribers = registry.subscribers_for(name, "error")
      deadline_seconds = registry.chain_deadline_seconds

      chain_ctx = ctx.with_metadata(**{ERROR_EXC_METADATA_KEY: exc})
      last_good_ctx = chain_ctx
      pending: asyncio.Task[HookContext[T] | None] | None = None

      try:
          async with asyncio.timeout(deadline_seconds):
              for sub in subscribers:
                  pending = _spawn_subscriber(sub, chain_ctx)
                  try:
                      result = await pending
                  except Exception as raised_exc:
                      pending = None
                      if isinstance(raised_exc, HookRefusal):
                          raise
                      await _emit_subscriber_error_audit(
                          sub=sub, exc=raised_exc,
                          hookpoint=name, kind="error",
                          correlation_id=chain_ctx.correlation_id,
                      )
                      if fail_closed:
                          raise _wrap_subscriber_error(
                              sub=sub, correlation_id=chain_ctx.correlation_id,
                          ) from raised_exc
                      chain_ctx = last_good_ctx
                      continue
                  pending = None
                  if result is None:
                      continue
                  # Subscriber returned non-None. PR-S4-3 contract:
                  # the subscriber MUST embed its substitute as
                  # ``result.metadata["substitute_result"]`` typed as
                  # SubstituteResult[T]. (We extract from metadata
                  # because the existing subscriber signature returns
                  # HookContext[T] | None; widening to ErrorOutcome[T]
                  # would break every Slice-2.5 subscriber.)
                  subscribed = _extract_substitute_from_ctx(
                      result, carrier_type=carrier_type,
                  )
                  if subscribed is None:
                      # No substitute embedded -- treat as observation only,
                      # continue the chain.
                      chain_ctx = result
                      last_good_ctx = result
                      continue
                  outcome = await _disposition_substitute(
                      registry=registry,
                      sub=sub,
                      name=name,
                      substitute=subscribed,
                      allow_substitution=allow_substitution,
                      carrier_tier=carrier_tier_for_guard,
                      correlation_id=chain_ctx.correlation_id,
                      exc=exc,
                  )
                  if isinstance(outcome, ReRaise):
                      # Refused (tier upgrade / not allowed). Continue
                      # the chain so a later subscriber may substitute
                      # successfully.
                      chain_ctx = last_good_ctx
                      continue
                  return outcome
      except TimeoutError:
          await _handle_chain_timeout(
              pending=pending, chain_ctx=chain_ctx,
              hookpoint=name, kind="error",
              deadline_seconds=deadline_seconds,
              fail_closed=fail_closed,
          )
          # Timeout returns last-good ctx in the legacy shape. PR-S4-3
          # maps that to ReRaise() -- the chain didn't get to decide.
          return ReRaise()

      return ReRaise()
  ```

  And two helpers:

  ```python
  def _extract_substitute_from_ctx[T](
      ctx: HookContext[T], *, carrier_type: type[T],
  ) -> SubstituteResult[T] | None:
      """Pull SubstituteResult[T] off ctx.metadata["substitute_result"], if any.

      Subscribers that want to substitute on the error chain write the
      SubstituteResult instance to ctx.metadata under the
      ``substitute_result`` key BEFORE returning the ctx. The dispatcher
      reads it here; an absent key signals "observation only".

      We pin the carrier_type at the extract site so a malicious
      subscriber that constructs SubstituteResult[OtherType] is refused
      via a Pydantic validation against ``carrier_type``.
      """
      raw = ctx.metadata.get("substitute_result")
      if raw is None:
          return None
      if not isinstance(raw, SubstituteResult):
          return None
      # Validate payload against carrier_type by re-constructing the model.
      try:
          return SubstituteResult[carrier_type](
              payload=raw.payload,
              source_tier=raw.source_tier,
              subscriber_id=raw.subscriber_id,
          )
      except Exception:
          return None


  async def _disposition_substitute[T](
      *,
      registry: HookRegistry,
      sub: Subscriber,
      name: str,
      substitute: SubstituteResult[T],
      allow_substitution: bool,
      carrier_tier: type[TrustTier] | None,
      correlation_id: str,
      exc: BaseException,
  ) -> ErrorOutcome[T]:
      """Apply the tier-upgrade guard + allow_error_substitution check.

      Three refusal arms:

      * ``allow_substitution=False`` -- emit CARRIER_SUBSTITUTION_REFUSED
        with ``reason="substitution_not_allowed"``. Returns ReRaise().
      * ``carrier_tier`` is None and the hookpoint is one of the meta-
        hookpoints -- emit ``reason="recursion_refused"``. Returns ReRaise().
      * tier-upgrade guard fails -- emit ``reason="tier_upgrade_refused"``.
        Returns ReRaise().

      Happy path: emit CARRIER_SUBSTITUTION with the matched substitute;
      return SubstituteResult[T] verbatim.
      """
      if not allow_substitution:
          await registry.sink.emit(
              event=HOOKS_CARRIER_SUBSTITUTION_REFUSED,
              correlation_id=correlation_id,
              fields={
                  "hookpoint": name,
                  "subscriber_id": sub.hook_fn.__qualname__,
                  "attempted_source_tier": substitute.source_tier,
                  "carrier_tier": (carrier_tier.name if carrier_tier else "none"),
                  "reason": "substitution_not_allowed",
                  "refused_at": _now_iso(),
              },
          )
          return ReRaise()
      if carrier_tier is None:
          # Meta-hookpoint case -- allow_substitution should already be
          # False here; this is defense-in-depth.
          await registry.sink.emit(
              event=HOOKS_CARRIER_SUBSTITUTION_REFUSED,
              correlation_id=correlation_id,
              fields={
                  "hookpoint": name,
                  "subscriber_id": sub.hook_fn.__qualname__,
                  "attempted_source_tier": substitute.source_tier,
                  "carrier_tier": "none",
                  "reason": "recursion_refused",
                  "refused_at": _now_iso(),
              },
          )
          return ReRaise()
      if not _enforce_substitute_tier(
          carrier_tier=carrier_tier, source_tier=substitute.source_tier,
      ):
          await registry.sink.emit(
              event=HOOKS_CARRIER_SUBSTITUTION_REFUSED,
              correlation_id=correlation_id,
              fields={
                  "hookpoint": name,
                  "subscriber_id": sub.hook_fn.__qualname__,
                  "attempted_source_tier": substitute.source_tier,
                  "carrier_tier": carrier_tier.name,
                  "reason": "tier_upgrade_refused",
                  "refused_at": _now_iso(),
              },
          )
          return ReRaise()
      await registry.sink.emit(
          event=HOOKS_CARRIER_SUBSTITUTION,
          correlation_id=correlation_id,
          fields={
              "hookpoint": name,
              "subscriber_id": sub.hook_fn.__qualname__,
              "source_tier": substitute.source_tier,
              "carrier_tier": carrier_tier.name,
              "substituted_at": _now_iso(),
          },
      )
      return substitute
  ```

  Add the two new audit-row event constants to `src/alfred/hooks/audit_sink.py`:

  ```python
  HOOKS_CARRIER_SUBSTITUTION: Final[str] = "hooks.carrier_substitution"
  HOOKS_CARRIER_SUBSTITUTION_REFUSED: Final[str] = "hooks.carrier_substitution_refused"
  ```

  Add `_now_iso()` (a thin wrapper around `datetime.now(UTC).isoformat()`) in `src/alfred/hooks/invoke.py` if no shared helper already exists.

  Update `_dispatch_by_kind` (line 638-645) to thread `carrier_type` through to `_run_error`. The public `invoke[T]` entry point (line 404) gains `carrier_type: type[T] | None = None` and forwards it; the early-precondition check for `kind == "error" and exc is None` (line 541) extends with a parallel check for `carrier_type is None`.

  **Run:** `uv run pytest tests/unit/hooks/test_run_error_signature.py tests/unit/hooks/test_tier_upgrade_guard.py -x`

  **Expected:** `18 passed`.

  **Run quality gate:** `uv run mypy src/alfred/hooks/invoke.py --strict && uv run ruff check src/alfred/hooks/`

  **Expected:** clean.

  **Commit:**

  ```
  feat(hooks): _run_error returns ErrorOutcome[T] with strict total-order tier guard (#170)
  ```

- [ ] **Task D5 — Failing test: `invoke[T]` public surface forwards `carrier_type`**

  **Files:** Extend `tests/unit/hooks/test_run_error_signature.py`.

  Add a test that calls `await invoke("x.action", ctx, kind="error", exc=ValueError("x"), carrier_type=SomeType, ...)` against a fixture registry with one subscriber that embeds a `SubstituteResult` on ctx.metadata. Assert the returned outcome is the SubstituteResult and the substitution audit row is emitted.

- [ ] **Task D6 — Implementation: thread `carrier_type` through `invoke[T]`**

  Update `invoke[T]` signature at line 404. Update `_dispatch_by_kind` at line 601. Run the test green.

  **Commit:**

  ```
  feat(hooks): thread carrier_type through invoke[T] public surface (#170)
  ```

### Component E — Meta-hookpoint registration

- [ ] **Task E1 — Failing test: meta-hookpoints register with the documented shape**

  **Files:** Create `tests/unit/hooks/test_meta_hookpoint_registration.py`.

  ```python
  """Meta-hookpoints register observation-only; subscribers cannot substitute."""

  from __future__ import annotations

  import pytest

  from alfred.hooks.errors import HookError
  from alfred.hooks.invoke import SubstituteResult, invoke
  from alfred.hooks.registry import (
      HookRegistry, SYSTEM_ONLY_TIERS,
  )
  from alfred.hooks._known_hookpoints import declare_meta_hookpoints
  from tests.helpers.gates import grant_all_gate


  def test_declare_meta_hookpoints_registers_carrier_substituted() -> None:
      reg = HookRegistry(gate=grant_all_gate(), strict_declarations=True)
      declare_meta_hookpoints(reg)
      meta = reg.hookpoint_meta("hooks.carrier_substituted")
      assert meta is not None
      assert meta.subscribable_tiers == SYSTEM_ONLY_TIERS
      assert meta.refusable_tiers == frozenset()
      assert meta.fail_closed is False
      assert meta.carrier_tier is None
      assert meta.allow_error_substitution is False


  def test_declare_meta_hookpoints_registers_refused_variant() -> None:
      reg = HookRegistry(gate=grant_all_gate(), strict_declarations=True)
      declare_meta_hookpoints(reg)
      meta = reg.hookpoint_meta("hooks.carrier_substitution_refused")
      assert meta is not None
      assert meta.allow_error_substitution is False


  def test_meta_hookpoint_substitute_refused_at_dispatch() -> None:
      # Defense-in-depth: even if a subscriber somehow gets registered
      # for kind="error" on a meta-hookpoint AND tries to return a
      # SubstituteResult on ctx.metadata, the dispatcher refuses via
      # the allow_error_substitution check.
      # ... (full test exercises invoke with an error subscriber on the
      # meta-hookpoint; asserts ReRaise outcome + audit row with
      # reason="substitution_not_allowed").
      ...
  ```

  **Run:** `uv run pytest tests/unit/hooks/test_meta_hookpoint_registration.py -x`

  **Expected:** `FAILED` with `ImportError: cannot import name 'declare_meta_hookpoints'`.

- [ ] **Task E2 — Implementation: `declare_meta_hookpoints`**

  **Files:** Modify `src/alfred/hooks/_known_hookpoints.py`.

  Add:

  ```python
  def declare_meta_hookpoints(registry: HookRegistry | None = None) -> None:
      """Register the two observation-only carrier-substitution meta-hookpoints.

      Called once at bootstrap from src/alfred/bootstrap/... (the existing
      ``declare_hookpoints`` orchestrator).
      """
      reg = registry if registry is not None else get_registry()
      reg.register_hookpoint(
          name="hooks.carrier_substituted",
          subscribable_tiers=SYSTEM_ONLY_TIERS,
          refusable_tiers=frozenset(),
          fail_closed=False,
          carrier_tier=None,
          allow_error_substitution=False,
      )
      reg.register_hookpoint(
          name="hooks.carrier_substitution_refused",
          subscribable_tiers=SYSTEM_ONLY_TIERS,
          refusable_tiers=frozenset(),
          fail_closed=False,
          carrier_tier=None,
          allow_error_substitution=False,
      )
  ```

  Wire into the existing bootstrap surface (search for `declare_hookpoints` callers in `src/alfred/bootstrap/`).

  **Run:** `uv run pytest tests/unit/hooks/test_meta_hookpoint_registration.py -x`

  **Expected:** `3 passed`.

  **Commit:**

  ```
  feat(hooks): declare hooks.carrier_substituted + carrier_substitution_refused meta-hookpoints (#170)
  ```

### Component F — Sibling-site migrations

Each sibling-site task is a self-contained test-then-implementation pair. The four sites can ship in any order; they all converge on the same AST guard once their `register_hookpoint(...)` calls update.

- [ ] **Task F1 — Failing test: `QuarantinedExtractor.extract` propagates `SubstituteResult[ExtractionResult]`**

  **Files:** Create `tests/unit/security/test_quarantine_extract_carrier.py`.

  Boot a registry with one error-stage subscriber on `security.quarantined.extract.write_failed` that embeds a `SubstituteResult[ExtractionResult]` on `ctx.metadata["substitute_result"]`. Call `QuarantinedExtractor.extract(...)`. Assert it returns the substitute payload AND emits `CARRIER_SUBSTITUTION_FIELDS`. Cross-test: a T2-source-tier substitute on a T3 carrier is ACCEPTED; a T3-source-tier substitute on a T3 carrier is ACCEPTED; the T3 carrier accepts every tier.

  **Expected:** `FAILED` — `QuarantinedExtractor.extract` still uses the Slice-3 `raise exc` short-circuit.

- [ ] **Task F2 — Implementation: migrate `QuarantinedExtractor.extract`**

  **Files:** Modify `src/alfred/security/quarantine.py` (line 596).

  Locate the existing `_dispatch_error_chain` inside `QuarantinedExtractor.extract`. Replace its body with:

  ```python
  outcome: ErrorOutcome[ExtractionResult] = await invoke(
      "security.quarantined.extract.write_failed",
      ctx, kind="error", exc=exc,
      carrier_type=ExtractionResult,
      subscribable_tiers=SYSTEM_OPERATOR_TIERS,
      fail_closed=True,
  )
  match outcome:
      case ReRaise():
          raise exc
      case SubstituteResult(payload=p):
          return p
  ```

  Update the five existing `register_hookpoint(...)` calls (search the file) to add `carrier_tier=T3`. The Slice-3 hookpoint declarations live elsewhere in this file; the Task adjusts each.

  **Run:** `uv run pytest tests/unit/security/test_quarantine_extract_carrier.py tests/unit/hooks/test_carrier_tier_required.py -x`

  **Expected:** sibling test passes; the AST guard now has fewer offenders.

  **Commit:**

  ```
  feat(security): QuarantinedExtractor.extract consumes ErrorOutcome[ExtractionResult] (#170)
  ```

- [ ] **Task F3 — Failing test: `EpisodicMemory.record` propagates `SubstituteResult[EpisodicRecordOutcome]`**

  **Files:** Create `tests/unit/memory/test_episodic_record_carrier.py`.

  Similar shape to F1. Subscriber on `memory.episodic.record.write_failed` embeds a `SubstituteResult[EpisodicRecordOutcome]`; record() returns the substitute (an `EpisodicRecordOutcome` Pydantic model carrying the would-have-been-written row's metadata).

- [ ] **Task F4 — Implementation: migrate `EpisodicMemory.record`**

  **Files:** Modify `src/alfred/memory/episodic.py`.

  Add `EpisodicRecordOutcome` Pydantic frozen model at file scope (carries `episode_id: UUID`, `user_id: str`, `role: str`, `substituted: bool = True`). Update `Flow.body(error=...)` consumption — the existing call at line 268's `async with invoking(...)` block uses `flow.body(post=..., error=..., cancel=...)`. The `Flow.body` helper at `src/alfred/hooks/invoke.py:1895` needs a `carrier_type=EpisodicRecordOutcome` kwarg added (this lives in Component D's edits — Task D7).

  Update the five existing `register_hookpoint(...)` calls at lines 56-60 + the `declare_hookpoints` function at line 59 to add `carrier_tier=T2`.

  **Run:** `uv run pytest tests/unit/memory/test_episodic_record_carrier.py -x`

  **Expected:** test passes; AST guard further reduced.

  **Commit:**

  ```
  feat(memory): EpisodicMemory.record consumes ErrorOutcome[EpisodicRecordOutcome] (#170)
  ```

- [ ] **Task F5 — Failing test: `_ingest_tier` wraps in `invoking()` and propagates `ErrorOutcome[IngestTierOutcome]`**

  **Files:** Create `tests/unit/identity/test_ingest_tier_carrier.py`.

  Subscriber on `identity._ingest_tier.resolve_failed` embeds a `SubstituteResult[IngestTierOutcome]`; `_ingest_tier()` returns the substitute (`type[TrustTier]` wrapped in the outcome). T1-source-tier substitute on T1 carrier ACCEPTED; T2 substitute REFUSED.

- [ ] **Task F6 — Implementation: migrate `_ingest_tier`**

  **Files:** Modify `src/alfred/identity/_ingest.py`.

  Add `IngestTierOutcome` Pydantic frozen model carrying `tier_name: Literal["T0","T1","T2","T3"]`. Wrap `_ingest_tier` (currently pure at line 103) with `invoking("identity._ingest_tier", inp)` and consume `Flow.body(error=..., carrier_type=IngestTierOutcome)`.

  Extend `declare_hookpoints` (line 59) to register the five new `identity._ingest_tier.*` hookpoints with `carrier_tier=T1`.

  Update any existing `register_hookpoint(...)` calls in this file (search) to add `carrier_tier=T1`.

  **Run:** `uv run pytest tests/unit/identity/test_ingest_tier_carrier.py -x`

  **Expected:** test passes.

  **Commit:**

  ```
  feat(identity): wrap _ingest_tier in invoking() with ErrorOutcome[IngestTierOutcome] (#170)
  ```

- [ ] **Task F7 — Failing test: `state.dispatch_loop._record_failure` propagates `ErrorOutcome[DispatchFailureOutcome]`**

  **Files:** Create `tests/unit/state/test_dispatch_loop_record_failure_carrier.py`.

  Subscriber on `state.dispatch_loop._record_failure.write_failed` embeds a `SubstituteResult[DispatchFailureOutcome]`; `_record_failure` returns the substitute (DispatchFailureOutcome carries the substituted `failure_reason`).

- [ ] **Task F8 — Implementation: migrate `_record_failure`**

  **Files:** Modify `src/alfred/state/dispatch_loop.py`.

  Locate `_record_failure` at line 819 (verified — the user prompt's `_handle_dispatch_failure` does NOT exist; the real name is `_record_failure`).

  Add `DispatchFailureOutcome` Pydantic frozen model carrying the substituted failure_reason. Wrap `_record_failure` in `invoking("state.dispatch_loop._record_failure", inp)`. Use `Flow.body(error="state.dispatch_loop._record_failure.write_failed", carrier_type=DispatchFailureOutcome, ...)`.

  Register the five new hookpoints in a new `declare_hookpoints` function in this file (mirroring the `src/alfred/memory/episodic.py:59` pattern). `carrier_tier=T0` (dispatch loop is system-tier).

  Wire the new `declare_hookpoints` into the bootstrap orchestrator alongside the meta-hookpoint declaration.

  **Run:** `uv run pytest tests/unit/state/test_dispatch_loop_record_failure_carrier.py tests/unit/hooks/test_carrier_tier_required.py -x`

  **Expected:** sibling test passes; the AST guard is now GREEN (every `register_hookpoint(...)` call site in `src/` passes `carrier_tier=`).

  **Commit:**

  ```
  feat(state): wrap dispatch_loop._record_failure in invoking() with ErrorOutcome[DispatchFailureOutcome] (#170)
  ```

### Component G — Adversarial corpus (`crf-` prefix)

- [ ] **Task G1 — Corpus YAML: tier-upgrade matrix (`crf-2026-001`)**

  **Files:** Create `tests/adversarial/carrier_substitution_tamper/__init__.py` (empty package marker) AND `tests/adversarial/carrier_substitution_tamper/crf-2026-001-tier-upgrade.yaml`.

  YAML shape (per the existing `tier_laundering` corpus conventions from PR-S3-1):

  ```yaml
  id: crf-2026-001
  category: carrier_substitution_tamper
  title: malicious_error_subscriber_attempts_tier_upgrade
  description: |
    A T2-source-tier subscriber returns a SubstituteResult on a T0 carrier.
    The substitute attempts to elevate the action's effective trust tier.
    Strict total-order guard MUST refuse and emit CARRIER_SUBSTITUTION_REFUSED
    with reason="tier_upgrade_refused".
  variants:
    - name: t3_substitute_on_t0_carrier
      carrier_tier: T0
      source_tier: T3
      expected_outcome: refused
      expected_reason: tier_upgrade_refused
    - name: t3_substitute_on_t1_carrier
      carrier_tier: T1
      source_tier: T3
      expected_outcome: refused
      expected_reason: tier_upgrade_refused
    - name: t3_substitute_on_t2_carrier
      carrier_tier: T2
      source_tier: T3
      expected_outcome: refused
      expected_reason: tier_upgrade_refused
    - name: t2_substitute_on_t0_carrier
      carrier_tier: T0
      source_tier: T2
      expected_outcome: refused
      expected_reason: tier_upgrade_refused
    - name: t2_substitute_on_t1_carrier
      carrier_tier: T1
      source_tier: T2
      expected_outcome: refused
      expected_reason: tier_upgrade_refused
    - name: t1_substitute_on_t0_carrier
      carrier_tier: T0
      source_tier: T1
      expected_outcome: refused
      expected_reason: tier_upgrade_refused
  ```

- [ ] **Task G2 — Executable test: tier-upgrade refused**

  **Files:** Create `tests/adversarial/carrier_substitution_tamper/test_tier_upgrade_refused.py`.

  Loads the YAML; for each variant, registers a fixture hookpoint with the variant's `carrier_tier`, registers an error subscriber that embeds a `SubstituteResult` with the variant's `source_tier`, invokes the chain, asserts a `ReRaise` outcome AND a captured audit row matching `CARRIER_SUBSTITUTION_REFUSED_FIELDS` with the expected reason.

  **Commit:**

  ```
  test(adversarial): crf-2026-001 tier-upgrade-refused corpus (#170)
  ```

- [ ] **Task G3 — Corpus + test: malformed substitute (`crf-2026-002`)**

  YAML carries a payload whose Pydantic validation against `carrier_type` fails (e.g., wrong field set). Test asserts the substitute is refused with `reason="payload_type_mismatch"` AND the original exception re-raises.

  **Commit:**

  ```
  test(adversarial): crf-2026-002 malformed-substitute-payload corpus (#170)
  ```

- [ ] **Task G4 — Corpus + test: wrong type substitute (`crf-2026-003`)**

  YAML carries a payload that satisfies Python's runtime type system loosely (e.g., a `dict` where a `BaseModel` was expected) but fails Pydantic validation. Test asserts refusal + original exception re-raises.

  **Commit:**

  ```
  test(adversarial): crf-2026-003 wrong-type-substitute corpus (#170)
  ```

- [ ] **Task G5 — Corpus + test: meta-hookpoint recursion (`crf-2026-004`)**

  YAML describes the threat shape: a subscriber on `hooks.carrier_substituted` that tries to substitute on the meta-hookpoint's own error chain.

  Test asserts two refusals:
  1. **Registration-time refusal** — the subscriber's `@hook(hookpoint, kind="error", tier="system")` decoration causes `register_hookpoint`'s subscriber surface to refuse via the `allow_error_substitution=False` check.
  2. **Dispatch-time defense-in-depth** — even if the registration somehow slipped past, dispatching the chain would refuse with `reason="recursion_refused"`.

  **Commit:**

  ```
  test(adversarial): crf-2026-004 meta-hookpoint-recursion-refused corpus (#170)
  ```

### Component H — Merge-blocking integration test

- [ ] **Task H1 — Failing test: `test_error_chain_substitution_propagates.py`**

  **Files:** Create `tests/integration/test_error_chain_substitution_propagates.py`.

  Boots Postgres + Redis via testcontainers (the existing `tests/integration/conftest.py` fixture). For each of the four sibling sites, registers a known-good substitute subscriber and exercises the action end-to-end:

  1. `QuarantinedExtractor.extract` — substitute returns a synthetic `ExtractionResult`; assert DB row written with substituted data; assert `CARRIER_SUBSTITUTION_FIELDS` audit row landed in Postgres.
  2. `EpisodicMemory.record` — substitute returns a synthetic `EpisodicRecordOutcome`; assert the action's caller sees the substitute return; assert audit row landed.
  3. `_ingest_tier` — substitute returns a synthetic `IngestTierOutcome`; assert the caller observes the substituted tier value (within T1's accept-set).
  4. `_record_failure` — substitute returns a synthetic `DispatchFailureOutcome`; assert the ledger row carries the substituted reason.

  This test is promoted to merge-blocking required-status-check per index §4 (`Owning PR: PR-S4-3 | Topology: ubuntu-latest`).

- [ ] **Task H2 — Promote to required-status check**

  After the test runs green locally, follow the `author-gating-workflow` skill to:
  1. Add the test path to `.github/workflows/ci.yml`'s integration job.
  2. After PR merge, promote the job to required-status via `gh api`.
  3. Update the tracked required-checks manifest at `.github/required-checks.md` (or equivalent).

  **Commit:**

  ```
  test(integration): error_chain_substitution_propagates merge-blocking gate (#170)
  ```

### Component I — Verification + quality gates

- [ ] **Task I1 — Run the full quality bar**

  ```bash
  uv run pytest tests/unit/hooks/ tests/unit/security/ tests/unit/memory/ tests/unit/identity/ tests/unit/state/ -x
  uv run pytest tests/adversarial/carrier_substitution_tamper/ -x
  uv run pytest tests/integration/test_error_chain_substitution_propagates.py -x
  uv run mypy src/alfred/hooks/ src/alfred/security/quarantine.py src/alfred/memory/episodic.py src/alfred/identity/_ingest.py src/alfred/state/dispatch_loop.py --strict
  uv run pyright src/alfred/hooks/ src/alfred/security/quarantine.py src/alfred/memory/episodic.py src/alfred/identity/_ingest.py src/alfred/state/dispatch_loop.py
  uv run ruff check src/alfred/ tests/
  uv run ruff format --check src/alfred/ tests/
  uv run coverage run -m pytest tests/unit/hooks/ tests/unit/security/test_quarantine_extract_carrier.py tests/unit/memory/test_episodic_record_carrier.py tests/unit/identity/test_ingest_tier_carrier.py tests/unit/state/test_dispatch_loop_record_failure_carrier.py
  uv run coverage report --fail-under=100 --include='src/alfred/hooks/invoke.py,src/alfred/hooks/registry.py'
  uv run pybabel extract -F babel.cfg -o messages.pot src/
  uv run pybabel update -i messages.pot -d locales/
  uv run pybabel compile --check -d locales/
  ```

  **Expected:** every gate green.

- [ ] **Task I2 — Run the adversarial suite**

  Per CLAUDE.md security rule #1 ("If you change anything in `src/alfred/security/`, you must run the full adversarial suite locally") — this PR touches `src/alfred/security/quarantine.py`. Run:

  ```bash
  uv run pytest tests/adversarial/ -x
  ```

  **Expected:** every adversarial test green, including the four new `crf-` entries AND every Slice-1/Slice-2/Slice-3 entry (tier-laundering, prompt-injection, capability, DLP, canary, ingestion-path, hook).

- [ ] **Task I3 — Local `/review-pr` pass**

  Run `/review-pr` locally before pushing (per project memory: "Run /review-pr + CodeRabbit CLI locally before EVERY push — closes the iteration loop in seconds-to-minutes vs cloud round-trip"). Address every finding before opening the PR.

- [ ] **Task I4 — Open PR**

  Use `/commit-push-pr` skill. PR title:

  ```
  feat(hooks): PR-S4-3 carrier substitution -- recoverable-carrier semantic for error-stage hookpoint dispatch (#170)
  ```

  PR body — 6 sections per project convention:

  1. **Summary** — what shipped: `HookpointMeta.carrier_tier`, `ErrorOutcome[T]`, `_run_error` rewrite, four sibling migrations, two meta-hookpoint declarations, AST guard, `crf-` adversarial corpus, merge-blocking integration test.
  2. **Why** — ADR-0022 / #170 closure; Critical 5 strict-total-order tier-upgrade refusal; rev-007 placement of HookpointMeta fields in PR-S4-3 not PR-S4-0a.
  3. **Spec anchors** — `docs/superpowers/specs/2026-06-06-slice-4-design.md` §4.1-4.7; `docs/superpowers/plans/2026-06-07-slice-4-index.md` §3 `HookpointMeta.carrier_tier` contract.
  4. **Verification** — `make check` green; adversarial suite green; integration test green; coverage 100% on the four trust-boundary files.
  5. **Cross-PR contracts** — restate what downstream PR-S4-1/4/5/6/7/8/9 may assume (see §4 of this plan).
  6. **Closes** — `Closes #170`.

  After PR merges:
  - Promote `tests/integration/test_error_chain_substitution_propagates.py` to required-status check via `gh api` per `author-gating-workflow` skill.
  - Update the required-checks manifest.

---

## §6 Verification gate — fabricated-surfaces audit

Per index §8's "Fabricated-surfaces watchlist for writing-plans" backlog entry, this plan grep-verifies every cited Slice-3 / Slice-2.5 surface BEFORE asserting it in §2-§5. The audit follows:

| Cited surface | Status | Evidence |
| --- | --- | --- |
| `class HookpointMeta` at `src/alfred/hooks/registry.py` | ✅ VERIFIED | Defined at line 175, `@dataclass(frozen=True, slots=True)`. |
| `HookRegistry.register_hookpoint` shape | ✅ VERIFIED | Defined at line 539; takes `name`, `subscribable_tiers`, `refusable_tiers`, `fail_closed` keyword-only. |
| `_run_error` current signature | ✅ VERIFIED | Defined at `src/alfred/hooks/invoke.py:1519-1526`. Returns `HookContext[T]`, NOT `None`. **Spec §4.3's "Before" claim (`-> None`) is wrong** — the actual return type was `HookContext[T]` already. The plan's "before" → "after" delta is the addition of `carrier_type` and the change from `HookContext[T]` to `ErrorOutcome[T]`. |
| `alfred.memory.episodic.record` invoking call | ⚠️ DRIFT | User prompt says line 259; the actual line is **268** (`async with invoking("memory.episodic.record", inp) as flow:`). Plan uses 268. |
| `alfred.identity._ingest` path | ⚠️ DRIFT | The function the spec calls "alfred.identity._ingest" is actually `_ingest_tier` at `src/alfred/identity/_ingest.py:103`. There is no bare `_ingest` callable. The function is currently PURE — it does NOT route through `invoking()`. PR-S4-3 wraps it (this is a code-change, not just a migration). |
| `alfred.state.dispatch_loop._handle_dispatch_failure` | ❌ FABRICATED | **Does not exist.** The actual function is `_record_failure` at `src/alfred/state/dispatch_loop.py:819`. Plan uses the real name. |
| `class TrustTier` at `src/alfred/security/` | ✅ VERIFIED | Defined at `src/alfred/security/tiers.py:28`. NOT `trust_tiers.py` as spec §4.4 claims — that path is fabricated. |
| `T0`, `T1`, `T2`, `T3` ordering via `<` operator | ❌ FABRICATED | Spec §4.4 says `TrustTier("T0") < TrustTier("T3")`. **No such operator exists** — `TrustTier` subclasses are CLASS objects (never instantiated), and they have no `__lt__`. The plan introduces ordering via `_TRUST_TIER_RANK` dict instead. |
| `T3DerivedData` at `src/alfred/security/quarantine.py:145` | ✅ VERIFIED | `NewType("T3DerivedData", dict[str, object])`. |
| `CARRIER_SUBSTITUTION_FIELDS` / `CARRIER_SUBSTITUTION_REFUSED_FIELDS` | ✅ VERIFIED (scheduled) | Defined in PR-S4-0a per `docs/superpowers/plans/2026-06-07-slice-4-pr-s4-0a-docs-adrs-foundations.md:803-823`. This PR consumes them. |
| `hooks.carrier_substituted` / `hooks.carrier_substitution_refused` hookpoint names | ✅ VERIFIED | Index §3 references both. Spec §4.7 has a typo (`carrier_substituted_refused`); plan uses the index spelling (`carrier_substitution_refused`) per the rev-010 round-4 hookpoint table. |
| `ExtractionResult` discriminated union at `src/alfred/security/quarantine.py` | ✅ VERIFIED | Slice-3-shipped per PR-S3-1 plan §3 file structure. |
| `Flow.body(post=, error=, cancel=)` at `src/alfred/hooks/invoke.py:1895` | ✅ VERIFIED | Defined at line 1895; existing signature takes `post`, `error`, `cancel` as required kwargs. PR-S4-3 extends to add `carrier_type`. |

Two drift / fabrication items are loud-failures that any downstream PR using this plan should NOT blindly assume to match the spec. The plan uses the real names; downstream PRs reading the spec directly must reconcile via this audit. A follow-up issue should be opened to amend spec §4.3 ("Before" type), §4.4 (`trust_tiers.py` path + the `TrustTier()` instantiation shape), and §4.5 (the `_handle_dispatch_failure` callable name).

---

## §7 What PR-S4-3 does NOT do (boundaries)

To prevent scope creep, this section enumerates the work explicitly out of scope:

- **Other PRs' hookpoint registrations.** PR-S4-3 only registers the two meta-hookpoints AND the new declarations for the four sibling sites. Every other downstream hookpoint (daemon.boot.*, supervisor.config_reload, operator.session.*, etc.) is registered in its owning PR per index §3 hookpoint-surface table.
- **Other adversarial corpus categories.** PR-S4-3 ships only `carrier_substitution_tamper` (the `crf-` prefix). Other Slice-4 categories (`sandbox_escape` / `sbx-`, `config_reload_bypass` / `csb-`, `operator_session_forgery` / `osf-`, `comms_identity_boundary` / `cib-`) land in their owning PRs.
- **Per-kind `fail_closed` override on `HookpointMeta`.** Deferred to Slice 5 per #167 / index §1 explicit-out-of-scope.
- **`__lt__` on `TrustTier` subclasses.** Out of scope. PR-S4-3 introduces ordering via `_TRUST_TIER_RANK` only; a future Slice-5+ refactor may unify ordering surfaces, but not in this PR.
- **Spec-correction follow-up issue.** The spec §4.3 "Before" type, §4.4 `trust_tiers.py` path, §4.4 `TrustTier()` instantiation shape, and §4.5 `_handle_dispatch_failure` callable name corrections are tracked but NOT shipped in this PR. The plan's §6 fabricated-surfaces audit IS the corrective lens.

---

## §8 Rollback strategy

Per index §5 rollback table:

> Carrier substitution reverts to "subscriber suppression allowed but raise short-circuits" (Slice-3 documented baseline in `quarantine.py`).

Concrete revert steps if PR-S4-3 needs to be backed out:

1. `git revert <PR-S4-3 merge commit>` on `main`.
2. Run the adversarial suite — every `crf-` test will fail (the corpus is gone), but no other suite should regress.
3. Downstream PRs (PR-S4-1, PR-S4-4, etc.) that already merged with `carrier_tier=` in their `register_hookpoint(...)` calls will FAIL `make check` against the reverted `HookpointMeta` (the field no longer exists). Each downstream PR must be reverted IN REVERSE MERGE ORDER, or PR-S4-3 must be re-landed before any downstream PR can re-merge.

This is the rev-009 ancestry constraint made concrete: PR-S4-3 cannot be reverted in isolation once a downstream PR has merged.

A safer alternative if a regression surfaces post-merge: ship a follow-up PR-S4-3.1 that addresses the regression directly, rather than reverting the foundational PR. The rev-009 ancestry chain is hard.

---

## §9 What success looks like

PR-S4-3 is merged when:

1. ✅ All §5 task tests are green (Components A-I).
2. ✅ `make check` is green.
3. ✅ Adversarial suite is green (every existing entry + four new `crf-` entries).
4. ✅ `tests/integration/test_error_chain_substitution_propagates.py` is green AND promoted to required-status check.
5. ✅ `tests/unit/hooks/test_carrier_tier_required.py` is green (AST guard confirms every `src/alfred/` `register_hookpoint(...)` call passes `carrier_tier=`).
6. ✅ 100% line + branch coverage on `src/alfred/hooks/invoke.py` (the `_run_error` rewrite is the trust-boundary) and `src/alfred/hooks/registry.py` (the `HookpointMeta` extension and `register_hookpoint` gates).
7. ✅ `uv run mypy --strict` + `uv run pyright` clean on the six modified files.
8. ✅ `uv run ruff check` + `uv run ruff format --check` clean.
9. ✅ `pybabel extract` shows the new i18n keys; `pybabel compile --check` is clean.
10. ✅ CodeRabbit cloud + local `/review-pr` cycles complete with all findings either fixed or explicitly acked.
11. ✅ #170 closes on merge.

Downstream PR-S4-1/4/5/6/7/8/9 plans assume `HookpointMeta.carrier_tier` exists, `ErrorOutcome[T]` is importable from `alfred.hooks.invoke`, `_enforce_substitute_tier` is module-private but the public `invoke[T]` shape is the consumed surface, and the AST guard is enforced on every `register_hookpoint(...)` call.

---

## §10 References

- Spec: [`docs/superpowers/specs/2026-06-06-slice-4-design.md`](../specs/2026-06-06-slice-4-design.md) §4 (4.1-4.7).
- Index: [`docs/superpowers/plans/2026-06-07-slice-4-index.md`](./2026-06-07-slice-4-index.md) §3 `HookpointMeta.carrier_tier` contract.
- Sibling template (shape only): [`docs/superpowers/plans/2026-05-31-slice-3-pr-s3-1-trust-tier-types.md`](./2026-05-31-slice-3-pr-s3-1-trust-tier-types.md).
- PR-S4-0a foundations: [`docs/superpowers/plans/2026-06-07-slice-4-pr-s4-0a-docs-adrs-foundations.md`](./2026-06-07-slice-4-pr-s4-0a-docs-adrs-foundations.md) lines 87-88, 803-823, 843-856 (`CARRIER_SUBSTITUTION_FIELDS` / `CARRIER_SUBSTITUTION_REFUSED_FIELDS` definitions).
- ADR-0014: [`docs/adr/0014-pluggable-hooks-for-every-action.md`](../../adr/0014-pluggable-hooks-for-every-action.md) — the hookpoint subsystem this PR extends.
- ADR-0022: ships in PR-S4-0a (full body) — recoverable-carrier semantic for error-stage hookpoint dispatch.
- ADR-0017: [`docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md`](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — the trust-tier model this PR enforces.
- CLAUDE.md: security rules #1 (never log secrets), #3 (always tag input trust tier), #7 (no silent failures in security paths); i18n rule #1 (`t()` for operator-facing strings); coding conventions (PEP 604/685/695 modern Python; Pydantic v2; mypy strict + pyright).
- Karpathy guidelines: surgical changes; surface assumptions in the §6 fabricated-surfaces audit; verifiable success criteria in §9.
