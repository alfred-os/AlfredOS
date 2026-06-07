# ADR-0022 — Recoverable-carrier semantic for error-stage hookpoint dispatch

**Date:** 2026-06-07
**Status:** Proposed
**Closes:** [#170](https://github.com/alfred-os/AlfredOS/issues/170)
**Implemented in:** PR-S4-3 (planned)
**Related:** [ADR-0014](./0014-pluggable-hooks-for-every-action.md) (pluggable-hooks contract this ADR extends)

## Context

[ADR-0014](./0014-pluggable-hooks-for-every-action.md) defines four hook kinds — `pre`, `post`, `error`, `cancel` — and a "first non-None wins" carrier-substitution semantic for every kind.

The error chain runs when an instrumented action raises. The Slice-3 implementation at `src/alfred/security/quarantine.py::_dispatch_error_chain` does NOT honour `invoke`'s substitution semantic: an error subscriber that returns a substitute carrier has no way to propagate it back, because the caller's outer `raise exc` unconditionally short-circuits the chain. The inline doc-comment in `quarantine.py` already documented the slice-scoped deferral ("Slice-4+ would honour `invoke`'s 'first non-None wins' carrier-substitution semantic"). CodeRabbit on [PR #168](https://github.com/alfred-os/AlfredOS/pull/168) flagged this gap; [#170](https://github.com/alfred-os/AlfredOS/issues/170) tracks closure.

Without the recoverable-carrier semantic, every quarantined-extraction failure is unrecoverable. Operators have no in-tree mechanism to install a fallback (e.g., a cached prior extraction, a deterministic stub for offline development) without monkey-patching the supervisor — explicitly outside the trust boundary.

## Decision

PR-S4-3 lands the recoverable-carrier semantic for the error stage as follows:

1. **`HookpointMeta` carries the carrier trust tier.** A new required field `carrier_tier: TrustTier` declares the maximum trust tier the substituted carrier may upgrade to. Substitution refuses on strict total order: any subscriber whose registered tier is greater than `carrier_tier` cannot substitute. The strict total order (`T0 < T1 < T2 < T3`) replaces the Slice-3-drafted "refuse T3 only" rule (Critical 5 closure on the round-2 review).

2. **`ErrorOutcome[T]` discriminated union.** `_run_error()` returns `ErrorOutcome[T] = ReRaise | SubstituteResult[T]` instead of `HookContext[T]`. The caller pattern-matches: `ReRaise` re-raises the original exception; `SubstituteResult` extracts the substitute carrier and resumes normal post-chain dispatch.

3. **Subscriber-attested `source_tier`.** `SubstituteResult.source_tier` is NOT subscriber-supplied. The dispatcher reads the firing subscriber's registered tier (`HookRegistration.subscriber_tier`, frozen at registration time) and sets `source_tier` from that. This prevents subscriber-spoofing of `source_tier="T0"` while registered at T3.

4. **`allow_error_substitution` opt-out.** Meta-hookpoints (e.g., `hooks.carrier_substituted`) declare `allow_error_substitution=False`. Both registration-time and dispatch-time guards refuse substitute results from `kind="error"` subscribers on those hookpoints. This blocks recursion through observation hooks.

5. **Wave-migration discipline.** The `HookpointMeta.carrier_tier` field ships in two stages within PR-S4-3: Stage A introduces it as `Optional`, every in-tree call site migrates to an explicit value; Stage B (final PR commit) flips the field to required. The AST guard at `tests/unit/hooks/test_carrier_tier_required.py` catches in-tree call sites; the Pydantic field-required gate catches runtime-registered hookpoints.

## Consequences

**Positive.** Operators can install error-stage fallbacks via a stable in-tree hookpoint. The trust-tier guard prevents T3 → T0 upgrade attacks. The wave-migration discipline keeps every commit green during the rollout. Meta-hookpoints remain observation-only.

**Negative.** Every `register_hookpoint(...)` call site must specify `carrier_tier=` once the wave completes. The strict-total-order semantic differs from the Slice-3 informal docs; operators reading old notes need the §3 reference. Reverting PR-S4-3 after downstream hookpoint-registering PRs have merged requires a coordinated cascade revert covering every PR in the dependent set — concretely, every PR-S4-* that ships a `register_hookpoint(...)` call (PR-S4-1 daemon-boot, PR-S4-4 config watcher, PR-S4-5 operator session, PR-S4-6 sandbox launcher, PR-S4-8 comms, PR-S4-9 Discord, PR-S4-10 TUI). PR-S4-3 ships `scripts/revert-pr-s4-3-cascade.sh` that computes the dependent-PR set from `git log --grep` against the slice-4 epic, opens revert PRs in dependency order, and refuses to remove `carrier_tier=` from a hookpoint whose runtime-loaded plugin manifests still declare it (Slice-5 hardens the plugin-manifest path).

**Alternatives considered.** Returning `HookContext[T]` from `_run_error` and inspecting a magic field on the context — rejected because the type contract becomes implicit, mypy can't help, and the "carrier or not" decision is opaque to readers. Per-hookpoint opt-in instead of universal substitution — rejected because the silent-failure shape (subscriber returns substitute, dispatcher ignores) is exactly the failure mode [#170](https://github.com/alfred-os/AlfredOS/issues/170) documents.

## References

- [#170 — Recoverable-carrier semantic in error chain](https://github.com/alfred-os/AlfredOS/issues/170)
- [ADR-0014](./0014-pluggable-hooks-for-every-action.md) (Pluggable hooks for every action)
- [PR #168](https://github.com/alfred-os/AlfredOS/pull/168) (CodeRabbit flag history)
- Spec: [`docs/superpowers/specs/2026-06-06-slice-4-design.md`](../superpowers/specs/2026-06-06-slice-4-design.md) §3 (carrier substitution)
- Plan: [`docs/superpowers/plans/2026-06-07-slice-4-pr-s4-3-carrier-substitution.md`](../superpowers/plans/2026-06-07-slice-4-pr-s4-3-carrier-substitution.md)
