# ADR-0028 — The daemon mints and registers the authorised T3 nonce once at boot

- **Status**: Proposed (accepted at Slice-4 graduation, per the ADR-0015/0016/0025/0026/0027 precedent)
- **Date**: 2026-06-11
- **Slice**: 4 — `docs/superpowers/specs/2026-06-06-slice-4-design.md`
- **Relates to**: [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (Decision 1 — the per-process nonce-gated `tag(T3, ...)` design this operationalises), [ADR-0026](0026-first-party-system-bootstrap-grants-and-boot-hook-registry.md) (the boot trust-boundary infra this registration is sequenced after), [ADR-0027](0027-daemon-comms-runtime-fixture-extractor-first-cut.md) (the daemon comms runtime whose `record_body` seam is the first consumer), issue #237 (the daemon comms-MCP runtime epic)
- **Supersedes**: —

## Context

[ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) Decision 1 made the `tag(T3, ...)` factory capability-gated by a per-process random nonce compared by identity (`is`, not `==`). The mechanism is `alfred.security.tiers.tag_t3_with_nonce(content, *, caller_token)`: it compares `caller_token` against the module-level `_AUTHORIZED_T3_NONCE` slot and raises `ValueError` unless they are the *same object*. The slot is set exactly once at process start by `alfred.bootstrap.nonce_factory.create_and_register_t3_nonce()`, which mints a fresh `CapabilityGateNonce`, installs it under the bootstrap lock (`_NONCE_LOCK`), and returns it so the boot caller can distribute it by DI to the authorised tagging call sites. A second call raises `T3NonceAlreadyRegisteredError`: re-running registration would silently invalidate every authorised holder (its `is` check would suddenly start failing), so the factory refuses rather than rotate. There is deliberately **no production reset API** (CR-138 round-2 finding #4 removed `reset_authorized_t3_nonce_for_tests` from `src/` because any production code could call it to clear the live slot and mint its own authorised nonce — a runtime-callable bypass of the bootstrap DI invariant). Tests reset the slot only through the `clean_t3_nonce_slot` / `authorized_t3_nonce` fixtures (`tests/unit/security/conftest.py`), which poke it inline under the same lock.

The factory was authored, unit-covered, and documented — but **no production process ever called it**. In a live `alfred daemon`, `_AUTHORIZED_T3_NONCE` stayed `None`, so *every* authorised T3-tagging path was dead: `tag_t3_with_nonce(..., caller_token=<anything>)` raised, because `None` is never the authorised nonce. The gate was not just closed, it was un-openable. That latent gap blocks PR-S4-11c-2a: the comms inbound `record_body` seam (the injected `_BodyRecorderLike` on `CommsExtractorBridge`, `src/alfred/comms_mcp/bootstrap.py`) is documented to "tag the body `TaggedContent[T3]` (via the capability-gate nonce path) and write it to the content store the extractor's transport reads." Without a registered nonce, `record_body` cannot tag anything — the host boundary that is supposed to own the gate has no nonce to hold.

This precursor closes the gap the same way the 11b epic closed its boot-infra gaps: a small, security-reviewed boot-wiring PR merged *before* its consumer (the 11b0 grant-seed precursor → 11b spawn; the 11c-1 orchestrator-graph precursor → 11c reply). It mints + registers + threads the nonce; the consumer (`record_body`) lands in 2a.

## Decision

**Decision 1 — Register the authorised T3 nonce once, unconditionally, at daemon boot.** `_start_async` (`src/alfred/cli/daemon/_commands.py`) calls `create_and_register_t3_nonce()` exactly once and holds the returned object in a local. Registration is **always at boot**, not gated on `comms_enabled_adapters`:

- The factory docstring binds the contract to "once at process start" and names future *non-comms* consumers (`StdioTransport` tool paths, `quarantine_host`) that also require the slot. Gating on comms would starve those paths and re-introduce the dead-slot bug for any non-comms T3-tagging surface.
- A `None` slot **is** the production defect. Registering only when an adapter is enabled would leave a default-empty boot with a dead gate — fixing the symptom for one path and not the cause.
- The default-empty boot stays observationally unchanged everywhere *except* the slot: no comms graph is built, no plugin spawns. The nonce object is inert until a consumer reads it.

**Decision 2 — Sequence the registration AFTER the boot trust-boundary infra, BEFORE the comms-graph build.** The call is placed after the [ADR-0026](0026-first-party-system-bootstrap-grants-and-boot-hook-registry.md) seed-gate build + boot `HookRegistry` install + first-party-grant assertion, and after the Postgres-reachability handshake (probe c). Rationale: a daemon that cannot stand up its capability gate has no business holding a live T3 slot, so the nonce is minted only once that boundary is known-good. It is placed before `_build_comms_boot_graph` so the same object can be threaded in by DI.

**Decision 3 — Thread the nonce by DI onto the comms boot graph; do not consume it yet.** `_build_comms_boot_graph` takes the nonce as a keyword parameter and stores it on the frozen `_CommsBootGraph` (`t3_nonce` field). In *this* precursor the field is carried-but-not-consumed — `CommsExtractorBridge` still constructs without a `record_body`; 2a wires `record_body` to read `graph.t3_nonce`. This is the same threaded-but-inert DI pattern as 11c-1's orchestrator and 11b0's grant seed. The nonce is **never** re-fetched from the `tiers` module slot by a consumer and **never** stashed in a module global outside `alfred.security.tiers` — the factory docstring forbids both, because either would break the gate's `is`-identity guarantee (a consumer holding a copy, or a second authoritative slot, defeats the single-object invariant).

**Decision 4 — Fail-closed on a non-empty slot at boot.** A fresh process boots with an empty slot, so registration succeeds. A non-`None` slot at boot means a nonce was already minted (a re-entrant boot path, a leaked test fixture, a duplicate registration), at which point the factory raises `T3NonceAlreadyRegisteredError`. The boot path catches it and runs the audited `_refuse_boot` (exit 2 + a `daemon.boot.failed` row carrying the new `t3_nonce_registration_failed` `failure_reason`) — mirroring 11b0's `boot_infra_install_failed` refusal. Refusing is correct over either silently continuing (the slot would not hold *this* boot's nonce, so every authorised tagging call would fail mysteriously later) or force-resetting (the silent-rotation failure mode the factory exists to prevent). The boot path calls the factory exactly once, so in normal single-process operation this arm never fires.

**Decision 5 — Test reentrancy is handled by the existing slot-cleaning fixture pattern, never a new production reset.** Multiple daemon-boot tests in one pytest process each drive a boot, so each would hit `create_and_register_t3_nonce()` and the second would raise. The `apply_boot_success_patches` harness (behind the `boot_success_env` fixture) now clears the slot to `None` before the boot and restores the prior value on teardown, under `_NONCE_LOCK` — exactly the `clean_t3_nonce_slot` contract, inlined so every daemon-boot-success test inherits it. No production reset API is added (Decision 4 / CR-138 round-2 finding #4 stand).

## Consequences

### Positive

- Every authorised T3-tagging path is live in a production daemon for the first time: `tag_t3_with_nonce` with the booted nonce returns `TaggedContent[T3]` instead of raising. The dual-LLM split's taint-tagging mechanism is no longer un-openable in production.
- PR-S4-11c-2a can wire `record_body` to a host-owned, gate-authorised tagging closure without itself reaching into the `tiers` slot — the nonce arrives by DI on the boot graph, keeping the authorised-tagging authority at the host boundary that owns the gate (the `CommsExtractorBridge` docstring's stated contract).
- The boot path is fail-closed and audited on the only realistic failure (a slot already set), consistent with every other daemon-boot refusal (CLAUDE.md hard rule #7).

### Negative / accepted

- The `_CommsBootGraph.t3_nonce` field is threaded-but-inert in this PR — a deliberate precursor smell (Decision 3), accepted as the cost of shipping the security-reviewed registration ahead of its consumer, exactly as 11b0 and 11c-1 did.
- A second `create_and_register_t3_nonce()` call in a process is fatal-to-boot by design. Test suites that boot the daemon must clean the slot (Decision 5); the harness does this for them, but a new daemon-boot test that bypasses `boot_success_env` must clean the slot itself or it will poison sibling tests.

### Scope boundary

This PR (PR-S4-11c-2a0) ONLY mints + registers + DI-threads the nonce and adds the fail-closed boot refusal. It does **not** build `QuarantineStdioTransport`, the `record_body` recorder, or any 2a code. PR-S4-11c-2a wires `record_body` to tag the inbound comms body `TaggedContent[T3]` using the nonce this precursor threads onto the boot graph.

## Alternatives considered

### Option A — Register the nonce only when `comms_enabled_adapters` is non-empty

Rejected (Decision 1). It would leave a default-empty daemon with a dead T3 gate and starve the future non-comms consumers the factory docstring names (`StdioTransport`, `quarantine_host`). The dead-slot bug is in the *cause* (nobody calls the factory), not in the comms path specifically; the fix belongs at unconditional boot.

### Option B — Have `record_body` (in 2a) call `create_and_register_t3_nonce()` lazily on first use

Rejected. It moves a process-wide, once-only registration onto a per-message hot path, re-introduces the double-call hazard on the second inbound message, and scatters the registration authority away from the single boot site. The factory contract is explicitly "once at process start".

### Option C — Re-fetch the authorised nonce from the `tiers` slot inside the consumer instead of threading it by DI

Rejected. It would let any consumer read `_AUTHORIZED_T3_NONCE` directly, normalising a pattern where the live slot is a global other code reaches into — the exact runtime-callable-bypass surface CR-138 round-2 finding #4 removed. DI-threading the returned object keeps the authority at the boot site and the slot as a write-once gate the factory alone manages.

### Option D — Add a production reset API so duplicate registration is recoverable

Rejected. CR-138 round-2 finding #4 removed the test-only reset from `src/` precisely because a runtime-callable reset lets any code clear the live slot and mint its own authorised nonce. The loud `T3NonceAlreadyRegisteredError` → audited boot refusal is the intended failure mode; recovery is "boot a fresh process", not "rotate the live nonce".

## References

- [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) Decision 1 — the per-process nonce-gated `tag(T3, ...)` design.
- [PRD §7.1 Security & Prompt Injection Defense](../../PRD.md#71-security--prompt-injection-defense) — dual-LLM split; T0–T3 trust tiers.
- Code anchors:
  - `src/alfred/bootstrap/nonce_factory.py` (`create_and_register_t3_nonce`, `T3NonceAlreadyRegisteredError`, `_NONCE_LOCK`)
  - `src/alfred/security/tiers.py` (`_AUTHORIZED_T3_NONCE`, `tag_t3_with_nonce`, `CapabilityGateNonce`)
  - `src/alfred/cli/daemon/_commands.py` (`_start_async` registration + `_build_comms_boot_graph` / `_CommsBootGraph.t3_nonce` threading)
  - `src/alfred/cli/daemon/_failures.py` (`T3NonceRegistrationFailedFailure`)
  - `src/alfred/comms_mcp/bootstrap.py` (`CommsExtractorBridge.record_body` — the 2a consumer)
  - `tests/unit/security/conftest.py` (`clean_t3_nonce_slot` — the slot-cleaning contract the boot harness mirrors)
- Implementing PR: PR-S4-11c-2a0 (boot-time authorised T3-nonce registration).
