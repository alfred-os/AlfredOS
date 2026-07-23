# #469 Blocker 2b — invalid-token legibility (typed auth-failure, end to end)

**Status:** design v1 — split out of Blocker 2 (`469-blocker2-gateway-optin-discord`)
after a focused 4-lane `/review-plan` re-review (comms / security / architect / test)
found the folded-in version **Critical-as-written** and trust-boundary-weighted enough
to warrant its own PR. Depends on Blocker 2 merging first (it reuses the
`GatewayAdapterCredentialError` marker + the `_EXIT_ADAPTER_SPAWN_FAILED=10` friendly
arm that Blocker 2 introduces for the *missing*-token case). **This is a security-
weighted change (comms wire contract + trust-boundary provenance) — it needs its own
ADR and a comms + security review; do NOT fold it back into a devex PR.**

## Goal

Make a *wrong* (present-but-invalid) Discord token **legible** — a friendly
`t("gateway.start.adapter_spawn_failed")` message + exit 10, like the missing-token
case — WITHOUT softening a genuine handshake bug (which must keep surfacing loud, hard
rule #7). Today a `LoginFailure` becomes a secret-free `ok=False` handshake that the
gateway raises as a **bare** `GatewayAdapterSpawnError`, indistinguishable from a
handshake bug — so a wrong token crash-loops with a raw traceback (Blocker 2 leaves
this as a documented residual).

## Why it is not a one-line change (the re-review findings)

The naive "wire + adapter + factory" design is **not implementable** and has several
trust-boundary traps. Every point below is a confirmed re-review finding:

1. **The factory never sees `LifecycleStartResult` (comms-c6-001, Critical; arch-c6-001;
   sec; test-c6-002).** The `ok=false`→raise happens in the SHARED
   `CommsPluginRunner._handshake` (`comms_runner.py:517-525`), which reads the result
   as a raw mapping, discards everything but `ok`/`seq_ack`, and raises a generic
   `PluginError` — caught by the factory's `except BaseException` and wrapped bare. So
   a **fourth layer** is required: `comms_runner._handshake` must propagate the
   closed-vocab reason as a **typed exception**. This runner is shared with the **daemon**
   path, widening the blast radius.
2. **The audit-gate widening strips the marker (comms-c6-002, High; sec-c6-004, High).**
   Extending the supervisor's `isinstance(exc, AdapterCredentialError)` gate
   (`adapter_supervisor.py:490-503`) to cover the factory-raised
   `GatewayAdapterCredentialError` routes it into the bare re-wrap that **replaces the
   marker with a plain `GatewayAdapterSpawnError`** → `start_gateway`'s narrow catch
   misses it → raw traceback returns. It must be a **distinct audit-but-don't-re-wrap
   branch** that preserves the marker. Pin this with a supervisor-level unit test.
3. **Provenance conflation (sec, Medium).** `auth_failed` is **plugin-attested** (a
   bwrap-sandboxed, untrusted child sets it), while `missing_secret`/`grant_mismatch`
   are **host-verified**. Stamping both into the same `spawn_aborted.reason` vocabulary
   conflates provenance. Carry a provenance marker (or a separate reason namespace) so
   an auditor can tell host-verified from plugin-attested.
4. **The real enforcement is the equality gate, not the wire type (sec, Medium).**
   `comms_runner` reads the result as a raw `Mapping` and never `model_validate`s it, so
   "closed-vocab `Literal` ⇒ safe" is not the enforcement point — the `== "auth_failed"`
   equality gate is. Design + test around the equality gate; the `Literal` is documentation.
5. **No wire-version bump needed, but the citation was wrong (comms-c6-003).** §4.9 is
   the manifest_version pin, unrelated to the wire result. An additive optional
   `failure_reason` field is safe within the version because the only emitter (the
   Discord failure path) is read on the raw-mapping runner path, so the strict
   `extra="forbid"` validators (`client_link:170`, `core_link`, TUI) never see it. Drop
   the §4.9 claim.
6. **Closed-vocab drift-guard (comms-c6-006).** `auth_failed` widens a closed reason
   vocabulary — bind it in a frozenset with an AST drift-guard (the #432 pattern), not a
   prose comment.
7. **Circular-import placement (comms-c6-004).** `AuthGatewayError(GatewayError)` must
   live in `plugins/alfred_discord/lifecycle.py` (not `gateway_adapter.py`) to avoid a
   latent import cycle.
8. **Test the discrimination at `connect`, with the real exception (test-c6-001, High).**
   Pin that a real `discord.LoginFailure` maps to `AuthGatewayError` while a non-login
   error maps to the **bare** `GatewayError` — at `DiscordGatewayAdapter.connect`, not
   only `DiscordLifecycle.start`. The existing `pytest.raises(GatewayError)` goes
   **vacuous** once `AuthGatewayError` subclasses it, so assert the exact subtype.
9. **Coverage (sec / test).** 4 of the touched modules — `protocol.py`,
   `adapter_child_factory.py`, `adapter_supervisor.py`, `comms_runner.py` — carry
   per-module **100% line+branch** CI gates, so every new branch must be covered. The
   two Discord plugin files are ungated (75% floor) but hold the security-critical
   discrimination branch — cover them anyway.
10. **`_audit_spawn_aborted` is unsigned structlog, not a "signed row" (sec / comms).**
    The gateway is keyless (ADR-0036); the durable trail it writes is unsigned structlog
    (the *core* credential resolver writes the signed refused row). State this precisely.

## Design (corrected)

- **Wire (`comms_mcp/protocol.py`):** add `failure_reason: Literal["auth_failed"] | None
  = None` to `LifecycleStartResult` (documentation of the closed vocab; back-compat).
- **Shared runner (`comms_runner.py:517-525`) — the fourth layer:** on `ok=false`, read
  `failure_reason` from the result mapping; if `== "auth_failed"`, raise a typed
  `PluginAuthError(PluginError)`; else the generic `PluginError` as today. Reuse the
  frozenset drift-guard for the reason value.
- **Discord adapter (`plugins/alfred_discord/lifecycle.py`):** `AuthGatewayError(GatewayError)`
  raised on `discord.LoginFailure` only; `DiscordLifecycle.start` sets
  `failure_reason="auth_failed"` (constant, secret-free). Every other error →
  `failure_reason=None`, bare `GatewayError`.
- **Factory (`adapter_child_factory.py`):** catch `PluginAuthError` from the runner and
  raise `GatewayAdapterCredentialError` (the Blocker-2 marker, with a plugin-attested
  provenance); any other `PluginError`/`BaseException` → bare `GatewayAdapterSpawnError`
  (loud).
- **Supervisor (`adapter_supervisor.py:490-503`):** a **distinct branch** for the
  factory-raised `GatewayAdapterCredentialError`: write the unsigned `spawn_aborted`
  structlog trail (provenance=plugin-attested) **and re-raise the marker unchanged**
  (never re-wrap to bare). The existing `missing_secret` branch is untouched.
- **`start_gateway`:** the Blocker-2 [R1] arm already catches
  `GatewayAdapterCredentialError` → friendly message + exit 10. No change beyond
  Blocker 2.

## ADR

Own ADR (precedent: **ADR-0035** recorded `lifecycle.start` field optionality), or an
explicit widening of Blocker 2's ADR-0054. Records: the plugin→host `failure_reason`
wire field; that a plugin-attested reason drives the *operator message*, never a
trust decision (the abort still fires either way); the provenance separation in audit;
and the daemon-path ripple of the shared-runner change.

## Testing (all findings folded)

- **Adapter:** a real `discord.LoginFailure` at `connect` → `AuthGatewayError`; a
  non-login error → bare `GatewayError` (non-vacuous: assert exact subtype); a
  `LoginFailure` → `start` result carries `failure_reason="auth_failed"`, secret-free.
- **Runner:** `ok=false` + `auth_failed` → `PluginAuthError`; `ok=false` without it →
  generic `PluginError` (the bug-stays-loud control); other adapters (tui/comms_test)
  still handshake; a non-`auth_failed` value is rejected/ignored by the equality gate.
- **Factory:** `PluginAuthError` → `GatewayAdapterCredentialError`; any other error →
  bare `GatewayAdapterSpawnError`.
- **Supervisor (lowest layer):** the factory-raised marker is audited
  (`_audit_spawn_aborted`, plugin-attested provenance) **and re-raised unchanged** (not
  re-wrapped) — the marker-preservation regression guard.
- **End to end:** a present-but-invalid token drives the **real** handshake → runner →
  factory → supervisor → `start_gateway` path → friendly message + exit 10 + the
  unsigned audit trail (not a raw traceback).
- **Coverage:** 100% line+branch on the 4 gated modules' new branches.

## Out of scope

- **#331 park-not-abort** — this makes the invalid-token abort *legible*, not
  survivable. Surviving it is still #331.
- Generalising `failure_reason` into an adapter-agnostic reason vocabulary beyond
  `auth_failed` (design the vocab to allow it — arch-c6-004 Low — but only ship
  `auth_failed`).
