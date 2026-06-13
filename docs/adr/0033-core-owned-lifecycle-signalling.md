# ADR-0033 — The core owns its lifecycle signalling (going_down / ready + per-boot epoch)

- **Status**: Proposed (Spec A; accepted when the gateway G3 consumes it)
- **Date**: 2026-06-13
- **Slice**: Spec A — `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` (§4, §8 G1)
- **Relates to**: [ADR-0025](0025-comms-stdio-transport-line-delimited-and-thin.md) (the line-delimited comms wire these frames are defined for), [ADR-0031](0031-comms-socket-transport-for-the-foreground-tui.md) (the TUI socket carrier), [ADR-0028](0028-boot-time-authorized-t3-nonce-registration.md) (boot-time T3 nonce — the epoch mirrors its bootstrap shape, NOT its trust), issue #237 (graduation criterion #7)
- **Supersedes**: —

## Context

The core self-modifies and restarts. A dial-in client (the TUI) connected through the future gateway (Spec A) must not see a bare socket EOF on a core restart; the gateway needs to know when the core is leaving and when a fresh core is genuinely healthy, and it needs to tell a fresh core's reset sequence numbers apart from a stale buffer's high-water mark.

Two facts the gateway cannot infer from the byte stream alone:

- **When the core begins a planned drain.** A socket EOF is ambiguous (clean stop vs crash). An explicit `going_down` distinguishes the planned case and lets the gateway hold buffers deliberately rather than guessing.
- **When a restarted core is HEALTHY**, not merely bound. Socket-bind happens early; the security boot graph (quarantined extractor, identity resolver, supervisor) comes up later. Replaying buffered input into a half-booted core is a correctness hole. The gateway must wait for a HEALTH signal.

It also needs a **per-boot epoch** to reconcile a fresh core (seq resets to 0) against its retained high-water mark.

These signals are CORE-owned: only the core knows its own drain point and its own boot-graph health. The gateway consumes them; it does not produce them.

## Decision

**Decision 1 — Two host-to-outward notification frames DEFINED on the existing comms wire; G1 is AUDIT-ONLY.** `core.lifecycle.going_down{reason}` and `core.lifecycle.ready{epoch}` are added as `_WireModel` notifications in `src/alfred/comms_mcp/protocol.py`, in the OPPOSITE direction to the existing plugin-to-host notifications. **G1 DEFINES these frames but does NOT send them** — there is no consumer yet (the gateway lands in G3), and capturing a single runner against the multi-adapter spawn loop would be wrong. G1's runtime behaviour is to write the `daemon.lifecycle.*` AUDIT rows only. **G3 wires the gateway carrier and adds the actual wire send** (an id-less JSON-RPC frame — a notification, not a request — via a `CommsPluginRunner.send_notification` seam introduced THEN, together with its consumer). No new carrier, no new codec; G1 is audit-only because there is no consumer yet.

**Decision 2 — `ready` = HEALTH, not socket-bind.** The `daemon.lifecycle.ready` AUDIT row is emitted by the daemon ONLY after the full security boot graph has come up and `daemon.boot.completed` is written — never on a boot that then refuses. A consumer that (in G3) sees the `ready` frame may safely release held buffers / replay input.

**Decision 3 — `going_down` is recorded at the drain, for a PLANNED shutdown only, and can never skip the teardown reaps.** The `daemon.lifecycle.going_down` AUDIT row is written at the head of the boot teardown, before the supervisor stop, and is guarded so it fires only when the daemon had actually come up (reached `ready`). A boot refusal — which also runs the teardown — does NOT emit `going_down`; it already audits `daemon.boot.failed`. The going_down audit emit is fail-loud but is NESTED inside its own `try` whose `finally` is the existing supervisor-stop + bwrap-child-reap + socket-reap + pidfile-delete chain (the #255 leak fix), so a failed going_down audit can NEVER skip those reaps. `reason` is the closed vocabulary `Literal["shutdown"]` in G1 — a bare SIGTERM carries no intent and G1 has no other intent-producer; widening a closed `Literal` is non-breaking, so G3 adds `restart` / aligned tokens when a real producer + consumer land together.

**Decision 4 — A per-boot, non-secret, serialisable epoch.** Minted once per process by `alfred.bootstrap.lifecycle_epoch.mint_boot_epoch` (a `uuid4().hex`), mirroring the nonce-factory's slot + lock + once-per-process guard. It is the TRUST-OPPOSITE of the `CapabilityGateNonce`: the nonce is identity-only and must never be serialised; the epoch EXISTS to be serialised onto the wire and into an audit row. It is recorded in `ready` and `going_down` and reserved for the comms handshake.

**Decision 5 — Every transition is audited; the audit row is authoritative (and, in G1, the ONLY record).** Each `going_down` / `ready` writes a `daemon.lifecycle.*` row over the new `DAEMON_LIFECYCLE_FIELDS` field-set via the existing `_emit_or_quarantine` path (fail-loud, exit 3 on an unwritable audit). G1 sends no wire frame, so the audit row is the authoritative and sole record of each transition. When G3 adds the wire send, the going_down send will be best-effort (suppressed so a teardown-time send failure never masks the real exit), with the audit row remaining the authoritative record — but that suppressed wire send does not exist in G1.

## Consequences

### Positive

- The gateway (G3) gains an unambiguous planned-drain signal and a health-gated replay barrier without decoding any payload — it stays a T1 carrier.
- The signals reuse the existing wire, codec, and runner; the G1 surface is two frozen models, one epoch factory, one audit field-set, and two emit sites.
- The epoch closes the seq-reconciliation hole (fresh-core seq=0 vs retained high-water) with a non-secret value that is safe on the wire and in the audit log.

### Negative / accepted

- The lifecycle frames have NO consumer until G3 — this is a wire-substrate cut (like PR-S4-11a). G1 is AUDIT-ONLY: it records the transitions and defines the frame models, but sends nothing on the wire. We assert the AUDIT rows at the right lifecycle points and the frame-model round-trip, not an end-to-end round-trip and not a wire send.
- `going_down`'s `reason` is the single closed value `shutdown` in G1 — a bare SIGTERM carries no intent and there is no other intent-producer yet. A richer intent path (`restart`, `config_reload`) is deferred until a producer of that intent exists; widening a closed `Literal` is non-breaking, so G3 adds it with its consumer.

### Scope boundary (this ADR)

- This ADR ships the core AUDIT EMISSION + the two DEFINED wire frames + the epoch, proven by unit tests over the frame models (incl. round-trip), the epoch factory (incl. the test reset seam), and the daemon emit points (ready AUDIT row after boot-healthy, going_down AUDIT row at the drain, planned-only, shared epoch on both, audit rows on a default-empty boot, audit-but-no-wire contract).
- The runner `send_notification` seam + the actual wire send are DEFERRED to G3 (G1 is audit-only because there is no consumer yet). The gateway/consumer (G3), the resume buffer (G4), and the seq/ack codec (G2) are OUT of scope.
- **Forward reference (no G1 code):** the per-boot epoch's reconciliation purpose introduces an attack surface for G3 — a spoofed/replayed epoch against the gateway's `ready`/handshake reconciliation. G3 MUST add an adversarial-corpus entry covering "epoch spoof / replay against the gateway reconciliation" (a fresh-core `seq=0` masquerading against a retained high-water mark, and a stale-epoch replay) when it lands the consumer. G1 ships no gateway and no reconciliation code, so this is a reserved corpus slot, not a G1 test.

## Alternatives considered

- **Infer drain from socket EOF.** Rejected: EOF cannot distinguish a clean stop from a crash, and gives no health signal for the restarted core.
- **Reuse the `CapabilityGateNonce` as the epoch.** Rejected: the nonce is identity-only and forbidden from serialisation (`alfred.security.tiers`); putting it on the wire would defeat the gate's identity check and leak a security primitive. The epoch is a distinct, non-secret value.
- **`ready` on socket-bind.** Rejected: replaying input into a half-booted core is a correctness hole; `ready` must mean HEALTH.
- **Send the frames in G1.** Rejected: there is no consumer until G3, and the boot path has a multi-adapter spawn loop with no single canonical runner to carry a host-to-outward frame. Defining the frames now (so G3 has the contract) while emitting only audit rows keeps G1 a clean substrate cut.
