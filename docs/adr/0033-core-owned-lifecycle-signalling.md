# ADR-0033 — The core owns its lifecycle signalling (going_down / ready + per-boot epoch)

- **Status**: Proposed (Spec A; accepted when the gateway G3 consumes it)
- **Date**: 2026-06-13
- **Slice**: Spec A — `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` (§4, §8 G1)
- **Relates to**: [ADR-0025](0025-comms-stdio-transport-line-delimited-and-thin.md) (the line-delimited comms wire these frames are defined for), [ADR-0031](0031-comms-socket-transport-for-the-foreground-tui.md) (the TUI socket carrier), [ADR-0028](0028-boot-time-authorized-t3-nonce-registration.md) (boot-time T3 nonce — the epoch mirrors its bootstrap shape, NOT its trust), issue #237 (graduation criterion #7)
- **Supersedes**: —
- **Amended by**: [ADR-0036](0036-gateway-adapter-hosting-inversion.md) — Spec B reuses this lifecycle for the gateway-hosted adapter legs + the spawn-credential control frames.

## Context

The core self-modifies and restarts. A dial-in client (the TUI) connected through the future gateway (Spec A) must not see a bare socket EOF on a core restart; the gateway needs to know when the core is leaving and when a fresh core is genuinely healthy, and it needs to tell a fresh core's reset sequence numbers apart from a stale buffer's high-water mark.

Two facts the gateway cannot infer from the byte stream alone:

- **When the core begins a planned drain.** A socket EOF is ambiguous (clean stop vs crash). An explicit `going_down` distinguishes the planned case and lets the gateway hold buffers deliberately rather than guessing.
- **When a restarted core is HEALTHY**, not merely bound. Socket-bind happens early; the security boot graph (quarantined extractor, identity resolver, supervisor) comes up later. Replaying buffered input into a half-booted core is a correctness hole. The gateway must wait for a HEALTH signal.

It also needs a **per-boot epoch** to reconcile a fresh core (seq resets to 0) against its retained high-water mark.

These signals are CORE-owned: only the core knows its own drain point and its own boot-graph health. The gateway consumes them; it does not produce them.

## Decision

**Decision 1 — Two host-to-outward notification frames DEFINED on the existing comms wire; G1 is AUDIT-ONLY.** `daemon.lifecycle.going_down{reason}` and `daemon.lifecycle.ready{epoch}` are added as `_WireModel` notifications in `src/alfred/comms_mcp/protocol.py`, in the OPPOSITE direction to the existing plugin-to-host notifications. **G1 DEFINES these frames but does NOT send them** — there is no consumer yet (the gateway lands in G3), and capturing a single runner against the multi-adapter spawn loop would be wrong. G1's runtime behaviour is to write the `daemon.lifecycle.*` AUDIT rows only. **G3-2 wires the carrier and adds the actual wire send** (an id-less JSON-RPC frame — a notification, not a request — via a `CommsPluginRunner.send_notification` seam, together with the socket-carrier consumer registration). No new carrier, no new codec. The canonical method names are `daemon.lifecycle.*` (matching the G1 audit event names) — NOT `core.lifecycle.*`; G3-2 reconciled the audit-event-name and wire-method-name to a single `Final` constant (`DAEMON_LIFECYCLE_READY` / `DAEMON_LIFECYCLE_GOING_DOWN` in `protocol.py`) so they cannot drift, and both the core-send and the G3-3 gateway-consume import them there.

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

## G3-2 amendment — the core now SENDS the lifecycle frames (audit-only → wire-send)

Spec A G3-2 (#237) implements the wire send Decision 1/5 deferred to G3. G1 stays the authoritative audit-only record; G3-2 adds the best-effort wire frame ON TOP. The decisions are unchanged; this records HOW the send is implemented.

- **Method names.** The canonical wire methods are `daemon.lifecycle.ready` / `daemon.lifecycle.going_down`, exported as `Final` constants from `comms_mcp/protocol.py`. `_emit_ready` / `_emit_going_down` use the SAME constants for their audit `event=`, so the audit-event-name and the wire-method-name cannot drift.
- **Socket-carrier only.** Frames are broadcast over the socket-listener carrier alone (the foreground TUI / future gateway dial-in), never to the daemon-spawned stdio adapters — those die with the core, so they neither need nor receive a lifecycle frame. A boot-local `LifecycleBroadcaster` collects the socket-carrier runner's id-less `send_notification` (registered post-handshake); `_emit_ready` / `_emit_going_down` broadcast through it AFTER the authoritative audit row.
- **The boot-`ready` reaches ZERO senders in the normal case.** `_emit_ready` fires synchronously on the boot coroutine, while the socket peer connects on-demand later via the separately-scheduled accept task. So a fresh core's boot `ready` broadcast normally reaches no sender — a clean DEBUG no-op. Therefore **the gateway derives core-liveness from a successful handshake that carries the epoch, NOT from a received `ready` frame.** The runner's `lifecycle.start` handshake params now include `epoch` (`current_boot_epoch()`, non-secret) alongside `seq_ack`. Late-connect `ready` delivery is deferred to G3-3; it is only valid BECAUSE the epoch rides the handshake.
- **Lifecycle frames occupy seq slots on a negotiated wire.** Once `AlfredSeqAck/1` is negotiated, `transport.send` frames EVERY payload with an incrementing `_send_seq`, so a `ready`/`going_down` notification consumes a seq number and rides INSIDE the seq stream (in-band in the seq sequence, out-of-band only in JSON-RPC semantics). The G3-3 gateway `decode_seq_frame`s them, then routes by `method`. There is no separate unframed write.
- **Single-writer lock.** The boot coroutine's lifecycle-send is a SECOND writer racing the pump's reentrant `send_request`, so `CommsSocketTransport.send` (and, for defensive symmetry, `CommsStdioTransport.send`) wraps `encode → write → drain → seq-increment` in an `asyncio.Lock`. The lock intentionally spans `drain()` (a torn frame is worse than a delayed one); the reader never takes it (no reader/writer deadlock). No acquisition timeout (a G4 back-pressure concern).
- **Best-effort wire, authoritative audit.** A wire-send failure is logged-not-fatal (`comms.lifecycle.wire_send_failed`, with `error=repr(exc)`); the per-sender catch is NARROW (`BrokenPipeError`, `ConnectionResetError`, `CommsProtocolError`, `OSError`) — never bare `Exception`, and `asyncio.CancelledError` propagates so the `going_down` broadcast (which runs in the shutdown `finally`) never wedges the drain. H1 ordering: `going_down` is broadcast AFTER the audit row and BEFORE `supervisor.stop()` (which sets `shutdown_event` → the pump closes the transport).
- **Epoch wire-exposure reviewed.** The epoch's appearance in the handshake + frames is non-disclosing: it is non-secret per-boot metadata and the socket peer is same-uid T1. A future multi-user / non-local-client change (spec §10) re-opens this review (security M-1).
- **Peer-auth-reject diagnostic (closes the G3-1 deferral).** A mismatched-uid peer on the 0600 socket fires a `CommsSocketListener.on_peer_rejected` callback (with the rejected uid), and the daemon writes a `comms.socket.peer_uid_rejected` AUDIT row (peer_uid + expected_uid). A rejection is an EXPECTED adversarial event, so the boot is NOT refused (refusing would be a self-inflicted DoS an attacker could trigger by racing the socket): loud audit row + metric, boot continues. If the audit WRITE ITSELF fails, however, that is hard-rule-#7 territory: `_on_connect` catches the callback exception and ESCALATES it onto the supervised `accept()` future (`set_exception`), so a broken security audit fails LOUD (an audited supervisor crash) rather than being orphaned in the detached `start_unix_server` callback (corroborated PR #264 fleet finding).
