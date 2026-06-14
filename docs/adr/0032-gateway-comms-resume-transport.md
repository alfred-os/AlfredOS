# ADR-0032 — The comms-resume gateway transport carries an out-of-band seq/ack header

- **Status**: Proposed (first cut — codec / wire-format only; G3/G4 amend)
- **Date**: 2026-06-13
- **Slice**: Spec A (Comms-Resume Gateway) — `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md`
- **Relates to**: ADR-0025 (the line-delimited comms transport this extends), ADR-0031 (the TUI socket carrier), ADR-0033 (core lifecycle signalling / epoch, G1), issue #237 (graduation criterion #7).
- **Supersedes**: —

## Context

The comms-resume gateway (Spec A) fronts dial-in clients with a resumable, payload-blind wire so a core restart never drops the operator or loses in-flight input. The ADR-0025 wire is a thin line-delimited JSON-RPC frame (`json.dumps(frame) + "\n"`) with a per-frame DoS bound (`_MAX_COMMS_LINE_BYTES`) and no notion of sequence, acknowledgement, or replay-dedup. Buffer-and-replay across a restart (G4) needs all three. They cannot live in the JSON-RPC payload: the relay (G3) must forward the body byte-for-byte to stay payload-blind (a T1 carrier, not a trust-tier authority) and to preserve the runner's request/response `id` correlation end-to-end. So the sequence metadata must ride OUT OF BAND, wrapping the opaque payload. The codec needs the existing frame bound + the loud-failure type, which moved into a shared leaf module (`src/alfred/plugins/comms_wire.py`) so the codec and both transports import them from one place rather than closing a codec↔transport import cycle.

## Decision

The following decisions are recorded by G2 (the codec); the gateway, buffer, epoch-auth, shared-volume AF_UNIX, and audit-reconcile decisions the spec §8 also assigns to ADR-0032 are amended in by G3/G4 when those components land. This first cut is scoped to the wire format.

- **Decision 1 — An out-of-band, magic-gated ASCII header wraps the verbatim payload.** A negotiated wire unit is `A1 s=<seq> a=<ack> n=<payload_len> |<opaque-payload>\n` — a single newline-terminated line, so the existing `readline()` reader on both transports is unchanged. `A1` is the magic + wire version. The codec (`src/alfred/plugins/comms_seq_codec.py`) never decodes the payload; it splits the header off and returns the payload bytes untouched.

- **Decision 2 — `seq` is a per-direction monotonic counter, additive to and distinct from the JSON-RPC `id`.** The relay preserves `id` end-to-end (the runner's `_pending`/`_resolve_pending` correlation survives the relay) because the codec touches no payload byte. `seq` is a second, header-level counter.

- **Decision 3 — Cumulative ack = the highest CONTIGUOUS seq durably intaken; the G2 wire ack is an `a=0` placeholder.** A gap does not advance the ack. Acks are coalesced (piggyback + bounded timer) by the sender/relay — there is NO standalone ack per data frame. The G2 transport emits `a=0` as a PLACEHOLDER and deliberately does NOT piggyback a `max(seq seen)` high-water: a high-water would falsely ack PAST gaps, contradicting this contiguous-ack definition. G2 ships the ack VALUE semantics on the PURE, property-tested `SeqDedupWindow.cumulative_ack()`; the G3 relay wires that as the ack source AND owns the coalescing timer. The transport carries `a=0` and consumes no ack.

- **Decision 4 — Idempotent dedup keyed on `(leg, seq)` ONLY, never payload-derived.** `SeqDedupWindow` is constructed per-leg; a re-seen `(leg, seq)` is dropped idempotently. No header value is derived from payload content — the structural guarantee that the carrier stays payload-blind.

- **Decision 5 — Version-gated at the handshake, default-OFF, mixed-safe; decode is direction-agnostic.** The header is emitted only when both peers advertise `AlfredSeqAck/1` in the `lifecycle.start` capability exchange (`SeqAckCapability` on `LifecycleStartRequest`/`LifecycleStartResult`). The gate flag is per-transport and controls only what `send` EMITS; `decode` is magic-gated and direction-agnostic, so a seq-enabled reader still reads a plain `{`-line from an un-upgraded peer (and vice versa). The runner flips the transport via a TYPED `enable_seq_ack` on the `_CommsTransportLike` Protocol — never `getattr` duck-typing.

  - **A daemon-spawned plugin is NOT the seq/ack peer (G2 scope).** seq/ack exists to make the **core↔gateway** leg (G3) resumable across a core restart. A daemon-SPAWNED comms plugin (e.g. the reference adapter, or Discord) dies *with* the core, so it gets no resume benefit and must NOT advertise the capability — it stays plain ADR-0025. The host (runner) MAY keep advertising `AlfredSeqAck/1` on `lifecycle.start`: that is HARMLESS, because the version-gate only flips `send` to the `A1` header when a peer ECHOES the capability, and a spawned plugin never does. The gateway (G3) is the peer that both echoes the capability **and** deframes the header. (A plugin that echoed without deframing would flip the gate ON and then be unable to parse the `A1`-wrapped frames the host sent it — so the reference adapter deliberately does not echo.)

- **Decision 6 — The header costs payload budget (Option A).** `_MAX_COMMS_LINE_BYTES` is unchanged and bounds the WHOLE unit (header + payload + `\n`). Because the `A1 s=… a=… n=… |` header plus the trailing newline add a bounded overhead, on a NEGOTIATED wire the effective payload ceiling is `max_unit_bytes - _MAX_HEADER_BYTES`, where `_MAX_HEADER_BYTES` is the worst-case NON-payload width — the literal skeleton (incl. the `|` delimiter), three base-10 counters each at most the decimal width of `_MAX_COMMS_LINE_BYTES`, and the trailing `\n`. A payload at or under the ceiling is GUARANTEED to encode for any counter widths. The runtime check is on the OUTER unit; `_MAX_HEADER_BYTES` is the documented reservation the G3 relay sizes payloads against.

## Consequences

### Positive

- The relay can forward the JSON-RPC body verbatim, staying payload-blind, while seq/ack/dedup ride alongside.
- `id` correlation survives the relay untouched; the existing runner is undisturbed.
- The codec is a pure, hypothesis-property-testable unit, decoupled from the gateway/buffer that consume it.

### Negative / accepted

- A second framing concept (the seq header) now layers over ADR-0025. The cost is one small codec; the alternative — an in-band JSON field — would force the relay to parse + re-serialize every frame, breaking payload-blindness and adding a hot-path cost.
- G2 wires the codec into both transports behind the gate but ships NO consumer of ack/dedup. The seq value is computed and carried; the ack is an `a=0` placeholder and the dedup window is unwired — they are not acted on until G3/G4. Recorded so a later reader does not mistake the unconsumed ack/window for a bug.

### Scope boundary (this ADR / G2)

G2 ships the codec (`CommsSeqCodec` + `SeqDedupWindow`), the `comms_wire` leaf module, the handshake version-gate (`SeqAckCapability`), and the gate-conditional transport insertion. It builds NO gateway (G3), NO `ReplayBuffer` (G4), NO ack-coalescing timer, NO send-window/back-pressure, and changes NO resume behaviour. The buffer-security, epoch-auth, shared-volume AF_UNIX, and gateway-local audit-reconcile sections the spec assigns to ADR-0032 are amended by G3/G4.

## Amendment — Peer authentication (G3-1)

The gateway↔core leg rendezvous over the ADR-0031 named AF_UNIX socket (`CommsSocketListener` binds + accepts; the gateway/foreground `alfred chat` dials in). Spec A §4/§6 require the core to authenticate the peer via `SO_PEERCRED` on accept, in BOTH directions. G3-1 lands the **accept side**; the dial side (the gateway authenticating the core after `connect`) is G3-3.

- **FS perms are the enforcement-of-record.** The socket is `0600` under a `0700` runtime dir, so only the owner uid can `connect()` it. This already bars a cross-uid peer on every platform; the `SO_PEERCRED` check is defense-in-depth ON TOP, not the only line.

- **`SO_PEERCRED` is cross-platform best-effort.** On Linux, `_resolve_peer_uid` reads the kernel-attested `(pid, uid, gid)` of the connector off the **accepted child socket** (`writer.get_extra_info("socket")`) — never the listening socket, which would return our own uid and always pass. The creds are unpacked as three UNSIGNED ints (`"3I"` — the kernel `struct ucred`). A platform without `SO_PEERCRED` (macOS dev hosts) resolves to `None`.

- **It NEVER fail-closes on an unanswerable platform.** `_peer_uid_authorized` accepts a `None` uid (degrade to the FS-perms guarantee) and a uid equal to `os.getuid()`; it refuses only a uid that genuinely mismatches ours (a same-uid-race re-bind or a wider-perm misconfig). `getsockopt` may also return fewer bytes than requested — a length-guard plus an `(OSError, struct.error)` catch degrade a short read / closed socket to `None` rather than crashing the accept callback and wedging the listener (CLAUDE.md hard rule #7).

- **A rejected peer is refused without wedging a legitimate dial-in.** On reject the listener closes the writer, logs `comms.socket.peer_uid_rejected` (structlog), and does NOT resolve the accept future — so a subsequent same-uid peer still connects. The core-side daemon AUDIT row for the rejection lands in G3-2 (the daemon caller owns the injected audit writer; the G3-1 listener is a dependency-light library whose loud surface is the structlog warning + the refusal).

This amendment introduces NO env override: the configurable runtime/socket dir (`ALFRED_COMMS_RUNTIME_DIR`, behind fail-closed validation) is deferred to G3-4 with the shared-volume mount it serves.
