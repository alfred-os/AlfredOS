# ADR-0035 — `lifecycle.start` credentials are optional (adapter-dependent), not a credential-delivery channel

- **Status**: Proposed (Spec A; accepted on G3-3b-2b merge)
- **Date**: 2026-06-14
- **Slice**: Spec A — `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` (§8 G3-3b)
- **Relates to**: [ADR-0016](0016-slice4-discord-tui-comms-mcp-rewrite.md) (the comms-MCP rewrite whose wire-format schemas this model belongs to), [ADR-0025](0025-comms-stdio-transport-line-delimited-and-thin.md) (the line-delimited wire the handshake rides), [ADR-0031](0031-comms-socket-transport-for-the-foreground-tui.md) (the TUI socket carrier whose handshake this fixes), [ADR-0032](0032-gateway-comms-resume-transport.md) (the gateway client leg that sends `lifecycle.start`), issue #237 (graduation criterion #7)
- **Supersedes**: —

## Context

`lifecycle.start` is the first frame the host (a runner, or the G3 gateway acting
as HOST on its client leg) sends to a comms peer. Its params are validated by
`LifecycleStartRequest` in `src/alfred/comms_mcp/protocol.py`. As shipped in
ADR-0016 the model REQUIRED two non-empty string fields — `credentials_ref` and
`policies_snapshot_hash` (`Field(min_length=1)`).

Three facts make those fields over-specified:

- **No producer sends them.** The merged host handshake
  (`alfred.plugins.comms_runner._handshake`) puts only
  `{adapter_id, seq_ack, epoch?}` on the wire. The daemon never constructs a
  `LifecycleStartRequest` for the wire at all. The grep
  `credentials_ref|policies_snapshot_hash` over `src/` finds them only in
  daemon AUDIT-subject code (`DAEMON_BOOT_FIELDS`), which is an unrelated audit
  row, not a wire producer.
- **The sole strict consumer discards them.** The TUI co-host
  (`plugins/alfred_tui/src/alfred_tui/server.py`) calls
  `LifecycleStartRequest.model_validate(params)` and then reads ONLY
  `start_req.adapter_id`. The two credential fields are never used.
- **It is a latent bug.** Because the required fields are never sent, the merged
  daemon-to-TUI socket handshake (ADR-0031) would fail validation today — the
  model rejects the exact shape its only producer emits. The same break sits on
  the new gateway-to-TUI client leg (ADR-0032).

Critically, these fields were never the credential-delivery mechanism. Real
adapter credentials flow through the secret broker at the tool-call boundary
(hard rule #6) — the broker substitutes secret values; the model never sees a
secret. `credentials_ref` / `policies_snapshot_hash` are adapter-dependent
handshake metadata, and the only adapters that exist (the reference plugin, the
operator-local TUI) have neither.

## Decision

**`credentials_ref` and `policies_snapshot_hash` become optional** — typed
`str | None = None` rather than required `Field(min_length=1)`. The model stays
`frozen=True, extra="forbid"`; `adapter_id` stays required and validated against
the `adapter_kind` frozenset; an unknown adapter id, an unknown field, or a
missing `adapter_id` still fails loudly. A request that DOES carry the two
fields still validates and round-trips their values (back-compat for a future
credential-bearing adapter's host).

The class docstring records that these are adapter-dependent handshake metadata,
NOT the credential channel: real credentials flow through the secret broker at
the tool-call boundary (hard rule #6), so relaxing these fields does not weaken
any adapter's credential handling.

## Consequences

### Positive

- Fixes BOTH the gateway-to-TUI (ADR-0032) and the latent daemon-to-TUI
  (ADR-0031) handshakes: the model now accepts the exact
  `{adapter_id, seq_ack, epoch?}` shape every host producer actually emits.
- Removes an over-specified wire contract that no producer satisfied and no
  consumer read — the model now matches reality.
- `extra="forbid"` is unchanged, so a typo'd or smuggled wire field still
  surfaces as a loud validation failure.

### Neutral / unchanged

- The secret-broker credential path (hard rule #6) is UNCHANGED. These fields
  were never the credential-delivery mechanism, so making them optional cannot
  weaken credential handling.
- A future credential-bearing adapter's HOST may still supply both fields; they
  round-trip exactly as before.

### Negative / accepted

- The two fields now admit `None`, so a future consumer that needs them must
  validate their presence at its own call site rather than relying on the
  model. No such consumer exists today.
