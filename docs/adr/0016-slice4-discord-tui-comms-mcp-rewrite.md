# ADR-0016 — Slice 4: rewrite Discord and TUI adapters as MCP plugins

## Status

Accepted

**Date:** 2026-05-31

## Context

ADR-0009 shipped Discord and TUI adapters as in-process Python Protocols,
explicitly noting that "the rewrite is intentional" and that "the Slice-3
reviewer gate re-checks PRD §5 compliance." Slice 3 ships the `PluginTransport`
Protocol and `StdioTransport` implementation (ADR-0017 §4) plus a
`CommsAdapterMCP` Protocol stub and a reference test plugin
(`plugins/alfred_comms_test/`). The in-process adapters remain unchanged
through Slice 3.

PRD §5 requires all comms surfaces to speak MCP. The MCP transport is now
shipped. The remaining gap is the adapter implementations themselves.

## Decision

Slice 4 rewrites `DiscordAdapter` and `TuiAdapter` as MCP plugins under the
Slice-3 `StdioTransport`. The message-contract definition (full field schema,
error shapes, rate-limit signalling) is co-defined with this ADR at Slice-4
implementation time. The four wire methods contracted in the Slice-3
reference test plugin (`lifecycle.start`, `lifecycle.stop`,
`inbound.message`, `adapter.health`) are the seed; Slice 4 extends this
contract with Discord-specific fields (embeds T3-promotion, attachment
handling) and finalises the ADR-0009 polarity-inversion note.

### Sandbox posture for the Discord adapter (PR-S4-9, sec-1 round-2 closure)

The Discord adapter manifest declares `[sandbox] kind = "full"`, NOT the
first-party-relay `kind = "none"` carve-out the original plan sketched. Rationale,
grounded in the ADR-0015 quarantined-LLM precedent: the Discord adapter ingests
adversary-controlled bytes from arbitrary Discord users (embed titles, attachment
filenames, message content, reply targets) and opens its WSS connection to the
Discord gateway in-process, so a compromise in the event-parsing path must be
contained by the kernel, not by convention. The policy bytes ship at
`config/sandbox/discord-adapter.{linux.bwrap.policy,macos.sb,windows.stub.policy}`
and MIRROR the quarantined-LLM policies' fs/namespace containment (ro-binds
`/usr` `/lib` `/lib64`, tmpfs scratch, synthesised `/dev`, unshare
`pid`/`uts`/`cgroup`/`ipc`, `die_with_parent`, `keep_fds=[3]`) with ONE
deliberate addition — a `/etc/ssl/certs` ro-bind the quarantined LLM does not
need, for verifying the Discord TLS chain.

**Egress is NOT yet kernel-enforced — deferred to #230.** The Discord policy does
NOT `unshare net`: the plugin needs outbound network for the Discord WSS
connection, and the `SandboxPolicy` schema cannot yet express a Discord-only
egress allowlist. Filesystem and process/namespace containment ARE kernel-enforced;
egress is the documented, accepted gap for the mid-flight slice state. The
manifest's `[network] allowlist` records the intended Discord-only cap
(`discord.com`, `gateway.discord.gg`); #230 lands the `network.outbound_allowlist`
schema field + the bwrap `--unshare-net` + a filtered forwarder/egress-proxy that
enforces it at the kernel boundary.

> **Amended 2026-06-26, Spec C G7-1 (#333).** The quarantined-LLM policy now
> `--unshare-net`s its deterministic-echo child (which needs no egress), so the
> Discord adapter no longer mirrors it on the net-namespace axis — the Discord
> egress deferral stands ALONE, tracked by #230 / G7-4. The quarantined-LLM 2c
> real-LLM egress (also #230) and the Discord egress both route through the gateway
> L7 CONNECT proxy when they land, not by re-opening their own net namespaces.

> **Amended 2026-06-30, Spec C G7-4 (#333).** The **Discord half** of `#230` is now
> closed. The Linux policy adds `"net"` to `unshare` (empty netns, kernel-enforced);
> the adapter reaches the gateway's L7 CONNECT proxy via a bind-mounted AF_UNIX socket
> on a gateway-only `alfred_discord_egress` volume (never `alfred_run` / never reachable
> from the connectivity-free core). A thin in-child TCP→unix shim lets
> `discord.py`'s `Client(proxy=...)` work unmodified. See
> [ADR-0043](0043-discord-adapter-egress-l7-proxy-netns-bridge.md) for the full
> decision record. The **2c real-LLM quarantine-child egress deferred to #230/#340**
> (ADR-0015) is **not** closed here and remains open.

## Consequences

### Positive

- PRD §5 "Plugins are MCP servers" invariant fully satisfied for comms adapters.
- T3-promotion for Discord embeds/attachments/polls lands naturally alongside
  the MCP rewrite — the DLP scan is at the transport boundary, not in-adapter.

### Negative

- The `CommsAdapter` in-process Protocol (`src/alfred/comms/`) is removed.
  Any external code (custom personas, third-party skills) that imported
  concrete adapter classes directly rather than using the Protocol type will
  break. The import-isolation AST test (`tests/unit/comms/test_no_direct_adapter_imports.py`)
  already enforces this invariant, so breakage is restricted to code that
  bypasses the test gate.

### Neutral

- The `IdentityResolver` placement (host-side in Slice 3, per §9.1) is
  revisited when the full host-side callback wire type is designed for Slice 4.
- (PR-S4-8 follow-up, #152) `SupervisorBreakerTripper.trip_comms_breaker`
  currently collapses every comms breaker-trip reason onto
  `plugin_lifecycle_crash`. When the rate-limit handler lands in PR-S4-9,
  `TripBreakerReason` must gain a `comms.rate_limit.exhausted` member so a
  global-exhaustion trip is distinguishable from a lifecycle crash in the audit
  graph. Tracked in the PR-S4-9 follow-up issue (#233).

## References

- [PRD §5](../../PRD.md#5-architecture-overview) — "Plugins are MCP servers."
- [ADR-0009](0009-comms-adapter-protocol-slice2-only.md) — in-process Protocol; superseded by this ADR for new adapters.
- [ADR-0015](0015-slice4-containerised-quarantined-llm.md) — the `kind=full` bwrap precedent + the identical egress-deferred-to-#230 posture the Discord adapter mirrors.
- [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice-3 transport decision.
- #230 — kernel-enforced egress allowlist (`network.outbound_allowlist` + `--unshare-net`); blocks production Discord/quarantined-LLM traffic until landed.
- [Spec §9](../superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md#9-adr-0009-comms-mcp-rewrite-fork-8) — ADR-0009 comms-MCP rewrite scope.
