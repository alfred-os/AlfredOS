# ADR-0042 — Connectivity-free-core cutover

- **Status**: Proposed (accepted on G7-3 merge)
- **Date**: 2026-06-29
- **Slice**: Spec C — G7-3 connectivity-free-core cutover (`docs/superpowers/specs/2026-06-29-g7-3-connectivity-free-core-cutover-design.md`)
- **Relates to**: ADR-0040 (reserved — comprehensive Spec-C egress ADR, G7-5),
  [ADR-0036](0036-gateway-adapter-hosting-inversion.md) (gateway holds no vault key),
  ADR-0041 (web.fetch fused fetch+extract),
  epic [#333](https://github.com/alfred-os/AlfredOS/issues/333),
  issues [#338](https://github.com/alfred-os/AlfredOS/issues/338) / [#339](https://github.com/alfred-os/AlfredOS/issues/339) (orchestrator boot-wiring — the live boot-boundary refusal hand-off)
- **Supersedes**: —

## Context

G7-0..G7-2.5 built the connectivity-free-core machinery (two-network compose topology, the
in-core `EgressClient` proxy seam, the gateway L7 proxy + tool-egress relay) but left the
core internet-reachable: `alfred_internal` was not `internal: true`, `alfred-core` was still
on `alfred_external`, and `EgressClient` retained a direct-egress fallback (unset
`ALFRED_EGRESS_PROXY_URL` ⇒ providers build their own un-proxied httpx client). This ADR
records the atomic cutover.

## Decision

1. **Atomic flip, one PR.** Add `internal: true` to `alfred_internal` AND remove
   `alfred_external` from `alfred-core` AND delete the provider-proxy direct-egress fallback,
   together. The invariant — never isolate while a fallback exists; never delete the fallback
   while still routable — is load-bearing; a guarded sequence would re-introduce the window.
   This is the deliberate exception to the "small PRs" rule.
2. **Fail-closed.** A missing/empty `ALFRED_EGRESS_PROXY_URL` raises `IOPlaneUnavailableError`
   at the `EgressClient` seam, never a silent direct hop.
3. **Kernel isolation is the enforcement-of-record.** `internal: true` is the primary control;
   the userspace forward-proxy allowlist and the AST import-guard are independent
   defense-in-depth. The import-guard covers only the httpx/SDK vector — `subprocess`,
   `urllib.request`, `http.client`, and raw `socket` are exempt by design, so the kernel
   block is the *sole* control for those residual vectors.
4. **Layered, paper-gate-proof proof.** Static (un-skipped compose-invariant tests +
   import-guard, always required) plus a docker-gated runtime egress/DNS proof in the required
   `Integration` lane, carrying a #245-style not-skipped assertion (a loud skip is still a
   green required check).

## Consequences

- **macOS/OrbStack host-port loss.** An `internal: true` container's host-published port is
  not forwarded on OrbStack/Docker-Desktop (verified 2026-06-29); `alfred-postgres`'s
  `5432:5432` keeps working on Linux but is unreachable from a Mac host. We keep the port and
  document the limitation; the compose-internal core (over `alfred_internal`) and the dev test
  loop (testcontainers) are unaffected.
- **DNS-hole closure is daemon-scoped.** The runtime proof's `getaddrinfo`-must-fail assertion
  validates that the *tested* daemons (OrbStack, the GitHub `ubuntu-latest` daemon) do not
  forward their embedded resolver out of an `internal: true` network. The durable invariant is
  "the core performs no client-side DNS — the gateway resolves for both the proxy and the
  relay"; a resolver-strip / operator-verify backstop is a G7-5 ops residual.
- **Runtime reality — seam vs boot.** The fallback deletion is a fail-closed *seam* guarantee
  now (`EgressClient` can no longer hand a provider an un-proxied client). It is not yet a live
  daemon boot-refusal: `build_router`'s only production caller (`build_orchestrator`) is not
  wired into daemon `start` today, and `IOPlaneUnavailableError` is in no daemon-start `except`
  tuple. The live G7-3 enforcement is the kernel isolation. **Hand-off:** when #338/#339 wires
  `build_orchestrator` into boot, that PR MUST catch `IOPlaneUnavailableError` at the boot
  boundary → audited `_refuse_boot` (HARD rule #7), not a bare traceback.
- **Cred-concentration preserved (ADR-0036).** The gateway remains the sole egress plane while
  holding no vault key — the provider path is an L7 CONNECT tunnel (the gateway sees the
  destination, never the prompt or the API key). The Proxy-Authorization upgrade stays a future add.
- **Symmetry is nominal.** The proxy seam raises a typed/audited `IOPlaneUnavailableError`; the
  relay assembly raises a bare `ValueError`. A typed `RelayIOPlaneUnavailableError` at the
  assembly seam is a #339-era cleanup. The `io_plane_unavailable` audit token is reused for both
  "unreachable" and "unconfigured" (the `detail` string disambiguates); a distinct token is a
  future refinement.
- **PRD lag.** This realizes the PRD §5 / §7.1 (line 447, default-deny outbound) invariant in
  code; the PRD prose + the comprehensive ADR-0040 are human-gated to G7-5.

## Alternatives considered

- **Guarded sequence (2+ PRs behind a flag).** Rejected — re-introduces the forbidden window and
  needs guard machinery deleted again at the end.
- **Full-stack runtime proof (boot the real `alfred-core` and assert it cannot curl out).**
  Deferred to the G7-5 smoke/ops lane — heavy (bwrap profiles) and opt-in (a paper gate on the
  merge path). The required proof tests the `internal: true` primitive; the static ratchet ties
  the real core to that primitive.
